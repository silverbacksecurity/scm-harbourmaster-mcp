"""Prisma Access Browser configuration backup and restore.

Covers the objects the Browser Management API (``/seb-api/v1``) can both read
and create:

  * custom applications (types ``custom``, ``private``, ``non-web``,
    ``localdesktopcustom``) and their plugins,
  * application groups,
  * device groups (posture attributes),
  * user groups (membership is carried as user emails).

NOT covered, because the API has no endpoint for them: browser policy rules,
data controls, security settings and customisation. Those must be copied in
the SCM UI. Users and devices are tenant enrolments, not configuration.

Identifiers are tenant-specific for custom applications and users, so a
restore maps them by name (applications) and email (users). Catalog
application IDs are global — the predefined "Google Workspace" group has the
same member IDs in every tenant — so they are kept as-is.

Changes made through the API land in a draft; ``publish=True`` publishes it.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..audit.extractor import _bearer_session_for
from ..utils.logging import get_logger
from ..utils.paths import backup_dir
from ..utils.tool_decorator import scm_tool
from ..utils.write_safety import (
    DRY_RUN_HINT,
    audit_write,
    normalize_ticket_ref,
    ticket_ref_error,
)
from .pab import _BASE, _status_hint

logger = get_logger(__name__)

BACKUP_VERSION = "pab-1.0"
APP_TYPES = ("custom", "private", "non-web", "localdesktopcustom")
_TIMEOUT = (5, 60)
_MAX_PAGES = 100

# Response-only fields dropped before an object is re-created.
_APP_READ_ONLY = frozenset({"id", "metadata", "catalog_name", "catalog_attributes"})
_DEVICE_GROUP_FIELDS = ("name", "platform", "attributes")


def _default_backup_dir() -> Path:
    return backup_dir()


def _list(session: Any, path: str, paginate: bool = True) -> tuple[list[dict[str, Any]], str]:
    """All items at *path* (cursor pagination when supported), or an error string."""
    items: list[dict[str, Any]] = []
    cursor = ""
    for _ in range(_MAX_PAGES):
        params: dict[str, Any] = {}
        if paginate:
            params["limit"] = 200
            if cursor:
                params["cursor"] = cursor
        resp = session.get(f"{_BASE}/{path}", params=params, timeout=_TIMEOUT)
        try:
            body = resp.json()
        except Exception:
            body = (resp.text or "")[:200]
        if resp.status_code != 200:
            return items, _status_hint(path, resp.status_code, body)
        if isinstance(body, list):
            return body, ""
        if not isinstance(body, dict):
            return items, f"{path}: unexpected response shape"
        items.extend(body.get("data") or [])
        info = body.get("pageInfo") or {}
        cursor = info.get("cursor") or ""
        if not paginate or not info.get("hasNextPage") or not cursor:
            return items, ""
    return items, f"{path}: stopped after {_MAX_PAGES} pages"


def _group_ids(user: dict[str, Any]) -> set[str]:
    """IDs of the user groups a user belongs to (API returns ids or objects)."""
    out: set[str] = set()
    for g in user.get("userGroups") or []:
        gid = g.get("id") if isinstance(g, dict) else g
        if gid:
            out.add(str(gid))
    return out


def build_backup(session: Any, tenant_id: str) -> dict[str, Any]:
    """Collect every restorable Prisma Browser object from one tenant."""
    errors: dict[str, str] = {}

    def fetch(path: str, paginate: bool = True) -> list[dict[str, Any]]:
        items, err = _list(session, path, paginate)
        if err:
            errors[path] = err
        return items

    applications: list[dict[str, Any]] = []
    for app_type in APP_TYPES:
        applications.extend(fetch(f"applications/type/{app_type}"))

    user_groups = fetch("user-groups")
    members: dict[str, list[str]] = {}
    if user_groups:
        wanted = {str(g.get("id")) for g in user_groups}
        for user in fetch("users"):
            email = str(user.get("email") or "").strip().lower()
            for gid in _group_ids(user) & wanted:
                if email:
                    members.setdefault(gid, []).append(email)

    return {
        "backup_version": BACKUP_VERSION,
        "timestamp": datetime.now(UTC).isoformat(),
        "source_tenant": tenant_id or "default",
        "applications": applications,
        "plugins": fetch("applications/plugins", paginate=False),
        "application_groups": fetch("application-groups"),
        "device_groups": fetch("device-groups"),
        "user_groups": [
            {
                "name": g.get("name"),
                "id": g.get("id"),
                "member_emails": members.get(str(g.get("id")), []),
            }
            for g in user_groups
        ],
        "errors": errors,
    }


def _response_id(resp: Any) -> str:
    try:
        body = resp.json()
    except Exception:
        return ""
    if isinstance(body, dict):
        data = body.get("data")
        if isinstance(data, dict) and data.get("id"):
            return str(data["id"])
        if body.get("id"):
            return str(body["id"])
    return ""


def _error_text(resp: Any) -> str:
    try:
        body = resp.json()
        err = body.get("error") or body.get("errorResponse") or body
        if isinstance(err, dict) and err.get("message"):
            return f"HTTP {resp.status_code}: {str(err['message'])[:200]}"
        return f"HTTP {resp.status_code}: {str(body)[:200]}"
    except Exception:
        return f"HTTP {resp.status_code}: {(resp.text or '')[:200]}"


class _Report:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str]] = []
        self.counts = {"created": 0, "would create": 0, "skipped": 0, "failed": 0}

    def add(self, kind: str, name: str, status: str, bucket: str) -> None:
        self.rows.append((kind, name, status))
        self.counts[bucket] += 1


def restore_backup(
    session: Any, backup: dict[str, Any], *, dry_run: bool, publish: bool
) -> tuple[_Report, list[str]]:
    """Recreate a backup's objects in dependency order; never overwrites."""
    report = _Report()
    notes: list[str] = []

    def post(path: str, body: dict[str, Any]) -> Any:
        return session.post(f"{_BASE}/{path}", json=body, timeout=_TIMEOUT)

    # ── Target state ──────────────────────────────────────────────────────────
    # Every skip decision depends on this, so an unreadable target aborts the
    # restore rather than risking duplicate creates.
    read_errors: list[str] = []

    def target_list(path: str, paginate: bool = True) -> list[dict[str, Any]]:
        items, err = _list(session, path, paginate)
        if err:
            read_errors.append(err)
        return items

    target_apps: dict[tuple[str, str], str] = {}
    for app_type in APP_TYPES:
        for app in target_list(f"applications/type/{app_type}"):
            target_apps[(app_type, str(app.get("name")))] = str(app.get("id"))
    app_group_names = {str(g.get("name")) for g in target_list("application-groups")}
    device_group_names = {str(g.get("name")) for g in target_list("device-groups")}
    user_group_names = {str(g.get("name")) for g in target_list("user-groups")}
    target_plugins = {
        str(p.get("applicationId")) for p in target_list("applications/plugins", paginate=False)
    }
    if read_errors:
        return report, ["Restore aborted — could not read the target tenant:", *read_errors]

    # ── 1. Applications ───────────────────────────────────────────────────────
    app_ids: dict[str, str] = {}  # source id -> target id ("" in a dry run)
    custom_ids = {str(a.get("id")) for a in backup.get("applications", [])}
    for app in backup.get("applications", []):
        app_type, name, src_id = str(app.get("type")), str(app.get("name")), str(app.get("id"))
        if app_type not in APP_TYPES:
            continue
        if (app_type, name) in target_apps:
            app_ids[src_id] = target_apps[(app_type, name)]
            report.add(f"app ({app_type})", name, "skipped — exists in target", "skipped")
            continue
        if dry_run:
            app_ids[src_id] = ""
            report.add(f"app ({app_type})", name, "would create", "would create")
            continue
        body = {k: v for k, v in app.items() if k not in _APP_READ_ONLY and v is not None}
        resp = post(f"applications/type/{app_type}", body)
        if resp.status_code in (200, 201):
            app_ids[src_id] = _response_id(resp)
            report.add(f"app ({app_type})", name, "created", "created")
        else:
            report.add(f"app ({app_type})", name, f"failed — {_error_text(resp)}", "failed")

    def target_app_id(src_id: str) -> str | None:
        """Mapped id for a custom app, the same id for a catalog app, None if it failed."""
        if src_id in app_ids:
            return app_ids[src_id] or None
        return None if src_id in custom_ids else src_id

    # ── 2. Plugins ────────────────────────────────────────────────────────────
    for plugin in backup.get("plugins", []):
        src_app = str(plugin.get("applicationId"))
        label = f"plugin for app {src_app}"
        dst_app = target_app_id(src_app)
        if dry_run and src_app in app_ids and not app_ids[src_app]:
            report.add("plugin", label, "would create (after its application)", "would create")
            continue
        if not dst_app:
            report.add("plugin", label, "skipped — its application was not restored", "skipped")
            continue
        if dst_app in target_plugins:
            report.add(
                "plugin", label, "skipped — target application already has a plugin", "skipped"
            )
            continue
        if dry_run:
            report.add("plugin", label, "would create", "would create")
            continue
        resp = post(f"applications/{dst_app}/plugins", {"plugin": plugin.get("plugin") or {}})
        if resp.status_code in (200, 201):
            report.add("plugin", label, "created", "created")
        else:
            report.add("plugin", label, f"failed — {_error_text(resp)}", "failed")

    # ── 3. Application groups ─────────────────────────────────────────────────
    for group in backup.get("application_groups", []):
        name = str(group.get("name"))
        if name in app_group_names:
            report.add("application group", name, "skipped — exists in target", "skipped")
            continue
        members = [
            str(a.get("id") if isinstance(a, dict) else a) for a in group.get("applications") or []
        ]
        mapped = [target_app_id(m) for m in members]
        dropped = sum(1 for m in mapped if m is None and not dry_run)
        if dry_run:
            report.add(
                "application group", name, f"would create ({len(members)} apps)", "would create"
            )
            continue
        body = {"name": name, "applications": [m for m in mapped if m]}
        resp = post("application-groups", body)
        suffix = f", {dropped} member app(s) not restored" if dropped else ""
        if resp.status_code in (200, 201):
            report.add(
                "application group",
                name,
                f"created ({len(body['applications'])} apps{suffix})",
                "created",
            )
        else:
            report.add("application group", name, f"failed — {_error_text(resp)}", "failed")

    # ── 4. Device groups ──────────────────────────────────────────────────────
    for group in backup.get("device_groups", []):
        name = str(group.get("name"))
        if name in device_group_names:
            report.add("device group", name, "skipped — exists in target", "skipped")
            continue
        if dry_run:
            report.add("device group", name, "would create", "would create")
            continue
        body = {k: group[k] for k in _DEVICE_GROUP_FIELDS if group.get(k) is not None}
        resp = post("device-groups", body)
        if resp.status_code in (200, 201):
            report.add("device group", name, "created", "created")
        else:
            report.add("device group", name, f"failed — {_error_text(resp)}", "failed")

    # ── 5. User groups ────────────────────────────────────────────────────────
    pending_user_groups = [
        g for g in backup.get("user_groups", []) if str(g.get("name")) not in user_group_names
    ]
    users_by_email: dict[str, str] = {}
    if pending_user_groups:
        users, err = _list(session, "users")
        if err:
            notes.append(f"Could not list target users, so user groups are created empty: {err}")
        for user in users:
            email = str(user.get("email") or "").strip().lower()
            if email:
                users_by_email[email] = str(user.get("id"))
    for group in backup.get("user_groups", []):
        name = str(group.get("name"))
        if name in user_group_names:
            report.add("user group", name, "skipped — exists in target", "skipped")
            continue
        emails = [str(e).strip().lower() for e in group.get("member_emails") or []]
        user_ids = [users_by_email[e] for e in emails if e in users_by_email]
        detail = f"{len(user_ids)}/{len(emails)} members enrolled in target"
        if dry_run:
            report.add("user group", name, f"would create ({detail})", "would create")
            continue
        resp = post("user-groups", {"name": name, "userIds": user_ids})
        if resp.status_code in (200, 201):
            report.add("user group", name, f"created ({detail})", "created")
        else:
            report.add("user group", name, f"failed — {_error_text(resp)}", "failed")

    # ── Publish ───────────────────────────────────────────────────────────────
    if not dry_run and publish:
        if report.counts["created"]:
            resp = post("configuration-management/draft/publish", {})
            if resp.status_code in (200, 201, 202, 204):
                notes.append("Draft published.")
            else:
                notes.append(f"Draft publish failed — {_error_text(resp)}")
        else:
            notes.append("Nothing was created, so the draft was not published.")
    elif not dry_run and report.counts["created"]:
        notes.append(
            "Changes are in the Prisma Browser draft — publish them in the SCM UI or "
            "re-run with publish=True (already-created objects are skipped)."
        )
    return report, notes


def register_pab_transfer_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register scm_pab_backup and scm_pab_restore."""
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_pab_backup(client: Any, tenant_id: str, output_dir: str = "") -> str:
        """Back up a tenant's Prisma Access Browser configuration to a local JSON file.

        Read-only. Saves every object the Browser Management API can re-create:
        custom applications (custom, private, non-web, local desktop) and their
        plugins, application groups, device groups, and user groups (members as
        emails). Browser policy rules, data controls, security settings and
        customisation have no API and are NOT included — copy those in the UI.

        The file (which can contain user emails) is written locally and not
        returned inline. Pass its path to scm_pab_restore.

        Args:
            tenant_id: Source tenant ID.
            output_dir: Directory for the backup file (default: ./backups or
                $SCM_MCP_BACKUP_DIR).
        """
        backup = build_backup(_bearer_session_for(client), tenant_id)
        directory = Path(output_dir) if output_dir else _default_backup_dir()
        directory.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        path = directory / f"pab_backup_{tenant_id or 'default'}_{stamp}.json"
        path.write_text(json.dumps(backup, indent=2, default=str))
        logger.info("pab_backup_written", path=str(path), tenant_id=tenant_id)

        member_count = sum(len(g["member_emails"]) for g in backup["user_groups"])
        lines = [
            f"## Prisma Browser Backup — tenant `{tenant_id or 'default'}`",
            "",
            f"**File:** `{path}`",
            "",
            "| Object | Count |",
            "|---|---|",
            f"| Custom applications | {len(backup['applications'])} |",
            f"| Application plugins | {len(backup['plugins'])} |",
            f"| Application groups | {len(backup['application_groups'])} |",
            f"| Device groups | {len(backup['device_groups'])} |",
            f"| User groups | {len(backup['user_groups'])} ({member_count} memberships) |",
            "",
            "_Not included (no API): browser policy rules, data controls, security "
            "settings, customisation._",
        ]
        if backup["errors"]:
            lines += ["", "**Could not read:**"]
            lines += [f"- {err}" for err in backup["errors"].values()]
        return "\n".join(lines)

    @mcp.tool()
    @tool
    def scm_pab_restore(
        client: Any,
        tenant_id: str,
        backup_file: str,
        publish: bool = False,
        dry_run: bool = True,
        ticket_ref: str = "",
    ) -> str:
        """Restore a scm_pab_backup file onto a tenant's Prisma Access Browser config.

        Creates, in dependency order: custom applications, their plugins,
        application groups, device groups, user groups. Never overwrites — an
        object whose name already exists in the target is skipped (so
        predefined groups such as "Microsoft 365" are left alone). Custom
        application IDs are mapped by name and user-group members by email;
        members not enrolled in the target are left out and counted.

        Changes land in the Prisma Browser draft. ``publish=True`` publishes
        it after a successful restore; otherwise publish in the SCM UI.

        Args:
            tenant_id: Target tenant ID.
            backup_file: Path to a file written by scm_pab_backup.
            publish: Publish the draft after creating objects (default False).
            dry_run: If True (default), report what would be created without writing.
            ticket_ref: Mandatory change-ticket reference (never sent to the API).

        **Write safety (SSR pattern):** ``dry_run=True`` by default;
        ``ticket_ref`` is mandatory.
        """
        err = ticket_ref_error(ticket_ref)
        if err:
            return f"Error: {err}"
        ticket_ref = normalize_ticket_ref(ticket_ref)
        try:
            backup = json.loads(Path(backup_file).read_text())
        except FileNotFoundError:
            return f"Error: backup file not found — {backup_file}"
        except (OSError, json.JSONDecodeError) as exc:
            return f"Error: could not read backup file — {exc}"
        if not isinstance(backup, dict) or backup.get("backup_version") != BACKUP_VERSION:
            return f"Error: not a scm_pab_backup file (expected backup_version '{BACKUP_VERSION}')"
        if str(backup.get("source_tenant")) == str(tenant_id):
            logger.info("pab_restore_same_tenant", tenant_id=tenant_id)

        if not dry_run:
            audit_write(
                "scm_pab_restore",
                ticket_ref,
                tenant_id,
                backup_file=backup_file,
                source_tenant=backup.get("source_tenant"),
                publish=publish,
            )
        report, notes = restore_backup(
            _bearer_session_for(client), backup, dry_run=dry_run, publish=publish
        )
        logger.info(
            "pab_restore",
            tenant_id=tenant_id,
            dry_run=dry_run,
            ticket_ref=ticket_ref,
            **{k.replace(" ", "_"): v for k, v in report.counts.items()},
        )

        lines = [
            f"## Prisma Browser Restore{' — DRY-RUN' if dry_run else ''}",
            "",
            f"**Source:** `{backup.get('source_tenant')}` ({backup.get('timestamp')}) → "
            f"**Target:** `{tenant_id or 'default'}`  |  **Ticket ref:** {ticket_ref}",
            "",
            "  |  ".join(f"**{k.capitalize()}:** {v}" for k, v in report.counts.items() if v)
            or "The backup contains no restorable objects.",
        ]
        if report.rows:
            lines += ["", "| Object | Name | Result |", "|---|---|---|"]
            lines += [
                f"| {kind} | `{name.replace('|', '/')}` | {status.replace('|', '/')} |"
                for kind, name, status in report.rows
            ]
        if notes:
            lines += [""] + [f"- {n}" for n in notes]
        lines += [
            "",
            "_Not restorable (no API): browser policy rules, data controls, security "
            "settings, customisation — copy those in the SCM UI._",
        ]
        if dry_run:
            lines += ["", DRY_RUN_HINT]
        return "\n".join(lines)
