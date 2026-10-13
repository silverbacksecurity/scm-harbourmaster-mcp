"""
MCP tools for SCM Deployment resources.

Covers: remote networks, service connections, bandwidth allocations,
        auto-scaling, commit/push operations, and config version management.
"""

from __future__ import annotations

import json
import re
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..utils.errors import handle_scm_exception
from ..utils.formatting import format_result as _fmt
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool
from ..utils.write_safety import (
    DRY_RUN_HINT,
    audit_write,
    normalize_ticket_ref,
    ticket_ref_error,
)

logger = get_logger(__name__)

_CV_BASE = "/config/operations/v1/config-versions"
# R3 device-settings spec: list, :load and DELETE /{name}.  There is no create
# endpoint; snapshots are saved in the SCM UI.
_SNAPSHOT_BASE = "/config/device/v1/named-snapshots"
_SNAPSHOT_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _cv_get(client: Any, path: str) -> dict[str, Any]:
    """GET a config-version endpoint; returns parsed JSON dict or {} on any error."""
    try:
        result = client.get(path)
        if isinstance(result, dict):
            return result
    except Exception:
        pass
    return {}


def _running_versions(client: Any, folders: list[str]) -> dict[str, Any]:
    """Running config version per pushed scope, for dry-run previews and rollback."""
    versions: dict[str, Any] = {}
    running_raw = _cv_get(client, f"{_CV_BASE}/running")
    for entry in running_raw.get("data") or []:
        device = entry.get("device") if isinstance(entry, dict) else None
        if device in folders:
            versions[device] = entry.get("version")
    return versions


def _named_snapshots(client: Any) -> list[dict[str, Any]]:
    """Named snapshots ({name, timestamp, savedby}); [] when unavailable."""
    rows = _cv_get(client, _SNAPSHOT_BASE).get("data")
    return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []


def _snapshot_lines(snapshots: list[dict[str, Any]]) -> list[str]:
    """Markdown section listing named snapshots for scm_config_versions."""
    if not snapshots:
        return ["", "Named snapshots: none saved."]
    lines = [
        "",
        f"### Named snapshots ({len(snapshots)})",
        "",
        "| Name | Saved | By |",
        "|---|---|---|",
    ]
    for snap in snapshots:
        ts = snap.get("timestamp")
        lines.append(
            f"| {snap.get('name', '?')} | {_age(ts)} ({ts or '—'}) | {snap.get('savedby') or '—'} |"
        )
    lines += [
        "",
        "Use `scm_config_rollback(snapshot=NAME, ticket_ref=...)` to preview loading a "
        "named snapshot into the candidate config.",
    ]
    return lines


def _age(ts: str | None) -> str:
    """Human-readable age from ISO timestamp."""
    if not ts:
        return "—"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        delta = datetime.now(UTC) - dt
        days = delta.days
        hours = delta.seconds // 3600
        if days > 0:
            return f"{days}d {hours}h ago"
        mins = delta.seconds // 60
        return f"{hours}h {mins % 60}m ago" if hours > 0 else f"{mins}m ago"
    except Exception:
        return ts


def register_deployment_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register all SCM Deployment tools onto the MCP server."""
    tool = scm_tool(get_client)
    tool = scm_tool(get_client)
    tool = scm_tool(get_client)

    # ── Remote Networks ─────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_remote_network_list(client: Any, folder: str, limit: int = 200) -> str:
        """List remote networks (branch/SD-WAN connections) in SCM.

        Args:
            folder: SCM folder (unused — remote networks always live in the
                    fixed "Remote Networks" container; kept for interface
                    consistency with the other _list tools).
            tenant_id: SCM tenant ID.
            limit: Maximum results.
        """
        results = client.remote_network.list(folder="Remote Networks")[: max(0, limit)]
        return _fmt(results)

    @mcp.tool()
    @tool
    def scm_remote_network_get(client: Any, name: str, folder: str) -> str:
        """Fetch details for a single remote network.

        Args:
            name: Remote network name.
            folder: SCM folder (unused — see scm_remote_network_list).
            tenant_id: SCM tenant ID.
        """
        obj = client.remote_network.fetch(name=name, folder="Remote Networks")
        return _fmt(obj)

    # ── Service Connections ─────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_service_connection_list(client: Any, folder: str, limit: int = 200) -> str:
        """List service connections (cloud/DC interconnects) in SCM.

        Args:
            folder: SCM folder.
            tenant_id: SCM tenant ID.
            limit: Maximum results.
        """
        results = client.service_connection.list()[: max(0, limit)]
        return _fmt(results)

    # ── Bandwidth Allocations ───────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_bandwidth_allocation_list(client: Any, folder: str, limit: int = 200) -> str:
        """List bandwidth allocations for Prisma Access compute locations.

        Args:
            folder: SCM folder.
            tenant_id: SCM tenant ID.
            limit: Maximum results.
        """
        results = client.bandwidth_allocation.list()[: max(0, limit)]
        return _fmt(results)

    # ── Commit ──────────────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_commit(
        client: Any,
        tenant_id: str,
        folders: list[str],
        description: str = "",
        admin: str = "",
        dry_run: bool = True,
        ticket_ref: str = "",
    ) -> str:
        """Commit pending SCM configuration changes.

        Commits the candidate config for the listed folders.  This is
        the equivalent of 'commit' on a firewall — required after any
        create/update/delete operation to make changes effective.

        **Write safety (SSR pattern):** ``dry_run=True`` by default reports what
        would be committed (folders, description, current running versions)
        without committing; ``ticket_ref`` is mandatory. For a blast-radius
        analysis of the pending changes run ``scm_commit_preview`` first.

        Args:
            folders: Folders whose changes to commit.
            description: Commit description (sent to SCM as-is).
            tenant_id: SCM tenant ID.
            admin: Whose pending changes to push. Empty (default) pushes only
                this service account's own changes — SCM makes it a partial
                commit, so edits made by another admin (e.g. in the UI) are
                left behind. A comma-separated list of admin/service-account
                logins pushes those admins' changes. ``all`` pushes every
                pending change in the folders, whoever made it.
            dry_run: If True (default), preview the commit without running it.
            ticket_ref: Mandatory change-ticket reference (logged and echoed,
                never added to the commit description).
        """
        err = ticket_ref_error(ticket_ref)
        if err:
            return f"Error: {err}"
        ticket_ref = normalize_ticket_ref(ticket_ref)
        if not folders:
            return "Error: folders is required — list the folders whose changes to commit."
        desc = description or "Committed via scm-harbourmaster-mcp"
        admins = [a.strip() for a in (admin or "").split(",") if a.strip()]
        push_all = any(a.lower() == "all" for a in admins)
        if push_all and len(admins) > 1:
            return "Error: admin='all' cannot be combined with named admins."
        scope = (
            "all admins"
            if push_all
            else ", ".join(admins)
            if admins
            else "this service account's own changes only"
        )

        if dry_run:
            return _fmt(
                {
                    "action": "commit",
                    "dry_run": True,
                    "ticket_ref": ticket_ref,
                    "folders": folders,
                    "description": desc,
                    "admin_scope": scope,
                    "running_versions": _running_versions(client, folders),
                    "note": "A commit pushes every pending change in these folders made by "
                    "the admins in admin_scope — not just this session's changes. Run "
                    "scm_commit_preview(folder=...) for a blast-radius analysis.",
                    "hint": DRY_RUN_HINT,
                }
            )

        audit_write(
            "scm_commit", ticket_ref, tenant_id, folders=folders, description=desc, admin=scope
        )
        if push_all:
            # The SDK always sends an admin list (defaulting to the service
            # account); the push API only covers every admin when the field is
            # omitted, so this path calls the endpoint directly.
            result = client.post(
                "/config/operations/v1/config-versions/candidate:push",
                json={"folders": folders, "description": desc},
            )
            job_id = result.get("job_id") if isinstance(result, dict) else None
            if job_id:
                client.wait_for_job(job_id, timeout=300)
        else:
            result = client.commit(
                folders=folders,
                description=desc,
                admin=admins or None,
                sync=True,
                timeout=300,
            )
        logger.info(
            "commit_triggered",
            folders=folders,
            admin=scope,
            job_id=getattr(result, "job_id", None),
            ticket_ref=ticket_ref,
        )
        return _fmt(result)

    @mcp.tool()
    @tool
    def scm_job_status(client: Any, job_id: str) -> str:
        """Check the status of an asynchronous SCM job (e.g. commit).

        Args:
            job_id: Job ID returned by commit or other async operations.
            tenant_id: SCM tenant ID.
        """
        result = client.get_job_status(job_id)
        return _fmt(result)

    @mcp.tool()
    @tool
    def scm_list_jobs(client: Any, limit: int = 50, offset: int = 0, job_type: str = "") -> str:
        """List SCM configuration jobs (commits, pushes) showing who triggered each one.

        Returns recent jobs ordered newest-first, including the SCM username (uname)
        who triggered each job, the job type, result, timestamps, and description.
        Use this to audit commit history, find who last changed config, or investigate
        failed pushes.

        Job types include: Commit, CommitAndPush, NGFW_Push, PA_Push.
        Result values: OK, FAIL, PENDING, RUNNING.

        Args:
            tenant_id: SCM tenant ID. Defaults to the configured default tenant.
            limit: Maximum jobs to return (default 50, max 200).
            offset: Pagination offset.
            job_type: Optional filter — e.g. "Commit" or "NGFW_Push".
        """
        response = client.list_jobs(limit=min(limit, 200), offset=offset)

        jobs = response.data if hasattr(response, "data") else []

        # Optional client-side type filter (SDK doesn't support server-side type filter)
        if job_type:
            jobs = [
                j for j in jobs if job_type.lower() in (getattr(j, "type_str", "") or "").lower()
            ]

        if not jobs:
            return json.dumps({"total": 0, "jobs": [], "note": "No jobs found."})

        rows = []
        for j in jobs:
            rows.append(
                {
                    "job_id": getattr(j, "id", ""),
                    "type": getattr(j, "type_str", getattr(j, "job_type", "")),
                    "result": getattr(j, "result_str", ""),
                    "user": getattr(j, "uname", ""),
                    "description": getattr(j, "description", ""),
                    "start_ts": str(getattr(j, "start_ts", "")),
                    "end_ts": str(getattr(j, "end_ts", "")),
                    "percent": getattr(j, "percent", ""),
                    "parent_id": getattr(j, "parent_id", None),
                }
            )

        total = getattr(response, "total", len(rows))
        return json.dumps(
            {
                "total": total,
                "showing": len(rows),
                "offset": offset,
                "jobs": rows,
            },
            indent=2,
            default=str,
        )

    # ── Config Version Management ────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_config_versions(client: Any, tenant_id: str) -> str:
        """List SCM configuration versions with timestamps, descriptions, and running state.

        Shows the full version history of committed configs for this tenant.
        The running version is the currently active config on Prisma Access.
        Also lists the named snapshots saved in SCM (name, time, who saved it).
        Use version numbers or snapshot names with scm_config_rollback to
        revert to a prior state.

        Args:
            tenant_id: SCM tenant ID. Defaults to the configured default tenant.
        """
        raw = _cv_get(client, _CV_BASE)
        versions: list[dict[str, Any]] = raw.get("data", []) if raw else []

        # Fetch running version per scope (Mobile Users, Remote Networks, ...) to annotate
        running_by_scope: dict[str, Any] = {}
        try:
            running_raw = _cv_get(client, f"{_CV_BASE}/running")
            for entry in running_raw.get("data") or []:
                device = entry.get("device")
                if device:
                    running_by_scope[device] = entry.get("version")
        except Exception:
            pass

        snapshot_lines = _snapshot_lines(_named_snapshots(client))

        if not versions:
            running_summary = (
                ", ".join(f"{k}={v}" for k, v in running_by_scope.items()) or "unknown"
            )
            return "\n".join(
                [
                    "No config versions found. Config versions are saved after each commit.",
                    "",
                    f"Running versions: {running_summary}",
                    *snapshot_lines,
                ]
            )

        _DESC_W = 40
        entries: list[tuple[str, str, str, str, str]] = []
        for v in versions:
            # `id` is the config version number — the one /running reports and the
            # one scm_config_rollback loads. The `version` field is the PAN-OS
            # content release ("192-external"), identical across long runs of
            # commits, so it must not be shown here.
            ver = str(v.get("id") or v.get("version") or "?")
            ts = _age(v.get("created_at") or v.get("timestamp") or v.get("date"))
            admin = str(v.get("created_by") or v.get("admin") or v.get("uname") or "—")
            desc = str(v.get("description") or "—")[:_DESC_W]
            # `scope` is a comma-separated list ("Mobile Users,Remote Networks,...")
            # and the NGFW scope arrives separately as a serial in `ngfw_scope`,
            # so a plain dict lookup on the raw string never matched.
            scopes = [s.strip() for s in str(v.get("scope") or "").split(",") if s.strip()]
            if v.get("ngfw_scope"):
                scopes.append(str(v["ngfw_scope"]))
            flag = " ◀ running" if any(str(running_by_scope.get(s)) == ver for s in scopes) else ""
            entries.append((ver, ts, admin, desc, flag))

        # Size the first three columns to their content rather than to fixed
        # widths. Admin in particular was clipped to 10 chars, which rendered
        # every account on a shared domain as the same label.
        col_w = (
            max(len("Version"), *(len(e[0]) for e in entries)),
            max(len("Committed"), *(len(e[1]) for e in entries)),
            max(len("Admin"), *(len(e[2]) for e in entries)),
            _DESC_W,
        )
        header = (
            f"{'Version':<{col_w[0]}}  {'Committed':<{col_w[1]}}  "
            f"{'Admin':<{col_w[2]}}  {'Description':<{col_w[3]}}"
        )
        sep = "  ".join("─" * w for w in col_w)

        rows = [header, sep]
        for ver, ts, admin, desc, flag in entries:
            rows.append(
                f"{ver:<{col_w[0]}}  {ts:<{col_w[1]}}  {admin:<{col_w[2]}}  {desc:<{col_w[3]}}{flag}"
            )

        lines = [
            f"## Config Versions — {tenant_id or 'default tenant'}",
            "",
            f"Total versions: {raw.get('total', len(versions))}  "
            f"|  Running: {', '.join(f'{k}={v}' for k, v in running_by_scope.items()) or 'unknown'}",
            "",
            "```",
            *rows,
            "```",
            "",
            "Use `scm_config_rollback(version=N, ticket_ref=...)` to preview loading a version back to candidate.",
            *snapshot_lines,
        ]
        return "\n".join(lines)

    @mcp.tool()
    @tool
    def scm_config_push_track(
        client: Any,
        tenant_id: str,
        folders: list[str],
        description: str = "",
        timeout: int = 300,
        rollback_on_failure: bool = False,
        dry_run: bool = True,
        ticket_ref: str = "",
    ) -> str:
        """Push candidate config with async job tracking and optional auto-rollback.

        Unlike scm_commit (which blocks silently), this tool polls the job every
        10 seconds and streams progress, then returns a rich result including
        warnings, affected devices, push duration, and rollback status if used.

        When rollback_on_failure=True, if the push job fails the tool automatically
        loads the last known-good running version back to candidate — so the next
        commit restores the previous state.

        Args:
            folders: Folders whose changes to push (e.g. ["Prisma Access"]).
            description: Commit description or change-ticket reference.
            timeout: Max seconds to wait for the push job (default 300).
            rollback_on_failure: If True, auto-load the previous running version on failure.
            dry_run: If True (default), report what would be pushed without pushing.
            ticket_ref: Mandatory change-ticket reference (logged and echoed,
                never added to the commit description).
            tenant_id: SCM tenant ID. Defaults to the configured default tenant.

        **Write safety (SSR pattern):** ``dry_run=True`` by default;
        ``ticket_ref`` is mandatory.
        """
        err = ticket_ref_error(ticket_ref)
        if err:
            return f"Error: {err}"
        ticket_ref = normalize_ticket_ref(ticket_ref)
        if not folders:
            return "Error: folders is required — list the folders whose changes to push."

        try:
            desc = description or "Push via scm-harbourmaster-mcp"

            if dry_run:
                return _fmt(
                    {
                        "action": "push",
                        "dry_run": True,
                        "ticket_ref": ticket_ref,
                        "folders": folders,
                        "description": desc,
                        "timeout": timeout,
                        "rollback_on_failure": rollback_on_failure,
                        "running_versions": _running_versions(client, folders),
                        "note": "A push commits EVERYTHING pending in these folders. Run "
                        "scm_commit_preview(folder=...) for a blast-radius analysis first.",
                        "hint": DRY_RUN_HINT,
                    }
                )

            # Snapshot running version per pushed folder (for rollback capability).
            # The /running endpoint reports one running version per scope
            # (e.g. "Remote Networks", "Mobile Users"), not a single global version.
            rollback_versions: dict[str, Any] = {}
            if rollback_on_failure:
                with suppress(Exception):
                    rollback_versions = _running_versions(client, folders)

            audit_write(
                "scm_config_push_track", ticket_ref, tenant_id, folders=folders, description=desc
            )
            logger.info("config_push_start", folders=folders, tenant_id=tenant_id, desc=desc)

            # Start push async
            push_result = client.commit(
                folders=folders,
                description=desc,
                sync=False,
            )
            job_id = getattr(push_result, "job_id", None) or str(push_result)
            logger.info("config_push_job_started", job_id=job_id, tenant_id=tenant_id)

            # Poll until complete
            final = client.wait_for_job(job_id, timeout=timeout, poll_interval=10)

            if not final or not final.data:
                return f"Push job {job_id} started but status could not be retrieved within {timeout}s."

            job = final.data[0]
            result_str = job.result_str  # "OK" | "FAIL"
            status_str = job.status_str  # "FIN" | etc.
            percent = job.percent
            details = job.details or ""
            summary = job.summary or ""
            duration_s = ""
            if job.start_ts and job.end_ts:
                secs = int((job.end_ts - job.start_ts).total_seconds())
                duration_s = f"{secs}s" if secs < 60 else f"{secs // 60}m {secs % 60}s"

            success = result_str == "OK"
            icon = "✅" if success else "❌"
            logger.info(
                "config_push_complete",
                job_id=job_id,
                result=result_str,
                percent=percent,
                duration=duration_s,
                tenant_id=tenant_id,
            )

            rollback_note = ""
            if not success and rollback_on_failure:
                if rollback_versions:
                    loaded: list[str] = []
                    failed: list[str] = []
                    for scope, ver in rollback_versions.items():
                        try:
                            client.post(f"{_CV_BASE}/{ver}:load")
                            loaded.append(f"{scope} → v{ver}")
                        except Exception as rb_exc:
                            failed.append(f"{scope}: {rb_exc}")
                    if loaded:
                        rollback_note = (
                            f"\n\n**Auto-rollback triggered**: {', '.join(loaded)} "
                            "loaded to candidate. Run `scm_commit` to restore the previous config."
                        )
                    if failed:
                        rollback_note += f"\n\n**Auto-rollback FAILED** for: {'; '.join(failed)}"
                    logger.warning(
                        "config_push_rollback",
                        job_id=job_id,
                        rollback_versions=rollback_versions,
                        tenant_id=tenant_id,
                    )
                else:
                    rollback_note = "\n\n**Auto-rollback skipped**: could not determine running version before push."

            lines = [
                f"## {icon} Config Push — {result_str}",
                "",
                "| Field | Value |",
                "|---|---|",
                f"| Job ID | `{job_id}` |",
                f"| Status | {status_str} ({percent}%) |",
                f"| Result | **{result_str}** |",
                f"| Duration | {duration_s or '—'} |",
                f"| Folders | {', '.join(folders)} |",
                f"| Description | {desc} |",
            ]
            if summary:
                lines += ["", f"**Summary:** {summary}"]
            if details and details != "{}":
                # Try to pretty-print JSON details
                try:
                    det = json.loads(details) if isinstance(details, str) else details
                    lines += ["", "**Details:**", "```json", json.dumps(det, indent=2), "```"]
                except Exception:
                    lines += ["", f"**Details:** {details}"]
            if rollback_note:
                lines.append(rollback_note)

            return "\n".join(lines)

        except TimeoutError:
            return (
                f"Push job timed out after {timeout}s. "
                "Use `scm_job_status` with the job ID to check completion, "
                "or `scm_list_jobs` to find the job."
            )
        except Exception as exc:
            return f"Error: {handle_scm_exception(exc, tool='scm_config_push_track', tenant_id=tenant_id)}"

    @mcp.tool()
    @tool
    def scm_config_rollback(
        client: Any,
        tenant_id: str,
        version: int = 0,
        commit_immediately: bool = False,
        description: str = "",
        dry_run: bool = True,
        ticket_ref: str = "",
        snapshot: str = "",
        push_folders: list[str] | None = None,
        push_devices: list[str] | None = None,
    ) -> str:
        """Restore an earlier SCM config: a config version or a named snapshot.

        Three ways to restore, picked by the arguments:
          * ``version=N`` — load version N into the candidate config, then
            commit it (``commit_immediately=True``) or leave the commit to
            ``scm_commit``.
          * ``snapshot=NAME`` — load a named snapshot (saved in the SCM UI)
            into the candidate config, then commit as above.
          * ``version=N`` with ``push_folders`` and/or ``push_devices`` — push
            version N straight to those folders/firewalls without touching the
            candidate config (``config-versions:push``).  The push runs as a
            job; check it and its child push jobs with ``scm_list_jobs``.

        Run `scm_config_versions` first: it lists the versions and the named
        snapshots.

        Args:
            version: The config version number to restore.
            snapshot: Name of a named snapshot to load instead of a version.
            push_folders: With ``version``, folders to push the version to.
            push_devices: With ``version``, firewall serial numbers to push the
                version to.
            commit_immediately: If True, commit the loaded version or snapshot
                immediately after loading (not used with a push).
            description: Commit description when commit_immediately=True.
            dry_run: If True (default), show what would be loaded or pushed
                without changing anything.
            ticket_ref: Mandatory change-ticket reference (logged and echoed,
                never added to the commit description or request body).
            tenant_id: SCM tenant ID. Defaults to the configured default tenant.

        **Write safety (SSR pattern):** ``dry_run=True`` by default;
        ``ticket_ref`` is mandatory.
        """
        err = ticket_ref_error(ticket_ref)
        if err:
            return f"Error: {err}"
        ticket_ref = normalize_ticket_ref(ticket_ref)
        snapshot = (snapshot or "").strip()
        folders = [f for f in (push_folders or []) if f]
        devices = [d for d in (push_devices or []) if d]
        if bool(snapshot) == bool(version):
            return "Error: pass exactly one of version or snapshot."
        if snapshot and not _SNAPSHOT_NAME_RE.match(snapshot):
            return (
                "Error: snapshot names are 1-64 letters, digits, '-' or '_' "
                "(see scm_config_versions)."
            )
        if (folders or devices) and snapshot:
            return (
                "Error: push_folders/push_devices push a config version; "
                "a named snapshot can only be loaded."
            )
        if (folders or devices) and commit_immediately:
            return "Error: a version push needs no commit — drop commit_immediately."

        if snapshot:
            return _restore_snapshot(
                client, tenant_id, snapshot, commit_immediately, description, dry_run, ticket_ref
            )

        ver_info: dict[str, Any] = {}
        with suppress(Exception):
            raw_ver = client.get(f"{_CV_BASE}/{version}")
            if isinstance(raw_ver, list) and raw_ver:
                ver_info = raw_ver[0]
            elif isinstance(raw_ver, dict):
                ver_info = raw_ver

        ver_date = (
            ver_info.get("created_at")
            or ver_info.get("timestamp")
            or ver_info.get("date")
            or "unknown date"
        )
        ver_desc = ver_info.get("description") or "—"
        ver_admin = ver_info.get("created_by") or ver_info.get("admin") or "—"
        version_rows = [
            f"| Version | {version} |",
            f"| Originally committed | {_age(str(ver_date))} ({ver_date}) |",
            f"| Original description | {ver_desc} |",
            f"| Original admin | {ver_admin} |",
        ]

        if folders or devices:
            return _push_version(
                client,
                tenant_id,
                version,
                (folders, devices),
                ver_info,
                version_rows,
                dry_run,
                ticket_ref,
            )

        if dry_run:
            found = "yes" if ver_info else "no — version details could not be read"
            return "\n".join(
                [
                    f"## Config Rollback — DRY-RUN — Version {version}",
                    "",
                    "| Field | Value |",
                    "|---|---|",
                    version_rows[0],
                    f"| Version details found | {found} |",
                    *version_rows[1:],
                    f"| Ticket ref | {ticket_ref} |",
                    "",
                    "Would:",
                    f"1. Load version {version} into the candidate config "
                    "(replacing any pending candidate changes)",
                    _commit_step(commit_immediately),
                    "",
                    DRY_RUN_HINT,
                ]
            )

        audit_write(
            "scm_config_rollback",
            ticket_ref,
            tenant_id,
            version=version,
            commit_immediately=commit_immediately,
        )

        # Load the version to candidate
        logger.info(
            "config_rollback_start",
            version=version,
            tenant_id=tenant_id,
            commit_immediately=commit_immediately,
        )
        client.post(f"{_CV_BASE}/{version}:load")
        logger.info("config_rollback_loaded", version=version, tenant_id=tenant_id)

        lines = [
            f"## Config Rollback — Version {version} Loaded to Candidate",
            "",
            "| Field | Value |",
            "|---|---|",
            *version_rows,
        ]
        desc = description or f"Rollback to version {version} via scm-harbourmaster-mcp"
        return "\n".join(
            lines + _after_load(client, tenant_id, commit_immediately, desc, version=version)
        )


def _commit_step(commit_immediately: bool) -> str:
    """Dry-run line describing what happens after a load."""
    return (
        "2. Commit all folders immediately (commit_immediately=True)"
        if commit_immediately
        else "2. Stop — nothing is committed; run `scm_commit` separately"
    )


def _after_load(
    client: Any, tenant_id: str, commit_immediately: bool, desc: str, **log: Any
) -> list[str]:
    """Commit the freshly loaded candidate, or describe the next steps."""
    if not commit_immediately:
        return [
            "",
            "✅ Loaded to candidate. **No changes have been pushed yet.**",
            "",
            "Next steps:",
            "1. Review the candidate config in the SCM UI if desired",
            "2. Run `scm_commit(folders=[...], ticket_ref=..., dry_run=False)` to push the rollback",
            "   or `scm_config_push_track(folders=[...], ticket_ref=..., dry_run=False)` for a tracked push",
        ]
    commit_result = client.commit(folders=["all"], description=desc, sync=True, timeout=300)
    job_id = getattr(commit_result, "job_id", "—")
    logger.info("config_rollback_committed", job_id=job_id, tenant_id=tenant_id, **log)
    return ["", f"✅ **Committed immediately** — Job ID: `{job_id}`", f"Description: _{desc}_"]


def _restore_snapshot(
    client: Any,
    tenant_id: str,
    snapshot: str,
    commit_immediately: bool,
    description: str,
    dry_run: bool,
    ticket_ref: str,
) -> str:
    """scm_config_rollback(snapshot=...): load a named snapshot into candidate."""
    match = next((s for s in _named_snapshots(client) if s.get("name") == snapshot), None)
    ts = (match or {}).get("timestamp")
    rows = [
        "| Field | Value |",
        "|---|---|",
        f"| Named snapshot | {snapshot} |",
        f"| Saved | {_age(ts)} ({ts or '—'}) |",
        f"| Saved by | {(match or {}).get('savedby') or '—'} |",
    ]
    if dry_run:
        found = "yes" if match else "no — not in the tenant's named snapshots"
        return "\n".join(
            [
                f"## Config Rollback — DRY-RUN — Named Snapshot {snapshot}",
                "",
                *rows[:3],
                f"| Snapshot found | {found} |",
                *rows[3:],
                f"| Ticket ref | {ticket_ref} |",
                "",
                "Would:",
                f"1. Load named snapshot {snapshot} into the candidate config "
                "(replacing any pending candidate changes)",
                _commit_step(commit_immediately),
                "",
                DRY_RUN_HINT,
            ]
        )
    if match is None:
        return (
            f"Error: named snapshot {snapshot!r} not found — "
            "run scm_config_versions to list the saved snapshots."
        )

    audit_write(
        "scm_config_rollback",
        ticket_ref,
        tenant_id,
        snapshot=snapshot,
        commit_immediately=commit_immediately,
    )
    raw = client.post(f"{_SNAPSHOT_BASE}:load", json={"name": snapshot})
    result: dict[str, Any] = raw if isinstance(raw, dict) else {}
    status = str(result.get("status") or "")
    logger.info("config_snapshot_loaded", snapshot=snapshot, status=status, tenant_id=tenant_id)
    lines = [f"## Config Rollback — Named Snapshot {snapshot} Loaded to Candidate", "", *rows]
    if result.get("message"):
        lines.append(f"| API message | {result['message']} |")
    if status and status != "success":
        return "\n".join(
            [*lines, "", f"⚠️ Load returned status `{status}` — nothing was committed."]
        )
    desc = description or f"Rollback to named snapshot {snapshot} via scm-harbourmaster-mcp"
    return "\n".join(
        lines + _after_load(client, tenant_id, commit_immediately, desc, snapshot=snapshot)
    )


def _push_version(
    client: Any,
    tenant_id: str,
    version: int,
    targets: tuple[list[str], list[str]],
    ver_info: dict[str, Any],
    version_rows: list[str],
    dry_run: bool,
    ticket_ref: str,
) -> str:
    """scm_config_rollback(version, push_folders/push_devices): config-versions:push."""
    folders, devices = targets
    target_rows = [
        f"| Push to folders | {', '.join(folders) or '—'} |",
        f"| Push to devices | {', '.join(devices) or '—'} |",
    ]
    if dry_run:
        found = "yes" if ver_info else "no — version details could not be read"
        running = _running_versions(client, folders) if folders else {}
        running_now = ", ".join(f"{k}={v}" for k, v in running.items()) or "unknown"
        return "\n".join(
            [
                f"## Config Push — DRY-RUN — Version {version}",
                "",
                "| Field | Value |",
                "|---|---|",
                version_rows[0],
                f"| Version details found | {found} |",
                *version_rows[1:],
                *target_rows,
                f"| Running now | {running_now} |",
                f"| Ticket ref | {ticket_ref} |",
                "",
                f"Would push version {version} straight to the targets above. The "
                "candidate config is not changed.",
                "",
                DRY_RUN_HINT,
            ]
        )

    body: dict[str, Any] = {"version": version}
    if folders:
        body["containers"] = folders
    if devices:
        body["devices"] = devices
    audit_write(
        "scm_config_rollback",
        ticket_ref,
        tenant_id,
        version=version,
        push_folders=folders,
        push_devices=devices,
    )
    raw = client.post(f"{_CV_BASE}:push", json=body)
    result: dict[str, Any] = raw if isinstance(raw, dict) else {}
    job_id = result.get("job_id") or "—"
    logger.info("config_version_pushed", version=version, job_id=job_id, tenant_id=tenant_id)
    lines = [
        f"## Config Push — Version {version}",
        "",
        "| Field | Value |",
        "|---|---|",
        *version_rows,
        *target_rows,
        f"| Job ID | `{job_id}` |",
    ]
    if result.get("message"):
        lines.append(f"| API message | {result['message']} |")
    lines += [
        "",
        "The push runs as a job. Check it with `scm_job_status(job_id=...)` and its "
        "child push jobs with `scm_list_jobs` — a child push can fail after the "
        "parent job reports OK.",
    ]
    return "\n".join(lines)
