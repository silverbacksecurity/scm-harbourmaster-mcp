"""Copy SSL decryption rules and Mobile Users GlobalProtect settings between tenants.

Both tools read from a source tenant and write to a target tenant's candidate
configuration. Neither commits: each report ends with the scm_commit call to
run. Both are dry runs by default and need a ``ticket_ref``.

Behaviour verified live while copying one tenant's configuration to another:

Decryption rules (``/sse/config/v1/decryption-rules``)
  * Snippet attachments appear in the rule list as placeholder "rules" with no
    ``action`` (``optional-default``, ``office365``, ...). They are not copied.
  * An enabled ``decrypt`` rule fails the Prisma Access push with
    "forward decrypt trust cert is not configured" unless the target's SSL
    decryption settings select a forward-trust certificate. Those settings are
    often unreadable to service accounts (HTTP 403), so the tool warns and can
    create rules disabled.
  * A new rule is appended to the bottom of the rulebase position.

Mobile Users GlobalProtect (``/config/mobile-agent/v1``)
  * Infrastructure settings are created with a short ``name``; SCM appends the
    portal domain itself (sending the FQDN doubles the suffix).
  * PUT on infrastructure settings looks the object up by name, and deleting it
    resets the manual-gateway regions in global settings, so existing
    infrastructure is never replaced here.
  * Agent profiles read back ``os: ["any"]``, which the PUT validator rejects;
    it is dropped. ``gp_app_config`` accepts only ``connect-method`` and
    ``tunnel-mtu``; every other app setting is reported for the UI.
  * Authentication settings are returned without an ``id`` and cannot be
    updated through the API; only missing ones are created.
  * Cloud Identity Engine authentication profiles are bound to one CIE tenant
    and are not copied.
"""

from __future__ import annotations

import copy
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..audit.extractor import _bearer_session_for
from ..auth.oauth import resolve_tenant_id
from ..utils.errors import handle_scm_exception
from ..utils.logging import get_logger
from ..utils.write_safety import (
    DRY_RUN_HINT,
    audit_write,
    normalize_ticket_ref,
    ticket_ref_error,
)
from .ops import _SCM_BASE

logger = get_logger(__name__)

_MA_BASE = "https://api.sase.paloaltonetworks.com/config/mobile-agent/v1"
_MU = {"folder": "Mobile Users"}
_TIMEOUT = (5, 60)

# Read-only fields returned on decryption rules.
_RULE_READ_ONLY = frozenset({"id", "folder", "snippet", "device", "position"})
# gp_app_config entries the agent-profile API accepts.
_API_APP_CONFIG = frozenset({"connect-method", "tunnel-mtu"})
# Folders an authentication profile can be inherited from by Mobile Users.
_AUTH_PROFILE_FOLDERS = ("All", "Shared", "Mobile Users")


# ── Shared helpers ────────────────────────────────────────────────────────────


def _json(resp: Any) -> Any:
    try:
        return resp.json()
    except Exception:
        return {}


def _rows(body: Any) -> list[dict[str, Any]]:
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        data = body.get("data")
        if isinstance(data, list):
            return data
    return []


def _error_text(resp: Any) -> str:
    body = _json(resp)
    if isinstance(body, dict):
        errors = body.get("_errors") or []
        if errors and isinstance(errors[0], dict):
            first = errors[0]
            details = first.get("details")
            if isinstance(details, dict) and details.get("message"):
                return f"HTTP {resp.status_code}: {details['message']}"
            if isinstance(details, list) and details:
                return f"HTTP {resp.status_code}: {'; '.join(str(d) for d in details)[:200]}"
            return (
                f"HTTP {resp.status_code}: {str(first.get('code') or first.get('message'))[:200]}"
            )
        if body.get("message"):
            return f"HTTP {resp.status_code}: {str(body['message'])[:200]}"
    return f"HTTP {resp.status_code}"


def _canonical(value: Any) -> Any:
    """Order-insensitive form for comparing settings (lists of locations, regions)."""
    if isinstance(value, dict):
        return {k: _canonical(v) for k, v in value.items()}
    if isinstance(value, list):
        return sorted((_canonical(v) for v in value), key=repr)
    return value


def _same(current: Any, desired: Any) -> bool:
    return isinstance(current, dict) and _canonical(current) == _canonical(desired)


def _ok(resp: Any) -> bool:
    return resp.status_code in (200, 201, 204)


class _Plan:
    """Ordered report rows plus counts, shared by both tools."""

    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str]] = []
        self.counts = {"applied": 0, "would apply": 0, "skipped": 0, "failed": 0}
        self.notes: list[str] = []

    def add(self, kind: str, name: str, status: str, bucket: str) -> None:
        self.rows.append((kind, name, status))
        self.counts[bucket] += 1

    def render(self, title: str, header: list[str]) -> list[str]:
        lines = [
            f"## {title}",
            "",
            *header,
            "",
            "  |  ".join(f"**{k.capitalize()}:** {v}" for k, v in self.counts.items() if v)
            or "Nothing to do.",
        ]
        if self.rows:
            lines += ["", "| Object | Name | Result |", "|---|---|---|"]
            lines += [
                f"| {kind} | `{name.replace('|', '/')}` | {status.replace('|', '/')} |"
                for kind, name, status in self.rows
            ]
        if self.notes:
            lines += [""] + [f"- {n}" for n in self.notes]
        return lines


def _resolve_pair(tenant_id: str, target_tenant_id: str) -> tuple[str, str] | str:
    if not target_tenant_id:
        return "Error: target_tenant_id is required"
    target = resolve_tenant_id(str(target_tenant_id))
    if str(target) == str(tenant_id):
        return "Error: source and target tenant are the same"
    return str(tenant_id), str(target)


# ── Decryption rules ──────────────────────────────────────────────────────────


def _list_rules(session: Any, folder: str, position: str) -> tuple[list[dict[str, Any]], str]:
    resp = session.get(
        f"{_SCM_BASE}/decryption-rules",
        params={"folder": folder, "position": position, "limit": 500},
        timeout=_TIMEOUT,
    )
    if resp.status_code != 200:
        return [], f"decryption-rules ({folder}/{position}): {_error_text(resp)}"
    # The list includes inherited rules; keep the folder's own.
    return [r for r in _rows(_json(resp)) if r.get("folder") == folder], ""


def _decryption_profile_names(session: Any) -> set[str] | None:
    names: set[str] = set()
    for folder in _AUTH_PROFILE_FOLDERS:
        resp = session.get(
            f"{_SCM_BASE}/decryption-profiles",
            params={"folder": folder, "limit": 500},
            timeout=_TIMEOUT,
        )
        if resp.status_code != 200:
            return None
        names.update(str(p.get("name")) for p in _rows(_json(resp)))
    return names


def _forward_trust_state(session: Any) -> str:
    """The target's forward-trust certificate state: configured, missing or unknown."""
    for folder in ("All", "Shared"):
        resp = session.get(
            f"{_SCM_BASE}/ssl-decryption-settings", params={"folder": folder}, timeout=_TIMEOUT
        )
        if resp.status_code != 200:
            return "unknown"
        for row in _rows(_json(resp)) or [_json(resp)]:
            trust = row.get("forward_trust_certificate") if isinstance(row, dict) else None
            if isinstance(trust, dict) and (trust.get("rsa") or trust.get("ecdsa")):
                return "configured"
    return "missing"


def copy_decryption_rules(
    source: Any,
    target: Any,
    *,
    names: list[str] | None,
    folder: str,
    position: str,
    create_disabled: bool,
    dry_run: bool,
) -> _Plan:
    plan = _Plan()
    src, dst = _bearer_session_for(source), _bearer_session_for(target)

    src_rules, err = _list_rules(src, folder, position)
    if err:
        plan.notes.append(f"Could not read source rules — {err}")
        return plan
    real = [r for r in src_rules if r.get("action")]
    if names:
        by_name = {str(r.get("name")): r for r in src_rules}
        missing = [n for n in names if n not in by_name]
        if missing:
            plan.notes.append(f"Not in source {folder}/{position}: {', '.join(missing)}")
            return plan
        placeholders = [n for n in names if not by_name[n].get("action")]
        if placeholders:
            plan.notes.append(
                f"Snippet placeholders, not rules (attach the snippet instead): {', '.join(placeholders)}"
            )
        selected = [by_name[n] for n in names if by_name[n].get("action")]
    else:
        selected = real
    selected.sort(key=lambda r: src_rules.index(r))  # source rulebase order

    dst_rules, err = _list_rules(dst, folder, position)
    if err:
        plan.notes.append(f"Aborted — could not read target rules: {err}")
        return plan
    existing = {str(r.get("name")) for r in dst_rules}
    profiles = _decryption_profile_names(dst)
    trust = _forward_trust_state(dst)

    enabled_decrypt = 0
    for rule in selected:
        name = str(rule.get("name"))
        if name in existing:
            plan.add("decryption rule", name, "skipped — exists in target", "skipped")
            continue
        profile = rule.get("profile")
        if profile and profiles is not None and profile not in profiles:
            plan.add(
                "decryption rule",
                name,
                f"skipped — decryption profile `{profile}` missing in target",
                "skipped",
            )
            continue
        body = {k: v for k, v in rule.items() if k not in _RULE_READ_ONLY}
        body["folder"] = folder
        if create_disabled:
            body["disabled"] = True
        state = "disabled" if body.get("disabled") else "enabled"
        if body.get("action") == "decrypt" and state == "enabled":
            enabled_decrypt += 1
        if dry_run:
            plan.add("decryption rule", name, f"would create ({state})", "would apply")
            continue
        resp = dst.post(
            f"{_SCM_BASE}/decryption-rules",
            params={"position": position},
            json=body,
            timeout=_TIMEOUT,
        )
        if _ok(resp):
            existing.add(name)
            plan.add("decryption rule", name, f"created ({state})", "applied")
        else:
            plan.add("decryption rule", name, f"failed — {_error_text(resp)}", "failed")

    if profiles is None:
        plan.notes.append("Target decryption profiles unreadable — profile references not checked.")
    if enabled_decrypt:
        if trust == "missing":
            plan.notes.append(
                f"⚠️ {enabled_decrypt} enabled decrypt rule(s) but the target has no forward-trust "
                "certificate selected — the push will fail with 'forward decrypt trust cert is not "
                "configured'. Select one in SSL decryption settings or use create_disabled=True."
            )
        elif trust == "unknown":
            plan.notes.append(
                f"⚠️ {enabled_decrypt} enabled decrypt rule(s): the target's SSL decryption settings "
                "are unreadable, so the forward-trust certificate was not checked. If none is "
                "selected the push fails — consider create_disabled=True."
            )
    if selected:
        plan.notes.append("New rules are appended to the bottom of the target rulebase position.")
    return plan


# ── Mobile Users GlobalProtect ────────────────────────────────────────────────


def _ma_get(session: Any, path: str) -> tuple[Any, str]:
    resp = session.get(f"{_MA_BASE}/{path}", params=_MU, timeout=_TIMEOUT)
    if resp.status_code != 200:
        return None, f"{path}: {_error_text(resp)}"
    return _json(resp), ""


def _auth_profiles(session: Any) -> dict[str, dict[str, Any]] | None:
    found: dict[str, dict[str, Any]] = {}
    for folder in _AUTH_PROFILE_FOLDERS:
        resp = session.get(
            f"{_SCM_BASE}/authentication-profiles",
            params={"folder": folder, "limit": 500},
            timeout=_TIMEOUT,
        )
        if resp.status_code != 200:
            return None
        for profile in _rows(_json(resp)):
            found.setdefault(str(profile.get("name")), profile)
    return found


def agent_profile_body(profile: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """(API-safe PUT/POST body, app settings the API refuses → set in the UI)."""
    body = copy.deepcopy({k: v for k, v in profile.items() if k != "id"})
    if body.get("os") in (["any"], "any"):
        body.pop("os")
    ui_only: dict[str, Any] = {}
    app = body.get("gp_app_config")
    if isinstance(app, dict) and isinstance(app.get("config"), list):
        kept = []
        for entry in app["config"]:
            if entry.get("name") in _API_APP_CONFIG:
                kept.append(entry)
            else:
                ui_only[str(entry.get("name"))] = entry.get("value")
        app["config"] = kept
    return body, ui_only


def copy_globalprotect(
    source: Any,
    target: Any,
    *,
    portal_hostname: str,
    ip_pool: str,
    locations: list[str] | None,
    copy_agent_version: bool,
    dry_run: bool,
) -> _Plan:
    plan = _Plan()
    src, dst = _bearer_session_for(source), _bearer_session_for(target)

    read: dict[str, Any] = {}
    for side, session in (("source", src), ("target", dst)):
        for path in (
            "infrastructure-settings",
            "global-settings",
            "agent-profiles",
            "authentication-settings",
        ):
            body, err = _ma_get(session, path)
            if err:
                plan.notes.append(f"Aborted — could not read {side} {err}")
                return plan
            read[f"{side}:{path}"] = body
    src_locations, err = _ma_get(src, "locations")
    if err:
        plan.notes.append(f"Aborted — could not read source {err}")
        return plan

    # Region layout, with an optional single-region location override.
    regions = copy.deepcopy((src_locations or {}).get("region") or [])
    if locations:
        if len(regions) != 1:
            plan.notes.append(
                f"Aborted — `locations` override needs a single-region source (source has {len(regions)})."
            )
            return plan
        regions[0]["locations"] = list(locations)

    # 1. Infrastructure — created only when the target has none.
    src_infra = _rows(read["source:infrastructure-settings"])
    dst_infra = _rows(read["target:infrastructure-settings"])
    if not src_infra:
        plan.add(
            "infrastructure", "—", "skipped — source has no GlobalProtect infrastructure", "skipped"
        )
    elif dst_infra:
        plan.add(
            "infrastructure",
            str(dst_infra[0].get("name")),
            "skipped — target already has infrastructure (replacing it resets global "
            "settings; change it in the UI)",
            "skipped",
        )
    elif not portal_hostname:
        plan.notes.append(
            "Aborted — the target has no infrastructure, so `portal_hostname` is required."
        )
        return plan
    else:
        infra = {k: v for k, v in copy.deepcopy(src_infra[0]).items() if k not in ("id", "folder")}
        infra["name"] = portal_hostname  # SCM appends the portal domain
        infra["portal_hostname"] = {"default_domain": {"hostname": portal_hostname}}
        if ip_pool:
            infra["ip_pools"] = [{"name": "worldwide", "ip_pool": [ip_pool]}]
        if regions:
            infra["deployment"] = {"region": copy.deepcopy(regions)}
        pools = ", ".join(p for pool in infra.get("ip_pools", []) for p in pool.get("ip_pool", []))
        detail = f"portal `{portal_hostname}`, pool {pools or '—'}"
        if dry_run:
            plan.add("infrastructure", portal_hostname, f"would create ({detail})", "would apply")
        else:
            resp = dst.post(
                f"{_MA_BASE}/infrastructure-settings", params=_MU, json=infra, timeout=_TIMEOUT
            )
            if not _ok(resp):
                plan.add(
                    "infrastructure", portal_hostname, f"failed — {_error_text(resp)}", "failed"
                )
                plan.notes.append("Stopped — later settings depend on the infrastructure.")
                return plan
            plan.add("infrastructure", portal_hostname, f"created ({detail})", "applied")

    # 2. Locations and 3. global settings (manual gateways follow the locations).
    loc_text = "; ".join(f"{r.get('name')}: {', '.join(r.get('locations') or [])}" for r in regions)
    global_body = {
        "agent_version": (
            read["source:global-settings"] if copy_agent_version else read["target:global-settings"]
        ).get("agent_version"),
        "manual_gateway": {"region": copy.deepcopy(regions)} if regions else {},
    }
    # Locations can 500 on a tenant with nothing onboarded — treat as "differs".
    dst_locations, _ = _ma_get(dst, "locations")
    current = {"locations": dst_locations, "global-settings": read["target:global-settings"]}
    for kind, path, body, detail in (
        ("locations", "locations", {"region": regions}, loc_text or "none"),
        (
            "global settings",
            "global-settings",
            global_body,
            f"agent {global_body['agent_version']}",
        ),
    ):
        if not regions and kind == "locations":
            plan.add(kind, "Mobile Users", "skipped — source has no locations", "skipped")
            continue
        if _same(current[path], body):
            plan.add(kind, "Mobile Users", f"skipped — already matches ({detail})", "skipped")
            continue
        if dry_run:
            plan.add(kind, "Mobile Users", f"would set ({detail})", "would apply")
            continue
        resp = dst.put(f"{_MA_BASE}/{path}", params=_MU, json=body, timeout=_TIMEOUT)
        if _ok(resp):
            plan.add(kind, "Mobile Users", f"set ({detail})", "applied")
        else:
            plan.add(kind, "Mobile Users", f"failed — {_error_text(resp)}", "failed")

    # 4. Agent profiles.
    dst_profiles = {str(p.get("name")) for p in _rows(read["target:agent-profiles"])}
    for profile in _rows(read["source:agent-profiles"]):
        name = str(profile.get("name"))
        body, ui_only = agent_profile_body(profile)
        verb = "update" if name in dst_profiles else "create"
        if ui_only:
            plan.notes.append(
                f"Agent profile `{name}` — set in the UI (not accepted by the API): "
                + ", ".join(
                    f"{k}={'/'.join(map(str, v)) if isinstance(v, list) else v}"
                    for k, v in ui_only.items()
                )
            )
        if dry_run:
            plan.add("agent profile", name, f"would {verb}", "would apply")
            continue
        method = dst.put if verb == "update" else dst.post
        resp = method(f"{_MA_BASE}/agent-profiles", params=_MU, json=body, timeout=_TIMEOUT)
        if _ok(resp):
            plan.add("agent profile", name, f"{verb}d", "applied")
        else:
            plan.add("agent profile", name, f"failed — {_error_text(resp)}", "failed")

    # 5. Authentication settings — create missing ones only.
    dst_auth = {str(a.get("name")): a for a in _rows(read["target:authentication-settings"])}
    profiles = _auth_profiles(dst)
    for setting in _rows(read["source:authentication-settings"]):
        name = str(setting.get("name"))
        if name in dst_auth:
            differs = {
                k: v
                for k, v in setting.items()
                if k not in ("folder",) and dst_auth[name].get(k) != v
            }
            if differs:
                plan.add(
                    "auth setting",
                    name,
                    "exists — differs; the API cannot update it (use the UI)",
                    "skipped",
                )
                plan.notes.append(f"Auth setting `{name}` — set in the UI: {differs}")
            else:
                plan.add("auth setting", name, "skipped — identical in target", "skipped")
            continue
        profile_name = str(setting.get("authentication_profile"))
        if profiles is None:
            plan.add("auth setting", name, "skipped — target auth profiles unreadable", "skipped")
            continue
        if profile_name not in profiles:
            plan.add(
                "auth setting",
                name,
                f"skipped — authentication profile `{profile_name}` missing in target "
                "(Cloud Identity Engine profiles are tenant-bound and not copied)",
                "skipped",
            )
            continue
        body = {k: v for k, v in setting.items() if k != "folder"}
        if dry_run:
            plan.add("auth setting", name, "would create", "would apply")
            continue
        resp = dst.post(
            f"{_MA_BASE}/authentication-settings", params=_MU, json=body, timeout=_TIMEOUT
        )
        if _ok(resp):
            plan.add("auth setting", name, "created", "applied")
        else:
            plan.add("auth setting", name, f"failed — {_error_text(resp)}", "failed")
    return plan


# ── Registration ──────────────────────────────────────────────────────────────


def register_tenant_copy_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register scm_decryption_rule_copy and scm_gp_copy."""

    # Not @scm_tool: both tools need clients for two tenants (as scm_cert_copy).
    @mcp.tool()
    def scm_decryption_rule_copy(
        tenant_id: str,
        target_tenant_id: str,
        names: list[str] | None = None,
        folder: str = "Shared",
        position: str = "pre",
        create_disabled: bool = False,
        dry_run: bool = True,
        ticket_ref: str = "",
    ) -> str:
        """Copy SSL decryption rules from one tenant to another.

        Copies the named rules — or every real rule in the folder/position,
        skipping snippet placeholders — in source rulebase order, appended to
        the bottom of the target position. Never overwrites: same-name rules
        are skipped, as are rules whose decryption profile is missing in the
        target. Warns when enabled ``decrypt`` rules would reach a target
        without a forward-trust certificate (the push would fail);
        ``create_disabled=True`` creates every copied rule disabled. Never
        commits — run scm_commit afterwards.

        Args:
            tenant_id: Source tenant ID.
            target_tenant_id: Destination tenant ID.
            names: Rule names to copy (default: all real rules).
            folder: Folder of the rules in both tenants (default: Shared).
            position: Rulebase position, ``pre`` or ``post`` (default: pre).
            create_disabled: Create every copied rule disabled.
            dry_run: If True (default), report without writing.
            ticket_ref: Mandatory change-ticket reference (never sent to SCM).

        **Write safety (SSR pattern):** ``dry_run=True`` by default;
        ``ticket_ref`` is mandatory.
        """
        err = ticket_ref_error(ticket_ref)
        if err:
            return f"Error: {err}"
        ticket_ref = normalize_ticket_ref(ticket_ref)
        if position not in ("pre", "post"):
            return "Error: position must be 'pre' or 'post'"
        try:
            pair = _resolve_pair(tenant_id, target_tenant_id)
            if isinstance(pair, str):
                return pair
            source_id, target_id = pair
            if not dry_run:
                audit_write(
                    "scm_decryption_rule_copy",
                    ticket_ref,
                    target_id,
                    source_tenant_id=source_id,
                    folder=folder,
                    position=position,
                    names=names or "all",
                )
            plan = copy_decryption_rules(
                get_client(source_id),
                get_client(target_id),
                names=names,
                folder=folder,
                position=position,
                create_disabled=create_disabled,
                dry_run=dry_run,
            )
        except Exception as exc:
            return f"Error: {handle_scm_exception(exc, tool='scm_decryption_rule_copy', tenant_id=tenant_id)}"
        lines = plan.render(
            f"Decryption Rule Copy{' — DRY-RUN' if dry_run else ''}",
            [
                f"**Source:** `{source_id}` → **Target:** `{target_id}`  |  "
                f"**Folder:** {folder}/{position}  |  **Ticket ref:** {ticket_ref}"
            ],
        )
        lines.append("")
        if dry_run:
            lines.append(DRY_RUN_HINT)
        elif plan.counts["applied"]:
            lines.append(
                f"Nothing is committed yet — run `scm_commit(folders=['{folder}'], "
                f"tenant_id='{target_id}', ticket_ref=..., dry_run=False)`."
            )
        return "\n".join(lines)

    @mcp.tool()
    def scm_gp_copy(
        tenant_id: str,
        target_tenant_id: str,
        portal_hostname: str = "",
        ip_pool: str = "",
        locations: list[str] | None = None,
        copy_agent_version: bool = False,
        dry_run: bool = True,
        ticket_ref: str = "",
    ) -> str:
        """Copy Mobile Users GlobalProtect configuration from one tenant to another.

        Applies, in order: infrastructure settings (only if the target has
        none — then ``portal_hostname`` is required, since portal names are
        globally unique), locations, global settings (manual-gateway regions;
        the target keeps its agent version unless ``copy_agent_version``),
        agent profiles (created or updated), and missing authentication
        settings. Handles the mobile-agent API's limits: app settings other
        than connect-method and tunnel-mtu, existing authentication settings,
        and Cloud Identity Engine profiles cannot be written — they are listed
        for the UI. Onboarding infrastructure deploys Prisma Access Mobile
        Users locations. Never commits — run scm_commit on ``Mobile Users``
        with ``admin="all"`` afterwards.

        Args:
            tenant_id: Source tenant ID.
            target_tenant_id: Destination tenant ID.
            portal_hostname: Portal hostname for new target infrastructure
                (short form, e.g. "acme-lab"; SCM appends the domain).
            ip_pool: Mobile Users IP pool for new infrastructure (default: source's).
            locations: Location override for a single-region source, e.g.
                ["eu-west-1", "eu-west-2"] (default: source's).
            copy_agent_version: Also copy the source's GlobalProtect agent version.
            dry_run: If True (default), report without writing.
            ticket_ref: Mandatory change-ticket reference (never sent to SCM).

        **Write safety (SSR pattern):** ``dry_run=True`` by default;
        ``ticket_ref`` is mandatory.
        """
        err = ticket_ref_error(ticket_ref)
        if err:
            return f"Error: {err}"
        ticket_ref = normalize_ticket_ref(ticket_ref)
        try:
            pair = _resolve_pair(tenant_id, target_tenant_id)
            if isinstance(pair, str):
                return pair
            source_id, target_id = pair
            if not dry_run:
                audit_write(
                    "scm_gp_copy",
                    ticket_ref,
                    target_id,
                    source_tenant_id=source_id,
                    portal_hostname=portal_hostname,
                    ip_pool=ip_pool,
                    locations=locations,
                )
            plan = copy_globalprotect(
                get_client(source_id),
                get_client(target_id),
                portal_hostname=portal_hostname.strip(),
                ip_pool=ip_pool.strip(),
                locations=locations,
                copy_agent_version=copy_agent_version,
                dry_run=dry_run,
            )
        except Exception as exc:
            return f"Error: {handle_scm_exception(exc, tool='scm_gp_copy', tenant_id=tenant_id)}"
        lines = plan.render(
            f"GlobalProtect Copy{' — DRY-RUN' if dry_run else ''}",
            [
                f"**Source:** `{source_id}` → **Target:** `{target_id}`  |  "
                f"**Folder:** Mobile Users  |  **Ticket ref:** {ticket_ref}"
            ],
        )
        lines.append("")
        if dry_run:
            lines.append(DRY_RUN_HINT)
        elif plan.counts["applied"]:
            lines.append(
                "Nothing is committed yet — run `scm_commit(folders=['Mobile Users'], "
                f"tenant_id='{target_id}', admin='all', ticket_ref=..., dry_run=False)`."
            )
        return "\n".join(lines)
