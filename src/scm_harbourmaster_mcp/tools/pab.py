"""
Prisma Access Browser — tenant-level management/inventory tools.

Covers the pan.dev `prisma-browser` family (/seb-api/v1/*, "Prisma
Browser Management Console Public API"): enrolled users, device inventory
with endpoint posture (screen lock / disk encryption / firewall), user and
device groups, the application catalog, and pending user access requests.
Also lists the four browser policy rulebases (access & data, security,
customization, sign-in), draft changes awaiting publish, and the IdP
app-sync / cloud-storage integrations. Read-only — the write side
(suspend/resume/force-reauth, rule edits, config publish) is deliberately
not exposed.

Complements tools/pab_msp.py, which is the MSP cross-tenant reporting layer
(/mt/pab/*); this module is the per-tenant view.

Auth: common SASE bearer token. There is no `seb` entry in the subscription
licenses API even on tenants where this API serves data — provisioning is
detected from the API itself: unprovisioned tenants return empty lists from
/users and /devices but 404/500 ("tenant not found") from /applications.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..audit.extractor import _bearer_session_for
from ..audit.panos_import import PanosImportError, convert, load_xml
from ..utils.formatting import format_result as _fmt
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool

logger = get_logger(__name__)

_BASE = "https://api.sase.paloaltonetworks.com/seb-api/v1"
_MAX_PAGES = 10  # cursor-pagination cap: limit*pages records max per call


def _get_json(client: Any, path: str, params: dict[str, Any] | None = None) -> tuple[int, Any]:
    session = _bearer_session_for(client)
    resp = session.get(f"{_BASE}/{path}", params=params or {}, timeout=(5, 30))
    try:
        return resp.status_code, resp.json()
    except Exception:
        return resp.status_code, (resp.text or "")[:300]


def _paginate(
    client: Any,
    path: str,
    params: dict[str, Any],
    limit: int,
    meta: dict[str, Any] | None = None,
) -> tuple[list[dict], str]:
    """Follow cursor pagination until `limit` records or _MAX_PAGES; returns (items, error).

    Pass `meta` to collect the first page's `metadata` block (policy endpoints
    report the configuration version served there).
    """
    out: list[dict] = []
    cursor = ""
    for _ in range(_MAX_PAGES):
        page_params = {**params, "limit": min(limit - len(out), 200)}
        if cursor:
            page_params["cursor"] = cursor
        status, body = _get_json(client, path, page_params)
        if status != 200:
            return out, _status_hint(path, status, body)
        if not isinstance(body, dict):
            return out, f"{path}: unexpected response shape"
        if meta is not None and not meta:
            meta.update(body.get("metadata") or {})
        out.extend(body.get("data") or [])
        info = body.get("pageInfo") or {}
        cursor = info.get("cursor") or ""
        if len(out) >= limit or not info.get("hasNextPage"):
            break
    return out[:limit], ""


def _status_hint(path: str, status: int, body: Any) -> str:
    text = body if isinstance(body, str) else str(body)[:200]
    if status == 403 and "not yet available" in text:
        return (
            f"{path}: HTTP 403 — Palo Alto Networks has published this endpoint in the "
            'API spec but not enabled it yet ("This endpoint is not yet available").'
        )
    if status in (401, 403):
        return (
            f"{path}: HTTP {status} — the service account lacks Prisma Browser access "
            "(the API accepts only Super User or View-Only Administrator roles)."
        )
    if status == 404 or (status == 500 and "tenant not found" in text):
        return (
            f"{path}: HTTP {status} — Prisma Access Browser is not provisioned on this "
            "tenant (unprovisioned tenants 404/500 here while /users returns empty lists)."
        )
    if status == 500 and "INTERNAL_ERROR" in text:
        return (
            f"{path}: HTTP 500 INTERNAL_ERROR — Prisma Access Browser is most likely not "
            "provisioned on this tenant (unprovisioned tenants answer every /seb-api "
            "call this way)."
        )
    return f"{path}: HTTP {status} {text}"


_ENABLED_SUFFIX = "Enabled"

# Tool-facing rulebase names -> /policy/{path}
_POLICIES = {
    "access_and_data": "access-and-data",
    "security": "security",
    "customization": "customization",
    "sign_in": "sign-in",
}
_DETAIL_CAP = 100  # max per-rule detail fetches in one rulebase call


def _config_version(meta: dict[str, Any]) -> dict[str, Any] | None:
    cv = meta.get("configurationVersion")
    return cv if isinstance(cv, dict) else None


def _rulebase(
    client: Any,
    policy: str,
    params: dict[str, Any],
    limit: int,
    include_details: bool,
) -> dict[str, Any]:
    """One rulebase in evaluation order, rules grouped under their sections."""
    path = f"policy/{_POLICIES[policy]}"
    meta: dict[str, Any] = {}
    items, err = _paginate(client, path, params, limit, meta)
    items.sort(key=lambda i: i.get("position") or 0)
    sections: list[dict[str, Any]] = []
    unsectioned: list[dict[str, Any]] = []
    by_section: dict[str, dict[str, Any]] = {}
    rules: list[dict[str, Any]] = []
    for item in items:
        if item.get("type") == "Section":
            section: dict[str, Any] = {"id": item.get("id"), "name": item.get("name"), "rules": []}
            by_section[str(item.get("id"))] = section
            sections.append(section)
    for item in items:
        if item.get("type") != "Rule":
            continue
        rule: dict[str, Any] = {
            "id": item.get("id"),
            "name": item.get("name"),
            "mode": item.get("mode"),
            "evaluation_order": item.get("evaluationOrder"),
        }
        rules.append(rule)
        sec_ref = item.get("section") or {}
        parent = by_section.get(str(sec_ref.get("id"))) if sec_ref else None
        (parent["rules"] if parent else unsectioned).append(rule)
    warnings = [err] if err else []
    if include_details:
        version = params.get("configurationVersion")
        detail_params = {"configurationVersion": version} if version else {}
        for rule in rules[:_DETAIL_CAP]:
            status, body = _get_json(client, f"{path}/rules/{rule['id']}", detail_params)
            if status == 200 and isinstance(body, dict):
                rule["detail"] = {
                    k: v for k, v in body.items() if k not in ("id", "name", "mode", "metadata")
                }
            else:
                warnings.append(_status_hint(f"{path}/rules/{rule['id']}", status, body))
        if len(rules) > _DETAIL_CAP:
            warnings.append(
                f"{policy}: details fetched for the first {_DETAIL_CAP} of {len(rules)} rules"
            )
    by_mode: dict[str, int] = {}
    for r in rules:
        by_mode[r["mode"] or "?"] = by_mode.get(r["mode"] or "?", 0) + 1
    out: dict[str, Any] = {
        "policy": policy,
        "configuration_version": _config_version(meta),
        "rules_total": len(rules),
        "rules_by_mode": by_mode,
        "sections": sections,
    }
    if unsectioned:
        out["unsectioned_rules"] = unsectioned
    if warnings:
        out["warnings"] = warnings
    return out


def _posture_ok(value: str | None) -> bool:
    return bool(value) and str(value).endswith(_ENABLED_SUFFIX)


_URL_APP_TYPES = ("custom", "private")  # admin-defined apps that carry URL lists
_SCHEME_RE = re.compile(r"^[a-z*]+://")


def _norm_url(entry: str) -> str:
    """Reduce SCM ("*.example.com/path") and PAB ("*://*.example.com/*") forms to host[/path]."""
    s = _SCHEME_RE.sub("", entry.strip().lower())
    while s.endswith("/*") or s.endswith("/"):
        s = s[:-2] if s.endswith("/*") else s[:-1]
    return s


def _pair_key(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _url_drift(scm_urls: list[str], pab_urls: list[str]) -> dict[str, Any]:
    """Compare one custom URL category (SCM or PAN-OS) with one PAB app's URL list."""
    scm = {_norm_url(u) for u in scm_urls if u.strip()}
    pab = {_norm_url(u) for u in pab_urls if u.strip()}
    pab_wild = [p for p in pab if "*" in p]
    scm_wild = [s for s in scm if "*" in s]
    only_scm: list[str] = []
    covered_pab: list[str] = []
    for u in sorted(scm - pab):
        (covered_pab if any(fnmatch.fnmatchcase(u, w) for w in pab_wild) else only_scm).append(u)
    only_pab: list[str] = []
    covered_scm: list[str] = []
    for u in sorted(pab - scm):
        (covered_scm if any(fnmatch.fnmatchcase(u, w) for w in scm_wild) else only_pab).append(u)
    out: dict[str, Any] = {
        "in_sync": not only_scm and not only_pab,
        "matching": len(scm & pab),
        "only_in_category": only_scm,
        "only_in_pab": only_pab,
    }
    if covered_pab:
        out["category_only_but_covered_by_pab_wildcard"] = covered_pab
    if covered_scm:
        out["pab_only_but_covered_by_category_wildcard"] = covered_scm
    return out


def register_pab_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register tenant-level Prisma Access Browser tools."""
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_pab_inventory(
        client: Any,
        view: str = "summary",
        limit: int = 50,
        os_type: str = "",
        user_status: str = "",
    ) -> str:
        """Prisma Access Browser enrolled users, devices, and posture.

        Views:
        - summary: counts — users by status, devices by OS, and endpoint
          posture compliance (screen lock / disk encryption / firewall
          enabled) across the device fleet.
        - users: enrolled browser users (email, status, provider,
          first/last seen, groups).
        - devices: device inventory with per-device posture status,
          OS/model/serial, and last seen.
        - user_groups / device_groups: group definitions (device groups
          carry the posture-policy platform).

        Unprovisioned tenants report clearly (users/devices come back
        empty while config endpoints return "tenant not found").

        Args:
            tenant_id: SCM tenant ID (MSSP mode).
            view: summary | users | devices | user_groups | device_groups.
            limit: Max records per list view (default 50, cursor-paginated).
            os_type: devices view — filter by OS type (e.g. macOS, Windows).
            user_status: users view — filter by status (e.g. active).

        Returns:
            JSON with the requested view plus any endpoint warnings.
        """
        try:
            warnings: list[str] = []
            if view == "users":
                params = {"user.status": user_status} if user_status else {}
                users, err = _paginate(client, "users", params, limit)
                if err:
                    warnings.append(err)
                items = [
                    {
                        "email": u.get("email"),
                        "name": u.get("name"),
                        "status": u.get("status"),
                        "provider": u.get("provider"),
                        "first_seen": u.get("firstSeen"),
                        "last_seen": u.get("lastSeen"),
                        "user_groups": u.get("userGroups") or [],
                        "device_count": len(u.get("deviceIds") or []),
                    }
                    for u in users
                ]
                result: dict[str, Any] = {"view": view, "total": len(items), "users": items}
            elif view == "devices":
                params = {"device.os_type": os_type} if os_type else {}
                devices, err = _paginate(client, "devices", params, limit)
                if err:
                    warnings.append(err)
                items = [
                    {
                        "hostname": d.get("hostname"),
                        "status": d.get("status"),
                        "os": d.get("osDisplayName") or d.get("osType"),
                        "model": d.get("model"),
                        "serial": d.get("serialNumber"),
                        "arch": d.get("arch"),
                        "last_seen": d.get("lastSeen"),
                        "screen_lock": _posture_ok(d.get("screenLockStatus")),
                        "disk_encryption": _posture_ok(d.get("diskEncryptionStatus")),
                        "firewall": _posture_ok(d.get("firewallStatus")),
                    }
                    for d in devices
                ]
                result = {"view": view, "total": len(items), "devices": items}
            elif view in ("user_groups", "device_groups"):
                path = "user-groups" if view == "user_groups" else "device-groups"
                groups, err = _paginate(client, path, {}, limit)
                if err:
                    warnings.append(err)
                result = {"view": view, "total": len(groups), "groups": groups}
            elif view == "summary":
                users, u_err = _paginate(client, "users", {}, 500)
                devices, d_err = _paginate(client, "devices", {}, 500)
                warnings += [e for e in (u_err, d_err) if e]
                by_status: dict[str, int] = {}
                for u in users:
                    by_status[u.get("status") or "?"] = by_status.get(u.get("status") or "?", 0) + 1
                by_os: dict[str, int] = {}
                posture = {"screen_lock": 0, "disk_encryption": 0, "firewall": 0}
                for d in devices:
                    by_os[d.get("osType") or "?"] = by_os.get(d.get("osType") or "?", 0) + 1
                    posture["screen_lock"] += _posture_ok(d.get("screenLockStatus"))
                    posture["disk_encryption"] += _posture_ok(d.get("diskEncryptionStatus"))
                    posture["firewall"] += _posture_ok(d.get("firewallStatus"))
                result = {
                    "view": view,
                    "users_total": len(users),
                    "users_by_status": by_status,
                    "devices_total": len(devices),
                    "devices_by_os": by_os,
                    "device_posture_enabled": posture,
                }
                if not users and not devices and not warnings:
                    # Distinguish "provisioned but empty" from "not provisioned"
                    status, _body = _get_json(client, "applications", {"limit": 1})
                    if status != 200:
                        result["note"] = _status_hint("applications", status, _body)
            else:
                return (
                    "Error: view must be one of summary, users, devices, user_groups, device_groups"
                )
            if warnings:
                result["warnings"] = warnings
            return _fmt(result)
        except Exception as exc:
            return f"Error: {exc}"

    @mcp.tool()
    @tool
    def scm_pab_apps(
        client: Any, view: str = "apps", app_type: str = "", name: str = "", limit: int = 50
    ) -> str:
        """Prisma Access Browser application catalog and app groups.

        Views:
        - apps: configured applications (name, type, category, URLs) with
          optional type/name filters.
        - categories: the list of application categories.
        - app_groups: application group definitions.

        Args:
            tenant_id: SCM tenant ID (MSSP mode).
            view: apps | categories | app_groups.
            app_type: apps view — filter by application type.
            name: apps view — search by name.
            limit: Max records (default 50).

        Returns:
            JSON with the requested view.
        """
        try:
            if view == "apps":
                params: dict[str, Any] = {"limit": limit}
                if app_type:
                    params["type"] = app_type
                if name:
                    params["name"] = name
                status, body = _get_json(client, "applications", params)
                if status != 200:
                    hint = _status_hint("applications", status, body)
                    if "not provisioned" in hint:
                        return _fmt({"view": view, "total": 0, "applications": [], "note": hint})
                    return f"Error: {hint}"
                apps = (body.get("data") or []) if isinstance(body, dict) else []
                items = [
                    {
                        "name": a.get("name"),
                        "type": a.get("type"),
                        "category": a.get("category"),
                        "catalog_name": a.get("catalog_name"),
                        "urls": a.get("urls") or [],
                    }
                    for a in apps[:limit]
                ]
                return _fmt({"view": view, "total": len(items), "applications": items})
            if view == "categories":
                status, body = _get_json(client, "applications/categories", {})
                if status != 200:
                    hint = _status_hint("applications/categories", status, body)
                    if "not provisioned" in hint:
                        return _fmt({"view": view, "total": 0, "categories": [], "note": hint})
                    return f"Error: {hint}"
                cats = (body.get("data") or []) if isinstance(body, dict) else []
                return _fmt({"view": view, "total": len(cats), "categories": cats})
            if view == "app_groups":
                status, body = _get_json(client, "application-groups", {"limit": limit})
                if status != 200:
                    hint = _status_hint("application-groups", status, body)
                    if "not provisioned" in hint:
                        return _fmt(
                            {"view": view, "total": 0, "application_groups": [], "note": hint}
                        )
                    return f"Error: {hint}"
                groups = (body.get("data") or []) if isinstance(body, dict) else []
                return _fmt({"view": view, "total": len(groups), "application_groups": groups})
            return "Error: view must be one of apps, categories, app_groups"
        except Exception as exc:
            return f"Error: {exc}"

    @mcp.tool()
    @tool
    def scm_pab_user_requests(
        client: Any, status: str = "", request_type: str = "", limit: int = 50
    ) -> str:
        """Prisma Access Browser user access requests (helpdesk queue).

        Lists end-user requests raised from the browser (e.g. access to a
        blocked site or app) with their status — the queue an admin
        approves or denies in the PAB console.

        Args:
            tenant_id: SCM tenant ID (MSSP mode).
            status: Filter by request status.
            request_type: Filter by request type.
            limit: Max records (default 50).

        Returns:
            JSON array of user requests.
        """
        try:
            params: dict[str, Any] = {}
            if status:
                params["request.status"] = status
            if request_type:
                params["request.type"] = request_type
            requests_, err = _paginate(client, "user-requests", params, limit)
            result: dict[str, Any] = {"total": len(requests_), "user_requests": requests_}
            if err:
                result["warnings"] = [err]
            return _fmt(result)
        except Exception as exc:
            return f"Error: {exc}"

    @mcp.tool()
    @tool
    def scm_pab_policy(
        client: Any,
        view: str = "rulebase",
        policy: str = "all",
        configuration_version: str = "active",
        rule_id: str = "",
        name: str = "",
        mode: str = "",
        include_details: bool = False,
        limit: int = 500,
    ) -> str:
        """Prisma Access Browser policy rulebases, draft changes, and integrations.

        Views:
        - rulebase: rules in evaluation order, grouped under their sections,
          with mode (active / disabled / monitor) counts. The list API gives
          rule summaries only; set include_details to fetch each rule's
          scope, controls and actions (one call per rule, first 100).
        - rule: one rule's full definition (needs policy + rule_id).
        - pending_changes: draft edits not yet published (entity, operation,
          last updated by) — what a publish would push.
        - integrations: IdP application-sync and cloud-storage providers
          and their connection status.

        Args:
            tenant_id: SCM tenant ID (MSSP mode).
            view: rulebase | rule | pending_changes | integrations.
            policy: access_and_data | security | customization | sign_in,
                or all (rulebase view only).
            configuration_version: active (default, what is enforced), draft
                (includes unpublished edits), or a version number / ID.
            rule_id: rule view — the rule ID from the rulebase view.
            name: rulebase view — filter rules by name.
            mode: rulebase view — filter by mode (active, disabled, monitor;
                security and customization have no monitor mode).
            include_details: rulebase view — fetch each rule's full body.
            limit: Max items per rulebase (default 500, cursor-paginated).

        Returns:
            JSON with the requested view plus any endpoint warnings.
        """
        try:
            if view == "rulebase":
                if policy != "all" and policy not in _POLICIES:
                    return f"Error: policy must be all or one of {', '.join(_POLICIES)}"
                params: dict[str, Any] = {"configurationVersion": configuration_version}
                if name:
                    params["name"] = name
                if mode:
                    params["mode"] = [mode]
                names = list(_POLICIES) if policy == "all" else [policy]
                rulebases = [_rulebase(client, p, params, limit, include_details) for p in names]
                result: dict[str, Any] = {"view": view, "rulebases": rulebases}
                # Every rulebase failed (unprovisioned, no access, or not yet
                # enabled): one note instead of four identical warnings.
                if all(not rb["rules_total"] and rb.get("warnings") for rb in rulebases):
                    return _fmt(
                        {"view": view, "rulebases": [], "note": rulebases[0]["warnings"][0]}
                    )
                return _fmt(result)
            if view == "rule":
                if policy not in _POLICIES or not rule_id:
                    return (
                        "Error: rule view needs rule_id and policy set to one of "
                        f"{', '.join(_POLICIES)}"
                    )
                path = f"policy/{_POLICIES[policy]}/rules/{rule_id}"
                status, body = _get_json(
                    client, path, {"configurationVersion": configuration_version}
                )
                if status != 200:
                    return f"Error: {_status_hint(path, status, body)}"
                return _fmt({"view": view, "policy": policy, "rule": body})
            if view == "pending_changes":
                path = "configuration-management/draft/pending-changes"
                changes, err = _paginate(client, path, {}, limit)
                by_type: dict[str, int] = {}
                for c in changes:
                    key = c.get("entityType") or "?"
                    by_type[key] = by_type.get(key, 0) + 1
                result = {
                    "view": view,
                    "total": len(changes),
                    "by_entity_type": by_type,
                    "pending_changes": [
                        {
                            "entity_type": c.get("entityType"),
                            "name": c.get("name"),
                            "operation": c.get("operation"),
                            "last_updated_by": c.get("lastUpdatedBy"),
                            "entity_id": c.get("entityId"),
                        }
                        for c in changes
                    ],
                }
                if err:
                    result["warnings"] = [err]
                return _fmt(result)
            if view == "integrations":
                result = {"view": view}
                warnings: list[str] = []
                for key, path in (
                    ("idp_application_sync", "integrations/idp-application-sync"),
                    ("cloud_storage", "integrations/cloud-storage"),
                ):
                    status, body = _get_json(client, path)
                    if status == 200 and isinstance(body, dict):
                        result[key] = [
                            {
                                "display_name": p.get("displayName"),
                                "type": p.get("type"),
                                "status": p.get("status"),
                                "id": p.get("id"),
                            }
                            for p in body.get("providers") or []
                        ]
                    else:
                        result[key] = []
                        warnings.append(_status_hint(path, status, body))
                if warnings:
                    result["warnings"] = warnings
                return _fmt(result)
            return "Error: view must be one of rulebase, rule, pending_changes, integrations"
        except Exception as exc:
            return f"Error: {exc}"

    @mcp.tool()
    @tool
    def scm_pab_url_drift(
        client: Any,
        folder: str = "",
        panorama_xml: str = "",
        device_group: str = "",
        vsys: str = "",
        category: str = "",
        pab_app: str = "",
        limit: int = 500,
    ) -> str:
        """Drift check: custom URL categories vs Prisma Browser app URL lists.

        NGFW / Prisma Access policy uses custom URL categories; Prisma
        Browser's own rules use browser application objects that carry
        their own URL lists, and nothing keeps the two aligned. This
        compares them read-only.

        Category source (exactly one):
        - folder: SCM custom URL categories in that folder.
        - panorama_xml: a Panorama or firewall config export (offline, no
          Panorama access needed). Pass device_group for Panorama (its
          parent device groups and shared are included, nearest scope
          wins, as PAN-OS resolves them) or vsys for a firewall
          (default vsys1).

        Pairing: by default each "URL List" category is paired with the
        custom or private PAB app of the same name (case and punctuation
        ignored). Set category + pab_app to compare one explicit pair
        whose names differ.

        URLs are normalised before comparing (scheme, trailing "/" and
        "/*" dropped, lower-cased), so "*.example.com" matches
        "*://*.example.com/*" in PAB. An entry missing on one side but
        matched by a wildcard on the other is reported separately, not as
        drift. Matching is exact otherwise: PAN-OS prefix-match semantics
        for entries without a trailing "/" are not modelled.

        Args:
            tenant_id: SCM tenant ID (MSSP mode) — the Prisma Browser tenant.
            folder: SCM folder holding the custom URL categories (e.g.
                "Prisma Access", "All Firewalls", or a snippet's folder).
            panorama_xml: Path to a Panorama / firewall config export XML
                on the server, instead of folder.
            device_group: panorama_xml — Panorama device group.
            vsys: panorama_xml — firewall vsys (default vsys1).
            category: Custom URL category for an explicit pair.
            pab_app: PAB application name for an explicit pair.
            limit: Max PAB apps read per type (custom, private; default 500).

        Returns:
            JSON with per-pair drift (only_in_category / only_in_pab), plus
            the categories and custom PAB apps that have no counterpart.
        """
        try:
            if bool(folder) == bool(panorama_xml):
                return "Error: set exactly one of folder or panorama_xml"
            if bool(category) != bool(pab_app):
                return "Error: set both category and pab_app for an explicit pair, or neither"
            if panorama_xml:
                try:
                    conv = convert(
                        load_xml(panorama_xml),
                        device_group=device_group,
                        vsys=vsys,
                        include_rules=False,
                    )
                except PanosImportError as exc:
                    return f"Error: {exc}"
                source = conv.source
                raw = conv.backup["resources"].get("url_categories", [])
                cats = [
                    (c["name"], list(c.get("list") or []))
                    for c in raw
                    if c.get("type") in (None, "URL List")  # skip Category Match
                ]
            else:
                source = f"SCM folder `{folder}`"
                cats = []
                for c in client.url_category.list(folder=folder):
                    kind = getattr(c, "type", None)
                    if getattr(kind, "value", kind) in (None, "URL List"):
                        cats.append((c.name, list(c.list or [])))
            # Admin-defined URL apps only: the catalog runs to 1000+ entries
            # and is Palo Alto's own definitions, never a sync target.
            apps: list[dict] = []
            warnings: list[str] = []
            for app_type in _URL_APP_TYPES:
                found, err = _paginate(client, "applications", {"type": app_type}, limit)
                apps += found
                if err:
                    warnings.append(err)
            if warnings and not apps:
                if any("not provisioned" in w for w in warnings):
                    return _fmt({"source": source, "pairs": [], "note": warnings[0]})
                return f"Error: {warnings[0]}"

            if category:
                cat = next((c for c in cats if c[0] == category), None)
                app = next((a for a in apps if a.get("name") == pab_app), None)
                if cat is None:
                    return f"Error: no URL List category '{category}' in {source}"
                if app is None:
                    return f"Error: no custom or private Prisma Browser app named '{pab_app}'"
                pairs = [(cat, app)]
                unpaired_cats: list[str] = []
                unpaired_apps: list[str] = []
            else:
                by_key = {_pair_key(a.get("name") or ""): a for a in apps}
                pairs, unpaired_cats = [], []
                for c in cats:
                    app = by_key.get(_pair_key(c[0]))
                    if app is None:
                        unpaired_cats.append(c[0])
                    else:
                        pairs.append((c, app))
                paired = {id(a) for _c, a in pairs}
                unpaired_apps = sorted(
                    a.get("name") or "" for a in apps if id(a) not in paired and a.get("urls")
                )

            results = []
            for (name, urls), app in pairs:
                pab_urls = list(app.get("urls") or [])
                results.append(
                    {
                        "category": name,
                        "pab_app": app.get("name"),
                        "category_entries": len(urls),
                        "pab_entries": len(pab_urls),
                        **_url_drift(urls, pab_urls),
                    }
                )
            result: dict[str, Any] = {
                "source": source,
                "pairs_compared": len(results),
                "pairs_in_sync": sum(r["in_sync"] for r in results),
                "pairs": results,
            }
            if not category:
                result["categories_without_pab_app"] = sorted(unpaired_cats)
                result["pab_custom_apps_without_category"] = unpaired_apps
            if warnings:
                result["warnings"] = warnings
            return _fmt(result)
        except Exception as exc:
            return f"Error: {exc}"
