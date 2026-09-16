"""
MCP tools for Palo Alto Networks Enterprise DLP management.

Covers the Enterprise DLP API (api.dlp.paloaltonetworks.com) and the
SCM Config REST DLP endpoints (/config/v1/data-filtering-profiles,
/config/v1/data-objects), enabling MSSP operators to:

  dlp_enterprise_list  — list Enterprise DLP data patterns and profiles
  dlp_backup           — export full DLP config (SCM + Enterprise) as JSON
  dlp_restore          — import a DLP backup into a target tenant/folder

Reference: https://pan.dev/dlp/api/
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..utils.errors import handle_scm_exception
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool
from ..utils.write_safety import (
    audit_write,
    normalize_ticket_ref,
    ticket_ref_error,
)

logger = get_logger(__name__)

_SCM_CONFIG_BASE = "https://api.sase.paloaltonetworks.com/config/v1"
_DLP_BASE = "https://api.dlp.paloaltonetworks.com"


# ── Helpers ───────────────────────────────────────────────────────────────────

_NOT_LICENSED_STATUSES = frozenset({401, 403, 404, 424})


def _exc_status(exc: Any) -> int | None:
    resp = getattr(exc, "response", None)
    return getattr(resp, "status_code", None)


def _rest_get(session: Any, url: str, params: dict | None = None) -> list[dict]:
    try:
        resp = session.get(url, params=params, timeout=(5, 15))
    except Exception as exc:
        if _exc_status(exc) in _NOT_LICENSED_STATUSES:
            return []
        raise
    if resp.status_code in _NOT_LICENSED_STATUSES:
        return []
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, list):
        return data
    return data.get("data", data.get("items", data.get("patterns", data.get("profiles", []))))


def _dlp_company_id(session: Any) -> str:
    """Resolve Enterprise DLP company ID for the current auth token."""
    try:
        resp = session.get(f"{_DLP_BASE}/v1/config/companies", timeout=(4, 10))
        if resp.status_code not in (200, 201):
            return ""
        data = resp.json()
        companies = data if isinstance(data, list) else data.get("companies", data.get("data", []))
        if companies:
            c = companies[0]
            return str(c.get("company_id", c.get("id", "")))
    except Exception as exc:
        logger.warning("dlp_company_id_failed", error=str(exc))
    return ""


def _dlp_list_patterns(session: Any, company_id: str) -> list[dict]:
    return _rest_get(session, f"{_DLP_BASE}/v1/config/companies/{company_id}/data-patterns")


def _dlp_list_profiles(session: Any, company_id: str) -> list[dict]:
    return _rest_get(session, f"{_DLP_BASE}/v1/config/companies/{company_id}/data-profiles")


def _scm_list(session: Any, path: str, folder: str) -> list[dict]:
    params = {"folder": folder, "limit": 1000}
    return _rest_get(session, f"{_SCM_CONFIG_BASE}{path}", params)


def _scm_create(session: Any, path: str, payload: dict) -> dict:
    resp = session.post(f"{_SCM_CONFIG_BASE}{path}", json=payload, timeout=(5, 15))
    resp.raise_for_status()
    return resp.json()


def _dlp_create_pattern(session: Any, company_id: str, payload: dict) -> dict:
    resp = session.post(
        f"{_DLP_BASE}/v1/config/companies/{company_id}/data-patterns",
        json=payload,
        timeout=(5, 15),
    )
    resp.raise_for_status()
    return resp.json()


def _dlp_create_profile(session: Any, company_id: str, payload: dict) -> dict:
    resp = session.post(
        f"{_DLP_BASE}/v1/config/companies/{company_id}/data-profiles",
        json=payload,
        timeout=(5, 15),
    )
    resp.raise_for_status()
    return resp.json()


# ── Strip read-only fields before restore ─────────────────────────────────────

_SCM_RO_FIELDS = {"id", "created_at", "updated_at", "last_modified", "etag", "_etag"}
_DLP_PATTERN_RO = {"id", "pattern_id", "created_at", "updated_at", "is_system", "revision"}
_DLP_PROFILE_RO = {"id", "profile_id", "created_at", "updated_at", "is_system", "revision"}


def _strip(obj: dict, readonly: set[str]) -> dict:
    return {k: v for k, v in obj.items() if k not in readonly}


# ── Tool registration ─────────────────────────────────────────────────────────


def register_dlp_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register Enterprise DLP backup / restore / list tools onto the MCP server."""
    tool = scm_tool(get_client)
    tool = scm_tool(get_client)
    tool = scm_tool(get_client)

    # ── List ──────────────────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def dlp_enterprise_list(client: Any, tenant_id: str, company_id: str = "") -> str:
        """List Enterprise DLP data patterns and data profiles for a tenant.

        Queries the PAN Enterprise DLP API (api.dlp.paloaltonetworks.com)
        which covers ML-based DLP patterns used by Prisma SaaS Security and
        Cloud SWG — distinct from inline SCM data-filtering-profiles.

        If company_id is omitted the tool auto-discovers it via
        GET /v1/config/companies.

        Args:
            tenant_id:  SCM tenant ID (MSSP mode). Omit for default tenant.
            company_id: Enterprise DLP company ID. Auto-discovered if blank.

        Returns:
            Markdown summary of Enterprise DLP data patterns and profiles.

        Ref: https://pan.dev/dlp/api/
        """
        session = client.session
        cid = company_id or _dlp_company_id(session)
        if not cid:
            return (
                "⚠️ Could not resolve Enterprise DLP company ID. "
                "The tenant may not have Enterprise DLP licensed, or the API returned no companies. "
                "Pass `company_id` explicitly if known."
            )
        patterns = _dlp_list_patterns(session, cid)
        profiles = _dlp_list_profiles(session, cid)

        lines = [
            f"# Enterprise DLP — Tenant `{tenant_id or 'default'}` | Company `{cid}`\n",
        ]

        lines.append(f"## Data Patterns ({len(patterns)})\n")
        if patterns:
            lines += [
                "| Name | ID | Type | Active | Description |",
                "|------|----|------|--------|-------------|",
            ]
            for p in patterns:
                lines.append(
                    "| {} | {} | {} | {} | {} |".format(
                        p.get("name", "—"),
                        p.get("pattern_id", p.get("id", "—")),
                        p.get("pattern_type", p.get("type", "—")),
                        "✓" if p.get("active", True) else "✗",
                        (p.get("description") or "—")[:80],
                    )
                )
        else:
            lines.append("_No Enterprise DLP data patterns found._")

        lines.append(f"\n## Data Profiles ({len(profiles)})\n")
        if profiles:
            lines += [
                "| Name | ID | Pattern Count | Status | Description |",
                "|------|----|---------------|--------|-------------|",
            ]
            for p in profiles:
                pattern_count = len(
                    p.get("profile_type", {})
                    .get("custom", {})
                    .get("primary_match", {})
                    .get("rules", [])
                )
                lines.append(
                    "| {} | {} | {} | {} | {} |".format(
                        p.get("name", "—"),
                        p.get("profile_id", p.get("id", "—")),
                        pattern_count or "—",
                        p.get("status", "active"),
                        (p.get("description") or "—")[:80],
                    )
                )
        else:
            lines.append("_No Enterprise DLP data profiles found._")

        lines.append(
            "\n> 📎 Ref: <https://pan.dev/dlp/api/>  |  "
            "Use `dlp_backup` to export these for MSSP cross-tenant provisioning."
        )
        return "\n".join(lines)

    # ── Backup ────────────────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def dlp_backup(
        client: Any,
        tenant_id: str,
        folder: str = "All",
        company_id: str = "",
        include_enterprise: bool = True,
    ) -> str:
        """Export full DLP configuration as a JSON backup for cross-tenant redeployment.

        Exports two layers of DLP config:

          SCM DLP (inline):
            - Data filtering profiles  (/config/v1/data-filtering-profiles)
            - Data objects             (/config/v1/data-objects)

          Enterprise DLP (ML-based, optional):
            - Data patterns            (api.dlp.paloaltonetworks.com data-patterns)
            - Data profiles            (api.dlp.paloaltonetworks.com data-profiles)

        The returned JSON can be passed directly to `dlp_restore` to provision
        an identical DLP configuration on another tenant/folder.

        Args:
            folder:             SCM folder to export inline DLP from (default: All).
            tenant_id:          Source tenant ID (MSSP mode).
            company_id:         Enterprise DLP company ID. Auto-discovered if blank.
            include_enterprise: Include Enterprise DLP patterns and profiles (default: True).

        Returns:
            JSON backup payload (pretty-printed).

        Ref: https://pan.dev/dlp/api/
        """
        session = client.session

        data_objects = _scm_list(session, "/data-objects", folder)
        data_filtering_profiles = _scm_list(session, "/data-filtering-profiles", folder)

        enterprise: dict[str, Any] = {
            "company_id": "",
            "data_patterns": [],
            "data_profiles": [],
        }
        if include_enterprise:
            cid = company_id or _dlp_company_id(session)
            if cid:
                enterprise["company_id"] = cid
                enterprise["data_patterns"] = _dlp_list_patterns(session, cid)
                enterprise["data_profiles"] = _dlp_list_profiles(session, cid)
            else:
                enterprise["_note"] = (
                    "Enterprise DLP company ID could not be resolved — "
                    "tenant may not have Enterprise DLP licensed."
                )

        backup = {
            "backup_version": "1.0",
            "timestamp": datetime.now(UTC).isoformat(),
            "source_tenant": tenant_id or "default",
            "source_folder": folder,
            "scm_dlp": {
                "data_objects": data_objects,
                "data_filtering_profiles": data_filtering_profiles,
            },
            "enterprise_dlp": enterprise,
        }

        total = (
            len(data_objects)
            + len(data_filtering_profiles)
            + len(enterprise.get("data_patterns", []))
            + len(enterprise.get("data_profiles", []))
        )

        result_lines = [
            f"# DLP Backup — `{folder}` | Tenant `{tenant_id or 'default'}`\n",
            f"**Exported {total} objects** at {backup['timestamp']}\n",
            f"- SCM data objects: {len(data_objects)}",
            f"- SCM data filtering profiles: {len(data_filtering_profiles)}",
            f"- Enterprise DLP data patterns: {len(enterprise.get('data_patterns', []))}",
            f"- Enterprise DLP data profiles: {len(enterprise.get('data_profiles', []))}\n",
            "Pass the JSON below to `dlp_restore` to provision on a target tenant:\n",
            "```json",
            json.dumps(backup, indent=2, default=str),
            "```",
        ]
        return "\n".join(result_lines)

    # ── Restore ───────────────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def dlp_restore(
        client: Any,
        tenant_id: str,
        backup_json: str,
        target_folder: str,
        company_id: str = "",
        dry_run: bool = True,
        ticket_ref: str = "",
    ) -> str:
        """Restore a DLP backup onto a target tenant/folder.

        Accepts a JSON backup produced by `dlp_backup` and provisions the
        contained DLP objects on the target tenant:

          1. SCM data objects             → POST /config/v1/data-objects
          2. SCM data filtering profiles  → POST /config/v1/data-filtering-profiles
          3. Enterprise DLP data patterns → POST /v1/config/companies/{cid}/data-patterns
          4. Enterprise DLP data profiles → POST /v1/config/companies/{cid}/data-profiles

        Objects are skipped if a resource with the same name already exists
        (HTTP 409 / 400 duplicate-name response).

        Args:
            backup_json:   JSON string produced by `dlp_backup`.
            target_folder: SCM folder to restore inline DLP objects into.
            tenant_id:     Target tenant ID (MSSP mode).
            company_id:    Enterprise DLP company ID for the target tenant.
                           Auto-discovered if blank.
            dry_run:       If True (default), only report what would be created.
                           Set to False to apply changes.
            ticket_ref:    Mandatory change-ticket reference (never sent to the API).

        **Write safety (SSR pattern):** ``dry_run=True`` by default;
        ``ticket_ref`` is mandatory.

        Returns:
            Markdown restore report listing created / skipped / failed objects.

        Ref: https://pan.dev/dlp/api/
        """
        err = ticket_ref_error(ticket_ref)
        if err:
            return f"Error: {err}"
        ticket_ref = normalize_ticket_ref(ticket_ref)

        try:
            raw = backup_json.strip()
            if not raw.startswith("{"):
                # Accept the Markdown-wrapped output of dlp_backup (```json...```)
                start = raw.find("{")
                end = raw.rfind("}") + 1
                if start == -1 or end == 0:
                    return "Error: backup_json contains no JSON object — pass the output of dlp_backup directly"
                raw = raw[start:end]
            backup = json.loads(raw)
        except json.JSONDecodeError as exc:
            return f"Error: backup_json is not valid JSON — {exc}"

        if backup.get("backup_version") != "1.0":
            return (
                "Error: unrecognised backup format. "
                "backup_version must be '1.0'. "
                "Generate a new backup with `dlp_backup`."
            )

        scm_dlp = backup.get("scm_dlp", {})
        ent_dlp = backup.get("enterprise_dlp", {})

        data_objects = scm_dlp.get("data_objects", [])
        data_profiles = scm_dlp.get("data_filtering_profiles", [])
        # Skip built-in system patterns/profiles — the API rejects POSTs for them
        ent_patterns = [p for p in ent_dlp.get("data_patterns", []) if not p.get("is_system")]
        ent_profiles = [p for p in ent_dlp.get("data_profiles", []) if not p.get("is_system")]

        created: list[str] = []
        skipped: list[str] = []
        failed: list[str] = []

        if dry_run:
            for o in data_objects:
                created.append(f"[DRY-RUN] Would create SCM data-object: `{o.get('name', '?')}`")
            for p in data_profiles:
                created.append(
                    f"[DRY-RUN] Would create SCM data-filtering-profile: `{p.get('name', '?')}`"
                )
            for pat in ent_patterns:
                created.append(
                    f"[DRY-RUN] Would create Enterprise DLP pattern: `{pat.get('name', '?')}`"
                )
            for prof in ent_profiles:
                created.append(
                    f"[DRY-RUN] Would create Enterprise DLP profile: `{prof.get('name', '?')}`"
                )

            lines = [
                f"# DLP Restore — DRY-RUN — Target: `{target_folder}` | Tenant `{tenant_id or 'default'}`\n",
                "> ℹ️ **dry_run=True**: No changes applied. Set `dry_run=False` to execute.\n",
                f"**Ticket ref:** {ticket_ref}\n",
                f"**Objects that would be created ({len(created)}):**\n",
            ]
            for item in created:
                lines.append(f"- {item}")
            return "\n".join(lines)

        # Live restore
        audit_write(
            "dlp_restore",
            ticket_ref,
            tenant_id,
            target_folder=target_folder,
            data_objects=len(data_objects),
            data_profiles=len(data_profiles),
            enterprise_patterns=len(ent_patterns),
            enterprise_profiles=len(ent_profiles),
        )
        try:
            session = client.session
        except Exception as exc:
            return f"Error connecting to tenant: {handle_scm_exception(exc)}"

        # 1. SCM data objects (must precede data-filtering-profiles that reference them)
        for o in data_objects:
            name = o.get("name", "?")
            payload = _strip(o, _SCM_RO_FIELDS)
            payload["folder"] = target_folder
            try:
                _scm_create(session, "/data-objects", payload)
                created.append(f"✅ Created SCM data-object: `{name}`")
                logger.info("dlp_restore_created", type="data-object", name=name)
            except Exception as exc:
                msg = str(exc)
                if (
                    _exc_status(exc) == 409
                    or "already exists" in msg.lower()
                    or "duplicate" in msg.lower()
                ):
                    skipped.append(f"⏭️ Skipped (exists): SCM data-object `{name}`")
                else:
                    failed.append(f"❌ Failed SCM data-object `{name}`: {msg}")
                    logger.warning("dlp_restore_failed", type="data-object", name=name, error=msg)

        # 2. SCM data filtering profiles
        for p in data_profiles:
            name = p.get("name", "?")
            payload = _strip(p, _SCM_RO_FIELDS)
            payload["folder"] = target_folder
            try:
                _scm_create(session, "/data-filtering-profiles", payload)
                created.append(f"✅ Created SCM data-filtering-profile: `{name}`")
                logger.info("dlp_restore_created", type="data-filtering-profile", name=name)
            except Exception as exc:
                msg = str(exc)
                if (
                    _exc_status(exc) == 409
                    or "already exists" in msg.lower()
                    or "duplicate" in msg.lower()
                ):
                    skipped.append(f"⏭️ Skipped (exists): SCM data-filtering-profile `{name}`")
                else:
                    failed.append(f"❌ Failed SCM data-filtering-profile `{name}`: {msg}")
                    logger.warning(
                        "dlp_restore_failed", type="data-filtering-profile", name=name, error=msg
                    )

        # 3. Enterprise DLP patterns (if present in backup)
        if ent_patterns or ent_profiles:
            cid = company_id or _dlp_company_id(session)
            if not cid:
                failed.append(
                    "❌ Could not resolve Enterprise DLP company ID — "
                    "Enterprise DLP patterns/profiles were not restored."
                )
            else:
                for pat in ent_patterns:
                    name = pat.get("name", "?")
                    payload = _strip(pat, _DLP_PATTERN_RO)
                    try:
                        _dlp_create_pattern(session, cid, payload)
                        created.append(f"✅ Created Enterprise DLP pattern: `{name}`")
                        logger.info("dlp_restore_created", type="dlp-pattern", name=name)
                    except Exception as exc:
                        msg = str(exc)
                        if (
                            _exc_status(exc) == 409
                            or "already exists" in msg.lower()
                            or "duplicate" in msg.lower()
                        ):
                            skipped.append(f"⏭️ Skipped (exists): Enterprise DLP pattern `{name}`")
                        else:
                            failed.append(f"❌ Failed Enterprise DLP pattern `{name}`: {msg}")
                            logger.warning(
                                "dlp_restore_failed", type="dlp-pattern", name=name, error=msg
                            )

                # 4. Enterprise DLP profiles (created after patterns they reference)
                for prof in ent_profiles:
                    name = prof.get("name", "?")
                    payload = _strip(prof, _DLP_PROFILE_RO)
                    try:
                        _dlp_create_profile(session, cid, payload)
                        created.append(f"✅ Created Enterprise DLP profile: `{name}`")
                        logger.info("dlp_restore_created", type="dlp-profile", name=name)
                    except Exception as exc:
                        msg = str(exc)
                        if (
                            _exc_status(exc) == 409
                            or "already exists" in msg.lower()
                            or "duplicate" in msg.lower()
                        ):
                            skipped.append(f"⏭️ Skipped (exists): Enterprise DLP profile `{name}`")
                        else:
                            failed.append(f"❌ Failed Enterprise DLP profile `{name}`: {msg}")
                            logger.warning(
                                "dlp_restore_failed", type="dlp-profile", name=name, error=msg
                            )

        lines = [
            f"# DLP Restore Report — `{target_folder}` | Tenant `{tenant_id or 'default'}`\n",
            f"**Source backup:** tenant `{backup.get('source_tenant', '?')}` "
            f"/ folder `{backup.get('source_folder', '?')}` "
            f"/ created {backup.get('timestamp', '?')}\n",
            f"✅ Created: {len(created)}  |  ⏭️ Skipped: {len(skipped)}  |  ❌ Failed: {len(failed)}\n",
        ]
        for item in created + skipped + failed:
            lines.append(f"- {item}")

        return "\n".join(lines)

    # ── Incidents (v4 Beta API + v1 GA) ──────────────────────────────────────

    @mcp.tool()
    @tool
    def dlp_incidents_list(
        client: Any, status: str = "", severity: str = "", limit: int = 50
    ) -> str:
        """List Enterprise DLP incidents from the v4 Beta Incidents API.

        Queries GET /v4/api/incidents on api.dlp.paloaltonetworks.com.
        The DLP Incidents API surfaces policy violations detected by
        Enterprise DLP — distinct from the Email DLP incidents API.

        Args:
            tenant_id:  SCM tenant ID (MSSP mode). Omit for default tenant.
            status:     Filter by incident status (e.g. "open", "resolved").
            severity:   Filter by severity (e.g. "critical", "high", "medium", "low").
            limit:      Max incidents to return (default 50, max 200).

        Returns:
            JSON: list of DLP incidents with total count.
        """
        session = client.session
        params: dict[str, Any] = {"limit": min(limit, 200)}
        if status:
            params["status"] = status
        if severity:
            params["severity"] = severity

        resp = session.get(
            f"{_DLP_BASE}/v4/api/incidents",
            params=params,
            timeout=(5, 15),
        )
        if resp.status_code in _NOT_LICENSED_STATUSES:
            return json.dumps(
                {
                    "incidents": [],
                    "total": 0,
                    "hint": (
                        "Enterprise DLP Incidents API returned "
                        f"{resp.status_code} — the tenant may not have "
                        "Enterprise DLP licensed, or the v4 Beta API is "
                        "not enabled for this account."
                    ),
                },
                indent=2,
                default=str,
            )
        resp.raise_for_status()
        data = resp.json()

        items = data if isinstance(data, list) else data.get("items", data.get("data", []))
        return json.dumps(
            {
                "incidents": items,
                "total": len(items),
                "filters": {
                    "status": status or "all",
                    "severity": severity or "all",
                    "limit": min(limit, 200),
                },
            },
            indent=2,
            default=str,
        )

    @mcp.tool()
    @tool
    def dlp_incidents_get(client: Any, incident_id: str = "") -> str:
        """Get a single Enterprise DLP incident by ID.

        Queries GET /v4/api/incidents/{id} on api.dlp.paloaltonetworks.com.

        Args:
            tenant_id:   SCM tenant ID (MSSP mode). Omit for default tenant.
            incident_id: DLP incident ID (required).

        Returns:
            JSON: incident detail.
        """
        if not incident_id:
            return json.dumps({"error": "incident_id is required"}, indent=2)

        session = client.session
        resp = session.get(
            f"{_DLP_BASE}/v4/api/incidents/{incident_id}",
            timeout=(5, 15),
        )
        if resp.status_code in _NOT_LICENSED_STATUSES:
            return json.dumps(
                {
                    "incident_id": incident_id,
                    "available": False,
                    "hint": f"DLP Incidents API returned {resp.status_code}.",
                },
                indent=2,
                default=str,
            )
        resp.raise_for_status()
        data = resp.json()

        return json.dumps({"incident_id": incident_id, "incident": data}, indent=2, default=str)

    @mcp.tool()
    @tool
    def dlp_incidents_assignees(client: Any) -> str:
        """List DLP incident assignees from the v1 GA Incidents API.

        Queries GET /v1/api/incidents/assignee on api.dlp.paloaltonetworks.com.
        Returns the list of users/groups that can be assigned to DLP incidents.

        Args:
            tenant_id:  SCM tenant ID (MSSP mode). Omit for default tenant.

        Returns:
            JSON: list of assignees.
        """
        session = client.session
        resp = session.get(
            f"{_DLP_BASE}/v1/api/incidents/assignee",
            timeout=(5, 15),
        )
        if resp.status_code in _NOT_LICENSED_STATUSES:
            return json.dumps(
                {
                    "assignees": [],
                    "hint": f"DLP Incidents API returned {resp.status_code}.",
                },
                indent=2,
                default=str,
            )
        resp.raise_for_status()
        data = resp.json()

        items = data if isinstance(data, list) else data.get("items", data.get("data", []))
        return json.dumps({"assignees": items, "total": len(items)}, indent=2, default=str)
