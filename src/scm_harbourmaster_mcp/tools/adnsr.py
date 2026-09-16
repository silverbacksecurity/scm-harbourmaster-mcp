"""
MCP tools for Advanced DNS Security Resolver (ADNSR) and NGFW Operations APIs.

Tools:
    scm_adnsr_list          — list ADNSR profiles, internal domains, connection sources
    scm_adnsr_profile_create — create an ADNSR DNS security profile
    scm_adnsr_internal_domains — list/manage internal domain bypass configurations
    scm_ngfw_local_config_list — list local config versions pushed to an NGFW device
    scm_ngfw_local_config_get  — fetch the XML configuration file for a specific version

Both APIs require feature licences; 403 responses are surfaced with actionable
guidance rather than generic errors.
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
    DRY_RUN_HINT,
    audit_write,
    normalize_ticket_ref,
    ticket_ref_error,
)

logger = get_logger(__name__)

# ADNSR API — confirmed via pan.dev: /adns-resolver/v1/
_ADNSR_BASE = "https://api.strata.paloaltonetworks.com/adns-resolver/v1"

# NGFW Operations API — confirmed to exist at this prefix (403 = not licensed)
_NGFW_OPS_BASE = "https://api.strata.paloaltonetworks.com/sse/config/v1"

_ADNSR_LICENSE_HINT = (
    "\n\n**Advanced DNS Security Resolver** is a premium add-on for Strata Cloud Manager. "
    "Contact your PAN account team or enable via SCM Admin → Subscriptions to unlock this API."
)

_NGFW_OPS_LICENSE_HINT = (
    "\n\n**NGFW Operations API** requires the NGFW Operations entitlement for your TSG. "
    "Contact your PAN account team to enable programmatic device config access."
)


def _adnsr_get(session: Any, path: str, params: dict[str, str] | None = None) -> tuple[int, Any]:
    """GET from the ADNSR API. Returns (status_code, parsed_body)."""
    url = f"{_ADNSR_BASE}{path}"
    resp = session.get(url, params=params or {}, timeout=(10, 30))
    try:
        body = resp.json()
    except Exception:
        body = resp.text
    return resp.status_code, body


def _check_license(status: int, body: Any) -> str | None:
    """Return a licence-gate message if the request was blocked, else None."""
    if status == 403:
        if isinstance(body, dict):
            msg = body.get("message") or body.get("msg") or "Access denied"
            detail = body.get("details", [])
            if isinstance(detail, list):
                detail = "; ".join(str(d) for d in detail)
            return f"{msg}. {detail}".strip(". ")
        return str(body)[:200] if body else "Access denied"
    return None


def register_adnsr_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register Advanced DNS Security Resolver and NGFW Operations tools."""
    tool = scm_tool(get_client)
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_adnsr_list(client: Any, resource: str = "profiles", folder: str = "Shared") -> str:
        """List Advanced DNS Security Resolver (ADNSR) resources.

        Queries the ADNSR API (`/adns-resolver/v1/`) introduced May 2026.
        ADNSR provides enterprise DNS security with custom resolvers, internal
        domain bypass, EDL-based domain blocking, sinkholing, and CA certificate
        management — all configurable per Prisma Access tenant.

        **Requires Advanced DNS Security Resolver licence** (separate add-on).

        Resources available:
        - `profiles` — DNS security profiles (default)
        - `internal-domains` — internal domain bypass rules
        - `connection-sources` — resolver source IP/interface config
        - `custom-fqdns` — custom FQDN override entries
        - `edl-definitions` — external dynamic list DNS definitions
        - `misconfigured-domains` — detected misconfigured domain records
        - `resolver-info` — resolver health and connectivity status
        - `ca-certs` — trusted CA certificates for DNS-over-TLS

        Args:
            resource: Resource type to list (see above, default "profiles").
            folder: SCM folder scope (default "Shared").
            tenant_id: SCM tenant ID. Defaults to active tenant.
        """
        session = getattr(client, "session", None)
        if not session:
            return "Error: no HTTP session available on SCM client."

        valid = {
            "profiles",
            "internal-domains",
            "connection-sources",
            "custom-fqdns",
            "edl-definitions",
            "misconfigured-domains",
            "resolver-info",
            "ca-certs",
        }
        resource = resource.strip().lower()
        if resource not in valid:
            return f"Unknown resource '{resource}'. Valid values: {', '.join(sorted(valid))}"

        params: dict[str, str] = {}
        if folder and resource not in ("resolver-info",):
            params["folder"] = folder

        status, body = _adnsr_get(session, f"/{resource}", params)

        lic_err = _check_license(status, body)
        if lic_err:
            return f"**ADNSR {resource} — {lic_err}**{_ADNSR_LICENSE_HINT}"

        if status != 200:
            return f"Error {status}: {json.dumps(body, default=str)[:500]}"

        ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        lines = [
            f"## ADNSR {resource.title()} — {folder}",
            "",
            f"*Retrieved: {ts}*",
            "",
        ]

        items = body if isinstance(body, list) else body.get("data", [body])
        if not items:
            lines.append(f"No {resource} configured.")
            return "\n".join(lines)

        lines.append(f"**{len(items)} item(s)**")
        lines.append("")
        lines += ["```json", json.dumps(items, indent=2, default=str)[:4000], "```"]
        return "\n".join(lines)

    @mcp.tool()
    @tool
    def scm_adnsr_profile_create(
        client: Any,
        tenant_id: str,
        name: str,
        folder: str = "Shared",
        action: str = "sinkhole",
        log_queries: bool = True,
        dry_run: bool = True,
        ticket_ref: str = "",
    ) -> str:
        """Create an Advanced DNS Security Resolver profile.

        Creates a new ADNSR DNS security profile via `POST /adns-resolver/v1/profiles`.
        Profiles control how DNS queries are inspected, blocked, or sinkhol'd for
        malicious domains. Use `scm_adnsr_list` to check existing profiles first.

        **Requires Advanced DNS Security Resolver licence.**

        Args:
            name: Profile name (must be unique within the folder).
            folder: SCM folder scope (default "Shared").
            action: Default action for threat domains — "sinkhole" (default),
                    "block", or "allow".
            log_queries: Enable DNS query logging (default True).
            dry_run: If True (default), return the planned profile without creating it.
            ticket_ref: Mandatory change-ticket reference (never sent to SCM).
            tenant_id: SCM tenant ID. Defaults to active tenant.

        **Write safety (SSR pattern):** ``dry_run=True`` by default;
        ``ticket_ref`` is mandatory.
        """
        err = ticket_ref_error(ticket_ref)
        if err:
            return f"Error: {err}"
        ticket_ref = normalize_ticket_ref(ticket_ref)

        session = getattr(client, "session", None)
        if not session:
            return "Error: no HTTP session available on SCM client."

        if not name or not name.strip():
            return "Error: name is required."

        valid_actions = {"sinkhole", "block", "allow"}
        if action not in valid_actions:
            return f"Invalid action '{action}'. Valid: {', '.join(sorted(valid_actions))}"

        payload: dict[str, Any] = {
            "name": name.strip(),
            "folder": folder,
            "action": action,
            "log_queries": log_queries,
        }

        url = f"{_ADNSR_BASE}/profiles"
        if dry_run:
            return (
                f"## ADNSR Profile Create — DRY-RUN — `{payload['name']}`\n\n"
                f"Ticket ref: {ticket_ref}\n\n"
                "Would POST to `/adns-resolver/v1/profiles`:\n\n"
                f"```json\n{json.dumps(payload, indent=2)}\n```\n\n"
                f"Run `scm_adnsr_list` to check for an existing profile of the same name.\n\n"
                f"{DRY_RUN_HINT}"
            )

        audit_write(
            "scm_adnsr_profile_create", ticket_ref, tenant_id, name=payload["name"], folder=folder
        )
        resp = session.post(url, json=payload, timeout=(10, 30))

        if resp.status_code == 403:
            try:
                body = resp.json()
            except Exception:
                body = {"message": resp.text}
            lic_err = _check_license(403, body)
            return f"**ADNSR profile create — {lic_err}**{_ADNSR_LICENSE_HINT}"

        if resp.status_code not in (200, 201):
            return f"Error {resp.status_code}: {resp.text[:500]}"

        created = resp.json()
        profile_id = created.get("id") or created.get("name") or name
        return (
            f"✅ ADNSR profile `{name}` created (id: `{profile_id}`).\n\n"
            f"Action: **{action}**  |  Log queries: **{log_queries}**  |  Folder: **{folder}**\n\n"
            "Run `scm_adnsr_list` to verify, then apply the profile to your Prisma Access "
            "mobile user or remote network configuration."
        )

    @mcp.tool()
    @tool
    def scm_ngfw_local_config_list(client: Any, serial: str) -> str:
        """List local configuration versions pushed to a specific SCM-managed NGFW.

        Uses the NGFW Operations API (`GET /sse/config/v1/local-config/versions`)
        introduced May 2026. Returns the history of configuration versions that
        SCM has pushed to the device, including timestamps and version identifiers.

        Use `scm_ngfw_device_list` to find valid device serial numbers first.

        **Requires NGFW Operations entitlement** on the TSG.

        Args:
            serial: Device serial number (e.g. "007351000123456").
            tenant_id: SCM tenant ID. Defaults to active tenant.
        """
        session = getattr(client, "session", None)
        if not session:
            return "Error: no HTTP session available on SCM client."

        if not serial or not serial.strip():
            return (
                "Error: serial is required. Run `scm_ngfw_device_list` to find "
                "the serial numbers of SCM-managed NGFW devices."
            )

        url = f"{_NGFW_OPS_BASE}/local-config/versions"
        resp = session.get(url, params={"serial": serial.strip()}, timeout=(10, 30))

        if resp.status_code == 403:
            return (
                f"**NGFW Operations API — access denied for device `{serial}`**"
                f"{_NGFW_OPS_LICENSE_HINT}"
            )

        resp.raise_for_status()
        data = resp.json()

        versions = data if isinstance(data, list) else data.get("data", [])
        ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

        lines = [
            f"## NGFW Local Config Versions — {serial}",
            "",
            f"*Retrieved: {ts}  |  {len(versions)} version(s)*",
            "",
        ]

        if not versions:
            lines.append(
                "No local config versions found. The device may not have received a push yet."
            )
            return "\n".join(lines)

        lines += [
            "| Version | Timestamp | Status | Description |",
            "|---|---|---|---|",
        ]
        for v in versions:
            ver = v.get("version") or v.get("id") or "—"
            pushed = _fmt_local_ts(v.get("timestamp") or v.get("created_at") or "")
            status = v.get("status") or v.get("state") or "—"
            desc = str(v.get("description") or v.get("comment") or "—")[:60]
            lines.append(f"| {ver} | {pushed} | {status} | {desc} |")

        lines += [
            "",
            f'Use `scm_ngfw_local_config_get(serial="{serial}", version="<version>")` '
            "to retrieve the XML config for a specific version.",
        ]
        return "\n".join(lines)

    @mcp.tool()
    @tool
    def scm_ngfw_local_config_get(client: Any, serial: str, version: str = "running") -> str:
        """Fetch the XML configuration file for a specific NGFW local config version.

        Uses the NGFW Operations API to retrieve the actual PAN-OS XML config
        that was pushed to the device. The returned XML can be fed directly into
        `scm_aiops_bpa` for device-level Best Practice Assessment without manual
        config export.

        Workflow: `scm_ngfw_device_list` → `scm_ngfw_local_config_list` →
        `scm_ngfw_local_config_get` → `scm_aiops_bpa(config_xml=...)`

        **Requires NGFW Operations entitlement** on the TSG.

        Args:
            serial: Device serial number.
            version: Config version identifier from `scm_ngfw_local_config_list`,
                     or "running" for the currently active config (default).
            tenant_id: SCM tenant ID. Defaults to active tenant.
        """
        session = getattr(client, "session", None)
        if not session:
            return "Error: no HTTP session available on SCM client."

        if not serial or not serial.strip():
            return "Error: serial is required."

        # Try version-specific path first, then running config path
        if version.lower() == "running":
            url = f"{_NGFW_OPS_BASE}/local-config/running"
        else:
            url = f"{_NGFW_OPS_BASE}/local-config/versions/{version}"

        resp = session.get(url, params={"serial": serial.strip()}, timeout=(10, 60))

        if resp.status_code == 403:
            return (
                f"**NGFW Operations API — access denied for device `{serial}`**"
                f"{_NGFW_OPS_LICENSE_HINT}"
            )

        if resp.status_code == 404:
            return (
                f"Config version `{version}` not found for device `{serial}`.\n"
                f'Run `scm_ngfw_local_config_list(serial="{serial}")` to see available versions.'
            )

        resp.raise_for_status()

        # Response may be XML directly or JSON with a url/content field
        ct = resp.headers.get("Content-Type", "")
        if "xml" in ct or resp.text.strip().startswith("<?xml"):
            xml_preview = resp.text[:500]
            xml_len = len(resp.text)
            return (
                f"## NGFW Config XML — {serial} (version: {version})\n\n"
                f"*Length: {xml_len:,} characters*\n\n"
                f"```xml\n{xml_preview}\n... (truncated)\n```\n\n"
                f"**Full XML available** — pass `config_xml` to `scm_aiops_bpa` for BPA analysis:\n"
                f'`scm_aiops_bpa(config_xml=<full_xml>, device_serial="{serial}", '
                f'requester_email="your@csp-email.com")`\n\n'
                f"*Full config:*\n```xml\n{resp.text}\n```"
            )
        else:
            data = resp.json()
            dl_url = data.get("download-url") or data.get("url") or data.get("config_url")
            if dl_url:
                import requests as _r

                xml_resp = _r.get(dl_url, timeout=(10, 60))
                return (
                    f"## NGFW Config XML — {serial} (version: {version})\n\n"
                    f"```xml\n{xml_resp.text[:500]}\n... (truncated)\n```\n\n"
                    f"Full XML ({len(xml_resp.text):,} chars) available for `scm_aiops_bpa`."
                )
            return f"```json\n{json.dumps(data, indent=2, default=str)[:2000]}\n```"

    @mcp.tool()
    @tool
    def scm_ngfw_wan_ip_summary(
        client: Any, tenant_id: str, serial: str = "", enrich: bool = False
    ) -> str:
        """Report configured WAN/internet-facing interface IP addresses for NGFW devices.

        For each SCM-managed NGFW device (or just `serial` if given), fetches its
        running-config via the NGFW Operations API and parses physical/aggregate
        interfaces (ethernetX/Y, aeN) that have Layer 3 addressing, along with
        their assigned security zone.

        With enrich=true, each public interface IP is additionally looked up
        against an external IP-intelligence provider (ISP, organisation, ASN,
        reverse DNS, IP geolocation). Note this sends the tenant's public IPs
        to a third-party service (`ip_enrichment_provider` in settings, default
        ip-api.com) — hence opt-in, never on by default.

        Use this to populate a WAN IP inventory table for AS-BUILT documentation.
        Note: this reflects **configuration**, not live operational state — a
        DHCP-configured interface is reported with addressing="dhcp" but no IP,
        since (unlike Prisma SD-WAN) there is no live-lease-status endpoint for
        NGFW interfaces.

        **Requires NGFW Operations entitlement** on the TSG.

        Args:
            tenant_id: SCM tenant ID. Defaults to active tenant.
            serial: Optional — limit to a single device serial number.
            enrich: Look up ISP/ASN/rDNS/geo for each public interface IP.
        """
        try:
            from ..audit.extractor import extract_ngfw_devices, extract_ngfw_interface_ips
            from ..audit.models import AuditSnapshot

            snap = AuditSnapshot(folder="", tenant_id=tenant_id or "default")
            extract_ngfw_devices(client, snap)
            if serial:
                snap.ngfw_devices = [
                    d
                    for d in snap.ngfw_devices
                    if (d.get("serial_number") or d.get("serial")) == serial
                ]
                if not snap.ngfw_devices:
                    return f"Error: device serial {serial!r} not found via scm_ngfw_device_list."
            extract_ngfw_interface_ips(client, snap)

            enrich_warnings: list[str] = []
            if enrich:
                from ..utils.ipenrich import enrich_public_ips, global_ips

                candidates = [
                    ip for rec in snap.ngfw_interface_ips for ip in (rec.get("ip_addresses") or [])
                ]
                by_ip, enrich_warnings = enrich_public_ips(candidates)
                for rec in snap.ngfw_interface_ips:
                    matches = [
                        by_ip[ip] for ip in global_ips(rec.get("ip_addresses") or []) if ip in by_ip
                    ]
                    if matches:
                        rec["enrichment"] = matches

            result: dict[str, Any] = {
                "total": len(snap.ngfw_interface_ips),
                "interface_ips": snap.ngfw_interface_ips,
            }
            if enrich_warnings:
                result["warnings"] = [f"enrichment: {w}" for w in enrich_warnings]
            if not snap.ngfw_interface_ips:
                result["note"] = (
                    "No data returned — requires NGFW Operations entitlement, "
                    "or no devices have L3-addressed interfaces."
                )
            return json.dumps(result, indent=2, default=str)
        except Exception as exc:
            return f"Error: {handle_scm_exception(exc, tool='scm_ngfw_wan_ip_summary', tenant_id=tenant_id)}"


def _fmt_local_ts(ts: str) -> str:
    if not ts:
        return "—"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return ts[:16] if ts else "—"
