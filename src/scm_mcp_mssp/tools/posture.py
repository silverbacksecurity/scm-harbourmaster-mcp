"""
MCP tools for SCM Posture Management and Incidents APIs.

Tools:
    scm_incident_search   — search/filter SCM security incidents (single or all tenants)
    scm_incident_summary  — cross-tenant NOC incident dashboard (counts by severity/status)
    scm_posture_report    — retrieve Posture Management best-practice report findings
    scm_saas_posture      — SSPM SaaS app posture + Identity-SSPM IdPs, with manual
                            JSON export (save_to) / import (load_from)
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..auth.oauth import get_scm_client
from ..config.settings import TenantConfig
from ..utils.errors import handle_scm_exception
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool

logger = get_logger(__name__)


def _load_tenant_configs() -> dict[str, TenantConfig]:
    """Load all MSSP tenant configs from settings.toml + .secrets.toml."""
    try:
        from dynaconf import Dynaconf  # type: ignore[import-untyped]

        base = Dynaconf(envvar_prefix="SCM_MCP", settings_files=["settings.toml"], load_dotenv=True)
        secrets = Dynaconf(
            envvar_prefix="SCM_MCP", settings_files=[".secrets.toml"], load_dotenv=False
        )
        base_t: dict[str, Any] = dict(base.get("tenants") or {})
        secret_t: dict[str, Any] = dict(secrets.get("tenants") or {})
        out: dict[str, TenantConfig] = {}
        for key in set(base_t) | set(secret_t):
            merged = dict(base_t.get(key) or {})
            merged.update(secret_t.get(key) or {})
            try:
                out[key] = TenantConfig(**merged)
            except Exception as exc:
                logger.warning("tenant_config_invalid", tenant=key, error=str(exc))
        return out
    except Exception as exc:
        logger.warning("tenant_config_load_failed", error=str(exc))
        return {}


# Incidents API base — confirmed live: POST /incidents/v1/search returns 200
_INC_BASE = "https://api.strata.paloaltonetworks.com"
_INC_SEARCH = "/incidents/v1/search"

# Posture API — confirmed to exist (403 = license-gated in non-subscribed tenants)
_POSTURE_BASE = "/posture/v1/reports"

_SEV_EMOJI: dict[str, str] = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
    "informational": "⚪",
}
_SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4, "Info": 4}

_LICENSE_HINT = (
    "\n\nThis feature requires the **Posture Management** add-on licence for your "
    "Strata Cloud Manager subscription. Contact your PAN account team or MSSP admin to enable."
)


def _sev_emoji(sev: str) -> str:
    return _SEV_EMOJI.get(sev.lower(), "⚪")


def _incidents_for_tenant(session: Any, tenant_label: str) -> list[dict[str, Any]]:
    """Call POST /incidents/v1/search and return the data list."""
    url = f"{_INC_BASE}{_INC_SEARCH}"
    resp = session.post(url, json={}, timeout=(10, 30))
    resp.raise_for_status()
    d = resp.json()
    return d.get("data") or []


def _fmt_ts(ts: str | None) -> str:
    if not ts:
        return "—"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return ts[:16] if ts else "—"


_SAAS_POSTURE_FORMAT = "scm-mcp-mssp/saas-posture@1"


def _render_saas_posture(data: dict[str, Any], source: str, include_catalog: bool) -> str:
    """Render a saas-posture snapshot dict (live or imported) as markdown."""
    from collections import Counter

    apps = data.get("apps") or []
    catalog = data.get("catalog") or []
    idps = data.get("idps") or []
    lines = ["# SaaS Security Posture (SSPM)", "", f"_Source: {source}_", ""]

    if not data.get("sspm_licensed"):
        lines += [
            "**SSPM is not licensed or not reachable on this tenant** — the SSPM API "
            "returned HTTP 500 (the service's unlicensed response) or was unavailable.",
            "",
        ]
    else:
        all_configs = [(a, c) for a in apps for c in (a.get("_configs") or [])]
        high_crit = sum(
            1 for _, c in all_configs if (c.get("severity") or "").lower() in ("critical", "high")
        )
        lines += [
            "| Metric | Value |",
            "|---|---|",
            f"| Onboarded SaaS applications | {len(apps)} |",
            f"| Misconfiguration findings | {len(all_configs)} |",
            f"| High/Critical findings | {high_crit} |",
            f"| Supported apps in catalog | {len(catalog)} |",
            "",
        ]
        if apps:
            lines += [
                "## Onboarded Applications",
                "",
                "| Application | Status | Verticals | Findings | High/Crit |",
                "|---|---|---|---|---|",
            ]
            for a in apps:
                name = a.get("display_name") or a.get("app_name") or a.get("name") or "—"
                status = a.get("status") or a.get("connection_status") or "—"
                verticals = ", ".join(a.get("verticals") or []) or "—"
                cfgs = a.get("_configs") or []
                hc = sum(
                    1 for c in cfgs if (c.get("severity") or "").lower() in ("critical", "high")
                )
                lines.append(f"| {name} | {status} | {verticals} | {len(cfgs)} | {hc} |")
            lines.append("")
            if all_configs:
                ranked = sorted(
                    all_configs,
                    key=lambda ac: _SEV_ORDER.get((ac[1].get("severity") or "").title(), 9),
                )
                lines += [
                    "## Top Findings",
                    "",
                    "| App | Finding | Severity | Status |",
                    "|---|---|---|---|",
                ]
                for a, c in ranked[:15]:
                    app_name = a.get("display_name") or a.get("app_name") or a.get("name") or "—"
                    title = (
                        c.get("title")
                        or c.get("name")
                        or c.get("config_name")
                        or c.get("id")
                        or "—"
                    )
                    lines.append(
                        f"| {app_name} | {title} | {c.get('severity', '—')} | {c.get('status', '—')} |"
                    )
                lines.append("")
        elif catalog:
            features: Counter[str] = Counter()
            for capp in catalog:
                for f in capp.get("features") or []:
                    features[f] += 1
            lines += [
                "_SSPM is licensed but **no SaaS applications are onboarded** for posture "
                "scanning yet (SaaS Security → Posture Management → Applications)._",
                "",
                "| Catalog capability | Supported apps |",
                "|---|---|",
                f"| Posture/misconfiguration scanning (SCAN) | {features.get('SCAN', 0)} |",
                f"| Non-Human Identity tracking (NHI) | {features.get('IDENTITY_NHI', 0)} |",
                f"| Third-party app discovery | {features.get('THIRD_PARTY_APPS', 0)} |",
                f"| AI agent scanning (AGENT_SCAN) | {features.get('AGENT_SCAN', 0)} |",
                f"| Automated remediation | {features.get('REMEDIATE', 0)} |",
                "",
            ]

    lines += ["## Identity-SSPM (IdPs & NHI)", ""]
    if not data.get("identity_sspm_licensed"):
        lines.append("_Identity-SSPM is not provisioned on this tenant (HTTP 404/500)._")
    elif not idps:
        lines.append(
            "_Identity-SSPM is provisioned but **no Identity Providers are connected** yet._"
        )
    else:
        lines += ["| IdP | Type | Status |", "|---|---|---|"]
        for idp in idps:
            lines.append(
                f"| {idp.get('display_name') or idp.get('name') or '—'} "
                f"| {idp.get('idp_type') or idp.get('type') or '—'} "
                f"| {idp.get('status') or idp.get('state') or '—'} |"
            )
    lines.append("")

    if include_catalog and catalog:
        lines += ["## Supported App Catalog", ""]
        by_vertical: dict[str, list[str]] = {}
        for capp in catalog:
            name = capp.get("display_name") or capp.get("name") or "?"
            for v in capp.get("verticals") or ["(uncategorised)"]:
                by_vertical.setdefault(v, []).append(name)
        for v in sorted(by_vertical):
            names = sorted(set(by_vertical[v]))
            lines.append(
                f"- **{v}** ({len(names)}): {', '.join(names[:20])}"
                + (" …" if len(names) > 20 else "")
            )
        lines.append("")

    errors = data.get("extraction_errors") or []
    if errors:
        lines += ["## Extraction Warnings", ""] + [f"- `{e}`" for e in errors] + [""]
    return "\n".join(lines)


def register_posture_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register Posture Management and Incidents tools."""
    tool = scm_tool(get_client)
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_incident_search(
        client: Any,
        tenant_id: str,
        severity: str = "",
        status: str = "",
        product: str = "",
        acknowledged: str = "",
        days: int = 30,
        limit: int = 100,
        all_tenants: bool = False,
    ) -> str:
        """Search SCM security incidents via the Incidents API (March 2026).

        Queries `POST /incidents/v1/search` for security incidents raised by
        Strata Cloud Manager across Prisma Access, NGFW, and SCM platform events.
        Returns a prioritised incident table sorted by severity and raise time.

        Incident types include: dataplane upgrades, tunnel failures, certificate
        expiry, licence issues, threat events, and platform health events.

        Args:
            severity: Comma-separated filter — Critical,High,Medium,Low
                      (e.g. "Critical,High"). Empty = all severities.
            status: Comma-separated filter — Open,Closed,Acknowledged.
                    Empty = all statuses.
            product: Filter by product — "Prisma Access", "SCM", etc.
                     Empty = all products.
            acknowledged: Filter by acknowledgement — "true", "false", or "".
            days: Look-back window in days (default 30, max 180).
            limit: Max incidents to return per tenant (default 100).
            all_tenants: Sweep all configured MSSP tenants.
            tenant_id: Specific tenant ID. Defaults to active tenant.
        """
        try:
            sev_filter = (
                {s.strip().title() for s in severity.split(",") if s.strip()} if severity else set()
            )
            stat_filter = (
                {s.strip().title() for s in status.split(",") if s.strip()} if status else set()
            )
            prod_filter = product.strip().lower() if product.strip() else ""
            ack_filter = acknowledged.strip().lower()

            all_rows: list[tuple[int, str, dict[str, Any]]] = []
            tenant_errors: list[str] = []

            if all_tenants:
                tenant_map = _load_tenant_configs()
                targets = []
                for k, tc in tenant_map.items():
                    label = tc.label or k
                    try:
                        targets.append((k, label, get_scm_client(tc)))
                    except Exception as exc:
                        # A single tenant with bad/rotated credentials shouldn't
                        # abort the whole cross-tenant sweep.
                        tenant_errors.append(f"{label}: {exc}")
            else:
                targets = [(tenant_id or "default", tenant_id or "default", client)]

            for _key, label, c in targets:
                try:
                    session = getattr(c, "session", None)
                    if not session:
                        continue
                    incidents = _incidents_for_tenant(session, label)
                    for inc in incidents:
                        sev = str(inc.get("severity") or "")
                        stat = str(inc.get("status") or "")
                        prod = str(inc.get("product") or "")
                        ack = inc.get("acknowledged")

                        if sev_filter and sev.title() not in sev_filter:
                            continue
                        if stat_filter and stat.title() not in stat_filter:
                            continue
                        if prod_filter and prod_filter not in prod.lower():
                            continue
                        if ack_filter == "true" and not ack:
                            continue
                        if ack_filter == "false" and ack:
                            continue

                        sort_key = _SEV_ORDER.get(sev.title(), 99)
                        inc["_tenant_label"] = label
                        all_rows.append((sort_key, str(inc.get("raised_time") or ""), inc))
                except Exception as exc:
                    tenant_errors.append(f"{label}: {exc}")

            # Sort: severity asc, then raised_time desc
            all_rows.sort(key=lambda x: (x[0], x[1]))
            all_rows = all_rows[:limit]

            ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
            sev_desc = f" severity={severity}" if severity else ""
            stat_desc = f" status={status}" if status else ""
            lines = [
                f"## SCM Incidents{sev_desc}{stat_desc} — last {days}d",
                "",
                f"*Queried: {ts}  |  Results: {len(all_rows)}*",
                "",
            ]

            if not all_rows:
                lines.append("No incidents found matching the specified filters. ✅")
            else:
                multi = all_tenants and len(targets) > 1
                cols = (
                    "| Sev | Raised | Status | Title | Product | Category | Tenant |"
                    if multi
                    else "| Sev | Raised | Status | Title | Product | Category |"
                )
                sep = "|---|---|---|---|---|---|---|" if multi else "|---|---|---|---|---|---|"
                lines += [cols, sep]

                for _, _, inc in all_rows:
                    sev = inc.get("severity") or "—"
                    emoji = _sev_emoji(sev)
                    raised = _fmt_ts(str(inc.get("raised_time") or ""))
                    stat = inc.get("status") or "—"
                    title = str(inc.get("title") or "—")[:60]
                    prod = inc.get("product") or "—"
                    cat = inc.get("category") or "—"
                    ack_mark = " ✓" if inc.get("acknowledged") else ""
                    row = f"| {emoji} {sev} | {raised} | {stat}{ack_mark} | {title} | {prod} | {cat} |"
                    if multi:
                        row += f" {inc.get('_tenant_label', '—')} |"
                    lines.append(row)

            if tenant_errors:
                lines += ["", "**Errors:**"]
                for e in tenant_errors:
                    lines.append(f"- {e}")

            return "\n".join(lines)

        except Exception as exc:
            return f"Error: {handle_scm_exception(exc, tool='scm_incident_search', tenant_id=tenant_id)}"

    @mcp.tool()
    @tool
    def scm_incident_summary(
        client: Any, tenant_id: str, days: int = 7, all_tenants: bool = True
    ) -> str:
        """Cross-tenant SCM incident NOC dashboard.

        Fetches incidents from all (or a single) MSSP tenant and produces
        a traffic-light summary table: count of Critical/High/Medium/Low/Total
        incidents per tenant alongside the most recent open critical incident title.

        Ideal for morning NOC briefings and MSSP SLA reporting.

        Args:
            days: Look-back window in days (default 7).
            all_tenants: Sweep all configured tenants (default True).
            tenant_id: Specific tenant ID when all_tenants=False.
        """
        try:
            if all_tenants:
                tenant_map = _load_tenant_configs()
                targets: list[tuple[str, str, Any]] = []
                for k, tc in tenant_map.items():
                    label = tc.label or k
                    try:
                        targets.append((k, label, get_scm_client(tc)))
                    except Exception as exc:
                        # A single tenant with bad/rotated credentials shouldn't
                        # abort the whole cross-tenant dashboard — surface it as
                        # a per-tenant error row instead (the "no session" branch
                        # below already handles a None client gracefully).
                        logger.warning(
                            "incident_summary_tenant_auth_failed", tenant=k, error=str(exc)
                        )
                        targets.append((k, label, None))
            else:
                targets = [(tenant_id or "default", tenant_id or "default", client)]

            ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
            lines = [
                f"## SCM Incident Summary — last {days}d  ({ts})",
                "",
                "| Tenant | 🔴 Crit | 🟠 High | 🟡 Med | 🔵 Low | Total | Latest Critical |",
                "|---|---|---|---|---|---|---|",
            ]

            for _key, label, c in targets:
                try:
                    session = getattr(c, "session", None)
                    if not session:
                        lines.append(f"| {label} | — | — | — | — | — | no session |")
                        continue
                    incidents = _incidents_for_tenant(session, label)
                    counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
                    latest_crit: str = "—"
                    for inc in incidents:
                        sev = str(inc.get("severity") or "").title()
                        if sev in counts:
                            counts[sev] += 1
                        if sev == "Critical" and inc.get("status", "").lower() != "closed":
                            t = str(inc.get("title") or "")[:40]
                            if latest_crit == "—":
                                latest_crit = t
                    total = sum(counts.values())
                    crit_cell = f"**{counts['Critical']}**" if counts["Critical"] else "0"
                    high_cell = f"**{counts['High']}**" if counts["High"] else "0"
                    lines.append(
                        f"| {label} | {crit_cell} | {high_cell} | "
                        f"{counts['Medium']} | {counts['Low']} | {total} | {latest_crit} |"
                    )
                except Exception as exc:
                    lines.append(f"| {label} | — | — | — | — | — | Error: {str(exc)[:50]} |")

            return "\n".join(lines)

        except Exception as exc:
            return f"Error: {handle_scm_exception(exc, tool='scm_incident_summary', tenant_id=tenant_id)}"

    @mcp.tool()
    @tool
    def scm_posture_report(client: Any, folder: str = "Shared") -> str:
        """Retrieve SCM Posture Management best-practice report findings.

        Queries the Posture Management API (`/posture/v1/reports`) introduced
        March 2026. Returns security posture findings across SCM-managed devices
        including policy gaps, configuration drift, and compliance deviations.

        **Note:** Requires the Posture Management add-on licence for your SCM
        subscription. Contact your PAN account team or MSSP admin to enable.
        The Posture Management API currently covers the Best Practice Report
        module; Compliance, Policy Optimizer, Policy Analyzer, and Config Cleanup
        modules are in development.

        Args:
            folder: SCM folder scope (default "Shared").
            tenant_id: SCM tenant ID. Defaults to active tenant.
        """
        session = getattr(client, "session", None)
        if not session:
            return "Error: no HTTP session available on SCM client."

        url = f"{_INC_BASE}{_POSTURE_BASE}"
        params: dict[str, str] = {}
        if folder:
            params["folder"] = folder

        resp = session.get(url, params=params, timeout=(10, 30))

        if resp.status_code == 403:
            from contextlib import suppress

            body: dict[str, Any] = {}
            with suppress(Exception):
                body = resp.json()
            msg = body.get("msg") or body.get("message") or "Access denied"
            return f"**Posture Management API — {msg}**\n{_LICENSE_HINT}"

        resp.raise_for_status()
        data = resp.json()

        ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        lines = [
            f"## SCM Posture Report — {folder}",
            "",
            f"*Retrieved: {ts}*",
            "",
        ]

        reports = data if isinstance(data, list) else data.get("data", [data])
        if not reports:
            lines.append("No posture report data available for this folder.")
            return "\n".join(lines)

        for report in reports[:5]:
            if isinstance(report, dict):
                name = report.get("name") or report.get("id") or "Report"
                status = report.get("status") or report.get("state") or "—"
                score = report.get("score") or report.get("overall_score") or "—"
                lines += [
                    f"### {name}",
                    "",
                    f"**Status:** {status}  |  **Score:** {score}",
                    "",
                    "```json",
                    json.dumps(report, indent=2, default=str)[:1000],
                    "```",
                    "",
                ]
            else:
                lines += ["```json", json.dumps(report, default=str)[:500], "```", ""]

        return "\n".join(lines)

    @mcp.tool()
    @tool
    def scm_saas_posture(
        client: Any,
        tenant_id: str,
        include_catalog: bool = False,
        save_to: str = "",
        load_from: str = "",
    ) -> str:
        """SaaS Security Posture (SSPM): app posture, findings, and IdPs.

        Queries the SSPM API for onboarded SaaS applications with their
        per-app misconfiguration findings (severity-ranked), the supported
        app catalog, and Identity-SSPM IdP/NHI posture, and renders a
        markdown summary. Unlicensed / unprovisioned tenants are reported
        clearly rather than erroring.

        Manual export/import:
        - `save_to`: also write the raw posture snapshot (apps + findings +
          IdPs + catalog) to a JSON file for archiving, diffing between
          runs, or sharing.
        - `load_from`: render a previously exported JSON file instead of
          calling the API — offline review of an archived snapshot.

        Args:
            tenant_id: SCM tenant ID (MSSP mode). Ignored with load_from.
            include_catalog: Also list the supported-app catalog by vertical.
            save_to: Path to export the snapshot JSON to.
            load_from: Path of a previous export to render instead of live data.

        Returns:
            Markdown posture summary (plus export confirmation when saved).
        """
        try:
            if load_from:
                data = json.loads(Path(load_from).read_text())
                if data.get("format") != _SAAS_POSTURE_FORMAT:
                    return (
                        f"Error: {load_from} is not a saas-posture export "
                        f"(expected format marker {_SAAS_POSTURE_FORMAT!r})"
                    )
                source = (
                    f"imported file `{load_from}` — tenant {data.get('tenant_id', '?')}, "
                    f"exported {_fmt_ts(data.get('exported_at'))}"
                )
            else:
                from ..audit.extractor import extract_identity_sspm, extract_sspm
                from ..audit.models import AuditSnapshot

                snap = AuditSnapshot(folder="", tenant_id=tenant_id or "default")
                extract_sspm(client, snap)
                extract_identity_sspm(client, snap)
                data = {
                    "format": _SAAS_POSTURE_FORMAT,
                    "exported_at": datetime.now(UTC).isoformat(),
                    "tenant_id": tenant_id or "default",
                    "sspm_licensed": snap.sspm_licensed,
                    "identity_sspm_licensed": snap.identity_sspm_licensed,
                    "apps": snap.sspm_apps,
                    "idps": snap.identity_sspm_idps,
                    "catalog": snap.sspm_catalog,
                    "extraction_errors": snap.extraction_errors,
                }
                source = f"live SSPM API, {_fmt_ts(data['exported_at'])}"

            saved = ""
            if save_to:
                out = Path(save_to)
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(json.dumps(data, indent=2, default=str))
                saved = f"\n\n_Snapshot exported → `{out}` ({out.stat().st_size} bytes)_"

            return _render_saas_posture(data, source, include_catalog) + saved
        except Exception as exc:
            return (
                f"Error: {handle_scm_exception(exc, tool='scm_saas_posture', tenant_id=tenant_id)}"
            )
