"""MCP tool for the MSR — Monthly Service Review pack (``scm_msr_report``).

Assembles the per-tenant monthly customer deliverable from sources the
server already produces: period-bounded incidents and config jobs, the
SSR provenance ledger, compliance posture, licence
expiry, and the Insights bandwidth snapshot. Every source degrades
gracefully — a licence-API outage costs one section, not the pack. When
``mssp_tenant_capabilities`` has a cached verdict that a family is
forbidden/unprovisioned, that section is skipped up front instead.

Pure period/SLA/rendering logic lives in ``audit/msr_report.py``.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..audit.extractor import _bearer_session_for, extract_adem
from ..audit.insights_extractor import extract_insights
from ..audit.models import AuditSnapshot
from ..audit.msr_report import (
    MsrData,
    fallback_window_days,
    in_period,
    merge_bw_allocation,
    month_bounds,
    month_window_filter,
    parse_ssr_notes,
    render_msr_report,
    summarize_mu_locations,
)
from ..auth.oauth import fetch_licenses
from ..config.settings import load_all_tenant_configs
from ..utils.capabilities import capability_skip_reason
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool
from .compliance import _compliance_get
from .insights import _INSIGHTS_BASE_V3, _insights_call, _refresh_token, region_header
from .mt_monitor import _BASE as _MT_BASE
from .ops import _licence_rows
from .posture import _incidents_for_tenant
from .ssr import _get_ssr_config, _resolve_default_folder

logger = get_logger(__name__)

# ssr_objects key → (SCM SDK resource attribute, fetch kwarg style)
_SSR_OBJECT_RESOURCES = {
    "url_allow_list": "url_category",
    "url_block_list": "url_category",
    "anti_spyware_profile": "anti_spyware_profile",
    "vulnerability_protection_profile": "vulnerability_protection_profile",
    "ssl_decrypt_exclude_rule": "decryption_rule",
}


def _insights_try(
    session: Any, path: str, tenant_id: str, body: dict | None, region: str
) -> tuple[int, Any]:
    """``_insights_call`` that returns ``(-1, error)`` instead of raising.

    The Insights backend answers HTTP 500 (until urllib3's retry adapter
    gives up and raises) on filter shapes it can't inline into its SQL
    template — a failed query attempt must fall through to the fallback
    window, not abort the section.
    """
    try:
        return _insights_call(session, path, tenant_id, body, region)
    except Exception as exc:
        return -1, str(exc)


class _CapabilitySkipped(RuntimeError):
    """A section skipped up front because a cached capability probe rules it out.

    Raised inside a section's ``try`` so the existing per-section degradation
    records the reason in ``data.errors`` (and so the §11 coverage table).
    """


def _require_capability(tenant_id: str, family: str) -> None:
    """Raise :class:`_CapabilitySkipped` when the cache marks *family* unusable."""
    reason = capability_skip_reason(tenant_id, family)
    if reason is not None:
        raise _CapabilitySkipped(reason)


def _resolve_tenant_meta(tenant_id: str) -> tuple[str, str, str]:
    """Return (label, tsg_id, insights_region) for *tenant_id*.

    Same single-tenant fallback rule as the SSR tool: empty tenant_id maps
    to the first configured tenant; an explicit non-matching tenant_id
    returns empty metadata rather than another tenant's.
    """
    tenants = load_all_tenant_configs()
    tc = None
    if tenant_id:
        tc = next((t for t in tenants.values() if t.tenant_id == tenant_id), None)
    elif tenants:
        tc = next(iter(tenants.values()))
    if tc is None:
        return "", tenant_id, "eu"
    return tc.label or tc.tenant_id, tc.tenant_id, tc.insights_region


def _gather_ssr_ledger(client: Any, tenant_id: str) -> list[dict[str, str]]:
    """Parse SSR provenance notes off every configured SSR-managed object."""
    ssr_config = _get_ssr_config(tenant_id)
    if not ssr_config:
        return []
    folder = _resolve_default_folder(tenant_id)
    ledger: list[dict[str, str]] = []
    for key, obj_name in ssr_config.items():
        resource_attr = _SSR_OBJECT_RESOURCES.get(key)
        if not resource_attr or not obj_name:
            continue
        try:
            obj = getattr(client, resource_attr).fetch(name=obj_name, folder=folder)
            desc = (obj.model_dump() or {}).get("description") or ""
            ledger.extend(parse_ssr_notes(desc, obj_name))
        except Exception as exc:
            logger.warning("msr_ssr_object_failed", object=obj_name, error=str(exc))
    return ledger


def gather_msr_data(
    client: Any,
    tenant_id: str = "",
    month: str = "",
    mssp_name: str = "MSSP",
    include_insights: bool = True,
) -> MsrData:
    """Gather every MSR source for the period, degrading per-source."""
    start, end, label = month_bounds(month)
    tenant_label, tsg_id, region = _resolve_tenant_meta(tenant_id)
    data = MsrData(
        tenant_label=tenant_label,
        tenant_id=tsg_id,
        mssp_name=mssp_name,
        period_start=start,
        period_end=end,
        period_label=label,
    )

    # ── Incidents (period-bounded) ──────────────────────────────────────
    try:
        _require_capability(tsg_id, "incidents")
        session = getattr(client, "session", None)
        if session is None:
            raise RuntimeError("client has no HTTP session")
        raw = _incidents_for_tenant(session, tenant_label)
        data.incidents = [i for i in raw if in_period(i.get("raised_time"), start, end)]
        data.gathered.append(f"incidents — {len(data.incidents)} in period (Incidents API)")
    except Exception as exc:
        data.errors["incidents"] = str(exc)

    # ── Config jobs (period-bounded) ────────────────────────────────────
    try:
        _require_capability(tsg_id, "config_jobs")
        response = client.list_jobs(limit=200)
        jobs = response.data if hasattr(response, "data") else []
        rows = [
            {
                "job_id": getattr(j, "id", ""),
                "type": getattr(j, "type_str", getattr(j, "job_type", "")),
                "result": getattr(j, "result_str", ""),
                "user": getattr(j, "uname", ""),
                "description": getattr(j, "description", ""),
                "start_ts": str(getattr(j, "start_ts", "")),
                "end_ts": str(getattr(j, "end_ts", "")),
            }
            for j in jobs
        ]
        data.jobs = [r for r in rows if in_period(r["start_ts"], start, end)]
        data.gathered.append(f"config jobs — {len(data.jobs)} in period (Jobs API)")
    except Exception as exc:
        data.errors["jobs"] = str(exc)

    # ── SSR ledger (cumulative provenance) ──────────────────────────────
    try:
        data.ssr_ledger = _gather_ssr_ledger(client, tenant_id)
        if data.ssr_ledger:
            data.gathered.append(f"SSR ledger — {len(data.ssr_ledger)} provenance notes")
    except Exception as exc:
        data.errors["ssr_ledger"] = str(exc)

    # ── Licences ────────────────────────────────────────────────────────
    try:
        _require_capability(tsg_id, "licensing")
        data.licence_rows = _licence_rows(fetch_licenses(client))
        data.gathered.append(f"licences — {len(data.licence_rows)} SKU groups (Subscription API)")
    except Exception as exc:
        data.errors["licences"] = str(exc)

    # ── Bandwidth + connected MU (Insights snapshot) ────────────────────
    insights_skip = capability_skip_reason(tsg_id, "insights") if include_insights else None
    if include_insights and insights_skip is None:
        try:
            ins = extract_insights(client, tenant_id=tsg_id, region=region)
            data.bandwidth_rows = list(ins.location_rn_bandwidth) + list(ins.location_sc_bandwidth)
            data.connected_mu = ins.connected_mu_count if ins.connected_mu_count >= 0 else None
            # Only bandwidth-endpoint failures belong in this section's error —
            # extract_insights also probes MU/tunnel/alert endpoints whose
            # errors (RBAC 403s etc.) must not mask a legitimate 0-row result.
            bw_errors = [e for e in ins.errors if "_bw" in e or "bandwidth" in e]
            if bw_errors and not data.bandwidth_rows:
                data.errors["bandwidth"] = "; ".join(bw_errors[:3])
            else:
                data.gathered.append(
                    f"bandwidth — {len(data.bandwidth_rows)} location rows (Insights v3, 24h window)"
                )
        except Exception as exc:
            data.errors["bandwidth"] = str(exc)

        # ── Month-window RN bandwidth vs allocation ─────────────────────
        try:
            session = getattr(client, "session", None)
            if session is None:
                raise RuntimeError("client has no HTTP session")
            _refresh_token(client)
            mapped = region_header(region) or "europe"
            path = f"{_INSIGHTS_BASE_V3}/query/locations/location_rn_bandwidth"
            status, resp = _insights_try(
                session, path, tsg_id, month_window_filter(start, end), mapped
            )
            window = f"{label} (calendar month)"
            if status != 200:
                # Resource rejected the between filter — honest fallback window
                days = fallback_window_days(start)
                fb = {
                    "filter": {
                        "rules": [
                            {
                                "property": "event_time",
                                "operator": "last_n_days",
                                "values": [str(days)],
                            }
                        ]
                    }
                }
                status, resp = _insights_try(session, path, tsg_id, fb, mapped)
                window = f"last {days} days (month filter unsupported)"
            if status != 200:
                raise RuntimeError(f"HTTP {status}: {str(resp)[:200]}")
            month_rows = resp.get("data") if isinstance(resp, dict) else None
            data.bw_month_rows = list(month_rows or [])
            data.bw_month_window = window

            try:
                allocs = client.bandwidth_allocation.list()
                data.bw_allocations = [
                    {
                        "name": getattr(a, "name", None),
                        "allocated_mbps": getattr(a, "allocated_bandwidth", None),
                    }
                    for a in allocs
                ]
            except Exception as alloc_exc:
                logger.warning("msr_bw_allocations_failed", error=str(alloc_exc))

            data.bw_month_rows = merge_bw_allocation(data.bw_month_rows, data.bw_allocations)
            data.gathered.append(
                f"bandwidth vs allocation — {len(data.bw_month_rows)} rows, "
                f"{len(data.bw_allocations)} allocations ({window})"
            )
        except Exception as exc:
            data.errors["bandwidth_month"] = str(exc)

        # ── Mobile users in period (count + location breakdown) ─────────
        try:
            session = getattr(client, "session", None)
            if session is None:
                raise RuntimeError("client has no HTTP session")
            _refresh_token(client)
            mapped = region_header(region) or "europe"
            win: dict[str, Any] = month_window_filter(start, end)
            window = f"{label} (calendar month)"
            cpath = f"{_INSIGHTS_BASE_V3}/query/users/agent/connected_user_count"
            status, resp = _insights_try(session, cpath, tsg_id, win, mapped)
            if status != 200:
                days = fallback_window_days(start)
                win = {
                    "filter": {
                        "rules": [
                            {
                                "property": "event_time",
                                "operator": "last_n_days",
                                "values": [str(days)],
                            }
                        ]
                    }
                }
                window = f"last {days} days"
                status, resp = _insights_try(session, cpath, tsg_id, win, mapped)
            if status == 200 and isinstance(resp, dict):
                mu_rows = resp.get("data") or []
                first = mu_rows[0] if mu_rows else {}
                count = next(
                    (
                        v
                        for v in first.values()
                        if isinstance(v, int | float) and not isinstance(v, bool)
                    ),
                    None,
                )
                if count is not None:
                    data.mu_month_users = int(count)
                    data.mu_month_window = window
            # Location breakdown from user_list, with whichever window worked
            lpath = f"{_INSIGHTS_BASE_V3}/query/users/agent/user_list"
            lstatus, lresp = _insights_try(session, lpath, tsg_id, win, mapped)
            if lstatus == 200 and isinstance(lresp, dict):
                data.mu_month_locations = summarize_mu_locations(lresp.get("data") or [])
                if not data.mu_month_window:
                    data.mu_month_window = window
            if data.mu_month_users is not None or data.mu_month_locations:
                count_s = data.mu_month_users if data.mu_month_users is not None else "?"
                data.gathered.append(
                    f"mobile users — {count_s} unique, "
                    f"{len(data.mu_month_locations)} location(s) ({window})"
                )
            else:
                data.errors["mobile_users"] = f"HTTP {status} on connected_user_count"
        except Exception as exc:
            data.errors["mobile_users"] = str(exc)
    else:
        why = insights_skip or "skipped (include_insights=False)"
        data.errors["bandwidth"] = why
        data.errors["bandwidth_month"] = why
        data.errors["mobile_users"] = why

    # ── ADEM experience snapshot (3-day window, falls back to 30-day) ───
    try:
        _require_capability(tsg_id, "adem")
        snap = AuditSnapshot(folder="", tenant_id=tsg_id)
        extract_adem(client, snap)
        if snap.adem_agent_summary:
            data.adem_summary = {
                "agents": snap.adem_agent_summary,
                "errors": snap.adem_errors,
                "timerange_used": snap.adem_timerange_used,
            }
            _window = "3-day" if snap.adem_timerange_used == "last_3_day" else "30-day"
            data.gathered.append(
                f"ADEM — {len(snap.adem_agent_summary)} agent scope(s) ({_window} window)"
            )
        elif snap.adem_errors:
            data.errors["adem"] = "; ".join(snap.adem_errors[:2])
    except Exception as exc:
        data.errors["adem"] = str(exc)

    # ── Blocked security events (Monitor API threat summary) ────────────
    try:
        mt_session = _bearer_session_for(client)
        days = fallback_window_days(start)
        body = {
            "filter": {
                "operator": "AND",
                "rules": [
                    {
                        "operator": "in",
                        "property": "severity",
                        "values": ["Critical", "High", "Medium"],
                    },
                    {"operator": "last_n_days", "property": "event_time", "values": [days]},
                ],
            },
            "properties": [{"property": "total_threats"}, {"property": "blocked_count"}],
        }
        mapped = region_header(region) or "europe"
        candidates = [mapped, *{"europe": ["uk"], "uk": ["europe"]}.get(mapped, [])]
        for cand in candidates:
            resp = mt_session.post(
                f"{_MT_BASE}/threats/summary",
                params={"agg_by": "tenant"},
                headers={"X-PANW-Region": cand},
                json=body,
                timeout=(5, 30),
            )
            if resp.status_code != 200:
                continue
            threat_rows = (resp.json() or {}).get("data") or []
            if threat_rows:
                total = sum(r.get("total_threats") or 0 for r in threat_rows)
                blocked = sum(r.get("blocked_count") or 0 for r in threat_rows)
                data.threat_summary = {
                    "total_threats": total,
                    "blocked_count": blocked,
                    "window_days": days,
                }
                data.gathered.append(
                    f"security events — {blocked} blocked of {total} threats "
                    f"(last {days}d, Monitor API)"
                )
                break
        if not data.threat_summary:
            data.errors["security_events"] = "no threat rows returned (Monitor API)"
    except Exception as exc:
        data.errors["security_events"] = str(exc)

    # ── Compliance (framework scores + 30-day trend annex) ────────────
    try:
        _require_capability(tsg_id, "compliance")
        raw = _compliance_get(client, "/summaries", {"product": "all"}, tenant_id=tsg_id)
        items = raw if isinstance(raw, list) else (raw or {}).get("data") or []
        data.compliance_summaries = items
        data.gathered.append(f"compliance — {len(items)} frameworks (Compliance Center API)")
        bench = next((i for i in items if i.get("benchmark")), None)
        if bench:
            revisions = bench.get("revision_summary") or []
            data.compliance_framework_name = str(
                (revisions[0] if revisions else {}).get("name") or bench.get("id") or ""
            )
            tl = _compliance_get(
                client,
                f"/overall-compliance-timeline/{bench.get('id')}",
                {"product": "all"},
                tenant_id=tsg_id,
            )
            data.compliance_timeline = (tl or {}).get("timeline_30_days") or []
    except Exception as exc:
        data.errors["compliance"] = str(exc)

    return data


def register_msr_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register the MSR tool — ``scm_msr_report``."""
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_msr_report(
        client: Any,
        tenant_id: str,
        month: str = "",
        mssp_name: str = "MSSP",
        output_format: str = "markdown",
        save_to: str = "",
        include_insights: bool = True,
    ) -> str:
        """Generate the Monthly Service Review pack for a customer tenant.

        Assembles the monthly customer deliverable from live tenant data:

          1. Executive summary — ranked headline bullets (worst first)
          2. Service statistics — incidents, MTTR, ack rate, commit count,
             change failure rate, unique mobile users
          3. Incidents raised in the period (severity-ranked)
          4. Change record — config jobs in period + cumulative SSR ledger
          5. Compliance posture — framework scores + 30-day score trend
          6. Licence & renewal posture — expiry countdown within 180 days
          7. Bandwidth vs allocation — per-RN-location usage over the month
             compared against the region's allocated bandwidth
          8. Mobile users — unique logins in period + location breakdown
          9. Digital experience — ADEM agent scores (3-day telemetry window)
          10. Security events — threats detected/blocked summary
          11. Data-source coverage — what was gathered vs unavailable

        Every source degrades gracefully: an unavailable API costs one
        section (disclosed in §11), never the whole pack.

        Args:
            tenant_id: SCM tenant ID. Defaults to the first configured tenant.
            month: Review period as ``YYYY-MM`` (e.g. "2026-06"). Defaults to
                   the previous full calendar month.
            mssp_name: Service-provider name for the header.
            output_format: 'markdown' (default) or 'docx' (pandoc via the
                           bundled pypandoc-binary).
            save_to: Optional output path. Defaults for docx to
                     'reports/<tenant>-msr-<period>.docx'; markdown returns
                     inline unless a path is given.
            include_insights: Set False to skip the Insights bandwidth/MU
                              calls (faster; §7 is marked skipped).
        """
        try:
            start_end_label = month_bounds(month)
        except ValueError as exc:
            return f"Error: {exc}"
        period_label = start_end_label[2]

        data = gather_msr_data(
            client,
            tenant_id=tenant_id,
            month=month,
            mssp_name=mssp_name,
            include_insights=include_insights,
        )
        report_md = render_msr_report(data)

        if output_format.lower() == "docx":
            from .audit import _md_to_docx

            slug = re.sub(r"[^a-zA-Z0-9-]+", "-", data.tenant_label or "tenant").strip("-").lower()
            out_path = (
                Path(save_to) if save_to else Path("reports") / f"{slug}-msr-{period_label}.docx"
            )
            try:
                result = _md_to_docx(report_md, out_path)
            except Exception as exc:
                return f"Error converting to DOCX: {exc}\n\n{report_md}"
            return f"MSR pack for {data.tenant_label} ({period_label}) saved to `{result}`."

        if save_to:
            Path(save_to).parent.mkdir(parents=True, exist_ok=True)
            Path(save_to).write_text(report_md)
            return f"MSR pack for {data.tenant_label} ({period_label}) saved to `{save_to}`."
        return report_md
