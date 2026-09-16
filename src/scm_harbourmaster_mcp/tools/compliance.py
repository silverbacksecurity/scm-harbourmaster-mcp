"""MCP tools for PAN Compliance Center API (released 2026-07-14).

Two tools covering 15 endpoints:

    scm_compliance_center    — read-side analytics: frameworks, summaries, scores,
                               timeline, controls, assessed configs, benchmark
                               monitoring, framework detail
    scm_compliance_framework — write-side CRUD: create, update, delete, clone,
                               benchmark, un-benchmark

The API base is ``https://api.strata.paloaltonetworks.com/posture/compliance-frameworks/v1``.
Since it is a brand-new product surface, most lab tenants will not yet hold the
entitlement — the tool detects 401/403 and returns a clear licence-hint message
rather than a raw HTTP error (same pattern as ``scm_posture_report`` in posture.py).
"""

from __future__ import annotations

import contextlib
import json
import threading
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

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_COMPLIANCE_BASE = "https://api.strata.paloaltonetworks.com/posture/compliance-frameworks/v1"
_TIMEOUT = (10, 30)
_LONG_TIMEOUT = (15, 60)

_LICENSE_HINT = (
    "\n\nThis feature requires the **Compliance Center** add-on licence for your "
    "Strata Cloud Manager subscription. Contact your PAN account team or MSSP admin to enable."
)

# The Compliance API documents X-PANW-Region as required, but does not enforce
# it: a missing, empty, misspelled or wrongly-cased value all return HTTP 200
# with an *empty* payload (overall_score -1, data_available false, zero counts)
# rather than an error. Sending the right value is therefore the difference
# between real data and a report full of zeroes that looks legitimate.
#
# The vocabulary is case-sensitive and differs from Prisma Access Insights:
# "uk" works, "UK"/"eu"/"us"/"gb" do not.
_COMPLIANCE_REGIONS = ("americas", "europe", "uk", "au")

# tenant_id -> (region, how_it_was_resolved). "" means "no region found";
# cached either way so discovery runs at most once per tenant per process.
_region_cache: dict[str, tuple[str, str]] = {}
_region_lock = threading.Lock()

_ACTIONS_HELP = """\
Valid actions for scm_compliance_center (read-side):
  list-frameworks   — list all compliance frameworks
  summaries         — framework summaries with scores and benchmark status
  scores            — overall/industry compliance scores by product + category
  timeline          — 30-day + 1-year compliance score trend
  controls          — per-control pass/fail detail with severity
  assessed          — check, assessment, and exception counts
  framework-detail  — full framework hierarchy (JSON)
  benchmark-monitoring — live BPC monitoring data

Valid actions for scm_compliance_framework (write-side):
  create            — create a new compliance framework
  update            — update an existing framework
  delete            — delete a framework
  clone             — clone a framework
  benchmark         — mark a framework as benchmark
  un-benchmark      — remove benchmark designation"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bearer_session(client: Any) -> Any:
    """Return the SDK client's requests session, refreshing the token first.

    Falls back to a plain ``requests.Session`` with a freshly extracted Bearer
    token when the SDK's OAuth2 session raises on ``api.strata`` endpoints.
    """
    import requests as _requests

    oauth = getattr(client, "oauth_client", None)
    if oauth is not None:
        with contextlib.suppress(Exception):
            oauth.refresh_token()

    # Try the SDK's native session first (works for most api.sase endpoints)
    sdk_session = getattr(client, "session", None)
    if sdk_session is not None:
        # Quick smoke test — if the session is usable, return it
        try:
            token = getattr(sdk_session, "token", None)
            if token and token.get("access_token"):
                return sdk_session
        except Exception:
            pass

    # Fallback: plain requests.Session with bearer token
    token = None
    if sdk_session is not None:
        raw = getattr(sdk_session, "token", None) or {}
        token = raw.get("access_token")

    sess = _requests.Session()
    if token:
        sess.headers["Authorization"] = f"Bearer {token}"
    return sess


def _configured_region(tenant_id: str) -> str:
    """The tenant's explicitly configured compliance_region, or ""."""
    if not tenant_id:
        return ""
    try:
        from ..auth.oauth import get_tenant_meta

        meta = get_tenant_meta(tenant_id)
    except Exception:
        return ""
    return (getattr(meta, "compliance_region", "") or "").strip().lower() if meta else ""


def _discover_region(client: Any, tenant_id: str) -> str:
    """Probe the documented regions and return the one holding this tenant's data.

    Compliance *definitions* are global (the same predefined frameworks answer
    in every region), so they cannot be used to identify the right one. The
    per-tenant assessment results are regional, and ``data_available`` on
    ``/overall-compliance`` is an explicit flag for exactly that — so pick a
    framework from /summaries, then ask each region whether it holds results.

    Costs at most four extra GETs, once per tenant per process. Returns "" if
    no region has data, which is a legitimate state for an unassessed tenant.
    """
    session = _bearer_session(client)
    try:
        resp = session.get(f"{_COMPLIANCE_BASE}/summaries", timeout=_TIMEOUT)
        if resp.status_code != 200:
            return ""
        rows = (resp.json() or {}).get("data") or []
        framework_id = next((r.get("id") for r in rows if r.get("id")), None)
        if not framework_id:
            return ""

        for region in _COMPLIANCE_REGIONS:
            probe = session.get(
                f"{_COMPLIANCE_BASE}/overall-compliance/{framework_id}",
                headers={"X-PANW-Region": region},
                timeout=_TIMEOUT,
            )
            if probe.status_code != 200:
                continue
            products = (probe.json() or {}).get("products") or {}
            if any(p.get("data_available") for p in products.values() if isinstance(p, dict)):
                logger.info("compliance_region_discovered", tenant_id=tenant_id, region=region)
                return region
    except Exception as exc:  # discovery is best-effort — never break the call
        logger.warning("compliance_region_discovery_failed", tenant_id=tenant_id, error=str(exc))
    return ""


def _resolve_region(client: Any, tenant_id: str) -> tuple[str, str]:
    """Return (region, source) for *tenant_id*, discovering it once if needed."""
    key = tenant_id or "<default>"
    with _region_lock:
        cached = _region_cache.get(key)
    if cached is not None:
        return cached

    configured = _configured_region(tenant_id)
    result = (
        (configured, "configured")
        if configured
        else (_discover_region(client, tenant_id), "auto-detected")
    )
    if not result[0]:
        result = ("", "none")

    with _region_lock:
        _region_cache[key] = result
    return result


def _reset_region_cache() -> None:
    """Drop every cached region. Used by tests and after a settings reload."""
    with _region_lock:
        _region_cache.clear()


def _region_headers(client: Any, tenant_id: str) -> dict[str, str]:
    """X-PANW-Region header for this tenant, or {} when no region is known."""
    region, _ = _resolve_region(client, tenant_id)
    return {"X-PANW-Region": region} if region else {}


def _region_note(client: Any, tenant_id: str) -> str:
    """One-line provenance footer so an empty report is never mistaken for a clean one."""
    region, source = _resolve_region(client, tenant_id)
    if region:
        return f"*Data region: `{region}` ({source}).*"
    return (
        "> ⚠️ **No data region identified for this tenant.** The Compliance API returns "
        "an empty result set (scores of `N/A`, zero counts) rather than an error when it "
        "is queried without a matching region, so the figures below may be blank for that "
        "reason rather than because the tenant is non-compliant. Set `compliance_region` "
        f"for this tenant in settings.toml — one of: {', '.join(_COMPLIANCE_REGIONS)}."
    )


def _compliance_get(
    client: Any, path: str, params: dict[str, str] | None = None, tenant_id: str = ""
) -> Any:
    """GET *path* under the Compliance Center base, returning parsed JSON."""
    session = _bearer_session(client)
    url = f"{_COMPLIANCE_BASE}{path}"
    resp = session.get(
        url,
        params=params or {},
        headers=_region_headers(client, tenant_id),
        timeout=_TIMEOUT,
    )

    if resp.status_code == 403:
        _raise_403(resp)
    resp.raise_for_status()
    ct = resp.headers.get("Content-Type", "")
    if "json" in ct or not ct:
        return resp.json()
    return resp.text


def _compliance_post(
    client: Any,
    path: str,
    body: Any = None,
    timeout: tuple[int, int] = _TIMEOUT,
    tenant_id: str = "",
) -> Any:
    """POST *path* with JSON *body*, returning parsed JSON or text."""
    session = _bearer_session(client)
    url = f"{_COMPLIANCE_BASE}{path}"
    resp = session.post(url, json=body, headers=_region_headers(client, tenant_id), timeout=timeout)

    if resp.status_code == 403:
        _raise_403(resp)
    resp.raise_for_status()
    ct = resp.headers.get("Content-Type", "")
    if "json" in ct or not ct:
        return resp.json()
    return resp.text


def _compliance_put(
    client: Any,
    path: str,
    body: Any = None,
    params: dict[str, str] | None = None,
    tenant_id: str = "",
) -> Any:
    """PUT *path* with JSON *body* and optional query *params*."""
    session = _bearer_session(client)
    url = f"{_COMPLIANCE_BASE}{path}"
    resp = session.put(
        url,
        json=body,
        params=params or {},
        headers=_region_headers(client, tenant_id),
        timeout=_TIMEOUT,
    )

    if resp.status_code == 403:
        _raise_403(resp)
    resp.raise_for_status()
    ct = resp.headers.get("Content-Type", "")
    if "json" in ct or not ct:
        return resp.json()
    return resp.text


def _compliance_delete(client: Any, path: str, tenant_id: str = "") -> str:
    """DELETE *path*. Returns a success or error string."""
    session = _bearer_session(client)
    url = f"{_COMPLIANCE_BASE}{path}"
    resp = session.delete(url, headers=_region_headers(client, tenant_id), timeout=_TIMEOUT)

    if resp.status_code == 403:
        _raise_403(resp)
    if resp.status_code == 204:
        return "✓ Deleted successfully (204 No Content)"
    resp.raise_for_status()
    return "✓ Deleted successfully"


def _raise_403(resp: Any) -> None:
    """Extract the 403 error message and raise with the licence hint."""
    body: dict[str, Any] = {}
    with contextlib.suppress(Exception):
        body = resp.json() if callable(getattr(resp, "json", None)) else {}
    # PAN error bodies nest messages differently — try common keys
    errors = body.get("_errors") or []
    msg = ""
    if errors and isinstance(errors, list):
        msg = errors[0].get("message", "") if isinstance(errors[0], dict) else str(errors[0])
    if not msg:
        msg = body.get("message") or body.get("msg") or "Access denied"
    raise PermissionError(f"**Compliance Center API — {msg}**{_LICENSE_HINT}")


# ---------------------------------------------------------------------------
# Markdown renderers
# ---------------------------------------------------------------------------


def _fmt_ts(ts: str | None) -> str:
    """Format an ISO timestamp to a compact display string."""
    if not ts:
        return "—"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return ts[:16] if ts else "—"


def _sev_name(category: int | str) -> str:
    """Map numeric severity to human-readable name."""
    try:
        c = int(category)
    except (ValueError, TypeError):
        return str(category)
    return {1: "Informational", 3: "Warning", 5: "Critical"}.get(c, str(c))


_SEV_EMOJI: dict[str, str] = {
    "critical": "🔴",
    "warning": "🟡",
    "informational": "🔵",
    "pass": "🟢",
}


def _sev_badge(sev: str) -> str:
    return f"{_SEV_EMOJI.get(sev.lower(), '⚪')} {sev.title()}"


def _score_bar(score: float | int | None) -> str:
    """Render a compliance score with a colour hint."""
    if score is None:
        return "—"
    try:
        s = float(score)
    except (ValueError, TypeError):
        return str(score)
    if s < 0:
        return "N/A"
    if s >= 90:
        return f"🟢 **{s:.0f}%**"
    if s >= 70:
        return f"🟡 **{s:.0f}%**"
    return f"🔴 **{s:.0f}%**"


# ---------------------------------------------------------------------------
# Read-side action handlers
# ---------------------------------------------------------------------------


def _do_list_frameworks(
    client: Any, category: str = "", status_filter: str = "", tenant_id: str = "", **__: Any
) -> str:
    """GET /definitions — list compliance frameworks."""
    params: dict[str, str] = {}
    if category:
        params["category"] = category
    if status_filter:
        params["status"] = status_filter

    data = _compliance_get(client, "/definitions", params, tenant_id=tenant_id)
    frameworks = data if isinstance(data, list) else (data or {}).get("data") or []

    ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "## Compliance Frameworks",
        "",
        f"*Retrieved: {ts}  |  Count: {len(frameworks)}*",
        "",
    ]

    if not frameworks:
        lines.append("No compliance frameworks found for this tenant.")
        return "\n".join(lines)

    lines += [
        "| Name | ID | Category | Status | Source |",
        "|---|---|---|---|---|",
    ]
    for fw in frameworks:
        name = str(fw.get("name") or "—")[:50]
        fw_id = str(fw.get("id") or "—")[:40]
        cat = str(fw.get("category") or "—")
        status = str(fw.get("status") or "—")
        source = str(fw.get("source") or "—")[:30]
        lines.append(f"| {name} | {fw_id} | {cat} | {status} | {source} |")

    return "\n".join(lines)


def _do_summaries(client: Any, product: str = "all", tenant_id: str = "", **__: Any) -> str:
    """GET /summaries — framework summaries with scores."""
    params: dict[str, str] = {}
    if product:
        params["product"] = product

    data = _compliance_get(client, "/summaries", params, tenant_id=tenant_id)
    items = data if isinstance(data, list) else (data or {}).get("data") or []

    ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "## Framework Summaries",
        "",
        f"*Retrieved: {ts}  |  Product: {product}  |  Count: {len(items)}*",
        _region_note(client, tenant_id),
        "",
    ]

    if not items:
        lines.append("No framework summaries available for this tenant.")
        return "\n".join(lines)

    lines += [
        "| Framework | Category | Benchmark | Latest Score | Revision | State |",
        "|---|---|---|---|---|---|",
    ]
    for item in items:
        fw_id = str(item.get("id") or "—")[:36]
        cat = str(item.get("category") or "—")
        # "benchmark_by " carries a trailing space in the upstream payload.
        benchmark_by = item.get("benchmark_by") or item.get("benchmark_by ") or ""
        benchmark = "✓" if item.get("benchmark") else "—"
        if benchmark_by:
            benchmark = f"✓ {str(benchmark_by).split('@')[0]}"

        revisions = item.get("revision_summary") or []
        latest = revisions[0] if revisions else {}
        name = str(latest.get("name") or fw_id)[:35]
        score = latest.get("overall_score")
        score_str = _score_bar(score)
        rev = str(latest.get("revision_number") or "—")[:15]
        state = str(latest.get("state") or "—")

        lines.append(f"| {name} | {cat} | {benchmark} | {score_str} | {rev} | {state} |")

    return "\n".join(lines)


def _do_scores(
    client: Any, framework_id: str = "", product: str = "all", tenant_id: str = "", **__: Any
) -> str:
    """GET /overall-compliance/{id} — compliance scores."""
    if not framework_id:
        return "Error: `framework_id` is required for the `scores` action."

    params: dict[str, str] = {}
    if product:
        params["product"] = product

    data = _compliance_get(
        client, f"/overall-compliance/{framework_id}", params, tenant_id=tenant_id
    )

    products = data.get("products") or {}
    category = data.get("category", "—")

    lines = [
        f"## Compliance Scores — {framework_id}",
        "",
        f"*Category: {category}  |  Product filter: {product}*",
        _region_note(client, tenant_id),
        "",
    ]

    # An all-empty scoreboard means "no results in the region we asked", which
    # is not the same as "nothing to report" — say so rather than printing a
    # column of N/A that reads like a genuine zero score.
    if not any(pd.get("data_available") for pd in products.values() if isinstance(pd, dict)):
        region, _src = _resolve_region(client, tenant_id)
        where = f"region `{region}`" if region else "the default region"
        lines += [
            f"> **No assessment results in {where}.** The API returned "
            "`data_available: false` for every product, so there are no scores to show. "
            "This means the framework has not been assessed in that region — it is not "
            "a compliance score of zero.",
            "",
        ]
        return "\n".join(lines)

    lines += [
        "### Scoreboard",
        "",
        "| Product | Data Available | Overall Score | Industry Score |",
        "|---|---|---|---|",
    ]

    for prod_key in ("all", "sase", "ngfw"):
        pd = products.get(prod_key, {})
        if not pd:
            continue
        name = pd.get("name", prod_key)
        available = "✓" if pd.get("data_available") else "✗"
        comp = pd.get("compliance") or {}
        overall = _score_bar(comp.get("overall_score"))
        industry = _score_bar(comp.get("industry_score"))
        lines.append(f"| {name} | {available} | {overall} | {industry} |")

        # Category breakdown
        cats = pd.get("categories") or []
        if cats:
            lines.append("")  # blank line before sub-table
            for c in cats:
                c_name = c.get("name", "—")
                c_comp = c.get("compliance") or {}
                lines.append(
                    f"| ↳ {c_name} | | {_score_bar(c_comp.get('overall_score'))} | {_score_bar(c_comp.get('industry_score'))} |"
                )

    return "\n".join(lines)


def _do_timeline(
    client: Any, framework_id: str = "", product: str = "all", tenant_id: str = "", **__: Any
) -> str:
    """GET /overall-compliance-timeline/{id} — compliance score timeline."""
    if not framework_id:
        return "Error: `framework_id` is required for the `timeline` action."

    params: dict[str, str] = {}
    if product:
        params["product"] = product

    data = _compliance_get(
        client, f"/overall-compliance-timeline/{framework_id}", params, tenant_id=tenant_id
    )

    timeline_30d = data.get("timeline_30_days") or []
    timeline_1y = data.get("timeline_1_year") or []

    lines = [
        f"## Compliance Timeline — {framework_id}",
        "",
        f"*Product filter: {product}*",
        "",
    ]

    if not timeline_30d:
        lines.append("No timeline data available.")
        return "\n".join(lines)

    lines += [
        "### 30-Day Trend",
        "",
        "| Date | Score |",
        "|---|---|",
    ]
    for entry in timeline_30d[:10]:  # latest 10 entries
        ts_micro = entry.get("ts", 0)
        try:
            dt = datetime.fromtimestamp(int(ts_micro) / 1_000_000, tz=UTC)
            date_str = dt.strftime("%Y-%m-%d")
        except (ValueError, OSError, TypeError):
            date_str = str(ts_micro)[:10]
        score = entry.get("compliance_score")
        score_str = _score_bar(score)
        lines.append(f"| {date_str} | {score_str} |")

    if len(timeline_30d) > 10:
        lines.append(f"| ... | *({len(timeline_30d) - 10} more entries)* |")

    # Summary stats
    if timeline_30d:
        scores = [
            e.get("compliance_score", -1)
            for e in timeline_30d
            if e.get("compliance_score", -1) >= 0
        ]
        if scores:
            lines += [
                "",
                f"**30d range:** {min(scores)}% – {max(scores)}%  |  "
                f"**Latest:** {scores[0]}%  |  "
                f"**1y entries:** {len(timeline_1y)}",
            ]

    return "\n".join(lines)


def _do_controls(
    client: Any, framework_id: str = "", product: str = "all", tenant_id: str = "", **__: Any
) -> str:
    """GET /compliance-controls/{id} — per-control detail."""
    if not framework_id:
        return "Error: `framework_id` is required for the `controls` action."

    params: dict[str, str] = {}
    if product:
        params["product"] = product

    data = _compliance_get(
        client, f"/compliance-controls/{framework_id}", params, tenant_id=tenant_id
    )

    meta = data.get("compliance_framework_metadata") or {}
    fw_name = meta.get("name", framework_id)
    assessment_date = meta.get("assessment_date", "—")
    controls: list[dict[str, Any]] = data.get("compliance_framework_control_groups") or []

    lines = [
        f"## Compliance Controls — {fw_name}",
        "",
        f"*Framework: {framework_id}  |  Assessed: {assessment_date}  |  Product: {product}*",
        "",
    ]

    if not controls:
        lines.append("No control data available for this framework.")
        return "\n".join(lines)

    lines += [
        "| Control | Passed | Failed | Most Severe | Score |",
        "|---|---|---|---|---|",
    ]
    for ctrl in controls:
        name = str(ctrl.get("control_name") or "—")[:55]
        agg = ctrl.get("all") or {}
        passed = agg.get("passed", 0)
        failed = agg.get("failed", 0)
        severe = agg.get("most_severe") or {}
        sev_cat = severe.get("category", "—")
        sev_name_str = _sev_name(sev_cat)
        score = agg.get("overall_score")
        score_str = _score_bar(score)
        lines.append(f"| {name} | {passed} | {failed} | {sev_name_str} ({sev_cat}) | {score_str} |")

    lines += [
        "",
        "*Severity levels: 1 = Informational, 3 = Warning, 5 = Critical*",
    ]

    return "\n".join(lines)


def _do_assessed(
    client: Any, framework_id: str = "", product: str = "all", tenant_id: str = "", **__: Any
) -> str:
    """GET /configurations-assessed/{id} — check/assessment counts."""
    if not framework_id:
        return "Error: `framework_id` is required for the `assessed` action."

    params: dict[str, str] = {}
    if product:
        params["product"] = product

    data = _compliance_get(
        client, f"/configurations-assessed/{framework_id}", params, tenant_id=tenant_id
    )

    ca = data.get("configurations_assessed") or {}

    # Upstream spells this key both ways: "total_exceptions" in the empty
    # response, "total_exception" in the populated one. Accept either.
    total_exceptions = ca.get("total_exceptions", ca.get("total_exception", "—"))

    lines = [
        f"## Configurations Assessed — {framework_id}",
        "",
        f"*Product filter: {product}*",
        _region_note(client, tenant_id),
        "",
        "| Metric | Count |",
        "|---|---|",
        f"| Checks | {ca.get('checks', '—')} |",
        f"| Assessments | {ca.get('assessments', '—')} |",
        f"| Total Exceptions | {total_exceptions} |",
        f"| Expiring Exceptions | {ca.get('expiring_exceptions', '—')} |",
    ]

    if not ca.get("checks") and not ca.get("assessments"):
        region, _src = _resolve_region(client, tenant_id)
        where = f"region `{region}`" if region else "the default region"
        lines += [
            "",
            f"> **Nothing assessed in {where}.** Zero checks and zero assessments "
            "usually means the results live in a different region, not that the "
            "tenant has no configuration to assess.",
        ]

    return "\n".join(lines)


def _do_framework_detail(
    client: Any, framework_id: str = "", tenant_id: str = "", **__: Any
) -> str:
    """GET /definitions/{id}?op=view_aggregated — full framework JSON."""
    if not framework_id:
        return "Error: `framework_id` is required for the `framework-detail` action."

    data = _compliance_get(
        client, f"/definitions/{framework_id}", {"op": "view_aggregated"}, tenant_id=tenant_id
    )

    lines = [
        f"## Framework Detail — {framework_id}",
        "",
        "```json",
        json.dumps(data, indent=2, default=str),
        "```",
    ]
    return "\n".join(lines)


def _do_monitor_benchmarks(
    client: Any, request_body: str = "", tenant_id: str = "", **__: Any
) -> str:
    """POST /benchmark-monitoring — benchmark monitoring data."""
    body: dict[str, Any] = {}
    if request_body:
        try:
            body = json.loads(request_body)
        except json.JSONDecodeError:
            return "Error: `request_body` must be valid JSON (or empty for default filters)."

    data = _compliance_post(
        client, "/benchmark-monitoring", body, timeout=_LONG_TIMEOUT, tenant_id=tenant_id
    )

    devices = data.get("device_serial") or []
    bpcs = data.get("bpc_id") or []
    severities = data.get("severity") or []
    statuses = data.get("bpc_status") or []
    stats = data.get("bpc_stats") or {}
    controls_stats = stats.get("controls") or {}
    exceptions_stats = stats.get("exceptions") or {}

    lines = [
        "## Benchmark Monitoring",
        "",
        f"*Devices: {len(devices)}  |  BPCs: {len(bpcs)}  |  "
        f"Compliance rate: {controls_stats.get('compliance_rate', '—')}%*",
        "",
    ]

    # Severity breakdown
    sev_breakdown = controls_stats.get("severity") or {}
    if sev_breakdown:
        lines += [
            "### Severity Breakdown",
            "",
            "| Severity | Count |",
            "|---|---|",
            f"| {_sev_badge('critical')} | {sev_breakdown.get('critical', '—')} |",
            f"| {_sev_badge('warning')} | {sev_breakdown.get('warning', '—')} |",
            f"| {_sev_badge('informational')} | {sev_breakdown.get('informational', '—')} |",
            f"| {_sev_badge('pass')} | {sev_breakdown.get('pass', '—')} |",
            "",
        ]

    # Exception stats
    if exceptions_stats:
        lines += [
            "### Exceptions",
            "",
            f"- Total: **{exceptions_stats.get('total_exceptions', '—')}**  |  "
            f"Expiring: **{exceptions_stats.get('expiring_exceptions', '—')}**",
            "",
        ]

    # Show distinct BPC statuses and severities
    if statuses:
        lines.append(f"**BPC Statuses:** {', '.join(str(s) for s in statuses)}")
    if severities:
        lines.append(f"**Severities:** {', '.join(str(s) for s in severities)}")

    lines += [
        "",
        f"*Full response has {len(devices)} device serials and {len(bpcs)} BPC IDs. "
        "Use `request_body` with filters to narrow results, or "
        "`scm_compliance_framework` with action `download` to export as CSV.*",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Write-side action handlers (scm_compliance_framework)
# ---------------------------------------------------------------------------


def _do_create(client: Any, payload_json: str = "", tenant_id: str = "", **__: Any) -> str:
    """POST /definitions — create a new framework."""
    if not payload_json:
        return "Error: `payload_json` is required for the `create` action."
    try:
        body = json.loads(payload_json)
    except json.JSONDecodeError as exc:
        return f"Error: invalid JSON in `payload_json`: {exc}"

    data = _compliance_post(client, "/definitions", body, tenant_id=tenant_id)
    fw_id = data.get("id", "?")
    return (
        f"## Framework Created\n\n"
        f"**ID:** `{fw_id}`\n\n"
        f"```json\n{json.dumps(data, indent=2, default=str)}\n```"
    )


def _do_update(
    client: Any,
    framework_id: str = "",
    payload_json: str = "",
    release: bool = False,
    tenant_id: str = "",
    **__: Any,
) -> str:
    """PUT /definitions/{id} — update a framework."""
    if not framework_id:
        return "Error: `framework_id` is required for the `update` action."
    if not payload_json:
        return "Error: `payload_json` is required for the `update` action."
    try:
        body = json.loads(payload_json)
    except json.JSONDecodeError as exc:
        return f"Error: invalid JSON in `payload_json`: {exc}"

    params = {"release": "true"} if release else {}
    data = _compliance_put(
        client, f"/definitions/{framework_id}", body, params, tenant_id=tenant_id
    )
    return (
        f"## Framework Updated — `{framework_id}`\n\n"
        f"```json\n{json.dumps(data, indent=2, default=str)}\n```"
    )


def _do_delete(client: Any, framework_id: str = "", tenant_id: str = "", **__: Any) -> str:
    """DELETE /definitions/{id} — delete a framework."""
    if not framework_id:
        return "Error: `framework_id` is required for the `delete` action."
    result = _compliance_delete(client, f"/definitions/{framework_id}", tenant_id=tenant_id)
    return f"## Framework Deleted — `{framework_id}`\n\n{result}"


def _do_clone(
    client: Any, framework_id: str = "", payload_json: str = "", tenant_id: str = "", **__: Any
) -> str:
    """POST /definitions/{id}:clone — clone a framework."""
    if not framework_id:
        return "Error: `framework_id` is required for the `clone` action."
    body: dict[str, Any] = {}
    if payload_json:
        try:
            body = json.loads(payload_json)
        except json.JSONDecodeError as exc:
            return f"Error: invalid JSON in `payload_json`: {exc}"

    data = _compliance_post(
        client, f"/definitions/{framework_id}:clone", body or None, tenant_id=tenant_id
    )
    fw_id = data.get("id", "?")
    return (
        f"## Framework Cloned — `{framework_id}` → `{fw_id}`\n\n"
        f"```json\n{json.dumps(data, indent=2, default=str)}\n```"
    )


def _do_benchmark(client: Any, framework_id: str = "", tenant_id: str = "", **__: Any) -> str:
    """POST /definitions/{id}:benchmark — mark as benchmark."""
    if not framework_id:
        return "Error: `framework_id` is required for the `benchmark` action."
    data = _compliance_post(client, f"/definitions/{framework_id}:benchmark", tenant_id=tenant_id)
    return (
        f"## Framework Benchmarked — `{framework_id}`\n\n"
        f"```json\n{json.dumps(data, indent=2, default=str)}\n```"
    )


def _do_un_benchmark(client: Any, framework_id: str = "", tenant_id: str = "", **__: Any) -> str:
    """POST /definitions/{id}:un-benchmark — remove benchmark."""
    if not framework_id:
        return "Error: `framework_id` is required for the `un-benchmark` action."
    data = _compliance_post(
        client, f"/definitions/{framework_id}:un-benchmark", tenant_id=tenant_id
    )
    return (
        f"## Benchmark Removed — `{framework_id}`\n\n"
        f"```json\n{json.dumps(data, indent=2, default=str)}\n```"
    )


_WRITE_METHODS: dict[str, str] = {
    "create": "POST /definitions",
    "update": "PUT /definitions/{id}",
    "delete": "DELETE /definitions/{id}",
    "clone": "POST /definitions/{id}:clone",
    "benchmark": "POST /definitions/{id}:benchmark",
    "un-benchmark": "POST /definitions/{id}:un-benchmark",
}


def _preview_write(
    client: Any,
    action: str,
    ticket_ref: str,
    framework_id: str = "",
    payload_json: str = "",
    release: bool = False,
    tenant_id: str = "",
) -> str:
    """Dry run for scm_compliance_framework — validate inputs and show the target."""
    if action != "create" and not framework_id:
        return f"Error: `framework_id` is required for the `{action}` action."
    if action in ("create", "update") and not payload_json:
        return f"Error: `payload_json` is required for the `{action}` action."
    body: Any = None
    if payload_json:
        try:
            body = json.loads(payload_json)
        except json.JSONDecodeError as exc:
            return f"Error: invalid JSON in `payload_json`: {exc}"

    method = _WRITE_METHODS[action].replace("{id}", framework_id)
    lines = [
        f"## Compliance Framework `{action}` — DRY-RUN",
        "",
        f"**Ticket ref:** {ticket_ref}",
        f"**Would call:** `{method}`" + (" with `release=true`" if release else ""),
    ]
    if action == "delete":
        lines.append("")
        lines.append("> ⚠️ Delete removes the framework and all its revisions — cannot be undone.")
    if body is not None:
        lines += ["", "**Request body:**", "```json", json.dumps(body, indent=2), "```"]
    if framework_id:
        try:
            current = _compliance_get(
                client,
                f"/definitions/{framework_id}",
                {"op": "view_aggregated"},
                tenant_id=tenant_id,
            )
            lines += [
                "",
                "**Current framework:**",
                "```json",
                json.dumps(current, indent=2, default=str),
                "```",
            ]
        except Exception as exc:
            lines += ["", f"**Current framework:** could not be read ({exc})"]
    lines += ["", DRY_RUN_HINT]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Action dispatch tables
# ---------------------------------------------------------------------------

_READ_ACTIONS: dict[str, Any] = {
    "list-frameworks": _do_list_frameworks,
    "summaries": _do_summaries,
    "scores": _do_scores,
    "timeline": _do_timeline,
    "controls": _do_controls,
    "assessed": _do_assessed,
    "framework-detail": _do_framework_detail,
    "benchmark-monitoring": _do_monitor_benchmarks,
}

_WRITE_ACTIONS: dict[str, Any] = {
    "create": _do_create,
    "update": _do_update,
    "delete": _do_delete,
    "clone": _do_clone,
    "benchmark": _do_benchmark,
    "un-benchmark": _do_un_benchmark,
}


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_compliance_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register Compliance Center tools (read-side analytics + write-side CRUD)."""
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_compliance_center(
        client: Any,
        tenant_id: str,
        action: str,
        framework_id: str = "",
        product: str = "all",
        category: str = "",
        status_filter: str = "",
        request_body: str = "",
    ) -> str:
        """PAN Compliance Center — read-side analytics for compliance frameworks.

        New API (released 2026-07-14). Requires the **Compliance Center** add-on
        licence. If your tenant is not yet provisioned, the tool returns a clear
        licence-hint message rather than a raw HTTP error.

        **Actions:**

        ``list-frameworks`` — list all compliance frameworks (PCF/CCF).
          Filters: `category` (PCF/CCF/all), `status_filter` (draft/released).

        ``summaries`` — framework summaries with compliance scores, revision
          state, and benchmark status. Filter: `product` (sase/ngfw/all).

        ``scores`` — overall + industry compliance scores per product, with
          per-category breakdown. Requires `framework_id`. Filter: `product`.

        ``timeline`` — 30-day + 1-year compliance score trend. Requires
          `framework_id`. Filter: `product`.

        ``controls`` — per-control pass/fail counts with most-severe finding
          severity (1=Informational, 3=Warning, 5=Critical) and compliance %.
          Requires `framework_id`. Filter: `product`.

        ``assessed`` — check, assessment, and exception counts. Requires
          `framework_id`. Filter: `product`.

        ``framework-detail`` — full framework hierarchy as JSON (view_aggregated
          revision). Requires `framework_id`.

        ``benchmark-monitoring`` — live BPC monitoring data with severity
          breakdown and exception stats. Optional `request_body` JSON with
          filters (product, bpc_status[], severity[], bpc_id[], object_type[],
          etc. — see API spec). An empty body returns an unfiltered view.

        Args:
            action: Which read operation to perform (see list above).
            tenant_id: SCM tenant ID. Defaults to active tenant.
            framework_id: Compliance framework ID (required for scores,
                          timeline, controls, assessed, framework-detail).
            product: Product filter — sase, ngfw, or all (default).
            category: Framework category filter — PCF, CCF, or empty=all.
            status_filter: Framework status — draft, released, or empty=all.
            request_body: JSON string of filter criteria for benchmark-monitoring.
        """
        handler = _READ_ACTIONS.get(action)
        if handler is None:
            return (
                f"Error: unknown action `{action}`.\n\n"
                f"Valid read actions: {', '.join(sorted(_READ_ACTIONS))}\n"
                f"For write actions (create/update/delete/clone/benchmark), "
                f"use `scm_compliance_framework`."
            )

        try:
            return handler(
                client,
                tenant_id=tenant_id,
                framework_id=framework_id,
                product=product,
                category=category,
                status_filter=status_filter,
                request_body=request_body,
            )
        except PermissionError as exc:
            return str(exc)
        except Exception as exc:
            return f"Error: {handle_scm_exception(exc, tool='scm_compliance_center', tenant_id=tenant_id)}"

    @mcp.tool()
    @tool
    def scm_compliance_framework(
        client: Any,
        tenant_id: str,
        action: str,
        framework_id: str = "",
        payload_json: str = "",
        release: bool = False,
        dry_run: bool = True,
        ticket_ref: str = "",
    ) -> str:
        """PAN Compliance Center — write-side framework CRUD.

        New API (released 2026-07-14). Requires the **Compliance Center** add-on
        licence plus a role that permits framework authoring (most read-only
        service accounts will get 403 on write operations).

        **Actions:**

        ``create`` — create a new compliance framework. Requires `payload_json`
          (see API spec for ComplianceFrameworkRequest schema).

        ``update`` — update an existing framework. Requires `framework_id` and
          `payload_json`. Set `release=true` to release after update.

        ``delete`` — permanently delete a framework and all its revisions.
          Requires `framework_id`. **Destructive — cannot be undone.**

        ``clone`` — clone a framework to a new one. Requires `framework_id`.

        ``benchmark`` — mark a framework as a benchmark. Requires `framework_id`.

        ``un-benchmark`` — remove the benchmark designation. Requires
          `framework_id`.

        Args:
            action: Which write operation to perform (see list above).
            tenant_id: SCM tenant ID. Defaults to active tenant.
            framework_id: Compliance framework ID (required for all actions
                          except `create`).
            payload_json: JSON string of the framework body for create/update.
            release: Set to True to release the framework after update.
            dry_run: If True (default), validate inputs and show the target
                framework without changing anything.
            ticket_ref: Mandatory change-ticket reference (never sent to the API).

        **Write safety (SSR pattern):** every action here is a write —
        ``dry_run=True`` by default and ``ticket_ref`` is mandatory.
        """
        handler = _WRITE_ACTIONS.get(action)
        if handler is None:
            return (
                f"Error: unknown action `{action}`.\n\n"
                f"Valid write actions: {', '.join(sorted(_WRITE_ACTIONS))}\n"
                f"For read actions (list/scores/timeline/controls/etc.), "
                f"use `scm_compliance_center`."
            )

        err = ticket_ref_error(ticket_ref)
        if err:
            return f"Error: {err}"
        ticket_ref = normalize_ticket_ref(ticket_ref)

        try:
            if dry_run:
                return _preview_write(
                    client,
                    action,
                    ticket_ref,
                    framework_id=framework_id,
                    payload_json=payload_json,
                    release=release,
                    tenant_id=tenant_id,
                )
            audit_write(
                "scm_compliance_framework",
                ticket_ref,
                tenant_id,
                action=action,
                framework_id=framework_id,
            )
            return handler(
                client,
                tenant_id=tenant_id,
                framework_id=framework_id,
                payload_json=payload_json,
                release=release,
            )
        except PermissionError as exc:
            return str(exc)
        except Exception as exc:
            return f"Error: {handle_scm_exception(exc, tool='scm_compliance_framework', tenant_id=tenant_id)}"
