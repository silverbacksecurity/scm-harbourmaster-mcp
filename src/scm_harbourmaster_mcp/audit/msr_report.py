"""MSR — Monthly Service Review pack: period bounding, SLA maths, renderer.

Pure functions only — no API calls. ``tools/msr.py`` gathers the live data
(each source degrading gracefully) into :class:`MsrData` and calls
:func:`render_msr_report`. Keeping this module import-light makes the
period-bounding, SSR-ledger parsing, SLA computation, and section rendering
unit-testable without a client.

The pack assembles what the server already produces for the period:
incidents, the change record (config jobs + SSR provenance notes),
compliance posture, licence/renewal posture, bandwidth, and mechanically
computed service stats (MTTR, ack rate, change failure rate).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .incident_rca import parse_any_ts

# ---------------------------------------------------------------------------
# Period bounding
# ---------------------------------------------------------------------------


def month_bounds(month: str = "", now: datetime | None = None) -> tuple[datetime, datetime, str]:
    """Return (start, end, label) for a review period.

    *month* is ``YYYY-MM``; empty selects the previous full calendar month
    (the month an MSR is normally written about). *end* is exclusive.
    Raises ValueError on a malformed month string.
    """
    if month:
        m = re.fullmatch(r"(\d{4})-(\d{2})", month.strip())
        if not m:
            raise ValueError(f"month must be YYYY-MM, got `{month}`")
        year, mon = int(m.group(1)), int(m.group(2))
        if not 1 <= mon <= 12:
            raise ValueError(f"month must be 01-12, got `{month}`")
    else:
        ref = now or datetime.now(UTC)
        year, mon = (ref.year, ref.month - 1) if ref.month > 1 else (ref.year - 1, 12)

    start = datetime(year, mon, 1, tzinfo=UTC)
    end = (
        datetime(year + 1, 1, 1, tzinfo=UTC)
        if mon == 12
        else datetime(year, mon + 1, 1, tzinfo=UTC)
    )
    return start, end, f"{year:04d}-{mon:02d}"


def in_period(ts_value: Any, start: datetime, end: datetime) -> bool:
    """True if *ts_value* parses to a timestamp within [start, end)."""
    ts = parse_any_ts(ts_value)
    if ts is None:
        return False
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return start <= ts < end


# ---------------------------------------------------------------------------
# SSR provenance ledger
# ---------------------------------------------------------------------------

# Matches the notes scm_ssr_execute stamps into object descriptions:
#   "SSR add: example.com — INC-12345"
#   "SSR threat-exception remove: 12345 — CHG-9"
#   "SSR ssl-decrypt add: gambling — INC-7"
_SSR_NOTE_RE = re.compile(
    r"SSR (?:(?P<kind>threat-exception|ssl-decrypt) )?(?P<action>add|remove): "
    r"(?P<target>.+?) — (?P<ticket>[^|]+?)(?:\s*\||$)"
)


def parse_ssr_notes(description: str, obj_name: str = "") -> list[dict[str, str]]:
    """Extract SSR change entries from an object *description*.

    The notes carry no timestamps (they are cumulative provenance), so the
    ledger is rendered as object state, not period activity.
    """
    entries: list[dict[str, str]] = []
    for m in _SSR_NOTE_RE.finditer(description or ""):
        entries.append(
            {
                "object": obj_name,
                "kind": m.group("kind") or "url-list",
                "action": m.group("action"),
                "target": m.group("target").strip(),
                "ticket_ref": m.group("ticket").strip(),
            }
        )
    return entries


# ---------------------------------------------------------------------------
# Month-window query bodies (Insights)
# ---------------------------------------------------------------------------


def month_window_filter(start: datetime, end: datetime) -> dict[str, Any]:
    """Insights filter body bounding ``event_time`` to [start, end).

    Uses the ``between`` operator with second-resolution UTC timestamps.
    Callers should fall back to a ``last_n_days`` window (and disclose it)
    if the resource rejects this shape.
    """
    fmt = "%Y-%m-%d %H:%M:%S"
    return {
        "filter": {
            "rules": [
                {
                    "property": "event_time",
                    "operator": "between",
                    "values": [start.strftime(fmt), end.strftime(fmt)],
                }
            ]
        }
    }


def fallback_window_days(start: datetime, now: datetime | None = None) -> int:
    """Days from *start* to now, clamped to [7, 62] for last_n_days fallbacks."""
    ref = now or datetime.now(UTC)
    return max(7, min(62, (ref - start).days + 1))


# ---------------------------------------------------------------------------
# Bandwidth: consumption vs allocation join
# ---------------------------------------------------------------------------


def _norm_loc(name: Any) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(name or "").lower()).strip()


_BW_USAGE_KEYS = ("peak_consumption", "max_consumption", "total_consumption", "avg_consumption")


def merge_bw_allocation(
    bw_rows: list[dict[str, Any]], allocations: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Join per-location consumption rows with SCM bandwidth allocations.

    Match is on normalised location name (equality, then containment either
    way). Adds ``allocated_mbps`` and ``utilisation_pct`` (peak-ish usage ÷
    allocated) to each consumption row; allocations with no consumption row
    are appended as allocation-only rows so unused regions still show.
    """
    alloc_by_norm = {_norm_loc(a.get("name")): a for a in allocations if a.get("name")}
    merged: list[dict[str, Any]] = []
    matched_allocs: set[str] = set()

    for row in bw_rows:
        out = dict(row)
        norm = _norm_loc(
            row.get("location")
            or row.get("edge_location_display")
            or row.get("edge_location")
            or row.get("region")
            or row.get("name")
        )
        alloc = alloc_by_norm.get(norm)
        if alloc is None and norm:
            alloc = next(
                (a for n, a in alloc_by_norm.items() if n and (n in norm or norm in n)),
                None,
            )
        if alloc is not None:
            matched_allocs.add(_norm_loc(alloc.get("name")))
            allocated = alloc.get("allocated_mbps")
            if isinstance(allocated, int | float) and allocated > 0:
                out["allocated_mbps"] = allocated
                usage = next(
                    (
                        row[k]
                        for k in _BW_USAGE_KEYS
                        if isinstance(row.get(k), int | float) and not isinstance(row[k], bool)
                    ),
                    None,
                )
                if usage is not None:
                    out["utilisation_pct"] = round(usage / allocated * 100)
        merged.append(out)

    for norm, alloc in alloc_by_norm.items():
        if norm not in matched_allocs:
            merged.append(
                {
                    "location": alloc.get("name"),
                    "allocated_mbps": alloc.get("allocated_mbps"),
                    "_allocation_only": True,
                }
            )
    return merged


# ---------------------------------------------------------------------------
# Mobile users: per-location login breakdown
# ---------------------------------------------------------------------------

_MU_LOCATION_KEYS = (
    "pa_location",
    "location",
    "source_location",
    "gw_location",
    "region",
    "city",
    "country",
)


def summarize_mu_locations(rows: list[dict[str, Any]]) -> list[tuple[str, int]]:
    """Count unique users per location from Insights user_list rows.

    The first location-ish key present in the rows is used consistently;
    users deduplicate by username-ish key when one exists (a user connecting
    twice from one location counts once), else rows are counted.
    """
    loc_key = next((k for k in _MU_LOCATION_KEYS if any(r.get(k) for r in rows)), None)
    if loc_key is None:
        return []
    user_key = next(
        (
            k
            for k in ("user", "username", "user_name", "source_user")
            if any(r.get(k) for r in rows)
        ),
        None,
    )
    per_loc: dict[str, set[str] | int] = {}
    for i, r in enumerate(rows):
        loc = str(r.get(loc_key) or "Unknown")
        if user_key:
            per_loc.setdefault(loc, set()).add(str(r.get(user_key) or f"row{i}"))  # type: ignore[union-attr]
        else:
            per_loc[loc] = int(per_loc.get(loc) or 0) + 1  # type: ignore[arg-type]
    counts = {loc: (len(v) if isinstance(v, set) else v) for loc, v in per_loc.items()}
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


# ---------------------------------------------------------------------------
# Service stats (mechanical, from timestamps we already hold)
# ---------------------------------------------------------------------------

_RESOLVED_KEYS = ("resolved_time", "closed_time", "resolution_time", "updated_time")
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def compute_service_stats(
    incidents: list[dict[str, Any]], jobs: list[dict[str, Any]]
) -> dict[str, Any]:
    """Compute MTTR/ack-rate/change stats from period incidents and jobs.

    MTTR uses raised_time → the first available resolution-ish timestamp on
    Closed incidents; if none of the API's records carry one, mttr_hours is
    None and the renderer says so rather than inventing a number.
    """
    sev_counts: dict[str, int] = {}
    open_count = 0
    acked = 0
    mttr_samples: list[float] = []

    for inc in incidents:
        sev = str(inc.get("severity") or "unknown").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        status = str(inc.get("status") or "").lower()
        if status != "closed":
            open_count += 1
        if inc.get("acknowledged"):
            acked += 1
        if status == "closed":
            raised = parse_any_ts(inc.get("raised_time"))
            resolved = next(
                (parse_any_ts(inc.get(k)) for k in _RESOLVED_KEYS if parse_any_ts(inc.get(k))),
                None,
            )
            if raised and resolved and resolved >= raised:
                mttr_samples.append((resolved - raised).total_seconds() / 3600)

    ok_jobs = sum(1 for j in jobs if str(j.get("result") or "").upper() == "OK")
    failed_jobs = sum(1 for j in jobs if str(j.get("result") or "").upper() == "FAIL")
    commit_jobs = sum(1 for j in jobs if "commit" in str(j.get("type") or "").lower())

    return {
        "commit_count": commit_jobs,
        "incident_total": len(incidents),
        "severity_counts": sev_counts,
        "open_at_generation": open_count,
        "ack_rate_pct": round(acked / len(incidents) * 100) if incidents else None,
        "mttr_hours": round(sum(mttr_samples) / len(mttr_samples), 1) if mttr_samples else None,
        "mttr_samples": len(mttr_samples),
        "change_total": len(jobs),
        "change_ok": ok_jobs,
        "change_failed": failed_jobs,
        "change_failure_pct": round(failed_jobs / len(jobs) * 100) if jobs else None,
    }


# ---------------------------------------------------------------------------
# Data container
# ---------------------------------------------------------------------------


@dataclass
class MsrData:
    """Everything the renderer needs, gathered by tools/msr.py."""

    tenant_label: str = ""
    tenant_id: str = ""
    tier: str = "bronze"
    mssp_name: str = "MSSP"
    period_start: datetime = field(default_factory=lambda: datetime.now(UTC))
    period_end: datetime = field(default_factory=lambda: datetime.now(UTC))
    period_label: str = ""

    incidents: list[dict[str, Any]] = field(default_factory=list)  # period-bounded
    jobs: list[dict[str, Any]] = field(default_factory=list)  # period-bounded
    ssr_ledger: list[dict[str, str]] = field(default_factory=list)  # cumulative
    licence_rows: list[dict[str, Any]] = field(default_factory=list)
    bandwidth_rows: list[dict[str, Any]] = field(default_factory=list)  # 24h snapshot
    connected_mu: int | None = None
    compliance_summaries: list[dict[str, Any]] = field(default_factory=list)
    compliance_timeline: list[dict[str, Any]] = field(default_factory=list)  # 30d entries
    compliance_framework_name: str = ""

    # Month-window additions (2026-07-18)
    bw_month_rows: list[dict[str, Any]] = field(default_factory=list)  # RN bandwidth, period
    bw_month_window: str = ""  # disclosure of the window actually used
    bw_allocations: list[dict[str, Any]] = field(default_factory=list)  # SCM allocations
    mu_month_users: int | None = None  # unique MU logins in window
    mu_month_locations: list[tuple[str, int]] = field(default_factory=list)  # (location, users)
    mu_month_window: str = ""
    adem_summary: dict[str, Any] = field(default_factory=dict)  # agent scores, 3d snapshot
    threat_summary: dict[str, Any] = field(default_factory=dict)  # blocked-event counts

    # source name → error string; sources absent from BOTH this and `gathered`
    # were not attempted (e.g. compliance below gold tier)
    errors: dict[str, str] = field(default_factory=dict)
    gathered: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

_SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}


def _fmt_ts(value: Any) -> str:
    ts = parse_any_ts(value)
    return ts.strftime("%Y-%m-%d %H:%M") if ts else "—"


def _sorted_incidents(incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        incidents,
        key=lambda i: (
            _SEV_ORDER.get(str(i.get("severity") or "").lower(), 9),
            str(i.get("raised_time") or ""),
        ),
    )


def _bw_name(row: dict[str, Any]) -> str:
    for key in (
        "location",
        "edge_location_display",
        "edge_location",
        "region",
        "site_name",
        "name",
    ):
        if row.get(key):
            return str(row[key])
    return "—"


def _bw_columns(rows: list[dict[str, Any]]) -> list[str]:
    """Numeric-ish columns present in the bandwidth rows, stable order."""
    preferred = [
        "allocated_bandwidth",
        "total_consumption",
        "avg_consumption",
        "peak_consumption",
        "rn_sites_up",
        "sc_sites_up",
    ]
    present: set[str] = set()
    for r in rows:
        present.update(
            k for k, v in r.items() if isinstance(v, int | float) and not isinstance(v, bool)
        )
    return [c for c in preferred if c in present] or sorted(present)[:5]


def _exec_summary(data: MsrData, stats: dict[str, Any]) -> list[str]:
    """Ranked headline bullets — worst news first, good news last."""
    bullets: list[str] = []
    crit = stats["severity_counts"].get("critical", 0)
    high = stats["severity_counts"].get("high", 0)
    if crit or high:
        bullets.append(
            f"🔴 **{crit + high} Critical/High incident(s)** raised this period"
            f" ({stats['open_at_generation']} of {stats['incident_total']} still open)."
        )
    if stats["change_failed"]:
        bullets.append(
            f"🟠 **{stats['change_failed']} of {stats['change_total']} config jobs failed**"
            f" ({stats['change_failure_pct']}% change failure rate)."
        )
    expiring = [r for r in data.licence_rows if r.get("days") is not None and 0 <= r["days"] <= 90]
    if expiring:
        bullets.append(
            f"🟠 **{len(expiring)} licence group(s) expire within 90 days** — see Renewal Posture."
        )
    if (
        data.tier.lower() != "bronze"
        and data.compliance_timeline
        and len(data.compliance_timeline) >= 2
    ):
        first = data.compliance_timeline[0].get("overall_score")
        last = data.compliance_timeline[-1].get("overall_score")
        if isinstance(first, int | float) and isinstance(last, int | float) and last < first:
            bullets.append(
                f"🟡 **Compliance score declined** {first:.0f} → {last:.0f}"
                f" ({data.compliance_framework_name or 'benchmarked framework'}, 30d)."
            )
    hot = [
        r
        for r in data.bw_month_rows
        if isinstance(r.get("utilisation_pct"), int | float) and r["utilisation_pct"] >= 90
    ]
    if hot:
        worst = max(hot, key=lambda r: r["utilisation_pct"])
        bullets.append(
            f"🟠 **{len(hot)} remote-network location(s) at ≥90% of allocated bandwidth**"
            f" (worst: {_bw_name(worst)} at {worst['utilisation_pct']}%) — see Bandwidth."
        )
    if not bullets:
        bullets.append(
            "🟢 No critical incidents, failed changes, or expiring licences this period."
        )
    blocked = data.threat_summary.get("blocked_count")
    if isinstance(blocked, int | float) and blocked >= 0:
        bullets.append(
            f"ℹ️ **{int(blocked)} security threat(s) blocked**"
            f" over the last {data.threat_summary.get('window_days', '—')} days."
        )
    if stats["mttr_hours"] is not None:
        bullets.append(
            f"ℹ️ Mean time to resolve (closed incidents): **{stats['mttr_hours']}h**"
            f" over {stats['mttr_samples']} incident(s)."
        )
    return bullets


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------


def render_msr_report(data: MsrData) -> str:  # noqa: C901
    """Render the MSR pack as markdown. Tier controls compliance-annex depth."""
    stats = compute_service_stats(data.incidents, data.jobs)
    tier = data.tier.lower()
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    lines: list[str] = [
        f"# Monthly Service Review — {data.tenant_label or data.tenant_id}",
        "",
        f"**Period:** {data.period_label}  |  **Service tier:** {tier.title()}  |  "
        f"**Prepared by:** {data.mssp_name}  |  **Generated:** {generated}",
        "",
        "## 1. Executive Summary",
        "",
    ]
    lines += [f"- {b}" for b in _exec_summary(data, stats)]

    # ── 2. Service stats ────────────────────────────────────────────────
    ack = f"{stats['ack_rate_pct']}%" if stats["ack_rate_pct"] is not None else "n/a"
    mttr = (
        f"{stats['mttr_hours']}h ({stats['mttr_samples']} samples)"
        if stats["mttr_hours"] is not None
        else "n/a — no resolution timestamps in period"
    )
    cfr = f"{stats['change_failure_pct']}%" if stats["change_failure_pct"] is not None else "n/a"
    lines += [
        "",
        "## 2. Service Statistics",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Incidents raised | {stats['incident_total']} |",
        f"| Open at generation | {stats['open_at_generation']} |",
        f"| Acknowledgement rate | {ack} |",
        f"| MTTR (closed incidents) | {mttr} |",
        f"| Config jobs | {stats['change_total']} ({stats['change_ok']} OK, {stats['change_failed']} failed) |",
        f"| Commit jobs | {stats['commit_count']} |",
        f"| Change failure rate | {cfr} |",
    ]
    if data.mu_month_users is not None:
        lines.append(
            f"| Unique mobile users ({data.mu_month_window or 'period'}) | {data.mu_month_users} |"
        )
    if data.connected_mu is not None and data.connected_mu >= 0:
        lines.append(f"| Connected mobile users (at generation) | {data.connected_mu} |")

    # ── 3. Incidents ────────────────────────────────────────────────────
    lines += ["", f"## 3. Incidents ({data.period_label})", ""]
    if data.incidents:
        lines += ["| Sev | Raised | Status | Title | Category |", "|---|---|---|---|---|"]
        for inc in _sorted_incidents(data.incidents)[:50]:
            sev = str(inc.get("severity") or "—")
            emoji = _SEV_EMOJI.get(sev.lower(), "⚪")
            title = str(inc.get("title") or inc.get("description") or "—")[:70]
            lines.append(
                f"| {emoji} {sev} | {_fmt_ts(inc.get('raised_time'))} "
                f"| {inc.get('status') or '—'} | {title} | {inc.get('category') or '—'} |"
            )
        if len(data.incidents) > 50:
            lines.append(f"| ... | *({len(data.incidents) - 50} more)* | | | |")
        lines += [
            "",
            "_Root-cause analyses for individual incidents are produced with"
            " `scm_incident_rca` and attached separately where commissioned._",
        ]
    elif "incidents" in data.errors:
        lines.append(f"> ⚠️ Incident data unavailable: {data.errors['incidents']}")
    else:
        lines.append("No incidents raised in the period. ✅")

    # ── 4. Change record ────────────────────────────────────────────────
    lines += ["", f"## 4. Change Record ({data.period_label})", ""]
    if data.jobs:
        lines += ["| Date | Type | Result | By | Description |", "|---|---|---|---|---|"]
        for j in sorted(data.jobs, key=lambda x: str(x.get("start_ts") or ""), reverse=True)[:60]:
            desc = str(j.get("description") or "—")[:60]
            lines.append(
                f"| {_fmt_ts(j.get('start_ts'))} | {j.get('type') or '—'} "
                f"| {j.get('result') or '—'} | {j.get('user') or '—'} | {desc} |"
            )
        if len(data.jobs) > 60:
            lines.append(f"| ... | *({len(data.jobs) - 60} more)* | | | |")
    elif "jobs" in data.errors:
        lines.append(f"> ⚠️ Config job history unavailable: {data.errors['jobs']}")
    else:
        lines.append("No configuration jobs ran in the period.")

    if data.ssr_ledger:
        lines += [
            "",
            "### Service-request ledger (SSR-managed objects, cumulative)",
            "",
            "_Provenance notes stamped on SSR-managed objects; the API does not"
            " timestamp them, so this shows current object state, not"
            " period-only activity._",
            "",
            "| Object | Type | Action | Target | Ticket |",
            "|---|---|---|---|---|",
        ]
        for e in data.ssr_ledger[:80]:
            lines.append(
                f"| {e['object']} | {e['kind']} | {e['action']} | {e['target']} | {e['ticket_ref']} |"
            )

    # ── 5. Compliance (tier-gated depth) ────────────────────────────────
    lines += ["", "## 5. Compliance Posture", ""]
    if tier == "bronze":
        lines.append(
            "_Compliance reporting is included at Silver tier and above."
            " Contact your service manager to upgrade._"
        )
    elif "compliance" in data.errors:
        lines.append(f"> ⚠️ Compliance data unavailable: {data.errors['compliance']}")
    elif data.compliance_summaries:
        lines += ["| Framework | Category | Benchmark | Score | State |", "|---|---|---|---|---|"]
        for item in data.compliance_summaries:
            revisions = item.get("revision_summary") or []
            latest = revisions[0] if revisions else {}
            name = str(latest.get("name") or item.get("id") or "—")[:40]
            score = latest.get("overall_score")
            # The API reports -1 for released-but-never-assessed frameworks
            score_s = (
                f"{score:.0f}%" if isinstance(score, int | float) and score >= 0 else "not assessed"
            )
            bench = "✓" if item.get("benchmark") else "—"
            lines.append(
                f"| {name} | {item.get('category') or '—'} | {bench} "
                f"| {score_s} | {latest.get('state') or '—'} |"
            )
        if tier == "gold" and data.compliance_timeline:
            lines += [
                "",
                f"### 30-day score trend — {data.compliance_framework_name or 'benchmarked framework'}",
                "",
                "| Date | Score |",
                "|---|---|",
            ]
            for entry in data.compliance_timeline[-15:]:
                score = entry.get("overall_score")
                score_s = f"{score:.0f}%" if isinstance(score, int | float) else "—"
                lines.append(
                    f"| {_fmt_ts(entry.get('date') or entry.get('timestamp'))[:10]} | {score_s} |"
                )
    else:
        lines.append("No compliance framework data returned for this tenant.")

    # ── 6. Renewal posture ──────────────────────────────────────────────
    lines += ["", "## 6. Licence & Renewal Posture", ""]
    if "licences" in data.errors:
        lines.append(f"> ⚠️ Licence data unavailable: {data.errors['licences']}")
    elif data.licence_rows:
        dated = [r for r in data.licence_rows if r.get("days") is not None]
        upcoming = [r for r in dated if 0 <= r["days"] <= 180]
        # Recently-expired SKUs (≤90d) belong in the renewal conversation;
        # long-dead evals would drown the table, so they compress to a count.
        recent_expired = [r for r in dated if -90 <= r["days"] < 0]
        older_expired = len([r for r in dated if r["days"] < -90])
        if upcoming or recent_expired:
            lines += ["| Product | Type | Expires | Days left |", "|---|---|---|---|"]
            for r in upcoming + recent_expired:
                if r["days"] < 0:
                    days_s = f"expired {-r['days']}d ago 🔴"
                else:
                    days_s = f"{r['days']} " + (
                        "🔴" if r["days"] <= 30 else "🟠" if r["days"] <= 90 else ""
                    )
                lines.append(
                    f"| {r.get('app') or '—'} | {r.get('license_type') or '—'} "
                    f"| {str(r.get('exp') or '—')[:10]} | {days_s} |"
                )
        else:
            lines.append("No licences expire within 180 days. ✅")
        if older_expired:
            lines += [
                "",
                f"_{older_expired} SKU group(s) expired more than 90 days ago (omitted)._",
            ]
        lines += [
            "",
            "_Full consumption-vs-contract analysis is available via"
            " `scm_renewal_brief` for the renewal conversation._",
        ]
    else:
        lines.append("No licence data returned.")

    # ── 7. Bandwidth ────────────────────────────────────────────────────
    lines += ["", "## 7. Bandwidth Consumption vs Allocation", ""]
    if data.bw_month_rows:
        cols = _bw_columns(data.bw_month_rows)
        # Keep the comparison columns at the end, in a fixed order
        for special in ("allocated_mbps", "utilisation_pct"):
            if special in cols:
                cols.remove(special)
            if any(special in r for r in data.bw_month_rows):
                cols.append(special)
        header = " | ".join(c.replace("_", " ").title() for c in cols)
        lines += [
            f"_Per remote-network location over **{data.bw_month_window or data.period_label}**,"
            " compared against the allocated bandwidth for its aggregate region"
            " (Insights + SCM bandwidth allocations)._",
            "",
            f"| Location | {header} |",
            "|" + "---|" * (len(cols) + 1),
        ]
        for row in data.bw_month_rows[:40]:
            vals: list[str] = []
            for c in cols:
                v = row.get(c, "—")
                if c == "utilisation_pct" and isinstance(v, int | float):
                    flag = " 🔴" if v >= 90 else " 🟠" if v >= 75 else ""
                    vals.append(f"{v}%{flag}")
                else:
                    vals.append(str(v))
            suffix = " _(allocation only — no traffic rows)_" if row.get("_allocation_only") else ""
            lines.append(f"| {_bw_name(row)}{suffix} | {' | '.join(vals)} |")
        if "bandwidth" in data.errors:
            lines.append("")
            lines.append(f"> ⚠️ 24h snapshot source also reported: {data.errors['bandwidth']}")
    elif "bandwidth_month" in data.errors and not data.bandwidth_rows:
        lines.append(f"> ⚠️ Bandwidth data unavailable: {data.errors['bandwidth_month']}")
    elif data.bandwidth_rows:
        cols = _bw_columns(data.bandwidth_rows)
        header = " | ".join(c.replace("_", " ").title() for c in cols)
        lines += [
            "_Per-location snapshot from the Insights API (24-hour window at"
            " generation time — the month-window query was unavailable)._",
            "",
            f"| Location | {header} |",
            "|" + "---|" * (len(cols) + 1),
        ]
        for row in data.bandwidth_rows[:40]:
            row_str = " | ".join(str(row.get(c, "—")) for c in cols)
            lines.append(f"| {_bw_name(row)} | {row_str} |")
    elif "bandwidth" in data.errors:
        lines.append(f"> ⚠️ Bandwidth data unavailable: {data.errors['bandwidth']}")
    else:
        lines.append("No per-location bandwidth data returned.")

    # ── 8. Mobile users ─────────────────────────────────────────────────
    lines += ["", "## 8. Mobile Users", ""]
    if data.mu_month_users is not None or data.mu_month_locations:
        if data.mu_month_users is not None:
            lines.append(
                f"**{data.mu_month_users} unique mobile user(s)** connected over"
                f" {data.mu_month_window or 'the period window'}."
            )
        if data.mu_month_locations:
            lines += [
                "",
                "| Location | Users |",
                "|---|---|",
            ]
            for loc, count in data.mu_month_locations[:25]:
                lines.append(f"| {loc} | {count} |")
            if len(data.mu_month_locations) > 25:
                lines.append(f"| ... | *({len(data.mu_month_locations) - 25} more locations)* |")
    elif "mobile_users" in data.errors:
        lines.append(f"> ⚠️ Mobile-user data unavailable: {data.errors['mobile_users']}")
    else:
        lines.append("No mobile-user login data returned for the period.")

    # ── 9. Digital experience (ADEM) ────────────────────────────────────
    lines += ["", "## 9. Digital Experience (ADEM)", ""]
    agents = data.adem_summary.get("agents") or {}
    if agents:
        _fell_back = data.adem_summary.get("timerange_used") == "last_30_day"
        _window = "30-day" if _fell_back else "3-day"
        _note = (
            " Fell back to a 30-day window because no activity was found in the last 3 days."
            if _fell_back
            else ""
        )
        lines += [
            f"_Experience scores from Autonomous DEM ({_window} window at generation"
            f" time — ADEM telemetry does not retain a month of history.{_note}_",
            "",
            "| Scope | Score | Clients | Good | Fair | Poor |",
            "|---|---|---|---|---|---|",
        ]
        labels = {"muAgent": "Mobile Users", "rnAgent": "Remote Networks"}
        for ep_type, s in agents.items():
            score = s.get("score")
            score_s = f"{score:.0f}" if isinstance(score, int | float) else "—"
            lines.append(
                f"| {labels.get(ep_type, ep_type)} | {score_s} | {s.get('clients') or 0} "
                f"| {s.get('clients_good') if s.get('clients_good') is not None else '—'} "
                f"| {s.get('clients_fair') if s.get('clients_fair') is not None else '—'} "
                f"| {s.get('clients_poor') if s.get('clients_poor') is not None else '—'} |"
            )
    elif "adem" in data.errors:
        lines.append(f"> ⚠️ ADEM data unavailable: {data.errors['adem']}")
    else:
        lines.append(
            "No ADEM telemetry returned — the tenant may not have ADEM licensed"
            " or the service account lacks the ADEM scope."
        )

    # ── 10. Security events ─────────────────────────────────────────────
    lines += ["", "## 10. Security Events", ""]
    ts = data.threat_summary
    if ts:
        total = ts.get("total_threats")
        blocked = ts.get("blocked_count")
        lines += [
            f"_Threat activity over the last **{ts.get('window_days', '—')} days**"
            " (Critical/High/Medium, Monitor API)._",
            "",
            "| Metric | Count |",
            "|---|---|",
            f"| Threats detected | {int(total) if isinstance(total, int | float) else '—'} |",
            f"| Threats blocked | {int(blocked) if isinstance(blocked, int | float) else '—'} |",
        ]
    elif "security_events" in data.errors:
        lines.append(f"> ⚠️ Security-event data unavailable: {data.errors['security_events']}")
    else:
        lines.append("No threat summary returned for this tenant.")

    # ── 11. Data sources ────────────────────────────────────────────────
    lines += ["", "## 11. Data Sources & Coverage", ""]
    for src in data.gathered:
        lines.append(f"- ✅ {src}")
    for src, err in data.errors.items():
        lines.append(f"- ⚠️ {src} — {err}")
    if tier == "bronze":
        lines.append("- ➖ compliance — not included at Bronze tier")
    lines += [
        "",
        "---",
        f"_Generated by scm-harbourmaster-mcp `scm_msr_report` for period {data.period_label}."
        " Figures are drawn live from the tenant APIs at generation time._",
    ]

    return "\n".join(lines)
