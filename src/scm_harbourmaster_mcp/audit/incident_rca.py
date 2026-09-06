"""
Incident → root-cause correlation (scm_incident_rca).

Given an incident time, walks the evidence the server can already reach —
config push/commit jobs, certificate expiries, licence expiries, and config
drift vs the last approved baseline — and ranks candidate causes by temporal
proximity to the incident. Event evidence (things with a timestamp) is
ranked; drift is presented as state evidence (the extraction can't say
*when* an object changed, only that it differs from the baseline).

Every candidate cites its evidence (job ID, cert CN, SKU, diff section) and
the output states plainly that this is temporal correlation pending operator
confirmation — the RFO draft embeds that caveat rather than hiding it.

Pure functions only — no SCM client or MCP imports.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from .asbuilt_verify import SectionDiff, _name_list
from .drift_baseline import drift_severity

# A push finishing just after the reported incident time can still be the
# cause (clock skew, delayed symptom reports) — allow a small grace window.
_AFTER_GRACE_MIN = 15


def parse_any_ts(value: Any) -> datetime | None:
    """Parse SCM job timestamps, ISO strings, or epoch seconds to aware UTC."""
    if value is None:
        return None
    s = str(value).strip()
    if not s or s.lower() in ("none", "?"):
        return None
    if s.isdigit() and len(s) >= 9:  # epoch seconds
        try:
            return datetime.fromtimestamp(int(s), tz=UTC)
        except (ValueError, OverflowError):
            return None
    # ISO 8601 with Z or offset (Incidents API raised_time is Z-suffixed)
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt.astimezone(UTC) if dt.tzinfo else dt.replace(tzinfo=UTC)
    except ValueError:
        pass
    s = s.split(".")[0].replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def collect_candidates(
    incident_dt: datetime,
    lookback_hours: int,
    jobs: list[dict[str, Any]],
    certs: list[dict[str, Any]],
    licences: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build the ranked candidate-cause list from timestamped evidence.

    Inclusion window: [incident - lookback, incident + grace]. Candidates
    sort by proximity to the incident; failed jobs sort ahead of successful
    ones at equal distance.

    jobs:     {job_id, type, result, user, description, start_ts, end_ts}
    certs:    SCM certificate dicts (expiry_epoch, name, common_name)
    licences: rows with {app, license_type, exp} (see ops._licence_rows)
    """
    window_start = incident_dt - timedelta(hours=lookback_hours)
    grace_end = incident_dt + timedelta(minutes=_AFTER_GRACE_MIN)
    candidates: list[dict[str, Any]] = []

    def _add(kind: str, ts: datetime, desc: str, evidence: str, failed: bool = False) -> None:
        if not (window_start <= ts <= grace_end):
            return
        delta_min = round((incident_dt - ts).total_seconds() / 60)
        candidates.append(
            {
                "kind": kind,
                "ts": ts.strftime("%Y-%m-%d %H:%M UTC"),
                "delta_min": delta_min,
                "desc": desc,
                "evidence": evidence,
                "failed": failed,
            }
        )

    for j in jobs:
        ts = parse_any_ts(j.get("end_ts")) or parse_any_ts(j.get("start_ts"))
        if ts is None:
            continue
        result = str(j.get("result", "")).upper()
        failed = "FAIL" in result
        jtype = j.get("type") or "job"
        desc = f"{jtype} by `{j.get('user', '?')}`"
        if j.get("description"):
            desc += f" — “{j['description']}”"
        if failed:
            desc += " — **job FAILED**"
        _add("config push", ts, desc, f"job `{j.get('job_id', '?')}` result={result}", failed)

    for c in certs:
        ts = parse_any_ts(c.get("expiry_epoch"))
        if ts is None or ts > grace_end:
            continue
        cn = c.get("common_name") or c.get("name", "?")
        _add(
            "certificate expiry",
            ts,
            f"certificate `{c.get('name', '?')}` (CN {cn}) expired",
            f"cert CN `{cn}`, not_valid_after {c.get('not_valid_after', '?')}",
            failed=True,  # an expiry inside the window is always a hard fault
        )

    for r in licences:
        ts = parse_any_ts(r.get("exp"))
        if ts is None or ts > grace_end:
            continue
        _add(
            "licence expiry",
            ts,
            f"licence `{r.get('app', '?')}` ({r.get('license_type', '')}) expired",
            f"SKU `{r.get('license_type', '?')}` expiry {r.get('exp', '?')[:19]}",
            failed=True,
        )

    candidates.sort(key=lambda c: (abs(c["delta_min"]), not c["failed"]))
    return candidates


def _rfo_draft(
    incident_dt: datetime,
    symptom: str,
    candidates: list[dict[str, Any]],
    drifted: list[SectionDiff],
) -> str:
    what = symptom or "a service-affecting event"
    when = incident_dt.strftime("%Y-%m-%d %H:%M UTC")
    if candidates:
        top = candidates[0]
        direction = "before" if top["delta_min"] >= 0 else "after"
        cause = (
            f"Investigation of the change and expiry timeline identified {top['desc']} at "
            f"{top['ts']} ({abs(top['delta_min'])} minutes {direction} the reported incident) "
            f"as the most probable contributing factor (evidence: {top['evidence']})."
        )
    else:
        cause = (
            "Investigation of the change and expiry timeline found no configuration push, "
            "certificate expiry, or licence expiry correlated with the incident window; "
            "the cause is currently attributed to factors outside recorded configuration "
            "events (e.g. carrier, platform, or upstream service)."
        )
    drift_note = ""
    if drifted:
        sections = ", ".join(d.label for d in drifted[:4])
        drift_note = (
            f" Configuration analysis additionally shows {len(drifted)} section(s) changed "
            f"since the last approved baseline ({sections})."
        )
    return (
        f"On {when}, {what} was reported. {cause}{drift_note} "
        "Remediation and monitoring actions: [OPERATOR TO COMPLETE]. This statement is "
        "based on temporal correlation of recorded events and is pending operator "
        "confirmation of the causal chain."
    )


def render_rca_report(
    incident_dt: datetime,
    symptom: str,
    lookback_hours: int,
    candidates: list[dict[str, Any]],
    drifted: list[SectionDiff],
    baseline_saved_at: str | None,
    unchecked: list[str],
    tenant_label: str,
    folder: str,
    generated_at: str,
) -> str:
    lines = [
        "# Incident Root-Cause Correlation",
        "",
        f"**Tenant:** `{tenant_label}`  |  **Folder:** `{folder}`  |  "
        f"**Incident:** {incident_dt.strftime('%Y-%m-%d %H:%M UTC')}  |  "
        f"**Lookback:** {lookback_hours}h  |  **Generated:** {generated_at}",
    ]
    if symptom:
        lines.append(f"**Reported symptom:** {symptom}")
    lines.append("")

    if candidates:
        lines += [
            f"## Candidate Causes ({len(candidates)}) — nearest first",
            "",
            "| # | When | Relative to incident | Kind | What | Evidence |",
            "|---|---|---|---|---|---|",
        ]
        for i, c in enumerate(candidates[:15], 1):
            rel = f"{abs(c['delta_min'])} min " + ("before" if c["delta_min"] >= 0 else "after")
            lines.append(
                f"| {i} | {c['ts']} | {rel} | {c['kind']} | {c['desc']} | {c['evidence']} |"
            )
        if len(candidates) > 15:
            lines.append(f"| … | | | | +{len(candidates) - 15} more in window | |")
        lines.append("")
    else:
        lines += [
            "## Candidate Causes",
            "",
            "🟢 No config pushes, certificate expiries, or licence expiries fall inside "
            "the incident window.",
            "",
        ]

    if drifted:
        lines += [
            "## State Evidence — Drift Since Last Approved Baseline",
            "",
            f"_Baseline from {baseline_saved_at or '?'} — drift shows *what* differs, "
            "not *when* it changed; correlate with the job timeline above._",
            "",
        ]
        for d in drifted:
            sev = drift_severity(d)
            icon = {"HIGH": "🔴", "MEDIUM": "🟡"}.get(sev, "⚪")
            parts = []
            if d.added:
                parts.append(f"added {_name_list(d.added, cap=8)}")
            if d.removed:
                parts.append(f"removed {_name_list(d.removed, cap=8)}")
            if d.changed:
                parts.append(f"modified {_name_list(d.changed, cap=8)}")
            lines.append(f"- {icon} **[{sev}] {d.label}**: " + "; ".join(parts))
        lines.append("")
    elif baseline_saved_at is not None:
        lines += [
            "## State Evidence — Drift Since Last Approved Baseline",
            "",
            f"🟢 No drift vs the baseline from {baseline_saved_at}.",
            "",
        ]

    lines += ["## RFO Draft (customer-facing)", ""]
    lines.append(f"> {_rfo_draft(incident_dt, symptom, candidates, drifted)}")
    lines.append("")

    lines += ["## Caveats", ""]
    lines.append(
        "- **Correlation is not causation** — every candidate above is a temporal match; "
        "confirm the causal chain before publishing the RFO."
    )
    for u in unchecked:
        lines.append(f"- Not checked this run: {u}")
    lines.append("")
    return "\n".join(lines)
