"""MCP tool for NGFW software-upgrade rules, schedules and status (read-only).

Covers the software-upgrade part of the R3 device-settings spec
(``openapi-specs/scm/config/ngfw/device/device-settings_R3.yaml``), base
``https://api.strata.paloaltonetworks.com/config/device/v1``:

  * ``/software-upgrade-schedules``      — what PAN-OS image goes where, when
  * ``/software-upgrade-rules``          — which firewalls a schedule targets
  * ``/software-upgrade-status``         — per-device, per-phase progress
  * ``/software-upgrade-match-criteria`` — preview the devices a rule matches
    (a POST, but it only reads)

pan-scm-sdk has no binding, so this is raw REST over the shared Bearer
session.  The tool is read-only: creating or editing a schedule can queue a
download-install-reboot on a customer's firewalls, which needs the SSR write
pattern before it is exposed.

Live quirks (lab tenants, 2026-10-12) the code handles:
  * List calls without ``limit`` return a bare JSON list; with ``limit`` they
    return the usual ``{"data", "total"}`` envelope.
  * The status GET answers 201, not 200.
  * ``job_type`` is ``download-install-reboot`` in practice, which is not in
    the spec's enum (download, install); it is passed through as given.
  * The ``date`` filter on schedules means "starts on or after" and only
    accepts ``YYYY/MM/DD`` (the spec's ``YYYY-MM-DD`` is a 500 "invalid
    date"), and any ``date`` sent with ``limit`` is a 500.  ``from_date`` is
    therefore applied here, to the schedules' own start dates.
  * Schedules list their rules by name; status entries carry the rule's id.
  * Phase states are COMPLETED, FAILED, SKIPPED or "" (not reached), and the
    timestamps are Go-formatted strings.
"""

from __future__ import annotations

import re
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..audit.extractor import _bearer_session_for
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool

logger = get_logger(__name__)

_BASE = "https://api.strata.paloaltonetworks.com/config/device/v1"
_TIMEOUT = (10, 30)
_PAGE = 200
_MAX_PAGES = 25
# Schedule UUIDs per status call: the ids travel comma-separated in the query.
_STATUS_CHUNK = 50

_VIEWS = ("overview", "schedules", "rules", "status", "match")

# Upgrade phases in the order a device goes through them.
_PHASES = ("initialize", "content", "precheck", "downloading", "upgrading", "postcheck")

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_DATE_RE = re.compile(r"^(\d{4})[-/](\d{2})[-/](\d{2})$")


class _ApiError(Exception):
    pass


# ---------------------------------------------------------------------------
# REST helpers
# ---------------------------------------------------------------------------


def _error_text(resp: Any) -> str:
    try:
        body = resp.json()
    except Exception:
        body = None
    if isinstance(body, dict):
        errors = body.get("_errors") or []
        if errors and isinstance(errors[0], dict):
            first = errors[0]
            return f"HTTP {resp.status_code}: {first.get('message') or first.get('code')}"
    return f"HTTP {resp.status_code}: {str(getattr(resp, 'text', ''))[:200]}"


def _call(session: Any, method: str, path: str, **kwargs: Any) -> Any:
    """JSON body of a 2xx response; raises _ApiError otherwise."""
    try:
        resp = session.request(method, f"{_BASE}/{path}", timeout=_TIMEOUT, **kwargs)
    except Exception as exc:
        raise _ApiError(str(exc)[:200]) from exc
    # The status endpoint answers 201 to a GET
    if not 200 <= resp.status_code < 300:
        hint = ""
        if resp.status_code in (401, 403):
            hint = " (the service account's role may not include NGFW device settings)"
        raise _ApiError(_error_text(resp) + hint)
    try:
        return resp.json()
    except Exception:
        return None


def _rows(body: Any) -> tuple[list[dict[str, Any]], int | None]:
    if isinstance(body, list):
        return [r for r in body if isinstance(r, dict)], None
    if isinstance(body, dict):
        data = body.get("data")
        rows = [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []
        total = body.get("total")
        return rows, total if isinstance(total, int) else None
    return [], None


def _list(session: Any, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Every row of a list endpoint.  Always sends limit, so the API pages."""
    rows: list[dict[str, Any]] = []
    for page in range(_MAX_PAGES):
        body = _call(
            session,
            "GET",
            path,
            params={**(params or {}), "limit": _PAGE, "offset": page * _PAGE},
        )
        batch, total = _rows(body)
        rows.extend(batch)
        if len(batch) < _PAGE or total is None or len(rows) >= total:
            break
    return rows


def _status(session: Any, schedule_ids: list[str], serial: str = "") -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for i in range(0, len(schedule_ids), _STATUS_CHUNK):
        params = {"uuid": ",".join(schedule_ids[i : i + _STATUS_CHUNK])}
        if serial:
            params["serial"] = serial
        body = _call(session, "GET", "software-upgrade-status", params=params)
        entries.extend(e for e in body or [] if isinstance(e, dict))
    return entries


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


def _api_date(value: str) -> str:
    """YYYY-MM-DD or YYYY/MM/DD → YYYY/MM/DD, the form schedules store."""
    m = _DATE_RE.match(value.strip())
    if not m:
        raise ValueError(f"from_date must be YYYY-MM-DD, got {value!r}")
    return "/".join(m.groups())


def _schedules_from(session: Any, from_date: str) -> list[dict[str, Any]]:
    """Every schedule, or those with a start date on or after *from_date*."""
    floor = _api_date(from_date) if from_date else ""
    schedules = _list(session, "software-upgrade-schedules")
    if not floor:
        return schedules
    kept = []
    for s in schedules:
        dates = []
        for st in (s.get("download_starttime"), s.get("install_starttime")):
            m = _DATE_RE.match(str(st.get("date") or "")) if isinstance(st, dict) else None
            if m:
                dates.append("/".join(m.groups()))
        if any(d >= floor for d in dates):
            kept.append(s)
    return kept


def _start(schedule: dict[str, Any]) -> str:
    parts = []
    for key, label in (("download_starttime", "download"), ("install_starttime", "install")):
        st = schedule.get(key)
        if isinstance(st, dict) and (st.get("date") or st.get("at")):
            parts.append(f"{label} {st.get('date', '?')} {st.get('at', '')}".strip())
    return "; ".join(parts) or "—"


def _phase_states(device: dict[str, Any]) -> dict[str, dict[str, Any]]:
    status = device.get("status") if isinstance(device.get("status"), dict) else {}
    details = status.get("status_details") if isinstance(status, dict) else None
    return details if isinstance(details, dict) else {}


def _device_outcome(device: dict[str, Any]) -> tuple[str, str, str]:
    """(outcome, phase, description) for one device's status entry.

    outcome is failed / completed / in progress / not started.  For a failure
    phase and description name the first failed phase in run order.
    """
    phases = _phase_states(device)
    states = {p: str((phases.get(p) or {}).get("state") or "").upper() for p in phases}
    for phase in (*_PHASES, *sorted(set(phases) - set(_PHASES))):
        if states.get(phase) == "FAILED":
            desc = str((phases.get(phase) or {}).get("description") or "")
            return "failed", phase, desc
    run = [p for p in _PHASES if p in states]
    if run and all(states[p] in ("COMPLETED", "SKIPPED") for p in run):
        return "completed", "", ""
    if any(s for s in states.values()):
        current = next((p for p in run if states[p] not in ("COMPLETED", "SKIPPED")), "")
        return "in progress", current, ""
    return "not started", "", ""


def _criteria_text(match: Any) -> str:
    if not isinstance(match, dict) or not match:
        return "—"
    parts: list[str] = []
    for key in ("folders", "models"):
        block = match.get(key)
        if not isinstance(block, dict):
            continue
        if "any" in block:
            parts.append(f"{key}: any")

        def names(values: Any) -> list[str]:
            out = []
            for v in values or []:
                out.append(str(v.get("name")) if isinstance(v, dict) else str(v))
            return out

        if block.get("include"):
            parts.append(f"{key}: {', '.join(names(block['include']))}")
        if block.get("exclude"):
            parts.append(f"{key} except: {', '.join(names(block['exclude']))}")
    if match.get("labels"):
        parts.append(f"labels: {match['labels']}")
    if match.get("exclude_devices"):
        parts.append(f"excluded devices: {len(match['exclude_devices'])}")
    return "; ".join(parts) or "—"


def _cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _yes(value: Any) -> str:
    return "yes" if value else "no"


def _find_schedule(schedules: list[dict[str, Any]], ref: str) -> dict[str, Any] | None:
    for s in schedules:
        if s.get("id") == ref or s.get("name") == ref:
            return s
    lowered = ref.lower()
    matches = [s for s in schedules if str(s.get("name", "")).lower() == lowered]
    return matches[0] if len(matches) == 1 else None


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------


def _summarise_entry(entry: dict[str, Any] | None) -> tuple[str, str, list[str]]:
    """(overall status, device counts, deduplicated failure lines)."""
    if not entry or not entry.get("devices"):
        return "no status yet", "—", []
    counts: dict[str, int] = {}
    failures: dict[tuple[str, str], int] = {}
    for device in entry["devices"]:
        outcome, phase, desc = _device_outcome(device)
        counts[outcome] = counts.get(outcome, 0) + 1
        if outcome == "failed":
            key = (phase, desc)
            failures[key] = failures.get(key, 0) + 1
    overall = str(entry.get("overall_status") or "") or "unknown"
    order = ("completed", "in progress", "failed", "not started")
    count_text = ", ".join(f"{counts[o]} {o}" for o in order if counts.get(o))
    lines = [
        f"{n} device{'s' if n != 1 else ''} failed at **{phase}**: {_cell(desc[:400]) or '(no detail)'}"
        for (phase, desc), n in failures.items()
    ]
    return overall, count_text, lines


def _overview(session: Any, from_date: str) -> str:
    schedules = _schedules_from(session, from_date)
    rules = _list(session, "software-upgrade-rules")
    lines = ["# NGFW software upgrades", ""]
    if from_date:
        lines.append(f"Schedules starting on or after {from_date}.\n")
    if not schedules:
        lines.append("No software-upgrade schedules.")
        lines.append(f"\n{len(rules)} upgrade rule(s) defined.")
        return "\n".join(lines)

    ids = [str(s["id"]) for s in schedules if s.get("id")]
    status_error = ""
    try:
        status_by_id = {str(e.get("schedule_id")): e for e in _status(session, ids)}
    except _ApiError as exc:
        status_by_id, status_error = {}, str(exc)

    lines.append(f"{len(schedules)} schedule(s), {len(rules)} rule(s).\n")
    lines.append("| Schedule | Enabled | Job | Image | Starts | Rules | Status | Devices |")
    lines.append("|---|---|---|---|---|---|---|---|")
    failure_notes: list[str] = []
    for s in schedules:
        overall, counts, failures = _summarise_entry(status_by_id.get(str(s.get("id"))))
        if status_error:
            overall, counts = "unavailable", "—"
        flags = []
        if s.get("allow_downgrade"):
            flags.append("downgrade allowed")
        if s.get("ha_orchestration"):
            flags.append("HA orchestration")
        image = _cell(s.get("image_version", "—")) + (f" ({', '.join(flags)})" if flags else "")
        lines.append(
            f"| {_cell(s.get('name', '?'))} | {_yes(s.get('enabled'))} "
            f"| {_cell(s.get('job_type', '—'))} | {image} | {_cell(_start(s))} "
            f"| {_cell(', '.join(s.get('rules') or []) or '—')} | {overall} | {counts} |"
        )
        if failures:
            failure_notes.append(f"**{_cell(s.get('name', '?'))}**")
            failure_notes += [f"- {f}" for f in failures]
    if status_error:
        lines.append(f"\nStatus could not be read: {status_error}")
    if failure_notes:
        lines += ["", "## Failures", "", *failure_notes]
    known = {str(r.get("name")) for r in rules}
    dangling = sorted({r for s in schedules for r in s.get("rules") or []} - known)
    if dangling:
        lines.append(f"\nSchedules name rules that do not exist: {', '.join(dangling)}")
    return "\n".join(lines)


def _schedules(session: Any, from_date: str) -> str:
    schedules = _schedules_from(session, from_date)
    if not schedules:
        return "No software-upgrade schedules."
    lines = ["# Software-upgrade schedules", ""]
    for s in schedules:
        lines.append(f"## {_cell(s.get('name', '?'))}")
        if s.get("description"):
            lines.append(f"{_cell(s['description'])}\n")
        lines.append(f"- id: `{s.get('id', '')}`")
        lines.append(f"- enabled: {_yes(s.get('enabled'))}")
        lines.append(f"- job type: {s.get('job_type', '—')}")
        lines.append(f"- image: {s.get('image_version', '—')}")
        lines.append(f"- starts: {_start(s)}")
        lines.append(f"- downgrade allowed: {_yes(s.get('allow_downgrade'))}")
        lines.append(f"- HA orchestration: {_yes(s.get('ha_orchestration'))}")
        lines.append(f"- rules: {', '.join(s.get('rules') or []) or '—'}\n")
    return "\n".join(lines)


def _rules(session: Any) -> str:
    rules = _list(session, "software-upgrade-rules")
    if not rules:
        return "No software-upgrade rules."
    lines = ["# Software-upgrade rules", "", "| Rule | Enabled | Matches | Description |"]
    lines.append("|---|---|---|---|")
    for r in rules:
        enabled = "—" if "enabled" not in r else _yes(r.get("enabled"))
        lines.append(
            f"| {_cell(r.get('name', '?'))} | {enabled} | {_cell(_criteria_text(r.get('match_criteria')))} "
            f"| {_cell(r.get('description') or '')} |"
        )
    lines.append("\nUse view='match' with rule=<name> to list the firewalls a rule matches now.")
    return "\n".join(lines)


def _status_view(session: Any, schedule: str, serial: str) -> str:
    if not schedule:
        return "Error: view='status' needs schedule=<schedule name or id>."
    schedules = _list(session, "software-upgrade-schedules")
    target = _find_schedule(schedules, schedule)
    if target is None:
        if not _UUID_RE.match(schedule):
            return f"Error: no software-upgrade schedule named {schedule!r}."
        target = {"id": schedule, "name": schedule}
    rules = {str(r.get("id")): str(r.get("name")) for r in _list(session, "software-upgrade-rules")}
    entries = _status(session, [str(target["id"])], serial)
    entry = next((e for e in entries if e.get("schedule_id") == target["id"]), None)
    name = _cell(target.get("name", target["id"]))
    lines = [f"# Upgrade status — {name}", ""]
    lines.append(
        f"Image {target.get('image_version', '—')}, {target.get('job_type', '—')}, "
        f"starts {_start(target)}."
    )
    if not entry or not entry.get("devices"):
        scope = f" for device {serial}" if serial else ""
        lines.append(f"\nNo status{scope} yet: the schedule has not run on any device.")
        return "\n".join(lines)
    overall, counts, _ = _summarise_entry(entry)
    lines.append(f"\nOverall: **{overall}** ({counts}).\n")
    header = "| Device | Rule | Outcome | " + " | ".join(_PHASES) + " |"
    lines += [header, "|" + "---|" * (3 + len(_PHASES))]
    failures: list[str] = []
    for device in entry["devices"]:
        outcome, phase, desc = _device_outcome(device)
        phases = _phase_states(device)
        states = [str((phases.get(p) or {}).get("state") or "—").lower() for p in _PHASES]
        serial_no = _cell(device.get("device_serial_no", "?"))
        rule = _cell(rules.get(str(device.get("rule_id")), device.get("rule_id", "—")))
        lines.append(f"| {serial_no} | {rule} | {outcome} | " + " | ".join(states) + " |")
        if outcome == "failed":
            failures.append(f"- **{serial_no}** at {phase}: {_cell(desc) or '(no detail)'}")
    if failures:
        lines += ["", "## Failures", "", *failures]
    return "\n".join(lines)


def _match(session: Any, rule: str) -> str:
    if not rule:
        return "Error: view='match' needs rule=<rule name>."
    rules = _list(session, "software-upgrade-rules")
    target = next((r for r in rules if r.get("name") == rule or r.get("id") == rule), None)
    if target is None:
        return f"Error: no software-upgrade rule named {rule!r}."
    body = {
        "rule": {
            "name": target["name"],
            "id": target.get("id"),
            "match_criteria": target.get("match_criteria") or {},
        }
    }
    result = _call(session, "POST", "software-upgrade-match-criteria", json=body) or {}
    devices = [str(d) for d in result.get("devices") or []]
    lines = [f"# Devices matched by rule {_cell(target['name'])}", ""]
    lines.append(f"Criteria: {_cell(_criteria_text(target.get('match_criteria')))}\n")
    if not devices:
        lines.append("No firewalls match this rule now.")
    else:
        lines.append(f"{len(devices)} firewall(s):")
        lines += [f"- {d}" for d in devices]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_software_upgrade_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register the read-only NGFW software-upgrade tool."""
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_software_upgrade(
        client: Any,
        tenant_id: str,
        view: str = "overview",
        schedule: str = "",
        rule: str = "",
        serial: str = "",
        from_date: str = "",
    ) -> str:
        """Show NGFW software-upgrade schedules, rules and upgrade progress.

        Read-only view of SCM's software-upgrade scheduler for NGFWs (the
        ``config/device/v1`` software-upgrade API). Schedules say which
        PAN-OS image to download or install and when; rules say which
        firewalls a schedule targets (by folder, model, label or excluded
        serials). Rules and schedules are tenant-wide, not per folder.

        Views:
          - ``overview`` (default): every schedule with its job type, image,
            start time and rules, joined with its latest upgrade status
            (overall result, devices by outcome, and the phase and PAN error
            text for failed devices).
          - ``schedules``: full detail of each schedule, including ids.
          - ``rules``: each rule's match criteria.
          - ``status``: per-device, per-phase progress for one schedule
            (``schedule`` = name or id; ``serial`` narrows to one firewall).
            Phases run initialize, content, precheck, downloading, upgrading,
            postcheck.
          - ``match``: the firewalls a rule matches now (``rule`` = name).
            The API is a POST, but it only reads.

        Args:
            tenant_id: SCM tenant ID (MSSP mode).
            view: overview | schedules | rules | status | match.
            schedule: Schedule name or id, for view='status'.
            rule: Rule name, for view='match'.
            serial: Firewall serial number, to narrow view='status'.
            from_date: YYYY-MM-DD; overview and schedules then list only
                schedules starting on or after that date.

        Returns:
            Markdown.
        """
        if view not in _VIEWS:
            return f"Error: view must be one of {', '.join(_VIEWS)}."
        try:
            session = _bearer_session_for(client)
            if view == "overview":
                return _overview(session, from_date)
            if view == "schedules":
                return _schedules(session, from_date)
            if view == "rules":
                return _rules(session)
            if view == "status":
                return _status_view(session, schedule.strip(), serial.strip())
            return _match(session, rule.strip())
        except ValueError as exc:
            return f"Error: {exc}"
        except _ApiError as exc:
            logger.warning("software_upgrade_api_error", view=view, error=str(exc))
            return f"Error: software-upgrade API call failed: {exc}"
