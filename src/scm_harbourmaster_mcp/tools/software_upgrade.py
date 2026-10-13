"""MCP tools for NGFW software-upgrade rules, schedules and status.

Covers the software-upgrade part of the R3 device-settings spec
(``openapi-specs/scm/config/ngfw/device/device-settings_R3.yaml``), base
``https://api.strata.paloaltonetworks.com/config/device/v1``:

  * ``/software-upgrade-schedules``      — what PAN-OS image goes where, when
  * ``/software-upgrade-rules``          — which firewalls a schedule targets
  * ``/software-upgrade-status``         — per-device, per-phase progress
  * ``/software-upgrade-match-criteria`` — preview the devices a rule matches
    (a POST, but it only reads)

pan-scm-sdk has no binding, so this is raw REST over the shared Bearer
session.  ``scm_software_upgrade`` is read-only.  ``scm_software_upgrade_manage``
creates, updates and deletes schedules and rules; since an enabled schedule
can queue a download-install-reboot on a customer's firewalls it follows the
SSR write pattern (``utils/write_safety``): dry_run by default (returns the
exact request, sends nothing that writes), ticket_ref mandatory and never put
in a request body, and an audit-log line before every applied write.

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

import datetime as dt
import json
import re
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..audit.extractor import _bearer_session_for
from ..utils.formatting import format_result as _fmt
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool
from ..utils.write_safety import DRY_RUN_HINT, audit_write, normalize_ticket_ref, ticket_ref_error

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


def _matched_devices(
    session: Any, rule: dict[str, Any], position: dict[str, str] | None = None
) -> list[str]:
    """Serials a (saved or unsaved) rule matches now.  A POST that only reads.

    Rules are first-match: a firewall an earlier rule matches is not counted.
    A saved rule is placed by its id; an unsaved one by *position*
    (``{"id": <rule id>, "order": "pre" | "post"}``).  Without either the
    API counts nothing (lab tenants, 2026-10-13).
    """
    payload: dict[str, Any] = {
        "name": rule.get("name") or "tempRule",
        "match_criteria": rule.get("match_criteria") or {},
    }
    if rule.get("id"):
        payload["id"] = rule["id"]
    body: dict[str, Any] = {"rule": payload}
    if position and not rule.get("id"):
        body["position"] = position
    result = _call(session, "POST", "software-upgrade-match-criteria", json=body)
    devices = result.get("devices") if isinstance(result, dict) else None
    return [str(d) for d in devices or []]


def _match(session: Any, rule: str) -> str:
    if not rule:
        return "Error: view='match' needs rule=<rule name>."
    rules = _list(session, "software-upgrade-rules")
    target = next((r for r in rules if r.get("name") == rule or r.get("id") == rule), None)
    if target is None:
        return f"Error: no software-upgrade rule named {rule!r}."
    devices = _matched_devices(session, target)
    lines = [f"# Devices matched by rule {_cell(target['name'])}", ""]
    lines.append(f"Criteria: {_cell(_criteria_text(target.get('match_criteria')))}\n")
    if not devices:
        lines.append("No firewalls match this rule now.")
    else:
        lines.append(f"{len(devices)} firewall(s):")
        lines += [f"- {d}" for d in devices]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Writes (scm_software_upgrade_manage) — SSR pattern
# ---------------------------------------------------------------------------

_WRITE_TOOL = "scm_software_upgrade_manage"
_WRITE_RESOURCES = {
    "schedule": "software-upgrade-schedules",
    "rule": "software-upgrade-rules",
}
_WRITE_ACTIONS = ("create", "update", "delete")

# Writable fields per the R3 spec (``id`` is read-only and never sent).
_SCHEDULE_KEYS = frozenset(
    {
        "name",
        "description",
        "enabled",
        "image_version",
        "job_type",
        "download_starttime",
        "install_starttime",
        "allow_downgrade",
        "ha_orchestration",
        "rules",
    }
)
_RULE_KEYS = frozenset({"name", "description", "enabled", "match_criteria"})
_CRITERIA_KEYS = frozenset({"folders", "models", "labels", "exclude_devices"})
_SCOPE_KEYS = frozenset({"any", "include", "exclude"})
_START_KEYS = ("download_starttime", "install_starttime")

# job_type -> the start time it needs.  ``download-install-reboot`` is what
# the API stores in practice (the spec's enum only lists download/install).
_JOB_TYPES = {
    "download": "download_starttime",
    "install": "install_starttime",
    "download-install-reboot": "install_starttime",
}
_TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def _parse_body(body_json: str, allowed: frozenset[str], resource: str) -> dict[str, Any]:
    """body_json -> dict, rejecting read-only, unknown and provenance keys."""
    if not body_json or not body_json.strip():
        raise ValueError(f"body_json is required: a JSON object with the {resource}'s fields")
    try:
        body = json.loads(body_json)
    except json.JSONDecodeError as exc:
        raise ValueError(f"body_json is not valid JSON: {exc}") from exc
    if not isinstance(body, dict):
        raise ValueError("body_json must be a JSON object")
    if "ticket_ref" in body:
        raise ValueError(
            "ticket_ref belongs in the ticket_ref argument, not body_json; it is never sent to SCM"
        )
    if "id" in body:
        raise ValueError(f"id is read-only; name the {resource} to change with target=")
    unknown = sorted(set(body) - allowed)
    if unknown:
        raise ValueError(
            f"unknown {resource} field(s): {', '.join(unknown)}. "
            f"Allowed: {', '.join(sorted(allowed))}"
        )
    return body


def _str_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise ValueError(f"{field} must be a list of non-empty strings")
    return [v.strip() for v in value]


def _check_types(body: dict[str, Any], strings: tuple[str, ...], bools: tuple[str, ...]) -> None:
    for key in strings:
        if key in body and not isinstance(body[key], str):
            raise ValueError(f"{key} must be a string")
    for key in bools:
        if key in body and not isinstance(body[key], bool):
            raise ValueError(f"{key} must be true or false")


def _start_datetime(key: str, value: Any) -> tuple[dict[str, str], dt.datetime]:
    """Validate one start-time object; return it normalised and as a datetime."""
    if not isinstance(value, dict) or set(value) != {"date", "at"}:
        raise ValueError(f'{key} must be {{"date": "YYYY-MM-DD", "at": "HH:MM"}}')
    date_m = _DATE_RE.match(str(value["date"]).strip())
    if not date_m:
        raise ValueError(f"{key}.date must be YYYY-MM-DD, got {value['date']!r}")
    at = str(value["at"]).strip()
    if not _TIME_RE.match(at):
        raise ValueError(f"{key}.at must be HH:MM (24-hour), got {value['at']!r}")
    year, month, day = (int(g) for g in date_m.groups())
    try:
        when = dt.datetime(year, month, day, int(at[:2]), int(at[3:]))
    except ValueError as exc:
        raise ValueError(f"{key}.date is not a real date: {value['date']!r}") from exc
    # Schedules store dates as YYYY/MM/DD (and the date filter rejects the
    # spec's dashes), so the slash form is what gets sent.
    return {"date": "/".join(date_m.groups()), "at": at}, when


def _validate_schedule(
    body: dict[str, Any],
    rules: list[dict[str, Any]],
    check_future: set[str],
    today: dt.date,
) -> list[str]:
    """Validate (and normalise in place) a full schedule body; return warnings.

    *check_future* names the start times that must not lie in the past: the
    ones this call sets, so editing the description of a schedule that has
    already run still works.
    """
    _check_types(
        body,
        ("name", "description", "image_version", "job_type"),
        ("enabled", "allow_downgrade", "ha_orchestration"),
    )
    warnings: list[str] = []
    for key in ("name", "image_version", "job_type"):
        if not str(body.get(key) or "").strip():
            raise ValueError(f"schedule {key} is required")
    job_type = body["job_type"]
    if job_type not in _JOB_TYPES:
        raise ValueError(f"job_type must be one of {', '.join(_JOB_TYPES)}, got {job_type!r}")
    needed = _JOB_TYPES[job_type]
    if needed not in body:
        raise ValueError(f"job_type {job_type!r} needs {needed}")
    if job_type == "download" and "install_starttime" in body:
        raise ValueError(
            "job_type 'download' only downloads: drop install_starttime (null on update)"
        )

    starts: dict[str, dt.datetime] = {}
    for key in _START_KEYS:
        if key not in body:
            continue
        body[key], starts[key] = _start_datetime(key, body[key])
        if key not in check_future:
            continue
        when = f"{body[key]['date']} {body[key]['at']}"
        if starts[key].date() < today:
            raise ValueError(f"{key} {when} is in the past")
        if starts[key].date() == today:
            warnings.append(
                f"{key} is today ({when}); the API does not say which time zone 'at' "
                "is in, so check it has not already passed"
            )
    if len(starts) == 2 and starts["download_starttime"] > starts["install_starttime"]:
        raise ValueError("download_starttime must not be after install_starttime")

    if "rules" not in body:
        raise ValueError("schedule rules is required: the names of the rules it targets")
    refs = _str_list(body["rules"], "rules")
    if not refs:
        raise ValueError("rules must name at least one software-upgrade rule")
    by_id = {str(r.get("id")): str(r.get("name")) for r in rules}
    known = {str(r.get("name")) for r in rules}
    resolved: list[str] = []
    missing: list[str] = []
    for ref in refs:
        # Schedules reference rules by name; an id is converted to its name
        name = ref if ref in known else by_id.get(ref, "")
        if not name:
            missing.append(ref)
        elif name not in resolved:
            resolved.append(name)
    if missing:
        raise ValueError(f"no software-upgrade rule named {', '.join(map(repr, missing))}")
    body["rules"] = resolved
    if body.get("allow_downgrade"):
        warnings.append("allow_downgrade is true: matched firewalls may be downgraded")
    if job_type == "download-install-reboot" and body.get("enabled", True):
        warnings.append(
            "job_type download-install-reboot REBOOTS every matched firewall at install time"
        )
    return warnings


def _validate_rule(body: dict[str, Any]) -> list[str]:
    """Validate (and normalise in place) a full rule body; return warnings."""
    _check_types(body, ("name", "description"), ("enabled",))
    if not str(body.get("name") or "").strip():
        raise ValueError("rule name is required")
    criteria = body.get("match_criteria")
    if not isinstance(criteria, dict) or not criteria:
        raise ValueError(
            "rule match_criteria is required: an object with folders, models, labels "
            "and/or exclude_devices"
        )
    unknown = sorted(set(criteria) - _CRITERIA_KEYS)
    if unknown:
        raise ValueError(
            f"unknown match_criteria field(s): {', '.join(unknown)}. "
            f"Allowed: {', '.join(sorted(_CRITERIA_KEYS))}"
        )
    for key in ("folders", "models"):
        if key not in criteria:
            continue
        scope = criteria[key]
        if not isinstance(scope, dict) or not scope or set(scope) - _SCOPE_KEYS:
            raise ValueError(f"match_criteria.{key} must be an object with any, include or exclude")
        if "any" in scope:
            if scope["any"] not in ({}, None):
                raise ValueError(f"match_criteria.{key}.any must be {{}}")
            if "include" in scope:
                raise ValueError(f"match_criteria.{key} cannot have both any and include")
            scope["any"] = {}
        for part in ("include", "exclude"):
            if part not in scope:
                continue
            values = scope[part]
            if key == "models":
                # Models are {"name": ...} objects; plain strings are accepted
                if isinstance(values, list):
                    values = [v.get("name") if isinstance(v, dict) else v for v in values]
                scope[part] = [{"name": n} for n in _str_list(values, f"models.{part}")]
            else:
                scope[part] = _str_list(values, f"folders.{part}")
    if "labels" in criteria and not isinstance(criteria["labels"], str):
        raise ValueError("match_criteria.labels must be a string (a label expression)")
    if "exclude_devices" in criteria:
        criteria["exclude_devices"] = _str_list(criteria["exclude_devices"], "exclude_devices")
    narrows = [
        k
        for k in ("folders", "models", "labels")
        if k in criteria and not (isinstance(criteria[k], dict) and "any" in criteria[k])
    ]
    if not narrows:
        return ["match_criteria does not narrow by folder, model or label"]
    return []


def _find_rule(rules: list[dict[str, Any]], ref: str) -> dict[str, Any] | None:
    return next((r for r in rules if r.get("id") == ref or r.get("name") == ref), None)


def _impact(session: Any, rules: list[dict[str, Any]]) -> dict[str, Any]:
    """Firewalls the given rules match now (best effort; read-only POSTs)."""
    devices: set[str] = set()
    per_rule: dict[str, int] = {}
    try:
        for rule in rules:
            matched = _matched_devices(session, rule)
            per_rule[str(rule.get("name"))] = len(matched)
            devices.update(matched)
    except _ApiError as exc:
        return {"error": f"could not preview matched firewalls: {exc}"}
    return {
        "firewalls_matched": len(devices),
        "per_rule": per_rule,
        "serials": sorted(devices)[:50],
    }


def _new_rule_impact(
    session: Any, rule: dict[str, Any], existing: list[dict[str, Any]]
) -> dict[str, Any]:
    """Preview for a rule that is not saved yet.

    Rules are first-match and a new rule is assumed to land last, so its
    real reach excludes firewalls earlier rules already match.  The count
    as if it were first shows what the criteria alone would match.
    """
    ordered = [r for r in existing if r.get("id")]
    if not ordered:
        return _impact(session, [rule])
    try:
        last = _matched_devices(session, rule, {"id": ordered[-1]["id"], "order": "post"})
        first = _matched_devices(session, rule, {"id": ordered[0]["id"], "order": "pre"})
    except _ApiError as exc:
        return {"error": f"could not preview matched firewalls: {exc}"}
    out: dict[str, Any] = {
        "firewalls_matched": len(last),
        "per_rule": {str(rule.get("name")): len(last)},
        "serials": sorted(last)[:50],
        "firewalls_matched_if_first": len(first),
        "note": "Rules are first-match and a new rule is assumed to be added last; "
        "firewalls an earlier rule already matches are not counted.",
    }
    return out


def _diff(current: dict[str, Any], planned: dict[str, Any]) -> dict[str, Any]:
    keys = sorted((set(current) | set(planned)) - {"id"})
    return {
        k: {"from": current.get(k), "to": planned.get(k)}
        for k in keys
        if current.get(k) != planned.get(k)
    }


def _schedules_using(schedules: list[dict[str, Any]], rule_name: str) -> list[str]:
    return [str(s.get("name")) for s in schedules if rule_name in (s.get("rules") or [])]


def _plan_write(
    session: Any,
    resource: str,
    action: str,
    target: str,
    patch: dict[str, Any],
    out: dict[str, Any],
) -> tuple[str, str, dict[str, Any] | None, dict[str, Any] | None]:
    """Validate a write and fill *out*; return (method, path, body, current).

    Reads only: list GETs, a status GET, and match-criteria POSTs (which
    only read) for the impact preview.
    """
    path = _WRITE_RESOURCES[resource]
    if action != "create" and not target:
        raise ValueError(f"target (the {resource}'s name or id) is required for {action}")
    existing = _list(session, path)
    current: dict[str, Any] | None = None
    if action != "create":
        current = (
            _find_schedule(existing, target)
            if resource == "schedule"
            else _find_rule(existing, target)
        )
        if current is None or not current.get("id"):
            raise ValueError(f"no software-upgrade {resource} named {target!r}")
        out["target"] = {"id": current["id"], "name": current.get("name")}

    warnings: list[str] = []
    if action == "delete":
        assert current is not None
        out["current"] = current
        if resource == "rule":
            users = _schedules_using(
                _list(session, _WRITE_RESOURCES["schedule"]), str(current.get("name"))
            )
            if users:
                raise ValueError(
                    f"rule {current.get('name')!r} is used by schedule(s) "
                    f"{', '.join(users)}; remove it from them first"
                )
        else:
            try:
                entries = _status(session, [str(current["id"])])
            except _ApiError:
                entries = []
            state = next((str(e.get("overall_status") or "") for e in entries), "")
            if state in ("inprogress", "started"):
                warnings.append(
                    f"this schedule's upgrade is {state}; deleting it may not stop "
                    "firewalls that have already started"
                )
        if warnings:
            out["warnings"] = warnings
        return "DELETE", f"{path}/{current['id']}", None, current

    if current is None:
        planned = dict(patch)
        changed = set(planned)
    else:
        planned = {k: v for k, v in current.items() if k != "id"}
        for key, value in patch.items():
            # PUT replaces the whole object; null removes a field
            if value is None:
                planned.pop(key, None)
            else:
                planned[key] = value
        changed = {k for k in patch if current.get(k) != planned.get(k)}

    if "name" in changed and isinstance(planned.get("name"), str):
        planned["name"] = planned["name"].strip()
        clash = next(
            (
                e
                for e in existing
                if e is not current and str(e.get("name", "")).lower() == planned["name"].lower()
            ),
            None,
        )
        if clash is not None:
            raise ValueError(
                f"a software-upgrade {resource} named {clash.get('name')!r} already exists"
            )

    impact: dict[str, Any] | None = None
    if resource == "schedule":
        rules = _list(session, _WRITE_RESOURCES["rule"])
        check = {k for k in _START_KEYS if k in changed}
        if current is not None and planned.get("enabled") and not current.get("enabled"):
            # Re-enabling an old schedule must not fire on a stale start time
            check |= {k for k in _START_KEYS if k in planned}
            warnings.append("this update ENABLES the schedule")
        warnings += _validate_schedule(planned, rules, check, dt.datetime.now(dt.UTC).date())
        if planned.get("enabled", True):
            impact = _impact(session, [r for r in rules if r.get("name") in planned["rules"]])
    else:
        warnings += _validate_rule(planned)
        if current is not None and planned["name"] != current.get("name"):
            users = _schedules_using(
                _list(session, _WRITE_RESOURCES["schedule"]), str(current.get("name"))
            )
            if users:
                warnings.append(
                    "schedules name their rules, so renaming leaves these still "
                    f"pointing at {current.get('name')!r}: {', '.join(users)}"
                )
        if current is None:
            impact = _new_rule_impact(session, planned, existing)
        elif "match_criteria" in changed:
            # The saved rule's id keeps its place in the first-match order
            impact = _impact(session, [{**planned, "id": current["id"]}])
            enabled_users = [
                str(s.get("name"))
                for s in _list(session, _WRITE_RESOURCES["schedule"])
                if s.get("enabled") and current.get("name") in (s.get("rules") or [])
            ]
            if enabled_users:
                warnings.append(
                    "changes which firewalls these ENABLED schedules upgrade: "
                    + ", ".join(enabled_users)
                )

    if current is not None:
        out["diff"] = _diff(current, planned)
        if not out["diff"]:
            raise ValueError(f"nothing to change: the {resource} already has these values")
    if impact is not None:
        out["impact"] = impact
    if warnings:
        out["warnings"] = warnings
    if current is None:
        return "POST", path, planned, None
    return "PUT", f"{path}/{current['id']}", planned, current


def _manage(
    session: Any,
    tenant_id: str,
    resource: str,
    action: str,
    target: str,
    body_json: str,
    dry_run: bool,
    ticket_ref: str,
) -> dict[str, Any]:
    allowed = _SCHEDULE_KEYS if resource == "schedule" else _RULE_KEYS
    patch = _parse_body(body_json, allowed, resource) if action != "delete" else {}
    out: dict[str, Any] = {
        "tool": _WRITE_TOOL,
        "resource": resource,
        "action": action,
        "dry_run": dry_run,
        "ticket_ref": ticket_ref,
    }
    method, path, body, current = _plan_write(session, resource, action, target, patch, out)
    request: dict[str, Any] = {"method": method, "url": f"{_BASE}/{path}"}
    if body is not None:
        request["body"] = body
    out["request"] = request

    if dry_run:
        out["hint"] = DRY_RUN_HINT
        return out

    audit_write(
        _WRITE_TOOL,
        ticket_ref,
        tenant_id,
        resource=resource,
        action=action,
        name=(body or current or {}).get("name"),
        resource_id=(current or {}).get("id", ""),
    )
    if body is not None:
        result = _call(session, method, path, json=body)
    else:
        result = _call(session, method, path)
    out["applied"] = True
    if result is not None:
        out["result"] = result
    out["hint"] = "Check progress with scm_software_upgrade (view='overview' or 'status')."
    return out


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_software_upgrade_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register the NGFW software-upgrade tools (read view + SSR-gated writes)."""
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

    @mcp.tool()
    @tool
    def scm_software_upgrade_manage(
        client: Any,
        tenant_id: str,
        resource: str,
        action: str,
        target: str = "",
        body_json: str = "",
        dry_run: bool = True,
        ticket_ref: str = "",
    ) -> str:
        """Create, update or delete NGFW software-upgrade schedules and rules.

        Write side of ``scm_software_upgrade`` (use that tool to look first).
        A **schedule** says which PAN-OS image to download or install and
        when; a **rule** says which firewalls a schedule targets. An enabled
        schedule with job_type ``download-install-reboot`` installs the image
        on, and REBOOTS, every firewall its rules match at the install time.

        **Write safety (SSR pattern):**
          - ``dry_run=True`` by default: validates, then returns the exact
            request (method, URL, JSON body) that would be sent, the current
            object and a diff for update/delete, and, for an enabled schedule
            or a rule's criteria, the firewalls matched now. Nothing is
            written (the device preview is a match-criteria POST that only
            reads). Rules are first-match, so a new rule (added last) only
            counts firewalls no earlier rule matches; the preview also gives
            the count as if it were first.
          - ``ticket_ref`` is mandatory on every call, dry run included. It is
            written to the audit log and echoed back, never sent to SCM.

        Checks before anything is sent: only spec fields are allowed (``id``
        and ``ticket_ref`` are rejected); start times set by the call must
        not be in the past; job_type must match its start time; a
        schedule's rules must exist (ids are converted to names, which is
        how schedules reference rules); names must be unique; a rule used
        by a schedule cannot be deleted; re-enabling a schedule needs a
        future start time.

        body_json fields:
          - schedule: name, description, enabled, image_version, job_type
            (download | install | download-install-reboot),
            download_starttime / install_starttime
            ``{"date": "YYYY-MM-DD", "at": "HH:MM"}`` (download jobs use
            download_starttime, the others install_starttime), allow_downgrade,
            ha_orchestration, rules (rule names).
          - rule: name, description, enabled, match_criteria with folders
            ``{"include": [...]}`` / ``{"any": {}}`` / ``exclude``, models
            ``{"include": ["PA-440"]}``, labels (a label expression) and
            exclude_devices (serials).

        Update sends the whole object (the API's PUT replaces it): the
        current object is read and body_json's fields are merged over it;
        set a field to null to remove it.

        Args:
            tenant_id: SCM tenant ID (MSSP mode).
            resource: schedule | rule.
            action: create | update | delete.
            target: Name or id of the schedule/rule, for update and delete.
            body_json: JSON object of fields, for create and update.
            dry_run: If True (default), plan and validate without writing.
            ticket_ref: Mandatory change-ticket reference (never sent to SCM).

        Returns:
            JSON: the planned or applied request, diff, impact and warnings.
        """
        err = ticket_ref_error(ticket_ref)
        if err:
            return _fmt({"error": err})
        ticket_ref = normalize_ticket_ref(ticket_ref)
        if resource not in _WRITE_RESOURCES:
            return _fmt({"error": f"resource must be one of {', '.join(_WRITE_RESOURCES)}"})
        if action not in _WRITE_ACTIONS:
            return _fmt({"error": f"action must be one of {', '.join(_WRITE_ACTIONS)}"})
        try:
            session = _bearer_session_for(client)
            return _fmt(
                _manage(
                    session,
                    tenant_id,
                    resource,
                    action,
                    target.strip(),
                    body_json,
                    dry_run,
                    ticket_ref,
                )
            )
        except ValueError as exc:
            return _fmt({"error": str(exc), "ticket_ref": ticket_ref, "dry_run": dry_run})
        except _ApiError as exc:
            logger.warning(
                "software_upgrade_write_error", resource=resource, action=action, error=str(exc)
            )
            return _fmt(
                {
                    "error": f"software-upgrade API call failed: {exc}",
                    "applied": False,
                    "ticket_ref": ticket_ref,
                    "dry_run": dry_run,
                }
            )
