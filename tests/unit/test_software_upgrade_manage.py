"""Unit tests for scm_software_upgrade_manage (SSR-gated software-upgrade writes).

Every name, id and serial here is invented. The fake session records every
request so the tests can prove a dry run sends nothing that writes.
"""

from __future__ import annotations

import copy
import datetime as dt
import json
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.tools import software_upgrade
from scm_harbourmaster_mcp.tools.software_upgrade import register_software_upgrade_tools
from scm_harbourmaster_mcp.utils.tool_annotations import annotations_for

_BASE = "https://api.strata.paloaltonetworks.com/config/device/v1"
SCHED_ID = "11111111-1111-4111-8111-111111111111"
SCHED_OFF_ID = "22222222-2222-4222-8222-222222222222"
RULE_ID = "44444444-4444-4444-8444-444444444444"
RULE_SPARE_ID = "55555555-5555-4555-8555-555555555555"
TICKET = "CHG-0001"

RULES = [
    {
        "id": RULE_ID,
        "name": "fw-wave",
        "match_criteria": {"folders": {"include": ["branches"]}},
    },
    {
        "id": RULE_SPARE_ID,
        "name": "fw-spare",
        "match_criteria": {"models": {"include": [{"name": "PA-440"}]}},
    },
]

SCHEDULES = [
    {
        "id": SCHED_ID,
        "name": "wave-1",
        "enabled": True,
        "image_version": "11.2.0",
        "job_type": "download-install-reboot",
        "install_starttime": {"date": "2000/01/01", "at": "02:00"},
        "allow_downgrade": False,
        "rules": ["fw-wave"],
    },
    {
        "id": SCHED_OFF_ID,
        "name": "wave-off",
        "enabled": False,
        "image_version": "11.2.0",
        "job_type": "download",
        "download_starttime": {"date": "2000/01/01", "at": "02:00"},
        "rules": ["fw-wave"],
    },
]

FUTURE = {"date": "2099-01-02", "at": "03:30"}
FUTURE_SENT = {"date": "2099/01/02", "at": "03:30"}
PAST = {"date": "2001-01-01", "at": "03:30"}

_WRITE_METHODS = ("PUT", "DELETE")


class FakeResp:
    def __init__(self, status_code: int, body: Any) -> None:
        self.status_code = status_code
        self._body = body
        self.text = json.dumps(body)

    def json(self) -> Any:
        if self._body is None:
            raise ValueError("no body")
        return self._body


class FakeSession:
    def __init__(self, *, fail: str = "", overall: str = "") -> None:
        self.calls: list[tuple[str, str, dict[str, Any], Any]] = []
        self.fail = fail
        self.overall = overall
        self.schedules = copy.deepcopy(SCHEDULES)
        self.rules = copy.deepcopy(RULES)

    def writes(self) -> list[tuple[str, str, dict[str, Any], Any]]:
        """Every call that would change SCM (match-criteria POSTs only read)."""
        return [
            c
            for c in self.calls
            if c[0] in _WRITE_METHODS
            or (c[0] == "POST" and c[1] != "software-upgrade-match-criteria")
        ]

    def request(
        self, method: str, url: str, *, params: Any = None, json: Any = None, timeout: Any = None
    ) -> FakeResp:
        params = dict(params or {})
        path = url.removeprefix(_BASE + "/")
        self.calls.append((method, path, params, json))
        if (
            self.fail
            and method == self.fail.split(" ")[0]
            and path.startswith(self.fail.split(" ")[1])
        ):
            return FakeResp(400, {"_errors": [{"code": "E400", "message": "Invalid body"}]})
        if method == "GET" and path in ("software-upgrade-schedules", "software-upgrade-rules"):
            rows = self.schedules if path.endswith("schedules") else self.rules
            return FakeResp(200, {"data": rows, "total": len(rows), "limit": params.get("limit")})
        if method == "GET" and path == "software-upgrade-status":
            if not self.overall:
                return FakeResp(201, [])
            entry = {"schedule_id": params["uuid"], "overall_status": self.overall, "devices": []}
            return FakeResp(201, [entry])
        if method == "POST" and path == "software-upgrade-match-criteria":
            criteria = json["rule"]["match_criteria"]
            # First-match: placed after every rule, earlier rules claim the devices
            if (json.get("position") or {}).get("order") == "post":
                return FakeResp(200, {"devices": []})
            if "models" in criteria:
                return FakeResp(200, {"devices": ["SER3"]})
            return FakeResp(200, {"devices": ["SER1", "SER2"]})
        if method == "POST":
            return FakeResp(201, {**json, "id": "99999999-9999-4999-8999-999999999999"})
        if method == "PUT":
            return FakeResp(200, {**json, "id": path.rsplit("/", 1)[1]})
        if method == "DELETE":
            return FakeResp(200, None)
        return FakeResp(404, {"_errors": [{"message": "not found"}]})


@pytest.fixture
def session(monkeypatch: pytest.MonkeyPatch) -> FakeSession:
    fake = FakeSession()
    monkeypatch.setattr(software_upgrade, "_bearer_session_for", lambda client: fake)
    return fake


@pytest.fixture
def manage() -> Any:
    mcp = FastMCP("test")
    register_software_upgrade_tools(mcp, lambda tenant_id="": MagicMock())
    fn = mcp._tool_manager._tools["scm_software_upgrade_manage"].fn

    def call(**kwargs: Any) -> dict[str, Any]:
        kwargs.setdefault("tenant_id", "t")
        kwargs.setdefault("ticket_ref", TICKET)
        if "body" in kwargs:
            kwargs["body_json"] = json.dumps(kwargs.pop("body"))
        result: dict[str, Any] = json.loads(fn(**kwargs))
        return result

    return call


def _schedule(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": "wave-2",
        "enabled": True,
        "image_version": "11.2.1",
        "job_type": "download-install-reboot",
        "install_starttime": FUTURE,
        "rules": ["fw-wave"],
    }
    body.update(overrides)
    return body


# ---------------------------------------------------------------------------
# Safety gate
# ---------------------------------------------------------------------------


def test_ticket_ref_required_even_for_dry_run(manage: Any, session: FakeSession) -> None:
    for kwargs in ({"ticket_ref": ""}, {"ticket_ref": "   "}, {"ticket_ref": "", "dry_run": False}):
        out = manage(resource="schedule", action="create", body=_schedule(), **kwargs)
        assert "ticket_ref is mandatory" in out["error"]
    assert session.calls == []


def test_dry_run_is_the_default_and_sends_no_write(manage: Any, session: FakeSession) -> None:
    out = manage(resource="schedule", action="create", body=_schedule())
    assert out["dry_run"] is True and "applied" not in out
    assert out["ticket_ref"] == TICKET
    assert "Dry run only" in out["hint"]
    assert session.writes() == []


def test_ticket_ref_is_never_in_a_request_body(manage: Any, session: FakeSession) -> None:
    manage(resource="schedule", action="create", body=_schedule(), dry_run=False)
    manage(
        resource="rule",
        action="update",
        target="fw-spare",
        body={"description": "x"},
        dry_run=False,
    )
    sent = [c[3] for c in session.calls if c[3] is not None]
    assert sent and all(TICKET not in json.dumps(b) for b in sent)
    out = manage(resource="rule", action="create", body={"name": "r", "ticket_ref": TICKET})
    assert "ticket_ref belongs in the ticket_ref argument" in out["error"]


def test_applied_write_is_audited_before_the_call(
    manage: Any, session: FakeSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[tuple[str, int]] = []

    def fake_audit(tool: str, ticket_ref: str, tenant_id: str = "", **details: Any) -> None:
        events.append((f"{tool}|{ticket_ref}|{details['action']}", len(session.writes())))

    monkeypatch.setattr(software_upgrade, "audit_write", fake_audit)
    manage(resource="schedule", action="create", body=_schedule())
    assert events == []  # dry run: no audit line
    out = manage(resource="schedule", action="create", body=_schedule(), dry_run=False)
    assert out["applied"] is True
    # Logged once, before the write reached the API
    assert events == [(f"scm_software_upgrade_manage|{TICKET}|create", 0)]


def test_bad_resource_and_action(manage: Any, session: FakeSession) -> None:
    assert "resource must be one of" in manage(resource="device", action="create")["error"]
    assert "action must be one of" in manage(resource="rule", action="move")["error"]
    assert session.calls == []


def test_write_tool_annotations() -> None:
    write = annotations_for("scm_software_upgrade_manage")
    assert write.readOnlyHint is False and write.destructiveHint is True
    assert write.idempotentHint is False
    assert annotations_for("scm_software_upgrade").readOnlyHint is True


# ---------------------------------------------------------------------------
# Schedules
# ---------------------------------------------------------------------------


def test_schedule_create_dry_run_shows_exact_request_and_impact(
    manage: Any, session: FakeSession
) -> None:
    out = manage(resource="schedule", action="create", body=_schedule(rules=[RULE_ID]))
    req = out["request"]
    assert req["method"] == "POST"
    assert req["url"] == f"{_BASE}/software-upgrade-schedules"
    # Dates go out as YYYY/MM/DD; a rule id is converted to its name
    assert req["body"] == {**_schedule(), "install_starttime": FUTURE_SENT, "rules": ["fw-wave"]}
    assert out["impact"]["firewalls_matched"] == 2
    assert out["impact"]["per_rule"] == {"fw-wave": 2}
    assert any("REBOOTS" in w for w in out["warnings"])


def test_schedule_create_applies(manage: Any, session: FakeSession) -> None:
    out = manage(resource="schedule", action="create", body=_schedule(), dry_run=False)
    assert out["applied"] is True and out["result"]["name"] == "wave-2"
    method, path, _, body = session.writes()[0]
    assert (method, path) == ("POST", "software-upgrade-schedules")
    assert body["install_starttime"] == FUTURE_SENT and "id" not in body


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"install_starttime": PAST}, "is in the past"),
        ({"install_starttime": {"date": "2099-02-30", "at": "01:00"}}, "not a real date"),
        ({"install_starttime": {"date": "02/01/2099", "at": "01:00"}}, "must be YYYY-MM-DD"),
        ({"install_starttime": {"date": "2099-01-02", "at": "25:00"}}, "must be HH:MM"),
        ({"install_starttime": {"date": "2099-01-02"}}, "must be {"),
        ({"rules": ["no-such-rule"]}, "no software-upgrade rule named 'no-such-rule'"),
        ({"rules": []}, "at least one"),
        ({"rules": "fw-wave"}, "list of non-empty strings"),
        ({"job_type": "reboot"}, "job_type must be one of"),
        ({"job_type": "download"}, "needs download_starttime"),
        (
            {"job_type": "download", "download_starttime": FUTURE},
            "only downloads: drop install_starttime",
        ),
        (
            {"download_starttime": {"date": "2099-01-03", "at": "00:00"}},
            "must not be after install_starttime",
        ),
        ({"image_version": ""}, "image_version is required"),
        ({"enabled": "yes"}, "enabled must be true or false"),
        ({"name": "WAVE-1"}, "already exists"),
        ({"colour": "red"}, "unknown schedule field(s): colour"),
    ],
)
def test_schedule_create_validation(
    manage: Any, session: FakeSession, overrides: dict[str, Any], message: str
) -> None:
    out = manage(resource="schedule", action="create", body=_schedule(**overrides), dry_run=False)
    assert message in out["error"], out
    assert session.writes() == []


def test_body_json_errors(manage: Any, session: FakeSession) -> None:
    assert "body_json is required" in manage(resource="schedule", action="create")["error"]
    out = manage(resource="schedule", action="create", body_json="{nope")
    assert "not valid JSON" in out["error"]
    assert "JSON object" in manage(resource="rule", action="create", body=[1])["error"]
    out = manage(resource="schedule", action="create", body={**_schedule(), "id": SCHED_ID})
    assert "id is read-only" in out["error"]


def test_start_today_warns(manage: Any, session: FakeSession) -> None:
    today = dt.datetime.now(dt.UTC).date().isoformat()
    out = manage(
        resource="schedule",
        action="create",
        body=_schedule(install_starttime={"date": today, "at": "23:59"}),
    )
    assert "error" not in out
    assert any("time zone" in w for w in out["warnings"])


def test_schedule_update_merges_over_current(manage: Any, session: FakeSession) -> None:
    out = manage(
        resource="schedule", action="update", target="wave-1", body={"description": "notes"}
    )
    req = out["request"]
    assert req["method"] == "PUT"
    assert req["url"] == f"{_BASE}/software-upgrade-schedules/{SCHED_ID}"
    expected = {k: v for k, v in SCHEDULES[0].items() if k != "id"}
    assert req["body"] == {**expected, "description": "notes"}
    assert out["diff"] == {"description": {"from": None, "to": "notes"}}
    assert out["target"] == {"id": SCHED_ID, "name": "wave-1"}
    # The past start time was not touched, so it is not re-checked
    assert "error" not in out
    assert session.writes() == []


def test_schedule_update_by_id_applies(manage: Any, session: FakeSession) -> None:
    out = manage(
        resource="schedule",
        action="update",
        target=SCHED_ID,
        body={"install_starttime": FUTURE},
        dry_run=False,
    )
    assert out["applied"] is True
    method, path, _, body = session.writes()[0]
    assert (method, path) == ("PUT", f"software-upgrade-schedules/{SCHED_ID}")
    assert body["install_starttime"] == FUTURE_SENT and "id" not in body


def test_schedule_update_past_start_and_noop(manage: Any, session: FakeSession) -> None:
    out = manage(
        resource="schedule", action="update", target="wave-1", body={"install_starttime": PAST}
    )
    assert "is in the past" in out["error"]
    out = manage(resource="schedule", action="update", target="wave-1", body={"enabled": True})
    assert "nothing to change" in out["error"]


def test_schedule_reenable_needs_future_start(manage: Any, session: FakeSession) -> None:
    out = manage(resource="schedule", action="update", target="wave-off", body={"enabled": True})
    assert "download_starttime 2000/01/01 02:00 is in the past" in out["error"]
    out = manage(
        resource="schedule",
        action="update",
        target="wave-off",
        body={"enabled": True, "download_starttime": FUTURE},
    )
    assert "this update ENABLES the schedule" in out["warnings"]
    assert out["impact"]["firewalls_matched"] == 2


def test_schedule_update_null_removes_field(manage: Any, session: FakeSession) -> None:
    out = manage(
        resource="schedule",
        action="update",
        target="wave-off",
        body={
            "job_type": "download-install-reboot",
            "download_starttime": None,
            "install_starttime": FUTURE,
        },
    )
    body = out["request"]["body"]
    assert "download_starttime" not in body and body["install_starttime"] == FUTURE_SENT
    assert out["diff"]["download_starttime"]["to"] is None


def test_schedule_update_unknown_target(manage: Any, session: FakeSession) -> None:
    out = manage(resource="schedule", action="update", target="nope", body={"enabled": False})
    assert "no software-upgrade schedule named 'nope'" in out["error"]
    out = manage(resource="schedule", action="update", body={"enabled": False})
    assert "target" in out["error"]


def test_schedule_delete(manage: Any, session: FakeSession) -> None:
    out = manage(resource="schedule", action="delete", target="wave-1")
    assert out["request"] == {
        "method": "DELETE",
        "url": f"{_BASE}/software-upgrade-schedules/{SCHED_ID}",
    }
    assert out["current"]["name"] == "wave-1" and session.writes() == []
    out = manage(resource="schedule", action="delete", target="wave-1", dry_run=False)
    assert out["applied"] is True and "result" not in out
    assert session.writes() == [("DELETE", f"software-upgrade-schedules/{SCHED_ID}", {}, None)]


def test_schedule_delete_warns_when_running(monkeypatch: pytest.MonkeyPatch, manage: Any) -> None:
    fake = FakeSession(overall="inprogress")
    monkeypatch.setattr(software_upgrade, "_bearer_session_for", lambda client: fake)
    out = manage(resource="schedule", action="delete", target="wave-1")
    assert any("inprogress" in w for w in out["warnings"])


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def test_rule_create_normalises_and_previews(manage: Any, session: FakeSession) -> None:
    body = {
        "name": "fw-lab",
        "match_criteria": {
            "folders": {"include": ["lab"]},
            "models": {"include": ["PA-440", {"name": "PA-450"}]},
            "exclude_devices": ["SER9"],
        },
    }
    out = manage(resource="rule", action="create", body=body)
    req = out["request"]
    assert req["method"] == "POST" and req["url"] == f"{_BASE}/software-upgrade-rules"
    assert req["body"]["match_criteria"]["models"] == {
        "include": [{"name": "PA-440"}, {"name": "PA-450"}]
    }
    # A new rule lands last; the criteria alone would match one firewall
    assert out["impact"]["firewalls_matched"] == 0
    assert out["impact"]["firewalls_matched_if_first"] == 1
    assert "first-match" in out["impact"]["note"]
    previews = [c[3] for c in session.calls if c[1] == "software-upgrade-match-criteria"]
    assert [p["position"] for p in previews] == [
        {"id": RULE_SPARE_ID, "order": "post"},
        {"id": RULE_ID, "order": "pre"},
    ]
    assert all(p["rule"]["name"] == "fw-lab" and "id" not in p["rule"] for p in previews)
    assert session.writes() == []
    out = manage(resource="rule", action="create", body=body, dry_run=False)
    assert out["applied"] is True
    assert session.writes()[0][:2] == ("POST", "software-upgrade-rules")


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ({"name": "r"}, "match_criteria is required"),
        ({"name": "r", "match_criteria": {}}, "match_criteria is required"),
        ({"name": "r", "match_criteria": {"sites": []}}, "unknown match_criteria field(s): sites"),
        (
            {"name": "r", "match_criteria": {"folders": {"include": "lab"}}},
            "folders.include must be a list",
        ),
        (
            {"name": "r", "match_criteria": {"folders": {"any": {}, "include": ["lab"]}}},
            "both any and include",
        ),
        ({"name": "r", "match_criteria": {"folders": {"all": True}}}, "any, include or exclude"),
        ({"name": "r", "match_criteria": {"labels": ["x"]}}, "labels must be a string"),
        ({"name": "", "match_criteria": {"labels": "x"}}, "rule name is required"),
        ({"name": "FW-WAVE", "match_criteria": {"labels": "x"}}, "already exists"),
        ({"name": "r", "match_criteria": {"labels": "x"}, "rules": []}, "unknown rule field(s)"),
    ],
)
def test_rule_validation(
    manage: Any, session: FakeSession, body: dict[str, Any], message: str
) -> None:
    out = manage(resource="rule", action="create", body=body, dry_run=False)
    assert message in out["error"], out
    assert session.writes() == []


def test_rule_matching_everything_warns(manage: Any, session: FakeSession) -> None:
    out = manage(
        resource="rule",
        action="create",
        body={"name": "all", "match_criteria": {"folders": {"any": {}}}},
    )
    assert any("does not narrow" in w for w in out["warnings"])


def test_rule_update_rename_warns_about_schedules(manage: Any, session: FakeSession) -> None:
    out = manage(resource="rule", action="update", target="fw-wave", body={"name": "fw-wave-2"})
    assert out["request"]["url"] == f"{_BASE}/software-upgrade-rules/{RULE_ID}"
    assert out["diff"] == {"name": {"from": "fw-wave", "to": "fw-wave-2"}}
    assert any("wave-1, wave-off" in w for w in out["warnings"])
    # Criteria unchanged: no device preview
    assert "impact" not in out


def test_rule_update_criteria_previews_saved_rule(manage: Any, session: FakeSession) -> None:
    out = manage(
        resource="rule",
        action="update",
        target=RULE_ID,
        body={"match_criteria": {"folders": {"include": ["branches", "lab"]}}},
    )
    preview = next(c for c in session.calls if c[1] == "software-upgrade-match-criteria")
    # A saved rule keeps its place by id; no position is sent
    assert preview[3]["rule"]["id"] == RULE_ID and "position" not in preview[3]
    assert out["impact"]["firewalls_matched"] == 2
    # Only the enabled schedule is named: its targets change
    assert "changes which firewalls these ENABLED schedules upgrade: wave-1" in out["warnings"]


def test_first_rule_preview_without_existing_rules(
    monkeypatch: pytest.MonkeyPatch, manage: Any
) -> None:
    fake = FakeSession()
    fake.rules = []
    monkeypatch.setattr(software_upgrade, "_bearer_session_for", lambda client: fake)
    out = manage(
        resource="rule",
        action="create",
        body={"name": "fw-lab", "match_criteria": {"folders": {"include": ["lab"]}}},
    )
    preview = next(c for c in fake.calls if c[1] == "software-upgrade-match-criteria")
    assert "position" not in preview[3]
    assert out["impact"]["firewalls_matched"] == 2


def test_rule_delete_blocked_while_used(manage: Any, session: FakeSession) -> None:
    out = manage(resource="rule", action="delete", target="fw-wave", dry_run=False)
    assert "used by schedule(s) wave-1, wave-off" in out["error"]
    assert session.writes() == []


def test_rule_delete_unused(manage: Any, session: FakeSession) -> None:
    out = manage(resource="rule", action="delete", target="fw-spare")
    assert out["request"]["method"] == "DELETE" and session.writes() == []
    out = manage(resource="rule", action="delete", target="fw-spare", dry_run=False)
    assert out["applied"] is True
    assert session.writes() == [("DELETE", f"software-upgrade-rules/{RULE_SPARE_ID}", {}, None)]


# ---------------------------------------------------------------------------
# API errors
# ---------------------------------------------------------------------------


def test_api_error_on_apply(monkeypatch: pytest.MonkeyPatch, manage: Any) -> None:
    fake = FakeSession(fail="POST software-upgrade-schedules")
    monkeypatch.setattr(software_upgrade, "_bearer_session_for", lambda client: fake)
    out = manage(resource="schedule", action="create", body=_schedule(), dry_run=False)
    assert out["applied"] is False and "HTTP 400: Invalid body" in out["error"]
    assert out["ticket_ref"] == TICKET


def test_impact_preview_failure_degrades(monkeypatch: pytest.MonkeyPatch, manage: Any) -> None:
    fake = FakeSession(fail="POST software-upgrade-match-criteria")
    monkeypatch.setattr(software_upgrade, "_bearer_session_for", lambda client: fake)
    out = manage(resource="schedule", action="create", body=_schedule())
    assert "could not preview" in out["impact"]["error"]
    assert out["request"]["method"] == "POST"


def test_list_failure_is_reported(monkeypatch: pytest.MonkeyPatch, manage: Any) -> None:
    fake = FakeSession(fail="GET software-upgrade-rules")
    monkeypatch.setattr(software_upgrade, "_bearer_session_for", lambda client: fake)
    out = manage(resource="rule", action="delete", target="fw-spare")
    assert "software-upgrade API call failed" in out["error"]
