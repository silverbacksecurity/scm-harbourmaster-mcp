"""Unit tests for the read-only NGFW software-upgrade tool.

Response shapes follow what the live API returned on lab tenants
(2026-10-12); every name, id and serial here is invented.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.tools import software_upgrade
from scm_harbourmaster_mcp.tools.software_upgrade import register_software_upgrade_tools

_BASE = "https://api.strata.paloaltonetworks.com/config/device/v1"
SCHED_A = "11111111-1111-4111-8111-111111111111"
SCHED_B = "22222222-2222-4222-8222-222222222222"
SCHED_C = "33333333-3333-4333-8333-333333333333"
RULE_ID = "44444444-4444-4444-8444-444444444444"

_BASE_IMAGE_ERROR = (
    "Preloading into software managerThe required 11.0.0 base image must be loaded "
    "before this image can be loaded."
)


def _phase(state: str, description: str = "") -> dict[str, str]:
    return {"state": state, "description": description, "starttimestamp": "", "endtimestamp": ""}


def _device(serial: str, **states: str) -> dict[str, Any]:
    details = {p: _phase("") for p in software_upgrade._PHASES}
    for phase, state in states.items():
        details[phase] = _phase(state, _BASE_IMAGE_ERROR if state == "FAILED" else "")
    return {
        "device_serial_no": serial,
        "rule_id": RULE_ID,
        "status": {"starttime": "", "endtime": "", "status_details": details},
    }


SCHEDULES = [
    {
        "id": SCHED_A,
        "name": "wave-1",
        "enabled": True,
        "job_type": "download-install-reboot",
        "image_version": "11.0.1",
        "install_starttime": {"at": "20:00", "date": "2026/02/18"},
        "allow_downgrade": False,
        "rules": ["branch-firewalls"],
    },
    {
        "id": SCHED_B,
        "name": "wave-2",
        "enabled": True,
        "job_type": "download",
        "image_version": "11.0.2",
        "download_starttime": {"at": "08:15", "date": "2026/02/19"},
        "rules": ["branch-firewalls", "gone-rule"],
    },
    {
        "id": SCHED_C,
        "name": "wave-3",
        "enabled": False,
        "job_type": "download-install-reboot",
        "image_version": "11.0.2",
        "install_starttime": {"at": "12:30", "date": "2026/03/01"},
        "rules": ["branch-firewalls"],
    },
]

RULES = [
    {
        "id": RULE_ID,
        "name": "branch-firewalls",
        "match_criteria": {
            "folders": {"include": ["branches"]},
            "models": {"include": [{"name": "PA-400"}]},
            "exclude_devices": ["000000000003"],
            "labels": "wave",
        },
    }
]

_DONE = dict.fromkeys(software_upgrade._PHASES, "COMPLETED")

STATUS = [
    {
        "schedule_id": SCHED_A,
        "overall_status": "failed",
        "devices": [
            _device(
                "000000000001", initialize="COMPLETED", content="COMPLETED", downloading="FAILED"
            ),
            _device(
                "000000000002", initialize="COMPLETED", content="SKIPPED", downloading="FAILED"
            ),
            _device("000000000004", **_DONE),
        ],
    },
    {
        "schedule_id": SCHED_B,
        "overall_status": "inprogress",
        "devices": [_device("000000000001", initialize="COMPLETED", precheck="COMPLETED")],
    },
]


class FakeResp:
    def __init__(self, status_code: int, body: Any) -> None:
        self.status_code = status_code
        self._body = body
        self.text = json.dumps(body)

    def json(self) -> Any:
        return self._body


class FakeSession:
    """Answers like the live API: bare lists without limit, envelopes with it."""

    def __init__(self, *, status_code: int = 201, fail: str = "") -> None:
        self.calls: list[tuple[str, str, dict[str, Any], Any]] = []
        self.status_code = status_code
        self.fail = fail

    def request(
        self, method: str, url: str, *, params: Any = None, json: Any = None, timeout: Any = None
    ) -> FakeResp:
        params = dict(params or {})
        path = url.removeprefix(_BASE + "/")
        self.calls.append((method, path, params, json))
        if self.fail and path.startswith(self.fail):
            return FakeResp(403, {"_errors": [{"code": "E403", "message": "Forbidden"}]})
        if path in ("software-upgrade-schedules", "software-upgrade-rules"):
            rows = SCHEDULES if path.endswith("schedules") else RULES
            if "date" in params:
                floor = params["date"]
                rows = [
                    r
                    for r in rows
                    if (r.get("install_starttime") or r.get("download_starttime"))["date"] >= floor
                ]
            if "limit" not in params:
                return FakeResp(200, rows)
            start = int(params.get("offset", 0))
            page = rows[start : start + int(params["limit"])]
            return FakeResp(200, {"data": page, "total": len(rows), "limit": params["limit"]})
        if path == "software-upgrade-status":
            wanted = params["uuid"].split(",")
            entries = [e for e in STATUS if e["schedule_id"] in wanted]
            if params.get("serial"):
                entries = [
                    {
                        **e,
                        "devices": [
                            d for d in e["devices"] if d["device_serial_no"] == params["serial"]
                        ],
                    }
                    for e in entries
                ]
            return FakeResp(self.status_code, entries)
        if path == "software-upgrade-match-criteria":
            return FakeResp(200, {"devices": ["000000000001", "000000000002"]})
        return FakeResp(404, {"_errors": [{"message": "not found"}]})


@pytest.fixture
def session(monkeypatch: pytest.MonkeyPatch) -> FakeSession:
    fake = FakeSession()
    monkeypatch.setattr(software_upgrade, "_bearer_session_for", lambda client: fake)
    return fake


@pytest.fixture
def tool() -> Any:
    mcp = FastMCP("test")
    register_software_upgrade_tools(mcp, lambda tenant_id="": MagicMock())
    return mcp._tool_manager._tools["scm_software_upgrade"].fn


def test_overview_joins_status_and_dedupes_failures(tool: Any, session: FakeSession) -> None:
    out = tool(tenant_id="t")
    assert "3 schedule(s), 1 rule(s)" in out
    row_a = next(line for line in out.splitlines() if line.startswith("| wave-1 "))
    assert "download-install-reboot" in row_a and "failed" in row_a
    assert "1 completed, 2 failed" in row_a
    # Two devices failed the same way: reported once with a count
    assert out.count("base image must be loaded") == 1
    assert "2 devices failed at **downloading**" in out
    row_b = next(line for line in out.splitlines() if line.startswith("| wave-2 "))
    assert "inprogress" in row_b and "1 in progress" in row_b
    row_c = next(line for line in out.splitlines() if line.startswith("| wave-3 "))
    assert "no status yet" in row_c and "| no |" in row_c
    assert "gone-rule" in out.split("do not exist:")[1]
    # One batched status call carrying every schedule id
    status_calls = [c for c in session.calls if c[1] == "software-upgrade-status"]
    assert len(status_calls) == 1
    assert status_calls[0][2]["uuid"].split(",") == [SCHED_A, SCHED_B, SCHED_C]


def test_list_calls_always_send_limit(tool: Any, session: FakeSession) -> None:
    tool(tenant_id="t", view="rules")
    gets = [c for c in session.calls if c[0] == "GET"]
    assert gets and all(c[2].get("limit") == software_upgrade._PAGE for c in gets)


def test_bare_list_bodies_are_accepted() -> None:
    assert software_upgrade._rows(SCHEDULES) == (SCHEDULES, None)
    assert software_upgrade._rows({"data": RULES, "total": 1}) == (RULES, 1)


def test_pagination_follows_total(monkeypatch: pytest.MonkeyPatch, session: FakeSession) -> None:
    monkeypatch.setattr(software_upgrade, "_PAGE", 2)
    rows = software_upgrade._list(session, "software-upgrade-schedules")
    assert [r["name"] for r in rows] == ["wave-1", "wave-2", "wave-3"]
    assert [c[2]["offset"] for c in session.calls] == [0, 2]


def test_from_date_filters_on_start_dates(tool: Any, session: FakeSession) -> None:
    out = tool(tenant_id="t", view="schedules", from_date="2026-02-19")
    # The API 500s on date + limit, so the filter is applied locally
    assert all("date" not in c[2] for c in session.calls)
    assert "wave-1" not in out and "wave-2" in out and "wave-3" in out
    assert "wave-1" not in tool(tenant_id="t", from_date="2026/02/19")
    assert "Error" in tool(tenant_id="t", from_date="19/02/2026")


def test_status_view_by_name_with_phases(tool: Any, session: FakeSession) -> None:
    out = tool(tenant_id="t", view="status", schedule="wave-1")
    assert "Overall: **failed** (1 completed, 2 failed)" in out
    line = next(line for line in out.splitlines() if line.startswith("| 000000000002 "))
    # Rule ids in status map back to rule names
    assert "| branch-firewalls | failed |" in line
    assert "skipped" in line and "failed" in line
    assert "**000000000001** at downloading" in out


def test_status_view_serial_and_not_run(tool: Any, session: FakeSession) -> None:
    out = tool(tenant_id="t", view="status", schedule="wave-1", serial="000000000004")
    assert "Overall: **failed** (1 completed)" in out
    status_call = next(c for c in session.calls if c[1] == "software-upgrade-status")
    assert status_call[2]["serial"] == "000000000004"
    assert "has not run" in tool(tenant_id="t", view="status", schedule="wave-3")
    assert "no software-upgrade schedule named" in tool(
        tenant_id="t", view="status", schedule="nope"
    )
    assert "needs schedule" in tool(tenant_id="t", view="status")


def test_status_201_and_200_both_succeed(monkeypatch: pytest.MonkeyPatch, tool: Any) -> None:
    for code in (200, 201):
        fake = FakeSession(status_code=code)
        monkeypatch.setattr(software_upgrade, "_bearer_session_for", lambda client, f=fake: f)
        assert "Overall: **failed**" in tool(tenant_id="t", view="status", schedule=SCHED_A)


def test_rules_view_renders_criteria(tool: Any, session: FakeSession) -> None:
    out = tool(tenant_id="t", view="rules")
    assert "folders: branches" in out and "models: PA-400" in out
    assert "labels: wave" in out and "excluded devices: 1" in out


def test_match_posts_the_saved_rule(tool: Any, session: FakeSession) -> None:
    out = tool(tenant_id="t", view="match", rule="branch-firewalls")
    assert "2 firewall(s)" in out and "000000000002" in out
    method, path, _, body = session.calls[-1]
    assert (method, path) == ("POST", "software-upgrade-match-criteria")
    assert body == {
        "rule": {
            "name": "branch-firewalls",
            "id": RULE_ID,
            "match_criteria": RULES[0]["match_criteria"],
        }
    }
    assert "no software-upgrade rule named" in tool(tenant_id="t", view="match", rule="x")


def test_status_failure_degrades_in_overview(monkeypatch: pytest.MonkeyPatch, tool: Any) -> None:
    fake = FakeSession(fail="software-upgrade-status")
    monkeypatch.setattr(software_upgrade, "_bearer_session_for", lambda client: fake)
    out = tool(tenant_id="t")
    assert "wave-1" in out and "Status could not be read: HTTP 403" in out


def test_api_errors_and_bad_view(monkeypatch: pytest.MonkeyPatch, tool: Any) -> None:
    fake = FakeSession(fail="software-upgrade-schedules")
    monkeypatch.setattr(software_upgrade, "_bearer_session_for", lambda client: fake)
    out = tool(tenant_id="t", view="schedules")
    assert out.startswith("Error:") and "403" in out and "role" in out
    assert "view must be one of" in tool(tenant_id="t", view="bogus")


def test_device_outcomes() -> None:
    outcome = software_upgrade._device_outcome
    assert outcome(_device("s", **_DONE))[0] == "completed"
    assert outcome(_device("s"))[0] == "not started"
    assert outcome(_device("s", initialize="COMPLETED", precheck="COMPLETED")) == (
        "in progress",
        "content",
        "",
    )
    assert outcome(_device("s", initialize="COMPLETED", upgrading="FAILED"))[:2] == (
        "failed",
        "upgrading",
    )
