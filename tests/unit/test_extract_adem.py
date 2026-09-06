"""Unit tests for extract_adem (audit/extractor.py).

Pins the last_3_day → last_30_day fallback: low-activity tenants (e.g. a lab
tenant whose test user hasn't logged in for a few days) come back empty at
the default 3-day window even though ADEM has data further back. extract_adem
must retry once at last_30_day and record which window actually produced
data in snap.adem_timerange_used — but must not retry on a real API error
(401), since a wider window won't fix that.

No network — client.session is replaced with a fake GET session keyed by the
`timerange` query param.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from scm_harbourmaster_mcp.audit.extractor import extract_adem
from scm_harbourmaster_mcp.audit.models import AuditSnapshot


class FakeResponse:
    def __init__(self, status_code: int = 200, payload: Any = None):
        self.status_code = status_code
        self._payload = payload
        self.text = ""

    def json(self) -> Any:
        return self._payload

    def raise_for_status(self) -> None:
        pass


EMPTY_DIST = {"distribution": {"clients": 0}}
EMPTY_GROUPED = {"collection": []}
EMPTY_SUMMARY = {"rowCount": 0}

DATA_DIST = {"distribution": {"clients": 5, "score": 90, "good": 5, "fair": 0, "poor": 0}}
DATA_GROUPED = {"collection": [{"entityValue": "alice", "score": {"score": 95}}]}
DATA_SUMMARY = {"rowCount": 10, "startTime": 1, "endTime": 2}


class FakeSession:
    """Routes responses by timerange: 'empty' timeranges get zero data,
    others get real data. status/error overrides always win."""

    def __init__(self, empty_timeranges: set[str], status: int = 200):
        self.empty_timeranges = empty_timeranges
        self.status = status
        self.calls: list[dict[str, Any]] = []

    def get(
        self, url: str, headers: Any = None, params: Any = None, timeout: Any = None
    ) -> FakeResponse:
        params = dict(params or {})
        self.calls.append({"url": url, "params": params})
        if self.status != 200:
            return FakeResponse(status_code=self.status, payload={})

        empty = params.get("timerange") in self.empty_timeranges
        response_type = params.get("response-type")
        if "/agent/score" in url:
            payload = (
                EMPTY_SUMMARY
                if response_type == "summary" and empty
                else DATA_SUMMARY
                if response_type == "summary"
                else EMPTY_DIST
                if empty
                else DATA_DIST
            )
        elif response_type == "grouped-summary":
            payload = EMPTY_GROUPED if empty else DATA_GROUPED
        else:
            payload = EMPTY_DIST if empty else DATA_DIST
        return FakeResponse(status_code=200, payload=payload)


def _client(session: FakeSession) -> Any:
    client = MagicMock()
    client.session = session
    return client


def test_falls_back_to_30_day_when_3_day_is_empty() -> None:
    session = FakeSession(empty_timeranges={"last_3_day"})
    snap = AuditSnapshot(folder="", tenant_id="tsg-lab")

    extract_adem(_client(session), snap)

    assert snap.adem_timerange_used == "last_30_day"
    assert snap.adem_app_scores
    assert snap.adem_agent_summary
    timeranges_called = {c["params"]["timerange"] for c in session.calls}
    assert timeranges_called == {"last_3_day", "last_30_day"}


def test_no_fallback_when_3_day_already_has_data() -> None:
    session = FakeSession(empty_timeranges=set())
    snap = AuditSnapshot(folder="", tenant_id="tsg-active")

    extract_adem(_client(session), snap)

    assert snap.adem_timerange_used == "last_3_day"
    timeranges_called = {c["params"]["timerange"] for c in session.calls}
    assert timeranges_called == {"last_3_day"}


def test_no_fallback_when_both_windows_empty() -> None:
    session = FakeSession(empty_timeranges={"last_3_day", "last_30_day"})
    snap = AuditSnapshot(folder="", tenant_id="tsg-idle")

    extract_adem(_client(session), snap)

    assert snap.adem_timerange_used == "last_3_day"
    assert not snap.adem_app_scores
    assert all((d.get("clients") or 0) == 0 for d in snap.adem_agent_summary.values())


def test_no_fallback_on_real_api_error() -> None:
    session = FakeSession(empty_timeranges={"last_3_day"}, status=401)
    snap = AuditSnapshot(folder="", tenant_id="tsg-noauth")

    extract_adem(_client(session), snap)

    assert snap.adem_timerange_used == "last_3_day"
    assert snap.adem_errors
    timeranges_called = {c["params"]["timerange"] for c in session.calls}
    assert timeranges_called == {"last_3_day"}
