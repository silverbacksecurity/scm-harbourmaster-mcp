"""Unit tests for email_dlp tools."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from src.scm_harbourmaster_mcp.tools.email_dlp import register_email_dlp_tools

# ---------------------------------------------------------------------------
# Fake helpers
# ---------------------------------------------------------------------------


class FakeResp:
    """Mimic a requests.Response with .status_code and .json()."""

    def __init__(self, status_code: int, json_data: dict | list | None = None) -> None:
        self.status_code = status_code
        self._json = json_data
        self.text = json.dumps(json_data) if json_data else ""

    def json(self) -> dict | list:
        if self._json is None:
            raise ValueError("no JSON body")
        return self._json

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")


def _make_fake_session(responses: dict[str, FakeResp]) -> MagicMock:
    """Return a MagicMock session whose .get() routes by URL prefix."""
    session = MagicMock()

    def _get(url: str, **kwargs) -> FakeResp:
        for prefix, resp in responses.items():
            if url.startswith(prefix):
                return resp
        return FakeResp(404, {"error": "not found"})

    session.get = _get
    session.headers = {}
    return session


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def tools() -> dict:
    """Register email_dlp tools with a valid get_client mock.

    Individual tests monkeypatch ``_bearer_session`` to control HTTP responses.
    """

    def _get_client(tenant_id: str = ""):
        client = MagicMock()
        oauth = MagicMock()
        oauth.is_expired = False
        client.oauth_client = oauth
        return client

    mcp = FastMCP("test")
    register_email_dlp_tools(mcp, _get_client)
    return {name: tool.fn for name, tool in mcp._tool_manager._tools.items()}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestEmailDlpIncidents:
    """scm_email_dlp_incidents tests."""

    def test_list_incidents_ok(self, tools, monkeypatch) -> None:
        canned = [
            {"id": "inc-1", "status": "open", "severity": "high", "subject": "Phishing email"},
            {"id": "inc-2", "status": "resolved", "severity": "low", "subject": "Spam report"},
        ]
        session = _make_fake_session(
            {
                "https://api.us-west1.email.dlp.paloaltonetworks.com/incident/api/v1/incidents": FakeResp(
                    200, canned
                ),
            }
        )
        monkeypatch.setattr(
            "src.scm_harbourmaster_mcp.tools.email_dlp._bearer_session",
            lambda client: session,
        )

        result = tools["scm_email_dlp_incidents"](tenant_id="test")
        data = json.loads(result)
        assert data["total"] == 2
        assert data["incidents"][0]["id"] == "inc-1"

    def test_list_incidents_403_returns_empty(self, tools, monkeypatch) -> None:
        session = _make_fake_session(
            {
                "https://api.us-west1.email.dlp.paloaltonetworks.com/incident/api/v1/incidents": FakeResp(
                    403
                ),
            }
        )
        monkeypatch.setattr(
            "src.scm_harbourmaster_mcp.tools.email_dlp._bearer_session",
            lambda client: session,
        )

        result = tools["scm_email_dlp_incidents"](tenant_id="test")
        data = json.loads(result)
        assert data["total"] == 0
        assert "hint" in data

    def test_list_incidents_400_returns_graceful_error(self, tools, monkeypatch) -> None:
        session = _make_fake_session(
            {
                "https://api.us-west1.email.dlp.paloaltonetworks.com/incident/api/v1/incidents": FakeResp(
                    400, {"message": "bad request"}
                ),
            }
        )
        monkeypatch.setattr(
            "src.scm_harbourmaster_mcp.tools.email_dlp._bearer_session",
            lambda client: session,
        )

        result = tools["scm_email_dlp_incidents"](tenant_id="test")
        data = json.loads(result)
        assert data["error"] == "email_dlp_api_error"
        assert data["status_code"] == 400

    def test_get_incident_by_id(self, tools, monkeypatch) -> None:
        canned = {"id": "inc-1", "status": "open", "severity": "critical"}
        session = _make_fake_session(
            {
                "https://api.us-west1.email.dlp.paloaltonetworks.com/incident/api/v1/incidents/inc-1": FakeResp(
                    200, canned
                ),
            }
        )
        monkeypatch.setattr(
            "src.scm_harbourmaster_mcp.tools.email_dlp._bearer_session",
            lambda client: session,
        )

        result = tools["scm_email_dlp_incidents"](tenant_id="test", incident_id="inc-1")
        data = json.loads(result)
        assert data["incident_id"] == "inc-1"
        assert data["incident"]["severity"] == "critical"

    def test_get_report_by_id(self, tools, monkeypatch) -> None:
        canned = {"report_id": "rpt-1", "findings": 12, "status": "complete"}
        session = _make_fake_session(
            {
                "https://api.us-west1.email.dlp.paloaltonetworks.com/report/api/v1/reports/rpt-1": FakeResp(
                    200, canned
                ),
            }
        )
        monkeypatch.setattr(
            "src.scm_harbourmaster_mcp.tools.email_dlp._bearer_session",
            lambda client: session,
        )

        result = tools["scm_email_dlp_incidents"](tenant_id="test", report_id="rpt-1")
        data = json.loads(result)
        assert data["report_id"] == "rpt-1"
        assert data["report"]["findings"] == 12

    def test_auth_failure(self, tools, monkeypatch) -> None:
        monkeypatch.setattr(
            "src.scm_harbourmaster_mcp.tools.email_dlp._bearer_session",
            lambda client: (_ for _ in ()).throw(ValueError("No tenant configured")),
        )

        result = tools["scm_email_dlp_incidents"](tenant_id="test")
        data = json.loads(result)
        assert data.get("error") == "auth_failed"

    def test_filters_status_and_limit(self, tools, monkeypatch) -> None:
        captured: dict = {}

        class CaptureSession:
            headers = {}

            def get(self, url: str, **kwargs) -> FakeResp:
                captured["url"] = url
                captured["kwargs"] = kwargs
                return FakeResp(200, [])

        monkeypatch.setattr(
            "src.scm_harbourmaster_mcp.tools.email_dlp._bearer_session",
            lambda client: CaptureSession(),
        )

        tools["scm_email_dlp_incidents"](tenant_id="test", status="open", limit=10)
        params = captured["kwargs"].get("params", {})
        assert params.get("status") == "open"
        assert params.get("limit") == 10
