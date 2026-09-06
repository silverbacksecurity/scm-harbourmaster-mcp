"""Unit tests for cdl_logforwarding tools."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from src.scm_harbourmaster_mcp.tools.cdl_logforwarding import register_cdl_logforwarding_tools

# ---------------------------------------------------------------------------
# Fake helpers
# ---------------------------------------------------------------------------


class FakeResp:
    """Mimic a requests.Response."""

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
    """Register cdl_logforwarding tools with a valid get_client mock."""

    def _get_client(tenant_id: str = ""):
        client = MagicMock()
        oauth = MagicMock()
        oauth.is_expired = False
        client.oauth_client = oauth
        return client

    mcp = FastMCP("test")
    register_cdl_logforwarding_tools(mcp, _get_client)
    return {name: tool.fn for name, tool in mcp._tool_manager._tools.items()}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCdlLogforwarding:
    """scm_cdl_logforwarding tests."""

    def test_list_email_profiles_ok(self, tools, monkeypatch) -> None:
        canned = [
            {"profileId": "p1", "name": "corp-syslog", "server": "syslog.example.com:514"},
            {"profileId": "p2", "name": "audit-https", "server": "https://logs.example.com"},
        ]
        session = _make_fake_session(
            {
                "https://api.sase.paloaltonetworks.com/logging-service/logforwarding/v1/email-profiles": FakeResp(
                    200, canned
                ),
            }
        )
        monkeypatch.setattr(
            "src.scm_harbourmaster_mcp.tools.cdl_logforwarding._bearer_session",
            lambda client: session,
        )

        result = tools["scm_cdl_logforwarding"](tenant_id="test", profile_type="email")
        data = json.loads(result)
        assert data["total"] == 2
        assert data["profiles"][0]["name"] == "corp-syslog"

    def test_list_https_profiles_ok(self, tools, monkeypatch) -> None:
        canned = [{"profileId": "h1", "name": "webhook-logs", "url": "https://hooks.example.com"}]
        session = _make_fake_session(
            {
                "https://api.sase.paloaltonetworks.com/logging-service/logforwarding/v1/https-profiles": FakeResp(
                    200, canned
                ),
            }
        )
        monkeypatch.setattr(
            "src.scm_harbourmaster_mcp.tools.cdl_logforwarding._bearer_session",
            lambda client: session,
        )

        result = tools["scm_cdl_logforwarding"](tenant_id="test", profile_type="https")
        data = json.loads(result)
        assert data["total"] == 1
        assert data["profile_type"] == "https"

    def test_list_syslog_profiles_ok(self, tools, monkeypatch) -> None:
        canned = [{"profileId": "s1", "name": "siem-forwarder", "facility": "local0"}]
        session = _make_fake_session(
            {
                "https://api.sase.paloaltonetworks.com/logging-service/logforwarding/v1/syslog-profiles": FakeResp(
                    200, canned
                ),
            }
        )
        monkeypatch.setattr(
            "src.scm_harbourmaster_mcp.tools.cdl_logforwarding._bearer_session",
            lambda client: session,
        )

        result = tools["scm_cdl_logforwarding"](tenant_id="test", profile_type="syslog")
        data = json.loads(result)
        assert data["total"] == 1

    def test_get_profile_by_id(self, tools, monkeypatch) -> None:
        canned = {"profileId": "p1", "name": "corp-syslog", "server": "syslog.example.com:514"}
        session = _make_fake_session(
            {
                "https://api.sase.paloaltonetworks.com/logging-service/logforwarding/v1/email-profiles/p1": FakeResp(
                    200, canned
                ),
            }
        )
        monkeypatch.setattr(
            "src.scm_harbourmaster_mcp.tools.cdl_logforwarding._bearer_session",
            lambda client: session,
        )

        result = tools["scm_cdl_logforwarding"](
            tenant_id="test", profile_type="email", profile_id="p1"
        )
        data = json.loads(result)
        assert data["profile_id"] == "p1"
        assert data["profile"]["name"] == "corp-syslog"

    def test_list_403_returns_empty(self, tools, monkeypatch) -> None:
        session = _make_fake_session(
            {
                "https://api.sase.paloaltonetworks.com/logging-service/logforwarding/v1/email-profiles": FakeResp(
                    403
                ),
            }
        )
        monkeypatch.setattr(
            "src.scm_harbourmaster_mcp.tools.cdl_logforwarding._bearer_session",
            lambda client: session,
        )

        result = tools["scm_cdl_logforwarding"](tenant_id="test")
        data = json.loads(result)
        assert data["total"] == 0
        assert "hint" in data

    def test_invalid_profile_type(self, tools) -> None:
        result = tools["scm_cdl_logforwarding"](tenant_id="test", profile_type="invalid")
        data = json.loads(result)
        assert "Unknown profile_type" in data["error"]

    def test_auth_failure(self, tools, monkeypatch) -> None:
        monkeypatch.setattr(
            "src.scm_harbourmaster_mcp.tools.cdl_logforwarding._bearer_session",
            lambda client: (_ for _ in ()).throw(ValueError("No tenant configured")),
        )

        result = tools["scm_cdl_logforwarding"](tenant_id="test")
        data = json.loads(result)
        assert data.get("error") == "auth_failed"
