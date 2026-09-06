"""Unit tests for dns_security tools."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from src.scm_harbourmaster_mcp.tools.dns_security import register_dns_security_tools

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


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def tools() -> dict:
    """Register dns_security tools with a valid get_client mock."""

    def _get_client(tenant_id: str = ""):
        client = MagicMock()
        oauth = MagicMock()
        oauth.is_expired = False
        client.oauth_client = oauth
        return client

    mcp = FastMCP("test")
    register_dns_security_tools(mcp, _get_client)
    return {name: tool.fn for name, tool in mcp._tool_manager._tools.items()}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestDnsSecurityLookup:
    """scm_dns_security_lookup tests."""

    def test_info_ok(self, tools, monkeypatch) -> None:
        canned = {"domain": "evil.example.com", "category": "malware", "reputation": "bad"}
        session = MagicMock()
        session.headers = {}
        session.post = MagicMock(return_value=FakeResp(200, canned))
        monkeypatch.setattr(
            "src.scm_harbourmaster_mcp.tools.dns_security._bearer_session",
            lambda client: session,
        )

        result = tools["scm_dns_security_lookup"](tenant_id="test", domain="evil.example.com")
        data = json.loads(result)
        assert data["domain"] == "evil.example.com"
        assert data["result"]["category"] == "malware"

    def test_info_403_returns_unavailable(self, tools, monkeypatch) -> None:
        session = MagicMock()
        session.headers = {}
        session.post = MagicMock(return_value=FakeResp(403))
        monkeypatch.setattr(
            "src.scm_harbourmaster_mcp.tools.dns_security._bearer_session",
            lambda client: session,
        )

        result = tools["scm_dns_security_lookup"](tenant_id="test", domain="evil.example.com")
        data = json.loads(result)
        assert data["available"] is False
        assert data["status_code"] == 403

    def test_missing_domain(self, tools) -> None:
        result = tools["scm_dns_security_lookup"](tenant_id="test")
        data = json.loads(result)
        assert data["error"] == "domain is required"

    def test_changerequest_missing_ticket_ref(self, tools) -> None:
        result = tools["scm_dns_security_lookup"](
            tenant_id="test",
            domain="evil.example.com",
            action="changerequest",
            change_action="add",
        )
        data = json.loads(result)
        assert "ticket_ref is mandatory" in data["error"]

    def test_changerequest_invalid_action(self, tools) -> None:
        result = tools["scm_dns_security_lookup"](
            tenant_id="test",
            domain="evil.example.com",
            action="changerequest",
            change_action="block",  # invalid
            ticket_ref="TICKET-1",
        )
        data = json.loads(result)
        assert "Invalid change_action" in data["error"]

    def test_changerequest_ok(self, tools, monkeypatch) -> None:
        canned = {"request_id": "req-1", "status": "submitted"}
        session = MagicMock()
        session.headers = {}
        session.post = MagicMock(return_value=FakeResp(200, canned))
        monkeypatch.setattr(
            "src.scm_harbourmaster_mcp.tools.dns_security._bearer_session",
            lambda client: session,
        )

        result = tools["scm_dns_security_lookup"](
            tenant_id="test",
            domain="evil.example.com",
            action="changerequest",
            change_action="add",
            change_category="malware",
            ticket_ref="TICKET-42",
        )
        data = json.loads(result)
        assert data["ticket_ref"] == "TICKET-42"
        assert data["result"]["status"] == "submitted"

    def test_unknown_action(self, tools) -> None:
        result = tools["scm_dns_security_lookup"](tenant_id="test", domain="x.com", action="delete")
        data = json.loads(result)
        assert "Unknown action" in data["error"]

    def test_auth_failure(self, tools, monkeypatch) -> None:
        monkeypatch.setattr(
            "src.scm_harbourmaster_mcp.tools.dns_security._bearer_session",
            lambda client: (_ for _ in ()).throw(ValueError("No tenant configured")),
        )

        result = tools["scm_dns_security_lookup"](tenant_id="test", domain="example.com")
        data = json.loads(result)
        assert data.get("error") == "auth_failed"
