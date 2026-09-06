"""Unit tests for the Enterprise DLP incidents tools (tools/dlp.py additions)."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from src.scm_harbourmaster_mcp.tools.dlp import register_dlp_tools


class FakeResp:
    def __init__(self, status_code: int = 200, payload: Any = None) -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = json.dumps(payload) if payload is not None else ""

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("no JSON body")
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")


class FakeSession:
    def __init__(self, resp: FakeResp) -> None:
        self.resp = resp
        self.calls: list[dict[str, Any]] = []

    def get(self, url: str, **kwargs: Any) -> FakeResp:
        self.calls.append({"url": url, "params": kwargs.get("params")})
        return self.resp


@pytest.fixture
def make_tools():
    def _make(resp: FakeResp) -> tuple[dict, FakeSession]:
        session = FakeSession(resp)
        client = MagicMock()
        client.session = session
        mcp = FastMCP("test")
        register_dlp_tools(mcp, lambda tenant_id="": client)
        return {name: tool.fn for name, tool in mcp._tool_manager._tools.items()}, session

    return _make


class TestDlpIncidents:
    def test_list_ok_with_filters(self, make_tools) -> None:
        tools, session = make_tools(FakeResp(200, {"items": [{"id": "i1"}, {"id": "i2"}]}))
        data = json.loads(
            tools["dlp_incidents_list"](tenant_id="t", status="open", severity="high")
        )
        assert data["total"] == 2
        params = session.calls[0]["params"]
        assert params["status"] == "open"
        assert params["severity"] == "high"

    def test_list_limit_clamped_to_200(self, make_tools) -> None:
        tools, session = make_tools(FakeResp(200, []))
        data = json.loads(tools["dlp_incidents_list"](tenant_id="t", limit=999))
        assert session.calls[0]["params"]["limit"] == 200
        assert data["filters"]["limit"] == 200

    def test_list_unlicensed_hint(self, make_tools) -> None:
        tools, _ = make_tools(FakeResp(403))
        data = json.loads(tools["dlp_incidents_list"](tenant_id="t"))
        assert data["total"] == 0
        assert "403" in data["hint"]

    def test_get_requires_incident_id(self, make_tools) -> None:
        tools, _ = make_tools(FakeResp(200, {}))
        data = json.loads(tools["dlp_incidents_get"](tenant_id="t"))
        assert "incident_id is required" in data["error"]

    def test_get_ok(self, make_tools) -> None:
        tools, session = make_tools(FakeResp(200, {"id": "i1", "severity": "high"}))
        data = json.loads(tools["dlp_incidents_get"](tenant_id="t", incident_id="i1"))
        assert data["incident"]["severity"] == "high"
        assert session.calls[0]["url"].endswith("/v4/api/incidents/i1")

    def test_assignees_ok(self, make_tools) -> None:
        tools, session = make_tools(FakeResp(200, {"items": [{"name": "soc-team"}]}))
        data = json.loads(tools["dlp_incidents_assignees"](tenant_id="t"))
        assert data["total"] == 1
        assert session.calls[0]["url"].endswith("/v1/api/incidents/assignee")
