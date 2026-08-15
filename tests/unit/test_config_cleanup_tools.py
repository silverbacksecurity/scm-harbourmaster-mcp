"""Tests for the Config Cleanup (zero-hit rules) tool module (no network)."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

import scm_mcp_mssp.tools.config_cleanup as config_cleanup_mod
from scm_mcp_mssp.tools.config_cleanup import _render, register_config_cleanup_tools


class _FakeResp:
    def __init__(self, status_code: int, data=None) -> None:
        self.status_code = status_code
        self._data = data
        self.text = "" if data is None else str(data)

    def json(self):
        if self._data is None:
            raise ValueError("no JSON body")
        return self._data


class _FakeSession:
    def __init__(self, resp: _FakeResp) -> None:
        self._resp = resp
        self.calls: list[tuple[str, dict]] = []

    def get(self, url, params=None, **kwargs):
        self.calls.append((url, params or {}))
        return self._resp


def _mcp_with_tools() -> FastMCP:
    mcp = FastMCP("test")
    register_config_cleanup_tools(mcp, lambda tenant_id="": None)
    return mcp


def test_tool_registers() -> None:
    mcp = _mcp_with_tools()
    assert "scm_zerohit_rules" in mcp._tool_manager._tools


def test_render_forbidden() -> None:
    out = _render(403, None)
    assert "HTTP 403" in out and "entitlement" in out


def test_render_not_found() -> None:
    assert "HTTP 404" in _render(404, None)


def test_render_server_error() -> None:
    out = _render(500, "<html>stack</html>")
    assert "HTTP 500" in out and "suppressed" in out


def test_render_happy_path_sorts_by_days_desc() -> None:
    data = {
        "ok": True,
        "result": {
            "status": "success",
            "lastAnalysisTime": "2026-08-01T00:00:00Z",
            "platform": "scm",
            "total": 2,
            "data": [
                {
                    "name": "rule-a",
                    "type": "security",
                    "location": "Shared",
                    "days_with_zero_hits": 10,
                    "tag": [],
                },
                {
                    "name": "rule-b",
                    "type": "security",
                    "location": "Shared",
                    "days_with_zero_hits": 90,
                    "tag": ["stale"],
                },
            ],
        },
    }
    out = _render(200, data)
    assert "Total zero-hit rules: **2**" in out
    # worst offender (90 days) should appear before rule-a (10 days)
    assert out.index("rule-b") < out.index("rule-a")


def test_render_handles_mixed_type_days_field() -> None:
    # Brand-new API, no SDK schema validation — a plausible malformed
    # response mixes int and str days_with_zero_hits across rules. Must not
    # raise TypeError out of sorted().
    data = {
        "result": {
            "status": "success",
            "total": 3,
            "data": [
                {
                    "name": "rule-int",
                    "type": "security",
                    "location": "Shared",
                    "days_with_zero_hits": 10,
                    "tag": [],
                },
                {
                    "name": "rule-str",
                    "type": "security",
                    "location": "Shared",
                    "days_with_zero_hits": "90",
                    "tag": [],
                },
                {
                    "name": "rule-bad",
                    "type": "security",
                    "location": "Shared",
                    "days_with_zero_hits": "not-a-number",
                    "tag": [],
                },
            ],
        },
    }
    out = _render(200, data)
    # numeric string 90 sorts ahead of int 10, both ahead of the unparsable
    # value (coerced to 0)
    assert out.index("rule-str") < out.index("rule-int") < out.index("rule-bad")


def test_render_in_progress_flag() -> None:
    data = {"result": {"status": "in_progress", "data": [], "total": 0}}
    out = _render(200, data)
    assert "Analysis in progress" in out


def test_render_empty() -> None:
    data = {"result": {"status": "success", "data": [], "total": 0}}
    out = _render(200, data)
    assert "No zero-hit rules found." in out


def test_tool_happy_path(monkeypatch) -> None:
    mcp = _mcp_with_tools()
    session = _FakeSession(
        _FakeResp(
            200,
            {
                "result": {
                    "status": "success",
                    "total": 1,
                    "data": [
                        {
                            "name": "old-rule",
                            "type": "security",
                            "location": "Shared",
                            "days_with_zero_hits": 45,
                            "tag": [],
                        }
                    ],
                }
            },
        )
    )
    monkeypatch.setattr(config_cleanup_mod, "_bearer_session_for", lambda client: session)
    out = mcp._tool_manager.get_tool("scm_zerohit_rules").fn(tenant_id="t")
    assert "old-rule" in out
    url, params = session.calls[0]
    assert url == config_cleanup_mod._URL
    assert params["manager_hostname"] == "SCM"
