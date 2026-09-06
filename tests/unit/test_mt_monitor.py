"""Tests for scm_mt_analytics (mt-monitor aggregation API, mocked session)."""

from __future__ import annotations

import json
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

import scm_harbourmaster_mcp.tools.mt_monitor as mtm


class FakeResp:
    def __init__(self, status: int, data: list | None = None):
        self.status_code = status
        self._data = data or []

    def json(self) -> dict:
        return {"data": self._data}


def _tool(monkeypatch: pytest.MonkeyPatch, by_region: dict[str, list]) -> Any:
    calls: list[tuple[str, str]] = []

    class S:
        def post(self, url: str, params=None, headers=None, json=None, timeout=None) -> FakeResp:
            region = (headers or {}).get("X-PANW-Region", "?")
            calls.append((url.rsplit("/agg/", 1)[1], region))
            assert (params or {}).get("agg_by") == "tenant"
            return FakeResp(200, by_region.get(region, []))

    monkeypatch.setattr(mtm, "_bearer_session_for", lambda c: S())
    from types import SimpleNamespace

    monkeypatch.setattr(
        "scm_harbourmaster_mcp.config.settings.load_all_tenant_configs",
        lambda: {"t1": SimpleNamespace(insights_region="eu")},
    )
    mcp = FastMCP("test")
    mtm.register_mt_monitor_tools(mcp, lambda tenant_id="": object())
    return mcp._tool_manager.get_tool("scm_mt_analytics").fn, calls


def test_region_fallback_to_uk_sibling(monkeypatch: pytest.MonkeyPatch) -> None:
    fn, calls = _tool(monkeypatch, {"europe": [], "uk": [{"total_app_count": 5}]})
    data = json.loads(fn(tenant_id="t1", view="apps"))
    assert data["region"] == "uk"
    assert data["summary"] == [{"total_app_count": 5}]
    assert [c[1] for c in calls] == ["europe", "uk"]


def test_explicit_region_no_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    fn, calls = _tool(monkeypatch, {"sg": []})
    data = json.loads(fn(tenant_id="t1", view="threats", region="sg"))
    assert data["region"] == "sg"
    assert "note" in data
    assert [c[1] for c in calls] == ["sg"]


def test_bad_view_and_region(monkeypatch: pytest.MonkeyPatch) -> None:
    fn, _ = _tool(monkeypatch, {})
    assert "view must be one of" in fn(view="users")
    assert "region must be one of" in fn(view="apps", region="mars")


def test_view_bodies_shapes() -> None:
    for view in ("apps", "threats", "connectivity", "incidents"):
        (key, path, body) = mtm._view_queries(view, 7)[0]
        assert body["properties"] and body["filter"]["rules"]
