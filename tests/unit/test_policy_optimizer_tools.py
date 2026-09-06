"""Tests for the Policy Optimizer tool module (no network)."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

import scm_harbourmaster_mcp.tools.policy_optimizer as po_mod
from scm_harbourmaster_mcp.tools.policy_optimizer import (
    _render_detail,
    _render_list,
    register_policy_optimizer_tools,
)


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
    register_policy_optimizer_tools(mcp, lambda tenant_id="": None)
    return mcp


def test_tools_register() -> None:
    tools = _mcp_with_tools()._tool_manager._tools
    assert "scm_policy_optimizer_rules" in tools
    assert "scm_policy_optimizer_rule" in tools


def test_render_forbidden() -> None:
    out = _render_list(403, None)
    assert "HTTP 403" in out and "entitlement" in out


def test_render_server_error_suppresses_body() -> None:
    out = _render_list(500, "<html>stack</html>")
    assert "HTTP 500" in out and "suppressed" in out
    assert "stack" not in out


def test_render_bad_request_flattens_errors_envelope() -> None:
    data = {
        "_errors": [
            {
                "code": "API_I00035",
                "message": "Invalid Request Payload",
                "details": ["Missing required parameter: manager_hostname"],
            }
        ],
        "_request_id": "eb18eb0c-d5b7-43f3-9e38-38464ee11e2f",
    }
    out = _render_list(400, data)
    assert "API_I00035" in out
    assert "Missing required parameter: manager_hostname" in out
    assert "eb18eb0c" in out


def test_render_list_sorts_by_recommendation_count_desc() -> None:
    data = {
        "total": 2,
        "data": [
            {"id": "a", "name": "rule-a", "recommendation_count": 1, "overall_traffic": 500},
            {"id": "b", "name": "rule-b", "recommendation_count": 9, "overall_traffic": 100},
        ],
    }
    out = _render_list(200, data)
    assert "Rules returned by the optimizer: **2**" in out
    assert out.index("rule-b") < out.index("rule-a")
    # Both rules carry recommendations, so no under-reporting caveat is needed.
    assert "under-reports" not in out


def test_render_list_caveats_zero_recommendation_counts() -> None:
    # Observed live: a rule listed with recommendation_count 0 returned 2
    # recommendations from the by-ID endpoint, so a 0 here means "unknown",
    # not "clean".
    data = {"total": 1, "data": [{"id": "a", "name": "rule-a", "recommendation_count": 0}]}
    out = _render_list(200, data)
    assert "under-reports" in out
    assert "1 of these report" in out
    assert "scm_policy_optimizer_rule" in out


def test_render_list_shows_placeholder_for_empty_string_fields() -> None:
    # Observed live: name/action/location come back as "" rather than absent,
    # which would otherwise render as blank table cells.
    data = {
        "total": 1,
        "data": [
            {
                "id": "62eb5fe4",
                "name": "",
                "action": "",
                "location": "",
                "recommendation_count": 0,
                "overall_traffic": 18160803,
            }
        ],
    }
    out = _render_list(200, data)
    assert "| — | — | — |" in out or "| — |" in out
    assert "|  |" not in out


def test_render_list_breaks_ties_on_traffic() -> None:
    data = {
        "data": [
            {"id": "a", "name": "rule-light", "recommendation_count": 3, "overall_traffic": 10},
            {"id": "b", "name": "rule-heavy", "recommendation_count": 3, "overall_traffic": 10**9},
        ]
    }
    out = _render_list(200, data)
    assert out.index("rule-heavy") < out.index("rule-light")


def test_render_list_handles_mixed_type_counts() -> None:
    # Brand-new API with no SDK schema validation — mixed int/str counts across
    # rules must not raise TypeError out of sorted().
    data = {
        "data": [
            {"id": "1", "name": "rule-int", "recommendation_count": 2},
            {"id": "2", "name": "rule-str", "recommendation_count": "7"},
            {"id": "3", "name": "rule-bad", "recommendation_count": "not-a-number"},
        ]
    }
    out = _render_list(200, data)
    assert out.index("rule-str") < out.index("rule-int") < out.index("rule-bad")


def test_render_list_handles_non_list_data() -> None:
    out = _render_list(200, {"data": {"id": "x", "name": "solo"}, "total": 1})
    assert "was not a list" in out


def test_render_list_tolerates_string_application_field() -> None:
    # A bare string where the spec declares an array must not be joined
    # character-by-character.
    data = {"data": [{"id": "a", "name": "r", "recommendation_count": 1, "application": "ssl"}]}
    out = _render_list(200, data)
    assert "| ssl |" in out
    assert "s, s, l" not in out


def test_render_list_empty() -> None:
    out = _render_list(200, {"data": [], "total": 0})
    assert "No rules with optimization recommendations found." in out


def test_render_detail_lists_recommendations_by_traffic() -> None:
    data = {
        "id": "550e8400",
        "name": "Allow-All-Outbound",
        "location": "Shared",
        "action": "allow",
        "application": ["any"],
        "overall_traffic": 279906035550,
        "recommended_rules": [
            {
                "id": "r1",
                "name": "optrule_1",
                "application": ["ssl"],
                "traffic": 10,
                "status": "pending",
            },
            {
                "id": "r2",
                "name": "optrule_2",
                "application": ["web-browsing"],
                "traffic": 10**9,
                "status": "accepted",
            },
        ],
    }
    out = _render_detail(200, data, "550e8400")
    assert "Allow-All-Outbound" in out
    assert "Recommended replacement rules (2)" in out
    assert out.index("optrule_2") < out.index("optrule_1")


def test_render_detail_no_recommendations() -> None:
    data = {"id": "x", "name": "rule-x", "recommended_rules": []}
    out = _render_detail(200, data, "x")
    assert "No recommendations are currently available" in out


def test_render_detail_not_found() -> None:
    out = _render_detail(404, {"_errors": [{"code": "E1", "message": "Rule not found"}]}, "x")
    assert "HTTP 404" in out and "Rule not found" in out


def test_render_404_with_empty_body_has_no_dangling_colon() -> None:
    # Observed live: some tenants 404 with a completely empty response body.
    out = _render_list(404, "")
    assert "HTTP 404" in out
    assert "available for it." in out
    assert "available for it:" not in out


def test_render_404_points_at_the_manager_hostname_sentinel() -> None:
    out = _render_list(404, {"_errors": [{"message": "Manager not found"}]})
    assert "cloud_managed" in out and "SCM" in out


def test_list_tool_sends_cloud_managed_and_omits_unset_filters(monkeypatch) -> None:
    mcp = _mcp_with_tools()
    session = _FakeSession(_FakeResp(200, {"data": [], "total": 0}))
    monkeypatch.setattr(po_mod, "_bearer_session_for", lambda client: session)

    mcp._tool_manager.get_tool("scm_policy_optimizer_rules").fn(tenant_id="t")
    url, params = session.calls[0]
    assert url == po_mod._LIST_URL
    # Sentinel differs from the sibling Config Cleanup API, which uses "SCM".
    assert params["manager_hostname"] == "cloud_managed"
    assert not any(k.startswith(("overall_traffic", "sessions")) for k in params)


def test_list_tool_passes_zero_bound_filters(monkeypatch) -> None:
    # 0 is a valid bound for these filters, so it must reach the API rather than
    # being treated as "unset".
    mcp = _mcp_with_tools()
    session = _FakeSession(_FakeResp(200, {"data": [], "total": 0}))
    monkeypatch.setattr(po_mod, "_bearer_session_for", lambda client: session)

    mcp._tool_manager.get_tool("scm_policy_optimizer_rules").fn(
        tenant_id="t", min_traffic=0, max_sessions=100
    )
    _, params = session.calls[0]
    assert params["overall_traffic[ge]"] == 0
    assert params["sessions[le]"] == 100
    assert "overall_traffic[le]" not in params
    assert "sessions[ge]" not in params


def test_detail_tool_builds_url_and_requires_id(monkeypatch) -> None:
    mcp = _mcp_with_tools()
    session = _FakeSession(_FakeResp(200, {"id": "abc", "name": "r", "recommended_rules": []}))
    monkeypatch.setattr(po_mod, "_bearer_session_for", lambda client: session)

    out = mcp._tool_manager.get_tool("scm_policy_optimizer_rule").fn(tenant_id="t", rule_id="")
    assert "`rule_id` is required" in out
    assert session.calls == []

    mcp._tool_manager.get_tool("scm_policy_optimizer_rule").fn(tenant_id="t", rule_id="abc")
    url, params = session.calls[0]
    assert url == f"{po_mod._LIST_URL}/abc"
    assert params["manager_hostname"] == "cloud_managed"
