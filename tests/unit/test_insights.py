"""Unit tests for scm_insights_query (tools/insights.py).

The tool had no tests when added; these pin URL construction per API
version, region resolution, body validation, error pass-through, and the
two fixes from review: OAuth refresh before direct-session calls and no
empty Prisma-Tenant header.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.tools.insights import register_insights_tools


class FakeResponse:
    def __init__(self, status_code: int = 200, payload: Any = None, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class FakeSession:
    def __init__(self, response: FakeResponse, *more: FakeResponse):
        self.responses = [response, *more]
        self.calls: list[dict[str, Any]] = []

    def post(self, url, json=None, headers=None, timeout=None):  # noqa: A002
        self.calls.append({"url": url, "json": json, "headers": headers})
        if len(self.responses) > 1:
            return self.responses.pop(0)
        return self.responses[0]


def _client(session: FakeSession) -> Any:
    client = MagicMock()
    client.session = session
    client.oauth_client = MagicMock()
    return client


def _invoke(session: FakeSession, client: Any | None = None, **kwargs: Any) -> str:
    mcp = FastMCP("test-insights")
    the_client = client or _client(session)
    register_insights_tools(mcp, get_client=lambda tid="": the_client)
    tool = mcp._tool_manager.get_tool("scm_insights_query")
    return tool.fn(**kwargs)


class TestUrlConstruction:
    def test_v3_prefixes_query_segment(self) -> None:
        session = FakeSession(FakeResponse(payload={"data": []}))
        _invoke(session, resource="gp_mobileusers/connected_user_count", tenant_id="123")
        assert session.calls[0]["url"] == (
            "https://api.sase.paloaltonetworks.com/insights/v3.0/resource"
            "/query/gp_mobileusers/connected_user_count"
        )

    def test_v2_uses_raw_resource_path(self) -> None:
        session = FakeSession(FakeResponse(payload={"data": []}))
        _invoke(
            session,
            resource="custom/query/gp_mobileusers/connected_user_count",
            tenant_id="123",
            api_version="v2",
        )
        assert session.calls[0]["url"].startswith(
            "https://api.sase.paloaltonetworks.com/api/sase/v2.0/resource/custom/query/"
        )

    def test_leading_slash_is_tolerated(self) -> None:
        session = FakeSession(FakeResponse(payload={"data": []}))
        _invoke(session, resource="/tunnels/tunnel_list", tenant_id="123")
        assert "/query/tunnels/tunnel_list" in session.calls[0]["url"]


class TestHeaders:
    def test_tenant_header_present_when_tenant_given(self) -> None:
        session = FakeSession(FakeResponse(payload={"data": []}))
        _invoke(session, resource="x", tenant_id="1234567890")
        assert session.calls[0]["headers"]["Prisma-Tenant"] == "1234567890"

    def test_no_empty_tenant_header(self) -> None:
        session = FakeSession(FakeResponse(payload={"data": []}))
        _invoke(session, resource="x", tenant_id="")
        assert "Prisma-Tenant" not in session.calls[0]["headers"]

    def test_region_override_wins(self) -> None:
        session = FakeSession(FakeResponse(payload={"data": []}))
        _invoke(session, resource="x", tenant_id="1", region="americas")
        assert session.calls[0]["headers"]["X-PANW-Region"] == "americas"

    def test_token_refresh_attempted_before_call(self) -> None:
        session = FakeSession(FakeResponse(payload={"data": []}))
        client = _client(session)
        _invoke(session, client=client, resource="x", tenant_id="1")
        client.oauth_client.refresh_token.assert_called()


class TestBodyAndResults:
    def test_invalid_body_json_is_a_clear_error(self) -> None:
        session = FakeSession(FakeResponse(payload={"data": []}))
        out = _invoke(session, resource="x", tenant_id="1", body="{not json")
        assert out.startswith("Error: invalid JSON in `body`")
        assert session.calls == []  # nothing was sent

    def test_body_keys_preserved_with_assumed_window(self) -> None:
        session = FakeSession(FakeResponse(payload={"data": []}))
        _invoke(session, resource="x", tenant_id="1", body='{"count": 5}')
        sent = session.calls[0]["json"]
        assert sent["count"] == 5
        assert "filter" in sent  # window assumed alongside the caller's keys

    def test_data_array_extracted_with_count(self) -> None:
        session = FakeSession(FakeResponse(payload={"data": [{"a": 1}, {"a": 2}]}))
        out = json.loads(_invoke(session, resource="x", tenant_id="1"))
        assert out["count"] == 2
        assert out["data"] == [{"a": 1}, {"a": 2}]

    def test_http_error_surfaces_status_and_detail(self) -> None:
        session = FakeSession(FakeResponse(status_code=403, payload=None, text="Forbidden"))
        out = json.loads(_invoke(session, resource="tunnels/tunnel_list", tenant_id="1"))
        assert out["error"] == "HTTP 403"
        assert "Forbidden" in out["detail"]
        assert len(session.calls) == 1  # 403 is not the reject-window signal — no retry


class TestDefaultTimeWindow:
    def test_empty_body_assumes_24h_event_time_window(self) -> None:
        session = FakeSession(FakeResponse(payload={"data": []}))
        out = json.loads(
            _invoke(session, resource="locations/location_rn_bandwidth", tenant_id="1")
        )
        rule = session.calls[0]["json"]["filter"]["rules"][0]
        assert rule == {"property": "event_time", "operator": "last_n_hours", "values": ["24"]}
        assert out["time_window"] == "last_24h (assumed)"

    def test_hours_param_widens_the_window(self) -> None:
        session = FakeSession(FakeResponse(payload={"data": []}))
        _invoke(session, resource="x", tenant_id="1", hours=72)
        assert session.calls[0]["json"]["filter"]["rules"][0]["values"] == ["72"]

    def test_caller_filter_is_never_touched(self) -> None:
        session = FakeSession(FakeResponse(payload={"data": []}))
        body = '{"filter": {"rules": [{"property": "site", "operator": "in", "values": ["x"]}]}}'
        out = json.loads(_invoke(session, resource="x", tenant_id="1", body=body))
        rules = session.calls[0]["json"]["filter"]["rules"]
        assert rules == [{"property": "site", "operator": "in", "values": ["x"]}]
        assert out["time_window"] == "caller-provided filter"

    def test_400_on_assumed_window_retries_without_it(self) -> None:
        # A resource with no event_time column rejects the assumed filter;
        # the call falls back to the bare body and succeeds.
        session = FakeSession(
            FakeResponse(status_code=400, payload=None, text="unknown property event_time"),
            FakeResponse(payload={"data": [{"a": 1}]}),
        )
        out = json.loads(_invoke(session, resource="x", tenant_id="1"))
        assert len(session.calls) == 2
        assert "filter" in session.calls[0]["json"]  # first try: assumed window
        assert session.calls[1]["json"] == {}  # retry: bare body
        assert out["count"] == 1
        assert out["time_window"] == "none (resource rejected the time filter)"

    def test_400_with_caller_filter_is_not_retried(self) -> None:
        session = FakeSession(FakeResponse(status_code=400, payload=None, text="bad filter"))
        body = '{"filter": {"rules": []}}'
        out = json.loads(_invoke(session, resource="x", tenant_id="1", body=body))
        assert out["error"] == "HTTP 400"
        assert len(session.calls) == 1

    def test_extractor_shares_the_same_default_window(self) -> None:
        from scm_harbourmaster_mcp.tools.insights import DEFAULT_WINDOW_HOURS, default_time_window

        window = default_time_window()
        rule = window["filter"]["rules"][0]
        assert rule["operator"] == "last_n_hours"
        assert rule["values"] == [str(DEFAULT_WINDOW_HOURS)]
        assert DEFAULT_WINDOW_HOURS == 24


def _invoke_export(session: FakeSession, **kwargs: Any) -> str:
    mcp = FastMCP("test-insights")
    the_client = _client(session)
    register_insights_tools(mcp, get_client=lambda tid="": the_client)
    tool = mcp._tool_manager.get_tool("scm_insights_export")
    return tool.fn(**kwargs)


class TestExportWorkflow:
    def test_unknown_action(self) -> None:
        out = _invoke_export(FakeSession(FakeResponse()), resource="x", action="bogus")
        assert "Unknown action" in out

    def test_schedule_requires_resource(self) -> None:
        out = _invoke_export(FakeSession(FakeResponse()), action="schedule")
        assert "resource is required" in out

    def test_status_requires_download_id(self) -> None:
        out = _invoke_export(FakeSession(FakeResponse()), action="status")
        assert "download_id is required" in out

    def test_schedule_v2_path_and_download_id(self) -> None:
        session = FakeSession(FakeResponse(payload={"download_id": "dl-1"}))
        out = _invoke_export(session, resource="users/agent/user_list", tenant_id="123")
        assert session.calls[0]["url"] == (
            "https://api.sase.paloaltonetworks.com/api/sase/v2.0/resource"
            "/export/schedule/query/users/agent/user_list"
        )
        data = json.loads(out)
        assert data["download_id"] == "dl-1"
        assert "status" in data["next_step"]

    def test_schedule_v3_path(self) -> None:
        session = FakeSession(FakeResponse(payload={"id": "dl-2"}))
        out = _invoke_export(
            session, resource="users/agent/user_list", tenant_id="123", api_version="v3"
        )
        assert session.calls[0]["url"] == (
            "https://api.sase.paloaltonetworks.com/insights/v3.0/resource"
            "/export/query/users/agent/user_list"
        )
        assert json.loads(out)["download_id"] == "dl-2"

    def test_status_posts_download_id(self) -> None:
        session = FakeSession(FakeResponse(payload={"state": "ready"}))
        out = _invoke_export(session, action="status", download_id="dl-1", tenant_id="123")
        call = session.calls[0]
        assert call["url"].endswith("/download/status")
        assert call["json"] == {"download_id": "dl-1"}
        assert json.loads(out)["data"] == {"state": "ready"}

    def test_download_posts_download_id(self) -> None:
        session = FakeSession(FakeResponse(payload={"rows": []}))
        out = _invoke_export(session, action="download", download_id="dl-1", tenant_id="123")
        call = session.calls[0]
        assert call["url"].endswith("/download")
        assert json.loads(out)["download_id"] == "dl-1"

    def test_schedule_error_passthrough(self) -> None:
        session = FakeSession(FakeResponse(status_code=403, payload={"error": "no"}))
        out = _invoke_export(session, resource="users/agent/user_list", tenant_id="123")
        data = json.loads(out)
        assert data["error"] == "HTTP 403"
