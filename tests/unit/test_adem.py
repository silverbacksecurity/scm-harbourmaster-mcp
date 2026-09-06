"""Unit tests for scm_adem_query (tools/adem.py).

No network — `_bearer_session_for` is replaced with a fake GET session.
Pins per-view parameter validation (endpoint-type/response-type enums vary
across the 13 ADEM views, some don't accept either param at all), the
required-filter guard on agent_properties, header/param construction, and
error rendering for 401/403/404/5xx.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

import scm_harbourmaster_mcp.tools.adem as adem_mod


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
    def __init__(self, response: FakeResponse):
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def get(
        self, url: str, headers: Any = None, params: Any = None, timeout: Any = None
    ) -> FakeResponse:
        self.calls.append({"url": url, "headers": headers, "params": dict(params or {})})
        return self.response


@pytest.fixture
def tools(monkeypatch: pytest.MonkeyPatch) -> Any:
    def _make(response: FakeResponse) -> tuple[dict[str, Any], FakeSession]:
        session = FakeSession(response)
        monkeypatch.setattr(adem_mod, "_bearer_session_for", lambda c: session)
        mcp = FastMCP("test-adem")
        adem_mod.register_adem_tools(mcp, get_client=lambda tenant_id="": MagicMock())
        tool = mcp._tool_manager.get_tool("scm_adem_query")
        return tool.fn, session

    return _make


class TestViewValidation:
    def test_unknown_view_lists_valid_views(self, tools: Any) -> None:
        fn, session = tools(FakeResponse(payload={}))
        result = fn(view="bogus")
        assert "Unknown view" in result
        assert "agent_score" in result
        assert session.calls == []

    def test_agent_properties_requires_filter(self, tools: Any) -> None:
        fn, session = tools(FakeResponse(payload={}))
        result = fn(view="agent_properties", tenant_id="123")
        assert "requires a non-empty `filter`" in result
        assert session.calls == []

    def test_agent_properties_proceeds_with_filter(self, tools: Any) -> None:
        fn, session = tools(FakeResponse(payload={"rowCount": 0}))
        fn(view="agent_properties", tenant_id="123", filter="agent_uuid=='x'")
        assert len(session.calls) == 1
        assert session.calls[0]["params"]["filter"] == "agent_uuid=='x'"

    def test_invalid_endpoint_type_rejected(self, tools: Any) -> None:
        fn, session = tools(FakeResponse(payload={}))
        result = fn(view="agent_score", endpoint_type="bogusAgent")
        assert "Invalid endpoint_type" in result
        assert "muAgent" in result
        assert session.calls == []

    def test_invalid_response_type_rejected(self, tools: Any) -> None:
        fn, session = tools(FakeResponse(payload={}))
        result = fn(view="agent_score", response_type="bogus-type")
        assert "Invalid response_type" in result
        assert session.calls == []

    def test_view_without_endpoint_type_param_ignores_it_silently(self, tools: Any) -> None:
        fn, session = tools(FakeResponse(payload={"average": {}}))
        fn(view="rum_score", endpoint_type="muAgent")
        assert "endpoint-type" not in session.calls[0]["params"]

    def test_view_without_response_type_param_ignores_it_silently(self, tools: Any) -> None:
        fn, session = tools(FakeResponse(payload={}))
        fn(view="route_hops", response_type="summary", filter="site_id=='s1'")
        assert "response-type" not in session.calls[0]["params"]


class TestDefaults:
    def test_default_response_type_prefers_summary(self, tools: Any) -> None:
        fn, session = tools(FakeResponse(payload={}))
        fn(view="application_score", tenant_id="123")
        assert session.calls[0]["params"]["response-type"] == "summary"

    def test_default_response_type_falls_back_to_first_when_no_summary(self, tools: Any) -> None:
        fn, session = tools(FakeResponse(payload={}))
        fn(view="agent_metric", tenant_id="123")
        assert session.calls[0]["params"]["response-type"] == "timeseries"

    def test_default_endpoint_type_is_views_first_value(self, tools: Any) -> None:
        fn, session = tools(FakeResponse(payload={}))
        fn(view="application_metric", tenant_id="123")
        assert session.calls[0]["params"]["endpoint-type"] == "muAgent"

    def test_default_timerange(self, tools: Any) -> None:
        fn, session = tools(FakeResponse(payload={}))
        fn(view="agent_score", tenant_id="123")
        assert session.calls[0]["params"]["timerange"] == "last_3_day"


class TestRequestConstruction:
    def test_url_uses_view_path(self, tools: Any) -> None:
        fn, session = tools(FakeResponse(payload={}))
        fn(view="internet_metric", tenant_id="123")
        assert session.calls[0]["url"] == (
            "https://api.sase.paloaltonetworks.com/adem/telemetry/v2/measure/internet/metric"
        )

    def test_prisma_tenant_header_set_from_tenant_id(self, tools: Any) -> None:
        fn, session = tools(FakeResponse(payload={}))
        fn(view="agent_score", tenant_id="987654321")
        assert session.calls[0]["headers"]["prisma-tenant"] == "987654321"

    def test_no_tenant_header_when_tenant_id_empty(self, tools: Any) -> None:
        fn, session = tools(FakeResponse(payload={}))
        fn(view="agent_score")
        assert session.calls[0]["headers"] == {}

    def test_group_param_passed_through_when_given(self, tools: Any) -> None:
        fn, session = tools(FakeResponse(payload={}))
        fn(view="agent_score", tenant_id="123", group="Entity.user")
        assert session.calls[0]["params"]["group"] == "Entity.user"

    def test_group_param_absent_when_not_given(self, tools: Any) -> None:
        fn, session = tools(FakeResponse(payload={}))
        fn(view="agent_score", tenant_id="123")
        assert "group" not in session.calls[0]["params"]


class TestErrorRendering:
    def test_401_renders_adem_scope_hint(self, tools: Any) -> None:
        fn, session = tools(FakeResponse(status_code=401, payload={}))
        result = fn(view="agent_score", tenant_id="123")
        assert "ADEM OAuth" in result
        assert "401" in result

    def test_403_renders_not_provisioned(self, tools: Any) -> None:
        fn, session = tools(FakeResponse(status_code=403, payload={}))
        result = fn(view="agent_score", tenant_id="123")
        assert "not provisioned" in result

    def test_5xx_renders_transient_hint(self, tools: Any) -> None:
        fn, session = tools(FakeResponse(status_code=503, payload={}))
        result = fn(view="agent_score", tenant_id="123")
        assert "503" in result
        assert "transient" in result

    def test_400_passes_through_body(self, tools: Any) -> None:
        fn, session = tools(
            FakeResponse(status_code=400, payload={"error": {"message": "bad filter"}})
        )
        result = fn(view="route_hops", tenant_id="123", filter="agent_uuid=='x'")
        assert "400" in result
        assert "bad filter" in result

    def test_200_renders_json_payload(self, tools: Any) -> None:
        fn, session = tools(FakeResponse(payload={"rowCount": 3}))
        result = fn(view="agent_score", tenant_id="123")
        assert "```json" in result
        assert '"rowCount": 3' in result

    def test_request_exception_surfaces_as_error(
        self, tools: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(url: str, headers: Any = None, params: Any = None, timeout: Any = None) -> Any:
            raise ConnectionError("timed out")

        session = MagicMock()
        session.get = boom
        monkeypatch.setattr(adem_mod, "_bearer_session_for", lambda c: session)
        mcp = FastMCP("test-adem-error")
        adem_mod.register_adem_tools(mcp, get_client=lambda tenant_id="": MagicMock())
        tool = mcp._tool_manager.get_tool("scm_adem_query")
        result = tool.fn(view="agent_score", tenant_id="123")
        assert "Error" in result
        assert "timed out" in result


class TestTruncation:
    def test_large_payload_is_truncated(self, tools: Any) -> None:
        big = {"collection": [{"i": i, "pad": "x" * 200} for i in range(200)]}
        fn, session = tools(FakeResponse(payload=big))
        result = fn(view="agent_score", tenant_id="123")
        assert "truncated" in result
        assert len(result) < len(json.dumps(big)) + 500
