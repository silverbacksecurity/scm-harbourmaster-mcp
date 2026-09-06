"""Unit tests for scm_csp_licensing_query (tools/csp_licensing.py).

No network — requests.post/get on the module are replaced with fakes.
Pins: view validation, required-param guards per view, token caching
(one token fetch across repeated calls), missing-credentials handling,
and error rendering for 401/403/404/5xx.
"""

from __future__ import annotations

from typing import Any

import pytest

import scm_harbourmaster_mcp.tools.csp_licensing as csp_mod
from scm_harbourmaster_mcp.config.settings import Settings


class FakeResponse:
    def __init__(self, status_code: int = 200, payload: Any = None, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("no json")
        return self._payload

    def raise_for_status(self) -> None:
        pass


@pytest.fixture(autouse=True)
def _reset_token_cache() -> None:
    csp_mod._token_cache.clear()
    yield
    csp_mod._token_cache.clear()


@pytest.fixture
def configured_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    s = Settings(csp_client_id="dc-test-client", csp_client_secret="test-secret")
    monkeypatch.setattr(csp_mod, "get_settings", lambda: s)


@pytest.fixture
def tool() -> Any:
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("test-csp")
    csp_mod.register_csp_licensing_tools(mcp)
    return mcp._tool_manager.get_tool("scm_csp_licensing_query").fn


class TestViewValidation:
    def test_unknown_view_lists_valid_views(self, tool: Any) -> None:
        result = tool(view="bogus")
        assert "Unknown view" in result
        assert "credit_pools" in result

    def test_credit_pool_requires_credit_pool_id(self, tool: Any) -> None:
        result = tool(view="credit_pool")
        assert "requires credit_pool_id" in result

    def test_deployment_profiles_requires_credit_pool_id(self, tool: Any) -> None:
        result = tool(view="deployment_profiles")
        assert "requires credit_pool_id" in result

    def test_deployment_profile_requires_auth_code(self, tool: Any) -> None:
        result = tool(view="deployment_profile")
        assert "requires auth_code" in result

    def test_firewall_serial_numbers_requires_auth_code(self, tool: Any) -> None:
        result = tool(view="firewall_serial_numbers")
        assert "requires auth_code" in result

    def test_credit_pools_needs_no_params(
        self, tool: Any, configured_settings: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            csp_mod._requests,
            "post",
            lambda *a, **k: FakeResponse(200, {"access_token": "tok", "expires_in": 3600}),
        )
        monkeypatch.setattr(
            csp_mod._requests, "get", lambda *a, **k: FakeResponse(200, {"pools": []})
        )
        result = tool(view="credit_pools")
        assert "credit_pools" in result
        assert "pools" in result


class TestCredentials:
    def test_missing_credentials_returns_actionable_message(
        self, tool: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Explicit empty overrides beat any real secret sitting in a local
        # .env — this must never touch the network with real credentials.
        monkeypatch.setattr(
            csp_mod, "get_settings", lambda: Settings(csp_client_id="", csp_client_secret="")
        )
        monkeypatch.setattr(
            csp_mod._requests, "post", lambda *a, **k: pytest.fail("must not call network")
        )
        result = tool(view="credit_pools")
        assert "No CSP credentials configured" in result
        assert "SCM_MCP_CSP_CLIENT_ID" in result


class TestTokenFlow:
    def test_token_fetched_and_sent_as_bare_header(
        self, tool: Any, configured_settings: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        token_calls = []
        get_calls = []

        def fake_post(url: str, **kwargs: Any) -> FakeResponse:
            token_calls.append((url, kwargs))
            return FakeResponse(200, {"access_token": "shiny-token", "expires_in": 3600})

        def fake_get(url: str, headers: Any = None, **kwargs: Any) -> FakeResponse:
            get_calls.append((url, headers, kwargs))
            return FakeResponse(200, {"pools": []})

        monkeypatch.setattr(csp_mod._requests, "post", fake_post)
        monkeypatch.setattr(csp_mod._requests, "get", fake_get)

        tool(view="credit_pools")

        assert token_calls[0][0] == csp_mod._TOKEN_URL
        assert token_calls[0][1]["data"]["scope"] == "fwflex-service"
        assert token_calls[0][1]["data"]["grant_type"] == "client_credentials"
        assert get_calls[0][1] == {"token": "shiny-token"}
        assert get_calls[0][0] == f"{csp_mod._API_BASE}/creditPool"

    def test_token_cached_across_calls(
        self, tool: Any, configured_settings: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        token_calls = []

        def fake_post(url: str, **kwargs: Any) -> FakeResponse:
            token_calls.append(url)
            return FakeResponse(200, {"access_token": "tok", "expires_in": 3600})

        monkeypatch.setattr(csp_mod._requests, "post", fake_post)
        monkeypatch.setattr(
            csp_mod._requests, "get", lambda *a, **k: FakeResponse(200, {"pools": []})
        )

        tool(view="credit_pools")
        tool(view="credit_pools")

        assert len(token_calls) == 1


class TestUrlConstruction:
    def _do(self, tool: Any, monkeypatch: pytest.MonkeyPatch, **kwargs: Any) -> str:
        monkeypatch.setattr(
            csp_mod._requests,
            "post",
            lambda *a, **k: FakeResponse(200, {"access_token": "tok", "expires_in": 3600}),
        )
        captured = {}

        def fake_get(url: str, headers: Any = None, params: Any = None, **k: Any) -> FakeResponse:
            captured["url"] = url
            captured["params"] = params
            return FakeResponse(200, {"ok": True})

        monkeypatch.setattr(csp_mod._requests, "get", fake_get)
        tool(**kwargs)
        return captured["url"], captured["params"]

    def test_credit_pool_url(
        self, tool: Any, configured_settings: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        url, _ = self._do(tool, monkeypatch, view="credit_pool", credit_pool_id="cp-1")
        assert url == f"{csp_mod._API_BASE}/creditPool/cp-1"

    def test_deployment_profiles_url(
        self, tool: Any, configured_settings: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        url, _ = self._do(tool, monkeypatch, view="deployment_profiles", credit_pool_id="cp-1")
        assert url == f"{csp_mod._API_BASE}/creditPool/cp-1/deploymentProfile"

    def test_deployment_profile_url(
        self, tool: Any, configured_settings: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        url, _ = self._do(tool, monkeypatch, view="deployment_profile", auth_code="AUTH-1")
        assert url == f"{csp_mod._API_BASE}/deploymentProfile/AUTH-1"

    def test_firewall_serial_numbers_uses_query_param(
        self, tool: Any, configured_settings: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        url, params = self._do(
            tool, monkeypatch, view="firewall_serial_numbers", auth_code="AUTH-1"
        )
        assert url == f"{csp_mod._API_BASE}/firewallserialnumbers"
        assert params == {"auth_code": "AUTH-1"}


class TestErrorRendering:
    def _query_with_status(self, tool: Any, monkeypatch: pytest.MonkeyPatch, status: int) -> str:
        monkeypatch.setattr(
            csp_mod._requests,
            "post",
            lambda *a, **k: FakeResponse(200, {"access_token": "tok", "expires_in": 3600}),
        )
        monkeypatch.setattr(csp_mod._requests, "get", lambda *a, **k: FakeResponse(status, {}))
        return tool(view="credit_pools")

    def test_401_renders_hint(
        self, tool: Any, configured_settings: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._query_with_status(tool, monkeypatch, 401)
        assert "fwflex-service" in result

    def test_404_renders_not_entitled(
        self, tool: Any, configured_settings: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._query_with_status(tool, monkeypatch, 404)
        assert "not entitled" in result

    def test_5xx_renders_transient_hint(
        self, tool: Any, configured_settings: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._query_with_status(tool, monkeypatch, 502)
        assert "transient" in result
