"""Tests for the MCP transports on the HTTP server (server_http).

Covers:
  - /mcp (Streamable HTTP) serves initialize + tools/list behind AuthMiddleware
  - Host header checks: allowlist on/off, loopback default, 421 on a bad host
  - SCM_MCP_HTTP_STATELESS reaches the FastMCP settings
"""

from __future__ import annotations

import json

import pytest
from mcp.server.fastmcp import FastMCP
from starlette.testclient import TestClient

import scm_harbourmaster_mcp.server_http as server_http

API_KEY = "test-key"
MCP_HEADERS = {
    "X-API-Key": API_KEY,
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
}
INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "pytest", "version": "0"},
    },
}


def _tiny_server() -> FastMCP:
    mcp = FastMCP(name="test-server")

    @mcp.tool()
    def ping() -> str:
        """Reply with pong."""
        return "pong"

    return mcp


@pytest.fixture
def app_env(monkeypatch: pytest.MonkeyPatch):
    """Point create_http_app at a tiny real FastMCP with API-key auth."""
    created: list[FastMCP] = []

    def factory() -> FastMCP:
        created.append(_tiny_server())
        return created[-1]

    monkeypatch.setattr(server_http, "create_server", factory)
    monkeypatch.setattr(server_http, "_AUTH_MODE", "apikey")
    monkeypatch.setattr(server_http, "_API_KEY", API_KEY)
    monkeypatch.setattr(server_http, "_HOST", "0.0.0.0")
    monkeypatch.setattr(server_http, "_ALLOWED_HOSTS", [])
    monkeypatch.setattr(server_http, "_STATELESS", False)
    return created


def _rpc_result(resp) -> dict:
    """Pull the JSON-RPC message out of a JSON or SSE-framed response."""
    if resp.headers.get("content-type", "").startswith("text/event-stream"):
        data = [
            ln[len("data:") :].strip() for ln in resp.text.splitlines() if ln.startswith("data:")
        ]
        return json.loads(data[-1])
    return resp.json()


class TestStreamableHttp:
    def test_initialize_and_list_tools(self, app_env) -> None:
        with TestClient(server_http.create_http_app()) as client:
            init = client.post("/mcp", json=INITIALIZE, headers=MCP_HEADERS)
            assert init.status_code == 200
            assert _rpc_result(init)["result"]["serverInfo"]["name"] == "test-server"
            session = init.headers["mcp-session-id"]

            headers = {**MCP_HEADERS, "Mcp-Session-Id": session}
            client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                headers=headers,
            )
            tools = client.post(
                "/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, headers=headers
            )
            assert tools.status_code == 200
            names = [t["name"] for t in _rpc_result(tools)["result"]["tools"]]
            assert names == ["ping"]

    def test_requires_auth(self, app_env) -> None:
        with TestClient(server_http.create_http_app()) as client:
            headers = {k: v for k, v in MCP_HEADERS.items() if k != "X-API-Key"}
            resp = client.post("/mcp", json=INITIALIZE, headers=headers)
            assert resp.status_code == 401

    def test_sse_still_requires_auth(self, app_env) -> None:
        with TestClient(server_http.create_http_app()) as client:
            assert client.get("/sse").status_code == 401

    def test_stateless_flag_reaches_fastmcp(self, app_env, monkeypatch) -> None:
        monkeypatch.setattr(server_http, "_STATELESS", True)
        server_http.create_http_app()
        assert app_env[-1].settings.stateless_http is True


class TestHostChecks:
    def _status_for_host(self, host: str) -> int:
        with TestClient(server_http.create_http_app(), base_url=f"http://{host}") as client:
            return client.post("/mcp", json=INITIALIZE, headers=MCP_HEADERS).status_code

    def test_public_bind_without_allowlist_accepts_any_host(self, app_env) -> None:
        # Regression: FastMCP's localhost-only default 421'd every remote client.
        assert self._status_for_host("mcp.example.com") == 200

    def test_allowlist_accepts_listed_host(self, app_env, monkeypatch) -> None:
        monkeypatch.setattr(server_http, "_ALLOWED_HOSTS", ["mcp.example.com"])
        assert self._status_for_host("mcp.example.com") == 200

    def test_allowlist_rejects_other_host(self, app_env, monkeypatch) -> None:
        monkeypatch.setattr(server_http, "_ALLOWED_HOSTS", ["mcp.example.com"])
        assert self._status_for_host("attacker.example.net") == 421

    def test_allowlist_keeps_localhost_for_health_and_port_forwards(
        self, app_env, monkeypatch
    ) -> None:
        monkeypatch.setattr(server_http, "_ALLOWED_HOSTS", ["mcp.example.com"])
        assert self._status_for_host("localhost:8080") == 200

    def test_loopback_bind_keeps_localhost_only_default(self, app_env, monkeypatch) -> None:
        monkeypatch.setattr(server_http, "_HOST", "127.0.0.1")
        assert self._status_for_host("mcp.example.com") == 421
        assert self._status_for_host("localhost:8080") == 200
