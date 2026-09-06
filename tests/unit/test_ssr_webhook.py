"""Tests for the /webhook/ssr intake endpoint (server_http).

Covers:
  - Payload validation (missing fields, non-object body)
  - Parameter defaults (dry_run=True, action=add) and string-bool coercion
  - HTTP status mapping: planned/applied -> 200, tool error -> 422
  - requested_by provenance echo
  - Route gating: SCM_MCP_HTTP_SSR_WEBHOOK off -> 403, auth still applies
"""

from __future__ import annotations

import asyncio
import json

from starlette.applications import Starlette
from starlette.testclient import TestClient

import scm_harbourmaster_mcp.server_http as server_http
from scm_harbourmaster_mcp.server_http import process_ssr_webhook

# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------


class _Block:
    def __init__(self, text: str) -> None:
        self.text = text


class StubMCP:
    """Minimal FastMCP stand-in: records call_tool invocations, canned reply."""

    def __init__(self, response: str) -> None:
        self.response = response
        self.calls: list[tuple[str, dict]] = []

    async def call_tool(self, name: str, params: dict) -> list[_Block]:
        self.calls.append((name, params))
        return [_Block(self.response)]

    def sse_app(self) -> Starlette:
        return Starlette()


def _planned_response(**overrides) -> str:
    body = {
        "operation": "url-allow-list",
        "target": "example.com",
        "dry_run": True,
        "ticket_ref": "INC-1",
        "status": "planned",
        "commit_required": True,
    }
    body.update(overrides)
    return json.dumps(body)


VALID_PAYLOAD = {
    "operation": "url-allow-list",
    "target": "example.com",
    "ticket_ref": "INC-1",
}


# ---------------------------------------------------------------------------
# process_ssr_webhook — validation
# ---------------------------------------------------------------------------


class TestValidation:
    def test_non_object_body_is_400(self) -> None:
        mcp = StubMCP(_planned_response())
        body, status = asyncio.run(process_ssr_webhook(mcp, ["not", "a", "dict"]))
        assert status == 400
        assert "JSON object" in body["error"]
        assert mcp.calls == []

    def test_missing_fields_are_400_and_named(self) -> None:
        mcp = StubMCP(_planned_response())
        body, status = asyncio.run(process_ssr_webhook(mcp, {"operation": "url-allow-list"}))
        assert status == 400
        assert "target" in body["error"]
        assert "ticket_ref" in body["error"]
        assert mcp.calls == []

    def test_whitespace_only_field_counts_as_missing(self) -> None:
        mcp = StubMCP(_planned_response())
        payload = {**VALID_PAYLOAD, "ticket_ref": "   "}
        body, status = asyncio.run(process_ssr_webhook(mcp, payload))
        assert status == 400
        assert "ticket_ref" in body["error"]


# ---------------------------------------------------------------------------
# process_ssr_webhook — parameter mapping
# ---------------------------------------------------------------------------


class TestParameterMapping:
    def test_defaults_dry_run_true_action_add(self) -> None:
        mcp = StubMCP(_planned_response())
        _, status = asyncio.run(process_ssr_webhook(mcp, dict(VALID_PAYLOAD)))
        assert status == 200
        (name, params) = mcp.calls[0]
        assert name == "scm_ssr_execute"
        assert params["dry_run"] is True
        assert params["action"] == "add"
        assert params["tenant_id"] == ""
        assert params["folder"] == ""

    def test_string_bools_are_coerced(self) -> None:
        # Power Automate form outputs commonly arrive as strings
        mcp = StubMCP(_planned_response())
        payload = {**VALID_PAYLOAD, "dry_run": "false", "action": "Remove"}
        asyncio.run(process_ssr_webhook(mcp, payload))
        (_, params) = mcp.calls[0]
        assert params["dry_run"] is False
        assert params["action"] == "remove"

    def test_unknown_dry_run_string_stays_dry(self) -> None:
        # A malformed dry_run must never flip a request into execute mode
        mcp = StubMCP(_planned_response())
        payload = {**VALID_PAYLOAD, "dry_run": "banana"}
        asyncio.run(process_ssr_webhook(mcp, payload))
        (_, params) = mcp.calls[0]
        assert params["dry_run"] is True

    def test_fields_are_stripped(self) -> None:
        mcp = StubMCP(_planned_response())
        payload = {**VALID_PAYLOAD, "target": "  example.com  ", "tenant_id": " t-1 "}
        asyncio.run(process_ssr_webhook(mcp, payload))
        (_, params) = mcp.calls[0]
        assert params["target"] == "example.com"
        assert params["tenant_id"] == "t-1"


# ---------------------------------------------------------------------------
# process_ssr_webhook — status mapping + provenance
# ---------------------------------------------------------------------------


class TestResponses:
    def test_planned_is_200(self) -> None:
        mcp = StubMCP(_planned_response(status="planned"))
        body, status = asyncio.run(process_ssr_webhook(mcp, dict(VALID_PAYLOAD)))
        assert status == 200
        assert body["status"] == "planned"

    def test_applied_is_200(self) -> None:
        mcp = StubMCP(_planned_response(status="applied", dry_run=False))
        payload = {**VALID_PAYLOAD, "dry_run": False}
        body, status = asyncio.run(process_ssr_webhook(mcp, payload))
        assert status == 200
        assert body["status"] == "applied"

    def test_tool_error_is_422(self) -> None:
        mcp = StubMCP(json.dumps({"status": "error", "error": "No SSR configuration found."}))
        body, status = asyncio.run(process_ssr_webhook(mcp, dict(VALID_PAYLOAD)))
        assert status == 422
        assert "SSR configuration" in body["error"]

    def test_unparseable_tool_response_is_422(self) -> None:
        mcp = StubMCP("Traceback (most recent call last): boom")
        body, status = asyncio.run(process_ssr_webhook(mcp, dict(VALID_PAYLOAD)))
        assert status == 422
        assert body["status"] == "error"
        assert "unparseable" in body["error"]

    def test_requested_by_is_echoed(self) -> None:
        mcp = StubMCP(_planned_response())
        payload = {**VALID_PAYLOAD, "requested_by": "user@customer.example"}
        body, status = asyncio.run(process_ssr_webhook(mcp, payload))
        assert status == 200
        assert body["requested_by"] == "user@customer.example"

    def test_tuple_result_shape_is_unwrapped(self) -> None:
        # FastMCP.call_tool may return (blocks, raw) tuples
        class TupleMCP(StubMCP):
            async def call_tool(self, name: str, params: dict):  # type: ignore[override]
                self.calls.append((name, params))
                return ([_Block(self.response)], {"raw": True})

        mcp = TupleMCP(_planned_response())
        body, status = asyncio.run(process_ssr_webhook(mcp, dict(VALID_PAYLOAD)))
        assert status == 200
        assert body["status"] == "planned"


# ---------------------------------------------------------------------------
# Route gating + auth (full app with stubbed MCP server)
# ---------------------------------------------------------------------------


def _make_client(monkeypatch, *, enabled: bool) -> tuple[TestClient, StubMCP]:
    stub = StubMCP(_planned_response())
    monkeypatch.setattr(server_http, "create_server", lambda: stub)
    monkeypatch.setattr(server_http, "_SSR_WEBHOOK_ENABLED", enabled)
    monkeypatch.setattr(server_http, "_AUTH_MODE", "apikey")
    monkeypatch.setattr(server_http, "_API_KEY", "test-key")
    return TestClient(server_http.create_http_app()), stub


class TestRoute:
    def test_disabled_gate_returns_403(self, monkeypatch) -> None:
        client, stub = _make_client(monkeypatch, enabled=False)
        resp = client.post("/webhook/ssr", json=VALID_PAYLOAD, headers={"X-API-Key": "test-key"})
        assert resp.status_code == 403
        assert "SCM_MCP_HTTP_SSR_WEBHOOK" in resp.json()["error"]
        assert stub.calls == []

    def test_auth_applies_to_webhook(self, monkeypatch) -> None:
        client, stub = _make_client(monkeypatch, enabled=True)
        resp = client.post("/webhook/ssr", json=VALID_PAYLOAD)
        assert resp.status_code == 401
        assert stub.calls == []

    def test_enabled_and_authed_roundtrip(self, monkeypatch) -> None:
        client, stub = _make_client(monkeypatch, enabled=True)
        resp = client.post("/webhook/ssr", json=VALID_PAYLOAD, headers={"X-API-Key": "test-key"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "planned"
        assert stub.calls[0][0] == "scm_ssr_execute"

    def test_non_json_body_is_400(self, monkeypatch) -> None:
        client, stub = _make_client(monkeypatch, enabled=True)
        resp = client.post(
            "/webhook/ssr",
            content=b"not json",
            headers={"X-API-Key": "test-key", "Content-Type": "application/json"},
        )
        assert resp.status_code == 400
        assert stub.calls == []
