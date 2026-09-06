"""Unit tests for Configuration Orchestration (config_orch) tools."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from src.scm_harbourmaster_mcp.tools.config_orch import register_config_orch_tools

# ---------------------------------------------------------------------------
# Fake helpers
# ---------------------------------------------------------------------------


class FakeResp:
    """Mimic a requests.Response."""

    def __init__(self, status_code: int, json_data: dict | list | None = None) -> None:
        self.status_code = status_code
        self._json = json_data
        self.text = json.dumps(json_data) if json_data is not None else ""

    def json(self) -> dict | list:
        if self._json is None:
            raise ValueError("no JSON body")
        return self._json


class FakeSession:
    """Routes by (method, url prefix) and records every call."""

    def __init__(self, responses: dict[tuple[str, str], FakeResp]) -> None:
        self._responses = responses
        self.calls: list[dict] = []

    def _dispatch(self, method: str, url: str, **kwargs) -> FakeResp:
        self.calls.append({"method": method, "url": url, "json": kwargs.get("json")})
        for (m, prefix), resp in self._responses.items():
            if m == method and url.startswith(prefix):
                return resp
        return FakeResp(404, {"error": "not found"})

    def get(self, url: str, **kwargs) -> FakeResp:
        return self._dispatch("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> FakeResp:
        return self._dispatch("POST", url, **kwargs)

    def put(self, url: str, **kwargs) -> FakeResp:
        return self._dispatch("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs) -> FakeResp:
        return self._dispatch("DELETE", url, **kwargs)


_BASE = "https://api.sase.paloaltonetworks.com"


@pytest.fixture
def tools() -> dict:
    mcp = FastMCP("test")
    register_config_orch_tools(mcp, lambda tenant_id="": MagicMock())
    return {name: tool.fn for name, tool in mcp._tool_manager._tools.items()}


def _patch_session(monkeypatch, session: FakeSession) -> None:
    monkeypatch.setattr(
        "src.scm_harbourmaster_mcp.tools.config_orch._bearer_session",
        lambda client: session,
    )


# ---------------------------------------------------------------------------
# Remote networks
# ---------------------------------------------------------------------------


class TestRemoteNetworks:
    def test_list_ok(self, tools, monkeypatch) -> None:
        session = FakeSession(
            {
                ("GET", f"{_BASE}/v1/remote-networks-read"): FakeResp(
                    200, {"items": [{"id": "rn1"}, {"id": "rn2"}]}
                ),
            }
        )
        _patch_session(monkeypatch, session)
        data = json.loads(tools["scm_config_orch_remote_networks"](tenant_id="t"))
        assert data["total"] == 2

    def test_list_unlicensed_returns_hint(self, tools, monkeypatch) -> None:
        session = FakeSession(
            {
                ("GET", f"{_BASE}/v1/remote-networks-read"): FakeResp(403),
                ("GET", f"{_BASE}/v1/remote-networks"): FakeResp(403),
            }
        )
        _patch_session(monkeypatch, session)
        data = json.loads(tools["scm_config_orch_remote_networks"](tenant_id="t"))
        assert data["total"] == 0
        assert "hint" in data

    def test_write_requires_ticket_ref(self, tools) -> None:
        data = json.loads(tools["scm_config_orch_remote_networks"](action="create", body_json="{}"))
        assert "ticket_ref" in data["error"]

    def test_create_dry_run_default(self, tools, monkeypatch) -> None:
        session = FakeSession({})
        _patch_session(monkeypatch, session)
        data = json.loads(
            tools["scm_config_orch_remote_networks"](
                action="create", body_json='{"name": "site-a"}', ticket_ref="CHG-1"
            )
        )
        assert data["dry_run"] is True
        assert session.calls == []  # dry run never hits the API

    def test_create_applied_does_not_inject_ticket_ref(self, tools, monkeypatch) -> None:
        session = FakeSession(
            {("POST", f"{_BASE}/v1/remote-networks"): FakeResp(201, {"id": "rn9"})}
        )
        _patch_session(monkeypatch, session)
        data = json.loads(
            tools["scm_config_orch_remote_networks"](
                action="create",
                body_json='{"name": "site-a"}',
                ticket_ref="CHG-1",
                dry_run=False,
            )
        )
        assert data["applied"] is True
        posted = session.calls[0]["json"]
        assert posted == {"name": "site-a"}
        assert "ticket_ref" not in posted

    def test_delete_applied(self, tools, monkeypatch) -> None:
        session = FakeSession({("DELETE", f"{_BASE}/v1/remote-networks/rn1"): FakeResp(204)})
        _patch_session(monkeypatch, session)
        data = json.loads(
            tools["scm_config_orch_remote_networks"](
                action="delete", resource_id="rn1", ticket_ref="CHG-2", dry_run=False
            )
        )
        assert data["applied"] is True


# ---------------------------------------------------------------------------
# Bandwidth allocations
# ---------------------------------------------------------------------------


class TestBandwidth:
    def test_list_v2_ok(self, tools, monkeypatch) -> None:
        session = FakeSession(
            {
                ("GET", f"{_BASE}/v2/bandwidth-allocations"): FakeResp(
                    200, {"items": [{"id": "bw1"}]}
                ),
            }
        )
        _patch_session(monkeypatch, session)
        data = json.loads(tools["scm_config_orch_bandwidth"](tenant_id="t"))
        assert data["total"] == 1
        assert data["api_version"] == "v2"

    def test_delete_needs_no_body_json(self, tools, monkeypatch) -> None:
        """Regression: delete used to be blocked by the create/update body check."""
        session = FakeSession({("DELETE", f"{_BASE}/v2/bandwidth-allocations/bw1"): FakeResp(204)})
        _patch_session(monkeypatch, session)
        data = json.loads(
            tools["scm_config_orch_bandwidth"](
                action="delete", resource_id="bw1", ticket_ref="CHG-3", dry_run=False
            )
        )
        assert data["applied"] is True

    def test_delete_dry_run_shows_current(self, tools, monkeypatch) -> None:
        session = FakeSession(
            {("GET", f"{_BASE}/v2/bandwidth-allocations/bw1"): FakeResp(200, {"id": "bw1"})}
        )
        _patch_session(monkeypatch, session)
        data = json.loads(
            tools["scm_config_orch_bandwidth"](
                action="delete", resource_id="bw1", ticket_ref="CHG-3"
            )
        )
        assert data["dry_run"] is True
        assert data["current_state"] == {"id": "bw1"}

    def test_create_requires_body_json(self, tools, monkeypatch) -> None:
        _patch_session(monkeypatch, FakeSession({}))
        data = json.loads(tools["scm_config_orch_bandwidth"](action="create", ticket_ref="CHG-4"))
        assert "body_json" in data["error"]

    def test_update_applied_does_not_inject_ticket_ref(self, tools, monkeypatch) -> None:
        session = FakeSession(
            {("PUT", f"{_BASE}/v2/bandwidth-allocations/bw1"): FakeResp(200, {"id": "bw1"})}
        )
        _patch_session(monkeypatch, session)
        data = json.loads(
            tools["scm_config_orch_bandwidth"](
                action="update",
                resource_id="bw1",
                body_json='{"mbps": 100}',
                ticket_ref="CHG-5",
                dry_run=False,
            )
        )
        assert data["applied"] is True
        assert session.calls[0]["json"] == {"mbps": 100}

    def test_invalid_api_version(self, tools) -> None:
        data = json.loads(tools["scm_config_orch_bandwidth"](api_version="v9"))
        assert "api_version" in data["error"]


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------


class TestProfiles:
    def test_list_ike_crypto(self, tools, monkeypatch) -> None:
        session = FakeSession(
            {
                ("GET", f"{_BASE}/v1/ike-crypto-profiles"): FakeResp(
                    200, {"items": [{"id": "p1"}]}
                ),
            }
        )
        _patch_session(monkeypatch, session)
        data = json.loads(tools["scm_config_orch_profiles"](tenant_id="t"))
        assert data["total"] == 1
        assert data["profile_type"] == "ike-crypto"

    def test_ike_gateway_write_rejected(self, tools) -> None:
        data = json.loads(
            tools["scm_config_orch_profiles"](
                profile_type="ike-gateway", action="delete", resource_id="g1", ticket_ref="CHG-6"
            )
        )
        assert "read-only" in data["error"]

    def test_delete_needs_no_body_json(self, tools, monkeypatch) -> None:
        """Regression: delete used to be blocked by the create/update body check."""
        session = FakeSession({("DELETE", f"{_BASE}/v1/ike-crypto-profiles/p1"): FakeResp(200, {})})
        _patch_session(monkeypatch, session)
        data = json.loads(
            tools["scm_config_orch_profiles"](
                action="delete", resource_id="p1", ticket_ref="CHG-7", dry_run=False
            )
        )
        assert data["applied"] is True

    def test_create_applied_does_not_inject_ticket_ref(self, tools, monkeypatch) -> None:
        session = FakeSession(
            {("POST", f"{_BASE}/v1/ike-crypto-profiles"): FakeResp(201, {"id": "p9"})}
        )
        _patch_session(monkeypatch, session)
        data = json.loads(
            tools["scm_config_orch_profiles"](
                action="create",
                body_json='{"name": "ike-aes256"}',
                ticket_ref="CHG-8",
                dry_run=False,
            )
        )
        assert data["applied"] is True
        assert session.calls[0]["json"] == {"name": "ike-aes256"}

    def test_unknown_profile_type(self, tools) -> None:
        data = json.loads(tools["scm_config_orch_profiles"](profile_type="bogus"))
        assert "Unknown profile_type" in data["error"]
