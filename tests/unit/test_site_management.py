"""Unit tests for Site Management (NGFW device onboarding) tools."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from src.scm_harbourmaster_mcp.tools.site_management import register_site_management_tools

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
        self.calls.append(
            {
                "method": method,
                "url": url,
                "json": kwargs.get("json"),
                "params": kwargs.get("params"),
            }
        )
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


_BASE = "https://api.strata.paloaltonetworks.com/config/setup/device-onboarding/v1"


@pytest.fixture
def tools() -> dict:
    mcp = FastMCP("test")
    register_site_management_tools(mcp, lambda tenant_id="": MagicMock())
    return {name: tool.fn for name, tool in mcp._tool_manager._tools.items()}


def _patch_session(monkeypatch, session: FakeSession) -> None:
    monkeypatch.setattr(
        "src.scm_harbourmaster_mcp.tools.site_management._bearer_session_for",
        lambda client: session,
    )


def _call(tools, **kwargs):
    return json.loads(tools["scm_site_management"](**kwargs))


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_unknown_resource_type(tools) -> None:
    data = _call(tools, resource_type="bogus")
    assert "Unknown resource_type" in data["error"]
    for rt in ("site", "property", "onboarding-rule", "site-group"):
        assert rt in data["error"]


def test_unknown_action(tools) -> None:
    data = _call(tools, action="bogus")
    assert "Unknown action" in data["error"]


def test_move_only_valid_for_onboarding_rule(tools) -> None:
    data = _call(tools, resource_type="site", action="move")
    assert "onboarding-rule" in data["error"]


def test_write_action_without_ticket_ref(tools) -> None:
    data = _call(tools, action="create", body_json="{}")
    assert "ticket_ref" in data["error"]


def test_get_missing_resource_id(tools) -> None:
    data = _call(tools, action="get")
    assert "resource_id" in data["error"]


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------


class TestList:
    def test_list_site_ok(self, tools, monkeypatch) -> None:
        session = FakeSession(
            {
                ("GET", f"{_BASE}/sites"): FakeResp(
                    200, {"status": "success", "data": [{"id": "s1"}]}
                )
            }
        )
        _patch_session(monkeypatch, session)
        data = _call(tools, resource_type="site", tenant_id="t")
        assert data["total"] == 1
        assert data["items"][0]["id"] == "s1"

    def test_list_property_ok(self, tools, monkeypatch) -> None:
        session = FakeSession(
            {
                ("GET", f"{_BASE}/properties"): FakeResp(
                    200, {"status": "success", "data": [{"id": "p1"}, {"id": "p2"}]}
                )
            }
        )
        _patch_session(monkeypatch, session)
        data = _call(tools, resource_type="property")
        assert data["total"] == 2

    def test_list_onboarding_rule_ok_with_metadata(self, tools, monkeypatch) -> None:
        session = FakeSession(
            {
                ("GET", f"{_BASE}/onboarding-rules"): FakeResp(
                    200,
                    {
                        "status": "success",
                        "data": [{"id": "r1"}],
                        "metadata": {"types_mapping": {"a": "b"}},
                    },
                )
            }
        )
        _patch_session(monkeypatch, session)
        data = _call(tools, resource_type="onboarding-rule")
        assert data["total"] == 1
        assert data["metadata"] == {"types_mapping": {"a": "b"}}

    def test_list_site_group_ok(self, tools, monkeypatch) -> None:
        session = FakeSession(
            {("GET", f"{_BASE}/site-groups"): FakeResp(200, {"status": "success", "data": []})}
        )
        _patch_session(monkeypatch, session)
        data = _call(tools, resource_type="site-group")
        assert data["total"] == 0

    def test_list_not_licensed_returns_hint(self, tools, monkeypatch) -> None:
        session = FakeSession({("GET", f"{_BASE}/sites"): FakeResp(403)})
        _patch_session(monkeypatch, session)
        data = _call(tools, resource_type="site", tenant_id="t")
        assert data["total"] == 0
        assert "hint" in data

    def test_list_site_invalid_status_filter(self, tools, monkeypatch) -> None:
        _patch_session(monkeypatch, FakeSession({}))
        data = _call(tools, resource_type="site", status="bogus")
        assert "Unknown status" in data["error"]

    def test_list_property_invalid_type_filter(self, tools, monkeypatch) -> None:
        _patch_session(monkeypatch, FakeSession({}))
        data = _call(tools, resource_type="property", property_type="bogus")
        assert "Unknown property_type" in data["error"]


# ---------------------------------------------------------------------------
# Get
# ---------------------------------------------------------------------------


class TestGet:
    def test_get_ok(self, tools, monkeypatch) -> None:
        session = FakeSession(
            {
                ("GET", f"{_BASE}/sites/s1"): FakeResp(
                    200, {"status": "success", "data": {"id": "s1"}}
                )
            }
        )
        _patch_session(monkeypatch, session)
        data = _call(tools, resource_type="site", action="get", resource_id="s1")
        assert data["item"] == {"id": "s1"}

    def test_get_not_found(self, tools, monkeypatch) -> None:
        session = FakeSession({("GET", f"{_BASE}/sites/nope"): FakeResp(404)})
        _patch_session(monkeypatch, session)
        data = _call(tools, resource_type="site", action="get", resource_id="nope")
        assert data["found"] is False


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------


class TestCreate:
    def test_create_dry_run_default(self, tools, monkeypatch) -> None:
        session = FakeSession({})
        _patch_session(monkeypatch, session)
        data = _call(
            tools,
            resource_type="site",
            action="create",
            body_json='{"name": "site-a", "site_group": "grp1"}',
            ticket_ref="CHG-1",
        )
        assert data["dry_run"] is True
        assert session.calls == []  # dry run never hits the API
        assert data["planned_payload"] == {"sites": [{"name": "site-a", "site_group": "grp1"}]}

    def test_create_applied_site_wraps_body_and_omits_ticket_ref(self, tools, monkeypatch) -> None:
        session = FakeSession(
            {
                ("POST", f"{_BASE}/sites"): FakeResp(
                    201, {"status": "success", "data": [{"id": "s9"}]}
                )
            }
        )
        _patch_session(monkeypatch, session)
        data = _call(
            tools,
            resource_type="site",
            action="create",
            body_json='{"name": "site-a", "site_group": "grp1"}',
            ticket_ref="CHG-1",
            dry_run=False,
        )
        assert data["applied"] is True
        posted = session.calls[0]["json"]
        assert posted == {"sites": [{"name": "site-a", "site_group": "grp1"}]}
        assert "ticket_ref" not in posted
        assert "ticket_ref" not in posted["sites"][0]

    def test_create_applied_property_does_not_inject_ticket_ref(self, tools, monkeypatch) -> None:
        session = FakeSession(
            {
                ("POST", f"{_BASE}/properties"): FakeResp(
                    201, {"status": "success", "data": {"id": "p9"}}
                )
            }
        )
        _patch_session(monkeypatch, session)
        data = _call(
            tools,
            resource_type="property",
            action="create",
            body_json='{"name": "prop1", "type": "string"}',
            ticket_ref="CHG-2",
            dry_run=False,
        )
        assert data["applied"] is True
        posted = session.calls[0]["json"]
        assert posted == {"name": "prop1", "type": "string"}
        assert "ticket_ref" not in posted

    def test_create_requires_body_json(self, tools) -> None:
        data = _call(tools, resource_type="site", action="create", ticket_ref="CHG-3")
        assert "body_json" in data["error"]

    def test_create_invalid_json(self, tools) -> None:
        data = _call(
            tools, resource_type="site", action="create", body_json="{bad", ticket_ref="CHG-4"
        )
        assert "not valid JSON" in data["error"]


# ---------------------------------------------------------------------------
# Update
# ---------------------------------------------------------------------------


class TestUpdate:
    def test_update_dry_run_shows_current(self, tools, monkeypatch) -> None:
        session = FakeSession(
            {
                ("GET", f"{_BASE}/sites/s1"): FakeResp(
                    200, {"status": "success", "data": {"id": "s1"}}
                )
            }
        )
        _patch_session(monkeypatch, session)
        data = _call(
            tools,
            resource_type="site",
            action="update",
            resource_id="s1",
            body_json='{"name": "renamed"}',
            ticket_ref="CHG-5",
        )
        assert data["dry_run"] is True
        assert data["current"] == {"id": "s1"}
        assert data["planned_changes"] == {"name": "renamed"}

    def test_update_applied_does_not_inject_ticket_ref(self, tools, monkeypatch) -> None:
        session = FakeSession(
            {
                ("PUT", f"{_BASE}/sites/s1"): FakeResp(
                    200, {"status": "success", "data": {"id": "s1"}}
                )
            }
        )
        _patch_session(monkeypatch, session)
        data = _call(
            tools,
            resource_type="site",
            action="update",
            resource_id="s1",
            body_json='{"name": "renamed"}',
            ticket_ref="CHG-6",
            dry_run=False,
        )
        assert data["applied"] is True
        posted = session.calls[0]["json"]
        assert posted == {"name": "renamed"}
        assert "ticket_ref" not in posted

    def test_update_requires_resource_id(self, tools) -> None:
        data = _call(
            tools, resource_type="site", action="update", body_json="{}", ticket_ref="CHG-7"
        )
        assert "resource_id" in data["error"]


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------


class TestDelete:
    def test_delete_applied(self, tools, monkeypatch) -> None:
        session = FakeSession({("DELETE", f"{_BASE}/sites/s1"): FakeResp(204)})
        _patch_session(monkeypatch, session)
        data = _call(
            tools,
            resource_type="site",
            action="delete",
            resource_id="s1",
            ticket_ref="CHG-8",
            dry_run=False,
        )
        assert data["applied"] is True

    def test_delete_dry_run_shows_current(self, tools, monkeypatch) -> None:
        session = FakeSession(
            {
                ("GET", f"{_BASE}/sites/s1"): FakeResp(
                    200, {"status": "success", "data": {"id": "s1"}}
                )
            }
        )
        _patch_session(monkeypatch, session)
        data = _call(
            tools, resource_type="site", action="delete", resource_id="s1", ticket_ref="CHG-9"
        )
        assert data["dry_run"] is True
        assert data["current_state"] == {"id": "s1"}

    def test_delete_force_true_passed_as_query_param(self, tools, monkeypatch) -> None:
        session = FakeSession({("DELETE", f"{_BASE}/sites/s1"): FakeResp(204)})
        _patch_session(monkeypatch, session)
        data = _call(
            tools,
            resource_type="site",
            action="delete",
            resource_id="s1",
            ticket_ref="CHG-8b",
            dry_run=False,
            force=True,
        )
        assert data["applied"] is True
        assert session.calls[0]["method"] == "DELETE"
        assert session.calls[0].get("params") == {"force": "true"}

    def test_delete_force_not_applied_to_non_site_resources(self, tools, monkeypatch) -> None:
        session = FakeSession({("DELETE", f"{_BASE}/properties/p1"): FakeResp(200, {})})
        _patch_session(monkeypatch, session)
        data = _call(
            tools,
            resource_type="property",
            action="delete",
            resource_id="p1",
            ticket_ref="CHG-8c",
            dry_run=False,
            force=True,
        )
        assert data["applied"] is True
        assert session.calls[0].get("params") is None


# ---------------------------------------------------------------------------
# Move (onboarding-rule)
# ---------------------------------------------------------------------------


class TestMove:
    def test_move_dry_run_shows_current(self, tools, monkeypatch) -> None:
        session = FakeSession(
            {
                ("GET", f"{_BASE}/onboarding-rules/r1"): FakeResp(
                    200, {"status": "success", "data": {"id": "r1", "rule_order": 3}}
                )
            }
        )
        _patch_session(monkeypatch, session)
        data = _call(
            tools,
            resource_type="onboarding-rule",
            action="move",
            resource_id="r1",
            position="top",
            ticket_ref="CHG-10",
        )
        assert data["dry_run"] is True
        assert data["current"] == {"id": "r1", "rule_order": 3}
        assert data["planned_move"] == {"position": "top"}
        # dry run previews via GET only — never calls the write (:move) endpoint
        assert all(c["method"] == "GET" for c in session.calls)

    def test_move_dry_run_top_bottom_omit_reference(self, tools, monkeypatch) -> None:
        """top/bottom carry no reference — even if a stray one were passed, it's dropped."""
        session = FakeSession({("GET", f"{_BASE}/onboarding-rules/r1"): FakeResp(200, {})})
        _patch_session(monkeypatch, session)
        data = _call(
            tools,
            resource_type="onboarding-rule",
            action="move",
            resource_id="r1",
            position="bottom",
            reference="stray-id",
            ticket_ref="CHG-10b",
        )
        assert data["planned_move"] == {"position": "bottom"}
        assert "reference" not in data["planned_move"]

    def test_move_before_requires_reference(self, tools) -> None:
        data = _call(
            tools,
            resource_type="onboarding-rule",
            action="move",
            resource_id="r1",
            position="before",
            ticket_ref="CHG-11",
        )
        assert "reference" in data["error"]

    def test_move_invalid_position(self, tools) -> None:
        data = _call(
            tools,
            resource_type="onboarding-rule",
            action="move",
            resource_id="r1",
            position="sideways",
            ticket_ref="CHG-12",
        )
        assert "Unknown position" in data["error"]

    def test_move_applied(self, tools, monkeypatch) -> None:
        session = FakeSession(
            {
                ("POST", f"{_BASE}/onboarding-rules/r1:move"): FakeResp(
                    200, {"status": "success", "message": "moved"}
                )
            }
        )
        _patch_session(monkeypatch, session)
        data = _call(
            tools,
            resource_type="onboarding-rule",
            action="move",
            resource_id="r1",
            position="after",
            reference="r0",
            ticket_ref="CHG-13",
            dry_run=False,
        )
        assert data["applied"] is True
        posted = session.calls[0]["json"]
        assert posted == {"position": "after", "reference": "r0"}
        assert "ticket_ref" not in posted

    def test_move_requires_resource_id(self, tools) -> None:
        data = _call(
            tools,
            resource_type="onboarding-rule",
            action="move",
            position="top",
            ticket_ref="CHG-14",
        )
        assert "resource_id" in data["error"]
