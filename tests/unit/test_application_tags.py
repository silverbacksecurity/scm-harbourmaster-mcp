"""scm_application_tags and scm_device_models (fake clients, no network)."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.tools import adnsr as adnsr_mod
from scm_harbourmaster_mcp.tools import application_tags as at_mod

TENANT = "1234567890"
TICKET = "CHG-TEST"
BASE = "/config/objects/v1/application-tags"
ENTRY = {"id": "at-1", "name": "app-synthetic", "folder": "fw-a", "tags": ["old"]}


def _tool(register: Any, name: str, client: Any) -> Any:
    mcp = FastMCP("test")
    register(mcp, lambda tenant_id="": client)
    return mcp._tool_manager.get_tool(name).fn


def _client(rows: list[dict[str, Any]] | None = None) -> MagicMock:
    rows = [ENTRY] if rows is None else rows
    client = MagicMock()

    def _get(path: str, params: dict[str, Any] | None = None) -> Any:
        if path == BASE:
            params = params or {}
            hits = [r for r in rows if not params.get("name") or r["name"] == params["name"]]
            start, limit = int(params["offset"]), int(params["limit"])
            return {"data": hits[start : start + limit], "total": len(hits)}
        return next((r for r in rows if path == f"{BASE}/{r['id']}"), {})

    client.get.side_effect = _get
    return client


def _tags(client: Any) -> Any:
    return _tool(at_mod.register_application_tag_tools, "scm_application_tags", client)


class TestReads:
    def test_list_pages_and_filters(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(at_mod, "_PAGE", 2)
        rows = [{"id": f"at-{i}", "name": f"app-{i}", "tags": []} for i in range(5)]
        client = _client(rows)
        out = json.loads(_tags(client)(tenant_id=TENANT, folder="fw-a"))
        assert out["total"] == 5
        assert out["scope"] == {"folder": "fw-a"}
        offsets = [c.kwargs["params"]["offset"] for c in client.get.call_args_list]
        assert offsets == ["0", "2", "4"]

        out = json.loads(_tags(client)(tenant_id=TENANT, folder="fw-a", name="app-3"))
        assert [r["id"] for r in out["items"]] == ["at-3"]

    def test_get_by_id(self) -> None:
        out = json.loads(_tags(_client())(tenant_id=TENANT, action="get", tag_id="at-1"))
        assert out["item"] == ENTRY

    @pytest.mark.parametrize(
        ("kwargs", "message"),
        [
            ({"action": "nope"}, "unknown action"),
            ({"folder": "a", "snippet": "b"}, "only one of folder, snippet or device"),
            ({"action": "get"}, "tag_id is required"),
            ({"action": "create", "name": "x"}, "ticket_ref is mandatory"),
        ],
    )
    def test_argument_errors(self, kwargs: dict[str, Any], message: str) -> None:
        client = _client()
        out = _tags(client)(tenant_id=TENANT, **kwargs)
        assert out.startswith("Error:") and message in out
        client.post.assert_not_called()


class TestWrites:
    def test_create_dry_run_is_default_and_reads_nothing(self) -> None:
        client = _client()
        out = json.loads(
            _tags(client)(
                tenant_id=TENANT,
                action="create",
                folder="fw-a",
                name="app-synthetic",
                tags=["sanctioned"],
                ticket_ref=TICKET,
            )
        )
        assert out["dry_run"] is True
        assert out["request"] == {
            "method": "POST",
            "path": BASE,
            "body": {"name": "app-synthetic", "folder": "fw-a", "tags": ["sanctioned"]},
        }
        client.post.assert_not_called()

    def test_create_applies_without_ticket_in_body(self) -> None:
        client = _client()
        client.post.return_value = {"id": "at-9"}
        out = json.loads(
            _tags(client)(
                tenant_id=TENANT,
                action="create",
                device="000000000000001",
                name="app-synthetic",
                tags=["t"],
                dry_run=False,
                ticket_ref=TICKET,
            )
        )
        client.post.assert_called_once_with(
            BASE, json={"name": "app-synthetic", "device": "000000000000001", "tags": ["t"]}
        )
        assert TICKET not in json.dumps(client.post.call_args.kwargs)
        assert out["applied"] is True and out["result"] == {"id": "at-9"}

    def test_create_needs_name_and_scope(self) -> None:
        out = _tags(_client())(tenant_id=TENANT, action="create", name="x", ticket_ref=TICKET)
        assert "create needs name and one of folder" in out

    def test_update_by_name_shows_current_then_puts(self) -> None:
        client = _client()
        fn = _tags(client)
        dry = json.loads(
            fn(
                tenant_id=TENANT,
                action="update",
                folder="fw-a",
                name="app-synthetic",
                tags=["new"],
                ticket_ref=TICKET,
            )
        )
        assert dry["current"] == ENTRY
        assert dry["request"]["method"] == "PUT"
        assert dry["request"]["path"] == f"{BASE}/at-1"
        client.put.assert_not_called()

        fn(tenant_id=TENANT, action="update", tag_id="at-1", tags=["new"], dry_run=False,
           ticket_ref=TICKET)  # fmt: skip
        client.put.assert_called_once_with(
            f"{BASE}/at-1", json={"name": "app-synthetic", "tags": ["new"]}
        )

    def test_update_needs_tags(self) -> None:
        out = _tags(_client())(tenant_id=TENANT, action="update", tag_id="at-1", ticket_ref=TICKET)
        assert "update needs tags" in out

    def test_delete_dry_run_then_apply(self) -> None:
        client = _client()
        fn = _tags(client)
        dry = json.loads(fn(tenant_id=TENANT, action="delete", tag_id="at-1", ticket_ref=TICKET))
        assert dry["current"] == ENTRY and dry["request"]["method"] == "DELETE"
        client.delete.assert_not_called()

        fn(tenant_id=TENANT, action="delete", tag_id="at-1", dry_run=False, ticket_ref=TICKET)
        client.delete.assert_called_once_with(f"{BASE}/at-1")

    def test_delete_by_unknown_name(self) -> None:
        out = _tags(_client())(
            tenant_id=TENANT, action="delete", folder="fw-a", name="missing", ticket_ref=TICKET
        )
        assert "no application-tag entry named 'missing'" in out

    def test_bulk_create_and_update(self) -> None:
        client = _client()
        apps = [{"name": "app-a", "tags": ["x"]}, {"name": "app-b", "tags": ["y"]}]
        fn = _tags(client)
        fn(tenant_id=TENANT, action="bulk_create", folder="fw-a",
           applications_json=json.dumps(apps), dry_run=False, ticket_ref=TICKET)  # fmt: skip
        client.post.assert_called_once_with(
            f"{BASE}/bulk", json={"folder": "fw-a", "applications": apps}
        )
        fn(tenant_id=TENANT, action="bulk_update", snippet="snip-a",
           applications_json=json.dumps(apps), dry_run=False, ticket_ref=TICKET)  # fmt: skip
        client.put.assert_called_once_with(BASE, json={"snippet": "snip-a", "applications": apps})

    @pytest.mark.parametrize(
        ("apps", "message"),
        [
            ("not json", "not valid JSON"),
            ("[]", "non-empty list"),
            (json.dumps([{"tags": []}]), "every application needs a name"),
            (json.dumps([{"name": f"a{i}"} for i in range(51)]), "at most 50"),
        ],
    )
    def test_bulk_validation(self, apps: str, message: str) -> None:
        client = _client()
        out = _tags(client)(
            tenant_id=TENANT,
            action="bulk_create",
            folder="fw-a",
            applications_json=apps,
            dry_run=False,
            ticket_ref=TICKET,
        )
        assert out.startswith("Error:") and message in out
        client.post.assert_not_called()

    def test_bulk_needs_scope(self) -> None:
        out = _tags(_client())(
            tenant_id=TENANT, action="bulk_create", applications_json="[]", ticket_ref=TICKET
        )
        assert "bulk_create needs one of folder" in out


# ── scm_device_models ──────────────────────────────────────────────────────

MODELS = [
    {
        "name": "PA-TEST-1",
        "help": "Synthetic small",
        "interfaces": {
            "ethernet": [{"name": "ethernet1/1"}, {"name": "ethernet1/2", "flags": {"poe": "yes"}}],
            "cellular": [{"name": "cellular1/1"}],
        },
    },
    {"name": "PA-TEST-2", "help": "Synthetic large", "interfaces": {"ethernet": []}},
    {"name": "VM-TEST", "help": "No interfaces"},
]


def _models(client: Any) -> Any:
    return _tool(adnsr_mod.register_adnsr_tools, "scm_device_models", client)


class TestDeviceModels:
    def test_summary_rows(self) -> None:
        client = MagicMock()
        client.get.return_value = {"data": MODELS, "total": 3, "limit": 200, "offset": 0}
        out = json.loads(_models(client)(tenant_id=TENANT))
        assert out["total"] == 3
        assert out["models"][0] == {
            "name": "PA-TEST-1",
            "description": "Synthetic small",
            "ethernet": 2,
            "cellular": 1,
        }
        assert out["models"][2]["ethernet"] == 0
        client.get.assert_called_once_with(
            "/config/device/v1/models", params={"limit": "200", "offset": "0"}
        )

    def test_filter_returns_full_interfaces(self) -> None:
        client = MagicMock()
        client.get.return_value = MODELS  # bare-list shape (no limit honoured)
        out = json.loads(_models(client)(tenant_id=TENANT, model="test-1"))
        assert out["total"] == 1
        assert out["models"][0]["interfaces"]["ethernet"][1]["flags"] == {"poe": "yes"}

    def test_pages_by_offset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(adnsr_mod, "_MODELS_PAGE", 2)
        client = MagicMock()
        client.get.side_effect = lambda path, params: {
            "data": MODELS[int(params["offset"]) : int(params["offset"]) + 2],
            "total": 3,
        }
        out = json.loads(_models(client)(tenant_id=TENANT))
        assert [m["name"] for m in out["models"]] == ["PA-TEST-1", "PA-TEST-2", "VM-TEST"]
        assert client.get.call_count == 2
