"""Tests for the object / security / network CRUD tools (no network).

These are the tools that write to a customer's candidate config, so the
payload shape and the "fetch then delete by id" flow matter more than the
list formatting.
"""

from __future__ import annotations

import functools
import inspect
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.tools.network import register_network_tools
from scm_harbourmaster_mcp.tools.objects import register_object_tools
from scm_harbourmaster_mcp.tools.security import register_security_tools

TENANT = "1234567890"


def _tools(client: Any) -> dict[str, Any]:
    mcp = FastMCP("test")
    for register in (register_object_tools, register_security_tools, register_network_tools):
        register(mcp, lambda tenant_id="": client)
    return {name: _gated(t.fn) for name, t in mcp._tool_manager._tools.items()}


def _gated(fn: Any) -> Any:
    """Default the write-safety args so tests exercise the apply path.

    Write tools default to ``dry_run=True`` and require ``ticket_ref``; the
    dry-run contract itself is covered in ``test_write_safety.py``.
    """
    if "ticket_ref" not in inspect.signature(fn).parameters:
        return fn
    return functools.partial(fn, ticket_ref="CHG-TEST", dry_run=False)


def _obj(**fields: Any) -> MagicMock:
    m = MagicMock()
    for k, v in fields.items():
        setattr(m, k, v)
    m.model_dump.return_value = fields
    return m


# ── Addresses ──────────────────────────────────────────────────────────────


class TestAddressTools:
    @pytest.mark.parametrize(
        ("kwargs", "key", "value"),
        [
            ({"ip_netmask": "10.0.0.0/8", "fqdn": "ignored.example"}, "ip_netmask", "10.0.0.0/8"),
            ({"fqdn": "app.example.com"}, "fqdn", "app.example.com"),
            ({"ip_range": "10.0.0.1-10.0.0.9"}, "ip_range", "10.0.0.1-10.0.0.9"),
        ],
    )
    def test_create_uses_exactly_one_address_type(
        self, kwargs: dict[str, str], key: str, value: str
    ) -> None:
        client = MagicMock()
        client.address.create.return_value = _obj(name="a1", id="uuid-1")
        out = _tools(client)["scm_address_create"](
            tenant_id=TENANT, name="a1", folder="Branch", **kwargs
        )
        payload = client.address.create.call_args.args[0]
        assert payload == {"name": "a1", "folder": "Branch", key: value}
        assert json.loads(out)["result"]["id"] == "uuid-1"

    def test_create_with_description(self) -> None:
        client = MagicMock()
        client.address.create.return_value = {"ok": True}
        _tools(client)["scm_address_create"](
            name="a1", folder="Branch", fqdn="x.example", description="web tier"
        )
        assert client.address.create.call_args.args[0]["description"] == "web tier"

    def test_create_requires_an_address_value(self) -> None:
        client = MagicMock()
        out = _tools(client)["scm_address_create"](name="a1", folder="Branch")
        assert out == "Error: supply one of ip_netmask, fqdn, or ip_range"
        client.address.create.assert_not_called()

    def test_create_sdk_error_is_normalised(self) -> None:
        client = MagicMock()
        client.address.create.side_effect = RuntimeError("name not unique")
        out = _tools(client)["scm_address_create"](name="a1", folder="Branch", fqdn="x.example")
        assert out == "Error: [RuntimeError] name not unique"

    def test_delete_fetches_then_deletes_by_id(self) -> None:
        client = MagicMock()
        client.address.fetch.return_value = SimpleNamespace(id="uuid-9")
        out = _tools(client)["scm_address_delete"](tenant_id=TENANT, name="a1", folder="Branch")
        client.address.fetch.assert_called_once_with(name="a1", folder="Branch")
        client.address.delete.assert_called_once_with("uuid-9")
        assert out == "Deleted address 'a1' from folder 'Branch' (ticket_ref: CHG-TEST)"

    def test_delete_missing_object_does_not_delete(self) -> None:
        client = MagicMock()
        client.address.fetch.side_effect = RuntimeError("object not present")
        out = _tools(client)["scm_address_delete"](name="gone", folder="Branch")
        assert out.startswith("Error:")
        client.address.delete.assert_not_called()

    def test_list_filter_and_limit(self) -> None:
        client = MagicMock()
        client.address.list.return_value = [
            _obj(name="Web-1"),
            _obj(name="db-1"),
            _obj(name="web-2"),
            _obj(name="WEB-3"),
        ]
        out = json.loads(
            _tools(client)["scm_address_list"](folder="Branch", name_filter="web", limit=2)
        )
        assert [o["name"] for o in out] == ["Web-1", "web-2"]

    def test_get_and_other_object_lists(self) -> None:
        client = MagicMock()
        client.address.fetch.return_value = _obj(name="a1")
        client.address_group.list.return_value = [_obj(name="g1"), _obj(name="g2")]
        client.service.list.return_value = [_obj(name="tcp-8443")]
        client.tag.list.return_value = [_obj(name="prod")]
        client.external_dynamic_list.list.return_value = [_obj(name="blocklist")]
        tools = _tools(client)
        assert json.loads(tools["scm_address_get"](name="a1", folder="B"))["name"] == "a1"
        assert len(json.loads(tools["scm_address_group_list"](folder="B", limit=1))) == 1
        assert "tcp-8443" in tools["scm_service_list"](folder="B")
        assert "prod" in tools["scm_tag_list"](folder="B")
        assert "blocklist" in tools["scm_edl_list"](folder="B")


# ── Security rules ─────────────────────────────────────────────────────────


class TestSecurityRuleTools:
    def test_create_applies_safe_defaults(self) -> None:
        client = MagicMock()
        client.security_rule.create.return_value = {"id": "r1"}
        _tools(client)["scm_security_rule_create"](
            tenant_id=TENANT,
            name="allow-web",
            folder="Branch",
            action="allow",
            source_zones=["trust"],
            destination_zones=["untrust"],
        )
        payload = client.security_rule.create.call_args.args[0]
        assert payload == {
            "name": "allow-web",
            "folder": "Branch",
            "action": "allow",
            "from": ["trust"],
            "to": ["untrust"],
            "source": ["any"],
            "destination": ["any"],
            "application": ["any"],
            "service": ["application-default"],
            "disabled": False,
        }

    def test_create_passes_explicit_values(self) -> None:
        client = MagicMock()
        client.security_rule.create.return_value = {"id": "r1"}
        _tools(client)["scm_security_rule_create"](
            name="allow-web",
            folder="Branch",
            action="deny",
            source_zones=["trust"],
            destination_zones=["untrust"],
            source_addresses=["10.0.0.0/8"],
            destination_addresses=["web"],
            applications=["ssl"],
            services=["service-https"],
            profile_setting={"group": ["best-practice"]},
            description="ticket CHG-1",
            disabled=True,
        )
        payload = client.security_rule.create.call_args.args[0]
        assert payload["source"] == ["10.0.0.0/8"]
        assert payload["application"] == ["ssl"]
        assert payload["service"] == ["service-https"]
        assert payload["profile_setting"] == {"group": ["best-practice"]}
        assert payload["description"] == "ticket CHG-1"
        assert payload["disabled"] is True

    def test_create_missing_required_argument_degrades(self) -> None:
        client = MagicMock()
        out = _tools(client)["scm_security_rule_create"](name="x", folder="Branch", action="allow")
        assert out.startswith("Error: [TypeError]")
        client.security_rule.create.assert_not_called()

    def test_delete_and_get(self) -> None:
        client = MagicMock()
        client.security_rule.fetch.return_value = _obj(id="rid-1", name="old")
        tools = _tools(client)
        out = tools["scm_security_rule_delete"](name="old", folder="Branch")
        client.security_rule.delete.assert_called_once_with("rid-1")
        assert out == "Deleted security rule 'old' from folder 'Branch' (ticket_ref: CHG-TEST)"
        assert (
            json.loads(tools["scm_security_rule_get"](name="old", folder="Branch"))["id"] == "rid-1"
        )

    def test_list_uses_rulebase_kwarg(self) -> None:
        client = MagicMock()
        client.security_rule.list.return_value = [_obj(name="a"), _obj(name="b")]
        out = json.loads(
            _tools(client)["scm_security_rule_list"](folder="Branch", position="post", limit=1)
        )
        client.security_rule.list.assert_called_once_with(folder="Branch", rulebase="post")
        assert [r["name"] for r in out] == ["a"]

    def test_profile_lists(self) -> None:
        client = MagicMock()
        client.anti_spyware_profile.list.return_value = [_obj(name="as")]
        client.url_category.list.return_value = [_obj(name="cat")]
        tools = _tools(client)
        assert "as" in tools["scm_anti_spyware_profile_list"](folder="B")
        assert "cat" in tools["scm_url_category_list"](folder="B")


# ── Network ────────────────────────────────────────────────────────────────


class TestNetworkTools:
    def test_nat_rules_use_position_kwarg(self) -> None:
        client = MagicMock()
        client.nat_rule.list.return_value = [_obj(name="n1")]
        client.nat_rule.fetch.return_value = _obj(name="n1")
        tools = _tools(client)
        assert "n1" in tools["scm_nat_rule_list"](folder="Branch", position="post")
        client.nat_rule.list.assert_called_once_with(folder="Branch", position="post")
        assert json.loads(tools["scm_nat_rule_get"](name="n1", folder="Branch"))["name"] == "n1"

    def test_list_tools_slice_client_side(self) -> None:
        client = MagicMock()
        many = [_obj(name=f"o{i}") for i in range(4)]
        for attr in ("security_zone", "ike_gateway", "ipsec_tunnel", "internal_dns_server"):
            getattr(client, attr).list.return_value = many
        tools = _tools(client)
        for tool_name in (
            "scm_zone_list",
            "scm_ike_gateway_list",
            "scm_ipsec_tunnel_list",
            "scm_dns_server_list",
        ):
            assert len(json.loads(tools[tool_name](folder="Branch", limit=3))) == 3
        # DNS servers are deployment-global: folder is not forwarded
        client.internal_dns_server.list.assert_called_once_with()

    def test_errors_are_normalised(self) -> None:
        client = MagicMock()
        client.security_zone.list.side_effect = RuntimeError("403 forbidden")
        assert _tools(client)["scm_zone_list"](folder="B") == "Error: [RuntimeError] 403 forbidden"
