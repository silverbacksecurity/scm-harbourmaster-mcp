"""scm_decryption_rule_copy / scm_gp_copy against in-memory SCM APIs (no network)."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.tools import tenant_copy
from scm_harbourmaster_mcp.tools.tenant_copy import agent_profile_body, register_tenant_copy_tools

TICKET = "CHG-COPY-1"
SRC, DST = "1000000001", "1000000002"


def _resp(status: int, body: Any) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.json.return_value = body
    return r


class FakeTenant:
    """GET routes return canned bodies (path -> body, or (status, body)); writes are recorded."""

    def __init__(self, routes: dict[str, Any]) -> None:
        self.routes = routes
        self.writes: list[tuple[str, str, dict[str, Any]]] = []
        self.write_status: dict[str, int] = {}
        self.client = MagicMock()
        s = self.client.session
        s.get.side_effect = self._get
        s.post.side_effect = lambda url, **kw: self._write("POST", url, **kw)
        s.put.side_effect = lambda url, **kw: self._write("PUT", url, **kw)

    @staticmethod
    def _key(url: str, params: dict[str, Any] | None) -> str:
        path = url.split("/v1/", 1)[1]
        folder = (params or {}).get("folder")
        pos = (params or {}).get("position")
        return path + (f"@{folder}" if folder else "") + (f"#{pos}" if pos else "")

    def _get(
        self, url: str, params: dict[str, Any] | None = None, timeout: Any = None
    ) -> MagicMock:
        key = self._key(url, params)
        value = self.routes.get(key, self.routes.get(key.split("@")[0], {"data": []}))
        if isinstance(value, tuple):
            return _resp(*value)
        return _resp(200, value)

    def _write(
        self, method: str, url: str, params: Any = None, json: Any = None, timeout: Any = None
    ) -> MagicMock:  # noqa: A002
        path = url.split("/v1/", 1)[1]
        self.writes.append((method, path, json))
        return _resp(self.write_status.get(path, 201), {"id": "new"})


def _tools(tenants: dict[str, FakeTenant], monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setattr(tenant_copy, "_bearer_session_for", lambda client: client.session)
    monkeypatch.setattr(tenant_copy, "resolve_tenant_id", lambda t: t)
    mcp = FastMCP("test-tenant-copy")
    register_tenant_copy_tools(mcp, lambda tenant_id="": tenants[tenant_id].client)
    return {
        n: mcp._tool_manager.get_tool(n).fn for n in ("scm_decryption_rule_copy", "scm_gp_copy")
    }  # noqa: SLF001


# ── Decryption rules ──────────────────────────────────────────────────────────


def _rule(name: str, **kw: Any) -> dict[str, Any]:
    base = {
        "id": f"id-{name}",
        "name": name,
        "folder": "Shared",
        "position": "pre",
        "action": "decrypt",
        "profile": "Corp-Decrypt",
        "from": ["trust"],
        "to": ["untrust"],
        "disabled": False,
    }
    base.update(kw)
    return base


@pytest.fixture
def decrypt_tenants() -> dict[str, FakeTenant]:
    src_rules = [
        _rule("No-Decrypt-Finance", action="no-decrypt", disabled=True),
        {"id": "p1", "name": "office365", "folder": "Shared"},  # snippet placeholder
        _rule("Existing-Rule"),
        _rule("Missing-Profile", profile="Not-There"),
        _rule("Inherited", folder="All"),
        _rule("Decrypt-All"),
    ]
    src = FakeTenant({"decryption-rules@Shared#pre": {"data": src_rules}})
    dst = FakeTenant(
        {
            "decryption-rules@Shared#pre": {"data": [_rule("Existing-Rule")]},
            "decryption-profiles@Shared": {"data": [{"name": "Corp-Decrypt"}]},
            "ssl-decryption-settings": (403, {"_errors": [{"code": "forbidden"}]}),
        }
    )
    return {SRC: src, DST: dst}


def test_rule_copy_dry_run(
    decrypt_tenants: dict[str, FakeTenant], monkeypatch: pytest.MonkeyPatch
) -> None:
    out = _tools(decrypt_tenants, monkeypatch)["scm_decryption_rule_copy"](
        tenant_id=SRC, target_tenant_id=DST, ticket_ref=TICKET
    )
    assert "DRY-RUN" in out and "**Would apply:** 2" in out and "**Skipped:** 2" in out
    assert "office365" not in out and "Inherited" not in out
    assert "`Missing-Profile` | skipped — decryption profile `Not-There` missing" in out
    assert "SSL decryption settings are unreadable" in out
    assert decrypt_tenants[DST].writes == []


def test_rule_copy_creates_in_order_and_can_disable(
    decrypt_tenants: dict[str, FakeTenant], monkeypatch: pytest.MonkeyPatch
) -> None:
    out = _tools(decrypt_tenants, monkeypatch)["scm_decryption_rule_copy"](
        tenant_id=SRC, target_tenant_id=DST, ticket_ref=TICKET, dry_run=False, create_disabled=True
    )
    writes = decrypt_tenants[DST].writes
    assert [w[2]["name"] for w in writes] == ["No-Decrypt-Finance", "Decrypt-All"]
    body = writes[1][2]
    assert body["disabled"] is True and body["folder"] == "Shared"
    assert "id" not in body and "position" not in body
    assert "**Applied:** 2" in out and "scm_commit(folders=['Shared']" in out
    assert "enabled decrypt rule" not in out  # all created disabled


def test_rule_copy_named_placeholder_and_unknown(
    decrypt_tenants: dict[str, FakeTenant], monkeypatch: pytest.MonkeyPatch
) -> None:
    copy_rules = _tools(decrypt_tenants, monkeypatch)["scm_decryption_rule_copy"]
    out = copy_rules(
        tenant_id=SRC, target_tenant_id=DST, names=["office365"], ticket_ref=TICKET, dry_run=False
    )
    assert "Snippet placeholders" in out and decrypt_tenants[DST].writes == []
    out = copy_rules(tenant_id=SRC, target_tenant_id=DST, names=["Nope"], ticket_ref=TICKET)
    assert "Not in source Shared/pre: Nope" in out


def test_rule_copy_guards(
    decrypt_tenants: dict[str, FakeTenant], monkeypatch: pytest.MonkeyPatch
) -> None:
    copy_rules = _tools(decrypt_tenants, monkeypatch)["scm_decryption_rule_copy"]
    assert "ticket_ref is mandatory" in copy_rules(tenant_id=SRC, target_tenant_id=DST)
    assert "same" in copy_rules(tenant_id=SRC, target_tenant_id=SRC, ticket_ref=TICKET)
    assert "position must be" in copy_rules(
        tenant_id=SRC, target_tenant_id=DST, position="x", ticket_ref=TICKET
    )


# ── GlobalProtect ─────────────────────────────────────────────────────────────

_SRC_PROFILE = {
    "name": "DEFAULT",
    "os": ["any"],
    "client_certificate": {"local": "GP_Log_Certificate"},
    "gp_app_config": {
        "config": [
            {"name": "connect-method", "value": ["on-demand"]},
            {"name": "dem-agent", "value": ["install-with-user-control"]},
            {"name": "cdl-log", "value": ["yes"]},
        ]
    },
}


def _gp_tenants(target_infra: list[dict[str, Any]]) -> dict[str, FakeTenant]:
    src = FakeTenant(
        {
            "infrastructure-settings@Mobile Users": [
                {
                    "id": "i1",
                    "folder": "Mobile Users",
                    "name": "source.lab.gpcloudservice.com",
                    "portal_hostname": {"default_domain": {"hostname": "source"}},
                    "ip_pools": [{"name": "worldwide", "ip_pool": ["100.127.0.0/16"]}],
                    "deployment": {
                        "region": [{"name": "europe", "locations": ["eu-west-1", "eu-west-2"]}]
                    },
                },
            ],
            "global-settings@Mobile Users": {"agent_version": "6.2.3", "manual_gateway": {}},
            "locations@Mobile Users": {
                "region": [{"name": "europe", "locations": ["eu-west-1", "eu-west-2"]}]
            },
            "agent-profiles@Mobile Users": {"data": [_SRC_PROFILE]},
            "authentication-settings@Mobile Users": {
                "data": [
                    {
                        "name": "DEFAULT",
                        "folder": "Mobile Users",
                        "authentication_profile": "Local Users",
                        "os": "Any",
                        "user_credential_or_client_cert_required": True,
                    },
                    {
                        "name": "CIE-Auth",
                        "folder": "Mobile Users",
                        "authentication_profile": "CIE-Profile",
                        "os": "Any",
                    },
                    {
                        "name": "Extra-Auth",
                        "folder": "Mobile Users",
                        "authentication_profile": "Local Users",
                        "os": "Any",
                    },
                ]
            },
        }
    )
    dst = FakeTenant(
        {
            "infrastructure-settings@Mobile Users": target_infra,
            "global-settings@Mobile Users": {"agent_version": "6.3.3-1121", "manual_gateway": {}},
            "agent-profiles@Mobile Users": {"data": [{"name": "DEFAULT"}]},
            "authentication-settings@Mobile Users": {
                "data": [
                    {
                        "name": "DEFAULT",
                        "folder": "Mobile Users",
                        "authentication_profile": "Local Users",
                        "os": "Any",
                    },
                ]
            },
            "authentication-profiles@All": {"data": [{"name": "Local Users"}]},
        }
    )
    return {SRC: src, DST: dst}


def test_agent_profile_body_strips_api_rejects() -> None:
    body, ui_only = agent_profile_body(_SRC_PROFILE)
    assert "os" not in body
    assert body["gp_app_config"]["config"] == [{"name": "connect-method", "value": ["on-demand"]}]
    assert ui_only == {"dem-agent": ["install-with-user-control"], "cdl-log": ["yes"]}
    assert _SRC_PROFILE["os"] == ["any"]  # source untouched


def test_gp_copy_requires_hostname_for_new_infrastructure(monkeypatch: pytest.MonkeyPatch) -> None:
    tenants = _gp_tenants([])
    out = _tools(tenants, monkeypatch)["scm_gp_copy"](
        tenant_id=SRC, target_tenant_id=DST, ticket_ref=TICKET
    )
    assert "portal_hostname` is required" in out and tenants[DST].writes == []


def test_gp_copy_onboards_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    tenants = _gp_tenants([])
    out = _tools(tenants, monkeypatch)["scm_gp_copy"](
        tenant_id=SRC,
        target_tenant_id=DST,
        portal_hostname="target-lab",
        locations=["eu-west-2"],
        ticket_ref=TICKET,
        dry_run=False,
    )
    writes = tenants[DST].writes
    assert [(m, p) for m, p, _ in writes] == [
        ("POST", "infrastructure-settings"),
        ("PUT", "locations"),
        ("PUT", "global-settings"),
        ("PUT", "agent-profiles"),
        ("POST", "authentication-settings"),
    ]
    infra = writes[0][2]
    assert infra["name"] == "target-lab"  # short name — SCM appends the domain
    assert infra["portal_hostname"] == {"default_domain": {"hostname": "target-lab"}}
    assert infra["deployment"] == {"region": [{"name": "europe", "locations": ["eu-west-2"]}]}
    assert "id" not in infra and "folder" not in infra
    assert writes[2][2] == {
        "agent_version": "6.3.3-1121",
        "manual_gateway": {"region": [{"name": "europe", "locations": ["eu-west-2"]}]},
    }
    assert "os" not in writes[3][2]
    assert writes[4][2]["name"] == "Extra-Auth"
    assert "`CIE-Auth` | skipped — authentication profile `CIE-Profile` missing" in out
    assert "`DEFAULT` | exists — differs; the API cannot update it" in out
    assert "dem-agent=install-with-user-control" in out
    assert "admin='all'" in out


def test_gp_copy_never_replaces_existing_infrastructure(monkeypatch: pytest.MonkeyPatch) -> None:
    tenants = _gp_tenants([{"name": "already.lab.gpcloudservice.com"}])
    out = _tools(tenants, monkeypatch)["scm_gp_copy"](
        tenant_id=SRC, target_tenant_id=DST, ticket_ref=TICKET, dry_run=False
    )
    paths = [p for _, p, _ in tenants[DST].writes]
    assert "infrastructure-settings" not in paths and paths[0] == "locations"
    assert "target already has infrastructure" in out


def test_gp_copy_stops_when_infrastructure_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    tenants = _gp_tenants([])
    tenants[DST].write_status["infrastructure-settings"] = 400
    out = _tools(tenants, monkeypatch)["scm_gp_copy"](
        tenant_id=SRC, target_tenant_id=DST, portal_hostname="t", ticket_ref=TICKET, dry_run=False
    )
    assert [p for _, p, _ in tenants[DST].writes] == ["infrastructure-settings"]
    assert "Stopped" in out and "**Failed:** 1" in out


def test_gp_copy_dry_run_writes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    tenants = _gp_tenants([])
    out = _tools(tenants, monkeypatch)["scm_gp_copy"](
        tenant_id=SRC, target_tenant_id=DST, portal_hostname="target-lab", ticket_ref=TICKET
    )
    assert "DRY-RUN" in out and tenants[DST].writes == []
    assert "`target-lab` | would create (portal `target-lab`, pool 100.127.0.0/16)" in out


def test_gp_copy_skips_settings_that_already_match(monkeypatch: pytest.MonkeyPatch) -> None:
    tenants = _gp_tenants([{"name": "already.lab.gpcloudservice.com"}])
    region = {"region": [{"name": "europe", "locations": ["eu-west-2", "eu-west-1"]}]}
    tenants[DST].routes["locations@Mobile Users"] = region
    tenants[DST].routes["global-settings@Mobile Users"] = {
        "agent_version": "6.3.3-1121",
        "manual_gateway": region,
    }
    out = _tools(tenants, monkeypatch)["scm_gp_copy"](
        tenant_id=SRC, target_tenant_id=DST, ticket_ref=TICKET, dry_run=False
    )
    paths = [p for _, p, _ in tenants[DST].writes]
    assert "locations" not in paths and "global-settings" not in paths
    assert out.count("skipped — already matches") == 2
