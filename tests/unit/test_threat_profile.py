"""scm_threat_profile (fake clients, no network)."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.tools import threat_profile as tp

TENANT = "1234567890"
TICKET = "CHG-TEST"
ASP = "/config/security/v1/anti-spyware-profiles"
VULN = "/config/security/v1/vulnerability-protection-profiles"


@pytest.fixture(autouse=True)
def _no_token_refresh(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tp.scm_rest, "refresh_token", lambda c: None)


def _fn(client: Any) -> Any:
    mcp = FastMCP("test")
    tp.register_threat_profile_tools(mcp, lambda tenant_id="": client)
    return mcp._tool_manager.get_tool("scm_threat_profile").fn


def _client(
    base: str, profiles: list[dict[str, Any]], *, put_applies: bool = True, clears: bool = True
) -> MagicMock:
    store = {p["id"]: dict(p) for p in profiles}
    client = MagicMock()
    # ENDPOINT lookups in scm_rest.put_object
    client.anti_spyware_profile.ENDPOINT = ASP
    client.vulnerability_protection_profile.ENDPOINT = VULN

    def _get(path: str, params: dict[str, Any] | None = None) -> Any:
        if path == base:
            params = params or {}
            hits = [
                p for p in store.values() if not params.get("name") or p["name"] == params["name"]
            ]
            return {"data": hits, "total": len(hits)}
        return store.get(path.rsplit("/", 1)[-1], {})

    def _put(path: str, json: Any = None, params: Any = None) -> Any:
        pid = path.rsplit("/", 1)[-1]
        if put_applies:
            old = store[pid]
            new = {**json, "id": pid}
            if not clears and "threat_exception" in old and "threat_exception" not in json:
                new["threat_exception"] = old["threat_exception"]
            store[pid] = new
        return {"id": pid}

    client.get.side_effect = _get
    client.put.side_effect = _put
    client.post.return_value = {"id": "new-1"}
    client.store = store
    return client


def _asp_rule(**over: Any) -> dict[str, Any]:
    return {
        "name": "r1",
        "severity": ["critical"],
        "category": "any",
        "action": {"drop": {}},
        **over,
    }


def _vuln_rule(**over: Any) -> dict[str, Any]:
    return {
        "name": "v1",
        "severity": ["high"],
        "category": "any",
        "host": "any",
        "vendor_id": ["any"],
        "cve": ["any"],
        "threat_name": "any",
        "packet_capture": "disable",
        "action": {"reset_both": {}},
        **over,
    }


ASP_PROFILE = {
    "id": "a-1",
    "name": "asp-test",
    "folder": "fw-a",
    "description": "old",
    "cloud_inline_analysis": True,
    "rules": [_asp_rule()],
    "threat_exception": [
        {"name": "12345", "packet_capture": "disable", "action": {"allow": {}}},
    ],
}
VULN_PROFILE = {
    "id": "v-1",
    "name": "vuln-test",
    "folder": "fw-a",
    "rules": [_vuln_rule()],
    "threat_exception": [{"name": "54321", "action": {"default": {}}}],
}


class TestValidation:
    def test_vendor_dash_rejected_with_hint(self) -> None:
        _, errors = tp.parse_rules(
            "vulnerability", json.dumps([{**_vuln_rule(), "vendor-id": ["x"]}])
        )
        assert "vendor_id" in errors[0]

    def test_vuln_defaults_and_vendor_id_kept(self) -> None:
        rules, errors = tp.parse_rules(
            "vulnerability", json.dumps([{"name": "a", "severity": ["low"], "vendor_id": ["MS99"]}])
        )
        assert not errors
        assert rules[0]["vendor_id"] == ["MS99"]
        assert rules[0]["host"] == "any" and rules[0]["cve"] == ["any"]

    def test_collects_all_errors(self) -> None:
        raw = json.dumps(
            [
                {"name": "a", "severity": ["bogus"]},
                {"name": "b", "severity": ["low"], "category": "nope"},
                {
                    "name": "c",
                    "severity": ["low"],
                    "action": {"default": {}},
                },  # no default for ASP rules
                {"name": "d", "severity": ["low"], "extra": 1},
            ]
        )
        _, errors = tp.parse_rules("anti_spyware", raw)
        assert len(errors) == 4

    def test_action_shorthand_and_block_ip(self) -> None:
        rules, errors = tp.parse_rules(
            "anti_spyware",
            json.dumps(
                [
                    _asp_rule(action="reset-both"),
                    _asp_rule(
                        name="r2", action={"block_ip": {"track_by": "source", "duration": 60}}
                    ),
                ]
            ),
        )
        assert not errors
        assert rules[0]["action"] == {"reset_both": {}}
        _, errors = tp.parse_rules(
            "anti_spyware", json.dumps([_asp_rule(action={"block_ip": {"duration": 99999}})])
        )
        assert "duration" in errors[0]

    def test_exceptions(self) -> None:
        exc, errors = tp.parse_exceptions(
            "anti_spyware", json.dumps([{"name": 12345, "exempt_ip": ["10.0.0.1"]}])
        )
        assert not errors
        assert exc[0] == {
            "name": "12345",
            "packet_capture": "disable",
            "exempt_ip": [{"name": "10.0.0.1"}],
        }
        _, errors = tp.parse_exceptions(
            "vulnerability",
            json.dumps([{"name": "1", "time_attribute": {"interval": 0}}, {"name": "1"}]),
        )
        assert len(errors) == 2  # bad interval, then duplicate ID
        _, errors = tp.parse_exceptions(
            "anti_spyware", json.dumps([{"name": "1", "time_attribute": {}}])
        )
        assert "unknown field" in errors[0]  # time_attribute is vulnerability-only


class TestReadAndSafety:
    def test_list_get(self) -> None:
        client = _client(ASP, [ASP_PROFILE])
        fn = _fn(client)
        out = json.loads(fn(tenant_id=TENANT, folder="fw-a"))
        assert out["total"] == 1
        got = json.loads(fn(tenant_id=TENANT, action="get", folder="fw-a", name="asp-test"))
        assert got["item"]["threat_exception"][0]["name"] == "12345"
        assert fn(tenant_id=TENANT, action="list").startswith("Error: list needs")

    def test_bad_kind_action_scope(self) -> None:
        fn = _fn(MagicMock())
        assert "unknown kind" in fn(tenant_id=TENANT, kind="url")
        assert "unknown action" in fn(tenant_id=TENANT, action="nuke")
        assert "only one of" in fn(tenant_id=TENANT, folder="a", snippet="b")

    @pytest.mark.parametrize("action", ["create", "update", "delete"])
    @pytest.mark.parametrize("dry_run", [True, False])
    def test_ticket_ref_mandatory_even_for_dry_run(self, action: str, dry_run: bool) -> None:
        client = _client(ASP, [ASP_PROFILE])
        out = _fn(client)(
            tenant_id=TENANT, action=action, folder="fw-a", name="asp-test", dry_run=dry_run
        )
        assert "ticket_ref is mandatory" in out
        client.post.assert_not_called()
        client.put.assert_not_called()
        client.delete.assert_not_called()


class TestCreate:
    def test_dry_run_default_no_write(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _client(VULN, [])
        out = json.loads(
            _fn(client)(
                tenant_id=TENANT,
                kind="vulnerability",
                action="create",
                folder="fw-a",
                name="new-vuln",
                rules_json=json.dumps([_vuln_rule()]),
                ticket_ref=TICKET,
            )
        )
        assert out["dry_run"] is True and out["request"]["method"] == "POST"
        assert out["request"]["body"]["folder"] == "fw-a"
        assert TICKET not in json.dumps(out["request"])
        client.post.assert_not_called()

    def test_vuln_requires_rules_and_valid_name(self) -> None:
        fn = _fn(_client(VULN, []))
        base = {"tenant_id": TENANT, "kind": "vulnerability", "action": "create", "folder": "f"}
        assert "needs rules_json" in fn(**base, name="ok", ticket_ref=TICKET)
        assert "name does not match" in fn(
            **base, name="bad name", rules_json=json.dumps([_vuln_rule()]), ticket_ref=TICKET
        )

    def test_duplicate_refused(self) -> None:
        out = _fn(_client(ASP, [ASP_PROFILE]))(
            tenant_id=TENANT, action="create", folder="fw-a", name="asp-test", ticket_ref=TICKET
        )
        assert "already exists" in out

    def test_real_create_audits_posts_and_verifies(self, monkeypatch: pytest.MonkeyPatch) -> None:
        audits: list[tuple[Any, ...]] = []
        monkeypatch.setattr(tp, "audit_write", lambda *a, **k: audits.append(a))
        client = _client(ASP, [])
        client.post.side_effect = lambda path, json=None: (
            client.store.update({"n-1": {**json, "id": "n-1"}}) or {"id": "n-1"}
        )
        out = json.loads(
            _fn(client)(
                tenant_id=TENANT,
                action="create",
                folder="fw-a",
                name="asp-new",
                rules_json=json.dumps([_asp_rule()]),
                threat_exceptions_json=json.dumps([{"name": "999"}]),
                dry_run=False,
                ticket_ref=TICKET,
            )
        )
        assert out["applied"] is True and out["verified"] is True
        assert audits and audits[0][0] == "scm_threat_profile"
        body = client.post.call_args.kwargs["json"]
        assert body["threat_exception"][0]["packet_capture"] == "disable"
        assert TICKET not in json.dumps(body)


class TestUpdate:
    def test_dry_run_preserves_everything_unchanged(self) -> None:
        client = _client(ASP, [ASP_PROFILE])
        out = json.loads(
            _fn(client)(
                tenant_id=TENANT,
                action="update",
                folder="fw-a",
                name="asp-test",
                description="new",
                ticket_ref=TICKET,
            )
        )
        body = out["request"]["body"]
        assert body["rules"] == ASP_PROFILE["rules"]
        assert body["threat_exception"] == ASP_PROFILE["threat_exception"]
        assert body["cloud_inline_analysis"] is True
        assert body["folder"] == "fw-a" and "id" not in body
        assert "cloud_inline_analysis" in out["preserved"]
        client.put.assert_not_called()

    def test_real_rules_update_verified_and_exceptions_kept(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(tp, "audit_write", lambda *a, **k: None)
        client = _client(VULN, [VULN_PROFILE])
        out = json.loads(
            _fn(client)(
                tenant_id=TENANT,
                kind="vulnerability",
                action="update",
                folder="fw-a",
                name="vuln-test",
                rules_json=json.dumps([_vuln_rule(name="v2", vendor_id=["MS01"])]),
                dry_run=False,
                ticket_ref=TICKET,
            )
        )
        assert out["verified"] is True
        assert out["rule_diff"] == {"added": ["v2"], "removed": ["v1"], "changed": []}
        sent = client.put.call_args.kwargs["json"]
        assert sent["rules"][0]["vendor_id"] == ["MS01"] and "vendor-id" not in json.dumps(sent)
        assert sent["folder"] == "fw-a"
        assert sent["threat_exception"] == VULN_PROFILE["threat_exception"]

    def test_noop_put_reported_unverified(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(tp, "audit_write", lambda *a, **k: None)
        client = _client(VULN, [VULN_PROFILE], put_applies=False)
        out = json.loads(
            _fn(client)(
                tenant_id=TENANT,
                kind="vulnerability",
                action="update",
                folder="fw-a",
                name="vuln-test",
                rules_json=json.dumps([_vuln_rule(name="v2")]),
                dry_run=False,
                ticket_ref=TICKET,
            )
        )
        assert out["verified"] is False and "ignored" in out["warning"]

    def test_clear_exceptions_omits_field_and_checks_read_back(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(tp, "audit_write", lambda *a, **k: None)
        for clears, expect in ((True, True), (False, False)):
            client = _client(ASP, [ASP_PROFILE], clears=clears)
            out = json.loads(
                _fn(client)(
                    tenant_id=TENANT,
                    action="update",
                    folder="fw-a",
                    name="asp-test",
                    threat_exceptions_json="[]",
                    dry_run=False,
                    ticket_ref=TICKET,
                )
            )
            assert "threat_exception" not in client.put.call_args.kwargs["json"]
            assert out["verified"] is expect
            assert out["threat_exception_diff"]["removed"] == ["12345"]

    def test_new_asp_exception_ids_warn(self) -> None:
        out = json.loads(
            _fn(_client(ASP, [ASP_PROFILE]))(
                tenant_id=TENANT,
                action="update",
                folder="fw-a",
                name="asp-test",
                threat_exceptions_json=json.dumps([{"name": "12345"}, {"name": "777"}]),
                ticket_ref=TICKET,
            )
        )
        assert "777" in out["warnings"][0]

    def test_update_needs_something_and_profile(self) -> None:
        fn = _fn(_client(ASP, [ASP_PROFILE]))
        base = {"tenant_id": TENANT, "action": "update", "folder": "fw-a", "ticket_ref": TICKET}
        assert "update needs" in fn(**base, name="asp-test")
        assert "not found" in fn(**base, name="missing", description="x")


class TestDelete:
    def _groups(self, monkeypatch: pytest.MonkeyPatch, rows: Any, status: int = 200) -> MagicMock:
        session = MagicMock()
        resp = MagicMock(status_code=status)
        resp.json.return_value = {"data": rows}
        session.get.return_value = resp
        monkeypatch.setattr(tp.scm_rest, "bearer_session", lambda c: session)
        return session

    def test_refused_when_group_uses_it_and_states_scope(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        session = self._groups(monkeypatch, [{"name": "grp", "spyware": ["asp-test"]}])
        client = _client(ASP, [ASP_PROFILE])
        out = _fn(client)(
            tenant_id=TENANT,
            action="delete",
            folder="fw-a",
            name="asp-test",
            dry_run=False,
            ticket_ref=TICKET,
        )
        assert out.startswith("Error") and "grp" in out and "Not scanned" in out
        assert session.get.call_args.kwargs["params"]["folder"] == "fw-a"
        client.delete.assert_not_called()

    def test_vuln_uses_vulnerability_group_field(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._groups(monkeypatch, [{"name": "grp", "spyware": ["vuln-test"], "vulnerability": []}])
        out = json.loads(
            _fn(_client(VULN, [VULN_PROFILE]))(
                tenant_id=TENANT,
                kind="vulnerability",
                action="delete",
                folder="fw-a",
                name="vuln-test",
                ticket_ref=TICKET,
            )
        )
        assert out["reference_check"]["referenced_by"] == []
        assert out["reference_check"]["not_scanned"]

    def test_dry_run_then_real_delete(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(tp, "audit_write", lambda *a, **k: None)
        self._groups(monkeypatch, [])
        client = _client(ASP, [ASP_PROFILE])
        fn = _fn(client)
        args = {"tenant_id": TENANT, "action": "delete", "folder": "fw-a", "name": "asp-test"}
        out = json.loads(fn(**args, ticket_ref=TICKET))
        assert out["dry_run"] is True
        client.delete.assert_not_called()
        out = json.loads(fn(**args, dry_run=False, ticket_ref=TICKET))
        assert out["applied"] is True
        client.delete.assert_called_once_with(f"{ASP}/a-1")

    def test_lookup_failure_blocks_real_delete_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._groups(monkeypatch, [], status=500)
        client = _client(ASP, [ASP_PROFILE])
        fn = _fn(client)
        args = {"tenant_id": TENANT, "action": "delete", "folder": "fw-a", "name": "asp-test"}
        dry = json.loads(fn(**args, ticket_ref=TICKET))
        assert "HTTP 500" in dry["reference_check"]["warning"]
        out = fn(**args, dry_run=False, ticket_ref=TICKET)
        assert out.startswith("Error") and "refusing" in out
        client.delete.assert_not_called()
