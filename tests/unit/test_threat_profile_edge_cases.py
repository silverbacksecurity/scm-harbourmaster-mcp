"""scm_threat_profile edge cases (fake clients, no network, no real tenant data)."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest

from scm_harbourmaster_mcp.tools import threat_profile as tp

from .test_threat_profile import (
    ASP,
    ASP_PROFILE,
    TENANT,
    TICKET,
    VULN,
    VULN_PROFILE,
    _asp_rule,
    _client,
    _fn,
    _vuln_rule,
)

BASES = {"anti_spyware": (ASP, ASP_PROFILE), "vulnerability": (VULN, VULN_PROFILE)}


@pytest.fixture(autouse=True)
def _quiet(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tp.scm_rest, "refresh_token", lambda c: None)
    monkeypatch.setattr(tp, "audit_write", lambda *a, **k: None)


def _groups(monkeypatch: pytest.MonkeyPatch, pages: list[Any], status: int = 200) -> MagicMock:
    session = MagicMock()
    resps = []
    for rows in pages:
        resp = MagicMock(status_code=status)
        resp.json.return_value = {"data": rows}
        resps.append(resp)
    session.get.side_effect = resps
    monkeypatch.setattr(tp.scm_rest, "bearer_session", lambda c: session)
    return session


# -- ticket_ref: every kind x every write action x dry/real x blank forms ----------


@pytest.mark.parametrize("kind", list(BASES))
@pytest.mark.parametrize("action", ["create", "update", "delete"])
@pytest.mark.parametrize("dry_run", [True, False])
@pytest.mark.parametrize("ticket", ["", "   ", "\t\n"])
def test_every_kind_and_write_action_needs_ticket_ref(
    kind: str, action: str, dry_run: bool, ticket: str
) -> None:
    base, profile = BASES[kind]
    client = _client(base, [profile])
    out = _fn(client)(
        tenant_id=TENANT,
        kind=kind,
        action=action,
        folder="fw-a",
        name=profile["name"],
        description="x",
        dry_run=dry_run,
        ticket_ref=ticket,
    )
    assert "ticket_ref is mandatory" in out
    assert not (client.post.called or client.put.called or client.delete.called)
    # rejected before any lookup, so no REST read was made either
    client.get.assert_not_called()


def test_reads_do_not_need_ticket_ref() -> None:
    client = _client(ASP, [ASP_PROFILE])
    assert json.loads(_fn(client)(tenant_id=TENANT, folder="fw-a"))["total"] == 1


# -- validation -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "name", "ok"),
    [
        ("anti_spyware", "has space.and-dot_1", True),
        ("anti_spyware", "-leading", False),
        ("anti_spyware", " leading", False),
        ("anti_spyware", "bad/slash", False),
        ("anti_spyware", "", False),
        ("vulnerability", "no.space_ok-1", True),
        ("vulnerability", "has space", False),
        ("vulnerability", "bad$", False),
        ("vulnerability", "", False),
    ],
)
def test_name_pattern_per_kind(kind: str, name: str, ok: bool) -> None:
    base, _ = BASES[kind]
    out = _fn(_client(base, []))(
        tenant_id=TENANT,
        kind=kind,
        action="create",
        folder="fw-a",
        name=name,
        rules_json=json.dumps([_vuln_rule() if kind == "vulnerability" else _asp_rule()]),
        ticket_ref=TICKET,
    )
    assert ("name does not match" not in out) is ok


def test_vendor_dash_rejected_through_the_tool_with_hint() -> None:
    client = _client(VULN, [])
    out = _fn(client)(
        tenant_id=TENANT,
        kind="vulnerability",
        action="create",
        folder="fw-a",
        name="v-new",
        rules_json=json.dumps([{"name": "r", "severity": ["low"], "vendor-id": ["x"]}]),
        dry_run=False,
        ticket_ref=TICKET,
    )
    assert (
        out.startswith("Error: invalid rules_json")
        and "vendor_id" in out
        and "not 'vendor-id'" in out
    )
    client.post.assert_not_called()


@pytest.mark.parametrize("raw", ["", "{bad", "null", '"str"', "{}", "[1]", '[["a"]]'])
def test_rules_json_shape_errors(raw: str) -> None:
    rules, errors = tp.parse_rules("anti_spyware", raw) if raw else ([], ["x"])
    assert rules == [] and errors


@pytest.mark.parametrize("raw", ["{bad", "null", "{}", "[1]"])
def test_exceptions_json_shape_errors_through_tool(raw: str) -> None:
    client = _client(ASP, [])
    out = _fn(client)(
        tenant_id=TENANT,
        action="create",
        folder="fw-a",
        name="n",
        threat_exceptions_json=raw,
        ticket_ref=TICKET,
    )
    assert out.startswith("Error: invalid threat_exceptions_json")
    client.post.assert_not_called()


def test_unknown_keys_reported_for_rules_and_exceptions_each_kind() -> None:
    for kind in BASES:
        _, errs = tp.parse_rules(kind, json.dumps([{"name": "a", "severity": ["low"], "zzz": 1}]))
        assert "unknown field" in errs[0] and "zzz" in errs[0]
    _, errs = tp.parse_exceptions("anti_spyware", json.dumps([{"name": "1", "time_attribute": {}}]))
    assert "unknown field" in errs[0]  # time_attribute is vulnerability-only
    _, errs = tp.parse_exceptions("vulnerability", json.dumps([{"name": "1", "zzz": 1}]))
    assert "unknown field" in errs[0]


@pytest.mark.parametrize(
    "rule",
    [
        {"name": "r"},  # severity missing
        {"name": "r", "severity": []},
        {"name": "r", "severity": "low "},
        {"name": "r", "severity": ["low"], "threat_name": "ab"},  # asp min 3
        {"name": "r", "severity": ["low"], "packet_capture": "yes"},
        {"name": "r", "severity": ["low"], "action": {"alert": {}, "drop": {}}},
        {"name": "r", "severity": ["low"], "action": {"default": {}}},  # asp has no default
        {"name": "r", "severity": ["low"], "action": {"alert": {"x": 1}}},
        {"name": "r", "severity": ["low"], "action": {"block_ip": {"duration": 0}}},
        {"name": "r", "severity": ["low"], "action": {"block_ip": {"duration": 3601}}},
        {"name": "r", "severity": ["low"], "action": {"block_ip": {"duration": True}}},
        {"name": "r", "severity": ["low"], "action": {"block_ip": {"track_by": "dest"}}},
        {"name": "r", "severity": ["low"], "action": {"block_ip": {"bogus": 1}}},
        {"severity": ["low"]},
        {"name": 5, "severity": ["low"]},
    ],
)
def test_asp_rule_rejections(rule: dict[str, Any]) -> None:
    rules, errors = tp.parse_rules("anti_spyware", json.dumps([rule]))
    assert rules == [] and len(errors) == 1


def test_duplicate_rule_and_exception_names() -> None:
    _, errs = tp.parse_rules("anti_spyware", json.dumps([_asp_rule(), _asp_rule()]))
    assert "duplicate" in errs[0]
    _, errs = tp.parse_exceptions("anti_spyware", json.dumps([{"name": "1"}, {"name": 1}]))
    assert "duplicate" in errs[0]  # int ids are normalised to str first


def test_exception_int_id_and_exempt_ip_normalised() -> None:
    out, errs = tp.parse_exceptions(
        "anti_spyware", json.dumps([{"name": 12345, "exempt_ip": ["10.0.0.1"], "action": "alert"}])
    )
    assert not errs
    assert out[0]["name"] == "12345"
    assert out[0]["exempt_ip"] == [{"name": "10.0.0.1"}]
    assert out[0]["packet_capture"] == "disable"  # asp default
    assert out[0]["action"] == {"alert": {}}


@pytest.mark.parametrize(
    "exc",
    [
        {"name": "1", "exempt_ip": []},
        {"name": "1", "exempt_ip": "10.0.0.1"},
        {"name": "1", "exempt_ip": [1]},
        {"name": "1", "notes": 5},
        {"name": "1", "packet_capture": "nope"},
        {"name": "", "action": "alert"},
        {"name": True},
    ],
)
def test_exception_rejections(exc: dict[str, Any]) -> None:
    out, errs = tp.parse_exceptions("anti_spyware", json.dumps([exc]))
    assert out == [] and errs


def test_vulnerability_exception_notes_rejected() -> None:
    """SCM silently drops notes on vulnerability exceptions; fail loudly instead."""
    out, errs = tp.parse_exceptions("vulnerability", json.dumps([{"name": "1", "notes": "x"}]))
    assert out == [] and "notes is not supported" in errs[0]
    out, errs = tp.parse_exceptions("anti_spyware", json.dumps([{"name": "1", "notes": "x"}]))
    assert not errs and out[0]["notes"] == "x"


@pytest.mark.parametrize(
    "ta",
    [
        {"interval": 0},
        {"interval": 3601},
        {"threshold": 0},
        {"threshold": 65536},
        {"track_by": "nowhere"},
        {"bogus": 1},
        "str",
        {"interval": "5"},
    ],
)
def test_time_attribute_rejections(ta: Any) -> None:
    out, errs = tp.parse_exceptions(
        "vulnerability", json.dumps([{"name": "1", "time_attribute": ta}])
    )
    assert out == [] and errs


def test_time_attribute_valid_bounds() -> None:
    ta = {"interval": 3600, "threshold": 65535, "track_by": "source-and-destination"}
    out, errs = tp.parse_exceptions(
        "vulnerability", json.dumps([{"name": "1", "time_attribute": ta}])
    )
    assert not errs and out[0]["time_attribute"] == ta


@pytest.mark.parametrize("field", ["interval", "threshold"])
def test_time_attribute_bool_should_be_rejected(field: str) -> None:
    _, errs = tp.parse_exceptions(
        "vulnerability", json.dumps([{"name": "1", "time_attribute": {field: True}}])
    )
    assert errs


# -- update ---------------------------------------------------------------------


def test_exceptions_only_update_preserves_rules_description_and_unknown_fields() -> None:
    client = _client(ASP, [ASP_PROFILE])
    out = json.loads(
        _fn(client)(
            tenant_id=TENANT,
            action="update",
            folder="fw-a",
            name="asp-test",
            threat_exceptions_json=json.dumps([{"name": "12345", "action": "alert"}]),
            dry_run=False,
            ticket_ref=TICKET,
        )
    )
    sent = client.put.call_args.kwargs["json"]
    assert sent["rules"] == ASP_PROFILE["rules"]
    assert sent["description"] == "old"
    assert sent["cloud_inline_analysis"] is True
    assert sent["threat_exception"][0]["action"] == {"alert": {}}
    assert out["rule_diff"] == {"added": [], "removed": [], "changed": []}
    assert out["threat_exception_diff"]["changed"] == ["12345"]
    assert out["verified"] is True


def test_description_only_update_keeps_rules_and_exceptions() -> None:
    client = _client(VULN, [VULN_PROFILE])
    _fn(client)(
        tenant_id=TENANT,
        kind="vulnerability",
        action="update",
        folder="fw-a",
        name="vuln-test",
        description="",
        dry_run=False,
        ticket_ref=TICKET,
    )
    sent = client.put.call_args.kwargs["json"]
    assert sent["description"] == ""  # empty string is a real change, not "unspecified"
    assert sent["rules"] == VULN_PROFILE["rules"]
    assert sent["threat_exception"] == VULN_PROFILE["threat_exception"]


@pytest.mark.parametrize("kind", list(BASES))
def test_clear_exceptions_with_empty_list_both_kinds(kind: str) -> None:
    base, profile = BASES[kind]
    client = _client(base, [profile])
    out = json.loads(
        _fn(client)(
            tenant_id=TENANT,
            kind=kind,
            action="update",
            folder="fw-a",
            name=profile["name"],
            threat_exceptions_json="[]",
            dry_run=False,
            ticket_ref=TICKET,
        )
    )
    sent = client.put.call_args.kwargs["json"]
    assert "threat_exception" not in sent
    assert sent["rules"] == profile["rules"]
    assert out["verified"] is True
    assert "clearing works by omitting" in out["warnings"][0]
    assert client.store[profile["id"]].get("threat_exception") is None


def test_clearing_when_there_are_no_exceptions_does_not_warn() -> None:
    profile = {k: v for k, v in ASP_PROFILE.items() if k != "threat_exception"}
    out = json.loads(
        _fn(_client(ASP, [profile]))(
            tenant_id=TENANT,
            action="update",
            folder="fw-a",
            name="asp-test",
            threat_exceptions_json="[]",
            ticket_ref=TICKET,
        )
    )
    assert "warnings" not in out


def test_asp_empty_rules_list_is_omitted_vuln_empty_rules_refused() -> None:
    client = _client(ASP, [ASP_PROFILE])
    out = json.loads(
        _fn(client)(
            tenant_id=TENANT,
            action="update",
            folder="fw-a",
            name="asp-test",
            rules_json="[]",
            ticket_ref=TICKET,
        )
    )
    assert "rules" not in out["request"]["body"]
    out = _fn(_client(VULN, [VULN_PROFILE]))(
        tenant_id=TENANT,
        kind="vulnerability",
        action="update",
        folder="fw-a",
        name="vuln-test",
        rules_json="[]",
        ticket_ref=TICKET,
    )
    assert "at least one rule" in out


def test_update_invalid_json_never_puts() -> None:
    client = _client(ASP, [ASP_PROFILE])
    out = _fn(client)(
        tenant_id=TENANT,
        action="update",
        folder="fw-a",
        name="asp-test",
        rules_json='[{"name": "r", "severity": ["low"], "vendor-id": ["x"]}]',
        dry_run=False,
        ticket_ref=TICKET,
    )
    assert out.startswith("Error: invalid rules_json")
    client.put.assert_not_called()


def test_update_by_profile_id_and_ticket_not_in_put_body() -> None:
    client = _client(ASP, [ASP_PROFILE])
    _fn(client)(
        tenant_id=TENANT,
        action="update",
        profile_id="a-1",
        description="n",
        dry_run=False,
        ticket_ref=TICKET,
    )
    assert client.put.call_args.args[0] == f"{ASP}/a-1"
    assert TICKET not in json.dumps(client.put.call_args.kwargs["json"])


def test_update_without_target_or_container() -> None:
    out = _fn(_client(ASP, [ASP_PROFILE]))(
        tenant_id=TENANT, action="update", name="asp-test", description="x", ticket_ref=TICKET
    )
    assert "needs profile_id, or name" in out


# -- read-back mismatch ---------------------------------------------------------------


def test_create_read_back_mismatch_warns() -> None:
    client = _client(ASP, [])  # POST stores nothing, so the read-back finds nothing
    out = json.loads(
        _fn(client)(
            tenant_id=TENANT,
            action="create",
            folder="fw-a",
            name="asp-new",
            rules_json=json.dumps([_asp_rule()]),
            dry_run=False,
            ticket_ref=TICKET,
        )
    )
    assert out["applied"] is True and out["verified"] is False
    assert "read-back does not match" in out["warning"]


def test_create_read_back_altered_value_warns() -> None:
    client = _client(ASP, [])

    def _post(path: str, json: Any = None) -> Any:
        altered = {**json, "id": "n-1", "description": "server changed it"}
        client.store["n-1"] = altered
        return {"id": "n-1"}

    client.post.side_effect = _post
    out = json.loads(
        _fn(client)(
            tenant_id=TENANT,
            action="create",
            folder="fw-a",
            name="asp-new",
            description="mine",
            rules_json=json.dumps([_asp_rule()]),
            dry_run=False,
            ticket_ref=TICKET,
        )
    )
    assert out["verified"] is False and "warning" in out


def test_update_read_back_unaffected_by_extra_server_fields() -> None:
    client = _client(ASP, [ASP_PROFILE])
    real_put = client.put.side_effect

    def _put(path: str, json: Any = None, params: Any = None) -> Any:
        res = real_put(path, json=json, params=params)
        client.store["a-1"]["server_default"] = "x"
        return res

    client.put.side_effect = _put
    out = json.loads(
        _fn(client)(
            tenant_id=TENANT,
            action="update",
            folder="fw-a",
            name="asp-test",
            description="n",
            dry_run=False,
            ticket_ref=TICKET,
        )
    )
    assert out["verified"] is True


def test_update_exceptions_silently_ignored_is_unverified() -> None:
    client = _client(ASP, [ASP_PROFILE])
    real_put = client.put.side_effect

    def _put(path: str, json: Any = None, params: Any = None) -> Any:
        real_put(path, json=json, params=params)
        client.store["a-1"]["threat_exception"] = ASP_PROFILE["threat_exception"]  # not applied
        return {"id": "a-1"}

    client.put.side_effect = _put
    out = json.loads(
        _fn(client)(
            tenant_id=TENANT,
            action="update",
            folder="fw-a",
            name="asp-test",
            threat_exceptions_json=json.dumps([{"name": "12345", "action": "drop"}]),
            dry_run=False,
            ticket_ref=TICKET,
        )
    )
    assert out["verified"] is False and "ignored" in out["warning"]


# -- delete ----------------------------------------------------------------------------


@pytest.mark.parametrize("dry_run", [True, False])
def test_delete_refused_when_referenced_in_both_modes(
    dry_run: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    _groups(monkeypatch, [[{"name": "grp", "spyware": "asp-test"}]])  # str, not list
    client = _client(ASP, [ASP_PROFILE])
    out = _fn(client)(
        tenant_id=TENANT,
        action="delete",
        folder="fw-a",
        name="asp-test",
        dry_run=dry_run,
        ticket_ref=TICKET,
    )
    assert out.startswith("Error") and "['grp']" in out
    client.delete.assert_not_called()


def test_delete_ignores_groups_that_use_other_profiles(monkeypatch: pytest.MonkeyPatch) -> None:
    _groups(monkeypatch, [[{"name": "g", "spyware": ["other"], "vulnerability": ["asp-test"]}]])
    out = json.loads(
        _fn(_client(ASP, [ASP_PROFILE]))(
            tenant_id=TENANT, action="delete", folder="fw-a", name="asp-test", ticket_ref=TICKET
        )
    )
    assert out["reference_check"]["referenced_by"] == []


def test_delete_reference_check_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    full = [{"name": f"g{i}", "spyware": []} for i in range(tp._PAGE)]
    session = _groups(monkeypatch, [full, [{"name": "last", "spyware": ["asp-test"]}]])
    out = _fn(_client(ASP, [ASP_PROFILE]))(
        tenant_id=TENANT, action="delete", folder="fw-a", name="asp-test", ticket_ref=TICKET
    )
    assert "last" in out
    assert session.get.call_count == 2
    assert session.get.call_args_list[1].kwargs["params"]["offset"] == tp._PAGE


def test_delete_lookup_exception_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    session = MagicMock()
    session.get.side_effect = RuntimeError("boom")
    monkeypatch.setattr(tp.scm_rest, "bearer_session", lambda c: session)
    client = _client(ASP, [ASP_PROFILE])
    args = {"tenant_id": TENANT, "action": "delete", "folder": "fw-a", "name": "asp-test"}
    dry = json.loads(_fn(client)(**args, ticket_ref=TICKET))
    assert "boom" in dry["reference_check"]["warning"]
    real = _fn(client)(**args, dry_run=False, ticket_ref=TICKET)
    assert real.startswith("Error") and "refusing to delete" in real
    client.delete.assert_not_called()


def test_delete_token_refresh_failure_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(c: Any) -> None:
        raise RuntimeError("token expired")

    monkeypatch.setattr(tp.scm_rest, "refresh_token", _boom)
    client = _client(VULN, [VULN_PROFILE])
    out = _fn(client)(
        tenant_id=TENANT,
        kind="vulnerability",
        action="delete",
        folder="fw-a",
        name="vuln-test",
        dry_run=False,
        ticket_ref=TICKET,
    )
    assert out.startswith("Error") and "refusing" in out
    client.delete.assert_not_called()


def test_delete_scan_uses_profile_own_container(monkeypatch: pytest.MonkeyPatch) -> None:
    profile = {k: v for k, v in ASP_PROFILE.items() if k != "folder"} | {"snippet": "snip-a"}
    session = _groups(monkeypatch, [[]])
    out = json.loads(
        _fn(_client(ASP, [profile]))(
            tenant_id=TENANT,
            action="delete",
            profile_id="a-1",
            ticket_ref=TICKET,
        )
    )
    assert session.get.call_args.kwargs["params"]["snippet"] == "snip-a"
    assert "snippet" in out["reference_check"]["scanned"]


def test_delete_missing_profile() -> None:
    out = _fn(_client(ASP, []))(
        tenant_id=TENANT, action="delete", folder="fw-a", name="nope", ticket_ref=TICKET
    )
    assert "not found" in out
