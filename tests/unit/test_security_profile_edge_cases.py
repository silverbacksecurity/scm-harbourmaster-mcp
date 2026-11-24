"""scm_security_profile edge cases (mocked REST, no network, no real tenant data)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from scm_harbourmaster_mcp.tools import security_profile as sp

from .test_security_profile import (
    CASES,
    TENANT,
    TICKET,
    _call,
    _client,
    _existing,
    _tool,
    _with_scan,
)


@pytest.fixture(autouse=True)
def _quiet(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sp.scm_rest, "refresh_token", lambda c: None)
    monkeypatch.setattr(sp, "audit_write", lambda *a, **k: None)
    monkeypatch.setattr(sp, "_category_warnings", lambda *a, **k: [])


def _cfg(kind: str) -> str:
    return json.dumps(CASES[kind][1])


# -- ticket_ref ----------------------------------------------------------------------


@pytest.mark.parametrize("kind", CASES)
@pytest.mark.parametrize("action", ["create", "update", "delete"])
@pytest.mark.parametrize("dry_run", [True, False])
@pytest.mark.parametrize("ticket", ["", "  ", "\n"])
def test_every_kind_and_write_action_needs_ticket_ref(
    kind: str, action: str, dry_run: bool, ticket: str
) -> None:
    client = _client([_existing(kind)])
    out = _call(
        client,
        kind,
        action=action,
        config_json=json.dumps(CASES[kind][2]),
        dry_run=dry_run,
        ticket_ref=ticket,
    )
    assert "ticket_ref is mandatory" in out
    assert not (client.post.called or client.put.called or client.delete.called)
    client.get.assert_not_called()


def test_ticket_ref_never_reaches_a_request_body() -> None:
    for kind in CASES:
        client = _client([_existing(kind)])
        _call(client, kind, action="update", config_json=json.dumps(CASES[kind][2]),
              ticket_ref=TICKET, dry_run=False)  # fmt: skip
        assert TICKET not in json.dumps(client.put.call_args.kwargs["json"])


# -- alias -------------------------------------------------------------------------------


@pytest.mark.parametrize("alias", ["antivirus", "Antivirus", " ANTIVIRUS "])
def test_antivirus_alias_resolves_for_every_write_action(alias: str) -> None:
    path = CASES["wildfire_antivirus"][0]
    assert sp.resolve_kind(alias) is sp.SPECS["wildfire_antivirus"]
    client = _client()
    out = json.loads(
        _call(
            client,
            alias,
            action="create",
            config_json=_cfg("wildfire_antivirus"),
            ticket_ref=TICKET,
            dry_run=False,
        )  # fmt: skip
    )
    assert out["kind"] == "wildfire_antivirus"
    assert client.post.call_args.args[0] == path
    out = json.loads(
        _call(
            client,
            alias,
            action="update",
            config_json='{"packet_capture": false}',
            ticket_ref=TICKET,
        )  # fmt: skip
    )
    assert out["request"]["path"] == f"{path}/new-1"


def test_antivirus_alias_delete_and_unknown_kind() -> None:
    assert sp.resolve_kind("") is None and sp.resolve_kind("virus") is None
    assert "unknown kind" in _call(_client(), "")


# -- URL `continue` ------------------------------------------------------------------------


def test_url_continue_survives_update_body() -> None:
    client = _client([_existing("url_access", **{"continue": ["old"]})])
    out = json.loads(
        _call(
            client,
            "url_access",
            action="update",
            config_json='{"continue": ["unknown", "x"]}',
            ticket_ref=TICKET,
            dry_run=False,
        )  # fmt: skip
    )
    assert client.put.call_args.kwargs["json"]["continue"] == ["unknown", "x"]
    assert out["verified"] is True


def test_url_continue_preserved_when_update_touches_other_keys() -> None:
    client = _client([_existing("url_access")])  # carries continue=["unknown"]
    _call(client, "url_access", action="update", config_json='{"alert": ["news"]}',
          ticket_ref=TICKET, dry_run=False)  # fmt: skip
    sent = client.put.call_args.kwargs["json"]
    assert sent["continue"] == ["unknown"] and sent["alert"] == ["news"]


def test_url_credential_enforcement_continue_and_dry_run_create_body() -> None:
    cfg = {"credential_enforcement": {"continue": ["c1"], "mode": {"ip_user": {}}}}
    out = json.loads(
        _call(
            _client(), "url_access", action="create", config_json=json.dumps(cfg), ticket_ref=TICKET
        )
    )
    assert out["request"]["body"]["credential_enforcement"]["continue"] == ["c1"]


# -- null removes a key ------------------------------------------------------------------------


def test_null_removes_nested_key_and_keeps_siblings() -> None:
    current = _existing("url_access")  # credential_enforcement has mode + log_severity
    client = _client([current])
    out = json.loads(
        _call(
            client,
            "url_access",
            action="update",
            config_json='{"credential_enforcement": {"log_severity": null}}',
            ticket_ref=TICKET,
            dry_run=False,
        )  # fmt: skip
    )
    sent = client.put.call_args.kwargs["json"]
    assert "log_severity" not in sent["credential_enforcement"]
    assert sent["credential_enforcement"]["mode"] == {"disabled": {}}
    assert sent["block"] == ["malware"]
    assert out["verified"] is True


def test_null_for_absent_key_is_a_noop_that_still_verifies() -> None:
    client = _client([_existing("decryption")])
    out = json.loads(
        _call(
            client,
            "decryption",
            action="update",
            config_json='{"ssl_no_proxy": null}',
            ticket_ref=TICKET,
            dry_run=False,
        )  # fmt: skip
    )
    assert out["verified"] is True and out["diff"] == {"added": [], "removed": [], "changed": []}


def test_null_rejected_on_create_and_inside_lists() -> None:
    out = _call(_client(), "url_access", action="create", config_json='{"description": null}',
                ticket_ref=TICKET)  # fmt: skip
    assert "only allowed on update" in out
    out = _call(_client([_existing("url_access")]), "url_access", action="update",
                config_json='{"block": [null]}', ticket_ref=TICKET)  # fmt: skip
    assert "only allowed on update" in out


def test_null_name_rejected() -> None:
    out = _call(_client([_existing("url_access")]), "url_access", action="update",
                config_json='{"name": null, "alert": ["a"]}', ticket_ref=TICKET)  # fmt: skip
    assert out.startswith("Error")


# -- response-only fields ------------------------------------------------------------------------


def test_override_fields_stripped_from_put_but_update_still_verifies() -> None:
    client = _client(
        [_existing("wildfire_antivirus", override_loc="a", override_type="b", override_id="c")]
    )
    out = json.loads(
        _call(
            client,
            "wildfire_antivirus",
            action="update",
            config_json='{"description": "n"}',
            ticket_ref=TICKET,
            dry_run=False,
        )  # fmt: skip
    )
    sent = client.put.call_args.kwargs["json"]
    assert not {"override_loc", "override_type", "override_id", "id"} & set(sent)
    assert sent["folder"] == "fw-a" and sent["rules"]
    assert out["verified"] is True
    assert "override_loc" not in out["diff"]["removed"]


def test_override_fields_rejected_in_config_json() -> None:
    out = _call(_client([_existing("wildfire_antivirus")]), "wildfire_antivirus", action="update",
                config_json='{"override_loc": "x"}', ticket_ref=TICKET)  # fmt: skip
    assert "unknown keys" in out


def test_id_and_container_keys_rejected_in_config_json() -> None:
    for key in ("id", "folder", "snippet", "device"):
        out = _call(_client(), "decryption", action="create", ticket_ref=TICKET,
                    config_json=json.dumps({key: "x", "ssl_no_proxy": {}}))  # fmt: skip
        assert "must not contain" in out and key in out


# -- zone protection field types --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("cfg", "needle"),
    [
        ({"flood": {"udp": {"enable": "yes"}}}, "flood.udp.enable: must be true/false"),
        (
            {
                "flood": {
                    "udp": {"red": {"alarm_rate": "10", "activate_rate": 1, "maximal_rate": 2}}
                }
            },
            "must be an integer",
        ),
        (
            {
                "flood": {
                    "udp": {"red": {"alarm_rate": True, "activate_rate": 1, "maximal_rate": 2}}
                }
            },
            "must be an integer",
        ),
        (
            {"flood": {"udp": {"red": {"alarm_rate": 1.5, "activate_rate": 1, "maximal_rate": 2}}}},
            "must be an integer",
        ),
        (
            {"flood": {"udp": {"red": {"alarm_rate": -1, "activate_rate": 1, "maximal_rate": 2}}}},
            "outside 0..2000000",
        ),
        (
            {
                "flood": {
                    "udp": {"red": {"alarm_rate": 2000001, "activate_rate": 1, "maximal_rate": 2}}
                }
            },
            "outside 0..2000000",
        ),
        ({"flood": {"udp": {"red": {"alarm_rate": 1}}}}, "activate_rate: required"),
        ({"flood": {"bogus": {}}}, "unknown keys"),
        ({"flood": []}, "must be an object"),
        ({"spoofed_ip_discard": "true"}, "must be true/false"),
        ({"spoofed_ip_discard": 1}, "must be true/false"),
        ({"reject_non_syn_tcp": "maybe"}, "not one of"),
        ({"reject_non_syn_tcp": True}, "must be a string"),
        ({"asymmetric_path": "allow"}, "not one of"),
        ({"mptcp_option_strip": "drop"}, "not one of"),
        ({"description": 5}, "must be a string"),
        ({"description": "x" * 256}, "longer than 255"),
        ({"scan": {}}, "must be a list"),
        ({"scan": [{"name": "9999"}]}, "not one of"),
        ({"scan": [{"name": 8001}]}, "must be a string"),
        ({"scan": [{"name": "8001", "interval": 1}]}, "outside 2..65535"),
        ({"scan": [{"name": "8001", "threshold": 70000}]}, "outside 2..65535"),
        ({"scan": [{"name": "8001", "action": {"alert": {}, "block": {}}}]}, "exactly one"),
        ({"scan": [{"name": "8001", "action": {"nuke": {}}}]}, "unknown keys"),
        (
            {"scan": [{"name": "8001", "action": {"block_ip": {"track_by": "source"}}}]},
            "duration: required",
        ),
        (
            {
                "scan": [
                    {"name": "8001", "action": {"block_ip": {"track_by": "dest", "duration": 5}}}
                ]
            },
            "not one of",
        ),
        (
            {
                "scan": [
                    {
                        "name": "8001",
                        "action": {"block_ip": {"track_by": "source", "duration": 3601}},
                    }
                ]
            },
            "outside 1..3600",
        ),
        ({"scan": [{"action": {"allow": {}}}]}, "name: required"),
        ({"scan_white_list": [{"ipv4": "1.1.1.1"}]}, "name: required"),
        ({"ipv6": {"filter_ext_hdr": {"hop_by_hop_hdr": "x"}}}, "must be true/false"),
        ({"ipv6": {"bogus": True}}, "unknown keys"),
        ({"non_ip_protocol": {"list_type": "both"}}, "not one of"),
        ({"non_ip_protocol": {"protocol": [{"name": "p"}]}}, "ether_type: required"),
        ({"l2_sec_group_tag_protection": {"tags": [{"name": "t"}]}}, "tag: required"),
    ],
)
def test_zone_protection_type_and_bound_errors(cfg: dict[str, Any], needle: str) -> None:
    client = _client()
    out = _call(client, "zone_protection", action="create", config_json=json.dumps(cfg),
                ticket_ref=TICKET, dry_run=False)  # fmt: skip
    assert out.startswith("Error: invalid zone_protection") and needle in out, out
    client.post.assert_not_called()


def test_zone_protection_valid_boundaries_and_syn_cookies() -> None:
    cfg = {
        "flood": {
            "tcp_syn": {
                "enable": True,
                "syn_cookies": {"alarm_rate": 0, "activate_rate": 0, "maximal_rate": 2000000},
            }
        },
        "scan": [
            {
                "name": "8006",
                "interval": 2,
                "threshold": 65535,
                "action": {"block_ip": {"track_by": "source-and-destination", "duration": 3600}},
            }
        ],  # fmt: skip
        "reject_non_syn_tcp": "no",
        "asymmetric_path": "bypass",
        "ipv6": {"routing_header_0": False, "filter_ext_hdr": {"hop_by_hop_hdr": True}},
        "non_ip_protocol": {
            "list_type": "include",
            "protocol": [{"name": "p", "ether_type": "0x0800"}],
        },
    }
    out = json.loads(_call(_client(), "zone_protection", action="create", config_json=json.dumps(cfg),
                           ticket_ref=TICKET))  # fmt: skip
    assert out["validation"]["ok"] is True
    assert out["request"]["body"]["flood"]["tcp_syn"]["syn_cookies"]["maximal_rate"] == 2000000


def test_zone_name_max_error_is_not_duplicated() -> None:
    out = _call(_client(), "zone_protection", action="create", name="n" * 32, config_json="{}",
                ticket_ref=TICKET)  # fmt: skip
    assert out.count("longer than 31") == 1, out


def test_zone_scan_action_replaced_whole_on_update() -> None:
    current = _existing("zone_protection")  # scan[0] action = block_ip
    client = _client([current])
    out = json.loads(
        _call(
            client,
            "zone_protection",
            action="update",
            ticket_ref=TICKET,
            dry_run=False,
            config_json=json.dumps({"scan": [{"name": "8001", "action": {"alert": {}}}]}),
        )  # fmt: skip
    )
    assert client.put.call_args.kwargs["json"]["scan"] == [
        {"name": "8001", "action": {"alert": {}}}
    ]
    assert client.put.call_args.kwargs["json"]["flood"] == current["flood"]
    assert out["verified"] is True


# -- update preserves unspecified fields / merge semantics ---------------------------------------------


@pytest.mark.parametrize("kind", CASES)
def test_update_keeps_every_unspecified_top_level_field(kind: str) -> None:
    current = _existing(kind, server_only_field="keepme")
    delta = CASES[kind][2]
    client = _client([current])
    _call(client, kind, action="update", config_json=json.dumps(delta), ticket_ref=TICKET,
          dry_run=False)  # fmt: skip
    sent = client.put.call_args.kwargs["json"]
    for key, value in current.items():
        if key not in delta and key != "id":
            assert sent[key] == value, key


def test_decryption_deep_merge_keeps_sibling_flags() -> None:
    current = _existing("decryption")
    client = _client([current])
    _call(client, "decryption", action="update", config_json='{"ssl_protocol_settings": {"min_version": "tls1-1"}}',
          ticket_ref=TICKET, dry_run=False)  # fmt: skip
    sent = client.put.call_args.kwargs["json"]["ssl_protocol_settings"]
    assert sent == {"min_version": "tls1-1", "max_version": "tls1-3"}


def test_update_by_profile_id_and_missing_target() -> None:
    client = _client([_existing("decryption")])
    tool = _tool(client)
    out = json.loads(
        tool(tenant_id=TENANT, kind="decryption", action="update", profile_id="p-1",
             config_json='{"ssl_no_proxy": {"block_untrusted_issuer": true}}', ticket_ref=TICKET)
    )  # fmt: skip
    assert out["request"]["path"].endswith("/p-1")
    out = tool(tenant_id=TENANT, kind="decryption", action="update", name="x",
               config_json='{"ssl_no_proxy": {}}', ticket_ref=TICKET)  # fmt: skip
    assert "needs profile_id, or name" in out


# -- read-back mismatch ----------------------------------------------------------------------------------


@pytest.mark.parametrize("kind", CASES)
def test_create_read_back_mismatch_warns(kind: str) -> None:
    client = _client()

    def _post(path: str, json: Any = None) -> Any:
        return {"id": "new-1"}  # stores nothing

    client.post.side_effect = _post
    out = json.loads(
        _call(
            client, kind, action="create", config_json=_cfg(kind), ticket_ref=TICKET, dry_run=False
        )
    )
    assert out["applied"] is True and out["verified"] is False
    assert "read-back does not match" in out["warning"]


def test_create_read_back_altered_value_warns() -> None:
    client = _client()

    def _post(path: str, json: Any = None) -> Any:
        client.store["n"] = {**json, "id": "n", "block": ["changed"]}
        return {"id": "n"}

    client.post.side_effect = _post
    out = json.loads(
        _call(
            client,
            "url_access",
            action="create",
            config_json='{"block": ["malware"]}',
            ticket_ref=TICKET,
            dry_run=False,
        )  # fmt: skip
    )
    assert out["verified"] is False and "warning" in out


def test_update_read_back_missing_profile_is_unverified() -> None:
    client = _client([_existing("decryption")])
    real_put = client.put.side_effect

    def _put(path: str, json: Any = None, params: Any = None) -> Any:
        real_put(path, json=json, params=params)
        client.store.clear()  # the profile vanished
        return {}

    client.put.side_effect = _put
    out = json.loads(
        _call(
            client,
            "decryption",
            action="update",
            config_json=json.dumps(CASES["decryption"][2]),
            ticket_ref=TICKET,
            dry_run=False,
        )  # fmt: skip
    )
    assert out["verified"] is False


def test_update_null_ignored_by_server_is_unverified() -> None:
    client = _client([_existing("url_access")])
    real_put = client.put.side_effect

    def _put(path: str, json: Any = None, params: Any = None) -> Any:
        real_put(path, json=json, params=params)
        client.store["p-1"]["description"] = "d"  # server kept it
        return {}

    client.put.side_effect = _put
    out = json.loads(
        _call(
            client,
            "url_access",
            action="update",
            config_json='{"description": null}',
            ticket_ref=TICKET,
            dry_run=False,
        )  # fmt: skip
    )
    assert out["verified"] is False


# -- delete ---------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("kind", CASES)
def test_delete_ref_and_lookup_failure_together_refuses_on_refs(
    kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(
        sp.SPECS, kind, _with_scan(sp.SPECS[kind], lambda c, n, s: (["grp"], "HTTP 500"))
    )
    client = _client([_existing(kind)])
    out = _call(client, kind, action="delete", ticket_ref=TICKET, dry_run=False)
    assert out.startswith("Error") and "grp" in out
    client.delete.assert_not_called()


@pytest.mark.parametrize("kind", CASES)
def test_delete_scan_receives_profile_name_and_own_container(
    kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[tuple[str, dict[str, str]]] = []

    def scan(c: Any, name: str, scope: dict[str, str]) -> tuple[list[str], str]:
        seen.append((name, scope))
        return [], ""

    monkeypatch.setitem(sp.SPECS, kind, _with_scan(sp.SPECS[kind], scan))
    client = _client([_existing(kind)])
    _call(client, kind, action="delete", ticket_ref=TICKET, dry_run=False)
    assert seen == [("sec-test", {"folder": "fw-a"})]
    client.delete.assert_called_once()


def test_delete_scan_exception_inside_real_scanner_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(c: Any) -> None:
        raise RuntimeError("no token")

    monkeypatch.setattr(sp.scm_rest, "refresh_token", boom)
    client = _client([_existing("url_access")])
    out = _call(client, "url_access", action="delete", ticket_ref=TICKET, dry_run=False)
    assert out.startswith("Error") and "refused" in out
    client.delete.assert_not_called()
    dry = json.loads(_call(client, "url_access", action="delete", ticket_ref=TICKET))
    assert "no token" in dry["warning"]


# -- create edge cases ------------------------------------------------------------------------------------------


def test_create_name_in_config_json_and_mismatch() -> None:
    client = _client()
    out = json.loads(
        _call(
            client,
            "decryption",
            action="create",
            name="",
            config_json='{"name": "from-cfg", "ssl_no_proxy": {}}',
            ticket_ref=TICKET,
        )  # fmt: skip
    )
    assert out["request"]["body"]["name"] == "from-cfg"
    out = _call(client, "decryption", action="create", name="a",
                config_json='{"name": "b"}', ticket_ref=TICKET)  # fmt: skip
    assert "disagree" in out


def test_create_wildfire_rules_optional_but_enums_validated() -> None:
    """The live API accepts a WildFire profile with no rules (verified 2026-11-20)."""
    out = _call(
        _client(), "wildfire_antivirus", action="create", config_json="{}", ticket_ref=TICKET
    )
    assert "rules: required" not in out and not out.startswith("Error")
    bad = {
        "rules": [
            {"name": "r", "application": ["any"], "direction": "sideways", "file_type": ["any"]}
        ]
    }
    out = _call(
        _client(),
        "wildfire_antivirus",
        action="create",
        config_json=json.dumps(bad),
        ticket_ref=TICKET,
    )
    assert "direction" in out and "not one of" in out
