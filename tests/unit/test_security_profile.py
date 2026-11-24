"""scm_security_profile: every kind, every action (mocked REST, no network)."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.tools import security_profile as sp

TENANT = "1234567890"
TICKET = "CHG-TEST"

# kind -> (endpoint, valid create body, update delta, key checked after update)
CASES: dict[str, tuple[str, dict[str, Any], dict[str, Any]]] = {
    "wildfire_antivirus": (
        "/config/security/v1/wildfire-anti-virus-profiles",
        {
            "description": "d",
            "packet_capture": True,
            "rules": [
                {
                    "name": "r1",
                    "analysis": "public-cloud",
                    "application": ["any"],
                    "direction": "both",
                    "file_type": ["any"],
                }
            ],
        },
        {"packet_capture": False},
    ),
    "url_access": (
        "/config/security/v1/url-access-profiles",
        {
            "description": "d",
            "block": ["malware"],
            "continue": ["unknown"],
            "log_http_hdr_xff": True,
            "credential_enforcement": {"mode": {"disabled": {}}, "log_severity": "medium"},
        },
        {"alert": ["news"]},
    ),
    "decryption": (
        "/config/security/v1/decryption-profiles",
        {
            "ssl_forward_proxy": {"block_expired_certificate": True},
            "ssl_protocol_settings": {"min_version": "tls1-2", "max_version": "tls1-3"},
        },
        {"ssl_forward_proxy": {"block_unknown_cert": True}},
    ),
    "zone_protection": (
        "/config/network/v1/zone-protection-profiles",
        {
            "description": "d",
            "flood": {
                "tcp_syn": {"enable": True},
                "udp": {
                    "enable": True,
                    "red": {"alarm_rate": 10, "activate_rate": 20, "maximal_rate": 30},
                },
            },
            "scan": [
                {"name": "8001", "action": {"block_ip": {"track_by": "source", "duration": 60}}}
            ],
            "reject_non_syn_tcp": "global",
        },
        {"spoofed_ip_discard": True},
    ),
}


@pytest.fixture(autouse=True)
def _no_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sp.scm_rest, "refresh_token", lambda c: None)


def _tool(client: Any) -> Any:
    mcp = FastMCP("test")
    sp.register_security_profile_tools(mcp, lambda tenant_id="": client)
    return mcp._tool_manager.get_tool("scm_security_profile").fn


def _client(profiles: list[dict[str, Any]] | None = None, *, put_applies: bool = True) -> MagicMock:
    store = {p["id"]: dict(p) for p in (profiles or [])}
    client = MagicMock()

    def _get(path: str, params: dict[str, Any] | None = None) -> Any:
        if path.count("/") == 4:  # collection
            params = params or {}
            hits = [
                p for p in store.values() if not params.get("name") or p["name"] == params["name"]
            ]
            return {"data": hits, "total": len(hits)}
        return store.get(path.rsplit("/", 1)[-1], {})

    def _put(path: str, json: Any = None, params: Any = None) -> Any:
        pid = path.rsplit("/", 1)[-1]
        if put_applies:
            store[pid] = {**json, "id": pid}
        return {"id": pid}

    def _post(path: str, json: Any = None) -> Any:
        store["new-1"] = {**json, "id": "new-1"}
        return {"id": "new-1"}

    client.get.side_effect = _get
    client.put.side_effect = _put
    client.post.side_effect = _post
    client.store = store
    return client


def _existing(kind: str, **over: Any) -> dict[str, Any]:
    _, body, _ = CASES[kind]
    return {"id": "p-1", "name": "sec-test", "folder": "fw-a", **body, **over}


def _call(client: Any, kind: str, **kw: Any) -> str:
    args: dict[str, Any] = {"tenant_id": TENANT, "kind": kind, "folder": "fw-a", "name": "sec-test"}
    args.update(kw)
    return _tool(client)(**args)


# -- reads ---------------------------------------------------------------------


@pytest.mark.parametrize("kind", CASES)
def test_list_and_get(kind: str) -> None:
    client = _client([_existing(kind), _existing(kind, id="p-2", name="other")])
    out = json.loads(_tool(client)(tenant_id=TENANT, kind=kind, folder="fw-a", name="SEC"))
    assert out["total"] == 1
    assert out["items"][0]["name"] == "sec-test" and "id" in out["items"][0]
    assert client.get.call_args.args[0] == CASES[kind][0]
    by_id = json.loads(_tool(client)(tenant_id=TENANT, kind=kind, action="get", profile_id="p-2"))
    assert by_id["item"]["name"] == "other"
    by_name = json.loads(_call(client, kind, action="get"))
    assert by_name["item"]["id"] == "p-1"
    assert "not found" in _call(client, kind, action="get", name="zzz")


def test_list_needs_container_and_validates_inputs() -> None:
    client = _client()
    fn = _tool(client)
    assert "one of folder" in fn(tenant_id=TENANT, kind="decryption")
    assert "only one of" in fn(tenant_id=TENANT, kind="decryption", folder="a", snippet="b")
    assert "unknown kind" in fn(tenant_id=TENANT, kind="nope")
    assert "unknown action" in fn(tenant_id=TENANT, kind="decryption", action="zap")


def test_antivirus_alias_is_the_wildfire_endpoint() -> None:
    client = _client([_existing("wildfire_antivirus")])
    out = json.loads(_tool(client)(tenant_id=TENANT, kind="antivirus", folder="fw-a"))
    assert out["kind"] == "wildfire_antivirus" and out["total"] == 1
    assert client.get.call_args.args[0] == CASES["wildfire_antivirus"][0]


# -- create --------------------------------------------------------------------


@pytest.mark.parametrize("kind", CASES)
def test_create_dry_run_then_real(kind: str) -> None:
    path, body, _ = CASES[kind]
    client = _client()
    out = json.loads(
        _call(client, kind, action="create", config_json=json.dumps(body), ticket_ref=TICKET)
    )
    assert out["dry_run"] is True and out["ticket_ref"] == TICKET
    assert out["request"] == {
        "method": "POST",
        "path": path,
        "body": {**body, "name": "sec-test", "folder": "fw-a"},
    }
    client.post.assert_not_called()

    real = json.loads(
        _call(
            client,
            kind,
            action="create",
            config_json=json.dumps(body),
            ticket_ref=TICKET,
            dry_run=False,
        )
    )
    assert real["applied"] is True and real["verified"] is True
    sent = client.post.call_args.kwargs["json"]
    assert "ticket_ref" not in sent and sent["folder"] == "fw-a"
    assert client.post.call_args.args[0] == path


def test_url_access_continue_survives_raw_write() -> None:
    """The SDK drops ``continue``; the raw path must carry it."""
    client = _client()
    cfg = {"continue": ["unknown"]}
    _call(
        client,
        "url_access",
        action="create",
        config_json=json.dumps(cfg),
        ticket_ref=TICKET,
        dry_run=False,
    )
    assert client.post.call_args.kwargs["json"]["continue"] == ["unknown"]


@pytest.mark.parametrize("kind", CASES)
def test_create_requires_ticket_ref_even_for_dry_run(kind: str) -> None:
    client = _client()
    out = _call(client, kind, action="create", config_json=json.dumps(CASES[kind][1]))
    assert "ticket_ref is mandatory" in out
    client.post.assert_not_called()


def test_create_refuses_existing_and_missing_scope() -> None:
    client = _client([_existing("decryption")])
    cfg = json.dumps(CASES["decryption"][1])
    assert "already exists" in _call(
        client, "decryption", action="create", config_json=cfg, ticket_ref=TICKET
    )
    assert "needs one of folder" in _tool(client)(
        tenant_id=TENANT,
        kind="decryption",
        action="create",
        name="n",
        config_json=cfg,
        ticket_ref=TICKET,
    )


def test_create_reports_all_problems_at_once() -> None:
    client = _client()
    cfg = {
        "rules": [
            {"name": "r", "application": ["any"], "direction": "sideways", "file_type": ["any"]}
        ],
        "bogus": 1,
        "packet_capture": "yes",
        "folder": "x",
    }
    out = _call(
        client,
        "wildfire_antivirus",
        action="create",
        config_json=json.dumps(cfg),
        ticket_ref=TICKET,
        dry_run=False,
    )
    assert out.startswith("Error")
    for needle in ("sideways", "bogus", "packet_capture", "folder"):
        assert needle in out
    client.post.assert_not_called()


@pytest.mark.parametrize(
    ("kind", "cfg", "needle"),
    [
        ("wildfire_antivirus", {"rules": [{"name": "r"}]}, "application: required"),
        ("url_access", {"description": "x" * 256}, "longer than 255"),
        (
            "url_access",
            {"credential_enforcement": {"mode": {"ip_user": {}, "disabled": {}}}},
            "exactly one",
        ),
        ("decryption", {"ssl_protocol_settings": {"min_version": "tls9"}}, "not one of"),
        ("decryption", {"ssl_no_proxy": {"nope": True}}, "unknown keys"),
        ("zone_protection", {"scan": [{"name": "1234"}]}, "not one of"),
        ("zone_protection", {"flood": {"udp": {"red": {"alarm_rate": 5}}}}, "required"),
        (
            "zone_protection",
            {
                "flood": {
                    "icmp": {"red": {"alarm_rate": 9999999, "activate_rate": 1, "maximal_rate": 1}}
                }
            },
            "outside",
        ),
        ("zone_protection", {"reject_non_syn_tcp": True}, "must be a string"),
        (
            "zone_protection",
            {"scan": [{"name": "8001", "action": {"block_ip": {"track_by": "source"}}}]},
            "duration: required",
        ),
        ("zone_protection", {"scan": [{"name": "8001", "interval": 1}]}, "outside 2..65535"),
        ("decryption", {"ssl_no_proxy": None}, "only allowed on update"),
    ],
)
def test_schema_rejections(kind: str, cfg: dict[str, Any], needle: str) -> None:
    out = _call(_client(), kind, action="create", config_json=json.dumps(cfg), ticket_ref=TICKET)
    assert out.startswith("Error") and needle in out


@pytest.mark.parametrize(
    ("kind", "name", "needle"),
    [
        ("wildfire_antivirus", "has space", "does not match"),
        ("decryption", "-lead", "does not match"),
        ("zone_protection", "n" * 32, "longer than 31"),
    ],
)
def test_name_rules(kind: str, name: str, needle: str) -> None:
    out = _call(
        _client(),
        kind,
        action="create",
        name=name,
        config_json=json.dumps(CASES[kind][1]),
        ticket_ref=TICKET,
    )
    assert needle in out


def test_bad_json_is_reported() -> None:
    assert "not valid JSON" in _call(
        _client(), "decryption", action="create", config_json="{", ticket_ref=TICKET
    )
    assert "JSON object" in _call(
        _client(), "decryption", action="create", config_json="[]", ticket_ref=TICKET
    )


# -- update --------------------------------------------------------------------


@pytest.mark.parametrize("kind", CASES)
def test_update_merges_preserves_and_verifies(kind: str) -> None:
    _, body, delta = CASES[kind]
    client = _client([_existing(kind)])
    dry = json.loads(
        _call(client, kind, action="update", config_json=json.dumps(delta), ticket_ref=TICKET)
    )
    assert dry["dry_run"] is True and dry["request"]["method"] == "PUT"
    client.put.assert_not_called()
    sent_dry = dry["request"]["body"]
    assert "id" not in sent_dry and sent_dry["folder"] == "fw-a"
    for key in body:  # unspecified fields are preserved
        if key not in delta:
            assert key in sent_dry

    real = json.loads(
        _call(
            client,
            kind,
            action="update",
            config_json=json.dumps(delta),
            ticket_ref=TICKET,
            dry_run=False,
        )
    )
    assert real["applied"] is True and real["verified"] is True
    assert client.put.call_args.args[0] == f"{CASES[kind][0]}/p-1"
    sent = client.put.call_args.kwargs["json"]
    assert "ticket_ref" not in sent
    for key, value in delta.items():
        assert sent[key] == value or isinstance(value, dict)


def test_update_deep_merges_objects_and_replaces_lists_and_oneofs() -> None:
    cur = _existing(
        "zone_protection",
        flood={
            "udp": {"enable": True, "red": {"alarm_rate": 1, "activate_rate": 2, "maximal_rate": 3}}
        },
        scan=[{"name": "8001", "action": {"alert": {}}}],
    )
    client = _client([cur])
    delta = {
        "flood": {"icmp": {"enable": True}},
        "scan": [{"name": "8002", "action": {"block": {}}}],
    }
    out = json.loads(
        _call(
            client,
            "zone_protection",
            action="update",
            config_json=json.dumps(delta),
            ticket_ref=TICKET,
        )
    )
    body = out["request"]["body"]
    assert body["flood"]["udp"]["enable"] is True and body["flood"]["icmp"] == {"enable": True}
    assert body["scan"] == delta["scan"]

    cur = _existing(
        "url_access", credential_enforcement={"mode": {"ip_user": {}}, "log_severity": "low"}
    )
    client = _client([cur])
    delta = {"credential_enforcement": {"mode": {"disabled": {}}}}
    out = json.loads(
        _call(
            client,
            "url_access",
            action="update",
            config_json=json.dumps(delta),
            ticket_ref=TICKET,
            skip_category_check=True,
        )
    )
    assert out["request"]["body"]["credential_enforcement"] == {
        "mode": {"disabled": {}},
        "log_severity": "low",
    }


def test_update_null_removes_key_and_is_verified() -> None:
    client = _client([_existing("url_access")])
    out = json.loads(
        _call(
            client,
            "url_access",
            action="update",
            config_json='{"description": null}',
            ticket_ref=TICKET,
            dry_run=False,
        )
    )
    assert "description" not in client.put.call_args.kwargs["json"]
    assert out["diff"]["removed"] == ["description"] and out["verified"] is True


def test_update_strips_response_only_fields() -> None:
    client = _client(
        [_existing("wildfire_antivirus", override_loc="x", override_type="y", override_id="z")]
    )
    out = json.loads(
        _call(
            client,
            "wildfire_antivirus",
            action="update",
            config_json='{"description": "n"}',
            ticket_ref=TICKET,
        )
    )
    body = out["request"]["body"]
    assert not {"override_loc", "override_type", "override_id", "id"} & set(body)


def test_silent_noop_put_reports_unverified() -> None:
    client = _client([_existing("decryption")], put_applies=False)
    cfg = json.dumps(CASES["decryption"][2])
    out = json.loads(
        _call(
            client, "decryption", action="update", config_json=cfg, ticket_ref=TICKET, dry_run=False
        )
    )
    assert out["verified"] is False and "warning" in out


def test_update_rejections() -> None:
    client = _client([_existing("decryption")])
    assert "nothing to change" in _call(
        client, "decryption", action="update", config_json="{}", ticket_ref=TICKET
    )
    assert "renaming" in _call(
        client, "decryption", action="update", config_json='{"name": "other"}', ticket_ref=TICKET
    )
    assert "unknown keys" in _call(
        client, "decryption", action="update", config_json='{"zzz": 1}', ticket_ref=TICKET
    )
    assert "not found" in _call(
        _client(),
        "decryption",
        action="update",
        config_json='{"ssl_no_proxy": {}}',
        ticket_ref=TICKET,
    )
    assert "ticket_ref is mandatory" in _call(
        client, "decryption", action="update", config_json='{"ssl_no_proxy": {}}'
    )
    client.put.assert_not_called()


def test_url_category_warning_is_non_blocking(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = {
        sp._URL_CATEGORIES_URL: [{"value": "malware"}, {"value": "news"}],
        sp._CUSTOM_URL_CATEGORIES_URL: [{"name": "my-cat"}],
    }
    monkeypatch.setattr(sp.clone_preflight, "list_rows", lambda s, url, folder: (rows[url], ""))
    monkeypatch.setattr(sp.scm_rest, "bearer_session", lambda c: MagicMock())
    client = _client()
    cfg = json.dumps({"block": ["malware", "my-cat", "no-such-cat"]})
    out = json.loads(
        _call(client, "url_access", action="create", config_json=cfg, ticket_ref=TICKET)
    )
    assert "no-such-cat" in out["validation"]["warnings"][0]
    assert "malware" not in out["validation"]["warnings"][0]
    ok = json.loads(
        _call(
            client,
            "url_access",
            action="create",
            config_json='{"block": ["news"]}',
            ticket_ref=TICKET,
        )
    )
    assert ok["validation"]["warnings"] == []

    monkeypatch.setattr(sp.clone_preflight, "list_rows", lambda s, url, folder: ([], "HTTP 500"))
    failed = json.loads(
        _call(client, "url_access", action="create", config_json=cfg, ticket_ref=TICKET)
    )
    assert "skipped" in failed["validation"]["warnings"][0]


# -- delete --------------------------------------------------------------------


@pytest.mark.parametrize("kind", CASES)
def test_delete_dry_run_and_real(kind: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sp.SPECS, kind, _with_scan(sp.SPECS[kind], lambda c, n, s: ([], "")))
    client = _client([_existing(kind)])
    dry = json.loads(_call(client, kind, action="delete", ticket_ref=TICKET))
    assert dry["dry_run"] is True and dry["referenced_by"] == []
    assert dry["reference_check"]
    client.delete.assert_not_called()
    real = json.loads(_call(client, kind, action="delete", ticket_ref=TICKET, dry_run=False))
    assert real["applied"] is True
    client.delete.assert_called_once_with(f"{CASES[kind][0]}/p-1")


def _with_scan(spec: sp.Spec, scan: Any) -> sp.Spec:
    from dataclasses import replace

    return replace(spec, ref_scan=scan)


@pytest.mark.parametrize("kind", CASES)
def test_delete_refused_when_referenced(kind: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sp.SPECS, kind, _with_scan(sp.SPECS[kind], lambda c, n, s: (["grp-a"], "")))
    client = _client([_existing(kind)])
    for dry in (True, False):
        out = _call(client, kind, action="delete", ticket_ref=TICKET, dry_run=dry)
        assert out.startswith("Error") and "grp-a" in out and "same container" in out
    client.delete.assert_not_called()


@pytest.mark.parametrize("kind", CASES)
def test_delete_refused_on_lookup_error_unless_dry_run(
    kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(
        sp.SPECS, kind, _with_scan(sp.SPECS[kind], lambda c, n, s: ([], "HTTP 403"))
    )
    client = _client([_existing(kind)])
    out = _call(client, kind, action="delete", ticket_ref=TICKET, dry_run=False)
    assert out.startswith("Error") and "refused" in out and "HTTP 403" in out
    client.delete.assert_not_called()
    dry = json.loads(_call(client, kind, action="delete", ticket_ref=TICKET))
    assert dry["warning"] == "HTTP 403"


@pytest.mark.parametrize("kind", CASES)
def test_delete_requires_ticket_ref(kind: str) -> None:
    client = _client([_existing(kind)])
    assert "ticket_ref is mandatory" in _call(client, kind, action="delete")
    client.delete.assert_not_called()


# -- reference scanners (real code, fake session) ---------------------------------


def _session(pages: dict[tuple[str, str], list[dict[str, Any]]], status: int = 200) -> MagicMock:
    session = MagicMock()

    def _get(url: str, params: dict[str, Any] | None = None, timeout: Any = None) -> Any:
        resp = MagicMock(status_code=status)
        resp.json.return_value = {"data": pages.get((url, (params or {}).get("position", "")), [])}
        return resp

    session.get.side_effect = _get
    return session


def _patch_session(monkeypatch: pytest.MonkeyPatch, session: Any) -> None:
    monkeypatch.setattr(sp.scm_rest, "bearer_session", lambda c: session)


def test_group_scan_wildfire_and_url(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [
        {"name": "g1", "virus_and_wildfire_analysis": ["p"], "url_filtering": ["x"]},
        {"name": "g2", "virus_and_wildfire_analysis": "p"},
        {"name": "g3", "url_filtering": ["p"]},
    ]
    session = _session({(sp._PROFILE_GROUPS_URL, ""): rows})
    _patch_session(monkeypatch, session)
    assert sp.SPECS["wildfire_antivirus"].ref_scan(MagicMock(), "p", {"folder": "f"}) == (
        ["g1", "g2"],
        "",
    )
    assert sp.SPECS["url_access"].ref_scan(MagicMock(), "p", {"folder": "f"}) == (["g3"], "")
    assert session.get.call_args.kwargs["params"]["folder"] == "f"


def test_decryption_scan_covers_both_rulebases(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _session(
        {
            (sp._DECRYPTION_RULES_URL, "pre"): [
                {"name": "r1", "profile": "p"},
                {"name": "r2", "profile": "q"},
            ],
            (sp._DECRYPTION_RULES_URL, "post"): [{"name": "r3", "profile": "p"}],
        }
    )
    _patch_session(monkeypatch, session)
    refs, err = sp.SPECS["decryption"].ref_scan(MagicMock(), "p", {"folder": "f"})
    assert refs == ["r1 (pre)", "r3 (post)"] and err == ""
    assert {c.kwargs["params"]["position"] for c in session.get.call_args_list} == {"pre", "post"}


def test_zone_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [
        {"name": "z1", "network": {"zone_protection_profile": "p"}},
        {"name": "z2", "network": {"zone_protection_profile": "q"}},
        {"name": "z3"},
    ]
    _patch_session(monkeypatch, _session({(sp._ZONES_URL, ""): rows}))
    assert sp.SPECS["zone_protection"].ref_scan(MagicMock(), "p", {"folder": "f"}) == (["z1"], "")


@pytest.mark.parametrize("kind", CASES)
def test_scan_reports_http_failure(kind: str, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_session(monkeypatch, _session({}, status=403))
    refs, err = sp.SPECS[kind].ref_scan(MagicMock(), "p", {"folder": "f"})
    assert refs == [] and "403" in err


def test_scan_reports_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    session = MagicMock()
    session.get.side_effect = RuntimeError("boom")
    _patch_session(monkeypatch, session)
    refs, err = sp.SPECS["zone_protection"].ref_scan(MagicMock(), "p", {"folder": "f"})
    assert refs == [] and "boom" in err


def test_every_spec_has_a_schema_name_and_scan() -> None:
    for kind, spec in sp.SPECS.items():
        assert spec.kind == kind and "name" in spec.schema and callable(spec.ref_scan)
        assert spec.path.startswith("/config/") and spec.ref_scope
