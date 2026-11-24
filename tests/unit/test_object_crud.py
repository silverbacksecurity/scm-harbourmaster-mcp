"""scm_object: schemas, member checks, cycle detection and the delete guard (mocked REST)."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.tools import object_crud as oc

TENANT = "1234567890"
TICKET = "CHG-TEST"
OBJ = "/config/objects/v1"


class Net:
    """Fake REST layer: an SDK-style client plus the paged ``_rows`` lookup."""

    def __init__(
        self,
        stored: list[dict[str, Any]] | None = None,
        lists: dict[str, list[dict[str, Any]]] | None = None,
        *,
        fail: set[str] | None = None,
    ) -> None:
        self.store = {o["id"]: dict(o) for o in (stored or [])}
        self.lists = lists or {}
        self.fail = fail or set()
        self.calls: list[tuple[str, dict[str, Any]]] = []
        client = MagicMock()

        def _get(path: str, params: dict[str, Any] | None = None) -> Any:
            params = params or {}
            if path.rsplit("/", 1)[-1] in self.store:
                return self.store[path.rsplit("/", 1)[-1]]
            hits = [
                o
                for o in self.store.values()
                if (not params.get("name") or o["name"] == params["name"])
            ]
            return {"data": hits, "total": len(hits)}

        def _put(path: str, json: Any = None, params: Any = None) -> Any:
            pid = path.rsplit("/", 1)[-1]
            self.store[pid] = {**json, "id": pid}
            return {"id": pid}

        def _post(path: str, json: Any = None) -> Any:
            self.store["new-1"] = {**json, "id": "new-1"}
            return {"id": "new-1"}

        client.get.side_effect = _get
        client.put.side_effect = _put
        client.post.side_effect = _post
        client.delete.side_effect = lambda path: {}
        self.client = client

    def rows(self, client: Any, url: str, params: dict[str, Any]) -> Any:
        key = url.split("/v1/", 1)[1]
        position = params.get("position")
        self.calls.append((f"{key}#{position}" if position else key, dict(params)))
        if any(f in key for f in self.fail):
            return [], "HTTP 500"
        return list(self.lists.get(f"{key}#{position}" if position else key, [])), ""


def _tool(net: Net, monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setattr(oc, "_rows", net.rows)
    mcp = FastMCP("test")
    oc.register_object_crud_tools(mcp, lambda tenant_id="": net.client)
    return mcp._tool_manager.get_tool("scm_object").fn


def _j(out: str) -> dict[str, Any]:
    return json.loads(out)


ADDRS = {"addresses": [{"name": "h1"}, {"name": "h2"}], "address-groups": []}


def _group(**over: Any) -> dict[str, Any]:
    return {"id": "g-1", "name": "grp", "folder": "fw-a", "static": ["h1"], **over}


def _create(fn: Any, kind: str, cfg: dict[str, Any], **kw: Any) -> str:
    return fn(
        kind=kind,
        action="create",
        folder="fw-a",
        name=kw.pop("name", "obj"),
        config_json=json.dumps(cfg),
        ticket_ref=TICKET,
        **kw,
    )


# -- validation -----------------------------------------------------------------------------


def test_unknown_kind_and_action(monkeypatch: pytest.MonkeyPatch) -> None:
    fn = _tool(Net(), monkeypatch)
    assert "unknown kind" in fn(kind="address")
    assert "unknown action" in fn(kind="tag", action="nope")


@pytest.mark.parametrize(
    ("kind", "cfg", "needle"),
    [
        ("tag", {"color": "Pink"}, "not one of"),
        ("tag", {"bogus": 1}, "unknown keys"),
        ("service", {}, "protocol: required"),
        ("service", {"protocol": {"tcp": {}}}, "port: required"),
        ("service", {"protocol": {"tcp": {"port": "80"}, "udp": {"port": "53"}}}, "exactly one"),
        (
            "service",
            {"protocol": {"tcp": {"port": "80", "override": {"timewait_timeout": 601}}}},
            "601",
        ),
        ("service_group", {}, "members: required"),
        ("service_group", {"members": "svc"}, "must be a list"),
        ("address_group", {"static": ["h1"], "folder": "x"}, "must not contain"),
    ],
)
def test_create_rejects_bad_config(
    monkeypatch: pytest.MonkeyPatch, kind: str, cfg: dict[str, Any], needle: str
) -> None:
    fn = _tool(Net(lists=ADDRS), monkeypatch)
    out = _create(fn, kind, cfg)
    assert out.startswith("Error") and needle in out


def test_address_group_needs_exactly_one_type(monkeypatch: pytest.MonkeyPatch) -> None:
    fn = _tool(Net(lists=ADDRS), monkeypatch)
    assert "exactly one of static or dynamic" in _create(fn, "address_group", {"description": "x"})
    both = {"static": ["h1"], "dynamic": {"filter": "'a'"}}
    assert "exactly one of static or dynamic" in _create(fn, "address_group", both)


def test_bad_name_pattern(monkeypatch: pytest.MonkeyPatch) -> None:
    fn = _tool(Net(lists=ADDRS), monkeypatch)
    out = _create(fn, "service", {"protocol": {"tcp": {"port": "1"}}}, name="bad/name")
    assert out.startswith("Error") and "does not match" in out


# -- create / update -------------------------------------------------------------------------


def test_create_dry_run_then_apply(monkeypatch: pytest.MonkeyPatch) -> None:
    net = Net(lists=ADDRS)
    fn = _tool(net, monkeypatch)
    dry = _j(_create(fn, "address_group", {"static": ["h1", "h2"]}))
    assert dry["dry_run"] and dry["request"]["path"] == f"{OBJ}/address-groups"
    assert dry["request"]["body"] == {"static": ["h1", "h2"], "name": "obj", "folder": "fw-a"}
    net.client.post.assert_not_called()
    out = _j(_create(fn, "address_group", {"static": ["h1", "h2"]}, dry_run=False))
    assert out["applied"] and out["verified"]
    net.client.post.assert_called_once()


def test_ticket_ref_mandatory(monkeypatch: pytest.MonkeyPatch) -> None:
    fn = _tool(Net(lists=ADDRS), monkeypatch)
    out = fn(kind="tag", action="create", folder="fw-a", name="t", config_json="{}")
    assert out.startswith("Error")


def test_tag_and_service_create(monkeypatch: pytest.MonkeyPatch) -> None:
    net = Net()
    fn = _tool(net, monkeypatch)
    assert _j(_create(fn, "tag", {"color": "Red", "comments": "c"}, dry_run=False))["verified"]
    svc = {"protocol": {"tcp": {"port": "80,443", "override": {"timeout": 60}}}}
    assert _j(_create(fn, "service", svc, name="web", dry_run=False))["applied"]


def test_create_existing(monkeypatch: pytest.MonkeyPatch) -> None:
    net = Net([{"id": "t-1", "name": "obj", "folder": "fw-a"}])
    out = _create(_tool(net, monkeypatch), "tag", {})
    assert out.startswith("Error") and "already exists" in out


def test_update_merges_and_refuses_rename(monkeypatch: pytest.MonkeyPatch) -> None:
    net = Net([_group(description="d")], ADDRS)
    fn = _tool(net, monkeypatch)
    out = fn(
        kind="address_group",
        action="update",
        folder="fw-a",
        name="grp",
        config_json='{"static": ["h1", "h2"]}',
        ticket_ref=TICKET,
        dry_run=False,
    )
    res = _j(out)
    assert res["applied"] and res["verified"]
    assert net.store["g-1"]["static"] == ["h1", "h2"] and net.store["g-1"]["description"] == "d"
    bad = fn(
        kind="address_group",
        action="update",
        folder="fw-a",
        name="grp",
        config_json='{"name": "renamed", "description": "x"}',
        ticket_ref=TICKET,
    )
    assert bad.startswith("Error") and "renaming" in bad


def test_update_cannot_switch_group_type_to_both(monkeypatch: pytest.MonkeyPatch) -> None:
    net = Net([_group()], ADDRS)
    out = _tool(net, monkeypatch)(
        kind="address_group",
        action="update",
        folder="fw-a",
        name="grp",
        config_json='{"dynamic": {"filter": "\'a\'"}}',
        ticket_ref=TICKET,
    )
    assert out.startswith("Error") and "exactly one of static or dynamic" in out


# -- members and cycles ----------------------------------------------------------------------


def test_missing_members_error_and_allow_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    fn = _tool(Net(lists=ADDRS), monkeypatch)
    out = _create(fn, "address_group", {"static": ["h1", "ghost"]})
    assert out.startswith("Error") and "ghost" in out
    ok = _j(
        _create(fn, "address_group", {"static": ["h1", "ghost"]}, allow_unresolved_members=True)
    )
    assert any("ghost" in w for w in ok["validation"]["warnings"])


def test_service_group_member_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    lists = {
        "services": [{"name": "web"}],
        "service-groups": [{"name": "other", "members": ["web"]}],
    }
    fn = _tool(Net(lists=lists), monkeypatch)
    assert _j(_create(fn, "service_group", {"members": ["web", "other"]}))["dry_run"]
    out = _create(fn, "service_group", {"members": ["nope"]})
    assert out.startswith("Error") and "nope" in out


def test_member_lookup_failure_is_a_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    fn = _tool(Net(lists=ADDRS, fail={"addresses"}), monkeypatch)
    out = _j(_create(fn, "address_group", {"static": ["h1"]}))
    assert any("could not check" in w for w in out["validation"]["warnings"])


def test_self_member_and_cycle_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    lists = {
        "addresses": [{"name": "h1"}],
        "address-groups": [
            {"name": "a", "static": ["b"]},
            {"name": "b", "static": ["c"]},
            {"name": "c", "static": ["h1"]},
        ],
    }
    fn = _tool(Net(lists=lists), monkeypatch)
    assert "lists itself" in _create(fn, "address_group", {"static": ["h1", "me"]}, name="me")
    out = _create(fn, "address_group", {"static": ["a"]}, name="c")
    assert out.startswith("Error") and "cycle: c -> a -> b -> c" in out


def test_duplicate_members_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    out = _create(_tool(Net(lists=ADDRS), monkeypatch), "address_group", {"static": ["h1", "h1"]})
    assert out.startswith("Error") and "more than once" in out


# -- delete guard ----------------------------------------------------------------------------


def _delete(fn: Any, kind: str, name: str, **kw: Any) -> str:
    return fn(kind=kind, action="delete", folder="fw-a", name=name, ticket_ref=TICKET, **kw)


def test_delete_clean_dry_run_and_apply(monkeypatch: pytest.MonkeyPatch) -> None:
    net = Net([_group()], {"security-rules#pre": [{"name": "r", "source": ["other"]}]})
    fn = _tool(net, monkeypatch)
    dry = _j(_delete(fn, "address_group", "grp"))
    assert dry["dry_run"] and dry["referenced_by"] == []
    assert "not scanned" in dry["reference_check"]
    out = _j(_delete(fn, "address_group", "grp", dry_run=False))
    assert out["applied"]
    net.client.delete.assert_called_once()


@pytest.mark.parametrize(
    ("kind", "stored", "lists", "needle"),
    [
        (
            "address_group",
            {"name": "grp"},
            {"security-rules#post": [{"name": "r1", "destination": ["grp"]}]},
            "security rule (post) r1",
        ),
        (
            "address_group",
            {"name": "grp"},
            {"address-groups": [{"name": "outer", "static": ["grp"]}]},
            "address group outer",
        ),
        (
            "address_group",
            {"name": "grp"},
            {
                "nat-rules#pre": [
                    {
                        "name": "n1",
                        "source_translation": {"static_ip": {"translated_address": "grp"}},
                    }
                ]
            },
            "NAT rule (pre) n1",
        ),
        (
            "service",
            {"name": "web"},
            {"service-groups": [{"name": "sg", "members": ["web"]}]},
            "service group sg",
        ),
        (
            "service",
            {"name": "web"},
            {"decryption-rules#pre": [{"name": "d1", "service": ["web"]}]},
            "decryption rule (pre) d1",
        ),
        (
            "tag",
            {"name": "prod"},
            {"address-groups": [{"name": "dyn", "dynamic": {"filter": "'prod' and not 'old'"}}]},
            "address group dyn",
        ),
        (
            "tag",
            {"name": "prod"},
            {"addresses": [{"name": "h1", "tag": ["prod"]}]},
            "address h1",
        ),
        (
            "tag",
            {"name": "prod"},
            {"app-override-rules#post": [{"name": "o1", "tag": ["prod"]}]},
            "app-override rule (post) o1",
        ),
    ],
)
def test_delete_refused_while_referenced(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    stored: dict[str, Any],
    lists: dict[str, list[dict[str, Any]]],
    needle: str,
) -> None:
    net = Net([{"id": "o-1", "folder": "fw-a", **stored}], lists)
    out = _delete(_tool(net, monkeypatch), kind, stored["name"], dry_run=False)
    assert out.startswith("Error") and "referenced by" in out and needle in out
    net.client.delete.assert_not_called()


def test_group_does_not_block_itself(monkeypatch: pytest.MonkeyPatch) -> None:
    net = Net([_group()], {"address-groups": [{"name": "grp", "static": ["grp"]}]})
    out = _j(_delete(_tool(net, monkeypatch), "address_group", "grp"))
    assert out["referenced_by"] == []


def test_delete_fails_closed_on_lookup_error(monkeypatch: pytest.MonkeyPatch) -> None:
    net = Net([_group()], fail={"nat-rules"})
    fn = _tool(net, monkeypatch)
    out = _delete(fn, "address_group", "grp", dry_run=False)
    assert out.startswith("Error") and "cannot confirm" in out
    net.client.delete.assert_not_called()
    assert "warning" in _j(_delete(fn, "address_group", "grp"))  # dry run still works


def test_top_level_folder_needs_acknowledgement(monkeypatch: pytest.MonkeyPatch) -> None:
    net = Net([{"id": "t-1", "name": "t", "folder": "All"}])
    fn = _tool(net, monkeypatch)
    call = {"kind": "tag", "action": "delete", "folder": "All", "name": "t", "ticket_ref": TICKET}
    refused = fn(**call, dry_run=False)
    assert refused.startswith("Error") and "acknowledge_unscanned_scope" in refused
    net.client.delete.assert_not_called()
    assert _j(fn(**call, dry_run=False, acknowledge_unscanned_scope=True))["applied"]


def test_tag_scan_covers_every_resource(monkeypatch: pytest.MonkeyPatch) -> None:
    net = Net([{"id": "t-1", "name": "t", "folder": "fw-a"}])
    _delete(_tool(net, monkeypatch), "tag", "t")
    scanned = {c[0] for c in net.calls}
    assert {"addresses", "services", "address-groups", "service-groups"} <= scanned
    for base in ("security-rules", "nat-rules", "decryption-rules", "app-override-rules"):
        assert {f"{base}#pre", f"{base}#post"} <= scanned


# -- list / get ------------------------------------------------------------------------------


def test_list_and_get(monkeypatch: pytest.MonkeyPatch) -> None:
    net = Net([_group(), _group(id="g-2", name="other")])
    fn = _tool(net, monkeypatch)
    listed = _j(fn(kind="address_group", folder="fw-a", name="oth"))
    assert listed["total"] == 1 and listed["items"][0]["name"] == "other"
    assert (
        _j(fn(kind="address_group", action="get", folder="fw-a", name="grp"))["item"]["id"] == "g-1"
    )
    assert fn(kind="tag", action="get", folder="fw-a", name="zz").startswith("Error")
    assert "needs one of folder" in fn(kind="tag")
