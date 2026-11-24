"""scm_profile_group review fixes: inherited-scope delete gate, folder-only alias,
snippet/device member warnings, real-container echo, empty member lists."""

from __future__ import annotations

import json
from typing import Any

import pytest

from tests.unit.test_profile_group import (
    BASE,
    PROFILES,
    TICKET,
    Net,
    _group,
    _json,
    _tool,
)

RULE_HIT = {"pre": [{"name": "r-child", "profile_setting": {"group": ["grp"]}}], "post": []}
EMPTY = {"pre": [], "post": []}


def _rule_queries(net: Net) -> list[dict[str, Any]]:
    return [p for u, p in net.session_calls if u.endswith("/security-rules")]


def test_delete_scans_child_folders_for_top_level_folder(monkeypatch: pytest.MonkeyPatch) -> None:
    net = Net([_group(folder="Shared")], PROFILES, EMPTY)
    fn = _tool(net, monkeypatch)
    out = _json(fn(action="delete", folder="Shared", name="grp", ticket_ref=TICKET))
    folders = {q["folder"] for q in _rule_queries(net)}
    assert folders == {"Prisma Access", "Mobile Users", "Remote Networks"}
    assert "unscanned_scope_warning" in out and "acknowledge_unscanned_scope" in out["would_refuse"]


def test_delete_blocked_by_rule_in_child_folder(monkeypatch: pytest.MonkeyPatch) -> None:
    class ChildNet(Net):
        def paged(self, client: Any, url: str, params: dict[str, Any], extract: Any) -> Any:
            if url.endswith("/security-rules") and params["folder"] != "Mobile Users":
                self.session_calls.append((url, dict(params)))
                return [], ""
            return super().paged(client, url, params, extract)

    net = ChildNet([_group(folder="All")], PROFILES, RULE_HIT)
    fn = _tool(net, monkeypatch)
    out = fn(action="delete", folder="All", name="grp", dry_run=False, ticket_ref=TICKET)
    assert out.startswith("Error") and "r-child (pre in Mobile Users)" in out
    net.client.delete.assert_not_called()


@pytest.mark.parametrize("container", [{"folder": "All"}, {"snippet": "snip"}])
def test_real_delete_needs_acknowledgement(
    monkeypatch: pytest.MonkeyPatch, container: dict[str, str]
) -> None:
    grp = {k: v for k, v in _group().items() if k != "folder"}
    net = Net([{**grp, **container}], PROFILES, EMPTY)
    fn = _tool(net, monkeypatch)
    kw: dict[str, Any] = {**container, "name": "grp", "ticket_ref": TICKET, "action": "delete"}
    out = fn(dry_run=False, **kw)
    assert out.startswith("Error: delete refused") and "acknowledge_unscanned_scope" in out
    net.client.delete.assert_not_called()
    done = _json(fn(dry_run=False, acknowledge_unscanned_scope=True, **kw))
    assert done["applied"] is True
    net.client.delete.assert_called_once_with(f"{BASE}/g-1")


def test_plain_folder_delete_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    net = Net([_group()], PROFILES, EMPTY)
    fn = _tool(net, monkeypatch)
    dry = _json(fn(action="delete", folder="fw-a", name="grp", ticket_ref=TICKET))
    assert "would_refuse" not in dry and "unscanned_scope_warning" not in dry
    assert {q["folder"] for q in _rule_queries(net)} == {"fw-a"}


def test_refs_checked_before_lookup_error_before_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    net = Net([_group(folder="All")], PROFILES, RULE_HIT)
    fn = _tool(net, monkeypatch)
    assert "used by security rule" in fn(
        action="delete", folder="All", name="grp", dry_run=False, ticket_ref=TICKET
    )
    net = Net([_group(folder="All")], PROFILES, EMPTY, fail={"security-rules"})
    fn = _tool(net, monkeypatch)
    assert fn(
        action="delete", folder="All", name="grp", dry_run=False, ticket_ref=TICKET
    ).startswith("Error: cannot confirm")


def test_only_folder_is_aliased(monkeypatch: pytest.MonkeyPatch) -> None:
    net = Net([_group(folder=None, snippet="Shared")], PROFILES, EMPTY)
    fn = _tool(net, monkeypatch)
    assert _json(fn(snippet="Shared"))["scope"] == {"snippet": "Shared"}
    assert _json(fn(folder="Shared"))["scope"] == {"folder": "Prisma Access"}
    fn(action="delete", snippet="Shared", name="grp", ticket_ref=TICKET)
    assert all("folder" not in q for q in _rule_queries(net))
    assert _rule_queries(net)[0]["snippet"] == "Shared"
    create = _json(
        fn(
            action="create",
            folder="Shared",
            name="new",
            config_json=json.dumps({"spyware": ["spy-1"]}),
            ticket_ref=TICKET,
        )
    )
    assert create["request"]["body"]["folder"] == "Prisma Access"


def test_snippet_member_not_found_is_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    net = Net(profiles=PROFILES)
    fn = _tool(net, monkeypatch)
    cfg = json.dumps({"spyware": ["inherited-one"]})
    out = _json(fn(action="create", snippet="s1", name="n", config_json=cfg, ticket_ref=TICKET))
    assert out["validation"]["ok"] is True
    assert any(
        "inherited-one" in w and "inherited profiles" in w for w in out["validation"]["warnings"]
    )
    folder = fn(action="create", folder="fw-a", name="n", config_json=cfg, ticket_ref=TICKET)
    assert folder.startswith("Error: member profiles not found")


def test_update_echoes_inherited_parent_container(monkeypatch: pytest.MonkeyPatch) -> None:
    net = Net([_group(folder="parent")], PROFILES)
    fn = _tool(net, monkeypatch)
    cfg = json.dumps({"spyware": ["spy-2"]})
    kw: dict[str, Any] = {
        "action": "update",
        "folder": "child",
        "name": "grp",
        "config_json": cfg,
        "ticket_ref": TICKET,
    }
    dry = _json(fn(**kw))
    assert dry["container"] == {"folder": "parent"} and "inherited" in dry["container_warning"]
    done = _json(fn(dry_run=False, **kw))
    assert done["container"] == {"folder": "parent"} and "container_warning" in done


def test_delete_echoes_inherited_parent_container(monkeypatch: pytest.MonkeyPatch) -> None:
    net = Net([_group(folder="parent")], PROFILES, EMPTY)
    fn = _tool(net, monkeypatch)
    dry = _json(fn(action="delete", folder="child", name="grp", ticket_ref=TICKET))
    assert dry["container"] == {"folder": "parent"} and "container_warning" in dry
    same = _json(fn(action="delete", folder="parent", name="grp", ticket_ref=TICKET))
    assert "container_warning" not in same


def test_empty_member_list_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    net = Net([_group()], PROFILES)
    fn = _tool(net, monkeypatch)
    out = fn(
        action="update",
        folder="fw-a",
        name="grp",
        config_json=json.dumps({"spyware": []}),
        ticket_ref=TICKET,
    )
    assert out.startswith("Error") and "empty list" in out and "null" in out
    net.client.put.assert_not_called()
    # null removes the type
    ok = _json(
        fn(
            action="update",
            folder="fw-a",
            name="grp",
            config_json=json.dumps({"spyware": None}),
            ticket_ref=TICKET,
        )
    )
    assert "spyware" not in ok["request"]["body"]
