"""scm_profile_group: CRUD, member validation, rule-reference delete scan (mocked REST)."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.tools import profile_group as pg

TENANT = "1234567890"
TICKET = "CHG-TEST"
BASE = "/config/security/v1/profile-groups"


class Net:
    """Fake REST layer: the paged-names lookup plus an SDK-style client."""

    def __init__(
        self,
        groups: list[dict[str, Any]] | None = None,
        profiles: dict[str, list[str]] | None = None,
        rules: dict[str, list[dict[str, Any]]] | None = None,
        *,
        fail: set[str] | None = None,
        put_applies: bool = True,
    ) -> None:
        self.store = {g["id"]: dict(g) for g in (groups or [])}
        self.profiles = profiles if profiles is not None else {}
        self.rules = rules or {}
        self.fail = fail or set()
        self.session_calls: list[tuple[str, dict[str, Any]]] = []
        client = MagicMock()

        def _get(path: str, params: dict[str, Any] | None = None) -> Any:
            if path == BASE:
                params = params or {}
                hits = [
                    g
                    for g in self.store.values()
                    if not params.get("name") or g["name"] == params["name"]
                ]
                return {"data": hits, "total": len(hits)}
            return self.store.get(path.rsplit("/", 1)[-1], {})

        def _put(path: str, json: Any = None, params: Any = None) -> Any:
            pid = path.rsplit("/", 1)[-1]
            if put_applies:
                self.store[pid] = {**json, "id": pid}
            return {"id": pid}

        def _post(path: str, json: Any = None) -> Any:
            self.store["new-1"] = {**json, "id": "new-1"}
            return {"id": "new-1"}

        client.get.side_effect = _get
        client.put.side_effect = _put
        client.post.side_effect = _post
        self.client = client

    def paged(self, client: Any, url: str, params: dict[str, Any], extract: Any) -> Any:
        self.session_calls.append((url, dict(params)))
        if any(key in url for key in self.fail):
            return [], "HTTP 500"
        if url.endswith("/security-rules"):
            rows = self.rules.get(params["position"], [])
        else:
            rows = [{"name": n} for n in self.profiles.get(url.rsplit("/", 1)[-1], [])]
        names: list[str] = []
        for row in rows:
            names.extend(extract(row))
        return sorted(set(names)), ""


def _tool(net: Net, monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setattr(pg, "_paged_names", net.paged)
    mcp = FastMCP("test")
    pg.register_profile_group_tools(mcp, lambda tenant_id="": net.client)
    return mcp._tool_manager.get_tool("scm_profile_group").fn


def _group(**over: Any) -> dict[str, Any]:
    return {
        "id": "g-1",
        "name": "grp",
        "folder": "fw-a",
        "spyware": ["spy-1"],
        "file_blocking": ["fb-1"],
        **over,
    }


PROFILES = {
    "anti-spyware-profiles": ["spy-1", "spy-2"],
    "file-blocking-profiles": ["fb-1"],
    "vulnerability-protection-profiles": ["vul-1"],
}


def _json(out: str) -> dict[str, Any]:
    return json.loads(out)


def test_list_and_get(monkeypatch: pytest.MonkeyPatch) -> None:
    net = Net([_group(), _group(id="g-2", name="other")])
    fn = _tool(net, monkeypatch)
    listed = _json(fn(folder="fw-a", name="oth"))
    assert listed["total"] == 1 and listed["items"][0]["name"] == "other"
    assert _json(fn(action="get", folder="fw-a", name="grp"))["item"]["id"] == "g-1"
    assert "not found" in fn(action="get", folder="fw-a", name="nope")
    assert "needs one of folder" in fn()


def test_create_dry_run_validates_members(monkeypatch: pytest.MonkeyPatch) -> None:
    net = Net(profiles=PROFILES)
    fn = _tool(net, monkeypatch)
    cfg = json.dumps({"spyware": ["spy-1"], "vulnerability": ["vul-1"]})
    out = _json(fn(action="create", folder="fw-a", name="new", config_json=cfg, ticket_ref=TICKET))
    assert out["dry_run"] is True
    assert out["request"]["body"] == {
        "spyware": ["spy-1"],
        "vulnerability": ["vul-1"],
        "name": "new",
        "folder": "fw-a",
    }
    assert out["validation"]["ok"] is True
    net.client.post.assert_not_called()
    # one list call per member type used, from the group's own container
    assert {u.rsplit("/", 1)[-1] for u, _ in net.session_calls} == {
        "anti-spyware-profiles",
        "vulnerability-protection-profiles",
    }
    assert all(p == {"folder": "fw-a"} for _, p in net.session_calls)


def test_create_missing_member_is_error_then_overridable(monkeypatch: pytest.MonkeyPatch) -> None:
    fn = _tool(Net(profiles=PROFILES), monkeypatch)
    cfg = json.dumps({"spyware": ["ghost"], "file_blocking": ["fb-1"]})
    out = fn(action="create", folder="fw-a", name="new", config_json=cfg, ticket_ref=TICKET)
    assert out.startswith("Error: member profiles not found")
    assert "spyware" in out and "ghost" in out
    ok = _json(
        fn(
            action="create",
            folder="fw-a",
            name="new",
            config_json=cfg,
            ticket_ref=TICKET,
            allow_unresolved_members=True,
        )
    )
    assert ok["validation"]["ok"] is True
    assert any("ghost" in w for w in ok["validation"]["warnings"])


def test_predefined_name_and_unverifiable_are_warnings(monkeypatch: pytest.MonkeyPatch) -> None:
    net = Net(profiles={"anti-spyware-profiles": []}, fail={"file-blocking"})
    fn = _tool(net, monkeypatch)
    cfg = json.dumps(
        {"spyware": ["best-practice"], "file_blocking": ["fb-1"], "saas_security": ["s"]}
    )
    out = _json(fn(action="create", folder="fw-a", name="n", config_json=cfg, ticket_ref=TICKET))
    warns = " | ".join(out["validation"]["warnings"])
    assert "predefined" in warns
    assert "could not list" in warns
    assert "saas_security" in warns and "no list API" in warns
    assert out["validation"]["ok"] is True


def test_shared_folder_is_aliased_for_lookups(monkeypatch: pytest.MonkeyPatch) -> None:
    net = Net(profiles=PROFILES)
    fn = _tool(net, monkeypatch)
    fn(
        action="create",
        folder="Shared",
        name="n",
        config_json=json.dumps({"spyware": ["spy-1"]}),
        ticket_ref=TICKET,
    )
    assert net.session_calls[0][1] == {"folder": "Prisma Access"}


@pytest.mark.parametrize(
    "cfg, expect",
    [
        ("", "config_json is required"),
        ("[]", "must be a JSON object"),
        ('{"bogus": ["x"]}', "unknown keys"),
        ('{"spyware": "x"}', "must be a list"),
        ('{"spyware": [""]}', "does not match"),
        ('{"spyware": ["a", "a"]}', "at most one profile"),
        ('{"vulnerability": ["a", "b"]}', "at most one profile"),
        ('{"folder": "x", "spyware": ["a"]}', "must not contain"),
        ('{"spyware": null}', "null is only allowed on update"),
    ],
)
def test_create_rejects_bad_config(monkeypatch: pytest.MonkeyPatch, cfg: str, expect: str) -> None:
    fn = _tool(Net(profiles=PROFILES), monkeypatch)
    out = fn(action="create", folder="fw-a", name="n", config_json=cfg, ticket_ref=TICKET)
    assert out.startswith("Error") and expect in out


def test_create_existing_and_no_container(monkeypatch: pytest.MonkeyPatch) -> None:
    fn = _tool(Net([_group()], PROFILES), monkeypatch)
    cfg = json.dumps({"spyware": ["spy-1"]})
    assert "already exists" in fn(
        action="create", folder="fw-a", name="grp", config_json=cfg, ticket_ref=TICKET
    )
    assert "needs one of folder" in fn(
        action="create", name="x", config_json=cfg, ticket_ref=TICKET
    )


def test_create_apply_verifies(monkeypatch: pytest.MonkeyPatch) -> None:
    net = Net(profiles=PROFILES)
    fn = _tool(net, monkeypatch)
    out = _json(
        fn(
            action="create",
            folder="fw-a",
            name="new",
            config_json=json.dumps({"spyware": ["spy-1"]}),
            dry_run=False,
            ticket_ref=TICKET,
        )
    )
    assert out["applied"] is True and out["verified"] is True
    body = net.client.post.call_args.kwargs["json"]
    assert body["folder"] == "fw-a" and TICKET not in json.dumps(body)


def test_update_merges_and_preserves(monkeypatch: pytest.MonkeyPatch) -> None:
    net = Net([_group()], PROFILES)
    fn = _tool(net, monkeypatch)
    cfg = json.dumps({"vulnerability": ["vul-1"], "spyware": ["spy-2"]})
    out = _json(
        fn(
            action="update",
            folder="fw-a",
            name="grp",
            config_json=cfg,
            dry_run=False,
            ticket_ref=TICKET,
        )
    )
    assert out["verified"] is True
    put = net.client.put.call_args
    assert put.args[0] == f"{BASE}/g-1"
    body = put.kwargs["json"]
    assert body["file_blocking"] == ["fb-1"]  # untouched member kept
    assert body["spyware"] == ["spy-2"] and body["vulnerability"] == ["vul-1"]
    assert "id" not in body and body["folder"] == "fw-a"
    assert out["diff"]["added"] == ["vulnerability"] and out["diff"]["changed"] == ["spyware"]


def test_update_null_removes_member_in_dry_run(monkeypatch: pytest.MonkeyPatch) -> None:
    net = Net([_group()], PROFILES)
    fn = _tool(net, monkeypatch)
    out = _json(
        fn(
            action="update",
            folder="fw-a",
            name="grp",
            config_json='{"file_blocking": null}',
            ticket_ref=TICKET,
        )
    )
    assert out["dry_run"] is True and "file_blocking" not in out["request"]["body"]
    assert out["diff"]["removed"] == ["file_blocking"]
    net.client.put.assert_not_called()


def test_update_missing_member_refused_and_noop_put_unverified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    net = Net([_group()], PROFILES, put_applies=False)
    fn = _tool(net, monkeypatch)
    bad = fn(
        action="update",
        profile_id="g-1",
        config_json='{"spyware": ["ghost"]}',
        dry_run=False,
        ticket_ref=TICKET,
    )
    assert bad.startswith("Error: member profiles not found")
    net.client.put.assert_not_called()
    out = _json(
        fn(
            action="update",
            profile_id="g-1",
            config_json='{"spyware": ["spy-2"]}',
            dry_run=False,
            ticket_ref=TICKET,
        )
    )
    assert out["verified"] is False and "warning" in out


def test_update_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    fn = _tool(Net([_group()], PROFILES), monkeypatch)
    assert "renaming" in fn(
        action="update", profile_id="g-1", config_json='{"name": "x"}', ticket_ref=TICKET
    )
    assert "nothing to change" in fn(
        action="update", profile_id="g-1", config_json="{}", ticket_ref=TICKET
    )
    assert "not found" in fn(
        action="update", profile_id="zzz", config_json='{"spyware": ["a"]}', ticket_ref=TICKET
    )


RULES = {
    "pre": [{"name": "r-pre", "profile_setting": {"group": ["grp"]}}, {"name": "x"}],
    "post": [{"name": "r-post", "profile_setting": {"group": ["grp"]}}],
}


def test_delete_refused_while_rule_references(monkeypatch: pytest.MonkeyPatch) -> None:
    net = Net([_group()], PROFILES, RULES)
    fn = _tool(net, monkeypatch)
    for dry in (True, False):
        out = fn(action="delete", folder="fw-a", name="grp", dry_run=dry, ticket_ref=TICKET)
        assert out.startswith("Error") and "r-pre (pre)" in out and "r-post (post)" in out
        assert "Not scanned" in out
    net.client.delete.assert_not_called()
    positions = [p["position"] for u, p in net.session_calls if u.endswith("/security-rules")]
    assert positions[:2] == ["pre", "post"]


def test_delete_dry_run_and_apply(monkeypatch: pytest.MonkeyPatch) -> None:
    net = Net([_group()], PROFILES, {"pre": [], "post": []})
    fn = _tool(net, monkeypatch)
    dry = _json(fn(action="delete", folder="fw-a", name="grp", ticket_ref=TICKET))
    assert dry["dry_run"] is True and dry["referenced_by"] == [] and dry["not_scanned"]
    net.client.delete.assert_not_called()
    done = _json(fn(action="delete", folder="fw-a", name="grp", dry_run=False, ticket_ref=TICKET))
    assert done["applied"] is True
    net.client.delete.assert_called_once_with(f"{BASE}/g-1")


def test_delete_fails_closed_on_lookup_error(monkeypatch: pytest.MonkeyPatch) -> None:
    net = Net([_group()], PROFILES, RULES, fail={"security-rules"})
    fn = _tool(net, monkeypatch)
    out = fn(action="delete", folder="fw-a", name="grp", dry_run=False, ticket_ref=TICKET)
    assert out.startswith("Error: cannot confirm") and "delete refused" in out
    net.client.delete.assert_not_called()
    dry = _json(fn(action="delete", folder="fw-a", name="grp", ticket_ref=TICKET))
    assert dry["dry_run"] is True and "lookup" in dry["warning"]


def test_ticket_ref_and_unknown_action(monkeypatch: pytest.MonkeyPatch) -> None:
    fn = _tool(Net(), monkeypatch)
    assert "ticket_ref is mandatory" in fn(action="create", folder="f", name="n", config_json="{}")
    assert "unknown action" in fn(action="nuke")
    assert "only one of" in fn(folder="a", snippet="b")
