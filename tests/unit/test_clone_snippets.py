"""Snippet-preserving clone (snippet_mode="preserve") and the backup's snippets record."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from scm_harbourmaster_mcp.audit import cloner
from scm_harbourmaster_mcp.audit.extractor import backup_snippets

from .test_config_cloner import FakeClient

SETUP = "https://api.sase.paloaltonetworks.com/config/setup/v1"
SSE = "https://api.sase.paloaltonetworks.com/sse/config/v1"


class FakeResponse:
    def __init__(self, status: int, body: Any = None) -> None:
        self.status_code = status
        self.ok = status < 400
        self._body = body
        self.content = b"x" if body is not None else b""
        self.text = json.dumps(body)

    def json(self) -> Any:
        return self._body


class FakeSession:
    """The /config/setup/v1 snippets and folders endpoints, and rulebase
    listing and :move under /sse/config/v1 (rulebases keyed by (path, position),
    holding the target's rows as they stand after the clone's creates)."""

    def __init__(
        self,
        snippets: list[dict[str, Any]] | None = None,
        folders: list[dict[str, Any]] | None = None,
        rulebases: dict[tuple[str, str], list[dict[str, Any]]] | None = None,
        move_status: int = 200,
        apply_moves: bool = True,
    ) -> None:
        self.snippets = snippets or []
        self.folders = folders or [
            {"id": "f-dst", "name": "dst", "parent": "ngfw-shared", "description": "keep me"}
        ]
        self.rulebases = rulebases or {}
        self.move_status = move_status
        self.apply_moves = apply_moves
        self.posts: list[tuple[str, dict[str, Any]]] = []
        self.puts: list[tuple[str, dict[str, Any]]] = []
        self.moves: list[tuple[str, dict[str, Any]]] = []

    def get(self, url: str, params: dict[str, Any] | None = None, timeout: int = 0) -> FakeResponse:
        if url.startswith(SSE):
            key = (url.removeprefix(f"{SSE}/"), (params or {}).get("position", ""))
            return FakeResponse(200, {"data": list(self.rulebases.get(key, []))})
        if url == f"{SETUP}/snippets":
            return FakeResponse(200, {"data": self.snippets})
        if url == f"{SETUP}/folders":
            return FakeResponse(200, {"data": self.folders})
        fid = url.rsplit("/", 1)[-1]
        row = next((f for f in self.folders if f["id"] == fid), None)
        return FakeResponse(200, dict(row)) if row else FakeResponse(404, {"error": "nf"})

    def post(self, url: str, json: dict[str, Any], timeout: int = 0) -> FakeResponse:
        if url.endswith(":move"):
            return self._move(url, json)
        self.posts.append((url, json))
        self.snippets.append({"name": json["name"], "type": None})
        return FakeResponse(201, {"id": "s-new", **json})

    def put(self, url: str, json: dict[str, Any], timeout: int = 0) -> FakeResponse:
        self.puts.append((url, json))
        fid = url.rsplit("/", 1)[-1]
        for f in self.folders:
            if f["id"] == fid:
                f.update(json)
        return FakeResponse(200, json)

    def _move(self, url: str, body: dict[str, Any]) -> FakeResponse:
        path, rid = url.removeprefix(f"{SSE}/").removesuffix(":move").rsplit("/", 1)
        self.moves.append((rid, body))
        if self.move_status >= 400:
            return FakeResponse(self.move_status, {"error": "nope"})
        rows = self.rulebases[(path, body["rulebase"])]
        row = next(r for r in rows if r["id"] == rid)
        if self.apply_moves:
            rows.remove(row)
            if body["destination"] == "bottom":
                rows.append(row)
            else:
                at = next(i for i, r in enumerate(rows) if r["id"] == body["destination_rule"])
                rows.insert(at, row)
        return FakeResponse(200, row)


def _backup(tmp_path: Path, resources: dict[str, Any], **extra: Any) -> str:
    path = tmp_path / "backup.json"
    path.write_text(json.dumps({"backup_version": "1", "resources": resources, **extra}))
    return str(path)


def _client(session: FakeSession) -> FakeClient:
    client = FakeClient()
    client.session = session  # type: ignore[attr-defined]
    return client


_CUSTOM = {"snippet_types": {"Web-Security-Default": "predefined"}}
_RECORD = {
    "snippets": [
        {
            "name": "branch-std",
            "description": "branch standard",
            "labels": ["gold"],
            "enable_prefix": False,
            "folders": ["ngfw-shared"],
        }
    ]
}


def test_preserve_creates_the_snippet_and_puts_its_objects_in_it(tmp_path):
    session = FakeSession()
    client = _client(session)
    src = _backup(
        tmp_path,
        {
            "tags": [
                {"name": "t-snip", "folder": "ngfw-shared", "snippet": "branch-std"},
                {"name": "t-folder", "folder": "ngfw-shared"},
            ],
            "security_rules_pre": [{"name": "r-snip", "snippet": "branch-std"}],
        },
        **_CUSTOM,
        **_RECORD,
    )
    report = cloner.clone_config(client, src, "dst", dry_run=False, snippet_mode="preserve")

    assert client.resources["tag"].created == [
        ({"name": "t-snip", "snippet": "branch-std"}, {}),
        ({"name": "t-folder", "folder": "dst"}, {}),
    ]
    assert client.resources["security_rule"].created == [
        ({"name": "r-snip", "snippet": "branch-std"}, {"rulebase": "pre"})
    ]
    # Created with the recorded description; labels are never sent
    assert session.posts == [
        (f"{SETUP}/snippets", {"name": "branch-std", "description": "branch standard"})
    ]
    # Associated with the folder, keeping the folder's other fields
    assert session.puts == [
        (
            f"{SETUP}/folders/f-dst",
            {
                "name": "dst",
                "parent": "ngfw-shared",
                "description": "keep me",
                "snippets": ["branch-std"],
            },
        )
    ]
    [plan] = report.snippets
    assert (plan.action, plan.objects, plan.outcome) == (
        "create",
        2,
        ["created", "associated with `dst`"],
    )
    md = report.to_markdown()
    assert "## Snippets" in md and "labels not copied (gold)" in md


def test_preserve_dry_run_writes_nothing(tmp_path):
    session = FakeSession()
    client = _client(session)
    src = _backup(
        tmp_path,
        {"tags": [{"name": "t-snip", "snippet": "branch-std"}]},
        **_CUSTOM,
    )
    report = cloner.clone_config(client, src, "dst", dry_run=True, snippet_mode="preserve")

    assert session.posts == [] and session.puts == []
    assert report.results[0].detail == "would create in snippet 'branch-std'"
    assert report.snippets[0].outcome == ["would create", "would associate with `dst`"]


def test_flatten_is_the_default_and_reads_no_snippets(tmp_path):
    session = FakeSession()
    client = _client(session)
    src = _backup(tmp_path, {"tags": [{"name": "t-snip", "snippet": "branch-std"}]}, **_CUSTOM)
    report = cloner.clone_config(client, src, "dst", dry_run=False)

    assert client.resources["tag"].created == [({"name": "t-snip", "folder": "dst"}, {})]
    assert session.posts == [] and session.puts == [] and report.snippets == []


def test_existing_snippet_used_by_other_folders_is_only_associated(tmp_path):
    session = FakeSession(
        snippets=[{"name": "branch-std", "type": None}],
        folders=[
            {"id": "f-dst", "name": "dst", "parent": "ngfw-shared"},
            {"id": "f-b", "name": "branch-b", "parent": "ngfw-shared", "snippets": ["branch-std"]},
        ],
    )
    client = _client(session)
    src = _backup(tmp_path, {"tags": [{"name": "t-snip", "snippet": "branch-std"}]}, **_CUSTOM)
    report = cloner.clone_config(client, src, "dst", dry_run=False, snippet_mode="preserve")

    assert "tag" not in client.resources
    assert report.results[0].status == "not_cloned"
    assert session.posts == []
    assert session.puts[0][1]["snippets"] == ["branch-std"]
    assert report.snippets[0].target_folders == ["branch-b"]
    assert "allow_shared_snippet=True" in report.to_markdown()


def test_allow_shared_snippet_writes_into_it(tmp_path):
    session = FakeSession(
        snippets=[{"name": "branch-std", "type": None}],
        folders=[
            {"id": "f-dst", "name": "dst", "parent": "ngfw-shared", "snippets": ["branch-std"]},
            {"id": "f-b", "name": "branch-b", "parent": "ngfw-shared", "snippets": ["branch-std"]},
        ],
    )
    client = _client(session)
    src = _backup(tmp_path, {"tags": [{"name": "t-snip", "snippet": "branch-std"}]}, **_CUSTOM)
    report = cloner.clone_config(
        client, src, "dst", dry_run=False, snippet_mode="preserve", allow_shared_snippet=True
    )

    assert client.resources["tag"].created == [({"name": "t-snip", "snippet": "branch-std"}, {})]
    # Already associated with dst: no folder PUT
    assert session.puts == []
    assert report.snippets[0].outcome == ["already associated"]


def test_pan_snippet_is_never_written_even_without_snippet_types(tmp_path):
    session = FakeSession(snippets=[{"name": "Web-Security-Default", "type": "predefined"}])
    client = _client(session)
    # No snippet_types in the backup, and the fake client's snippet.list() fails
    src = _backup(tmp_path, {"tags": [{"name": "t1", "snippet": "Web-Security-Default"}]})
    report = cloner.clone_config(client, src, "dst", dry_run=False, snippet_mode="preserve")

    assert "tag" not in client.resources
    assert report.snippets[0].action == "pan"
    assert session.posts == [] and session.puts == []


def test_name_prefix_renames_the_snippet(tmp_path):
    session = FakeSession()
    client = _client(session)
    src = _backup(tmp_path, {"tags": [{"name": "t-snip", "snippet": "branch-std"}]}, **_CUSTOM)
    cloner.clone_config(
        client, src, "dst", dry_run=False, snippet_mode="preserve", name_prefix="C1_"
    )

    assert session.posts[0][1]["name"] == "C1_branch-std"
    assert client.resources["tag"].created == [
        ({"name": "C1_t-snip", "snippet": "C1_branch-std"}, {})
    ]


def test_fixed_folder_objects_stay_in_their_folder(tmp_path):
    session = FakeSession()
    client = _client(session)
    src = _backup(
        tmp_path,
        {"qos_profiles": [{"name": "qos-1", "folder": "Remote Networks", "snippet": "branch-std"}]},
        **_CUSTOM,
    )
    report = cloner.clone_config(client, src, "dst", dry_run=False, snippet_mode="preserve")

    assert client.resources["qos_profile"].created == [
        ({"name": "qos-1", "folder": "Remote Networks"}, {})
    ]
    assert report.snippets == [] and session.posts == []


def test_failed_snippet_create_fails_its_objects(tmp_path):
    session = FakeSession()
    session.post = lambda url, json, timeout=0: FakeResponse(400, {"error": "bad"})  # type: ignore[method-assign]
    client = _client(session)
    src = _backup(tmp_path, {"tags": [{"name": "t-snip", "snippet": "branch-std"}]}, **_CUSTOM)
    report = cloner.clone_config(client, src, "dst", dry_run=False, snippet_mode="preserve")

    assert "tag" not in client.resources
    assert report.results[0].status == "failed"
    assert session.puts == []


def test_unreadable_target_pushes_nothing(tmp_path):
    session = FakeSession()
    session.get = lambda url, params=None, timeout=0: FakeResponse(403, {"error": "rbac"})  # type: ignore[method-assign]
    client = _client(session)
    src = _backup(tmp_path, {"tags": [{"name": "t-snip", "snippet": "branch-std"}]}, **_CUSTOM)
    report = cloner.clone_config(client, src, "dst", dry_run=False, snippet_mode="preserve")

    assert "tag" not in client.resources
    assert any("nothing was pushed" in w for w in report.warnings)


def test_unknown_snippet_mode_is_rejected(tmp_path):
    src = _backup(tmp_path, {})
    with pytest.raises(ValueError, match="snippet_mode"):
        cloner.clone_config(FakeClient(), src, "dst", snippet_mode="copy")


def test_backup_records_customer_snippets_with_their_folders():
    snap = SimpleNamespace(
        scm_snippets=[
            {"name": "predefined-snippet", "type": None},
            {"name": "hip-default", "type": "readonly"},
            {"name": "branch-std", "type": None, "description": "d", "labels": ["gold"]},
            {"name": "unused", "type": None},
        ],
        scm_folders=[
            {"name": "ngfw-shared", "snippets": ["hip-default", "branch-std"]},
            {"name": "branch-b", "snippets": ["branch-std"]},
        ],
    )
    assert backup_snippets(snap) == [  # type: ignore[arg-type]
        {
            "name": "branch-std",
            "description": "d",
            "labels": ["gold"],
            "enable_prefix": False,
            "folders": ["branch-b", "ngfw-shared"],
        },
        {"name": "unused", "description": "", "labels": [], "enable_prefix": False, "folders": []},
    ]


# ── Snippet placeholder rows and rule order ───────────────────────────────

# How SCM lists a snippet associated with a folder: a row named after the
# snippet, which the SDK fills with allow/any defaults.
_ANCHOR = {
    "name": "office365",
    "folder": "Shared",
    "snippet": None,
    "action": "allow",
    "source": ["any"],
    "destination": ["any"],
    "application": ["any"],
}


def test_snippet_placeholder_rows_are_never_pushed_as_rules(tmp_path):
    client = FakeClient()
    src = _backup(
        tmp_path,
        {
            "security_rules_pre": [_ANCHOR, {"name": "real", "folder": "Shared", "action": "deny"}],
            "decryption_rules": [{**_ANCHOR, "action": None}],
        },
        snippet_types={"office365": "predefined"},
    )
    report = cloner.clone_config(client, src, "dst", dry_run=False)

    assert [p["name"] for p, _ in client.resources["security_rule"].created] == ["real"]
    assert "decryption_rule" not in client.resources
    assert [r.status for r in report.results if r.name == "office365"] == ["not_cloned"] * 2


def test_placeholder_rows_found_from_the_target_list_for_old_backups(tmp_path):
    client = FakeClient()
    client.resources["snippet"] = SimpleNamespace(  # type: ignore[assignment]
        list=lambda: [SimpleNamespace(name="office365", type="predefined")], created=[]
    )
    src = _backup(tmp_path, {"security_rules_pre": [_ANCHOR]})
    cloner.clone_config(client, src, "dst", dry_run=False)

    assert "security_rule" not in client.resources


def _rule(name: str, **kw: Any) -> dict[str, Any]:
    return {"name": name, "folder": "src", "action": "deny", **kw}


def _row(name: str, folder: str = "dst") -> dict[str, Any]:
    """A target rulebase row as raw REST lists it (a snippet's has no action)."""
    return {"id": f"id-{name}", "name": name, "folder": folder}


def _rule_row(name: str) -> dict[str, Any]:
    return {**_row(name), "action": "deny"}


def _order(session: FakeSession, key: tuple[str, str] = ("security-rules", "pre")) -> list[str]:
    return [r["name"] for r in session.rulebases[key] if r["folder"] == "dst"]


def _ph(name: str) -> dict[str, Any]:
    """The source folder's row for an associated snippet."""
    return {**_ANCHOR, "name": name, "folder": "src"}


def test_snippet_row_is_moved_before_the_next_source_rule(tmp_path):
    session = FakeSession(
        rulebases={
            ("security-rules", "pre"): [
                _row("Web-Security-Default", "All"),
                _row("branch-std"),
                _rule_row("first"),
                _rule_row("second"),
            ]
        }
    )
    client = _client(session)
    src = _backup(
        tmp_path,
        {
            "security_rules_pre": [
                _rule("first"),
                _ph("branch-std"),
                _rule("second"),
                {"name": "in-snip", "snippet": "branch-std", "action": "deny"},
            ]
        },
        **_CUSTOM,
        **_RECORD,
    )
    report = cloner.clone_config(client, src, "dst", dry_run=False, snippet_mode="preserve")

    assert session.moves == [
        (
            "id-branch-std",
            {"destination": "before", "rulebase": "pre", "destination_rule": "id-second"},
        )
    ]
    assert _order(session) == ["first", "branch-std", "second"]
    assert not [w for w in report.warnings if "rule order" in w]
    assert "security_rules_pre row moved before `second`" in report.snippets[0].outcome


def test_snippet_row_last_in_the_source_goes_to_the_bottom(tmp_path):
    session = FakeSession(
        rulebases={("security-rules", "post"): [_row("branch-std"), _rule_row("first")]}
    )
    client = _client(session)
    src = _backup(
        tmp_path,
        {
            "security_rules_post": [
                _rule("first"),
                _ph("branch-std"),
                {"name": "in-snip", "snippet": "branch-std", "action": "deny"},
            ]
        },
        **_CUSTOM,
        **_RECORD,
    )
    report = cloner.clone_config(client, src, "dst", dry_run=False, snippet_mode="preserve")

    assert session.moves == [("id-branch-std", {"destination": "bottom", "rulebase": "post"})]
    assert _order(session, ("security-rules", "post")) == ["first", "branch-std"]
    assert not report.warnings


def test_several_snippets_with_a_prefix_and_a_skipped_rule(tmp_path):
    # SCM put both snippet rows above the rules the clone created; "gone" was
    # not created (a preflight skip, a conflict or a failure)
    session = FakeSession(
        rulebases={
            ("security-rules", "pre"): [
                _row("c-a"),
                _row("c-b"),
                _rule_row("c-r1"),
                _rule_row("c-r2"),
            ]
        }
    )
    client = _client(session)
    src = _backup(
        tmp_path,
        {
            "security_rules_pre": [
                _ph("a"),
                _rule("r1"),
                _ph("b"),
                _rule("gone"),
                _rule("r2"),
                {"name": "in-a", "snippet": "a", "action": "deny"},
                {"name": "in-b", "snippet": "b", "action": "deny"},
            ]
        },
        snippets=[{"name": "a"}, {"name": "b"}],
        **_CUSTOM,
    )
    report = cloner.clone_config(
        client, src, "dst", dry_run=False, snippet_mode="preserve", name_prefix="c-"
    )

    # Bottom-up: b first, then a before the rule below it
    assert [m[0] for m in session.moves] == ["id-c-b", "id-c-a"]
    assert session.moves[0][1]["destination_rule"] == "id-c-r2"
    assert _order(session) == ["c-a", "c-r1", "c-b", "c-r2"]
    assert not [w for w in report.warnings if "rule order" in w]


def test_nat_rules_in_a_snippet_still_warn(tmp_path):
    session = FakeSession()
    client = _client(session)
    src = _backup(
        tmp_path,
        {
            "nat_rules_pre": [
                _rule("first"),
                _ph("branch-std"),
                {"name": "in-snip", "snippet": "branch-std"},
            ]
        },
        **_CUSTOM,
        **_RECORD,
    )
    report = cloner.clone_config(client, src, "dst", dry_run=False, snippet_mode="preserve")

    assert not session.moves
    [warning] = [w for w in report.warnings if "rule order" in w]
    assert "no move for this rulebase" in warning and "nat_rules_pre row 2 of 2" in warning


def test_dry_run_reports_the_move_and_sends_none(tmp_path):
    session = FakeSession()
    client = _client(session)
    src = _backup(
        tmp_path,
        {
            "security_rules_pre": [
                _rule("first"),
                _ph("branch-std"),
                _rule("second"),
                {"name": "in-snip", "snippet": "branch-std", "action": "deny"},
            ]
        },
        **_CUSTOM,
        **_RECORD,
    )
    report = cloner.clone_config(client, src, "dst", dry_run=True, snippet_mode="preserve")

    assert not session.moves and not session.puts
    assert "would move its security_rules_pre row before `second`" in report.snippets[0].outcome
    assert not [w for w in report.warnings if "rule order" in w]


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"move_status": 400}, "HTTP 400"),
        ({"apply_moves": False}, "read back in a different order"),
    ],
)
def test_a_move_that_does_not_land_keeps_the_warning(tmp_path, kwargs, expected):
    session = FakeSession(
        rulebases={
            ("security-rules", "pre"): [_row("branch-std"), _rule_row("first"), _rule_row("second")]
        },
        **kwargs,
    )
    client = _client(session)
    src = _backup(
        tmp_path,
        {
            "security_rules_pre": [
                _rule("first"),
                _ph("branch-std"),
                _rule("second"),
                {"name": "in-snip", "snippet": "branch-std", "action": "deny"},
            ]
        },
        **_CUSTOM,
        **_RECORD,
    )
    report = cloner.clone_config(client, src, "dst", dry_run=False, snippet_mode="preserve")

    [warning] = [w for w in report.warnings if "rule order" in w]
    assert expected in warning and "security_rules_pre row 2 of 3" in warning


def test_already_associated_snippet_row_is_left_alone(tmp_path):
    session = FakeSession(
        snippets=[{"name": "branch-std", "type": None}],
        folders=[
            {"id": "f-dst", "name": "dst", "parent": "ngfw-shared", "snippets": ["branch-std"]}
        ],
    )
    client = _client(session)
    src = _backup(
        tmp_path,
        {
            "security_rules_pre": [
                _ph("branch-std"),
                {"name": "in-snip", "snippet": "branch-std", "action": "deny"},
            ]
        },
        **_CUSTOM,
        **_RECORD,
    )
    report = cloner.clone_config(client, src, "dst", dry_run=False, snippet_mode="preserve")

    assert not session.moves
    [warning] = [w for w in report.warnings if "rule order" in w]
    assert "associated before this clone" in warning


def test_failed_association_is_a_top_level_warning(tmp_path):
    session = FakeSession(folders=[{"id": "f-x", "name": "other", "parent": "All"}])
    client = _client(session)
    src = _backup(tmp_path, {"tags": [{"name": "t-snip", "snippet": "branch-std"}]}, **_CUSTOM)
    report = cloner.clone_config(client, src, "dst", dry_run=False, snippet_mode="preserve")

    assert any("could not be associated" in w for w in report.warnings)
