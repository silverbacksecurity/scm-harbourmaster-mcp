"""Review fixes: inherited-scope delete gate, folder alias, read-back comparison."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any
from unittest.mock import MagicMock

import pytest

from scm_harbourmaster_mcp.tools import security_profile as sp
from scm_harbourmaster_mcp.tools import threat_profile as tp

TICKET = "CHG-TEST"


@pytest.fixture(autouse=True)
def _quiet(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sp.scm_rest, "refresh_token", lambda c: None)
    monkeypatch.setattr(tp.scm_rest, "refresh_token", lambda c: None)
    monkeypatch.setattr(sp, "audit_write", lambda *a, **k: None)
    monkeypatch.setattr(tp, "audit_write", lambda *a, **k: None)


# -- security_profile delete ---------------------------------------------------


def _sec_delete(
    monkeypatch: pytest.MonkeyPatch, folder: str, scan: Any, **kw: Any
) -> tuple[str, MagicMock]:
    spec = replace(sp.SPECS["url_access"], ref_scan=scan)
    client = MagicMock()
    current = {"id": "p-1", "name": "prof", "folder": folder}
    args = {"dry_run": False, "ticket_ref": TICKET, **kw}
    return sp._delete(client, "t", spec, current, **args), client


def test_security_top_level_scans_children_with_alias(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[dict[str, str]] = []

    def scan(c: Any, n: str, s: dict[str, str]) -> tuple[list[str], str]:
        seen.append(s)
        return [], ""

    _sec_delete(monkeypatch, "Shared", scan, dry_run=True)
    assert [s["folder"] for s in seen] == ["Prisma Access", "Mobile Users", "Remote Networks"]


def test_security_child_reference_blocks_delete(monkeypatch: pytest.MonkeyPatch) -> None:
    def scan(c: Any, n: str, s: dict[str, str]) -> tuple[list[str], str]:
        return (["grp"], "") if s["folder"] == "Mobile Users" else ([], "")

    out, client = _sec_delete(monkeypatch, "All", scan, acknowledge_unscanned_scope=True)
    assert out.startswith("Error") and "grp (in Mobile Users)" in out
    client.delete.assert_not_called()


def test_security_inherited_real_delete_needs_ack(monkeypatch: pytest.MonkeyPatch) -> None:
    ok = lambda c, n, s: ([], "")  # noqa: E731
    out, client = _sec_delete(monkeypatch, "All", ok)
    assert out.startswith("Error") and "acknowledge_unscanned_scope=True" in out
    client.delete.assert_not_called()
    dry, _ = _sec_delete(monkeypatch, "All", ok, dry_run=True)
    body = json.loads(dry)
    assert "inherited" in body["unscanned_scope_warning"]
    assert "acknowledge_unscanned_scope" in body["would_refuse"]
    out, client = _sec_delete(monkeypatch, "All", ok, acknowledge_unscanned_scope=True)
    assert json.loads(out)["applied"] is True
    client.delete.assert_called_once()


def test_security_plain_folder_unchanged_and_lookup_error_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out, client = _sec_delete(monkeypatch, "fw-a", lambda c, n, s: ([], ""))
    assert json.loads(out)["applied"] is True
    out, client = _sec_delete(
        monkeypatch,
        "Mobile Users",
        lambda c, n, s: ([], "HTTP 500"),
    )
    assert out.startswith("Error") and "HTTP 500" in out


def test_security_child_lookup_error_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def scan(c: Any, n: str, s: dict[str, str]) -> tuple[list[str], str]:
        return ([], "HTTP 500") if s["folder"] == "Remote Networks" else ([], "")

    out, client = _sec_delete(monkeypatch, "All", scan, acknowledge_unscanned_scope=True)
    assert out.startswith("Error") and "HTTP 500" in out
    client.delete.assert_not_called()


def test_ref_scope_wording_matches_threat() -> None:
    for spec in sp.SPECS.values():
        assert "naming the profile directly" not in spec.ref_scope


def test_category_warning_uses_alias(monkeypatch: pytest.MonkeyPatch) -> None:
    folders: list[str] = []

    def rows(s: Any, url: str, folder: str) -> tuple[list[Any], str]:
        folders.append(folder)
        return [], ""

    monkeypatch.setattr(sp.clone_preflight, "list_rows", rows)
    monkeypatch.setattr(sp.scm_rest, "bearer_session", lambda c: MagicMock())
    sp._category_warnings(MagicMock(), {"folder": "Shared"}, {"block": ["x"]})
    assert folders and set(folders) == {"Prisma Access"}


# -- threat_profile delete -----------------------------------------------------


def _groups(monkeypatch: pytest.MonkeyPatch, rows_by_folder: dict[str, list[Any]]) -> MagicMock:
    session = MagicMock()

    def get(url: str, params: dict[str, Any] | None = None, timeout: Any = None) -> Any:
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"data": rows_by_folder.get((params or {}).get("folder"), [])}
        return resp

    session.get.side_effect = get
    monkeypatch.setattr(tp.scm_rest, "bearer_session", lambda c: session)
    return session


def _thr_delete(folder: str, **kw: Any) -> tuple[str, MagicMock]:
    client = MagicMock()
    current = {"id": "a-1", "name": "asp", "folder": folder}
    return tp._delete(
        client, "t", "anti_spyware", current, **{"dry_run": False, **kw}, ticket_ref=TICKET
    ), client


def test_threat_top_level_scans_children_with_alias(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _groups(monkeypatch, {})
    out, _ = _thr_delete("Shared", dry_run=True)
    folders = [c.kwargs["params"]["folder"] for c in session.get.call_args_list]
    assert folders == ["Prisma Access", "Mobile Users", "Remote Networks"]
    body = json.loads(out)
    assert "acknowledge_unscanned_scope" in body["reference_check"]["would_refuse"]


def test_threat_child_group_blocks_and_ack_allows(monkeypatch: pytest.MonkeyPatch) -> None:
    _groups(monkeypatch, {"Remote Networks": [{"name": "grp", "spyware": ["asp"]}]})
    out, client = _thr_delete("All", acknowledge_unscanned_scope=True)
    assert out.startswith("Error") and "grp (in Remote Networks)" in out
    client.delete.assert_not_called()
    _groups(monkeypatch, {})
    out, client = _thr_delete("All")
    assert out.startswith("Error") and "acknowledge_unscanned_scope=True" in out
    client.delete.assert_not_called()
    out, client = _thr_delete("All", acknowledge_unscanned_scope=True)
    assert json.loads(out)["applied"] is True


def test_threat_paging_uses_raw_page_length(monkeypatch: pytest.MonkeyPatch) -> None:
    pages = [
        [{"spyware": ["x"]}] * tp._PAGE,  # nameless rows fill the page
        [{"name": "late", "spyware": ["asp"]}],
    ]
    session = MagicMock()
    calls = iter(pages)

    def get(url: str, params: dict[str, Any] | None = None, timeout: Any = None) -> Any:
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"data": next(calls, [])}
        return resp

    session.get.side_effect = get
    monkeypatch.setattr(tp.scm_rest, "bearer_session", lambda c: session)
    report, err = tp._reference_check(MagicMock(), "anti_spyware", "asp", {"folder": "fw-a"})
    assert not err and report["referenced_by"] == ["late"]


# -- read-back comparison ------------------------------------------------------


def test_threat_covers_order_and_blank() -> None:
    want = {"description": "", "rules": [{"name": "a", "x": 1}, {"name": "b", "x": 2}]}
    got = {"rules": [{"name": "b", "x": 2, "extra": 1}, {"name": "a", "x": 1}]}
    assert tp._covers(want, got)
    assert not tp._covers(want, {"rules": [{"name": "a", "x": 1}, {"name": "b", "x": 3}]})
    assert not tp._covers(want, {"rules": [{"name": "a", "x": 1}]})
    assert not tp._covers({"description": "d"}, {})


def test_security_covers_order_and_blank() -> None:
    exp = {"description": "", "rules": [{"name": "a", "x": 1}, {"name": "b", "x": 2}]}
    stored = {"rules": [{"name": "b", "x": 2}, {"name": "a", "x": 1, "y": 0}]}
    assert sp._covers(stored, exp)
    assert not sp._covers({"rules": [{"name": "a", "x": 9}, {"name": "b", "x": 2}]}, exp)
    assert not sp._covers({}, {"description": "d"})
    assert sp._covers({}, {"k": None})


# -- items from the testing agent ---------------------------------------------


def test_wildfire_rules_null_allowed_on_update() -> None:
    """rules is optional on the live API, so null removes it (verified 2026-11-20)."""
    _, errs = sp.parse_config(sp.SPECS["wildfire_antivirus"], '{"rules": null}', create=False)
    assert not errs
