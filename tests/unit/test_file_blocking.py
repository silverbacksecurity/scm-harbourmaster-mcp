"""scm_file_blocking_apps and scm_file_blocking_profile (fake clients, no network)."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.tools import file_blocking as fb

TENANT = "1234567890"
TICKET = "CHG-TEST"
BASE = "/config/security/v1/file-blocking-profiles"

# Every app comes back twice with null ids; the flag is on one row only.
ROWS: list[dict[str, Any]] = [
    {"name": "app-synthetic", "id": None, "category": "general", "subcategory": "x", "risk": 2},
    {"name": "app-synthetic", "id": None, "file_type_ident": True, "risk": 2},
    {"name": "app-synthetic-two", "file_type_ident": True, "category": "general"},
    {"name": "app-synthetic-two", "category": "general"},
    {"name": "app-transfer", "able_to_transfer_file": True, "file_type_ident": False},
    {"name": "app-transfer", "able_to_transfer_file": True},
    {"name": "app-plain", "file_type_ident": False},
    {"name": "app-child", "container": "app-box", "file_type_ident": True},
    {"name": "app-child", "container": "app-box"},
]


@pytest.fixture(autouse=True)
def _reset_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    fb._CACHE.clear()
    fb._INFLIGHT.clear()
    monkeypatch.setattr(fb.scm_rest, "refresh_token", lambda c: None)


def _tools(client: Any) -> tuple[Any, Any]:
    mcp = FastMCP("test")
    fb.register_file_blocking_tools(mcp, lambda tenant_id="": client)
    mgr = mcp._tool_manager
    return mgr.get_tool("scm_file_blocking_apps").fn, mgr.get_tool("scm_file_blocking_profile").fn


def _patch_fetch(monkeypatch: pytest.MonkeyPatch, rows: Any = None, err: str = "") -> list[int]:
    calls: list[int] = []

    def _f(client: Any) -> tuple[list[dict[str, Any]], str]:
        calls.append(1)
        return ([] if err else list(ROWS if rows is None else rows)), err

    monkeypatch.setattr(fb, "_fetch_catalogue", _f)
    return calls


def _rule(**over: Any) -> dict[str, Any]:
    return {
        "name": "r1",
        "action": "block",
        "application": ["app-synthetic"],
        "direction": "both",
        "file_type": ["pdf"],
        **over,
    }


def _profile_client(
    profiles: list[dict[str, Any]] | None = None, *, put_applies: bool = True
) -> MagicMock:
    store = {p["id"]: dict(p) for p in (profiles or [])}
    client = MagicMock()

    def _get(path: str, params: dict[str, Any] | None = None) -> Any:
        if path == BASE:
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

    client.get.side_effect = _get
    client.put.side_effect = _put
    client.post.return_value = {"id": "new-1"}
    client.store = store
    return client


PROFILE = {
    "id": "p-1",
    "name": "fb-test-profile",
    "folder": "fw-a",
    "description": "old",
    "rules": [_rule()],
}


class TestCatalogue:
    def test_merge_by_name_with_flag_on_one_row(self) -> None:
        cat = fb.merge_rows(ROWS)
        assert cat.apps["app-synthetic"].eligible is True
        assert cat.apps["app-synthetic"].category == "general"
        assert cat.apps["app-synthetic-two"].eligible is True
        assert cat.apps["app-transfer"].transfer_only is True
        assert cat.apps["app-plain"].eligible is False
        assert cat.containers == {"app-box": ["app-child"]}
        assert cat.totals()["unique_apps"] == 5

    def test_verdicts(self) -> None:
        cat = fb.merge_rows(ROWS)
        assert fb.classify("app-synthetic", cat)["verdict"] == "eligible"
        assert fb.classify("any", cat)["verdict"] == "eligible"
        assert fb.classify("app-transfer", cat)["verdict"] == "not_eligible_transfer_only"
        assert fb.classify("app-plain", cat)["verdict"] == "not_eligible"
        box = fb.classify("app-box", cat)
        assert box["verdict"] == "container"
        assert box["eligible_children"] == ["app-child"]
        unk = fb.classify("app-syntheti", cat)
        assert unk["verdict"] == "unknown"
        assert "app-synthetic" in unk["close_matches"]

    def test_cache_hit_ttl_refresh(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls = _patch_fetch(monkeypatch)
        now = [1000.0]
        monkeypatch.setattr(fb, "_clock", lambda: now[0])
        cat, err = fb.get_catalogue(None, TENANT)
        assert not err and not cat.cached
        cat, _ = fb.get_catalogue(None, TENANT)
        assert cat.cached and len(calls) == 1
        fb.get_catalogue(None, TENANT, refresh=True)
        assert len(calls) == 2
        now[0] += fb.CACHE_TTL + 1
        cat, _ = fb.get_catalogue(None, TENANT)
        assert not cat.cached and len(calls) == 3

    def test_partial_fetch_not_cached(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fetch(monkeypatch, err="stopped after 40 pages")
        cat, err = fb.get_catalogue(None, TENANT)
        assert err and not cat.apps
        assert TENANT not in fb._CACHE
        _patch_fetch(monkeypatch)
        _, err = fb.get_catalogue(None, TENANT)
        assert not err and TENANT in fb._CACHE

    def test_fetch_refreshes_token_before_each_attempt(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        refreshed: list[int] = []
        monkeypatch.setattr(fb.scm_rest, "refresh_token", lambda c: refreshed.append(1))
        monkeypatch.setattr(fb.scm_rest, "bearer_session", lambda c: object())
        results = iter([([], "HTTP 401: expired"), (list(ROWS), "")])
        monkeypatch.setattr(fb.clone_preflight, "list_rows", lambda s, u, f, **kw: next(results))
        rows, err = fb._fetch_catalogue(object())
        assert not err and len(rows) == len(ROWS)
        assert len(refreshed) == 2

    def test_fetch_does_not_retry_other_errors(self, monkeypatch: pytest.MonkeyPatch) -> None:
        n: list[int] = []
        monkeypatch.setattr(fb.scm_rest, "bearer_session", lambda c: object())

        def _rows(s: Any, u: str, f: str, **kw: Any) -> tuple[list[Any], str]:
            n.append(1)
            return [], "HTTP 502"

        monkeypatch.setattr(fb.clone_preflight, "list_rows", _rows)
        assert fb._fetch_catalogue(object()) == ([], "HTTP 502")
        assert len(n) == 1


class TestWarming:
    def test_slow_load_reports_warming_then_hits_cache(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import threading

        release = threading.Event()
        calls: list[int] = []

        def _slow(client: Any) -> tuple[list[dict[str, Any]], str]:
            calls.append(1)
            release.wait(5)
            return list(ROWS), ""

        monkeypatch.setattr(fb, "_fetch_catalogue", _slow)
        cat, err = fb.get_catalogue(None, TENANT, wait=0.05)
        assert err == fb.WARMING_MSG and not cat.apps
        # A second caller joins the same load instead of starting another fetch.
        _, err = fb.get_catalogue(None, TENANT, wait=0.05)
        assert err == fb.WARMING_MSG and len(calls) == 1
        release.set()
        cat, err = fb.get_catalogue(None, TENANT, wait=5)
        assert not err and cat.apps and len(calls) == 1
        cat, err = fb.get_catalogue(None, TENANT, wait=0.05)
        assert not err and cat.cached

    def test_failed_background_load_is_not_cached_and_can_retry(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_fetch(monkeypatch, err="HTTP 502")
        _, err = fb.get_catalogue(None, TENANT, wait=5)
        assert err == "HTTP 502" and TENANT not in fb._CACHE
        _patch_fetch(monkeypatch)
        cat, err = fb.get_catalogue(None, TENANT, wait=5)
        assert not err and cat.apps

    def test_apps_tool_says_warming_not_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(fb, "WAIT_BUDGET", 0.05)
        import threading

        release = threading.Event()
        monkeypatch.setattr(
            fb, "_fetch_catalogue", lambda c: (release.wait(5), (list(ROWS), ""))[1]
        )
        apps, _ = _tools(MagicMock())
        out = apps(tenant_id=TENANT, check=["app-synthetic"])
        assert out.startswith("Catalogue warming") and "Error" not in out
        release.set()

    def test_validation_degrades_with_a_note_while_warming(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(fb, "WAIT_BUDGET", 0.05)
        import threading

        release = threading.Event()
        monkeypatch.setattr(
            fb, "_fetch_catalogue", lambda c: (release.wait(5), (list(ROWS), ""))[1]
        )
        block, err = fb._validate(None, TENANT, [_rule()], skip_app_check=False)
        assert not err and "still loading" in block["app_check"]
        release.set()


class FakeSession:
    """Serves a catalogue of N rows in 1000-row pages and records offsets."""

    def __init__(self, total: int) -> None:
        self.total = total
        self.offsets: list[int] = []

    def get(self, url: str, params: dict[str, Any], timeout: Any) -> Any:
        off, lim = int(params["offset"]), int(params["limit"])
        self.offsets.append(off)
        n = max(0, min(lim, self.total - off))
        resp = MagicMock(status_code=200)
        resp.json.return_value = {
            "data": [{"name": f"a{off + i}"} for i in range(n)],
            "total": self.total,
        }
        return resp


class TestPrefetchPager:
    def test_prefetch_covers_everything_in_one_wave(self) -> None:
        from scm_harbourmaster_mcp.audit import clone_preflight as cp

        sess = FakeSession(11162)
        rows, err = cp._list_rows(sess, "u", "All", prefetch_pages=12)
        assert not err and len(rows) == 11162
        assert sorted(sess.offsets) == [i * 1000 for i in range(12)]

    def test_prefetch_continues_when_the_last_page_is_full(self) -> None:
        from scm_harbourmaster_mcp.audit import clone_preflight as cp

        sess = FakeSession(13500)
        rows, err = cp._list_rows(sess, "u", "All", prefetch_pages=12)
        assert not err and len(rows) == 13500
        assert max(sess.offsets) == 13000

    def test_prefetch_clamps_the_page_count(self) -> None:
        from scm_harbourmaster_mcp.audit import clone_preflight as cp

        sess = FakeSession(1500)
        rows, err = cp._list_rows(sess, "u", "All", prefetch_pages=500)
        assert not err and len(rows) == 1500
        assert len(sess.offsets) == cp._MAX_PAGES

    def test_prefetch_reports_a_page_error(self) -> None:
        from scm_harbourmaster_mcp.audit import clone_preflight as cp

        sess = FakeSession(3000)
        bad = MagicMock(status_code=502, text="bad gateway")
        bad.json.side_effect = ValueError
        sess.get = lambda *a, **k: bad  # type: ignore[method-assign]
        rows, err = cp._list_rows(sess, "u", "All", prefetch_pages=3)
        assert rows == [] and "502" in err

    def test_default_path_unchanged(self) -> None:
        from scm_harbourmaster_mcp.audit import clone_preflight as cp

        sess = FakeSession(2500)
        rows, err = cp._list_rows(sess, "u", "All")
        assert not err and len(rows) == 2500


class TestAppsTool:
    def test_check_returns_verdicts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fetch(monkeypatch)
        apps, _ = _tools(MagicMock())
        out = json.loads(apps(tenant_id=TENANT, check=["app-synthetic", "app-box", "nope"]))
        assert [r["verdict"] for r in out["results"]] == ["eligible", "container", "unknown"]
        assert out["content_note"] == fb.CONTENT_NOTE
        assert out["totals"]["eligible"] == 3

    def test_list_filters_and_clamps(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fetch(monkeypatch)
        apps, _ = _tools(MagicMock())
        out = json.loads(apps(tenant_id=TENANT, name_contains="TWO", limit=9999))
        assert out["limit"] == fb.LIMIT_MAX
        assert [i["name"] for i in out["items"]] == ["app-synthetic-two"]
        out = json.loads(apps(tenant_id=TENANT, include_all=True, limit=0))
        assert out["limit"] == 1 and out["total_matches"] == 5
        out = json.loads(apps(tenant_id=TENANT, include_all=True, name_contains="transfer"))
        assert out["items"][0]["reason"] == "transfer_only"

    def test_check_too_long_and_fetch_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        apps, _ = _tools(MagicMock())
        assert apps(tenant_id=TENANT, check=["a"] * 201).startswith("Error")
        _patch_fetch(monkeypatch, err="HTTP 502")
        assert apps(tenant_id=TENANT).startswith("Error: could not read")


class TestParseRules:
    def test_defaults_and_string_coercion(self) -> None:
        rules, errors = fb.parse_rules(json.dumps([{"name": "r", "application": "app-x"}]))
        assert not errors
        assert rules == [
            {
                "name": "r",
                "action": "alert",
                "application": ["app-x"],
                "direction": "both",
                "file_type": ["any"],
            }
        ]

    def test_bad_values(self) -> None:
        raw = json.dumps(
            [
                {"name": "r", "action": "deny", "direction": "sideways", "extra": 1},
                {"name": "r", "application": ["any", "x"], "file_type": ["any", "pdf"]},
            ]
        )
        _, errors = fb.parse_rules(raw)
        text = "\n".join(errors)
        assert "unknown keys" in text and "action" in text and "direction" in text
        assert "duplicate rule name" in text
        assert "application names" in text and "file types" in text

    def test_invalid_json(self) -> None:
        assert fb.parse_rules("{")[1]
        assert fb.parse_rules("[]")[1]


class TestCreate:
    def _call(self, client: Any, **kw: Any) -> str:
        _, prof = _tools(client)
        args: dict[str, Any] = {
            "tenant_id": TENANT,
            "action": "create",
            "folder": "fw-a",
            "name": "fb-test-profile",
            "rules_json": json.dumps([_rule()]),
            "ticket_ref": TICKET,
        }
        args.update(kw)
        return prof(**args)

    def test_dry_run_is_default_and_never_posts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fetch(monkeypatch)
        client = _profile_client()
        out = json.loads(self._call(client))
        assert out["dry_run"] is True and out["exists"] is False
        assert out["request"]["body"]["folder"] == "fw-a"
        assert "ticket_ref" not in out["request"]["body"]
        assert out["validation"]["ok"] is True
        client.post.assert_not_called()

    def test_ticket_ref_required_even_for_dry_run(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fetch(monkeypatch)
        client = _profile_client()
        assert "ticket_ref is mandatory" in self._call(client, ticket_ref="")
        client.post.assert_not_called()

    def test_real_create_posts_without_ticket(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fetch(monkeypatch)
        client = _profile_client()
        out = json.loads(self._call(client, dry_run=False, description="d"))
        assert out["applied"] is True and "scm_commit" in out["hint"]
        body = client.post.call_args.kwargs["json"]
        assert body["description"] == "d" and "ticket_ref" not in body
        assert body["rules"][0]["application"] == ["app-synthetic"]

    def test_multi_offender_error_lists_all(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fetch(monkeypatch)
        client = _profile_client()
        rules = [
            _rule(name="a", application=["app-transfer", "app-synthetic"]),
            _rule(name="b", application=["app-box", "app-syntheti"]),
        ]
        out = self._call(client, rules_json=json.dumps(rules), dry_run=False)
        assert out.startswith("Error: 3 application(s)")
        for token in ("app-transfer", "app-box", "app-syntheti", "did you mean app-synthetic"):
            assert token in out
        assert "app-child" in out  # container -> eligible children
        client.post.assert_not_called()

    def test_skip_app_check_passes_through(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls = _patch_fetch(monkeypatch)
        client = _profile_client()
        out = json.loads(
            self._call(
                client,
                dry_run=False,
                skip_app_check=True,
                rules_json=json.dumps([_rule(application=["app-transfer"])]),
            )
        )
        assert out["applied"] is True and "skipped" in out["validation"]["app_check"]
        assert not calls
        client.post.assert_called_once()

    def test_catalogue_failure_degrades_to_warning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fetch(monkeypatch, err="HTTP 502")
        out = json.loads(self._call(_profile_client()))
        assert out["validation"]["app_check"].startswith("skipped (HTTP 502")

    def test_existing_profile_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fetch(monkeypatch)
        client = _profile_client([PROFILE])
        out = self._call(client, dry_run=False)
        assert "already exists" in out and "action=update" in out
        client.post.assert_not_called()

    def test_input_errors(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fetch(monkeypatch)
        client = _profile_client()
        assert "one of folder" in self._call(client, folder="")
        assert "only one of" in self._call(client, snippet="s")
        assert "name must be" in self._call(client, name="bad/name")
        assert "invalid rules_json" in self._call(client, rules_json="nope")
        assert "unknown action" in self._call(client, action="zap")

    def test_snippet_scope(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fetch(monkeypatch)
        out = json.loads(self._call(_profile_client(), folder="", snippet="sn-a"))
        assert out["request"]["body"]["snippet"] == "sn-a"


class TestUpdate:
    def _call(self, client: Any, **kw: Any) -> str:
        _, prof = _tools(client)
        args: dict[str, Any] = {
            "tenant_id": TENANT,
            "action": "update",
            "folder": "fw-a",
            "name": "fb-test-profile",
            "rules_json": json.dumps([_rule(name="r2", action="alert")]),
            "ticket_ref": TICKET,
        }
        args.update(kw)
        return prof(**args)

    def test_dry_run_shows_diff_and_body_keeps_container(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_fetch(monkeypatch)
        client = _profile_client([PROFILE])
        out = json.loads(self._call(client))
        assert out["rule_diff"] == {"added": ["r2"], "removed": ["r1"], "changed": []}
        req = out["request"]
        assert req["method"] == "PUT" and req["path"] == f"{BASE}/p-1"
        assert req["body"]["folder"] == "fw-a" and "id" not in req["body"]
        client.put.assert_not_called()

    def test_real_update_verifies_read_back(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fetch(monkeypatch)
        client = _profile_client([PROFILE])
        out = json.loads(self._call(client, dry_run=False, description="new"))
        assert out["verified"] is True
        sent = client.put.call_args.kwargs["json"]
        assert sent["folder"] == "fw-a" and "id" not in sent and sent["description"] == "new"

    def test_silent_noop_put_reports_unverified(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fetch(monkeypatch)
        client = _profile_client([PROFILE], put_applies=False)
        out = json.loads(self._call(client, dry_run=False))
        assert out["verified"] is False and "warning" in out

    def test_update_needs_something_and_existing_profile(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_fetch(monkeypatch)
        client = _profile_client([PROFILE])
        assert "needs rules_json" in self._call(client, rules_json="")
        assert "not found" in self._call(_profile_client(), dry_run=False)

    def test_update_multi_offender(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_fetch(monkeypatch)
        client = _profile_client([PROFILE])
        rules = [_rule(application=["app-plain", "app-transfer"])]
        out = self._call(client, rules_json=json.dumps(rules), dry_run=False)
        assert "app-plain" in out and "app-transfer" in out
        client.put.assert_not_called()


class TestDeleteAndReads:
    def _call(self, client: Any, **kw: Any) -> str:
        _, prof = _tools(client)
        args: dict[str, Any] = {
            "tenant_id": TENANT,
            "action": "delete",
            "folder": "fw-a",
            "name": "fb-test-profile",
            "ticket_ref": TICKET,
        }
        args.update(kw)
        return prof(**args)

    def test_refused_when_group_references_it(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(fb, "_referencing_groups", lambda c, n, s: (["grp-a"], ""))
        client = _profile_client([PROFILE])
        out = self._call(client, dry_run=False)
        assert out.startswith("Error") and "grp-a" in out
        client.delete.assert_not_called()

    def test_reference_lookup_via_session(self, monkeypatch: pytest.MonkeyPatch) -> None:
        resp = MagicMock(status_code=200)
        resp.json.return_value = {
            "data": [
                {"name": "grp-a", "file_blocking": ["fb-test-profile"]},
                {"name": "grp-b", "file_blocking": ["other"]},
                {"name": "grp-c", "file_blocking": "fb-test-profile"},
            ]
        }
        session = MagicMock()
        session.get.return_value = resp
        refreshed: list[int] = []
        monkeypatch.setattr(fb.scm_rest, "refresh_token", lambda c: refreshed.append(1))
        monkeypatch.setattr(fb.scm_rest, "bearer_session", lambda c: session)
        groups, err = fb._referencing_groups(object(), "fb-test-profile", {"folder": "fw-a"})
        assert groups == ["grp-a", "grp-c"] and not err and refreshed
        assert session.get.call_args.kwargs["params"]["folder"] == "fw-a"

    def test_lookup_failure_warns_but_does_not_block(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(fb, "_referencing_groups", lambda c, n, s: ([], "HTTP 403"))
        client = _profile_client([PROFILE])
        out = json.loads(self._call(client))
        assert out["dry_run"] is True and out["warning"] == "HTTP 403"
        assert out["referenced_by"] == []

    def test_real_delete(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(fb, "_referencing_groups", lambda c, n, s: ([], ""))
        client = _profile_client([PROFILE])
        out = json.loads(self._call(client, dry_run=False))
        assert out["applied"] is True
        client.delete.assert_called_once_with(f"{BASE}/p-1")

    def test_delete_requires_ticket(self) -> None:
        assert "ticket_ref is mandatory" in self._call(_profile_client([PROFILE]), ticket_ref="")

    def test_list_and_get(self) -> None:
        client = _profile_client([PROFILE, {**PROFILE, "id": "p-2", "name": "other"}])
        _, prof = _tools(client)
        out = json.loads(prof(tenant_id=TENANT, folder="fw-a", name="TEST"))
        assert out["total"] == 1
        assert "one of folder" in prof(tenant_id=TENANT)
        got = json.loads(prof(tenant_id=TENANT, action="get", profile_id="p-2"))
        assert got["item"]["name"] == "other"
        assert "not found" in prof(tenant_id=TENANT, action="get", folder="fw-a", name="zzz")


def test_put_payload_leaves_keys_untouched() -> None:
    body = fb.scm_rest.put_payload(
        "file_blocking_profile",
        {"id": "x", "name": "n", "folder": "f", "rules": [_rule(action="continue")]},
    )
    assert body == {"name": "n", "folder": "f", "rules": [_rule(action="continue")]}
