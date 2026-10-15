"""Tests for utils/saa.py — region gate, paging, secret stripping, risks and tables."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from scm_harbourmaster_mcp.utils import saa
from scm_harbourmaster_mcp.utils.airs import render_sections_markdown
from scm_harbourmaster_mcp.utils.saa import (
    SAA_REGIONS,
    SaaInventory,
    assess_saa,
    covered_apps,
    fetch_saa,
    find_region,
    not_provisioned_text,
    region_line,
    risk_headline,
    saa_changes,
    saa_sections,
)

NOW = datetime(2026, 10, 15, tzinfo=UTC)
NOT_FOUND = {"_errors": [{"code": "SAA_12008", "message": "Not Found"}]}


def _resp(status: int, data: Any = None) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.json.return_value = data
    if status >= 400:
        r.raise_for_status.side_effect = RuntimeError(f"HTTP {status}")
    return r


def _session(regions: dict[str, dict[str, Any]]) -> MagicMock:
    """regions: x-panw-region -> {path suffix: response | callable(params)}.

    Any region or path not listed answers 404 "tenant not found", like the
    live API for a wrong region.
    """
    session = MagicMock()

    def get(url: str, params: Any = None, headers: Any = None, timeout: Any = None) -> Any:
        routes = regions.get((headers or {}).get("x-panw-region", ""), {})
        path = url.removeprefix(saa.SAA_BASE)
        resp = routes.get(path)
        if resp is None:
            return _resp(404, NOT_FOUND)
        return resp if isinstance(resp, MagicMock) else resp(params or {})

    session.get.side_effect = get
    return session


def _page(items: list[dict[str, Any]], **meta: Any) -> MagicMock:
    return _resp(200, {"data": items, **meta})


@pytest.fixture(autouse=True)
def _isolated_region() -> Any:
    saa.clear_region_cache()
    with patch.object(saa, "resolve_region_with_source", return_value=("", "none")):
        yield
    saa.clear_region_cache()


def _provisioned(region: str = "uk", **lists: Any) -> dict[str, dict[str, Any]]:
    routes: dict[str, Any] = {
        "/applications": _page([]),
        "/application-groups": _page([]),
        "/application-profiles": _page([{"profile_id": "0", "is_read_only": True}]),
        "/application-policies": _page([]),
        "/active-sessions": _page([]),
    }
    routes.update(lists)
    return {region: routes}


class TestRegionGate:
    def test_no_region_answers_is_not_provisioned(self) -> None:
        inv = fetch_saa(_session({}), "t1")
        assert not inv.provisioned and inv.region == ""
        assert inv.probe_failures == {}
        assert "not provisioned" in not_provisioned_text(inv)
        assert f"all {len(SAA_REGIONS)} regions" in not_provisioned_text(inv)

    def test_lists_not_fetched_without_region(self) -> None:
        s = _session({})
        fetch_saa(s, "t1")
        paths = {c.args[0].removeprefix(saa.SAA_BASE) for c in s.get.call_args_list}
        # Profiles/policies/sessions answer 200 in any region — never asked.
        assert paths == {"/applications", "/application-groups"}

    def test_probe_finds_the_one_region(self) -> None:
        s = _session(_provisioned("europe"))
        inv = fetch_saa(s, "t1")
        assert inv.region == "europe" and inv.region_source == "probed"
        list_calls = [c for c in s.get.call_args_list if c.kwargs["params"] != {"limit": 1}]
        assert len(list_calls) == 5
        assert all(c.kwargs["headers"] == {"x-panw-region": "europe"} for c in list_calls)

    def test_groups_alone_establish_the_region(self) -> None:
        # First touch: groups answer before applications.
        regions = _provisioned("uk")
        del regions["uk"]["/applications"]
        inv = fetch_saa(_session(regions), "t1")
        assert inv.region == "uk"
        assert inv.refused == {"applications": 404}
        assert not inv.complete("applications")

    def test_configured_region_tried_first(self) -> None:
        s = _session(_provisioned("uk"))
        with patch.object(saa, "resolve_region_with_source", return_value=("uk", "configured")):
            inv = fetch_saa(s, "t1")
        assert (inv.region, inv.region_source) == ("uk", "configured")
        probe_regions = {
            c.kwargs["headers"]["x-panw-region"]
            for c in s.get.call_args_list
            if c.kwargs["params"] == {"limit": 1}
        }
        assert probe_regions == {"uk"}

    def test_cached_region_reused(self) -> None:
        s = _session(_provisioned("uk"))
        fetch_saa(s, "t1")
        inv = fetch_saa(s, "t1")
        assert inv.region_source == "cached"

    def test_explicit_region_is_not_replaced(self) -> None:
        s = _session(_provisioned("uk"))
        inv = fetch_saa(s, "t1", region="europe")
        assert not inv.provisioned
        assert "region `europe`" in not_provisioned_text(inv, "europe")
        ok = fetch_saa(s, "t1", region="UK")  # case folded
        assert (ok.region, ok.region_source) == ("uk", "override")

    def test_forbidden_probe_is_not_called_unprovisioned(self) -> None:
        s = _session({r: {"/application-groups": _resp(403)} for r in SAA_REGIONS})
        inv = fetch_saa(s, "t1")
        assert inv.forbidden
        text = not_provisioned_text(inv)
        assert "HTTP 403" in text and "not provisioned" not in text

    def test_server_error_makes_absence_unprovable(self) -> None:
        s = _session({"uk": {"/application-groups": _resp(500), "/applications": _resp(500)}})
        inv = fetch_saa(s, "t1")
        assert not inv.provisioned and "uk" in inv.probe_failures
        assert not_provisioned_text(inv).startswith("Error: the SAA region probe failed")

    def test_several_regions_answering_reported(self) -> None:
        regions = {**_provisioned("uk"), **_provisioned("americas")}
        region, source, failures = find_region(_session(regions), "t1")
        assert region == "americas"  # first in SAA_REGIONS order
        assert source == "probed" and failures == {"uk": "also answered"}
        inv = SaaInventory(region=region, region_source=source, probe_failures=failures)
        assert "also answered in `uk`" in region_line(inv)


class TestFetch:
    def test_paginates_until_short_page(self) -> None:
        def apps(params: dict[str, Any]) -> Any:
            if params["offset"] == 0:
                return _page([{"app_id": f"a{i}"} for i in range(saa._PAGE_SIZE)], total=501)
            return _page([{"app_id": "last"}], total=501)

        inv = fetch_saa(_session(_provisioned(**{"/applications": apps})), "t1")
        assert len(inv.applications) == saa._PAGE_SIZE + 1
        assert inv.complete("applications")

    def test_page_limit_marks_truncated(self) -> None:
        full = _page([{"group_id": "g"}] * saa._PAGE_SIZE)
        inv = fetch_saa(_session(_provisioned(**{"/application-groups": full})), "t1", max_pages=2)
        assert "groups" in inv.truncated and len(inv.groups) == 2 * saa._PAGE_SIZE

    def test_policies_without_total_or_offset(self) -> None:
        inv = fetch_saa(
            _session(
                _provisioned(**{"/application-policies": _resp(200, {"data": [], "limit": 500})})
            ),
            "t1",
        )
        assert inv.policies == [] and inv.complete("policies")

    def test_bad_shape_marks_list_incomplete(self) -> None:
        inv = fetch_saa(
            _session(_provisioned(**{"/application-policies": _resp(200, {"data": {"x": 1}})})),
            "t1",
        )
        assert "policies" in inv.errors and not inv.complete("policies")

    def test_secrets_stripped_at_any_depth(self) -> None:
        app = {
            "app_id": "a1",
            "name": "jump-host",
            "type": "vnc",
            "vnc_settings": {
                "credentials": {"username": "svc", "password": "p"},
                "sftp_password": "s",
                "sftp_private_key": "k",
                "sftp_passphrase": "x",
                "has_credentials": {"has_password": True},
            },
            "ssh_settings": {"private_key": "k", "passphrase": "x"},
        }
        inv = fetch_saa(_session(_provisioned(**{"/applications": _page([app])})), "t1")
        got = inv.applications[0]
        assert got["vnc_settings"] == {
            "credentials": {"username": "svc"},
            "has_credentials": {"has_password": True},
        }
        assert got["ssh_settings"] == {}

    def test_sessions_skipped_when_not_wanted(self) -> None:
        s = _session(_provisioned())
        inv = fetch_saa(s, "t1", include_sessions=False)
        assert not inv.sessions_fetched
        assert not any("active-sessions" in c.args[0] for c in s.get.call_args_list)


def _inv(**kw: Any) -> SaaInventory:
    base: dict[str, Any] = {"region": "uk", "region_source": "probed"}
    base.update(kw)
    return SaaInventory(**base)


RDP_APP = {"app_id": "a1", "name": "rdp-1", "type": "rdp", "app_group_ids": ["g1"]}
SSH_APP = {"app_id": "a2", "name": "ssh-1", "type": "ssh", "ssh_settings": {"host_key": "AAAA"}}
GROUP = {"group_id": "g1", "name": "servers", "app_ids": ["a1"]}
OPEN_PROFILE = {
    "profile_id": "p1",
    "name": "open",
    "rdp": {"allow_file_upload": True, "allow_session_recording": False},
    "ssh": {"allow_file_download": True, "allow_session_recording": False},
}
POLICY = {
    "policy_id": "pol1",
    "name": "admins",
    "enabled": True,
    "profile_id": "p1",
    "app_group_ids": ["g1"],
    "rules": {"actions": [{"action": "allow", "user_groups": ["corp\\admins"]}]},
}


class TestRisks:
    def test_unprovisioned_has_no_risks(self) -> None:
        assert assess_saa(SaaInventory()) == []

    def test_profile_checks_count_only_reached_protocols(self) -> None:
        inv = _inv(
            applications=[RDP_APP],
            groups=[GROUP],
            profiles=[OPEN_PROFILE],
            policies=[POLICY],
        )
        findings = [r.finding for r in assess_saa(inv, NOW)]
        assert any("file transfer over RDP" in f for f in findings)
        assert any("does not record RDP sessions" in f for f in findings)
        # The policy reaches only an RDP app: SSH settings are not judged.
        assert not any("SSH" in f for f in findings)

    def test_dangling_references_and_empty_policy(self) -> None:
        bad = {
            "name": "stale",
            "enabled": True,
            "profile_id": "gone",
            "app_ids": ["missing-app"],
            "rules": {"actions": [{"action": "allow"}]},
        }
        empty = {"name": "nothing", "enabled": True, "profile_id": "p1", "rules": {}}
        inv = _inv(profiles=[OPEN_PROFILE], policies=[bad, empty])
        findings = {r.finding: r.severity for r in assess_saa(inv, NOW)}
        assert findings["Policy `stale` uses profile `gone`, which does not exist."] == "MEDIUM"
        assert any("targets 1 application(s)" in f for f in findings)
        assert "Policy `nothing` targets no applications or groups." in findings
        assert "Policy `stale` names no users or user groups." in findings

    def test_dangling_checks_skipped_when_lists_incomplete(self) -> None:
        bad = {"name": "stale", "enabled": True, "profile_id": "gone", "app_ids": ["x"]}
        inv = _inv(policies=[bad], errors={"profiles": "HTTP 500", "applications": "HTTP 500"})
        findings = [r.finding for r in assess_saa(inv, NOW)]
        assert not any("does not exist" in f or "no longer exist" in f for f in findings)

    def test_disabled_policy_and_unreachable_app(self) -> None:
        off = {**POLICY, "enabled": False}
        inv = _inv(applications=[RDP_APP], groups=[GROUP], profiles=[OPEN_PROFILE], policies=[off])
        findings = [r.finding for r in assess_saa(inv, NOW)]
        assert "Policy `admins` is disabled." in findings
        assert any("`rdp-1` is not reachable" in f for f in findings)
        assert any("group `servers` is not used" in f for f in findings)
        # A disabled policy's profile is not judged.
        assert not any("file transfer" in f for f in findings)

    def test_application_hardening(self) -> None:
        tls = {**RDP_APP, "rdp_settings": {"security_mode": "tls"}}
        unpinned = {**SSH_APP, "app_id": "a3", "ssh_settings": {}}
        inv = _inv(applications=[tls, unpinned, SSH_APP])
        findings = {r.finding: r.severity for r in assess_saa(inv, NOW)}
        assert findings["RDP application `rdp-1` uses TLS security mode, not NLA."] == "LOW"
        assert findings["SSH application `ssh-1` has no pinned host key."] == "MEDIUM"
        assert sum("host key" in f for f in findings) == 1

    def test_empty_group_and_long_session(self) -> None:
        inv = _inv(
            groups=[{"group_id": "g9", "name": "spare", "app_ids": []}],
            sessions=[
                {"start_time": "2026-10-14T00:00:00Z"},
                {"start_time": "2026-10-14T23:00:00Z"},
                {"start_time": "not a date"},
            ],
        )
        findings = [r.finding for r in assess_saa(inv, NOW)]
        assert "Application group `spare` is empty." in findings
        assert "1 active session(s) have run for over 12 hours." in findings

    def test_malformed_entries_do_not_abort(self) -> None:
        inv = _inv(
            applications=["junk", {"app_id": "a"}],
            policies=[None, {"name": "p", "rules": "bad", "app_ids": "x"}],
        )
        assess_saa(inv, NOW)  # no exception

    def test_sorted_and_headline(self) -> None:
        inv = _inv(
            applications=[{**SSH_APP, "ssh_settings": {}}],
            policies=[{**POLICY, "enabled": False}],
        )
        risks = assess_saa(inv, NOW)
        assert [r.severity for r in risks] == sorted(
            (r.severity for r in risks), key=lambda s: saa._SEVERITY_ORDER[s]
        )
        assert risk_headline(risks).startswith("**SAA risks:** 🟡 0 high · 1 medium")
        assert risk_headline([]) == "**SAA risks:** none found."

    def test_covered_apps_via_group_and_direct(self) -> None:
        direct = {**POLICY, "app_group_ids": [], "app_ids": ["a2"]}
        inv = _inv(groups=[GROUP], policies=[POLICY, direct])
        assert covered_apps(inv) == {"a1", "a2"}


class TestSections:
    def test_tables_resolve_names_and_hide_sessions(self) -> None:
        inv = _inv(
            applications=[
                {
                    **RDP_APP,
                    "destinations": [{"host": "10.0.0.5", "port": 3389}],
                    "rdp_settings": {"has_credentials": {"has_password": True}},
                    "updated_at": "2026-10-01T10:00:00Z",
                    "created_at": "2026-09-01T10:00:00Z",
                }
            ],
            groups=[GROUP],
            profiles=[OPEN_PROFILE],
            policies=[POLICY],
            sessions=[{"user_id": "someone", "app_id": "a1"}],
            sessions_fetched=True,
        )
        md = "\n".join(render_sections_markdown(saa_sections(inv, assess_saa(inv, NOW))))
        assert "| rdp-1 | rdp | 10.0.0.5:3389 | servers | stored |" in md
        assert "| servers | rdp-1 | 1 |" in md
        assert "| admins | ✓ | open | — | servers | 1 |" in md
        assert "Active Sessions (1)" in md and "| someone | rdp-1 |" in md
        assert "upload ✓" in md and "record ✗" in md
        hidden = "\n".join(render_sections_markdown(saa_sections(inv, [], include_sessions=False)))
        assert "Active Sessions" not in hidden and "someone" not in hidden

    def test_refused_and_incomplete_lists_say_so(self) -> None:
        inv = _inv(refused={"applications": 404}, errors={"policies": "page 2: timeout"})
        md = "\n".join(render_sections_markdown(saa_sections(inv, [])))
        assert "Refused by the API (HTTP 404)" in md
        assert "Access Policies (0+)" in md and "Incomplete — page 2: timeout" in md

    def test_cells_are_escaped(self) -> None:
        inv = _inv(groups=[{"group_id": "g", "name": "a|b", "description": "x\ny"}])
        md = "\n".join(render_sections_markdown(saa_sections(inv, [])))
        assert "a\\|b" in md and "x y" in md

    def test_changes_newest_first(self) -> None:
        inv = _inv(
            applications=[
                {"name": "old", "created_at": "2026-01-01T00:00:00Z"},
                {
                    "name": "new",
                    "created_at": "2026-02-01T00:00:00Z",
                    "updated_at": "2026-03-01T00:00:00Z",
                },
            ],
            groups=[{"name": "nodate"}],
        )
        rows = saa_changes(inv)
        assert [(r["name"], r["action"]) for r in rows] == [("new", "updated"), ("old", "created")]
