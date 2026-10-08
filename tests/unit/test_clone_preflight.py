"""Unit tests for the clone reference preflight (audit/clone_preflight.py)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from scm_harbourmaster_mcp.audit import cloner
from scm_harbourmaster_mcp.audit.clone_preflight import (
    TargetInventory,
    check_references,
    fetch_target_inventory,
)

# ── Fakes ─────────────────────────────────────────────────────────────────────


class FakeResp:
    def __init__(self, status: int, body: Any = None) -> None:
        self.status_code = status
        self._body = body if body is not None else {}
        self.headers: dict[str, str] = {}
        self.text = json.dumps(self._body)

    def json(self) -> Any:
        return self._body


class FakeSession:
    """Serves list calls by URL suffix; unknown URLs return an empty list."""

    def __init__(self, routes: dict[str, Any]) -> None:
        self.routes = routes
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def get(self, url: str, params: dict[str, Any] | None = None, timeout: Any = None) -> FakeResp:
        params = params or {}
        self.calls.append((url, params))
        for suffix, handler in self.routes.items():
            if url.endswith(suffix):
                return handler(params) if callable(handler) else handler
        return FakeResp(200, {"data": [], "total": 0})


def _inv(folder: str = "dst", unreadable: dict[str, str] | None = None, **names: set[str]):
    return TargetInventory(folder=folder, names=dict(names), unreadable=unreadable or {})


# Everything a typical rule references by default resolves
_BASE = {
    "application": {"web-browsing", "ssl"},
    "service": set(),
    "category": {"news"},
    "hip": set(),
    "profile_group": {"best-practice"},
    "log_setting": {"Cortex Data Lake"},
    "decryption_profile": set(),
}


def _base(**overrides: set[str]) -> dict[str, set[str]]:
    return {**{k: set(v) for k, v in _BASE.items()}, **overrides}


def _rule(name: str, action: str = "allow", **fields: Any) -> dict[str, Any]:
    rule = {
        "name": name,
        "action": action,
        "application": ["web-browsing"],
        "service": ["application-default"],
        "category": ["any"],
        "source_hip": ["any"],
        "destination_hip": ["any"],
        "profile_setting": {"group": ["best-practice"]},
        "log_setting": "Cortex Data Lake",
    }
    rule.update(fields)
    return rule


def _backup(tmp_path: Path, resources: dict[str, Any]) -> str:
    path = tmp_path / "backup.json"
    path.write_text(json.dumps({"backup_version": "1", "folder": "src", "resources": resources}))
    return str(path)


class FakeResource:
    def __init__(self) -> None:
        self.created: list[tuple[dict[str, Any], dict[str, Any]]] = []

    def create(self, data: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        self.created.append((data, kwargs))
        return data


class FakeClient:
    def __init__(self) -> None:
        self.resources: dict[str, FakeResource] = {}

    def __getattr__(self, name: str) -> FakeResource:
        if name.startswith("_"):
            raise AttributeError(name)
        return self.resources.setdefault(name, FakeResource())


# ── Inventory ────────────────────────────────────────────────────────────────


def test_app_catalogue_includes_container_names():
    apps = FakeResp(
        200,
        {
            "data": [
                {"name": "zoom-base", "container": "zoom"},
                {"name": "ssl", "container": None},
            ],
            "total": 2,
        },
    )
    inv = fetch_target_inventory(FakeSession({"/applications": apps}), "dst")
    assert {"zoom", "zoom-base", "ssl"} <= inv.names["application"]


def test_inventory_paginates_until_a_short_page():
    def pages(params: dict[str, Any]) -> FakeResp:
        offset = params["offset"]
        rows = [{"name": f"app-{offset + i}"} for i in range(1000 if offset < 2000 else 5)]
        return FakeResp(200, {"data": rows})

    inv = fetch_target_inventory(FakeSession({"/applications": pages}), "dst")
    assert len(inv.names["application"]) == 2005


def test_inventory_fetches_every_page_when_total_is_reported():
    def pages(params: dict[str, Any]) -> FakeResp:
        offset = params["offset"]
        rows = [{"name": f"app-{offset + i}"} for i in range(min(1000, 3500 - offset))]
        return FakeResp(200, {"data": rows, "total": 3500})

    session = FakeSession({"/applications": pages})
    inv = fetch_target_inventory(session, "dst")
    assert len(inv.names["application"]) == 3500
    offsets = sorted(p["offset"] for u, p in session.calls if u.endswith("/applications"))
    assert offsets == [0, 1000, 2000, 3000]


def test_a_failed_page_makes_the_catalogue_unreadable():
    def pages(params: dict[str, Any]) -> FakeResp:
        if params["offset"] == 2000:
            return FakeResp(502, {})
        return FakeResp(
            200,
            {"data": [{"name": f"a{params['offset']}-{i}"} for i in range(1000)], "total": 3000},
        )

    inv = fetch_target_inventory(FakeSession({"/applications": pages}), "dst")
    assert "502" in inv.unreadable["application"]


def test_unreadable_catalogue_is_recorded_not_emptied_silently():
    forbidden = FakeResp(403, {"_errors": [{"message": "Forbidden"}]})
    inv = fetch_target_inventory(FakeSession({"/data-filtering-profiles": forbidden}), "dst")
    assert "403" in inv.unreadable["data_filtering"]
    # No read API is wired for these at all
    assert "saas_security" in inv.unreadable and "ai_security" in inv.unreadable
    assert "application" not in inv.unreadable


def test_missing_target_folder_falls_back_to_all():
    def services(params: dict[str, Any]) -> FakeResp:
        if params["folder"] == "new-folder":
            return FakeResp(400, {"_errors": [{"details": {"message": "Folder does not exist"}}]})
        return FakeResp(200, {"data": [{"name": "service-http"}]})

    session = FakeSession({"/services": services})
    inv = fetch_target_inventory(session, "new-folder")
    assert inv.folder == "All"
    assert "service-http" in inv.names["service"]
    assert inv.notes and "does not exist" in inv.notes[0]


def test_shared_is_queried_as_prisma_access():
    session = FakeSession({})
    fetch_target_inventory(session, "Shared")
    assert {p["folder"] for _, p in session.calls} == {"Prisma Access"}


# ── Resolution ───────────────────────────────────────────────────────────────


def test_keywords_created_objects_and_inventory_resolve():
    resources = {
        "application_groups": [{"name": "grp", "members": ["ssl"]}],
        "security_rules_pre": [_rule("r1", application=["grp", "any"])],
    }
    result = check_references(
        resources, ["application_groups", "security_rules_pre"], _inv(**_base())
    )
    assert result.issues == [] and not result.blocked


def test_predefined_backup_objects_resolve_but_source_app_catalogue_does_not():
    resources = {
        "hip_profiles": [{"name": "is-win", "snippet": "predefined-snippet"}],
        "applications": [{"name": "retired-app", "snippet": "predefined-snippet"}],
        "security_rules_pre": [_rule("r1", application=["retired-app"], source_hip=["is-win"])],
    }
    result = check_references(resources, ["security_rules_pre"], _inv(**_base()))
    assert [(i.kind, i.name) for i in result.missing] == [("application", "retired-app")]
    assert "retired App-ID" in result.missing[0].detail


def test_fail_mode_blocks_and_lists_every_missing_reference():
    resources = {
        "application_groups": [{"name": "grp", "members": ["ssl", "gone-1", "gone-2"]}],
        "security_rules_pre": [_rule("r1", service=["svc-missing"])],
    }
    result = check_references(
        resources, ["application_groups", "security_rules_pre"], _inv(**_base())
    )
    assert result.blocked
    assert sorted(i.name for i in result.missing) == ["gone-1", "gone-2", "svc-missing"]
    assert result.skip == {} and result.strip == {}


def test_unverifiable_references_do_not_block():
    resources = {
        "profile_groups": [{"name": "pg", "data_filtering": ["dlp-1"], "spyware": ["as-1"]}],
    }
    inv = _inv(
        **_base(spyware={"as-1"}),
        unreadable={"data_filtering": "data-filtering-profiles: HTTP 403: Forbidden"},
    )
    result = check_references(resources, ["profile_groups"], inv)
    assert not result.blocked
    assert [(i.name, i.status) for i in result.issues] == [("dlp-1", "unverifiable")]
    assert "data_filtering" in result.unreadable


def test_skip_object_cascades_to_dependants():
    resources = {
        "application_groups": [{"name": "grp", "members": ["gone"]}],
        "security_rules_pre": [_rule("uses-grp", application=["grp"]), _rule("fine")],
    }
    result = check_references(
        resources,
        ["application_groups", "security_rules_pre"],
        _inv(**_base()),
        on_missing_reference="skip_object",
    )
    assert not result.blocked
    assert set(result.skip) == {
        ("application_groups", "grp"),
        ("security_rules_pre", "uses-grp"),
    }
    cascaded = next(i for i in result.issues if i.referrer == "uses-grp")
    assert "skipped by preflight" in cascaded.detail


def test_strip_member_on_group_and_allow_rule():
    resources = {
        "application_groups": [{"name": "grp", "members": ["ssl", "gone"]}],
        "security_rules_pre": [_rule("r1", application=["web-browsing", "gone"])],
    }
    result = check_references(
        resources,
        ["application_groups", "security_rules_pre"],
        _inv(**_base()),
        on_missing_reference="strip_member",
    )
    assert result.skip == {}
    assert result.strip == {
        ("application_groups", "grp"): {"members": {"gone"}},
        ("security_rules_pre", "r1"): {"application": {"gone"}},
    }


def test_strip_member_never_narrows_a_deny_rule():
    resources = {"security_rules_pre": [_rule("block", action="deny", application=["ssl", "gone"])]}
    result = check_references(
        resources, ["security_rules_pre"], _inv(**_base()), on_missing_reference="strip_member"
    )
    assert ("security_rules_pre", "block") in result.skip
    assert result.strip == {}


def test_strip_member_skips_when_the_list_would_be_empty():
    resources = {"application_groups": [{"name": "grp", "members": ["gone"]}]}
    result = check_references(
        resources, ["application_groups"], _inv(**_base()), on_missing_reference="strip_member"
    )
    assert "empty" in result.skip[("application_groups", "grp")]


def test_strip_member_skips_objects_with_singular_references():
    # Dropping a profile group from a rule would remove its threat inspection
    resources = {"security_rules_pre": [_rule("r1", profile_setting={"group": ["gone-pg"]})]}
    result = check_references(
        resources, ["security_rules_pre"], _inv(**_base()), on_missing_reference="strip_member"
    )
    assert ("security_rules_pre", "r1") in result.skip


def test_stripped_group_used_by_a_deny_rule_warns():
    resources = {
        "application_groups": [{"name": "bad-apps", "members": ["ssl", "gone"]}],
        "security_rules_pre": [_rule("block-bad", action="deny", application=["bad-apps"])],
    }
    result = check_references(
        resources,
        ["application_groups", "security_rules_pre"],
        _inv(**_base()),
        on_missing_reference="strip_member",
    )
    assert ("application_groups", "bad-apps") in result.strip
    assert any("block-bad" in w for w in result.warnings)


def test_name_prefix_hint_when_reference_points_at_a_renamed_clone():
    resources = {
        "application_groups": [{"name": "grp", "members": ["ssl"]}],
        "security_rules_pre": [_rule("r1", application=["grp"])],
    }
    result = check_references(
        resources,
        ["application_groups", "security_rules_pre"],
        _inv(**_base()),
        name_prefix="C1_",
    )
    [issue] = result.missing
    assert "C1_grp" in issue.detail


def test_only_planned_keys_are_checked_or_counted_as_created():
    resources = {
        "application_groups": [{"name": "grp", "members": ["gone"]}],
        "security_rules_pre": [_rule("r1", application=["grp"])],
    }
    # resource_filter excluded the groups: they are neither checked nor created
    result = check_references(resources, ["security_rules_pre"], _inv(**_base()))
    assert [i.name for i in result.missing] == ["grp"]


# ── Forward-trust prerequisite ───────────────────────────────────────────────


def _decrypt_rule(name: str, **fields: Any) -> dict[str, Any]:
    rule = {"name": name, "action": "decrypt", "disabled": False, "service": ["any"]}
    rule.update(fields)
    return rule


def test_enabled_decrypt_rule_without_trust_cert_blocks_by_default():
    resources = {"decryption_rules": [_decrypt_rule("d1"), _decrypt_rule("off", disabled=True)]}
    result = check_references(
        resources, ["decryption_rules"], _inv(**_base()), trust_state=lambda: "missing"
    )
    assert result.blocked and result.decrypt_rules == ["d1"]


def test_disable_rule_mode_creates_decrypt_rules_disabled():
    resources = {"decryption_rules": [_decrypt_rule("d1")]}
    result = check_references(
        resources,
        ["decryption_rules"],
        _inv(**_base()),
        trust_state=lambda: "missing",
        on_missing_trust_cert="disable_rule",
    )
    assert not result.blocked and result.disable == {("decryption_rules", "d1")}


def test_unknown_trust_state_warns_without_blocking():
    resources = {"decryption_rules": [_decrypt_rule("d1")]}
    result = check_references(
        resources, ["decryption_rules"], _inv(**_base()), trust_state=lambda: "unknown"
    )
    assert not result.blocked and result.warnings


def test_trust_state_not_read_without_enabled_decrypt_rules():
    def boom() -> str:
        raise AssertionError("trust state read unnecessarily")

    resources = {"decryption_rules": [_decrypt_rule("nd", action="no-decrypt")]}
    result = check_references(resources, ["decryption_rules"], _inv(**_base()), trust_state=boom)
    assert not result.blocked


# ── Cloner integration ───────────────────────────────────────────────────────


def test_blocked_real_run_pushes_nothing(tmp_path):
    src = _backup(
        tmp_path,
        {
            "tags": [{"name": "t1"}],
            "application_groups": [{"name": "grp", "members": ["gone"]}],
        },
    )
    client = FakeClient()
    report = cloner.clone_config(
        client,
        src,
        "dst",
        dry_run=False,
        on_missing_reference="fail",
        inventory=_inv(**_base()),
    )
    assert report.results == [] and client.resources == {}
    md = report.to_markdown()
    assert "BLOCKED BY PREFLIGHT" in md and "`gone`" in md


def test_blocked_dry_run_still_previews(tmp_path):
    src = _backup(tmp_path, {"application_groups": [{"name": "grp", "members": ["gone"]}]})
    report = cloner.clone_config(
        FakeClient(),
        src,
        "dst",
        dry_run=True,
        on_missing_reference="fail",
        inventory=_inv(**_base()),
    )
    assert [r.status for r in report.results] == ["dry_run"]
    assert "A real run would stop here" in report.to_markdown()


def test_skip_and_strip_are_applied_to_the_push(tmp_path):
    src = _backup(
        tmp_path,
        {
            "application_groups": [
                {"name": "keep", "members": ["ssl", "gone"]},
                {"name": "drop", "members": ["gone"]},
            ],
        },
    )
    client = FakeClient()
    report = cloner.clone_config(
        client,
        src,
        "dst",
        dry_run=False,
        on_missing_reference="strip_member",
        inventory=_inv(**_base()),
    )
    [(payload, _)] = client.resources["application_group"].created
    assert payload["name"] == "keep" and payload["members"] == ["ssl"]
    statuses = {r.name: (r.status, r.detail) for r in report.results}
    assert statuses["drop"][0] == "ref_skipped"
    assert "stripped members: gone" in statuses["keep"][1]


def test_disabled_decrypt_rule_is_pushed_disabled(tmp_path, monkeypatch):
    src = _backup(tmp_path, {"decryption_rules": [_decrypt_rule("d1")]})
    monkeypatch.setattr(
        "scm_harbourmaster_mcp.audit.extractor._bearer_session_for", lambda client: object()
    )
    monkeypatch.setattr(
        "scm_harbourmaster_mcp.tools.tenant_copy._forward_trust_state", lambda session: "missing"
    )
    client = FakeClient()
    cloner.clone_config(
        client,
        src,
        "dst",
        dry_run=False,
        on_missing_reference="fail",
        on_missing_trust_cert="disable_rule",
        inventory=_inv(**_base()),
    )
    [(payload, _)] = client.resources["decryption_rule"].created
    assert payload["disabled"] is True


def test_preflight_off_by_default_for_library_callers(tmp_path):
    src = _backup(tmp_path, {"application_groups": [{"name": "grp", "members": ["gone"]}]})
    report = cloner.clone_config(FakeClient(), src, "dst", dry_run=False)
    assert report.preflight is None and report.results[0].status == "created"


def test_invalid_mode_is_rejected(tmp_path):
    src = _backup(tmp_path, {"tags": [{"name": "t"}]})
    with pytest.raises(ValueError, match="on_missing_reference"):
        cloner.clone_config(
            FakeClient(), src, "dst", on_missing_reference="ignore", inventory=_inv()
        )
