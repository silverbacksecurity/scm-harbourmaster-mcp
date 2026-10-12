"""Clone follow-ups: address/zone/tag references, application filters, the
name_prefix reference rewrite, and custom-apps-only backups.

All names are placeholders.  Backups store SDK field names, so rule zones are
``from_``/``to_`` and PAN content is ``snippet: "predefined-snippet"``.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any

import pytest

from scm_harbourmaster_mcp.audit import cloner
from scm_harbourmaster_mcp.audit.clone_preflight import (
    REFERENCE_FIELDS,
    TargetInventory,
    _expression_names,
    _rewrite_expression,
    check_references,
    is_ip_literal,
    rewrite_references,
)
from scm_harbourmaster_mcp.audit.extractor import backup_resource_payload
from scm_harbourmaster_mcp.audit.models import AuditSnapshot

PREDEFINED = "predefined-snippet"


def _inv(**names: set[str]) -> TargetInventory:
    base: dict[str, set[str]] = {
        "application": {"web-browsing"},
        "service": set(),
        "category": set(),
        "hip": set(),
        "profile_group": set(),
        "log_setting": set(),
        "address": {"DE", "corp-net"},
        "zone": {"zone-internal"},
        "tag": {"prod"},
    }
    base.update(names)
    return TargetInventory(folder="dst", names=base)


def _rule(name: str, action: str = "allow", **fields: Any) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "name": name,
        "action": action,
        "from_": ["trust"],
        "to_": ["untrust"],
        "source": ["any"],
        "destination": ["any"],
        "application": ["web-browsing"],
        "service": ["application-default"],
    }
    rule.update(fields)
    return rule


# ── Reference table vs the SDK models ────────────────────────────────────────

# Backup key → (module, create model).  REST-only types are left out.
_MODELS = {
    "addresses": ("scm.models.objects.address", "AddressCreateModel"),
    "address_groups": ("scm.models.objects.address_group", "AddressGroupCreateModel"),
    "services": ("scm.models.objects.service", "ServiceCreateModel"),
    "service_groups": ("scm.models.objects.service_group", "ServiceGroupCreateModel"),
    "application_groups": ("scm.models.objects.application_group", "ApplicationGroupCreateModel"),
    "url_access_profiles": (
        "scm.models.security.url_access_profiles",
        "URLAccessProfileCreateModel",
    ),
    "security_rules_pre": ("scm.models.security.security_rules", "SecurityRuleCreateModel"),
    "security_rules_post": ("scm.models.security.security_rules", "SecurityRuleCreateModel"),
    "nat_rules_pre": ("scm.models.network.nat_rules", "NatRuleCreateModel"),
    "nat_rules_post": ("scm.models.network.nat_rules", "NatRuleCreateModel"),
    "nat_rules": ("scm.models.network.nat_rules", "NatRuleCreateModel"),
    "decryption_rules": ("scm.models.security.decryption_rules", "DecryptionRuleCreateModel"),
    "app_override_rules": ("scm.models.security.app_override_rules", "AppOverrideRuleCreateModel"),
}


@pytest.mark.parametrize("key", sorted(_MODELS))
def test_reference_paths_exist_on_the_sdk_model(key: str) -> None:
    module, name = _MODELS[key]
    model = getattr(importlib.import_module(module), name)
    known = set(model.model_fields) | {f.alias for f in model.model_fields.values() if f.alias}
    for ref in REFERENCE_FIELDS[key]:
        assert ref.field.split(".")[0] in known, (key, ref.field)


def test_every_referencing_key_has_a_model_or_is_rest_only() -> None:
    assert set(REFERENCE_FIELDS) - set(_MODELS) == {"profile_groups"}


# ── Literals and expressions ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    "value", ["192.0.2.10", "192.0.2.0/24", "192.0.2.1-192.0.2.9", "2001:db8::/32", "2001:db8::1"]
)
def test_ip_literals(value: str) -> None:
    assert is_ip_literal(value)


@pytest.mark.parametrize("value", ["corp-net", "cafe", "DE", "web-1-2", ""])
def test_names_are_not_literals(value: str) -> None:
    assert not is_ip_literal(value)


def test_expression_names_and_rewrite() -> None:
    expr = "'web servers' and (prod or not \"old\")"
    assert _expression_names(expr) == ["web servers", "prod", "old"]
    assert _rewrite_expression(expr, {"web servers": "C_web servers", "prod": "C_prod"}) == (
        "'C_web servers' and (C_prod or not \"old\")"
    )
    assert _rewrite_expression("a and b", {"a": "x y"}) == "'x y' and b"


# ── Preflight: addresses, zones, tags ────────────────────────────────────────


def test_builtin_zones_literals_and_regions_resolve() -> None:
    rule = _rule("r", source=["192.0.2.0/24", "DE", "corp-net"], destination=["2001:db8::1"])
    result = check_references({"security_rules_pre": [rule]}, ["security_rules_pre"], _inv())
    assert result.issues == []


def test_missing_zone_address_and_tag_are_reported() -> None:
    rule = _rule("r", from_=["zone-gone"], destination=["srv-gone"], tag=["tag-gone"])
    result = check_references({"security_rules_pre": [rule]}, ["security_rules_pre"], _inv())
    assert sorted((i.kind, i.name) for i in result.missing) == [
        ("address", "srv-gone"),
        ("tag", "tag-gone"),
        ("zone", "zone-gone"),
    ]
    assert result.blocked


def test_cloned_objects_satisfy_references() -> None:
    resources = {
        "tags": [{"name": "web"}],
        "zones": [{"name": "dmz"}],
        "addresses": [{"name": "srv", "ip_netmask": "192.0.2.1/32", "tag": ["web"]}],
        "address_groups": [{"name": "dag", "dynamic": {"filter": "'web' and 'prod'"}}],
        "edls": [{"name": "bad-ips"}],
        "security_rules_pre": [
            _rule("r", to_=["dmz"], destination=["srv", "dag"], source=["bad-ips"])
        ],
    }
    keys = list(resources)
    assert check_references(resources, keys, _inv()).issues == []


def test_dynamic_group_filter_tags_are_checked() -> None:
    resources = {"address_groups": [{"name": "dag", "dynamic": {"filter": "'gone' or prod"}}]}
    [issue] = check_references(resources, ["address_groups"], _inv()).missing
    assert (issue.kind, issue.name, issue.field) == ("tag", "gone", "dynamic.filter")


def test_nat_translation_addresses_are_checked_and_never_stripped() -> None:
    nat = {
        "name": "n",
        "from_": ["trust"],
        "to_": ["untrust"],
        "source": ["any"],
        "destination": ["any"],
        "service": "any",
        "source_translation": {"dynamic_ip_and_port": {"translated_address": ["egress-gone"]}},
        "destination_translation": {"translated_address": "192.0.2.5"},
    }
    result = check_references(
        {"nat_rules_pre": [nat]}, ["nat_rules_pre"], _inv(), on_missing_reference="strip_member"
    )
    [issue] = result.missing
    assert issue.name == "egress-gone" and issue.action == "skipped"
    assert ("nat_rules_pre", "n") in result.skip


def test_strip_from_allow_rule_source() -> None:
    rule = _rule("r", source=["corp-net", "gone"])
    result = check_references(
        {"security_rules_pre": [rule]},
        ["security_rules_pre"],
        _inv(),
        on_missing_reference="strip_member",
    )
    assert result.strip[("security_rules_pre", "r")] == {"source": {"gone"}}


def test_no_strip_from_negated_source() -> None:
    rule = _rule("r", source=["corp-net", "gone"], negate_source=True)
    result = check_references(
        {"security_rules_pre": [rule]},
        ["security_rules_pre"],
        _inv(),
        on_missing_reference="strip_member",
    )
    assert ("security_rules_pre", "r") in result.skip
    assert "narrow" in result.skip[("security_rules_pre", "r")]


def test_stripped_address_group_warns_for_nat_and_negated_rules() -> None:
    resources = {
        "address_groups": [{"name": "grp", "static": ["corp-net", "gone"]}],
        "security_rules_pre": [
            _rule("plain", destination=["grp"]),
            _rule("negated", destination=["grp"], negate_destination=True),
        ],
        "nat_rules_pre": [{"name": "nat", "source": ["grp"], "destination": ["any"]}],
    }
    result = check_references(
        resources, list(resources), _inv(), on_missing_reference="strip_member"
    )
    [warning] = result.warnings
    assert "`negated`" in warning and "`nat`" in warning and "`plain`" not in warning


def test_application_filters_satisfy_application_references() -> None:
    resources = {
        "application_filters": [{"name": "risky", "risk": [5]}],
        "security_rules_pre": [_rule("r", application=["risky"])],
    }
    assert check_references(resources, list(resources), _inv()).issues == []


def test_missing_application_hint_says_custom_apps_are_not_cloned() -> None:
    resources = {"security_rules_pre": [_rule("r", application=["custom-app"])]}
    [issue] = check_references(resources, ["security_rules_pre"], _inv()).missing
    assert "custom application" in issue.detail and "does not create" in issue.detail


# ── Rewrite ──────────────────────────────────────────────────────────────────


def test_rewrite_references_covers_nested_lists_strings_and_expressions() -> None:
    renames = {"address": {"srv": "C_srv"}, "zone": {"dmz": "C_dmz"}, "tag": {"web": "C_web"}}
    nat = {
        "to_": ["dmz", "untrust"],
        "destination": ["srv"],
        "source_translation": {"static_ip": {"translated_address": "srv"}},
        "tag": ["web"],
    }
    rewrite_references("nat_rules_pre", nat, renames)
    assert nat == {
        "to_": ["C_dmz", "untrust"],
        "destination": ["C_srv"],
        "source_translation": {"static_ip": {"translated_address": "C_srv"}},
        "tag": ["C_web"],
    }
    dag = {"dynamic": {"filter": "'web' and prod"}}
    rewrite_references("address_groups", dag, renames)
    assert dag["dynamic"]["filter"] == "'C_web' and prod"


# ── Cloner ───────────────────────────────────────────────────────────────────


class _Resp:
    status_code = 201
    ok = True
    text = "{}"
    content = b"{}"

    def json(self) -> Any:
        return {}


class _Session:
    def __init__(self) -> None:
        self.posts: list[tuple[str, Any]] = []

    def post(self, url: str, json: Any = None, timeout: Any = None) -> _Resp:
        self.posts.append((url, json))
        return _Resp()


class _Resource:
    def __init__(self, sink: list[tuple[str, dict[str, Any]]], attr: str) -> None:
        self.sink, self.attr = sink, attr

    def create(self, data: dict[str, Any], **kwargs: Any) -> Any:
        self.sink.append((self.attr, data))
        return data


class _Client:
    def __init__(self) -> None:
        self.created: list[tuple[str, dict[str, Any]]] = []
        self.session = _Session()

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        return _Resource(self.created, name)


def _backup(tmp_path: Path, resources: dict[str, Any]) -> str:
    path = tmp_path / "backup.json"
    path.write_text(json.dumps({"backup_version": "1", "folder": "src", "resources": resources}))
    return str(path)


def test_name_prefix_rewrites_references_to_cloned_objects(tmp_path: Path) -> None:
    src = _backup(
        tmp_path,
        {
            "tags": [{"name": "web", "folder": "src"}],
            "addresses": [{"name": "srv", "ip_netmask": "192.0.2.1/32", "tag": ["web"]}],
            "address_groups": [
                {"name": "dag", "dynamic": {"filter": "'web'"}},
                {"name": "grp", "static": ["srv", "other"]},
            ],
            "security_rules_pre": [
                _rule("r", destination=["grp", "elsewhere"], tag=["web"], from_=["trust"])
            ],
        },
    )
    client = _Client()
    cloner.clone_config(client, src, "dst", name_prefix="C_", dry_run=False)
    made = {data["name"]: data for _, data in client.created}
    assert made["C_srv"]["tag"] == ["C_web"]
    assert made["C_dag"]["dynamic"]["filter"] == "'C_web'"
    assert made["C_grp"]["static"] == ["C_srv", "other"]
    rule = made["C_r"]
    assert rule["destination"] == ["C_grp", "elsewhere"]
    assert rule["tag"] == ["C_web"] and rule["from_"] == ["trust"]


def test_preflight_skipped_objects_are_not_rename_targets(tmp_path: Path) -> None:
    src = _backup(
        tmp_path,
        {
            "address_groups": [{"name": "grp", "static": ["gone"]}],
            "security_rules_pre": [_rule("r", destination=["grp", "corp-net"])],
        },
    )
    client = _Client()
    cloner.clone_config(
        client,
        src,
        "dst",
        name_prefix="C_",
        dry_run=False,
        on_missing_reference="strip_member",
        inventory=_inv(),
    )
    made = {data["name"]: data for _, data in client.created}
    assert "C_grp" not in made  # emptied group → skipped
    assert made["C_r"]["destination"] == ["corp-net"]  # grp stripped, not renamed


def test_application_filters_are_pushed_over_rest_before_groups(tmp_path: Path) -> None:
    src = _backup(
        tmp_path,
        {
            "application_groups": [{"name": "apps", "members": ["risky"]}],
            "application_filters": [
                {"name": "risky", "folder": "All", "snippet": "Some-Snippet", "risk": [5]},
                {"name": "pan", "folder": "All", "snippet": PREDEFINED, "new_appid": True},
                {"name": "web", "tagging": {"tag": ["[Web App]"]}},
            ],
        },
    )
    client = _Client()
    report = cloner.clone_config(client, src, "dst", dry_run=False)
    posts = client.session.posts
    assert [p[1]["name"] for p in posts] == ["risky", "web"]
    assert all(p[0].endswith("/config/objects/v1/application-filters") for p in posts)
    assert posts[0][1] == {"name": "risky", "folder": "dst", "risk": [5]}
    assert posts[1][1]["tagging"] == {"tag": ["[Web App]"]}
    assert [a for a, _ in client.created] == ["application_group"]
    assert report.predefined == 1


# ── Backup payload ───────────────────────────────────────────────────────────


def test_backup_keeps_custom_apps_and_application_filters() -> None:
    snap = AuditSnapshot(folder="f", tenant_id="t")
    snap.applications = [
        {"name": "pan-app", "snippet": PREDEFINED},
        {"name": "custom-app", "folder": "f"},
    ]
    snap.application_filters = [{"name": "risky", "risk": [5]}]
    payload = backup_resource_payload(snap)
    assert [a["name"] for a in payload["applications"]] == ["custom-app"]
    assert payload["application_filters"] == [{"name": "risky", "risk": [5]}]
    # The snapshot itself keeps the catalogue for the config index
    assert len(snap.applications) == 2


def test_rewrite_happens_before_ip_anonymisation(tmp_path: Path) -> None:
    src = _backup(
        tmp_path,
        {
            "addresses": [{"name": "H-192.0.2.1", "ip_netmask": "192.0.2.1/32"}],
            "security_rules_pre": [_rule("r", destination=["H-192.0.2.1"])],
        },
    )
    client = _Client()
    cloner.clone_config(client, src, "dst", name_prefix="C_", anonymise_ips=True, dry_run=False)
    made = {data["name"]: data for _, data in client.created}
    assert made["C_r"]["destination"] == ["C_H-{{IP_1}}"]
    assert "C_H-{{IP_1}}" in made


def test_predefined_url_categories_resolve_from_their_own_list() -> None:
    session_rows = {
        "/url-filtering-categories": [{"value": "scanning-activity", "type": "pan-url-categories"}],
    }

    class _S:
        def get(self, url: str, params: Any = None, timeout: Any = None) -> Any:
            body = next((v for k, v in session_rows.items() if url.endswith(k)), {"data": []})

            class R:
                status_code = 200
                headers: dict[str, str] = {}

                def json(self) -> Any:
                    return body

            return R()

    from scm_harbourmaster_mcp.audit.clone_preflight import fetch_target_inventory

    inv = fetch_target_inventory(_S(), "dst")
    assert "scanning-activity" in inv.names["category"]


# ── PAN snippets other than predefined-snippet ───────────────────────────────

_SNIPPET_TYPES = {
    "predefined-snippet": "",
    "Web-Security-Default": "predefined",
    "hip-default": "readonly",
}


def _snippet_backup(tmp_path: Path, resources: dict[str, Any], **extra: Any) -> str:
    path = tmp_path / "backup.json"
    path.write_text(
        json.dumps({"backup_version": "1", "folder": "src", "resources": resources, **extra})
    )
    return str(path)


def test_objects_from_pan_snippets_are_not_cloned(tmp_path: Path) -> None:
    src = _snippet_backup(
        tmp_path,
        {
            "tags": [
                {"name": "pan-tag", "snippet": "Web-Security-Default"},
                {"name": "own-tag", "snippet": "Customer-Snippet"},
                {"name": "plain", "folder": "src"},
            ],
            "hip_objects": [{"name": "pan-hip", "snippet": "hip-default"}],
        },
        snippet_types=_SNIPPET_TYPES,
    )
    client = _Client()
    report = cloner.clone_config(client, src, "dst", dry_run=False)
    assert [d["name"] for _, d in client.created] == ["own-tag", "plain"]
    assert report.predefined == 2
    by_name = {r.name: r for r in report.results}
    assert "`Web-Security-Default`" in by_name["pan-tag"].detail
    assert "`hip-default`" in by_name["pan-hip"].detail
    assert "custom snippet `Customer-Snippet`" in by_name["own-tag"].detail


def test_legacy_backup_reads_snippet_types_from_the_target(tmp_path: Path) -> None:
    src = _snippet_backup(
        tmp_path, {"tags": [{"name": "pan-tag", "snippet": "Web-Security-Default"}]}
    )

    class _Snippets:
        def list(self) -> list[Any]:
            row = type("Row", (), {"name": "Web-Security-Default", "type": "predefined"})
            return [row()]

    client = _Client()
    client.snippet = _Snippets()  # type: ignore[attr-defined]
    report = cloner.clone_config(client, src, "dst", dry_run=False)
    assert client.created == [] and report.predefined == 1


def test_preflight_checks_pan_snippet_objects_against_the_target() -> None:
    resources = {
        "profile_groups": [{"name": "best-practice", "snippet": "Web-Security-Default"}],
        "security_rules_pre": [_rule("r", profile_setting={"group": ["best-practice"]})],
    }
    keys = ["profile_groups", "security_rules_pre"]
    # Not created by the clone and not visible from the target folder
    [issue] = check_references(resources, keys, _inv(), snippet_types=_SNIPPET_TYPES).missing
    assert issue.name == "best-practice" and "`Web-Security-Default`" in issue.detail
    # The snippet is associated with the target folder
    inv = _inv(profile_group={"best-practice"})
    assert check_references(resources, keys, inv, snippet_types=_SNIPPET_TYPES).issues == []
    # Without the type map the group is customer content the clone creates
    assert check_references(resources, keys, _inv()).issues == []


def test_name_prefix_leaves_references_to_pan_snippet_objects(tmp_path: Path) -> None:
    src = _snippet_backup(
        tmp_path,
        {
            "tags": [{"name": "pan-tag", "snippet": "Web-Security-Default"}, {"name": "web"}],
            "addresses": [{"name": "srv", "ip_netmask": "192.0.2.1/32", "tag": ["pan-tag", "web"]}],
        },
        snippet_types=_SNIPPET_TYPES,
    )
    client = _Client()
    cloner.clone_config(client, src, "dst", name_prefix="C_", dry_run=False)
    made = {data["name"]: data for _, data in client.created}
    assert set(made) == {"C_web", "C_srv"}
    assert made["C_srv"]["tag"] == ["pan-tag", "C_web"]


def test_backup_records_snippet_types() -> None:
    from scm_harbourmaster_mcp.audit.extractor import backup_snippet_types

    snap = AuditSnapshot(folder="f", tenant_id="t")
    snap.scm_snippets = [
        {"name": "predefined-snippet", "type": None},
        {"name": "hip-default", "type": "readonly"},
        {"name": "Customer-Snippet", "type": "custom"},
    ]
    assert backup_snippet_types(snap) == {"hip-default": "readonly", "Customer-Snippet": "custom"}


def test_empty_recorded_snippet_types_fall_back_to_the_target(tmp_path: Path) -> None:
    src = _snippet_backup(
        tmp_path,
        {"tags": [{"name": "pan-tag", "snippet": "Web-Security-Default"}]},
        snippet_types={},
    )

    class _Snippets:
        def list(self) -> list[Any]:
            return [type("Row", (), {"name": "Web-Security-Default", "type": "predefined"})()]

    client = _Client()
    client.snippet = _Snippets()  # type: ignore[attr-defined]
    report = cloner.clone_config(client, src, "dst", dry_run=False)
    assert client.created == [] and report.predefined == 1 and not report.warnings


def test_unreadable_snippet_types_are_reported(tmp_path: Path) -> None:
    src = _snippet_backup(tmp_path, {"tags": [{"name": "t", "snippet": "Web-Security-Default"}]})

    class _Snippets:
        def list(self) -> list[Any]:
            raise RuntimeError("HTTP 403")

    client = _Client()
    client.snippet = _Snippets()  # type: ignore[attr-defined]
    report = cloner.clone_config(client, src, "dst", dry_run=True)
    assert report.warnings and "could not be read" in report.to_markdown()


def test_predefined_override_reads_as_global_pan_content(tmp_path: Path) -> None:
    src = _snippet_backup(
        tmp_path,
        {"edls": [{"name": "o365", "snippet": "office365", "override_loc": PREDEFINED}]},
        snippet_types=_SNIPPET_TYPES,
    )
    report = cloner.clone_config(_Client(), src, "dst", dry_run=True)
    [result] = report.results
    assert result.status == "predefined" and "every tenant" in result.detail
