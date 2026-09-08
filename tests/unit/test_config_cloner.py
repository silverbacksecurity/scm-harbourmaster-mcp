"""Unit tests for the SCM config cloner (audit/cloner.py)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from scm_harbourmaster_mcp.audit import cloner


class FakeResource:
    """Records create/fetch/update calls made by the cloner."""

    def __init__(self, update_model: type | None = None) -> None:
        self.created: list[tuple[dict[str, Any], dict[str, Any]]] = []
        self.updated: list[tuple[Any, dict[str, Any]]] = []
        self.fetched: list[dict[str, Any]] = []
        self._update_model = update_model

    def create(self, data: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        self.created.append((data, kwargs))
        return data

    def fetch(self, **kwargs: Any) -> Any:
        self.fetched.append(kwargs)
        return type("Existing", (), {"id": "abc-123"})()

    def update(self, rule: Any, **kwargs: Any) -> Any:
        self.updated.append((rule, kwargs))
        return rule


class FakeClient:
    def __init__(self) -> None:
        self.resources: dict[str, FakeResource] = {}

    def __getattr__(self, name: str) -> FakeResource:
        if name.startswith("_"):
            raise AttributeError(name)
        return self.resources.setdefault(name, FakeResource())


def _backup(tmp_path: Path, resources: dict[str, list[dict[str, Any]]]) -> str:
    path = tmp_path / "backup.json"
    path.write_text(json.dumps({"backup_version": "1", "folder": "src", "resources": resources}))
    return str(path)


# ── rulebase / position kwargs ────────────────────────────────────────────


def test_rules_pass_rulebase_as_kwarg_not_payload(tmp_path):
    client = FakeClient()
    src = _backup(
        tmp_path,
        {
            "security_rules_pre": [{"name": "pre-1", "folder": "src"}],
            "security_rules_post": [{"name": "post-1", "folder": "src"}],
            "decryption_rules": [{"name": "dec-1", "folder": "src"}],
            "app_override_rules": [{"name": "app-1", "folder": "src"}],
        },
    )
    cloner.clone_config(client, src, "dst", dry_run=False)

    sec = client.resources["security_rule"].created
    assert [kwargs for _, kwargs in sec] == [{"rulebase": "pre"}, {"rulebase": "post"}]
    assert all("position" not in payload for payload, _ in sec)
    assert client.resources["decryption_rule"].created[0][1] == {"rulebase": "pre"}
    assert client.resources["app_override_rule"].created[0][1] == {"rulebase": "pre"}


def test_nat_rules_use_position_kwarg(tmp_path):
    client = FakeClient()
    src = _backup(
        tmp_path,
        {
            "nat_rules_pre": [{"name": "nat-pre", "folder": "src"}],
            "nat_rules_post": [{"name": "nat-post", "folder": "src"}],
        },
    )
    cloner.clone_config(client, src, "dst", dry_run=False)

    calls = client.resources["nat_rule"].created
    assert [(p["name"], k) for p, k in calls] == [
        ("nat-pre", {"position": "pre"}),
        ("nat-post", {"position": "post"}),
    ]


def test_legacy_flat_nat_key_is_replayed_as_pre(tmp_path):
    client = FakeClient()
    src = _backup(tmp_path, {"nat_rules": [{"name": "legacy-nat", "folder": "src"}]})
    cloner.clone_config(client, src, "dst", dry_run=False)

    calls = client.resources["nat_rule"].created
    assert [(p["name"], k) for p, k in calls] == [("legacy-nat", {"position": "pre"})]


def test_legacy_flat_nat_key_ignored_when_split_keys_present(tmp_path):
    client = FakeClient()
    src = _backup(
        tmp_path,
        {
            "nat_rules_pre": [{"name": "nat-pre", "folder": "src"}],
            "nat_rules": [{"name": "nat-pre", "folder": "src"}],
        },
    )
    cloner.clone_config(client, src, "dst", dry_run=False)

    assert [p["name"] for p, _ in client.resources["nat_rule"].created] == ["nat-pre"]


def test_objects_are_created_without_rule_kwargs(tmp_path):
    client = FakeClient()
    src = _backup(tmp_path, {"tags": [{"name": "t1", "folder": "src"}]})
    cloner.clone_config(client, src, "dst", dry_run=False)

    assert client.resources["tag"].created == [({"name": "t1", "folder": "dst"}, {})]


def test_dry_run_detail_names_the_rulebase(tmp_path):
    client = FakeClient()
    src = _backup(tmp_path, {"security_rules_post": [{"name": "post-1", "folder": "src"}]})
    report = cloner.clone_config(client, src, "dst", dry_run=True)

    assert not client.resources
    assert "rulebase=post" in report.results[0].detail


# ── payload sanitation ────────────────────────────────────────────────────


def test_sanitise_strips_provenance_and_readonly_fields():
    obj = {
        "name": "r1",
        "id": "1234",
        "folder": "All",
        "_folder": "All",
        "_position": "pre",
        "policy_type": "Security",
        "rulebase": "pre",
        "action": "allow",
    }
    out, _ = cloner._sanitise(
        obj, target_folder="dst", name_prefix="", anonymise_ips=False, ip_map={}
    )
    assert out == {"name": "r1", "folder": "dst", "action": "allow"}


def test_sanitise_drops_source_container_fields():
    obj = {"name": "t1", "folder": "All", "snippet": "Web-Security-Default", "device": None}
    out, _ = cloner._sanitise(
        obj, target_folder="dst", name_prefix="", anonymise_ips=False, ip_map={}
    )
    assert out == {"name": "t1", "folder": "dst"}


def test_sanitise_drops_nulls_recursively():
    obj = {
        "name": "a1",
        "tag": None,
        "profile_setting": {"group": ["best-practice"], "unused": None},
        "members": [{"value": "10.0.0.1", "note": None}],
    }
    out, _ = cloner._sanitise(
        obj, target_folder="dst", name_prefix="", anonymise_ips=False, ip_map={}
    )
    assert out == {
        "name": "a1",
        "profile_setting": {"group": ["best-practice"]},
        "members": [{"value": "10.0.0.1"}],
        "folder": "dst",
    }


def test_sanitise_still_scrubs_psk_and_applies_prefix():
    obj = {"name": "gw1", "authentication": {"pre_shared_key": {"key": "s3cret"}}}
    out, warning = cloner._sanitise(
        obj,
        target_folder="Remote Networks",
        name_prefix="CUST1_",
        anonymise_ips=False,
        ip_map={},
        is_ike_gateway=True,
    )
    assert out["name"] == "CUST1_gw1"
    assert out["authentication"]["pre_shared_key"]["key"] == "CHANGEME_gw1"
    assert warning == "CUST1_gw1"


# ── conflict handling ─────────────────────────────────────────────────────


class Conflict(Exception):
    pass


class ConflictingResource(FakeResource):
    def create(self, data: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        raise Conflict("object already exists")


class Model(BaseModel):
    model_config = {"extra": "allow"}


class ModelledResource(ConflictingResource):
    def update(self, rule: Model, **kwargs: Any) -> Model:
        assert isinstance(rule, Model), "update() must receive its update model, not a dict"
        self.updated.append((rule, kwargs))
        return rule


def test_conflict_skips_by_default(tmp_path):
    client = FakeClient()
    client.resources["tag"] = ConflictingResource()
    src = _backup(tmp_path, {"tags": [{"name": "t1", "folder": "src"}]})
    report = cloner.clone_config(client, src, "dst", dry_run=False)

    assert report.skipped == 1
    assert report.results[0].detail == "already exists"


def test_overwrite_wraps_payload_in_the_update_model(tmp_path):
    client = FakeClient()
    resource = ModelledResource()
    client.resources["security_rule"] = resource
    src = _backup(tmp_path, {"security_rules_post": [{"name": "post-1", "folder": "src"}]})
    report = cloner.clone_config(client, src, "dst", dry_run=False, on_conflict="overwrite")

    assert report.overwritten == 1
    assert resource.fetched == [{"name": "post-1", "folder": "dst", "rulebase": "post"}]
    model, kwargs = resource.updated[0]
    assert kwargs == {"rulebase": "post"}
    assert model.model_dump() == {"name": "post-1", "folder": "dst", "id": "abc-123"}


def test_to_update_model_passes_dict_when_update_is_untyped():
    class Untyped:
        def update(self, payload):  # noqa: ANN001, ANN201 - deliberately untyped
            return payload

    assert cloner._to_update_model(Untyped(), {"name": "x"}) == {"name": "x"}


# ── PAN predefined content ────────────────────────────────────────────────


def test_predefined_objects_are_skipped_not_pushed(tmp_path):
    client = FakeClient()
    src = _backup(
        tmp_path,
        {
            "edls": [
                {"name": "panw-known-ip-list", "folder": "All", "snippet": "predefined"},
                {"name": "office365-url", "folder": "All", "override_loc": "predefined-snippet"},
                {"name": "customer-blocklist", "folder": "All"},
            ],
            "services": [
                {"name": "service-http", "folder": "All", "snippet": "predefined-snippet"}
            ],
        },
    )
    report = cloner.clone_config(client, src, "dst", dry_run=False)

    assert [p["name"] for p, _ in client.resources["external_dynamic_list"].created] == [
        "customer-blocklist"
    ]
    assert "service" not in client.resources
    assert report.predefined == 3
    assert report.created == 1
    assert report.skipped == 0  # conflict skips are counted separately


def test_predefined_skips_are_listed_in_the_report(tmp_path):
    client = FakeClient()
    src = _backup(
        tmp_path,
        {"edls": [{"name": "panw-known-ip-list", "folder": "All", "snippet": "predefined"}]},
    )
    md = cloner.clone_config(client, src, "dst", dry_run=True).to_markdown()

    assert "| Skipped (PAN predefined) | 1 |" in md
    assert "already present in every tenant" in md


def test_objects_in_a_customer_snippet_are_still_cloned(tmp_path):
    client = FakeClient()
    src = _backup(
        tmp_path,
        {"tags": [{"name": "t1", "folder": "All", "snippet": "Web-Security-Default"}]},
    )
    cloner.clone_config(client, src, "dst", dry_run=False)

    assert client.resources["tag"].created == [({"name": "t1", "folder": "dst"}, {})]
