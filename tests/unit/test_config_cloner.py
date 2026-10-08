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


class MissingResource(FakeResource):
    """A resource whose fetch finds nothing (the object does not exist yet)."""

    def fetch(self, **kwargs: Any) -> Any:
        self.fetched.append(kwargs)
        raise LookupError("not found")


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


# ── GP / identity / network infrastructure ───────────────────────────────


def test_gp_and_identity_objects_push_with_folder_in_payload(tmp_path):
    client = FakeClient()
    client.resources["auth_setting"] = MissingResource()
    src = _backup(
        tmp_path,
        {
            "mobile_agent_auth_settings": [{"name": "auths-1", "folder": "Mobile Users"}],
            "forwarding_profiles": [{"name": "fp-1", "folder": "Mobile Users"}],
            "authentication_profiles": [{"name": "authp-1", "folder": "All"}],
            "saml_server_profiles": [{"name": "saml-1", "folder": "All"}],
            "internal_dns_servers": [{"name": "dns-1", "folder": "Remote Networks"}],
            "qos_profiles": [{"name": "qos-1", "folder": "Remote Networks"}],
        },
    )
    cloner.clone_config(client, src, "dst", dry_run=False)

    assert client.resources["auth_setting"].created == [
        ({"name": "auths-1", "folder": "Mobile Users"}, {})
    ]
    assert client.resources["forwarding_profile"].created == [
        ({"name": "fp-1", "folder": "Mobile Users"}, {})
    ]
    # Identity profiles are folder-scoped like any other customer object.
    assert client.resources["authentication_profile"].created == [
        ({"name": "authp-1", "folder": "dst"}, {})
    ]
    assert client.resources["saml_server_profile"].created == [
        ({"name": "saml-1", "folder": "dst"}, {})
    ]
    assert client.resources["internal_dns_server"].created == [
        ({"name": "dns-1", "folder": "Remote Networks"}, {})
    ]
    assert client.resources["qos_profile"].created == [
        ({"name": "qos-1", "folder": "Remote Networks"}, {})
    ]


def test_folder_kwarg_resources_pass_folder_as_kwarg_not_payload(tmp_path):
    client = FakeClient()
    src = _backup(
        tmp_path,
        {
            "mobile_agent_tunnel_profiles": [{"name": "tp-1", "folder": "Mobile Users"}],
            "mobile_agent_infrastructure": [{"name": "infra-1", "folder": "Mobile Users"}],
        },
    )
    cloner.clone_config(client, src, "dst", dry_run=False)

    tp = client.resources["tunnel_profile"].created
    assert tp == [({"name": "tp-1"}, {"folder": "Mobile Users"})]
    assert "folder" not in tp[0][0]

    infra = client.resources["infrastructure_settings"].created
    assert infra == [({"name": "infra-1"}, {"folder": "Mobile Users"})]
    assert "folder" not in infra[0][0]


def test_folder_kwarg_dry_run_names_the_folder(tmp_path):
    client = FakeClient()
    src = _backup(
        tmp_path,
        {"mobile_agent_tunnel_profiles": [{"name": "tp-1", "folder": "Mobile Users"}]},
    )
    report = cloner.clone_config(client, src, "dst", dry_run=True)

    assert "folder 'Mobile Users'" in report.results[0].detail


def test_folder_kwarg_conflict_overwrite_passes_folder_once(tmp_path):
    client = FakeClient()
    client.resources["tunnel_profile"] = ConflictingResource()
    src = _backup(
        tmp_path,
        {"mobile_agent_tunnel_profiles": [{"name": "tp-1", "folder": "Mobile Users"}]},
    )
    report = cloner.clone_config(client, src, "dst", dry_run=False, on_conflict="overwrite")

    # Overwrite succeeds on the fake resource — the point is that fetch and
    # update received exactly one folder kwarg each, never a duplicate.
    assert report.results[0].status == "overwritten"
    resource = client.resources["tunnel_profile"]
    assert resource.fetched == [{"name": "tp-1", "folder": "Mobile Users"}]


# ── URL categories and profile groups ─────────────────────────────────────


def test_url_categories_and_profile_groups_precede_dependants(tmp_path):
    client = FakeClient()
    order: list[str] = []
    for attr in ("url_category", "url_access_profile", "profile_group", "security_rule"):
        res = client.resources.setdefault(attr, FakeResource())
        res.create = (lambda a: lambda data, **kw: order.append(a))(attr)  # type: ignore[method-assign]
    src = _backup(
        tmp_path,
        {
            "security_rules_pre": [{"name": "r", "folder": "src"}],
            "profile_groups": [{"name": "pg", "folder": "src", "spyware": ["as"]}],
            "url_access_profiles": [{"name": "url", "folder": "src"}],
            "url_categories": [{"name": "cat", "folder": "src", "list": ["*.bing.com"]}],
        },
    )
    cloner.clone_config(client, src, "dst", dry_run=False)
    assert order == ["url_category", "url_access_profile", "profile_group", "security_rule"]


class _Resp:
    def __init__(self, status: int, body: Any) -> None:
        self.status_code = status
        self.ok = status < 400
        self._body = body
        self.text = json.dumps(body)
        self.content = self.text.encode()

    def json(self) -> Any:
        return self._body


class _Session:
    def __init__(self, post_status: int = 201, post_body: Any = None) -> None:
        self.calls: list[tuple[str, str, Any]] = []
        self._post = _Resp(post_status, post_body or {"id": "new"})

    def post(self, url: str, json: Any = None, timeout: Any = None) -> _Resp:
        self.calls.append(("POST", url, json))
        return self._post

    def get(self, url: str, params: Any = None, timeout: Any = None) -> _Resp:
        self.calls.append(("GET", url, params))
        return _Resp(200, {"data": [{"id": "pg-1", "name": params["name"]}]})

    def put(self, url: str, json: Any = None, timeout: Any = None) -> _Resp:
        self.calls.append(("PUT", url, json))
        return _Resp(200, json)


class _SdkClientWithoutProfileGroups:
    def __init__(self, session: _Session) -> None:
        self.session = session

    def __getattr__(self, name: str) -> Any:
        raise AttributeError(name)


def test_profile_groups_pushed_via_rest_when_sdk_lacks_them(tmp_path):
    session = _Session()
    client = _SdkClientWithoutProfileGroups(session)
    src = _backup(
        tmp_path,
        {
            "profile_groups": [
                {
                    "id": "old",
                    "name": "example-group",
                    "folder": "Shared",
                    "spyware": ["example-spyware"],
                }
            ]
        },
    )
    report = cloner.clone_config(client, src, "Prisma Access", dry_run=False)

    method, url, body = session.calls[0]
    assert method == "POST" and url.endswith("/sse/config/v1/profile-groups")
    assert body == {
        "name": "example-group",
        "folder": "Prisma Access",
        "spyware": ["example-spyware"],
    }
    assert [r.status for r in report.results] == ["created"]


def test_profile_group_conflict_overwrite_uses_put_without_container(tmp_path):
    session = _Session(
        post_status=400, post_body={"_errors": [{"message": "Object already exists"}]}
    )
    client = _SdkClientWithoutProfileGroups(session)
    src = _backup(
        tmp_path, {"profile_groups": [{"name": "pg", "folder": "Shared", "spyware": ["x"]}]}
    )
    report = cloner.clone_config(
        client, src, "Prisma Access", on_conflict="overwrite", dry_run=False
    )

    assert [r.status for r in report.results] == ["overwritten"]
    method, url, body = session.calls[-1]
    assert method == "PUT" and url.endswith("/profile-groups/pg-1")
    assert body == {"name": "pg", "spyware": ["x"]}


def test_threat_profile_empty_actions_are_omitted(tmp_path):
    client = FakeClient()
    src = _backup(
        tmp_path,
        {
            "anti_spyware_profiles": [
                {
                    "name": "sp",
                    "folder": "Shared",
                    "rules": [
                        {"name": "crit", "action": {"reset_both": {}}},
                        {"name": "info", "action": {}},
                    ],
                }
            ]
        },
    )
    cloner.clone_config(client, src, "Prisma Access", dry_run=False)

    rules = client.resources["anti_spyware_profile"].created[0][0]["rules"]
    assert [r.get("action") for r in rules] == [{"reset_both": {}}, None]
    assert "action" not in rules[1]


def test_bandwidth_allocations_carry_no_folder(tmp_path):
    client = FakeClient()
    src = _backup(
        tmp_path,
        {"bandwidth_allocations": [{"name": "region-a", "allocated_bandwidth": 50.0}]},
    )
    cloner.clone_config(client, src, "Remote Networks", include_deployment=True, dry_run=False)

    payload = client.resources["bandwidth_allocation"].created[0][0]
    assert "folder" not in payload


def test_sdk_validation_error_retries_create_over_rest(tmp_path):
    session = _Session()

    class StrictResource:
        ENDPOINT = "/config/security/v1/wildfire-anti-virus-profiles"

        def create(self, data: dict[str, Any], **kwargs: Any) -> Any:
            raise ValueError("1 validation error for WildfireAvProfileCreateModel\nname")

    class Client:
        api_base_url = "https://api.example"

        def __init__(self) -> None:
            self.session = session
            self.wildfire_antivirus_profile = StrictResource()

    src = _backup(
        tmp_path, {"wildfire_profiles": [{"name": "Profile With Spaces", "folder": "Shared"}]}
    )
    report = cloner.clone_config(Client(), src, "Prisma Access", dry_run=False)

    assert [r.status for r in report.results] == ["created"]
    method, url, body = session.calls[0]
    assert (method, url) == (
        "POST",
        "https://api.example/config/security/v1/wildfire-anti-virus-profiles",
    )
    assert body["name"] == "Profile With Spaces"


def test_url_profile_continue_action_is_sent_under_its_api_name(tmp_path):
    session = _Session()

    class UrlProfiles:
        ENDPOINT = "/config/security/v1/url-access-profiles"

        def create(self, data: dict[str, Any], **kwargs: Any) -> Any:
            raise AssertionError("SDK create drops continue_; must not be used")

    class Client:
        api_base_url = "https://api.example"

        def __init__(self) -> None:
            self.session = session
            self.url_access_profile = UrlProfiles()

    src = _backup(
        tmp_path,
        {
            "url_access_profiles": [
                {
                    "name": "url",
                    "folder": "Shared",
                    "continue_": ["cat-a"],
                    "credential_enforcement": {"continue_": ["cat-b"]},
                }
            ]
        },
    )
    report = cloner.clone_config(Client(), src, "Prisma Access", dry_run=False)

    assert [r.status for r in report.results] == ["created"]
    method, url, body = session.calls[0]
    assert (method, url) == ("POST", "https://api.example/config/security/v1/url-access-profiles")
    assert body["continue"] == ["cat-a"] and "continue_" not in body
    assert body["credential_enforcement"] == {"continue": ["cat-b"]}


def test_auth_settings_existing_name_is_skipped_not_duplicated(tmp_path):
    client = FakeClient()  # FakeResource.fetch always finds an object
    src = _backup(
        tmp_path,
        {
            "mobile_agent_auth_settings": [
                {"name": "DEFAULT", "authentication_profile": "Local Users"}
            ]
        },
    )
    report = cloner.clone_config(client, src, "Mobile Users", dry_run=False)

    assert [r.status for r in report.results] == ["skipped"]
    assert client.resources["auth_setting"].created == []
