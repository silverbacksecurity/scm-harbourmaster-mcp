"""PAN-OS / Panorama XML → backup translation (audit/panos_import.py)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from scm.models.objects.tag import Colors

from scm_harbourmaster_mcp.audit import cloner
from scm_harbourmaster_mcp.audit import panos_import as p

from .test_config_cloner import FakeClient, MissingResource, _Resp

FIXTURES = Path(__file__).parent.parent / "fixtures" / "panos"
PANORAMA = FIXTURES / "panorama.xml"
FIREWALL = FIXTURES / "firewall.xml"


@pytest.fixture(scope="module")
def branch() -> p.Conversion:
    return p.convert(p.load_xml(PANORAMA), device_group="dg-branch")


def _res(conv: p.Conversion, key: str) -> dict[str, dict[str, Any]]:
    return {o["name"]: o for o in conv.backup["resources"].get(key, [])}


def _items(conv: p.Conversion, action: str) -> set[tuple[str, str]]:
    return {(i.kind, i.name) for i in conv.items if i.action == action}


# ── Loading and scopes ──────────────────────────────────────────────────────


def test_scopes_walk_the_parent_chain_to_shared(branch):
    assert branch.source == "Panorama device group `dg-branch`"
    assert branch.scopes == ["device group `dg-branch`", "device group `dg-parent`", "shared"]
    assert branch.backup["folder"] == "dg-branch"


def test_firewall_export_defaults_to_vsys1():
    conv = p.convert(p.load_xml(FIREWALL))
    assert conv.source == "firewall vsys `vsys1`"
    assert set(_res(conv, "addresses")) == {"lan", "ntp-a"}  # vsys + shared
    assert [r["name"] for r in conv.backup["resources"]["security_rules_pre"]] == [
        "lan-ntp",
        "lan-deny",
    ]


@pytest.mark.parametrize(
    ("path", "kwargs", "message"),
    [
        (PANORAMA, {}, "pass device_group (one of: dg-branch, dg-parent)"),
        (PANORAMA, {"device_group": "nope"}, "`nope` not found (have: dg-branch, dg-parent)"),
        (PANORAMA, {"device_group": "dg-branch", "vsys": "vsys1"}, "not vsys"),
        (FIREWALL, {"vsys": "vsys9"}, "`vsys9` not found (have: vsys1, vsys2)"),
        (FIREWALL, {"device_group": "dg"}, "not device_group"),
    ],
)
def test_bad_scope_names_list_what_exists(path, kwargs, message):
    with pytest.raises(p.PanosImportError, match="") as exc:
        p.convert(p.load_xml(path), **kwargs)
    assert message in str(exc.value)


def test_entity_expansion_and_dtds_are_refused(tmp_path):
    bomb = tmp_path / "bomb.xml"
    bomb.write_text(
        '<?xml version="1.0"?><!DOCTYPE config [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]>'
        "<config>&b;</config>"
    )
    with pytest.raises(p.PanosImportError, match="refused"):
        p.load_xml(bomb)
    ext = tmp_path / "xxe.xml"
    ext.write_text(
        '<?xml version="1.0"?><!DOCTYPE config [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
        "<config>&x;</config>"
    )
    with pytest.raises(p.PanosImportError, match="refused"):
        p.load_xml(ext)


def test_not_a_config_export(tmp_path):
    other = tmp_path / "other.xml"
    other.write_text("<response><result/></response>")
    with pytest.raises(p.PanosImportError, match="expected <config>"):
        p.load_xml(other)
    with pytest.raises(p.PanosImportError, match="not a file"):
        p.load_xml(tmp_path / "missing.xml")
    broken = tmp_path / "broken.xml"
    broken.write_text("<config><shared>")
    with pytest.raises(p.PanosImportError, match="not well-formed"):
        p.load_xml(broken)


def test_size_cap(tmp_path, monkeypatch):
    big = tmp_path / "big.xml"
    big.write_text("<config/>")
    monkeypatch.setattr(p, "MAX_XML_BYTES", 4)
    with pytest.raises(p.PanosImportError, match="byte limit"):
        p.load_xml(big)


# ── Objects ─────────────────────────────────────────────────────────────────


def test_nearest_scope_wins_and_the_hidden_copy_is_reported(branch):
    assert _res(branch, "addresses")["web-1"]["ip_netmask"] == "192.0.2.81/32"
    assert ("addresses", "web-1") in _items(branch, p.OVERRIDDEN)
    # Inherited objects come along
    assert {"dns-a", "net-parent", "range-1", "fqdn-1"} <= set(_res(branch, "addresses"))


def test_object_shapes(branch):
    addrs = _res(branch, "addresses")
    assert addrs["range-1"] == {
        "name": "range-1",
        "ip_range": "192.0.2.100-192.0.2.110",
        "tag": ["tag-branch"],
    }
    assert addrs["fqdn-1"]["fqdn"] == "www.example.com"
    groups = _res(branch, "address_groups")
    assert groups["grp-web"]["static"] == ["web-1", "range-1"]
    assert groups["grp-dyn"]["dynamic"] == {"filter": "'tag-branch'"}
    assert _res(branch, "service_groups")["sg-web"]["members"] == ["svc-web-alt", "svc-timeout"]
    assert _res(branch, "url_categories")["url-allow"] == {
        "name": "url-allow",
        "list": ["www.example.com", "*.example.org"],
        "type": "URL List",
    }


def test_tag_colours_map_to_scm_names(branch):
    tags = _res(branch, "tags")
    assert tags["tag-shared"]["color"] == "Red"
    assert "color" not in tags["tag-branch"]
    assert ("tags", "tag-branch") in _items(branch, p.DROPPED)
    assert set(p.TAG_COLORS.values()) <= {c.value for c in Colors}


def test_services(branch):
    svcs = _res(branch, "services")
    assert svcs["svc-web-alt"]["protocol"] == {"tcp": {"port": "8080,8443"}}
    assert svcs["svc-timeout"]["protocol"] == {
        "udp": {"port": "5000", "override": {"timeout": 120}}
    }
    # A source port can't be kept: the service now matches more
    assert svcs["svc-src"]["protocol"] == {"tcp": {"port": "22"}}
    assert ("services", "svc-src") in _items(branch, p.REVIEW)


def test_edl_credentials_are_never_carried(branch):
    edl = _res(branch, "edls")["edl-ips"]
    assert "auth" not in edl["type"]["ip"]
    assert edl["type"]["ip"]["url"] == "https://feeds.example.com/ips.txt"
    assert edl["type"]["ip"]["recurring"] == {"hourly": {}}
    assert ("edls", "edl-ips") in _items(branch, p.MANUAL)


def test_security_profiles(branch):
    spy = _res(branch, "anti_spyware_profiles")["as-strict"]
    assert spy["rules"][0]["action"] == {"reset_both": {}}
    assert spy["rules"][0]["severity"] == ["critical", "high"]
    assert ("anti_spyware_profiles", "as-strict") in _items(branch, p.DROPPED)  # botnet-domains
    url = _res(branch, "url_access_profiles")["url-basic"]
    assert url["continue_"] == ["gambling"] and url["safe_search_enforcement"] is True
    assert ("url_access_profiles", "url-basic") in _items(branch, p.REVIEW)  # override
    assert _res(branch, "file_blocking_profiles")["fb-basic"]["rules"][0]["file_type"] == ["exe"]
    assert _res(branch, "wildfire_profiles")["wf-basic"]["rules"][0]["analysis"] == "public-cloud"
    dec = _res(branch, "decryption_profiles")["dec-basic"]
    assert dec["ssl_forward_proxy"] == {
        "block_expired_certificate": True,
        "block_untrusted_issuer": True,
    }
    assert ("virus", "av-default") in _items(branch, p.MANUAL)


def test_profile_groups_drop_antivirus(branch):
    pg = _res(branch, "profile_groups")["pg-standard"]
    assert pg == {"name": "pg-standard", "spyware": ["as-strict"]}
    assert ("profile_groups", "pg-standard") in _items(branch, p.MANUAL)


# ── Rules ───────────────────────────────────────────────────────────────────


def test_rule_order_follows_panos_evaluation(branch):
    pre = [r["name"] for r in branch.backup["resources"]["security_rules_pre"]]
    assert pre == [
        "shared-block-bad",
        "parent-allow-dns",
        "branch-web",
        "branch-web-2",
        "branch-intra",
    ]
    post = [r["name"] for r in branch.backup["resources"]["security_rules_post"]]
    assert post == ["branch-post", "shared-cleanup"]


def test_security_rule_shape(branch):
    rules = _res(branch, "security_rules_pre")
    web2 = rules["branch-web-2"]
    assert web2["from_"] == ["trust"] and web2["to_"] == ["untrust"]
    assert web2["negate_source"] is True and web2["disabled"] is True
    assert rules["parent-allow-dns"]["profile_setting"] == {"group": ["pg-standard"]}
    web = rules["branch-web"]
    assert "schedule" not in web and "target" not in web
    assert web["log_end"] is True and web["log_start"] is False
    assert ("security_rules_pre", "branch-web") in _items(branch, p.REVIEW)  # schedule
    assert ("security_rules_pre", "branch-intra") in _items(branch, p.REVIEW)  # intrazone


def test_individual_profiles_become_one_shared_generated_group(branch):
    rules = _res(branch, "security_rules_pre")
    assert rules["branch-web"]["profile_setting"] == {"group": ["branch-web-profiles"]}
    # Same profiles once antivirus is set aside → the same group
    assert rules["branch-web-2"]["profile_setting"] == {"group": ["branch-web-profiles"]}
    gen = _res(branch, "profile_groups")["branch-web-profiles"]
    assert gen == {
        "name": "branch-web-profiles",
        "url_filtering": ["url-basic"],
        "file_blocking": ["fb-basic"],
        "virus_and_wildfire_analysis": ["wf-basic"],
    }
    assert _items(branch, p.GENERATED) == {("profile_groups", "branch-web-profiles")}


def test_nat_decryption_and_app_override_rules(branch):
    nat = _res(branch, "nat_rules_pre")
    assert nat["nat-out"]["source_translation"] == {
        "dynamic_ip_and_port": {"interface_address": {"interface": "ethernet1/1"}}
    }
    assert nat["nat-web"]["service"] == "svc-web-alt"
    assert nat["nat-web"]["destination_translation"]["translated_port"] == 8080
    dec = _res(branch, "decryption_rules")["dec-out"]
    assert dec["type"] == {"ssl_forward_proxy": {}} and dec["log_success"] is True
    ao = _res(branch, "app_override_rules")["ao-app"]
    assert ao["port"] == "8443" and ao["application"] == "ssl"


def test_gaps_are_listed_not_dropped_silently(branch):
    unsupported = _items(branch, p.UNSUPPORTED)
    assert ("pbf", "1 rule(s)") in unsupported
    assert ("application", "1 entry") in unsupported
    assert ("schedule", "1 entry") in unsupported
    assert ("default-security-rules", "intrazone-default") in _items(branch, p.MANUAL)


def test_include_rules_false_keeps_objects_only():
    conv = p.convert(p.load_xml(PANORAMA), device_group="dg-branch", include_rules=False)
    keys = set(conv.backup["resources"])
    assert not {k for k in keys if "rules" in k}
    # Groups that rules would generate aren't needed either
    assert set(_res(conv, "profile_groups")) == {"pg-standard"}


def test_invalid_object_is_reported_and_left_out(tmp_path):
    xml = tmp_path / "bad.xml"
    xml.write_text(
        "<config><devices><entry name='localhost.localdomain'><vsys><entry name='vsys1'>"
        "<address><entry name='bad'><ip-netmask><member>x</member></ip-netmask></entry>"
        "<entry name='odd'><ip-netmask>192.0.2.1</ip-netmask><region>moon</region></entry>"
        "</address></entry></vsys></entry></devices></config>"
    )
    conv = p.convert(p.load_xml(xml))
    assert set(_res(conv, "addresses")) == {"odd"}
    assert ("addresses", "bad") in _items(conv, p.INVALID)
    assert ("addresses", "odd") in _items(conv, p.DROPPED)


def test_plan_markdown_lists_every_item(branch):
    md = "\n".join(p.plan_markdown(branch))
    assert "## Migration plan" in md
    for item in branch.items:
        assert f"`{item.name}`" in md


# ── Through the clone ───────────────────────────────────────────────────────


class _EmptySession:
    """The REST resources (profile groups): nothing found, every create accepted."""

    def __init__(self) -> None:
        self.posts: list[tuple[str, Any]] = []

    def get(self, url: str, params: Any = None, timeout: Any = None) -> _Resp:
        return _Resp(200, {"data": []})

    def post(self, url: str, json: Any = None, timeout: Any = None) -> _Resp:
        self.posts.append((url, json))
        return _Resp(201, {"id": "new"})


class _NewTenant(FakeClient):
    """Nothing exists in the target yet."""

    def __init__(self) -> None:
        super().__init__()
        self.session = _EmptySession()

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        return self.resources.setdefault(name, MissingResource())


def test_translated_backup_clones_in_order(tmp_path, branch):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(branch.backup))
    client = _NewTenant()
    report = cloner.clone_config(client, str(path), "migrated", dry_run=False)

    failed = [r for r in report.results if r.status == "failed"]
    assert not failed, failed
    pre = [
        d["name"]
        for d, kw in client.resources["security_rule"].created
        if kw == {"rulebase": "pre"}
    ]
    assert pre == [
        "shared-block-bad",
        "parent-allow-dns",
        "branch-web",
        "branch-web-2",
        "branch-intra",
    ]
    created = {d["name"]: d for d, _ in client.resources["address"].created}
    groups = [body["name"] for url, body in client.session.posts if "profile-groups" in url]
    assert groups == ["pg-standard", "branch-web-profiles"]
    assert created["web-1"] == {
        "name": "web-1",
        "ip_netmask": "192.0.2.81/32",
        "description": "branch copy",
        "folder": "migrated",
    }


def test_rule_named_like_a_target_snippet_is_still_migrated(tmp_path, branch):
    """A PAN-OS export has no snippet rows, so the target's snippet names must not
    turn a migrated rule into a "placeholder"."""
    from types import SimpleNamespace

    data = json.loads(json.dumps(branch.backup))
    data["resources"]["security_rules_pre"][0]["name"] = "default"
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(data))
    client = _NewTenant()
    client.resources["snippet"] = SimpleNamespace(  # type: ignore[assignment]
        list=lambda: [SimpleNamespace(name="default", type=None)]
    )
    report = cloner.clone_config(client, str(path), "migrated", dry_run=False)

    created = [d["name"] for d, _ in client.resources["security_rule"].created]
    assert "default" in created
    assert not [r for r in report.results if r.status == "not_cloned"]


def test_unknown_nested_fields_are_stripped_and_flagged_not_fatal(tmp_path):
    xml = tmp_path / "nested.xml"
    xml.write_text(
        "<config><devices><entry name='localhost.localdomain'><vsys><entry name='vsys1'>"
        "<profiles><decryption><entry name='dec'><ssl-forward-proxy>"
        "<block-expired-certificate>yes</block-expired-certificate>"
        "<block-if-moonphase>yes</block-if-moonphase>"
        "</ssl-forward-proxy></entry></decryption>"
        "<spyware><entry name='as'><rules><entry name='r'><category>any</category>"
        "<severity><member>any</member></severity><future-knob>on</future-knob>"
        "</entry></rules></entry></spyware></profiles>"
        "</entry></vsys></entry></devices></config>"
    )
    conv = p.convert(p.load_xml(xml))
    dec = _res(conv, "decryption_profiles")["dec"]
    assert dec["ssl_forward_proxy"] == {"block_expired_certificate": True}
    assert _res(conv, "anti_spyware_profiles")["as"]["rules"][0] == {
        "name": "r",
        "category": "any",
        "severity": ["any"],
    }
    reasons = {i.name: i.reason for i in conv.items if i.action == p.REVIEW}
    assert "ssl_forward_proxy.block_if_moonphase" in reasons["dec"]
    assert "rules[].future_knob" in reasons["as"]


def test_application_filters_use_the_api_field_names(branch):
    # Pushed over REST: subcategory and tagging as the API names them
    assert _res(branch, "application_filters")["af-risky"] == {
        "name": "af-risky",
        "category": ["networking"],
        "subcategory": ["proxy"],
        "risk": [4, 5],
        "evasive": True,
        "tagging": {"tag": ["tag-branch"]},
    }
