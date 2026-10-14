"""Framework snippet templates: SDK model validity, control citations, tools (no network)."""

from __future__ import annotations

import functools
import inspect
import re
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
import scm.client
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel
from scm.models.objects.log_forwarding_profile import LogForwardingProfileCreateModel
from scm.models.objects.tag import TagCreateModel
from scm.models.security.anti_spyware_profiles import AntiSpywareProfileCreateModel
from scm.models.security.decryption_profiles import DecryptionProfileCreateModel
from scm.models.security.dns_security_profiles import DNSSecurityProfileCreateModel
from scm.models.security.file_blocking_profiles import FileBlockingProfileCreateModel
from scm.models.security.url_access_profiles import URLAccessProfileCreateModel
from scm.models.security.url_categories import URLCategoriesCreateModel
from scm.models.security.vulnerability_protection_profiles import VulnerabilityProfileCreateModel
from scm.models.security.wildfire_antivirus_profiles import WildfireAvProfileCreateModel

from scm_harbourmaster_mcp.audit import nist_templates, snippet_templates
from scm_harbourmaster_mcp.audit.dspt_controls import DSPT_ASSERTIONS
from scm_harbourmaster_mcp.audit.iso27001_controls import ISO27001_CONTROLS
from scm_harbourmaster_mcp.audit.ncsc_templates import build_snippet_templates
from scm_harbourmaster_mcp.audit.snippet_blocks import SnippetObject, SnippetSpec
from scm_harbourmaster_mcp.tools.ncsc_baseline import register_ncsc_tools

TENANT = "1234567890"
SNIPPET = "Test-Snippet"

# Every sdk_attr a snippet template may use → the model its create() validates with
CREATE_MODELS: dict[str, type[BaseModel]] = {
    "anti_spyware_profile": AntiSpywareProfileCreateModel,
    "vulnerability_protection_profile": VulnerabilityProfileCreateModel,
    "wildfire_antivirus_profile": WildfireAvProfileCreateModel,
    "url_access_profile": URLAccessProfileCreateModel,
    "log_forwarding_profile": LogForwardingProfileCreateModel,
    "dns_security_profile": DNSSecurityProfileCreateModel,
    "file_blocking_profile": FileBlockingProfileCreateModel,
    "decryption_profile": DecryptionProfileCreateModel,
    "url_category": URLCategoriesCreateModel,
    "tag": TagCreateModel,
}


def _legacy_objects(templates: Any) -> list[SnippetObject]:
    return [*templates.all_profiles, ("tag", templates.tag)]


# (id, objects) for every snippet the tools create — NCSC/NIST included so a
# shared-block change can never silently break them
SPECS: dict[str, SnippetSpec] = {
    "iso27001": snippet_templates.build_iso27001_snippet(SNIPPET, "siem"),
    "dspt": snippet_templates.build_dspt_snippet(SNIPPET, "siem"),
    "dns_security": snippet_templates.build_dns_security_snippet(SNIPPET),
    "decryption": snippet_templates.build_decryption_snippet(SNIPPET),
    "ransomware": snippet_templates.build_ransomware_snippet(SNIPPET, "siem"),
}
# The tool that creates each spec, and whether it takes syslog_profile
SPEC_TOOLS: dict[str, tuple[str, bool]] = {
    "iso27001": ("scm_create_iso27001_snippet", True),
    "dspt": ("scm_create_dspt_snippet", True),
    "dns_security": ("scm_create_dns_security_snippet", False),
    "decryption": ("scm_create_decryption_snippet", False),
    "ransomware": ("scm_create_ransomware_snippet", True),
}
ALL_OBJECTS: dict[str, list[SnippetObject]] = {
    "ncsc": _legacy_objects(build_snippet_templates(SNIPPET, "siem")),
    "nist": _legacy_objects(nist_templates.build_nist_snippet_templates(SNIPPET, "siem")),
    **{k: spec.objects for k, spec in SPECS.items()},
}


def _key_paths(value: Any, prefix: str = "") -> set[str]:
    """Dotted key paths through nested dicts/lists (list indices collapsed)."""
    if isinstance(value, dict):
        out: set[str] = set()
        for k, v in value.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            out |= {path} | _key_paths(v, path)
        return out
    if isinstance(value, list):
        return set().union(*(_key_paths(v, prefix) for v in value)) if value else set()
    return set()


def _tools(client: Any) -> dict[str, Any]:
    mcp = FastMCP("test")
    register_ncsc_tools(mcp, lambda tenant_id="": client)
    return {
        name: functools.partial(t.fn, ticket_ref="CHG-TEST")
        for name, t in mcp._tool_manager._tools.items()
    }


class TestSdkModels:
    @pytest.mark.parametrize("key", sorted(ALL_OBJECTS))
    def test_payloads_validate_against_create_models(self, key: str) -> None:
        for sdk_attr, payload in ALL_OBJECTS[key]:
            assert sdk_attr in CREATE_MODELS, f"no create model mapped for {sdk_attr}"
            model = CREATE_MODELS[sdk_attr](**payload)
            # create() sends model_dump(exclude_unset=True): nothing we set may
            # be dropped (a payload keyed by a field's alias would be)
            dumped = model.model_dump(exclude_unset=True)
            assert set(payload) <= set(dumped), (sdk_attr, set(payload) - set(dumped))

    @pytest.mark.parametrize("key", sorted(ALL_OBJECTS))
    def test_sent_keys_match_the_api_aliases(self, key: str) -> None:
        # create() dumps without by_alias, so a field whose API name differs
        # (an alias) goes out under its Python name. The only such field the
        # snippets set is the vulnerability rules' vendor_id (API: vendor-id),
        # an SDK quirk inherited from the NCSC/NIST payloads — always ["any"],
        # which is also the API default.
        for sdk_attr, payload in ALL_OBJECTS[key]:
            model = CREATE_MODELS[sdk_attr](**payload)
            plain = _key_paths(model.model_dump(exclude_unset=True))
            aliased = _key_paths(model.model_dump(exclude_unset=True, by_alias=True))
            renamed = {p.rsplit(".", 1)[-1] for p in plain ^ aliased}
            expected = {"vendor_id", "vendor-id"} if sdk_attr.startswith("vuln") else set()
            assert renamed == expected, (sdk_attr, renamed)

    @pytest.mark.parametrize("key", sorted(ALL_OBJECTS))
    def test_objects_are_scoped_to_the_snippet(self, key: str) -> None:
        names = [p["name"] for _, p in ALL_OBJECTS[key]]
        assert len(names) == len(set(names))
        for _, payload in ALL_OBJECTS[key]:
            assert payload["snippet"] == SNIPPET
            assert "folder" not in payload
            # PAN-OS profile names are capped at 31 characters
            assert len(payload["name"]) <= 31, payload["name"]

    def test_every_sdk_attr_is_a_real_client_service(self) -> None:
        source = inspect.getsource(scm.client)
        for attr in CREATE_MODELS:
            assert f'"{attr}": (' in source, attr

    def test_decryption_profile_disables_weak_crypto(self) -> None:
        profile = next(p for a, p in SPECS["iso27001"].objects if a == "decryption_profile")
        proto = profile["ssl_protocol_settings"]
        assert proto["min_version"] == "tls1-2"
        for weak in ("auth_algo_md5", "auth_algo_sha1", "enc_algo_3des", "enc_algo_rc4"):
            assert proto[weak] is False, weak
        assert proto["keyxchg_algo_rsa"] is False
        assert profile["ssl_forward_proxy"]["block_untrusted_issuer"] is True
        assert profile["ssl_forward_proxy"]["block_expired_certificate"] is True


class TestControlCitations:
    def _descriptions(self, spec: SnippetSpec) -> list[str]:
        return [p["description"] for _, p in spec.objects if "description" in p]

    def test_iso_citations_exist_and_come_from_bpa_mapping(self) -> None:
        spec = SPECS["iso27001"]
        for desc in self._descriptions(spec):
            refs = re.findall(r"A\.\d+\.\d+", desc)
            assert refs, desc
            assert set(refs) <= set(ISO27001_CONTROLS), desc
        by_name = {p["name"]: p.get("description", "") for _, p in spec.objects}
        assert "A.8.7/A.8.28" in by_name[snippet_templates.ISO_VULN_PROTECTION_NAME]
        assert "A.5.14" in by_name[snippet_templates.ISO_FILE_BLOCKING_NAME]
        assert "A.8.23" in by_name[snippet_templates.ISO_URL_ACCESS_NAME]
        assert "A.5.28/A.8.15" in by_name[snippet_templates.ISO_LOG_FORWARDING_NAME]

    @pytest.mark.parametrize("key", ["dns_security", "decryption"])
    def test_building_block_citations_exist(self, key: str) -> None:
        for desc in self._descriptions(SPECS[key]):
            iso = re.findall(r"A\.\d+\.\d+", desc)
            dspt = re.findall(r"DSPT (\d+\.\d+\.\d+)", desc)
            assert iso and dspt, desc
            assert set(iso) <= set(ISO27001_CONTROLS), desc
            assert {f"DSPT-{r}" for r in dspt} <= set(DSPT_ASSERTIONS), desc

    def test_dspt_citations_exist(self) -> None:
        for desc in self._descriptions(SPECS["dspt"]):
            refs = re.findall(r"\d+\.\d+\.\d+", desc)
            assert refs, desc
            assert {f"DSPT-{r}" for r in refs} <= set(DSPT_ASSERTIONS), desc


class TestTools:
    @pytest.mark.parametrize(
        ("tool", "label", "default_name", "count"),
        [
            ("scm_create_iso27001_snippet", "ISO 27001", "ISO27001-Compliance", 9),
            ("scm_create_dspt_snippet", "DSPT", "DSPT-Compliance", 8),
            ("scm_create_dns_security_snippet", "DNS Security", "DNS-Security", 2),
            ("scm_create_decryption_snippet", "Decryption", "Decryption-Baseline", 4),
            (
                "scm_create_ransomware_snippet",
                "Ransomware Readiness",
                "Ransomware-Readiness",
                8,
            ),
        ],
    )
    def test_dry_run_writes_nothing(self, tool: str, label: str, default_name: str, count: int):
        client = MagicMock()
        out = _tools(client)[tool](tenant_id=TENANT)
        assert f"## {label} Snippet — DRY-RUN: '{default_name}'" in out
        assert f"Created: {count} | Skipped: 0 | Failed: 0" in out
        assert "No changes written" in out
        assert client.mock_calls == []

    @pytest.mark.parametrize("spec_key", sorted(SPEC_TOOLS))
    def test_apply_creates_every_object(self, spec_key: str) -> None:
        tool, takes_syslog = SPEC_TOOLS[spec_key]
        client = MagicMock()
        client.snippet.create.return_value = SimpleNamespace(id="snip-1")
        extra = {"syslog_profile": "siem"} if takes_syslog else {}
        out = _tools(client)[tool](tenant_id=TENANT, snippet_name=SNIPPET, dry_run=False, **extra)
        assert "Created snippet 'Test-Snippet' (id=snip-1)" in out
        assert "Failed: 0" in out and "created.**" in out
        sent = [
            (attr, call.args[0])
            for attr in CREATE_MODELS
            for call in getattr(client, attr).create.call_args_list
        ]
        expected = SPECS[spec_key].objects
        assert sorted(sent, key=lambda o: o[1]["name"]) == sorted(
            expected, key=lambda o: o[1]["name"]
        )

    def test_dspt_associates_folder_on_request(self) -> None:
        client = MagicMock()
        out = _tools(client)["scm_create_dspt_snippet"](tenant_id=TENANT, associate_folder="Branch")
        assert "would associate snippet 'DSPT-Compliance' with folder 'Branch'" in out
        assert client.mock_calls == []

    def test_decryption_snippet_wires_exclusions(self) -> None:
        objs = dict((p["name"], (a, p)) for a, p in SPECS["decryption"].objects)
        attr, category = objs[snippet_templates.NO_DECRYPT_CATEGORY_NAME]
        assert attr == "url_category" and category["type"] == "Category Match"
        assert "financial-services" in category["list"]
        attr, nodecrypt = objs[snippet_templates.NO_DECRYPT_PROFILE_NAME]
        assert attr == "decryption_profile"
        assert set(nodecrypt) == {"name", "snippet", "ssl_no_proxy"}
        out = _tools(MagicMock())["scm_create_decryption_snippet"](tenant_id=TENANT)
        assert "forward-trust certificate" not in out  # next steps are apply-only
        assert "Note: This snippet holds profiles and objects only" in out

    def test_dns_snippet_sinkholes_c2(self) -> None:
        (attr, profile), _tag = SPECS["dns_security"].objects
        assert attr == "dns_security_profile"
        cats = {
            c["name"]: c["action"] for c in profile["botnet_domains"]["dns_security_categories"]
        }
        assert cats["pan-dns-sec-cc"] == "sinkhole"
        assert cats["pan-dns-sec-adtracking"] == "default"
        assert profile["botnet_domains"]["sinkhole"]["ipv4_address"] == "pan-sinkhole-default-ip"

    def test_ransomware_snippet_blocks_encrypted_archives(self) -> None:
        objs = {p["name"]: p for _, p in SPECS["ransomware"].objects}
        fb = objs[snippet_templates.RANSOMWARE_FILE_BLOCKING_NAME]
        assert {"encrypted-rar", "encrypted-zip"} <= set(fb["rules"][0]["file_type"])
        assert fb["rules"][0]["action"] == "block"
        # The ISO/DSPT file-blocking block stays without them
        iso = {p["name"]: p for _, p in SPECS["iso27001"].objects}
        assert (
            "encrypted-zip"
            not in iso[snippet_templates.ISO_FILE_BLOCKING_NAME]["rules"][0]["file_type"]
        )
        for p in objs.values():
            if "description" in p:
                assert "NIST IR 8374" in p["description"] and re.search(
                    r"SP 800-53 [A-Z]{2}-\d", p["description"]
                ), p["name"]
        client = MagicMock()
        out = _tools(client)["scm_create_ransomware_snippet"](tenant_id=TENANT, dry_run=False)
        assert "Isolate backup traffic" in out
        assert "east-west and intrazone allow rules" in out
