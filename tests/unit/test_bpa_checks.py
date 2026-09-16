"""Behavioural tests for the BPA check engine (audit/bpa_checks.py).

Each check is exercised against a compliant and a non-compliant snapshot so a
regression in either direction (false pass or false fail) is caught. The PAB
checks already have their own module (test_pab_checks.py).
"""

from __future__ import annotations

from typing import Any

import pytest

from scm_harbourmaster_mcp.audit import bpa_checks as bpa
from scm_harbourmaster_mcp.audit.models import AuditSnapshot, Status


def _snap(**fields: Any) -> AuditSnapshot:
    snap = AuditSnapshot(folder="Shared", tenant_id="1234567890")
    for key, value in fields.items():
        setattr(snap, key, value)
    return snap


def _rule(name: str, **overrides: Any) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "name": name,
        "action": "allow",
        "source": ["10.0.0.0/8"],
        "destination": ["web-servers"],
        "application": ["web-browsing"],
        "profile_setting": {"group": ["best-practice"]},
        "log_end": True,
        "log_forwarding": "lfp-default",
    }
    rule.update(overrides)
    return rule


DENY_ALL = {
    "name": "deny-all",
    "action": "deny",
    "source": ["any"],
    "destination": ["any"],
    "application": ["any"],
    "log_end": True,
}


# ── Helpers ────────────────────────────────────────────────────────────────


class TestHelpers:
    def test_has_security_profile(self) -> None:
        assert bpa._has_security_profile({"profile_setting": {"group": ["g"]}})
        assert bpa._has_security_profile({"profile_setting": {"profiles": {"x": 1}}})
        assert not bpa._has_security_profile({"profile_setting": {}})
        assert not bpa._has_security_profile({"profile_setting": None})
        assert not bpa._has_security_profile({"profile_setting": ["g"]})

    def test_is_any(self) -> None:
        assert bpa._is_any(["any"])
        assert bpa._is_any([])
        assert bpa._is_any("ANY")
        assert not bpa._is_any(["any", "10.0.0.1"])
        assert not bpa._is_any("10.0.0.1")

    def test_rule_name_default(self) -> None:
        assert bpa._rule_name({}) == "<unnamed>"


# ── Security rules ─────────────────────────────────────────────────────────


class TestSecurityRuleChecks:
    def test_sr_001_flags_allow_rule_without_profile(self) -> None:
        good = _snap(security_rules_pre=[_rule("ok"), DENY_ALL])
        assert bpa.check_sr_001(good).status is Status.PASS

        bad = _snap(
            security_rules_pre=[
                _rule("naked", profile_setting=None),
                _rule("disabled-naked", profile_setting=None, disabled=True),
            ]
        )
        f = bpa.check_sr_001(bad)
        assert f.status is Status.FAIL
        assert f.affected_objects == ["naked"]

    def test_sr_002_any_any_any(self) -> None:
        bad = _snap(
            security_rules_pre=[
                _rule("wide-open", source=["any"], destination=["any"], application=["any"])
            ]
        )
        assert bpa.check_sr_002(bad).status is Status.FAIL
        assert bpa.check_sr_002(_snap(security_rules_pre=[_rule("ok")])).status is Status.PASS

    def test_sr_003_log_end_disabled(self) -> None:
        bad = _snap(security_rules_pre=[_rule("quiet", log_end=False)])
        f = bpa.check_sr_003(bad)
        assert f.status is Status.FAIL and f.affected_objects == ["quiet"]
        # log_end missing defaults to True (PAN-OS default)
        missing = _rule("implicit")
        missing.pop("log_end")
        assert bpa.check_sr_003(_snap(security_rules_pre=[missing])).status is Status.PASS

    def test_sr_004_disabled_rules_warn(self) -> None:
        f = bpa.check_sr_004(_snap(security_rules_post=[_rule("old", disabled=True)]))
        assert f.status is Status.WARN and f.affected_objects == ["old"]
        assert bpa.check_sr_004(_snap(security_rules_pre=[_rule("ok")])).status is Status.PASS

    def test_sr_005_application_any(self) -> None:
        f = bpa.check_sr_005(_snap(security_rules_pre=[_rule("any-app", application="any")]))
        assert f.status is Status.FAIL
        assert bpa.check_sr_005(_snap(security_rules_pre=[_rule("ok")])).status is Status.PASS

    def test_sr_006_deny_rules_must_log(self) -> None:
        bad = _snap(security_rules_pre=[{**DENY_ALL, "action": "drop", "log_end": False}])
        assert bpa.check_sr_006(bad).status is Status.FAIL
        assert bpa.check_sr_006(_snap(security_rules_pre=[DENY_ALL])).status is Status.PASS

    def test_sr_007_unrestricted_outbound(self) -> None:
        bad = _snap(security_rules_pre=[_rule("egress", destination=["any"], application=["any"])])
        assert bpa.check_sr_007(bad).status is Status.FAIL
        assert bpa.check_sr_007(_snap(security_rules_pre=[_rule("ok")])).status is Status.PASS

    def test_sr_008_explicit_deny_all_must_be_last(self) -> None:
        assert bpa.check_sr_008(_snap()).status is Status.SKIP
        ok = _snap(security_rules_pre=[_rule("ok")], security_rules_post=[DENY_ALL])
        assert bpa.check_sr_008(ok).status is Status.PASS
        # deny-all present but not last
        wrong_order = _snap(security_rules_pre=[DENY_ALL, _rule("after")])
        assert bpa.check_sr_008(wrong_order).status is Status.FAIL

    def test_sr_009_double_any(self) -> None:
        assert bpa.check_sr_009(_snap()).status is Status.SKIP
        bad = _snap(security_rules_pre=[_rule("double-any", source="any", destination=["any"])])
        assert bpa.check_sr_009(bad).status is Status.FAIL
        assert bpa.check_sr_009(_snap(security_rules_pre=[_rule("ok")])).status is Status.PASS

    def test_sr_010_unauthenticated_protocols(self) -> None:
        assert bpa.check_sr_010(_snap()).status is Status.SKIP
        bad = _snap(
            security_rules_pre=[
                _rule("legacy", application=["ssl", "Telnet", "ftp"]),
                _rule("str-app", application="tftp"),
                _rule("disabled", application=["telnet"], disabled=True),
                {**DENY_ALL, "application": ["telnet"]},
            ]
        )
        f = bpa.check_sr_010(bad)
        assert f.status is Status.FAIL
        assert f.affected_objects == ["legacy (Telnet, ftp)", "str-app (tftp)"]
        assert bpa.check_sr_010(_snap(security_rules_pre=[_rule("ok")])).status is Status.PASS


# ── Threat prevention / decryption / URL ───────────────────────────────────


class TestThreatPreventionChecks:
    def test_tp_001_sinkhole(self) -> None:
        assert bpa.check_tp_001(_snap()).status is Status.FAIL
        botnet = _snap(anti_spyware_profiles=[{"name": "as", "botnet_domains": {"sinkhole": {}}}])
        # an empty sinkhole dict is falsy -> not configured
        assert bpa.check_tp_001(botnet).status is Status.FAIL
        dns_cat = _snap(
            anti_spyware_profiles=[
                {"name": "as", "dns_security_categories": [{"action": "sinkhole"}]}
            ]
        )
        f = bpa.check_tp_001(dns_cat)
        assert f.status is Status.PASS and "as" in f.description
        configured = _snap(
            anti_spyware_profiles=[{"name": "as2", "botnet_domains": {"sinkhole": {"ipv4": "x"}}}]
        )
        assert bpa.check_tp_001(configured).status is Status.PASS

    def test_tp_002_to_005_presence_checks(self) -> None:
        empty = _snap()
        assert bpa.check_tp_002(empty).status is Status.FAIL
        assert bpa.check_tp_003(empty).status is Status.FAIL
        assert bpa.check_tp_004(empty).status is Status.FAIL
        assert bpa.check_tp_005(empty).status is Status.WARN
        assert bpa.check_tp_006(empty).status is Status.WARN

        full = _snap(
            dns_security_profiles=[{"name": "dns"}],
            vulnerability_profiles=[{"name": "vp"}],
            wildfire_profiles=[{"name": "wf"}],
            file_blocking_profiles=[{"name": "fb"}],
            decryption_profiles=[{"name": "dp"}],
        )
        assert bpa.check_tp_002(full).status is Status.PASS
        f3 = bpa.check_tp_003(full)
        assert f3.status is Status.PASS and f3.affected_objects == ["vp"]
        assert bpa.check_tp_004(full).status is Status.PASS
        assert bpa.check_tp_005(full).status is Status.PASS
        f6 = bpa.check_tp_006(full)
        assert f6.status is Status.PASS and f6.check_id == "BPA-DEC-001"

    def test_dec_002_decrypt_rules(self) -> None:
        assert bpa.check_dec_002(_snap()).status is Status.SKIP
        profiles = [{"name": "dp"}]
        assert bpa.check_dec_002(_snap(decryption_profiles=profiles)).status is Status.FAIL

        only_exclusions = _snap(
            decryption_profiles=profiles,
            decryption_rules=[
                {"name": "no-dec-bank", "action": "no-decrypt"},
                {"name": "disabled-dec", "action": "decrypt", "disabled": True},
            ],
        )
        f = bpa.check_dec_002(only_exclusions)
        assert f.status is Status.FAIL and "no-decrypt" in f.title

        active = _snap(
            decryption_profiles=profiles,
            decryption_rules=[{"name": "dec-web", "action": "DECRYPT"}],
        )
        f = bpa.check_dec_002(active)
        assert f.status is Status.PASS and f.affected_objects == ["dec-web"]

    def test_tp_007_wildfire_coverage(self) -> None:
        assert bpa.check_tp_007(_snap()).status is Status.SKIP

        any_block = _snap(
            wildfire_profiles=[{"name": "wf", "rules": [{"file_type": ["any"], "action": "block"}]}]
        )
        assert bpa.check_tp_007(any_block).status is Status.PASS

        narrow = _snap(
            wildfire_profiles=[
                {"name": "narrow", "rules": [{"file_type": "pe", "action": "block"}]}
            ]
        )
        f = bpa.check_tp_007(narrow)
        assert f.status is Status.FAIL and f.affected_objects == ["narrow"]

        no_block = _snap(
            wildfire_profiles=[{"name": "alert-only", "rules": [{"file_types": ["any"]}]}]
        )
        assert bpa.check_tp_007(no_block).status is Status.FAIL

    def test_tp_007_profile_level_malware_verdict_counts_as_block(self) -> None:
        # A profile-level malware=block verdict must count even when a
        # grayware verdict (typically alert) is also configured.
        snap = _snap(
            wildfire_profiles=[
                {
                    "name": "verdicts",
                    "rules": [{"file_type": ["any"]}],
                    "verdicts": {"malware": "block", "grayware": "alert"},
                }
            ]
        )
        assert bpa.check_tp_007(snap).status is Status.PASS

    def test_url_001(self) -> None:
        assert bpa.check_url_001(_snap()).status is Status.WARN
        assert bpa.check_url_001(_snap(url_categories=[{"name": "c"}])).status is Status.PASS

    def test_url_002_block_coverage(self) -> None:
        assert bpa.check_url_002(_snap()).status is Status.WARN

        full = _snap(
            url_access_profiles=[
                {
                    "name": "strict",
                    "access_rules": [
                        {"action": "alert", "categories": ["any"]},
                        {"action": "block", "categories": ["any"]},
                    ],
                }
            ]
        )
        assert bpa.check_url_002(full).status is Status.PASS

        partial = _snap(
            url_access_profiles=[
                {"name": "weak", "rules": [{"action": "block", "category": "malware"}]},
            ]
        )
        f = bpa.check_url_002(partial)
        assert f.status is Status.FAIL and f.affected_objects == ["weak"]


# ── Zones, logging, network ────────────────────────────────────────────────


class TestZoneLoggingNetworkChecks:
    def test_zp_001(self) -> None:
        assert bpa.check_zp_001(_snap()).status is Status.SKIP
        f = bpa.check_zp_001(
            _snap(zones=[{"name": "trust", "zone_protection_profile": "zp"}, {"name": "untrust"}])
        )
        assert f.status is Status.FAIL and f.affected_objects == ["untrust"]
        ok = _snap(zones=[{"name": "trust", "zone_protection_profile": "zp"}])
        assert bpa.check_zp_001(ok).status is Status.PASS

    def test_log_001_002(self) -> None:
        assert bpa.check_log_001(_snap()).status is Status.FAIL
        assert bpa.check_log_002(_snap()).status is Status.FAIL
        snap = _snap(log_forwarding_profiles=[{"name": "l"}], syslog_profiles=[{"name": "s"}])
        assert bpa.check_log_001(snap).status is Status.PASS
        assert bpa.check_log_002(snap).status is Status.PASS

    def test_log_003_rule_attachment(self) -> None:
        assert bpa.check_log_003(_snap()).status is Status.SKIP
        lfp = [{"name": "l"}]
        bad = _snap(
            log_forwarding_profiles=lfp,
            security_rules_pre=[_rule("unforwarded", log_forwarding=None), DENY_ALL],
        )
        f = bpa.check_log_003(bad)
        assert f.status is Status.FAIL and f.affected_objects == ["unforwarded"]
        good = _snap(log_forwarding_profiles=lfp, security_rules_pre=[_rule("ok")])
        assert bpa.check_log_003(good).status is Status.PASS

    def test_net_001_segmentation(self) -> None:
        assert bpa.check_net_001(_snap()).status is Status.SKIP
        assert bpa.check_net_001(_snap(zones=[{"name": "a"}])).status is Status.FAIL
        assert bpa.check_net_001(_snap(zones=[{"name": "a"}, {"name": "b"}])).status is Status.PASS

    def test_net_002_remote_network_ipsec(self) -> None:
        assert bpa.check_net_002(_snap()).status is Status.SKIP
        rn = [{"name": "branch"}]
        assert bpa.check_net_002(_snap(remote_networks=rn)).status is Status.WARN
        full = _snap(
            remote_networks=rn, ike_gateways=[{"name": "g"}], ipsec_tunnels=[{"name": "t"}]
        )
        assert bpa.check_net_002(full).status is Status.PASS


# ── VPN crypto ─────────────────────────────────────────────────────────────


class TestVpnChecks:
    def test_vpn_001_ikev2(self) -> None:
        assert bpa.check_vpn_001(_snap()).status is Status.SKIP
        snap = _snap(
            ike_gateways=[
                {"name": "v2", "version": "ikev2"},
                {"name": "default"},
                {"name": "pref", "version": "ikev2-preferred"},
            ]
        )
        f = bpa.check_vpn_001(snap)
        assert f.status is Status.FAIL and f.affected_objects == ["pref"]
        assert bpa.check_vpn_001(_snap(ike_gateways=[{"name": "v2"}])).status is Status.PASS

    @pytest.mark.parametrize(
        "profile",
        [
            {"name": "p", "encryption": ["3DES"]},
            {"name": "p", "authentication": ["sha1"]},
            {"name": "p", "dh_group": ["group2"]},
        ],
    )
    def test_vpn_002_weak_ike_algorithms(self, profile: dict[str, Any]) -> None:
        f = bpa.check_vpn_002(_snap(ike_crypto_profiles=[profile]))
        assert f.status is Status.FAIL and f.affected_objects == ["p"]

    def test_vpn_002_strong_and_skip(self) -> None:
        assert bpa.check_vpn_002(_snap()).status is Status.SKIP
        strong = {
            "name": "p",
            "encryption": ["aes-256-gcm"],
            "authentication": ["sha384"],
            "dh_group": ["group20"],
        }
        assert bpa.check_vpn_002(_snap(ike_crypto_profiles=[strong])).status is Status.PASS

    def test_vpn_003_and_004_ipsec(self) -> None:
        assert bpa.check_vpn_003(_snap()).status is Status.SKIP
        assert bpa.check_vpn_004(_snap()).status is Status.SKIP

        weak = {"name": "weak", "esp": {"encryption": ["null"]}, "dh_group": "no-pfs"}
        strong = {
            "name": "strong",
            "esp": {"encryption": ["aes-256-gcm"], "authentication": ["sha256"]},
            "dh_group": "group20",
        }
        snap = _snap(ipsec_crypto_profiles=[weak, strong])
        f3 = bpa.check_vpn_003(snap)
        assert f3.status is Status.FAIL and f3.affected_objects == ["weak"]
        f4 = bpa.check_vpn_004(snap)
        assert f4.status is Status.FAIL and f4.affected_objects == ["weak"]

        only_strong = _snap(ipsec_crypto_profiles=[strong])
        assert bpa.check_vpn_003(only_strong).status is Status.PASS
        assert bpa.check_vpn_004(only_strong).status is Status.PASS


# ── Authentication ─────────────────────────────────────────────────────────


class TestAuthChecks:
    def test_auth_001_mfa(self) -> None:
        assert bpa.check_auth_001(_snap()).status is Status.SKIP
        snap = _snap(
            authentication_profiles=[
                {"name": "mfa-flag", "multi_factor_auth": {"mfa_enable": True}},
                {"name": "factors", "mfa": {"factors": ["okta"]}},
                {"name": "top-factors", "factors": ["duo"]},
                {"name": "single"},
            ]
        )
        f = bpa.check_auth_001(snap)
        assert f.status is Status.FAIL and f.affected_objects == ["single"]
        ok = _snap(authentication_profiles=[{"name": "x", "factors": ["duo"]}])
        assert bpa.check_auth_001(ok).status is Status.PASS

    def test_auth_002_saml_cert_validation(self) -> None:
        assert bpa.check_auth_002(_snap()).status is Status.SKIP
        snap = _snap(
            saml_server_profiles=[{"name": "ok"}, {"name": "bad", "validate_idp_cert": False}]
        )
        f = bpa.check_auth_002(snap)
        assert f.status is Status.FAIL and f.affected_objects == ["bad"]
        assert (
            bpa.check_auth_002(_snap(saml_server_profiles=[{"name": "ok"}])).status is Status.PASS
        )

    def test_auth_003_lockout(self) -> None:
        assert bpa.check_auth_003(_snap()).status is Status.SKIP
        snap = _snap(
            authentication_profiles=[
                {"name": "locked", "lockout": {"failed_attempts": 5}},
                {"name": "open", "lockout": {"failed_attempts": 0}},
                {"name": "weird", "lockout": "yes"},
            ]
        )
        f = bpa.check_auth_003(snap)
        assert f.status is Status.FAIL and f.affected_objects == ["open", "weird"]
        ok = _snap(authentication_profiles=[{"name": "locked", "lockout": {"failed_attempts": 3}}])
        assert bpa.check_auth_003(ok).status is Status.PASS


# ── HIP ────────────────────────────────────────────────────────────────────


class TestHipChecks:
    def test_hip_001_and_002(self) -> None:
        assert bpa.check_hip_001(_snap()).status is Status.SKIP
        assert bpa.check_hip_002(_snap()).status is Status.SKIP

        bare = _snap(hip_objects=[{"name": "os-only"}])
        assert bpa.check_hip_001(bare).status is Status.FAIL
        assert bpa.check_hip_002(bare).status is Status.FAIL

        rich = _snap(
            hip_objects=[
                {"name": "patch", "patch_management": {"criteria": {}}},
                {"name": "disk", "disk_encryption": {"criteria": {}}},
            ]
        )
        f1 = bpa.check_hip_001(rich)
        assert f1.status is Status.PASS and f1.affected_objects == ["patch"]
        f2 = bpa.check_hip_002(rich)
        assert f2.status is Status.PASS and f2.affected_objects == ["disk"]

    def test_hip_003_rule_references(self) -> None:
        assert bpa.check_hip_003(_snap()).status is Status.SKIP
        profiles = [{"name": "compliant-endpoint"}]
        unused = _snap(hip_profiles=profiles, security_rules_pre=[_rule("gp")])
        assert bpa.check_hip_003(unused).status is Status.WARN

        nested = _snap(
            hip_profiles=profiles,
            security_rules_pre=[
                _rule("gp", profile_setting={"hip_profiles": ["compliant-endpoint"]})
            ],
        )
        assert bpa.check_hip_003(nested).status is Status.PASS

        top_level = _snap(
            hip_profiles=profiles,
            security_rules_pre=[_rule("gp2", profile_setting=None, hip_profiles=["any"])],
        )
        f = bpa.check_hip_003(top_level)
        assert f.status is Status.PASS and f.affected_objects == ["gp2"]


# ── NGFW device health ─────────────────────────────────────────────────────


class TestNgfwChecks:
    def test_ngw_001_connectivity(self) -> None:
        assert bpa.check_ngw_001(_snap()).status is Status.SKIP
        snap = _snap(
            ngfw_devices=[
                {"name": "fw1", "connectivity_status": "Connected"},
                {"hostname": "fw2", "connected": False},
                {"serial_number": "0001", "connectivity_status": "disconnected"},
                {"name": "fw4"},
            ]
        )
        f = bpa.check_ngw_001(snap)
        assert f.status is Status.FAIL
        assert f.affected_objects == ["fw2", "0001"]
        ok = _snap(ngfw_devices=[{"name": "fw1", "connected": True}])
        assert bpa.check_ngw_001(ok).status is Status.PASS

    def test_ngw_002_version_uniformity(self) -> None:
        assert bpa.check_ngw_002(_snap()).status is Status.SKIP
        assert bpa.check_ngw_002(_snap(ngfw_devices=[{"name": "fw"}])).status is Status.SKIP

        uniform = _snap(ngfw_devices=[{"sw_version": "11.1.4"}, {"sw_version": "11.1.4"}])
        f = bpa.check_ngw_002(uniform)
        assert f.status is Status.PASS and "11.1.4" in f.description

        mixed = _snap(
            ngfw_devices=[
                {"software_version": "11.1.4"},
                {"software_version": "11.1.4"},
                {"software_version": "10.2.9"},
            ]
        )
        f = bpa.check_ngw_002(mixed)
        assert f.status is Status.WARN
        assert "11.1.4 (2 devices)" in f.description and "10.2.9 (1 device)" in f.description

    def test_ngw_003_registration(self) -> None:
        assert bpa.check_ngw_003(_snap()).status is Status.WARN
        assert bpa.check_ngw_003(_snap(ngfw_devices=[{"name": "fw"}])).status is Status.PASS


# ── Registry ───────────────────────────────────────────────────────────────


class TestRunAllChecks:
    def test_every_check_runs_on_an_empty_snapshot(self) -> None:
        findings = bpa.run_all_checks(_snap())
        assert len(findings) == len(bpa._ALL_CHECKS)
        # No check should blow up on an empty snapshot
        assert not [f for f in findings if f.title.startswith("Check error")]

    def test_check_ids_are_unique(self) -> None:
        ids = [f.check_id for f in bpa.run_all_checks(_snap())]
        assert len(ids) == len(set(ids))

    def test_crashing_check_degrades_to_skip(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def boom(_snap: AuditSnapshot) -> Any:
            raise RuntimeError("kaboom")

        monkeypatch.setattr(bpa, "_ALL_CHECKS", [bpa.check_tp_002, boom])
        findings = bpa.run_all_checks(_snap())
        assert findings[0].check_id == "BPA-TP-002"
        assert findings[1].status is Status.SKIP
        assert "kaboom" in findings[1].description
        assert findings[1].check_id == "boom"
