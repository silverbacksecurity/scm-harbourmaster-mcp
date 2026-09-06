"""Unit tests for the Gold / Silver / Bronze tier engine."""

from __future__ import annotations

import pytest

from scm_harbourmaster_mcp.audit.models import Finding, Severity, Status
from scm_harbourmaster_mcp.audit.tiers import (
    TIER_ORDER,
    TIERS,
    get_tier,
    score_findings_against_tier,
    upgrade_gap,
)
from scm_harbourmaster_mcp.config.settings import TenantConfig


def _finding(check_id: str, severity: Severity, status: Status) -> Finding:
    return Finding(
        check_id=check_id,
        title=f"Test {check_id}",
        severity=severity,
        status=status,
        description="test",
        remediation="fix it",
    )


class TestTierDefinitions:
    def test_all_three_tiers_exist(self) -> None:
        assert set(TIERS.keys()) == {"gold", "silver", "bronze"}

    def test_tier_order_is_ascending(self) -> None:
        assert TIER_ORDER == ["bronze", "silver", "gold"]

    def test_get_tier_valid(self) -> None:
        t = get_tier("gold")
        assert t.name == "gold"
        assert t.label == "Gold"

    def test_get_tier_case_insensitive(self) -> None:
        assert get_tier("SILVER").name == "silver"
        assert get_tier("Bronze").name == "bronze"

    def test_get_tier_invalid_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown tier"):
            get_tier("platinum")

    def test_bronze_requires_only_critical(self) -> None:
        t = get_tier("bronze")
        assert t.required_severities == (Severity.CRITICAL,)

    def test_silver_requires_critical_and_high(self) -> None:
        t = get_tier("silver")
        assert Severity.CRITICAL in t.required_severities
        assert Severity.HIGH in t.required_severities
        assert Severity.MEDIUM not in t.required_severities

    def test_gold_requires_all_severities(self) -> None:
        t = get_tier("gold")
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
            assert sev in t.required_severities

    def test_gold_is_superset_of_silver(self) -> None:
        gold = set(get_tier("gold").required_severities)
        silver = set(get_tier("silver").required_severities)
        assert silver.issubset(gold)

    def test_silver_is_superset_of_bronze(self) -> None:
        silver = set(get_tier("silver").required_severities)
        bronze = set(get_tier("bronze").required_severities)
        assert bronze.issubset(silver)

    def test_snippets_are_non_empty(self) -> None:
        for name, tier in TIERS.items():
            assert len(tier.scm_snippets) > 0, f"{name} tier has no snippets"

    def test_ncsc_frameworks_populated(self) -> None:
        assert "CE v3.2" in get_tier("bronze").ncsc_frameworks
        assert "10 Steps" in get_tier("silver").ncsc_frameworks
        assert "CAF v4.0" in get_tier("gold").ncsc_frameworks


class TestTierScoring:
    def test_no_findings_bronze_compliant(self) -> None:
        result = score_findings_against_tier([], get_tier("bronze"))
        assert result["tier_compliant"] is True
        assert result["required_checks"] == 0
        assert result["breach_count"] == 0

    def test_critical_fail_breaches_bronze(self) -> None:
        findings = [_finding("BPA-SR-001", Severity.CRITICAL, Status.FAIL)]
        result = score_findings_against_tier(findings, get_tier("bronze"))
        assert result["tier_compliant"] is False
        assert result["breach_count"] == 1
        assert result["breaches"][0]["check_id"] == "BPA-SR-001"

    def test_high_fail_does_not_breach_bronze(self) -> None:
        findings = [_finding("BPA-SR-003", Severity.HIGH, Status.FAIL)]
        result = score_findings_against_tier(findings, get_tier("bronze"))
        # HIGH is not required at Bronze — so it goes to advisory, not breaches
        assert result["tier_compliant"] is True
        assert result["breach_count"] == 0
        assert result["advisory_count"] == 1

    def test_high_fail_breaches_silver(self) -> None:
        findings = [_finding("BPA-SR-003", Severity.HIGH, Status.FAIL)]
        result = score_findings_against_tier(findings, get_tier("silver"))
        assert result["tier_compliant"] is False
        assert result["breach_count"] == 1

    def test_medium_fail_does_not_breach_silver(self) -> None:
        findings = [_finding("BPA-TP-005", Severity.MEDIUM, Status.FAIL)]
        result = score_findings_against_tier(findings, get_tier("silver"))
        assert result["tier_compliant"] is True
        assert result["advisory_count"] == 1

    def test_medium_fail_breaches_gold(self) -> None:
        findings = [_finding("BPA-TP-005", Severity.MEDIUM, Status.FAIL)]
        result = score_findings_against_tier(findings, get_tier("gold"))
        assert result["tier_compliant"] is False

    def test_warn_counts_as_breach(self) -> None:
        findings = [_finding("BPA-SR-001", Severity.CRITICAL, Status.WARN)]
        result = score_findings_against_tier(findings, get_tier("bronze"))
        assert result["tier_compliant"] is False
        assert result["breach_count"] == 1

    def test_pass_does_not_breach(self) -> None:
        findings = [_finding("BPA-SR-001", Severity.CRITICAL, Status.PASS)]
        result = score_findings_against_tier(findings, get_tier("bronze"))
        assert result["tier_compliant"] is True
        assert result["passed_required"] == 1

    def test_compliance_score_pct_all_pass(self) -> None:
        findings = [
            _finding("A", Severity.CRITICAL, Status.PASS),
            _finding("B", Severity.CRITICAL, Status.PASS),
        ]
        result = score_findings_against_tier(findings, get_tier("bronze"))
        assert result["compliance_score_pct"] == 100.0

    def test_compliance_score_pct_half_fail(self) -> None:
        findings = [
            _finding("A", Severity.CRITICAL, Status.PASS),
            _finding("B", Severity.CRITICAL, Status.FAIL),
        ]
        result = score_findings_against_tier(findings, get_tier("bronze"))
        assert result["compliance_score_pct"] == 50.0


class TestUpgradeGap:
    def test_upgrade_bronze_to_silver_no_blockers_when_all_pass(self) -> None:
        findings = [
            _finding("BPA-SR-001", Severity.CRITICAL, Status.PASS),
            _finding("BPA-SR-003", Severity.HIGH, Status.PASS),
        ]
        result = upgrade_gap(findings, "bronze", "silver")
        assert result["upgrade_ready"] is True
        assert result["blocking_count"] == 0

    def test_upgrade_bronze_to_silver_blocked_by_high_fail(self) -> None:
        findings = [
            _finding("BPA-SR-003", Severity.HIGH, Status.FAIL),
        ]
        result = upgrade_gap(findings, "bronze", "silver")
        assert result["upgrade_ready"] is False
        assert result["blocking_count"] == 1
        assert result["blocking_findings"][0]["check_id"] == "BPA-SR-003"

    def test_upgrade_identifies_new_snippets(self) -> None:
        result = upgrade_gap([], "bronze", "silver")
        bronze_snips = set(get_tier("bronze").scm_snippets)
        silver_snips = set(get_tier("silver").scm_snippets)
        expected_new = silver_snips - bronze_snips
        assert set(result["snippets_to_apply"]) == expected_new

    def test_upgrade_gold_identifies_additional_ncsc_controls(self) -> None:
        result = upgrade_gap([], "silver", "gold")
        silver_ncsc = set(get_tier("silver").required_ncsc_controls)
        gold_ncsc = set(get_tier("gold").required_ncsc_controls)
        expected_extra = gold_ncsc - silver_ncsc
        assert set(result["additional_ncsc_controls"]) == expected_extra

    def test_same_tier_raises(self) -> None:
        # upgrade_gap doesn't validate this — the tool layer does
        # but we can assert the logic still works (no crash)
        result = upgrade_gap([], "gold", "gold")
        assert result["blocking_count"] == 0

    def test_upgrade_skips_two_tiers(self) -> None:
        findings = [
            _finding("BPA-SR-003", Severity.HIGH, Status.FAIL),
            _finding("BPA-TP-005", Severity.MEDIUM, Status.FAIL),
        ]
        result = upgrade_gap(findings, "bronze", "gold")
        # Both HIGH and MEDIUM are extra vs bronze
        assert result["blocking_count"] == 2


class TestTenantConfigTierField:
    def test_default_tier_is_bronze(self) -> None:
        tc = TenantConfig(
            tenant_id="t-1",
            client_id="svc@iam",
            client_secret="s",
        )
        assert tc.tier == "bronze"

    def test_tier_gold_accepted(self) -> None:
        tc = TenantConfig(
            tenant_id="t-1",
            client_id="svc@iam",
            client_secret="s",
            tier="gold",
        )
        assert tc.tier == "gold"

    def test_service_term_default_one_year(self) -> None:
        tc = TenantConfig(
            tenant_id="t-1",
            client_id="svc@iam",
            client_secret="s",
        )
        assert tc.service_term_years == 1

    def test_service_term_accepts_three_years(self) -> None:
        tc = TenantConfig(
            tenant_id="t-1",
            client_id="svc@iam",
            client_secret="s",
            service_term_years=3,
        )
        assert tc.service_term_years == 3

    def test_account_ref_optional(self) -> None:
        tc = TenantConfig(
            tenant_id="t-1",
            client_id="svc@iam",
            client_secret="s",
            account_ref="CRM-99",
        )
        assert tc.account_ref == "CRM-99"
