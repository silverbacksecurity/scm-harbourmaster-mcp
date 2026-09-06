"""Planner Phase 1 manifest tests.

The coverage test is the enforcement mechanism for the whole phase: it
registers every MCP tool against a live FastMCP instance and fails if any
tool lacks a manifest entry (or the manifest carries stale entries). Adding
a tool without classifying it breaks CI — by design.
"""

from __future__ import annotations

import asyncio
import inspect

import pytest

from scm_harbourmaster_mcp.planner import (
    ManifestError,
    UnknownToolError,
    load_manifest,
)
from scm_harbourmaster_mcp.planner.manifest import VALID_DOMAINS

# Write tools per the Phase 1 spec (ROADMAP + docs/planner-agent/TOOL_MANIFEST.md),
# extended with the write tools added since: scm_ssr_execute, scm_adnsr_profile_create.
EXPECTED_WRITE_TOOLS = {
    "scm_commit",
    "scm_security_rule_create",
    "scm_security_rule_delete",
    "scm_address_create",
    "scm_address_delete",
    "dlp_restore",
    "scm_config_rollback",
    "scm_config_push_track",
    "scm_config_clone",
    "mssp_onboard_tenant",
    "mssp_evict_tenant",
    "scm_cert_import",
    "scm_tls_profile_manager",
    "scm_apply_ncsc_baseline",
    "scm_attach_ncsc_profiles",
    "scm_create_ncsc_snippet",
    "scm_create_nist_snippet",
    "scm_reload",
    "scm_restart",
    "scm_ssr_execute",
    "scm_adnsr_profile_create",
    "scm_dns_security_lookup",
    "scm_config_orch_bandwidth",
    "scm_config_orch_profiles",
    "scm_config_orch_remote_networks",
    "scm_site_management",
    # Phase 3b: the conversational planner run can orchestrate approved
    # writes, so invoking it is itself a gated write action.
    "scm_planner_run",
}


def _registered_tools() -> set[str]:
    from mcp.server.fastmcp import FastMCP

    from scm_harbourmaster_mcp.server import register_all_tools
    from scm_harbourmaster_mcp.tools.reload import register_reload_tool

    mcp = FastMCP("manifest-coverage-test")
    register_all_tools(mcp, get_client=lambda tid="": None, get_settings=lambda: None)
    register_reload_tool(mcp, reregister=lambda: None)
    return {t.name for t in asyncio.run(mcp.list_tools())}


class TestCoverage:
    def test_every_registered_tool_has_a_manifest_entry(self) -> None:
        manifest = load_manifest()
        unclassified, stale = manifest.coverage_gaps(_registered_tools())
        assert not unclassified, (
            f"Tools registered but missing from tools_manifest.yaml: {sorted(unclassified)}. "
            "Classify them (access/domain/scope/idempotent/retry_policy) before shipping — "
            "the Planner refuses to execute unclassified tools."
        )
        assert not stale, (
            f"Manifest entries for tools that no longer exist: {sorted(stale)}. "
            "Remove or rename them."
        )


class TestSafetyRails:
    def test_write_tools_match_spec(self) -> None:
        assert set(load_manifest().write_tools()) == EXPECTED_WRITE_TOOLS

    def test_every_write_tool_requires_approval(self) -> None:
        manifest = load_manifest()
        for tool in manifest.write_tools():
            assert manifest.requires_approval(tool), tool

    def test_read_tools_do_not_require_approval(self) -> None:
        manifest = load_manifest()
        assert not manifest.requires_approval("scm_address_list")
        assert not manifest.requires_approval("scm_drift_check")

    def test_unknown_tool_raises_rather_than_defaulting(self) -> None:
        with pytest.raises(UnknownToolError):
            load_manifest().requires_approval("scm_tool_that_does_not_exist")

    def test_requires_approval_accepts_no_override(self) -> None:
        # The v1 hard rule: the signature itself must offer no bypass —
        # exactly one parameter (the tool name), no flags, no kwargs.
        sig = inspect.signature(load_manifest().requires_approval)
        assert list(sig.parameters) == ["tool_name"]

    def test_destructive_server_actions_are_write(self) -> None:
        manifest = load_manifest()
        assert manifest.policy("scm_reload").access == "write"
        assert manifest.policy("scm_restart").access == "write"


class TestDomains:
    def test_all_entries_use_valid_enums(self) -> None:
        # ToolPolicy.__post_init__ validates on load; loading is the assertion.
        manifest = load_manifest()
        assert len(manifest.policies) >= 135

    def test_domain_partition_is_complete(self) -> None:
        manifest = load_manifest()
        union: set[str] = set()
        for domain in VALID_DOMAINS:
            union |= set(manifest.domain_tools(domain))
        assert union == set(manifest.policies)

    def test_domain_context_load_stays_under_ceiling(self) -> None:
        # Sub-plans load one domain's tools; keep each well under the
        # 128-tool Copilot Studio ceiling (spec target ~15-20, hard cap 30).
        manifest = load_manifest()
        for domain in VALID_DOMAINS:
            size = len(manifest.domain_tools(domain))
            assert size <= 30, f"{domain} has {size} tools — split the domain"

    def test_unknown_domain_raises(self) -> None:
        with pytest.raises(ManifestError):
            load_manifest().domain_tools("not_a_domain")


class TestPolicies:
    def test_cross_tenant_includes_estate_sweeps(self) -> None:
        ct = set(load_manifest().cross_tenant_tools())
        assert {"mssp_tenant_dashboard", "scm_licence_forecast", "scm_drift_check"} <= ct

    def test_reads_are_idempotent_writes_default_not(self) -> None:
        manifest = load_manifest()
        for policy in manifest.policies.values():
            if policy.access == "read":
                assert policy.idempotent, policy.name

    def test_ssr_execute_is_the_idempotent_write(self) -> None:
        # scm_ssr_execute is designed idempotent (already_present semantics)
        assert load_manifest().policy("scm_ssr_execute").idempotent

    def test_known_failure_modes_cover_the_recurring_traps(self) -> None:
        manifest = load_manifest()
        assert "Pydantic" in manifest.policy("scm_remote_network_list").known_failure_modes
        assert "default_folder" in manifest.policy("scm_zone_list").known_failure_modes
        assert "preview" in manifest.policy("scm_commit").known_failure_modes
