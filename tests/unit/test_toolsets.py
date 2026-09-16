"""Toolset filtering + read-only mode tests."""

from __future__ import annotations

import pytest
from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp import server
from scm_harbourmaster_mcp.config.settings import Settings
from scm_harbourmaster_mcp.planner import load_manifest
from scm_harbourmaster_mcp.planner.manifest import UnknownToolError
from scm_harbourmaster_mcp.server import register_all_tools
from scm_harbourmaster_mcp.tools.reload import register_reload_tool
from scm_harbourmaster_mcp.toolsets import (
    CORE_TOOLSET,
    PROFILES,
    TOOLSETS,
    UnknownToolsetError,
    _is_write_tool,
    parse_toolset_names,
    resolve_toolsets,
)


def _tools(toolsets: list[str] | str | None = None, read_only: bool = False) -> set[str]:
    mcp = FastMCP("toolset-test")
    register_all_tools(
        mcp,
        get_client=lambda tid="": None,
        get_settings=lambda: None,
        toolsets=toolsets,
        read_only=read_only,
    )
    return {t.name for t in mcp._tool_manager.list_tools()}


CORE_TOOLS = _tools([CORE_TOOLSET])


class TestDefinitions:
    def test_every_registrar_belongs_to_exactly_one_toolset(self) -> None:
        mapped = [r for regs in TOOLSETS.values() for r in regs]
        assert len(mapped) == len(set(mapped)), "a registrar is in two toolsets"
        assert set(mapped) == set(server._registrars(lambda: None, lambda: None))

    def test_profiles_only_reference_real_toolsets(self) -> None:
        for profile, members in PROFILES.items():
            assert set(members) <= set(TOOLSETS), profile
            assert profile not in TOOLSETS


class TestFiltering:
    def test_default_registers_all(self) -> None:
        everything = _tools()
        assert everything == _tools([]) == _tools(["all"])
        union: set[str] = set()
        for name in TOOLSETS:
            union |= _tools([name])
        assert everything == union
        assert len(everything) >= 150

    def test_filter_by_toolset(self) -> None:
        tools = _tools(["sdwan"])
        assert "sdwan_list_sites" in tools
        assert "scm_address_list" not in tools
        assert tools >= CORE_TOOLS
        assert all(t.startswith("sdwan_") for t in tools - CORE_TOOLS)

    def test_comma_separated_string_and_case(self) -> None:
        assert _tools("SDWAN, objects") == _tools(["sdwan", "objects"])

    def test_profile_expands(self) -> None:
        expected: set[str] = set()
        for member in PROFILES["noc"]:
            expected |= _tools([member])
        assert _tools(["noc"]) == expected
        assert "scm_tenant_dashboard" in expected
        assert "scm_incident_summary" in expected

    def test_core_always_included(self) -> None:
        assert "scm_folder_list" in _tools(["dlp"])
        assert CORE_TOOLSET in resolve_toolsets(["dlp"])

    def test_unknown_toolset_errors_clearly(self) -> None:
        with pytest.raises(UnknownToolsetError) as exc:
            resolve_toolsets(["sdwan", "sd-wan-typo"])
        msg = str(exc.value)
        assert "sd-wan-typo" in msg
        assert "sdwan" in msg and "noc" in msg  # lists valid choices

    def test_unknown_toolset_errors_from_register_all_tools(self) -> None:
        with pytest.raises(UnknownToolsetError):
            _tools(["nope"])


class TestReadOnly:
    def test_read_only_removes_write_tools(self) -> None:
        tools = _tools(read_only=True)
        for write in (
            "scm_commit",
            "scm_address_create",
            "scm_security_rule_delete",
            "scm_config_rollback",
            "dlp_restore",
            "scm_site_management",
            "scm_tls_profile_manager",
        ):
            assert write not in tools, write
        for read in ("scm_address_list", "scm_commit_preview", "scm_ir_trigger", "sdwan_events"):
            assert read in tools, read

    def test_read_only_matches_planner_manifest_write_set(self) -> None:
        removed = _tools() - _tools(read_only=True)
        manifest_writes = set(load_manifest().write_tools()) - {"scm_reload", "scm_restart"}
        assert removed == manifest_writes

    def test_is_write_tool_follows_manifest(self) -> None:
        assert _is_write_tool("scm_address_create")
        assert _is_write_tool("scm_config_push_track")
        # Regression: action-dispatch writer whose name and schema carry no
        # signal — the old name/schema heuristic missed it.
        assert _is_write_tool("scm_compliance_framework")
        assert not _is_write_tool("scm_commit_preview")
        assert not _is_write_tool("scm_address_list")
        assert not _is_write_tool("scm_ir_trigger")  # read-only triage templates
        with pytest.raises(UnknownToolError):
            _is_write_tool("scm_thing")  # unclassified tools fail loudly

    def test_read_only_combines_with_toolsets(self) -> None:
        tools = _tools(["objects"], read_only=True)
        assert "scm_address_list" in tools
        assert "scm_address_create" not in tools


class TestReload:
    def test_reregister_respects_filter(self) -> None:
        mcp = FastMCP("reload-test")

        def _register() -> None:
            register_all_tools(
                mcp, lambda tid="": None, lambda: None, toolsets=["sdwan"], read_only=True
            )

        _register()
        register_reload_tool(mcp, reregister=_register)
        before = {t.name for t in mcp._tool_manager.list_tools()}
        assert {"scm_reload", "scm_restart"} <= before

        result = mcp._tool_manager.get_tool("scm_reload").fn(modules=["no_such_module"])
        assert "Re-registered" in result
        after = {t.name for t in mcp._tool_manager.list_tools()}
        assert after == before
        assert "scm_address_list" not in after


class TestSettings:
    def test_defaults_are_all_and_writable(self) -> None:
        s = Settings()
        assert s.enabled_toolsets == []
        assert s.read_only is False

    def test_env_overrides(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SCM_MCP_ENABLED_TOOLSETS", "sdwan, noc")
        monkeypatch.setenv("SCM_MCP_READ_ONLY", "true")
        s = Settings()
        assert s.enabled_toolsets == ["sdwan", "noc"]
        assert s.read_only is True

    def test_json_list_string(self) -> None:
        assert parse_toolset_names('["sdwan", "ops"]') == ["sdwan", "ops"]
