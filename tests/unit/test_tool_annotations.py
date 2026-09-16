"""MCP ToolAnnotations coverage and classification tests.

Every registered tool must carry annotations. Adding a tool without a
manifest classification fails here (and in test_planner_manifest.py).
"""

from __future__ import annotations

import asyncio

import pytest
from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.planner import UnknownToolError, load_manifest
from scm_harbourmaster_mcp.utils.tool_annotations import (
    CLOSED_WORLD_TOOLS,
    DESTRUCTIVE_TOOLS,
    IDEMPOTENT_WRITE_TOOLS,
    annotations_for,
    apply_tool_annotations,
    tool_access,
    tool_title,
)


def _server() -> FastMCP:
    from scm_harbourmaster_mcp.server import register_all_tools
    from scm_harbourmaster_mcp.tools.reload import register_reload_tool

    mcp = FastMCP("annotations-test")
    register_all_tools(mcp, get_client=lambda tid="": None, get_settings=lambda: None)
    register_reload_tool(
        mcp,
        reregister=lambda: register_all_tools(
            mcp, get_client=lambda tid="": None, get_settings=lambda: None
        ),
    )
    return mcp


class TestCoverage:
    def test_every_registered_tool_has_annotations(self) -> None:
        tools = asyncio.run(_server().list_tools())
        assert len(tools) >= 160
        missing = [t.name for t in tools if t.annotations is None]
        assert not missing, f"Tools without ToolAnnotations: {sorted(missing)}"
        for t in tools:
            ann = t.annotations
            assert ann is not None
            assert ann.readOnlyHint is not None, t.name
            assert ann.destructiveHint is not None, t.name
            assert ann.idempotentHint is not None, t.name
            assert ann.openWorldHint is not None, t.name
            assert ann.title, t.name

    def test_apply_reports_no_unclassified_tools(self) -> None:
        assert apply_tool_annotations(_server()) == []

    def test_hint_sets_only_name_real_write_tools(self) -> None:
        manifest = load_manifest()
        writes = set(manifest.write_tools())
        assert writes >= DESTRUCTIVE_TOOLS
        assert writes >= IDEMPOTENT_WRITE_TOOLS
        assert set(manifest.policies) >= CLOSED_WORLD_TOOLS

    def test_annotations_survive_hot_reload(self) -> None:
        mcp = _server()
        scm_reload = mcp._tool_manager.get_tool("scm_reload")
        assert scm_reload is not None
        # An unknown module name is skipped, so nothing is actually reloaded —
        # but tool re-registration still runs.
        out = scm_reload.fn(modules=["not_a_loaded_module"])
        assert "Re-registered" in out
        tools = asyncio.run(mcp.list_tools())
        assert all(t.annotations is not None for t in tools)


class TestClassification:
    def test_access_lookup(self) -> None:
        assert tool_access("scm_address_list") == "read"
        assert tool_access("scm_commit") == "write"
        assert tool_access("scm_compliance_framework") == "write"
        assert tool_access("scm_compliance_center") == "read"

    def test_unknown_tool_raises(self) -> None:
        with pytest.raises(UnknownToolError):
            tool_access("scm_tool_that_does_not_exist")

    @pytest.mark.parametrize(
        "name", ["scm_address_list", "sdwan_list_sites", "scm_asbuilt_report", "scm_config_backup"]
    )
    def test_read_tools(self, name: str) -> None:
        ann = annotations_for(name)
        assert ann.readOnlyHint is True
        assert ann.destructiveHint is False
        assert ann.idempotentHint is True
        assert ann.openWorldHint is True

    @pytest.mark.parametrize(
        "name", ["scm_address_create", "scm_commit", "scm_cert_import", "dlp_restore"]
    )
    def test_additive_write_tools(self, name: str) -> None:
        ann = annotations_for(name)
        assert ann.readOnlyHint is False
        assert ann.destructiveHint is False
        assert ann.idempotentHint is False

    @pytest.mark.parametrize(
        "name",
        [
            "scm_security_rule_delete",
            "scm_config_rollback",
            "mssp_evict_tenant",
            "scm_compliance_framework",
        ],
    )
    def test_destructive_tools(self, name: str) -> None:
        ann = annotations_for(name)
        assert ann.readOnlyHint is False
        assert ann.destructiveHint is True

    def test_ssr_is_idempotent_write(self) -> None:
        ann = annotations_for("scm_ssr_execute")
        assert ann.readOnlyHint is False
        assert ann.idempotentHint is True

    def test_local_only_tools_are_closed_world(self) -> None:
        assert annotations_for("scm_reload").openWorldHint is False
        assert annotations_for("scm_planner_status").openWorldHint is False

    def test_title(self) -> None:
        assert tool_title("sdwan_list_sites") == "SD-WAN List Sites"
        assert tool_title("scm_ncsc_gap") == "SCM NCSC Gap"
