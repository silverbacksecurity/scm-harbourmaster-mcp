"""scm_config_diff must survive every shape scm_config_backup writes.

Not every resource type is a list of named objects: singleton config blobs
(bgp_routing_config, mobile_agent_global_settings) are stored as a bare dict,
and a few types are plain lists of strings.  Indexing those as dicts raised
``AttributeError: 'str' object has no attribute 'get'`` and killed the whole
diff — see _index_backup_resources.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.tools import audit as audit_mod
from scm_harbourmaster_mcp.tools.audit import _index_backup_resources


@pytest.fixture
def diff_tool() -> Any:
    mcp = FastMCP("test")
    audit_mod.register_audit_tools(mcp, lambda tenant_id="": object())
    return mcp._tool_manager.get_tool("scm_config_diff").fn


def _write(path: Path, resources: dict[str, Any]) -> str:
    path.write_text(json.dumps({"folder": "ngfw-shared", "resources": resources}))
    return str(path)


def test_indexer_handles_each_backup_shape():
    assert _index_backup_resources({"agent_version": "6.2.3"}) == {"agent_version": "6.2.3"}
    assert _index_backup_resources([{"name": "a"}]) == {"a": {"name": "a"}}
    assert _index_backup_resources([{"id": "u-1"}]) == {"u-1": {"id": "u-1"}}
    assert _index_backup_resources([{}]) == {"0": {}}
    assert _index_backup_resources(["one"]) == {"one": "one"}
    assert _index_backup_resources(None) == {}


def test_diff_reports_field_changes_in_singleton_blobs(diff_tool, tmp_path):
    a = _write(tmp_path / "a.json", {"mobile_agent_global_settings": {"agent_version": "6.2.3"}})
    b = _write(
        tmp_path / "b.json", {"mobile_agent_global_settings": {"agent_version": "6.3.3-1121"}}
    )

    diff = json.loads(diff_tool(a, b))

    assert diff["changes"]["mobile_agent_global_settings"]["modified"] == ["agent_version"]


def test_diff_reports_membership_of_string_lists(diff_tool, tmp_path):
    a = _write(tmp_path / "a.json", {"snippets": ["default", "Custom-Interfaces-Snippet"]})
    b = _write(tmp_path / "b.json", {"snippets": ["default", "GlobalProtect-Default"]})

    diff = json.loads(diff_tool(a, b))

    assert diff["changes"]["snippets"] == {
        "added": ["GlobalProtect-Default"],
        "removed": ["Custom-Interfaces-Snippet"],
        "modified": [],
    }


def test_diff_of_mixed_shapes_does_not_error(diff_tool, tmp_path):
    """A singleton blob alongside normal lists must not abort the diff."""
    a = _write(
        tmp_path / "a.json",
        {
            "bgp_routing_config": {"routing_preference": {"default": {}}},
            "zones": [{"name": "internet"}, {"name": "DMZZone"}],
        },
    )
    b = _write(
        tmp_path / "b.json",
        {
            "bgp_routing_config": {"routing_preference": {"hot_potato_routing": {}}},
            "zones": [{"name": "internet"}, {"name": "local"}],
        },
    )

    out = diff_tool(a, b)

    assert not out.startswith("Error")
    diff = json.loads(out)
    assert diff["changes"]["bgp_routing_config"]["modified"] == ["routing_preference"]
    assert diff["changes"]["zones"] == {
        "added": ["local"],
        "removed": ["DMZZone"],
        "modified": [],
    }
    assert diff["summary"]["resource_types_changed"] == 2
