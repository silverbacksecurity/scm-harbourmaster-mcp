"""Unit tests for scripts/gen_docs.py's AST-based tool-signature extraction.

Guards against the class of bug found while auditing the @scm_tool rollout:
gen_docs.py parses tool functions' *raw* source signatures, but functions
decorated with @scm_tool (utils/tool_decorator.py) have a different exposed
signature at runtime — `client` (and an optional `tenant_id` passthrough
param) collapse into one synthesized `tenant_id: str = ""`. Naively using
the raw signature leaked `client` into the docs and dropped `tenant_id`
entirely for every migrated tool until this was caught and fixed.
"""

from __future__ import annotations

import importlib.util
import textwrap
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "gen_docs", Path(__file__).parent.parent.parent / "scripts" / "gen_docs.py"
)
gen_docs = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(gen_docs)


def _write_tool_module(tmp_path: Path, source: str) -> Path:
    path = tmp_path / "fake_tools.py"
    path.write_text(textwrap.dedent(source))
    return path


def test_scm_tool_decorated_function_hides_client_and_exposes_tenant_id(tmp_path: Path) -> None:
    path = _write_tool_module(
        tmp_path,
        '''
        """Fake module."""
        from typing import Any
        from mcp.server.fastmcp import FastMCP

        def register_fake_tools(mcp: FastMCP, get_client: Any) -> None:
            tool = scm_tool(get_client)

            @mcp.tool()
            @tool
            def scm_fake_list(client: Any, folder: str, limit: int = 200) -> str:
                """List fakes.

                Args:
                    folder: SCM folder.
                    tenant_id: SCM tenant ID.
                    limit: Maximum results.
                """
                return ""
        ''',
    )
    tools = gen_docs.get_tools(path)
    assert len(tools) == 1
    _, _, args = tools[0]
    names = [a[0] for a in args]
    assert "client" not in names
    assert names[0] == "tenant_id"
    assert args[0] == ("tenant_id", "str", "''")
    assert "folder" in names
    assert "limit" in names


def test_scm_tool_with_tenant_id_passthrough_is_not_duplicated(tmp_path: Path) -> None:
    path = _write_tool_module(
        tmp_path,
        '''
        """Fake module."""
        from typing import Any
        from mcp.server.fastmcp import FastMCP

        def register_fake_tools(mcp: FastMCP, get_client: Any) -> None:
            tool = scm_tool(get_client)

            @mcp.tool()
            @tool
            def scm_fake_report(client: Any, tenant_id: str, folder: str = "Shared") -> str:
                """Report needing the resolved tenant_id for display."""
                return ""
        ''',
    )
    tools = gen_docs.get_tools(path)
    _, _, args = tools[0]
    names = [a[0] for a in args]
    assert names.count("tenant_id") == 1
    assert names[0] == "tenant_id"
    assert args[0] == ("tenant_id", "str", "''")
    assert names == ["tenant_id", "folder"]


def test_non_scm_tool_function_uses_its_raw_signature_unchanged(tmp_path: Path) -> None:
    path = _write_tool_module(
        tmp_path,
        '''
        """Fake module."""
        from typing import Any
        from mcp.server.fastmcp import FastMCP

        def register_fake_tools(mcp: FastMCP, get_client: Any) -> None:
            @mcp.tool()
            def scm_fake_plain(folder: str, tenant_id: str = "", limit: int = 200) -> str:
                """Plain tool, not migrated to @scm_tool."""
                return ""
        ''',
    )
    tools = gen_docs.get_tools(path)
    _, _, args = tools[0]
    assert args == [
        ("folder", "str", ""),
        ("tenant_id", "str", "''"),  # ast.unparse normalizes string literals to single quotes
        ("limit", "int", "200"),
    ]


@pytest.mark.parametrize(
    "fpath",
    sorted((Path(__file__).parent.parent.parent / "src/scm_harbourmaster_mcp/tools").glob("*.py")),
    ids=lambda p: p.name,
)
def test_no_real_tool_module_leaks_client_into_generated_docs(fpath: Path) -> None:
    if fpath.name == "__init__.py":
        pytest.skip("not a tool module")
    for name, _doc, args in gen_docs.get_tools(fpath):
        arg_names = [a[0] for a in args]
        assert "client" not in arg_names, f"{fpath.name}:{name} leaks `client` into generated docs"
