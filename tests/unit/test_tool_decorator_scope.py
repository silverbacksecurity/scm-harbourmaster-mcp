"""Architectural guard: @scm_tool must not wrap tools that resolve their own
client conditionally.

The decorator resolves `get_client(tenant_id)` eagerly, before the function
body runs. That is correct for the ~105 tools that always operate on exactly
one tenant, but WRONG for tools that only need a single-tenant client on some
code paths:

  * cross-tenant sweeps (`all_tenants=True`) build their own per-tenant
    clients and must survive one tenant having bad credentials — there is a
    comment in posture.py saying exactly that;
  * tools that can load from a saved file instead of the API need no client
    at all on that path.

Migrating those eagerly made the whole call fail whenever the single
`tenant_id` was unresolvable, even though it was never needed. That
regression shipped once (caught by live tenant testing, reverted); these
tests keep it from coming back.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

TOOLS_DIR = Path(__file__).parent.parent.parent / "src/scm_mcp_mssp/tools"

# Parameters implying the tool serves more than one tenant, or can skip the
# API entirely — both mean the client must stay lazily/conditionally resolved.
CONDITIONAL_CLIENT_PARAMS = {"all_tenants", "load_from"}


def _tool_functions(path: Path) -> list[ast.FunctionDef]:
    tree = ast.parse(path.read_text())
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        if any(
            (isinstance(d, ast.Attribute) and d.attr == "tool")
            or (
                isinstance(d, ast.Call)
                and isinstance(d.func, ast.Attribute)
                and d.func.attr == "tool"
            )
            for d in node.decorator_list
        ):
            out.append(node)
    return out


def _uses_scm_tool(node: ast.FunctionDef) -> bool:
    return any(isinstance(d, ast.Name) and d.id == "tool" for d in node.decorator_list)


@pytest.mark.parametrize(
    "fpath",
    sorted(p for p in TOOLS_DIR.glob("*.py") if p.name != "__init__.py"),
    ids=lambda p: p.name,
)
def test_conditional_client_tools_are_not_scm_tool_decorated(fpath: Path) -> None:
    for node in _tool_functions(fpath):
        if not _uses_scm_tool(node):
            continue
        params = {a.arg for a in node.args.args}
        clash = params & CONDITIONAL_CLIENT_PARAMS
        assert not clash, (
            f"{fpath.name}:{node.name} takes {sorted(clash)} but is decorated with @scm_tool. "
            "The decorator resolves get_client(tenant_id) eagerly, which breaks the path "
            "where that client is not needed (e.g. an all_tenants sweep must survive one "
            "tenant's credentials failing). Resolve the client inside the function instead."
        )


@pytest.mark.parametrize(
    "fpath",
    sorted(p for p in TOOLS_DIR.glob("*.py") if p.name != "__init__.py"),
    ids=lambda p: p.name,
)
def test_scm_tool_functions_do_not_also_call_get_client(fpath: Path) -> None:
    """A @scm_tool function already receives `client`; calling get_client()
    again inside it means the migration was incomplete or the tool has a
    second, conditional resolution path that the decorator cannot model."""
    for node in _tool_functions(fpath):
        if not _uses_scm_tool(node):
            continue
        for sub in ast.walk(node):
            if (
                isinstance(sub, ast.Call)
                and isinstance(sub.func, ast.Name)
                and sub.func.id == "get_client"
            ):
                pytest.fail(
                    f"{fpath.name}:{node.name} is @scm_tool-decorated but still calls "
                    "get_client() internally."
                )
