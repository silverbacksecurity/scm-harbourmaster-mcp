"""scm_reload's module list must stay complete and dependency-ordered (no network).

A module missing from the list is never reloaded, so an importer reloaded after
it binds the stale copy — a new function then fails to import mid-reload. A
module reloaded before a package module it imports binds that module's old
objects. Both are checked against the package's actual top-level imports.
"""

from __future__ import annotations

import ast
import sys
import types
from pathlib import Path

import pytest
from mcp.server.fastmcp import FastMCP

import scm_harbourmaster_mcp
from scm_harbourmaster_mcp.tools import reload as reload_mod

PKG = "scm_harbourmaster_mcp"
ROOT = Path(scm_harbourmaster_mcp.__file__).parent
SCOPE = ("utils", "auth", "audit", "tools")


def _package_modules() -> dict[str, Path]:
    mods: dict[str, Path] = {}
    for path in ROOT.rglob("*.py"):
        parts = path.relative_to(ROOT.parent).with_suffix("").parts
        name = ".".join(parts[:-1]) if parts[-1] == "__init__" else ".".join(parts)
        mods[name] = path
    return mods


MODULES = _package_modules()


def _top_level_imports(name: str, path: Path) -> set[str]:
    """Package modules *name* imports at module level (including inside
    module-level if/try blocks); imports inside functions resolve at call
    time and don't constrain reload order."""
    package = name if path.name == "__init__.py" else name.rsplit(".", 1)[0]
    found: set[str] = set()
    for stmt in ast.parse(path.read_text()).body:
        nodes = list(ast.walk(stmt)) if isinstance(stmt, ast.If | ast.Try) else [stmt]
        for node in nodes:
            if isinstance(node, ast.ImportFrom):
                if node.level:
                    base = package.split(".")
                    if node.level > 1:
                        base = base[: len(base) - (node.level - 1)]
                    target = ".".join(base + ([node.module] if node.module else []))
                else:
                    target = node.module or ""
                for alias in node.names:
                    candidate = f"{target}.{alias.name}"
                    found.add(candidate if candidate in MODULES else target)
            elif isinstance(node, ast.Import):
                found.update(alias.name for alias in node.names)
    return {m for m in found if m in MODULES and m != name}


def test_every_scoped_module_is_listed_or_excluded() -> None:
    scoped = {n for n in MODULES if n.split(".")[1:2] and n.split(".")[1] in SCOPE}
    scoped -= {f"{PKG}.{s}" for s in SCOPE}  # package __init__s
    listed = set(reload_mod._RELOAD_ORDER)
    missing = sorted(scoped - listed - reload_mod._RELOAD_EXCLUDED)
    assert not missing, f"add to _RELOAD_ORDER (or _RELOAD_EXCLUDED): {missing}"


def test_listed_modules_exist_and_are_unique() -> None:
    order = reload_mod._RELOAD_ORDER
    assert len(order) == len(set(order))
    assert not [n for n in order if n not in MODULES]
    assert not set(order) & reload_mod._RELOAD_EXCLUDED


def test_modules_reload_after_their_package_imports() -> None:
    position = {n: i for i, n in enumerate(reload_mod._RELOAD_ORDER)}
    late = [
        (name, dep)
        for name in reload_mod._RELOAD_ORDER
        for dep in _top_level_imports(name, MODULES[name])
        if dep in position and position[dep] > position[name]
    ]
    assert not late, f"reloaded before a module it imports: {late}"


@pytest.fixture
def reload_tool(monkeypatch: pytest.MonkeyPatch):
    """scm_reload with importlib.reload stubbed and two fake loaded modules."""
    reloaded: list[str] = []
    order = [f"{PKG}.utils.capabilities", f"{PKG}.tools.capabilities", f"{PKG}.tools.ssr"]
    monkeypatch.setattr(reload_mod, "_RELOAD_ORDER", order)
    for name in order:
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    monkeypatch.setattr(reload_mod.importlib, "reload", lambda m: reloaded.append(m.__name__))
    monkeypatch.setattr(reload_mod, "_patch_cross_module_refs", lambda: [])
    mcp = FastMCP("test")
    reload_mod.register_reload_tool(mcp)
    return mcp._tool_manager.get_tool("scm_reload").fn, reloaded


def test_short_name_reloads_every_match_in_order(reload_tool) -> None:
    fn, reloaded = reload_tool
    fn(modules=["capabilities"])
    assert reloaded == [f"{PKG}.utils.capabilities", f"{PKG}.tools.capabilities"]


def test_unknown_module_is_reported_not_skipped(reload_tool) -> None:
    fn, reloaded = reload_tool
    out = fn(modules=["ssr", "no_such_module"])
    assert reloaded == [f"{PKG}.tools.ssr"]
    assert "no_such_module: not in the reload list" in out
    assert "Skipped" not in out
