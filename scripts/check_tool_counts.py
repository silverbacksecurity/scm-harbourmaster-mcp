#!/usr/bin/env python3
"""Keep the tool/module counts quoted in README.md and docs/ in sync with the server.

The authoritative count comes from actually registering every tool on a throwaway
FastMCP instance (``register_all_tools`` + ``register_reload_tool``, exactly what
``create_server`` does) — no credentials or network needed.

Counts in docs live between marker comments, which render invisibly on GitHub:

    <!-- tool-count -->164<!-- /tool-count -->
    <!-- module-count -->36<!-- /module-count -->

The check fails when:
  * a marked count disagrees with the live server,
  * an *unmarked* "<N> tools" / "<N> MCP tools" / "<N> SCM operations" phrase
    appears in README.md or docs/ (add markers, or drop the number; append
    ``<!-- tool-count: ignore -->`` to the line for a deliberate exception),
  * gen_docs' AST discovery and the live registry disagree on the tool set.

Only README.md and docs/**/*.md are scanned — ROADMAP.md and CHANGELOG.md hold
historical counts that must not be rewritten.

Usage:
    uv run python scripts/check_tool_counts.py          # check, exit 1 on drift
    uv run python scripts/check_tool_counts.py --fix    # rewrite marked counts
"""

from __future__ import annotations

import argparse
import asyncio
import functools
import importlib.util
import re
import sys
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parent.parent

MARKER_RE = re.compile(r"<!-- (tool-count|module-count) -->(\d*)<!-- /\1 -->")
IGNORE_TOKEN = "tool-count: ignore"
# A bare count in prose. Ranges/approximations ("~15–20 tools") are not counts
# of the whole server, so a preceding ~, -, – or digit excludes the match.
UNMARKED_RE = re.compile(
    r"(?<![~\d\-–])\b(\d{2,4})\s+(?:MCP\s+tools|SCM\s+operations|tools)\b",
    re.IGNORECASE,
)


class Counts(NamedTuple):
    tools: int
    modules: int

    def for_kind(self, kind: str) -> int:
        return self.tools if kind == "tool-count" else self.modules


def _load_gen_docs():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("gen_docs", ROOT / "scripts" / "gen_docs.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@functools.cache
def registered_tool_names() -> frozenset[str]:
    """Tool names exposed by a fully-registered server (no credentials needed)."""
    from mcp.server.fastmcp import FastMCP

    from scm_harbourmaster_mcp.server import register_all_tools
    from scm_harbourmaster_mcp.tools.reload import register_reload_tool

    mcp = FastMCP("tool-count-check")
    register_all_tools(mcp, get_client=lambda tid="": None, get_settings=lambda: None)
    register_reload_tool(mcp, reregister=lambda: None)
    return frozenset(t.name for t in asyncio.run(mcp.list_tools()))


def documented_tool_modules() -> dict[str, set[str]]:
    """Tool module filename -> tool names, as gen_docs discovers them via AST."""
    gen_docs = _load_gen_docs()
    return {
        fname: {name for name, _doc, _args in gen_docs.get_tools(gen_docs.TOOLS_DIR / fname)}
        for fname in gen_docs._ordered_modules()
    }


def doc_files(root: Path = ROOT) -> list[Path]:
    files = [root / "README.md"] if (root / "README.md").exists() else []
    return files + sorted((root / "docs").rglob("*.md"))


def check_text(text: str, counts: Counts) -> list[str]:
    """Return human-readable problems for one document's text."""
    problems = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for m in MARKER_RE.finditer(line):
            want = counts.for_kind(m.group(1))
            if m.group(2) != str(want):
                problems.append(
                    f"line {lineno}: {m.group(1)} is {m.group(2) or '<empty>'}, expected {want}"
                )
        if IGNORE_TOKEN in line:
            continue
        for m in UNMARKED_RE.finditer(MARKER_RE.sub("", line)):
            problems.append(
                f"line {lineno}: unmarked count {m.group(0)!r} — wrap the number in "
                "<!-- tool-count --> markers or drop it"
            )
    return problems


def fix_text(text: str, counts: Counts) -> str:
    return MARKER_RE.sub(
        lambda m: f"<!-- {m.group(1)} -->{counts.for_kind(m.group(1))}<!-- /{m.group(1)} -->",
        text,
    )


def run(fix: bool = False, root: Path = ROOT) -> list[str]:
    """Check (or fix) every doc; return the remaining problems."""
    registered = registered_tool_names()
    modules = documented_tool_modules()
    ast_tools = set().union(*modules.values()) if modules else set()
    counts = Counts(tools=len(registered), modules=len(modules))

    problems = []
    if ast_tools != registered:
        problems.append(
            "gen_docs AST discovery and the live registry disagree: "
            f"only registered={sorted(registered - ast_tools)}, "
            f"only in AST={sorted(ast_tools - registered)}"
        )
    for path in doc_files(root):
        text = path.read_text()
        if fix:
            fixed = fix_text(text, counts)
            if fixed != text:
                path.write_text(fixed)
                print(f"updated {path.relative_to(root)}")
            text = fixed
        problems += [f"{path.relative_to(root)}: {p}" for p in check_text(text, counts)]
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--fix", action="store_true", help="rewrite marked counts in place")
    args = parser.parse_args()

    problems = run(fix=args.fix)
    if problems:
        print("Tool-count drift in docs:", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        if not args.fix:
            print(
                "Run `uv run python scripts/check_tool_counts.py --fix` to update markers.",
                file=sys.stderr,
            )
        return 1
    print("Documented tool counts match the server.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
