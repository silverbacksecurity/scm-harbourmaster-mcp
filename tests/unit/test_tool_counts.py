"""Docs must quote the real number of registered MCP tools (scripts/check_tool_counts.py)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_ROOT = Path(__file__).parent.parent.parent
_SPEC = importlib.util.spec_from_file_location(
    "check_tool_counts", _ROOT / "scripts" / "check_tool_counts.py"
)
assert _SPEC and _SPEC.loader
check_tool_counts = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(check_tool_counts)

COUNTS = check_tool_counts.Counts(tools=164, modules=36)


def test_readme_and_docs_counts_match_registered_tools() -> None:
    problems = check_tool_counts.run(fix=False)
    assert not problems, (
        "Docs tool counts drifted — run `uv run python scripts/check_tool_counts.py --fix`:\n"
        + ("\n".join(problems))
    )


def test_registered_tools_include_reload_tools() -> None:
    names = check_tool_counts.registered_tool_names()
    assert {"scm_reload", "scm_restart"} <= names


def test_matching_markers_pass() -> None:
    text = "Exposes <!-- tool-count -->164<!-- /tool-count --> tools in <!-- module-count -->36<!-- /module-count --> modules"
    assert check_tool_counts.check_text(text, COUNTS) == []


def test_stale_marker_is_flagged_and_fixed() -> None:
    text = "**<!-- tool-count -->93<!-- /tool-count --> tools** across <!-- module-count --><!-- /module-count -->"
    problems = check_tool_counts.check_text(text, COUNTS)
    assert len(problems) == 2
    fixed = check_tool_counts.fix_text(text, COUNTS)
    assert "<!-- tool-count -->164<!-- /tool-count -->" in fixed
    assert "<!-- module-count -->36<!-- /module-count -->" in fixed
    assert check_tool_counts.check_text(fixed, COUNTS) == []


@pytest.mark.parametrize(
    "line",
    [
        "Exposes 85 SCM operations as MCP tools.",
        'tools["93 MCP Tools\\nobjects · policy"]',
        "The server registers as 95 tools in Cowork mode.",
        "The existing 125 MCP tools over Streamable transport",
        "**164 tools** across 36 modules.",
    ],
)
def test_unmarked_counts_are_flagged(line: str) -> None:
    assert check_tool_counts.check_text(line, COUNTS)


@pytest.mark.parametrize(
    "line",
    [
        "an executor loaded with only that domain's ~15–20 tools",
        "Legacy note: 85 tools at v0.3 <!-- tool-count: ignore -->",
        "## MCP tools reference",
    ],
)
def test_ranges_ignores_and_headings_are_not_flagged(line: str) -> None:
    assert check_tool_counts.check_text(line, COUNTS) == []


def test_only_readme_and_docs_are_scanned() -> None:
    names = {p.name for p in check_tool_counts.doc_files()}
    assert "README.md" in names
    assert "ROADMAP.md" not in names
    assert "CHANGELOG.md" not in names
