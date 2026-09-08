#!/usr/bin/env python3
"""Regenerate docs/TOOL_REFERENCE.md from tool docstrings.

Discovers every ``@mcp.tool()``-decorated function in src/scm_harbourmaster_mcp/tools/
via AST — no imports, no credentials needed. Modules listed in SECTION_MAP get
curated titles/descriptions and ordering; any module *not* in the map is still
documented (title derived from the filename, description from the module
docstring) so new tool modules can never silently drop out of the reference.

Usage:
    uv run python scripts/gen_docs.py
"""

from __future__ import annotations

import ast
import contextlib
import re
from pathlib import Path

ROOT = Path(__file__).parent.parent
TOOLS_DIR = ROOT / "src/scm_harbourmaster_mcp/tools"
OUT_PATH = ROOT / "docs/TOOL_REFERENCE.md"

# Curated section titles, descriptions, and ordering. Modules absent from this
# map are appended alphabetically with derived metadata — never skipped.
SECTION_MAP: dict[str, tuple[str, str]] = {
    "objects.py": ("Objects", "Addresses, address groups, services, tags, EDLs."),
    "security.py": (
        "Security Policy & Profiles",
        "Security rules (CRUD), Anti-Spyware profiles, URL categories.",
    ),
    "network.py": ("Network", "Zones, NAT rules, IKE gateways, IPSec tunnels, DNS servers."),
    "deployment.py": (
        "Deployment & Connectivity",
        "Remote Networks, Service Connections, Bandwidth Allocations, config versions, jobs.",
    ),
    "setup.py": ("Setup & Tenant Management", "Folders, devices, snippets, tenant list/evict."),
    "audit.py": (
        "Audit & Reporting",
        "Configuration backup, BPA, NCSC/NIST/DSPT/ISO 27001, AS-BUILT & HLD reports, "
        "config diff & clone.",
    ),
    "ncsc_baseline.py": (
        "NCSC Baseline",
        "Apply NCSC-aligned security baseline, attach profiles, gap analysis.",
    ),
    "dlp.py": ("Enterprise DLP", "Enterprise DLP profile listing, backup, and restore."),
    "mssp.py": (
        "MSSP Multi-Tenant",
        "Tenant dashboard, licensing, CDL, CASB, ZTNA, Browser, NGFW, AIRS.",
    ),
    "sdwan.py": (
        "Prisma SD-WAN",
        "Sites, elements, WAN interfaces/networks, path groups, policies and rules, "
        "topology, events/alarms, audit log, software status, link health.",
    ),
    "ops.py": (
        "Operational Visibility",
        "Certificate scan/lifecycle, TLS profile manager, licence forecast, tenant NOC "
        "dashboard, SPN bandwidth, GP sessions, device/user summaries, SDK & spec drift "
        "update check.",
    ),
    "posture.py": (
        "Posture Management",
        "SCM Posture Management and Incidents APIs.",
    ),
    "adnsr.py": (
        "Advanced DNS Security & NGFW Operations",
        "Advanced DNS Security Resolver (ADNSR) and NGFW Operations APIs.",
    ),
    "aiops.py": ("AIOps", "PAN AIOps BPA integration."),
    "ai_advisor.py": (
        "AI Compliance Advisor",
        "AI-assisted compliance analysis (Anthropic API).",
    ),
    "mt_interconnect.py": (
        "Service Provider Interconnect",
        "SP backbone attach to Prisma Access: interconnects, physical connections, "
        "regions, settings, IP-pool usage (multitenant MSP API).",
    ),
    "pab_msp.py": (
        "Prisma Access Browser for MSP",
        "Region-level PAB summaries and per-TSG security-event reports (multitenant MSP API).",
    ),
    "reload.py": ("Utility", "Hot-reload and restart of the running MCP server."),
}


def _derived_section(fname: str) -> tuple[str, str]:
    """Title from the filename, description from the module docstring."""
    title = fname[:-3].replace("_", " ").title()
    doc = ast.get_docstring(ast.parse((TOOLS_DIR / fname).read_text())) or ""
    desc = doc.strip().split("\n")[0] or "_No module description._"
    return title, desc


def _anchor(title: str) -> str:
    """GitHub-style heading slug (spaces map to hyphens without collapsing)."""
    s = re.sub(r"[^\w\s-]", "", title.lower())
    return s.replace(" ", "-")


def _raw_args_info(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[tuple[str, str, str]]:
    args_info = []
    defaults_offset = len(node.args.args) - len(node.args.defaults)
    for i, arg in enumerate(node.args.args):
        if arg.arg == "self":
            continue
        ann = ""
        if arg.annotation:
            with contextlib.suppress(Exception):
                ann = ast.unparse(arg.annotation)
        default = ""
        default_idx = i - defaults_offset
        if default_idx >= 0:
            with contextlib.suppress(Exception):
                default = ast.unparse(node.args.defaults[default_idx])
        args_info.append((arg.arg, ann, default))
    return args_info


def _is_scm_tool_decorator(dec: ast.expr) -> bool:
    """True for the bare `@tool` decorator (utils/tool_decorator.scm_tool)."""
    return isinstance(dec, ast.Name) and dec.id == "tool"


def _exposed_args_info(args_info: list[tuple[str, str, str]]) -> list[tuple[str, str, str]]:
    """Mirror what @scm_tool actually presents to FastMCP: `client` (and a
    function-declared `tenant_id`, if present) replaced by one synthesized
    `tenant_id: str = ""` param up front — see utils/tool_decorator.py.
    """
    rest = args_info[1:]  # drop `client`
    if rest and rest[0][0] == "tenant_id":
        rest = rest[1:]  # already represented by the synthesized param below
    # Single-quoted to match ast.unparse's string-literal convention used
    # for every other default in this table (see _raw_args_info).
    return [("tenant_id", "str", "''"), *rest]


def get_tools(fpath: Path) -> list[tuple[str, str, list[tuple[str, str, str]]]]:
    tree = ast.parse(fpath.read_text())
    tools = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        is_tool = False
        is_scm_tool = False
        for dec in node.decorator_list:
            if (
                isinstance(dec, ast.Attribute)
                and dec.attr == "tool"
                or (
                    isinstance(dec, ast.Call)
                    and isinstance(dec.func, ast.Attribute)
                    and dec.func.attr == "tool"
                )
            ):
                is_tool = True
            if _is_scm_tool_decorator(dec):
                is_scm_tool = True
        if is_tool:
            doc = ast.get_docstring(node) or "_No description._"
            args_info = _raw_args_info(node)
            if is_scm_tool:
                args_info = _exposed_args_info(args_info)
            tools.append((node.name, doc, args_info))
    return tools


def _ordered_modules() -> list[str]:
    """Curated order first, then any unmapped tool modules alphabetically."""
    present = {f.name for f in TOOLS_DIR.glob("*.py") if f.name != "__init__.py" and get_tools(f)}
    ordered = [f for f in SECTION_MAP if f in present]
    ordered += sorted(present - set(SECTION_MAP))
    return ordered


def build() -> str:
    modules = _ordered_modules()
    sections = {fname: SECTION_MAP.get(fname) or _derived_section(fname) for fname in modules}
    tools_by_module = {fname: get_tools(TOOLS_DIR / fname) for fname in modules}
    total = sum(len(t) for t in tools_by_module.values())

    lines = []
    lines.append("# SCM Harbourmaster — Tool Reference\n")
    lines.append(
        "> Auto-generated from source docstrings. Do not edit manually — run "
        "`uv run python scripts/gen_docs.py` to regenerate.\n"
    )
    lines.append(
        "All tools authenticate via Bearer-token OAuth (SASE client credentials) "
        "configured in `settings.toml` / `.secrets.toml`.\n"
    )
    lines.append(f"**{total} tools** across {len(modules)} modules.\n")

    lines.append("## Table of Contents\n")
    for fname in modules:
        section_name, _ = sections[fname]
        lines.append(f"- [{section_name}](#{_anchor(section_name)})")
    lines.append("")

    for fname in modules:
        section_name, section_desc = sections[fname]
        lines.append("---\n")
        lines.append(f"## {section_name}\n")
        lines.append(f"_{section_desc}_\n")

        for name, doc, args in tools_by_module[fname]:
            lines.append(f"### `{name}`\n")
            doc_lines = doc.strip().split("\n")
            in_summary, summary, rest = True, [], []
            for dl in doc_lines:
                if in_summary and not dl.strip():
                    in_summary = False
                elif in_summary:
                    summary.append(dl.strip())
                else:
                    rest.append(dl)
            lines.append(" ".join(summary) + "\n")
            detail = "\n".join(rest).strip()
            if detail:
                lines.append("```")
                lines.append(detail)
                lines.append("```\n")
            if args:
                lines.append("| Parameter | Type | Default |")
                lines.append("|-----------|------|---------|")
                for aname, atype, adefault in args:
                    # GFM tables split on raw pipes even inside backticks —
                    # escape them so `list[str] | None` stays in one cell.
                    a_type = (atype or "—").replace("|", "\\|")
                    a_def = (adefault or "—").replace("|", "\\|")
                    lines.append(f"| `{aname}` | `{a_type}` | `{a_def}` |")
                lines.append("")

    return "\n".join(lines)


if __name__ == "__main__":
    OUT_PATH.parent.mkdir(exist_ok=True)
    content = build()
    OUT_PATH.write_text(content)
    print(f"Written {len(content)} chars → {OUT_PATH}")
