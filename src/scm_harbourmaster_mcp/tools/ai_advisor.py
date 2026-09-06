"""
MCP tools for AI-assisted compliance analysis.

  scm_ai_compliance_advisor — run NCSC/NIST gap check then ask Claude to
                               produce a remediation playbook + exec summary
                               tailored to the tenant's actual config.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP

from ..audit import nist_templates as _nist
from ..audit.ncsc_templates import (
    GapItem,
    check_anti_spyware_profiles,
    check_log_forwarding,
    check_security_rules,
)
from ..config.settings import get_settings
from ..utils.logging import get_logger

logger = get_logger(__name__)

Framework = Literal["ncsc", "nist", "both"]

_SYSTEM_PROMPT = """\
You are a senior network-security consultant specialising in Palo Alto Networks Prisma Access
and Strata Cloud Manager (SCM). You are helping an MSSP operations team understand compliance
gaps found in a tenant's SCM configuration and how to fix them efficiently.

Guidelines:
- Be direct and actionable. Every gap must have a concrete fix.
- Where possible, reference the exact SCM MCP tool or CLI command to apply the fix
  (e.g., scm_apply_ncsc_baseline, scm_create_nist_snippet).
- Map remediation steps to the specific control IDs cited in the gap report.
- Produce TWO sections:
    1. EXECUTIVE SUMMARY  (≤150 words, plain English, risk-focused)
    2. REMEDIATION PLAYBOOK  (one numbered entry per gap, ordered critical→info)
       Each entry: control ID | gap description | exact fix steps | estimated effort
- Use Markdown formatting.
- Do not invent gaps or controls not present in the input.
"""


def _build_user_prompt(
    folder: str,
    framework: Framework,
    gaps: list[GapItem],
    tenant_label: str,
) -> str:
    framework_label = {
        "ncsc": "NCSC (CAF v4.0 / Cyber Essentials v3.2 / 10 Steps)",
        "nist": "NIST (CSF v2.0 / SP 800-53 Rev 5 / SP 800-171)",
        "both": "NCSC (CAF v4.0 / CE v3.2) and NIST (CSF v2.0 / SP 800-53 / SP 800-171)",
    }[framework]

    lines = [
        "## Compliance Gap Report",
        f"Tenant: {tenant_label}",
        f"SCM Folder: {folder}",
        f"Framework(s): {framework_label}",
        f"Total gaps found: {len(gaps)}",
        "",
    ]

    by_sev: dict[str, list[GapItem]] = {"critical": [], "high": [], "medium": [], "info": []}
    for g in gaps:
        by_sev.get(g.severity, by_sev["info"]).append(g)

    icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "info": "🔵"}
    for sev in ("critical", "high", "medium", "info"):
        items = by_sev[sev]
        if not items:
            continue
        lines.append(f"### {icons[sev]} {sev.capitalize()} gaps ({len(items)})")
        for g in items:
            obj = f" (object: `{g.object_name}`)" if g.object_name else ""
            lines.append(f"- **[{g.control}]{obj}** {g.finding}")
            lines.append(f"  Suggested fix: {g.remediation}")
        lines.append("")

    lines += [
        "---",
        "Please produce the EXECUTIVE SUMMARY and REMEDIATION PLAYBOOK as instructed.",
    ]
    return "\n".join(lines)


def _run_ncsc_checks(
    client: Any,
    folder: str,
    position: str,
) -> tuple[list[GapItem], list[str]]:
    """Return (gaps, warnings) for NCSC checks."""
    gaps: list[GapItem] = []
    warnings: list[str] = []
    try:
        positions = ["pre", "post"] if position == "both" else [position]
        seen: set[str] = set()
        rules: list[Any] = []
        for pos in positions:
            for r in client.security_rule.list(folder=folder, rulebase=pos):
                rid = str(getattr(r, "id", None) or getattr(r, "name", ""))
                if rid not in seen:
                    seen.add(rid)
                    rules.append(r)
        gaps.extend(check_security_rules(rules))
    except Exception as exc:
        warnings.append(f"Could not fetch security rules: {exc}")
    try:
        gaps.extend(check_anti_spyware_profiles(client.anti_spyware_profile.list(folder=folder)))
    except Exception as exc:
        warnings.append(f"Could not fetch anti-spyware profiles: {exc}")
    try:
        gaps.extend(check_log_forwarding(client.log_forwarding_profile.list(folder=folder)))
    except Exception as exc:
        warnings.append(f"Could not fetch log forwarding profiles: {exc}")
    return gaps, warnings


def _run_nist_checks(
    client: Any,
    folder: str,
    position: str,
) -> tuple[list[GapItem], list[str]]:
    """Return (gaps, warnings) for NIST checks — reuses NCSC checks + remaps controls."""
    raw_gaps, warnings = _run_ncsc_checks(client, folder, position)
    gaps: list[GapItem] = []
    for g in raw_gaps:
        ctrl = (
            g.control.replace("CAF C2a", "CSF PR.AC-5")
            .replace("CAF C2b", "SP 800-53 AC-3")
            .replace("CE v3.2", "SP 800-53 SI-3")
            .replace("10 Steps", "SP 800-171 3.14")
        )
        gaps.append(GapItem(ctrl, g.severity, g.finding, g.remediation, g.object_name))

    # NIST baseline object existence checks
    def _check(sdk_attr: str, name: str, control: str) -> None:
        try:
            objs = getattr(client, sdk_attr).list(folder=folder)
            names = {getattr(o, "name", None) for o in objs}
            if name not in names:
                gaps.append(
                    GapItem(
                        control=control,
                        severity="info",
                        finding=f"NIST baseline object '{name}' not found in folder '{folder}'",
                        remediation=f"Run scm_create_nist_snippet(dry_run=False) then push to '{folder}'",
                    )
                )
        except Exception as exc:
            warnings.append(f"Could not check {sdk_attr} for '{name}': {exc}")

    _check("anti_spyware_profile", _nist.ANTI_SPYWARE_NAME, "SP 800-53 SI-3")
    _check("vulnerability_protection_profile", _nist.VULN_PROTECTION_NAME, "SP 800-53 SI-2 / RA-5")
    _check("wildfire_antivirus_profile", _nist.WILDFIRE_NAME, "SP 800-53 SI-3 / SP 800-171 3.14")
    _check("url_access_profile", _nist.URL_ACCESS_NAME, "CSF PR.AC-5 / SC-7")
    _check("log_forwarding_profile", _nist.LOG_FORWARDING_NAME, "SP 800-53 AU-2 / AU-12")
    return gaps, warnings


def register_ai_advisor_tools(mcp: FastMCP, get_client: Callable[..., Any]) -> None:
    """Register AI compliance advisor tools with the MCP server."""

    @mcp.tool()
    def scm_ai_compliance_advisor(
        folder: str,
        framework: str = "both",
        position: str = "pre",
        tenant_label: str = "",
        model: str = "",
    ) -> str:
        """
        AI-powered compliance advisor: run NCSC/NIST gap checks then generate
        a remediation playbook and executive summary using Claude.

        Combines the gap detection from scm_ncsc_gap / scm_nist_gap with an
        AI layer that interprets findings in plain English and maps each gap
        to concrete SCM remediation steps and MCP tool commands.

        Output contains two sections:
          1. EXECUTIVE SUMMARY  — ≤150 words, risk-focused, suitable for reports
          2. REMEDIATION PLAYBOOK — one entry per gap (critical → info), with
             exact fix steps and estimated effort per item

        Requirements:
          - ANTHROPIC_API_KEY environment variable (or SCM_MCP_ANTHROPIC_API_KEY)
          - pip/uv install anthropic>=0.40.0

        Args:
            folder: SCM folder to inspect (e.g. "Shared" or a tenant folder).
            framework: "ncsc", "nist", or "both" (default: "both").
            position: Security rule position — "pre", "post", or "both".
            tenant_label: Human-readable tenant name shown in the report header.
            model: Override the Claude model (default: from settings / claude-sonnet-4-6).
        """
        try:
            import anthropic  # type: ignore[import-untyped,unused-ignore]
        except ImportError:
            return (
                "ERROR: `anthropic` package not installed.\n"
                "Run: uv add anthropic\n"
                "Then restart the MCP server."
            )

        # ── Resolve API key ────────────────────────────────────────────────
        settings = get_settings()
        api_key = settings.anthropic_api_key.get_secret_value() or os.environ.get(
            "ANTHROPIC_API_KEY", ""
        )
        if not api_key:
            return (
                "ERROR: No Anthropic API key configured.\n"
                "Set ANTHROPIC_API_KEY in your environment or add\n"
                "  anthropic_api_key = '...'  to .secrets.toml"
            )

        resolved_model = model or settings.ai_advisor_model or "claude-sonnet-4-6"

        # ── Run gap checks ─────────────────────────────────────────────────
        client = get_client()
        _fw_lower = framework.lower()
        norm_fw: Framework = _fw_lower if _fw_lower in ("ncsc", "nist", "both") else "both"  # type: ignore[assignment]

        all_gaps: list[GapItem] = []
        all_warnings: list[str] = []

        if norm_fw in ("ncsc", "both"):
            g, w = _run_ncsc_checks(client, folder, position)
            all_gaps.extend(g)
            all_warnings.extend(w)

        if norm_fw in ("nist", "both"):
            g, w = _run_nist_checks(client, folder, position)
            all_gaps.extend(g)
            all_warnings.extend(w)

        if not all_gaps:
            return (
                f"## AI Compliance Advisor — folder '{folder}'\n\n"
                "**No gaps detected.** The folder appears compliant with all "
                f"{norm_fw.upper()} checks performed.\n\n"
                + (
                    ("Warnings:\n" + "\n".join(f"  ⚠ {w}" for w in all_warnings))
                    if all_warnings
                    else ""
                )
            )

        label = tenant_label or folder
        user_prompt = _build_user_prompt(folder, norm_fw, all_gaps, label)

        # ── Call Claude ────────────────────────────────────────────────────
        logger.info(
            "ai_advisor_request",
            folder=folder,
            framework=norm_fw,
            gaps=len(all_gaps),
            model=resolved_model,
        )
        try:
            anth = anthropic.Anthropic(api_key=api_key)
            response = anth.messages.create(
                model=resolved_model,
                max_tokens=4096,
                system=_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
            )
            first = response.content[0]
            ai_text = first.text if hasattr(first, "text") else str(first)
        except Exception as exc:
            logger.warning("ai_advisor_error", error=str(exc))
            return (
                f"## AI Compliance Advisor — folder '{folder}'\n\n"
                f"Gap detection succeeded ({len(all_gaps)} gaps found) but the AI "
                f"advisor call failed:\n\n```\n{exc}\n```\n\n"
                "Check your ANTHROPIC_API_KEY and network connectivity."
            )

        # ── Build final output ─────────────────────────────────────────────
        header_lines = [
            f"## AI Compliance Advisor — folder '{folder}'",
            f"Tenant: {label} | Framework: {norm_fw.upper()} | Gaps found: {len(all_gaps)}",
            f"Model: {resolved_model}",
            "",
        ]
        if all_warnings:
            header_lines += ["**Warnings during gap collection:**"]
            header_lines += [f"  ⚠ {w}" for w in all_warnings]
            header_lines += [""]

        return "\n".join(header_lines) + ai_text
