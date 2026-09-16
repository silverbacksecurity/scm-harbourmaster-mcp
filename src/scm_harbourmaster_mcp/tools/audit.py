"""
MCP tools for SCM configuration audit, BPA assessment, and NCSC compliance.

Tools:
    scm_config_backup    — export full config snapshot to JSON file
    scm_bpa_assess       — run PAN BPA checks against live SCM config
    scm_ncsc_assess      — NCSC CAF v4.0 / CE v3.2 / 10 Steps compliance view
    scm_audit_report     — combined BPA + NCSC Markdown report (AS-BUILT AS-IS)
    scm_config_diff      — compare two saved snapshots
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..audit.asbuilt_report import AsBuiltReportBuilder
from ..audit.asbuilt_verify import VERIFIED_SECTIONS
from ..audit.bpa_checks import run_all_checks
from ..audit.cloner import clone_config
from ..audit.commit_preview import (
    bpa_delta,
    build_address_index,
    find_shadowed_rules,
    render_commit_preview,
    render_shadow_audit,
    rule_identity,
    unresolved_address_names,
)
from ..audit.drift_baseline import (
    check_drift,
    diff_snapshots,
    load_baseline,
    render_drift_digest,
    save_baseline,
)
from ..audit.dspt_controls import BPA_TO_DSPT, DSPT_ASSERTIONS
from ..audit.extractor import (
    backup_resource_payload,
    extract_adem,
    extract_airs,
    extract_allocated_ips,
    extract_app_acceleration,
    extract_browser,
    extract_casb_dlp,
    extract_cdl,
    extract_egress_ips_datapath,
    extract_enterprise_dlp,
    extract_iam_access_policies,
    extract_iam_roles,
    extract_identity_sspm,
    extract_insights,
    extract_iot_security,
    extract_licenses,
    extract_managed_tenants,
    extract_mt_monitor_alerts,
    extract_ngfw_devices,
    extract_ngfw_interface_ips,
    extract_ngfw_routing,
    extract_pab_tenant,
    extract_sdwan_snapshot,
    extract_snapshot,
    extract_sspm,
    extract_traffic_steering,
    extract_ztna_connectors,
)
from ..audit.incident_rca import collect_candidates, parse_any_ts, render_rca_report
from ..audit.models import Status
from ..audit.ncsc_controls import NCSC_CONTROLS
from ..audit.report import ReportBuilder
from ..auth.oauth import fetch_licenses, get_scm_client, get_tenant_meta
from ..config.settings import load_all_tenant_configs
from ..utils.capabilities import capability_skip_reason
from ..utils.errors import handle_scm_exception
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool
from ..utils.write_safety import audit_write, normalize_ticket_ref, ticket_ref_error
from .ops import _CERT_FOLDERS, _fetch_certs, _licence_rows

logger = get_logger(__name__)

_DEFAULT_BACKUP_DIR = Path(os.getenv("SCM_MCP_BACKUP_DIR", "backups"))
_DEFAULT_BASELINE_DIR = Path(os.getenv("SCM_MCP_BASELINE_DIR", "baselines"))

# Background job store for scm_asbuilt_report / scm_asbuilt_result.
# Jobs expire after 1 hour. Thread-safe via _JOBS_LOCK.
_ASBUILT_JOBS: dict[str, dict[str, Any]] = {}
_JOBS_LOCK = threading.Lock()
_JOB_TTL = 3600  # seconds

# Background job store for the drift sentinel's all-tenants sweep
# (scm_drift_baseline / scm_drift_check with all_tenants=True).
_DRIFT_JOBS: dict[str, dict[str, Any]] = {}


def _prune_drift_jobs() -> None:
    cutoff = time.time() - _JOB_TTL
    with _JOBS_LOCK:
        for jid in [j for j, meta in _DRIFT_JOBS.items() if meta["started_at"] < cutoff]:
            del _DRIFT_JOBS[jid]


def _prune_asbuilt_jobs() -> None:
    cutoff = time.time() - _JOB_TTL
    with _JOBS_LOCK:
        stale = [k for k, v in _ASBUILT_JOBS.items() if v["started_at"] < cutoff]
        for k in stale:
            del _ASBUILT_JOBS[k]


_MERMAID_FENCE = re.compile(r"```mermaid\n(.*?)\n```", re.DOTALL)


def _find_chrome_for_mmdc() -> str | None:
    """Locate a Chrome/Chromium binary for mmdc's puppeteer.

    Used when mmdc's default resolution fails — e.g. its pinned Chrome build
    is absent from the puppeteer cache while another build or a system
    chrome/chromium is available."""
    for name in (
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
        "chrome",
    ):
        p = shutil.which(name)
        if p:
            return p
    cache = Path.home() / ".cache" / "puppeteer"
    for pattern in (
        "chrome/*/chrome-linux64/chrome",
        "chrome-headless-shell/*/chrome-headless-shell-linux64/chrome-headless-shell",
    ):
        candidates = sorted(cache.glob(pattern), reverse=True)
        if candidates:
            return str(candidates[0])
    return None


def _mermaid_to_png_local(diagram: str, dest: Path) -> bool:
    """
    Render a Mermaid diagram to PNG locally via mmdc (mermaid-cli).
    All processing is local — no data leaves the machine.
    Install: npm install -g @mermaid-js/mermaid-cli
    Returns True on success.
    """
    mmdc = shutil.which("mmdc")
    if not mmdc:
        return False
    try:
        src = dest.with_suffix(".mmd")
        src.write_text(diagram)
        base_cmd = [
            mmdc,
            "-i",
            str(src),
            "-o",
            str(dest),
            "--backgroundColor",
            "white",
            "--width",
            "1200",
        ]

        def _ok(result: subprocess.CompletedProcess[str]) -> bool:
            return result.returncode == 0 and dest.exists() and dest.stat().st_size > 200

        result = subprocess.run(base_cmd, capture_output=True, text=True, timeout=30)
        if not _ok(result):
            # mmdc's bundled puppeteer can fail to launch its pinned Chrome
            # (build missing from the cache, or the Chrome sandbox blocked by
            # kernel userns restrictions).  Retry once pointing puppeteer at a
            # locatable Chrome with the sandbox disabled.
            chrome = _find_chrome_for_mmdc()
            if chrome:
                cfg = dest.with_suffix(".pptr.json")
                cfg.write_text(json.dumps({"executablePath": chrome, "args": ["--no-sandbox"]}))
                retry = subprocess.run(
                    [*base_cmd, "-p", str(cfg)], capture_output=True, text=True, timeout=30
                )
                cfg.unlink(missing_ok=True)
                if _ok(retry):
                    logger.info("mmdc_render_retry_succeeded", chrome=chrome)
                    result = retry
                else:
                    logger.warning(
                        "mmdc_render_failed",
                        error=(retry.stderr or result.stderr or "").strip()[:300],
                    )
            else:
                logger.warning("mmdc_render_failed", error=(result.stderr or "").strip()[:300])
        src.unlink(missing_ok=True)
        return _ok(result)
    except Exception as exc:
        logger.warning("mmdc_render_failed", error=str(exc))
        return False


def _prerender_mermaid(md: str, tmp_dir: str) -> str:
    """
    Replace ```mermaid ... ``` fences with locally rendered PNG images (via mmdc).
    If mmdc is not installed, replaces with a descriptive text block so the
    diagram content still appears in the docx as readable text.
    All rendering is local — no customer data is sent to any external service.
    """
    img_dir = Path(tmp_dir) / "diagrams"
    img_dir.mkdir(exist_ok=True)
    mmdc_available = bool(shutil.which("mmdc"))
    counter = [0]

    def replace(match: re.Match[str]) -> str:
        diagram = match.group(1)
        counter[0] += 1
        if mmdc_available:
            png_path = img_dir / f"diagram_{counter[0]}.png"
            if _mermaid_to_png_local(diagram, png_path):
                return f"![Diagram {counter[0]}]({png_path})"
        # Fallback: emit diagram source as indented text so content is not lost
        indented = diagram.replace("\n", "\n> ")
        return (
            f"**[Diagram {counter[0]}]** "
            f"_(Install `npm install -g @mermaid-js/mermaid-cli` for rendered images in docx)_\n\n"
            f"> ```\n> {indented}\n> ```"
        )

    return _MERMAID_FENCE.sub(replace, md)


def _find_pandoc() -> str | None:
    """Locate a pandoc binary: system install first, then the one bundled
    with the pypandoc-binary wheel (a project dependency, so DOCX works
    without any system package)."""
    p = shutil.which("pandoc")
    if p:
        return p
    try:
        import pypandoc  # type: ignore[import-untyped]

        return str(pypandoc.get_pandoc_path())
    except Exception:
        return None


def _md_to_docx(md: str, out_path: Path) -> str:
    """
    Convert Markdown to .docx via pandoc (system binary or the bundled
    pypandoc-binary one). Mermaid diagrams are pre-rendered to PNG locally
    via mmdc before conversion so they appear as images rather than code
    blocks in the docx.
    """
    pandoc = _find_pandoc()
    if not pandoc:
        return (
            "pandoc not found — install with: sudo apt install pandoc "
            "(or: uv add pypandoc-binary / pip install pypandoc-binary)\n"
            "Markdown report returned instead."
        )
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Pre-render Mermaid blocks → PNG images
        md_rendered = _prerender_mermaid(md, tmp_dir)

        tmp_md = Path(tmp_dir) / "report.md"
        tmp_md.write_text(md_rendered)

        out_path.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            [
                pandoc,
                str(tmp_md),
                "-o",
                str(out_path),
                "--from",
                "markdown",
                "--to",
                "docx",
                "--resource-path",
                tmp_dir,
                "-V",
                "geometry:margin=2.5cm",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            return f"pandoc error: {result.stderr.strip()}\nMarkdown report returned instead."
        return str(out_path)


def register_audit_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register all audit, BPA, and NCSC compliance tools."""
    tool = scm_tool(get_client)
    tool = scm_tool(get_client)

    # ── Config Backup ─────────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_config_backup(client: Any, tenant_id: str, folder: str, output_dir: str = "") -> str:
        """Export a complete SCM configuration snapshot to a JSON backup file.

        Pulls all resource types for the folder — addresses, security rules,
        profiles, zones, VPN and deployment objects, network infrastructure
        (crypto/QoS profiles, internal DNS, BGP routing, GP IP pools) and the
        GlobalProtect mobile-agent stack (auth settings, tunnel and forwarding
        profiles, portals/gateways, SAML/Radius/LDAP auth profiles) — and
        writes a timestamped JSON file. The backup file can be used as input
        to scm_config_diff and scm_config_clone, and as the data source for
        the AS-BUILT report.

        Args:
            folder: SCM folder to back up.
            tenant_id: SCM tenant ID (MSSP mode).
            output_dir: Directory to write the backup file (default: ./backups).

        Returns:
            Path to the written backup file and a resource count summary.
        """
        snap = extract_snapshot(client, folder=folder, tenant_id=tenant_id or "default")

        backup_dir = Path(output_dir) if output_dir else _DEFAULT_BACKUP_DIR
        backup_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        safe_folder = folder.replace("/", "_").replace(" ", "-")
        filename = backup_dir / f"scm_backup_{safe_folder}_{ts}.json"

        data: dict[str, Any] = {
            "backup_version": "1",
            "generated_at": datetime.now(UTC).isoformat(),
            "folder": folder,
            "tenant_id": snap.tenant_id,
            "resources": backup_resource_payload(snap),
            "extraction_errors": snap.extraction_errors,
        }

        filename.write_text(json.dumps(data, indent=2, default=str))
        logger.info("config_backup_written", path=str(filename), folder=folder)

        counts = {k: len(v) for k, v in data["resources"].items() if v}
        summary = "\n".join(f"  {k}: {v}" for k, v in sorted(counts.items()))
        error_note = (
            f"\n\nExtraction errors ({len(snap.extraction_errors)}):\n"
            + "\n".join(f"  - {e}" for e in snap.extraction_errors)
            if snap.extraction_errors
            else ""
        )

        return f"Backup written to: {filename}\n\nResource counts:\n{summary}{error_note}"

    # ── BPA Assessment ────────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_bpa_assess(
        client: Any,
        tenant_id: str,
        folder: str,
        severity_filter: str = "",
        failed_only: bool = False,
    ) -> str:
        """Run Palo Alto Networks Best Practice Assessment checks against live SCM config.

        Pulls the current configuration from SCM and evaluates it against PAN
        best practice checks (security rules, threat prevention profiles, URL
        filtering, decryption, zone protection, and logging).

        Each finding includes:
        - Check ID and severity (critical/high/medium/low)
        - Pass/Fail/Warn status
        - Affected object names
        - Remediation guidance
        - NCSC control cross-references

        Args:
            folder: SCM folder to assess.
            tenant_id: SCM tenant ID (MSSP mode).
            severity_filter: Filter to a severity level (critical/high/medium/low).
            failed_only: If true, return only failed and warned checks.

        Returns:
            JSON-formatted BPA findings.
        """
        snap = extract_snapshot(client, folder=folder, tenant_id=tenant_id or "default")
        findings = run_all_checks(snap)

        if severity_filter:
            findings = [f for f in findings if f.severity.value == severity_filter.lower()]
        if failed_only:
            findings = [f for f in findings if f.status in (Status.FAIL, Status.WARN)]

        from collections import Counter

        status_counts = Counter(f.status.value for f in findings)

        result = {
            "folder": folder,
            "total": len(findings),
            "passed": status_counts.get("pass", 0),
            "failed": status_counts.get("fail", 0),
            "warnings": status_counts.get("warn", 0),
            "skipped": status_counts.get("skip", 0),
            "extraction_errors": len(snap.extraction_errors),
            "findings": [f.to_dict() for f in findings],
        }
        return json.dumps(result, indent=2)

    # ── NCSC Assessment ───────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_ncsc_assess(client: Any, tenant_id: str, folder: str, framework: str = "all") -> str:
        """Assess SCM configuration against UK NCSC compliance frameworks.

        Evaluates the live SCM configuration against:
        - NCSC CAF v4.0 (Cyber Assessment Framework, August 2025)
        - Cyber Essentials v3.2 (firewall controls)
        - NCSC 10 Steps to Cyber Security (network security steps)

        Returns a control-by-control compliance view showing which NCSC
        controls are satisfied, breached, or cannot be assessed.

        Args:
            folder: SCM folder to assess.
            tenant_id: SCM tenant ID (MSSP mode).
            framework: Filter to framework — 'caf', 'ce', '10steps', or 'all'.

        Returns:
            JSON NCSC compliance view with per-control status.
        """
        snap = extract_snapshot(client, folder=folder, tenant_id=tenant_id or "default")
        findings = run_all_checks(snap)

        # Build control → findings map
        ctrl_status: dict[str, list[dict[str, Any]]] = {k: [] for k in NCSC_CONTROLS}
        for f in findings:
            for ref in f.ncsc_refs:
                if ref in ctrl_status:
                    ctrl_status[ref].append(f.to_dict())

        framework_filter = {
            "caf": "CAF v4.0",
            "ce": "CE v3.2",
            "10steps": "10 Steps",
            "nsf": "NSF",
        }.get(framework.lower(), "")

        controls_output = []
        for ctrl_id, ctrl in NCSC_CONTROLS.items():
            if framework_filter and ctrl.source != framework_filter:
                continue
            related = ctrl_status[ctrl_id]
            has_fail = any(f["status"] in ("fail", "warn") for f in related)
            has_pass = any(f["status"] == "pass" for f in related)
            compliance = (
                "non-compliant" if has_fail else ("compliant" if has_pass else "not-assessed")
            )
            controls_output.append(
                {
                    "control_id": ctrl_id,
                    "title": ctrl.title,
                    "source": ctrl.source,
                    "objective": ctrl.objective,
                    "compliance_status": compliance,
                    "related_findings": [
                        {"check_id": f["check_id"], "status": f["status"], "title": f["title"]}
                        for f in related
                    ],
                }
            )

        compliant = sum(1 for c in controls_output if c["compliance_status"] == "compliant")
        non_compliant = sum(1 for c in controls_output if c["compliance_status"] == "non-compliant")
        not_assessed = sum(1 for c in controls_output if c["compliance_status"] == "not-assessed")

        return json.dumps(
            {
                "folder": folder,
                "framework_filter": framework,
                "summary": {
                    "total_controls": len(controls_output),
                    "compliant": compliant,
                    "non_compliant": non_compliant,
                    "not_assessed": not_assessed,
                },
                "controls": controls_output,
            },
            indent=2,
        )

    # ── DSPT Assessment ────────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_dspt_assess(
        client: Any,
        tenant_id: str,
        folder: str,
        standard: str = "all",
        output_format: str = "markdown",
        save_to: str = "",
    ) -> str:
        """Assess SCM configuration against the NHS DSPT (Data Security and Protection Toolkit).

        Evaluates live SCM/NGFW configuration against the technology standards
        of the NHS England DSPT 2024-25 (v5.1), specifically:

        - **Standard 7**: Continuity Planning (config backup and recovery)
        - **Standard 8**: Unsupported Systems (PAN-OS currency, patching)
        - **Standard 9**: IT Protection (firewall, malware, URL filtering,
          encryption, access control, MFA, audit logging)
        - **Standard 10**: Accountable Suppliers (MSSP DPAs, sub-processor assurance)

        For each DSPT assertion, the tool reports:
        - Compliance status (Compliant / Non-Compliant / Not Assessed)
        - Which BPA checks provide the evidence
        - An evidence statement ready to paste into the DSPT portal
        - DSPT assessment level (Approaching / Meeting / Exceeding Standards)

        Standards 1–6 (People and Process) cannot be automated from firewall
        config and must be self-assessed within the NHS DSPT portal.

        Args:
            folder: SCM folder to assess (e.g. "Shared" or a customer folder).
            tenant_id: SCM tenant ID (MSSP mode). Defaults to active tenant.
            standard: Filter by standard number — '7', '8', '9', '10', or 'all'.
            output_format: 'markdown' (default) or 'json'.
            save_to: Optional file path to save the report (e.g. 'reports/dspt.md').
        """
        snap = extract_snapshot(client, folder=folder, tenant_id=tenant_id or "default")
        findings = run_all_checks(snap)

        # Build: assertion_id → list of findings that evidence it
        assertion_findings: dict[str, list[dict[str, Any]]] = {k: [] for k in DSPT_ASSERTIONS}
        for f in findings:
            for assertion_id in BPA_TO_DSPT.get(f.check_id, []):
                if assertion_id in assertion_findings:
                    assertion_findings[assertion_id].append(f.to_dict())

        # Filter by standard if requested
        std_filter = standard.strip() if standard.strip() != "all" else ""
        assessed = []
        for aid, assertion in DSPT_ASSERTIONS.items():
            if std_filter and str(assertion.standard_number) != std_filter:
                continue
            related = assertion_findings[aid]
            has_fail = any(f["status"] in ("fail", "warn") for f in related)
            has_pass = any(f["status"] == "pass" for f in related)
            compliance = (
                "non-compliant" if has_fail else ("compliant" if has_pass else "not-assessed")
            )
            assessed.append(
                {
                    "assertion_id": aid,
                    "assertion_ref": assertion.assertion_ref,
                    "title": assertion.title,
                    "standard": assertion.standard,
                    "standard_number": assertion.standard_number,
                    "dspt_level": assertion.dspt_level,
                    "compliance_status": compliance,
                    "description": assertion.description,
                    "evidence_guidance": assertion.evidence_guidance,
                    "related_findings": [
                        {
                            "check_id": f["check_id"],
                            "status": f["status"],
                            "title": f["title"],
                            "severity": f["severity"],
                            "affected_objects": f.get("affected_objects", []),
                        }
                        for f in related
                    ],
                }
            )

        compliant = sum(1 for a in assessed if a["compliance_status"] == "compliant")
        non_compliant = sum(1 for a in assessed if a["compliance_status"] == "non-compliant")
        not_assessed_count = sum(1 for a in assessed if a["compliance_status"] == "not-assessed")

        if output_format.lower() == "json":
            result = json.dumps(
                {
                    "folder": folder,
                    "tenant_id": tenant_id or "default",
                    "standard_filter": standard,
                    "framework": "NHS DSPT 2024-25 v5.1",
                    "summary": {
                        "total_assertions": len(assessed),
                        "compliant": compliant,
                        "non_compliant": non_compliant,
                        "not_assessed": not_assessed_count,
                    },
                    "assertions": assessed,
                },
                indent=2,
            )
            if save_to:
                Path(save_to).write_text(result)
                return f"DSPT assessment saved to `{save_to}` ({len(assessed)} assertions)."
            return result

        # ── Markdown output ───────────────────────────────────────────────
        ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
        comp_icon = {"compliant": "✅", "non-compliant": "❌", "not-assessed": "⚠️"}
        level_label = {
            "approaching": "Approaching Standards",
            "meeting": "Meeting Standards",
            "exceeding": "Exceeding Standards",
        }

        lines = [
            f"# NHS DSPT 2024-25 Assessment — {folder}",
            "",
            f"**Tenant:** {tenant_id or 'default'}  |  "
            f"**Assessed:** {ts}  |  "
            f"**Framework:** NHS DSPT 2024-25 v5.1",
            "",
            "## Summary",
            "",
            "| ✅ Compliant | ❌ Non-Compliant | ⚠️ Not Assessed | Total |",
            "|---|---|---|---|",
            f"| {compliant} | {non_compliant} | {not_assessed_count} | {len(assessed)} |",
            "",
        ]

        # Overall DSPT level determination
        if non_compliant == 0 and compliant > 0:
            exc_assertions = [
                a
                for a in assessed
                if a["dspt_level"] == "exceeding" and a["compliance_status"] == "compliant"
            ]
            overall = "**Exceeding Standards** 🏆" if exc_assertions else "**Meeting Standards** ✅"
        elif non_compliant <= 2:
            overall = "**Approaching Standards** ⚠️ — address non-compliant items below"
        else:
            overall = (
                f"**Not Meeting Standards** ❌ — {non_compliant} assertion(s) require remediation"
            )

        lines += [
            f"**Overall DSPT Assessment Level:** {overall}",
            "",
            "> Standards 1–6 (People and Process) require human self-assessment in the "
            "DSPT portal and are not included here.",
            "",
        ]

        # Group by standard
        by_standard: dict[int, list[dict[str, Any]]] = {}
        for a in assessed:
            std_key: int = a["standard_number"]  # type: ignore[assignment]
            by_standard.setdefault(std_key, []).append(a)

        for std_num in sorted(by_standard):
            std_assertions = by_standard[std_num]
            std_name = str(std_assertions[0]["standard"])
            std_compliant = sum(1 for a in std_assertions if a["compliance_status"] == "compliant")
            std_fail = sum(1 for a in std_assertions if a["compliance_status"] == "non-compliant")
            std_icon = (
                "✅" if std_fail == 0 and std_compliant > 0 else ("❌" if std_fail > 0 else "⚠️")
            )

            lines += [
                f"## {std_icon} {std_name}",
                "",
            ]

            for a in std_assertions:
                comp_status = str(a["compliance_status"])
                dspt_level = str(a["dspt_level"])
                icon = comp_icon.get(comp_status, "⚠️")
                lvl = level_label.get(dspt_level, dspt_level)
                lines += [
                    f"### {icon} {a['assertion_ref']} — {a['title']}",
                    "",
                    f"**DSPT Level:** {lvl}  |  "
                    f"**Status:** {comp_status.replace('-', ' ').title()}",
                    "",
                    f"**Requirement:** {a['description']}",
                    "",
                ]

                a_findings: Any = a["related_findings"]
                if a_findings:
                    lines += ["**Evidence from SCM Configuration:**", ""]
                    for rf in a_findings:
                        rf_status = str(rf["status"])
                        ficon = (
                            "✅" if rf_status == "pass" else ("❌" if rf_status == "fail" else "⚠️")
                        )
                        sev = sev_icon.get(str(rf["severity"]), "⚪")
                        raw_objs: Any = rf.get("affected_objects") or []
                        objs: list[str] = [str(o) for o in raw_objs]
                        obj_str = f" — affected: {', '.join(objs[:5])}" if objs else ""
                        lines.append(f"- {ficon} {sev} `{rf['check_id']}` {rf['title']}{obj_str}")
                    lines.append("")

                if comp_status == "non-compliant":
                    lines += [
                        "**Remediation required to meet this assertion.**",
                        "",
                    ]

                lines += [
                    "<details>",
                    "<summary>Evidence guidance for DSPT portal</summary>",
                    "",
                    str(a["evidence_guidance"]),
                    "",
                    "</details>",
                    "",
                    "---",
                    "",
                ]

        result_md = "\n".join(lines)

        if save_to:
            Path(save_to).write_text(result_md)
            return (
                f"DSPT assessment saved to `{save_to}`.\n\n"
                f"Summary: {compliant} compliant / {non_compliant} non-compliant / "
                f"{not_assessed_count} not assessed\n\n"
                f"Overall: {overall}"
            )
        return result_md

    # ── ISO 27001:2022 Assessment ─────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_iso27001_assess(
        client: Any,
        tenant_id: str,
        folder: str,
        clause_filter: str = "all",
        output_format: str = "markdown",
        save_to: str = "",
    ) -> str:
        """Assess SCM/NGFW configuration against ISO 27001:2022 Annex A controls.

        Maps all 39 BPA checks to 12 automatable Annex A controls across the
        technological and organisational domains. Controls requiring non-technical
        ISMS evidence (governance, HR, physical) are out of scope and noted
        explicitly — this tool covers the firewall-observable subset only.

        Controls assessed:
          A.5.14  Information transfer (file blocking, DLP)
          A.5.28  Collection of evidence (logging, SIEM forwarding)
          A.8.7   Protection against malware (AV, WildFire, DNS sec)
          A.8.15  Logging (log forwarding, syslog, deny logging)
          A.8.20  Networks security (DNS sec, URL filter, zone protection)
          A.8.21  Security of network services (TLS decryption)
          A.8.22  Segregation of networks (zones, MFA, HIP, App-ID)
          A.8.23  Web filtering (URL categories, high-risk blocks)
          A.8.24  Use of cryptography (IKEv2, strong IKE/IPSec, PFS)
          A.8.27  Secure system architecture (zero trust, App-ID, no double-any)
          A.8.28  Secure coding (vulnerability protection as compensating control)
          A.8.29  Security testing (HIP patch management as compensating control)

        Args:
            folder: SCM folder to assess (e.g. 'Shared', 'All').
            tenant_id: Specific tenant; uses default if omitted.
            clause_filter: 'all' (default), '5' (org controls only),
                           '8' (technological only), or specific control e.g. 'A.8.22'.
            output_format: 'markdown' (default) or 'json'.
            save_to: Optional file path to save the report.

        Returns:
            Markdown report or JSON dict string.
        """
        import json as _json

        from ..audit.bpa_checks import run_all_checks
        from ..audit.iso27001_controls import BPA_TO_ISO27001, ISO27001_CONTROLS

        snap = extract_snapshot(client, folder, tenant_id)
        findings = run_all_checks(snap)

        # Map findings to controls
        control_findings: dict[str, list[dict[str, Any]]] = {cid: [] for cid in ISO27001_CONTROLS}
        for f in findings:
            for cid in BPA_TO_ISO27001.get(f.check_id, []):
                if cid in control_findings:
                    control_findings[cid].append(f.to_dict())

        # Filter controls
        def _include(cid: str) -> bool:
            if clause_filter == "all":
                return True
            if clause_filter == "5":
                return cid.startswith("A.5.")
            if clause_filter == "8":
                return cid.startswith("A.8.")
            return cid == clause_filter

        assessed: list[dict[str, Any]] = []
        for cid, control in ISO27001_CONTROLS.items():
            if not _include(cid):
                continue
            related = control_findings[cid]
            has_fail = any(f["status"] in ("fail", "warn") for f in related)
            has_pass = any(f["status"] == "pass" for f in related)
            compliance = (
                "non-compliant" if has_fail else ("compliant" if has_pass else "not-assessed")
            )
            assessed.append(
                {
                    "control_id": cid,
                    "title": control.title,
                    "clause": control.clause,
                    "category": control.category,
                    "implementation_level": control.implementation_level,
                    "compliance_status": compliance,
                    "finding_count": len(related),
                    "evidence_guidance": control.evidence_guidance,
                }
            )

        compliant = sum(1 for a in assessed if a["compliance_status"] == "compliant")
        non_compliant = sum(1 for a in assessed if a["compliance_status"] == "non-compliant")
        not_assessed_count = sum(1 for a in assessed if a["compliance_status"] == "not-assessed")
        total = len(assessed)
        pct = round(compliant / total * 100) if total else 0

        if non_compliant == 0 and compliant >= total * 0.8:
            overall = "CONFORMING"
        elif non_compliant <= 2:
            overall = "MINOR NONCONFORMITY"
        else:
            overall = "MAJOR NONCONFORMITY"

        if output_format.lower() == "json":
            result: dict[str, Any] = {
                "folder": folder,
                "tenant_id": tenant_id,
                "standard": "ISO/IEC 27001:2022",
                "clause_filter": clause_filter,
                "overall": overall,
                "summary": {
                    "total": total,
                    "compliant": compliant,
                    "non_compliant": non_compliant,
                    "not_assessed": not_assessed_count,
                    "compliance_pct": pct,
                },
                "controls": assessed,
            }
            out_str = _json.dumps(result, indent=2)
            if save_to:
                Path(save_to).write_text(out_str)
                return f"ISO 27001 assessment saved to `{save_to}`. Overall: {overall} ({pct}%)"
            return out_str

        # Markdown output
        _status_icon = {
            "compliant": "✅",
            "non-compliant": "❌",
            "not-assessed": "⚪",
        }
        _overall_style = {
            "CONFORMING": "🟢 **CONFORMING**",
            "MINOR NONCONFORMITY": "🟡 **MINOR NONCONFORMITY**",
            "MAJOR NONCONFORMITY": "🔴 **MAJOR NONCONFORMITY**",
        }
        status_order = {"non-compliant": 0, "compliant": 1, "not-assessed": 2}

        lines: list[str] = []
        lines.append(f"# ISO/IEC 27001:2022 Annex A Assessment — {folder}")
        lines.append("")
        lines.append(f"**Overall:** {_overall_style.get(overall, overall)}")
        lines.append(
            f"**Controls assessed:** {total}  |  "
            f"**Compliant:** {compliant}  |  "
            f"**Non-compliant:** {non_compliant}  |  "
            f"**Not assessed:** {not_assessed_count}  |  "
            f"**Score:** {pct}%"
        )
        lines.append("")
        lines.append(
            "> **Scope note:** This assessment covers the 12 Annex A controls "
            "observable from firewall and SCM configuration. Controls in Clauses 5 "
            "(Governance), 6 (People), and 7 (Physical) require ISMS documentation "
            "and are out of scope for automated assessment."
        )
        lines.append("")

        lines.append("## Control Assessment")
        lines.append("")
        lines.append("| Control | Title | Level | Status | Findings |")
        lines.append("|---|---|---|---|---|")

        for a in sorted(
            assessed,
            key=lambda x: (
                status_order.get(str(x["compliance_status"]), 9),
                str(x["control_id"]),
            ),
        ):
            icon = _status_icon.get(str(a["compliance_status"]), "⚪")
            level_badge = "🔵 Advanced" if a["implementation_level"] == "advanced" else "Basic"
            lines.append(
                f"| `{a['control_id']}` | {a['title']} | {level_badge} "
                f"| {icon} {str(a['compliance_status']).upper()} | {a['finding_count']} BPA checks |"
            )
        lines.append("")

        # Non-compliant detail
        non_compliant_controls = [a for a in assessed if a["compliance_status"] == "non-compliant"]
        if non_compliant_controls:
            lines.append("## Non-Compliant Controls — Evidence & Remediation")
            lines.append("")
            for a in sorted(non_compliant_controls, key=lambda x: str(x["control_id"])):
                lines.append(f"### ❌ `{a['control_id']}` — {a['title']}")
                lines.append(f"**Clause:** {a['clause']}")
                lines.append(f"**Evidence required:** {a['evidence_guidance']}")
                lines.append("")
                # Show failing BPA check names
                ctrl_findings = control_findings[str(a["control_id"])]
                failing = [f for f in ctrl_findings if f["status"] in ("fail", "warn")]
                if failing:
                    lines.append(f"**Failing BPA checks ({len(failing)}):**")
                    for ff in failing[:5]:
                        lines.append(f"- `{ff['check_id']}` — {ff['title']}")
                    if len(failing) > 5:
                        lines.append(f"- *…and {len(failing) - 5} more*")
                lines.append("")

        lines.append("## Out-of-Scope Controls (require ISMS documentation)")
        lines.append("")
        lines.append(
            "The following Annex A controls cannot be assessed from firewall config "
            "and must be evidenced through ISMS policies, procedures, and records:"
        )
        lines.append("")
        lines.append("| Clause | Controls |")
        lines.append("|---|---|")
        lines.append("| 5 — Organisational | A.5.1–A.5.13, A.5.15–A.5.27, A.5.29–A.5.37 |")
        lines.append("| 6 — People | A.6.1–A.6.8 |")
        lines.append("| 7 — Physical | A.7.1–A.7.14 |")
        lines.append(
            "| 8 — Technological (non-FW) | A.8.1–A.8.6, A.8.8–A.8.14, A.8.16–A.8.19, A.8.25–A.8.26, A.8.30–A.8.34 |"
        )
        lines.append("")

        lines.append("## References")
        lines.append("")
        lines.append("- ISO/IEC 27001:2022 — Information security management systems")
        lines.append("- ISO/IEC 27002:2022 — Controls guidance (implementation detail)")
        lines.append("- NCSC Cyber Essentials: <https://www.ncsc.gov.uk/cyberessentials/overview>")
        lines.append(
            "- PAN security profile best practices: <https://docs.paloaltonetworks.com/best-practices>"
        )
        lines.append("")

        result_md = "\n".join(lines)
        if save_to:
            Path(save_to).write_text(result_md)
            return (
                f"ISO 27001 assessment saved to `{save_to}`.\n\n"
                f"Overall: {overall} | {compliant}/{total} compliant ({pct}%)"
            )
        return result_md

    # ── Decryption Policy Audit ───────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_decrypt_policy_audit(
        client: Any, tenant_id: str, folder: str, output_format: str = "markdown", save_to: str = ""
    ) -> str:
        """Deep-dive SSL/TLS decryption policy audit for a SCM folder.

        Goes beyond BPA-DEC-001/002 to assess:
        - **Profile quality**: TLS version (min ≥ 1.2), weak algorithm flags (3DES,
          RC4, MD5, SHA-1, static RSA key exchange), forward-proxy block settings
          (expired cert, untrusted issuer, unknown cert, unsupported version).
        - **Rule coverage**: decrypt vs no-decrypt ratio, zone pairs covered, presence
          of any-any catch-all decrypt rule, disabled rules, rules without a profile.
        - **Inbound inspection**: whether inbound SSL inspection rules are configured
          for public-facing services.
        - **Gap analysis**: prioritised actionable findings with NCSC CAF (D3.b) and
          DSPT Standard 9 cross-references.
        - **Overall verdict**: Adequate / Partial / Insufficient with a concise
          executive summary.

        Args:
            folder: SCM folder to audit (e.g. 'Shared', 'All', 'Prisma Access').
            tenant_id: Specific tenant; uses default if omitted.
            output_format: 'markdown' (default) or 'json'.
            save_to: Optional file path to save the report.

        Returns:
            Markdown report or JSON dict string.
        """
        import json as _json

        snap = extract_snapshot(client, folder, tenant_id)

        profiles = snap.decryption_profiles
        rules = snap.decryption_rules

        # ── Profile quality analysis ──────────────────────────────────────
        _WEAK_TLS = {"sslv3", "tls1-0", "tls1-1"}
        _WEAK_ALGOS = {
            "enc_algo_3des": "3DES",
            "enc_algo_rc4": "RC4",
            "auth_algo_md5": "MD5",
            "auth_algo_sha1": "SHA-1",
            "keyxchg_algo_rsa": "Static RSA (no PFS)",
        }
        _BLOCK_SETTINGS = {
            "block_expired_certificate": "Block expired certs",
            "block_untrusted_issuer": "Block untrusted issuer",
            "block_unknown_cert": "Block unknown cert",
            "block_unsupported_version": "Block unsupported version",
        }

        profile_findings: list[dict[str, Any]] = []
        for p in profiles:
            pname = p.get("name", "<unnamed>")
            issues: list[str] = []
            good: list[str] = []

            proto = p.get("ssl_protocol_settings") or {}
            min_ver = str(proto.get("min_version") or "").lower()
            if min_ver in _WEAK_TLS or min_ver == "":
                issues.append(f"min TLS version is '{min_ver or 'unset'}' — should be tls1-2+")
            else:
                good.append(f"min TLS {min_ver}")

            for field_name, label in _WEAK_ALGOS.items():
                val = proto.get(field_name)
                if val is True:
                    issues.append(f"{label} enabled")
                elif val is False:
                    good.append(f"{label} disabled")

            fp = p.get("ssl_forward_proxy") or {}
            for field_name, label in _BLOCK_SETTINGS.items():
                val = fp.get(field_name)
                if val is False:
                    issues.append(f"Forward proxy: {label} is OFF")
                elif val is True:
                    good.append(f"{label} ON")

            profile_findings.append(
                {
                    "name": pname,
                    "has_forward_proxy": bool(p.get("ssl_forward_proxy")),
                    "has_inbound_proxy": bool(p.get("ssl_inbound_proxy")),
                    "has_no_proxy": bool(p.get("ssl_no_proxy")),
                    "min_tls": min_ver or "unset",
                    "issues": issues,
                    "good": good,
                    "quality": "PASS" if not issues else ("WARN" if len(issues) <= 2 else "FAIL"),
                }
            )

        # ── Rule coverage analysis ────────────────────────────────────────
        total_rules = len(rules)
        decrypt_rules = [
            r
            for r in rules
            if str(r.get("action", "")).lower() == "decrypt" and not r.get("disabled")
        ]
        no_decrypt_rules = [
            r
            for r in rules
            if str(r.get("action", "")).lower() in ("no-decrypt", "no_decrypt")
            and not r.get("disabled")
        ]
        disabled_rules = [r for r in rules if r.get("disabled")]
        no_profile_rules = [
            r for r in decrypt_rules if not r.get("profile") and not r.get("profile_setting")
        ]

        def _is_any(val: Any) -> bool:
            if val is None:
                return True
            if isinstance(val, str):
                return val.lower() in ("any", "")
            if isinstance(val, list):
                return len(val) == 0 or val == ["any"]
            return False

        catchall_rules = [
            r
            for r in decrypt_rules
            if _is_any(r.get("source"))
            and _is_any(r.get("destination"))
            and _is_any(r.get("category"))
        ]

        def _rule_from(r: dict[str, Any]) -> list[Any]:
            return r.get("from_") or r.get("from") or []  # SDK uses from_ (keyword escape)

        def _rule_to(r: dict[str, Any]) -> list[Any]:
            return r.get("to_") or r.get("to") or []

        inbound_decrypt_count = sum(
            1
            for r in decrypt_rules
            if str(r.get("type", "")).lower() in ("ssl-inbound-inspection", "inbound", "")
            and any(
                str(z).lower() in ("untrust", "external", "outside", "internet", "wan")
                for z in _rule_from(r)
            )
        )

        exclusion_categories: set[str] = set()
        for r in no_decrypt_rules:
            for cat in r.get("category") or []:
                exclusion_categories.add(str(cat))

        # ── Gap findings ──────────────────────────────────────────────────
        gaps: list[dict[str, Any]] = []

        if not profiles:
            gaps.append(
                {
                    "severity": "CRITICAL",
                    "id": "DEC-G001",
                    "title": "No decryption profiles configured",
                    "detail": "SSL/TLS traffic cannot be inspected without at least one decryption profile.",
                    "fix": "Create a decryption profile (Policies → Decryption Profiles) with TLS 1.2+ minimum.",
                    "ncsc": "D3.b",
                    "dspt": "DSPT-9.2.1",
                }
            )
        elif not decrypt_rules:
            gaps.append(
                {
                    "severity": "CRITICAL",
                    "id": "DEC-G002",
                    "title": "No active decrypt rules",
                    "detail": f"{total_rules} rule(s) exist but none have action=decrypt and are enabled.",
                    "fix": "Add a decrypt rule referencing your decryption profile to enforce SSL inspection.",
                    "ncsc": "D3.b",
                    "dspt": "DSPT-9.2.1",
                }
            )
        else:
            if not catchall_rules:
                gaps.append(
                    {
                        "severity": "HIGH",
                        "id": "DEC-G003",
                        "title": "No any-any catch-all decrypt rule",
                        "detail": (
                            f"{len(decrypt_rules)} decrypt rule(s) found but none cover "
                            "source=any / destination=any / category=any. Specific traffic "
                            "not matched by a rule will bypass SSL inspection."
                        ),
                        "fix": "Add a low-priority decrypt rule (any/any/any) as a catch-all after your no-decrypt exclusions.",
                        "ncsc": "D3.b",
                        "dspt": "DSPT-9.2.1",
                    }
                )

        for pf in profile_findings:
            for issue in pf["issues"]:
                sev = (
                    "HIGH"
                    if any(
                        k in issue
                        for k in (
                            "3DES",
                            "RC4",
                            "MD5",
                            "SHA-1",
                            "Static RSA",
                            "tls1-0",
                            "tls1-1",
                            "sslv3",
                        )
                    )
                    else "MEDIUM"
                )
                gaps.append(
                    {
                        "severity": sev,
                        "id": "DEC-G004",
                        "title": f"Profile '{pf['name']}': {issue}",
                        "detail": f"Decryption profile '{pf['name']}' has a weak configuration: {issue}.",
                        "fix": "Update the decryption profile SSL protocol settings to remediate.",
                        "ncsc": "D3.b",
                        "dspt": "DSPT-9.2.2",
                    }
                )

        if disabled_rules:
            gaps.append(
                {
                    "severity": "LOW",
                    "id": "DEC-G005",
                    "title": f"{len(disabled_rules)} disabled decryption rule(s)",
                    "detail": f"Rules: {', '.join(r.get('name', '?') for r in disabled_rules[:5])}",
                    "fix": "Review disabled rules — enable those needed or remove stale entries.",
                    "ncsc": "D3.b",
                    "dspt": "DSPT-9.6.1",
                }
            )

        if no_profile_rules:
            gaps.append(
                {
                    "severity": "HIGH",
                    "id": "DEC-G006",
                    "title": f"{len(no_profile_rules)} decrypt rule(s) without a decryption profile",
                    "detail": f"Rules: {', '.join(r.get('name', '?') for r in no_profile_rules[:5])}",
                    "fix": "Assign a decryption profile to every decrypt rule to enforce TLS controls.",
                    "ncsc": "D3.b",
                    "dspt": "DSPT-9.2.2",
                }
            )

        # ── Overall verdict ───────────────────────────────────────────────
        critical_gaps = [g for g in gaps if g["severity"] == "CRITICAL"]
        high_gaps = [g for g in gaps if g["severity"] == "HIGH"]
        if critical_gaps:
            verdict = "INSUFFICIENT"
            verdict_md = "🔴 **INSUFFICIENT** — Critical gaps prevent SSL inspection"
        elif high_gaps:
            verdict = "PARTIAL"
            verdict_md = (
                "🟡 **PARTIAL** — SSL inspection is configured but has significant weaknesses"
            )
        elif gaps:
            verdict = "ADEQUATE"
            verdict_md = (
                "🟢 **ADEQUATE** — SSL inspection is in place; minor improvements recommended"
            )
        else:
            verdict = "ADEQUATE"
            verdict_md = "🟢 **ADEQUATE** — SSL decryption policy meets best practice baseline"

        # ── Render ────────────────────────────────────────────────────────
        if output_format.lower() == "json":
            result: dict[str, Any] = {
                "folder": folder,
                "tenant_id": tenant_id,
                "verdict": verdict,
                "summary": {
                    "total_profiles": len(profiles),
                    "total_rules": total_rules,
                    "decrypt_rules": len(decrypt_rules),
                    "no_decrypt_rules": len(no_decrypt_rules),
                    "disabled_rules": len(disabled_rules),
                    "catchall_rules": len(catchall_rules),
                    "inbound_decrypt_rules": inbound_decrypt_count,
                    "exclusion_categories": sorted(exclusion_categories),
                },
                "profiles": profile_findings,
                "gaps": gaps,
            }
            out_str = _json.dumps(result, indent=2)
            if save_to:
                Path(save_to).write_text(out_str)
                return f"Decryption audit saved to `{save_to}`. Verdict: {verdict}"
            return out_str

        # Markdown output
        lines: list[str] = []
        lines.append(f"# SSL/TLS Decryption Policy Audit — {folder}")
        lines.append("")
        lines.append(f"**Verdict:** {verdict_md}")
        lines.append(
            f"**Profiles:** {len(profiles)}  |  "
            f"**Rules:** {total_rules} total / "
            f"{len(decrypt_rules)} decrypt / "
            f"{len(no_decrypt_rules)} no-decrypt / "
            f"{len(disabled_rules)} disabled"
        )
        lines.append(
            f"**Catch-all decrypt rule:** {'✅ Yes' if catchall_rules else '❌ None'}  |  "
            f"**Inbound inspection rules:** {inbound_decrypt_count}"
        )
        if exclusion_categories:
            lines.append(
                f"**Excluded categories ({len(exclusion_categories)}):** "
                + ", ".join(sorted(exclusion_categories)[:10])
                + ("…" if len(exclusion_categories) > 10 else "")
            )
        lines.append("")

        # Profile quality table
        lines.append("## Decryption Profile Quality")
        lines.append("")
        if not profiles:
            lines.append("> ⚠️ No decryption profiles found.")
        else:
            lines.append("| Profile | Type | Min TLS | Quality | Issues |")
            lines.append("|---|---|---|---|---|")
            _q_icon = {"PASS": "✅", "WARN": "⚠️", "FAIL": "❌"}
            for pf in profile_findings:
                ptype = (
                    ("Fwd+Inbound" if pf["has_forward_proxy"] and pf["has_inbound_proxy"] else "")
                    or ("Forward" if pf["has_forward_proxy"] else "")
                    or ("Inbound" if pf["has_inbound_proxy"] else "")
                    or ("No-decrypt" if pf["has_no_proxy"] else "Unknown")
                )
                icon = _q_icon.get(pf["quality"], "?")
                issue_summary = "; ".join(pf["issues"][:3]) or "None"
                lines.append(
                    f"| {pf['name']} | {ptype} | {pf['min_tls']} | {icon} {pf['quality']} | {issue_summary} |"
                )
        lines.append("")

        # Rule coverage table
        lines.append("## Decryption Rule Coverage")
        lines.append("")
        if not rules:
            lines.append("> ⚠️ No decryption rules found.")
        else:
            lines.append("| Rule | Action | From | To | Categories | Profile | Status |")
            lines.append("|---|---|---|---|---|---|---|")
            _action_icon = {"decrypt": "🔍", "no-decrypt": "🚫", "no_decrypt": "🚫"}
            for r in rules[:30]:
                action = str(r.get("action", "—")).lower()
                icon = _action_icon.get(action, "❓")
                from_zones = ", ".join(_rule_from(r) or ["any"])[:30]
                to_zones = ", ".join(_rule_to(r) or ["any"])[:30]
                cats = ", ".join((r.get("category") or [])[:3]) or "any"
                profile = str(r.get("profile") or r.get("profile_setting") or "—")[:20]
                status = "🚫 Disabled" if r.get("disabled") else "✅ Active"
                lines.append(
                    f"| {r.get('name', '?')[:30]} | {icon} {action} | {from_zones} | {to_zones} | {cats} | {profile} | {status} |"
                )
            if len(rules) > 30:
                lines.append(f"| *…{len(rules) - 30} more rules not shown* | | | | | | |")
        lines.append("")

        # Gap findings
        lines.append("## Gap Analysis")
        lines.append("")
        if not gaps:
            lines.append("✅ No gaps found. Decryption policy meets best-practice baseline.")
        else:
            _sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            for g in sorted(gaps, key=lambda x: sev_order.get(str(x["severity"]), 9)):
                sicon = _sev_icon.get(str(g["severity"]), "⚪")
                lines.append(f"### {sicon} [{g['severity']}] {g['id']} — {g['title']}")
                lines.append(f"**Detail:** {g['detail']}")
                lines.append(f"**Fix:** {g['fix']}")
                lines.append(f"**NCSC:** {g['ncsc']}  |  **DSPT:** {g['dspt']}")
                lines.append("")

        # References
        lines.append("## References")
        lines.append("")
        lines.append("- NCSC CAF D3.b — Protecting data in transit (TLS inspection)")
        lines.append("- DSPT Standard 9 — IT Protection (assertions 9.2.1, 9.2.2)")
        lines.append(
            "- NCSC TLS guidance: <https://www.ncsc.gov.uk/guidance/tls-external-facing-services>"
        )
        lines.append(
            "- PAN SSL decryption best practices: <https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/decryption>"
        )
        lines.append("")

        result_md = "\n".join(lines)
        if save_to:
            Path(save_to).write_text(result_md)
            return f"Decryption audit saved to `{save_to}`. Verdict: {verdict}"
        return result_md

    # ── Combined Audit Report ─────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_audit_report(
        client: Any, tenant_id: str, folder: str, output_format: str = "markdown", save_to: str = ""
    ) -> str:
        """Generate a combined BPA + NCSC compliance report for a SCM folder.

        Produces a full AS-BUILT audit document covering:
        - Configuration inventory (addresses, rules, profiles, zones, VPN)
        - PAN Best Practice Assessment findings with remediation guidance
        - NCSC CAF v4.0 / Cyber Essentials v3.2 / 10 Steps cross-reference
        - Prioritised remediation action list

        Args:
            folder: SCM folder to assess.
            tenant_id: SCM tenant ID (MSSP mode).
            output_format: 'markdown' or 'json'.
            save_to: Optional file path to write the report to disk.

        Returns:
            The full report as a string (Markdown or JSON).
        """
        snap = extract_snapshot(client, folder=folder, tenant_id=tenant_id or "default")
        findings = run_all_checks(snap)
        builder = ReportBuilder(snap, findings)

        report = builder.to_json() if output_format.lower() == "json" else builder.to_markdown()

        if save_to:
            Path(save_to).write_text(report)
            logger.info("audit_report_saved", path=save_to, folder=folder)
            return f"Report saved to: {save_to}\n\n{report}"

        return report

    # ── Prisma SASE AS-BUILT AS-IS Report ─────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_asbuilt_report(
        client: Any,
        tenant_id: str,
        deployment_type: str = "Prisma Access",
        folder: str = "",
        customer_name: str = "",
        mssp_name: str = "MSSP",
        doc_version: str = "1.0",
        include_sdwan: bool = False,
        include_extended: bool = False,
        include_insights: bool = False,
        insights_region: str = "eu",
        include_adem: bool = False,
        enrich_wan_ips: bool = False,
    ) -> str:
        """Generate a full Prisma SASE AS-IS AS-BUILT document.

        Pulls live configuration from SCM and produces a structured 9-section
        AS-BUILT covering:

          2. Deployed Prisma SASE Architecture — live topology Mermaid diagram,
             management plane, compute locations and egress IP reference
          3. Prisma Access Infrastructure — Remote Networks (branches with IPSec
             tunnels, BGP, QoS), Service Connections (DCs), Mobile Users
             (GlobalProtect portals, IP pools, forwarding profiles)
          4. Prisma SD-WAN — ION inventory template (manual; not in SCM API)
          5. SSE & Zero Trust — threat prevention, SWG, ZTNA security rules
          6. Identity & Posture — authentication profiles, SAML IdPs, HIP checks
          7. Observability — log forwarding profiles, syslog/HTTP destinations
          8. MSSP Service Model — RACI, MACD, ITSM integration, SLA matrix
          9. Appendices — subnet/IP pool tables, public egress IP whitelist
             reference, VPN crypto profiles

        Sections that cannot be derived from the SCM API (SD-WAN, ADEM, CDL,
        SOAR, CIE) are clearly marked with ⚠️ manual-input placeholders.

        Args:
            deployment_type: Deployment model — controls the default SCM folder
                and which sections are active.  Choose one of:
                  "Prisma Access" (default) — Prisma SASE/PA tenant;
                    folder defaults to "Prisma Access".
                  "NGFW"          — SCM-managed Next-Gen Firewall fleet;
                    folder defaults to "Prisma Access".
                  "SD-WAN Only"   — SD-WAN-only tenant (no PA);
                    folder defaults to "All".
            folder: SCM folder to report on.  Leave blank to use the
                deployment_type default ("Prisma Access" for PA/NGFW,
                "All" for SD-WAN Only).
            tenant_id: SCM tenant ID (MSSP mode).
            customer_name: Customer name shown in the document header.
            mssp_name: MSSP name shown in the document header.
            doc_version: Document version string (e.g. "1.0").
            output_format: 'markdown' (default) or 'docx' (requires pandoc).
            include_sdwan: If True, pull live SD-WAN data (sites, elements,
                           WAN interfaces, policies) using the same credentials.
                           Fills §4 with real data instead of placeholders.
            save_to: Optional file path to write the report to disk.
                     For docx format defaults to '<customer_name>-asbuilt.docx'
                     if not specified.
            include_extended: If True, also pull CASB/DLP profiles, ZTNA
                              Connector inventory, and Prisma Browser config.
                              Adds extra API calls — only enable when those
                              sections are needed and the tenant has the licences.
            include_insights: If True, query the Prisma Access Insights v3.0 API
                              for live operational data: RN/SC tunnel status,
                              bandwidth consumption, connected mobile user count,
                              and active alerts. Adds §3.1.2, §3.2.1, §3.3.7,
                              and §3.5 to the AS-BUILT.
            insights_region:  Prisma Access region for the X-PANW-Region header
                              used by the Insights API (default: "eu").
                              Common values: "eu", "us", "uk", "sg", "au".
            include_adem:     If True, query the Autonomous DEM Telemetry API for
                              live application experience scores (last 3 days) and
                              aggregate agent scores. Populates §7.1 with a scored
                              app table instead of the manual-input placeholder.
                              Uses the same SCM OAuth token — no extra credentials.
            enrich_wan_ips:   If True, reverse-look-up each public WAN IP (ISP,
                              ASN, geolocation) and add ISP/Geo/Drift columns to
                              the §4.2.1 SD-WAN and §3.4.7 NGFW WAN IP tables,
                              and populate §8.1.4 (SD-WAN detected public IPs
                              and ISP attribution, with configured-vs-detected
                              NAT/CGNAT mismatch notes). Sends tenant public IPs
                              to the configured IP-intelligence provider (see
                              ip_enrichment_provider setting) — opt-in for that
                              reason. Results are disk-cached 30 days, so
                              re-runs cost no lookups.

        Returns:
            Job ID string. Call scm_asbuilt_result(job_id) once extraction completes.
        """
        _prune_asbuilt_jobs()

        # Resolve folder before handing off to thread
        _dt = deployment_type.strip()
        _folder = folder or (
            "All"
            if _dt.lower() in ("sd-wan only", "sdwan only", "sdwan", "sd-wan")
            else "Prisma Access"
        )

        job_id = uuid.uuid4().hex[:8]
        with _JOBS_LOCK:
            _ASBUILT_JOBS[job_id] = {
                "status": "running",
                "started_at": time.time(),
                "folder": _folder,
                "tenant_id": tenant_id,
                "result": None,
                "error": None,
            }

        def _run() -> None:
            try:
                _tc_meta = get_tenant_meta(tenant_id) if tenant_id else None

                _inc_sdwan = include_sdwan
                if _tc_meta is not None and _tc_meta.sdwan_only:
                    _inc_sdwan = True

                snap = extract_snapshot(client, _folder, tenant_id or "default")

                # A cached mssp_tenant_capabilities probe lets us skip families
                # already known to be forbidden/unprovisioned, instead of
                # discovering the 403 mid-run. No cache → no skips (never probes).
                def _cap_ok(family: str, *sinks: list[str]) -> bool:
                    reason = capability_skip_reason(tenant_id, family)
                    if reason is None:
                        return True
                    note = f"{family}: {reason}"
                    snap.extraction_errors.append(note)
                    for sink in sinks:
                        sink.append(note)
                    logger.info("asbuilt_section_skipped_by_capability", family=family)
                    return False

                if _cap_ok("licensing"):
                    extract_licenses(client, snap)

                _pa_key = None
                if _tc_meta is not None and _tc_meta.prisma_access_api_key is not None:
                    _pa_key = _tc_meta.prisma_access_api_key.get_secret_value()
                if _pa_key:
                    extract_egress_ips_datapath(_pa_key, snap)
                elif _cap_ok("allocated_ips"):
                    extract_allocated_ips(client, snap)

                if include_insights and _cap_ok("insights", snap.insights_errors):
                    _effective_region = insights_region
                    if _effective_region == "eu" and tenant_id:
                        _tc = get_tenant_meta(tenant_id)
                        if _tc is not None:
                            _effective_region = _tc.insights_region
                    extract_insights(client, snap, region=_effective_region)
                if include_adem and _cap_ok("adem", snap.adem_errors):
                    extract_adem(client, snap)
                if include_extended:
                    extract_casb_dlp(client, snap, folder=_folder)
                    if _cap_ok("ztna_connector"):
                        extract_ztna_connectors(client, snap)
                    extract_browser(client, snap)
                    extract_cdl(client, snap)
                    extract_ngfw_devices(client, snap)
                    extract_ngfw_routing(client, snap)
                    extract_ngfw_interface_ips(client, snap)
                    extract_airs(client, snap)
                    if _cap_ok("enterprise_dlp"):
                        extract_enterprise_dlp(client, snap)
                    extract_iot_security(client, snap)
                    extract_app_acceleration(client, snap)

                if _cap_ok("sspm"):
                    extract_sspm(client, snap)
                extract_identity_sspm(client, snap)
                extract_traffic_steering(client, snap)
                extract_pab_tenant(client, snap)
                if _cap_ok("iam"):
                    extract_iam_roles(client, snap)
                    extract_iam_access_policies(client, snap)
                if _cap_ok("tenancy"):
                    extract_managed_tenants(client, snap)
                extract_mt_monitor_alerts(client, snap)

                if _inc_sdwan and _cap_ok("sdwan"):
                    try:
                        from ..auth.sdwan import get_sdwan_client
                        from ..config.settings import get_settings

                        _sdwan_tc = _tc_meta
                        if _sdwan_tc is None:
                            s = get_settings()
                            _sdwan_tc = s.default_tenant()
                        sdwan_client = get_sdwan_client(_sdwan_tc)
                        extract_sdwan_snapshot(sdwan_client, snap)
                    except Exception as exc:
                        snap.extraction_errors.append(f"sdwan_init: {exc}")
                        logger.warning("sdwan_init_failed", error=str(exc))

                if enrich_wan_ips:
                    try:
                        from ..audit.extractor import (
                            annotate_wan_ip_drift,
                            enrich_wan_ip_records,
                        )

                        site_geo = {
                            s.get("id"): (s.get("location") or {}) for s in snap.sdwan_sites
                        }
                        for rec in snap.sdwan_wan_ips:
                            rec.setdefault("site_location", site_geo.get(rec.get("site_id")) or {})
                        warns = enrich_wan_ip_records(
                            snap.sdwan_wan_ips, ("ipv4_addresses", "ipv6_addresses")
                        )
                        warns += enrich_wan_ip_records(snap.ngfw_interface_ips, ("ip_addresses",))
                        warns += enrich_wan_ip_records(
                            snap.sdwan_detected_public_ips, ("detected_public_ip",)
                        )
                        annotate_wan_ip_drift(snap.sdwan_wan_ips)
                        snap.extraction_errors.extend(f"wan_ip_enrichment: {w}" for w in warns)
                    except Exception as exc:
                        snap.extraction_errors.append(f"wan_ip_enrichment: {exc}")
                        logger.warning("wan_ip_enrichment_failed", error=str(exc))

                _jobs: list[dict[str, Any]] = []
                if _cap_ok("config_jobs"):
                    try:
                        _job_resp = client.list_jobs(limit=200, offset=0)
                        _all_jobs = _job_resp.data if hasattr(_job_resp, "data") else []
                        for j in _all_jobs:
                            parent = str(getattr(j, "parent_id", "") or "")
                            if parent not in ("0", "", "None"):
                                continue
                            _jobs.append(
                                {
                                    "job_id": str(getattr(j, "id", "")),
                                    "type": str(getattr(j, "type_str", getattr(j, "job_type", ""))),
                                    "result": str(getattr(j, "result_str", "")),
                                    "user": str(getattr(j, "uname", "")),
                                    "description": str(getattr(j, "description", "") or ""),
                                    "start_ts": str(getattr(j, "start_ts", "")),
                                    "end_ts": str(getattr(j, "end_ts", "")),
                                    "parent_id": parent,
                                }
                            )
                    except Exception as _je:
                        logger.warning("list_jobs_failed", error=str(_je))
                        snap.extraction_errors.append(f"list_jobs: {_je}")

                builder = AsBuiltReportBuilder(
                    snap,
                    customer_name=customer_name or _folder,
                    mssp_name=mssp_name,
                    doc_version=doc_version,
                    sdwan_only=_tc_meta.sdwan_only if _tc_meta is not None else False,
                    jobs=_jobs,
                )
                report_md = builder.to_markdown()
                elapsed = round(time.time() - _ASBUILT_JOBS[job_id]["started_at"])
                logger.info("asbuilt_job_complete", job_id=job_id, elapsed_s=elapsed)
                with _JOBS_LOCK:
                    _ASBUILT_JOBS[job_id]["status"] = "done"
                    _ASBUILT_JOBS[job_id]["result"] = report_md
                    # Kept for scm_asbuilt_verify — doc-vs-live drift checking
                    _ASBUILT_JOBS[job_id]["snap"] = snap

            except Exception as exc:
                logger.error("asbuilt_job_failed", job_id=job_id, error=str(exc))
                with _JOBS_LOCK:
                    _ASBUILT_JOBS[job_id]["status"] = "error"
                    _ASBUILT_JOBS[job_id]["error"] = handle_scm_exception(exc)

        threading.Thread(target=_run, daemon=True, name=f"asbuilt-{job_id}").start()

        _tid = tenant_id or "default"
        return (
            f"AS-BUILT extraction started (job `{job_id}`) — "
            f"tenant `{_tid}`, folder `{_folder}`.\n\n"
            f"Extraction takes **2–4 minutes**. When ready, call:\n\n"
            f'    scm_asbuilt_result(job_id="{job_id}")\n\n'
            f"To save directly to disk:\n\n"
            f'    scm_asbuilt_result(job_id="{job_id}", save_to="report.md")'
        )

    # ── AS-BUILT Result Retrieval ─────────────────────────────────────────────

    @mcp.tool()
    def scm_asbuilt_result(
        job_id: str,
        save_to: str = "",
        output_format: str = "markdown",
    ) -> str:
        """Retrieve a completed AS-BUILT report started by scm_asbuilt_report.

        Call this after scm_asbuilt_report returns a job ID. Extraction typically
        completes within 2–4 minutes. If still running, a status message is returned
        — simply call again after another minute.

        Args:
            job_id: Job ID returned by scm_asbuilt_report.
            save_to: Optional file path to write the completed report.
            output_format: 'markdown' (default) or 'docx' (requires pandoc).

        Returns:
            The full Markdown AS-BUILT, a save-path confirmation, or a status
            message if still running.
        """
        with _JOBS_LOCK:
            job = dict(_ASBUILT_JOBS.get(job_id, {}))

        if not job:
            active = list(_ASBUILT_JOBS.keys())
            hint = f"  Active jobs: {active}" if active else "  No active jobs."
            return f"Job `{job_id}` not found (expires after 1 hour).\n{hint}"

        elapsed = int(time.time() - job["started_at"])
        mins, secs = divmod(elapsed, 60)

        if job["status"] == "running":
            return (
                f"Job `{job_id}` is still running ({mins}m {secs}s elapsed). "
                f"Check again in a minute."
            )

        if job["status"] == "error":
            return f"Job `{job_id}` failed after {mins}m {secs}s: {job['error']}"

        report_md = job["result"]
        folder = job.get("folder", "asbuilt")
        logger.info(
            "asbuilt_result_retrieved", job_id=job_id, elapsed_s=elapsed, format=output_format
        )

        fmt = output_format.lower()
        if fmt == "docx":
            safe_name = folder.replace(" ", "-").replace("/", "-")
            out_path = Path(save_to) if save_to else Path(f"{safe_name}-asbuilt.docx")
            result = _md_to_docx(report_md, out_path)
            if out_path.exists():
                logger.info("asbuilt_report_saved", path=str(out_path), format="docx")
                return f"AS-BUILT report saved as Word document: {out_path}"
            return f"{result}\n\n{report_md}"

        if save_to:
            Path(save_to).write_text(report_md)
            logger.info("asbuilt_report_saved", path=save_to, format="markdown")
            return f"AS-BUILT report saved to: {save_to}\n\n{report_md}"

        return report_md

    # ── AS-BUILT Verification (doc vs live) ───────────────────────────────────

    @mcp.tool()
    def scm_asbuilt_verify(job_id: str) -> str:
        """Verify a completed AS-BUILT document against live tenant state.

        Re-extracts a fresh core config snapshot (bypassing the snapshot
        cache) for the same tenant and folder the document was built from,
        then diffs it section by section against the snapshot behind the
        document. Flags every section where the document and the API now
        disagree — objects added, removed, or modified since generation —
        plus any extraction gaps that made the document incomplete at
        generation time.

        Run this after scm_asbuilt_result before handing the document to a
        customer: a clean verdict means the document still reflects the
        tenant; a drift verdict lists exactly which sections are stale.

        Only sections fed by the core config extraction are verified.
        Optional live-data sections (Insights, ADEM, SD-WAN) are not
        re-checked — they are operational metrics expected to change.

        Args:
            job_id: Job ID of a completed scm_asbuilt_report job (jobs are
                    kept for 1 hour after completion).

        Returns:
            Markdown verification report with a per-section match/drift
            table, drift detail, and a refresh recommendation if needed.
        """
        from ..audit.asbuilt_verify import diff_snapshots, render_verification_report

        with _JOBS_LOCK:
            job = dict(_ASBUILT_JOBS.get(job_id, {}))

        if not job:
            active = list(_ASBUILT_JOBS.keys())
            hint = f"  Active jobs: {active}" if active else "  No active jobs."
            return f"Job `{job_id}` not found (expires after 1 hour).\n{hint}"
        if job["status"] == "running":
            return f"Job `{job_id}` is still running — verify after scm_asbuilt_result succeeds."
        if job["status"] == "error":
            return f"Job `{job_id}` failed — nothing to verify: {job['error']}"

        doc_snap = job.get("snap")
        if doc_snap is None:
            return (
                f"Job `{job_id}` has no stored snapshot (generated before verification "
                "support was added). Re-run scm_asbuilt_report to enable verification."
            )

        try:
            tenant_id = job.get("tenant_id", "")
            folder = job.get("folder", "Prisma Access")
            client = get_client(tenant_id)
            live_snap = extract_snapshot(client, folder, tenant_id or "default", fresh=True)

            diffs = diff_snapshots(doc_snap, live_snap)
            doc_generated = datetime.fromtimestamp(job["started_at"], tz=UTC).strftime(
                "%Y-%m-%d %H:%M UTC"
            )
            verified_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
            drift_count = sum(1 for d in diffs if d.drifted)
            logger.info(
                "asbuilt_verify_complete",
                job_id=job_id,
                sections=len(diffs),
                drifted=drift_count,
            )
            return render_verification_report(
                diffs, doc_snap, live_snap, job_id, doc_generated, verified_at
            )
        except Exception as exc:
            return f"Error: {handle_scm_exception(exc, tool='scm_asbuilt_verify')}"

    # ── Drift Sentinel (baseline / check / result) ────────────────────────────

    def _drift_targets(tenant_id: str, all_tenants: bool) -> list[tuple[str, str, Any, str | None]]:
        """Resolve (label, tsg_id, client, auth_error) per tenant to sweep."""
        if not all_tenants:
            return [(tenant_id or "default", tenant_id or "default", get_client(tenant_id), None)]
        targets: list[tuple[str, str, Any, str | None]] = []
        for key, tc in load_all_tenant_configs().items():
            label = tc.label or key
            try:
                targets.append((label, tc.tenant_id, get_scm_client(tc), None))
            except Exception as exc:
                logger.warning("drift_auth_failed", tenant=key, error=str(exc))
                targets.append((label, tc.tenant_id, None, str(exc)))
        return targets

    def _drift_one(
        mode: str,
        label: str,
        tsg_id: str,
        client: Any,
        auth_error: str | None,
        folder: str,
        update_baseline: bool,
    ) -> dict[str, Any]:
        """Run one tenant's baseline capture or drift check. Never raises."""
        result: dict[str, Any] = {"label": label, "drifted": [], "unverified": 0, "error": None}
        try:
            if client is None:
                result["error"] = f"authentication failed: {auth_error}"
                return result
            live = extract_snapshot(client, folder, tsg_id, fresh=True)
            if mode == "baseline":
                path = save_baseline(live, _DEFAULT_BASELINE_DIR)
                populated = sum(1 for _f, _l in VERIFIED_SECTIONS if getattr(live, _f, None))
                result["path"] = str(path)
                result["sections"] = populated
                return result
            loaded = load_baseline(tsg_id, folder, _DEFAULT_BASELINE_DIR)
            if loaded is None:
                result["error"] = (
                    f"no baseline for folder {folder!r} — run scm_drift_baseline first"
                )
                return result
            baseline, saved_at = loaded
            result["baseline_saved_at"] = saved_at
            result["drifted"] = check_drift(baseline, live)
            result["unverified"] = sum(1 for d in diff_snapshots(baseline, live) if d.unverified)
            if update_baseline:
                save_baseline(live, _DEFAULT_BASELINE_DIR)
                result["baseline_updated"] = True
            return result
        except Exception as exc:
            result["error"] = handle_scm_exception(exc)
            return result

    def _drift_run(
        mode: str, folder: str, tenant_id: str, all_tenants: bool, update_baseline: bool
    ) -> str:
        """Shared runner: sync for one tenant, background job for a sweep."""
        targets = _drift_targets(tenant_id, all_tenants)
        ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

        def _render(results: list[dict[str, Any]]) -> str:
            if mode == "baseline":
                lines = [
                    "## Drift Baselines Captured",
                    "",
                    f"**Captured:** {ts}  |  **Folder:** `{folder}`",
                    "",
                ]
                for r in results:
                    if r.get("error"):
                        lines.append(f"- ⚠️ {r['label']}: {r['error']}")
                    else:
                        lines.append(
                            f"- ✅ {r['label']}: {r['sections']} populated section(s) → "
                            f"`{r['path']}`"
                        )
                lines.append("")
                lines.append("Run `scm_drift_check` any time to compare live config against these.")
                return "\n".join(lines)
            return render_drift_digest(results, ts)

        if not all_tenants:
            (label, tsg_id, client, auth_error) = targets[0]
            return _render(
                [_drift_one(mode, label, tsg_id, client, auth_error, folder, update_baseline)]
            )

        _prune_drift_jobs()
        job_id = uuid.uuid4().hex[:8]
        with _JOBS_LOCK:
            _DRIFT_JOBS[job_id] = {
                "status": "running",
                "started_at": time.time(),
                "result": None,
                "error": None,
            }

        def _run() -> None:
            try:
                from concurrent.futures import ThreadPoolExecutor

                with ThreadPoolExecutor(max_workers=3) as pool:
                    results = list(
                        pool.map(
                            lambda t: _drift_one(
                                mode, t[0], t[1], t[2], t[3], folder, update_baseline
                            ),
                            targets,
                        )
                    )
                digest = _render(results)
                with _JOBS_LOCK:
                    _DRIFT_JOBS[job_id]["status"] = "done"
                    _DRIFT_JOBS[job_id]["result"] = digest
                logger.info("drift_job_complete", job_id=job_id, mode=mode, tenants=len(targets))
            except Exception as exc:
                logger.error("drift_job_failed", job_id=job_id, error=str(exc))
                with _JOBS_LOCK:
                    _DRIFT_JOBS[job_id]["status"] = "error"
                    _DRIFT_JOBS[job_id]["error"] = handle_scm_exception(exc)

        threading.Thread(target=_run, daemon=True, name=f"drift-{job_id}").start()
        return (
            f"Drift {mode} sweep started (job `{job_id}`) across {len(targets)} tenant(s).\n\n"
            f"Each tenant takes ~2 minutes to extract (3 run concurrently). When ready:\n\n"
            f'    scm_drift_result(job_id="{job_id}")'
        )

    @mcp.tool()
    def scm_drift_baseline(
        folder: str = "Prisma Access",
        tenant_id: str = "",
        all_tenants: bool = False,
    ) -> str:
        """Capture the known-good config baseline(s) for drift monitoring.

        Extracts a fresh core config snapshot per tenant and stores it on disk
        (SCM_MCP_BASELINE_DIR, default ./baselines). scm_drift_check later
        compares live config against these baselines and reports what changed.

        Capture a baseline after a change window closes, when config is in a
        reviewed, known-good state.

        Args:
            folder: SCM folder to baseline (default "Prisma Access").
            tenant_id: SCM tenant ID (MSSP mode) for a single tenant.
            all_tenants: If True, baseline every configured tenant in a
                         background job — returns a job ID for scm_drift_result.

        Returns:
            Capture summary (single tenant, ~2 min) or a job ID (all tenants).
        """
        try:
            return _drift_run("baseline", folder, tenant_id, all_tenants, False)
        except Exception as exc:
            return f"Error: {handle_scm_exception(exc, tool='scm_drift_baseline')}"

    @mcp.tool()
    def scm_drift_check(
        folder: str = "Prisma Access",
        tenant_id: str = "",
        all_tenants: bool = False,
        update_baseline: bool = False,
    ) -> str:
        """Check live config against the stored baseline and report drift.

        Re-extracts a fresh core snapshot per tenant and diffs it section by
        section against the baseline captured by scm_drift_baseline. Drifted
        sections are triaged by severity — HIGH (security/NAT/decryption/auth
        rules, zones, VPN, identity, log forwarding), MEDIUM (protection
        profiles, posture, EDLs), LOW (address/service/tag plumbing) — and the
        digest lists exactly which objects were added, removed, or modified.

        This is the overnight sentinel: run it on a schedule with
        all_tenants=True and review the digest each morning. Unexplained HIGH
        drift means an unauthorised or unticketed change.

        Args:
            folder: SCM folder to check (must match the baseline's folder).
            tenant_id: SCM tenant ID (MSSP mode) for a single tenant.
            all_tenants: If True, sweep every configured tenant in a
                         background job — returns a job ID for scm_drift_result.
            update_baseline: If True, roll the baseline forward to the current
                             live state after checking — accept the changes as
                             the new known-good once they are explained.

        Returns:
            Drift digest (single tenant, ~2 min) or a job ID (all tenants).
        """
        try:
            return _drift_run("check", folder, tenant_id, all_tenants, update_baseline)
        except Exception as exc:
            return f"Error: {handle_scm_exception(exc, tool='scm_drift_check')}"

    @mcp.tool()
    def scm_drift_result(job_id: str) -> str:
        """Retrieve the digest of an all-tenants drift sweep.

        Args:
            job_id: Job ID returned by scm_drift_baseline / scm_drift_check
                    with all_tenants=True (jobs are kept for 1 hour).

        Returns:
            The capture summary or drift digest, or a status message if the
            sweep is still running.
        """
        with _JOBS_LOCK:
            job = dict(_DRIFT_JOBS.get(job_id, {}))
        if not job:
            active = list(_DRIFT_JOBS.keys())
            hint = f"  Active jobs: {active}" if active else "  No active jobs."
            return f"Drift job `{job_id}` not found (expires after 1 hour).\n{hint}"
        elapsed = int(time.time() - job["started_at"])
        mins, secs = divmod(elapsed, 60)
        if job["status"] == "running":
            return f"Drift job `{job_id}` still running ({mins}m {secs}s). Check again shortly."
        if job["status"] == "error":
            return f"Drift job `{job_id}` failed after {mins}m {secs}s: {job['error']}"
        return str(job["result"])

    # ── Commit Preview (blast-radius gate) ───────────────────────────────────

    @mcp.tool()
    @tool
    def scm_commit_preview(client: Any, tenant_id: str, folder: str = "Prisma Access") -> str:
        """Analyse the blast radius of pending changes BEFORE committing.

        Run this instead of going straight to scm_commit. It extracts the
        current candidate config and compares it against the drift baseline
        (last known-good, captured by scm_drift_baseline), then reports:

          1. Pending changes — every object the commit would add, remove, or
             modify, triaged HIGH/MEDIUM/LOW by enforcement impact.
          2. Rule shadowing — new or changed security rules that an earlier
             rule fully covers (they can never match), or that themselves
             shadow existing rules. Pre-rulebase and post-rulebase are checked
             together in Panorama's pre-then-post evaluation order, so a
             pre-rule shadowing a later post-rule is caught too. Source/
             destination use real CIDR containment with address-group
             membership resolved recursively; FQDN/wildcard addresses,
             dynamic groups, and EDLs fall back to a conservative
             literal-value check rather than risk a false claim.
          3. Best-practice delta — BPA findings this change introduces or
             resolves, by running the check engine against both states.

        Verdict: 🔴 HIGH RISK (shadowing, new critical/high BPA findings, or
        removals/modifications in enforcement sections) / 🟡 REVIEW / 🟢 LOW
        RISK / no-op. After an approved commit, run
        scm_drift_check(update_baseline=True) so the next preview diffs
        against the newly approved state.

        Requires a drift baseline for the tenant+folder — capture one with
        scm_drift_baseline after each approved change window.

        Args:
            folder: SCM folder the pending commit targets.
            tenant_id: SCM tenant ID (MSSP mode).

        Returns:
            Markdown blast-radius report with verdict and next steps
            (~2 min: one fresh candidate extraction).
        """
        tsg = tenant_id or "default"
        loaded = load_baseline(tsg, folder, _DEFAULT_BASELINE_DIR)
        if loaded is None:
            return (
                f"No drift baseline for tenant `{tsg}`, folder `{folder}` — the preview "
                "needs a last-known-good reference. Run "
                f'`scm_drift_baseline(folder="{folder}", tenant_id="{tenant_id}")` '
                "at a point where config is approved, then retry."
            )
        baseline, saved_at = loaded
        candidate = extract_snapshot(client, folder, tsg, fresh=True)

        diffs = check_drift(baseline, candidate)

        # Shadow analysis focused on the rules this commit touches. Pre-rulebase
        # and post-rulebase are checked together, pre before post, matching
        # Panorama's evaluation order — a pre-rule can shadow a later post-rule,
        # which checking each rulebase separately would miss.
        #
        # Focus entries are (rulebase, name) tuples, not bare names: a rule
        # name isn't guaranteed unique across the pre- and post-rulebase, so
        # a bare-name focus set could pull in an unrelated, pre-existing
        # shadow between two untouched same-named rules in the *other*
        # rulebase just because a touched rule elsewhere happens to share
        # that name — defeating the point of focusing at all.
        _position_by_field = {
            "security_rules_pre": "pre",
            "security_rules_post": "post",
        }
        focus: set[str | tuple[str, str]] = set()
        for d in diffs:
            pos = _position_by_field.get(d.fieldname)
            if pos is not None:
                focus |= {(pos, n) for n in (set(d.added) | set(d.changed))}
        shadows = (
            find_shadowed_rules(
                candidate.security_rules_pre + candidate.security_rules_post,
                focus,
                addresses=candidate.addresses,
                address_groups=candidate.address_groups,
            )
            if focus
            else []
        )

        introduced, resolved = bpa_delta(run_all_checks(baseline), run_all_checks(candidate))

        report = render_commit_preview(
            diffs,
            shadows,
            introduced,
            resolved,
            tenant_label=tsg,
            folder=folder,
            baseline_saved_at=saved_at,
            generated_at=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        )
        logger.info(
            "commit_preview_complete",
            tenant_id=tsg,
            folder=folder,
            drifted=len(diffs),
            shadows=len(shadows),
            introduced=len(introduced),
        )
        return report

    # ── Rule Shadow Audit (standalone, whole rulebase) ─────────────────────────

    @mcp.tool()
    @tool
    def scm_rule_shadow_audit(client: Any, tenant_id: str, folder: str = "Prisma Access") -> str:
        """Audit the entire live rulebase for shadowed security rules — no
        baseline or pending commit required (unlike scm_commit_preview, which
        only checks rules the pending change touches).

        Tufin/Skybox-style rule-order analysis: for every enabled security rule,
        checks whether an earlier-evaluated rule already fully covers its
        source/destination/zones/application/service, meaning the later rule
        can never match any traffic. Source/destination are compared by real
        CIDR containment (not literal string equality) with address-group
        membership resolved recursively — "10.0.0.0/8 in rule 3" correctly
        shadows "10.1.2.0/24 in rule 47" even though the values differ.

        Pre-rulebase and post-rulebase are checked together in Panorama's
        pre-then-post evaluation order, so a pre-rule shadowing a later
        post-rule is caught too, not just shadows within the same rulebase.

        Args:
            folder: SCM folder to audit (also pulls in Remote Networks and
                Mobile Users rules, matching how the rulebase is actually
                evaluated — same multi-folder merge scm_commit_preview uses).
            tenant_id: SCM tenant ID (MSSP mode).

        Returns:
            Markdown report: shadowed-rule list with rulebase position, top
            offending rules ranked by how many others they shadow, and a
            caveats section disclosing any addresses that couldn't be
            resolved to concrete IP ranges (~1-2 min: one full extraction).
        """
        tsg = tenant_id or "default"
        snap = extract_snapshot(client, folder, tsg)

        all_rules = snap.security_rules_pre + snap.security_rules_post
        enabled = [r for r in all_rules if not r.get("disabled")]
        # Keyed by rule_identity(), not bare name — a name can legitimately
        # repeat across the pre- and post-rulebase (or across the folders
        # merged into `all_rules`), and a bare-name key would let a later
        # rule's metadata silently overwrite an earlier same-named rule's,
        # misattributing folder/position/action in the rendered report.
        rule_meta = {
            rule_identity(r): {
                "folder": str(r.get("_folder", "?")),
                "position": str(r.get("_position", "?")),
                "action": str(r.get("action", "?")),
            }
            for r in all_rules
        }

        # Build the address/group resolution index once and reuse it for
        # both the shadow scan and the unresolved-names disclosure below —
        # find_shadowed_rules would otherwise redo the same recursive
        # resolution internally, doubling the cost of the slowest part of
        # this tool for no benefit.
        index = build_address_index(snap.addresses, snap.address_groups)
        shadows = find_shadowed_rules(all_rules, index=index)
        unresolved = unresolved_address_names(index)

        report = render_shadow_audit(
            shadows,
            rule_meta,
            total_rules=len(enabled),
            unresolved=unresolved,
            tenant_label=tsg,
            folder=folder,
            generated_at=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        )
        logger.info(
            "rule_shadow_audit_complete",
            tenant_id=tsg,
            folder=folder,
            total_rules=len(enabled),
            shadows=len(shadows),
        )
        return report

    # ── Incident Root-Cause Correlation ───────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_incident_rca(
        client: Any,
        tenant_id: str,
        incident_time: str = "",
        symptom: str = "",
        lookback_hours: int = 24,
        folder: str = "Prisma Access",
        include_drift: bool = True,
    ) -> str:
        """Correlate an incident with config pushes, expiries, and drift.

        Given an incident time (default: now), walks the evidence this server
        can reach and ranks candidate causes by temporal proximity:

          - Config pushes/commits (job history: who, what, result — failed
            jobs rank ahead of successful ones at equal distance)
          - Certificate expiries falling inside the window
          - Licence expiries falling inside the window
          - Config drift vs the drift baseline — presented separately as
            state evidence, since extraction shows *what* differs, not *when*

        Output ends with a customer-facing RFO draft citing the top candidate
        and an explicit correlation-not-causation caveat, plus a list of
        evidence sources this run could not check.

        Args:
            incident_time: Incident timestamp, UTC — "YYYY-MM-DD HH:MM" or
                           epoch seconds. Empty = now (investigating live).
            symptom: Short symptom description for the report and RFO draft
                     (e.g. "branch VPN tunnels down in region X").
            lookback_hours: Evidence window before the incident (default 24).
            folder: SCM folder for the drift comparison.
            tenant_id: SCM tenant ID (MSSP mode).
            include_drift: If False, skip the ~2-minute drift extraction and
                           correlate timestamped evidence only.

        Returns:
            Markdown RCA report: ranked candidate table, drift state
            evidence, RFO draft, and caveats.
        """
        tsg = tenant_id or "default"
        incident_dt = parse_any_ts(incident_time) or datetime.now(UTC)
        unchecked: list[str] = [
            "SD-WAN element/servicelink status (use scm_sdwan tools to correlate manually "
            "on SD-WAN tenants)",
            "Prisma Access Insights alerts (RBAC 403 on current service accounts)",
        ]

        jobs: list[dict[str, Any]] = []
        try:
            resp = client.list_jobs(limit=200, offset=0)
            for j in resp.data if hasattr(resp, "data") else []:
                parent = str(getattr(j, "parent_id", "") or "")
                if parent not in ("0", "", "None"):
                    continue  # child jobs duplicate their parent push
                jobs.append(
                    {
                        "job_id": str(getattr(j, "id", "")),
                        "type": str(getattr(j, "type_str", getattr(j, "job_type", ""))),
                        "result": str(getattr(j, "result_str", "")),
                        "user": str(getattr(j, "uname", "")),
                        "description": str(getattr(j, "description", "") or ""),
                        "start_ts": str(getattr(j, "start_ts", "")),
                        "end_ts": str(getattr(j, "end_ts", "")),
                    }
                )
        except Exception as exc:
            unchecked.append(f"config job history (list_jobs failed: {exc})")

        certs: list[dict[str, Any]] = []
        session = getattr(client, "session", None)
        if session is not None:
            seen: set[str] = set()
            for f in dict.fromkeys([folder, *_CERT_FOLDERS]):
                for c in _fetch_certs(session, f):
                    cid = str(c.get("id", c.get("name", "")))
                    if cid not in seen:
                        seen.add(cid)
                        certs.append(c)
        else:
            unchecked.append("certificate expiries (no HTTP session)")

        try:
            lic_rows = _licence_rows(fetch_licenses(client))
        except Exception as exc:
            lic_rows = []
            unchecked.append(f"licence expiries (fetch failed: {exc})")

        candidates = collect_candidates(incident_dt, lookback_hours, jobs, certs, lic_rows)

        drifted: list[Any] = []
        baseline_saved_at: str | None = None
        if include_drift:
            loaded = load_baseline(tsg, folder, _DEFAULT_BASELINE_DIR)
            if loaded is None:
                unchecked.append("config drift (no baseline — run scm_drift_baseline to enable)")
            else:
                baseline, baseline_saved_at = loaded
                live = extract_snapshot(client, folder, tsg, fresh=True)
                drifted = check_drift(baseline, live)
        else:
            unchecked.append("config drift (include_drift=False)")

        report = render_rca_report(
            incident_dt,
            symptom,
            lookback_hours,
            candidates,
            drifted,
            baseline_saved_at,
            unchecked,
            tenant_label=tsg,
            folder=folder,
            generated_at=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        )
        logger.info(
            "incident_rca_complete",
            tenant_id=tsg,
            candidates=len(candidates),
            drifted=len(drifted),
        )
        return report

    # ── Config Diff ───────────────────────────────────────────────────────────

    @mcp.tool()
    def scm_config_diff(
        backup_file_a: str,
        backup_file_b: str,
    ) -> str:
        """Compare two SCM config backup files and report differences.

        Useful for change auditing — run a backup before and after a change
        window to produce a structured diff of what was added, removed, or
        modified across all resource types.

        Args:
            backup_file_a: Path to the baseline backup JSON file.
            backup_file_b: Path to the comparison backup JSON file.

        Returns:
            JSON diff report showing added, removed, and changed resources.
        """
        try:
            data_a = json.loads(Path(backup_file_a).read_text())
            data_b = json.loads(Path(backup_file_b).read_text())

            res_a: dict[str, dict[str, Any]] = {}
            res_b: dict[str, dict[str, Any]] = {}

            for rtype, items in data_a.get("resources", {}).items():
                res_a[rtype] = {
                    i.get("name", i.get("id", str(idx))): i for idx, i in enumerate(items)
                }
            for rtype, items in data_b.get("resources", {}).items():
                res_b[rtype] = {
                    i.get("name", i.get("id", str(idx))): i for idx, i in enumerate(items)
                }

            diff: dict[str, Any] = {
                "baseline": {
                    "file": backup_file_a,
                    "generated_at": data_a.get("generated_at"),
                    "folder": data_a.get("folder"),
                },
                "comparison": {
                    "file": backup_file_b,
                    "generated_at": data_b.get("generated_at"),
                    "folder": data_b.get("folder"),
                },
                "changes": {},
            }

            all_rtypes = set(res_a) | set(res_b)
            total_added = total_removed = total_changed = 0

            for rtype in sorted(all_rtypes):
                a_names = set(res_a.get(rtype, {}).keys())
                b_names = set(res_b.get(rtype, {}).keys())
                added = sorted(b_names - a_names)
                removed = sorted(a_names - b_names)
                changed = sorted(
                    name for name in a_names & b_names if res_a[rtype][name] != res_b[rtype][name]
                )
                if added or removed or changed:
                    diff["changes"][rtype] = {
                        "added": added,
                        "removed": removed,
                        "modified": changed,
                    }
                    total_added += len(added)
                    total_removed += len(removed)
                    total_changed += len(changed)

            diff["summary"] = {
                "total_added": total_added,
                "total_removed": total_removed,
                "total_modified": total_changed,
                "resource_types_changed": len(diff["changes"]),
            }

            return json.dumps(diff, indent=2)
        except FileNotFoundError as exc:
            return f"Error: backup file not found — {exc}"
        except Exception as exc:
            return f"Error: {handle_scm_exception(exc)}"

    # ── Config Clone ──────────────────────────────────────────────────────

    @mcp.tool()
    def scm_config_clone(
        source_backup_file: str,
        target_folder: str,
        target_tenant_id: str = "",
        name_prefix: str = "",
        anonymise_ips: bool = False,
        include_deployment: bool = False,
        skip_rules: bool = False,
        on_conflict: str = "skip",
        dry_run: bool = True,
        save_to: str = "",
        ticket_ref: str = "",
    ) -> str:
        """Clone a SCM config backup into a new folder or tenant.

        Loads a JSON backup created by scm_config_backup, sanitises every
        object (strips system fields, rewrites the folder, scrubs PSKs), then
        pushes it to the target folder in dependency order:

          Tags → Addresses → Groups → Security profiles → Log profiles →
          Zones → Rules (pre, post, NAT, decryption) → Deployment (optional)

        Beyond the policy layer, the cloner also restores GlobalProtect and
        identity configuration from the backup: auth settings, tunnel
        profiles, agent profiles, forwarding profiles and portal/gateway
        infrastructure settings (into the fixed 'Mobile Users' folder), plus
        SAML/Radius/LDAP auth profiles (customer folder).  With
        include_deployment it additionally clones network infrastructure —
        IKE/IPSec crypto profiles, QoS profiles, internal DNS servers and
        bandwidth allocations (fixed 'Remote Networks' folder).

        Typical use-cases
        -----------------
        - MSSP golden-config template → new customer tenant (speed up onboarding)
        - MSSP takeover migration → move config from old MSSP to new tenant
        - POV → Prod promotion (clone lab folder to production folder)
        - Multi-site rollout (one branch config → N sites with same structure)

        PAN predefined content (objects sourced from a predefined snippet —
        the PAN EDLs, default services and default security profiles) is
        listed in the report and never pushed: it already exists in every
        tenant and cannot be created inside a folder.

        PSK safety
        ----------
        Pre-shared keys in IKE gateways are ALWAYS replaced with
        CHANGEME_<gateway-name>. The report lists every gateway that needs
        a real PSK set before committing.

        Args:
            source_backup_file: Path to a JSON backup from scm_config_backup.
            target_folder: Destination SCM folder name.
            target_tenant_id: Destination tenant (empty = same tenant as server default).
            name_prefix: Prefix prepended to every object name (e.g. "CUST1_").
                         Useful when cloning into a shared folder.
            anonymise_ips: Replace all IPv4 literals with {{IP_N}} template
                           variables. Use when sharing configs as templates.
            include_deployment: Also clone IKE gateways, IPSec tunnels,
                                Remote Networks, and Service Connections.
                                These go into fixed SCM folders (Remote Networks,
                                Service Connections) regardless of target_folder.
            skip_rules: Omit all security, NAT, decryption, and app-override
                        rules. Useful when cloning only the object library.
            on_conflict: What to do if an object with the same name already
                         exists in the target — 'skip' (default) or 'overwrite'.
            dry_run: If True (default), preview what would be created without
                     making any API calls. Set to False to execute the push.
            save_to: Optional file path to write the clone report.
            ticket_ref: Mandatory change-ticket reference (never sent to SCM).

        **Write safety (SSR pattern):** ``dry_run=True`` by default;
        ``ticket_ref`` is mandatory.

        Returns:
            Markdown clone report showing per-object status and PSK warnings.
        """
        err = ticket_ref_error(ticket_ref)
        if err:
            return f"Error: {err}"
        ticket_ref = normalize_ticket_ref(ticket_ref)

        try:
            client = get_client(target_tenant_id)
            if not dry_run:
                audit_write(
                    "scm_config_clone",
                    ticket_ref,
                    target_tenant_id,
                    source_backup_file=source_backup_file,
                    target_folder=target_folder,
                )
            report = clone_config(
                client,
                source_backup_file=source_backup_file,
                target_folder=target_folder,
                name_prefix=name_prefix,
                anonymise_ips=anonymise_ips,
                include_deployment=include_deployment,
                skip_rules=skip_rules,
                on_conflict=on_conflict,
                dry_run=dry_run,
            )
            report.target_tenant_id = target_tenant_id

            md = report.to_markdown()

            if save_to:
                Path(save_to).write_text(md)
                logger.info("clone_report_saved", path=save_to, target_folder=target_folder)
                return f"Clone report saved to: {save_to}\n\n{md}"

            return md
        except FileNotFoundError as exc:
            return f"Error: backup file not found — {exc}"
        except Exception as exc:
            return f"Error: {handle_scm_exception(exc)}"
