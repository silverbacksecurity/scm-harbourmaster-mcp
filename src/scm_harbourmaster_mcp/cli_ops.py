"""
Rich-free core logic for the CLI's report/backup operations.

Each `run_*` function here does the actual work (connect, extract, check,
build, write to disk) and returns a small result object. It's called both by
the interactive Rich menu handlers in cli.py (which gather input via prompts,
then render the result as tables/panels) and by the non-interactive
subcommands in cli_commands.py (which parse args and print plain lines) —
so the extraction/report-generation logic exists in exactly one place.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .audit.models import Finding
    from .config.settings import TenantConfig

# Framework code -> display label, shared between the interactive picker
# (cli.py) and the --framework argparse choices (cli_commands.py).
NCSC_FRAMEWORK_LABELS: dict[str, str] = {
    "all": "All Frameworks",
    "caf": "CAF v4.0",
    "ce": "Cyber Essentials v3.2",
    "10steps": "10 Steps",
}

OnProgress = Callable[[str], None] | None


def _progress(on_progress: OnProgress, message: str) -> None:
    if on_progress:
        on_progress(message)


def _timestamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


# ── backup ────────────────────────────────────────────────────────────────


@dataclass
class BackupResult:
    path: Path
    size_kb: int
    prisma_counts: dict[str, int]
    sdwan_counts: dict[str, int] | None
    sdwan_error: str | None
    extraction_errors: list[str]


def run_backup(tenant: TenantConfig, on_progress: OnProgress = None) -> BackupResult:
    from .audit.extractor import extract_sdwan_snapshot, extract_snapshot
    from .auth.oauth import get_scm_client
    from .auth.sdwan import get_sdwan_client

    client = get_scm_client(tenant)

    _progress(on_progress, "Extracting Prisma Access config...")
    snap = extract_snapshot(client, "All", tenant.tenant_id)
    prisma_counts = {
        "addresses": len(snap.addresses),
        "rules": len(snap.security_rules_pre) + len(snap.security_rules_post),
        "nat": len(snap.nat_rules),
        "remote_networks": len(snap.remote_networks),
        "svc_conn": len(snap.service_connections),
    }
    _progress(
        on_progress,
        "✓ Prisma Access: " + ", ".join(f"{k}={v}" for k, v in prisma_counts.items()),
    )

    sdwan_counts: dict[str, int] | None = None
    sdwan_error: str | None = None
    _progress(on_progress, "Connecting SD-WAN...")
    try:
        sdwan = get_sdwan_client(tenant)
        extract_sdwan_snapshot(sdwan, snap)
        sdwan_counts = {
            "sites": len(snap.sdwan_sites),
            "elements": len(snap.sdwan_elements),
            "wan_networks": len(snap.sdwan_wan_networks),
            "path_groups": len(snap.sdwan_path_groups),
        }
        _progress(
            on_progress, "✓ SD-WAN: " + ", ".join(f"{k}={v}" for k, v in sdwan_counts.items())
        )
    except Exception as exc:
        sdwan_error = str(exc)
        _progress(on_progress, f"⚠ SD-WAN unavailable: {sdwan_error}")

    backup_dir = Path("backups")
    backup_dir.mkdir(exist_ok=True)
    out = backup_dir / f"scm_backup_{tenant.tenant_id}_{_timestamp()}.json"
    payload = {
        "backup_version": "1",
        "generated_at": datetime.now(UTC).isoformat(),
        "tenant_id": tenant.tenant_id,
        "label": tenant.label,
        "folder": "All",
        "resources": {
            "addresses": snap.addresses,
            "address_groups": snap.address_groups,
            "services": snap.services,
            "service_groups": snap.service_groups,
            "tags": snap.tags,
            "edls": snap.edls,
            "applications": snap.applications,
            "application_groups": snap.application_groups,
            "hip_objects": snap.hip_objects,
            "hip_profiles": snap.hip_profiles,
            "anti_spyware_profiles": snap.anti_spyware_profiles,
            "vulnerability_profiles": snap.vulnerability_profiles,
            "url_categories": snap.url_categories,
            "wildfire_profiles": snap.wildfire_profiles,
            "dns_security_profiles": snap.dns_security_profiles,
            "decryption_profiles": snap.decryption_profiles,
            "file_blocking_profiles": snap.file_blocking_profiles,
            "log_forwarding_profiles": snap.log_forwarding_profiles,
            "syslog_profiles": snap.syslog_profiles,
            "security_rules_pre": snap.security_rules_pre,
            "security_rules_post": snap.security_rules_post,
            "nat_rules": snap.nat_rules,
            "decryption_rules": snap.decryption_rules,
            "app_override_rules": snap.app_override_rules,
            "zones": snap.zones,
            "ike_gateways": snap.ike_gateways,
            "ipsec_tunnels": snap.ipsec_tunnels,
            "zone_protection_profiles": snap.zone_protection_profiles,
            "remote_networks": snap.remote_networks,
            "service_connections": snap.service_connections,
            "sdwan_sites": snap.sdwan_sites,
            "sdwan_elements": snap.sdwan_elements,
            "sdwan_wan_networks": snap.sdwan_wan_networks,
            "sdwan_path_groups": snap.sdwan_path_groups,
        },
        "extraction_errors": snap.extraction_errors,
    }
    out.write_text(json.dumps(payload, indent=2, default=str))

    return BackupResult(
        path=out,
        size_kb=out.stat().st_size // 1024,
        prisma_counts=prisma_counts,
        sdwan_counts=sdwan_counts,
        sdwan_error=sdwan_error,
        extraction_errors=list(snap.extraction_errors),
    )


# ── BPA ───────────────────────────────────────────────────────────────────


@dataclass
class BpaResult:
    path: Path
    folder: str
    findings: list[Finding]
    counts: dict[str, int]


def run_bpa(tenant: TenantConfig, on_progress: OnProgress = None) -> BpaResult:
    from collections import Counter

    from .audit.bpa_checks import run_all_checks
    from .audit.extractor import extract_snapshot
    from .auth.oauth import get_scm_client

    client = get_scm_client(tenant)
    folder = tenant.default_folder or "All"

    _progress(on_progress, f"Extracting config from {folder}...")
    snap = extract_snapshot(client, folder, tenant.tenant_id)

    _progress(on_progress, "Running BPA checks...")
    findings = run_all_checks(snap)
    counts = dict(Counter(f.status.value for f in findings))

    backup_dir = Path("backups")
    backup_dir.mkdir(exist_ok=True)
    ts = _timestamp()
    out = backup_dir / f"bpa_{tenant.tenant_id}_{ts}.json"
    out.write_text(
        json.dumps(
            {
                "tenant_id": tenant.tenant_id,
                "label": tenant.label,
                "folder": folder,
                "timestamp": ts,
                "summary": counts,
                "findings": [f.to_dict() for f in findings],
            },
            indent=2,
        )
    )

    return BpaResult(path=out, folder=folder, findings=findings, counts=counts)


# ── NCSC ──────────────────────────────────────────────────────────────────


@dataclass
class NcscResult:
    path: Path
    framework: str
    folder: str
    controls: list[dict[str, Any]]
    total: int
    compliant: int
    non_compliant: int
    not_assessed: int


def run_ncsc(tenant: TenantConfig, framework: str, on_progress: OnProgress = None) -> NcscResult:
    from .audit.bpa_checks import run_all_checks
    from .audit.extractor import extract_snapshot
    from .audit.ncsc_controls import NCSC_CONTROLS
    from .auth.oauth import get_scm_client

    client = get_scm_client(tenant)
    folder = tenant.default_folder or "All"

    _progress(on_progress, f"Extracting config from {folder}...")
    snap = extract_snapshot(client, folder, tenant.tenant_id)

    _progress(on_progress, "Running BPA + NCSC mapping...")
    findings = run_all_checks(snap)

    framework_filter = {
        "caf": "CAF v4.0",
        "ce": "CE v3.2",
        "10steps": "10 Steps",
        "nsf": "NSF",
    }.get(framework, "")

    ctrl_status: dict[str, list[dict[str, Any]]] = {k: [] for k in NCSC_CONTROLS}
    for f in findings:
        for ref in f.ncsc_refs:
            if ref in ctrl_status:
                ctrl_status[ref].append(f.to_dict())

    controls_output: list[dict[str, Any]] = []
    for ctrl_id, ctrl in NCSC_CONTROLS.items():
        if framework_filter and ctrl.source != framework_filter:
            continue
        related = ctrl_status[ctrl_id]
        has_fail = any(r["status"] in ("fail", "warn") for r in related)
        has_pass = any(r["status"] == "pass" for r in related)
        compliance = "non-compliant" if has_fail else ("compliant" if has_pass else "not-assessed")
        controls_output.append(
            {
                "control_id": ctrl_id,
                "title": ctrl.title,
                "source": ctrl.source,
                "objective": ctrl.objective,
                "compliance_status": compliance,
                "related_findings": [
                    {"check_id": r["check_id"], "status": r["status"], "title": r["title"]}
                    for r in related
                ],
            }
        )

    compliant = sum(1 for c in controls_output if c["compliance_status"] == "compliant")
    non_compliant = sum(1 for c in controls_output if c["compliance_status"] == "non-compliant")
    not_assessed = sum(1 for c in controls_output if c["compliance_status"] == "not-assessed")
    total = len(controls_output)

    backup_dir = Path("backups")
    backup_dir.mkdir(exist_ok=True)
    ts = _timestamp()
    out = backup_dir / f"ncsc_{tenant.tenant_id}_{framework}_{ts}.json"
    out.write_text(
        json.dumps(
            {
                "tenant_id": tenant.tenant_id,
                "label": tenant.label,
                "folder": folder,
                "framework": framework,
                "timestamp": ts,
                "summary": {
                    "total": total,
                    "compliant": compliant,
                    "non_compliant": non_compliant,
                    "not_assessed": not_assessed,
                },
                "controls": controls_output,
            },
            indent=2,
        )
    )

    return NcscResult(
        path=out,
        framework=framework,
        folder=folder,
        controls=controls_output,
        total=total,
        compliant=compliant,
        non_compliant=non_compliant,
        not_assessed=not_assessed,
    )


# ── AS-BUILT ──────────────────────────────────────────────────────────────


@dataclass
class AsbuiltResult:
    path: Path
    output_format: str
    size_kb: int
    sdwan_summary: str | None = None
    sdwan_error: str | None = None
    job_fetch_error: str | None = None
    docx_error: str | None = None
    extraction_errors: list[str] = field(default_factory=list)


def run_asbuilt(
    tenant: TenantConfig,
    *,
    inc_prisma: bool = True,
    inc_sdwan: bool = True,
    inc_ngfw: bool = True,
    output_format: str = "markdown",
    customer_name: str | None = None,
    mssp_name: str = "MSSP",
    doc_version: str = "1.0",
    on_progress: OnProgress = None,
) -> AsbuiltResult:
    from .audit.asbuilt_report import AsBuiltReportBuilder
    from .audit.extractor import (
        extract_airs,
        extract_allocated_ips,
        extract_browser,
        extract_casb_dlp,
        extract_cdl,
        extract_enterprise_dlp,
        extract_licenses,
        extract_ngfw_devices,
        extract_sdwan_snapshot,
        extract_snapshot,
        extract_ztna_connectors,
    )
    from .auth.oauth import get_scm_client
    from .auth.sdwan import get_sdwan_client

    customer_name = customer_name or tenant.label

    if inc_prisma and inc_ngfw:
        folder = "All"
    elif inc_ngfw:
        folder = "ngfw-shared"
    elif inc_prisma:
        folder = "Prisma Access"
    else:
        folder = tenant.default_folder or "All"

    client = get_scm_client(tenant)

    _progress(on_progress, f"Extracting config from {folder}...")
    snap = extract_snapshot(client, folder, tenant.tenant_id)
    extract_licenses(client, snap)
    extract_allocated_ips(client, snap)

    _progress(on_progress, "Extracting CASB/DLP, ZTNA, Browser, CDL, NGFW, AIRS, Enterprise DLP...")
    extract_casb_dlp(client, snap, folder=folder)
    extract_ztna_connectors(client, snap)
    extract_browser(client, snap)
    extract_cdl(client, snap)
    extract_ngfw_devices(client, snap)
    extract_airs(client, snap)
    extract_enterprise_dlp(client, snap)

    sdwan_summary: str | None = None
    sdwan_error: str | None = None
    if inc_sdwan:
        _progress(on_progress, "Connecting SD-WAN...")
        try:
            sdwan = get_sdwan_client(tenant)
            extract_sdwan_snapshot(sdwan, snap)
            sdwan_summary = f"sites={len(snap.sdwan_sites)}, elements={len(snap.sdwan_elements)}"
            _progress(on_progress, f"✓ SD-WAN: {sdwan_summary}")
        except Exception as exc:
            sdwan_error = str(exc)
            _progress(on_progress, f"⚠ SD-WAN unavailable: {sdwan_error}")

    jobs: list[dict[str, Any]] = []
    job_fetch_error: str | None = None
    try:
        job_resp = client.list_jobs(limit=200, offset=0)
        all_jobs = job_resp.data if hasattr(job_resp, "data") else []
        for j in all_jobs:
            parent = str(getattr(j, "parent_id", "") or "")
            if parent not in ("0", "", "None"):
                continue
            jobs.append(
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
    except Exception as exc:
        job_fetch_error = str(exc)
        _progress(on_progress, f"⚠ Could not fetch job history: {job_fetch_error}")

    _progress(on_progress, "Building AS-BUILT document...")
    builder = AsBuiltReportBuilder(
        snap,
        customer_name=customer_name,
        mssp_name=mssp_name,
        doc_version=doc_version,
        jobs=jobs,
    )
    report_md = builder.to_markdown()

    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    ts = _timestamp()
    safe_customer = customer_name.replace(" ", "-").replace("/", "-")

    docx_error: str | None = None
    if output_format == "docx":
        out = reports_dir / f"{safe_customer}-asbuilt-{ts}.docx"
        _progress(on_progress, "Converting to DOCX (pandoc)...")
        from .tools.audit import _md_to_docx

        result = _md_to_docx(report_md, out)
        if out.exists():
            actual_format = "docx"
            actual_path = out
        else:
            docx_error = str(result)
            _progress(on_progress, f"⚠ DOCX conversion failed: {docx_error}")
            md_out = reports_dir / f"{safe_customer}-asbuilt-{ts}.md"
            md_out.write_text(report_md)
            actual_format = "markdown"
            actual_path = md_out
    else:
        actual_path = reports_dir / f"{safe_customer}-asbuilt-{ts}.md"
        actual_path.write_text(report_md)
        actual_format = "markdown"

    return AsbuiltResult(
        path=actual_path,
        output_format=actual_format,
        size_kb=actual_path.stat().st_size // 1024,
        sdwan_summary=sdwan_summary,
        sdwan_error=sdwan_error,
        job_fetch_error=job_fetch_error,
        docx_error=docx_error,
        extraction_errors=list(snap.extraction_errors),
    )


# ── audit report ─────────────────────────────────────────────────────────


@dataclass
class AuditReportResult:
    path: Path
    size_kb: int
    counts: dict[str, int]


def run_audit_report(
    tenant: TenantConfig, output_format: str = "markdown", on_progress: OnProgress = None
) -> AuditReportResult:
    from collections import Counter

    from .audit.bpa_checks import run_all_checks
    from .audit.extractor import extract_snapshot
    from .audit.report import ReportBuilder
    from .auth.oauth import get_scm_client

    client = get_scm_client(tenant)
    folder = tenant.default_folder or "All"

    _progress(on_progress, f"Extracting config from {folder}...")
    snap = extract_snapshot(client, folder, tenant.tenant_id)

    _progress(on_progress, "Running BPA checks...")
    findings = run_all_checks(snap)

    _progress(on_progress, "Building report...")
    builder = ReportBuilder(snap, findings)
    ext = "json" if output_format == "json" else "md"
    report = builder.to_json() if output_format == "json" else builder.to_markdown()
    counts = dict(Counter(f.status.value for f in findings))

    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    out = reports_dir / f"audit_{tenant.tenant_id}_{_timestamp()}.{ext}"
    out.write_text(report)

    return AuditReportResult(path=out, size_kb=out.stat().st_size // 1024, counts=counts)
