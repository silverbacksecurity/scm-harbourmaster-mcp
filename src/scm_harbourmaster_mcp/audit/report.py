"""
Audit report builder.

Produces:
  - Structured JSON (machine-readable, suitable for SIEM ingestion)
  - Markdown (human-readable AS-BUILT / BPA / NCSC compliance report)
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from .models import AuditSnapshot, Finding, Severity, Status
from .ncsc_controls import NCSC_CONTROLS


class ReportBuilder:
    """Build audit reports from a snapshot and its findings."""

    def __init__(self, snap: AuditSnapshot, findings: list[Finding]) -> None:
        self.snap = snap
        self.findings = findings
        self.generated_at = datetime.now(UTC).isoformat()

    # ── Summary stats ─────────────────────────────────────────────────────────

    def _summary(self) -> dict[str, Any]:
        status_counts = Counter(f.status.value for f in self.findings)
        sev_counts = Counter(f.severity.value for f in self.findings if f.status == Status.FAIL)
        all_ncsc: list[str] = []
        for f in self.findings:
            if f.status == Status.FAIL:
                all_ncsc.extend(f.ncsc_refs)
        return {
            "total_checks": len(self.findings),
            "passed": status_counts.get("pass", 0),
            "failed": status_counts.get("fail", 0),
            "warnings": status_counts.get("warn", 0),
            "skipped": status_counts.get("skip", 0),
            "failures_by_severity": dict(sev_counts),
            "ncsc_controls_breached": sorted(set(all_ncsc)),
        }

    # ── JSON output ───────────────────────────────────────────────────────────

    def to_json(self) -> str:
        return json.dumps(
            {
                "report_type": "SCM BPA + NCSC Compliance Assessment",
                "generated_at": self.generated_at,
                "scope": {
                    "folder": self.snap.folder,
                    "tenant_id": self.snap.tenant_id,
                },
                "summary": self._summary(),
                "findings": [f.to_dict() for f in self.findings],
                "extraction_errors": self.snap.extraction_errors,
                "ncsc_control_catalogue": {
                    k: {
                        "title": v.title,
                        "source": v.source,
                        "objective": v.objective,
                        "description": v.description,
                    }
                    for k, v in NCSC_CONTROLS.items()
                },
            },
            indent=2,
        )

    # ── Markdown output ───────────────────────────────────────────────────────

    def to_markdown(self) -> str:
        s = self._summary()
        snap = self.snap
        lines: list[str] = []

        def h(level: int, text: str) -> None:
            lines.append(f"{'#' * level} {text}\n")

        def line(text: str = "") -> None:
            lines.append(text)

        # ── Header ────────────────────────────────────────────────────────────
        h(1, "SCM Configuration Assessment Report")
        line(f"**Generated:** {self.generated_at}")
        line(f"**Scope:** Folder `{snap.folder}` | Tenant `{snap.tenant_id}`")
        line(
            "**Framework:** PAN Best Practice Assessment + NCSC CAF v4.0 / Cyber Essentials v3.2 / 10 Steps"
        )
        line()

        # ── Executive Summary ─────────────────────────────────────────────────
        h(2, "Executive Summary")
        line("| Metric | Count |")
        line("|--------|-------|")
        line(f"| Total checks | {s['total_checks']} |")
        line(f"| Passed | {s['passed']} |")
        line(f"| **Failed** | **{s['failed']}** |")
        line(f"| Warnings | {s['warnings']} |")
        line(f"| Skipped (no data) | {s['skipped']} |")
        line()

        sev = s["failures_by_severity"]
        if sev:
            h(3, "Failures by Severity")
            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
                count = sev.get(severity.value, 0)
                if count:
                    icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(
                        severity.value, "⚪"
                    )
                    line(f"- {icon} **{severity.value.upper()}**: {count} failure(s)")
            line()

        if s["ncsc_controls_breached"]:
            h(3, "NCSC Controls with Failures")
            for ctrl_id in s["ncsc_controls_breached"]:
                ctrl = NCSC_CONTROLS.get(ctrl_id)
                if ctrl:
                    line(f"- **{ctrl_id}** ({ctrl.source}): {ctrl.title}")
                else:
                    line(f"- **{ctrl_id}**")
            line()

        # ── Config Inventory ──────────────────────────────────────────────────
        h(2, "AS-IS Configuration Inventory")
        line("| Resource | Count |")
        line("|----------|-------|")
        inventory = [
            ("Security rules (pre)", len(snap.security_rules_pre)),
            ("Security rules (post)", len(snap.security_rules_post)),
            ("Address objects", len(snap.addresses)),
            ("Address groups", len(snap.address_groups)),
            ("Service objects", len(snap.services)),
            ("Tags", len(snap.tags)),
            ("External dynamic lists", len(snap.edls)),
            ("Applications", len(snap.applications)),
            ("HIP objects", len(snap.hip_objects)),
            ("Anti-spyware profiles", len(snap.anti_spyware_profiles)),
            ("Vulnerability profiles", len(snap.vulnerability_profiles)),
            ("WildFire profiles", len(snap.wildfire_profiles)),
            ("DNS security profiles", len(snap.dns_security_profiles)),
            ("Decryption profiles", len(snap.decryption_profiles)),
            ("File blocking profiles", len(snap.file_blocking_profiles)),
            ("URL categories", len(snap.url_categories)),
            ("Log forwarding profiles", len(snap.log_forwarding_profiles)),
            ("Syslog profiles", len(snap.syslog_profiles)),
            ("NAT rules", len(snap.nat_rules)),
            ("Decryption rules", len(snap.decryption_rules)),
            ("Security zones", len(snap.zones)),
            ("IKE gateways", len(snap.ike_gateways)),
            ("IPSec tunnels", len(snap.ipsec_tunnels)),
            ("Remote networks", len(snap.remote_networks)),
            ("Service connections", len(snap.service_connections)),
        ]
        for label, count in inventory:
            line(f"| {label} | {count} |")
        line()

        # ── Findings ─────────────────────────────────────────────────────────
        h(2, "Audit Findings")

        sev_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for sev in sev_order:
            sev_findings = [
                f
                for f in self.findings
                if f.severity == sev and f.status in (Status.FAIL, Status.WARN)
            ]
            if not sev_findings:
                continue
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(
                sev.value, "⚪"
            )
            h(3, f"{icon} {sev.value.upper()} ({len(sev_findings)})")
            for f in sev_findings:
                status_badge = "**FAIL**" if f.status == Status.FAIL else "*WARN*"
                h(4, f"[{f.check_id}] {f.title} — {status_badge}")
                line(f"**Description:** {f.description}")
                line()
                if f.affected_objects:
                    line(
                        f"**Affected objects:** `{'`, `'.join(f.affected_objects[:10])}`"
                        + (
                            f" _(and {len(f.affected_objects) - 10} more)_"
                            if len(f.affected_objects) > 10
                            else ""
                        )
                    )
                    line()
                line(f"**Remediation:** {f.remediation}")
                line()
                refs = []
                if f.pan_bpa_ref:
                    refs.append(f"PAN BPA: `{f.pan_bpa_ref}`")
                if f.ncsc_refs:
                    refs.append("NCSC: " + ", ".join(f"`{r}`" for r in f.ncsc_refs))
                if refs:
                    line(f"**References:** {' | '.join(refs)}")
                line()
                line("---")
                line()

        # ── Passed checks ─────────────────────────────────────────────────────
        passed = [f for f in self.findings if f.status == Status.PASS]
        if passed:
            h(2, "Passed Checks")
            for f in passed:
                line(f"- ✅ `{f.check_id}` {f.title}")
            line()

        # ── Skipped checks ────────────────────────────────────────────────────
        skipped = [f for f in self.findings if f.status == Status.SKIP]
        if skipped:
            h(2, "Skipped Checks (insufficient data)")
            for f in skipped:
                line(f"- ⏭ `{f.check_id}` {f.title}: _{f.description}_")
            line()

        # ── Extraction errors ─────────────────────────────────────────────────
        if snap.extraction_errors:
            h(2, "Data Extraction Errors")
            line(
                "The following resources could not be retrieved (SDK errors or missing permissions):"
            )
            line()
            for err in snap.extraction_errors:
                line(f"- `{err}`")
            line()

        # ── NCSC control index ────────────────────────────────────────────────
        h(2, "NCSC Control Reference")
        breached = set(s["ncsc_controls_breached"])
        for ctrl_id, ctrl in NCSC_CONTROLS.items():
            status_icon = "❌" if ctrl_id in breached else "✅"
            line(f"**{status_icon} {ctrl_id}** — {ctrl.title} _{ctrl.source}_")
            line(f"> {ctrl.description}")
            line()

        return "\n".join(lines)
