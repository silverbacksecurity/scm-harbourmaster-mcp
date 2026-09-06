"""
Doc-vs-live verification for AS-BUILT reports.

An AS-BUILT is a point-in-time rendering of an AuditSnapshot. Config can
change between extraction and the moment the customer reads the document
(or the extraction itself may have been partial). This module diffs the
snapshot a document was built from against a freshly extracted snapshot
of the same tenant/folder and reports, per document section, whether the
document still matches the live API.

Pure functions only — no SCM client or MCP imports — so the diff engine
is unit-testable with hand-built snapshots.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .models import AuditSnapshot

# Snapshot fields covered by the core extract_snapshot() fan-out, mapped to
# the AS-BUILT section they populate. Fields empty in both snapshots are
# skipped at diff time, so listing a field a tenant doesn't use is harmless.
VERIFIED_SECTIONS: list[tuple[str, str]] = [
    ("remote_networks", "Prisma Access Infrastructure — Remote Networks"),
    ("service_connections", "Prisma Access Infrastructure — Service Connections"),
    ("ike_gateways", "Remote Networks — IKE Gateways"),
    ("ipsec_tunnels", "Remote Networks — IPSec Tunnels"),
    ("ike_crypto_profiles", "Appendices — IKE Crypto Profiles"),
    ("ipsec_crypto_profiles", "Appendices — IPSec Crypto Profiles"),
    ("mobile_agent_infrastructure", "Mobile Users — GlobalProtect Infrastructure"),
    ("mobile_agent_auth_settings", "Mobile Users — Authentication Settings"),
    ("forwarding_profiles", "Mobile Users — Forwarding Profiles"),
    ("bandwidth_allocations", "Architecture — Bandwidth Allocations"),
    ("internal_dns_servers", "Architecture — Internal DNS Servers"),
    ("security_rules_pre", "SSE & Zero Trust — Security Rules (pre)"),
    ("security_rules_post", "SSE & Zero Trust — Security Rules (post)"),
    ("nat_rules_pre", "SSE & Zero Trust — NAT Rules (pre)"),
    ("nat_rules_post", "SSE & Zero Trust — NAT Rules (post)"),
    ("decryption_rules", "SSE & Zero Trust — Decryption Rules"),
    ("authentication_rules", "SSE & Zero Trust — Authentication Rules"),
    ("zones", "SSE & Zero Trust — Zones"),
    ("anti_spyware_profiles", "SSE & Zero Trust — Anti-Spyware Profiles"),
    ("vulnerability_profiles", "SSE & Zero Trust — Vulnerability Profiles"),
    ("wildfire_profiles", "SSE & Zero Trust — WildFire Profiles"),
    ("dns_security_profiles", "SSE & Zero Trust — DNS Security Profiles"),
    ("url_categories", "SSE & Zero Trust — URL Categories"),
    ("decryption_profiles", "SSE & Zero Trust — Decryption Profiles"),
    ("file_blocking_profiles", "SSE & Zero Trust — File Blocking Profiles"),
    ("authentication_profiles", "Identity & Posture — Authentication Profiles"),
    ("saml_server_profiles", "Identity & Posture — SAML Server Profiles"),
    ("hip_objects", "Identity & Posture — HIP Objects"),
    ("hip_profiles", "Identity & Posture — HIP Profiles"),
    ("log_forwarding_profiles", "Observability — Log Forwarding Profiles"),
    ("syslog_profiles", "Observability — Syslog Server Profiles"),
    ("http_server_profiles", "Observability — HTTP Server Profiles"),
    ("addresses", "Appendices — Address Objects"),
    ("address_groups", "Appendices — Address Groups"),
    ("services", "Appendices — Service Objects"),
    ("service_groups", "Appendices — Service Groups"),
    ("edls", "Appendices — External Dynamic Lists"),
    ("tags", "Appendices — Tags"),
    ("qos_profiles", "Appendices — QoS Profiles"),
]


@dataclass
class SectionDiff:
    """Drift result for one AS-BUILT section (one snapshot field)."""

    fieldname: str
    label: str
    doc_count: int
    live_count: int
    added: list[str] = field(default_factory=list)  # in live, missing from doc
    removed: list[str] = field(default_factory=list)  # in doc, gone from live
    changed: list[str] = field(default_factory=list)  # same name, different content
    # Live re-extraction hit errors and returned nothing for a section the doc
    # has data for — can't tell drift from a transient API failure.
    unverified: bool = False

    @property
    def drifted(self) -> bool:
        return bool(self.added or self.removed or self.changed) and not self.unverified


def _key(item: dict[str, Any]) -> str:
    return str(item.get("name") or item.get("id") or "")


def _canon(item: dict[str, Any]) -> str:
    return json.dumps(item, sort_keys=True, default=str)


def diff_snapshots(doc: AuditSnapshot, live: AuditSnapshot) -> list[SectionDiff]:
    """Diff every verified section between the doc and live snapshots.

    Sections empty in both snapshots are omitted. When the live extraction
    recorded errors and returned nothing for a section the doc populated,
    the section is flagged unverified rather than reported as wholesale
    removal.
    """
    diffs: list[SectionDiff] = []
    live_had_errors = bool(live.extraction_errors)

    for fieldname, label in VERIFIED_SECTIONS:
        doc_items = [i for i in (getattr(doc, fieldname, None) or []) if isinstance(i, dict)]
        live_items = [i for i in (getattr(live, fieldname, None) or []) if isinstance(i, dict)]
        if not doc_items and not live_items:
            continue

        doc_map = {_key(i): i for i in doc_items if _key(i)}
        live_map = {_key(i): i for i in live_items if _key(i)}

        added = sorted(set(live_map) - set(doc_map))
        removed = sorted(set(doc_map) - set(live_map))
        changed = sorted(
            k for k in set(doc_map) & set(live_map) if _canon(doc_map[k]) != _canon(live_map[k])
        )
        unverified = bool(doc_items) and not live_items and live_had_errors

        diffs.append(
            SectionDiff(
                fieldname=fieldname,
                label=label,
                doc_count=len(doc_items),
                live_count=len(live_items),
                added=added,
                removed=removed,
                changed=changed,
                unverified=unverified,
            )
        )
    return diffs


def _name_list(names: list[str], cap: int = 20) -> str:
    shown = ", ".join(f"`{n}`" for n in names[:cap])
    extra = len(names) - cap
    return shown + (f" … +{extra} more" if extra > 0 else "")


def render_verification_report(
    diffs: list[SectionDiff],
    doc_snap: AuditSnapshot,
    live_snap: AuditSnapshot,
    job_id: str,
    doc_generated: str,
    verified_at: str,
) -> str:
    """Render the section diffs as a Markdown verification report."""
    drifted = [d for d in diffs if d.drifted]
    unverified = [d for d in diffs if d.unverified]

    if drifted:
        verdict = f"⚠️ **DRIFT DETECTED** — {len(drifted)} section(s) no longer match live config"
    elif unverified:
        verdict = (
            f"❓ **PARTIALLY VERIFIED** — no drift found, but {len(unverified)} "
            "section(s) could not be re-read"
        )
    else:
        verdict = "✅ **DOCUMENT CURRENT** — all verifiable sections match live config"

    lines = [
        "# AS-BUILT Verification Report",
        "",
        f"**Job:** `{job_id}`  |  **Tenant:** `{doc_snap.tenant_id}`  |  "
        f"**Folder:** `{doc_snap.folder}`",
        f"**Doc extracted:** {doc_generated}  |  **Verified against live:** {verified_at}",
        "",
        verdict,
        "",
        "| Section | Doc | Live | +/− | ~ | Status |",
        "|---|---|---|---|---|---|",
    ]
    for d in diffs:
        if d.unverified:
            status = "❓ unverified"
        elif d.drifted:
            status = "⚠️ drift"
        else:
            status = "✅ match"
        lines.append(
            f"| {d.label} | {d.doc_count} | {d.live_count} "
            f"| +{len(d.added)}/−{len(d.removed)} | {len(d.changed)} | {status} |"
        )
    lines.append("")

    if drifted:
        lines.append("## Drift Detail")
        lines.append("")
        for d in drifted:
            lines.append(f"### {d.label}")
            if d.added:
                lines.append(f"- **Added since doc:** {_name_list(d.added)}")
            if d.removed:
                lines.append(f"- **Removed since doc:** {_name_list(d.removed)}")
            if d.changed:
                lines.append(f"- **Modified since doc:** {_name_list(d.changed)}")
            lines.append("")

    if doc_snap.extraction_errors:
        lines.append("## Extraction Gaps at Generation Time")
        lines.append("")
        lines.append("The document may be incomplete in these areas regardless of drift:")
        lines.append("")
        for err in doc_snap.extraction_errors:
            lines.append(f"- {err}")
        lines.append("")

    if live_snap.extraction_errors:
        lines.append("## Live Re-Extraction Warnings")
        lines.append("")
        lines.append("Verification itself may be incomplete for the affected resources:")
        lines.append("")
        for err in live_snap.extraction_errors:
            lines.append(f"- {err}")
        lines.append("")

    if drifted:
        lines.append(
            "> **Recommendation:** re-run `scm_asbuilt_report` to refresh the document — "
            "the sections above no longer reflect the tenant."
        )
        lines.append("")

    return "\n".join(lines)
