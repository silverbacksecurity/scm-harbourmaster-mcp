"""
Baseline persistence and drift digest for the cross-tenant drift sentinel.

A baseline is a core AuditSnapshot serialized to disk as JSON. The sentinel
(scm_drift_check) re-extracts live config and diffs it against the stored
baseline using the same section diff engine as AS-BUILT verification, then
triages each drifted section by operational severity so an overnight sweep
surfaces "someone changed a security rule" above "someone added a tag".

Pure functions only — no SCM client or MCP imports.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, fields
from pathlib import Path
from typing import Any

from .asbuilt_verify import SectionDiff, _name_list, diff_snapshots
from .models import AuditSnapshot

# Section severity for drift triage. Anything not listed renders as LOW.
# HIGH   — enforcement or connectivity: a change here alters what traffic is
#          allowed, decrypted, authenticated, or how sites reach the cloud.
# MEDIUM — protection depth: profile/posture changes that weaken inspection
#          without directly opening the network.
# LOW    — object plumbing: usually a symptom of the above, rarely the story.
SECTION_SEVERITY: dict[str, str] = {
    "security_rules_pre": "HIGH",
    "security_rules_post": "HIGH",
    "nat_rules_pre": "HIGH",
    "nat_rules_post": "HIGH",
    "decryption_rules": "HIGH",
    "authentication_rules": "HIGH",
    "zones": "HIGH",
    "remote_networks": "HIGH",
    "service_connections": "HIGH",
    "ike_gateways": "HIGH",
    "ipsec_tunnels": "HIGH",
    "authentication_profiles": "HIGH",
    "saml_server_profiles": "HIGH",
    "log_forwarding_profiles": "HIGH",  # logging tamper = audit-trail loss
    "anti_spyware_profiles": "MEDIUM",
    "vulnerability_profiles": "MEDIUM",
    "wildfire_profiles": "MEDIUM",
    "dns_security_profiles": "MEDIUM",
    "url_categories": "MEDIUM",
    "decryption_profiles": "MEDIUM",
    "file_blocking_profiles": "MEDIUM",
    "hip_objects": "MEDIUM",
    "hip_profiles": "MEDIUM",
    "forwarding_profiles": "MEDIUM",
    "mobile_agent_infrastructure": "MEDIUM",
    "mobile_agent_auth_settings": "MEDIUM",
    "edls": "MEDIUM",
    "bandwidth_allocations": "MEDIUM",
    "internal_dns_servers": "MEDIUM",
    "syslog_profiles": "MEDIUM",
    "http_server_profiles": "MEDIUM",
}

_SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
_SEV_ICON = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "⚪"}

_SNAPSHOT_FIELDS = {f.name for f in fields(AuditSnapshot)}


def snapshot_to_dict(snap: AuditSnapshot) -> dict[str, Any]:
    return asdict(snap)


def snapshot_from_dict(data: dict[str, Any]) -> AuditSnapshot:
    """Rebuild an AuditSnapshot, dropping keys the current model doesn't know.

    Baselines outlive code versions — a field removed from the model must not
    make every stored baseline unreadable.
    """
    known = {k: v for k, v in data.items() if k in _SNAPSHOT_FIELDS}
    known.setdefault("folder", "")
    known.setdefault("tenant_id", "")
    return AuditSnapshot(**known)


def baseline_filename(tenant_id: str, folder: str) -> str:
    def _safe(s: str) -> str:
        return "".join(c if c.isalnum() or c in "-_" else "-" for c in s) or "default"

    return f"{_safe(tenant_id or 'default')}--{_safe(folder)}.json"


def save_baseline(snap: AuditSnapshot, baseline_dir: Path) -> Path:
    baseline_dir.mkdir(parents=True, exist_ok=True)
    path = baseline_dir / baseline_filename(snap.tenant_id, snap.folder)
    payload = {
        "saved_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "tenant_id": snap.tenant_id,
        "folder": snap.folder,
        "snapshot": snapshot_to_dict(snap),
    }
    path.write_text(json.dumps(payload, default=str))
    return path


def load_baseline(
    tenant_id: str, folder: str, baseline_dir: Path
) -> tuple[AuditSnapshot, str] | None:
    """Return (snapshot, saved_at) or None if no baseline exists."""
    path = baseline_dir / baseline_filename(tenant_id, folder)
    if not path.exists():
        return None
    payload = json.loads(path.read_text())
    return snapshot_from_dict(payload.get("snapshot", {})), str(payload.get("saved_at", "?"))


def drift_severity(diff: SectionDiff) -> str:
    return SECTION_SEVERITY.get(diff.fieldname, "LOW")


def check_drift(baseline: AuditSnapshot, live: AuditSnapshot) -> list[SectionDiff]:
    """Diff live config against the baseline; drifted sections only, worst first."""
    drifted = [d for d in diff_snapshots(baseline, live) if d.drifted]
    drifted.sort(key=lambda d: (_SEV_ORDER.get(drift_severity(d), 9), d.label))
    return drifted


def render_drift_digest(
    results: list[dict[str, Any]],
    generated_at: str,
) -> str:
    """Render the cross-tenant drift digest.

    Each entry in *results*: {label, baseline_saved_at, drifted: [SectionDiff],
    error: str|None, unverified: int}. Tenants with drift render first.
    """
    total_drift = sum(len(r.get("drifted") or []) for r in results)
    errored = [r for r in results if r.get("error")]

    lines = [
        "# Config Drift Digest",
        "",
        f"**Generated:** {generated_at}  |  **Tenants checked:** {len(results)}  |  "
        f"**Drifted sections:** {total_drift}",
        "",
    ]
    if total_drift == 0 and not errored:
        lines.append("🟢 **No drift detected** — every tenant matches its baseline.")
        lines.append("")

    def _sort_key(r: dict[str, Any]) -> tuple[int, int]:
        drifted = r.get("drifted") or []
        worst = min(
            (_SEV_ORDER.get(drift_severity(d), 9) for d in drifted),
            default=9,
        )
        return (worst, -len(drifted))

    for r in sorted(results, key=_sort_key):
        drifted: list[SectionDiff] = r.get("drifted") or []
        label = r["label"]
        if r.get("error"):
            lines += [f"## ⚠️ {label}", "", f"> Check failed: {r['error']}", ""]
            continue
        if not drifted:
            note = ""
            if r.get("unverified"):
                note = f"  ({r['unverified']} section(s) unverifiable this run)"
            lines += [f"## 🟢 {label} — no drift{note}", ""]
            continue

        worst = drift_severity(drifted[0])
        lines += [
            f"## {_SEV_ICON.get(worst, '')} {label} — {len(drifted)} drifted section(s)",
            "",
            f"_Baseline from {r.get('baseline_saved_at', '?')}_",
            "",
        ]
        for d in drifted:
            sev = drift_severity(d)
            parts = []
            if d.added:
                parts.append(f"added {_name_list(d.added, cap=10)}")
            if d.removed:
                parts.append(f"removed {_name_list(d.removed, cap=10)}")
            if d.changed:
                parts.append(f"modified {_name_list(d.changed, cap=10)}")
            lines.append(f"- {_SEV_ICON.get(sev, '')} **[{sev}] {d.label}**: " + "; ".join(parts))
        lines.append("")

    if total_drift:
        lines.append(
            "> Review each HIGH item against change tickets. Once explained, run "
            "`scm_drift_check(..., update_baseline=True)` to accept the new state."
        )
        lines.append("")
    return "\n".join(lines)
