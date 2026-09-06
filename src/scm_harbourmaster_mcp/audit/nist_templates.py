"""
NIST-compliant configuration snippet templates for Palo Alto Prisma Access / SCM.

Each template is a dict payload ready for the corresponding pan-scm-sdk `create()` call.
Call `build_nist_snippet_templates(snippet_name)` to get the full set.

Compliance mapping:
  NIST CSF v2.0  — GV (Govern), ID (Identify), PR (Protect), DE (Detect), RS (Respond)
  NIST SP 800-53 — SI-2 Flaw Remediation, SI-3 Malware Protection, SI-4 System Monitoring,
                   RA-5 Vulnerability Monitoring, AU-2/AU-12 Audit Logging,
                   SC-7 Boundary Protection, AC-3 Access Enforcement
  NIST SP 800-171 — 3.14 System and Information Integrity
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# ─── Profile names ────────────────────────────────────────────────────────────

ANTI_SPYWARE_NAME = "NIST-Baseline-AntiSpyware"
VULN_PROTECTION_NAME = "NIST-Baseline-Vulnerability"
WILDFIRE_NAME = "NIST-Baseline-WildFire"
URL_ACCESS_NAME = "NIST-Baseline-URL"
LOG_FORWARDING_NAME = "NIST-Baseline-Logging"
TAG_NAME = "NIST-Compliant"


@dataclass(frozen=True)
class NistSnippetTemplateSet:
    """Profile payloads scoped to a snippet, mapped to NIST controls."""

    snippet: str
    anti_spyware: dict[str, Any]
    vulnerability: dict[str, Any]
    wildfire: dict[str, Any]
    url_access: dict[str, Any]
    log_forwarding: dict[str, Any]
    tag: dict[str, Any]

    @property
    def all_profiles(self) -> list[tuple[str, dict[str, Any]]]:
        return [
            ("anti_spyware_profile", self.anti_spyware),
            ("vulnerability_protection_profile", self.vulnerability),
            ("wildfire_antivirus_profile", self.wildfire),
            ("url_access_profile", self.url_access),
            ("log_forwarding_profile", self.log_forwarding),
        ]

    @property
    def profile_names(self) -> list[str]:
        return [
            ANTI_SPYWARE_NAME,
            VULN_PROTECTION_NAME,
            WILDFIRE_NAME,
            URL_ACCESS_NAME,
            LOG_FORWARDING_NAME,
        ]


def build_nist_snippet_templates(
    snippet_name: str, syslog_profile: str | None = None
) -> NistSnippetTemplateSet:
    """
    Return the NIST baseline profile set scoped to *snippet_name*.

    Maps to: NIST CSF v2.0, SP 800-53 Rev 5, SP 800-171 Rev 3.

    Security rules are excluded — snippets hold reusable profiles/objects only.

    Args:
        snippet_name: Target SCM snippet name (e.g. ``"NIST-Compliance"``).
        syslog_profile: Optional syslog server profile name for log forwarding.
    """

    # ── Anti-spyware ──────────────────────────────────────────────────────────
    # SP 800-53 SI-3 (Malware Protection), SI-4 (System Monitoring)
    # CSF v2.0 DE.CM-01 (Networks/endpoints monitored), PR.PS-05 (Software unauthorised)
    anti_spyware: dict[str, Any] = {
        "name": ANTI_SPYWARE_NAME,
        "description": "NIST SP 800-53 SI-3/SI-4 — blocks critical+high spyware, C2 detection",
        "snippet": snippet_name,
        "cloud_inline_analysis": True,
        "mica_engine_spyware_enabled": [
            {"name": "HTTP Command and Control detector", "inline_policy_action": "reset-both"},
            {"name": "HTTP2 Command and Control detector", "inline_policy_action": "reset-both"},
            {"name": "SSL Command and Control detector", "inline_policy_action": "reset-both"},
            {
                "name": "Unknown-TCP Command and Control detector",
                "inline_policy_action": "reset-both",
            },
            {
                "name": "Unknown-UDP Command and Control detector",
                "inline_policy_action": "reset-both",
            },
        ],
        "rules": [
            {
                "name": "block-critical-high",
                "severity": ["critical", "high"],
                "category": "any",
                "action": "reset_both",
            },
            {
                "name": "alert-medium",
                "severity": ["medium"],
                "category": "any",
                "action": "alert",
            },
            {
                "name": "default-low-info",
                "severity": ["low", "informational"],
                "category": "any",
            },
        ],
    }

    # ── Vulnerability protection ───────────────────────────────────────────────
    # SP 800-53 SI-2 (Flaw Remediation), RA-5 (Vulnerability Monitoring)
    # CSF v2.0 ID.RA-01, PR.IP-12
    vulnerability: dict[str, Any] = {
        "name": VULN_PROTECTION_NAME,
        "description": "NIST SP 800-53 SI-2/RA-5 — reset-both on critical+high CVEs",
        "snippet": snippet_name,
        "rules": [
            {
                "name": "block-critical-high",
                "severity": ["critical", "high"],
                "cve": ["any"],
                "vendor_id": ["any"],
                "threat_name": "any",
                "host": "any",
                "category": "any",
                "action": "reset_both",
                "packet_capture": "single-packet",
            },
            {
                "name": "alert-medium",
                "severity": ["medium"],
                "cve": ["any"],
                "vendor_id": ["any"],
                "threat_name": "any",
                "host": "any",
                "category": "any",
                "action": "alert",
                "packet_capture": "disable",
            },
            {
                "name": "allow-low-info",
                "severity": ["low", "informational"],
                "cve": ["any"],
                "vendor_id": ["any"],
                "threat_name": "any",
                "host": "any",
                "category": "any",
                "action": "allow",
                "packet_capture": "disable",
            },
        ],
    }

    # ── WildFire antivirus ─────────────────────────────────────────────────────
    # SP 800-53 SI-3 (Malware Protection), SI-16
    # CSF v2.0 PR.PS-05, DE.CM-09
    wildfire: dict[str, Any] = {
        "name": WILDFIRE_NAME,
        "description": "NIST SP 800-53 SI-3 — WildFire cloud analysis for all file types",
        "snippet": snippet_name,
        "rules": [
            {
                "name": "all-files-both-directions",
                "application": ["any"],
                "direction": "both",
                "file_type": ["any"],
                "analysis": "public-cloud",
            }
        ],
    }

    # ── URL access profile ─────────────────────────────────────────────────────
    # SP 800-53 SC-7 (Boundary Protection), SI-3
    # CSF v2.0 PR.AA-05, DE.CM-01
    url_access: dict[str, Any] = {
        "name": URL_ACCESS_NAME,
        "description": "NIST SP 800-53 SC-7/SI-3 — block malware, C2, phishing categories",
        "snippet": snippet_name,
        "block": [
            "command-and-control",
            "malware",
            "phishing",
            "hacking",
            "dynamic-dns",
        ],
        "alert": [
            "unknown",
            "proxy-avoidance-and-anonymizers",
            "questionable",
        ],
        "cloud_inline_cat": True,
        "local_inline_cat": True,
    }

    # ── Log forwarding ─────────────────────────────────────────────────────────
    # SP 800-53 AU-2 (Event Logging), AU-12 (Audit Record Generation), SI-4
    # CSF v2.0 DE.CM-01, DE.AE-02, RS.AN-03
    def _log_match_entry(name: str, log_type: str, syslog: str | None) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "name": name,
            "log_type": log_type,
            "filter": "All Logs",
            "send_to_panorama": True,
            "quarantine": False,
        }
        if syslog:
            entry["send_syslog"] = [syslog]
        return entry

    log_forwarding: dict[str, Any] = {
        "name": LOG_FORWARDING_NAME,
        "description": "NIST SP 800-53 AU-2/AU-12/SI-4 — traffic, threat, WildFire, URL, auth logs",
        "snippet": snippet_name,
        "match_list": [
            _log_match_entry("traffic-logs", "traffic", syslog_profile),
            _log_match_entry("threat-logs", "threat", syslog_profile),
            _log_match_entry("wildfire-logs", "wildfire", syslog_profile),
            _log_match_entry("url-logs", "url", syslog_profile),
            _log_match_entry("auth-logs", "auth", syslog_profile),
        ],
    }

    # ── NIST tag ───────────────────────────────────────────────────────────────
    tag: dict[str, Any] = {
        "name": TAG_NAME,
        "snippet": snippet_name,
        "color": "Blue",
        "comments": "Managed by scm-harbourmaster-mcp NIST baseline",
    }

    return NistSnippetTemplateSet(
        snippet=snippet_name,
        anti_spyware=anti_spyware,
        vulnerability=vulnerability,
        wildfire=wildfire,
        url_access=url_access,
        log_forwarding=log_forwarding,
        tag=tag,
    )
