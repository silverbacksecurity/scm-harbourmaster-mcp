"""
NCSC-compliant configuration snippet templates for Palo Alto Prisma Access / SCM.

Each template is a dict payload ready for the corresponding pan-scm-sdk `create()` call.
Call `build_templates(folder)` to get the full set parameterised with a target folder.

Compliance mapping:
  CAF v4.0  — C3 (Identity/Access), C4 (Data security), C5 (Security monitoring)
  CE v3.2   — Malware protection, Patch management, Network monitoring, Secure configuration
  10 Steps  — Network security, Malware defences, Monitoring
  NSF       — Detect, Protect, Respond
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# ─── Profile names ────────────────────────────────────────────────────────────

ANTI_SPYWARE_NAME = "NCSC-Baseline-AntiSpyware"
VULN_PROTECTION_NAME = "NCSC-Baseline-Vulnerability"
WILDFIRE_NAME = "NCSC-Baseline-WildFire"
URL_ACCESS_NAME = "NCSC-Baseline-URL"
LOG_FORWARDING_NAME = "NCSC-Baseline-Logging"
DENY_ALL_RULE_NAME = "NCSC-Deny-All"
TAG_NAME = "NCSC-Compliant"


@dataclass(frozen=True)
class TemplateSet:
    """All payload dicts for one target folder, ready for SDK create() calls."""

    folder: str
    anti_spyware: dict[str, Any]
    vulnerability: dict[str, Any]
    wildfire: dict[str, Any]
    url_access: dict[str, Any]
    log_forwarding: dict[str, Any]
    deny_all_rule: dict[str, Any]
    tag: dict[str, Any]

    @property
    def all_profiles(self) -> list[tuple[str, dict[str, Any]]]:
        """(sdk_attr_name, payload) pairs for the four security profiles."""
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


def build_templates(folder: str, syslog_profile: str | None = None) -> TemplateSet:
    """
    Return the full NCSC baseline template set for ``folder``.

    Args:
        folder: SCM folder name (e.g. ``"Shared"`` or a tenant folder).
        syslog_profile: Optional syslog server profile name to add to log forwarding.
                        If ``None`` only Cortex Data Lake forwarding is configured.
    """

    # ── Anti-spyware ──────────────────────────────────────────────────────────
    # CAF C5.1 / CE Malware: block known C2 and high-severity spyware
    anti_spyware: dict[str, Any] = {
        "name": ANTI_SPYWARE_NAME,
        "description": "NCSC CAF v4.0 / CE v3.2 — blocks critical+high spyware, alerts medium",
        "folder": folder,
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
    # CE Patch management / CAF C4: prevent exploit of known vulns
    vulnerability: dict[str, Any] = {
        "name": VULN_PROTECTION_NAME,
        "description": "NCSC CAF v4.0 / CE v3.2 — reset-both on critical+high CVEs",
        "folder": folder,
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
    # CE Malware: submit all file types in both directions for analysis
    wildfire: dict[str, Any] = {
        "name": WILDFIRE_NAME,
        "description": "NCSC CE v3.2 — WildFire cloud analysis for all file types",
        "folder": folder,
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
    # CE v3.2 / 10 Steps: block malware/C2/phishing categories
    url_access: dict[str, Any] = {
        "name": URL_ACCESS_NAME,
        "description": "NCSC CE v3.2 — block malware, C2, phishing categories",
        "folder": folder,
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
    # CAF C5 / 10 Steps Monitoring: all log types to Cortex + optional syslog
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
        "description": "NCSC CAF v4.0 C5 — traffic, threat, WildFire, URL, auth logs",
        "folder": folder,
        "match_list": [
            _log_match_entry("traffic-logs", "traffic", syslog_profile),
            _log_match_entry("threat-logs", "threat", syslog_profile),
            _log_match_entry("wildfire-logs", "wildfire", syslog_profile),
            _log_match_entry("url-logs", "url", syslog_profile),
            _log_match_entry("auth-logs", "auth", syslog_profile),
        ],
    }

    # ── Deny-all security rule ─────────────────────────────────────────────────
    # CE v3.2 / CAF C3: explicit implicit-deny with logging for visibility
    deny_all_rule: dict[str, Any] = {
        "name": DENY_ALL_RULE_NAME,
        "description": "NCSC baseline — explicit deny-all with logging (bottom of rulebase)",
        "folder": folder,
        "action": "deny",
        "from_": ["any"],
        "to_": ["any"],
        "source": ["any"],
        "destination": ["any"],
        "application": ["any"],
        "service": ["any"],
        "log_end": True,
        "rulebase": "post",
    }

    # ── NCSC tag ───────────────────────────────────────────────────────────────
    tag: dict[str, Any] = {
        "name": TAG_NAME,
        "folder": folder,
        "color": "Red",
        "comments": "Managed by scm-harbourmaster-mcp NCSC baseline",
    }

    return TemplateSet(
        folder=folder,
        anti_spyware=anti_spyware,
        vulnerability=vulnerability,
        wildfire=wildfire,
        url_access=url_access,
        log_forwarding=log_forwarding,
        deny_all_rule=deny_all_rule,
        tag=tag,
    )


def _scope_to_snippet(payload: dict[str, Any], snippet_name: str) -> dict[str, Any]:
    """Return a copy of *payload* with 'folder' replaced by 'snippet'."""
    p = {k: v for k, v in payload.items() if k != "folder"}
    p["snippet"] = snippet_name
    return p


@dataclass(frozen=True)
class SnippetTemplateSet:
    """Profile payloads scoped to a snippet (no security rules — those live in folders)."""

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


def build_snippet_templates(
    snippet_name: str, syslog_profile: str | None = None
) -> SnippetTemplateSet:
    """
    Return the NCSC baseline profile set scoped to *snippet_name*.

    Security rules are excluded — SCM snippets hold reusable objects/profiles only;
    deny-all rules must be created separately in a folder rulebase.

    Args:
        snippet_name: Target SCM snippet name (e.g. ``"NCSC-Compliance"``).
        syslog_profile: Optional syslog server profile name for log forwarding.
    """
    # Reuse build_templates with a placeholder folder, then re-scope to snippet
    _t = build_templates("__snippet__", syslog_profile=syslog_profile)
    return SnippetTemplateSet(
        snippet=snippet_name,
        anti_spyware=_scope_to_snippet(_t.anti_spyware, snippet_name),
        vulnerability=_scope_to_snippet(_t.vulnerability, snippet_name),
        wildfire=_scope_to_snippet(_t.wildfire, snippet_name),
        url_access=_scope_to_snippet(_t.url_access, snippet_name),
        log_forwarding=_scope_to_snippet(_t.log_forwarding, snippet_name),
        tag=_scope_to_snippet(_t.tag, snippet_name),
    )


# ─── Gap check helpers ────────────────────────────────────────────────────────


@dataclass
class GapItem:
    """A single NCSC compliance gap found in the live config."""

    control: str  # NCSC control reference
    severity: str  # critical | high | medium | info
    finding: str  # one-line description of the gap
    remediation: str  # what to fix / apply
    object_name: str = ""  # the offending SCM object name, if any


def check_security_rules(rules: list[Any]) -> list[GapItem]:
    """Inspect security rules for NCSC-required properties."""
    gaps: list[GapItem] = []
    has_deny_all = False

    for rule in rules:
        d = rule.model_dump() if hasattr(rule, "model_dump") else rule
        name = d.get("name", "?")
        action = d.get("action", "")

        if action == "deny" and d.get("source") in (["any"], None):
            has_deny_all = True
            continue

        if action != "allow":
            continue

        # All allow rules must have a log setting (CE v3.2 / 10 Steps Monitoring)
        if not d.get("log_setting") and not d.get("log_end"):
            gaps.append(
                GapItem(
                    control="CE v3.2 / 10 Steps",
                    severity="high",
                    finding=f"Rule '{name}' has no log forwarding profile and log_end=False",
                    remediation=f"Attach '{LOG_FORWARDING_NAME}' profile and enable log_end",
                    object_name=name,
                )
            )

        # All allow rules must have a profile group or individual security profiles
        profile = d.get("profile_setting") or {}
        if hasattr(profile, "model_dump"):
            profile = profile.model_dump()
        group = profile.get("group") if isinstance(profile, dict) else None
        profiles = profile.get("profiles") if isinstance(profile, dict) else None
        if not group and not profiles:
            gaps.append(
                GapItem(
                    control="CE v3.2 Malware / CAF C4",
                    severity="critical",
                    finding=f"Rule '{name}' has no security profile group attached",
                    remediation="Attach anti-spyware, vulnerability, WildFire, and URL profiles",
                    object_name=name,
                )
            )

    if not has_deny_all:
        gaps.append(
            GapItem(
                control="CE v3.2 / CAF C3",
                severity="high",
                finding="No explicit deny-all rule found at bottom of rulebase",
                remediation=f"Create rule '{DENY_ALL_RULE_NAME}' with action=deny, log_end=True",
            )
        )

    return gaps


def check_anti_spyware_profiles(profiles: list[Any]) -> list[GapItem]:
    """Check anti-spyware profiles for NCSC requirements."""
    gaps: list[GapItem] = []
    names = set()
    for p in profiles:
        d = p.model_dump() if hasattr(p, "model_dump") else p
        names.add(d.get("name"))
        if not d.get("cloud_inline_analysis"):
            gaps.append(
                GapItem(
                    control="CE v3.2 Malware / CAF C5",
                    severity="high",
                    finding=f"Anti-spyware profile '{d['name']}' has cloud_inline_analysis disabled",
                    remediation="Enable cloud inline analysis for real-time C2 detection",
                    object_name=d["name"],
                )
            )
        # Check that MICA C2 detectors are enabled
        mica = d.get("mica_engine_spyware_enabled") or []
        if not mica:
            gaps.append(
                GapItem(
                    control="CAF C5.1",
                    severity="medium",
                    finding=f"Profile '{d['name']}' has no MICA C2 engine detectors configured",
                    remediation="Enable all MICA HTTP/SSL/TCP/UDP C2 detectors with reset-both",
                    object_name=d["name"],
                )
            )
    if ANTI_SPYWARE_NAME not in names:
        gaps.append(
            GapItem(
                control="CE v3.2 Malware / CAF C4",
                severity="info",
                finding=f"NCSC baseline profile '{ANTI_SPYWARE_NAME}' not present",
                remediation="Run scm_apply_ncsc_baseline to create the baseline profile set",
            )
        )
    return gaps


def check_log_forwarding(profiles: list[Any]) -> list[GapItem]:
    """Check that a log forwarding profile covering all log types exists."""
    gaps: list[GapItem] = []
    for p in profiles:
        d = p.model_dump() if hasattr(p, "model_dump") else p
        match_list = d.get("match_list") or []
        log_types = {e.get("log_type") for e in match_list if isinstance(e, dict)}
        required = {"traffic", "threat", "wildfire", "url"}
        missing = required - log_types
        if missing:
            gaps.append(
                GapItem(
                    control="CAF C5 / 10 Steps Monitoring",
                    severity="high",
                    finding=f"Log profile '{d['name']}' missing log types: {', '.join(sorted(missing))}",
                    remediation=f"Add match_list entries for: {', '.join(sorted(missing))}",
                    object_name=d["name"],
                )
            )
    if not profiles:
        gaps.append(
            GapItem(
                control="CAF C5 / 10 Steps Monitoring",
                severity="critical",
                finding="No log forwarding profiles found in folder",
                remediation=f"Run scm_apply_ncsc_baseline to create '{LOG_FORWARDING_NAME}'",
            )
        )
    return gaps
