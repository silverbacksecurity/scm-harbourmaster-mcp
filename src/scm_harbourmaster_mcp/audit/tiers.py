"""
MSSP Gold / Silver / Bronze tier definitions.

Each tier specifies:
  - Which BPA check severities are *required* to pass (fail = tier breach)
  - Which NCSC frameworks the tier claims compliance with
  - Which SCM snippets should be applied at onboarding
  - A human-readable service description

Tier hierarchy (each tier is a strict superset of the one below):
  Bronze → Cyber Essentials baseline  (Critical checks only)
  Silver → Cyber Essentials Plus       (Critical + High checks)
  Gold   → NCSC CAF v4.0 full         (All checks: Critical + High + Medium + Low)

Inspired by scotchoaf/mssp-cnc GSB model, rebuilt for SCM SDK + snippets.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import Severity


@dataclass(frozen=True)
class TierDefinition:
    name: str  # "gold" | "silver" | "bronze"
    label: str  # "Gold" | "Silver" | "Bronze"
    description: str
    service_description: str
    # BPA severities that must pass for this tier
    required_severities: tuple[Severity, ...]
    # NCSC frameworks claimed at this tier
    ncsc_frameworks: tuple[str, ...]
    # NCSC control IDs required at this tier
    required_ncsc_controls: tuple[str, ...]
    # SCM snippet names that should be applied on onboarding
    scm_snippets: tuple[str, ...]
    # What's included vs what's excluded vs next tier
    included_features: tuple[str, ...]
    excluded_features: tuple[str, ...]


TIERS: dict[str, TierDefinition] = {
    "bronze": TierDefinition(
        name="bronze",
        label="Bronze",
        description="Baseline managed firewall — Cyber Essentials compliant",
        service_description=(
            "Essential perimeter protection with anti-spyware and vulnerability "
            "prevention. Business-hours support. CE baseline compliance reporting."
        ),
        required_severities=(Severity.CRITICAL,),
        ncsc_frameworks=("CE v3.2",),
        required_ncsc_controls=(
            "CE-FW-1",  # Default deny inbound
            "CE-FW-3",  # Rule review hygiene
            "CE-FW-4",  # Restrict outbound
        ),
        scm_snippets=(
            "MSSP-Bronze-SecurityProfiles",
            "MSSP-Bronze-Policies",
        ),
        included_features=(
            "Anti-spyware profile (basic)",
            "Vulnerability protection profile",
            "Explicit deny-all rule",
            "Security zone segmentation (trust/untrust)",
            "CE v3.2 compliance reporting",
        ),
        excluded_features=(
            "WildFire analysis",
            "DNS security profiles",
            "SSL/TLS decryption",
            "Log forwarding to SIEM",
            "Zone protection profiles",
            "URL filtering",
            "File blocking",
            "CAF v4.0 reporting",
        ),
    ),
    "silver": TierDefinition(
        name="silver",
        label="Silver",
        description="Core managed security — Cyber Essentials Plus posture",
        service_description=(
            "Full threat prevention stack with WildFire, DNS security, and SIEM log "
            "forwarding. Zone protection profiles. Business-hours support with "
            "monthly reporting. CE Plus compliance reporting."
        ),
        required_severities=(Severity.CRITICAL, Severity.HIGH),
        ncsc_frameworks=("CE v3.2", "10 Steps"),
        required_ncsc_controls=(
            "CE-FW-1",
            "CE-FW-2",
            "CE-FW-3",
            "CE-FW-4",
            "10S-NS-1",  # Ingress/egress filtering
            "10S-NS-2",  # Protective DNS
            "10S-NS-3",  # URL filtering
            "CAF-C1.a",  # Log collection
            "NSF-LOG-1",  # Log availability
        ),
        scm_snippets=(
            "MSSP-Silver-SecurityProfiles",
            "MSSP-Silver-LogForwarding",
            "MSSP-Silver-Policies",
            "MSSP-Silver-ZoneProtection",
        ),
        included_features=(
            "Everything in Bronze",
            "WildFire antivirus profile",
            "DNS security profile",
            "Log forwarding profiles",
            "Syslog export to MSSP SIEM",
            "Zone protection profiles (all zones)",
            "App-ID enforcement on all allow rules",
            "Session-end logging on all rules",
            "CE v3.2 + 10 Steps compliance reporting",
        ),
        excluded_features=(
            "SSL/TLS decryption (requires CA cert deployment)",
            "File blocking profiles",
            "CAF v4.0 full reporting",
            "24/7 SOC monitoring",
            "Threat hunting",
        ),
    ),
    "gold": TierDefinition(
        name="gold",
        label="Gold",
        description="Full managed security — NCSC CAF v4.0 compliant",
        service_description=(
            "Complete security stack with SSL/TLS inspection, file blocking, "
            "full threat hunting, and 24/7 SOC monitoring. Full NCSC CAF v4.0 "
            "compliance posture with quarterly reporting."
        ),
        required_severities=(
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
        ),
        ncsc_frameworks=("CAF v4.0", "CE v3.2", "10 Steps", "NSF"),
        required_ncsc_controls=(
            "CAF-B2.a",
            "CAF-B2.b",
            "CAF-B2.c",
            "CAF-B3.a",
            "CAF-B3.b",
            "CAF-B4.a",
            "CAF-C1.a",
            "CAF-C1.b",
            "CE-FW-1",
            "CE-FW-2",
            "CE-FW-3",
            "CE-FW-4",
            "10S-NS-1",
            "10S-NS-2",
            "10S-NS-3",
            "10S-TP-1",
            "NSF-ZT-1",
            "NSF-LOG-1",
        ),
        scm_snippets=(
            "MSSP-Gold-SecurityProfiles",
            "MSSP-Gold-DecryptionProfiles",
            "MSSP-Gold-LogForwarding",
            "MSSP-Gold-Policies",
            "MSSP-Gold-DecryptionPolicies",
            "MSSP-Gold-ZoneProtection",
        ),
        included_features=(
            "Everything in Silver",
            "SSL/TLS decryption profiles + policies",
            "File blocking profiles",
            "URL filtering profiles",
            "Anti-spyware with DNS sinkholing",
            "Full rule hygiene enforcement",
            "24/7 SOC monitoring",
            "Threat hunting",
            "Full CAF v4.0 compliance reporting",
            "Quarterly security reviews",
        ),
        excluded_features=(),
    ),
}

# Ordered from least to most comprehensive — used for upgrade path logic
TIER_ORDER: list[str] = ["bronze", "silver", "gold"]


def get_tier(name: str) -> TierDefinition:
    t = TIERS.get(name.lower())
    if t is None:
        raise ValueError(f"Unknown tier '{name}'. Valid: gold, silver, bronze")
    return t


def score_findings_against_tier(
    findings: list[Any],
    tier: TierDefinition,
) -> dict[str, Any]:
    """
    Score BPA findings against a tier's required severities.

    Returns a structured result with:
      - tier_compliant: bool
      - required_checks: how many checks are required at this tier
      - passed_required: how many of those passed
      - breaches: list of findings that are required but failed/warned
      - advisory: list of findings outside tier scope (higher tier only)
    """
    from .models import Status

    breaches: list[Any] = []
    advisory: list[Any] = []
    passed_required = 0
    required_checks = 0

    for f in findings:
        is_required = f.severity in tier.required_severities
        if is_required:
            required_checks += 1
            if f.status == Status.PASS:
                passed_required += 1
            elif f.status in (Status.FAIL, Status.WARN):
                breaches.append(f)
        elif f.status in (Status.FAIL, Status.WARN):
            advisory.append(f)

    return {
        "tier": tier.name,
        "tier_label": tier.label,
        "tier_compliant": len(breaches) == 0,
        "required_checks": required_checks,
        "passed_required": passed_required,
        "breach_count": len(breaches),
        "advisory_count": len(advisory),
        "breaches": [f.to_dict() for f in breaches],
        "advisory": [f.to_dict() for f in advisory],
        "compliance_score_pct": round(
            (passed_required / required_checks * 100) if required_checks else 0, 1
        ),
    }


def upgrade_gap(
    findings: list[Any],
    from_tier: str,
    to_tier: str,
) -> dict[str, Any]:
    """
    Show exactly what needs to pass to upgrade from one tier to the next.
    Returns the additional failing checks blocking the upgrade.
    """
    from .models import Status

    current = get_tier(from_tier)
    target = get_tier(to_tier)

    # Additional severities the target tier requires beyond current
    extra_sevs = set(target.required_severities) - set(current.required_severities)
    extra_ncsc = set(target.required_ncsc_controls) - set(current.required_ncsc_controls)

    blocking = [
        f.to_dict()
        for f in findings
        if f.severity in extra_sevs and f.status in (Status.FAIL, Status.WARN)
    ]
    new_snippets = [s for s in target.scm_snippets if s not in current.scm_snippets]

    return {
        "from_tier": from_tier,
        "to_tier": to_tier,
        "blocking_findings": blocking,
        "blocking_count": len(blocking),
        "additional_ncsc_controls": sorted(extra_ncsc),
        "snippets_to_apply": new_snippets,
        "new_features": [
            f
            for f in target.included_features
            if f not in current.included_features and f != f"Everything in {current.label}"
        ],
        "upgrade_ready": len(blocking) == 0,
    }


# ── Snippet content templates ────────────────────────────────────────────────
# Reference definitions for what each tier's SCM snippets should contain.
# Used by the onboarding tool to validate or describe snippet requirements.

SNIPPET_TEMPLATES: dict[str, dict[str, str]] = {
    "MSSP-Bronze-SecurityProfiles": {
        "description": "Bronze tier: anti-spyware (basic) + vulnerability protection",
        "contains": (
            "Anti-spyware profile: default severity actions, no sinkholing. "
            "Vulnerability protection profile: block on critical/high, alert on medium/low."
        ),
    },
    "MSSP-Bronze-Policies": {
        "description": "Bronze tier: baseline security rulebase",
        "contains": (
            "Deny-all rule (logged). Outbound allow rules with Bronze security profiles attached."
        ),
    },
    "MSSP-Silver-SecurityProfiles": {
        "description": "Silver tier: full threat prevention stack",
        "contains": (
            "Anti-spyware profile with DNS sinkholing + passive DNS monitoring. "
            "Vulnerability protection: block/reset on critical+high. "
            "WildFire antivirus: forward all file types, block malware. "
            "DNS security profile: all categories block/sinkhole."
        ),
    },
    "MSSP-Silver-LogForwarding": {
        "description": "Silver tier: log forwarding to MSSP SIEM",
        "contains": (
            "Log forwarding profile: traffic + threat + URL + WildFire logs. "
            "Syslog server profile: TCP/TLS to MSSP SIEM endpoint."
        ),
    },
    "MSSP-Silver-ZoneProtection": {
        "description": "Silver tier: zone protection profiles",
        "contains": (
            "Zone protection profile: SYN flood, ICMP flood, UDP flood protection. "
            "Reconnaissance protection: host sweep + port scan (block). "
            "Attached to all defined security zones."
        ),
    },
    "MSSP-Silver-Policies": {
        "description": "Silver tier: security + NAT rulebase",
        "contains": (
            "All Bronze policies. "
            "App-ID enforced on all allow rules. "
            "Log forwarding profile attached to all rules. "
            "Session-end logging enabled on all rules."
        ),
    },
    "MSSP-Gold-SecurityProfiles": {
        "description": "Gold tier: complete security profile set",
        "contains": (
            "All Silver profiles. "
            "File blocking profile: block/alert on high-risk types (exe, dll, bat, ps1, msi, jar). "
            "URL filtering profile: malware + phishing + C2 + hacking categories blocked. "
            "Safe search enforcement enabled."
        ),
    },
    "MSSP-Gold-DecryptionProfiles": {
        "description": "Gold tier: SSL/TLS inspection profiles",
        "contains": (
            "SSL forward proxy decryption profile: block expired/untrusted certs. "
            "SSL inbound inspection profile for published services. "
            "Decryption exclusion list for banking/healthcare/pinned-cert categories."
        ),
    },
    "MSSP-Gold-DecryptionPolicies": {
        "description": "Gold tier: decryption policy rules",
        "contains": (
            "SSL forward proxy rule: decrypt all outbound HTTPS from trust zones. "
            "SSL inbound inspection rule: decrypt inbound to published services. "
            "No-decrypt rule: banking, healthcare, certificate-pinned apps."
        ),
    },
    "MSSP-Gold-LogForwarding": {
        "description": "Gold tier: enhanced logging + SIEM integration",
        "contains": (
            "All Silver log forwarding. "
            "HTTP server profile for SOAR/EDR webhook integration. "
            "Enhanced application logging enabled."
        ),
    },
    "MSSP-Gold-ZoneProtection": {
        "description": "Gold tier: hardened zone protection",
        "contains": (
            "All Silver zone protection. "
            "Packet-based attack protection enabled. "
            "Protocol validation enforced."
        ),
    },
    "MSSP-Gold-Policies": {
        "description": "Gold tier: complete hardened rulebase",
        "contains": (
            "All Silver policies. "
            "File blocking and URL filtering profiles on all allow rules. "
            "Decryption policies applied. "
            "Disabled rules removed."
        ),
    },
}
