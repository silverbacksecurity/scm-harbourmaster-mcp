"""
NCSC control reference catalogue.

Sources:
  - NCSC CAF v4.0 (published August 2025) — 4 objectives, 14 principles, 39 outcomes
  - NCSC 10 Steps to Cyber Security (2023 refresh)
  - Cyber Essentials v3.2 (firewall section)
  - NCSC Network Security Fundamentals

Each entry maps a control ID to its title, source, objective, and
the BPA check IDs it relates to.  The audit engine uses this table
to annotate each Finding with its NCSC cross-references.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class NcscControl:
    id: str  # e.g. "CAF-B2.b"
    title: str
    source: str  # "CAF v4.0" | "CE v3.2" | "10 Steps" | "NSF"
    objective: str  # CAF objective or equivalent grouping
    description: str


NCSC_CONTROLS: dict[str, NcscControl] = {
    # ── CAF v4.0 — Objective B: Protecting Against Cyber Attack ─────────────
    "CAF-B2.a": NcscControl(
        id="CAF-B2.a",
        title="Identity and Access Control — Network Access",
        source="CAF v4.0",
        objective="B: Protecting Against Cyber Attack",
        description=(
            "Access to networks and network services should be controlled. "
            "Traffic flows should be constrained to the minimum necessary using "
            "allow lists and explicit deny rules."
        ),
    ),
    "CAF-B2.b": NcscControl(
        id="CAF-B2.b",
        title="Network Segmentation",
        source="CAF v4.0",
        objective="B: Protecting Against Cyber Attack",
        description=(
            "Networks should be segmented to limit the impact of a compromise. "
            "Security zones must be defined and traffic between zones must be "
            "explicitly permitted — deny all by default."
        ),
    ),
    "CAF-B2.c": NcscControl(
        id="CAF-B2.c",
        title="Admin Interface Protection",
        source="CAF v4.0",
        objective="B: Protecting Against Cyber Attack",
        description=(
            "Administrative interfaces must be restricted to trusted source "
            "addresses and protected by multi-factor authentication."
        ),
    ),
    "CAF-B3.a": NcscControl(
        id="CAF-B3.a",
        title="Malware Protection",
        source="CAF v4.0",
        objective="B: Protecting Against Cyber Attack",
        description=(
            "Malware protection must be deployed at the network perimeter and "
            "on all devices. Anti-spyware, anti-virus and WildFire analysis "
            "profiles must be applied to all allow rules."
        ),
    ),
    "CAF-B3.b": NcscControl(
        id="CAF-B3.b",
        title="Threat Intelligence and DNS Security",
        source="CAF v4.0",
        objective="B: Protecting Against Cyber Attack",
        description=(
            "DNS sinkholing and DNS security profiles should be configured to "
            "prevent malware command-and-control communications."
        ),
    ),
    "CAF-B4.a": NcscControl(
        id="CAF-B4.a",
        title="Vulnerability Management",
        source="CAF v4.0",
        objective="B: Protecting Against Cyber Attack",
        description=(
            "Vulnerability protection profiles must cover all severity levels "
            "(critical, high, medium, low) with appropriate block/reset actions "
            "on critical and high severity vulnerabilities."
        ),
    ),
    # ── CAF v4.0 — Objective C: Detecting Cyber Security Events ─────────────
    "CAF-C1.a": NcscControl(
        id="CAF-C1.a",
        title="Security Monitoring — Log Collection",
        source="CAF v4.0",
        objective="C: Detecting Cyber Security Events",
        description=(
            "All allow and deny traffic must be logged. Log forwarding profiles "
            "must be configured and attached to security rules. Logs must be "
            "forwarded to a centralised SIEM or syslog receiver."
        ),
    ),
    "CAF-C1.b": NcscControl(
        id="CAF-C1.b",
        title="Security Monitoring — Anomaly Detection",
        source="CAF v4.0",
        objective="C: Detecting Cyber Security Events",
        description=(
            "Threat event logging must be enabled so that intrusion attempts, "
            "malware activity, and policy violations generate alerts in the "
            "monitoring platform."
        ),
    ),
    # ── Cyber Essentials v3.2 — Firewall Controls ────────────────────────────
    "CE-FW-1": NcscControl(
        id="CE-FW-1",
        title="Boundary Firewall — Default Deny Inbound",
        source="CE v3.2",
        objective="Firewalls",
        description=(
            "The firewall must block all inbound traffic by default. "
            "Only explicitly approved inbound connections should be permitted. "
            "An implicit or explicit deny-all rule must terminate the rulebase."
        ),
    ),
    "CE-FW-2": NcscControl(
        id="CE-FW-2",
        title="Unauthenticated Services Not Exposed",
        source="CE v3.2",
        objective="Firewalls",
        description=(
            "Services accessible from the internet must require authentication. "
            "Rules permitting inbound access to unauthenticated services should "
            "not exist."
        ),
    ),
    "CE-FW-3": NcscControl(
        id="CE-FW-3",
        title="Firewall Rule Review",
        source="CE v3.2",
        objective="Firewalls",
        description=(
            "Approved connections must be regularly reviewed. Disabled, unused, "
            "or shadow rules must be removed. Rules must be documented with a "
            "business justification."
        ),
    ),
    "CE-FW-4": NcscControl(
        id="CE-FW-4",
        title="Restrict Outbound Traffic",
        source="CE v3.2",
        objective="Firewalls",
        description=(
            "Outbound connections must be restricted to only those necessary "
            "for business operations. Unrestricted outbound allow-any rules "
            "are not acceptable."
        ),
    ),
    # ── NCSC 10 Steps to Cyber Security ──────────────────────────────────────
    "10S-NS-1": NcscControl(
        id="10S-NS-1",
        title="Network Security — Ingress/Egress Filtering",
        source="10 Steps",
        objective="Network Security",
        description=(
            "Implement ingress and egress filtering at network boundaries. "
            "Anti-spoofing controls must be in place. Rules permitting "
            "any-to-any traffic are a critical risk."
        ),
    ),
    "10S-NS-2": NcscControl(
        id="10S-NS-2",
        title="Network Security — Protective DNS",
        source="10 Steps",
        objective="Network Security",
        description=(
            "Deploy protective DNS (PDNS) or DNS security controls to block "
            "known malicious domains. DNS sinkholing must be enabled in "
            "anti-spyware profiles."
        ),
    ),
    "10S-NS-3": NcscControl(
        id="10S-NS-3",
        title="Network Security — URL Filtering",
        source="10 Steps",
        objective="Network Security",
        description=(
            "URL filtering must be deployed to block known malicious, phishing, "
            "and command-and-control categories. Safe search enforcement should "
            "be enabled."
        ),
    ),
    "10S-TP-1": NcscControl(
        id="10S-TP-1",
        title="Threat Protection — SSL/TLS Inspection",
        source="10 Steps",
        objective="Malware Defences",
        description=(
            "SSL/TLS decryption should be deployed to inspect encrypted traffic "
            "for threats. Decryption profiles and rules must be configured."
        ),
    ),
    # ── NCSC Network Security Fundamentals ───────────────────────────────────
    "NSF-ZT-1": NcscControl(
        id="NSF-ZT-1",
        title="Zero Trust — Explicit Verification",
        source="NSF",
        objective="Architecture",
        description=(
            "All traffic must be explicitly permitted — implicit permit rules "
            "are not acceptable. Rules must specify source, destination, "
            "application and user where possible."
        ),
    ),
    "NSF-LOG-1": NcscControl(
        id="NSF-LOG-1",
        title="Monitoring — Log Availability",
        source="NSF",
        objective="Monitoring",
        description=(
            "Logs must be available for security analysis. Session-level "
            "logging (start and end) must be enabled and forwarded to a "
            "centralised log store."
        ),
    ),
    # ── CAF v4.0 — Objective B: Protecting Against Cyber Attack (extended) ───
    "CAF-B2.d": NcscControl(
        id="CAF-B2.d",
        title="Secure Communications — VPN Cryptography",
        source="CAF v4.0",
        objective="B: Protecting Against Cyber Attack",
        description=(
            "All remote access and site-to-site VPN connections must use "
            "strong, approved cryptographic algorithms. IKEv2 must be enforced; "
            "IKEv1 aggressive mode must be disabled. Cipher suites must use "
            "AES-256 or AES-128-GCM, SHA-256 or stronger, and DH group 14 or "
            "higher (group 19/20/21 preferred). Perfect Forward Secrecy (PFS) "
            "must be enabled on all IPSec tunnels."
        ),
    ),
    "CAF-B5.a": NcscControl(
        id="CAF-B5.a",
        title="Endpoint Security — Endpoint Posture Checking",
        source="CAF v4.0",
        objective="B: Protecting Against Cyber Attack",
        description=(
            "Endpoint posture checks (HIP checks) must be used to verify that "
            "connecting devices meet minimum security standards before granting "
            "network access. This includes checking for disk encryption, "
            "anti-malware, and patch status. HIP profiles must be applied to "
            "GlobalProtect security rules."
        ),
    ),
    "CAF-B6.a": NcscControl(
        id="CAF-B6.a",
        title="Device Vulnerability Management — Patching",
        source="CAF v4.0",
        objective="B: Protecting Against Cyber Attack",
        description=(
            "All network devices must be running current, supported software "
            "versions. Security patches must be applied within defined timescales "
            "(critical within 14 days, high within 30 days). Devices must be "
            "monitored for connectivity and compliance status."
        ),
    ),
    # ── CAF v4.0 — Objective C: Detecting Cyber Security Events (extended) ───
    "CAF-C3.a": NcscControl(
        id="CAF-C3.a",
        title="Identity and Access Control — Authentication",
        source="CAF v4.0",
        objective="C: Detecting Cyber Security Events",
        description=(
            "Strong authentication must be enforced for all remote access. "
            "Multi-factor authentication (MFA) must be required for privileged "
            "accounts and remote access. Authentication profiles must enforce "
            "account lockout after repeated failures. SAML IdP certificate "
            "validation must be enabled to prevent assertion forgery."
        ),
    ),
    # ── Cyber Essentials v3.2 — Extended Controls ────────────────────────────
    "CE-MFA-1": NcscControl(
        id="CE-MFA-1",
        title="Multi-Factor Authentication",
        source="CE v3.2",
        objective="User Access Control",
        description=(
            "Multi-factor authentication must be enabled for all cloud services, "
            "remote access connections, and privileged accounts. A second factor "
            "beyond username/password is required — this can be TOTP, push "
            "notification, hardware token, or biometric."
        ),
    ),
    "CE-PATCH-1": NcscControl(
        id="CE-PATCH-1",
        title="Patch Management — Timely Patching",
        source="CE v3.2",
        objective="Patch Management",
        description=(
            "All software and firmware on in-scope devices must be patched "
            "within 14 days of a critical or high severity patch release. "
            "Unsupported software must be removed or risk-accepted. Device "
            "inventory must include software version and patch status."
        ),
    ),
    "CE-SC-1": NcscControl(
        id="CE-SC-1",
        title="Secure Configuration — Device Baseline",
        source="CE v3.2",
        objective="Secure Configuration",
        description=(
            "In-scope devices must be securely configured: authentication "
            "(screen lock / password) enforced before device access, full-disk "
            "encryption on devices holding organisational data, and a "
            "host-based firewall enabled. Where a managed browser (Prisma "
            "Access Browser) is the access boundary, its device-posture "
            "signals evidence this control for enrolled endpoints."
        ),
    ),
}


# Mapping: BPA check ID → list of applicable NCSC control IDs
BPA_TO_NCSC: dict[str, list[str]] = {
    # Security rule checks
    "BPA-SR-001": ["CAF-B3.a", "CAF-B4.a", "CE-FW-1", "10S-NS-1"],
    "BPA-SR-002": ["CAF-B2.a", "CE-FW-1", "CE-FW-4", "10S-NS-1", "NSF-ZT-1"],
    "BPA-SR-003": ["CAF-C1.a", "NSF-LOG-1"],
    "BPA-SR-004": ["CE-FW-3"],
    "BPA-SR-005": ["CAF-B2.a", "NSF-ZT-1"],
    "BPA-SR-006": ["CAF-C1.a", "NSF-LOG-1"],
    "BPA-SR-007": ["CAF-B2.a", "CE-FW-4", "10S-NS-1"],
    "BPA-SR-008": ["CE-FW-1", "CAF-B2.b"],
    "BPA-SR-009": ["NSF-ZT-1", "CAF-B2.a", "CAF-B2.b"],
    "BPA-SR-010": ["CE-FW-2", "CAF-B2.a", "10S-NS-1"],
    # Threat prevention
    "BPA-TP-001": ["CAF-B3.a", "CAF-B3.b", "10S-NS-2"],
    "BPA-TP-002": ["CAF-B3.b", "10S-NS-2"],
    "BPA-TP-003": ["CAF-B4.a"],
    "BPA-TP-004": ["CAF-B3.a"],
    "BPA-TP-005": ["CAF-B3.a"],
    "BPA-TP-006": ["CAF-B3.b", "10S-NS-2"],
    "BPA-TP-007": ["CAF-B4.a"],
    # URL filtering
    "BPA-URL-001": ["10S-NS-3", "CAF-B3.a"],
    "BPA-URL-002": ["10S-NS-3", "CAF-B3.a"],
    "BPA-URL-003": ["10S-NS-3"],
    # Decryption
    "BPA-DEC-001": ["10S-TP-1"],
    "BPA-DEC-002": ["10S-TP-1"],
    # Zone protection
    "BPA-ZP-001": ["CAF-B2.b", "CE-FW-1"],
    "BPA-ZP-002": ["CAF-B2.b"],
    "BPA-ZP-003": ["CAF-B2.b"],
    # Logging
    "BPA-LOG-001": ["CAF-C1.a", "CAF-C1.b", "NSF-LOG-1"],
    "BPA-LOG-002": ["CAF-C1.a", "NSF-LOG-1"],
    "BPA-LOG-003": ["CAF-C1.a", "NSF-LOG-1"],
    # Network / zone design
    "BPA-NET-001": ["CAF-B2.b", "CE-FW-1"],
    "BPA-NET-002": ["CAF-B2.c", "CE-FW-2"],
    # VPN / cryptography
    "BPA-VPN-001": ["CAF-B2.d", "NSF-ZT-1"],
    "BPA-VPN-002": ["CAF-B2.d"],
    "BPA-VPN-003": ["CAF-B2.d"],
    "BPA-VPN-004": ["CAF-B2.d"],
    # Authentication / identity
    "BPA-AUTH-001": ["CAF-C3.a", "CAF-B2.c", "CE-MFA-1"],
    "BPA-AUTH-002": ["CAF-C3.a"],
    "BPA-AUTH-003": ["CAF-C3.a", "CE-MFA-1"],
    # HIP / endpoint posture
    "BPA-HIP-001": ["CAF-B6.a", "CE-PATCH-1"],
    "BPA-HIP-002": ["CAF-B5.a"],
    "BPA-HIP-003": ["CAF-B5.a", "CAF-C3.a", "NSF-ZT-1"],
    # Prisma Access Browser / endpoint posture
    "BPA-PAB-001": ["CAF-B5.a", "CE-SC-1"],
    "BPA-PAB-002": ["CAF-B5.a"],
    # NGFW device health
    "BPA-NGW-001": ["CAF-B6.a", "CAF-C1.a"],
    "BPA-NGW-002": ["CAF-B6.a", "CE-PATCH-1"],
    "BPA-NGW-003": ["CAF-B6.a"],
}
