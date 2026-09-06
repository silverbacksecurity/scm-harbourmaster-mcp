"""
DSPT (Data Security and Protection Toolkit) control reference catalogue.

Source: NHS England DSPT 2024-25 (v5.1) — Technology Standards 7, 8, 9 and 10.
https://www.dsptoolkit.nhs.uk

The DSPT is the mandatory annual self-assessment for organisations that access
NHS patient data and systems. It is based on the National Data Guardian's
10 Data Security Standards and replaces the old IG Toolkit.

Assessment levels:
  Approaching Standards — minimum acceptable; mandatory controls partially met
  Meeting Standards     — all mandatory assertions evidenced (standard requirement)
  Exceeding Standards   — mandatory + recommended best-practice controls evidenced

This module covers only the Technology standards (7, 8, 9, 10) where SCM
configuration provides automated, auditable evidence. People and process
standards (1–6) require human self-assessment within the DSPT portal.

Each assertion is mapped to zero or more BPA check IDs so the audit engine
can automatically derive compliance status from live SCM configuration.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DsptAssertion:
    id: str  # e.g. "DSPT-9.1.1"
    title: str
    standard: str  # e.g. "Standard 9: IT Protection"
    standard_number: int  # 7, 8, 9 or 10
    assertion_ref: str  # e.g. "9.1.1" — exact DSPT portal reference
    description: str  # what the assertion requires
    evidence_guidance: str  # what evidence to copy into the DSPT portal
    dspt_level: str  # "approaching" | "meeting" | "exceeding"


# ── Standard 7: Continuity Planning ────────────────────────────────────────────
# Organisations must have processes for data recovery, testing, and continuity
# in the event of a cyber attack or system failure.

_S7 = "Standard 7: Continuity Planning"
_S8 = "Standard 8: Unsupported Systems"
_S9 = "Standard 9: IT Protection"
_S10 = "Standard 10: Accountable Suppliers"

DSPT_ASSERTIONS: dict[str, DsptAssertion] = {
    # ── Standard 7 ──────────────────────────────────────────────────────────────
    "DSPT-7.1.1": DsptAssertion(
        id="DSPT-7.1.1",
        title="Network Configuration Backup and Recovery",
        standard=_S7,
        standard_number=7,
        assertion_ref="7.1.1",
        description=(
            "Data recovery processes and tools are in place and tested regularly. "
            "Configuration backups must be taken and verified restorable."
        ),
        evidence_guidance=(
            "SCM configuration snapshots are exported via `scm_config_backup` and stored "
            "in timestamped JSON files. Version history is managed in SCM config-versions "
            "(see `scm_config_versions`). Rollback to any prior version is available via "
            "`scm_config_rollback`. Provide evidence of a recent backup export and a "
            "successful restore test to meet this assertion."
        ),
        dspt_level="meeting",
    ),
    "DSPT-7.2.1": DsptAssertion(
        id="DSPT-7.2.1",
        title="Cyber Incident Business Continuity",
        standard=_S7,
        standard_number=7,
        assertion_ref="7.2.1",
        description=(
            "Business continuity plans explicitly cover cyber attacks including "
            "ransomware, denial of service, and data exfiltration scenarios."
        ),
        evidence_guidance=(
            "Provide the organisation's Business Continuity Plan (BCP) referencing "
            "cyber attack scenarios. SCM config push tracking (`scm_config_push_track`) "
            "and rollback capability (`scm_config_rollback`) support recovery procedures. "
            "This assertion requires a documented BCP — cannot be fully evidenced from "
            "firewall configuration alone."
        ),
        dspt_level="meeting",
    ),
    # ── Standard 8 ──────────────────────────────────────────────────────────────
    "DSPT-8.1.1": DsptAssertion(
        id="DSPT-8.1.1",
        title="Supported Software and Operating Systems",
        standard=_S8,
        standard_number=8,
        assertion_ref="8.1.1",
        description=(
            "All systems and software in use are within vendor support lifecycle "
            "and receive security updates from the manufacturer."
        ),
        evidence_guidance=(
            "PAN-OS version currency is checked via `scm_check_updates`. Provide "
            "evidence that NGFW devices run a PAN-OS release within the current support "
            "lifecycle (not EoL) and that Content DB is updated. Run `scm_check_updates` "
            "and screenshot the result for DSPT portal evidence."
        ),
        dspt_level="meeting",
    ),
    "DSPT-8.3.1": DsptAssertion(
        id="DSPT-8.3.1",
        title="Critical Security Patches Applied Within 14 Days",
        standard=_S8,
        standard_number=8,
        assertion_ref="8.3.1",
        description=(
            "Critical severity security patches are applied within 14 calendar days "
            "of release. High severity patches are applied within 30 days."
        ),
        evidence_guidance=(
            "Provide evidence of a patching process with defined timescales. "
            "`scm_check_updates` shows the current PAN-OS version vs latest release. "
            "SCM config-versions history (`scm_config_versions`) shows the date "
            "firmware updates were pushed. For DSPT, document the patch SLA in your "
            "patching policy and provide the last 3 patch events with dates."
        ),
        dspt_level="meeting",
    ),
    # ── Standard 9 ──────────────────────────────────────────────────────────────
    # 9.1 — Firewall / network boundary protection
    "DSPT-9.1.1": DsptAssertion(
        id="DSPT-9.1.1",
        title="Firewall Protects Network Boundary",
        standard=_S9,
        standard_number=9,
        assertion_ref="9.1.1",
        description=(
            "Appropriate network firewalls or equivalent controls protect connections "
            "between the organisation's networks and the internet and other untrusted "
            "network connections. Only necessary ports and services are permitted."
        ),
        evidence_guidance=(
            "Strata Cloud Manager enforces security policies on PAN-OS NGFWs and "
            "Prisma Access. Evidence: (1) Security zones are defined separating trusted, "
            "untrusted, and DMZ traffic (BPA-NET-001, BPA-ZP-001). (2) A default "
            "deny-all rule exists at the bottom of the security policy (BPA-SR-008). "
            "(3) No unrestricted any-source/any-destination/any-application rules "
            "(BPA-SR-004, BPA-SR-007). Export the BPA assessment report via "
            "`scm_bpa_assess` and attach as evidence."
        ),
        dspt_level="meeting",
    ),
    "DSPT-9.1.2": DsptAssertion(
        id="DSPT-9.1.2",
        title="Network Segmentation for NHS Data Systems",
        standard=_S9,
        standard_number=9,
        assertion_ref="9.1.2",
        description=(
            "Networks are segmented so that systems handling NHS patient data are "
            "isolated from general corporate traffic. Access between segments is "
            "restricted to what is necessary."
        ),
        evidence_guidance=(
            "Provide evidence of security zone configuration in SCM showing separate "
            "zones for NHS data systems vs corporate/guest networks. BPA-NET-001 "
            "checks that ≥3 security zones are defined. BPA-SR-009 detects rules with "
            "no source or destination specificity (zero-trust gap). Include SCM zone "
            "configuration export or BPA assessment output."
        ),
        dspt_level="meeting",
    ),
    # 9.2 — Malware protection and URL filtering
    "DSPT-9.2.1": DsptAssertion(
        id="DSPT-9.2.1",
        title="Anti-Malware Protection on All Devices and Network",
        standard=_S9,
        standard_number=9,
        assertion_ref="9.2.1",
        description=(
            "Anti-malware (or equivalent) solutions are deployed and configured "
            "on all devices and at the network perimeter. This includes protection "
            "against viruses, ransomware, spyware, and advanced threats."
        ),
        evidence_guidance=(
            "Palo Alto NGFW / Prisma Access applies threat prevention, anti-spyware, "
            "and WildFire cloud sandboxing profiles to network traffic. Evidence: "
            "BPA-TP-001 (antivirus profile on all allow rules), BPA-TP-002 "
            "(anti-spyware on all allow rules), BPA-TP-003 (WildFire on all allow "
            "rules), BPA-TP-007 (WildFire file-type coverage). Export "
            "`scm_bpa_assess` results filtering for TP checks."
        ),
        dspt_level="meeting",
    ),
    "DSPT-9.2.2": DsptAssertion(
        id="DSPT-9.2.2",
        title="Malicious URL and Web Content Filtering",
        standard=_S9,
        standard_number=9,
        assertion_ref="9.2.2",
        description=(
            "Web content filtering blocks access to known malicious URLs, "
            "phishing sites, and command-and-control infrastructure. "
            "DNS security is configured to sinkhole malicious domains."
        ),
        evidence_guidance=(
            "PAN-OS URL filtering profiles block malicious, phishing, "
            "command-and-control, hacking, proxy-avoidance and dynamic-DNS "
            "categories (BPA-URL-001, BPA-URL-002). DNS sinkholing is configured "
            "in anti-spyware profiles (BPA-TP-006). Provide BPA assessment "
            "export showing URL and DNS security checks passing."
        ),
        dspt_level="meeting",
    ),
    "DSPT-9.2.3": DsptAssertion(
        id="DSPT-9.2.3",
        title="Encrypted Traffic Inspection",
        standard=_S9,
        standard_number=9,
        assertion_ref="9.2.3",
        description=(
            "SSL/TLS traffic is inspected to detect malware and data exfiltration "
            "hidden within encrypted sessions, where technically feasible."
        ),
        evidence_guidance=(
            "PAN-OS SSL/TLS decryption is configured via decryption policies and "
            "profiles. BPA-DEC-002 verifies that at least one active decryption rule "
            "with action=decrypt exists. BPA-DEC-001 checks that a decryption profile "
            "enforces certificate verification. Attach the BPA decryption check results "
            "and the decryption policy export."
        ),
        dspt_level="exceeding",
    ),
    # 9.3 — User access management
    "DSPT-9.3.1": DsptAssertion(
        id="DSPT-9.3.1",
        title="Network Access Restricted to Authorised Users and Devices",
        standard=_S9,
        standard_number=9,
        assertion_ref="9.3.1",
        description=(
            "Access to network services and systems is restricted to authorised "
            "users and devices only. Application-aware policies ensure only "
            "required services are accessible."
        ),
        evidence_guidance=(
            "SCM security policies use App-ID to restrict access to specific "
            "named applications rather than port-based rules. BPA-SR-002 flags "
            "rules with app=any and service=any. BPA-SR-005 detects source-any "
            "rules. BPA-SR-010 flags cleartext protocol exposure (Telnet, FTP). "
            "Export BPA security rule checks as evidence."
        ),
        dspt_level="meeting",
    ),
    # 9.4 — Authentication and MFA
    "DSPT-9.4.1": DsptAssertion(
        id="DSPT-9.4.1",
        title="Strong Authentication for Remote Access",
        standard=_S9,
        standard_number=9,
        assertion_ref="9.4.1",
        description=(
            "Remote access connections (VPN, GlobalProtect, Prisma Access) require "
            "multi-factor authentication. Weak authentication methods (password-only) "
            "are not permitted for remote access to NHS systems."
        ),
        evidence_guidance=(
            "GlobalProtect and Prisma Access enforce MFA via authentication profiles. "
            "BPA-AUTH-001 checks that GP gateways have an authentication profile "
            "configured with MFA or certificate-based auth. BPA-VPN-001 verifies "
            "strong IPsec IKE authentication. Provide BPA auth and VPN check results, "
            "and screenshots of the GP authentication profile configuration."
        ),
        dspt_level="meeting",
    ),
    "DSPT-9.4.2": DsptAssertion(
        id="DSPT-9.4.2",
        title="Privileged Access Controlled and Monitored",
        standard=_S9,
        standard_number=9,
        assertion_ref="9.4.2",
        description=(
            "Privileged administrative access to network devices and systems is "
            "restricted, audited, and subject to enhanced authentication controls."
        ),
        evidence_guidance=(
            "BPA-NET-002 checks that management access (SSH, HTTPS) to NGFW devices "
            "is restricted to specific trusted source addresses rather than 'any'. "
            "BPA-AUTH-002 verifies local admin account hardening. Provide BPA results "
            "and evidence of admin access restrictions in SCM device configuration."
        ),
        dspt_level="meeting",
    ),
    # 9.5 — Vulnerability management and pen testing
    "DSPT-9.5.1": DsptAssertion(
        id="DSPT-9.5.1",
        title="Regular Vulnerability Scanning of Internet-Facing Systems",
        standard=_S9,
        standard_number=9,
        assertion_ref="9.5.1",
        description=(
            "Vulnerability scanning is performed at least quarterly on all "
            "internet-facing systems. Results are tracked and remediated "
            "within defined timescales."
        ),
        evidence_guidance=(
            "HIP (Host Information Profile) checks in GlobalProtect can enforce "
            "endpoint vulnerability scanning requirements (BPA-HIP-001). For "
            "network-layer scanning, provide evidence of a quarterly vulnerability "
            "scan of internet-facing systems (e.g., Qualys, Tenable, Nessus reports). "
            "This assertion requires external tooling evidence beyond SCM configuration."
        ),
        dspt_level="meeting",
    ),
    "DSPT-9.5.2": DsptAssertion(
        id="DSPT-9.5.2",
        title="Annual Penetration Testing of Internet-Facing Systems",
        standard=_S9,
        standard_number=9,
        assertion_ref="9.5.2",
        description=(
            "Penetration testing is carried out at least annually on all "
            "internet-facing systems by a qualified tester (CREST or equivalent). "
            "Critical findings are remediated and retested."
        ),
        evidence_guidance=(
            "Provide the most recent penetration test report (CREST-certified) "
            "covering internet-facing systems. Note any findings relating to the "
            "firewall / Prisma Access configuration and evidence of remediation. "
            "This assertion cannot be evidenced from SCM configuration alone."
        ),
        dspt_level="meeting",
    ),
    # 9.6 — Audit logging and monitoring
    "DSPT-9.6.1": DsptAssertion(
        id="DSPT-9.6.1",
        title="Audit Logs of Network Access Retained for 6+ Months",
        standard=_S9,
        standard_number=9,
        assertion_ref="9.6.1",
        description=(
            "Audit logs recording access to systems and networks are kept for a "
            "minimum of 6 months and are protected from tampering or deletion."
        ),
        evidence_guidance=(
            "SCM security rules must have log-end=yes so all allowed session completions "
            "are logged (BPA-LOG-002, BPA-SR-003). Log forwarding to a SIEM or log "
            "management platform retains logs for ≥6 months (BPA-LOG-001). "
            "BPA-SR-006 verifies log forwarding profiles are attached to security rules. "
            "Provide log forwarding configuration and evidence of log retention policy "
            "(SIEM/Panorama/Cortex XDR retention settings)."
        ),
        dspt_level="meeting",
    ),
    "DSPT-9.6.2": DsptAssertion(
        id="DSPT-9.6.2",
        title="Security Monitoring and Anomaly Detection",
        standard=_S9,
        standard_number=9,
        assertion_ref="9.6.2",
        description=(
            "Security events, exceptions, and anomalies are monitored, alerted on, "
            "and investigated. A process exists to respond to security alerts."
        ),
        evidence_guidance=(
            "Threat logs from SCM NGFW / Prisma Access are forwarded to a SIEM "
            "for monitoring (BPA-LOG-003). SCM incident alerts are surfaced via "
            "`scm_incident_search`. Provide evidence of: (1) SIEM/Cortex XDR "
            "integration receiving threat logs, (2) alert rules covering critical "
            "threats, (3) an incident response process referencing these alerts."
        ),
        dspt_level="meeting",
    ),
    # ── Standard 10 ─────────────────────────────────────────────────────────────
    "DSPT-10.1.1": DsptAssertion(
        id="DSPT-10.1.1",
        title="MSSP / IT Supplier Data Processing Agreements",
        standard=_S10,
        standard_number=10,
        assertion_ref="10.1.1",
        description=(
            "All IT suppliers and managed service providers that process NHS patient "
            "data on behalf of the organisation have a Data Processing Agreement "
            "(DPA) in place, confirming compliance with UK GDPR and the National "
            "Data Guardian's data security standards."
        ),
        evidence_guidance=(
            "As an MSSP managing SCM tenants on behalf of NHS organisations, confirm "
            "that: (1) A DPA is in place between the MSSP and each NHS customer, "
            "(2) The MSSP's own DSPT submission is current (Meeting Standards), "
            "(3) Sub-processors (PAN Networks, AWS/cloud) have DPAs in place. "
            "Provide copies of DPAs and the MSSP's DSPT registration number."
        ),
        dspt_level="meeting",
    ),
    "DSPT-10.2.1": DsptAssertion(
        id="DSPT-10.2.1",
        title="Supplier Security Assurance",
        standard=_S10,
        standard_number=10,
        assertion_ref="10.2.1",
        description=(
            "Regular assurance is obtained from critical IT suppliers that they "
            "maintain appropriate data security standards (e.g., ISO 27001, Cyber "
            "Essentials Plus, or annual DSPT submission)."
        ),
        evidence_guidance=(
            "Palo Alto Networks holds ISO 27001, SOC 2 Type II, and FedRAMP "
            "certifications for the Prisma Access/SCM platform. Request and retain "
            "copies of current certification evidence from PAN. For other sub-processors "
            "in the stack (SIEM vendors, log storage), obtain equivalent assurance. "
            "Document this in your supplier register."
        ),
        dspt_level="meeting",
    ),
}


# Mapping: BPA check ID → list of DSPT assertion IDs
BPA_TO_DSPT: dict[str, list[str]] = {
    # Security rule checks — Standard 9.1 (boundary protection), 9.3 (access control)
    "BPA-SR-001": ["DSPT-9.2.1"],  # TP profiles on allow rules → malware protection
    "BPA-SR-002": ["DSPT-9.1.1", "DSPT-9.3.1"],  # app+service specificity → boundary + access
    "BPA-SR-003": ["DSPT-9.6.1"],  # log-start on rules → audit logging
    "BPA-SR-004": ["DSPT-9.1.1"],  # no any-any-any → boundary protection
    "BPA-SR-005": ["DSPT-9.3.1"],  # source specificity → access restriction
    "BPA-SR-006": ["DSPT-9.6.1"],  # log forwarding profile → audit logging
    "BPA-SR-007": ["DSPT-9.1.1", "DSPT-9.1.2"],  # rule specificity → boundary + segmentation
    "BPA-SR-008": ["DSPT-9.1.1"],  # deny-all default → boundary protection
    "BPA-SR-009": ["DSPT-9.1.2"],  # zero-trust gaps → network segmentation
    "BPA-SR-010": ["DSPT-9.3.1"],  # cleartext protocols → access restriction
    # Threat prevention — Standard 9.2 (malware protection)
    "BPA-TP-001": ["DSPT-9.2.1"],  # antivirus profile → malware
    "BPA-TP-002": ["DSPT-9.2.1"],  # anti-spyware → malware
    "BPA-TP-003": ["DSPT-9.2.1"],  # WildFire → malware (sandboxing)
    "BPA-TP-004": ["DSPT-9.2.1"],  # AV severity actions → malware response
    "BPA-TP-005": ["DSPT-9.2.1"],  # spyware severity actions → malware response
    "BPA-TP-006": ["DSPT-9.2.2"],  # DNS sinkholing → malicious URL/DNS
    "BPA-TP-007": ["DSPT-9.2.1"],  # WildFire file types → malware coverage
    # URL filtering — Standard 9.2.2 (malicious content)
    "BPA-URL-001": ["DSPT-9.2.2"],  # URL filtering profile → malicious URLs
    "BPA-URL-002": ["DSPT-9.2.2"],  # block high-risk categories → malicious URLs
    "BPA-URL-003": ["DSPT-9.2.2"],  # safe search → web content filtering
    # Decryption — Standard 9.2.3 (encrypted traffic inspection)
    "BPA-DEC-001": ["DSPT-9.2.3"],  # decryption profile → TLS inspection
    "BPA-DEC-002": ["DSPT-9.2.3"],  # decryption rule active → TLS inspection
    # Zone protection — Standard 9.1 (boundary/segmentation)
    "BPA-ZP-001": ["DSPT-9.1.1"],  # zone protection profiles → boundary
    "BPA-ZP-002": ["DSPT-9.1.1"],  # zone protection settings → boundary
    "BPA-ZP-003": ["DSPT-9.1.2"],  # zone design → segmentation
    # Logging — Standard 9.6 (audit logging)
    "BPA-LOG-001": ["DSPT-9.6.1"],  # log forwarding destinations → retention
    "BPA-LOG-002": ["DSPT-9.6.1"],  # traffic logs on all rules → audit trail
    "BPA-LOG-003": ["DSPT-9.6.2"],  # threat logs → security monitoring
    # Network design — Standard 9.1 (boundary + segmentation)
    "BPA-NET-001": ["DSPT-9.1.1", "DSPT-9.1.2"],  # security zones → boundary + segmentation
    "BPA-NET-002": ["DSPT-9.4.2"],  # mgmt access restriction → privileged access
    # VPN / cryptography — Standard 9.4 (authentication)
    "BPA-VPN-001": ["DSPT-9.4.1"],  # strong IKE crypto → remote access auth
    "BPA-VPN-002": ["DSPT-9.4.1"],  # DH group strength → remote access auth
    "BPA-VPN-003": ["DSPT-9.4.1"],  # IKEv2 → remote access auth
    "BPA-VPN-004": ["DSPT-9.4.1"],  # PFS → remote access security
    # Authentication — Standard 9.4 (MFA / strong auth)
    "BPA-AUTH-001": ["DSPT-9.4.1"],  # GP MFA → remote access MFA
    "BPA-AUTH-002": ["DSPT-9.4.2"],  # local account hardening → privileged access
    "BPA-AUTH-003": ["DSPT-9.4.1"],  # auth profile on GP gateways → remote access
    # HIP / endpoint posture — Standard 9.5 (vulnerability management)
    "BPA-HIP-001": ["DSPT-9.5.1"],  # HIP patch level check → vulnerability mgmt
    "BPA-HIP-002": ["DSPT-9.2.1"],  # endpoint malware check → malware protection
    "BPA-HIP-003": ["DSPT-9.4.1"],  # HIP posture for access → auth/access
    # NGFW health — Standard 8 (supported/patched systems)
    "BPA-NGW-001": ["DSPT-8.1.1"],  # PAN-OS current → supported systems
    "BPA-NGW-002": ["DSPT-8.1.1", "DSPT-8.3.1"],  # content DB current → patching
    "BPA-NGW-003": ["DSPT-8.3.1"],  # Panorama connectivity → patch management
}


def get_dspt_refs(check_id: str) -> list[str]:
    """Return DSPT assertion IDs that a BPA check ID maps to."""
    return BPA_TO_DSPT.get(check_id, [])
