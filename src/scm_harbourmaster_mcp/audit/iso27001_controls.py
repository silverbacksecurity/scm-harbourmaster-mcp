"""ISO 27001:2022 Annex A control definitions and BPA check mappings.

Only Annex A controls automatable from firewall/SCM configuration are
included. Controls from Clause 5 (Org), 6 (People), 7 (Physical) that
require non-technical evidence are excluded — they require self-assessment
in your ISMS documentation.

Automatable scope: Clause 8 (Technological) + A.5.14 + A.5.28
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Iso27001Control:
    id: str  # e.g. "A.8.7"
    title: str  # Short title from ISO 27001:2022 Annex A
    clause: str  # Clause heading (e.g. "8.7 Protection against malware")
    category: str  # "organizational" | "people" | "physical" | "technological"
    description: str  # What the control requires
    evidence_guidance: str  # What firewall config evidence demonstrates compliance
    implementation_level: str  # "basic" | "advanced"


ISO27001_CONTROLS: dict[str, Iso27001Control] = {
    "A.5.14": Iso27001Control(
        id="A.5.14",
        title="Information transfer",
        clause="5.14 Information transfer",
        category="organizational",
        description=(
            "Rules, procedures and controls shall be in place to protect the transfer "
            "of information through the use of all types of transfer facilities."
        ),
        evidence_guidance=(
            "File blocking profiles restrict transfer of sensitive file types. "
            "DLP data-filtering profiles enforce data classification controls at the perimeter."
        ),
        implementation_level="basic",
    ),
    "A.5.28": Iso27001Control(
        id="A.5.28",
        title="Collection of evidence",
        clause="5.28 Collection of evidence",
        category="organizational",
        description=(
            "The organisation shall establish and implement procedures for the "
            "identification, collection, acquisition, and preservation of evidence "
            "related to information security events."
        ),
        evidence_guidance=(
            "Log forwarding profiles ensure security events are forwarded to a SIEM/syslog "
            "server. All allow rules must have log-at-session-end enabled. Syslog server "
            "profiles must be configured and referenced."
        ),
        implementation_level="basic",
    ),
    "A.8.7": Iso27001Control(
        id="A.8.7",
        title="Protection against malware",
        clause="8.7 Protection against malware",
        category="technological",
        description=(
            "Protection against malware shall be implemented and supported by "
            "appropriate user awareness."
        ),
        evidence_guidance=(
            "Anti-spyware profiles with DNS sinkholing, WildFire AV profiles with "
            "broad file type coverage and block actions, vulnerability protection "
            "profiles, and DNS Security profiles demonstrate malware protection controls."
        ),
        implementation_level="basic",
    ),
    "A.8.15": Iso27001Control(
        id="A.8.15",
        title="Logging",
        clause="8.15 Logging",
        category="technological",
        description=(
            "Logs that record activities, exceptions, faults and other relevant events "
            "shall be produced, stored, protected and analysed."
        ),
        evidence_guidance=(
            "Log forwarding profiles must be configured and applied to all allow rules. "
            "Syslog server profiles must exist. Deny rules must log dropped traffic. "
            "Log retention and forwarding to an external SIEM satisfies this control."
        ),
        implementation_level="basic",
    ),
    "A.8.20": Iso27001Control(
        id="A.8.20",
        title="Networks security",
        clause="8.20 Networks security",
        category="technological",
        description=(
            "Networks and network devices shall be secured, managed and controlled "
            "to protect information in systems and applications."
        ),
        evidence_guidance=(
            "DNS security profiles block malicious domains. URL filtering enforces "
            "web access policy. DoS/flood protection and zone protection profiles "
            "defend network infrastructure. No cleartext protocols (telnet, FTP, etc.) "
            "should be permitted in allow rules."
        ),
        implementation_level="basic",
    ),
    "A.8.21": Iso27001Control(
        id="A.8.21",
        title="Security of network services",
        clause="8.21 Security of network services",
        category="technological",
        description=(
            "Security mechanisms, service levels and service requirements for all "
            "network services shall be identified, implemented and monitored."
        ),
        evidence_guidance=(
            "SSL/TLS decryption profiles with TLS 1.2+ minimum and strong cipher suites "
            "demonstrate encryption controls. Active decrypt rules applying SSL Forward "
            "Proxy inspection satisfy requirements for monitoring encrypted traffic."
        ),
        implementation_level="advanced",
    ),
    "A.8.22": Iso27001Control(
        id="A.8.22",
        title="Segregation of networks",
        clause="8.22 Segregation of networks",
        category="technological",
        description=(
            "Groups of information services, users and information systems shall be "
            "segregated in the organisation's networks."
        ),
        evidence_guidance=(
            "Multiple security zones with inter-zone policy enforcement, absence of "
            "permit-any-any rules, explicit deny-all at rulebase end, and zone-based "
            "HIP checks demonstrate network segregation. MFA and GlobalProtect "
            "enforce user-to-network access control."
        ),
        implementation_level="basic",
    ),
    "A.8.23": Iso27001Control(
        id="A.8.23",
        title="Web filtering",
        clause="8.23 Web filtering",
        category="technological",
        description=(
            "Access to external websites shall be managed to reduce exposure to malicious content."
        ),
        evidence_guidance=(
            "URL filtering profiles with safe search enforcement and explicit blocks "
            "on high-risk categories (malware, phishing, C2, hacking, proxy-avoidance, "
            "dynamic-DNS) applied to allow rules demonstrate web filtering controls."
        ),
        implementation_level="basic",
    ),
    "A.8.24": Iso27001Control(
        id="A.8.24",
        title="Use of cryptography",
        clause="8.24 Use of cryptography",
        category="technological",
        description=(
            "Rules for the effective use of cryptography, including cryptographic "
            "key management, shall be defined and implemented."
        ),
        evidence_guidance=(
            "IKEv2 enforcement, strong IKE crypto profiles (AES-GCM, SHA-256+, DH group 14+), "
            "strong IPSec profiles (AES-GCM, no 3DES/DES), and IPSec PFS enabled on all "
            "profiles demonstrate cryptographic controls for VPN. Remote networks using "
            "IPSec encryption satisfy transit encryption requirements."
        ),
        implementation_level="basic",
    ),
    "A.8.27": Iso27001Control(
        id="A.8.27",
        title="Secure system architecture and engineering principles",
        clause="8.27 Secure system architecture and engineering principles",
        category="technological",
        description=(
            "Principles for engineering secure systems shall be established, documented, "
            "maintained and applied to any information system implementation."
        ),
        evidence_guidance=(
            "Zero-trust rule specificity (no double-any allow rules), App-ID enforcement "
            "on allow rules (no application=any), zone-based segmentation, and "
            "HIP profile usage demonstrate secure architecture principles."
        ),
        implementation_level="advanced",
    ),
    "A.8.28": Iso27001Control(
        id="A.8.28",
        title="Secure coding",
        clause="8.28 Secure coding",
        category="technological",
        description=("Secure coding principles shall be applied to software development."),
        evidence_guidance=(
            "Vulnerability protection profiles with virtual-patching block exploitation "
            "of known CVEs in web applications and services — compensating control for "
            "unpatched or legacy code."
        ),
        implementation_level="advanced",
    ),
    "A.8.29": Iso27001Control(
        id="A.8.29",
        title="Security testing in development and acceptance",
        clause="8.29 Security testing in development and acceptance",
        category="technological",
        description=(
            "Security testing processes shall be defined and implemented in the "
            "development lifecycle."
        ),
        evidence_guidance=(
            "HIP objects enforcing patch management status on endpoints accessing "
            "the network act as a compensating control by verifying devices are "
            "maintained and patched before granting access."
        ),
        implementation_level="advanced",
    ),
}

# BPA check ID → list of ISO 27001:2022 Annex A control IDs
BPA_TO_ISO27001: dict[str, list[str]] = {
    # Security rules
    "BPA-SR-001": ["A.8.7", "A.8.22"],  # Allow rules have security profiles
    "BPA-SR-002": ["A.8.22", "A.8.27"],  # No permit-any-any
    "BPA-SR-003": ["A.5.28", "A.8.15"],  # Allow rules log at session end
    "BPA-SR-004": ["A.8.22"],  # No disabled rules
    "BPA-SR-005": ["A.8.22", "A.8.27"],  # App-ID usage
    "BPA-SR-006": ["A.5.28", "A.8.15"],  # Deny rules log traffic
    "BPA-SR-007": ["A.8.22", "A.8.27"],  # No unrestricted outbound
    "BPA-SR-008": ["A.8.22"],  # Explicit deny-all
    "BPA-SR-009": ["A.8.22", "A.8.27"],  # Zero trust rule specificity
    "BPA-SR-010": ["A.8.20", "A.8.21"],  # No cleartext protocols
    # Threat prevention
    "BPA-TP-001": ["A.8.7"],  # Anti-spyware / DNS sinkhole
    "BPA-TP-002": ["A.8.7"],  # DNS security profiles
    "BPA-TP-003": ["A.8.7", "A.8.28"],  # Vulnerability protection
    "BPA-TP-004": ["A.8.7"],  # WildFire AV
    "BPA-TP-005": ["A.5.14"],  # File blocking / DLP
    "BPA-TP-007": ["A.8.7"],  # WildFire content coverage
    # Decryption
    "BPA-DEC-001": ["A.8.21"],  # Decryption profiles
    "BPA-DEC-002": ["A.8.21"],  # Decryption rules active
    # URL filtering
    "BPA-URL-001": ["A.8.23"],  # URL category filtering
    "BPA-URL-002": ["A.8.23"],  # Block high-risk categories
    # Zone protection
    "BPA-ZP-001": ["A.8.20"],  # Zone protection profiles
    # Logging
    "BPA-LOG-001": ["A.8.15", "A.5.28"],  # Log forwarding profiles
    "BPA-LOG-002": ["A.8.15", "A.5.28"],  # Syslog server profiles
    "BPA-LOG-003": ["A.8.15", "A.5.28"],  # Log forwarding on allow rules
    # Network
    "BPA-NET-001": ["A.8.22"],  # Multiple zones
    "BPA-NET-002": ["A.8.24"],  # Remote network VPN encryption
    # VPN crypto
    "BPA-VPN-001": ["A.8.24"],  # IKEv2 enforcement
    "BPA-VPN-002": ["A.8.24"],  # IKE crypto strength
    "BPA-VPN-003": ["A.8.24"],  # IPSec crypto strength
    "BPA-VPN-004": ["A.8.24"],  # IPSec PFS
    # Auth
    "BPA-AUTH-001": ["A.8.22"],  # MFA in auth profiles
    "BPA-AUTH-002": ["A.8.22"],  # SAML IdP cert validation
    "BPA-AUTH-003": ["A.8.22"],  # Account lockout
    # HIP
    "BPA-HIP-001": ["A.8.29"],  # HIP patch management
    "BPA-HIP-002": ["A.8.29"],  # HIP disk encryption
    "BPA-HIP-003": ["A.8.22", "A.8.29"],  # HIP profiles on rules
    # NGFW
    "BPA-NGW-001": ["A.8.20"],  # NGFW connectivity
    "BPA-NGW-002": ["A.8.20"],  # PAN-OS version uniformity
    "BPA-NGW-003": ["A.8.20"],  # NGFW registered in SCM
}


def get_iso27001_refs(check_id: str) -> list[str]:
    """Return ISO 27001:2022 control IDs for a given BPA check ID."""
    return BPA_TO_ISO27001.get(check_id, [])
