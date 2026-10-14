"""
Shared snippet template plumbing for the ``scm_create_*_snippet`` tools.

``SnippetSpec`` is everything one compliance snippet writes — the ordered
(sdk_attr, payload) sections plus the framework-specific wording of the tool
output — so ``tools/snippet_builder.build_and_create_snippet()`` can create
any of them with one create / dry-run / error-handling path.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# (pan-scm-sdk client attribute, create() payload)
SnippetObject = tuple[str, dict[str, Any]]


@dataclass(frozen=True)
class SnippetSpec:
    """One framework's snippet: payloads to create plus the tool's output wording."""

    label: str  # framework label in the output, e.g. "NCSC"
    snippet: str  # target snippet name every payload is scoped to
    # (section heading, objects) in creation order — profiles before the
    # groups/tags that may reference them
    sections: tuple[tuple[str, tuple[SnippetObject, ...]], ...]
    log_event: str  # structlog event name for a failed object create
    dry_run_note: str = ""  # appended to the dry-run footer as "Note: ..."
    # Follow-ups after a clean apply; "assign/associate the snippet" is always
    # step 1 and is added by the builder
    next_steps: tuple[str, ...] = ()

    @property
    def objects(self) -> list[SnippetObject]:
        """Every (sdk_attr, payload) pair across all sections, in order."""
        return [obj for _, objs in self.sections for obj in objs]


# ─── Reusable payload builders ────────────────────────────────────────────────
#
# Each returns an (sdk_attr, payload) pair scoped to a snippet. Threat-profile
# settings mirror the NCSC/NIST baselines (audit/ncsc_templates.py) so every
# framework snippet enforces the same floor; callers supply the name and a
# description citing the control the object serves.
#
# Every payload must validate against the pan-scm-sdk create model for its
# sdk_attr. create() dumps without by_alias, so aliased fields (the URL
# profile's ``continue``) are never set here.

# MICA inline C2 detectors — same set as the NCSC/NIST anti-spyware profiles
_MICA_C2_DETECTORS = (
    "HTTP Command and Control detector",
    "HTTP2 Command and Control detector",
    "SSL Command and Control detector",
    "Unknown-TCP Command and Control detector",
    "Unknown-UDP Command and Control detector",
)

# URL categories the NCSC/NIST baselines block / alert on
URL_BLOCK_CATEGORIES = ("command-and-control", "malware", "phishing", "hacking", "dynamic-dns")
URL_ALERT_CATEGORIES = ("unknown", "proxy-avoidance-and-anonymizers", "questionable")

# Script and legacy executable formats with little legitimate web use; blocked
# in both directions. Every other type is alerted so transfers stay visible.
FILE_BLOCK_TYPES = (
    "bat",
    "chm",
    "cpl",
    "hlp",
    "hta",
    "jar",
    "ocx",
    "pif",
    "scr",
    "torrent",
    "vbe",
    "wsf",
)
# Password-protected archives hide their payload from WildFire and AV — a
# common ransomware dropper wrapper
ENCRYPTED_ARCHIVE_TYPES = ("encrypted-rar", "encrypted-zip")

# DNS Security categories: sinkhole everything malicious or high-risk, so an
# infected host shows up in threat logs by its sinkhole lookups; ad-tracking
# and parked domains keep PAN's default action.
DNS_SINKHOLE_CATEGORIES = (
    "pan-dns-sec-cc",  # C2, including DGA domains
    "pan-dns-sec-ddns",
    "pan-dns-sec-grayware",
    "pan-dns-sec-malware",
    "pan-dns-sec-phishing",
    "pan-dns-sec-proxy",
    "pan-dns-sec-recent",  # newly registered domains
)
DNS_DEFAULT_CATEGORIES = ("pan-dns-sec-adtracking", "pan-dns-sec-parked")

# Privacy-sensitive categories best practice leaves undecrypted
NO_DECRYPT_CATEGORIES = ("financial-services", "health-and-medicine", "government")


def anti_spyware(name: str, description: str, snippet: str) -> SnippetObject:
    """Block critical+high spyware, alert medium, MICA inline C2 detectors."""
    return (
        "anti_spyware_profile",
        {
            "name": name,
            "description": description,
            "snippet": snippet,
            "cloud_inline_analysis": True,
            "mica_engine_spyware_enabled": [
                {"name": d, "inline_policy_action": "reset-both"} for d in _MICA_C2_DETECTORS
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
        },
    )


def vulnerability(name: str, description: str, snippet: str) -> SnippetObject:
    """Reset-both on critical+high CVEs (with packet capture), alert medium."""

    def _rule(rule: str, severity: list[str], action: str, pcap: str) -> dict[str, Any]:
        return {
            "name": rule,
            "severity": severity,
            "cve": ["any"],
            "vendor_id": ["any"],
            "threat_name": "any",
            "host": "any",
            "category": "any",
            "action": action,
            "packet_capture": pcap,
        }

    return (
        "vulnerability_protection_profile",
        {
            "name": name,
            "description": description,
            "snippet": snippet,
            "rules": [
                _rule("block-critical-high", ["critical", "high"], "reset_both", "single-packet"),
                _rule("alert-medium", ["medium"], "alert", "disable"),
                _rule("allow-low-info", ["low", "informational"], "allow", "disable"),
            ],
        },
    )


def wildfire(name: str, description: str, snippet: str) -> SnippetObject:
    """WildFire public-cloud analysis for every file type, both directions."""
    return (
        "wildfire_antivirus_profile",
        {
            "name": name,
            "description": description,
            "snippet": snippet,
            "rules": [
                {
                    "name": "all-files-both-directions",
                    "application": ["any"],
                    "direction": "both",
                    "file_type": ["any"],
                    "analysis": "public-cloud",
                }
            ],
        },
    )


def url_access(
    name: str, description: str, snippet: str, *, safe_search: bool = False
) -> SnippetObject:
    """Block malware/C2/phishing categories, alert risky ones, inline categorisation."""
    payload: dict[str, Any] = {
        "name": name,
        "description": description,
        "snippet": snippet,
        "block": list(URL_BLOCK_CATEGORIES),
        "alert": list(URL_ALERT_CATEGORIES),
        "cloud_inline_cat": True,
        "local_inline_cat": True,
    }
    if safe_search:
        # Blocks search results unless the engine's strict safe search is on;
        # only effective on decrypted traffic
        payload["safe_search_enforcement"] = True
    return ("url_access_profile", payload)


def log_forwarding(
    name: str, description: str, snippet: str, syslog_profile: str | None = None
) -> SnippetObject:
    """Traffic, threat, WildFire, URL and auth logs to Cortex Data Lake (+ optional syslog)."""

    def _entry(entry: str, log_type: str) -> dict[str, Any]:
        e: dict[str, Any] = {
            "name": entry,
            "log_type": log_type,
            "filter": "All Logs",
            "send_to_panorama": True,
            "quarantine": False,
        }
        if syslog_profile:
            e["send_syslog"] = [syslog_profile]
        return e

    return (
        "log_forwarding_profile",
        {
            "name": name,
            "description": description,
            "snippet": snippet,
            "match_list": [
                _entry("traffic-logs", "traffic"),
                _entry("threat-logs", "threat"),
                _entry("wildfire-logs", "wildfire"),
                _entry("url-logs", "url"),
                _entry("auth-logs", "auth"),
            ],
        },
    )


def dns_security(name: str, description: str, snippet: str) -> SnippetObject:
    """Sinkhole malicious DNS Security categories and PAN's default DNS signature list."""
    categories = [
        {"name": c, "action": "sinkhole", "log_level": "default", "packet_capture": "disable"}
        for c in DNS_SINKHOLE_CATEGORIES
    ] + [
        {"name": c, "action": "default", "log_level": "default", "packet_capture": "disable"}
        for c in DNS_DEFAULT_CATEGORIES
    ]
    return (
        "dns_security_profile",
        {
            "name": name,
            "description": description,
            "snippet": snippet,
            "botnet_domains": {
                "dns_security_categories": categories,
                # Content-based DNS signatures — sinkholed even without the
                # DNS Security licence
                "lists": [
                    {
                        "name": "default-paloalto-dns",
                        "action": {"sinkhole": {}},
                        "packet_capture": "disable",
                    }
                ],
                "sinkhole": {"ipv4_address": "pan-sinkhole-default-ip", "ipv6_address": "::1"},
            },
        },
    )


def file_blocking(
    name: str, description: str, snippet: str, *, extra_block: tuple[str, ...] = ()
) -> SnippetObject:
    """Block high-risk file types both ways; alert on every other transfer."""
    return (
        "file_blocking_profile",
        {
            "name": name,
            "description": description,
            "snippet": snippet,
            "rules": [
                {
                    "name": "block-high-risk-types",
                    "action": "block",
                    "application": ["any"],
                    "direction": "both",
                    "file_type": [*FILE_BLOCK_TYPES, *extra_block],
                },
                {
                    "name": "alert-all-other-types",
                    "action": "alert",
                    "application": ["any"],
                    "direction": "both",
                    "file_type": ["any"],
                },
            ],
        },
    )


# TLS 1.2+ with AES and SHA-2 only; RSA key exchange off so every decrypted
# session keeps forward secrecy. Every flag is set explicitly — the API applies
# its own permissive defaults to anything left out.
_PROTOCOL_SETTINGS: dict[str, Any] = {
    "min_version": "tls1-2",
    "max_version": "max",
    "auth_algo_md5": False,
    "auth_algo_sha1": False,
    "auth_algo_sha256": True,
    "auth_algo_sha384": True,
    "enc_algo_3des": False,
    "enc_algo_rc4": False,
    "enc_algo_aes_128_cbc": True,
    "enc_algo_aes_256_cbc": True,
    "enc_algo_aes_128_gcm": True,
    "enc_algo_aes_256_gcm": True,
    "enc_algo_chacha20_poly1305": True,
    "keyxchg_algo_dhe": True,
    "keyxchg_algo_ecdhe": True,
    "keyxchg_algo_rsa": False,
}


def decryption_profile(name: str, snippet: str) -> SnippetObject:
    """Forward-proxy and inbound-inspection profile that enforces certificate checks.

    Decryption profiles have no description field, so the caller's code
    comment carries the control citation.
    """
    return (
        "decryption_profile",
        {
            "name": name,
            "snippet": snippet,
            "ssl_forward_proxy": {
                "auto_include_altname": True,
                "block_client_cert": False,
                "block_expired_certificate": True,
                "block_timeout_cert": True,
                "block_tls13_downgrade_no_resource": False,
                "block_unknown_cert": True,
                "block_unsupported_cipher": True,
                "block_unsupported_version": True,
                "block_untrusted_issuer": True,
                "restrict_cert_exts": False,
                "strip_alpn": False,
            },
            "ssl_inbound_proxy": {
                "block_if_hsm_unavailable": False,
                "block_if_no_resource": True,
                "block_unsupported_cipher": True,
                "block_unsupported_version": True,
            },
            "ssl_no_proxy": {
                "block_expired_certificate": True,
                "block_untrusted_issuer": True,
            },
            "ssl_protocol_settings": dict(_PROTOCOL_SETTINGS),
        },
    )


def no_decrypt_profile(name: str, snippet: str) -> SnippetObject:
    """Profile for no-decrypt rules: still blocks expired / untrusted server certs."""
    return (
        "decryption_profile",
        {
            "name": name,
            "snippet": snippet,
            "ssl_no_proxy": {
                "block_expired_certificate": True,
                "block_untrusted_issuer": True,
            },
        },
    )


def no_decrypt_category(name: str, description: str, snippet: str) -> SnippetObject:
    """Custom "Category Match" URL category holding a no-decrypt rule's exclusions."""
    return (
        "url_category",
        {
            "name": name,
            "description": description,
            "snippet": snippet,
            "type": "Category Match",
            "list": list(NO_DECRYPT_CATEGORIES),
        },
    )


def tag(name: str, snippet: str, color: str, comments: str) -> SnippetObject:
    """Marker tag for the objects and rules a framework baseline covers."""
    return ("tag", {"name": name, "snippet": snippet, "color": color, "comments": comments})
