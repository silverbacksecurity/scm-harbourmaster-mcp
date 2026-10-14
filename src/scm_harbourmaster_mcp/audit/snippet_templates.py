"""
Framework snippet templates built from the shared blocks in ``snippet_blocks``.

Each ``build_*_snippet()`` returns a ``SnippetSpec`` for
``tools/snippet_builder.build_and_create_snippet()``. Object descriptions cite
the control each object serves:

  ISO 27001:2022 — Annex A IDs derived from ``iso27001_controls.BPA_TO_ISO27001``
                   for the BPA checks the object satisfies
  NHS DSPT       — Standard 9 assertions whose evidence guidance names the
                   object (``dspt_controls.DSPT_ASSERTIONS``)

The DNS Security and decryption snippets are single-purpose building blocks
that can be layered onto any baseline; they cite the BPA check plus the
ISO 27001 / DSPT controls it evidences. The ransomware-readiness snippet cites
NIST IR 8374 (the CSF ransomware profile) and the SP 800-53 control behind each
kill-chain stage it breaks.

Security rules are excluded — these snippets hold reusable profiles/objects
only; rules stay in the folder rulebase.
"""

from __future__ import annotations

from . import snippet_blocks as b
from .iso27001_controls import ISO27001_CONTROLS, get_iso27001_refs
from .snippet_blocks import SnippetSpec

# Follow-ups shared by the full threat-prevention baselines
_RULEBASE_NEXT_STEPS = (
    "Add deny-all rule to the folder rulebase: "
    "`scm_apply_ncsc_baseline(folder=..., dry_run=False, ticket_ref=...)`",
    "Attach profiles to allow rules: `scm_attach_ncsc_profiles(folder=...)`",
)
_PROFILES_ONLY_NOTE = (
    "This snippet holds profiles and objects only — security and decryption "
    "rules stay in the folder rulebase."
)


def _iso(*checks: str) -> str:
    """ISO 27001:2022 Annex A IDs mapped to *checks*, in catalogue order."""
    refs = {r for c in checks for r in get_iso27001_refs(c)}
    return "/".join(c for c in ISO27001_CONTROLS if c in refs)


# ─── ISO 27001:2022 ───────────────────────────────────────────────────────────

ISO_ANTI_SPYWARE_NAME = "ISO27001-Baseline-AntiSpyware"
ISO_DNS_SECURITY_NAME = "ISO27001-Baseline-DNSSecurity"
ISO_VULN_PROTECTION_NAME = "ISO27001-Baseline-Vulnerability"
ISO_WILDFIRE_NAME = "ISO27001-Baseline-WildFire"
ISO_FILE_BLOCKING_NAME = "ISO27001-Baseline-FileBlocking"
ISO_URL_ACCESS_NAME = "ISO27001-Baseline-URL"
ISO_DECRYPTION_NAME = "ISO27001-Baseline-Decryption"
ISO_LOG_FORWARDING_NAME = "ISO27001-Baseline-Logging"
ISO_TAG_NAME = "ISO27001-Compliant"


def build_iso27001_snippet(snippet_name: str, syslog_profile: str | None = None) -> SnippetSpec:
    """
    Return the ISO 27001:2022 Annex A baseline scoped to *snippet_name*.

    Covers the automatable technological controls: A.8.7 malware, A.8.15 /
    A.5.28 logging and evidence, A.8.21 network services (decryption), A.8.23
    web filtering, A.8.28 virtual patching and A.5.14 information transfer.

    Args:
        snippet_name: Target SCM snippet name (e.g. ``"ISO27001-Compliance"``).
        syslog_profile: Optional syslog server profile name for log forwarding.
    """
    s = snippet_name
    profiles = (
        # A.8.7 — BPA-TP-001 anti-spyware with C2 detection
        b.anti_spyware(
            ISO_ANTI_SPYWARE_NAME,
            f"ISO 27001:2022 {_iso('BPA-TP-001')} — blocks critical+high spyware, C2 detection",
            s,
        ),
        # A.8.7 — BPA-TP-002 DNS Security sinkholing
        b.dns_security(
            ISO_DNS_SECURITY_NAME,
            f"ISO 27001:2022 {_iso('BPA-TP-002')} — sinkholes malicious and C2 domains",
            s,
        ),
        # A.8.7 / A.8.28 — BPA-TP-003 virtual patching of known CVEs
        b.vulnerability(
            ISO_VULN_PROTECTION_NAME,
            f"ISO 27001:2022 {_iso('BPA-TP-003')} — reset-both on critical+high CVEs",
            s,
        ),
        # A.8.7 — BPA-TP-004 / BPA-TP-007 WildFire coverage of every file type
        b.wildfire(
            ISO_WILDFIRE_NAME,
            f"ISO 27001:2022 {_iso('BPA-TP-004', 'BPA-TP-007')} — WildFire analysis, all files",
            s,
        ),
        # A.5.14 — BPA-TP-005 file blocking on transfers
        b.file_blocking(
            ISO_FILE_BLOCKING_NAME,
            f"ISO 27001:2022 {_iso('BPA-TP-005')} — blocks high-risk file types, alerts the rest",
            s,
        ),
        # A.8.23 — BPA-URL-001 / BPA-URL-002 web filtering with safe search,
        # which the A.8.23 evidence guidance calls for
        b.url_access(
            ISO_URL_ACCESS_NAME,
            f"ISO 27001:2022 {_iso('BPA-URL-001', 'BPA-URL-002')} — blocks malware, C2, "
            "phishing; safe search",
            s,
            safe_search=True,
        ),
        # A.8.21 — BPA-DEC-001 decryption profile, TLS 1.2+ and certificate checks
        b.decryption_profile(ISO_DECRYPTION_NAME, s),
        # A.8.15 / A.5.28 — BPA-LOG-001 log forwarding for evidence collection
        b.log_forwarding(
            ISO_LOG_FORWARDING_NAME,
            f"ISO 27001:2022 {_iso('BPA-LOG-001')} — traffic, threat, WildFire, URL, auth logs",
            s,
            syslog_profile,
        ),
    )
    return SnippetSpec(
        label="ISO 27001",
        snippet=s,
        sections=(
            ("Security Profiles", profiles),
            (
                "Tag",
                (
                    b.tag(
                        ISO_TAG_NAME,
                        s,
                        "Azure Blue",
                        "Managed by scm-harbourmaster-mcp ISO 27001:2022 baseline",
                    ),
                ),
            ),
        ),
        log_event="iso27001_snippet_create_failed",
        dry_run_note=_PROFILES_ONLY_NOTE,
        next_steps=(
            *_RULEBASE_NEXT_STEPS,
            f"Reference `{ISO_DECRYPTION_NAME}` from your decryption rules (A.8.21) — "
            "`scm_decrypt_policy_audit` shows current coverage",
        ),
    )


# ─── NHS DSPT ─────────────────────────────────────────────────────────────────

DSPT_ANTI_SPYWARE_NAME = "DSPT-Baseline-AntiSpyware"
DSPT_VULN_PROTECTION_NAME = "DSPT-Baseline-Vulnerability"
DSPT_WILDFIRE_NAME = "DSPT-Baseline-WildFire"
DSPT_DNS_SECURITY_NAME = "DSPT-Baseline-DNSSecurity"
DSPT_URL_ACCESS_NAME = "DSPT-Baseline-URL"
DSPT_DECRYPTION_NAME = "DSPT-Baseline-Decryption"
DSPT_LOG_FORWARDING_NAME = "DSPT-Baseline-Logging"
DSPT_TAG_NAME = "DSPT-Compliant"


def build_dspt_snippet(snippet_name: str, syslog_profile: str | None = None) -> SnippetSpec:
    """
    Return the NHS DSPT Standard 9 baseline scoped to *snippet_name*.

    Covers the assertions SCM configuration evidences: 9.2.1 anti-malware,
    9.2.2 URL and DNS filtering, 9.2.3 encrypted traffic inspection, 9.6.1
    audit logging and 9.6.2 security monitoring.

    Args:
        snippet_name: Target SCM snippet name (e.g. ``"DSPT-Compliance"``).
        syslog_profile: Optional syslog server profile name for log forwarding
            (9.6.1 needs ≥6 months retention — point it at the SIEM).
    """
    s = snippet_name
    profiles = (
        # 9.2.1 — threat prevention, anti-spyware and WildFire on network traffic
        b.anti_spyware(
            DSPT_ANTI_SPYWARE_NAME,
            "NHS DSPT 9.2.1 — blocks critical+high spyware, C2 detection",
            s,
        ),
        b.vulnerability(
            DSPT_VULN_PROTECTION_NAME,
            "NHS DSPT 9.2.1 — reset-both on critical+high CVEs",
            s,
        ),
        b.wildfire(
            DSPT_WILDFIRE_NAME,
            "NHS DSPT 9.2.1 — WildFire sandboxing for all file types",
            s,
        ),
        # 9.2.2 — "DNS security is configured to sinkhole malicious domains"
        b.dns_security(
            DSPT_DNS_SECURITY_NAME,
            "NHS DSPT 9.2.2 — sinkholes malicious and C2 domains",
            s,
        ),
        # 9.2.2 — URL filtering blocks malicious, phishing and C2 categories
        b.url_access(
            DSPT_URL_ACCESS_NAME,
            "NHS DSPT 9.2.2 — blocks malware, C2, phishing categories",
            s,
        ),
        # 9.2.3 — decryption profile that enforces certificate verification
        b.decryption_profile(DSPT_DECRYPTION_NAME, s),
        # 9.6.1 / 9.6.2 — session and threat logs forwarded for retention and monitoring
        b.log_forwarding(
            DSPT_LOG_FORWARDING_NAME,
            "NHS DSPT 9.6.1/9.6.2 — traffic, threat, WildFire, URL, auth logs",
            s,
            syslog_profile,
        ),
    )
    return SnippetSpec(
        label="DSPT",
        snippet=s,
        sections=(
            ("Security Profiles", profiles),
            (
                "Tag",
                (
                    b.tag(
                        DSPT_TAG_NAME,
                        s,
                        "Cobalt Blue",
                        "Managed by scm-harbourmaster-mcp NHS DSPT baseline",
                    ),
                ),
            ),
        ),
        log_event="dspt_snippet_create_failed",
        dry_run_note=_PROFILES_ONLY_NOTE,
        next_steps=(
            *_RULEBASE_NEXT_STEPS,
            f"Reference `{DSPT_DECRYPTION_NAME}` from your decryption rules (9.2.3)",
            "Evidence the assertions with `scm_dspt_assess` and attach the export in the "
            "DSPT portal",
        ),
    )


# ─── DNS Security / sinkhole (building block) ─────────────────────────────────

DNS_SECURITY_PROFILE_NAME = "DNS-Security-Baseline"
DNS_SECURITY_TAG_NAME = "DNS-Security-Managed"


def build_dns_security_snippet(snippet_name: str) -> SnippetSpec:
    """
    Return the standalone DNS Security sinkhole profile scoped to *snippet_name*.

    The same profile the ISO 27001 and DSPT snippets carry, split out so it can
    be layered onto any baseline: BPA-TP-002 → ISO 27001:2022 A.8.7, NHS DSPT
    9.2.2 ("DNS security is configured to sinkhole malicious domains").

    Args:
        snippet_name: Target SCM snippet name (e.g. ``"DNS-Security"``).
    """
    s = snippet_name
    return SnippetSpec(
        label="DNS Security",
        snippet=s,
        sections=(
            (
                "DNS Security Profile",
                (
                    b.dns_security(
                        DNS_SECURITY_PROFILE_NAME,
                        f"BPA-TP-002 — ISO 27001:2022 {_iso('BPA-TP-002')} / NHS DSPT 9.2.2 — "
                        "sinkholes C2, malware, phishing and new domains",
                        s,
                    ),
                ),
            ),
            (
                "Tag",
                (
                    b.tag(
                        DNS_SECURITY_TAG_NAME,
                        s,
                        "Turquoise Blue",
                        "Managed by scm-harbourmaster-mcp DNS Security baseline",
                    ),
                ),
            ),
        ),
        log_event="dns_security_snippet_create_failed",
        dry_run_note=_PROFILES_ONLY_NOTE,
        next_steps=(
            f"Add `{DNS_SECURITY_PROFILE_NAME}` to the profile group on your allow rules — "
            "the category sinkholes need the DNS Security licence; the "
            "`default-paloalto-dns` signature list works without it",
            "Sinkholed lookups are logged as threats, often with the internal DNS "
            "resolver as source — find the infected host from traffic logs to the "
            "sinkhole address",
        ),
    )


# ─── SSL/TLS decryption best practice (building block) ───────────────────────

DECRYPTION_PROFILE_NAME = "Decryption-Baseline"
NO_DECRYPT_PROFILE_NAME = "Decryption-Baseline-NoDecrypt"
NO_DECRYPT_CATEGORY_NAME = "Decryption-Baseline-Exclusions"
DECRYPTION_TAG_NAME = "Decryption-Managed"


def build_decryption_snippet(snippet_name: str) -> SnippetSpec:
    """
    Return the SSL/TLS decryption best-practice set scoped to *snippet_name*.

    BPA-DEC-001 → ISO 27001:2022 A.8.21, NHS DSPT 9.2.3:
      - forward-proxy + inbound-inspection profile (TLS 1.2+, no MD5/SHA-1/
        3DES/RC4/RSA key exchange, block expired/untrusted/unknown certificates)
      - no-decrypt profile that still blocks expired / untrusted server certs
      - "Category Match" URL category of privacy-sensitive categories
        (financial services, health, government) for the no-decrypt rule

    Args:
        snippet_name: Target SCM snippet name (e.g. ``"Decryption-Baseline"``).
    """
    s = snippet_name
    return SnippetSpec(
        label="Decryption",
        snippet=s,
        sections=(
            (
                "Decryption Profiles",
                (
                    # A.8.21 / DSPT 9.2.3 — decrypt profile with certificate checks
                    b.decryption_profile(DECRYPTION_PROFILE_NAME, s),
                    # A.8.21 — exclusions keep server-certificate validation
                    b.no_decrypt_profile(NO_DECRYPT_PROFILE_NAME, s),
                ),
            ),
            (
                "No-Decrypt Exclusions",
                (
                    b.no_decrypt_category(
                        NO_DECRYPT_CATEGORY_NAME,
                        f"ISO 27001:2022 {_iso('BPA-DEC-001')} / NHS DSPT 9.2.3 — "
                        "privacy-sensitive categories left undecrypted",
                        s,
                    ),
                ),
            ),
            (
                "Tag",
                (
                    b.tag(
                        DECRYPTION_TAG_NAME,
                        s,
                        "Gold",
                        "Managed by scm-harbourmaster-mcp decryption baseline",
                    ),
                ),
            ),
        ),
        log_event="decryption_snippet_create_failed",
        dry_run_note=_PROFILES_ONLY_NOTE,
        next_steps=(
            f"Add a no-decrypt rule matching URL category `{NO_DECRYPT_CATEGORY_NAME}` "
            f"with profile `{NO_DECRYPT_PROFILE_NAME}`, above your decrypt rules",
            f"Add decrypt rules (SSL Forward Proxy) with profile `{DECRYPTION_PROFILE_NAME}`; "
            "enabled decrypt rules only push once a forward-trust certificate is selected",
            "Check coverage with `scm_decrypt_policy_audit`",
        ),
    )


# ─── Ransomware readiness ─────────────────────────────────────────────────────

RANSOMWARE_ANTI_SPYWARE_NAME = "Ransomware-AntiSpyware"
RANSOMWARE_DNS_SECURITY_NAME = "Ransomware-DNSSecurity"
RANSOMWARE_VULN_PROTECTION_NAME = "Ransomware-Vulnerability"
RANSOMWARE_WILDFIRE_NAME = "Ransomware-WildFire"
RANSOMWARE_FILE_BLOCKING_NAME = "Ransomware-FileBlocking"
RANSOMWARE_URL_ACCESS_NAME = "Ransomware-URL"
RANSOMWARE_LOG_FORWARDING_NAME = "Ransomware-Logging"
RANSOMWARE_TAG_NAME = "Ransomware-Ready"

_IR8374 = "NIST IR 8374"  # Ransomware Risk Management: a CSF profile


def build_ransomware_snippet(snippet_name: str, syslog_profile: str | None = None) -> SnippetSpec:
    """
    Return the ransomware-readiness profile set scoped to *snippet_name*.

    Breaks the ransomware kill chain at each network stage, per NIST IR 8374
    (the CSF ransomware profile) and SP 800-53:
      delivery   — URL filtering, WildFire, file blocking of scripts and
                   password-protected archives (SI-3, SC-7)
      exploit    — vulnerability protection, including SMB exploits on
                   east-west rules (SI-2, RA-5)
      C2 / DGA   — anti-spyware C2 detectors + DNS Security sinkhole (SI-4)
      response   — full log forwarding for investigation (AU-2, AU-12)

    Args:
        snippet_name: Target SCM snippet name (e.g. ``"Ransomware-Readiness"``).
        syslog_profile: Optional syslog server profile name for log forwarding.
    """
    s = snippet_name
    profiles = (
        # SI-4 — C2 beaconing is how ransomware operators reach the host
        b.anti_spyware(
            RANSOMWARE_ANTI_SPYWARE_NAME,
            f"{_IR8374} / SP 800-53 SI-4 — blocks C2 and critical+high spyware",
            s,
        ),
        # SI-4 — DGA and newly registered domains are sinkholed
        b.dns_security(
            RANSOMWARE_DNS_SECURITY_NAME,
            f"{_IR8374} / SP 800-53 SI-4 — sinkholes C2, DGA and new domains",
            s,
        ),
        # SI-2 / RA-5 — blocks the exploits (SMB, RDP, VPN) used for entry and spread
        b.vulnerability(
            RANSOMWARE_VULN_PROTECTION_NAME,
            f"{_IR8374} / SP 800-53 SI-2/RA-5 — reset-both on critical+high CVEs",
            s,
        ),
        # SI-3 — WildFire detonates unknown droppers and loaders
        b.wildfire(
            RANSOMWARE_WILDFIRE_NAME,
            f"{_IR8374} / SP 800-53 SI-3 — WildFire analysis, all files",
            s,
        ),
        # SI-3 / SC-7 — scripts and encrypted archives are the usual droppers
        b.file_blocking(
            RANSOMWARE_FILE_BLOCKING_NAME,
            f"{_IR8374} / SP 800-53 SI-3/SC-7 — blocks scripts and encrypted archives",
            s,
            extra_block=b.ENCRYPTED_ARCHIVE_TYPES,
        ),
        # SC-7 — phishing and malware delivery sites
        b.url_access(
            RANSOMWARE_URL_ACCESS_NAME,
            f"{_IR8374} / SP 800-53 SC-7 — blocks malware, C2, phishing categories",
            s,
        ),
        # AU-2 / AU-12 — the evidence an incident responder needs
        b.log_forwarding(
            RANSOMWARE_LOG_FORWARDING_NAME,
            f"{_IR8374} / SP 800-53 AU-2/AU-12 — traffic, threat, WildFire, URL, auth logs",
            s,
            syslog_profile,
        ),
    )
    return SnippetSpec(
        label="Ransomware Readiness",
        snippet=s,
        sections=(
            ("Security Profiles", profiles),
            (
                "Tag",
                (
                    b.tag(
                        RANSOMWARE_TAG_NAME,
                        s,
                        "Maroon",
                        "Managed by scm-harbourmaster-mcp ransomware-readiness baseline",
                    ),
                ),
            ),
        ),
        log_event="ransomware_snippet_create_failed",
        dry_run_note=_PROFILES_ONLY_NOTE,
        next_steps=(
            *_RULEBASE_NEXT_STEPS,
            "Attach the profiles to east-west and intrazone allow rules too — SMB and RDP "
            "lateral movement is inspected there (SMB is not TLS, no decryption needed)",
            "Isolate backup traffic: put backup servers in their own zone and allow only "
            "the backup applications between them and protected hosts — deny SMB/RDP from "
            "user zones to backup repositories",
        ),
    )
