"""
MCP tools for NCSC/NIST baseline, compliance snippets and gap analysis.

  scm_apply_ncsc_baseline      — push NCSC-compliant security profiles + deny-all rule
  scm_create_ncsc_snippet      — create NCSC baseline as a reusable SCM snippet
  scm_attach_ncsc_profiles     — create NCSC-Baseline profile group + attach to allow rules
  scm_ncsc_gap                 — compare live config against NCSC baseline (CAF/CE/10 Steps)
  scm_create_nist_snippet      — create NIST CSF / SP 800-53 baseline as a reusable SCM snippet
  scm_create_iso27001_snippet  — create ISO 27001:2022 Annex A baseline as an SCM snippet
  scm_create_dspt_snippet      — create NHS DSPT Standard 9 baseline as an SCM snippet
  scm_create_dns_security_snippet — create a standalone DNS Security sinkhole snippet
  scm_create_decryption_snippet   — create an SSL/TLS decryption best-practice snippet
  scm_create_ransomware_snippet   — create a ransomware-readiness (NIST IR 8374) snippet
  scm_nist_gap                 — compare live config against NIST baseline (CSF/SP 800-53/800-171)
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..audit import nist_templates as _nist
from ..audit.extractor import list_with_rest_fallback
from ..audit.ncsc_templates import (
    ANTI_SPYWARE_NAME,
    DENY_ALL_RULE_NAME,
    LOG_FORWARDING_NAME,
    TAG_NAME,
    URL_ACCESS_NAME,
    VULN_PROTECTION_NAME,
    WILDFIRE_NAME,
    GapItem,
    build_snippet_templates,
    build_templates,
    check_anti_spyware_profiles,
    check_log_forwarding,
    check_security_rules,
)
from ..audit.snippet_blocks import SnippetSpec
from ..audit.snippet_templates import (
    build_decryption_snippet,
    build_dns_security_snippet,
    build_dspt_snippet,
    build_iso27001_snippet,
    build_ransomware_snippet,
)
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool
from ..utils.write_safety import audit_write, normalize_ticket_ref, ticket_ref_error
from .snippet_builder import build_and_create_snippet

logger = get_logger(__name__)

# Follow-ups shared by the baseline snippets: their profiles need a deny-all
# rule and a profile group on allow rules, which only a folder rulebase holds.
_BASELINE_NEXT_STEPS = (
    "Add deny-all rule to the folder rulebase: "
    "`scm_apply_ncsc_baseline(folder=..., dry_run=False, ticket_ref=...)`",
    "Attach profiles to allow rules: `scm_attach_ncsc_profiles(folder=...)`",
)


def register_ncsc_tools(mcp: FastMCP, get_client: Callable[..., Any]) -> None:
    """Register NCSC baseline tools with the MCP server."""
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_apply_ncsc_baseline(
        client: Any,
        tenant_id: str,
        folder: str,
        dry_run: bool = True,
        ticket_ref: str = "",
        syslog_profile: str = "",
        overwrite_existing: bool = False,
    ) -> str:
        """
        Create NCSC-compliant security profiles and deny-all rule in a SCM folder.

        Creates:
          - Anti-spyware profile with cloud inline analysis + MICA C2 detectors
          - Vulnerability protection profile (block critical/high, alert medium)
          - WildFire antivirus profile (all files, both directions)
          - URL access profile (block malware/C2/phishing categories)
          - Log forwarding profile (traffic/threat/wildfire/url/auth → Cortex Data Lake)
          - Explicit deny-all security rule with logging
          - NCSC-Compliant tag

        NCSC compliance mapping:
          CAF v4.0  — C3 Identity/Access, C4 Data security, C5 Security monitoring
          CE v3.2   — Malware protection, Patch management, Network monitoring
          10 Steps  — Network security, Malware defences, Monitoring

        Args:
            folder: Target SCM folder (e.g. "Shared" or a tenant folder name).
            tenant_id: SCM tenant ID. Defaults to the active tenant.
            dry_run: If True (default) show what WOULD be created without writing.
            ticket_ref: Mandatory change-ticket reference (never sent to SCM).
            syslog_profile: Optional syslog server profile name to add to log forwarding.
            overwrite_existing: If True, skip objects that already exist silently.
        """
        err = ticket_ref_error(ticket_ref)
        if err:
            return f"Error: {err}"
        ticket_ref = normalize_ticket_ref(ticket_ref)
        if not dry_run:
            audit_write("scm_apply_ncsc_baseline", ticket_ref, tenant_id, folder=folder)

        templates = build_templates(folder, syslog_profile=syslog_profile or None)

        results: list[str] = []
        created = 0
        skipped = 0
        failed = 0

        def _apply(sdk_attr: str, payload: dict[str, Any], display_name: str) -> None:
            nonlocal created, skipped, failed
            if dry_run:
                results.append(f"  [DRY-RUN] would create {display_name}")
                created += 1
                return

            resource = getattr(client, sdk_attr, None)
            if resource is None:
                results.append(f"  [SKIP] {display_name} — SDK attr '{sdk_attr}' not available")
                skipped += 1
                return

            try:
                obj = resource.create(payload)
                results.append(f"  [OK] Created {display_name} (id={getattr(obj, 'id', '?')})")
                created += 1
            except Exception as exc:
                msg = str(exc)
                if "already exists" in msg.lower() or "duplicate" in msg.lower():
                    results.append(f"  [SKIP] {display_name} already exists")
                    skipped += 1
                else:
                    results.append(f"  [FAIL] {display_name}: {msg}")
                    failed += 1
                    logger.warning("ncsc_baseline_create_failed", object=display_name, error=msg)

        mode = "DRY-RUN" if dry_run else "APPLY"
        results.append(f"## NCSC Baseline — {mode} to folder '{folder}'\n")

        results.append("### Security Profiles")
        _apply("anti_spyware_profile", templates.anti_spyware, ANTI_SPYWARE_NAME)
        _apply("vulnerability_protection_profile", templates.vulnerability, VULN_PROTECTION_NAME)
        _apply("wildfire_antivirus_profile", templates.wildfire, WILDFIRE_NAME)
        _apply("url_access_profile", templates.url_access, URL_ACCESS_NAME)
        _apply("log_forwarding_profile", templates.log_forwarding, LOG_FORWARDING_NAME)

        results.append("\n### Tag")
        _apply("tag", templates.tag, TAG_NAME)

        results.append("\n### Security Rule")
        _apply("security_rule", templates.deny_all_rule, DENY_ALL_RULE_NAME)

        results.append("\n### Summary")
        results.append(f"  Created: {created} | Skipped: {skipped} | Failed: {failed}")

        if dry_run:
            results.append(
                "\nNo changes written. Re-run with `dry_run=False` and the same `ticket_ref` to apply."
            )
        elif failed == 0:
            results.append(
                "\n**NCSC baseline applied.**\n"
                f"Next step: attach profiles to your allow rules and set "
                f"`log_setting='{LOG_FORWARDING_NAME}'` on each rule."
            )
        else:
            results.append(f"\n{failed} object(s) failed — see errors above.")

        return "\n".join(results)

    # ── Create NCSC snippet ───────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_create_ncsc_snippet(
        client: Any,
        tenant_id: str,
        snippet_name: str = "NCSC-Compliance",
        dry_run: bool = True,
        ticket_ref: str = "",
        syslog_profile: str = "",
        description: str = "NCSC CAF v4.0 / CE v3.2 compliance baseline — managed by scm-harbourmaster-mcp",
        associate_folder: str = "",
    ) -> str:
        """
        Create an SCM snippet containing NCSC-compliant security profiles.

        Creates a named snippet container and populates it with:
          - Anti-spyware profile (block C2 / critical+high spyware, MICA inline)
          - Vulnerability protection profile (block critical/high CVEs)
          - WildFire antivirus profile (all files, both directions, public cloud)
          - URL access profile (block malware/C2/phishing categories)
          - Log forwarding profile (traffic/threat/wildfire/url/auth → Cortex Data Lake)
          - NCSC-Compliant tag

        Snippets are reusable configuration bundles that can be pushed to multiple
        tenants or folders — they do NOT contain security rules (rules must be created
        separately in a folder rulebase).

        NCSC compliance mapping:
          CAF v4.0  — C3 Identity/Access, C4 Data security, C5 Security monitoring
          CE v3.2   — Malware protection, Patch management, Network monitoring
          10 Steps  — Network security, Malware defences, Monitoring

        Args:
            snippet_name: Name of the SCM snippet to create (default: "NCSC-Compliance").
            dry_run: If True (default) show what WOULD be created without writing.
            ticket_ref: Mandatory change-ticket reference (never sent to SCM).
            syslog_profile: Optional syslog server profile name to add to log forwarding.
            description: Description for the snippet container.
            associate_folder: Optional folder to associate the snippet with once every
                object is created (off by default — assign it in the portal instead).
            tenant_id: Tenant to target (default: first loaded tenant).
        """
        templates = build_snippet_templates(snippet_name, syslog_profile=syslog_profile or None)
        spec = SnippetSpec(
            label="NCSC",
            snippet=snippet_name,
            sections=(
                ("Security Profiles", tuple(templates.all_profiles)),
                ("Tag", (("tag", templates.tag),)),
            ),
            log_event="ncsc_snippet_create_failed",
            dry_run_note=(
                "Security rules (deny-all etc.) cannot be stored in a snippet — "
                "use `scm_apply_ncsc_baseline(folder=...)` to add rules to a folder rulebase."
            ),
            next_steps=_BASELINE_NEXT_STEPS,
        )
        return build_and_create_snippet(
            client,
            spec,
            tool_name="scm_create_ncsc_snippet",
            tenant_id=tenant_id,
            description=description,
            dry_run=dry_run,
            ticket_ref=ticket_ref,
            associate_folder=associate_folder,
        )

    # ── Create NIST snippet ───────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_create_nist_snippet(
        client: Any,
        tenant_id: str,
        snippet_name: str = "NIST-Compliance",
        dry_run: bool = True,
        ticket_ref: str = "",
        syslog_profile: str = "",
        description: str = "NIST CSF v2.0 / SP 800-53 Rev 5 compliance baseline — managed by scm-harbourmaster-mcp",
        associate_folder: str = "",
    ) -> str:
        """
        Create an SCM snippet containing NIST-compliant security profiles.

        Creates a named snippet container and populates it with:
          - Anti-spyware profile (C2 detection, block critical+high spyware)
          - Vulnerability protection profile (block critical/high CVEs, alert medium)
          - WildFire antivirus profile (all files, both directions, public cloud)
          - URL access profile (block malware/C2/phishing categories)
          - Log forwarding profile (traffic/threat/wildfire/url/auth → Cortex Data Lake)
          - NIST-Compliant tag

        Snippets are reusable configuration bundles — they do NOT contain security rules
        (add deny-all and rule tuning separately via scm_apply_ncsc_baseline).

        NIST compliance mapping:
          CSF v2.0   — GV.OC, PR.PS, PR.AA, DE.CM, DE.AE, RS.AN
          SP 800-53  — SI-2 Flaw Remediation, SI-3 Malware Protection, SI-4 Monitoring,
                       RA-5 Vulnerability Monitoring, AU-2/AU-12 Audit Logging,
                       SC-7 Boundary Protection, AC-3 Access Enforcement
          SP 800-171 — 3.14 System and Information Integrity

        Args:
            snippet_name: Name of the SCM snippet to create (default: "NIST-Compliance").
            dry_run: If True (default) show what WOULD be created without writing.
            ticket_ref: Mandatory change-ticket reference (never sent to SCM).
            syslog_profile: Optional syslog server profile name to add to log forwarding.
            description: Description for the snippet container.
            associate_folder: Optional folder to associate the snippet with once every
                object is created (off by default — assign it in the portal instead).
            tenant_id: Tenant to target (default: first loaded tenant).
        """
        templates = _nist.build_nist_snippet_templates(
            snippet_name, syslog_profile=syslog_profile or None
        )
        spec = SnippetSpec(
            label="NIST",
            snippet=snippet_name,
            sections=(
                ("Security Profiles", tuple(templates.all_profiles)),
                ("Tag", (("tag", templates.tag),)),
            ),
            log_event="nist_snippet_create_failed",
            dry_run_note=(
                "Security rules cannot be stored in a snippet — "
                "use `scm_apply_ncsc_baseline(folder=...)` to add a deny-all rule to a folder rulebase."
            ),
            next_steps=_BASELINE_NEXT_STEPS,
        )
        return build_and_create_snippet(
            client,
            spec,
            tool_name="scm_create_nist_snippet",
            tenant_id=tenant_id,
            description=description,
            dry_run=dry_run,
            ticket_ref=ticket_ref,
            associate_folder=associate_folder,
        )

    # ── Create ISO 27001 snippet ──────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_create_iso27001_snippet(
        client: Any,
        tenant_id: str,
        snippet_name: str = "ISO27001-Compliance",
        dry_run: bool = True,
        ticket_ref: str = "",
        syslog_profile: str = "",
        description: str = "ISO 27001:2022 Annex A compliance baseline — managed by scm-harbourmaster-mcp",
        associate_folder: str = "",
    ) -> str:
        """
        Create an SCM snippet containing ISO 27001:2022 Annex A security profiles.

        Creates a named snippet container and populates it with:
          - Anti-spyware profile (C2 detection, block critical+high spyware)
          - DNS Security profile (sinkhole C2/malware/phishing/new domains)
          - Vulnerability protection profile (block critical/high CVEs, alert medium)
          - WildFire antivirus profile (all files, both directions, public cloud)
          - File blocking profile (block script/legacy executable types, alert all)
          - URL access profile (block malware/C2/phishing, safe search enforced)
          - Decryption profile (TLS 1.2+, no RSA key exchange, certificate checks)
          - Log forwarding profile (traffic/threat/wildfire/url/auth → Cortex Data Lake)
          - ISO27001-Compliant tag

        Snippets are reusable configuration bundles — they do NOT contain security rules
        (add deny-all and rule tuning separately via scm_apply_ncsc_baseline).

        ISO 27001:2022 Annex A mapping (from the BPA → ISO control catalogue):
          A.8.7  Protection against malware — anti-spyware, DNS, vulnerability, WildFire
          A.8.28 Secure coding              — vulnerability protection (virtual patching)
          A.5.14 Information transfer       — file blocking
          A.8.23 Web filtering              — URL access profile
          A.8.21 Security of network services — decryption profile
          A.8.15 Logging / A.5.28 Evidence  — log forwarding

        Safe search enforcement blocks search results unless the engine's strict
        safe search is on, and needs decrypted traffic to take effect.

        Args:
            snippet_name: Name of the SCM snippet to create (default: "ISO27001-Compliance").
            dry_run: If True (default) show what WOULD be created without writing.
            ticket_ref: Mandatory change-ticket reference (never sent to SCM).
            syslog_profile: Optional syslog server profile name to add to log forwarding.
            description: Description for the snippet container.
            associate_folder: Optional folder to associate the snippet with once every
                object is created (off by default — assign it in the portal instead).
            tenant_id: Tenant to target (default: first loaded tenant).
        """
        return build_and_create_snippet(
            client,
            build_iso27001_snippet(snippet_name, syslog_profile=syslog_profile or None),
            tool_name="scm_create_iso27001_snippet",
            tenant_id=tenant_id,
            description=description,
            dry_run=dry_run,
            ticket_ref=ticket_ref,
            associate_folder=associate_folder,
        )

    # ── Create NHS DSPT snippet ───────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_create_dspt_snippet(
        client: Any,
        tenant_id: str,
        snippet_name: str = "DSPT-Compliance",
        dry_run: bool = True,
        ticket_ref: str = "",
        syslog_profile: str = "",
        description: str = "NHS DSPT Standard 9 compliance baseline — managed by scm-harbourmaster-mcp",
        associate_folder: str = "",
    ) -> str:
        """
        Create an SCM snippet containing NHS DSPT Standard 9 security profiles.

        Creates a named snippet container and populates it with:
          - Anti-spyware profile (C2 detection, block critical+high spyware)
          - Vulnerability protection profile (block critical/high CVEs, alert medium)
          - WildFire antivirus profile (all files, both directions, public cloud)
          - DNS Security profile (sinkhole C2/malware/phishing/new domains)
          - URL access profile (block malware/C2/phishing categories)
          - Decryption profile (TLS 1.2+, no RSA key exchange, certificate checks)
          - Log forwarding profile (traffic/threat/wildfire/url/auth → Cortex Data Lake)
          - DSPT-Compliant tag

        Snippets are reusable configuration bundles — they do NOT contain security rules
        (add deny-all and rule tuning separately via scm_apply_ncsc_baseline).

        NHS DSPT (Data Security and Protection Toolkit) assertion mapping:
          9.2.1 Anti-malware protection          — anti-spyware, vulnerability, WildFire
          9.2.2 Malicious URL and DNS filtering  — URL access + DNS Security sinkholing
          9.2.3 Encrypted traffic inspection     — decryption profile
          9.6.1 Audit logs retained 6+ months    — log forwarding (point syslog at the SIEM)
          9.6.2 Security monitoring              — threat logs forwarded

        Args:
            snippet_name: Name of the SCM snippet to create (default: "DSPT-Compliance").
            dry_run: If True (default) show what WOULD be created without writing.
            ticket_ref: Mandatory change-ticket reference (never sent to SCM).
            syslog_profile: Optional syslog server profile name to add to log forwarding.
            description: Description for the snippet container.
            associate_folder: Optional folder to associate the snippet with once every
                object is created (off by default — assign it in the portal instead).
            tenant_id: Tenant to target (default: first loaded tenant).
        """
        return build_and_create_snippet(
            client,
            build_dspt_snippet(snippet_name, syslog_profile=syslog_profile or None),
            tool_name="scm_create_dspt_snippet",
            tenant_id=tenant_id,
            description=description,
            dry_run=dry_run,
            ticket_ref=ticket_ref,
            associate_folder=associate_folder,
        )

    # ── Create DNS Security snippet ───────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_create_dns_security_snippet(
        client: Any,
        tenant_id: str,
        snippet_name: str = "DNS-Security",
        dry_run: bool = True,
        ticket_ref: str = "",
        description: str = "DNS Security sinkhole baseline — managed by scm-harbourmaster-mcp",
        associate_folder: str = "",
    ) -> str:
        """
        Create an SCM snippet containing a standalone DNS Security sinkhole profile.

        Creates a named snippet container and populates it with:
          - DNS Security profile — sinkholes C2 (including DGA), malware, phishing,
            dynamic-DNS, grayware, proxy and newly registered domains, plus PAN's
            content-based `default-paloalto-dns` list; ad-tracking and parked
            domains keep the default action. Sinkhole: pan-sinkhole-default-ip / ::1
          - DNS-Security-Managed tag

        A shared building block: layer it onto any baseline whose anti-spyware
        profile has no DNS policy. The category sinkholes need the DNS Security
        licence; the default-paloalto-dns list works without it.

        Compliance mapping:
          BPA-TP-002 — DNS security profile configured
          ISO 27001:2022 A.8.7 Protection against malware
          NHS DSPT 9.2.2 — DNS security sinkholes malicious domains

        Args:
            snippet_name: Name of the SCM snippet to create (default: "DNS-Security").
            dry_run: If True (default) show what WOULD be created without writing.
            ticket_ref: Mandatory change-ticket reference (never sent to SCM).
            description: Description for the snippet container.
            associate_folder: Optional folder to associate the snippet with once every
                object is created (off by default — assign it in the portal instead).
            tenant_id: Tenant to target (default: first loaded tenant).
        """
        return build_and_create_snippet(
            client,
            build_dns_security_snippet(snippet_name),
            tool_name="scm_create_dns_security_snippet",
            tenant_id=tenant_id,
            description=description,
            dry_run=dry_run,
            ticket_ref=ticket_ref,
            associate_folder=associate_folder,
        )

    # ── Create SSL/TLS decryption snippet ─────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_create_decryption_snippet(
        client: Any,
        tenant_id: str,
        snippet_name: str = "Decryption-Baseline",
        dry_run: bool = True,
        ticket_ref: str = "",
        description: str = "SSL/TLS decryption best-practice baseline — managed by scm-harbourmaster-mcp",
        associate_folder: str = "",
    ) -> str:
        """
        Create an SCM snippet containing SSL/TLS decryption best-practice objects.

        Creates a named snippet container and populates it with:
          - Decryption profile for SSL Forward Proxy and inbound inspection —
            TLS 1.2 minimum; MD5, SHA-1, 3DES, RC4 and RSA key exchange off;
            blocks expired, untrusted-issuer, unknown-status and timed-out
            certificates and unsupported versions/ciphers
          - No-decrypt profile — still blocks expired / untrusted server certificates
          - No-decrypt exclusion URL category (Category Match: financial-services,
            health-and-medicine, government)
          - Decryption-Managed tag

        Snippets hold the profiles only — create the decrypt and no-decrypt rules in
        the folder rulebase. Enabled decrypt rules only push once a forward-trust
        certificate is selected.

        Compliance mapping:
          BPA-DEC-001 — decryption profiles configured
          ISO 27001:2022 A.8.21 Security of network services
          NHS DSPT 9.2.3 — encrypted traffic inspection with certificate verification

        Args:
            snippet_name: Name of the SCM snippet to create (default: "Decryption-Baseline").
            dry_run: If True (default) show what WOULD be created without writing.
            ticket_ref: Mandatory change-ticket reference (never sent to SCM).
            description: Description for the snippet container.
            associate_folder: Optional folder to associate the snippet with once every
                object is created (off by default — assign it in the portal instead).
            tenant_id: Tenant to target (default: first loaded tenant).
        """
        return build_and_create_snippet(
            client,
            build_decryption_snippet(snippet_name),
            tool_name="scm_create_decryption_snippet",
            tenant_id=tenant_id,
            description=description,
            dry_run=dry_run,
            ticket_ref=ticket_ref,
            associate_folder=associate_folder,
        )

    # ── Create ransomware-readiness snippet ───────────────────────────────────

    @mcp.tool()
    @tool
    def scm_create_ransomware_snippet(
        client: Any,
        tenant_id: str,
        snippet_name: str = "Ransomware-Readiness",
        dry_run: bool = True,
        ticket_ref: str = "",
        syslog_profile: str = "",
        description: str = "Ransomware-readiness baseline (NIST IR 8374) — managed by scm-harbourmaster-mcp",
        associate_folder: str = "",
    ) -> str:
        """
        Create an SCM snippet containing ransomware-readiness security profiles.

        Creates a named snippet container and populates it with a profile per
        ransomware kill-chain stage:
          - Anti-spyware profile (C2 detectors, block critical+high spyware)
          - DNS Security profile (sinkhole C2/DGA, malware, phishing, new domains)
          - Vulnerability protection profile (block critical/high CVEs — SMB, RDP,
            VPN exploits used for entry and lateral movement)
          - WildFire antivirus profile (all files, both directions, public cloud)
          - File blocking profile (block scripts, legacy executables and
            password-protected archives; alert on everything else)
          - URL access profile (block malware/C2/phishing categories)
          - Log forwarding profile (traffic/threat/wildfire/url/auth → Cortex Data Lake)
          - Ransomware-Ready tag

        Snippets are reusable configuration bundles — they do NOT contain security
        rules. After applying, attach the profiles to east-west/intrazone allow rules
        as well as internet-bound ones (SMB lateral movement is inspected there
        without decryption), and isolate backup traffic in its own zone.

        Compliance mapping:
          NIST IR 8374 — Ransomware Risk Management (the CSF ransomware profile)
          SP 800-53   — SI-2/RA-5 exploit blocking, SI-3 malware, SI-4 C2 detection,
                        SC-7 boundary protection, AU-2/AU-12 logging

        Args:
            snippet_name: Name of the SCM snippet to create (default: "Ransomware-Readiness").
            dry_run: If True (default) show what WOULD be created without writing.
            ticket_ref: Mandatory change-ticket reference (never sent to SCM).
            syslog_profile: Optional syslog server profile name to add to log forwarding.
            description: Description for the snippet container.
            associate_folder: Optional folder to associate the snippet with once every
                object is created (off by default — assign it in the portal instead).
            tenant_id: Tenant to target (default: first loaded tenant).
        """
        return build_and_create_snippet(
            client,
            build_ransomware_snippet(snippet_name, syslog_profile=syslog_profile or None),
            tool_name="scm_create_ransomware_snippet",
            tenant_id=tenant_id,
            description=description,
            dry_run=dry_run,
            ticket_ref=ticket_ref,
            associate_folder=associate_folder,
        )

    # ── Attach profiles to rules ───────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_attach_ncsc_profiles(
        client: Any,
        tenant_id: str,
        folder: str,
        dry_run: bool = True,
        ticket_ref: str = "",
        profile_group_name: str = "NCSC-Baseline",
        skip_already_profiled: bool = True,
    ) -> str:
        """
        Create the NCSC-Baseline security profile group and attach it to all
        allow rules in the folder that are missing profiles or log forwarding.

        Steps:
          1. Create (or verify) the 'NCSC-Baseline' profile group referencing the
             four NCSC baseline profiles
          2. For every allow rule in the folder that has no profile_setting or
             no log_setting, update it with:
               - profile_setting.group = [profile_group_name]
               - log_setting = 'NCSC-Baseline-Logging'
               - log_end = True

        Only rules stored in an editable folder (not 'All') are updated.
        Rules from folder='All' are read-only predefined rules that cannot be changed.

        Args:
            folder: SCM folder to search for rules (e.g. 'Prisma Access').
            tenant_id: SCM tenant ID. Defaults to the active tenant.
            dry_run: If True (default) show what WOULD be changed without writing.
            ticket_ref: Mandatory change-ticket reference (never sent to SCM).
            profile_group_name: Name of the profile group to create/use.
            skip_already_profiled: If True (default), skip rules that already have
                                   a profile group set.
        """
        err = ticket_ref_error(ticket_ref)
        if err:
            return f"Error: {err}"
        ticket_ref = normalize_ticket_ref(ticket_ref)
        if not dry_run:
            audit_write(
                "scm_attach_ncsc_profiles",
                ticket_ref,
                tenant_id,
                folder=folder,
                profile_group_name=profile_group_name,
            )

        from scm.models.security.security_rules import SecurityRuleUpdateModel

        results: list[str] = []
        mode = "DRY-RUN" if dry_run else "APPLY"
        results.append(f"## NCSC Profile Attach — {mode} folder '{folder}'\n")

        # ── Step 1: ensure profile group exists ───────────────────────────────
        results.append("### Step 1: Profile Group")
        pg_url = "https://api.strata.paloaltonetworks.com/config/security/v1/profile-groups"
        pg_payload = {
            "name": profile_group_name,
            "folder": folder,
            "spyware": [ANTI_SPYWARE_NAME],
            "vulnerability": [VULN_PROTECTION_NAME],
            "virus_and_wildfire_analysis": [WILDFIRE_NAME],
            "url_filtering": [URL_ACCESS_NAME],
        }

        group_ok = False
        if dry_run:
            results.append(f"  [DRY-RUN] would create/verify profile group '{profile_group_name}'")
            group_ok = True
        else:
            try:
                # Check if it already exists
                check = client.session.get(
                    pg_url, params={"folder": folder, "name": profile_group_name}
                )
                existing = [
                    d for d in check.json().get("data", []) if d["name"] == profile_group_name
                ]
                if existing:
                    results.append(
                        f"  [OK] Profile group '{profile_group_name}' already exists (id={existing[0]['id']})"
                    )
                    group_ok = True
                else:
                    resp = client.session.post(pg_url, json=pg_payload)
                    if resp.status_code in (200, 201):
                        gid = resp.json().get("id", "?")
                        results.append(
                            f"  [OK] Created profile group '{profile_group_name}' (id={gid})"
                        )
                        group_ok = True
                    elif resp.status_code == 400 and "already exists" in resp.text.lower():
                        results.append(
                            f"  [OK] Profile group '{profile_group_name}' already exists"
                        )
                        group_ok = True
                    else:
                        results.append(
                            f"  [FAIL] Could not create profile group: {resp.text[:300]}"
                        )
            except Exception as exc:
                results.append(f"  [FAIL] Profile group error: {exc}")

        if not group_ok and not dry_run:
            results.append("\nCannot attach profiles — profile group creation failed.")
            return "\n".join(results)

        # ── Step 2: update allow rules ─────────────────────────────────────────
        results.append("\n### Step 2: Rule Updates")
        try:
            positions = ["pre", "post"]
            seen_ids: set[str] = set()
            rules: list[Any] = []
            for pos in positions:
                for r in client.security_rule.list(folder=folder, rulebase=pos):
                    rid = str(getattr(r, "id", ""))
                    if rid and rid not in seen_ids:
                        seen_ids.add(rid)
                        rules.append((r, pos))
        except Exception as exc:
            results.append(f"  [FAIL] Could not list rules: {exc}")
            return "\n".join(results)

        updated_count = 0
        skipped_count = 0
        failed_count = 0

        for rule, pos in rules:
            if rule.action != "allow":
                continue

            # Skip read-only rules (folder=All)
            if rule.folder == "All":
                results.append(f"  [SKIP] '{rule.name}' — folder=All (read-only predefined rule)")
                skipped_count += 1
                continue

            # Check if already has profile
            has_profile = bool(rule.profile_setting)
            has_log = bool(rule.log_setting) or rule.log_end
            if skip_already_profiled and has_profile and has_log:
                results.append(
                    f"  [SKIP] '{rule.name}' — already has profile group and log forwarding"
                )
                skipped_count += 1
                continue

            if dry_run:
                changes = []
                if not has_profile:
                    changes.append(f"profile_setting→{profile_group_name}")
                if not has_log:
                    changes.append("log_setting→NCSC-Baseline-Logging, log_end→True")
                results.append(
                    f"  [DRY-RUN] '{rule.name}' ({rule.folder}) — would set: {', '.join(changes)}"
                )
                updated_count += 1
                continue

            # Build full update payload (API requires all fields on PUT)
            rule_data = rule.model_dump()
            for drop in (
                "policy_type",
                "snippet",
                "device",
                "description",
                "schedule",
                "log_start",
                "rulebase",
            ):
                rule_data.pop(drop, None)
            for k in list(rule_data.keys()):
                if rule_data[k] is None:
                    rule_data.pop(k)

            rule_data["folder"] = rule.folder
            rule_data["profile_setting"] = {"group": [profile_group_name]}
            rule_data["log_setting"] = LOG_FORWARDING_NAME
            rule_data["log_end"] = True

            try:
                update_obj = SecurityRuleUpdateModel(**rule_data)
                client.security_rule.update(update_obj, rulebase=pos)
                results.append(
                    f"  [OK] '{rule.name}' ({rule.folder}) — profile group and log forwarding attached"
                )
                updated_count += 1
            except Exception as exc:
                results.append(f"  [FAIL] '{rule.name}': {str(exc)[:200]}")
                failed_count += 1
                logger.warning("ncsc_attach_rule_failed", rule=rule.name, error=str(exc))

        results.append("\n### Summary")
        results.append(
            f"  Updated: {updated_count} | Skipped: {skipped_count} | Failed: {failed_count}"
        )

        if dry_run:
            results.append(
                "\nNo changes written. Re-run with `dry_run=False` and the same `ticket_ref` to apply."
            )
        elif failed_count == 0:
            results.append("\n**Done.** Re-run `scm_ncsc_gap` to confirm all gaps are resolved.")
        else:
            results.append(f"\n{failed_count} rule(s) failed — see errors above.")

        return "\n".join(results)

    # ── Gap report ─────────────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_ncsc_gap(client: Any, folder: str, position: str = "pre") -> str:
        """
        Compare live SCM config against the NCSC baseline and report compliance gaps.

        Checks:
          - Every allow rule has a security profile group and log forwarding
          - An explicit deny-all rule exists at the bottom of the rulebase
          - Anti-spyware profiles have cloud inline analysis and MICA C2 detectors
          - Log forwarding profile covers traffic/threat/wildfire/url log types
          - NCSC baseline profile objects exist in the folder

        Maps gaps to: CAF v4.0, CE v3.2, NCSC 10 Steps, NSF controls.

        Args:
            folder: SCM folder to inspect.
            tenant_id: SCM tenant ID. Defaults to the active tenant.
            position: Security rule position — "pre", "post", or "both".
        """
        gaps: list[GapItem] = []
        warnings: list[str] = []

        # Security rules (deduplicate by id when fetching both positions)
        try:
            positions = ["pre", "post"] if position == "both" else [position]
            seen_ids: set[str] = set()
            rules: list[Any] = []
            for pos in positions:
                for r in client.security_rule.list(folder=folder, rulebase=pos):
                    rid = str(getattr(r, "id", None) or getattr(r, "name", ""))
                    if rid not in seen_ids:
                        seen_ids.add(rid)
                        rules.append(r)
            gaps += check_security_rules(rules)
        except Exception as exc:
            warnings.append(f"Could not fetch security rules: {exc}")

        # Anti-spyware profiles
        try:
            asp = client.anti_spyware_profile.list(folder=folder)
            gaps += check_anti_spyware_profiles(asp)
        except Exception as exc:
            warnings.append(f"Could not fetch anti-spyware profiles: {exc}")

        # Log forwarding profiles
        try:
            lfp = list_with_rest_fallback(client, "log_forwarding_profile", folder=folder)
            gaps += check_log_forwarding(lfp)
        except Exception as exc:
            warnings.append(f"Could not fetch log forwarding profiles: {exc}")

        # Check baseline object presence
        def _check_exists(sdk_attr: str, name: str, control: str) -> None:
            try:
                objs = list_with_rest_fallback(client, sdk_attr, folder=folder)
                names = {
                    o.get("name") if isinstance(o, dict) else getattr(o, "name", None) for o in objs
                }
                if name not in names:
                    gaps.append(
                        GapItem(
                            control=control,
                            severity="info",
                            finding=f"Baseline object '{name}' not found in folder '{folder}'",
                            remediation=f"Run scm_apply_ncsc_baseline(folder='{folder}')",
                        )
                    )
            except Exception as exc:
                warnings.append(f"Could not check {sdk_attr} for '{name}': {exc}")

        _check_exists("vulnerability_protection_profile", VULN_PROTECTION_NAME, "CE v3.2 Patch")
        _check_exists("wildfire_antivirus_profile", WILDFIRE_NAME, "CE v3.2 Malware")
        _check_exists("url_access_profile", URL_ACCESS_NAME, "CE v3.2 / 10 Steps")

        # Format output
        lines: list[str] = [
            f"## NCSC Compliance Gap Report — folder '{folder}'\n",
            f"Checks: security rules (position={position}), anti-spyware, log forwarding, baseline objects\n",
        ]

        if warnings:
            lines.append("### Warnings")
            for w in warnings:
                lines.append(f"  ⚠ {w}")
            lines.append("")

        if not gaps:
            lines.append("**All checks passed — no NCSC gaps detected in this folder.**")
            return "\n".join(lines)

        by_sev: dict[str, list[GapItem]] = {"critical": [], "high": [], "medium": [], "info": []}
        for g in gaps:
            by_sev.get(g.severity, by_sev["info"]).append(g)

        icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "info": "🔵"}
        total = len(gaps)
        lines.append(
            f"Found **{total} gaps** "
            f"({len(by_sev['critical'])} critical, {len(by_sev['high'])} high, "
            f"{len(by_sev['medium'])} medium, {len(by_sev['info'])} info)\n"
        )

        for sev in ("critical", "high", "medium", "info"):
            items = by_sev[sev]
            if not items:
                continue
            lines.append(f"### {icons[sev]} {sev.capitalize()} ({len(items)})\n")
            for g in items:
                obj = f" `{g.object_name}`" if g.object_name else ""
                lines.append(f"**[{g.control}]{obj}** {g.finding}")
                lines.append(f"  → {g.remediation}\n")

        lines.append("---")
        lines.append(
            "Run `scm_apply_ncsc_baseline` to create missing baseline objects, "
            "then attach profiles to your allow rules."
        )
        return "\n".join(lines)

    @mcp.tool()
    @tool
    def scm_nist_gap(client: Any, folder: str, position: str = "pre") -> str:
        """
        Compare live SCM config against the NIST baseline and report compliance gaps.

        Checks:
          - Every allow rule has a security profile group and log forwarding
            (NIST CSF PR.AC-5, SP 800-53 AC-3, SC-7)
          - An explicit deny-all rule exists at the bottom of the rulebase
            (SP 800-53 SC-7 Boundary Protection)
          - Anti-spyware profiles have cloud inline analysis and C2 detection
            (SP 800-53 SI-3 Malware Protection, SI-4 System Monitoring)
          - Log forwarding profile covers traffic/threat/wildfire/url log types
            (SP 800-53 AU-2 / AU-12 Audit Logging)
          - NIST baseline profile objects exist in the folder
            (SI-2 Flaw Remediation, RA-5 Vulnerability Monitoring, SP 800-171 3.14)

        Maps gaps to: NIST CSF v2.0 (GV/ID/PR/DE/RS), SP 800-53 Rev 5, SP 800-171.

        Args:
            folder: SCM folder to inspect.
            tenant_id: SCM tenant ID. Defaults to the active tenant.
            position: Security rule position — "pre", "post", or "both".
        """
        gaps: list[GapItem] = []
        warnings: list[str] = []

        # Re-use the same structural checks as NCSC (same SCM config patterns)
        # but remap control references to NIST framework identifiers.

        try:
            positions = ["pre", "post"] if position == "both" else [position]
            seen_ids: set[str] = set()
            rules: list[Any] = []
            for pos in positions:
                for r in client.security_rule.list(folder=folder, rulebase=pos):
                    rid = str(getattr(r, "id", None) or getattr(r, "name", ""))
                    if rid not in seen_ids:
                        seen_ids.add(rid)
                        rules.append(r)
            for gap in check_security_rules(rules):
                # Remap NCSC control strings to NIST equivalents
                ctrl = (
                    gap.control.replace("CAF C2a", "CSF PR.AC-5")
                    .replace("CAF C2b", "SP 800-53 AC-3")
                    .replace("CE v3.2", "SP 800-53 SI-3")
                    .replace("10 Steps", "SP 800-171 3.14")
                )
                gaps.append(
                    GapItem(ctrl, gap.severity, gap.finding, gap.remediation, gap.object_name)
                )
        except Exception as exc:
            warnings.append(f"Could not fetch security rules: {exc}")

        try:
            asp = client.anti_spyware_profile.list(folder=folder)
            for gap in check_anti_spyware_profiles(asp):
                ctrl = gap.control.replace("CAF C4", "SP 800-53 SI-4").replace(
                    "CE", "SP 800-53 SI-3"
                )
                gaps.append(
                    GapItem(ctrl, gap.severity, gap.finding, gap.remediation, gap.object_name)
                )
        except Exception as exc:
            warnings.append(f"Could not fetch anti-spyware profiles: {exc}")

        try:
            lfp = list_with_rest_fallback(client, "log_forwarding_profile", folder=folder)
            for gap in check_log_forwarding(lfp):
                ctrl = gap.control.replace("CAF C5", "SP 800-53 AU-12").replace(
                    "CE", "SP 800-53 AU-2"
                )
                gaps.append(
                    GapItem(ctrl, gap.severity, gap.finding, gap.remediation, gap.object_name)
                )
        except Exception as exc:
            warnings.append(f"Could not fetch log forwarding profiles: {exc}")

        # Check NIST baseline profile objects exist
        def _check_exists(sdk_attr: str, name: str, control: str) -> None:
            try:
                objs = list_with_rest_fallback(client, sdk_attr, folder=folder)
                names = {
                    o.get("name") if isinstance(o, dict) else getattr(o, "name", None) for o in objs
                }
                if name not in names:
                    gaps.append(
                        GapItem(
                            control=control,
                            severity="info",
                            finding=f"NIST baseline object '{name}' not found in folder '{folder}'",
                            remediation=f"Run scm_create_nist_snippet(dry_run=False, ticket_ref=...) then push to folder '{folder}'",
                        )
                    )
            except Exception as exc:
                warnings.append(f"Could not check {sdk_attr} for '{name}': {exc}")

        _check_exists("anti_spyware_profile", _nist.ANTI_SPYWARE_NAME, "SP 800-53 SI-3")
        _check_exists(
            "vulnerability_protection_profile", _nist.VULN_PROTECTION_NAME, "SP 800-53 SI-2 / RA-5"
        )
        _check_exists(
            "wildfire_antivirus_profile", _nist.WILDFIRE_NAME, "SP 800-53 SI-3 / SP 800-171 3.14"
        )
        _check_exists("url_access_profile", _nist.URL_ACCESS_NAME, "CSF PR.AC-5 / SC-7")
        _check_exists("log_forwarding_profile", _nist.LOG_FORWARDING_NAME, "SP 800-53 AU-2 / AU-12")

        # Format output
        lines: list[str] = [
            f"## NIST Compliance Gap Report — folder '{folder}'\n",
            "Frameworks: NIST CSF v2.0 | SP 800-53 Rev 5 | SP 800-171\n",
            f"Checks: security rules (position={position}), anti-spyware, log forwarding, baseline objects\n",
        ]

        if warnings:
            lines.append("### Warnings")
            for w in warnings:
                lines.append(f"  ⚠ {w}")
            lines.append("")

        if not gaps:
            lines.append("**All checks passed — no NIST gaps detected in this folder.**")
            return "\n".join(lines)

        by_sev: dict[str, list[GapItem]] = {"critical": [], "high": [], "medium": [], "info": []}
        for g in gaps:
            by_sev.get(g.severity, by_sev["info"]).append(g)

        icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "info": "🔵"}
        total = len(gaps)
        lines.append(
            f"Found **{total} gaps** "
            f"({len(by_sev['critical'])} critical, {len(by_sev['high'])} high, "
            f"{len(by_sev['medium'])} medium, {len(by_sev['info'])} info)\n"
        )

        for sev in ("critical", "high", "medium", "info"):
            items = by_sev[sev]
            if not items:
                continue
            lines.append(f"### {icons[sev]} {sev.capitalize()} ({len(items)})\n")
            for g in items:
                obj = f" `{g.object_name}`" if g.object_name else ""
                lines.append(f"**[{g.control}]{obj}** {g.finding}")
                lines.append(f"  → {g.remediation}\n")

        lines.append("---")
        lines.append(
            "Run `scm_create_nist_snippet` to create missing baseline objects, "
            "then attach profiles to your allow rules."
        )
        return "\n".join(lines)
