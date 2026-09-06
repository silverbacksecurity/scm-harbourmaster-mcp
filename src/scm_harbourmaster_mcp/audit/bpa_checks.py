"""
PAN BPA check engine — runs against an AuditSnapshot.

Each check function returns a Finding.  The run_all_checks() function
executes every registered check and returns the full list of findings
with NCSC cross-references applied.

Check IDs follow the convention:
    BPA-SR-NNN   Security Rule checks
    BPA-TP-NNN   Threat Prevention (profile) checks
    BPA-URL-NNN  URL Filtering checks
    BPA-DEC-NNN  Decryption checks
    BPA-ZP-NNN   Zone Protection checks
    BPA-LOG-NNN  Logging checks
    BPA-NET-NNN  Network / Zone design checks
    BPA-VPN-NNN  VPN / IKE / IPSec cryptography checks
    BPA-AUTH-NNN Authentication / Identity checks
    BPA-HIP-NNN  Host Information Profile (endpoint posture) checks
    BPA-NGW-NNN  NGFW managed device health checks

Sources:
  - PAN BPA AIOps API (api.stratacloud.paloaltonetworks.com/aiops)
  - PAN Best Practices documentation (docs.paloaltonetworks.com/best-practices)
  - pan.dev/products/aiops-ngfw-bpa
"""

from __future__ import annotations

from typing import Any

from .models import AuditSnapshot, Finding, Severity, Status
from .ncsc_controls import BPA_TO_NCSC


def _ncsc(check_id: str) -> list[str]:
    return BPA_TO_NCSC.get(check_id, [])


def _has_security_profile(rule: dict[str, Any]) -> bool:
    """True if the rule has at least one security profile group or individual profile."""
    ps = rule.get("profile_setting") or {}
    if isinstance(ps, dict):
        # group= is a named profile group; individual profiles are keyed directly
        return bool(ps.get("group") or ps.get("profiles"))
    return False


def _rule_name(rule: dict[str, Any]) -> str:
    return str(rule.get("name", "<unnamed>"))


def _is_any(value: Any) -> bool:
    """True if a zone/address/application field contains only 'any'."""
    if isinstance(value, list):
        return value == ["any"] or value == []
    return str(value).lower() == "any"


# ── Security Rule Checks ─────────────────────────────────────────────────────


def check_sr_001(snap: AuditSnapshot) -> Finding:
    """BPA-SR-001: Allow rules must have security profiles attached."""
    cid = "BPA-SR-001"
    failing = [
        _rule_name(r)
        for r in snap.all_security_rules
        if r.get("action") == "allow" and not r.get("disabled") and not _has_security_profile(r)
    ]
    if not failing:
        return Finding(
            check_id=cid,
            title="Allow rules have security profiles",
            severity=Severity.CRITICAL,
            status=Status.PASS,
            description="All enabled allow rules have at least one security profile or profile group.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="Allow rules missing security profiles",
        severity=Severity.CRITICAL,
        status=Status.FAIL,
        description=(
            f"{len(failing)} enabled allow rule(s) have no anti-spyware, "
            "vulnerability, URL, or WildFire profile attached. "
            "These rules permit traffic without any threat inspection."
        ),
        remediation=(
            "Attach a security profile group to each allow rule that includes "
            "anti-spyware, vulnerability protection, URL filtering, and "
            "WildFire antivirus profiles. Use a profile group (Objects → "
            "Security Profile Groups) for consistent application."
        ),
        affected_objects=failing,
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


def check_sr_002(snap: AuditSnapshot) -> Finding:
    """BPA-SR-002: No permit-any-any rules (source=any, dest=any, app=any, action=allow)."""
    cid = "BPA-SR-002"
    failing = [
        _rule_name(r)
        for r in snap.all_security_rules
        if (
            r.get("action") == "allow"
            and not r.get("disabled")
            and _is_any(r.get("source"))
            and _is_any(r.get("destination"))
            and _is_any(r.get("application"))
        )
    ]
    if not failing:
        return Finding(
            check_id=cid,
            title="No permit-any-any rules",
            severity=Severity.CRITICAL,
            status=Status.PASS,
            description="No allow rules with source=any, destination=any, application=any found.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="Permit-any-any rules detected",
        severity=Severity.CRITICAL,
        status=Status.FAIL,
        description=(
            f"{len(failing)} rule(s) allow all traffic from any source to any destination "
            "for any application. This is the most dangerous rule pattern and bypasses "
            "all zero-trust principles."
        ),
        remediation=(
            "Replace any-to-any allow rules with explicit application-specific rules. "
            "Define permitted applications using App-ID, specify source and destination "
            "zones/addresses, and attach a security profile group."
        ),
        affected_objects=failing,
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


def check_sr_003(snap: AuditSnapshot) -> Finding:
    """BPA-SR-003: Allow rules must log at session end."""
    cid = "BPA-SR-003"
    failing = [
        _rule_name(r)
        for r in snap.all_security_rules
        if (
            r.get("action") == "allow"
            and not r.get("disabled")
            and not r.get("log_end", True)  # log_end defaults True in PAN-OS
        )
    ]
    if not failing:
        return Finding(
            check_id=cid,
            title="Allow rules log at session end",
            severity=Severity.HIGH,
            status=Status.PASS,
            description="All enabled allow rules have log-at-session-end enabled.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="Allow rules not logging at session end",
        severity=Severity.HIGH,
        status=Status.FAIL,
        description=(
            f"{len(failing)} allow rule(s) do not log at session end. "
            "Traffic permitted by these rules will not appear in traffic logs, "
            "making threat investigation and compliance reporting impossible."
        ),
        remediation=(
            "Enable 'Log at Session End' on all allow rules. "
            "For high-volume rules consider using a Log Forwarding Profile "
            "with sampling rather than disabling logging entirely."
        ),
        affected_objects=failing,
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


def check_sr_004(snap: AuditSnapshot) -> Finding:
    """BPA-SR-004: No disabled rules (rule hygiene)."""
    cid = "BPA-SR-004"
    disabled = [_rule_name(r) for r in snap.all_security_rules if r.get("disabled")]
    if not disabled:
        return Finding(
            check_id=cid,
            title="No disabled rules present",
            severity=Severity.LOW,
            status=Status.PASS,
            description="Rulebase contains no disabled rules.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="Disabled rules present",
        severity=Severity.LOW,
        status=Status.WARN,
        description=(
            f"{len(disabled)} disabled rule(s) found. Disabled rules add noise to "
            "the rulebase, complicate audits, and may be re-enabled accidentally."
        ),
        remediation=(
            "Review all disabled rules. Remove any that are no longer required. "
            "If a rule must be retained for reference, document the reason in its "
            "description field and schedule a periodic review."
        ),
        affected_objects=disabled,
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


def check_sr_005(snap: AuditSnapshot) -> Finding:
    """BPA-SR-005: Allow rules should use App-ID, not application=any."""
    cid = "BPA-SR-005"
    failing = [
        _rule_name(r)
        for r in snap.all_security_rules
        if r.get("action") == "allow" and not r.get("disabled") and _is_any(r.get("application"))
    ]
    if not failing:
        return Finding(
            check_id=cid,
            title="Allow rules use App-ID",
            severity=Severity.HIGH,
            status=Status.PASS,
            description="All enabled allow rules specify applications using App-ID.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="Allow rules using application=any",
        severity=Severity.HIGH,
        status=Status.FAIL,
        description=(
            f"{len(failing)} allow rule(s) permit any application. "
            "Rules without App-ID allow malicious traffic to masquerade as "
            "legitimate services and bypass threat inspection context."
        ),
        remediation=(
            "Replace application=any with explicit App-ID application names. "
            "Use the Application Command Center (ACC) to identify traffic "
            "patterns and create application-specific rules."
        ),
        affected_objects=failing,
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


def check_sr_006(snap: AuditSnapshot) -> Finding:
    """BPA-SR-006: Deny rules must log traffic."""
    cid = "BPA-SR-006"
    failing = [
        _rule_name(r)
        for r in snap.all_security_rules
        if r.get("action") in ("deny", "drop") and not r.get("log_end", True)
    ]
    if not failing:
        return Finding(
            check_id=cid,
            title="Deny rules log traffic",
            severity=Severity.HIGH,
            status=Status.PASS,
            description="All deny/drop rules have logging enabled.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="Deny rules not logging traffic",
        severity=Severity.HIGH,
        status=Status.FAIL,
        description=(
            f"{len(failing)} deny/drop rule(s) do not log blocked traffic. "
            "Without logging on deny rules, reconnaissance and intrusion attempts "
            "will be invisible to security monitoring."
        ),
        remediation=(
            "Enable logging on all deny and drop rules. "
            "At minimum enable 'Log at Session End' and attach a Log Forwarding "
            "Profile that routes denied traffic logs to your SIEM."
        ),
        affected_objects=failing,
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


def check_sr_007(snap: AuditSnapshot) -> Finding:
    """BPA-SR-007: No unrestricted outbound allow rules (dest=any, app=any)."""
    cid = "BPA-SR-007"
    failing = [
        _rule_name(r)
        for r in snap.all_security_rules
        if (
            r.get("action") == "allow"
            and not r.get("disabled")
            and _is_any(r.get("destination"))
            and _is_any(r.get("application"))
        )
    ]
    if not failing:
        return Finding(
            check_id=cid,
            title="No unrestricted outbound rules",
            severity=Severity.HIGH,
            status=Status.PASS,
            description="No allow rules with destination=any and application=any found.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="Unrestricted outbound allow rules detected",
        severity=Severity.HIGH,
        status=Status.FAIL,
        description=(
            f"{len(failing)} rule(s) allow outbound traffic to any destination for any "
            "application. This enables data exfiltration and command-and-control "
            "communications without inspection or restriction."
        ),
        remediation=(
            "Replace catch-all outbound rules with explicit destination and "
            "application controls. Define permitted SaaS applications with App-ID, "
            "block uncategorised destinations, and enforce URL filtering."
        ),
        affected_objects=failing,
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


def check_sr_008(snap: AuditSnapshot) -> Finding:
    """BPA-SR-008: Rulebase must end with an explicit deny-all rule."""
    cid = "BPA-SR-008"
    all_rules = snap.all_security_rules
    if not all_rules:
        return Finding(
            check_id=cid,
            title="Explicit deny-all rule",
            severity=Severity.CRITICAL,
            status=Status.SKIP,
            description="No security rules found — cannot evaluate.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    last = all_rules[-1]
    has_deny_all = (
        last.get("action") in ("deny", "drop")
        and _is_any(last.get("source"))
        and _is_any(last.get("destination"))
    )
    if has_deny_all:
        return Finding(
            check_id=cid,
            title="Explicit deny-all rule present",
            severity=Severity.CRITICAL,
            status=Status.PASS,
            description=f"Last rule '{_rule_name(last)}' is an explicit deny-all.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="No explicit deny-all rule at end of rulebase",
        severity=Severity.CRITICAL,
        status=Status.FAIL,
        description=(
            "The rulebase does not end with an explicit deny-all rule. "
            "While PAN-OS has an implicit deny, an explicit deny-all with "
            "logging enabled is required by Cyber Essentials and CAF."
        ),
        remediation=(
            "Add a final security rule: name='Deny-All', source=any, "
            "destination=any, application=any, action=deny, log=enabled. "
            "This ensures all unmatched traffic is blocked and logged."
        ),
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


def check_sr_009(snap: AuditSnapshot) -> Finding:
    """BPA-SR-009: NSF-ZT-1 — Allow rules must not have source=any AND destination=any."""
    cid = "BPA-SR-009"
    all_rules = snap.all_security_rules
    if not all_rules:
        return Finding(
            check_id=cid,
            title="Zero trust rule specificity (source + destination scope)",
            severity=Severity.HIGH,
            status=Status.SKIP,
            description="No security rules found — cannot evaluate.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    # Flag allow rules where BOTH source and destination are unconstrained.
    # BPA-SR-007 already catches dest=any + app=any; this catches source=any + dest=any
    # regardless of application specificity — the network path itself is totally open.
    failing = [
        _rule_name(r)
        for r in all_rules
        if (
            r.get("action") == "allow"
            and not r.get("disabled")
            and _is_any(r.get("source"))
            and _is_any(r.get("destination"))
        )
    ]
    if not failing:
        return Finding(
            check_id=cid,
            title="Allow rules have source or destination constraints",
            severity=Severity.HIGH,
            status=Status.PASS,
            description=(
                f"No allow rules with source=any AND destination=any found across "
                f"{len(all_rules)} rule(s). All rules constrain at least one network dimension."
            ),
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="Allow rules with unconstrained source AND destination (double-any)",
        severity=Severity.HIGH,
        status=Status.FAIL,
        description=(
            f"{len(failing)} allow rule(s) have source=any AND destination=any. "
            "These rules impose no network-level segmentation — any host can reach any host. "
            "Zero trust requires explicit source and destination scope to enforce "
            "least-privilege access between segments."
        ),
        remediation=(
            "Restrict each rule to the minimum required source and destination scope. "
            "Replace 'source=any' with specific address objects or zone-restricted "
            "source addresses. Replace 'destination=any' with the specific server or "
            "subnet being accessed. Use address groups to keep rules maintainable."
        ),
        affected_objects=failing,
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


def check_sr_010(snap: AuditSnapshot) -> Finding:
    """BPA-SR-010: CE-FW-2 — Allow rules must not explicitly permit unauthenticated protocols."""
    cid = "BPA-SR-010"
    all_rules = snap.all_security_rules
    if not all_rules:
        return Finding(
            check_id=cid,
            title="Unauthenticated protocols in allow rules",
            severity=Severity.HIGH,
            status=Status.SKIP,
            description="No security rules found — cannot evaluate.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )

    # Protocols that provide no authentication or only cleartext auth.
    # Rules with application=any are flagged by BPA-SR-005; this check looks
    # for rules that EXPLICITLY name these dangerous apps.
    _UNAUTH_APPS = frozenset(
        {
            "telnet",  # no encryption, cleartext credentials
            "tftp",  # no authentication at all
            "ftp",  # cleartext credentials (control channel)
            "rsh",  # remote shell, no encryption
            "rlogin",  # remote login, no encryption
            "rexec",  # remote execution, cleartext
            "finger",  # user enumeration, no auth
            "chargen",  # amplification attack vector
            "daytime",  # no authentication, info disclosure
            "echo",  # amplification attack vector
            "snmp",  # v1/v2c community strings only (effectively no auth)
            "snmp-trap",  # same
            "netbios-ss",  # SMB without auth negotiation (legacy)
            "netbios-ns",  # NetBIOS name service
            "netbios-dg",  # NetBIOS datagram
            "ms-netlogon",  # can be unencrypted in legacy configs
        }
    )

    failing: list[str] = []
    for rule in all_rules:
        if rule.get("action") != "allow" or rule.get("disabled"):
            continue
        apps = rule.get("application") or []
        if isinstance(apps, str):
            apps = [apps]
        found_unauth = [a for a in apps if str(a).lower() in _UNAUTH_APPS]
        if found_unauth:
            failing.append(f"{_rule_name(rule)} ({', '.join(found_unauth)})")

    if not failing:
        return Finding(
            check_id=cid,
            title="No allow rules expose unauthenticated protocols",
            severity=Severity.HIGH,
            status=Status.PASS,
            description=(
                f"No allow rules explicitly permit unauthenticated or cleartext protocols "
                f"(telnet, FTP, TFTP, rsh, rlogin, rexec, finger, SNMPv1/v2, NetBIOS) "
                f"across {len(all_rules)} rule(s)."
            ),
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="Allow rules expose unauthenticated or cleartext protocols",
        severity=Severity.HIGH,
        status=Status.FAIL,
        description=(
            f"{len(failing)} allow rule(s) explicitly permit unauthenticated or cleartext "
            "protocols. Services accessible via these protocols cannot enforce strong "
            "authentication, violating Cyber Essentials CE-FW-2. Telnet, FTP, TFTP, "
            "rsh/rlogin/rexec, and SNMPv1/v2 are common attack vectors for credential "
            "interception and unauthenticated access."
        ),
        remediation=(
            "Replace each unauthenticated protocol with an authenticated, encrypted "
            "alternative: telnet → SSH, FTP → SFTP or FTPS, SNMP v1/v2 → SNMPv3 with "
            "auth+priv, HTTP management → HTTPS. If legacy protocols are operationally "
            "required, restrict them to specific trusted source addresses and document "
            "the risk exception. Use App-ID to confirm no substitution is possible."
        ),
        affected_objects=failing,
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


# ── Threat Prevention Checks ─────────────────────────────────────────────────


def check_tp_001(snap: AuditSnapshot) -> Finding:
    """BPA-TP-001: Anti-spyware profile with DNS sinkholing must exist."""
    cid = "BPA-TP-001"
    if not snap.anti_spyware_profiles:
        return Finding(
            check_id=cid,
            title="Anti-spyware profiles with DNS sinkholing",
            severity=Severity.CRITICAL,
            status=Status.FAIL,
            description="No anti-spyware profiles found in this folder.",
            remediation=(
                "Create at least one anti-spyware profile with DNS sinkholing "
                "enabled and botnet protection configured. Apply it to all allow rules."
            ),
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    # Check if any profile has sinkholing enabled
    sinkhole_profiles = [
        p.get("name", "")
        for p in snap.anti_spyware_profiles
        if p.get("botnet_domains", {}).get("sinkhole")
        or (
            p.get("dns_security_categories")
            and any(c.get("action") == "sinkhole" for c in (p.get("dns_security_categories") or []))
        )
    ]
    if sinkhole_profiles:
        return Finding(
            check_id=cid,
            title="Anti-spyware DNS sinkholing configured",
            severity=Severity.CRITICAL,
            status=Status.PASS,
            description=f"DNS sinkholing found in profile(s): {', '.join(sinkhole_profiles)}",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="Anti-spyware profiles lack DNS sinkholing",
        severity=Severity.CRITICAL,
        status=Status.FAIL,
        description=(
            f"{len(snap.anti_spyware_profiles)} anti-spyware profile(s) found but none "
            "have DNS sinkholing configured. Without sinkholing, malware C2 "
            "communications via DNS will succeed."
        ),
        remediation=(
            "Edit each anti-spyware profile: enable 'Sinkhole' under Botnet Protection "
            "and set the sinkhole IPv4/IPv6 address. Also enable passive DNS monitoring "
            "to feed threat intelligence."
        ),
        affected_objects=[p.get("name", "") for p in snap.anti_spyware_profiles],
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


def check_tp_002(snap: AuditSnapshot) -> Finding:
    """BPA-TP-002: DNS security profile must be configured."""
    cid = "BPA-TP-002"
    if snap.dns_security_profiles:
        return Finding(
            check_id=cid,
            title="DNS security profiles configured",
            severity=Severity.HIGH,
            status=Status.PASS,
            description=f"{len(snap.dns_security_profiles)} DNS security profile(s) found.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="No DNS security profiles configured",
        severity=Severity.HIGH,
        status=Status.FAIL,
        description=(
            "No DNS security profiles found. DNS security profiles block "
            "access to malicious domains using PAN's threat intelligence feed "
            "and provide DGA (domain generation algorithm) detection."
        ),
        remediation=(
            "Create a DNS security profile (Objects → Security Profiles → DNS Security). "
            "Enable all DNS security categories with appropriate actions (block/sinkhole). "
            "Attach the profile to your anti-spyware profiles."
        ),
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


def check_tp_003(snap: AuditSnapshot) -> Finding:
    """BPA-TP-003: Vulnerability protection profiles must exist and cover all severities."""
    cid = "BPA-TP-003"
    if not snap.vulnerability_profiles:
        return Finding(
            check_id=cid,
            title="Vulnerability protection profiles",
            severity=Severity.CRITICAL,
            status=Status.FAIL,
            description="No vulnerability protection profiles found.",
            remediation=(
                "Create a vulnerability protection profile covering critical, high, "
                "medium, and low severities. Set action=block-ip on critical/high, "
                "alert on medium/low. Apply to all allow rules."
            ),
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="Vulnerability protection profiles present",
        severity=Severity.CRITICAL,
        status=Status.PASS,
        description=f"{len(snap.vulnerability_profiles)} vulnerability profile(s) found.",
        remediation="",
        affected_objects=[p.get("name", "") for p in snap.vulnerability_profiles],
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


def check_tp_004(snap: AuditSnapshot) -> Finding:
    """BPA-TP-004: WildFire antivirus profiles must be configured."""
    cid = "BPA-TP-004"
    if snap.wildfire_profiles:
        return Finding(
            check_id=cid,
            title="WildFire antivirus profiles configured",
            severity=Severity.HIGH,
            status=Status.PASS,
            description=f"{len(snap.wildfire_profiles)} WildFire profile(s) found.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="No WildFire antivirus profiles configured",
        severity=Severity.HIGH,
        status=Status.FAIL,
        description=(
            "No WildFire antivirus profiles found. Without WildFire, unknown "
            "malware in file transfers will not be analysed or blocked."
        ),
        remediation=(
            "Create a WildFire antivirus profile covering all file types with "
            "forward action for unknown files. Set action=block for malware. "
            "Apply to all internet-facing allow rules."
        ),
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


def check_tp_005(snap: AuditSnapshot) -> Finding:
    """BPA-TP-005: File blocking profiles must be configured."""
    cid = "BPA-TP-005"
    if snap.file_blocking_profiles:
        return Finding(
            check_id=cid,
            title="File blocking profiles configured",
            severity=Severity.MEDIUM,
            status=Status.PASS,
            description=f"{len(snap.file_blocking_profiles)} file blocking profile(s) found.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="No file blocking profiles configured",
        severity=Severity.MEDIUM,
        status=Status.WARN,
        description=(
            "No file blocking profiles found. Without file type controls, "
            "dangerous executables and archive types can be transferred "
            "without inspection."
        ),
        remediation=(
            "Create a file blocking profile that alerts or blocks high-risk "
            "file types (exe, dll, bat, ps1, msi, jar) and forwards others to "
            "WildFire for analysis."
        ),
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


def check_tp_006(snap: AuditSnapshot) -> Finding:
    """BPA-TP-006: Decryption profiles must be configured for SSL inspection."""
    cid = "BPA-DEC-001"
    if snap.decryption_profiles:
        return Finding(
            check_id=cid,
            title="SSL/TLS decryption profiles configured",
            severity=Severity.HIGH,
            status=Status.PASS,
            description=f"{len(snap.decryption_profiles)} decryption profile(s) found.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="No SSL/TLS decryption profiles configured",
        severity=Severity.HIGH,
        status=Status.WARN,
        description=(
            "No decryption profiles found. The majority of malware and data "
            "exfiltration now uses TLS encryption. Without SSL inspection, "
            "threat profiles cannot inspect encrypted sessions."
        ),
        remediation=(
            "Deploy SSL Forward Proxy decryption for outbound traffic and "
            "SSL Inbound Inspection for inbound services. Create a decryption "
            "profile and decryption policy rules. Exclude banking/healthcare "
            "categories using decryption exclusions."
        ),
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


def check_dec_002(snap: AuditSnapshot) -> Finding:
    """BPA-DEC-002: Decryption rules must exist and include at least one decrypt action."""
    cid = "BPA-DEC-002"
    if not snap.decryption_profiles:
        return Finding(
            check_id=cid,
            title="Decryption rule coverage",
            severity=Severity.HIGH,
            status=Status.SKIP,
            description=(
                "No decryption profiles found — skipping decryption rule check. "
                "Resolve BPA-DEC-001 first."
            ),
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    if not snap.decryption_rules:
        return Finding(
            check_id=cid,
            title="No decryption rules configured",
            severity=Severity.HIGH,
            status=Status.FAIL,
            description=(
                "Decryption profiles exist but no decryption policy rules were found. "
                "Without decryption rules, SSL/TLS traffic is never inspected regardless "
                "of which profiles are configured — encrypted malware and data exfiltration "
                "pass through uninspected."
            ),
            remediation=(
                "Create decryption rules (Policies → Decryption) to apply the decryption "
                "profiles. At minimum: an SSL Forward Proxy rule for outbound web traffic "
                "(source=trust zones, destination=untrust, service=application-default, "
                "action=decrypt, profile=<your-decryption-profile>)."
            ),
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )

    # Verify at least one rule actively decrypts (action=decrypt) — not just no-decrypt exclusions
    decrypt_rules = [
        r
        for r in snap.decryption_rules
        if str(r.get("action", "")).lower() == "decrypt" and not r.get("disabled")
    ]
    if decrypt_rules:
        return Finding(
            check_id=cid,
            title="Decryption rules present and active",
            severity=Severity.HIGH,
            status=Status.PASS,
            description=(
                f"{len(decrypt_rules)} active decrypt rule(s) found out of "
                f"{len(snap.decryption_rules)} total decryption rule(s)."
            ),
            remediation="",
            affected_objects=[r.get("name", "<unnamed>") for r in decrypt_rules],
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="No active decrypt rules — only no-decrypt exclusions",
        severity=Severity.HIGH,
        status=Status.FAIL,
        description=(
            f"{len(snap.decryption_rules)} decryption rule(s) found but none have "
            "action=decrypt. All rules are no-decrypt exclusions, meaning SSL/TLS "
            "inspection is not actually being performed despite profiles being configured."
        ),
        remediation=(
            "Add at least one decryption rule with action=decrypt to enforce SSL inspection. "
            "Typical rule order: (1) no-decrypt exclusions for banking/healthcare/privacy-sensitive "
            "categories, (2) decrypt rule covering remaining outbound HTTPS traffic. "
            "Reference the decryption profile in the decrypt rule."
        ),
        affected_objects=[r.get("name", "<unnamed>") for r in snap.decryption_rules],
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


def check_tp_007(snap: AuditSnapshot) -> Finding:
    """BPA-TP-007: WildFire profiles must cover broad file types and block malware."""
    cid = "BPA-TP-007"
    if not snap.wildfire_profiles:
        return Finding(
            check_id=cid,
            title="WildFire profile content coverage",
            severity=Severity.HIGH,
            status=Status.SKIP,
            description="No WildFire profiles found — skipping content coverage check.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )

    # High-risk file types that must be forwarded for analysis
    _REQUIRED_TYPES = {"pe", "pdf", "ms-office", "jar", "elf", "apk", "flash"}
    _BLOCK_ACTIONS = {"block", "block-ip", "block-continue"}

    weak_profiles: list[str] = []
    for profile in snap.wildfire_profiles:
        name = profile.get("name", "<unnamed>")
        rules = profile.get("rules") or []

        # Collect all file types across all rules in this profile
        covered_types: set[str] = set()
        has_block_on_malware = False
        for rule in rules:
            fts = rule.get("file_type") or rule.get("file_types") or []
            if isinstance(fts, list):
                covered_types.update(str(f).lower() for f in fts)
            elif fts:
                covered_types.add(str(fts).lower())

            # Check if the rule blocks malware / malicious verdicts
            action = str(rule.get("action", "")).lower()
            if action in _BLOCK_ACTIONS:
                has_block_on_malware = True

            # "any" or "*" means all file types covered
            if "any" in covered_types or "*" in covered_types:
                covered_types = _REQUIRED_TYPES.copy()

        # WildFire profile verdict actions may also be at profile level
        verdict_actions = profile.get("verdicts") or profile.get("threat_exception") or {}
        if isinstance(verdict_actions, dict):
            malware_action = str(
                verdict_actions.get("grayware", verdict_actions.get("malware", ""))
            ).lower()
            if malware_action in _BLOCK_ACTIONS:
                has_block_on_malware = True

        missing_types = _REQUIRED_TYPES - covered_types
        if missing_types or not has_block_on_malware:
            weak_profiles.append(name)

    if not weak_profiles:
        return Finding(
            check_id=cid,
            title="WildFire profiles cover broad file types with block action",
            severity=Severity.HIGH,
            status=Status.PASS,
            description=(
                f"All {len(snap.wildfire_profiles)} WildFire profile(s) cover "
                "high-risk file types (PE, PDF, Office, JAR, ELF, APK) with malware blocking."
            ),
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="WildFire profiles with limited file type coverage or missing block action",
        severity=Severity.HIGH,
        status=Status.FAIL,
        description=(
            f"{len(weak_profiles)} WildFire profile(s) either do not cover all high-risk "
            "file types (PE, PDF, MS-Office, JAR, ELF, APK, Flash) or lack an explicit "
            "block action on malicious verdicts. Narrow coverage leaves gaps where "
            "malware in unchecked file types will be forwarded without inspection."
        ),
        remediation=(
            "Edit each WildFire profile: add a rule with file-type=any (or list all "
            "high-risk types), direction=both, analysis=public-cloud. Set the malware "
            "verdict action to 'block'. Remove any rules that skip or allow specific "
            "file types that are not explicitly excluded for business reasons."
        ),
        affected_objects=weak_profiles,
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


# ── URL Filtering Checks ─────────────────────────────────────────────────────


def check_url_001(snap: AuditSnapshot) -> Finding:
    """BPA-URL-001: URL categories must include blocks for malware/phishing."""
    cid = "BPA-URL-001"
    if not snap.url_categories:
        return Finding(
            check_id=cid,
            title="URL filtering categories",
            severity=Severity.HIGH,
            status=Status.WARN,
            description="No custom URL categories found — cannot verify URL filtering coverage.",
            remediation=(
                "Configure URL filtering profiles in a security profile group "
                "and attach to all internet-facing allow rules. Block malware, "
                "phishing, command-and-control, and hacking categories."
            ),
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="URL categories configured",
        severity=Severity.HIGH,
        status=Status.PASS,
        description=f"{len(snap.url_categories)} URL categorie(s) found.",
        remediation="",
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


def check_url_002(snap: AuditSnapshot) -> Finding:
    """BPA-URL-002: URL access profiles must block high-risk categories."""
    cid = "BPA-URL-002"
    if not snap.url_access_profiles:
        return Finding(
            check_id=cid,
            title="URL access profile block-category coverage",
            severity=Severity.HIGH,
            status=Status.WARN,
            description=(
                "No URL access profiles found. Without URL access profiles, malicious "
                "web categories (malware, phishing, C2, hacking) are not blocked at "
                "the firewall level."
            ),
            remediation=(
                "Create URL access profiles (Objects → Security Profiles → URL Access) "
                "with block rules for: malware, phishing, command-and-control, hacking, "
                "proxy-avoidance-and-anonymizers. Attach to all internet-facing allow rules."
            ),
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )

    _THREAT_CATEGORIES = {
        "malware",
        "phishing",
        "command-and-control",
        "hacking",
        "proxy-avoidance-and-anonymizers",
        "dynamic-dns",
    }
    _BLOCK_ACTIONS = {"block", "block-continue", "deny"}

    profiles_missing_blocks: list[str] = []
    for profile in snap.url_access_profiles:
        name = profile.get("name", "<unnamed>")
        rules = profile.get("access_rules") or profile.get("rules") or []
        blocked_categories: set[str] = set()
        for rule in rules:
            action = str(rule.get("action", "")).lower()
            if action not in _BLOCK_ACTIONS:
                continue
            cats = rule.get("categories") or rule.get("category") or []
            if isinstance(cats, str):
                cats = [cats]
            for cat in cats:
                blocked_categories.add(str(cat).lower())
            # "any" means all categories are blocked
            if "any" in blocked_categories:
                blocked_categories = _THREAT_CATEGORIES.copy()
                break

        uncovered = _THREAT_CATEGORIES - blocked_categories
        if uncovered:
            profiles_missing_blocks.append(name)

    if not profiles_missing_blocks:
        return Finding(
            check_id=cid,
            title="URL access profiles block high-risk categories",
            severity=Severity.HIGH,
            status=Status.PASS,
            description=(
                f"All {len(snap.url_access_profiles)} URL access profile(s) block "
                "malware, phishing, command-and-control, hacking, and proxy-avoidance categories."
            ),
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="URL access profiles missing blocks for high-risk categories",
        severity=Severity.HIGH,
        status=Status.FAIL,
        description=(
            f"{len(profiles_missing_blocks)} URL access profile(s) do not explicitly block "
            "all high-risk categories (malware, phishing, command-and-control, hacking, "
            "proxy-avoidance). Users may access malicious sites or C2 infrastructure "
            "through these profiles."
        ),
        remediation=(
            "Add a block rule to each URL access profile covering: malware, phishing, "
            "command-and-control, hacking, proxy-avoidance-and-anonymizers, dynamic-dns. "
            "Place the block rule before any allow-all catch-all rule in the profile."
        ),
        affected_objects=profiles_missing_blocks,
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


# ── Zone Protection Checks ───────────────────────────────────────────────────


def check_zp_001(snap: AuditSnapshot) -> Finding:
    """BPA-ZP-001: Security zones should have zone protection profiles attached."""
    cid = "BPA-ZP-001"
    if not snap.zones:
        return Finding(
            check_id=cid,
            title="Zone protection profiles",
            severity=Severity.HIGH,
            status=Status.SKIP,
            description="No security zones found.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    unprotected = [z.get("name", "") for z in snap.zones if not z.get("zone_protection_profile")]
    if not unprotected:
        return Finding(
            check_id=cid,
            title="All zones have protection profiles",
            severity=Severity.HIGH,
            status=Status.PASS,
            description="All security zones have a zone protection profile attached.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="Zones without protection profiles",
        severity=Severity.HIGH,
        status=Status.FAIL,
        description=(
            f"{len(unprotected)} zone(s) have no zone protection profile. "
            "Zones without protection profiles are vulnerable to flood attacks, "
            "reconnaissance, and packet-based exploits."
        ),
        remediation=(
            "Create zone protection profiles with flood protection (SYN, ICMP, UDP, other), "
            "reconnaissance protection (host sweep, port scan), and packet-based "
            "protection. Attach to all zones especially untrust/internet-facing zones."
        ),
        affected_objects=unprotected,
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


# ── Logging Checks ───────────────────────────────────────────────────────────


def check_log_001(snap: AuditSnapshot) -> Finding:
    """BPA-LOG-001: Log forwarding profiles must be configured."""
    cid = "BPA-LOG-001"
    if snap.log_forwarding_profiles:
        return Finding(
            check_id=cid,
            title="Log forwarding profiles configured",
            severity=Severity.HIGH,
            status=Status.PASS,
            description=f"{len(snap.log_forwarding_profiles)} log forwarding profile(s) found.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="No log forwarding profiles configured",
        severity=Severity.HIGH,
        status=Status.FAIL,
        description=(
            "No log forwarding profiles found. Without log forwarding, traffic, "
            "threat, and URL logs remain only on the firewall and are not "
            "available to centralised SIEM or SOC platforms."
        ),
        remediation=(
            "Create log forwarding profiles (Objects → Log Forwarding) that send "
            "traffic, threat, URL, and wildfire logs to syslog or an HTTP server. "
            "Attach profiles to all security rules."
        ),
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


def check_log_002(snap: AuditSnapshot) -> Finding:
    """BPA-LOG-002: Syslog server profiles must be configured."""
    cid = "BPA-LOG-002"
    if snap.syslog_profiles:
        return Finding(
            check_id=cid,
            title="Syslog server profiles configured",
            severity=Severity.HIGH,
            status=Status.PASS,
            description=f"{len(snap.syslog_profiles)} syslog profile(s) found.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="No syslog server profiles configured",
        severity=Severity.HIGH,
        status=Status.FAIL,
        description=(
            "No syslog server profiles found. Without a syslog destination, "
            "log forwarding profiles cannot export logs off-device."
        ),
        remediation=(
            "Configure syslog server profiles (Device → Server Profiles → Syslog) "
            "pointing to your SIEM or log aggregator. Use TCP with TLS where possible. "
            "Reference the syslog profile from log forwarding profiles."
        ),
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


def check_log_003(snap: AuditSnapshot) -> Finding:
    """BPA-LOG-003: Allow rules should attach a log forwarding profile."""
    cid = "BPA-LOG-003"
    if not snap.log_forwarding_profiles:
        return Finding(
            check_id=cid,
            title="Log forwarding on allow rules",
            severity=Severity.HIGH,
            status=Status.SKIP,
            description="No log forwarding profiles exist — skipping rule attachment check.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    missing = [
        _rule_name(r)
        for r in snap.all_security_rules
        if r.get("action") == "allow" and not r.get("disabled") and not r.get("log_forwarding")
    ]
    if not missing:
        return Finding(
            check_id=cid,
            title="Allow rules have log forwarding profiles",
            severity=Severity.HIGH,
            status=Status.PASS,
            description="All enabled allow rules have a log forwarding profile attached.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="Allow rules missing log forwarding profiles",
        severity=Severity.HIGH,
        status=Status.FAIL,
        description=(
            f"{len(missing)} allow rule(s) have no log forwarding profile attached. "
            "Logs from these rules will not reach the SIEM."
        ),
        remediation=(
            "Attach a log forwarding profile to every allow rule. "
            "Create a default log forwarding profile that forwards traffic and "
            "threat logs to syslog, then apply it as the default on all rules."
        ),
        affected_objects=missing,
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


# ── Network / Zone Design Checks ─────────────────────────────────────────────


def check_net_001(snap: AuditSnapshot) -> Finding:
    """BPA-NET-001: At least two security zones must exist (trust + untrust minimum)."""
    cid = "BPA-NET-001"
    if len(snap.zones) >= 2:
        return Finding(
            check_id=cid,
            title="Network segmentation — multiple zones",
            severity=Severity.HIGH,
            status=Status.PASS,
            description=f"{len(snap.zones)} security zones found.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="Insufficient network segmentation",
        severity=Severity.HIGH,
        status=Status.FAIL if snap.zones else Status.SKIP,
        description=(
            f"Only {len(snap.zones)} security zone(s) found. NCSC CAF requires network "
            "segmentation to limit lateral movement. At minimum trust and untrust "
            "zones must be defined."
        ),
        remediation=(
            "Define at minimum: untrust (internet-facing), trust (internal), and "
            "DMZ (public-facing services) zones. Add further segments for "
            "OT/IoT, management, and guest traffic per your architecture."
        ),
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


def check_net_002(snap: AuditSnapshot) -> Finding:
    """BPA-NET-002: Remote networks should use IPSec tunnels."""
    cid = "BPA-NET-002"
    if not snap.remote_networks:
        return Finding(
            check_id=cid,
            title="Remote network VPN encryption",
            severity=Severity.MEDIUM,
            status=Status.SKIP,
            description="No remote networks configured — skipping VPN check.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    # Check if IKE/IPSec is configured when remote networks exist
    if snap.ike_gateways and snap.ipsec_tunnels:
        return Finding(
            check_id=cid,
            title="Remote networks use IPSec encryption",
            severity=Severity.MEDIUM,
            status=Status.PASS,
            description=(
                f"{len(snap.remote_networks)} remote network(s), "
                f"{len(snap.ike_gateways)} IKE gateway(s), "
                f"{len(snap.ipsec_tunnels)} IPSec tunnel(s) found."
            ),
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="Remote networks without IPSec configuration",
        severity=Severity.MEDIUM,
        status=Status.WARN,
        description=(
            f"{len(snap.remote_networks)} remote network(s) found but "
            f"IKE gateways ({len(snap.ike_gateways)}) or "
            f"IPSec tunnels ({len(snap.ipsec_tunnels)}) appear incomplete."
        ),
        remediation=(
            "Ensure all remote network connections use IPSec with IKEv2 and strong "
            "cryptography (AES-256-GCM, SHA-384, DH group 20 or higher). "
            "Avoid legacy IKEv1 aggressive mode and weak cipher suites."
        ),
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


# ── VPN / Cryptography Checks ────────────────────────────────────────────────

_WEAK_IKE_CIPHERS = {"des", "3des"}
_WEAK_IKE_HASH = {"md5", "sha1"}
_WEAK_DH_GROUPS = {"group1", "group2", "group5", "1", "2", "5"}
_WEAK_IPSEC_CIPHERS = {"des", "3des", "null"}
_WEAK_IPSEC_AUTH = {"md5", "sha1"}


def check_vpn_001(snap: AuditSnapshot) -> Finding:
    """BPA-VPN-001: IKE gateways must enforce IKEv2 (not IKEv1 or ikev2-preferred)."""
    cid = "BPA-VPN-001"
    if not snap.ike_gateways:
        return Finding(
            check_id=cid,
            title="IKEv2 enforcement",
            severity=Severity.HIGH,
            status=Status.SKIP,
            description="No IKE gateways configured — skipping IKEv2 check.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    failing = [
        gw.get("name", "<unnamed>")
        for gw in snap.ike_gateways
        if str(gw.get("version", "ikev2")).lower() not in ("ikev2", "2")
    ]
    if not failing:
        return Finding(
            check_id=cid,
            title="IKE gateways enforce IKEv2",
            severity=Severity.HIGH,
            status=Status.PASS,
            description=f"All {len(snap.ike_gateways)} IKE gateway(s) are configured for IKEv2 only.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="IKE gateways not enforcing IKEv2",
        severity=Severity.HIGH,
        status=Status.FAIL,
        description=(
            f"{len(failing)} IKE gateway(s) allow IKEv1 or use 'ikev2-preferred' mode. "
            "IKEv1 has known weaknesses including aggressive mode vulnerabilities "
            "and weaker exchange protection."
        ),
        remediation=(
            "Set all IKE gateway versions to 'IKEv2 Only'. Disable IKEv1 fallback. "
            "If legacy peer compatibility requires IKEv1, document the exception "
            "and apply compensating controls."
        ),
        affected_objects=failing,
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


def check_vpn_002(snap: AuditSnapshot) -> Finding:
    """BPA-VPN-002: IKE crypto profiles must not use weak ciphers, hash, or DH groups."""
    cid = "BPA-VPN-002"
    if not snap.ike_crypto_profiles:
        return Finding(
            check_id=cid,
            title="IKE crypto profile strength",
            severity=Severity.HIGH,
            status=Status.SKIP,
            description="No IKE crypto profiles found — skipping cipher strength check.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    failing: list[str] = []
    for p in snap.ike_crypto_profiles:
        name = p.get("name", "<unnamed>")
        enc = [str(e).lower() for e in (p.get("encryption") or [])]
        auth = [str(a).lower() for a in (p.get("authentication") or [])]
        dh = [str(d).lower() for d in (p.get("dh_group") or [])]
        if (
            any(e in _WEAK_IKE_CIPHERS for e in enc)
            or any(a in _WEAK_IKE_HASH for a in auth)
            or any(d in _WEAK_DH_GROUPS for d in dh)
        ):
            failing.append(name)
    if not failing:
        return Finding(
            check_id=cid,
            title="IKE crypto profiles use strong algorithms",
            severity=Severity.HIGH,
            status=Status.PASS,
            description=f"All {len(snap.ike_crypto_profiles)} IKE crypto profile(s) use strong ciphers and DH groups.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="IKE crypto profiles contain weak algorithms",
        severity=Severity.HIGH,
        status=Status.FAIL,
        description=(
            f"{len(failing)} IKE crypto profile(s) contain weak encryption (DES/3DES), "
            "weak hash (MD5/SHA-1), or weak DH groups (group 1/2/5). "
            "These are vulnerable to offline decryption attacks."
        ),
        remediation=(
            "Update IKE crypto profiles to use: encryption=aes-256-gcm or aes-256-cbc, "
            "authentication=sha256 or sha384, dh-group=group14 minimum (group19/20 preferred). "
            "Remove any profile entries referencing DES, 3DES, MD5, SHA-1, or DH group 1/2/5."
        ),
        affected_objects=failing,
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


def check_vpn_003(snap: AuditSnapshot) -> Finding:
    """BPA-VPN-003: IPSec crypto profiles must not use weak encryption or authentication."""
    cid = "BPA-VPN-003"
    if not snap.ipsec_crypto_profiles:
        return Finding(
            check_id=cid,
            title="IPSec crypto profile strength",
            severity=Severity.HIGH,
            status=Status.SKIP,
            description="No IPSec crypto profiles found — skipping cipher strength check.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    failing: list[str] = []
    for p in snap.ipsec_crypto_profiles:
        name = p.get("name", "<unnamed>")
        esp = p.get("esp") or {}
        enc = [str(e).lower() for e in (esp.get("encryption") or [])]
        auth = [str(a).lower() for a in (esp.get("authentication") or [])]
        if any(e in _WEAK_IPSEC_CIPHERS for e in enc) or any(a in _WEAK_IPSEC_AUTH for a in auth):
            failing.append(name)
    if not failing:
        return Finding(
            check_id=cid,
            title="IPSec crypto profiles use strong algorithms",
            severity=Severity.HIGH,
            status=Status.PASS,
            description=f"All {len(snap.ipsec_crypto_profiles)} IPSec crypto profile(s) use strong ESP ciphers.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="IPSec crypto profiles contain weak algorithms",
        severity=Severity.HIGH,
        status=Status.FAIL,
        description=(
            f"{len(failing)} IPSec crypto profile(s) use weak ESP encryption (DES/3DES/null) "
            "or weak authentication (MD5/SHA-1). Tunnels using these profiles "
            "can be decrypted by a sufficiently motivated attacker."
        ),
        remediation=(
            "Set ESP encryption to aes-256-gcm or aes-256-cbc. Use aes-256-gcm "
            "where possible as it provides authenticated encryption (no separate "
            "auth algorithm needed). Remove null encryption and MD5/SHA-1 auth."
        ),
        affected_objects=failing,
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


def check_vpn_004(snap: AuditSnapshot) -> Finding:
    """BPA-VPN-004: IPSec crypto profiles must enable Perfect Forward Secrecy (PFS)."""
    cid = "BPA-VPN-004"
    if not snap.ipsec_crypto_profiles:
        return Finding(
            check_id=cid,
            title="IPSec Perfect Forward Secrecy",
            severity=Severity.HIGH,
            status=Status.SKIP,
            description="No IPSec crypto profiles found — skipping PFS check.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    failing = [
        p.get("name", "<unnamed>")
        for p in snap.ipsec_crypto_profiles
        if str(p.get("dh_group", "no-pfs")).lower() in ("no-pfs", "none", "")
    ]
    if not failing:
        return Finding(
            check_id=cid,
            title="IPSec PFS enabled on all profiles",
            severity=Severity.HIGH,
            status=Status.PASS,
            description=f"All {len(snap.ipsec_crypto_profiles)} IPSec profile(s) have PFS enabled.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="IPSec profiles without Perfect Forward Secrecy",
        severity=Severity.HIGH,
        status=Status.FAIL,
        description=(
            f"{len(failing)} IPSec crypto profile(s) have PFS disabled (dh-group=no-pfs). "
            "Without PFS, compromise of the long-term key allows decryption of all "
            "past recorded sessions."
        ),
        remediation=(
            "Enable PFS on all IPSec crypto profiles by setting dh-group to group14 "
            "or higher (group19/20/21 for ECDH). PFS ensures each session uses an "
            "independent key that cannot be derived from the master key."
        ),
        affected_objects=failing,
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


# ── Authentication / Identity Checks ─────────────────────────────────────────


def check_auth_001(snap: AuditSnapshot) -> Finding:
    """BPA-AUTH-001: Authentication profiles should require MFA."""
    cid = "BPA-AUTH-001"
    if not snap.authentication_profiles:
        return Finding(
            check_id=cid,
            title="MFA in authentication profiles",
            severity=Severity.HIGH,
            status=Status.SKIP,
            description="No authentication profiles found — skipping MFA check.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    no_mfa_profiles: list[str] = []
    for p in snap.authentication_profiles:
        name = p.get("name", "<unnamed>")
        mfa = p.get("multi_factor_auth") or p.get("mfa") or {}
        factors = p.get("factors") or (mfa.get("factors") if isinstance(mfa, dict) else None) or []
        mfa_enabled = (isinstance(mfa, dict) and mfa.get("mfa_enable")) or bool(factors)
        if not mfa_enabled:
            no_mfa_profiles.append(name)
    if not no_mfa_profiles:
        return Finding(
            check_id=cid,
            title="Authentication profiles require MFA",
            severity=Severity.HIGH,
            status=Status.PASS,
            description=f"All {len(snap.authentication_profiles)} authentication profile(s) have MFA configured.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="Authentication profiles without MFA",
        severity=Severity.HIGH,
        status=Status.FAIL,
        description=(
            f"{len(no_mfa_profiles)} authentication profile(s) do not have MFA enabled. "
            "Single-factor authentication is insufficient for remote access and "
            "administrative accounts per NCSC CAF and Cyber Essentials."
        ),
        remediation=(
            "Enable MFA on all authentication profiles used for GlobalProtect, "
            "admin access, and cloud-managed services. Supported factors include "
            "TOTP (Authenticator app), RADIUS OTP, push notification, or smart card. "
            "Use 'Multi Factor Auth' settings under Device → Authentication Profile."
        ),
        affected_objects=no_mfa_profiles,
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


def check_auth_002(snap: AuditSnapshot) -> Finding:
    """BPA-AUTH-002: SAML server profiles must validate the IdP certificate."""
    cid = "BPA-AUTH-002"
    if not snap.saml_server_profiles:
        return Finding(
            check_id=cid,
            title="SAML IdP certificate validation",
            severity=Severity.HIGH,
            status=Status.SKIP,
            description="No SAML server profiles found — skipping certificate validation check.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    failing = [
        p.get("name", "<unnamed>")
        for p in snap.saml_server_profiles
        if not p.get("validate_idp_cert", True)
    ]
    if not failing:
        return Finding(
            check_id=cid,
            title="SAML profiles validate IdP certificate",
            severity=Severity.HIGH,
            status=Status.PASS,
            description=f"All {len(snap.saml_server_profiles)} SAML profile(s) have IdP certificate validation enabled.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="SAML profiles with IdP certificate validation disabled",
        severity=Severity.CRITICAL,
        status=Status.FAIL,
        description=(
            f"{len(failing)} SAML server profile(s) have 'Validate Identity Provider Certificate' "
            "disabled. Without this, a man-in-the-middle attacker could present a forged "
            "SAML assertion and authenticate as any user (CVE-2020-2021 style attack)."
        ),
        remediation=(
            "Enable 'Validate Identity Provider Certificate' on all SAML server profiles. "
            "Import the IdP signing certificate into the firewall certificate store and "
            "reference it in the profile. Never disable certificate validation in production."
        ),
        affected_objects=failing,
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


def check_auth_003(snap: AuditSnapshot) -> Finding:
    """BPA-AUTH-003: Authentication profiles must configure account lockout."""
    cid = "BPA-AUTH-003"
    if not snap.authentication_profiles:
        return Finding(
            check_id=cid,
            title="Authentication account lockout policy",
            severity=Severity.MEDIUM,
            status=Status.SKIP,
            description="No authentication profiles found — skipping lockout policy check.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    no_lockout: list[str] = []
    for p in snap.authentication_profiles:
        name = p.get("name", "<unnamed>")
        lockout = p.get("lockout") or {}
        failed_attempts = lockout.get("failed_attempts", 0) if isinstance(lockout, dict) else 0
        if not failed_attempts:
            no_lockout.append(name)
    if not no_lockout:
        return Finding(
            check_id=cid,
            title="Authentication profiles enforce lockout policy",
            severity=Severity.MEDIUM,
            status=Status.PASS,
            description=f"All {len(snap.authentication_profiles)} profile(s) have account lockout configured.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="Authentication profiles without lockout policy",
        severity=Severity.MEDIUM,
        status=Status.FAIL,
        description=(
            f"{len(no_lockout)} authentication profile(s) have no failed-attempts lockout "
            "configured. Without lockout, brute-force attacks against user credentials "
            "will succeed without detection or blocking."
        ),
        remediation=(
            "Set 'Failed Attempts' to 5 or fewer and 'Lockout Time' to at least "
            "30 minutes on all authentication profiles. This applies to "
            "GlobalProtect VPN, Captive Portal, and admin auth profiles."
        ),
        affected_objects=no_lockout,
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


# ── HIP / Endpoint Posture Checks ────────────────────────────────────────────


def check_hip_001(snap: AuditSnapshot) -> Finding:
    """BPA-HIP-001: At least one HIP object must check patch management status."""
    cid = "BPA-HIP-001"
    if not snap.hip_objects:
        return Finding(
            check_id=cid,
            title="HIP patch management check",
            severity=Severity.MEDIUM,
            status=Status.SKIP,
            description="No HIP objects found — skipping patch management posture check.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    patch_objects = [
        o.get("name", "")
        for o in snap.hip_objects
        if o.get("patch_management") or o.get("missing_patches")
    ]
    if patch_objects:
        return Finding(
            check_id=cid,
            title="HIP objects check patch management",
            severity=Severity.MEDIUM,
            status=Status.PASS,
            description=f"{len(patch_objects)} HIP object(s) include patch management criteria.",
            remediation="",
            affected_objects=patch_objects,
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="No HIP objects checking patch management",
        severity=Severity.MEDIUM,
        status=Status.FAIL,
        description=(
            f"{len(snap.hip_objects)} HIP object(s) found but none include patch management "
            "criteria. Without patch posture checks, unpatched endpoints can connect "
            "to the network, violating CAF-B6 and Cyber Essentials patch requirements."
        ),
        remediation=(
            "Create a HIP object with Patch Management criteria: set 'Severity' to "
            "Critical and High, set check to 'is-installed' = false (missing patches). "
            "Reference this object in a HIP profile and apply to GlobalProtect rules "
            "to quarantine or restrict unpatched endpoints."
        ),
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


def check_hip_002(snap: AuditSnapshot) -> Finding:
    """BPA-HIP-002: At least one HIP object must check disk encryption status."""
    cid = "BPA-HIP-002"
    if not snap.hip_objects:
        return Finding(
            check_id=cid,
            title="HIP disk encryption check",
            severity=Severity.MEDIUM,
            status=Status.SKIP,
            description="No HIP objects found — skipping disk encryption posture check.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    enc_objects = [
        o.get("name", "")
        for o in snap.hip_objects
        if o.get("disk_encryption") or o.get("disk_backup")
    ]
    if enc_objects:
        return Finding(
            check_id=cid,
            title="HIP objects check disk encryption",
            severity=Severity.MEDIUM,
            status=Status.PASS,
            description=f"{len(enc_objects)} HIP object(s) include disk encryption criteria.",
            remediation="",
            affected_objects=enc_objects,
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="No HIP objects checking disk encryption",
        severity=Severity.MEDIUM,
        status=Status.FAIL,
        description=(
            f"{len(snap.hip_objects)} HIP object(s) found but none verify disk encryption. "
            "Without disk encryption checks, endpoints with unencrypted storage "
            "may access sensitive data over VPN."
        ),
        remediation=(
            "Create or update a HIP object to include 'Disk Encryption' criteria. "
            "Set location to 'system drive' and state to 'encrypted'. "
            "Apply to a HIP profile and reference in security rules to enforce "
            "full-disk encryption (BitLocker, FileVault) on all endpoints."
        ),
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


def check_hip_003(snap: AuditSnapshot) -> Finding:
    """BPA-HIP-003: Security rules for remote access should reference HIP profiles."""
    cid = "BPA-HIP-003"
    if not snap.hip_profiles:
        return Finding(
            check_id=cid,
            title="HIP profiles applied to security rules",
            severity=Severity.MEDIUM,
            status=Status.SKIP,
            description="No HIP profiles found — skipping HIP rule attachment check.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    hip_profile_names = {p.get("name", "") for p in snap.hip_profiles}
    rules_with_hip = [
        _rule_name(r)
        for r in snap.all_security_rules
        if r.get("action") == "allow"
        and not r.get("disabled")
        and bool(
            set(
                r.get("profile_setting", {}).get("hip_profiles", [])
                if isinstance(r.get("profile_setting"), dict)
                else []
            )
            & hip_profile_names
            or r.get("hip_profiles")
        )
    ]
    if rules_with_hip:
        return Finding(
            check_id=cid,
            title="HIP profiles applied to security rules",
            severity=Severity.MEDIUM,
            status=Status.PASS,
            description=f"{len(rules_with_hip)} allow rule(s) reference HIP profiles for endpoint posture enforcement.",
            remediation="",
            affected_objects=rules_with_hip,
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="HIP profiles not applied to security rules",
        severity=Severity.MEDIUM,
        status=Status.WARN,
        description=(
            f"{len(snap.hip_profiles)} HIP profile(s) defined but none are referenced "
            "in allow rules. HIP profiles that are not applied to rules provide no "
            "endpoint posture enforcement."
        ),
        remediation=(
            "Apply HIP profiles to GlobalProtect-facing allow rules: "
            "in the Security Rule, set 'HIP Profiles' to your posture-checking profile. "
            "Non-compliant endpoints will be matched against a separate restricted-access rule."
        ),
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


# ── NGFW Device Health Checks ─────────────────────────────────────────────────


def check_ngw_001(snap: AuditSnapshot) -> Finding:
    """BPA-NGW-001: All NGFW devices should be connected/online."""
    cid = "BPA-NGW-001"
    if not snap.ngfw_devices:
        return Finding(
            check_id=cid,
            title="NGFW device connectivity",
            severity=Severity.HIGH,
            status=Status.SKIP,
            description="No NGFW devices found — skipping connectivity check.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    offline = [
        d.get("name") or d.get("hostname") or d.get("serial_number", "<unknown>")
        for d in snap.ngfw_devices
        if str(d.get("connectivity_status", d.get("connected", "connected"))).lower()
        not in ("connected", "online", "up", "true", "1")
    ]
    if not offline:
        return Finding(
            check_id=cid,
            title="All NGFW devices are connected",
            severity=Severity.HIGH,
            status=Status.PASS,
            description=f"All {len(snap.ngfw_devices)} NGFW device(s) report connected status.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="NGFW devices offline or disconnected",
        severity=Severity.HIGH,
        status=Status.FAIL,
        description=(
            f"{len(offline)} of {len(snap.ngfw_devices)} NGFW device(s) are offline or "
            "disconnected from SCM. Disconnected devices are not receiving policy "
            "updates and may be running stale configuration."
        ),
        remediation=(
            "Investigate offline devices immediately. Check connectivity from the device "
            "to api.sase.paloaltonetworks.com on port 443. Verify panorama-server or "
            "cloud services are configured correctly. Check for certificate expiry or "
            "authentication failures in the system log."
        ),
        affected_objects=offline,
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


def check_ngw_002(snap: AuditSnapshot) -> Finding:
    """BPA-NGW-002: NGFW devices should run a uniform PAN-OS version."""
    cid = "BPA-NGW-002"
    if not snap.ngfw_devices:
        return Finding(
            check_id=cid,
            title="NGFW PAN-OS version uniformity",
            severity=Severity.MEDIUM,
            status=Status.SKIP,
            description="No NGFW devices found — skipping PAN-OS version check.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    from collections import Counter

    version_field = next(
        (
            k
            for k in ("sw_version", "software_version", "os_version", "version")
            if snap.ngfw_devices[0].get(k)
        ),
        None,
    )
    if not version_field:
        return Finding(
            check_id=cid,
            title="NGFW PAN-OS version uniformity",
            severity=Severity.MEDIUM,
            status=Status.SKIP,
            description="PAN-OS version field not available in device data — skipping.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    versions = Counter(str(d.get(version_field, "unknown")) for d in snap.ngfw_devices)
    if len(versions) == 1:
        version_str, count = next(iter(versions.items()))
        return Finding(
            check_id=cid,
            title="NGFW devices run uniform PAN-OS version",
            severity=Severity.MEDIUM,
            status=Status.PASS,
            description=f"All {count} device(s) run PAN-OS {version_str}.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    version_summary = ", ".join(
        f"{v} ({c} device{'s' if c > 1 else ''})" for v, c in versions.most_common()
    )
    return Finding(
        check_id=cid,
        title="Mixed PAN-OS versions across NGFW devices",
        severity=Severity.MEDIUM,
        status=Status.WARN,
        description=(
            f"Multiple PAN-OS versions detected across {len(snap.ngfw_devices)} device(s): "
            f"{version_summary}. Mixed versions complicate patch management, may introduce "
            "feature incompatibilities, and indicate some devices are not on the latest release."
        ),
        remediation=(
            "Standardise all devices to the latest recommended PAN-OS maintenance release. "
            "Follow PAN's Content Delivery Network for content updates and schedule "
            "maintenance windows for devices on older releases. Use SCM software lifecycle "
            "management to track and enforce version compliance."
        ),
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


def check_ngw_003(snap: AuditSnapshot) -> Finding:
    """BPA-NGW-003: NGFW devices must be registered and visible to SCM."""
    cid = "BPA-NGW-003"
    if snap.ngfw_devices:
        return Finding(
            check_id=cid,
            title="NGFW devices registered with SCM",
            severity=Severity.HIGH,
            status=Status.PASS,
            description=f"{len(snap.ngfw_devices)} NGFW device(s) registered and visible in SCM.",
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="No NGFW devices registered with SCM",
        severity=Severity.HIGH,
        status=Status.WARN,
        description=(
            "No NGFW managed devices were found in SCM. If physical or virtual NGFWs "
            "are deployed, they should be registered with Strata Cloud Manager for "
            "centralised policy management and visibility."
        ),
        remediation=(
            "Register NGFW devices with SCM via: Device → Setup → Management → "
            "Panorama Settings — set Panorama Server to api.sase.paloaltonetworks.com. "
            "Alternatively use the Cloud Management Agent (PAN-DB) for automated onboarding. "
            "Verify the device certificate and licensing are valid."
        ),
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


# ── Check Registry ───────────────────────────────────────────────────────────

# ── Prisma Access Browser / endpoint posture ────────────────────────────────

_PAB_POSTURE_FIELDS = (
    ("screenLockStatus", "screen lock"),
    ("diskEncryptionStatus", "disk encryption"),
    ("firewallStatus", "firewall"),
)


def _pab_posture_ok(value: Any) -> bool:
    return bool(value) and str(value).endswith("Enabled")


def check_pab_001(snap: AuditSnapshot) -> Finding:
    """BPA-PAB-001: enrolled Prisma Browser devices must pass endpoint posture."""
    cid = "BPA-PAB-001"
    if not snap.browser_devices:
        return Finding(
            check_id=cid,
            title="Browser device posture baseline",
            severity=Severity.MEDIUM,
            status=Status.SKIP,
            description=(
                "No Prisma Access Browser devices enrolled (or PAB not provisioned) — "
                "skipping browser endpoint posture check."
            ),
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    failing = []
    for d in snap.browser_devices:
        missing = [label for key, label in _PAB_POSTURE_FIELDS if not _pab_posture_ok(d.get(key))]
        if missing:
            name = d.get("hostname") or d.get("id") or "<unknown>"
            failing.append(f"{name} (missing: {', '.join(missing)})")
    total = len(snap.browser_devices)
    if not failing:
        return Finding(
            check_id=cid,
            title="Browser devices meet posture baseline",
            severity=Severity.HIGH,
            status=Status.PASS,
            description=(
                f"All {total} enrolled Prisma Browser device(s) have screen lock, "
                "disk encryption, and a host firewall enabled."
            ),
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="Browser devices failing posture baseline",
        severity=Severity.HIGH,
        status=Status.FAIL,
        description=(
            f"{len(failing)} of {total} enrolled Prisma Browser device(s) lack one or "
            "more baseline endpoint controls (screen lock, disk encryption, host "
            "firewall). These devices access organisational SaaS/web apps through the "
            "managed browser without meeting Cyber Essentials secure-configuration "
            "expectations."
        ),
        remediation=(
            "Enforce device posture in the Prisma Access Browser console: create a "
            "device-posture policy requiring screen lock, disk encryption, and an "
            "active host firewall, and restrict or step-up access for non-compliant "
            "devices. Remediate the listed endpoints via MDM/OS policy."
        ),
        affected_objects=failing[:25],
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


def check_pab_002(snap: AuditSnapshot) -> Finding:
    """BPA-PAB-002: active enrolled browser devices should not be stale (>90 days unseen)."""
    cid = "BPA-PAB-002"
    if not snap.browser_devices:
        return Finding(
            check_id=cid,
            title="Stale browser device enrolments",
            severity=Severity.LOW,
            status=Status.SKIP,
            description=(
                "No Prisma Access Browser devices enrolled (or PAB not provisioned) — "
                "skipping stale-enrolment check."
            ),
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    from datetime import UTC, datetime, timedelta

    cutoff = datetime.now(UTC) - timedelta(days=90)
    stale = []
    for d in snap.browser_devices:
        if d.get("status") != "active":
            continue
        last_seen = str(d.get("lastSeen") or "")
        try:
            seen_dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
        except ValueError:
            continue
        if seen_dt < cutoff:
            name = d.get("hostname") or d.get("id") or "<unknown>"
            stale.append(f"{name} (last seen {last_seen[:10]})")
    if not stale:
        return Finding(
            check_id=cid,
            title="No stale browser device enrolments",
            severity=Severity.LOW,
            status=Status.PASS,
            description=(
                f"All active enrolled browser device(s) out of "
                f"{len(snap.browser_devices)} have connected within the last 90 days."
            ),
            remediation="",
            pan_bpa_ref=cid,
            ncsc_refs=_ncsc(cid),
        )
    return Finding(
        check_id=cid,
        title="Stale browser device enrolments",
        severity=Severity.LOW,
        status=Status.FAIL,
        description=(
            f"{len(stale)} active enrolled browser device(s) have not connected in "
            "over 90 days. Stale enrolments inflate the trusted-device inventory and "
            "may represent lost, retired, or re-imaged endpoints that retain access."
        ),
        remediation=(
            "Review the listed devices in the Prisma Access Browser console and "
            "archive or delete enrolments that are no longer in service."
        ),
        affected_objects=stale[:25],
        pan_bpa_ref=cid,
        ncsc_refs=_ncsc(cid),
    )


_ALL_CHECKS = [
    check_sr_001,
    check_sr_002,
    check_sr_003,
    check_sr_004,
    check_sr_005,
    check_sr_006,
    check_sr_007,
    check_sr_008,
    check_sr_009,
    check_sr_010,
    check_tp_001,
    check_tp_002,
    check_tp_003,
    check_tp_004,
    check_tp_005,
    check_tp_006,
    check_dec_002,
    check_tp_007,
    check_url_001,
    check_url_002,
    check_zp_001,
    check_log_001,
    check_log_002,
    check_log_003,
    check_net_001,
    check_net_002,
    # VPN / cryptography
    check_vpn_001,
    check_vpn_002,
    check_vpn_003,
    check_vpn_004,
    # Authentication / identity
    check_auth_001,
    check_auth_002,
    check_auth_003,
    # HIP / endpoint posture
    check_hip_001,
    check_hip_002,
    check_hip_003,
    # NGFW device health
    check_ngw_001,
    check_ngw_002,
    check_ngw_003,
    # Prisma Access Browser / endpoint posture
    check_pab_001,
    check_pab_002,
]


def run_all_checks(snap: AuditSnapshot) -> list[Finding]:
    """Run every registered check and return findings."""
    findings: list[Finding] = []
    for check_fn in _ALL_CHECKS:
        try:
            findings.append(check_fn(snap))
        except Exception as exc:
            findings.append(
                Finding(
                    check_id=check_fn.__name__,
                    title=f"Check error: {check_fn.__name__}",
                    severity=Severity.INFO,
                    status=Status.SKIP,
                    description=f"Check raised an unexpected error: {exc}",
                    remediation="",
                )
            )
    return findings
