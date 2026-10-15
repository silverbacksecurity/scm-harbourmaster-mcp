"""Panorama → SCM migration report: before, after, what changed, and what it means.

``scm_panorama_migrate`` leaves two files behind: the *plan* (the translated
backup plus every :class:`~.panos_import.PlanItem`) and the *pre-migration
backup* of the target folder. With a backup of the target taken after the
push, this module works out what happened to every source object and what
that means for users, integrations and operations.

An object's status comes from the plan items first and the snapshots second.
The plan holds the *translated* objects, so a field the converter dropped is
already missing from them: "translated == SCM" does not mean "Panorama ==
SCM". So:

* a DROPPED / REVIEW / MANUAL item on the object → migrated with changes;
* a GENERATED item → created by the migration (profile groups);
* any difference left between the translated object and SCM → SCM changed
  or normalised it on push, reported separately;
* INVALID / UNSUPPORTED / OVERRIDDEN objects never reach ``resources``, so
  they are listed from the plan items alone.

The impact register is driven by a rule table keyed on the plan item's kind
and action (reason text only where nothing else tells two items apart), so
the same gap always produces the same advice. Every unsupported section and
rulebase the importer knows has a rule; a test enforces that.

Pure functions only — no SCM client or MCP imports.
"""

from __future__ import annotations

import copy
import json
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from .clone_preflight import PROVIDES, UNRENAMED_KEYS, rewrite_references
from .panos_import import (
    DROPPED,
    GENERATED,
    INVALID,
    MANUAL,
    OVERRIDDEN,
    REVIEW,
    UNSUPPORTED,
)

# ── Statuses ─────────────────────────────────────────────────────────────────

MIGRATED = "migrated"
MIGRATED_CHANGED = "migrated_with_changes"
NORMALISED = "migrated_scm_normalised"
CREATED = "created_by_migration"
KEPT_EXISTING = "conflict_kept_existing"
OVERWROTE = "conflict_overwrote"
IDENTICAL = "already_identical"
MISSING = "missing_after_push"
UNATTRIBUTED = "present_unattributed"
NOT_MIGRATED = "not_migrated"
HIDDEN = "hidden_by_nearer_scope"
PRE_EXISTING = "pre_existing"
ADDED_OUTSIDE = "added_outside_migration"

STATUS_TITLES: dict[str, str] = {
    MIGRATED: "Migrated unchanged",
    MIGRATED_CHANGED: "Migrated with changes",
    NORMALISED: "Migrated; SCM changed fields on push",
    CREATED: "Created by the migration",
    KEPT_EXISTING: "Name conflict: existing SCM object kept",
    OVERWROTE: "Name conflict: existing SCM object overwritten",
    IDENTICAL: "Already in SCM, identical",
    MISSING: "Not in SCM after the push",
    UNATTRIBUTED: "In SCM (no pre-migration backup to attribute it)",
    NOT_MIGRATED: "Not migrated",
    HIDDEN: "Hidden by a nearer scope (nearer copy migrated)",
    PRE_EXISTING: "Pre-existing in SCM, untouched",
    ADDED_OUTSIDE: "In SCM, not from this migration",
}

# Statuses that need someone to look at them, in report order
ATTENTION = (MISSING, NOT_MIGRATED, MIGRATED_CHANGED, KEPT_EXISTING, OVERWROTE, NORMALISED)

RULE_KEYS = frozenset(
    {
        "security_rules_pre",
        "security_rules_post",
        "nat_rules_pre",
        "nat_rules_post",
        "decryption_rules",
        "app_override_rules",
    }
)

# Fields SCM adds or that describe placement, never compared
_IGNORED_FIELDS = frozenset(
    {"id", "folder", "snippet", "device", "_folder", "_position", "rulebase", "policy_type"}
)

# Cloud leaf folders evaluate rules by their own order; position isn't kept
_UNORDERED_FOLDERS = frozenset({"Mobile Users", "Remote Networks", "Mobile Users Explicit Proxy"})

# ── Impact register ──────────────────────────────────────────────────────────

USERS = "Users"
SECURITY = "Security"
INTEGRATIONS = "Integrations"
OPERATIONS = "Operations"

_SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


@dataclass(frozen=True)
class Impact:
    severity: str
    area: str
    audience: str
    finding: str
    action: str
    owner: str


@dataclass(frozen=True)
class ImpactRule:
    """Matches plan items by kind and action (and reason text, if set)."""

    action: str
    impact: Impact
    kinds: frozenset[str] | None = None  # None = any kind
    reason_contains: str = ""

    def matches(self, item: dict[str, Any]) -> bool:
        return (
            item.get("action") == self.action
            and (self.kinds is None or item.get("kind") in self.kinds)
            and self.reason_contains in str(item.get("reason", ""))
        )


def _i(sev: str, area: str, audience: str, finding: str, action: str, owner: str) -> Impact:
    return Impact(sev, area, audience, finding, action, owner)


# Unsupported sections and rulebases (PlanItem.kind = the PAN-OS path or tag)
SECTION_IMPACT: dict[str, Impact] = {
    "application": _i(
        "HIGH",
        SECURITY,
        "Users of the custom apps",
        "Custom applications were not migrated. Rules that name them no longer match that traffic.",
        "Recreate the applications in SCM, then re-check the rules that use them.",
        "Security engineering",
    ),
    "schedule": _i(
        "MEDIUM",
        USERS,
        "Users covered by time-based rules",
        "Schedules were not migrated. Rules that used one are now always active.",
        "Recreate the schedules in SCM and re-attach them, or accept always-on.",
        "Security engineering",
    ),
    "profiles/hip-objects": _i(
        "HIGH",
        USERS,
        "Remote users (device posture)",
        "HIP objects were not migrated. Rules that match on device posture stop matching.",
        "Recreate HIP objects in SCM (Mobile Users) before cut-over.",
        "Endpoint / remote access team",
    ),
    "profiles/hip-profiles": _i(
        "HIGH",
        USERS,
        "Remote users (device posture)",
        "HIP profiles were not migrated. Rules that match on device posture stop matching.",
        "Recreate HIP profiles in SCM and re-attach them as source HIP on rules.",
        "Endpoint / remote access team",
    ),
    "dynamic-user-group": _i(
        "HIGH",
        USERS,
        "Users in dynamic user groups",
        "Dynamic user groups were not migrated. Rules that target them no longer match those users.",
        "Recreate the groups in SCM, and the automation that tags users into them.",
        "Identity team",
    ),
    "region": _i(
        "LOW",
        SECURITY,
        "Rules using custom regions",
        "Custom regions were not migrated.",
        "Recreate them as SCM regions or address objects.",
        "Security engineering",
    ),
    "log-settings/profiles": _i(
        "HIGH",
        INTEGRATIONS,
        "SOC / SIEM",
        "Log forwarding profiles were not migrated. Rules keep the profile name, but nothing in SCM "
        "forwards logs with it yet.",
        "Create the log forwarding profile in SCM (Strata Logging Service) and re-point SIEM ingest "
        "before cut-over.",
        "SOC / logging owner",
    ),
    "profiles/data-filtering": _i(
        "MEDIUM",
        SECURITY,
        "Data protection",
        "Data filtering profiles were not migrated. SCM uses Enterprise DLP instead.",
        "Rebuild the data patterns as Enterprise DLP profiles.",
        "Data protection team",
    ),
    "profiles/dos-protection": _i(
        "MEDIUM",
        SECURITY,
        "Internet-facing services",
        "DoS protection profiles were not migrated.",
        "Redesign DoS protection for the SCM-managed firewalls.",
        "Network security",
    ),
    "profiles/data-objects": _i(
        "MEDIUM",
        SECURITY,
        "Data protection",
        "Data patterns were not migrated.",
        "Recreate them as Enterprise DLP data patterns.",
        "Data protection team",
    ),
    "profiles/sdwan-path-quality": _i(
        "MEDIUM",
        OPERATIONS,
        "Branch connectivity",
        "SD-WAN path quality profiles were not migrated.",
        "Recreate SD-WAN profiles in SCM.",
        "Network engineering",
    ),
    "profiles/gtp": _i(
        "LOW",
        SECURITY,
        "Mobile network traffic",
        "GTP profiles were not migrated.",
        "Recreate them in SCM if GTP inspection is in use.",
        "Network security",
    ),
    "profiles/sctp": _i(
        "LOW",
        SECURITY,
        "SCTP traffic",
        "SCTP profiles were not migrated.",
        "Recreate them in SCM if SCTP inspection is in use.",
        "Network security",
    ),
    "threats": _i(
        "HIGH",
        SECURITY,
        "Everyone behind the firewall",
        "Custom threat signatures were not migrated. Those threats are no longer detected.",
        "Recreate the custom signatures in SCM.",
        "Security engineering",
    ),
    "pbf": _i(
        "MEDIUM",
        OPERATIONS,
        "Traffic steered by PBF",
        "Policy-based forwarding rules were not migrated. Traffic follows the routing table instead.",
        "Redesign the steering (SCM PBF or SD-WAN policy).",
        "Network engineering",
    ),
    "qos": _i(
        "MEDIUM",
        USERS,
        "Latency-sensitive apps (voice, video)",
        "QoS rules were not migrated. Traffic is no longer prioritised.",
        "Recreate QoS policy in SCM.",
        "Network engineering",
    ),
    "dos": _i(
        "MEDIUM",
        SECURITY,
        "Internet-facing services",
        "DoS protection rules were not migrated.",
        "Recreate DoS protection policy in SCM.",
        "Network security",
    ),
    "authentication": _i(
        "HIGH",
        USERS,
        "Users prompted for MFA / captive portal",
        "Authentication rules were not migrated. Users are no longer prompted to authenticate.",
        "Recreate authentication policy in SCM before cut-over.",
        "Identity team",
    ),
    "tunnel-inspect": _i(
        "LOW",
        SECURITY,
        "Tunnelled traffic",
        "Tunnel inspection rules were not migrated.",
        "Recreate them in SCM if tunnel inspection is needed.",
        "Network security",
    ),
    "sdwan": _i(
        "MEDIUM",
        OPERATIONS,
        "Branch connectivity",
        "SD-WAN rules were not migrated.",
        "Recreate SD-WAN policy in SCM.",
        "Network engineering",
    ),
    "network-packet-broker": _i(
        "LOW",
        OPERATIONS,
        "Security tool chain",
        "Network packet broker rules were not migrated.",
        "Redesign the packet broker chain.",
        "Network security",
    ),
}
for _alias in ("hip-objects", "hip-profiles"):
    SECTION_IMPACT[_alias] = SECTION_IMPACT[f"profiles/{_alias}"]

# Everything else, first match wins
IMPACT_RULES: tuple[ImpactRule, ...] = (
    ImpactRule(
        UNSUPPORTED,
        _i(
            "MEDIUM",
            SECURITY,
            "Traffic matched by post-rulebase rules",
            "Post-rulebase decryption and app-override rules were not migrated (the clone "
            "pushes these rulebases to pre only).",
            "Recreate them in the SCM pre-rulebase, below the migrated rules.",
            "Security engineering",
        ),
        frozenset({"decryption", "application-override"}),
        "post-rulebase",
    ),
    ImpactRule(
        REVIEW,
        _i(
            "MEDIUM",
            USERS,
            "Users covered by time-based rules",
            "Rules lost their schedule and are now always active.",
            "Check each rule: recreate the schedule in SCM or accept always-on.",
            "Security engineering",
        ),
        RULE_KEYS,
        "schedule",
    ),
    ImpactRule(
        REVIEW,
        _i(
            "LOW",
            SECURITY,
            "Traffic within a zone",
            "Intrazone or interzone rules were migrated as universal rules, so they now also "
            "match the other zone combinations they list.",
            "Check the source and destination zones on each rule.",
            "Security engineering",
        ),
        RULE_KEYS,
        "rule type",
    ),
    ImpactRule(
        REVIEW,
        _i(
            "MEDIUM",
            SECURITY,
            "Traffic matched by these services",
            "Services lost their source port. They now match any source port, so rules using them "
            "allow more than before.",
            "Check the rules that use these services.",
            "Security engineering",
        ),
        frozenset({"services"}),
    ),
    ImpactRule(
        REVIEW,
        _i(
            "MEDIUM",
            USERS,
            "Users who could override a URL block",
            "URL categories set to override fell back to the default action (allow), so users "
            "are no longer asked for the override password.",
            "Set those categories to block or continue in SCM.",
            "Security engineering",
        ),
        frozenset({"url_access_profiles"}),
    ),
    ImpactRule(
        REVIEW,
        _i(
            "LOW",
            OPERATIONS,
            "Configuration owners",
            "Nested fields SCM doesn't support were left out of migrated objects.",
            "Check the listed objects.",
            "Security engineering",
        ),
    ),
    ImpactRule(
        MANUAL,
        _i(
            "HIGH",
            INTEGRATIONS,
            "Threat-feed providers",
            "EDL credentials were not migrated (the export holds them encrypted). Lists that need "
            "authentication fail to download.",
            "Set the credentials on each EDL in SCM, and check the list servers accept "
            "connections from the SCM-managed firewalls' egress IPs.",
            "Security operations",
        ),
        frozenset({"edls"}),
    ),
    ImpactRule(
        MANUAL,
        _i(
            "HIGH",
            SECURITY,
            "Everyone behind the firewall",
            "Antivirus profiles can't be created over the SCM API. Rules and profile groups that "
            "used them have no antivirus inspection until one is added.",
            "Add a WildFire and antivirus profile to each listed profile group in SCM.",
            "Security engineering",
        ),
        frozenset({"virus", "profile_groups", *RULE_KEYS}),
    ),
    ImpactRule(
        MANUAL,
        _i(
            "MEDIUM",
            SECURITY,
            "Traffic hitting the default rules",
            "The device group overrode the intrazone/interzone default rules. SCM uses its own "
            "defaults until they are set.",
            "Set the default rules in the SCM folder's rulebase.",
            "Security engineering",
        ),
        frozenset({"default-security-rules"}),
    ),
    ImpactRule(
        UNSUPPORTED,
        _i(
            "MEDIUM",
            USERS,
            "Users reaching servers via dynamic NAT",
            "NAT rules with dynamic destination translation were not migrated.",
            "Recreate those NAT rules by hand.",
            "Network engineering",
        ),
        frozenset({"nat_rules_pre", "nat_rules_post"}),
    ),
    ImpactRule(
        DROPPED,
        _i(
            "MEDIUM",
            SECURITY,
            "DNS traffic",
            "Anti-spyware DNS policies (botnet domains) were not migrated. SCM keeps them in a "
            "DNS Security profile.",
            "Create a DNS Security profile (scm_create_dns_security_snippet).",
            "Security engineering",
        ),
        frozenset({"anti_spyware_profiles"}),
    ),
    ImpactRule(
        DROPPED,
        _i(
            "MEDIUM",
            SECURITY,
            "Traffic on the listed rules",
            "Security profiles that weren't migrated were left out of rules' profile groups, so "
            "that inspection no longer happens.",
            "Recreate the profiles and add them to the groups.",
            "Security engineering",
        ),
        RULE_KEYS,
        "profile",
    ),
    ImpactRule(
        DROPPED,
        _i(
            "LOW",
            USERS,
            "Latency-sensitive apps",
            "QoS marking was removed from rules.",
            "Recreate QoS marking in SCM if needed.",
            "Network engineering",
        ),
        RULE_KEYS,
        "QoS",
    ),
    ImpactRule(
        DROPPED,
        _i(
            "LOW",
            USERS,
            "Remote users (device posture)",
            "Legacy HIP profiles were removed from rules.",
            "Use source HIP on the rules in SCM.",
            "Endpoint / remote access team",
        ),
        RULE_KEYS,
        "HIP",
    ),
    ImpactRule(
        DROPPED,
        _i(
            "LOW",
            OPERATIONS,
            "Configuration owners",
            "Device targeting was removed from rules (SCM scopes rules by folder).",
            "Check the rules belong in this folder.",
            "Security engineering",
        ),
        RULE_KEYS,
        "device targeting",
    ),
    ImpactRule(
        DROPPED,
        _i(
            "LOW",
            OPERATIONS,
            "Configuration owners",
            "Fields or references with no SCM equivalent were left out.",
            "Check the listed objects.",
            "Security engineering",
        ),
    ),
    ImpactRule(
        INVALID,
        _i(
            "HIGH",
            OPERATIONS,
            "Configuration owners",
            "Objects failed SCM validation and were not migrated.",
            "Fix them in the source or recreate them in SCM.",
            "Security engineering",
        ),
    ),
    ImpactRule(
        GENERATED,
        _i(
            "INFO",
            OPERATIONS,
            "Configuration owners",
            "Profile groups were created, because SCM rules take a group rather than individual "
            "profiles.",
            "No action; keep the names in mind when editing rules.",
            "Security engineering",
        ),
    ),
)

# Plan items with no user, security or operations impact
NO_IMPACT_ACTIONS = frozenset({OVERRIDDEN})

# Not visible in a device-group export: listed so a sign-off doesn't mistake
# them for checked (phase 2 reads the template side of the export)
NOT_ASSESSED: tuple[Impact, ...] = (
    _i(
        "INFO",
        INTEGRATIONS,
        "SOC / SIEM",
        "Logging destination: Panorama and log collectors stop receiving logs; SCM-managed "
        "firewalls log to Strata Logging Service.",
        "Re-point SIEM ingest and check retention.",
        "SOC / logging owner",
    ),
    _i(
        "INFO",
        INTEGRATIONS,
        "Identity",
        "User-ID and LDAP group mapping move to the Cloud Identity Engine.",
        "Set up the Cloud Identity Engine and check group-based rules resolve.",
        "Identity team",
    ),
    _i(
        "INFO",
        INTEGRATIONS,
        "Automation owners",
        "Scripts, Terraform or Ansible that drive the Panorama XML API stop working.",
        "Move them to the SCM REST API (OAuth service account).",
        "Automation owners",
    ),
    _i(
        "INFO",
        USERS,
        "Remote users",
        "GlobalProtect portals, gateways and authentication live in templates, which this "
        "report doesn't read yet.",
        "Review remote-access settings separately.",
        "Endpoint / remote access team",
    ),
)

# Always true of a Panorama → SCM move
PROCESS_IMPACTS: tuple[Impact, ...] = (
    _i(
        "INFO",
        OPERATIONS,
        "Firewall administrators",
        "Changes are made in SCM and pushed from it; Panorama commit and push no longer apply "
        "to the migrated scope.",
        "Update runbooks and admin access; stop editing the device group in Panorama.",
        "Operations lead",
    ),
)


@dataclass
class ImpactRow:
    impact: Impact
    subjects: list[str] = field(default_factory=list)
    assessed: bool = True


def impact_for(item: dict[str, Any]) -> Impact | None:
    """The impact one plan item maps to; None for no impact or no rule."""
    if item.get("action") in NO_IMPACT_ACTIONS:
        return None
    if item.get("action") == UNSUPPORTED and item.get("kind") in SECTION_IMPACT:
        return SECTION_IMPACT[str(item["kind"])]
    for rule in IMPACT_RULES:
        if rule.matches(item):
            return rule.impact
    return None


def impact_register(items: list[dict[str, Any]]) -> list[ImpactRow]:
    """Plan items grouped into impact rows, most severe first."""
    rows: dict[Impact, ImpactRow] = {}
    for item in items:
        imp = impact_for(item)
        if imp is None:
            continue
        row = rows.setdefault(imp, ImpactRow(imp))
        subject = f"{item.get('kind')}: {item.get('name')}"
        if subject not in row.subjects:
            row.subjects.append(subject)
    out = sorted(rows.values(), key=lambda r: _SEVERITY_ORDER.get(r.impact.severity, 9))
    out += [ImpactRow(i) for i in PROCESS_IMPACTS]
    out += [ImpactRow(i, assessed=False) for i in NOT_ASSESSED]
    return out


# ── Change audit ─────────────────────────────────────────────────────────────


@dataclass
class ObjectRow:
    kind: str
    name: str
    target_name: str
    status: str
    detail: str = ""


@dataclass
class RuleOrder:
    rulebase: str
    preserved: bool | None  # None = not checked (unordered folder or < 2 rules)
    detail: str = ""


@dataclass
class MigrationReport:
    source: str
    settings: dict[str, Any]
    target_folder: str
    tenant_id: str
    source_counts: dict[str, int]
    before_counts: dict[str, int] | None
    after_counts: dict[str, int]
    item_counts: dict[str, int]
    rows: list[ObjectRow]
    impacts: list[ImpactRow]
    rule_order: list[RuleOrder]
    warnings: list[str] = field(default_factory=list)

    def status_counts(self) -> Counter[str]:
        return Counter(r.status for r in self.rows)


def _norm(value: Any) -> Any:
    if value in (None, "", [], {}):
        return None
    if isinstance(value, dict):
        out = {k: _norm(v) for k, v in value.items()}
        return {k: v for k, v in out.items() if v is not None} or None
    if isinstance(value, list):
        items = [_norm(v) for v in value]
        return sorted(items, key=lambda v: json.dumps(v, sort_keys=True, default=str))
    return value


def changed_fields(expected: dict[str, Any], actual: dict[str, Any]) -> list[str]:
    """Fields of *expected* whose value differs in *actual* (SCM-only fields ignored)."""
    return sorted(
        k
        for k, v in expected.items()
        if k not in _IGNORED_FIELDS and k != "name" and _norm(v) != _norm(actual.get(k))
    )


def _index(resources: dict[str, Any] | None) -> dict[str, dict[str, dict[str, Any]]]:
    out: dict[str, dict[str, dict[str, Any]]] = {}
    for key, objs in (resources or {}).items():
        if isinstance(objs, list):
            out[key] = {str(o["name"]): o for o in objs if isinstance(o, dict) and o.get("name")}
    return out


def _counts(resources: dict[str, Any] | None) -> dict[str, int]:
    return {k: len(v) for k, v in (resources or {}).items() if isinstance(v, list) and v}


def _renames(resources: dict[str, Any], prefix: str) -> dict[str, dict[str, str]]:
    """kind → source name → target name, as the cloner builds them."""
    renames: dict[str, dict[str, str]] = {}
    if not prefix:
        return renames
    for key, kinds in PROVIDES.items():
        if key in UNRENAMED_KEYS:
            continue
        for obj in resources.get(key) or []:
            name = str(obj.get("name") or "") if isinstance(obj, dict) else ""
            if name:
                for kind in kinds:
                    renames.setdefault(kind, {})[name] = f"{prefix}{name}"
    return renames


def _reasons(items: list[dict[str, Any]]) -> str:
    return "; ".join(f"{i['action']}: {i['reason']}" for i in items)


def build_report(
    plan: dict[str, Any],
    pre: dict[str, Any] | None,
    post: dict[str, Any],
    *,
    target_folder: str,
    tenant_id: str = "",
    name_prefix: str = "",
) -> MigrationReport:
    """Compare the plan's source objects with the target before and after the push."""
    resources: dict[str, Any] = plan.get("resources") or {}
    items: list[dict[str, Any]] = [i for i in plan.get("plan_items") or [] if isinstance(i, dict)]
    pre_idx = _index(pre.get("resources") if pre else None)
    post_idx = _index(post.get("resources"))
    renames = _renames(resources, name_prefix)

    by_object: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for it in items:
        by_object.setdefault((str(it.get("kind")), str(it.get("name"))), []).append(it)

    rows: list[ObjectRow] = []
    targets: dict[str, set[str]] = {}
    for key, objs in resources.items():
        if not isinstance(objs, list):
            continue
        for obj in objs:
            if not isinstance(obj, dict) or not obj.get("name"):
                continue
            name = str(obj["name"])
            tname = name if key in UNRENAMED_KEYS else f"{name_prefix}{name}"
            targets.setdefault(key, set()).add(tname)
            expected = rewrite_references(key, copy.deepcopy(obj), renames)
            mine = by_object.get((key, name), [])
            actions = {i.get("action") for i in mine}
            after = post_idx.get(key, {}).get(tname)
            before = pre_idx.get(key, {}).get(tname) if pre is not None else None
            reasons = _reasons(mine)

            if after is None:
                why = reasons or "push failed or was skipped: see the migrate job's push report"
                rows.append(ObjectRow(key, name, tname, MISSING, why))
                continue
            diff = changed_fields(expected, after)
            scm_note = f"SCM differs in: {', '.join(diff)}" if diff else ""
            if pre is None:
                status = UNATTRIBUTED
            elif before is not None:
                if not diff:
                    # SCM now matches the source: it already did, or the push replaced it
                    status = OVERWROTE if changed_fields(expected, before) else IDENTICAL
                elif not changed_fields(after, before):
                    status = KEPT_EXISTING
                else:
                    status = OVERWROTE
            elif GENERATED in actions:
                status = CREATED
            elif actions & {DROPPED, REVIEW, MANUAL}:
                status = MIGRATED_CHANGED
            elif diff:
                status = NORMALISED
            else:
                status = MIGRATED
            detail = "; ".join(d for d in (reasons, scm_note) if d)
            rows.append(ObjectRow(key, name, tname, status, detail))

    # Plan items for objects the translation left out of resources
    in_resources = {(r.kind, r.name) for r in rows}
    for (kind, name), mine in by_object.items():
        if (kind, name) in in_resources:
            continue
        actions = {i.get("action") for i in mine}
        status = HIDDEN if actions <= {OVERRIDDEN} else NOT_MIGRATED
        rows.append(ObjectRow(kind, name, "", status, _reasons(mine)))

    # SCM-side objects this migration didn't produce
    for key, objs in post_idx.items():
        for tname in objs:
            if tname in targets.get(key, set()):
                continue
            if pre is not None and tname in pre_idx.get(key, {}):
                rows.append(ObjectRow(key, "", tname, PRE_EXISTING))
            elif pre is not None:
                rows.append(ObjectRow(key, "", tname, ADDED_OUTSIDE))

    return MigrationReport(
        source=str(plan.get("migrated_from") or ""),
        settings=dict(plan.get("migration") or {}),
        target_folder=target_folder,
        tenant_id=tenant_id,
        source_counts=_counts(resources),
        before_counts=_counts(pre.get("resources")) if pre is not None else None,
        after_counts=_counts(post.get("resources")),
        item_counts=dict(Counter(str(i.get("action")) for i in items)),
        rows=rows,
        impacts=impact_register(items),
        rule_order=_rule_order(resources, post_idx, target_folder, name_prefix),
    )


def _rule_order(
    resources: dict[str, Any],
    post_idx: dict[str, dict[str, dict[str, Any]]],
    target_folder: str,
    prefix: str,
) -> list[RuleOrder]:
    out: list[RuleOrder] = []
    for key in sorted(RULE_KEYS):
        source = [f"{prefix}{o['name']}" for o in resources.get(key) or [] if o.get("name")]
        landed = [n for n in source if n in post_idx.get(key, {})]
        if len(landed) < 2:
            continue
        if target_folder in _UNORDERED_FOLDERS:
            out.append(
                RuleOrder(
                    key, None, f"`{target_folder}` evaluates rules by its own order; not checked"
                )
            )
            continue

        def pos(n: str, key: str = key) -> float:
            p = post_idx[key][n].get("_position")
            return float(p) if isinstance(p, int | float) else float("inf")

        actual = sorted(landed, key=pos)
        if actual == landed:
            out.append(RuleOrder(key, True, f"{len(landed)} rules in Panorama order"))
        else:
            first = next(i for i, (a, b) in enumerate(zip(landed, actual, strict=True)) if a != b)
            out.append(
                RuleOrder(
                    key,
                    False,
                    f"order differs from rule {first + 1}: expected `{landed[first]}`, "
                    f"found `{actual[first]}`",
                )
            )
    return out


# ── Rendering ────────────────────────────────────────────────────────────────


def _cell(value: Any) -> str:
    text = str(value) if value not in (None, "") else "—"
    return text.replace("|", "\\|").replace("\n", " ")


def _names(names: list[str], cap: int = 12) -> str:
    shown = ", ".join(f"`{n}`" for n in names[:cap])
    return shown + (f" and {len(names) - cap} more" if len(names) > cap else "")


def render_markdown(rep: MigrationReport, files: dict[str, str], generated_at: str) -> str:
    s = rep.settings
    counts = rep.status_counts()
    lines = [
        "# Panorama → SCM Migration Report",
        "",
        "| | |",
        "|---|---|",
        f"| **Source** | {_cell(rep.source)} |",
        f"| **Target folder** | `{rep.target_folder}` |",
        f"| **Tenant** | `{rep.tenant_id or 'default'}` |",
        f"| **Name prefix** | {_cell(s.get('name_prefix') and f'`{s["name_prefix"]}`')} |",
        f"| **On conflict** | {_cell(s.get('on_conflict'))} |",
        f"| **Report generated** | {generated_at} |",
        *(f"| **{label}** | `{path}` |" for label, path in files.items() if path),
        "",
    ]
    lines += [f"> ⚠️ {w}" for w in rep.warnings]
    if rep.warnings:
        lines.append("")

    sev = Counter(r.impact.severity for r in rep.impacts if r.assessed)
    attention = sum(counts[s_] for s_ in ATTENTION)
    lines += [
        "## 1. Summary",
        "",
        f"- **Objects from Panorama:** {sum(rep.source_counts.values())} translated, "
        f"{counts[MIGRATED] + counts[MIGRATED_CHANGED] + counts[NORMALISED] + counts[CREATED]} "
        f"created in SCM, {counts[MISSING]} missing after the push.",
        f"- **Needs attention:** {attention} object(s) — see section 4.",
        "- **Impact register:** "
        + " · ".join(
            f"{n} {k}" for k, n in sorted(sev.items(), key=lambda kv: _SEVERITY_ORDER[kv[0]])
        )
        + f" — plus {sum(1 for r in rep.impacts if not r.assessed)} area(s) not assessed from "
        "the export (section 6).",
        "",
        "## 2. Panorama as-is (source)",
        "",
        f"**Scopes (nearest first):** {', '.join(s.get('scopes') or []) or '—'}",
        "",
        "| Object type | Translated |",
        "|---|---|",
        *(f"| `{k}` | {n} |" for k, n in sorted(rep.source_counts.items())),
        "",
        "| Plan item | Count |",
        "|---|---|",
        *(f"| {k} | {n} |" for k, n in sorted(rep.item_counts.items())),
        "",
        "## 3. SCM as-is (target)",
        "",
    ]
    kinds = sorted(set(rep.after_counts) | set(rep.before_counts or {}) | set(rep.source_counts))
    if rep.before_counts is None:
        lines += ["| Object type | After |", "|---|---|"]
        lines += [f"| `{k}` | {rep.after_counts.get(k, 0)} |" for k in kinds]
    else:
        lines += ["| Object type | Before | After | Δ |", "|---|---|---|---|"]
        for k in kinds:
            b, a = rep.before_counts.get(k, 0), rep.after_counts.get(k, 0)
            lines.append(f"| `{k}` | {b} | {a} | {a - b:+d} |")
    lines += [
        "",
        "For the full SCM design document, run `scm_asbuilt_report` on the target folder.",
        "",
        "## 4. Change audit",
        "",
        "| Status | Objects |",
        "|---|---|",
        *(f"| {STATUS_TITLES[st]} | {counts[st]} |" for st in STATUS_TITLES if counts[st]),
        "",
    ]
    for st in ATTENTION:
        rows = [r for r in rep.rows if r.status == st]
        if not rows:
            continue
        lines += [
            f"### {STATUS_TITLES[st]} ({len(rows)})",
            "",
            "| Type | Name | In SCM as | Detail |",
        ]
        lines += ["|---|---|---|---|"]
        lines += [
            f"| `{r.kind}` | {_cell(r.name)} | {_cell(r.target_name)} | {_cell(r.detail)} |"
            for r in rows
        ]
        lines.append("")
    clean = [r for r in rep.rows if r.status in (MIGRATED, CREATED, IDENTICAL, UNATTRIBUTED)]
    if clean:
        by_kind: dict[str, list[str]] = {}
        for r in clean:
            by_kind.setdefault(r.kind, []).append(r.target_name)
        lines += ["### Migrated cleanly", "", "| Type | Objects |", "|---|---|"]
        lines += [f"| `{k}` | {_names(v)} |" for k, v in sorted(by_kind.items())]
        lines.append("")
    outside = [r for r in rep.rows if r.status in (PRE_EXISTING, ADDED_OUTSIDE)]
    if outside:
        lines += [
            f"SCM also holds {sum(r.status == PRE_EXISTING for r in outside)} pre-existing "
            f"object(s) and {sum(r.status == ADDED_OUTSIDE for r in outside)} added outside "
            "this migration in the target folder.",
            "",
        ]

    lines += ["## 5. Rule order", ""]
    if rep.rule_order:
        lines += ["| Rulebase | Result | Detail |", "|---|---|---|"]
        for ro in rep.rule_order:
            mark = {True: "✅ preserved", False: "❌ changed", None: "— not checked"}[ro.preserved]
            lines.append(f"| `{ro.rulebase}` | {mark} | {_cell(ro.detail)} |")
    else:
        lines.append("_Fewer than two migrated rules per rulebase; nothing to compare._")
    lines += [
        "",
        "## 6. Impact register",
        "",
        "| Severity | Area | Who is affected | Finding | Action | Owner | Affected |",
        "|---|---|---|---|---|---|---|",
    ]
    for ir in (x for x in rep.impacts if x.assessed):
        i = ir.impact
        lines.append(
            f"| {i.severity} | {i.area} | {_cell(i.audience)} | {_cell(i.finding)} | "
            f"{_cell(i.action)} | {_cell(i.owner)} | {_cell(_names(ir.subjects, 8))} |"
        )
    lines += [
        "",
        "### Not assessed from the export",
        "",
        "These can't be seen in a device-group export. Check them separately before sign-off.",
        "",
        "| Area | Who is affected | What to check | Action | Owner |",
        "|---|---|---|---|---|",
    ]
    for ir in (x for x in rep.impacts if not x.assessed):
        i = ir.impact
        lines.append(
            f"| {i.area} | {_cell(i.audience)} | {_cell(i.finding)} | {_cell(i.action)} | "
            f"{_cell(i.owner)} |"
        )
    lines += [
        "",
        "## 7. Sign-off",
        "",
        "| Role | Name | Date | Comments |",
        "|---|---|---|---|",
        "| Migration engineer | | | |",
        "| Customer technical owner | | | |",
        "| Security / SOC | | | |",
        "",
    ]
    return "\n".join(lines)
