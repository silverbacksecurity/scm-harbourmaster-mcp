"""
Pre-commit blast-radius analysis for the commit gate (scm_commit_preview).

Answers "what happens if I commit right now?" before scm_commit is issued:

  1. Pending changes — the candidate config (a fresh extraction reads
     candidate state) diffed against the drift baseline (last known-good),
     section by section, using the same diff engine as the drift sentinel.
  2. Rule shadowing — new/changed security rules that can never match
     because an earlier rule already covers their traffic, or that
     themselves shadow existing rules below them. Source/destination are
     compared by real CIDR containment (stdlib `ipaddress`), resolving
     address-group membership recursively — not just literal string equality.
  3. BPA delta — best-practice findings the pending change introduces or
     resolves, by running the check engine against both states.

The verdict triages the lot into 🔴 HIGH RISK / 🟡 REVIEW / 🟢 LOW RISK with
every claim citing the object or check that produced it.

Pure functions only — no SCM client or MCP imports.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

from .asbuilt_verify import SectionDiff, _name_list
from .drift_baseline import drift_severity
from .models import Finding, Status

# Rule match dimensions checked for shadowing. SDK model_dump() emits
# from_/to_ (Pydantic alias), raw REST emits from/to — accept either.
# source/destination get CIDR-aware treatment (_addr_covers); the rest are
# zone/App-ID/service names with no IP semantics, so literal-set containment
# (_covers) is the correct comparison for them.
_LITERAL_MATCH_FIELDS = [
    ("from_", "from"),
    ("to_", "to"),
    ("application", "application"),
    ("service", "service"),
]
_ADDRESS_FIELDS = [
    ("source", "source", "negate_source"),
    ("destination", "destination", "negate_destination"),
]

_IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def _vals(rule: dict[str, Any], keys: tuple[str, str]) -> list[str]:
    raw = rule.get(keys[0]) or rule.get(keys[1]) or ["any"]
    return [str(v) for v in raw] if isinstance(raw, list) else [str(raw)]


def _covers(a: list[str], b: list[str]) -> bool:
    """True when rule-field values *a* cover every value in *b*."""
    if "any" in a:
        return True
    if "any" in b:
        return False
    return set(b) <= set(a)


def _parse_ip_literal(value: str) -> list[_IPNetwork] | None:
    """Parse a literal IP/CIDR or hyphenated IP range. None if not IP syntax at all."""
    value = value.strip()
    if value.count("-") == 1 and not value.startswith("-"):
        lo, _, hi = value.partition("-")
        try:
            return list(
                ipaddress.summarize_address_range(
                    ipaddress.ip_address(lo.strip()), ipaddress.ip_address(hi.strip())
                )
            )
        except ValueError:
            pass  # not a range — might be an object/group name containing a hyphen
        except TypeError:
            # summarize_address_range raises TypeError (not ValueError) when the
            # two endpoints are different IP versions (e.g. "10.0.0.1-::1") — a
            # malformed range, not valid IP syntax at all. Treat it the same as
            # the ValueError case: fall through to "not a range".
            pass
    try:
        return [ipaddress.ip_network(value, strict=False)]
    except ValueError:
        return None


def _address_object_networks(addr: dict[str, Any]) -> list[_IPNetwork] | None:
    """Resolve an Address object to concrete networks. None if unresolvable.

    ip_netmask/ip_range are supported. ip_wildcard (non-contiguous bit masks
    aren't representable as CIDR blocks in general) and fqdn (needs live DNS
    resolution, and is unstable even then) are deliberately left unresolvable.
    """
    if addr.get("ip_netmask"):
        return _parse_ip_literal(str(addr["ip_netmask"]))
    if addr.get("ip_range"):
        return _parse_ip_literal(str(addr["ip_range"]))
    return None


def build_address_index(
    addresses: list[dict[str, Any]] | None,
    address_groups: list[dict[str, Any]] | None,
) -> dict[str, set[_IPNetwork] | None]:
    """name -> resolved CIDR networks, recursively through nested static groups.

    A value of None means "unresolvable" (fqdn/ip_wildcard address, a dynamic
    (tag-filter) group, an unknown name — external dynamic list, region object,
    etc. — or a membership cycle) — callers must treat that as "can't prove
    coverage", not as "covers nothing".
    """
    addr_by_name = {a["name"]: a for a in (addresses or []) if a.get("name")}
    group_by_name = {g["name"]: g for g in (address_groups or []) if g.get("name")}
    cache: dict[str, set[_IPNetwork] | None] = {}

    def resolve(name: str, stack: frozenset[str]) -> set[_IPNetwork] | None:
        if name in cache:
            return cache[name]
        if name in stack:
            cache[name] = None  # membership cycle — bail conservatively
            return None
        result: set[_IPNetwork] | None
        if name in addr_by_name:
            nets = _address_object_networks(addr_by_name[name])
            result = set(nets) if nets is not None else None
        elif name in group_by_name:
            group = group_by_name[name]
            if group.get("dynamic"):
                result = None
            else:
                members = group.get("static") or []
                out: set[_IPNetwork] = set()
                result = out
                for member in members:
                    sub = resolve(member, stack | {name})
                    if sub is None:
                        result = None
                        break
                    out |= sub
        else:
            result = None  # unknown name — EDL, region object, or not yet extracted
        cache[name] = result
        return result

    return {n: resolve(n, frozenset()) for n in {*addr_by_name, *group_by_name}}


def _resolve_value(value: str, index: dict[str, set[_IPNetwork] | None]) -> set[_IPNetwork] | None:
    literal = _parse_ip_literal(value)
    if literal is not None:
        return set(literal)
    return index.get(value)


def _resolve_all(
    tokens: list[str], index: dict[str, set[_IPNetwork] | None]
) -> set[_IPNetwork] | None:
    out: set[_IPNetwork] = set()
    for token in tokens:
        resolved = _resolve_value(token, index)
        if resolved is None:
            return None
        out |= resolved
    return out


def _is_subnet_of(inner: _IPNetwork, outer: _IPNetwork) -> bool:
    """Same-version CIDR containment; cross-version pairs are never a match."""
    if isinstance(inner, ipaddress.IPv4Network) and isinstance(outer, ipaddress.IPv4Network):
        return inner.subnet_of(outer)
    if isinstance(inner, ipaddress.IPv6Network) and isinstance(outer, ipaddress.IPv6Network):
        return inner.subnet_of(outer)
    return False


def _addr_covers(
    a_vals: list[str],
    a_nets: set[_IPNetwork] | None,
    b_vals: list[str],
    b_nets: set[_IPNetwork] | None,
) -> bool:
    """True when address-field values *a* cover every value in *b*, by real CIDR
    containment when every token on both sides resolved to concrete networks
    (*a_nets*/*b_nets* — precomputed once per rule by the caller, see
    `find_shadowed_rules`, rather than re-resolved on every pairing).

    Falls back to literal-value comparison (the pre-upgrade behaviour) when
    resolution is incomplete — an FQDN/wildcard address, a dynamic group, or a
    name not present in the snapshot (EDL, region object) — so this is a
    strict superset of what the old literal-only check caught, never a
    regression when address/address_group data isn't available.
    """
    if "any" in a_vals:
        return True
    if "any" in b_vals:
        return False
    if a_nets is not None and b_nets is not None:
        return all(any(_is_subnet_of(bn, an) for an in a_nets) for bn in b_nets)
    return set(b_vals) <= set(a_vals)


# Remote Networks and Mobile Users are mutually exclusive Prisma Access
# enforcement pipelines — a branch's traffic never transits the Mobile Users
# gateway and vice versa. Rules that exist ONLY in one of these two folders
# (extractor.py `_rule_folders`) must never be compared against each other
# for shadowing, even though both get flattened into one merged rulebase
# list (for pre/post ordering) alongside the queried base folder's rules.
# Any other `_folder` value — the queried base folder itself (e.g. "Prisma
# Access"), or an absent `_folder` on hand-built fixtures that predate the
# multi-folder merge — is treated as globally inherited scope: querying that
# folder returns rules inherited from parent folders, which DO apply to
# every child scope, so such a rule can legitimately shadow (or be shadowed
# by) a Remote-Networks-only or Mobile-Users-only rule.
_EXCLUSIVE_SCOPES = frozenset({"Remote Networks", "Mobile Users"})


def _scopes_overlap(a_folder: str | None, b_folder: str | None) -> bool:
    """True when two rules' defining folders can plausibly see the same
    traffic — false only when both sides are exclusive scopes and they
    differ (Remote Networks vs Mobile Users)."""
    a = a_folder if a_folder in _EXCLUSIVE_SCOPES else None
    b = b_folder if b_folder in _EXCLUSIVE_SCOPES else None
    if a is None or b is None:
        return True
    return a == b


def rule_identity(rule: dict[str, Any]) -> str:
    """Best-effort unique identity for one rule *instance*.

    A bare rule name is unique within a single rulebase/folder but NOT
    guaranteed unique across the merged pre+post, multi-folder rulebase this
    module analyses — the same name can legitimately appear once in the
    pre-rulebase and again in the post-rulebase (or in two different merged
    folders). Using the bare name alone as a lookup key (e.g. for per-rule
    metadata) can then silently attribute a finding to the wrong rule
    instance. Prefers the real SCM object id, which the extractor captures
    on every rule; falls back to a folder+rulebase+name composite when no id
    is present (e.g. hand-built test fixtures).
    """
    rid = rule.get("id")
    if rid:
        return f"id:{rid}"
    name = str(rule.get("name", "?"))
    return f"{rule.get('_folder', '?')}::{rule.get('_position', '?')}::{name}"


@dataclass
class _PreparedRule:
    """One rule's field values / resolved CIDR sets / identity, computed once
    up front so the O(n^2) pair loop in `find_shadowed_rules` doesn't redo
    this work on every pairing a rule takes part in."""

    rule: dict[str, Any]
    name: str
    identity: str
    folder: str | None
    negated: bool
    addr_vals: dict[str, list[str]]
    addr_nets: dict[str, set[_IPNetwork] | None]
    literal_vals: dict[str, list[str]]
    action: str


def _in_focus(name: str, rule: dict[str, Any], focus: set[str | tuple[str, str]]) -> bool:
    """True when *rule* (named *name*) matches a focus_names entry.

    A bare-string entry matches on name alone, anywhere in the rulebase — the
    original, coarser behaviour. A `(position, name)` tuple entry (position
    being the rule's own `_position`, "pre"/"post") additionally requires the
    rulebase to match, so a same-named rule in the *other* rulebase — which
    may carry an unrelated, pre-existing shadow — isn't pulled in just
    because it shares a name with the rule the caller actually means to
    focus on.
    """
    if name in focus:
        return True
    pos = rule.get("_position")
    return pos is not None and (pos, name) in focus


def find_shadowed_rules(
    rules: list[dict[str, Any]],
    focus_names: set[str | tuple[str, str]] | None = None,
    *,
    addresses: list[dict[str, Any]] | None = None,
    address_groups: list[dict[str, Any]] | None = None,
    index: dict[str, set[_IPNetwork] | None] | None = None,
) -> list[dict[str, str]]:
    """Detect rules that an earlier rule fully covers (classic shadow).

    Rule A shadows rule B when A precedes B and A's from/to/source/
    destination/application/service each cover B's — B can then never match.
    source/destination are checked by real CIDR containment: address-group
    (and nested group) membership is resolved recursively against `addresses`/
    `address_groups`. Pass the snapshot's, or pass a pre-built `index` (e.g.
    from a prior `build_address_index()` call) when the caller already needs
    one for something else too — `unresolved_address_names()`, say — so the
    (potentially large, recursive) address/group inventory only gets resolved
    once. `index` takes priority when given; `addresses`/`address_groups` are
    ignored in that case.

    Note: omitting `addresses`/`address_groups`/`index` entirely does *not*
    reproduce the pre-upgrade literal-value-only comparison for every field —
    it only disables address-*group* membership resolution. A bare CIDR/IP
    literal in source/destination (as opposed to an address-object name)
    still gets real containment treatment regardless, since parsing a literal
    needs no index at all.

    FQDN/ip_wildcard addresses, dynamic (tag-filter) groups, and names absent
    from the snapshot (EDLs, region objects) can't be resolved to concrete
    networks, so those pairs fall back to literal comparison rather than risk
    a false "shadowed" claim. A rule using `negate_source`/`negate_destination`
    inverts that field's meaning ("match everything except"), which this
    containment math doesn't model, so any pair where either rule negates
    either field is skipped entirely rather than risk a false claim. One
    ordering caveat: the extracted rulebase merges rules from several
    folders, which approximates but may not equal SCM's true evaluation
    order — treat a flagged shadow as "verify the rule positions", not as
    proof.

    Remote Networks and Mobile Users are mutually exclusive Prisma Access
    enforcement scopes (see `_scopes_overlap`): a rule defined only in one of
    those two folders is never compared against a rule defined only in the
    other, since neither ever evaluates the other's traffic. A rule defined
    in the queried base folder (or with no `_folder` tag at all, e.g. a
    hand-built single-folder rule list) is treated as globally inherited and
    can shadow, or be shadowed by, either exclusive scope.

    focus_names limits findings to pairs where the shadowing or shadowed
    rule is in the set (the pending change), keeping pre-existing shadow
    noise out of a commit preview. Entries may be bare rule names, or
    `(rule["_position"], name)` tuples for callers that can disambiguate —
    prefer tuples whenever the same rule name might appear in both
    rulebases, since a bare-name entry matches that name in *either*
    rulebase (see `_in_focus`). None means report everything.

    Each finding carries `shadowed_id`/`by_id` (see `rule_identity()`)
    alongside the bare-name `shadowed`/`by` fields, for callers needing to
    look up per-instance metadata without risking a same-name collision.
    """
    if index is None:
        index = build_address_index(addresses, address_groups)
    active = [r for r in rules if not r.get("disabled")]

    # Precompute each rule's field values, resolved CIDR sets, and identity
    # ONCE up front rather than inside the O(n^2) pair loop below — without
    # this, a rule near the top of a large rulebase has its source/
    # destination re-parsed and re-resolved against the address index on
    # every later pairing it takes part in.
    prepared: list[_PreparedRule] = []
    for r in active:
        name = str(r.get("name", "?"))
        addr_vals = {k1: _vals(r, (k1, k2)) for k1, k2, _ in _ADDRESS_FIELDS}
        addr_nets = {k1: _resolve_all(addr_vals[k1], index) for k1, _, _ in _ADDRESS_FIELDS}
        literal_vals = {f[0]: _vals(r, f) for f in _LITERAL_MATCH_FIELDS}
        prepared.append(
            _PreparedRule(
                rule=r,
                name=name,
                identity=rule_identity(r),
                folder=r.get("_folder"),
                negated=any(r.get(neg) for _, _, neg in _ADDRESS_FIELDS),
                addr_vals=addr_vals,
                addr_nets=addr_nets,
                literal_vals=literal_vals,
                action=str(r.get("action", "?")),
            )
        )

    findings: list[dict[str, str]] = []
    for i, earlier in enumerate(prepared):
        for later in prepared[i + 1 :]:
            if focus_names is not None and not (
                _in_focus(earlier.name, earlier.rule, focus_names)
                or _in_focus(later.name, later.rule, focus_names)
            ):
                continue
            if earlier.negated or later.negated:
                continue
            if not _scopes_overlap(earlier.folder, later.folder):
                continue
            addr_ok = all(
                _addr_covers(
                    earlier.addr_vals[k1],
                    earlier.addr_nets[k1],
                    later.addr_vals[k1],
                    later.addr_nets[k1],
                )
                for k1, _, _ in _ADDRESS_FIELDS
            )
            if not addr_ok:
                continue
            literal_ok = all(
                _covers(earlier.literal_vals[f[0]], later.literal_vals[f[0]])
                for f in _LITERAL_MATCH_FIELDS
            )
            if literal_ok:
                e_name, l_name = earlier.name, later.name
                findings.append(
                    {
                        "shadowed": l_name,
                        "by": e_name,
                        "shadowed_id": later.identity,
                        "by_id": earlier.identity,
                        "detail": (
                            f"`{e_name}` (action: {earlier.action}) precedes and "
                            f"fully covers `{l_name}` (action: {later.action}) — "
                            f"`{l_name}` can never match"
                        ),
                    }
                )
    return findings


def bpa_delta(
    reference: list[Finding], candidate: list[Finding]
) -> tuple[list[Finding], list[Finding]]:
    """(introduced, resolved) FAIL-status findings between the two states."""
    ref_fails = {f.check_id for f in reference if f.status == Status.FAIL}
    cand_fails = {f.check_id: f for f in candidate if f.status == Status.FAIL}
    introduced = [f for cid, f in cand_fails.items() if cid not in ref_fails]
    resolved = [f for f in reference if f.status == Status.FAIL and f.check_id not in cand_fails]
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    introduced.sort(key=lambda f: sev_order.get(str(f.severity), 9))
    resolved.sort(key=lambda f: sev_order.get(str(f.severity), 9))
    return introduced, resolved


def preview_verdict(
    diffs: list[SectionDiff],
    shadows: list[dict[str, str]],
    introduced: list[Finding],
) -> str:
    """HIGH RISK / REVIEW / LOW RISK / NO CHANGES."""
    if not diffs and not shadows and not introduced:
        return "NO CHANGES"
    new_high_bpa = any(str(f.severity) in ("critical", "high") for f in introduced)
    high_removals = any(drift_severity(d) == "HIGH" and (d.removed or d.changed) for d in diffs)
    if shadows or new_high_bpa or high_removals:
        return "HIGH RISK"
    if introduced or any(drift_severity(d) == "HIGH" for d in diffs):
        return "REVIEW"
    return "LOW RISK"


_VERDICT_LINE = {
    "NO CHANGES": "🟢 **NO PENDING CHANGES** — candidate matches the baseline; commit is a no-op",
    "LOW RISK": "🟢 **LOW RISK** — object plumbing only; no enforcement change detected",
    "REVIEW": "🟡 **REVIEW** — enforcement-relevant changes present; read the detail below",
    "HIGH RISK": "🔴 **HIGH RISK** — do not commit until every item below is explained",
}


def render_commit_preview(
    diffs: list[SectionDiff],
    shadows: list[dict[str, str]],
    introduced: list[Finding],
    resolved: list[Finding],
    tenant_label: str,
    folder: str,
    baseline_saved_at: str,
    generated_at: str,
) -> str:
    verdict = preview_verdict(diffs, shadows, introduced)
    lines = [
        "# Commit Preview — Blast Radius",
        "",
        f"**Tenant:** `{tenant_label}`  |  **Folder:** `{folder}`  |  "
        f"**Baseline:** {baseline_saved_at}  |  **Generated:** {generated_at}",
        "",
        _VERDICT_LINE[verdict],
        "",
    ]

    if diffs:
        lines += ["## Pending Changes vs Last Known-Good", ""]
        for d in diffs:
            sev = drift_severity(d)
            icon = {"HIGH": "🔴", "MEDIUM": "🟡"}.get(sev, "⚪")
            parts = []
            if d.added:
                parts.append(f"adds {_name_list(d.added, cap=10)}")
            if d.removed:
                parts.append(f"removes {_name_list(d.removed, cap=10)}")
            if d.changed:
                parts.append(f"modifies {_name_list(d.changed, cap=10)}")
            lines.append(f"- {icon} **[{sev}] {d.label}**: " + "; ".join(parts))
        lines.append("")

    if shadows:
        lines += ["## Rule Shadowing Introduced", ""]
        for s in shadows:
            lines.append(f"- 🔴 {s['detail']}")
        lines.append("")

    if introduced:
        lines += ["## Best-Practice Findings Introduced by This Change", ""]
        for f in introduced:
            objs = (
                f" — affects {_name_list(f.affected_objects, cap=5)}" if f.affected_objects else ""
            )
            lines.append(f"- 🔴 **[{str(f.severity).upper()}] {f.check_id}** {f.title}{objs}")
        lines.append("")

    if resolved:
        lines += ["## Findings Resolved by This Change", ""]
        for f in resolved:
            lines.append(f"- ✅ **{f.check_id}** {f.title}")
        lines.append("")

    if verdict == "NO CHANGES":
        return "\n".join(lines)

    lines += ["## Next Step", ""]
    if verdict == "HIGH RISK":
        lines.append("Resolve or explicitly accept each 🔴 item (change ticket reference), then:")
    else:
        lines.append("If the changes match the change ticket, proceed:")
    lines += [
        "",
        f'1. `scm_commit(folders=["{folder}"], ticket_ref="<ticket ref>", dry_run=False)`',
        f'2. `scm_drift_check(folder="{folder}", update_baseline=True)` — roll the '
        "baseline forward so the next preview diffs against this approved state.",
        "",
    ]
    return "\n".join(lines)


def unresolved_address_names(index: dict[str, set[_IPNetwork] | None]) -> list[str]:
    """Address/group names in the index that could not be resolved to concrete
    CIDR networks (FQDN, ip_wildcard, dynamic groups, membership cycles) —
    surfaced so a report can honestly disclose reduced shadow-detection
    confidence for rules referencing them, instead of silently degrading.
    """
    return sorted(name for name, nets in index.items() if nets is None)


def render_shadow_audit(
    shadows: list[dict[str, str]],
    rule_meta: dict[str, dict[str, str]],
    total_rules: int,
    unresolved: list[str],
    tenant_label: str,
    folder: str,
    generated_at: str,
) -> str:
    """Standalone whole-rulebase shadow audit — no baseline or pending commit
    required. Every enabled security rule is checked against every other rule
    that evaluates before it, Tufin/Skybox-style: does an earlier rule already
    cover this rule's traffic, meaning it can never fire?

    rule_meta maps rule name -> {"folder", "position", "action"} for the
    detail table (built by the caller from the raw extracted rule dicts,
    which is where that metadata lives). When a finding also carries
    `shadowed_id`/`by_id` (as `find_shadowed_rules` produces — see
    `rule_identity()`), rule_meta may be keyed by that identity instead of
    (or in addition to) the bare name; the identity lookup takes priority,
    which avoids misattributing folder/position/action when the same rule
    name appears in both the pre- and post-rulebase, or in more than one
    merged folder.
    """
    lines = [
        "# Rule Shadow Audit — Full Rulebase",
        "",
        f"**Tenant:** `{tenant_label}`  |  **Folder:** `{folder}`  |  "
        f"**Generated:** {generated_at}",
        "",
        f"Scanned **{total_rules}** enabled security rules "
        f"(pre-rulebase then post-rulebase, in evaluation order).",
        "",
    ]

    if unresolved:
        lines += [
            f"⚪ **{len(unresolved)} address object(s)/group(s) could not be resolved to "
            "concrete IP ranges** (FQDN, wildcard mask, dynamic/tag-filter group, or "
            "membership cycle) — shadow checks involving these fall back to literal name "
            "matching and may under-report:",
            "",
            f"`{', '.join(unresolved[:20])}`" + (" …" if len(unresolved) > 20 else ""),
            "",
        ]

    if not shadows:
        lines.append(
            "🟢 **No shadowed rules found.** Every enabled rule can be reached by at "
            "least some traffic not already claimed by an earlier rule."
        )
        return "\n".join(lines)

    lines.append(
        f"🔴 **{len(shadows)} shadowed rule(s) found** — traffic-dead, safe to review for removal."
    )
    lines.append("")

    def _fmt(name: str, ident: str | None = None) -> str:
        # Identity-keyed lookup takes priority — it disambiguates same-named
        # rules across rulebases/folders. Falls back to the bare-name lookup
        # when no identity was supplied (or it isn't present in rule_meta),
        # matching the original behaviour exactly.
        meta = (rule_meta.get(ident) if ident else None) or rule_meta.get(name, {})
        loc = meta.get("folder", "?")
        pos = meta.get("position", "?")
        action = meta.get("action", "?")
        return f"`{name}` ({action}, {loc}/{pos})"

    lines += ["## Shadowed Rules", ""]
    for s in shadows:
        lines.append(
            f"- 🔴 {_fmt(s['shadowed'], s.get('shadowed_id'))} is shadowed by "
            f"{_fmt(s['by'], s.get('by_id'))}"
        )
    lines.append("")

    # Offenders are counted by identity when available, so two distinct
    # same-named rules (one per rulebase) don't merge into a single bucket.
    offenders: dict[str, dict[str, Any]] = {}
    for s in shadows:
        key = s.get("by_id") or s["by"]
        entry = offenders.setdefault(key, {"name": s["by"], "id": s.get("by_id"), "count": 0})
        entry["count"] += 1
    top_offenders = sorted(offenders.values(), key=lambda e: -int(e["count"]))[:10]
    if len(top_offenders) > 1 or (top_offenders and top_offenders[0]["count"] > 1):
        lines += ["## Top Shadowing Rules", "", "| Rule | Rules it shadows |", "|---|---|"]
        for e in top_offenders:
            lines.append(f"| {_fmt(str(e['name']), e['id'])} | {e['count']} |")
        lines.append("")

    lines += [
        "## Caveats",
        "",
        "- Source/destination use real CIDR containment with address-group "
        "membership resolved recursively; unresolvable addresses (listed above, "
        "if any) fall back to literal-name comparison, which can miss shadows "
        "but never falsely claims one.",
        "- Rules using `negate_source`/`negate_destination` are excluded from "
        "shadow analysis — inverted-match semantics aren't modelled here.",
        "- Remote Networks and Mobile Users are mutually exclusive enforcement "
        "scopes — a rule that exists only in one is never compared against a "
        "rule that exists only in the other, since neither pipeline ever sees "
        "the other's traffic. Only a rule from the queried base folder (or "
        "either exclusive scope compared within itself) can shadow across scopes.",
        "- Evaluation order is approximated by merging rules from the queried "
        "folder plus Remote Networks and Mobile Users, pre-rulebase before "
        "post-rulebase — this mirrors Panorama's pre/post semantics but may "
        "not exactly equal SCM's true evaluation order. Treat a finding as "
        '"verify the rule positions in the SCM UI", not as final proof.',
        "",
    ]
    return "\n".join(lines)
