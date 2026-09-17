"""Unit tests for the commit blast-radius gate (audit/commit_preview.py).

Pins down the shadow-detection heuristic (any-coverage, literal supersets,
focus filtering, disabled rules), the BPA introduced/resolved delta, verdict
triage, and the rendered report's load-bearing content.
"""

from __future__ import annotations

from scm_harbourmaster_mcp.audit.asbuilt_verify import diff_snapshots
from scm_harbourmaster_mcp.audit.commit_preview import (
    bpa_delta,
    build_address_index,
    find_shadowed_rules,
    is_evaluable_rule,
    preview_verdict,
    render_commit_preview,
    render_shadow_audit,
    snippet_anchor_keys,
    unresolved_address_names,
)
from scm_harbourmaster_mcp.audit.models import AuditSnapshot, Finding, Severity, Status


def _rule(name: str, **over: object) -> dict:
    rule = {
        "name": name,
        "action": "allow",
        "from_": ["any"],
        "to_": ["any"],
        "source": ["any"],
        "destination": ["any"],
        "application": ["any"],
        "service": ["any"],
        "disabled": False,
    }
    rule.update(over)
    return rule


class TestFindShadowedRules:
    def test_any_rule_shadows_everything_below(self) -> None:
        rules = [_rule("allow-all"), _rule("block-web", action="deny")]
        (s,) = find_shadowed_rules(rules)
        assert s["shadowed"] == "block-web" and s["by"] == "allow-all"

    def test_literal_superset_shadows(self) -> None:
        rules = [
            _rule("broad", source=["10.0.0.0/8"], application=["web-browsing", "ssl"]),
            _rule("narrow", source=["10.0.0.0/8"], application=["ssl"]),
        ]
        (s,) = find_shadowed_rules(rules)
        assert s["shadowed"] == "narrow"

    def test_narrower_earlier_rule_does_not_shadow(self) -> None:
        rules = [
            _rule("narrow", source=["10.1.1.0/24"]),
            _rule("broad", source=["10.0.0.0/8"]),
        ]
        assert find_shadowed_rules(rules) == []

    def test_any_in_later_rule_is_not_covered_by_specific_earlier(self) -> None:
        rules = [_rule("specific", source=["10.1.1.1"]), _rule("catchall")]
        assert find_shadowed_rules(rules) == []

    def test_disabled_rules_are_ignored(self) -> None:
        rules = [_rule("allow-all", disabled=True), _rule("block-web", action="deny")]
        assert find_shadowed_rules(rules) == []

    def test_focus_names_filters_untouched_pairs(self) -> None:
        rules = [_rule("old-catchall"), _rule("old-below", action="deny")]
        # Pre-existing shadow, but neither rule is part of the pending change
        assert find_shadowed_rules(rules, focus_names={"new-rule"}) == []
        # Pending change includes the shadowed rule → reported
        assert len(find_shadowed_rules(rules, focus_names={"old-below"})) == 1


class TestCidrAwareShadowing:
    """The upgrade: real subnet containment + address-group resolution."""

    def test_broader_cidr_shadows_narrower_subnet(self) -> None:
        # /8 in rule 1 fully contains the /24 in rule 2 — different literal
        # strings, so the old literal-set check would have missed this.
        rules = [
            _rule("broad", source=["10.0.0.0/8"]),
            _rule("narrow", source=["10.1.2.0/24"]),
        ]
        (s,) = find_shadowed_rules(rules)
        assert s["shadowed"] == "narrow" and s["by"] == "broad"

    def test_narrower_cidr_does_not_shadow_broader(self) -> None:
        rules = [
            _rule("narrow", source=["10.1.2.0/24"]),
            _rule("broad", source=["10.0.0.0/8"]),
        ]
        assert find_shadowed_rules(rules) == []

    def test_disjoint_subnets_do_not_shadow(self) -> None:
        rules = [
            _rule("net-a", source=["10.1.0.0/16"]),
            _rule("net-b", source=["10.2.0.0/16"]),
        ]
        assert find_shadowed_rules(rules) == []

    def test_address_group_resolved_against_literal_superset(self) -> None:
        addresses = [{"name": "web-1", "ip_netmask": "10.1.2.10/32"}]
        address_groups = [{"name": "web-servers", "static": ["web-1"]}]
        rules = [
            _rule("broad", source=["10.0.0.0/8"]),
            _rule("narrow", source=["web-servers"]),
        ]
        (s,) = find_shadowed_rules(rules, addresses=addresses, address_groups=address_groups)
        assert s["shadowed"] == "narrow"

    def test_nested_group_resolved_recursively(self) -> None:
        addresses = [{"name": "host-1", "ip_netmask": "10.5.5.5/32"}]
        address_groups = [
            {"name": "inner", "static": ["host-1"]},
            {"name": "outer", "static": ["inner"]},
        ]
        rules = [
            _rule("broad", source=["10.0.0.0/8"]),
            _rule("narrow", source=["outer"]),
        ]
        (s,) = find_shadowed_rules(rules, addresses=addresses, address_groups=address_groups)
        assert s["shadowed"] == "narrow"

    def test_group_partially_outside_earlier_rule_not_shadowed(self) -> None:
        addresses = [
            {"name": "in-net", "ip_netmask": "10.1.2.10/32"},
            {"name": "out-of-net", "ip_netmask": "192.168.1.10/32"},
        ]
        address_groups = [{"name": "mixed", "static": ["in-net", "out-of-net"]}]
        rules = [
            _rule("broad", source=["10.0.0.0/8"]),
            _rule("mixed-group", source=["mixed"]),
        ]
        assert find_shadowed_rules(rules, addresses=addresses, address_groups=address_groups) == []

    def test_dynamic_group_is_unresolvable_falls_back_to_literal(self) -> None:
        address_groups = [{"name": "tagged", "dynamic": {"filter": "'env.prod'"}}]
        rules = [
            _rule("broad", source=["10.0.0.0/8"]),
            _rule("dyn", source=["tagged"]),
        ]
        # Can't prove a dynamic group is inside 10.0.0.0/8 — must not claim shadow.
        assert find_shadowed_rules(rules, addresses=[], address_groups=address_groups) == []

    def test_fqdn_address_is_unresolvable_falls_back_to_literal(self) -> None:
        addresses = [{"name": "example-com", "fqdn": "example.com"}]
        rules = [
            _rule("broad", source=["10.0.0.0/8"]),
            _rule("fqdn-rule", source=["example-com"]),
        ]
        assert find_shadowed_rules(rules, addresses=addresses, address_groups=[]) == []

    def test_membership_cycle_is_unresolvable_not_infinite_loop(self) -> None:
        address_groups = [
            {"name": "a", "static": ["b"]},
            {"name": "b", "static": ["a"]},
        ]
        rules = [
            _rule("broad", source=["10.0.0.0/8"]),
            _rule("cyclic", source=["a"]),
        ]
        assert find_shadowed_rules(rules, addresses=[], address_groups=address_groups) == []

    def test_ip_range_address_object_resolves(self) -> None:
        addresses = [{"name": "dhcp-pool", "ip_range": "10.1.2.1-10.1.2.254"}]
        rules = [
            _rule("broad", source=["10.0.0.0/8"]),
            _rule("pool", source=["dhcp-pool"]),
        ]
        (s,) = find_shadowed_rules(rules, addresses=addresses, address_groups=[])
        assert s["shadowed"] == "pool"

    def test_negated_source_never_claimed_as_shadowed(self) -> None:
        # negate_source=True on the narrower rule means "anything EXCEPT this
        # subnet" — inverted semantics this algorithm doesn't model, so no claim.
        rules = [
            _rule("broad", source=["10.0.0.0/8"]),
            _rule("negated", source=["10.1.2.0/24"], negate_source=True),
        ]
        assert find_shadowed_rules(rules) == []

    def test_remote_networks_only_and_mobile_users_only_never_shadow(self) -> None:
        # Two mutually exclusive Prisma Access enforcement pipelines — a
        # Remote-Networks-only rule never processes Mobile-Users traffic and
        # vice versa, even though real CIDR containment would otherwise
        # flag one as covering the other.
        rules = [
            _rule(
                "rn-allow-branch-mgmt",
                source=["10.0.0.0/8"],
                _folder="Remote Networks",
                _position="pre",
            ),
            _rule(
                "mu-allow-vpn-users",
                source=["10.1.2.0/24"],
                _folder="Mobile Users",
                _position="pre",
            ),
        ]
        assert find_shadowed_rules(rules) == []

    def test_base_folder_rule_still_shadows_across_exclusive_scopes(self) -> None:
        # A rule inherited from the queried base folder DOES apply to every
        # child scope, so it can legitimately shadow an exclusive-scope rule.
        rules = [
            _rule(
                "global-allow-all",
                source=["10.0.0.0/8"],
                _folder="Prisma Access",
                _position="pre",
            ),
            _rule(
                "mu-narrow",
                source=["10.1.2.0/24"],
                _folder="Mobile Users",
                _position="pre",
            ),
        ]
        (s,) = find_shadowed_rules(rules)
        assert s["shadowed"] == "mu-narrow" and s["by"] == "global-allow-all"

    def test_same_exclusive_scope_still_shadows(self) -> None:
        rules = [
            _rule("rn-broad", source=["10.0.0.0/8"], _folder="Remote Networks", _position="pre"),
            _rule("rn-narrow", source=["10.1.2.0/24"], _folder="Remote Networks", _position="pre"),
        ]
        (s,) = find_shadowed_rules(rules)
        assert s["shadowed"] == "rn-narrow" and s["by"] == "rn-broad"

    def test_unresolvable_source_still_checks_literal_equality_fallback(self) -> None:
        # Same unresolved group name on both sides: literal-equality fallback
        # still catches this even though CIDR resolution is unavailable.
        rules = [
            _rule("first", source=["unknown-edl"]),
            _rule("second", source=["unknown-edl"]),
        ]
        (s,) = find_shadowed_rules(rules)
        assert s["shadowed"] == "second"


def _finding(check_id: str, status: Status, sev: Severity = Severity.HIGH) -> Finding:
    return Finding(
        check_id=check_id,
        title=f"title {check_id}",
        severity=sev,
        status=status,
        description="",
        remediation="",
    )


class TestBpaDelta:
    def test_introduced_and_resolved_split(self) -> None:
        ref = [_finding("A", Status.FAIL), _finding("B", Status.PASS)]
        cand = [_finding("A", Status.PASS), _finding("B", Status.FAIL)]
        introduced, resolved = bpa_delta(ref, cand)
        assert [f.check_id for f in introduced] == ["B"]
        assert [f.check_id for f in resolved] == ["A"]

    def test_unchanged_fails_are_neither(self) -> None:
        ref = [_finding("A", Status.FAIL)]
        cand = [_finding("A", Status.FAIL)]
        introduced, resolved = bpa_delta(ref, cand)
        assert introduced == [] and resolved == []

    def test_introduced_sorted_most_severe_first(self) -> None:
        cand = [
            _finding("low", Status.FAIL, Severity.LOW),
            _finding("crit", Status.FAIL, Severity.CRITICAL),
        ]
        introduced, _ = bpa_delta([], cand)
        assert [f.check_id for f in introduced] == ["crit", "low"]


def _diffs(base: AuditSnapshot, cand: AuditSnapshot):
    return [d for d in diff_snapshots(base, cand) if d.drifted]


def _snap(**fields: object) -> AuditSnapshot:
    snap = AuditSnapshot(folder="Prisma Access", tenant_id="t1")
    for name, value in fields.items():
        setattr(snap, name, value)
    return snap


class TestPreviewVerdict:
    def test_no_changes(self) -> None:
        assert preview_verdict([], [], []) == "NO CHANGES"

    def test_low_risk_for_object_plumbing_additions(self) -> None:
        diffs = _diffs(_snap(tags=[]), _snap(tags=[{"name": "new-tag"}]))
        assert preview_verdict(diffs, [], []) == "LOW RISK"

    def test_high_section_addition_is_review(self) -> None:
        diffs = _diffs(
            _snap(security_rules_pre=[]),
            _snap(security_rules_pre=[_rule("new-rule")]),
        )
        assert preview_verdict(diffs, [], []) == "REVIEW"

    def test_high_section_removal_is_high_risk(self) -> None:
        diffs = _diffs(
            _snap(security_rules_pre=[_rule("old-rule")]),
            _snap(security_rules_pre=[]),
        )
        assert preview_verdict(diffs, [], []) == "HIGH RISK"

    def test_shadowing_is_high_risk(self) -> None:
        diffs = _diffs(_snap(tags=[]), _snap(tags=[{"name": "t"}]))
        shadows = [{"shadowed": "b", "by": "a", "detail": "x"}]
        assert preview_verdict(diffs, shadows, []) == "HIGH RISK"

    def test_new_high_bpa_finding_is_high_risk(self) -> None:
        diffs = _diffs(_snap(tags=[]), _snap(tags=[{"name": "t"}]))
        introduced = [_finding("X", Status.FAIL, Severity.HIGH)]
        assert preview_verdict(diffs, [], introduced) == "HIGH RISK"


class TestRenderCommitPreview:
    def _render(self, diffs, shadows=(), introduced=(), resolved=()) -> str:
        return render_commit_preview(
            list(diffs),
            list(shadows),
            list(introduced),
            list(resolved),
            tenant_label="t1",
            folder="Prisma Access",
            baseline_saved_at="2026-07-14",
            generated_at="2026-07-15 09:00 UTC",
        )

    def test_no_op_report(self) -> None:
        report = self._render([])
        assert "NO PENDING CHANGES" in report
        assert "Next Step" not in report

    def test_high_risk_report_names_everything(self) -> None:
        diffs = _diffs(
            _snap(security_rules_pre=[_rule("keep"), _rule("dropped")]),
            _snap(security_rules_pre=[_rule("keep")]),
        )
        shadows = [{"shadowed": "b", "by": "a", "detail": "`a` covers `b`"}]
        introduced = [_finding("BPA-X", Status.FAIL)]
        report = self._render(diffs, shadows, introduced)
        assert "HIGH RISK" in report
        assert "`dropped`" in report
        assert "`a` covers `b`" in report
        assert "BPA-X" in report
        assert "scm_commit" in report and "update_baseline=True" in report

    def test_resolved_findings_shown_as_wins(self) -> None:
        diffs = _diffs(_snap(tags=[]), _snap(tags=[{"name": "t"}]))
        report = self._render(diffs, resolved=[_finding("BPA-FIXED", Status.FAIL)])
        assert "Resolved by This Change" in report and "BPA-FIXED" in report


class TestUnresolvedAddressNames:
    def test_flags_unresolvable_entries(self) -> None:
        index = build_address_index(
            addresses=[{"name": "fqdn-addr", "fqdn": "example.com"}],
            address_groups=[{"name": "dyn-group", "dynamic": {"filter": "'x'"}}],
        )
        assert set(unresolved_address_names(index)) == {"fqdn-addr", "dyn-group"}

    def test_empty_when_everything_resolves(self) -> None:
        index = build_address_index(
            addresses=[{"name": "host-1", "ip_netmask": "10.1.1.1/32"}],
            address_groups=[{"name": "grp", "static": ["host-1"]}],
        )
        assert unresolved_address_names(index) == []


class TestRenderShadowAudit:
    def _meta(self, **rules: dict) -> dict:
        return rules

    def test_no_shadows_is_green(self) -> None:
        report = render_shadow_audit(
            [],
            {},
            total_rules=5,
            unresolved=[],
            tenant_label="t1",
            folder="Prisma Access",
            generated_at="2026-08-15 09:00 UTC",
        )
        assert "No shadowed rules found" in report
        assert "5" in report

    def test_shadow_entries_show_rule_metadata(self) -> None:
        rule_meta = {
            "broad": {"folder": "Prisma Access", "position": "pre", "action": "allow"},
            "narrow": {"folder": "Remote Networks", "position": "post", "action": "allow"},
        }
        shadows = [{"shadowed": "narrow", "by": "broad", "detail": "x"}]
        report = render_shadow_audit(
            shadows,
            rule_meta,
            total_rules=2,
            unresolved=[],
            tenant_label="t1",
            folder="Prisma Access",
            generated_at="2026-08-15 09:00 UTC",
        )
        assert "1 shadowed rule(s) found" in report
        assert "`narrow` (allow, Remote Networks/post)" in report
        assert "`broad` (allow, Prisma Access/pre)" in report

    def test_top_offenders_ranked_by_shadow_count(self) -> None:
        rule_meta = {
            n: {"folder": "Prisma Access", "position": "pre", "action": "allow"}
            for n in ("broad", "a", "b", "c")
        }
        shadows = [
            {"shadowed": "a", "by": "broad", "detail": "x"},
            {"shadowed": "b", "by": "broad", "detail": "x"},
            {"shadowed": "c", "by": "broad", "detail": "x"},
        ]
        report = render_shadow_audit(
            shadows,
            rule_meta,
            total_rules=4,
            unresolved=[],
            tenant_label="t1",
            folder="Prisma Access",
            generated_at="2026-08-15 09:00 UTC",
        )
        assert "Top Shadowing Rules" in report
        assert "| `broad` (allow, Prisma Access/pre) | 3 |" in report

    def test_unresolved_addresses_disclosed(self) -> None:
        report = render_shadow_audit(
            [],
            {},
            total_rules=1,
            unresolved=["some-fqdn", "some-dyn-group"],
            tenant_label="t1",
            folder="Prisma Access",
            generated_at="2026-08-15 09:00 UTC",
        )
        assert "2 address object(s)/group(s) could not be resolved" in report
        assert "some-fqdn" in report and "some-dyn-group" in report

    def test_caveats_section_always_present_when_shadows_exist(self) -> None:
        shadows = [{"shadowed": "b", "by": "a", "detail": "x"}]
        report = render_shadow_audit(
            shadows,
            {},
            total_rules=2,
            unresolved=[],
            tenant_label="t1",
            folder="Prisma Access",
            generated_at="2026-08-15 09:00 UTC",
        )
        assert "## Caveats" in report
        assert "negate_source" in report


class TestFindShadowedRulesCrossRulebase:
    """Pre-rulebase always evaluates before post-rulebase — a combined
    pre+post list run through find_shadowed_rules must catch a pre-rule
    shadowing a later post-rule, which scanning pre and post separately
    would miss."""

    def test_pre_rule_shadows_later_post_rule(self) -> None:
        pre = [_rule("pre-broad", source=["10.0.0.0/8"], _folder="Prisma Access", _position="pre")]
        post = [
            _rule("post-narrow", source=["10.1.2.0/24"], _folder="Prisma Access", _position="post")
        ]
        (s,) = find_shadowed_rules(pre + post)
        assert s["shadowed"] == "post-narrow" and s["by"] == "pre-broad"


class TestNonEvaluableEntries:
    """Rulebase entries that must never count as shadowing (or shadowed)."""

    FOLDERS = [
        {"name": "All", "snippets": ["default", "hip-default"]},
        {"name": "Prisma Access", "snippets": ["optional-default"]},
    ]

    def test_snippet_placeholders_do_not_shadow(self) -> None:
        anchors = snippet_anchor_keys(self.FOLDERS)
        rules = [
            _rule("default", folder="All"),
            _rule("optional-default", folder="Shared"),
            _rule("block-quic", folder="Shared", action="deny", application=["quic"]),
        ]
        assert find_shadowed_rules(rules, snippet_anchors=anchors) == []

    def test_snippet_name_in_another_folder_is_a_real_rule(self) -> None:
        anchors = snippet_anchor_keys(self.FOLDERS)
        rules = [
            _rule("optional-default", folder="Mobile Users"),
            _rule("later", folder="Mobile Users", application=["ssl"]),
        ]
        (s,) = find_shadowed_rules(rules, snippet_anchors=anchors)
        assert s["by"] == "optional-default"

    def test_without_folder_data_snippet_names_match_any_folder(self) -> None:
        anchors = snippet_anchor_keys([], [{"name": "rbi"}])
        assert not is_evaluable_rule(_rule("rbi", folder="Shared"), anchors)
        assert is_evaluable_rule(_rule("real", folder="Shared"), anchors)

    def test_internet_policy_rules_are_skipped(self) -> None:
        rules = [
            _rule("internet-access-default", policy_type="Internet"),
            _rule("later", policy_type="Security", application=["ssl"]),
        ]
        assert find_shadowed_rules(rules) == []


class TestNarrowingMatchFields:
    def test_hip_scoped_deny_does_not_cover_any_rule(self) -> None:
        rules = [
            _rule("block-fw-off", action="deny", source_hip=["if-firewall-disabled"]),
            _rule("allow-all"),
        ]
        assert find_shadowed_rules(rules) == []

    def test_category_and_user_scoping_narrow_coverage(self) -> None:
        rules = [
            _rule("news-only", action="deny", category=["news"]),
            _rule("user-only", action="deny", source_user=["corp\\alice"]),
            _rule("allow-all"),
        ]
        assert find_shadowed_rules(rules) == []

    def test_any_hip_still_covers_specific_hip(self) -> None:
        rules = [
            _rule("allow-all"),
            _rule("hip-scoped", source_hip=["is-mac"], category=["news"]),
        ]
        (s,) = find_shadowed_rules(rules)
        assert s["shadowed"] == "hip-scoped"
