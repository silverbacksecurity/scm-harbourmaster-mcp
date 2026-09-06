"""Unit tests for the AS-BUILT doc-vs-live verification engine.

diff_snapshots / render_verification_report are pure (no SCM client), so the
drift semantics — added/removed/modified detection, the unverified guard when
live extraction failed, and the report verdicts — are pinned down here.
"""

from __future__ import annotations

from scm_harbourmaster_mcp.audit.asbuilt_verify import (
    SectionDiff,
    diff_snapshots,
    render_verification_report,
)
from scm_harbourmaster_mcp.audit.models import AuditSnapshot


def _snap(**fields: object) -> AuditSnapshot:
    snap = AuditSnapshot(folder="Prisma Access", tenant_id="t1")
    for name, value in fields.items():
        setattr(snap, name, value)
    return snap


class TestDiffSnapshots:
    def test_identical_snapshots_have_no_drift(self) -> None:
        rn = [{"name": "branch-a", "subnets": ["10.0.0.0/24"]}]
        diffs = diff_snapshots(_snap(remote_networks=rn), _snap(remote_networks=list(rn)))
        assert len(diffs) == 1
        d = diffs[0]
        assert d.fieldname == "remote_networks"
        assert not d.drifted
        assert d.doc_count == d.live_count == 1

    def test_sections_empty_in_both_are_skipped(self) -> None:
        assert diff_snapshots(_snap(), _snap()) == []

    def test_added_and_removed_objects_detected(self) -> None:
        doc = _snap(zones=[{"name": "trust"}, {"name": "legacy"}])
        live = _snap(zones=[{"name": "trust"}, {"name": "guest"}])
        (d,) = diff_snapshots(doc, live)
        assert d.drifted
        assert d.added == ["guest"]
        assert d.removed == ["legacy"]
        assert d.changed == []

    def test_modified_object_detected_by_content(self) -> None:
        doc = _snap(security_rules_pre=[{"name": "allow-web", "action": "allow"}])
        live = _snap(security_rules_pre=[{"name": "allow-web", "action": "deny"}])
        (d,) = diff_snapshots(doc, live)
        assert d.drifted
        assert d.changed == ["allow-web"]
        assert d.added == [] and d.removed == []

    def test_live_extraction_failure_marks_section_unverified_not_removed(self) -> None:
        doc = _snap(addresses=[{"name": "srv-1"}, {"name": "srv-2"}])
        live = _snap(addresses=[])
        live.extraction_errors.append("address: HTTP 500")
        (d,) = diff_snapshots(doc, live)
        assert d.unverified
        assert not d.drifted  # transient API failure must not read as wholesale deletion

    def test_empty_live_without_errors_is_real_drift(self) -> None:
        doc = _snap(addresses=[{"name": "srv-1"}])
        live = _snap(addresses=[])
        (d,) = diff_snapshots(doc, live)
        assert not d.unverified
        assert d.drifted
        assert d.removed == ["srv-1"]

    def test_falls_back_to_id_when_name_missing(self) -> None:
        doc = _snap(tags=[{"id": "abc123", "color": "red"}])
        live = _snap(tags=[{"id": "abc123", "color": "blue"}])
        (d,) = diff_snapshots(doc, live)
        assert d.changed == ["abc123"]


class TestRenderVerificationReport:
    def _render(self, diffs: list[SectionDiff], doc: AuditSnapshot, live: AuditSnapshot) -> str:
        return render_verification_report(
            diffs, doc, live, "job1234", "2026-07-14 09:00 UTC", "2026-07-14 10:00 UTC"
        )

    def test_clean_verdict_when_everything_matches(self) -> None:
        doc = _snap(zones=[{"name": "trust"}])
        live = _snap(zones=[{"name": "trust"}])
        report = self._render(diff_snapshots(doc, live), doc, live)
        assert "DOCUMENT CURRENT" in report
        assert "Drift Detail" not in report

    def test_drift_verdict_lists_section_detail_and_recommendation(self) -> None:
        doc = _snap(zones=[{"name": "trust"}])
        live = _snap(zones=[{"name": "trust"}, {"name": "guest"}])
        report = self._render(diff_snapshots(doc, live), doc, live)
        assert "DRIFT DETECTED" in report
        assert "Drift Detail" in report
        assert "`guest`" in report
        assert "scm_asbuilt_report" in report  # refresh recommendation

    def test_partially_verified_verdict_on_live_extraction_gap(self) -> None:
        doc = _snap(addresses=[{"name": "srv-1"}])
        live = _snap(addresses=[])
        live.extraction_errors.append("address: HTTP 500")
        report = self._render(diff_snapshots(doc, live), doc, live)
        assert "PARTIALLY VERIFIED" in report
        assert "Live Re-Extraction Warnings" in report

    def test_doc_extraction_gaps_are_surfaced(self) -> None:
        doc = _snap(zones=[{"name": "trust"}])
        doc.extraction_errors.append("ike_gateway: HTTP 403")
        live = _snap(zones=[{"name": "trust"}])
        report = self._render(diff_snapshots(doc, live), doc, live)
        assert "Extraction Gaps at Generation Time" in report
        assert "ike_gateway: HTTP 403" in report

    def test_long_name_lists_are_capped(self) -> None:
        doc = _snap(addresses=[{"name": f"host-{i:03d}"} for i in range(30)])
        live = _snap(addresses=[])
        report = self._render(diff_snapshots(doc, live), doc, live)
        assert "+10 more" in report
