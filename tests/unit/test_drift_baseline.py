"""Unit tests for the drift-sentinel baseline layer (audit/drift_baseline.py).

Covers snapshot serialization round-trips (including forward compatibility
with baselines written by older/newer code), severity triage ordering, and
the cross-tenant digest rendering.
"""

from __future__ import annotations

from pathlib import Path

from scm_harbourmaster_mcp.audit.drift_baseline import (
    baseline_filename,
    check_drift,
    drift_severity,
    load_baseline,
    render_drift_digest,
    save_baseline,
    snapshot_from_dict,
    snapshot_to_dict,
)
from scm_harbourmaster_mcp.audit.models import AuditSnapshot


def _snap(**fields: object) -> AuditSnapshot:
    snap = AuditSnapshot(folder="Prisma Access", tenant_id="t1")
    for name, value in fields.items():
        setattr(snap, name, value)
    return snap


class TestSerialization:
    def test_round_trip_preserves_sections(self) -> None:
        snap = _snap(
            security_rules_pre=[{"name": "allow-web", "action": "allow"}],
            tags=[{"name": "prod"}],
        )
        restored = snapshot_from_dict(snapshot_to_dict(snap))
        assert restored.security_rules_pre == snap.security_rules_pre
        assert restored.tags == snap.tags
        assert restored.folder == "Prisma Access" and restored.tenant_id == "t1"

    def test_unknown_keys_from_future_baselines_are_dropped(self) -> None:
        data = snapshot_to_dict(_snap())
        data["field_added_in_v99"] = [{"name": "x"}]
        restored = snapshot_from_dict(data)  # must not raise
        assert restored.folder == "Prisma Access"

    def test_missing_required_keys_get_defaults(self) -> None:
        restored = snapshot_from_dict({"zones": [{"name": "trust"}]})
        assert restored.zones == [{"name": "trust"}]
        assert restored.folder == "" and restored.tenant_id == ""


class TestBaselineFiles:
    def test_save_and_load_round_trip(self, tmp_path: Path) -> None:
        snap = _snap(zones=[{"name": "trust"}])
        path = save_baseline(snap, tmp_path)
        assert path.exists()
        loaded = load_baseline("t1", "Prisma Access", tmp_path)
        assert loaded is not None
        restored, saved_at = loaded
        assert restored.zones == [{"name": "trust"}]
        assert "UTC" in saved_at

    def test_load_missing_baseline_returns_none(self, tmp_path: Path) -> None:
        assert load_baseline("t1", "Prisma Access", tmp_path) is None

    def test_filename_sanitizes_folder_and_tenant(self) -> None:
        name = baseline_filename("tsg/123", "Prisma Access")
        assert "/" not in name and " " not in name
        assert name.endswith(".json")


class TestCheckDrift:
    def test_no_change_yields_empty(self) -> None:
        base = _snap(zones=[{"name": "trust"}])
        live = _snap(zones=[{"name": "trust"}])
        assert check_drift(base, live) == []

    def test_high_severity_sections_sort_first(self) -> None:
        base = _snap(
            tags=[{"name": "old-tag"}],
            security_rules_pre=[{"name": "r1", "action": "allow"}],
        )
        live = _snap(
            tags=[{"name": "new-tag"}],
            security_rules_pre=[{"name": "r1", "action": "deny"}],
        )
        drifted = check_drift(base, live)
        assert [d.fieldname for d in drifted] == ["security_rules_pre", "tags"]
        assert drift_severity(drifted[0]) == "HIGH"
        assert drift_severity(drifted[1]) == "LOW"


class TestRenderDriftDigest:
    def test_all_clean_renders_green(self) -> None:
        digest = render_drift_digest(
            [{"label": "Tenant A", "drifted": [], "unverified": 0, "error": None}],
            "2026-07-14 22:00 UTC",
        )
        assert "No drift detected" in digest

    def test_drifted_tenant_sorts_before_clean_and_names_objects(self) -> None:
        base = _snap(security_rules_pre=[{"name": "r1", "action": "allow"}])
        live = _snap(security_rules_pre=[{"name": "r1", "action": "deny"}])
        results = [
            {"label": "Clean Tenant", "drifted": [], "unverified": 0, "error": None},
            {
                "label": "Drifted Tenant",
                "drifted": check_drift(base, live),
                "unverified": 0,
                "error": None,
                "baseline_saved_at": "2026-07-13",
            },
        ]
        digest = render_drift_digest(results, "2026-07-14 22:00 UTC")
        assert digest.index("Drifted Tenant") < digest.index("Clean Tenant")
        assert "[HIGH]" in digest and "`r1`" in digest
        assert "update_baseline=True" in digest  # accept-new-state instruction

    def test_errored_tenant_is_reported_not_dropped(self) -> None:
        digest = render_drift_digest(
            [{"label": "Broken", "drifted": [], "unverified": 0, "error": "auth failed"}],
            "2026-07-14 22:00 UTC",
        )
        assert "Broken" in digest and "auth failed" in digest
