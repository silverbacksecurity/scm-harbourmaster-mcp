"""Tests for the Prisma Access Browser BPA checks (BPA-PAB-001/002)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from scm_harbourmaster_mcp.audit.bpa_checks import check_pab_001, check_pab_002
from scm_harbourmaster_mcp.audit.models import AuditSnapshot, Status
from scm_harbourmaster_mcp.audit.ncsc_controls import NCSC_CONTROLS


def _snap(devices: list[dict] | None = None) -> AuditSnapshot:
    snap = AuditSnapshot(folder="Shared", tenant_id="t1")
    snap.browser_devices = devices or []
    return snap


GOOD = {
    "hostname": "MAC-1",
    "status": "active",
    "lastSeen": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "screenLockStatus": "ScreenLockStatusEnabled",
    "diskEncryptionStatus": "DiskEncryptionStatusEnabled",
    "firewallStatus": "FireWallStatusEnabled",
}
BAD = {
    "hostname": "WIN-1",
    "status": "active",
    "lastSeen": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "screenLockStatus": "ScreenLockStatusEnabled",
    "diskEncryptionStatus": "DiskEncryptionStatusDisabled",
    "firewallStatus": "FireWallStatusDisabled",
}


def test_pab_001_skips_without_devices() -> None:
    f = check_pab_001(_snap())
    assert f.status is Status.SKIP


def test_pab_001_passes_when_all_compliant() -> None:
    f = check_pab_001(_snap([GOOD]))
    assert f.status is Status.PASS
    assert "CE-SC-1" in f.ncsc_refs and "CAF-B5.a" in f.ncsc_refs


def test_pab_001_fails_and_names_missing_controls() -> None:
    f = check_pab_001(_snap([GOOD, BAD]))
    assert f.status is Status.FAIL
    assert f.affected_objects == ["WIN-1 (missing: disk encryption, firewall)"]
    assert "1 of 2" in f.description


def test_pab_002_flags_stale_active_devices() -> None:
    stale = {
        **GOOD,
        "hostname": "OLD-1",
        "lastSeen": (datetime.now(UTC) - timedelta(days=120)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    archived = {**stale, "hostname": "GONE-1", "status": "archived"}
    f = check_pab_002(_snap([GOOD, stale, archived]))
    assert f.status is Status.FAIL
    assert len(f.affected_objects) == 1 and f.affected_objects[0].startswith("OLD-1")


def test_pab_002_passes_when_recent() -> None:
    f = check_pab_002(_snap([GOOD]))
    assert f.status is Status.PASS


def test_ce_sc_1_control_registered() -> None:
    ctl = NCSC_CONTROLS["CE-SC-1"]
    assert ctl.source == "CE v3.2"
    assert "disk" in ctl.description.lower()
