"""Unit tests for the incident RCA correlator (audit/incident_rca.py).

Pins the timestamp parser's accepted formats, the candidate window/ranking
semantics (grace period, failed-job priority, expiry inclusion), and the
report/RFO content including the mandatory correlation caveat.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from scm_harbourmaster_mcp.audit.asbuilt_verify import diff_snapshots
from scm_harbourmaster_mcp.audit.incident_rca import (
    collect_candidates,
    parse_any_ts,
    render_rca_report,
)
from scm_harbourmaster_mcp.audit.models import AuditSnapshot

INCIDENT = datetime(2026, 7, 15, 12, 0, tzinfo=UTC)


def _job(job_id: str, minutes_before: int, result: str = "OK", **over: object) -> dict:
    ts = (INCIDENT - timedelta(minutes=minutes_before)).strftime("%Y-%m-%dT%H:%M:%S")
    job = {
        "job_id": job_id,
        "type": "CommitAndPush",
        "result": result,
        "user": "ops-admin",
        "description": "",
        "start_ts": ts,
        "end_ts": ts,
    }
    job.update(over)
    return job


class TestParseAnyTs:
    def test_iso_with_t_and_space(self) -> None:
        assert parse_any_ts("2026-07-15T12:00:00") == INCIDENT
        assert parse_any_ts("2026-07-15 12:00") == INCIDENT

    def test_epoch_seconds(self) -> None:
        assert parse_any_ts(str(int(INCIDENT.timestamp()))) == INCIDENT

    def test_garbage_and_empty_return_none(self) -> None:
        assert parse_any_ts("") is None
        assert parse_any_ts("None") is None
        assert parse_any_ts("not-a-date") is None


class TestCollectCandidates:
    def test_push_inside_window_is_candidate_with_delta(self) -> None:
        (c,) = collect_candidates(INCIDENT, 24, [_job("j1", 30)], [], [])
        assert c["kind"] == "config push"
        assert c["delta_min"] == 30
        assert "j1" in c["evidence"]

    def test_push_outside_lookback_is_excluded(self) -> None:
        assert collect_candidates(INCIDENT, 24, [_job("j1", 25 * 60)], [], []) == []

    def test_push_within_grace_after_incident_included(self) -> None:
        (c,) = collect_candidates(INCIDENT, 24, [_job("j1", -10)], [], [])
        assert c["delta_min"] == -10

    def test_push_beyond_grace_after_incident_excluded(self) -> None:
        assert collect_candidates(INCIDENT, 24, [_job("j1", -60)], [], []) == []

    def test_failed_job_ranks_ahead_at_equal_distance(self) -> None:
        jobs = [_job("ok-job", 30), _job("bad-job", 30, result="FAIL")]
        ranked = collect_candidates(INCIDENT, 24, jobs, [], [])
        assert ranked[0]["evidence"].startswith("job `bad-job`")
        assert "FAILED" in ranked[0]["desc"]

    def test_nearest_event_ranks_first(self) -> None:
        jobs = [_job("far", 300), _job("near", 5)]
        ranked = collect_candidates(INCIDENT, 24, jobs, [], [])
        assert ranked[0]["evidence"].startswith("job `near`")

    def test_cert_expiry_in_window_is_candidate(self) -> None:
        expiry = INCIDENT - timedelta(hours=2)
        cert = {
            "name": "gp-portal-cert",
            "common_name": "vpn.example.net",
            "expiry_epoch": str(int(expiry.timestamp())),
            "not_valid_after": "Jul 15 10:00:00 2026 GMT",
        }
        (c,) = collect_candidates(INCIDENT, 24, [], [cert], [])
        assert c["kind"] == "certificate expiry"
        assert "vpn.example.net" in c["evidence"]
        assert c["failed"] is True

    def test_licence_expiry_in_window_is_candidate(self) -> None:
        exp = (INCIDENT - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S")
        row = {"app": "logging_service", "license_type": "Production License", "exp": exp}
        (c,) = collect_candidates(INCIDENT, 24, [], [], [row])
        assert c["kind"] == "licence expiry"
        assert "logging_service" in c["desc"]

    def test_cert_expired_long_before_window_excluded(self) -> None:
        expiry = INCIDENT - timedelta(days=400)
        cert = {"name": "old", "expiry_epoch": str(int(expiry.timestamp()))}
        assert collect_candidates(INCIDENT, 24, [], [cert], []) == []


def _drifted():
    base = AuditSnapshot(folder="f", tenant_id="t")
    live = AuditSnapshot(folder="f", tenant_id="t")
    base.security_rules_pre = [{"name": "r1", "action": "allow"}]
    live.security_rules_pre = [{"name": "r1", "action": "deny"}]
    return [d for d in diff_snapshots(base, live) if d.drifted]


class TestRenderRcaReport:
    def _render(self, candidates, drifted=(), baseline="2026-07-14", unchecked=()) -> str:
        return render_rca_report(
            INCIDENT,
            "branch VPN down",
            24,
            list(candidates),
            list(drifted),
            baseline,
            list(unchecked),
            tenant_label="t1",
            folder="Prisma Access",
            generated_at="2026-07-15 13:00 UTC",
        )

    def test_top_candidate_feeds_rfo_draft(self) -> None:
        cands = collect_candidates(INCIDENT, 24, [_job("j9", 12, result="FAIL")], [], [])
        report = self._render(cands)
        assert "RFO Draft" in report
        assert "12 minutes before" in report
        assert "job `j9`" in report

    def test_no_candidates_rfo_attributes_outside_factors(self) -> None:
        report = self._render([])
        assert "no configuration push, certificate expiry, or licence expiry" in report.lower()

    def test_correlation_caveat_always_present(self) -> None:
        assert "Correlation is not causation" in self._render([])

    def test_drift_shown_as_state_evidence_with_when_caveat(self) -> None:
        report = self._render([], drifted=_drifted())
        assert "State Evidence" in report
        assert "not *when* it changed" in report
        assert "`r1`" in report

    def test_unchecked_sources_are_listed(self) -> None:
        report = self._render([], unchecked=["Insights alerts (RBAC 403)"])
        assert "Not checked this run: Insights alerts (RBAC 403)" in report

    def test_symptom_appears_in_header_and_rfo(self) -> None:
        report = self._render([])
        assert report.count("branch VPN down") >= 2
