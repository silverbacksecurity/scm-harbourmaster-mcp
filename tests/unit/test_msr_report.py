"""Tests for the MSR — Monthly Service Review pack generator.

Covers:
  - month_bounds parsing + previous-month default (incl. January rollover)
  - in_period boundary behaviour
  - SSR provenance-note parsing (all three note shapes, legacy prefixes)
  - compute_service_stats (MTTR from closed incidents, change failure rate,
    honest n/a when resolution timestamps are absent)
  - render_msr_report tier gating (bronze/silver/gold compliance depth)
  - renderer degradation notes (§8 coverage disclosure)
  - gather_msr_data period filtering + per-source degradation with a mock client
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

from scm_harbourmaster_mcp.audit.msr_report import (
    MsrData,
    compute_service_stats,
    in_period,
    month_bounds,
    parse_ssr_notes,
    render_msr_report,
)

# ---------------------------------------------------------------------------
# month_bounds / in_period
# ---------------------------------------------------------------------------


class TestMonthBounds:
    def test_explicit_month(self) -> None:
        start, end, label = month_bounds("2026-06")
        assert start == datetime(2026, 6, 1, tzinfo=UTC)
        assert end == datetime(2026, 7, 1, tzinfo=UTC)
        assert label == "2026-06"

    def test_december_rolls_into_next_year(self) -> None:
        start, end, _ = month_bounds("2025-12")
        assert end == datetime(2026, 1, 1, tzinfo=UTC)

    def test_default_is_previous_full_month(self) -> None:
        _, _, label = month_bounds(now=datetime(2026, 7, 17, tzinfo=UTC))
        assert label == "2026-06"

    def test_january_defaults_to_prior_december(self) -> None:
        start, _, label = month_bounds(now=datetime(2026, 1, 5, tzinfo=UTC))
        assert label == "2025-12"
        assert start.year == 2025

    @pytest.mark.parametrize("bad", ["2026", "06-2026", "2026-13", "2026-00", "banana"])
    def test_malformed_month_raises(self, bad: str) -> None:
        with pytest.raises(ValueError):
            month_bounds(bad)


class TestInPeriod:
    START, END, _ = month_bounds("2026-06")

    def test_inside(self) -> None:
        assert in_period("2026-06-15T12:00:00Z", self.START, self.END)

    def test_start_inclusive_end_exclusive(self) -> None:
        assert in_period("2026-06-01T00:00:00Z", self.START, self.END)
        assert not in_period("2026-07-01T00:00:00Z", self.START, self.END)

    def test_unparseable_is_excluded(self) -> None:
        assert not in_period("not a date", self.START, self.END)
        assert not in_period(None, self.START, self.END)


# ---------------------------------------------------------------------------
# SSR ledger parsing
# ---------------------------------------------------------------------------


class TestParseSsrNotes:
    def test_all_three_note_shapes(self) -> None:
        desc = (
            "Customer allow list | SSR add: example.com — INC-1 | "
            "SSR threat-exception remove: 55555 — CHG-2 | "
            "SSR ssl-decrypt add: gambling — INC-3"
        )
        entries = parse_ssr_notes(desc, "SSR-Obj")
        assert [e["kind"] for e in entries] == ["url-list", "threat-exception", "ssl-decrypt"]
        assert entries[0] == {
            "object": "SSR-Obj",
            "kind": "url-list",
            "action": "add",
            "target": "example.com",
            "ticket_ref": "INC-1",
        }
        assert entries[1]["action"] == "remove"
        assert entries[2]["ticket_ref"] == "INC-3"

    def test_non_ssr_description_yields_nothing(self) -> None:
        assert parse_ssr_notes("Managed by MSSP — change freeze Dec") == []

    def test_empty_and_none_safe(self) -> None:
        assert parse_ssr_notes("") == []
        assert parse_ssr_notes(None) == []  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Service stats
# ---------------------------------------------------------------------------


def _inc(
    sev: str, status: str, raised: str, resolved: str | None = None, ack: bool = False
) -> dict:
    d = {"severity": sev, "status": status, "raised_time": raised, "acknowledged": ack}
    if resolved:
        d["resolved_time"] = resolved
    return d


class TestServiceStats:
    def test_mttr_from_closed_incidents(self) -> None:
        stats = compute_service_stats(
            [
                _inc("High", "Closed", "2026-06-01T00:00:00Z", "2026-06-01T04:00:00Z"),
                _inc("Low", "Closed", "2026-06-02T00:00:00Z", "2026-06-02T02:00:00Z"),
            ],
            [],
        )
        assert stats["mttr_hours"] == 3.0
        assert stats["mttr_samples"] == 2
        assert stats["open_at_generation"] == 0

    def test_no_resolution_timestamps_is_none_not_zero(self) -> None:
        stats = compute_service_stats(
            [_inc("High", "Closed", "2026-06-01T00:00:00Z")],
            [],
        )
        assert stats["mttr_hours"] is None

    def test_open_and_ack_counting(self) -> None:
        stats = compute_service_stats(
            [
                _inc("Critical", "Open", "2026-06-01T00:00:00Z", ack=True),
                _inc("Medium", "Acknowledged", "2026-06-02T00:00:00Z"),
            ],
            [],
        )
        assert stats["open_at_generation"] == 2
        assert stats["ack_rate_pct"] == 50
        assert stats["severity_counts"] == {"critical": 1, "medium": 1}

    def test_change_failure_rate(self) -> None:
        jobs = [{"result": "OK"}, {"result": "OK"}, {"result": "FAIL"}, {"result": "PENDING"}]
        stats = compute_service_stats([], jobs)
        assert stats["change_total"] == 4
        assert stats["change_ok"] == 2
        assert stats["change_failed"] == 1
        assert stats["change_failure_pct"] == 25

    def test_empty_period_rates_are_none(self) -> None:
        stats = compute_service_stats([], [])
        assert stats["ack_rate_pct"] is None
        assert stats["change_failure_pct"] is None


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------


def _base_data(tier: str = "gold") -> MsrData:
    return MsrData(
        tenant_label="Test Customer",
        tenant_id="t-1",
        tier=tier,
        period_label="2026-06",
        compliance_summaries=[
            {
                "id": "fw-1",
                "category": "regulatory",
                "benchmark": True,
                "revision_summary": [{"name": "CE Plus", "overall_score": 82.0, "state": "active"}],
            }
        ],
        compliance_timeline=[
            {"date": "2026-06-01", "overall_score": 85.0},
            {"date": "2026-06-30", "overall_score": 82.0},
        ],
        compliance_framework_name="CE Plus",
    )


class TestRenderer:
    def test_bronze_gates_compliance(self) -> None:
        md = render_msr_report(_base_data(tier="bronze"))
        assert "included at Silver tier" in md
        assert "CE Plus" not in md

    def test_silver_gets_summary_not_trend(self) -> None:
        md = render_msr_report(_base_data(tier="silver"))
        assert "| CE Plus |" in md
        assert "30-day score trend" not in md

    def test_gold_gets_trend_annex(self) -> None:
        md = render_msr_report(_base_data(tier="gold"))
        assert "30-day score trend" in md
        assert "Compliance score declined" in md  # 85 → 82 in exec summary

    def test_quiet_month_has_green_summary(self) -> None:
        md = render_msr_report(MsrData(tenant_label="T", tier="bronze", period_label="2026-06"))
        assert "🟢 No critical incidents" in md

    def test_incident_and_change_sections_render(self) -> None:
        data = _base_data()
        data.incidents = [
            _inc("Critical", "Open", "2026-06-03T10:00:00Z") | {"title": "Tunnel down"}
        ]
        data.jobs = [
            {
                "type": "CommitAndPush",
                "result": "FAIL",
                "user": "ops@mssp",
                "description": "policy update",
                "start_ts": "2026-06-04 10:00:00",
            }
        ]
        md = render_msr_report(data)
        assert "Tunnel down" in md
        assert "🔴 **1 Critical/High incident(s)**" in md
        assert "CommitAndPush" in md
        assert "change failure rate" in md

    def test_licence_table_splits_expired_and_compresses_ancient(self) -> None:
        data = _base_data()
        data.licence_rows = [
            {"app": "pae", "license_type": "NFR-A", "exp": "2026-09-01", "days": 64},
            {"app": "pae", "license_type": "EVAL-B", "exp": "2026-05-14", "days": -65},
            {"app": "pae", "license_type": "EVAL-OLD", "exp": "2025-04-20", "days": -454},
        ]
        md = render_msr_report(data)
        assert "| 64 🟠 |" in md
        assert "expired 65d ago 🔴" in md
        assert "EVAL-OLD" not in md
        assert "1 SKU group(s) expired more than 90 days ago (omitted)." in md

    def test_unassessed_framework_score_is_not_a_percentage(self) -> None:
        data = _base_data(tier="silver")
        data.compliance_summaries = [
            {
                "id": "fw-x",
                "category": "PCF",
                "benchmark": False,
                "revision_summary": [
                    {"name": "PCF Base", "overall_score": -1, "state": "released"}
                ],
            }
        ]
        md = render_msr_report(data)
        assert "| not assessed |" in md
        assert "-1%" not in md

    def test_source_errors_disclosed(self) -> None:
        data = _base_data()
        data.errors["licences"] = "HTTP 403 from subscription API"
        data.errors["bandwidth"] = "skipped (include_insights=False)"
        md = render_msr_report(data)
        assert "⚠️ Licence data unavailable: HTTP 403" in md
        assert "⚠️ bandwidth — skipped" in md

    def test_ssr_ledger_renders_cumulative_note(self) -> None:
        data = _base_data()
        data.ssr_ledger = [
            {
                "object": "SSR-Allow-List",
                "kind": "url-list",
                "action": "add",
                "target": "example.com",
                "ticket_ref": "INC-9",
            }
        ]
        md = render_msr_report(data)
        assert "Service-request ledger" in md
        assert "| SSR-Allow-List | url-list | add | example.com | INC-9 |" in md
        assert "not" in md and "period-only activity" in md


# ---------------------------------------------------------------------------
# gather_msr_data with a mock client
# ---------------------------------------------------------------------------


def _mock_job(start_ts: str, result: str = "OK") -> MagicMock:
    j = MagicMock()
    j.id = "job-1"
    j.type_str = "Commit"
    j.result_str = result
    j.uname = "admin@mssp"
    j.description = "change"
    j.start_ts = start_ts
    j.end_ts = start_ts
    return j


class TestGather:
    def _client(self, incidents: list[dict], jobs: list[MagicMock]) -> MagicMock:
        client = MagicMock()
        resp = MagicMock()
        resp.json.return_value = {"data": incidents}
        resp.raise_for_status.return_value = None
        client.session.post.return_value = resp
        client.list_jobs.return_value = MagicMock(data=jobs)
        return client

    @staticmethod
    def _ext_patches() -> list:
        """Patches for the external calls added 2026-07-18 (ADEM, Monitor API,
        Insights month-window) so gather tests never touch the network."""
        return [
            patch("scm_harbourmaster_mcp.tools.msr.extract_adem", side_effect=lambda c, s: s),
            patch(
                "scm_harbourmaster_mcp.tools.msr._bearer_session_for",
                side_effect=RuntimeError("no mt session"),
            ),
            patch("scm_harbourmaster_mcp.tools.msr._insights_call", return_value=(403, "denied")),
            patch("scm_harbourmaster_mcp.tools.msr._refresh_token", return_value=None),
        ]

    def test_period_filtering_and_degradation(self) -> None:
        from scm_harbourmaster_mcp.tools.msr import gather_msr_data

        incidents = [
            {"severity": "High", "status": "Open", "raised_time": "2026-06-10T00:00:00Z"},
            {"severity": "Low", "status": "Open", "raised_time": "2026-05-10T00:00:00Z"},  # out
        ]
        jobs = [_mock_job("2026-06-05 10:00:00"), _mock_job("2026-07-05 10:00:00")]
        client = self._client(incidents, jobs)
        # Licence + insights + compliance calls fail → degradation, not raise
        import contextlib

        with contextlib.ExitStack() as stack:
            for p in [
                patch(
                    "scm_harbourmaster_mcp.tools.msr.fetch_licenses",
                    side_effect=RuntimeError("licence boom"),
                ),
                patch(
                    "scm_harbourmaster_mcp.tools.msr.extract_insights",
                    side_effect=RuntimeError("ins boom"),
                ),
                patch(
                    "scm_harbourmaster_mcp.tools.msr._compliance_get",
                    side_effect=RuntimeError("comp boom"),
                ),
                patch(
                    "scm_harbourmaster_mcp.tools.msr._resolve_tenant_meta",
                    return_value=("T", "t-1", "gold", "uk"),
                ),
                patch("scm_harbourmaster_mcp.tools.msr._get_ssr_config", return_value={}),
                *self._ext_patches(),
            ]:
                stack.enter_context(p)
            data = gather_msr_data(client, tenant_id="t-1", month="2026-06")

        assert len(data.incidents) == 1
        assert data.incidents[0]["severity"] == "High"
        assert len(data.jobs) == 1
        assert data.errors.keys() >= {"licences", "bandwidth", "compliance"}
        # Degraded pack still renders end-to-end
        md = render_msr_report(data)
        assert "Monthly Service Review — T" in md
        assert "licence boom" in md

    def test_bronze_skips_compliance_entirely(self) -> None:
        from scm_harbourmaster_mcp.tools.msr import gather_msr_data

        client = self._client([], [])
        import contextlib

        with contextlib.ExitStack() as stack:
            comp = stack.enter_context(patch("scm_harbourmaster_mcp.tools.msr._compliance_get"))
            for p in [
                patch("scm_harbourmaster_mcp.tools.msr.fetch_licenses", return_value=[]),
                patch(
                    "scm_harbourmaster_mcp.tools.msr._resolve_tenant_meta",
                    return_value=("T", "t-1", "bronze", "eu"),
                ),
                patch("scm_harbourmaster_mcp.tools.msr._get_ssr_config", return_value={}),
                *self._ext_patches(),
            ]:
                stack.enter_context(p)
            data = gather_msr_data(client, month="2026-06", include_insights=False)
        comp.assert_not_called()
        assert "compliance" not in data.errors

    def test_ssr_ledger_gathered_from_object_descriptions(self) -> None:
        from scm_harbourmaster_mcp.tools.msr import gather_msr_data

        client = self._client([], [])
        obj = MagicMock()
        obj.model_dump.return_value = {
            "description": "SSR add: example.com — INC-1 | SSR add: foo.example — INC-2"
        }
        client.url_category.fetch.return_value = obj
        import contextlib

        with contextlib.ExitStack() as stack:
            for p in [
                patch("scm_harbourmaster_mcp.tools.msr.fetch_licenses", return_value=[]),
                patch(
                    "scm_harbourmaster_mcp.tools.msr._resolve_tenant_meta",
                    return_value=("T", "t-1", "bronze", "eu"),
                ),
                patch(
                    "scm_harbourmaster_mcp.tools.msr._get_ssr_config",
                    return_value={"url_allow_list": "SSR-Allow"},
                ),
                patch(
                    "scm_harbourmaster_mcp.tools.msr._resolve_default_folder", return_value="Shared"
                ),
                *self._ext_patches(),
            ]:
                stack.enter_context(p)
            data = gather_msr_data(client, month="2026-06", include_insights=False)
        assert len(data.ssr_ledger) == 2
        assert data.ssr_ledger[0]["object"] == "SSR-Allow"
        assert data.ssr_ledger[1]["ticket_ref"] == "INC-2"


# ---------------------------------------------------------------------------
# Month-window additions (2026-07-18)
# ---------------------------------------------------------------------------


class TestMonthWindow:
    def test_between_filter_bounds(self) -> None:
        from scm_harbourmaster_mcp.audit.msr_report import month_bounds, month_window_filter

        start, end, _ = month_bounds("2026-06")
        body = month_window_filter(start, end)
        rule = body["filter"]["rules"][0]
        assert rule["operator"] == "between"
        assert rule["property"] == "event_time"
        assert rule["values"] == ["2026-06-01 00:00:00", "2026-07-01 00:00:00"]

    def test_fallback_days_clamped(self) -> None:
        from datetime import UTC, datetime

        from scm_harbourmaster_mcp.audit.msr_report import fallback_window_days

        now = datetime(2026, 7, 18, tzinfo=UTC)
        assert fallback_window_days(datetime(2026, 7, 17, tzinfo=UTC), now) == 7  # floor
        assert fallback_window_days(datetime(2026, 6, 1, tzinfo=UTC), now) == 48
        assert fallback_window_days(datetime(2025, 1, 1, tzinfo=UTC), now) == 62  # ceiling


class TestMergeBwAllocation:
    def test_exact_match_adds_utilisation(self) -> None:
        from scm_harbourmaster_mcp.audit.msr_report import merge_bw_allocation

        rows = [{"location": "UK South", "peak_consumption": 90.0}]
        allocs = [{"name": "uk-south", "allocated_mbps": 100}]
        merged = merge_bw_allocation(rows, allocs)
        assert merged[0]["allocated_mbps"] == 100
        assert merged[0]["utilisation_pct"] == 90

    def test_containment_match(self) -> None:
        from scm_harbourmaster_mcp.audit.msr_report import merge_bw_allocation

        rows = [{"location": "Frankfurt DE", "total_consumption": 25.0}]
        allocs = [{"name": "Frankfurt", "allocated_mbps": 50}]
        merged = merge_bw_allocation(rows, allocs)
        assert merged[0]["utilisation_pct"] == 50

    def test_unmatched_allocation_appended(self) -> None:
        from scm_harbourmaster_mcp.audit.msr_report import merge_bw_allocation

        merged = merge_bw_allocation([], [{"name": "us-east", "allocated_mbps": 200}])
        assert len(merged) == 1
        assert merged[0]["_allocation_only"] is True
        assert merged[0]["allocated_mbps"] == 200

    def test_no_allocation_leaves_row_untouched(self) -> None:
        from scm_harbourmaster_mcp.audit.msr_report import merge_bw_allocation

        rows = [{"location": "Tokyo", "peak_consumption": 10.0}]
        merged = merge_bw_allocation(rows, [])
        assert "allocated_mbps" not in merged[0]
        assert "utilisation_pct" not in merged[0]


class TestMuLocations:
    def test_dedups_users_per_location(self) -> None:
        from scm_harbourmaster_mcp.audit.msr_report import summarize_mu_locations

        rows = [
            {"user": "alice", "pa_location": "London"},
            {"user": "alice", "pa_location": "London"},  # reconnect — counts once
            {"user": "bob", "pa_location": "London"},
            {"user": "carol", "pa_location": "Paris"},
        ]
        assert summarize_mu_locations(rows) == [("London", 2), ("Paris", 1)]

    def test_counts_rows_without_user_key(self) -> None:
        from scm_harbourmaster_mcp.audit.msr_report import summarize_mu_locations

        rows = [{"location": "Berlin"}, {"location": "Berlin"}]
        assert summarize_mu_locations(rows) == [("Berlin", 2)]

    def test_no_location_key_returns_empty(self) -> None:
        from scm_harbourmaster_mcp.audit.msr_report import summarize_mu_locations

        assert summarize_mu_locations([{"user": "alice"}]) == []


class TestCommitCount:
    def test_commit_jobs_counted(self) -> None:
        from scm_harbourmaster_mcp.audit.msr_report import compute_service_stats

        jobs = [
            {"type": "CommitAndPush", "result": "OK"},
            {"type": "commit", "result": "OK"},
            {"type": "Validate", "result": "OK"},
        ]
        stats = compute_service_stats([], jobs)
        assert stats["commit_count"] == 2


class TestNewSectionsRender:
    def _base(self, **kwargs):
        from scm_harbourmaster_mcp.audit.msr_report import MsrData

        return MsrData(tenant_label="T", tier="gold", period_label="2026-06", **kwargs)

    def test_bw_month_table_with_utilisation_flags(self) -> None:
        from scm_harbourmaster_mcp.audit.msr_report import render_msr_report

        data = self._base(
            bw_month_rows=[
                {
                    "location": "UK South",
                    "peak_consumption": 95.0,
                    "allocated_mbps": 100,
                    "utilisation_pct": 95,
                },
                {"location": "us-east", "allocated_mbps": 200, "_allocation_only": True},
            ],
            bw_month_window="2026-06 (calendar month)",
        )
        md = render_msr_report(data)
        assert "## 7. Bandwidth Consumption vs Allocation" in md
        assert "95% 🔴" in md
        assert "allocation only" in md
        assert "at ≥90% of allocated bandwidth" in md  # exec bullet
        assert "2026-06 (calendar month)" in md

    def test_bw_falls_back_to_snapshot_when_month_unavailable(self) -> None:
        from scm_harbourmaster_mcp.audit.msr_report import render_msr_report

        data = self._base(
            bandwidth_rows=[{"location": "UK", "total_consumption": 5.0}],
        )
        data.errors["bandwidth_month"] = "HTTP 400"
        md = render_msr_report(data)
        assert "24-hour window" in md
        assert "month-window query was unavailable" in md

    def test_mu_section_renders_count_and_breakdown(self) -> None:
        from scm_harbourmaster_mcp.audit.msr_report import render_msr_report

        data = self._base(
            mu_month_users=42,
            mu_month_window="2026-06 (calendar month)",
            mu_month_locations=[("London", 30), ("Paris", 12)],
        )
        md = render_msr_report(data)
        assert "## 8. Mobile Users" in md
        assert "**42 unique mobile user(s)**" in md
        assert "| London | 30 |" in md
        assert "| Unique mobile users (2026-06 (calendar month)) | 42 |" in md  # stats row

    def test_adem_section_renders_scores(self) -> None:
        from scm_harbourmaster_mcp.audit.msr_report import render_msr_report

        data = self._base(
            adem_summary={
                "agents": {
                    "muAgent": {
                        "score": 87.0,
                        "clients": 10,
                        "clients_good": 8,
                        "clients_fair": 1,
                        "clients_poor": 1,
                    },
                }
            }
        )
        md = render_msr_report(data)
        assert "## 9. Digital Experience (ADEM)" in md
        assert "| Mobile Users | 87 | 10 | 8 | 1 | 1 |" in md
        assert "3-day window" in md

    def test_security_events_section_and_bullet(self) -> None:
        from scm_harbourmaster_mcp.audit.msr_report import render_msr_report

        data = self._base(
            threat_summary={"total_threats": 120, "blocked_count": 118, "window_days": 30}
        )
        md = render_msr_report(data)
        assert "## 10. Security Events" in md
        assert "| Threats detected | 120 |" in md
        assert "| Threats blocked | 118 |" in md
        assert "**118 security threat(s) blocked**" in md  # exec bullet

    def test_commit_row_in_stats(self) -> None:
        from scm_harbourmaster_mcp.audit.msr_report import render_msr_report

        data = self._base(
            jobs=[{"type": "CommitAndPush", "result": "OK", "start_ts": "2026-06-05 10:00:00"}]
        )
        md = render_msr_report(data)
        assert "| Commit jobs | 1 |" in md

    def test_sources_section_renumbered(self) -> None:
        from scm_harbourmaster_mcp.audit.msr_report import render_msr_report

        md = render_msr_report(self._base())
        assert "## 11. Data Sources & Coverage" in md


class TestGatherMonthAdditions:
    def _client(self) -> MagicMock:
        client = MagicMock()
        resp = MagicMock()
        resp.json.return_value = {"data": []}
        resp.raise_for_status.return_value = None
        client.session.post.return_value = resp
        client.list_jobs.return_value = MagicMock(data=[])
        return client

    def _base_patches(self) -> list:
        return [
            patch("scm_harbourmaster_mcp.tools.msr.fetch_licenses", return_value=[]),
            patch(
                "scm_harbourmaster_mcp.tools.msr._resolve_tenant_meta",
                return_value=("T", "t-1", "bronze", "uk"),
            ),
            patch("scm_harbourmaster_mcp.tools.msr._get_ssr_config", return_value={}),
            patch("scm_harbourmaster_mcp.tools.msr._refresh_token", return_value=None),
            patch(
                "scm_harbourmaster_mcp.tools.msr.extract_insights",
                return_value=MagicMock(
                    location_rn_bandwidth=[],
                    location_sc_bandwidth=[],
                    connected_mu_count=-1,
                    errors=[],
                ),
            ),
        ]

    def test_month_bandwidth_merged_and_gathered(self) -> None:
        import contextlib

        from scm_harbourmaster_mcp.tools.msr import gather_msr_data

        client = self._client()
        client.bandwidth_allocation.list.return_value = [
            MagicMock(name_attr="x", **{"name": "uk-south", "allocated_bandwidth": 100})
        ]

        def fake_call(session, path, tenant_id, body, region):
            if "location_rn_bandwidth" in path:
                assert body["filter"]["rules"][0]["operator"] == "between"
                return 200, {"data": [{"location": "UK South", "peak_consumption": 91.0}]}
            return 404, "nope"

        with contextlib.ExitStack() as stack:
            for p in [
                *self._base_patches(),
                patch("scm_harbourmaster_mcp.tools.msr._insights_call", side_effect=fake_call),
                patch("scm_harbourmaster_mcp.tools.msr.extract_adem", side_effect=lambda c, s: s),
                patch(
                    "scm_harbourmaster_mcp.tools.msr._bearer_session_for",
                    side_effect=RuntimeError("no mt"),
                ),
            ]:
                stack.enter_context(p)
            data = gather_msr_data(client, month="2026-06")

        assert data.bw_month_window == "2026-06 (calendar month)"
        row = data.bw_month_rows[0]
        assert row["allocated_mbps"] == 100
        assert row["utilisation_pct"] == 91
        assert any("bandwidth vs allocation" in g for g in data.gathered)

    def test_month_filter_rejected_falls_back_to_last_n_days(self) -> None:
        import contextlib

        from scm_harbourmaster_mcp.tools.msr import gather_msr_data

        client = self._client()
        client.bandwidth_allocation.list.return_value = []
        calls: list[dict] = []

        def fake_call(session, path, tenant_id, body, region):
            if "location_rn_bandwidth" not in path:
                return 404, "nope"
            calls.append(body)
            op = body["filter"]["rules"][0]["operator"]
            if op == "between":
                return 400, "Syntax error"
            return 200, {"data": [{"location": "UK", "peak_consumption": 1.0}]}

        with contextlib.ExitStack() as stack:
            for p in [
                *self._base_patches(),
                patch("scm_harbourmaster_mcp.tools.msr._insights_call", side_effect=fake_call),
                patch("scm_harbourmaster_mcp.tools.msr.extract_adem", side_effect=lambda c, s: s),
                patch(
                    "scm_harbourmaster_mcp.tools.msr._bearer_session_for",
                    side_effect=RuntimeError("no mt"),
                ),
            ]:
                stack.enter_context(p)
            data = gather_msr_data(client, month="2026-06")

        assert len(calls) == 2
        assert calls[1]["filter"]["rules"][0]["operator"] == "last_n_days"
        assert "month filter unsupported" in data.bw_month_window

    def test_mobile_users_count_and_breakdown(self) -> None:
        import contextlib

        from scm_harbourmaster_mcp.tools.msr import gather_msr_data

        client = self._client()
        client.bandwidth_allocation.list.return_value = []

        def fake_call(session, path, tenant_id, body, region):
            if "connected_user_count" in path:
                return 200, {"data": [{"connected_user_count": 42}]}
            if "user_list" in path:
                return 200, {
                    "data": [
                        {"user": "alice", "pa_location": "London"},
                        {"user": "bob", "pa_location": "London"},
                    ]
                }
            return 404, "nope"

        with contextlib.ExitStack() as stack:
            for p in [
                *self._base_patches(),
                patch("scm_harbourmaster_mcp.tools.msr._insights_call", side_effect=fake_call),
                patch("scm_harbourmaster_mcp.tools.msr.extract_adem", side_effect=lambda c, s: s),
                patch(
                    "scm_harbourmaster_mcp.tools.msr._bearer_session_for",
                    side_effect=RuntimeError("no mt"),
                ),
            ]:
                stack.enter_context(p)
            data = gather_msr_data(client, month="2026-06")

        assert data.mu_month_users == 42
        assert data.mu_month_locations == [("London", 2)]

    def test_adem_and_threats_gathered(self) -> None:
        import contextlib

        from scm_harbourmaster_mcp.tools.msr import gather_msr_data

        client = self._client()
        client.bandwidth_allocation.list.return_value = []

        def fake_adem(c, snap):
            snap.adem_agent_summary["muAgent"] = {"score": 90, "clients": 5}
            return snap

        mt_resp = MagicMock()
        mt_resp.status_code = 200
        mt_resp.json.return_value = {"data": [{"total_threats": 10, "blocked_count": 9}]}
        mt_session = MagicMock()
        mt_session.post.return_value = mt_resp

        with contextlib.ExitStack() as stack:
            for p in [
                *self._base_patches(),
                patch("scm_harbourmaster_mcp.tools.msr._insights_call", return_value=(404, "nope")),
                patch("scm_harbourmaster_mcp.tools.msr.extract_adem", side_effect=fake_adem),
                patch(
                    "scm_harbourmaster_mcp.tools.msr._bearer_session_for", return_value=mt_session
                ),
            ]:
                stack.enter_context(p)
            data = gather_msr_data(client, month="2026-06")

        assert data.adem_summary["agents"]["muAgent"]["score"] == 90
        assert data.threat_summary["blocked_count"] == 9
        assert data.threat_summary["total_threats"] == 10
        assert mt_session.post.call_args.kwargs["params"] == {"agg_by": "tenant"}


class TestInsightsTryGuard:
    def test_transport_exception_falls_back_to_last_n_days(self) -> None:
        """The Insights backend 500s (and the retry adapter raises) on the
        between filter for some tenants — the fallback window must engage
        on the exception, not only on a 4xx status."""
        import contextlib

        from scm_harbourmaster_mcp.tools.msr import gather_msr_data

        client = MagicMock()
        resp = MagicMock()
        resp.json.return_value = {"data": []}
        client.session.post.return_value = resp
        client.list_jobs.return_value = MagicMock(data=[])
        client.bandwidth_allocation.list.return_value = []

        def fake_call(session, path, tenant_id, body, region):
            if "location_rn_bandwidth" not in path:
                return 404, "nope"
            if body["filter"]["rules"][0]["operator"] == "between":
                raise RuntimeError("too many 500 error responses")
            return 200, {"data": [{"location": "UK", "peak_consumption": 2.0}]}

        with contextlib.ExitStack() as stack:
            for p in [
                patch("scm_harbourmaster_mcp.tools.msr.fetch_licenses", return_value=[]),
                patch(
                    "scm_harbourmaster_mcp.tools.msr._resolve_tenant_meta",
                    return_value=("T", "t-1", "bronze", "uk"),
                ),
                patch("scm_harbourmaster_mcp.tools.msr._get_ssr_config", return_value={}),
                patch("scm_harbourmaster_mcp.tools.msr._refresh_token", return_value=None),
                patch(
                    "scm_harbourmaster_mcp.tools.msr.extract_insights",
                    return_value=MagicMock(
                        location_rn_bandwidth=[],
                        location_sc_bandwidth=[],
                        connected_mu_count=-1,
                        errors=[],
                    ),
                ),
                patch("scm_harbourmaster_mcp.tools.msr._insights_call", side_effect=fake_call),
                patch("scm_harbourmaster_mcp.tools.msr.extract_adem", side_effect=lambda c, s: s),
                patch(
                    "scm_harbourmaster_mcp.tools.msr._bearer_session_for",
                    side_effect=RuntimeError("no mt"),
                ),
            ]:
                stack.enter_context(p)
            data = gather_msr_data(client, month="2026-06")

        assert "bandwidth_month" not in data.errors
        assert data.bw_month_rows[0]["location"] == "UK"
        assert "month filter unsupported" in data.bw_month_window
