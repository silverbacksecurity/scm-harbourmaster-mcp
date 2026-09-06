"""Unit tests for the scm_renewal_brief pure helpers in tools/ops.py.

_licence_rows, _consumption_signal, and _renewal_talking_points carry the
commercial logic of the renewal brief (grouping, over/under-consumption
signals, talking-point generation); they take plain dicts so the whole
surface is testable without an SCM client.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from scm_harbourmaster_mcp.tools.ops import (
    _consumption_signal,
    _licence_rows,
    _renewal_talking_points,
)


def _exp(days: int) -> str:
    return (datetime.now(UTC) + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")


def _bundle(app: str, *licenses: dict) -> dict:
    return {"app_id": app, "licenses": list(licenses)}


class TestLicenceRows:
    def test_groups_by_app_and_expiry_and_sums_seats(self) -> None:
        lics = [
            _bundle(
                "prisma_access_edition",
                {"license_expiration": _exp(100), "purchased_size": 100, "remaining_size": 40},
                {"license_expiration": _exp(100), "purchased_size": 50, "remaining_size": 10},
            )
        ]
        (row,) = _licence_rows(lics)
        assert row["purchased"] == 150
        assert row["remaining"] == 50
        assert row["consumed"] == 100

    def test_sorted_soonest_expiry_first(self) -> None:
        lics = [
            _bundle("late", {"license_expiration": _exp(300), "purchased_size": 1}),
            _bundle("soon", {"license_expiration": _exp(10), "purchased_size": 1}),
            _bundle("no_expiry", {"license_expiration": "", "purchased_size": 1}),
        ]
        rows = _licence_rows(lics)
        assert [r["app"] for r in rows] == ["soon", "late", "no_expiry"]

    def test_null_sizes_are_treated_as_zero(self) -> None:
        lics = [_bundle("x", {"license_expiration": _exp(5), "purchased_size": None})]
        (row,) = _licence_rows(lics)
        assert row["purchased"] == 0 and row["consumed"] == 0

    def test_same_day_bundles_merge_despite_timestamp_seconds(self) -> None:
        # Real Subscription API data: same SKU, expirations differing by seconds
        base = _exp(67)[:10]
        lics = [
            _bundle(
                "logging_service",
                {
                    "license_type": "Production License",
                    "license_expiration": f"{base}T10:00:01",
                    "purchased_size": 1,
                    "remaining_size": 0,
                },
                {
                    "license_type": "Production License",
                    "license_expiration": f"{base}T10:00:59",
                    "purchased_size": 1,
                    "remaining_size": 0,
                },
            )
        ]
        (row,) = _licence_rows(lics)
        assert row["purchased"] == 2

    def test_different_license_types_stay_separate(self) -> None:
        exp = _exp(67)
        lics = [
            _bundle(
                "prisma_access_edition",
                {"license_type": "PAE-MU-NFR", "license_expiration": exp, "purchased_size": 1},
                {"license_type": "PAE-NET-NFR", "license_expiration": exp, "purchased_size": 1},
            )
        ]
        assert len(_licence_rows(lics)) == 2


class TestConsumptionSignal:
    def test_zero_contract_is_na(self) -> None:
        assert _consumption_signal(0, 0) == "N/A"

    def test_over_contract_is_oversubscribed(self) -> None:
        assert _consumption_signal(100, 120) == "OVERSUBSCRIBED"

    def test_exactly_full_is_healthy(self) -> None:
        assert _consumption_signal(100, 100) == "HEALTHY"

    def test_below_threshold_is_underused(self) -> None:
        assert _consumption_signal(100, 39) == "UNDERUSED"
        assert _consumption_signal(100, 40) == "HEALTHY"

    def test_custom_threshold(self) -> None:
        assert _consumption_signal(100, 55, underuse_pct=60) == "UNDERUSED"

    def test_negative_consumption_is_na_not_underused(self) -> None:
        # Pooled parent SKU: remaining_size > purchased_size → consumed < 0
        assert _consumption_signal(8201, -4600) == "N/A"


class TestRenewalTalkingPoints:
    def _points(self, rows: list[dict], **kw: object) -> list[str]:
        defaults: dict = {
            "horizon_days": 180,
            "underuse_pct": 40,
            "bw_total_mbps": 0.0,
            "bw_locations": 0,
            "mu_connected": None,
            "mu_seats": 0,
        }
        defaults.update(kw)
        return _renewal_talking_points(rows, **defaults)

    def _row(self, app: str, days: int | None, purchased: int = 0, consumed: int = 0) -> dict:
        return {
            "app": app,
            "exp": _exp(days) if days is not None else "",
            "license_type": "",
            "purchased": purchased,
            "remaining": purchased - consumed,
            "consumed": consumed,
            "days": days,
        }

    def test_expired_licence_raises_immediate_renewal(self) -> None:
        points = self._points([self._row("prisma_access", -5, 10, 5)])
        assert any("expired" in p and "renew immediately" in p for p in points)

    def test_expiry_within_horizon_raises_renewal_point(self) -> None:
        points = self._points([self._row("prisma_access", 90, 10, 5)])
        assert any("Renew" in p and "90 day(s)" in p for p in points)

    def test_oversubscription_raises_true_up_point(self) -> None:
        points = self._points([self._row("prisma_access", 300, purchased=100, consumed=130)])
        assert any("true-up" in p for p in points)

    def test_underuse_raises_downsize_risk_point(self) -> None:
        points = self._points([self._row("prisma_access", 300, purchased=100, consumed=10)])
        assert any("downsize risk" in p for p in points)

    def test_expired_rows_do_not_also_flag_consumption(self) -> None:
        points = self._points([self._row("dead_sku", -400, purchased=100, consumed=5)])
        assert not any("downsize risk" in p for p in points)

    def test_mobile_user_headroom_point(self) -> None:
        points = self._points([], mu_connected=85, mu_seats=100)
        assert any("near seat capacity" in p for p in points)
        points = self._points([], mu_connected=20, mu_seats=100)
        assert any("healthy headroom" in p for p in points)

    def test_bandwidth_point_when_allocated(self) -> None:
        points = self._points([], bw_total_mbps=500.0, bw_locations=3)
        assert any("500 Mbps" in p and "3" in p for p in points)

    def test_identical_bullets_are_deduplicated(self) -> None:
        rows = [
            self._row("logging_service", 67, 1, 1),
            self._row("logging_service", 67, 1, 1),
        ]
        points = self._points(rows)
        assert len([p for p in points if "Renew" in p]) == 1

    def test_negative_consumption_produces_no_consumption_bullet(self) -> None:
        points = self._points([self._row("pooled_sku", 300, purchased=8201, consumed=-4600)])
        assert not any("downsize risk" in p or "true-up" in p for p in points)

    def test_no_risks_yields_green_summary(self) -> None:
        points = self._points([self._row("prisma_access", 400, purchased=100, consumed=60)])
        assert len(points) == 1
        assert "No renewal risks" in points[0]
