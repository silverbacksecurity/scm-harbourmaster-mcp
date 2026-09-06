"""Unit tests for the tenant-dashboard nearest-licence-expiry selection.

Regression cover for the case where a long-dead legacy SKU (e.g. an old
logging_service Production License expired in 2025) dragged the dashboard's
"nearest expiry" permanently negative, masking the active NFR/SLS licences that
run to 2027-2028.
"""

from __future__ import annotations

from scm_harbourmaster_mcp.tools.ops import _nearest_licence_expiry


def _bundle(*expirations: str) -> list[dict]:
    """Wrap expiry timestamps into the SDK's subscription-bundle shape."""
    return [{"licenses": [{"license_expiration": e} for e in expirations]}]


class TestNearestLicenceExpiry:
    def test_skips_expired_legacy_sku_by_default(self) -> None:
        """Active SKUs win over a long-expired legacy SKU."""
        lics = _bundle(
            "2025-01-02T00:00:00",  # long-dead legacy logging_service SKU
            "2027-06-30T00:00:00",  # active SLS
            "2028-03-15T00:00:00",  # active NFR
        )
        days, exp = _nearest_licence_expiry(lics)
        assert exp == "2027-06-30"
        assert days is not None and days > 0

    def test_include_expired_restores_worst_sku(self) -> None:
        """include_expired=True reproduces the old nearest-across-all behaviour."""
        lics = _bundle(
            "2025-01-02T00:00:00",
            "2027-06-30T00:00:00",
            "2028-03-15T00:00:00",
        )
        days, exp = _nearest_licence_expiry(lics, include_expired=True)
        assert exp == "2025-01-02"
        assert days is not None and days < 0

    def test_all_expired_falls_back_to_worst(self) -> None:
        """A tenant with no active licences still flags its worst expired SKU."""
        lics = _bundle("2025-01-02T00:00:00", "2024-05-01T00:00:00")
        days, exp = _nearest_licence_expiry(lics)
        assert exp == "2024-05-01"
        assert days is not None and days < 0

    def test_no_licences_returns_none(self) -> None:
        assert _nearest_licence_expiry([]) == (None, "—")

    def test_unparseable_dates_ignored(self) -> None:
        """Bad/missing timestamps are skipped, not treated as expiry 0."""
        lics = _bundle("", "None", "not-a-date", "2027-06-30T00:00:00")
        days, exp = _nearest_licence_expiry(lics)
        assert exp == "2027-06-30"
        assert days is not None and days > 0

    def test_space_separated_timestamp_format(self) -> None:
        """The 'YYYY-MM-DD HH:MM:SS' variant parses too."""
        days, exp = _nearest_licence_expiry(_bundle("2027-06-30 12:00:00"))
        assert exp == "2027-06-30"
        assert days is not None and days > 0
