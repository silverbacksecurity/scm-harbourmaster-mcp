"""Unit tests for the pure helper functions in tools/ops.py.

These back the certificate, licence, and update-check tooling. They are pure
(no I/O), so they're cheap to pin down and high-value to regression-guard.
"""

from __future__ import annotations

import time
from types import SimpleNamespace

from scm_harbourmaster_mcp.tools.ops import (
    _SPN_BW_RESOURCES,
    _connected_mu_count,
    _days_until_epoch,
    _insights_query,
    _parse_expiry_str,
    _parse_semver,
    _status,
)


class TestStatus:
    def test_none_is_unknown(self) -> None:
        assert _status(None) == "UNKNOWN"

    def test_negative_is_expired(self) -> None:
        assert _status(-1) == "EXPIRED"

    def test_boundaries_default_warn(self) -> None:
        # < 30 CRITICAL, < 60 WARNING, < 90 CAUTION, else OK
        assert _status(0) == "CRITICAL"
        assert _status(29) == "CRITICAL"
        assert _status(30) == "WARNING"
        assert _status(59) == "WARNING"
        assert _status(60) == "CAUTION"
        assert _status(89) == "CAUTION"
        assert _status(90) == "OK"
        assert _status(365) == "OK"

    def test_custom_warn_threshold(self) -> None:
        # With warn=120, 90..119 days is CAUTION rather than OK
        assert _status(100, warn=120) == "CAUTION"
        assert _status(120, warn=120) == "OK"


class TestParseExpiryStr:
    def test_empty_and_sentinels_return_none(self) -> None:
        assert _parse_expiry_str("") is None
        assert _parse_expiry_str("None") is None

    def test_unparseable_returns_none(self) -> None:
        assert _parse_expiry_str("not-a-date") is None

    def test_iso_t_separator(self) -> None:
        future = "2099-01-01T00:00:00"
        days = _parse_expiry_str(future)
        assert days is not None and days > 0

    def test_space_separator(self) -> None:
        past = "2000-01-01 00:00:00"
        days = _parse_expiry_str(past)
        assert days is not None and days < 0

    def test_fractional_seconds_tolerated(self) -> None:
        # The parser splits on '.', so a trailing .123 is dropped, not fatal.
        days = _parse_expiry_str("2099-01-01T00:00:00.123")
        assert days is not None and days > 0


class TestDaysUntilEpoch:
    def test_future_epoch(self) -> None:
        future = str(int(time.time()) + 100 * 86400)
        days = _days_until_epoch(future)
        assert days is not None and 99 <= days <= 100

    def test_past_epoch(self) -> None:
        days = _days_until_epoch("0")  # 1970
        assert days is not None and days < 0

    def test_invalid_returns_none(self) -> None:
        assert _days_until_epoch("not-an-int") is None
        assert _days_until_epoch("") is None


class TestParseSemver:
    def test_full_triplet(self) -> None:
        assert _parse_semver("0.15.1") == (0, 15, 1)

    def test_truncates_to_three(self) -> None:
        assert _parse_semver("1.2.3.4") == (1, 2, 3)

    def test_partial_version(self) -> None:
        assert _parse_semver("1.2") == (1, 2)

    def test_ordering_for_update_detection(self) -> None:
        # This comparison is what drives "update available" in scm_check_updates.
        assert _parse_semver("2.0.0") > _parse_semver("1.9.9")
        assert _parse_semver("0.16.0") > _parse_semver("0.15.1")

    def test_unparseable_falls_back_to_zeros(self) -> None:
        assert _parse_semver("not-a-version") == (0, 0, 0)


class _Resp:
    def __init__(self, status_code: int = 200, payload=None, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class _Session:
    def __init__(self, resp: _Resp):
        self.resp = resp
        self.calls: list[dict] = []

    def post(self, url, json=None, headers=None, timeout=None):  # noqa: A002
        self.calls.append({"url": url, "json": json, "headers": headers})
        return self.resp


class TestInsightsQueryFromOps:
    """ops.py had its own Insights caller that skipped the region resolver."""

    def test_region_header_is_a_header_value_not_a_settings_key(self) -> None:
        session = _Session(_Resp(payload={"data": []}))
        _insights_query(session, "sn_bandwidth", "1234567890")
        assert session.calls[0]["headers"]["X-PANW-Region"] == "europe"

    def test_non_200_returns_empty_but_is_logged(self, capsys) -> None:
        """DATA10003 used to vanish completely — [] with no trace of why."""
        session = _Session(
            _Resp(status_code=400, payload=None, text='{"_errors":[{"code":"DATA10003"}]}')
        )
        assert _insights_query(session, "pa_bandwidth_consumption", "1") == []
        out = capsys.readouterr().out
        assert "insights_query_failed" in out
        assert "DATA10003" in out
        assert "status=400" in out

    def test_dead_resource_is_no_longer_attempted(self) -> None:
        assert "pa_bandwidth_consumption" not in _SPN_BW_RESOURCES
        assert _SPN_BW_RESOURCES == ("sn_bandwidth", "edge_bandwidth")


class TestConnectedMuCountRegion:
    def test_settings_key_is_mapped_before_it_reaches_the_header(self) -> None:
        client = SimpleNamespace(session=_Session(_Resp(payload={"data": []})), oauth_client=None)
        _connected_mu_count(client, "1234567890", "eu")
        assert client.session.calls[0]["headers"]["X-PANW-Region"] == "europe"

    def test_unknown_region_falls_back_rather_than_sending_junk(self) -> None:
        client = SimpleNamespace(session=_Session(_Resp(payload={"data": []})), oauth_client=None)
        _connected_mu_count(client, "1234567890", "mars")
        assert client.session.calls[0]["headers"]["X-PANW-Region"] == "europe"
