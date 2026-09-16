"""The cassette scrubber must leave nothing identifying behind."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ._cassette import CASSETTE_DIR, load_cassette
from .scrubber import PLACEHOLDER_TSG_ID, Scrubber

pytestmark = pytest.mark.integration

# Obviously synthetic "real" values — none of these identify anything.
_RAW = {
    "description": "captured from Globex Widgets (tsg 5550001111)",
    "interactions": [
        {
            "name": "list incidents",
            "request": {
                "method": "GET",
                "url": "https://api.example.invalid/v1/incidents?tsgId=5550001111",
                "headers": {
                    "Authorization": "Bearer eyJhbGciOiJSUzI1NiJ9.fake.fake",
                    "Prisma-Tenant": "5550001111",
                    "X-PANW-Region": "uk",
                },
            },
            "response": {
                "status": 200,
                "headers": {"Set-Cookie": "session=abc", "Content-Type": "application/json"},
                "json": {
                    "tenant_name": "Globex Widgets Ltd",
                    "owner": "jane.doe@globex.invalid",
                    "access_token": "abc.def.ghi",
                    "created": 1758913230,
                    "time": "12:30:45",
                    "peers": ["10.20.30.40", "10.20.30.40", "8.8.8.8", "192.0.2.10"],
                    "v6": "fd00:1234::1",
                    "note": "Globex widgets tunnel to 10.20.30.40/32 for tenant_id=5550001111",
                },
            },
        }
    ],
}


def _scrubbed() -> dict:
    return Scrubber(tenant_names=["Globex Widgets"], known_ids=["5550001111"]).scrub_cassette(_RAW)


def test_credentials_are_removed() -> None:
    doc = _scrubbed()
    item = doc["interactions"][0]
    assert "Authorization" not in item["request"]["headers"]
    assert "Set-Cookie" not in item["response"]["headers"]
    assert item["response"]["json"]["access_token"] == "REDACTED"
    assert "eyJ" not in json.dumps(doc)


def test_identifiers_are_replaced() -> None:
    text = json.dumps(_scrubbed())
    assert "5550001111" not in text
    assert "globex" not in text.lower()
    assert "jane.doe" not in text
    assert PLACEHOLDER_TSG_ID in text
    assert "user@example.com" in text


def test_addresses_map_consistently_onto_documentation_ranges() -> None:
    body = _scrubbed()["interactions"][0]["response"]["json"]
    first, again, public, doc_range = body["peers"]
    assert first == again  # same real address -> same placeholder
    assert first != public
    assert first.startswith(("192.0.2.", "198.51.100.", "203.0.113."))
    assert doc_range == "192.0.2.10"  # already a documentation address
    assert body["v6"].startswith("2001:db8:")
    assert f"{first}/32" in body["note"]


def test_timestamps_and_clock_times_survive() -> None:
    body = _scrubbed()["interactions"][0]["response"]["json"]
    assert body["created"] == 1758913230
    assert body["time"] == "12:30:45"


def test_input_is_not_mutated() -> None:
    before = json.dumps(_RAW, sort_keys=True)
    _scrubbed()
    assert json.dumps(_RAW, sort_keys=True) == before


@pytest.mark.parametrize("path", sorted(CASSETTE_DIR.glob("*.json")), ids=lambda p: p.stem)
def test_shipped_cassettes_are_already_clean(path: Path) -> None:
    """Scrubbing a committed cassette must be a no-op — i.e. it holds nothing real."""
    doc = load_cassette(path.stem)
    assert Scrubber().scrub_cassette(doc) == doc
