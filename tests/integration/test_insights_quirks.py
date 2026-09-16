"""Prisma Access Insights v3.0 quirks, driven through scm_insights_query.

* Bandwidth resources (location_rn_bandwidth / location_sc_bandwidth) 400 on a
  body without a filter — the backend splices the time predicate into a SQL
  template — so the tool must supply an ``event_time`` window by default.
* A 400 carrying DATA10003 means the resource path no longer exists; DATA10005
  means it exists but the body is incomplete. They need different handling:
  retrying a missing resource with another body is pointless.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest
import requests
import responses

from scm_harbourmaster_mcp.tools.insights import register_insights_tools

from ._cassette import request_json
from .conftest import FAKE_TSG_ID

pytestmark = pytest.mark.integration

_QUERY = "https://api.sase.paloaltonetworks.com/insights/v3.0/resource/query"


def _query(invoke_tool: Callable[..., str], client: Any, **kwargs: Any) -> dict[str, Any]:
    out = invoke_tool(
        register_insights_tools,
        "scm_insights_query",
        client,
        tenant_id=FAKE_TSG_ID,
        region="uk",
        **kwargs,
    )
    parsed: dict[str, Any] = json.loads(out)
    return parsed


def test_cassette_reproduces_empty_body_400(cassette: Callable[[str], Any]) -> None:
    cassette("insights_bandwidth_time_window")
    resp = requests.post(f"{_QUERY}/locations/location_rn_bandwidth", json={}, timeout=5)
    assert resp.status_code == 400
    assert resp.json()["errors"][0]["code"] == "GCP10002"


@pytest.mark.parametrize("resource", ["location_rn_bandwidth", "location_sc_bandwidth"])
@pytest.mark.parametrize("body", ["", "{}"])
def test_bandwidth_query_sends_event_time_window(
    cassette: Callable[[str], Any],
    http: responses.RequestsMock,
    scm_client: Any,
    invoke_tool: Callable[..., str],
    resource: str,
    body: str,
) -> None:
    cassette("insights_bandwidth_time_window")
    out = _query(invoke_tool, scm_client, resource=f"locations/{resource}", body=body)

    assert "error" not in out, out
    assert out["count"] == 1
    assert out["data"][0]["edge_location_display_name"] == "Example Location"
    assert out["time_window"] == "last_24h (assumed)"

    assert len(http.calls) == 1, "a windowed body must succeed first time"
    sent = request_json(http.calls[0])
    rules = sent["filter"]["rules"]
    assert {"property": "event_time", "operator": "last_n_hours", "values": ["24"]} in rules
    call = http.calls[0].request
    assert call.headers["X-PANW-Region"] == "uk"
    assert call.headers["Prisma-Tenant"] == FAKE_TSG_ID


def test_bandwidth_window_size_follows_hours(
    cassette: Callable[[str], Any],
    http: responses.RequestsMock,
    scm_client: Any,
    invoke_tool: Callable[..., str],
) -> None:
    cassette("insights_bandwidth_time_window")
    out = _query(invoke_tool, scm_client, resource="locations/location_rn_bandwidth", hours=6)

    assert out["time_window"] == "last_6h (assumed)"
    assert request_json(http.calls[0])["filter"]["rules"][0]["values"] == ["6"]


def test_data10003_is_reported_as_missing_resource_without_retry(
    cassette: Callable[[str], Any],
    http: responses.RequestsMock,
    scm_client: Any,
    invoke_tool: Callable[..., str],
) -> None:
    cassette("insights_error_codes")
    out = _query(invoke_tool, scm_client, resource="pa_bandwidth_consumption")

    assert out["error"] == "HTTP 400"
    assert out["error_code"] == "DATA10003"
    assert out["hint"].startswith("resource_not_found")
    # The window was not blamed: no bare-body retry for a resource that is gone.
    assert len(http.calls) == 1
    assert out["time_window"] == "last_24h (assumed)"


def test_data10005_is_reported_as_invalid_body(
    cassette: Callable[[str], Any],
    http: responses.RequestsMock,
    scm_client: Any,
    invoke_tool: Callable[..., str],
) -> None:
    cassette("insights_error_codes")
    out = _query(invoke_tool, scm_client, resource="users/agent/user_list")

    assert out["error"] == "HTTP 400"
    assert out["error_code"] == "DATA10005"
    assert out["hint"].startswith("invalid_body")
    # The resource exists, so the bare-body fallback is still worth one try.
    assert len(http.calls) == 2
    assert "filter" in request_json(http.calls[0])
    assert request_json(http.calls[1]) == {}
