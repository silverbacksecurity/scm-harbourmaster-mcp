"""Compliance Frameworks: X-PANW-Region selects the data region.

The API documents the header as required but does not enforce it. A missing,
wrong or wrongly-cased region answers HTTP 200 with ``data_available: false``
and scores of -1 — a response that renders as a legitimate "non-compliant"
report. The tool must send the tenant's region, discover it when it is not
configured, and say plainly when a result is empty rather than zero.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
import requests
import responses

from scm_harbourmaster_mcp.tools import compliance as compliance_mod
from scm_harbourmaster_mcp.tools.compliance import register_compliance_tools

from .conftest import FAKE_TSG_ID

pytestmark = pytest.mark.integration

_BASE = "https://api.strata.paloaltonetworks.com/posture/compliance-frameworks/v1"
_FW = "PCF-00000000-0000-4000-8000-000000000301"


def _region_of(call: Any) -> str | None:
    value: str | None = call.request.headers.get("X-PANW-Region")
    return value


def _score_calls(http: responses.RequestsMock) -> list[Any]:
    return [c for c in http.calls if "/overall-compliance/" in (c.request.url or "")]


@pytest.mark.parametrize("region", [None, "UK", "eu", "americas"])
def test_cassette_reproduces_silent_empty_region(
    cassette: Callable[[str], Any], region: str | None
) -> None:
    """Every wrong region is a 200 with an empty payload, never an error."""
    cassette("compliance_region_uk")
    headers = {"X-PANW-Region": region} if region else {}
    resp = requests.get(f"{_BASE}/overall-compliance/{_FW}", headers=headers, timeout=5)
    assert resp.status_code == 200
    assert resp.json()["products"]["all"]["data_available"] is False


def test_unconfigured_region_is_discovered_and_sent(
    cassette: Callable[[str], Any],
    http: responses.RequestsMock,
    scm_client: Any,
    invoke_tool: Callable[..., str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cassette("compliance_region_uk")
    monkeypatch.setattr(compliance_mod, "_configured_region", lambda _tid: "")

    out = invoke_tool(
        register_compliance_tools,
        "scm_compliance_center",
        scm_client,
        tenant_id=FAKE_TSG_ID,
        action="scores",
        framework_id=_FW,
    )

    assert "### Scoreboard" in out, out
    assert "89" in out
    assert "*Data region: `uk` (auto-detected).*" in out
    assert "No assessment results" not in out
    # Discovery probes regions in order and stops at the one holding data;
    # the real request then carries that region.
    regions = [_region_of(c) for c in _score_calls(http)]
    assert regions == ["americas", "europe", "uk", "uk"]


def test_second_call_reuses_the_discovered_region(
    cassette: Callable[[str], Any],
    http: responses.RequestsMock,
    scm_client: Any,
    invoke_tool: Callable[..., str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cassette("compliance_region_uk")
    monkeypatch.setattr(compliance_mod, "_configured_region", lambda _tid: "")
    kwargs = {"tenant_id": FAKE_TSG_ID, "action": "scores", "framework_id": _FW}

    invoke_tool(register_compliance_tools, "scm_compliance_center", scm_client, **kwargs)
    first = len(http.calls)
    invoke_tool(register_compliance_tools, "scm_compliance_center", scm_client, **kwargs)

    new_calls = http.calls[first:]
    assert len(new_calls) == 1, "region discovery must run once per tenant per process"
    assert _region_of(new_calls[0]) == "uk"


def test_configured_wrong_region_is_flagged_not_scored(
    cassette: Callable[[str], Any],
    http: responses.RequestsMock,
    scm_client: Any,
    invoke_tool: Callable[..., str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cassette("compliance_region_uk")
    monkeypatch.setattr(compliance_mod, "_configured_region", lambda _tid: "americas")

    out = invoke_tool(
        register_compliance_tools,
        "scm_compliance_center",
        scm_client,
        tenant_id=FAKE_TSG_ID,
        action="scores",
        framework_id=_FW,
    )

    assert "No assessment results in region `americas`" in out, out
    assert "not a compliance score of zero" in out
    assert "### Scoreboard" not in out
    assert [_region_of(c) for c in _score_calls(http)] == ["americas"]


def test_unassessed_tenant_warns_that_no_region_was_found(
    cassette: Callable[[str], Any],
    http: responses.RequestsMock,
    scm_client: Any,
    invoke_tool: Callable[..., str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cassette("compliance_region_unassessed")
    monkeypatch.setattr(compliance_mod, "_configured_region", lambda _tid: "")

    out = invoke_tool(
        register_compliance_tools,
        "scm_compliance_center",
        scm_client,
        tenant_id=FAKE_TSG_ID,
        action="scores",
        framework_id=_FW,
    )

    assert "No data region identified for this tenant" in out, out
    assert "No assessment results in the default region" in out
    assert "### Scoreboard" not in out
    # All four regions were probed, then the real call went out header-less.
    regions = [_region_of(c) for c in _score_calls(http)]
    assert regions == ["americas", "europe", "uk", "au", None]
