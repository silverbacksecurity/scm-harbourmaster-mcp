"""Tests for scm_service_maintenance (public statuspage feed, mocked)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

import scm_harbourmaster_mcp.tools.service_status as ss_mod


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


NOW = datetime.now(UTC)

FEED = {
    "status.json": {"status": {"indicator": "minor", "description": "Partially Degraded Service"}},
    "incidents/unresolved.json": {
        "incidents": [
            {
                "name": "Azure westeurope outage impacting Cloud NGFW Services.",
                "impact": "minor",
                "status": "monitoring",
                "updated_at": _iso(NOW),
                "components": [{"name": "westeurope"}],
                "shortlink": "https://stspg.io/x",
            },
            {
                "name": "Prisma Cloud app.prismacloud.io degradation",
                "impact": "minor",
                "status": "investigating",
                "updated_at": _iso(NOW),
                "components": [{"name": "Americas - US - app.prismacloud.io"}],
                "shortlink": "https://stspg.io/y",
            },
        ]
    },
    "scheduled-maintenances/upcoming.json": {
        "scheduled_maintenances": [
            {
                "name": "Enterprise DLP: Australia Region Maintenance",
                "status": "scheduled",
                "scheduled_for": _iso(NOW + timedelta(days=2)),
                "scheduled_until": _iso(NOW + timedelta(days=2, hours=3)),
                "components": [{"name": "DLP (NGFW) APAC"}],
                "shortlink": "https://stspg.io/a",
            },
            {
                "name": "Prisma Access: EMEA (Frankfurt) upgrade",
                "status": "scheduled",
                "scheduled_for": _iso(NOW + timedelta(days=5)),
                "scheduled_until": _iso(NOW + timedelta(days=5, hours=2)),
                "components": [{"name": "EMEA (Frankfurt) - Prisma Access"}],
                "shortlink": "https://stspg.io/b",
            },
            {
                "name": "Strata Logging Service global upgrade",
                "status": "scheduled",
                "scheduled_for": _iso(NOW + timedelta(days=3)),
                "scheduled_until": _iso(NOW + timedelta(days=3, hours=1)),
                "components": [{"name": "Strata Logging Service"}],
                "shortlink": "https://stspg.io/c",
            },
            {
                "name": "Prisma Access: US East upgrade far out",
                "status": "scheduled",
                "scheduled_for": _iso(NOW + timedelta(days=40)),
                "scheduled_until": _iso(NOW + timedelta(days=40, hours=2)),
                "components": [{"name": "Americas (US East) - Prisma Access"}],
                "shortlink": "https://stspg.io/d",
            },
            {
                "name": "Prisma Cloud [APP.SG] - Scheduled maintenance",
                "status": "scheduled",
                "scheduled_for": _iso(NOW + timedelta(days=1)),
                "scheduled_until": _iso(NOW + timedelta(days=1, hours=2)),
                "components": [{"name": "Asia Pacific - Singapore - app.sg.prismacloud.io"}],
                "shortlink": "https://stspg.io/e",
            },
        ]
    },
    "scheduled-maintenances/active.json": {"scheduled_maintenances": []},
}


@pytest.fixture
def tool(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setattr(ss_mod, "_fetch", lambda path: FEED[path])
    from types import SimpleNamespace

    monkeypatch.setattr(
        "scm_harbourmaster_mcp.config.settings.load_all_tenant_configs",
        lambda: {
            "t-eu": SimpleNamespace(insights_region="eu"),
            "t-au": SimpleNamespace(insights_region="au"),
        },
    )
    mcp = FastMCP("test")
    ss_mod.register_service_status_tools(mcp, lambda tenant_id="": object())
    return mcp._tool_manager.get_tool("scm_service_maintenance").fn


def test_sase_filter_and_horizon(tool: Any) -> None:
    data = json.loads(tool(days=14))
    names = [w["name"] for w in data["maintenance_windows"]]
    # Prisma Cloud window filtered out; 40-day window beyond horizon
    assert "Prisma Cloud [APP.SG] - Scheduled maintenance" not in names
    assert "Prisma Access: US East upgrade far out" not in names
    assert len(names) == 3
    # incidents: Cloud NGFW kept, Prisma Cloud dropped
    assert len(data["unresolved_incidents"]) == 1
    assert data["indicator"] == "minor"


def test_region_matching(tool: Any) -> None:
    data = json.loads(tool(days=14))
    by_name = {w["name"]: w for w in data["maintenance_windows"]}
    assert "au" in by_name["Enterprise DLP: Australia Region Maintenance"]["regions"]
    assert by_name["Prisma Access: EMEA (Frankfurt) upgrade"]["regions"] == ["eu"]
    assert by_name["Strata Logging Service global upgrade"]["regions"] == ["global"]


def test_tenant_scoping(tool: Any) -> None:
    data = json.loads(tool(tenant_id="t-eu", days=14))
    names = [w["name"] for w in data["maintenance_windows"]]
    # EU tenant: Frankfurt window + global window, not the AU one
    assert names == [
        "Strata Logging Service global upgrade",
        "Prisma Access: EMEA (Frankfurt) upgrade",
    ]
    assert data["region"] == "eu"


def test_all_tenants_grouping(tool: Any) -> None:
    data = json.loads(tool(all_tenants=True, days=14))
    assert data["tenants"]["t-eu"]["count"] == 2
    assert data["tenants"]["t-au"]["count"] == 2  # AU DLP + global


def test_include_all_products(tool: Any) -> None:
    data = json.loads(tool(days=14, include_all_products=True))
    names = [w["name"] for w in data["maintenance_windows"]]
    assert "Prisma Cloud [APP.SG] - Scheduled maintenance" in names


def test_status_banner_degraded_and_maintenance(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ss_mod, "_fetch", lambda path, timeout=None: FEED[path])
    lines = ss_mod.status_banner(days=7)
    assert len(lines) == 2
    assert "PAN cloud status: Partially Degraded Service" in lines[0]
    assert "1 unresolved SASE incident(s)" in lines[0]
    assert "Cloud NGFW" in lines[0]
    # nearest SASE window within 7d is the AU DLP one (day 2)
    assert "Next SASE maintenance: Enterprise DLP: Australia Region Maintenance" in lines[1]
    assert "+2 more within 7d" in lines[1]


def test_status_banner_healthy_is_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    healthy = {
        "status.json": {"status": {"indicator": "none", "description": "Operational"}},
        "incidents/unresolved.json": {"incidents": []},
        "scheduled-maintenances/upcoming.json": {"scheduled_maintenances": []},
    }
    monkeypatch.setattr(ss_mod, "_fetch", lambda path, timeout=None: healthy[path])
    assert ss_mod.status_banner() == []


def test_status_banner_swallows_fetch_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(path: str, timeout: Any = None) -> Any:
        raise OSError("network down")

    monkeypatch.setattr(ss_mod, "_fetch", boom)
    assert ss_mod.status_banner() == []


def test_cli_status_light_degraded_and_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    import scm_harbourmaster_mcp.cli as cli

    calls = {"n": 0}

    def fetch(path: str, timeout: Any = None) -> Any:
        calls["n"] += 1
        return FEED[path]

    monkeypatch.setattr(ss_mod, "_fetch", fetch)
    cli._status_light_cache.update(ts=0.0, line="")
    line = cli._scm_status_light()
    assert line.startswith("🟡 PAN cloud: Partially Degraded Service")
    assert "1 SASE incident(s)" in line
    first_calls = calls["n"]
    assert cli._scm_status_light() == line  # cached — no refetch
    assert calls["n"] == first_calls


def test_cli_status_light_unreachable_grey(monkeypatch: pytest.MonkeyPatch) -> None:
    import scm_harbourmaster_mcp.cli as cli

    def boom(path: str, timeout: Any = None) -> Any:
        raise OSError("down")

    monkeypatch.setattr(ss_mod, "_fetch", boom)
    cli._status_light_cache.update(ts=0.0, line="")
    assert cli._scm_status_light() == "⚪ PAN cloud: status unavailable"
