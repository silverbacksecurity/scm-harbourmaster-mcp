"""Tests for scm_saas_posture — SSPM posture tool with manual export/import.

The SSPM extractors are monkeypatched to populate the snapshot with canned
data (shapes match the live API as captured from a lab tenant), so no network.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

import scm_harbourmaster_mcp.audit.extractor as extractor_mod
from scm_harbourmaster_mcp.tools.posture import register_posture_tools

APPS = [
    {
        "app_id": "o365",
        "display_name": "Office 365",
        "status": "connected",
        "verticals": ["Collaboration"],
        "_configs": [
            {"title": "MFA not enforced", "severity": "Critical", "status": "failed"},
            {"title": "Legacy auth enabled", "severity": "Low", "status": "failed"},
        ],
    },
    {
        "app_id": "slack",
        "display_name": "Slack",
        "status": "connected",
        "verticals": ["Messaging"],
        "_configs": [],
    },
]
IDPS = [{"display_name": "Okta Prod", "idp_type": "okta", "status": "active"}]
CATALOG = [
    {"display_name": "Office 365", "verticals": ["Collaboration"], "features": ["SCAN"]},
    {"display_name": "GitHub", "verticals": ["DevOps"], "features": ["SCAN", "IDENTITY_NHI"]},
]


def _fake_extractors(
    monkeypatch: pytest.MonkeyPatch,
    *,
    licensed: bool = True,
    apps: list[dict[str, Any]] | None = None,
    idps: list[dict[str, Any]] | None = None,
    catalog: list[dict[str, Any]] | None = None,
    calls: list[str] | None = None,
) -> None:
    def fake_sspm(client: Any, snap: Any) -> Any:
        if calls is not None:
            calls.append("sspm")
        snap.sspm_licensed = licensed
        snap.sspm_apps = list(apps or [])
        snap.sspm_catalog = list(catalog or [])
        return snap

    def fake_identity(client: Any, snap: Any) -> Any:
        if calls is not None:
            calls.append("identity")
        snap.identity_sspm_licensed = licensed
        snap.identity_sspm_idps = list(idps or [])
        return snap

    monkeypatch.setattr(extractor_mod, "extract_sspm", fake_sspm)
    monkeypatch.setattr(extractor_mod, "extract_identity_sspm", fake_identity)


def _tool() -> Any:
    mcp = FastMCP("test")
    register_posture_tools(mcp, lambda tenant_id="": object())
    return mcp._tool_manager.get_tool("scm_saas_posture").fn


def test_live_with_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_extractors(monkeypatch, apps=APPS, idps=IDPS, catalog=CATALOG)
    out = _tool()(tenant_id="t1")
    assert "| Onboarded SaaS applications | 2 |" in out
    assert "| Misconfiguration findings | 2 |" in out
    assert "| High/Critical findings | 1 |" in out
    # critical finding ranks first in Top Findings
    top = out.split("## Top Findings")[1]
    assert top.index("MFA not enforced") < top.index("Legacy auth enabled")
    assert "| Okta Prod | okta | active |" in out


def test_unlicensed(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_extractors(monkeypatch, licensed=False)
    out = _tool()(tenant_id="t1")
    assert "not licensed or not reachable" in out
    assert "not provisioned" in out


def test_licensed_no_apps_shows_catalog_capabilities(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_extractors(monkeypatch, apps=[], catalog=CATALOG)
    out = _tool()(tenant_id="t1")
    assert "no SaaS applications are onboarded" in out
    assert "| Posture/misconfiguration scanning (SCAN) | 2 |" in out
    assert "| Non-Human Identity tracking (NHI) | 1 |" in out


def test_export_and_import_round_trip(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    calls: list[str] = []
    _fake_extractors(monkeypatch, apps=APPS, idps=IDPS, catalog=CATALOG, calls=calls)
    export = tmp_path / "posture.json"
    out = _tool()(tenant_id="t1", save_to=str(export))
    assert "Snapshot exported" in out
    data = json.loads(export.read_text())
    assert data["format"] == "scm-harbourmaster-mcp/saas-posture@1"
    assert data["tenant_id"] == "t1"
    assert len(data["apps"]) == 2
    assert calls == ["sspm", "identity"]

    # import renders the same content without touching the API
    out2 = _tool()(load_from=str(export))
    assert calls == ["sspm", "identity"]  # no new extractor calls
    assert "imported file" in out2
    assert "| Onboarded SaaS applications | 2 |" in out2
    assert "MFA not enforced" in out2


def test_import_rejects_wrong_format(tmp_path: Any) -> None:
    bad = tmp_path / "other.json"
    bad.write_text(json.dumps({"format": "something-else", "apps": []}))
    out = _tool()(load_from=str(bad))
    assert out.startswith("Error:") and "format marker" in out


def test_import_missing_file() -> None:
    out = _tool()(load_from="/nonexistent/posture.json")
    assert out.startswith("Error:")


def test_include_catalog_groups_by_vertical(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_extractors(monkeypatch, apps=APPS, catalog=CATALOG)
    out = _tool()(tenant_id="t1", include_catalog=True)
    assert "## Supported App Catalog" in out
    assert "**DevOps** (1): GitHub" in out
