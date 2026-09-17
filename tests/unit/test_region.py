"""Tests for the shared X-PANW-Region resolver and mssp_detect_region.

Covers:
  - normalise/known region vocabulary (eu/us shorthand, case folding)
  - resolution order: override > settings region > detected > default
  - TenantConfig.region validation
  - format-preserving settings.toml persistence (and its refusals)
  - detection classification, caching and the dry-run report
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from scm_harbourmaster_mcp.config import region as region_mod
from scm_harbourmaster_mcp.config.settings import TenantConfig
from scm_harbourmaster_mcp.tools import region_detect
from scm_harbourmaster_mcp.tools.region_detect import Detection, RegionProbe

TSG = "1000000001"


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: Any) -> None:
    """No real settings.toml, no real tenant cache, no leftover detections."""
    monkeypatch.setattr("scm_harbourmaster_mcp.config.settings.load_all_tenant_configs", lambda: {})
    monkeypatch.setattr("scm_harbourmaster_mcp.auth.oauth.get_tenant_meta", lambda _tid: None)
    region_detect.reset_detections()


def _tenants(monkeypatch: Any, **cfgs: Any) -> None:
    monkeypatch.setattr(
        "scm_harbourmaster_mcp.config.settings.load_all_tenant_configs", lambda: dict(cfgs)
    )


def _tc(**kw: Any) -> SimpleNamespace:
    base = {"tenant_id": TSG, "region": "", "insights_region": "eu"}
    base.update(kw)
    return SimpleNamespace(**base)


# ── Vocabulary ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("eu", "europe"), ("US", "americas"), (" UK ", "uk"), ("europe", "europe"), ("", "")],
)
def test_normalise_region(raw: str, expected: str) -> None:
    assert region_mod.normalise_region(raw) == expected


def test_known_region_rejects_unknown_values() -> None:
    assert region_mod.known_region("de") == "de"
    assert region_mod.known_region("mars") == ""


def test_tenant_config_region_is_normalised_and_validated() -> None:
    tc = TenantConfig(tenant_id=TSG, client_id="c", client_secret="s", region="EU")
    assert tc.region == "europe"
    with pytest.raises(ValueError):
        TenantConfig(tenant_id=TSG, client_id="c", client_secret="s", region="mars")


# ── Resolution order ──────────────────────────────────────────────────────────


def test_override_beats_everything(monkeypatch: Any) -> None:
    _tenants(monkeypatch, acme=_tc(region="uk"))
    region_mod.remember_detected_region(TSG, "au")
    assert region_mod.resolve_region_with_source(TSG, explicit="us", default="sg") == (
        "americas",
        "override",
    )


def test_configured_region_beats_detection(monkeypatch: Any) -> None:
    _tenants(monkeypatch, acme=_tc(region="uk"))
    region_mod.remember_detected_region(TSG, "au")
    assert region_mod.resolve_region_with_source(TSG, default="europe") == ("uk", "configured")


def test_detected_region_beats_default_by_key_or_tsg(monkeypatch: Any) -> None:
    _tenants(monkeypatch, acme=_tc())
    region_mod.remember_detected_region(TSG, "uk")
    assert region_mod.resolve_region_with_source(TSG, default="europe") == ("uk", "detected")
    # The settings key resolves to the same tenant, so the TSG-keyed cache applies.
    assert region_mod.resolve_region_with_source("acme", default="europe") == ("uk", "detected")


def test_default_then_none() -> None:
    assert region_mod.resolve_region_with_source(TSG, default="eu") == ("europe", "default")
    assert region_mod.resolve_region_with_source(TSG) == ("", "none")


def test_forget_detected_region_clears_one_tenant() -> None:
    region_mod.remember_detected_region(TSG, "uk")
    region_mod.remember_detected_region("1000000002", "au")
    region_mod.forget_detected_region(TSG)
    assert region_mod.detected_region(TSG) == ""
    assert region_mod.detected_region("1000000002") == "au"


def test_insights_default_maps_settings_key(monkeypatch: Any) -> None:
    _tenants(monkeypatch, acme=_tc(insights_region="us"))
    assert region_mod.insights_default(TSG) == "americas"
    assert region_mod.insights_default("unknown-tenant") == "europe"


# ── settings.toml persistence ─────────────────────────────────────────────────

_SETTINGS = """\
[default]
log_level = "INFO"

[tenants.acme]
tenant_id       = "1000000001"
insights_region = "eu"   # keep this comment

[tenants.other]
tenant_id = "1000000002"
region    = "europe"  # set by hand
"""


def test_persist_adds_aligned_line_and_touches_nothing_else(tmp_path: Path) -> None:
    path = tmp_path / "settings.toml"
    path.write_text(_SETTINGS)
    plan = region_mod.plan_region_persist("acme", "uk", path)
    assert plan.ok, plan.message
    assert plan.old_line == ""
    assert plan.new_line == 'region          = "uk"'
    region_mod.write_region_setting(plan)
    after = path.read_text()
    assert after == _SETTINGS.replace(
        'insights_region = "eu"   # keep this comment\n',
        'insights_region = "eu"   # keep this comment\nregion          = "uk"\n',
    )


def test_persist_replaces_existing_value_keeping_comment(tmp_path: Path) -> None:
    path = tmp_path / "settings.toml"
    path.write_text(_SETTINGS)
    plan = region_mod.plan_region_persist("other", "uk", path)
    assert plan.ok, plan.message
    assert plan.new_line == 'region    = "uk"  # set by hand'


def test_persist_is_a_no_op_when_already_set(tmp_path: Path) -> None:
    path = tmp_path / "settings.toml"
    path.write_text(_SETTINGS)
    plan = region_mod.plan_region_persist("other", "europe", path)
    assert plan.ok
    assert plan.old_line == plan.new_line
    assert plan.new_text == _SETTINGS


@pytest.mark.parametrize(
    ("name", "tenant", "region", "reason"),
    [
        (".secrets.toml", "acme", "uk", "secrets"),
        ("settings.toml", "acme", "mars", "unknown region"),
        ("settings.toml", "missing", "uk", "no [tenants.missing]"),
    ],
)
def test_persist_refusals(tmp_path: Path, name: str, tenant: str, region: str, reason: str) -> None:
    path = tmp_path / name
    path.write_text(_SETTINGS)
    plan = region_mod.plan_region_persist(tenant, region, path)
    assert not plan.ok
    assert reason in plan.message
    with pytest.raises(ValueError):
        region_mod.write_region_setting(plan)
    assert path.read_text() == _SETTINGS


# ── Detection ─────────────────────────────────────────────────────────────────


def _probes(*with_data: str) -> list[RegionProbe]:
    return [
        RegionProbe(
            region=r, compliance="data" if r in with_data else "empty", has_data=r in with_data
        )
        for r in region_mod.KNOWN_REGIONS
    ]


def test_classify_detected_ambiguous_none() -> None:
    assert region_detect.classify(TSG, _probes("uk")).region == "uk"
    ambiguous = region_detect.classify(TSG, _probes("uk", "europe"))
    assert (ambiguous.status, ambiguous.region) == ("ambiguous", "")
    assert region_detect.classify(TSG, _probes()).status == "none"


def test_detect_region_caches_and_feeds_resolver(monkeypatch: Any) -> None:
    calls: list[str] = []

    def fake_probe(_client: Any, tsg: str) -> list[RegionProbe]:
        calls.append(tsg)
        return _probes("uk")

    monkeypatch.setattr(region_detect, "probe_regions", fake_probe)
    detection, cached = region_detect.detect_region(object(), TSG)
    assert (detection.status, detection.region, cached) == ("detected", "uk", False)
    assert region_mod.resolve_region(TSG, default="europe") == "uk"

    _, cached = region_detect.detect_region(object(), TSG)
    assert cached is True
    assert calls == [TSG]


def test_ambiguous_reprobe_forgets_previous_detection(monkeypatch: Any) -> None:
    results = iter([_probes("uk"), _probes("uk", "europe")])
    monkeypatch.setattr(region_detect, "probe_regions", lambda _c, _t: next(results))
    region_detect.detect_region(object(), TSG)
    region_detect.detect_region(object(), TSG, refresh=True)
    assert region_mod.resolve_region_with_source(TSG, default="europe") == ("europe", "default")


def test_report_dry_run_shows_line_without_writing(monkeypatch: Any, tmp_path: Path) -> None:
    path = tmp_path / "settings.toml"
    path.write_text(_SETTINGS)
    monkeypatch.setattr(region_detect, "settings_path", lambda: path)
    detection = Detection(TSG, "detected", "uk", ["uk"], _probes("uk"))

    report = region_detect.render_report(detection, False, "acme", persist=False)
    assert "Dry run" in report
    assert '`region          = "uk"`' in report
    assert path.read_text() == _SETTINGS

    report = region_detect.render_report(detection, False, "acme", persist=True)
    assert "Written" in report
    assert 'region          = "uk"' in path.read_text()


def test_report_never_persists_ambiguous(monkeypatch: Any, tmp_path: Path) -> None:
    path = tmp_path / "settings.toml"
    path.write_text(_SETTINGS)
    monkeypatch.setattr(region_detect, "settings_path", lambda: path)
    detection = Detection(TSG, "ambiguous", "", ["uk", "europe"], _probes("uk", "europe"))
    report = region_detect.render_report(detection, False, "acme", persist=True)
    assert "Nothing to write" in report
    assert path.read_text() == _SETTINGS
