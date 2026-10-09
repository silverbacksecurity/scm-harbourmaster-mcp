"""Tests for utils.paths — the single root for everything the server writes."""

from __future__ import annotations

from pathlib import Path

import pytest

from scm_harbourmaster_mcp.utils import paths

_OVERRIDES = (
    "SCM_MCP_DATA_DIR",
    "SCM_MCP_BACKUP_DIR",
    "SCM_MCP_BASELINE_DIR",
    "SCM_MCP_INDEX_DIR",
    "SCM_MCP_PLAN_DIR",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _OVERRIDES:
        monkeypatch.delenv(var, raising=False)


def test_defaults_are_relative_to_cwd() -> None:
    assert paths.data_dir() == Path(".")
    assert paths.backup_dir() == Path("backups")
    assert paths.baseline_dir() == Path("baselines")
    assert paths.index_dir() == Path("index")
    assert paths.plan_dir() == Path("plans")
    assert paths.reports_dir() == Path("reports")
    assert paths.logs_dir() == Path("logs")


def test_data_dir_moves_every_subdirectory(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SCM_MCP_DATA_DIR", "/data")
    assert paths.backup_dir() == Path("/data/backups")
    assert paths.baseline_dir() == Path("/data/baselines")
    assert paths.index_dir() == Path("/data/index")
    assert paths.plan_dir() == Path("/data/plans")
    assert paths.reports_dir() == Path("/data/reports")
    assert paths.logs_dir() == Path("/data/logs")


def test_per_directory_override_beats_data_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SCM_MCP_DATA_DIR", "/data")
    monkeypatch.setenv("SCM_MCP_BACKUP_DIR", "/mnt/backups")
    assert paths.backup_dir() == Path("/mnt/backups")
    assert paths.baseline_dir() == Path("/data/baselines")


def test_empty_data_dir_falls_back_to_cwd(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SCM_MCP_DATA_DIR", "")
    assert paths.backup_dir() == Path("backups")
