"""Unit tests for the CLI backup picker used by Config Clone (cli_menus.py)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from rich.console import Console

from scm_harbourmaster_mcp import cli_menus


@pytest.fixture
def backup_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    d = tmp_path / "backups"
    d.mkdir()
    for i, (name, label, folder) in enumerate(
        [
            ("scm_backup_111_20260101T000000Z.json", "Acme Corp", "Shared"),
            ("scm_backup_222_20260202T000000Z.json", "Contoso Ltd", "ngfw-shared"),
        ]
    ):
        path = d / name
        path.write_text(
            json.dumps(
                {
                    "backup_version": "1",
                    "tenant_id": name.split("_")[2],
                    "label": label,
                    "folder": folder,
                    "resources": {"tags": []},
                }
            )
        )
        # Second file is the newest, so it must sort first in the picker.
        os.utime(path, (1000 + i * 100, 1000 + i * 100))
    monkeypatch.setenv("SCM_MCP_BACKUP_DIR", str(d))
    return d


def _answer(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setattr(
        cli_menus, "Prompt", type("P", (), {"ask": staticmethod(lambda *a, **k: value)})
    )


@pytest.fixture
def console() -> Console:
    return Console(quiet=True)


def test_picks_newest_by_number(backup_dir, console, monkeypatch):
    _answer(monkeypatch, "1")
    assert cli_menus._pick_backup_file(console, lambda: None) == (
        backup_dir / "scm_backup_222_20260202T000000Z.json"
    )


def test_accepts_bare_filename_without_suffix(backup_dir, console, monkeypatch):
    _answer(monkeypatch, "scm_backup_111_20260101T000000Z")
    assert cli_menus._pick_backup_file(console, lambda: None) == (
        backup_dir / "scm_backup_111_20260101T000000Z.json"
    )


def test_accepts_full_path(backup_dir, console, monkeypatch):
    target = backup_dir / "scm_backup_111_20260101T000000Z.json"
    _answer(monkeypatch, str(target))
    assert cli_menus._pick_backup_file(console, lambda: None) == target


def test_unknown_name_returns_none(backup_dir, console, monkeypatch):
    _answer(monkeypatch, "showcase-1")
    assert cli_menus._pick_backup_file(console, lambda: None) is None


def test_out_of_range_number_returns_none(backup_dir, console, monkeypatch):
    _answer(monkeypatch, "99")
    assert cli_menus._pick_backup_file(console, lambda: None) is None


def test_empty_dir_falls_back_to_typed_path(tmp_path, console, monkeypatch):
    monkeypatch.setenv("SCM_MCP_BACKUP_DIR", str(tmp_path / "empty"))
    external = tmp_path / "golden.json"
    external.write_text("{}")
    _answer(monkeypatch, str(external))
    assert cli_menus._pick_backup_file(console, lambda: None) == external


def test_backup_meta_reads_label_and_folder(backup_dir):
    label, folder = cli_menus._backup_meta(backup_dir / "scm_backup_222_20260202T000000Z.json")
    assert (label, folder) == ("Contoso Ltd", "ngfw-shared")


def test_backup_meta_falls_back_to_tenant_id(tmp_path):
    path = tmp_path / "scm_backup_333_20260303T000000Z.json"
    path.write_text(json.dumps({"tenant_id": "333", "folder": "All", "resources": {}}))
    assert cli_menus._backup_meta(path) == ("333", "All")
