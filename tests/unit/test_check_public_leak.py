"""Unit tests for scripts/check_public_leak.py — the public-mirror leak guard.

This script had no tests, and shipped four defects that all shared one failure
mode: it reported success without actually checking anything. For a guard whose
only job is to refuse a push, a false "clean" is the worst possible outcome, so
these tests are written around *failing closed* rather than around the happy
path:

  * under pre-commit, git's pre-push stdin is consumed by pre-commit itself, so
    reading stdin found no refs and the hook passed having scanned nothing;
  * only the pushed tip was scanned, so a tenant name added in one commit and
    removed in the next was published to the mirror unnoticed — the exact shape
    of the 2026-07-13 leak;
  * a remote URL without a ".git" suffix silently skipped the check entirely;
  * a missing settings.toml produced an empty identifier list and a pass.
"""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "check_public_leak", Path(__file__).parent.parent.parent / "scripts" / "check_public_leak.py"
)
guard = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(guard)

PUB = "https://github.com/silverbacksecurity/scm-harbourmaster-mcp.git"
PRIV = "https://github.com/silverbacksecurity/scm-harbourmaster-mcp-dev.git"


# ── remote matching ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "url",
    [
        PUB,
        "https://github.com/silverbacksecurity/scm-harbourmaster-mcp",  # no .git — gh / UI form
        "https://github.com/silverbacksecurity/scm-harbourmaster-mcp/",
        "git@github.com:silverbacksecurity/scm-harbourmaster-mcp.git",
    ],
)
def test_public_remote_recognised_in_every_url_form(url: str) -> None:
    assert guard.is_public_remote(url), f"{url} must be treated as the public mirror"


@pytest.mark.parametrize(
    "url", [PRIV, "https://github.com/silverbacksecurity/scm-harbourmaster-mcp-dev", ""]
)
def test_private_remote_is_not_public(url: str) -> None:
    assert not guard.is_public_remote(url)


# ── fail-closed behaviour ──────────────────────────────────────────────────


def test_missing_settings_file_raises_rather_than_reporting_clean(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(guard, "SETTINGS_PATH", tmp_path / "nope.toml")
    with pytest.raises(FileNotFoundError):
        guard.load_identifiers()


def test_settings_file_without_tenants_raises(monkeypatch, tmp_path) -> None:
    p = tmp_path / "settings.toml"
    p.write_text("[default]\nlog_level = 'INFO'\n")
    monkeypatch.setattr(guard, "SETTINGS_PATH", p)
    with pytest.raises(ValueError):
        guard.load_identifiers()


def test_identifiers_include_keys_and_labels_and_drop_short_ones(monkeypatch, tmp_path) -> None:
    p = tmp_path / "settings.toml"
    p.write_text("[tenants.acme-corp]\nlabel = 'Acme Corporation'\n\n[tenants.xy]\nlabel = 'Q'\n")
    monkeypatch.setattr(guard, "SETTINGS_PATH", p)
    idents = guard.load_identifiers()
    assert "acme-corp" in idents
    assert "Acme Corporation" in idents
    assert "xy" not in idents  # below MIN_IDENTIFIER_LEN — too generic to grep
    assert "Q" not in idents


@pytest.fixture
def synthetic_settings(monkeypatch, tmp_path: Path) -> Path:
    """Point the guard at a throwaway tenant registry.

    ``run_hook_mode`` loads identifiers before it ever looks at the push range,
    so even a test that never reaches the range check needs a readable
    settings.toml. The real one is git-ignored — present on a developer's box,
    never on a CI runner — so a test that leans on it passes locally and fails
    everywhere else, and would assert against whatever tenants happen to be
    registered at the time.
    """
    p = tmp_path / "settings.toml"
    p.write_text("[tenants.acme-corp]\nlabel = 'Acme Corporation'\n")
    monkeypatch.setattr(guard, "SETTINGS_PATH", p)
    return p


def test_hook_refuses_when_no_remote_url_supplied(monkeypatch, capsys) -> None:
    monkeypatch.delenv("PRE_COMMIT_REMOTE_URL", raising=False)
    monkeypatch.setattr(guard.sys, "argv", ["check_public_leak.py"])
    assert guard.run_hook_mode() == 1
    assert "refusing" in capsys.readouterr().err


def test_hook_refuses_when_push_range_is_undeterminable(
    monkeypatch, capsys, synthetic_settings
) -> None:
    """The original bug: pre-commit ate stdin, so no refs were found and the
    hook passed having scanned nothing. It must refuse instead."""
    monkeypatch.setenv("PRE_COMMIT_REMOTE_URL", PUB)
    monkeypatch.delenv("PRE_COMMIT_FROM_REF", raising=False)
    monkeypatch.delenv("PRE_COMMIT_TO_REF", raising=False)
    monkeypatch.setattr(guard, "_stdin_ranges", lambda: [])
    assert guard.run_hook_mode() == 1
    assert "refusing" in capsys.readouterr().err


def test_private_remote_skips_but_announces_it(monkeypatch, capsys) -> None:
    monkeypatch.setenv("PRE_COMMIT_REMOTE_URL", PRIV)
    assert guard.run_hook_mode() == 0
    assert "not the public mirror" in capsys.readouterr().out


# ── range scanning against a real throwaway repo ───────────────────────────


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    def git(*args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=tmp_path, capture_output=True, text=True, check=True
        ).stdout.strip()

    git("init", "-q", "-b", "main")
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "T")
    (tmp_path / "README.md").write_text("clean\n")
    git("add", "-A")
    git("commit", "-qm", "base")
    return tmp_path


def test_leak_in_a_middle_commit_is_caught_even_when_the_tip_is_clean(
    repo: Path, monkeypatch
) -> None:
    """A tenant name added then removed still lands in the mirror's history
    permanently — scanning only the tip misses it entirely."""

    def git(*args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=repo, capture_output=True, text=True, check=True
        ).stdout.strip()

    base = git("rev-parse", "HEAD")
    (repo / "ROADMAP.md").write_text("mentions acme-corp here\n")
    git("add", "-A")
    git("commit", "-qm", "adds tenant name")
    (repo / "ROADMAP.md").write_text("redacted\n")
    git("add", "-A")
    git("commit", "-qm", "removes it")
    tip = git("rev-parse", "HEAD")

    monkeypatch.setattr(guard, "REPO_ROOT", repo)
    idents = ["acme-corp"]

    assert guard.check_commit(tip, idents) == [], "tip alone is clean, by construction"

    commits = guard.commits_in_range(base, tip)
    assert len(commits) == 2
    hits = guard.check_commits(commits, idents)
    assert hits, "the leak in the middle commit must be caught"
    assert any("acme-corp" in h for h in hits)


def test_clean_range_produces_no_hits(repo: Path, monkeypatch) -> None:
    def git(*args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=repo, capture_output=True, text=True, check=True
        ).stdout.strip()

    base = git("rev-parse", "HEAD")
    (repo / "notes.md").write_text("nothing sensitive\n")
    git("add", "-A")
    git("commit", "-qm", "innocuous")
    tip = git("rev-parse", "HEAD")

    monkeypatch.setattr(guard, "REPO_ROOT", repo)
    assert guard.check_commits(guard.commits_in_range(base, tip), ["acme-corp"]) == []


def test_tenant_named_file_is_caught_by_filename_alone(repo: Path, monkeypatch) -> None:
    def git(*args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=repo, capture_output=True, text=True, check=True
        ).stdout.strip()

    (repo / "acme-corp-asbuilt.md").write_text("content with nothing sensitive inside\n")
    git("add", "-A")
    git("commit", "-qm", "adds tenant-named file")
    tip = git("rev-parse", "HEAD")

    monkeypatch.setattr(guard, "REPO_ROOT", repo)
    hits = guard.check_commit(tip, ["acme-corp"])
    assert any("filename contains" in h for h in hits)
