"""Where the server keeps the files it writes.

Backups, drift baselines, reports, the plan and config-index stores and the
CLI history all live under one data directory: ``SCM_MCP_DATA_DIR``, default
the current working directory, which is how a source checkout has always
behaved. The container image sets it to ``/data`` (a volume), and a systemd
install can point it at ``/var/lib/scm-mcp`` so the code tree stays read-only.

The per-directory overrides (``SCM_MCP_BACKUP_DIR`` and friends) still win
over the data directory. Every helper reads the environment when called.
"""

from __future__ import annotations

import os
from pathlib import Path


def data_dir() -> Path:
    """Root for everything the server writes (``SCM_MCP_DATA_DIR``, default ``.``)."""
    return Path(os.getenv("SCM_MCP_DATA_DIR") or ".")


def _sub(env_var: str, name: str) -> Path:
    override = os.getenv(env_var)
    return Path(override) if override else data_dir() / name


def backup_dir() -> Path:
    """Config, DLP and PAB backups (``SCM_MCP_BACKUP_DIR``)."""
    return _sub("SCM_MCP_BACKUP_DIR", "backups")


def baseline_dir() -> Path:
    """Drift baselines (``SCM_MCP_BASELINE_DIR``)."""
    return _sub("SCM_MCP_BASELINE_DIR", "baselines")


def index_dir() -> Path:
    """Config-index SQLite store (``SCM_MCP_INDEX_DIR``)."""
    return _sub("SCM_MCP_INDEX_DIR", "index")


def plan_dir() -> Path:
    """Planner plan store (``SCM_MCP_PLAN_DIR``)."""
    return _sub("SCM_MCP_PLAN_DIR", "plans")


def reports_dir() -> Path:
    """Generated reports (MSR packs, AS-BUILTs, SD-WAN maps)."""
    return data_dir() / "reports"


def logs_dir() -> Path:
    """CLI history and other local logs."""
    return data_dir() / "logs"
