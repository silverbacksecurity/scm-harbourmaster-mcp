"""Append-only JSONL audit log of every gateway call (``logs/gateway_audit.jsonl``).

Arguments are recorded as a SHA-256 of their canonical JSON, never in
clear: they can hold object names and other customer data.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..utils.logging import get_logger
from ..utils.paths import logs_dir

logger = get_logger(__name__)
_lock = threading.Lock()


def audit_path() -> Path:
    return logs_dir() / "gateway_audit.jsonl"


def args_digest(arguments: Any) -> str:
    canonical = json.dumps(arguments, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def record(**fields: Any) -> bool:
    """Write one audit line. Returns False (and logs) when it can't be written.

    The gateway checks the result before running a write tool, so a write
    never runs unaudited.
    """
    entry = {"ts": datetime.now(UTC).isoformat(timespec="seconds"), **fields}
    try:
        path = audit_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(entry, default=str, separators=(",", ":"))
        with _lock, path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError as exc:
        logger.error("gateway_audit_write_failed", error=str(exc), **fields)
        return False
    return True
