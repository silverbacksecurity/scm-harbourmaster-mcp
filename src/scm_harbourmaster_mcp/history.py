"""
CLI action audit trail — append-only JSONL log of consequential operations
(backups, reports, tenant changes, server restarts) run via scm-mcp-cli,
whether from the interactive menu or a non-interactive subcommand.

Separate from the structured application logging in utils/logging.py: this is
a small, purpose-built history file meant to answer "who ran what against
which tenant when", not a general-purpose log stream.
"""

from __future__ import annotations

import functools
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar

HISTORY_PATH = Path("logs/cli_history.jsonl")

F = TypeVar("F", bound=Callable[..., Any])


def log_action(
    action: str,
    tenant_id: str | None,
    tenant_label: str | None,
    status: str,
    detail: str = "",
    source: str = "menu",
) -> None:
    """Append one entry to the CLI history log. Never raises — a logging
    failure (e.g. read-only filesystem) must not break the CLI."""
    entry = {
        "ts": datetime.now(UTC).isoformat(),
        "action": action,
        "tenant_id": tenant_id,
        "tenant_label": tenant_label,
        "status": status,
        "detail": detail,
        "source": source,
    }
    try:
        HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
        with HISTORY_PATH.open("a") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except Exception:
        pass


def read_history(limit: int = 50) -> list[dict[str, Any]]:
    """Return up to `limit` most recent history entries, newest first."""
    if not HISTORY_PATH.exists():
        return []
    try:
        lines = HISTORY_PATH.read_text().splitlines()
    except Exception:
        return []

    entries: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    entries.reverse()
    return entries


def audited(action: str) -> Callable[[F], F]:
    """Decorator that logs `action` to the CLI history on completion of the
    wrapped function. If the first positional argument looks like a
    TenantConfig (has tenant_id/label), it's recorded; otherwise the entry
    is logged with no tenant. Re-raises any exception after logging it."""

    def deco(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            tenant = args[0] if args and hasattr(args[0], "tenant_id") else None
            tenant_id = getattr(tenant, "tenant_id", None)
            tenant_label = getattr(tenant, "label", None)
            try:
                result = fn(*args, **kwargs)
            except Exception as exc:
                log_action(action, tenant_id, tenant_label, "error", detail=str(exc)[:200])
                raise
            log_action(action, tenant_id, tenant_label, "ok")
            return result

        return wrapper  # type: ignore[return-value]

    return deco
