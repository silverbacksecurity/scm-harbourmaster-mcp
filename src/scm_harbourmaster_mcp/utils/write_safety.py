"""Shared write-safety gate for MCP tools that mutate SCM (the SSR pattern).

Every tool that creates, updates, deletes, commits, loads or restores
configuration follows the same contract, first established by
``scm_ssr_execute``, ``scm_config_orch_*`` and ``scm_site_management``:

  * ``dry_run`` defaults to ``True`` — a dry run reads (never writes) and
    describes what *would* change, e.g. by fetching the target object.
  * ``ticket_ref`` is mandatory for every call of a write tool, dry run
    included, so a preview and its later execution share one change reference.
  * ``ticket_ref`` is provenance only: it is written to the structured audit
    log and echoed in the tool response, but never injected into an API
    request body.

Tools keep their own response shapes (JSON or Markdown); these helpers only
centralise the validation message, the dry-run hint and the audit log event.
"""

from __future__ import annotations

from typing import Any

from .logging import get_logger

logger = get_logger(__name__)

TICKET_REF_REQUIRED = (
    "ticket_ref is mandatory for write operations — pass a change/ticket reference "
    "(e.g. CHG-12345). Calls run as a dry run (dry_run=True) unless dry_run=False is set."
)

DRY_RUN_HINT = "Dry run only — no changes were made. Re-run with dry_run=False and the same ticket_ref to apply."


def normalize_ticket_ref(ticket_ref: Any) -> str:
    """Return *ticket_ref* as a stripped string ("" when absent)."""
    return str(ticket_ref or "").strip()


def ticket_ref_error(ticket_ref: Any) -> str:
    """Return an error message when *ticket_ref* is blank, else ``""``."""
    return "" if normalize_ticket_ref(ticket_ref) else TICKET_REF_REQUIRED


def dump_model(obj: Any) -> Any:
    """Return a JSON-friendly view of an SDK model (or *obj* unchanged)."""
    return obj.model_dump() if hasattr(obj, "model_dump") else obj


def audit_write(tool: str, ticket_ref: str, tenant_id: str = "", **details: Any) -> None:
    """Record an applied (non-dry-run) write in the structured audit log.

    Call this immediately before the mutating API call so the change reference
    is on record even if the call itself fails.
    """
    logger.info(
        "write_applied",
        tool=tool,
        ticket_ref=ticket_ref,
        tenant_id=tenant_id or "default",
        **details,
    )
