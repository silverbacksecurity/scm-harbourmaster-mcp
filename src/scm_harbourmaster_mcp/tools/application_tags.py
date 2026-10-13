"""MCP tool for SCM application tags (``config/objects/v1/application-tags``).

An application tag entry attaches tags to one application (predefined or
custom) in a folder, snippet or device.  The R3 objects spec covers list,
get, create, update and delete per entry, plus bulk create
(``POST /application-tags/bulk``) and bulk update (``PUT /application-tags``)
of up to 50 applications in one scope.  No ``pan-scm-sdk`` resource wraps
it, so calls go through the SDK client's raw ``get``/``post``/``put``/
``delete``.

Application tags are also saved by ``scm_config_backup``
(``application_tags`` key).

**Write safety (SSR pattern):** ``dry_run=True`` by default on every write
action; ``ticket_ref`` is mandatory for writes, logged and echoed, never
sent in a request body.  Commit is a separate ``scm_commit`` step.
"""

from __future__ import annotations

import json
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..utils.formatting import format_result as _fmt
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool
from ..utils.write_safety import (
    DRY_RUN_HINT,
    audit_write,
    normalize_ticket_ref,
    ticket_ref_error,
)

logger = get_logger(__name__)

_BASE = "/config/objects/v1/application-tags"
_PAGE = 200
_BULK_MAX = 50
_READ_ACTIONS = ("list", "get")
_WRITE_ACTIONS = ("create", "update", "delete", "bulk_create", "bulk_update")
_ACTIONS = _READ_ACTIONS + _WRITE_ACTIONS


def _scope(folder: str, snippet: str, device: str) -> tuple[dict[str, str], str]:
    """The one container (folder/snippet/device) given, or an error message."""
    given = {
        k: v.strip() for k, v in (("folder", folder), ("snippet", snippet), ("device", device))
    }
    given = {k: v for k, v in given.items() if v}
    if len(given) > 1:
        return {}, "pass only one of folder, snippet or device"
    return given, ""


def _list(client: Any, params: dict[str, str]) -> list[dict[str, Any]]:
    """Every application-tag entry for *params*, paging by offset/total."""
    rows: list[dict[str, Any]] = []
    while True:
        body = client.get(_BASE, params={**params, "limit": str(_PAGE), "offset": str(len(rows))})
        if isinstance(body, list):
            return [r for r in body if isinstance(r, dict)]
        page = body.get("data") if isinstance(body, dict) else None
        page = [r for r in page if isinstance(r, dict)] if isinstance(page, list) else []
        rows.extend(page)
        total = body.get("total") if isinstance(body, dict) else None
        if len(page) < _PAGE or (isinstance(total, int) and len(rows) >= total):
            return rows


def _get(client: Any, tag_id: str) -> dict[str, Any]:
    body = client.get(f"{_BASE}/{tag_id}")
    return body if isinstance(body, dict) else {}


def _resolve_id(client: Any, tag_id: str, name: str, scope: dict[str, str]) -> tuple[str, str]:
    """The entry id: *tag_id*, else the entry named *name* in *scope*."""
    if tag_id:
        return tag_id, ""
    if not name or not scope:
        return "", "pass tag_id, or name with one of folder, snippet or device"
    matches = [r for r in _list(client, {**scope, "name": name}) if r.get("name") == name]
    if not matches:
        return "", f"no application-tag entry named {name!r} in {next(iter(scope.values()))}"
    return str(matches[0].get("id") or ""), ""


def _parse_applications(applications_json: str) -> tuple[list[dict[str, Any]], str]:
    """Parse the bulk ``applications`` list: [{"name": ..., "tags": [...]}, ...]."""
    try:
        apps = json.loads(applications_json)
    except json.JSONDecodeError as exc:
        return [], f"applications_json is not valid JSON: {exc}"
    if not isinstance(apps, list) or not apps:
        return [], 'applications_json must be a non-empty list of {"name": ..., "tags": [...]}'
    if len(apps) > _BULK_MAX:
        return [], f"at most {_BULK_MAX} applications per bulk call (got {len(apps)})"
    if not all(isinstance(a, dict) and a.get("name") for a in apps):
        return [], "every application needs a name"
    return apps, ""


def register_application_tag_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register the application-tags MCP tool."""
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_application_tags(
        client: Any,
        tenant_id: str,
        action: str = "list",
        folder: str = "",
        snippet: str = "",
        device: str = "",
        name: str = "",
        tag_id: str = "",
        tags: list[str] | None = None,
        applications_json: str = "",
        dry_run: bool = True,
        ticket_ref: str = "",
    ) -> str:
        """List and manage application tags (tags attached to applications).

        Each entry attaches ``tags`` to one application ``name`` in a folder,
        snippet or device.

        Actions:
          * ``list`` — entries in the given folder/snippet/device (optional
            ``name`` filter).
          * ``get`` — one entry by ``tag_id``.
          * ``create`` — tag application ``name`` with ``tags`` in the given
            folder/snippet/device.
          * ``update`` — replace an entry's ``tags`` (entry by ``tag_id``, or
            by ``name`` + folder/snippet/device).
          * ``delete`` — remove an entry (``tag_id``, or ``name`` + scope).
          * ``bulk_create`` / ``bulk_update`` — up to 50 applications in one
            folder/snippet/device from ``applications_json``, a JSON list of
            ``{"name": "<app>", "tags": ["<tag>", ...]}``.

        **Write safety (SSR pattern):** ``dry_run=True`` by default — a dry
        run reads only and returns the planned request (and, for update and
        delete, the current entry).  ``ticket_ref`` is mandatory for writes and
        is never sent to SCM.  Commit is a separate ``scm_commit`` step.

        Args:
            action: list (default), get, create, update, delete, bulk_create
                or bulk_update.
            folder: Folder scope (pass only one of folder, snippet, device).
            snippet: Snippet scope.
            device: Device scope (firewall serial).
            name: Application name (list filter; create/update/delete target).
            tag_id: Entry UUID (get/update/delete).
            tags: Tags to attach (create/update).
            applications_json: Bulk list for bulk_create/bulk_update.
            dry_run: If True (default), preview a write without applying it.
            ticket_ref: Mandatory change-ticket reference for writes.
            tenant_id: SCM tenant ID.
        """
        if action not in _ACTIONS:
            return f"Error: unknown action {action!r} — use one of: {', '.join(_ACTIONS)}"
        scope, err = _scope(folder, snippet, device)
        if err:
            return f"Error: {err}"

        if action == "list":
            params = {**scope, **({"name": name} if name else {})}
            rows = _list(client, params)
            return _fmt({"scope": scope or "tenant default", "total": len(rows), "items": rows})
        if action == "get":
            if not tag_id:
                return "Error: tag_id is required for action='get'"
            return _fmt({"tag_id": tag_id, "item": _get(client, tag_id)})

        err = ticket_ref_error(ticket_ref)
        if err:
            return f"Error: {err}"
        ticket_ref = normalize_ticket_ref(ticket_ref)

        method, path = "", ""
        body: dict[str, Any] | None = None
        current: dict[str, Any] | None = None
        if action == "create":
            if not name or not scope:
                return "Error: create needs name and one of folder, snippet or device"
            method, path = "POST", _BASE
            body = {"name": name, "location": next(iter(scope.values())), "tags": list(tags or [])}
        elif action in ("update", "delete"):
            entry_id, err = _resolve_id(client, tag_id.strip(), name, scope)
            if err:
                return f"Error: {err}"
            current = _get(client, entry_id)
            path = f"{_BASE}/{entry_id}"
            if action == "delete":
                method = "DELETE"
            else:
                if tags is None:
                    return "Error: update needs tags (the full new list)"
                method = "PUT"
                body = {"name": current.get("name") or name, "tags": list(tags)}
                location = next(iter(scope.values()), "") or current.get("folder")
                if location:
                    body["location"] = location
        else:  # bulk_create / bulk_update
            if not scope:
                return f"Error: {action} needs one of folder, snippet or device"
            apps, err = _parse_applications(applications_json)
            if err:
                return f"Error: {err}"
            method = "POST" if action == "bulk_create" else "PUT"
            path = f"{_BASE}/bulk" if action == "bulk_create" else _BASE
            body = {**scope, "applications": apps}

        if dry_run:
            planned: dict[str, Any] = {
                "action": action,
                "dry_run": True,
                "ticket_ref": ticket_ref,
                "request": {"method": method, "path": path, "body": body},
                "hint": DRY_RUN_HINT,
            }
            if current is not None:
                planned["current"] = current
            return _fmt(planned)

        audit_write("scm_application_tags", ticket_ref, tenant_id, action=action, path=path)
        if method == "POST":
            result = client.post(path, json=body)
        elif method == "PUT":
            result = client.put(path, json=body)
        else:
            result = client.delete(path)
        logger.info("application_tags_write", action=action, path=path, ticket_ref=ticket_ref)
        return _fmt({"action": action, "applied": True, "ticket_ref": ticket_ref, "result": result})
