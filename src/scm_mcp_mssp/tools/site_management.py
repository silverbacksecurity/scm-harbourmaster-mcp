"""MCP tools for Site Management (NGFW device onboarding).

Covers the ``config/setup/device-onboarding/v1`` API family — a new
pan.dev API family (added 2026-06-26) that automates configuration-variable
resolution for NGFW device onboarding instead of hand-provisioning each
device: **Sites** (device/HA pair + property values), **Properties**
(customer-defined site metadata), **Onboarding Rules** (ordered
variable-resolution logic), and **Site Groups** (organisational containers).

This is a raw-REST API family — there is no ``pan-scm-sdk`` binding for it,
so every call goes through a small local ``_rest_call`` helper over a plain
Bearer-token ``requests.Session`` (via the shared
``audit.extractor._bearer_session_for``), the same pattern used by
``tools/config_orch.py`` for the RNHP site-onboarding API.

Base URL: ``https://api.strata.paloaltonetworks.com/config/setup/device-onboarding/v1``

**Write safety (SSR pattern), same contract as config_orch.py:**
  - ``dry_run=True`` by default on every write action (create/update/delete/move)
  - ``ticket_ref`` is mandatory for all write actions and is recorded via a
    structured audit log line plus the tool's own JSON response — **never**
    injected into the outgoing request body.  ``config_orch.py`` hit exactly
    this bug once already (the RNHP-style API 400s on unknown body fields);
    this module is written to not repeat it.
  - Commit is a separate explicit ``scm_commit`` step (unaffected by this tool).
"""

from __future__ import annotations

import json
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..audit.extractor import _bearer_session_for
from ..utils.formatting import format_result as _fmt
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool

logger = get_logger(__name__)

_BASE = "https://api.strata.paloaltonetworks.com/config/setup/device-onboarding/v1"
_NOT_LICENSED_STATUSES = frozenset({401, 403, 404, 424})

_RESOURCE_TYPES = ("site", "property", "onboarding-rule", "site-group")
_ACTIONS = ("list", "get", "create", "update", "delete", "move")
_READ_ACTIONS = ("list", "get")
_MOVE_POSITIONS = ("before", "after", "top", "bottom")

# resource_type -> API path segment
_RESOURCE_PATHS: dict[str, str] = {
    "site": "sites",
    "property": "properties",
    "onboarding-rule": "onboarding-rules",
    "site-group": "site-groups",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rest_call(
    session: Any,
    method: str,
    url: str,
    json_body: dict | None = None,
    params: dict | None = None,
    timeout: tuple = (10, 30),
) -> tuple[int, dict | list | None, str]:
    """Make a REST call with licence gating.

    Returns (status_code, data_or_None, error_message). 401/403/404/424 are
    treated as "not licensed / no data" rather than raised.
    """
    try:
        if method == "GET":
            resp = session.get(url, params=params, timeout=timeout)
        elif method == "POST":
            resp = session.post(url, json=json_body, params=params, timeout=timeout)
        elif method == "PUT":
            resp = session.put(url, json=json_body, timeout=timeout)
        elif method == "DELETE":
            resp = session.delete(url, params=params, timeout=timeout)
        else:
            return -1, None, f"Unknown method: {method}"
    except Exception as exc:
        return -1, None, str(exc)

    if resp.status_code in _NOT_LICENSED_STATUSES:
        return resp.status_code, None, ""

    try:
        return resp.status_code, resp.json(), ""
    except Exception:
        return resp.status_code, None, resp.text[:500]


def _check_write_safety(action: str, dry_run: bool, ticket_ref: str) -> str:
    """Validate write-operation preconditions. Returns empty string on success."""
    if action in _READ_ACTIONS:
        return ""
    if not ticket_ref:
        return "ticket_ref is mandatory for write actions (create/update/delete/move)"
    return ""


def _audit_write(tool: str, action: str, ticket_ref: str, tenant_id: str, resource_id: str) -> None:
    """Log an applied (non-dry-run) write for the change audit trail.

    The device-onboarding API doesn't accept a ticket_ref field in request
    bodies, so the ticket reference is recorded here and echoed in tool
    responses instead — never put into json_body.
    """
    logger.info(
        "site_management_write",
        tool=tool,
        action=action,
        ticket_ref=ticket_ref,
        tenant_id=tenant_id or "default",
        resource_id=resource_id,
    )


def _extract_items(data: Any) -> list[Any]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        inner = data.get("data")
        if isinstance(inner, list):
            return inner
        if inner is not None:
            return [inner]
        return data.get("items", [])
    return []


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_site_management_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register the Site Management (NGFW device onboarding) MCP tool."""
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_site_management(
        client: Any,
        tenant_id: str,
        resource_type: str = "site",
        action: str = "list",
        resource_id: str = "",
        body_json: str = "",
        name: str = "",
        status: str = "",
        site_group: str = "",
        property_type: str = "",
        force: bool = False,
        position: str = "",
        reference: str = "",
        dry_run: bool = True,
        ticket_ref: str = "",
    ) -> str:
        """Manage NGFW device-onboarding Site Management resources.

        Covers the ``config/setup/device-onboarding/v1`` API: **sites**,
        **properties**, **onboarding-rules**, and **site-groups**. This is a
        distinct API from the SCM Config API — it automates variable
        resolution for NGFW device onboarding (device/HA-pair + property
        values, ordered onboarding-rule logic, and organisational site
        groups), not per-device firewall configuration.

        Valid ``resource_type`` values: ``site``, ``property``,
        ``onboarding-rule``, ``site-group``.

        Valid ``action`` values: ``list``, ``get``, ``create``, ``update``,
        ``delete`` (all resource types); ``move`` (onboarding-rule only —
        reorders rule priority).

        **Write safety (SSR pattern):**
          - ``dry_run=True`` by default — returns planned state without
            applying (for ``update``/``delete``/``move`` this fetches current
            state via GET first and returns a current/planned diff).
          - ``ticket_ref`` is mandatory for create/update/delete/move.
          - Commit is a separate explicit ``scm_commit`` step (not applicable
            to this API, which is not part of the SCM config-push model).

        Footguns to know about:
          - **Site create wraps a single site into the API's batch envelope.**
            The live API's ``POST /sites`` body is
            ``{"sites": [ {...} ]}`` (a list, even for one site, all-or-nothing).
            This tool keeps the ergonomics of "one resource per call": pass
            ``body_json`` as the single site's fields (e.g.
            ``{"name": "...", "site_group": "..."}``) and the tool wraps it
            into ``{"sites": [body]}`` before POSTing.
          - **Site delete** accepts a ``force`` flag (default False) to delete
            even if the site is claimed.
          - **Onboarding-rule move** requires ``position`` — one of
            ``before``/``after``/``top``/``bottom`` — and ``reference`` (a
            rule UUID) is **required** when ``position`` is ``before`` or
            ``after``.
          - A site must be **unclaimed** to update it (API 409s otherwise).
          - A property name cannot start with ``_sys_``.
          - A site-group's name/property-list updates 409 if referenced by
            sites/rules using it.

        Args:
            tenant_id:      SCM tenant ID (MSSP mode). Omit for default tenant.
            resource_type:  ``site`` (default), ``property``,
                             ``onboarding-rule``, or ``site-group``.
            action:         ``list`` (default), ``get``, ``create``,
                             ``update``, ``delete``; ``move`` (onboarding-rule
                             only).
            resource_id:    Resource UUID (required for get/update/delete,
                             and the rule being moved for ``move``).
            body_json:      JSON payload for create/update (a JSON string;
                             see the sites-wrapping note above).
            name:            ``list`` filter for sites (repeatable name isn't
                             supported via this single string param — pass
                             one name; omit to list all).
            status:         ``list`` filter for sites: ``all`` (default),
                             ``claimed``, or ``unclaimed``.
            site_group:     ``list`` filter for sites, by site-group name.
            property_type:  ``list`` filter for properties: ``integer`` or
                             ``string``.
            force:          For site ``delete`` — delete even if claimed
                             (default False).
            position:       For onboarding-rule ``move``: ``before``,
                             ``after``, ``top``, or ``bottom``.
            reference:      For onboarding-rule ``move``: reference rule UUID
                             — required when ``position`` is before/after.
            dry_run:        If True (default), validate/plan without applying.
            ticket_ref:     Mandatory change-ticket reference for write actions.

        Returns:
            JSON: list, detail, or operation result with before/after diff.
        """
        if resource_type not in _RESOURCE_TYPES:
            return _fmt(
                {
                    "error": f"Unknown resource_type: {resource_type!r}. "
                    f"Use one of: {', '.join(_RESOURCE_TYPES)}"
                }
            )
        if action not in _ACTIONS:
            return _fmt({"error": f"Unknown action: {action!r}. Use one of: {', '.join(_ACTIONS)}"})
        if action == "move" and resource_type != "onboarding-rule":
            return _fmt(
                {"error": "action='move' is only supported for resource_type='onboarding-rule'"}
            )

        safety_err = _check_write_safety(action, dry_run, ticket_ref)
        if safety_err:
            return _fmt({"error": safety_err})

        try:
            session = _bearer_session_for(client)
        except Exception as exc:
            return _fmt({"error": "auth_failed", "detail": str(exc)})

        path = _RESOURCE_PATHS[resource_type]
        base = f"{_BASE}/{path}"

        # -- Read actions -----------------------------------------------------
        if action == "list":
            params: dict[str, Any] = {}
            if resource_type == "site":
                if name:
                    params["name"] = name
                if status:
                    if status not in ("all", "claimed", "unclaimed"):
                        return _fmt(
                            {
                                "error": f"Unknown status: {status!r}. "
                                "Use one of: all, claimed, unclaimed"
                            }
                        )
                    params["status"] = status
                if site_group:
                    params["site-group"] = site_group
            elif resource_type == "property" and property_type:
                if property_type not in ("integer", "string"):
                    return _fmt(
                        {
                            "error": f"Unknown property_type: {property_type!r}. "
                            "Use one of: integer, string"
                        }
                    )
                params["type"] = property_type

            status_code, data, err = _rest_call(session, "GET", base, params=params or None)
            if data is None:
                return _fmt(
                    {
                        "resource_type": resource_type,
                        "items": [],
                        "total": 0,
                        "status_code": status_code,
                        "hint": f"Site Management API returned {status_code} — "
                        "the tenant may not have NGFW device-onboarding access.",
                    }
                )
            items = _extract_items(data)
            result: dict[str, Any] = {
                "resource_type": resource_type,
                "items": items,
                "total": len(items),
            }
            if isinstance(data, dict) and data.get("request_id"):
                result["request_id"] = data["request_id"]
            if resource_type == "onboarding-rule" and isinstance(data, dict):
                metadata = data.get("metadata")
                if metadata is not None:
                    result["metadata"] = metadata
            return _fmt(result)

        if action == "get":
            if not resource_id:
                return _fmt({"error": "resource_id is required for action='get'"})
            status_code, data, err = _rest_call(session, "GET", f"{base}/{resource_id}")
            if data is None:
                return _fmt(
                    {
                        "resource_type": resource_type,
                        "resource_id": resource_id,
                        "found": False,
                        "status_code": status_code,
                        "detail": err or "not found",
                    }
                )
            item = data.get("data") if isinstance(data, dict) else data
            return _fmt({"resource_type": resource_type, "resource_id": resource_id, "item": item})

        # -- Write actions ----------------------------------------------------
        if action == "create":
            if not body_json:
                return _fmt(
                    {
                        "error": "body_json is required for create — "
                        f"provide the {resource_type} definition as a JSON string"
                    }
                )
            try:
                body = json.loads(body_json)
            except json.JSONDecodeError as exc:
                return _fmt({"error": f"body_json is not valid JSON: {exc}"})

            # Sites use a batch-create envelope: {"sites": [ {...} ]}, even
            # for one site.  Wrap here so tool ergonomics stay one-resource-
            # per-call for callers.
            post_body = {"sites": [body]} if resource_type == "site" else body

            if dry_run:
                return _fmt(
                    {
                        "resource_type": resource_type,
                        "action": "create",
                        "dry_run": True,
                        "ticket_ref": ticket_ref,
                        "planned_payload": post_body,
                        "hint": "Set dry_run=False to apply this change.",
                    }
                )

            _audit_write("scm_site_management", "create", ticket_ref, tenant_id, "")
            status_code, data, err = _rest_call(session, "POST", base, json_body=post_body)
            if data is None:
                return _fmt(
                    {
                        "resource_type": resource_type,
                        "action": "create",
                        "applied": False,
                        "status_code": status_code,
                        "detail": err or "API returned no data",
                    }
                )
            return _fmt(
                {
                    "resource_type": resource_type,
                    "action": "create",
                    "applied": True,
                    "result": data.get("data") if isinstance(data, dict) else data,
                }
            )

        if action == "update":
            if not resource_id:
                return _fmt({"error": "resource_id is required for update"})
            if not body_json:
                return _fmt({"error": "body_json is required for update"})
            try:
                body = json.loads(body_json)
            except json.JSONDecodeError as exc:
                return _fmt({"error": f"body_json is not valid JSON: {exc}"})

            if dry_run:
                _, current, _ = _rest_call(session, "GET", f"{base}/{resource_id}")
                return _fmt(
                    {
                        "resource_type": resource_type,
                        "action": "update",
                        "resource_id": resource_id,
                        "dry_run": True,
                        "ticket_ref": ticket_ref,
                        "current": current.get("data") if isinstance(current, dict) else current,
                        "planned_changes": body,
                        "hint": "Set dry_run=False to apply this change.",
                    }
                )

            _audit_write("scm_site_management", "update", ticket_ref, tenant_id, resource_id)
            status_code, data, err = _rest_call(
                session, "PUT", f"{base}/{resource_id}", json_body=body
            )
            if data is None:
                return _fmt(
                    {
                        "resource_type": resource_type,
                        "action": "update",
                        "resource_id": resource_id,
                        "applied": False,
                        "status_code": status_code,
                        "detail": err or "API returned no data",
                    }
                )
            return _fmt(
                {
                    "resource_type": resource_type,
                    "action": "update",
                    "resource_id": resource_id,
                    "applied": True,
                    "result": data.get("data") if isinstance(data, dict) else data,
                }
            )

        if action == "delete":
            if not resource_id:
                return _fmt({"error": "resource_id is required for delete"})

            delete_params = {"force": "true"} if force and resource_type == "site" else None

            if dry_run:
                _, current, _ = _rest_call(session, "GET", f"{base}/{resource_id}")
                return _fmt(
                    {
                        "resource_type": resource_type,
                        "action": "delete",
                        "resource_id": resource_id,
                        "dry_run": True,
                        "ticket_ref": ticket_ref,
                        "force": force,
                        "current_state": current.get("data")
                        if isinstance(current, dict)
                        else current,
                        "hint": "Set dry_run=False to apply this deletion.",
                    }
                )

            _audit_write("scm_site_management", "delete", ticket_ref, tenant_id, resource_id)
            status_code, data, err = _rest_call(
                session, "DELETE", f"{base}/{resource_id}", params=delete_params
            )
            return _fmt(
                {
                    "resource_type": resource_type,
                    "action": "delete",
                    "resource_id": resource_id,
                    "applied": status_code in (200, 202, 204),
                    "status_code": status_code,
                    "detail": err,
                }
            )

        if action == "move":
            if not resource_id:
                return _fmt({"error": "resource_id is required for action='move'"})
            if position not in _MOVE_POSITIONS:
                return _fmt(
                    {
                        "error": f"Unknown position: {position!r}. "
                        f"Use one of: {', '.join(_MOVE_POSITIONS)}"
                    }
                )
            if position in ("before", "after") and not reference:
                return _fmt(
                    {"error": f"reference (a rule UUID) is required when position={position!r}"}
                )

            move_body: dict[str, Any] = {"position": position}
            if position in ("before", "after"):
                move_body["reference"] = reference

            if dry_run:
                _, current, _ = _rest_call(session, "GET", f"{base}/{resource_id}")
                return _fmt(
                    {
                        "resource_type": resource_type,
                        "action": "move",
                        "resource_id": resource_id,
                        "dry_run": True,
                        "ticket_ref": ticket_ref,
                        "current": current.get("data") if isinstance(current, dict) else current,
                        "planned_move": move_body,
                        "hint": "Set dry_run=False to apply this move.",
                    }
                )

            _audit_write("scm_site_management", "move", ticket_ref, tenant_id, resource_id)
            status_code, data, err = _rest_call(
                session, "POST", f"{base}/{resource_id}:move", json_body=move_body
            )
            if data is None:
                return _fmt(
                    {
                        "resource_type": resource_type,
                        "action": "move",
                        "resource_id": resource_id,
                        "applied": False,
                        "status_code": status_code,
                        "detail": err or "API returned no data",
                    }
                )
            return _fmt(
                {
                    "resource_type": resource_type,
                    "action": "move",
                    "resource_id": resource_id,
                    "applied": True,
                    "result": data,
                }
            )

        return _fmt({"error": f"Unhandled action: {action!r}"})
