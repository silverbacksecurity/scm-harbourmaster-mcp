"""MCP tools for Configuration Orchestration (site-based Remote Networks).

Covers the ``sase/config-orch`` family — the partner-facing RNHP site
onboarding API.  This is a different API than the per-RN SCM Config API
(``/sse/config/v1/remote-networks``) exposed by existing tools like
``scm_remote_network_list``.  Config-orch is the site-onboarding workflow:
define a site, allocate bandwidth, configure IKE/IPSec crypto profiles,
and set up IKE gateways.

Reference: pan.dev endpoint catalog, openapi-specs/sase/config-orch/
"""

from __future__ import annotations

import contextlib
import json
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..utils.formatting import format_result as _fmt
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool

logger = get_logger(__name__)

_CONFIG_ORCH_BASE = "https://api.sase.paloaltonetworks.com"
_NOT_LICENSED_STATUSES = frozenset({401, 403, 404, 424})

# Allowed write actions
_ACTIONS = ("list", "get", "create", "update", "delete")
_READ_ACTIONS = ("list", "get")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bearer_session(client: Any) -> Any:
    """Return a plain ``requests.Session`` with a fresh Bearer token."""
    import requests as _requests

    oauth = getattr(client, "oauth_client", None)
    if oauth is not None:
        with contextlib.suppress(Exception):
            if getattr(oauth, "is_expired", False):
                oauth.refresh_token()

    token = None
    sdk_session = getattr(client, "session", None)
    if sdk_session is not None:
        raw = getattr(sdk_session, "token", None)
        if raw:
            token = raw.get("access_token")

    sess = _requests.Session()
    if token:
        sess.headers["Authorization"] = f"Bearer {token}"
    return sess


def _rest_call(
    session: Any,
    method: str,
    url: str,
    json_body: dict | None = None,
    timeout: tuple = (10, 30),
) -> tuple[int, dict | list | None, str]:
    """Make a REST call with licence gating.

    Returns (status_code, data_or_None, error_message).
    """
    try:
        if method == "GET":
            resp = session.get(url, timeout=timeout)
        elif method == "POST":
            resp = session.post(url, json=json_body, timeout=timeout)
        elif method == "PUT":
            resp = session.put(url, json=json_body, timeout=timeout)
        elif method == "DELETE":
            resp = session.delete(url, timeout=timeout)
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
    """Validate write-operation preconditions.  Returns empty string on success."""
    if action in _READ_ACTIONS:
        return ""
    if not ticket_ref:
        return "ticket_ref is mandatory for write actions (create/update/delete)"
    return ""


def _audit_write(tool: str, action: str, ticket_ref: str, tenant_id: str, resource_id: str) -> None:
    """Log an applied (non-dry-run) write for the change audit trail.

    The RNHP API doesn't accept a ticket_ref field in request bodies, so the
    ticket reference is recorded here and echoed in tool responses instead.
    """
    logger.info(
        "config_orch_write",
        tool=tool,
        action=action,
        ticket_ref=ticket_ref,
        tenant_id=tenant_id or "default",
        resource_id=resource_id,
    )


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_config_orch_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register Configuration Orchestration MCP tools."""
    tool = scm_tool(get_client)

    # ── Remote Networks ─────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_config_orch_remote_networks(
        client: Any,
        tenant_id: str,
        action: str = "list",
        resource_id: str = "",
        body_json: str = "",
        dry_run: bool = True,
        ticket_ref: str = "",
    ) -> str:
        """Manage Remote Network sites via the RNHP site-onboarding API.

        Covers ``/v1/remote-networks`` and ``/v1/remote-networks-read`` plus
        ``/v1/location-informations`` on the SASE config-orch API.

        This is the **partner-facing site provisioning API** — distinct from
        ``scm_remote_network_list`` / ``scm_remote_network_get`` which read
        per-RN config from the SCM Config API.

        **Write safety (SSR pattern):**
          - ``dry_run=True`` by default — returns planned state without applying
          - ``ticket_ref`` is mandatory for create/update/delete
          - Commit is a separate explicit ``scm_commit`` step

        Args:
            tenant_id:   SCM tenant ID (MSSP mode). Omit for default tenant.
            action:      ``list`` (default), ``get``, ``create``, ``update``, ``delete``.
            resource_id: Remote network ID (required for get/update/delete).
            body_json:   JSON payload for create/update (as a JSON string).
            dry_run:     If True (default), validate without applying changes.
            ticket_ref:  Mandatory change-ticket reference for write actions.

        Returns:
            JSON: list, detail, or operation result with before/after diff.
        """
        if action not in _ACTIONS:
            return _fmt({"error": f"Unknown action: {action!r}. Use one of: {', '.join(_ACTIONS)}"})

        # Write safety
        safety_err = _check_write_safety(action, dry_run, ticket_ref)
        if safety_err:
            return _fmt({"error": safety_err})

        try:
            session = _bearer_session(client)
        except Exception as exc:
            return _fmt({"error": "auth_failed", "detail": str(exc)})

        base = f"{_CONFIG_ORCH_BASE}/v1/remote-networks"
        read_base = f"{_CONFIG_ORCH_BASE}/v1/remote-networks-read"

        # -- Read actions -----------------------------------------------------
        if action == "list":
            # Try the -read variant first (supports filtered POST reads)
            status, data, err = _rest_call(session, "GET", read_base)
            if data is None:
                status, data, err = _rest_call(session, "GET", base)
            if data is None:
                return _fmt(
                    {
                        "remote_networks": [],
                        "total": 0,
                        "hint": f"Config-orch API returned {status} — "
                        "the tenant may not have Remote Network onboarding access.",
                    }
                )
            items = data if isinstance(data, list) else data.get("items", data.get("data", []))
            return _fmt({"remote_networks": items, "total": len(items)})

        if action == "get":
            if not resource_id:
                return _fmt({"error": "resource_id is required for action='get'"})
            status, data, err = _rest_call(session, "GET", f"{base}/{resource_id}")
            if data is None:
                return _fmt(
                    {
                        "resource_id": resource_id,
                        "found": False,
                        "status_code": status,
                        "detail": err or "not found",
                    }
                )
            return _fmt({"resource_id": resource_id, "remote_network": data})

        # -- Write actions ----------------------------------------------------
        if action == "create":
            if not body_json:
                return _fmt(
                    {
                        "error": "body_json is required for create — "
                        "provide the remote network definition as a JSON string"
                    }
                )
            try:
                body = json.loads(body_json)
            except json.JSONDecodeError as exc:
                return _fmt({"error": f"body_json is not valid JSON: {exc}"})

            if dry_run:
                return _fmt(
                    {
                        "action": "create",
                        "dry_run": True,
                        "ticket_ref": ticket_ref,
                        "planned_payload": body,
                        "hint": "Set dry_run=False to apply this change.",
                    }
                )

            _audit_write("scm_config_orch_remote_networks", "create", ticket_ref, tenant_id, "")
            status, data, err = _rest_call(session, "POST", base, json_body=body)
            if data is None:
                return _fmt(
                    {
                        "action": "create",
                        "applied": False,
                        "status_code": status,
                        "detail": err or "API returned no data",
                    }
                )
            return _fmt({"action": "create", "applied": True, "result": data})

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
                # Show current state for diff
                status, current, _ = _rest_call(session, "GET", f"{base}/{resource_id}")
                return _fmt(
                    {
                        "action": "update",
                        "resource_id": resource_id,
                        "dry_run": True,
                        "ticket_ref": ticket_ref,
                        "current": current,
                        "planned_changes": body,
                        "hint": "Set dry_run=False to apply this change.",
                    }
                )

            _audit_write(
                "scm_config_orch_remote_networks", "update", ticket_ref, tenant_id, resource_id
            )
            status, data, err = _rest_call(session, "PUT", f"{base}/{resource_id}", json_body=body)
            if data is None:
                return _fmt(
                    {
                        "action": "update",
                        "resource_id": resource_id,
                        "applied": False,
                        "status_code": status,
                        "detail": err or "API returned no data",
                    }
                )
            return _fmt(
                {"action": "update", "resource_id": resource_id, "applied": True, "result": data}
            )

        if action == "delete":
            if not resource_id:
                return _fmt({"error": "resource_id is required for delete"})

            if dry_run:
                status, current, _ = _rest_call(session, "GET", f"{base}/{resource_id}")
                return _fmt(
                    {
                        "action": "delete",
                        "resource_id": resource_id,
                        "dry_run": True,
                        "ticket_ref": ticket_ref,
                        "current_state": current,
                        "hint": "Set dry_run=False to apply this deletion.",
                    }
                )

            _audit_write(
                "scm_config_orch_remote_networks", "delete", ticket_ref, tenant_id, resource_id
            )
            status, data, err = _rest_call(session, "DELETE", f"{base}/{resource_id}")
            if status == 204:
                return _fmt({"action": "delete", "resource_id": resource_id, "applied": True})
            return _fmt(
                {
                    "action": "delete",
                    "resource_id": resource_id,
                    "applied": status in (200, 202, 204),
                    "status_code": status,
                    "detail": err,
                }
            )

        return _fmt({"error": f"Unhandled action: {action!r}"})

    # ── Bandwidth Allocations ────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_config_orch_bandwidth(
        client: Any,
        tenant_id: str,
        action: str = "list",
        resource_id: str = "",
        api_version: str = "v2",
        body_json: str = "",
        dry_run: bool = True,
        ticket_ref: str = "",
    ) -> str:
        """Manage bandwidth allocations via the RNHP site-onboarding API.

        Covers ``/v1/bandwidth-allocations`` and ``/v2/bandwidth-allocations``.
        v2 adds additional fields — default is v2.

        **Write safety (SSR pattern):** ``dry_run=True`` by default,
        ``ticket_ref`` mandatory for create/update/delete.

        Args:
            tenant_id:   SCM tenant ID (MSSP mode). Omit for default tenant.
            action:      ``list`` (default), ``get``, ``create``, ``update``, ``delete``.
            resource_id: Bandwidth allocation ID (required for get/update/delete).
            api_version: ``v1`` or ``v2`` (default: v2).
            body_json:   JSON payload for create/update.
            dry_run:     If True (default), validate without applying.
            ticket_ref:  Mandatory ticket reference for write actions.

        Returns:
            JSON: list, detail, or operation result.
        """
        if action not in _ACTIONS:
            return _fmt({"error": f"Unknown action: {action!r}"})
        if api_version not in ("v1", "v2"):
            return _fmt({"error": "api_version must be 'v1' or 'v2'"})

        safety_err = _check_write_safety(action, dry_run, ticket_ref)
        if safety_err:
            return _fmt({"error": safety_err})

        try:
            session = _bearer_session(client)
        except Exception as exc:
            return _fmt({"error": "auth_failed", "detail": str(exc)})

        base = f"{_CONFIG_ORCH_BASE}/{api_version}/bandwidth-allocations"
        read_base = f"{_CONFIG_ORCH_BASE}/{api_version}/bandwidth-allocations-read"

        if action in ("create", "update") and not body_json:
            return _fmt({"error": "body_json is required for create/update"})

        # -- Read actions -----------------------------------------------------
        if action == "list":
            status, data, err = _rest_call(
                session, "GET", read_base if api_version == "v1" else base
            )
            if data is None:
                return _fmt(
                    {
                        "bandwidth_allocations": [],
                        "total": 0,
                        "api_version": api_version,
                        "status_code": status,
                        "hint": "Config-orch API may not be accessible for this tenant.",
                    }
                )
            items = data if isinstance(data, list) else data.get("items", data.get("data", []))
            return _fmt(
                {"bandwidth_allocations": items, "total": len(items), "api_version": api_version}
            )

        if action == "get":
            if not resource_id:
                return _fmt({"error": "resource_id is required for action='get'"})
            status, data, err = _rest_call(session, "GET", f"{base}/{resource_id}")
            if data is None:
                return _fmt(
                    {"resource_id": resource_id, "found": False, "api_version": api_version}
                )
            return _fmt(
                {
                    "resource_id": resource_id,
                    "bandwidth_allocation": data,
                    "api_version": api_version,
                }
            )

        # -- Write actions ----------------------------------------------------
        # delete needs no payload; create/update parse theirs here (presence
        # was already checked above, before the API round-trips).
        body: dict[str, Any] = {}
        if action in ("create", "update"):
            try:
                body = json.loads(body_json)
            except json.JSONDecodeError as exc:
                return _fmt({"error": f"body_json is not valid JSON: {exc}"})

        if action == "create":
            if dry_run:
                return _fmt(
                    {
                        "action": "create",
                        "api_version": api_version,
                        "dry_run": True,
                        "ticket_ref": ticket_ref,
                        "planned_payload": body,
                        "hint": "Set dry_run=False to apply.",
                    }
                )
            _audit_write("scm_config_orch_bandwidth", "create", ticket_ref, tenant_id, "")
            status, data, err = _rest_call(session, "POST", base, json_body=body)
            if data is None:
                return _fmt(
                    {"action": "create", "applied": False, "status_code": status, "detail": err}
                )
            return _fmt({"action": "create", "applied": True, "result": data})

        if action == "update":
            if not resource_id:
                return _fmt({"error": "resource_id is required for update"})
            if dry_run:
                status, current, _ = _rest_call(session, "GET", f"{base}/{resource_id}")
                return _fmt(
                    {
                        "action": "update",
                        "resource_id": resource_id,
                        "api_version": api_version,
                        "dry_run": True,
                        "ticket_ref": ticket_ref,
                        "current": current,
                        "planned_changes": body,
                        "hint": "Set dry_run=False to apply.",
                    }
                )
            _audit_write("scm_config_orch_bandwidth", "update", ticket_ref, tenant_id, resource_id)
            status, data, err = _rest_call(session, "PUT", f"{base}/{resource_id}", json_body=body)
            if data is None:
                return _fmt(
                    {
                        "action": "update",
                        "resource_id": resource_id,
                        "applied": False,
                        "status_code": status,
                    }
                )
            return _fmt(
                {"action": "update", "resource_id": resource_id, "applied": True, "result": data}
            )

        if action == "delete":
            if not resource_id:
                return _fmt({"error": "resource_id is required for delete"})
            if dry_run:
                status, current, _ = _rest_call(session, "GET", f"{base}/{resource_id}")
                return _fmt(
                    {
                        "action": "delete",
                        "resource_id": resource_id,
                        "api_version": api_version,
                        "dry_run": True,
                        "ticket_ref": ticket_ref,
                        "current_state": current,
                        "hint": "Set dry_run=False to apply.",
                    }
                )
            _audit_write("scm_config_orch_bandwidth", "delete", ticket_ref, tenant_id, resource_id)
            status, data, err = _rest_call(session, "DELETE", f"{base}/{resource_id}")
            return _fmt(
                {
                    "action": "delete",
                    "resource_id": resource_id,
                    "applied": status in (200, 202, 204),
                    "api_version": api_version,
                }
            )

        return _fmt({"error": f"Unhandled action: {action!r}"})

    # ── Profiles (IKE / IPSec Crypto + IKE Gateways) ─────────────────────────

    @mcp.tool()
    @tool
    def scm_config_orch_profiles(
        client: Any,
        tenant_id: str,
        profile_type: str = "ike-crypto",
        action: str = "list",
        resource_id: str = "",
        body_json: str = "",
        dry_run: bool = True,
        ticket_ref: str = "",
    ) -> str:
        """Manage IKE/IPSec crypto profiles and IKE gateways via the RNHP API.

        Covers:
          - ``/v1/ike-crypto-profiles`` (CRUD)
          - ``/v1/ipsec-crypto-profiles`` (CRUD)
          - ``/v1/ike-gateways-read`` (READ only — no create/update/delete paths)

        **Write safety (SSR pattern):** write actions (create/update/delete on
        crypto profiles) require ``ticket_ref`` and default to ``dry_run=True``.
        IKE gateways are read-only.

        Args:
            tenant_id:    SCM tenant ID (MSSP mode). Omit for default tenant.
            profile_type: ``ike-crypto`` (default), ``ipsec-crypto``, or ``ike-gateway``.
            action:       ``list`` (default), ``get``. Also ``create``, ``update``,
                          ``delete`` for crypto profiles only.
            resource_id:  Profile/gateway ID (required for get/update/delete).
            body_json:    JSON payload for create/update.
            dry_run:      If True (default), validate without applying.
            ticket_ref:   Mandatory ticket reference for write actions.

        Returns:
            JSON: list, detail, or operation result.
        """
        _VALID_PROFILES = {
            "ike-crypto": "ike-crypto-profiles",
            "ipsec-crypto": "ipsec-crypto-profiles",
            "ike-gateway": "ike-gateways-read",
        }
        if profile_type not in _VALID_PROFILES:
            return _fmt(
                {
                    "error": f"Unknown profile_type: {profile_type!r}. "
                    f"Use one of: {', '.join(_VALID_PROFILES)}"
                }
            )

        if action not in _ACTIONS:
            return _fmt({"error": f"Unknown action: {action!r}"})

        resource = _VALID_PROFILES[profile_type]
        read_only = profile_type == "ike-gateway"

        # IKE gateways are read-only
        if read_only and action not in _READ_ACTIONS:
            return _fmt(
                {
                    "error": f"ike-gateway is read-only — action '{action}' is not supported. "
                    "Use 'list' or 'get'."
                }
            )

        safety_err = _check_write_safety(action, dry_run, ticket_ref)
        if safety_err:
            return _fmt({"error": safety_err})

        try:
            session = _bearer_session(client)
        except Exception as exc:
            return _fmt({"error": "auth_failed", "detail": str(exc)})

        base = f"{_CONFIG_ORCH_BASE}/v1/{resource}"

        # -- Read actions -----------------------------------------------------
        if action == "list":
            status, data, err = _rest_call(session, "GET", base)
            if data is None:
                return _fmt(
                    {
                        "profile_type": profile_type,
                        "profiles": [],
                        "total": 0,
                        "status_code": status,
                        "hint": "Config-orch API may not be accessible for this tenant.",
                    }
                )
            items = data if isinstance(data, list) else data.get("items", data.get("data", []))
            return _fmt({"profile_type": profile_type, "profiles": items, "total": len(items)})

        if action == "get":
            if not resource_id:
                return _fmt({"error": "resource_id is required for action='get'"})
            status, data, err = _rest_call(session, "GET", f"{base}/{resource_id}")
            if data is None:
                return _fmt(
                    {"profile_type": profile_type, "resource_id": resource_id, "found": False}
                )
            return _fmt({"profile_type": profile_type, "resource_id": resource_id, "profile": data})

        # -- Write actions (crypto profiles only) -----------------------------
        # delete needs no payload; create/update parse theirs here.
        body: dict[str, Any] = {}
        if action in ("create", "update"):
            if not body_json:
                return _fmt({"error": "body_json is required for create/update"})
            try:
                body = json.loads(body_json)
            except json.JSONDecodeError as exc:
                return _fmt({"error": f"body_json is not valid JSON: {exc}"})

        if action == "create":
            if dry_run:
                return _fmt(
                    {
                        "profile_type": profile_type,
                        "action": "create",
                        "dry_run": True,
                        "ticket_ref": ticket_ref,
                        "planned_payload": body,
                        "hint": "Set dry_run=False to apply.",
                    }
                )
            _audit_write("scm_config_orch_profiles", "create", ticket_ref, tenant_id, "")
            status, data, err = _rest_call(session, "POST", base, json_body=body)
            if data is None:
                return _fmt(
                    {
                        "profile_type": profile_type,
                        "action": "create",
                        "applied": False,
                        "status_code": status,
                    }
                )
            return _fmt(
                {"profile_type": profile_type, "action": "create", "applied": True, "result": data}
            )

        if action == "update":
            if not resource_id:
                return _fmt({"error": "resource_id is required for update"})
            if dry_run:
                status, current, _ = _rest_call(session, "GET", f"{base}/{resource_id}")
                return _fmt(
                    {
                        "profile_type": profile_type,
                        "action": "update",
                        "resource_id": resource_id,
                        "dry_run": True,
                        "ticket_ref": ticket_ref,
                        "current": current,
                        "planned_changes": body,
                        "hint": "Set dry_run=False to apply.",
                    }
                )
            _audit_write("scm_config_orch_profiles", "update", ticket_ref, tenant_id, resource_id)
            status, data, err = _rest_call(session, "PUT", f"{base}/{resource_id}", json_body=body)
            if data is None:
                return _fmt(
                    {
                        "profile_type": profile_type,
                        "action": "update",
                        "resource_id": resource_id,
                        "applied": False,
                    }
                )
            return _fmt(
                {
                    "profile_type": profile_type,
                    "action": "update",
                    "resource_id": resource_id,
                    "applied": True,
                    "result": data,
                }
            )

        if action == "delete":
            if not resource_id:
                return _fmt({"error": "resource_id is required for delete"})
            if dry_run:
                status, current, _ = _rest_call(session, "GET", f"{base}/{resource_id}")
                return _fmt(
                    {
                        "profile_type": profile_type,
                        "action": "delete",
                        "resource_id": resource_id,
                        "dry_run": True,
                        "ticket_ref": ticket_ref,
                        "current_state": current,
                        "hint": "Set dry_run=False to apply.",
                    }
                )
            _audit_write("scm_config_orch_profiles", "delete", ticket_ref, tenant_id, resource_id)
            status, data, err = _rest_call(session, "DELETE", f"{base}/{resource_id}")
            return _fmt(
                {
                    "profile_type": profile_type,
                    "action": "delete",
                    "resource_id": resource_id,
                    "applied": status in (200, 202, 204),
                }
            )

        return _fmt({"error": f"Unhandled action: {action!r}"})
