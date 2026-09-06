"""MCP tools for Advanced DNS Security domain operations.

Covers the DNS Security API, enabling MSSP operators to:

  scm_dns_security_domain  — query domain category/reputation + submit change requests

Reference: pan.dev endpoint catalog, openapi-specs/dns-security/
"""

from __future__ import annotations

import contextlib
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..utils.formatting import format_result as _fmt
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool

logger = get_logger(__name__)

# Base URL is empty in the catalog — the API shares the SASE base.
# The dns-security spec's server block has an empty URL; we derive from
# the common api.sase.paloaltonetworks.com pattern.
_DNS_SECURITY_BASE = "https://api.sase.paloaltonetworks.com"
_NOT_LICENSED_STATUSES = frozenset({401, 403, 404, 424})


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


def _rest_post(
    session: Any, url: str, json_body: dict | None = None, timeout: tuple = (5, 15)
) -> tuple[int, dict | None]:
    """POST with licence-gating.  Returns (status_code, data_or_None)."""
    try:
        resp = session.post(url, json=json_body, timeout=timeout)
    except Exception as exc:
        return -1, {"error": "transport_error", "detail": str(exc)}
    if resp.status_code in _NOT_LICENSED_STATUSES:
        return resp.status_code, None
    try:
        return resp.status_code, resp.json()
    except Exception:
        return resp.status_code, {"raw": resp.text[:500]}


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_dns_security_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register Advanced DNS Security MCP tools onto the MCP server."""
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_dns_security_lookup(
        client: Any,
        domain: str = "",
        action: str = "info",
        change_action: str = "",
        change_category: str = "",
        ticket_ref: str = "",
    ) -> str:
        """Query DNS domain info or submit a domain category change request.

        Covers the PAN Advanced DNS Security API:

          - POST /v1/domain/info          — query domain category/reputation
          - POST /v1/domain/changerequest — submit a domain category change

        **change_request** is a write operation: ``ticket_ref`` is mandatory,
        and the Planner write-approval gate applies.

        Args:
            tenant_id:       SCM tenant ID (MSSP mode). Omit for default tenant.
            domain:          Domain name to query or submit a change for (required).
            action:          ``"info"`` (default, read-only) or ``"changerequest"``.
            change_action:   For changerequest: ``"add"`` or ``"remove"``.
            change_category: For changerequest: target category (e.g. "malware").
            ticket_ref:      Mandatory ticket/provenance reference for changerequest.

        Returns:
            JSON with domain info or change request result.
        """
        if not domain:
            return _fmt({"error": "domain is required"})

        try:
            session = _bearer_session(client)
        except Exception as exc:
            return _fmt({"error": "auth_failed", "detail": str(exc)})

        # -- Domain info (read-only) -------------------------------------------
        if action == "info":
            status, data = _rest_post(
                session,
                f"{_DNS_SECURITY_BASE}/v1/domain/info",
                json_body={"domain": domain},
            )
            if data is None:
                return _fmt(
                    {
                        "domain": domain,
                        "available": False,
                        "status_code": status,
                        "hint": (
                            "DNS Security API returned 401/403/404 — the tenant may not "
                            "have Advanced DNS Security licensed, or the endpoint is "
                            "unavailable for this service account."
                        ),
                    }
                )
            return _fmt({"domain": domain, "status_code": status, "result": data})

        # -- Change request (write) --------------------------------------------
        if action == "changerequest":
            if not ticket_ref:
                return _fmt(
                    {
                        "error": "ticket_ref is mandatory for domain change requests. "
                        "Pass the change ticket / provenance reference."
                    }
                )
            if not change_action:
                return _fmt({"error": "change_action is required (add or remove)"})
            if change_action not in ("add", "remove"):
                return _fmt(
                    {"error": f"Invalid change_action: {change_action!r}. Use 'add' or 'remove'."}
                )

            body: dict[str, Any] = {
                "domain": domain,
                "action": change_action,
                "ticket_ref": ticket_ref,
            }
            if change_category:
                body["category"] = change_category

            status, data = _rest_post(
                session,
                f"{_DNS_SECURITY_BASE}/v1/domain/changerequest",
                json_body=body,
            )
            if data is None:
                return _fmt(
                    {
                        "domain": domain,
                        "action": change_action,
                        "submitted": False,
                        "status_code": status,
                        "hint": (
                            "DNS Security change request endpoint returned 401/403/404 — "
                            "the tenant may not have Advanced DNS Security licensed."
                        ),
                    }
                )
            return _fmt(
                {
                    "domain": domain,
                    "action": change_action,
                    "ticket_ref": ticket_ref,
                    "category": change_category or "unspecified",
                    "status_code": status,
                    "result": data,
                }
            )

        return _fmt({"error": f"Unknown action: {action!r}. Use 'info' or 'changerequest'."})
