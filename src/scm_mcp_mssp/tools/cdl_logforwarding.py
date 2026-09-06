"""MCP tools for CDL Log Forwarding profile management.

Covers the CDL Log Forwarding API (api.sase.paloaltonetworks.com),
enabling MSSP operators to:

  scm_cdl_logforwarding  — list/manage email, HTTPS, and syslog log-forwarding profiles

Reference: pan.dev endpoint catalog, openapi-specs/cdl/logforwarding/
"""

from __future__ import annotations

import contextlib
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..utils.formatting import format_result as _fmt
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool

logger = get_logger(__name__)

_CDL_BASE = "https://api.sase.paloaltonetworks.com"
_CDL_PATH = "/logging-service/logforwarding/v1"
_NOT_LICENSED_STATUSES = frozenset({401, 403, 404, 424})

_PROFILE_TYPES = ("email", "https", "syslog")
_PROFILE_PATHS = {
    "email": "email-profiles",
    "https": "https-profiles",
    "syslog": "syslog-profiles",
}


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


def _rest_get(session: Any, url: str, params: dict | None = None) -> dict | list | None:
    """GET with licence-gating — returns None on unlicensed/forbidden."""
    try:
        resp = session.get(url, params=params, timeout=(5, 15))
    except Exception:
        return None
    if resp.status_code in _NOT_LICENSED_STATUSES:
        return None
    resp.raise_for_status()
    data = resp.json()
    return data


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_cdl_logforwarding_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register CDL Log Forwarding MCP tools onto the MCP server."""
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_cdl_logforwarding(
        client: Any, profile_type: str = "email", profile_id: str = ""
    ) -> str:
        """List CDL log-forwarding profiles (email, HTTPS, syslog).

        Covers the CDL Log Forwarding API read surface:

          - GET /logging-service/logforwarding/v1/email-profiles
          - GET /logging-service/logforwarding/v1/https-profiles
          - GET /logging-service/logforwarding/v1/syslog-profiles

        Each profile type supports list + get-by-ID.  Write operations
        (create/update/delete) are deferred behind the write-approval gate.

        Args:
            tenant_id:    SCM tenant ID (MSSP mode). Omit for default tenant.
            profile_type: ``"email"`` (default), ``"https"``, or ``"syslog"``.
            profile_id:   If set, fetch a single profile by ID instead of listing.

        Returns:
            JSON: profile list or single profile detail.
        """
        if profile_type not in _PROFILE_TYPES:
            return _fmt(
                {
                    "error": f"Unknown profile_type: {profile_type!r}. "
                    f"Use one of: {', '.join(_PROFILE_TYPES)}"
                }
            )

        try:
            session = _bearer_session(client)
        except Exception as exc:
            return _fmt({"error": "auth_failed", "detail": str(exc)})

        resource = _PROFILE_PATHS[profile_type]

        # -- Single profile ----------------------------------------------------
        if profile_id:
            url = f"{_CDL_BASE}{_CDL_PATH}/{resource}/{profile_id}"
            data = _rest_get(session, url)
            if data is None:
                return _fmt(
                    {
                        "profile_type": profile_type,
                        "profile_id": profile_id,
                        "available": False,
                        "hint": (
                            "CDL Log Forwarding API returned 401/403/404 — the tenant "
                            "may not have CDL log forwarding licensed, or the profile "
                            "ID is invalid."
                        ),
                    }
                )
            return _fmt({"profile_type": profile_type, "profile_id": profile_id, "profile": data})

        # -- List profiles -----------------------------------------------------
        url = f"{_CDL_BASE}{_CDL_PATH}/{resource}"
        data = _rest_get(session, url)
        if data is None:
            return _fmt(
                {
                    "profile_type": profile_type,
                    "profiles": [],
                    "total": 0,
                    "hint": (
                        "CDL Log Forwarding API returned 401/403/404 — the tenant may "
                        "not have CDL log forwarding licensed.  This is expected on "
                        "most lab tenants."
                    ),
                }
            )

        items = data if isinstance(data, list) else data.get("items", data.get("data", []))
        return _fmt(
            {
                "profile_type": profile_type,
                "profiles": items,
                "total": len(items),
            }
        )
