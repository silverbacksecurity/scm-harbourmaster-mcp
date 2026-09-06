"""MCP tools for Email DLP incident and report access.

Covers the Email DLP API (api.us-west1.email.dlp.paloaltonetworks.com),
enabling MSSP operators to:

  scm_email_dlp_incidents  — list email DLP incidents + retrieve reports

Reference: pan.dev endpoint catalog, openapi-specs/email-dlp/
"""

from __future__ import annotations

import contextlib
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..utils.formatting import format_result as _fmt
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool

logger = get_logger(__name__)

_EMAIL_DLP_BASE = "https://api.us-west1.email.dlp.paloaltonetworks.com"
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


class _EmailDlpError(Exception):
    """Raised for Email DLP API errors that are not a licensing/permission gate."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


def _rest_get(session: Any, url: str, params: dict | None = None) -> dict | list | None:
    """GET with licence-gating — returns None on unlicensed/forbidden.

    Any other failure (bad request, server error, network error) raises
    ``_EmailDlpError`` rather than propagating a raw exception, so callers can
    degrade gracefully like every other tool in this server.
    """
    try:
        resp = session.get(url, params=params, timeout=(5, 15))
    except Exception as exc:
        raise _EmailDlpError(0, str(exc)) from exc
    if resp.status_code in _NOT_LICENSED_STATUSES:
        return None
    try:
        resp.raise_for_status()
    except Exception as exc:
        raise _EmailDlpError(resp.status_code, str(exc)) from exc
    return resp.json()


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_email_dlp_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register Email DLP MCP tools onto the MCP server."""
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_email_dlp_incidents(
        client: Any, incident_id: str = "", report_id: str = "", status: str = "", limit: int = 50
    ) -> str:
        """List Email DLP incidents or retrieve a specific incident / report.

        Covers the Email DLP API (api.us-west1.email.dlp.paloaltonetworks.com):

          - GET /incident/api/v1/incidents          — list incidents
          - GET /incident/api/v1/incidents/{id}     — incident detail (when incident_id set)
          - GET /report/api/v1/reports/{reportId}   — report retrieval (when report_id set)

        The API is read-only.  Incident status updates (PATCH) are deferred
        behind the write-approval gate.

        Args:
            tenant_id:   SCM tenant ID (MSSP mode). Omit for default tenant.
            incident_id: If set, fetch a single incident by ID instead of listing.
            report_id:   If set, fetch a report by ID instead of listing incidents.
            status:      Filter incidents by status (e.g. "open", "resolved").
            limit:       Max incidents to return (default 50).

        Returns:
            JSON: incident list, single incident, or report data.
        """
        try:
            session = _bearer_session(client)
        except Exception as exc:
            return _fmt({"error": "auth_failed", "detail": str(exc)})

        # -- Report retrieval --------------------------------------------------
        if report_id:
            try:
                data = _rest_get(session, f"{_EMAIL_DLP_BASE}/report/api/v1/reports/{report_id}")
            except _EmailDlpError as exc:
                return _fmt(
                    {
                        "error": "email_dlp_api_error",
                        "status_code": exc.status_code,
                        "detail": exc.detail,
                    }
                )
            if data is None:
                return _fmt(
                    {
                        "report_id": report_id,
                        "available": False,
                        "hint": (
                            "Email DLP API returned 401/403/404 — the tenant may not "
                            "have Email DLP licensed, or the report ID is invalid."
                        ),
                    }
                )
            return _fmt({"report_id": report_id, "report": data})

        # -- Single incident ---------------------------------------------------
        if incident_id:
            try:
                data = _rest_get(
                    session, f"{_EMAIL_DLP_BASE}/incident/api/v1/incidents/{incident_id}"
                )
            except _EmailDlpError as exc:
                return _fmt(
                    {
                        "error": "email_dlp_api_error",
                        "status_code": exc.status_code,
                        "detail": exc.detail,
                    }
                )
            if data is None:
                return _fmt(
                    {
                        "incident_id": incident_id,
                        "available": False,
                        "hint": (
                            "Email DLP API returned 401/403/404 — the tenant may not "
                            "have Email DLP licensed, or the incident ID is invalid."
                        ),
                    }
                )
            return _fmt({"incident_id": incident_id, "incident": data})

        # -- List incidents ----------------------------------------------------
        params: dict[str, Any] = {"limit": min(limit, 200)}
        if status:
            params["status"] = status

        try:
            data = _rest_get(session, f"{_EMAIL_DLP_BASE}/incident/api/v1/incidents", params=params)
        except _EmailDlpError as exc:
            return _fmt(
                {
                    "error": "email_dlp_api_error",
                    "status_code": exc.status_code,
                    "detail": exc.detail,
                }
            )
        if data is None:
            return _fmt(
                {
                    "incidents": [],
                    "total": 0,
                    "hint": (
                        "Email DLP API returned 401/403/404 — the tenant may not "
                        "have Email DLP licensed.  This is expected on most lab tenants."
                    ),
                }
            )

        items = data if isinstance(data, list) else data.get("items", data.get("data", []))
        return _fmt(
            {
                "incidents": items,
                "total": len(items),
                "filters": {"status": status or "all", "limit": limit},
            }
        )
