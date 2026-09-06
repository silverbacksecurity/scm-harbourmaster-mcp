"""MCP tool for Prisma Access Insights — general-purpose query interface.

A single tool (``scm_insights_query``) that unlocks all 103 Insights query
paths (v1.0 / v2.0 / v3.0 + custom queries + exports) behind one ergonomic
interface.  Replaces the 5 hardcoded queries in ``ops.py`` with a
general-purpose dispatch.

API base: ``https://api.sase.paloaltonetworks.com/insights/v3.0/resource/query``
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from ..utils.errors import handle_scm_exception
from ..utils.formatting import format_result as _fmt
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool
from ..utils.validation import validate_body as _validate_body

logger = get_logger(__name__)

_INSIGHTS_BASE_V3 = "https://api.sase.paloaltonetworks.com/insights/v3.0/resource"
_INSIGHTS_BASE_V2 = "https://api.sase.paloaltonetworks.com/api/sase/v2.0/resource"
_INSIGHTS_BASE_V1 = "https://api.sase.paloaltonetworks.com/api/sase/v1.0/resource"

_REGION_MAP = {"eu": "europe", "uk": "uk", "us": "americas", "sg": "sg", "au": "au"}


DEFAULT_WINDOW_HOURS = 24


def default_time_window(hours: int = DEFAULT_WINDOW_HOURS) -> dict[str, Any]:
    """The assumed Insights time window when a query gives none.

    Several v3.0 resources (the bandwidth/consumption family) inline the
    time predicate into a SQL template server-side and reject a body without
    one (HTTP 400 GCP10002 "Syntax error: Unexpected keyword AND"). Shared
    by scm_insights_query and the AS-BUILT extractor so both assume the
    same 24-hour window.
    """
    return {
        "filter": {
            "rules": [
                {
                    "property": "event_time",
                    "operator": "last_n_hours",
                    "values": [str(hours)],
                }
            ]
        }
    }


def with_time_window(body: dict[str, Any] | None, hours: int) -> dict[str, Any]:
    """Return *body* with the default event_time window when it has no filter.

    A caller-provided ``filter`` is never touched — the default only fills
    the gap the user's request left open.
    """
    merged = dict(body or {})
    if "filter" not in merged:
        merged["filter"] = default_time_window(hours)["filter"]
    return merged


def _resolve_region(tenant_id: str, region: str) -> str:
    """Resolve the X-PANW-Region header value for a tenant.

    An explicit ``region`` wins; otherwise the tenant's configured
    ``insights_region`` is mapped, falling back to ``europe``.
    """
    if region:
        return region
    try:
        from ..config.settings import load_all_tenant_configs

        cfgs = load_all_tenant_configs()
        if tenant_id:
            tc = next((c for c in cfgs.values() if c.tenant_id == tenant_id), None)
        else:
            tc = next(iter(cfgs.values()), None) if cfgs else None
        if tc is not None:
            return _REGION_MAP.get(tc.insights_region, "europe")
    except Exception:
        pass
    return "europe"


def _refresh_token(client: Any) -> None:
    """Refresh the OAuth token before direct-session calls.

    is_expired/token_expires_soon can miss stale tokens (see
    scm_mobile_user_stats) — always attempt an unconditional refresh so a
    long-lived server session never hits TokenExpiredError mid-request.
    """
    oauth = getattr(client, "oauth_client", None)
    if oauth is None:
        return
    try:
        oauth.refresh_token()
    except Exception:
        try:
            if oauth.is_expired or oauth.token_expires_soon:
                oauth.refresh_token()
        except Exception:  # noqa: S110 - best-effort; the request surfaces auth errors
            pass


def _insights_call(
    session: Any,
    path: str,
    tenant_id: str,
    body: dict | None = None,
    region: str = "europe",
    timeout: tuple[int, int] = (10, 30),
) -> tuple[int, Any]:
    """POST to Insights, returning (status_code, parsed_json_or_text)."""
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-PANW-Region": region,
    }
    if tenant_id:  # never send an empty Prisma-Tenant header
        headers["Prisma-Tenant"] = str(tenant_id)

    # Pre-request schema validation (advisory — surfaces issues without blocking)
    validation_errors = _validate_body(f"POST {path}", body or {})
    if validation_errors:
        logger.warning("insights_validation_warning", path=path, errors=validation_errors)

    resp = session.post(path, json=body or {}, headers=headers, timeout=timeout)
    try:
        return resp.status_code, resp.json()
    except Exception:
        return resp.status_code, resp.text


def register_insights_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register the Insights general-purpose query tool."""
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_insights_query(
        client: Any,
        tenant_id: str,
        resource: str,
        body: str = "",
        api_version: str = "v3",
        region: str = "",
        hours: int = DEFAULT_WINDOW_HOURS,
    ) -> str:
        """Run an arbitrary Prisma Access Insights query.

        Unlocks all 103 Insights paths (v1.0 / v2.0 / v3.0 + custom queries
        + scheduled exports) behind one general-purpose interface.

        **Common resource paths (v3.0):**
        - ``gp_mobileusers/connected_user_count`` — GP mobile user count
        - ``users/agent/connected_user_count`` — PA Agent connected users
        - ``gp_mobileusers/user_list`` — GP user list with locations
        - ``users/agent/user_list`` — PA Agent user list
        - ``pa_bandwidth_consumption`` — per-SPN bandwidth
        - ``agents/agent_versions`` — agent version distribution
        - ``tunnels/tunnel_list`` — IKE tunnel status (needs scope)

        **v2.0 / v1.0 format:**
        - ``query/{resource_name}`` — POST to named resource
        - ``custom/query/{feature}/{request}`` — custom query
        - ``download`` — export download

        **Scheduled exports (v2.0):**
        - ``export/schedule/query/{resource_name}`` — schedule an export
        - ``download/status`` — check download status

        Args:
            resource: Insights resource path (everything after /query/ or
                /resource/). E.g. ``gp_mobileusers/connected_user_count``.
            tenant_id: SCM tenant ID. Defaults to active tenant.
            body: JSON string of query filters (default ``{}``). The
                Insights API uses a simple ``{"key": "value"}`` filter
                format — see pan.dev for per-resource filter schemas.
                When the body carries no ``filter``, a default
                ``event_time last_n_hours`` window is assumed (see hours) —
                several resources (the bandwidth/consumption family) reject
                a query without a time window; if a resource instead rejects
                the time filter, the call automatically retries without it.
            api_version: API version — v1 | v2 | v3 (default v3).
            region: X-PANW-Region override (europe, americas, uk, sg, au).
                Defaults to tenant's insights_region.
            hours: Size of the assumed time window in hours (default 24).
                Ignored when the body already carries a ``filter``.

        Returns:
            JSON with ``resource``, ``data`` array, ``region``, and the
            ``time_window`` actually used.
        """
        import json

        session = getattr(client, "session", None)
        if not session:
            return "Error: no HTTP session available on SCM client."
        _refresh_token(client)

        # --- Resolve region ---
        region = _resolve_region(tenant_id, region)

        # --- Resolve base URL ---
        version = api_version.strip().lower()
        if version == "v2":
            base = _INSIGHTS_BASE_V2
        elif version == "v1":
            base = _INSIGHTS_BASE_V1
        else:
            base = _INSIGHTS_BASE_V3

        # --- Parse body ---
        body_dict: dict | None = None
        if body.strip():
            try:
                body_dict = json.loads(body)
            except json.JSONDecodeError as exc:
                return f"Error: invalid JSON in `body`: {exc}"

        # --- Build URL ---
        resource_clean = resource.strip().lstrip("/")
        if version in ("v1", "v2"):
            # v1/v2: /api/sase/v{X}.0/resource/{resource}
            path = f"{base}/{resource_clean}"
        elif resource_clean.startswith("export/") or resource_clean.startswith("download"):
            # v3 export/download paths don't take the /query/ prefix
            path = f"{base}/{resource_clean}"
        else:
            # v3: /insights/v3.0/resource/query/{resource}
            path = f"{base}/query/{resource_clean}"

        # --- Call (assume a time window when the caller gave none) ---
        caller_has_filter = body_dict is not None and "filter" in body_dict
        if caller_has_filter:
            time_window = "caller-provided filter"
            status, data = _insights_call(session, path, tenant_id, body_dict, region)
        else:
            time_window = f"last_{hours}h (assumed)"
            status, data = _insights_call(
                session, path, tenant_id, with_time_window(body_dict, hours), region
            )
            if status == 400:
                # Resource doesn't take an event_time filter — retry bare.
                logger.info("insights_window_fallback", resource=resource)
                time_window = "none (resource rejected the time filter)"
                status, data = _insights_call(session, path, tenant_id, body_dict, region)

        if status != 200:
            return _fmt(
                {
                    "resource": resource,
                    "api_version": api_version,
                    "region": region,
                    "time_window": time_window,
                    "error": f"HTTP {status}",
                    "detail": data if isinstance(data, str) else str(data)[:500],
                }
            )

        rows = data.get("data", data) if isinstance(data, dict) else data
        return _fmt(
            {
                "resource": resource,
                "api_version": api_version,
                "region": region,
                "time_window": time_window,
                "count": len(rows) if isinstance(rows, list) else 0,
                "data": rows,
            }
        )

    @mcp.tool()
    @tool
    def scm_insights_export(
        client: Any,
        tenant_id: str,
        resource: str = "",
        body: str = "",
        action: str = "schedule",
        download_id: str = "",
        api_version: str = "v2",
        region: str = "",
    ) -> str:
        """Schedule, poll, or download an Insights scheduled export.

        Handles the three-step Insights export workflow:

          1. **schedule** — POST to ``export/schedule/query/{resource}`` (v2)
             or ``export/query/{resource}`` (v3).  Returns a ``download_id``.
          2. **status** — POST to ``download/status`` with the ``download_id``
             to check whether the export is ready.
          3. **download** — POST to ``download`` with the ``download_id``
             to retrieve the exported data.

        **Example workflow (v2):**
          1. schedule → get download_id "abc-123"
          2. status with download_id="abc-123" → poll until ready
          3. download with download_id="abc-123" → get the data

        Args:
            resource:    Insights resource path to export (e.g.
                         ``users/agent/user_list``, ``gp_mobileusers/user_list``).
                         Required for ``schedule``; unused for status/download.
            tenant_id:   SCM tenant ID. Defaults to active tenant.
            body:        JSON query filter for the export (optional).
            action:      ``schedule`` (default), ``status``, or ``download``.
            download_id: The download ID returned by a previous ``schedule`` call.
            api_version: API version for schedule — ``v2`` (default) or ``v3``.
            region:      X-PANW-Region override.

        Returns:
            JSON with the schedule response (including download_id), status,
            or downloaded data.
        """
        import json as _json

        if action not in ("schedule", "status", "download"):
            return _fmt(
                {"error": f"Unknown action: {action!r}. Use 'schedule', 'status', or 'download'."}
            )

        # Status and download actions use v2 download endpoints
        if action in ("status", "download"):
            if not download_id:
                return _fmt({"error": "download_id is required for status/download actions"})

            try:
                client = get_client(tenant_id)
                session = getattr(client, "session", None)
                if not session:
                    return "Error: no HTTP session available on SCM client."
                _refresh_token(client)

                region = _resolve_region(tenant_id, region)

                if action == "status":
                    path = f"{_INSIGHTS_BASE_V2}/download/status"
                else:
                    path = f"{_INSIGHTS_BASE_V2}/download"

                status, data = _insights_call(
                    session,
                    path,
                    tenant_id,
                    {"download_id": download_id},
                    region,
                )
                return _fmt(
                    {
                        "action": action,
                        "download_id": download_id,
                        "status_code": status,
                        "data": data,
                    }
                )
            except Exception as exc:
                return f"Error: {handle_scm_exception(exc, tool='scm_insights_export', tenant_id=tenant_id)}"

        # --- Schedule action ---
        if not resource:
            return _fmt({"error": "resource is required for schedule action"})

        session = getattr(client, "session", None)
        if not session:
            return "Error: no HTTP session available on SCM client."
        _refresh_token(client)

        region = _resolve_region(tenant_id, region)

        resource_clean = resource.strip().lstrip("/")
        body_dict: dict | None = None
        if body.strip():
            try:
                body_dict = _json.loads(body)
            except _json.JSONDecodeError as exc:
                return f"Error: invalid JSON in `body`: {exc}"

        version = api_version.strip().lower()
        if version == "v3":
            path = f"{_INSIGHTS_BASE_V3}/export/query/{resource_clean}"
        else:
            path = f"{_INSIGHTS_BASE_V2}/export/schedule/query/{resource_clean}"

        status, data = _insights_call(session, path, tenant_id, body_dict, region)

        if status != 200:
            return _fmt(
                {
                    "action": "schedule",
                    "resource": resource,
                    "api_version": api_version,
                    "error": f"HTTP {status}",
                    "detail": data if isinstance(data, str) else str(data)[:500],
                }
            )

        # Extract download_id from response
        dl_id = ""
        if isinstance(data, dict):
            dl_id = str(data.get("download_id") or data.get("id") or data.get("request_id") or "")

        return _fmt(
            {
                "action": "schedule",
                "resource": resource,
                "api_version": api_version,
                "download_id": dl_id,
                "response": data,
                "next_step": (
                    f"Poll with: scm_insights_export(action='status', download_id='{dl_id}')"
                    if dl_id
                    else "Check response for download identifier"
                ),
            }
        )
