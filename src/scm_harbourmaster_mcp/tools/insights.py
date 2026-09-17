"""MCP tool for Prisma Access Insights — general-purpose query interface.

A single tool (``scm_insights_query``) that unlocks all 103 Insights query
paths (v1.0 / v2.0 / v3.0 + custom queries + exports) behind one ergonomic
interface.  Replaces the 5 hardcoded queries in ``ops.py`` with a
general-purpose dispatch.

API base: ``https://api.sase.paloaltonetworks.com/insights/v3.0/resource/query``
"""

from __future__ import annotations

import json
import re
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..config.region import insights_default, known_region, normalise_region
from ..config.region import resolve_region as _shared_resolve_region
from ..utils.errors import handle_scm_exception
from ..utils.formatting import format_result as _fmt
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool
from ..utils.validation import validate_body as _validate_body

logger = get_logger(__name__)

_INSIGHTS_BASE_V3 = "https://api.sase.paloaltonetworks.com/insights/v3.0/resource"
_INSIGHTS_BASE_V2 = "https://api.sase.paloaltonetworks.com/api/sase/v2.0/resource"
_INSIGHTS_BASE_V1 = "https://api.sase.paloaltonetworks.com/api/sase/v1.0/resource"

# settings.toml `insights_region` key -> X-PANW-Region header value. The two
# vocabularies are NOT the same: `eu` and `us` are settings keys, the header
# wants `europe` and `americas`. Sending a settings key verbatim is not
# rejected — the API answers 200 with an empty-looking result — so a mismatch
# fails silently, which is exactly how it went unnoticed in tools/ops.py.
# The mapping itself lives in config.region, shared by every header sender.
REGION_MAP = {"eu": "europe", "uk": "uk", "us": "americas", "sg": "sg", "au": "au"}


def region_header(value: str) -> str:
    """Normalise either vocabulary to an X-PANW-Region header value.

    Accepts a settings key (``eu``) or an already-valid header value
    (``europe``), in any case. Returns "" for anything unrecognised so callers
    can decide their own fallback.
    """
    return known_region(value)


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


# Insights 400s carry an error code that separates "this resource does not
# exist" from "this resource exists but rejected the body" — a distinction the
# HTTP status alone cannot make. Live-probed: DATA10003 comes back for bogus or
# removed resource paths, DATA10005 for real resources missing required query
# fields. Retrying a DATA10003 with a different body can never succeed.
_INSIGHTS_ERROR_HINTS: dict[str, str] = {
    "DATA10003": (
        "resource_not_found: Insights does not recognise this resource path — it "
        "has been removed or is misspelled. Changing the request body will not help."
    ),
    "DATA10005": (
        "invalid_body: the resource exists but rejected the request body — it "
        "needs additional query fields (for example properties, count or a filter)."
    ),
}
_INSIGHTS_ERROR_CODE_RE = re.compile(r"\b(DATA1000[35])\b")


def _insights_error_code(data: Any) -> str:
    """Return the Insights error code (DATA10003/DATA10005) in *data*, or ""."""
    text = data if isinstance(data, str) else json.dumps(data, default=str)
    match = _INSIGHTS_ERROR_CODE_RE.search(text or "")
    return match.group(1) if match else ""


def resolve_region(tenant_id: str, region: str = "") -> str:
    """Resolve the X-PANW-Region header value for a tenant.

    Delegates to :func:`config.region.resolve_region`: an explicit ``region``
    wins, then the tenant's ``region`` setting, then a region detected by
    mssp_detect_region, then the tenant's ``insights_region`` mapped to a
    header value, falling back to ``europe``. An unrecognised explicit value is
    passed through (lowercased) so a region added upstream still works before
    the known list learns about it.
    """
    if region.strip():
        return normalise_region(region)
    if not tenant_id:
        # No tenant named: the first configured tenant is the implied one.
        try:
            from ..config import settings as _settings

            first = next(iter(_settings.load_all_tenant_configs().values()), None)
            tenant_id = first.tenant_id if first is not None else ""
        except Exception:
            tenant_id = ""
    return _shared_resolve_region(tenant_id, explicit=region, default=insights_default(tenant_id))


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
        "X-PANW-Region": normalise_region(region) or "europe",
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
        region = resolve_region(tenant_id, region)

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
            if status == 400 and _insights_error_code(data) != "DATA10003":
                # Resource doesn't take an event_time filter — retry bare.
                # (DATA10003 means the resource itself is gone; skip the retry.)
                logger.info("insights_window_fallback", resource=resource)
                time_window = "none (resource rejected the time filter)"
                status, data = _insights_call(session, path, tenant_id, body_dict, region)

        if status != 200:
            error: dict[str, Any] = {
                "resource": resource,
                "api_version": api_version,
                "region": region,
                "time_window": time_window,
                "error": f"HTTP {status}",
                "detail": data if isinstance(data, str) else str(data)[:500],
            }
            code = _insights_error_code(data)
            if code:
                error["error_code"] = code
                error["hint"] = _INSIGHTS_ERROR_HINTS[code]
            return _fmt(error)

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
    def scm_insights_export(
        resource: str = "",
        tenant_id: str = "",
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

                region = resolve_region(tenant_id, region)

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

        try:
            client = get_client(tenant_id)
            session = getattr(client, "session", None)
            if not session:
                return "Error: no HTTP session available on SCM client."
            _refresh_token(client)

            region = resolve_region(tenant_id, region)

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
                dl_id = str(
                    data.get("download_id") or data.get("id") or data.get("request_id") or ""
                )

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

        except Exception as exc:
            return f"Error: {handle_scm_exception(exc, tool='scm_insights_export', tenant_id=tenant_id)}"
