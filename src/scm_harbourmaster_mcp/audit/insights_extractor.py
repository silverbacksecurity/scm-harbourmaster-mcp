"""
Prisma Access Insights API extractor.

Queries the Insights v3.0 REST API to pull live operational data
(tunnel health, RN/SC status, bandwidth consumption, connected MU count,
active alerts) that cannot be derived from the SCM config API alone.

Endpoint pattern:
  POST https://api.sase.paloaltonetworks.com/insights/v3.0/resource/query/{category}/{resource}

Required headers:
  X-PANW-Region: <region>   (e.g. "eu", "us", "uk")
  Content-Type: application/json
  Prisma-Tenant: <tsg_id>   (optional — scopes to a specific sub-tenant)

Auth: same OAuth 2.0 bearer token held by the Scm client session.

Ref: https://pan.dev/sase/api/insights/insights-api/
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..utils.logging import get_logger

logger = get_logger(__name__)

_INSIGHTS_BASE = "https://api.sase.paloaltonetworks.com"
_NOT_AVAILABLE_STATUSES = frozenset({401, 403, 404, 424})


@dataclass
class InsightsData:
    """Live operational data fetched from the Prisma Access Insights API."""

    # Mobile Users
    connected_mu_count: int = -1  # -1 = unavailable

    # Per-location status (RN, SC, MU availability per PA compute node)
    location_rn_status: list[dict[str, Any]] = field(default_factory=list)
    location_sc_status: list[dict[str, Any]] = field(default_factory=list)
    location_mu_status: list[dict[str, Any]] = field(default_factory=list)

    # Per-location bandwidth (allocated vs consumed)
    location_rn_bandwidth: list[dict[str, Any]] = field(default_factory=list)
    location_sc_bandwidth: list[dict[str, Any]] = field(default_factory=list)

    # Tunnel inventory with health state
    tunnel_list: list[dict[str, Any]] = field(default_factory=list)

    # Active alerts
    active_alerts: list[dict[str, Any]] = field(default_factory=list)

    # Errors encountered (non-fatal)
    errors: list[str] = field(default_factory=list)


def extract_insights(
    client: Any,
    tenant_id: str = "",
    region: str = "eu",
) -> InsightsData:
    """
    Fetch live operational data from the Prisma Access Insights v3.0 API.

    Parameters
    ----------
    client:
        Authenticated Scm client (uses client.session for HTTP).
    tenant_id:
        TSG ID of the tenant. Added as ``Prisma-Tenant`` header to scope
        queries to a specific sub-tenant under an MSSP hierarchy.
    region:
        Prisma Access region for the ``X-PANW-Region`` header.
        Common values: ``"eu"``, ``"us"``, ``"uk"``, ``"sg"``, ``"au"``.

    Returns
    -------
    InsightsData
        Populated dataclass; errors list is non-empty if any call failed.
    """
    data = InsightsData()

    session = getattr(client, "session", None)
    if session is None:
        data.errors.append("insights: Scm client has no .session")
        return data

    # Force token refresh before direct session calls — is_expired() can miss
    # stale tokens, so we attempt an unconditional refresh to avoid TokenExpiredError.
    oauth = getattr(client, "oauth_client", None)
    if oauth is not None:
        try:
            oauth.refresh_token()
            logger.info("insights_token_refreshed")
        except Exception:
            # Unconditional refresh may not be supported; fall back to conditional
            try:
                if oauth.is_expired or oauth.token_expires_soon:
                    oauth.refresh_token()
                    logger.info("insights_token_refreshed_conditional")
            except Exception as exc2:
                logger.warning("insights_token_refresh_failed", error=str(exc2))

    def _post(path: str, body: dict | None = None) -> tuple[int, Any]:
        """POST to Insights API; return (status_code, parsed_body_or_text)."""
        url = f"{_INSIGHTS_BASE}{path}"
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-PANW-Region": region,
        }
        if tenant_id:
            headers["Prisma-Tenant"] = tenant_id

        try:
            resp = session.post(url, json=body or {}, headers=headers, timeout=(5, 20))
            if resp.status_code == 200:
                try:
                    return resp.status_code, resp.json()
                except Exception:
                    return resp.status_code, {}
            return resp.status_code, resp.text[:300]
        except Exception as exc:
            err = str(exc)
            # Retry once after token refresh if we hit a TokenExpiredError
            if "token" in err.lower() and "expir" in err.lower() and oauth is not None:
                try:
                    oauth.refresh_token()
                    resp = session.post(url, json=body or {}, headers=headers, timeout=(5, 20))
                    if resp.status_code == 200:
                        try:
                            return resp.status_code, resp.json()
                        except Exception:
                            return resp.status_code, {}
                    return resp.status_code, resp.text[:300]
                except Exception as exc2:
                    return -1, str(exc2)
            return -1, err

    def _items(raw: Any) -> list[dict[str, Any]]:
        """Extract the list of result items from an Insights API response."""
        if isinstance(raw, list):
            return raw
        if isinstance(raw, dict):
            # Common envelopes: {"data": [...]} or {"items": [...]} or {"result": [...]}
            for key in ("data", "items", "result", "results", "resources"):
                val = raw.get(key)
                if isinstance(val, list):
                    return val
        return []

    # ── Connected MU count ────────────────────────────────────────────────────
    _mu_path = "/insights/v3.0/resource/query/users/agent/connected_user_count"
    status, body = _post(_mu_path)
    if status == 200:
        items = _items(body)
        if items:
            # Each item typically: {"count": N} or {"connected_count": N}
            first = items[0] if isinstance(items[0], dict) else {}
            count = first.get("count", first.get("connected_count", first.get("value", 0)))
            try:
                data.connected_mu_count = int(count or 0)
            except (TypeError, ValueError):
                data.connected_mu_count = 0
        elif isinstance(body, dict):
            # Some versions return {"count": N} at the top level
            count = body.get("count", body.get("connected_count", body.get("total", -1)))
            try:
                data.connected_mu_count = int(count or 0)
            except (TypeError, ValueError):
                data.connected_mu_count = 0
        logger.info("insights_mu_count", count=data.connected_mu_count)
    elif status in _NOT_AVAILABLE_STATUSES:
        logger.info("insights_mu_count_not_available", status=status)
    else:
        data.errors.append(f"insights_mu_count: HTTP {status} — {body}")
        logger.warning("insights_mu_count_error", status=status)

    # ── Location-based resource: one helper for each endpoint ─────────────────
    # The bandwidth resources reject an empty body with HTTP 400 GCP10002
    # ("Syntax error: Unexpected keyword AND" — the backend inlines the time
    # predicate into a SQL template), so they need an explicit event_time
    # window. The status resources accept an empty body, so they keep it.
    # The window is the shared Insights default (24h) so the AS-BUILT and
    # scm_insights_query always assume the same timeframe.
    from ..tools.insights import default_time_window

    _bw_query = default_time_window()
    _location_endpoints: list[tuple[str, str, str, dict | None]] = [
        # (snap_field, url_path, log_key, query_body)
        (
            "location_rn_status",
            "/insights/v3.0/resource/query/locations/location_rn_status",
            "rn_status",
            None,
        ),
        (
            "location_sc_status",
            "/insights/v3.0/resource/query/locations/location_sc_status",
            "sc_status",
            None,
        ),
        (
            "location_mu_status",
            "/insights/v3.0/resource/query/locations/location_mu_status",
            "mu_status",
            None,
        ),
        (
            "location_rn_bandwidth",
            "/insights/v3.0/resource/query/locations/location_rn_bandwidth",
            "rn_bw",
            _bw_query,
        ),
        (
            "location_sc_bandwidth",
            "/insights/v3.0/resource/query/locations/location_sc_bandwidth",
            "sc_bw",
            _bw_query,
        ),
    ]

    for attr, path, log_key, query_body in _location_endpoints:
        status, body = _post(path, query_body)
        if status == 200:
            items = _items(body)
            setattr(data, attr, items)
            logger.info(f"insights_{log_key}", count=len(items))
        elif status in _NOT_AVAILABLE_STATUSES:
            logger.info(f"insights_{log_key}_not_available", status=status)
        else:
            data.errors.append(f"insights_{log_key}: HTTP {status} — {body}")
            logger.warning(f"insights_{log_key}_error", status=status)

    # ── Tunnel list ───────────────────────────────────────────────────────────
    _tunnel_paths = [
        "/insights/v3.0/resource/query/tunnels/tunnel_list",
        "/insights/v3.0/resource/query/tunnels/tunnel_health",
    ]
    for tpath in _tunnel_paths:
        status, body = _post(tpath)
        if status == 200:
            data.tunnel_list = _items(body)
            logger.info("insights_tunnel_list", count=len(data.tunnel_list))
            break
        elif status in _NOT_AVAILABLE_STATUSES:
            logger.info("insights_tunnel_not_available", path=tpath, status=status)
            break
        else:
            logger.debug("insights_tunnel_path_failed", path=tpath, status=status)
    else:
        # Both paths failed — log only if neither was a "not available" status
        data.errors.append("insights_tunnels: both paths failed")

    # ── Active alerts ─────────────────────────────────────────────────────────
    _alert_paths = [
        "/insights/v3.0/resource/query/alerts/current_alerts_generated",
        "/insights/v3.0/resource/query/alerts/alert_list",
    ]
    for apath in _alert_paths:
        status, body = _post(apath)
        if status == 200:
            data.active_alerts = _items(body)
            logger.info("insights_alerts", count=len(data.active_alerts))
            break
        elif status in _NOT_AVAILABLE_STATUSES:
            logger.info("insights_alerts_not_available", path=apath, status=status)
            break
        else:
            logger.debug("insights_alert_path_failed", path=apath, status=status)

    logger.info(
        "insights_extraction_complete",
        mu_count=data.connected_mu_count,
        rn_status=len(data.location_rn_status),
        sc_status=len(data.location_sc_status),
        tunnels=len(data.tunnel_list),
        alerts=len(data.active_alerts),
        errors=len(data.errors),
    )
    return data
