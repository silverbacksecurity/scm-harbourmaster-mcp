"""
Autonomous Digital Experience Management (ADEM) — the `access/adem` family.

General-purpose query tool over the 13 `/adem/telemetry/v2/*` paths.
`audit/extractor.py`'s `extract_adem` already covers `agent_score` and
`application_score` for the AS-BUILT/MSR experience-score sections; this
module exposes those two plus the 11 other paths for ad-hoc use (per-agent
properties, per-application/internet/nav/route metrics, RUM, and Zoom QoS),
mirroring the `scm_insights_query` pattern of one consolidated tool over a
whole API family instead of 13 near-identical thin wrappers.

Auth: standard SASE bearer token plus a `Prisma-Tenant` header (this is an
MSP-style multitenant API — the header, not the OAuth scope alone, selects
the tenant). A 401 here almost always means the ADEM entitlement or scope
is missing, not a bad token.

Per-view parameter support differs across all 13 endpoints (confirmed
against the live OpenAPI spec, not guessed): `endpoint-type` is required by
some, absent from others; `response-type` enums vary per endpoint, and a
few endpoints (`route/hops`, `zoom/participant`) don't accept it at all;
`agent/properties` requires a non-empty `filter`. The `_VIEWS` table below
encodes exactly what each endpoint accepts so invalid combinations fail
with a helpful message instead of a raw 400.
"""

from __future__ import annotations

import json as _json
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..audit.extractor import _bearer_session_for
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool

logger = get_logger(__name__)

_BASE = "https://api.sase.paloaltonetworks.com/adem/telemetry/v2"
_MAX_CHARS = 15000

# path, valid endpoint-type values (None = param not accepted by this
# endpoint), valid response-type values (None = param not accepted),
# whether `filter` is required for a meaningful call.
_VIEWS: dict[str, dict[str, Any]] = {
    "agent_properties": {
        "path": "/agent/properties",
        "endpoint_types": ("muAgent", "rnAgent"),
        "response_types": ("timeseries", "summary"),
        "filter_required": True,
    },
    "agent_metric": {
        "path": "/measure/agent/metric",
        "endpoint_types": ("muAgent", "rnAgent"),
        "response_types": ("timeseries", "grouped-summary"),
    },
    "agent_score": {
        "path": "/measure/agent/score",
        "endpoint_types": ("muAgent", "rnAgent"),
        "response_types": (
            "timeseries",
            "summary",
            "distribution",
            "grouped-summary",
            "grouped-timeseries",
        ),
    },
    "application_metric": {
        "path": "/measure/application/metric",
        "endpoint_types": ("muAgent", "muProbe", "rnAgent", "rnProbe"),
        "response_types": ("timeseries", "summary", "grouped-summary", "grouped-timeseries"),
    },
    "application_score": {
        "path": "/measure/application/score",
        "endpoint_types": ("muAgent", "muProbe", "rnAgent", "rnProbe"),
        "response_types": (
            "timeseries",
            "summary",
            "distribution",
            "grouped-summary",
            "grouped-timeseries",
            "grouped-distribution",
        ),
    },
    "internet_metric": {
        "path": "/measure/internet/metric",
        "endpoint_types": ("muAgent", "muProbe", "rnAgent", "rnProbe"),
        "response_types": ("timeseries", "summary", "grouped-timeseries", "grouped-summary"),
    },
    "nav_traffic": {
        "path": "/measure/nav/traffic",
        "endpoint_types": None,
        "response_types": ("timeseries", "summary", "grouped-timeseries", "grouped-summary"),
    },
    "route_hops": {
        "path": "/measure/route/hops",
        "endpoint_types": ("muAgent", "muProbe", "rnAgent", "rnProbe"),
        "response_types": None,
    },
    "rum_metric": {
        "path": "/measure/rum/metric",
        "endpoint_types": None,
        "response_types": (
            "timeseries",
            "summary",
            "distribution",
            "grouped-summary",
            "grouped-timeseries",
            "grouped-distribution",
        ),
    },
    "rum_score": {
        "path": "/measure/rum/score",
        "endpoint_types": None,
        "response_types": (
            "timeseries",
            "summary",
            "distribution",
            "grouped-summary",
            "grouped-timeseries",
            "grouped-distribution",
        ),
    },
    "zoom_participant": {
        "path": "/measure/zoom/participant",
        "endpoint_types": None,
        "response_types": None,
    },
    "zoom_participant_score": {
        "path": "/measure/zoom/participant-score",
        "endpoint_types": None,
        "response_types": (
            "timeseries",
            "summary",
            "distribution",
            "grouped-summary",
            "grouped-timeseries",
        ),
    },
    "zoom_qos": {
        "path": "/measure/zoom/qos",
        "endpoint_types": None,
        "response_types": (
            "timeseries",
            "summary",
            "distribution",
            "grouped-summary",
            "grouped-timeseries",
            "grouped-distribution",
        ),
    },
}


def _render(title: str, url: str, status: int, body: Any) -> str:
    if status == 401:
        return (
            f"# {title}\n\n⚠️ HTTP 401 — the service account may lack the ADEM OAuth "
            f"scope. Ensure ADEM is licensed for this tenant and the service account "
            f"has the `adem` scope in the Prisma Access portal."
        )
    if status in (403, 404):
        return f"# {title}\n\nHTTP {status} — ADEM is not provisioned for this tenant."
    if status >= 500:
        return f"# {title}\n\nHTTP {status} — PAN backend error from `{url}` (transient; retry)."
    if status != 200:
        return f"# {title}\n\nHTTP {status} from `{url}`:\n\n{body}"
    text = _json.dumps(body, indent=2, default=str) if not isinstance(body, str) else body
    if len(text) > _MAX_CHARS:
        text = text[:_MAX_CHARS] + "\n… (truncated)"
    return f"# {title}\n\n```json\n{text}\n```"


def register_adem_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register the ADEM general-purpose query tool."""
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_adem_query(
        client: Any,
        tenant_id: str,
        view: str,
        endpoint_type: str = "",
        response_type: str = "",
        timerange: str = "last_3_day",
        filter: str = "",
        group: str = "",
    ) -> str:
        """Query Autonomous DEM (ADEM) telemetry — 13 views over `/adem/telemetry/v2/*`.

        Views:
            agent_properties — per-agent metadata (requires `filter`, e.g.
                an agent_uuid expression).
            agent_metric, agent_score — agent-level experience metrics/score
                (also used internally by the AS-BUILT/MSR ADEM section).
            application_metric, application_score — per-application experience.
            internet_metric — internet-path quality metrics.
            nav_traffic — browser navigation traffic volume.
            route_hops — network path hop detail (`filter` must include
                agent_uuid, site_id, or probe_uuid).
            rum_metric, rum_score — Real User Monitoring (web app) metrics/score.
            zoom_participant, zoom_participant_score, zoom_qos — Zoom
                meeting quality telemetry.

        Args:
            view: One of the views listed above.
            tenant_id: SCM tenant ID (sent as the Prisma-Tenant header).
            endpoint_type: muAgent | rnAgent | muProbe | rnProbe. Only some
                views accept this — ignored (with a note) if the view
                doesn't. Defaults to the view's first valid value.
            response_type: timeseries | summary | distribution |
                grouped-summary | grouped-timeseries | grouped-distribution.
                Valid values vary per view; some views don't accept this
                param at all. Defaults to "summary" if valid for the view,
                else the view's first valid value.
            timerange: ADEM timerange expression, e.g. last_3_day,
                last_1_day, last_7_day (default last_3_day).
            filter: Raw ADEM filter expression. Required for
                agent_properties; route_hops needs one naming agent_uuid,
                site_id, or probe_uuid.
            group: Raw `group` expression for grouped response types
                (e.g. "Entity.user").

        Returns:
            Markdown with the JSON payload, or an actionable message on
            4xx/5xx.
        """
        spec = _VIEWS.get(view)
        if spec is None:
            return f"Unknown view {view!r}. Valid views: {', '.join(sorted(_VIEWS))}"

        params: dict[str, str] = {"timerange": timerange}

        valid_ep_types = spec["endpoint_types"]
        if valid_ep_types is not None:
            ep = endpoint_type or valid_ep_types[0]
            if ep not in valid_ep_types:
                return (
                    f"Invalid endpoint_type {ep!r} for view {view!r}. "
                    f"Valid values: {', '.join(valid_ep_types)}"
                )
            params["endpoint-type"] = ep
        elif endpoint_type:
            logger.debug("adem_endpoint_type_ignored", view=view)

        valid_resp_types = spec["response_types"]
        if valid_resp_types is not None:
            rt = response_type or (
                "summary" if "summary" in valid_resp_types else valid_resp_types[0]
            )
            if rt not in valid_resp_types:
                return (
                    f"Invalid response_type {rt!r} for view {view!r}. "
                    f"Valid values: {', '.join(valid_resp_types)}"
                )
            params["response-type"] = rt
        elif response_type:
            logger.debug("adem_response_type_ignored", view=view)

        if spec.get("filter_required") and not filter:
            return f"view={view!r} requires a non-empty `filter` (e.g. an agent_uuid expression)."
        if filter:
            params["filter"] = filter
        if group:
            params["group"] = group

        session = _bearer_session_for(client)
        url = f"{_BASE}{spec['path']}"
        headers = {"prisma-tenant": tenant_id} if tenant_id else {}
        try:
            resp = session.get(url, headers=headers, params=params, timeout=(5, 30))
            try:
                body = resp.json()
            except Exception:
                body = (resp.text or "")[:500]
        except Exception as exc:
            logger.warning("adem_query_error", view=view, error=str(exc))
            return f"Error: {exc}"

        logger.info("adem_query", view=view, status=resp.status_code)
        return _render(f"ADEM — {view}", url, resp.status_code, body)
