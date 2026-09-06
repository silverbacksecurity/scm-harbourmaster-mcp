"""
Cross-tenant aggregate monitoring — the `sase/mt-monitor` family.

MSP-level analytics aggregated across a parent tenant and its children
(`agg_by=tenant`): application usage/risk, threats, GlobalProtect users by
location, SD-WAN/Prisma Access service connectivity, and incident counts.
Only the alerts sub-resource was previously wired (compliance snapshots);
this module surfaces the analytics surface as a tool.

Quirks learned live:
- Data lives in a CDL region selected by the `X-PANW-Region` header
  (de/americas/europe/uk/sg/ca/jp/au/in, default americas). A tenant whose
  `insights_region` says `eu` may still store data in `uk` (true for the
  lab tenants), so when no region is given we try the mapped region and its
  eu/uk sibling and keep the first non-empty answer.
- Requests use the aggregation query language from the spec examples:
  `{"filter": {"rules": [...]}, "properties": [...]}`; wrong/missing
  properties → HTTP 400.
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from ..audit.extractor import _bearer_session_for
from ..utils.formatting import format_result as _fmt
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool

logger = get_logger(__name__)

_BASE = "https://api.sase.paloaltonetworks.com/mt/monitor/v1/agg"
_REGION_MAP = {"eu": "europe", "uk": "uk", "us": "americas", "sg": "sg", "au": "au"}
_CDL_REGIONS = ("de", "americas", "europe", "uk", "sg", "ca", "jp", "au", "in")


def _days_filter(days: int, prop: str = "event_time") -> dict[str, Any]:
    return {"operator": "last_n_days", "property": prop, "values": [days]}


def _view_queries(view: str, days: int) -> list[tuple[str, str, dict[str, Any]]]:
    """(result_key, path, body) triples per view — bodies follow the spec examples."""
    if view == "apps":
        return [
            (
                "summary",
                "applications/summary",
                {
                    "filter": {"operator": "AND", "rules": [_days_filter(days)]},
                    "properties": [
                        {"property": "total_app_count"},
                        {"property": "risk_of_app_count"},
                        {"property": "blocked_app_count"},
                    ],
                },
            ),
        ]
    if view == "threats":
        return [
            (
                "summary",
                "threats/summary",
                {
                    "filter": {
                        "operator": "AND",
                        "rules": [
                            {
                                "operator": "in",
                                "property": "severity",
                                "values": ["Critical", "High", "Medium"],
                            },
                            _days_filter(days),
                        ],
                    },
                    "properties": [
                        {"property": "total_threats"},
                        {"property": "blocked_count"},
                    ],
                },
            )
        ]
    if view == "connectivity":
        return [
            (
                "sites_by_state",
                "serviceConnectivity",
                {
                    "filter": {
                        "rules": [
                            {"operator": "in", "property": "node_type", "values": [51, 48]},
                            {
                                "operator": "in",
                                "property": "site_state_name",
                                "values": ["Up", "Down"],
                            },
                        ]
                    },
                    "properties": [
                        {"property": "node_type"},
                        {"property": "sub_tenant_id"},
                        {"alias": "count", "function": "distinct_count", "property": "site_name"},
                    ],
                },
            )
        ]
    if view == "incidents":
        return [
            (
                "counts",
                "incidents/count",
                {
                    "filter": {
                        "rules": [
                            _days_filter(days, prop="raised_time"),
                            {"operator": "equals", "property": "status", "values": ["Raised"]},
                            {
                                "operator": "in",
                                "property": "severity",
                                "values": ["Critical", "Warning"],
                            },
                            {
                                "operator": "in",
                                "property": "domain",
                                "values": ["External", "external"],
                            },
                        ]
                    },
                    "properties": [
                        {"property": "total_count"},
                        {"property": "critical_count"},
                        {"property": "warning_count"},
                    ],
                },
            )
        ]
    # ── Round 2 views (2026-07-15) ──────────────────────────────────────────
    if view == "app-usage":
        return [
            (
                "app_usage",
                "applicationUsage",
                {
                    "filter": {"operator": "AND", "rules": [_days_filter(days)]},
                    "properties": [
                        {"property": "app_name"},
                        {"property": "app_category"},
                        {"property": "risk_level"},
                        {"property": "user_count"},
                    ],
                },
            ),
        ]
    if view == "url-logs":
        return [
            (
                "url_logs",
                "urlLogs",
                {
                    "filter": {"operator": "AND", "rules": [_days_filter(days)]},
                    "properties": [
                        {"property": "url"},
                        {"property": "url_category"},
                        {"property": "action"},
                        {"property": "count"},
                    ],
                },
            ),
        ]
    if view == "upgrades":
        return [
            (
                "upgrades",
                "upgrades/list",
                {
                    "filter": {"operator": "AND", "rules": [_days_filter(days)]},
                    "properties": [
                        {"property": "device_name"},
                        {"property": "current_version"},
                        {"property": "target_version"},
                        {"property": "status"},
                    ],
                },
            ),
        ]
    # GET-based views — no POST query body needed
    if view == "locations":
        return [("locations", "location/list", {})]
    if view == "licenses":
        return [
            ("quota", "custom/license/quota", {}),
            ("utilization", "custom/license/utilization", {}),
        ]
    # ── Round 3 views (2026-07-17) ──────────────────────────────────────────
    if view == "alerts":
        return [
            (
                "alerts",
                "alerts",
                {
                    "filter": {"operator": "AND", "rules": [_days_filter(days)]},
                    "properties": [
                        {"property": "alert_id"},
                        {"property": "alert_type"},
                        {"property": "severity"},
                        {"property": "status"},
                        {"property": "tenant_name"},
                        {"property": "raised_time"},
                    ],
                },
            ),
        ]
    if view == "threat-list":
        return [
            (
                "threats",
                "threats/list",
                {
                    "filter": {
                        "operator": "AND",
                        "rules": [
                            {
                                "operator": "in",
                                "property": "severity",
                                "values": ["Critical", "High", "Medium"],
                            },
                            _days_filter(days),
                        ],
                    },
                    "properties": [
                        {"property": "threat_name"},
                        {"property": "severity"},
                        {"property": "category"},
                        {"property": "count"},
                        {"property": "tenant_name"},
                    ],
                },
            ),
        ]
    if view == "threat-source":
        return [
            (
                "sources",
                "threats/source",
                {
                    "filter": {"operator": "AND", "rules": [_days_filter(days)]},
                    "properties": [
                        {"property": "source_ip"},
                        {"property": "source_country"},
                        {"property": "threat_count"},
                    ],
                },
            ),
        ]
    if view == "app-source":
        return [
            (
                "sources",
                "applications/source",
                {
                    "filter": {"operator": "AND", "rules": [_days_filter(days)]},
                    "properties": [
                        {"property": "source_ip"},
                        {"property": "app_name"},
                        {"property": "count"},
                    ],
                },
            ),
        ]
    if view == "incident-list":
        return [
            (
                "incidents",
                "incidents/list",
                {
                    "filter": {
                        "operator": "AND",
                        "rules": [
                            _days_filter(days, prop="raised_time"),
                        ],
                    },
                    "properties": [
                        {"property": "incident_id"},
                        {"property": "severity"},
                        {"property": "status"},
                        {"property": "domain"},
                        {"property": "tenant_name"},
                        {"property": "raised_time"},
                    ],
                },
            ),
        ]
    if view == "incident-trends":
        return [
            (
                "trends",
                "incidents/trends",
                {
                    "filter": {
                        "operator": "AND",
                        "rules": [
                            _days_filter(days, prop="raised_time"),
                        ],
                    },
                    "properties": [
                        {"property": "raised_time"},
                        {"property": "severity"},
                        {"function": "count", "property": "incident_id"},
                    ],
                },
            ),
        ]
    if view == "incident-tenants":
        return [
            (
                "tenant_counts",
                "incidents/tenants",
                {
                    "filter": {
                        "operator": "AND",
                        "rules": [_days_filter(days, prop="raised_time")],
                    },
                    "properties": [
                        {"property": "tenant_name"},
                        {"function": "count", "property": "incident_id"},
                    ],
                },
            ),
        ]
    if view == "incident-impacted":
        return [
            (
                "impacted",
                "incidents/impactedList",
                {
                    "filter": {
                        "operator": "AND",
                        "rules": [_days_filter(days, prop="raised_time")],
                    },
                    "properties": [
                        {"property": "incident_id"},
                        {"property": "impacted_resource"},
                        {"property": "impact_type"},
                    ],
                },
            ),
        ]
    if view == "service-health":
        return [
            (
                "cdl_status",
                "serviceConnectivity/cdlStatus",
                {
                    "filter": {"rules": []},
                    "properties": [
                        {"property": "tenant_name"},
                        {"property": "cdl_status"},
                        {"property": "last_seen"},
                    ],
                },
            ),
            (
                "gateway_status",
                "serviceConnectivity/gatewayStatus",
                {
                    "filter": {"rules": []},
                    "properties": [
                        {"property": "tenant_name"},
                        {"property": "gateway_name"},
                        {"property": "status"},
                        {"property": "tunnel_count"},
                    ],
                },
            ),
            (
                "top_outliers",
                "serviceConnectivity/topOutliers",
                {
                    "filter": {"rules": [_days_filter(days)]},
                    "properties": [
                        {"property": "tenant_name"},
                        {"property": "site_name"},
                        {"property": "metric"},
                        {"property": "value"},
                    ],
                },
            ),
            (
                "unique_users",
                "serviceConnectivity/uniqueUsers",
                {
                    "filter": {"rules": [_days_filter(days)]},
                    "properties": [
                        {"property": "tenant_name"},
                        {"property": "user_count"},
                    ],
                },
            ),
        ]
    if view == "url-summary":
        return [
            (
                "url_summary",
                "url/summary",
                {
                    "filter": {"operator": "AND", "rules": [_days_filter(days)]},
                    "properties": [
                        {"property": "url_category"},
                        {"property": "action"},
                        {"property": "count"},
                    ],
                },
            ),
        ]
    if view == "locations-tenants":
        return [
            (
                "locations_tenants",
                "locationsTenants",
                {
                    "filter": {"operator": "AND", "rules": [_days_filter(days)]},
                    "properties": [
                        {"property": "tenant_name"},
                        {"property": "user_count"},
                        {"property": "country"},
                    ],
                },
            ),
        ]
    # GET-based views (no POST query body)
    if view == "tenant-hierarchy":
        return [("hierarchy", "custom/tenant/hierarchy", {})]
    if view == "license-setup":
        return [("setup_status", "custom/license/setup/status", {})]
    if view == "license-allocated":
        return [("allocated", "serviceConnectivity/licenseAllocated", {})]
    if view == "app-monitor":
        return [
            ("applications", "custom/appMonitor/applications", {}),
            ("node_trends", "custom/appMonitor/nodeTrend", {}),
            ("tenants", "custom/appMonitor/tenants", {}),
        ]
    return []


def register_mt_monitor_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register cross-tenant MT Monitor analytics tools."""
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_mt_analytics(
        client: Any, tenant_id: str, view: str = "apps", days: int = 7, region: str = ""
    ) -> str:
        """Cross-tenant analytics aggregated over the MSP tenant hierarchy.

        Queries the MT Monitor aggregation API with `agg_by=tenant`, so a
        parent (MSSP) tenant answers for itself and all child tenants.

        Views (round 1):
        - apps: total / risky / blocked application counts.
        - threats: total and blocked threat counts (Critical/High/Medium).
        - connectivity: site counts by node type and up/down state per
          child tenant.
        - incidents: raised incident counts by severity.

        Views (round 2 — 2026-07-15):
        - app-usage: per-app usage with category, risk level, user count.
        - url-logs: URL activity with category, action, count.
        - upgrades: device upgrade status (current → target version).
        - locations: user location list (GET — no query body).
        - licenses: custom license quota + utilization (GET — no query body).

        Views (round 3 — 2026-07-17):
        - alerts: alert feed with type, severity, status, tenant.
        - threat-list: per-threat detail with category and count.
        - threat-source: source IP/country breakdown for threats.
        - app-source: source IP breakdown per application.
        - incident-list: incident detail list with severity, status, domain.
        - incident-trends: incident count trends over time.
        - incident-tenants: incident count per tenant.
        - incident-impacted: impacted resources per incident.
        - service-health: CDL status, gateway status, top outliers, unique users.
        - url-summary: URL activity by category and action.
        - locations-tenants: user counts per tenant by country.
        - tenant-hierarchy: MSP tenant hierarchy tree (GET).
        - license-setup: license setup status (GET).
        - license-allocated: service connectivity license allocated (GET).
        - app-monitor: custom app monitor applications, node trends, tenants (GET).

        (applications/list and locationsUsers are omitted: both reject or
        500 on the spec's own example payloads — revisit on a spec update.)

        Data resides in a CDL region (X-PANW-Region). If `region` is not
        given, the tenant's insights_region is mapped (eu→europe etc.) and
        its eu/uk sibling is also tried, keeping the first non-empty
        answer — e.g. lab tenants that say `eu` may hold data in `uk`.

        Args:
            tenant_id: SCM tenant ID (MSSP parent).
            view: apps | threats | connectivity | incidents | app-usage |
                url-logs | upgrades | locations | licenses.
            days: Look-back window in days (default 7).
            region: CDL region override (de, americas, europe, uk, sg,
                ca, jp, au, in).

        Returns:
            JSON with the view's result sets and the region that answered.
        """
        try:
            queries = _view_queries(view, days)
            if not queries:
                return (
                    "Error: view must be one of apps, threats, connectivity, "
                    "incidents, app-usage, url-logs, upgrades, locations, licenses, "
                    "alerts, threat-list, threat-source, app-source, incident-list, "
                    "incident-trends, incident-tenants, incident-impacted, "
                    "service-health, url-summary, locations-tenants, tenant-hierarchy, "
                    "license-setup, license-allocated, app-monitor"
                )
            if region and region not in _CDL_REGIONS:
                return f"Error: region must be one of {', '.join(_CDL_REGIONS)}"

            session = _bearer_session_for(client)

            if region:
                candidates = [region]
            else:
                mapped = "europe"
                try:
                    from ..config.settings import load_all_tenant_configs

                    cfgs = load_all_tenant_configs()
                    tc = cfgs.get(tenant_id) or next(
                        (c for c in cfgs.values() if c.tenant_id == tenant_id), None
                    )
                    if tc is not None:
                        mapped = _REGION_MAP.get(tc.insights_region, "europe")
                except Exception:
                    pass
                sibling = {"europe": ["uk"], "uk": ["europe"]}.get(mapped, [])
                candidates = [mapped, *sibling]

            # Detect GET vs POST — empty body means GET
            _GET_VIEWS = {
                "locations",
                "licenses",
                "tenant-hierarchy",
                "license-setup",
                "license-allocated",
                "app-monitor",
            }

            result: dict[str, Any] = {"view": view, "window_days": days}
            warnings: list[str] = []
            for cand in candidates:
                data: dict[str, Any] = {}
                hits = 0
                for key, path, body in queries:
                    if view in _GET_VIEWS or not body:
                        resp = session.get(
                            f"{_BASE}/{path}",
                            params={"agg_by": "tenant"},
                            headers={"X-PANW-Region": cand},
                            timeout=(5, 30),
                        )
                    else:
                        resp = session.post(
                            f"{_BASE}/{path}",
                            params={"agg_by": "tenant"},
                            headers={"X-PANW-Region": cand},
                            json=body,
                            timeout=(5, 30),
                        )
                    if resp.status_code != 200:
                        warnings.append(f"{path} [{cand}]: HTTP {resp.status_code}")
                        data[key] = []
                        continue
                    rows = (resp.json() or {}).get("data") or []
                    data[key] = rows
                    hits += len(rows)
                if hits or cand == candidates[-1]:
                    result["region"] = cand
                    result.update(data)
                    if not hits:
                        result["note"] = (
                            f"no datapoints in regions {', '.join(candidates)} for the last "
                            f"{days} day(s) — pass region= explicitly if the tenant's CDL "
                            "region differs from its insights_region"
                        )
                    break
            if warnings:
                result["warnings"] = warnings
            return _fmt(result)
        except Exception as exc:
            return f"Error: {exc}"
