"""
Palo Alto Networks cloud service status — maintenance-window awareness.

Source: status.paloaltonetworks.com (Atlassian Statuspage). Public JSON
API, no auth/licence/RBAC — completely independent of tenant credentials.
The page covers every PAN cloud product (526 components), so results are
filtered to the SASE/SCM product families this server manages and matched
against each configured tenant's region (TenantConfig.insights_region).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

import requests
from mcp.server.fastmcp import FastMCP

from ..utils.formatting import format_result as _fmt
from ..utils.logging import get_logger

logger = get_logger(__name__)

_STATUS_BASE = "https://status.paloaltonetworks.com/api/v2"
_TIMEOUT = (5, 20)

# Region → keywords matched (case-insensitively unless noted) against the
# maintenance name + component names. A window with no regional keyword at
# all is treated as global and matches every region.
_REGION_KEYWORDS: dict[str, list[str]] = {
    "eu": [
        "EMEA",
        "Europe",
        "Frankfurt",
        "London",
        "Netherlands",
        "Paris",
        "Germany",
        "France",
        "Ireland",
        "Spain",
        "Italy",
        "Poland",
        "westeurope",
    ],
    "uk": ["London", "United Kingdom", "uksouth", "UK South"],
    "us": [
        "Americas",
        "NAM",
        "United States",
        "N. Virginia",
        "Oregon",
        "Ohio",
        "Canada",
        "centralus",
        "us-east",
        "us-west",
        "US East",
        "US West",
        "North America",
    ],
    "sg": [
        "Singapore",
        "APAC",
        "Asia Pacific",
        "ap-southeast",
        "Indonesia",
        "Malaysia",
        "India",
        "Japan",
        "Hong Kong",
    ],
    "au": ["Australia", "Sydney", "ANZ", "australiaeast", "New Zealand"],
}
# All regional keywords flattened — used to decide whether a window is
# region-specific at all (no hit anywhere = global window).
_ALL_REGION_KEYWORDS = sorted({kw for kws in _REGION_KEYWORDS.values() for kw in kws})

# Product families this server manages. A window must mention one of these
# (name or component) to be considered relevant unless include_all_products.
_SASE_KEYWORDS = [
    "Prisma Access",
    "Prisma SASE",
    "SD-WAN",
    "GlobalProtect",
    "Strata",
    "Cloud Manager",
    "Cloud NGFW",
    "NGFW",
    "DLP",
    "Logging",
    "SaaS",
    "ADEM",
    "Browser",
    "Cloud Identity",
    "CIE",
    "WildFire",
    "DNS Security",
    "IoT Security",
    "Advanced Threat",
]


def _text_of(m: dict[str, Any]) -> str:
    parts = [m.get("name") or ""]
    parts += [c.get("name") or "" for c in m.get("components") or []]
    return " | ".join(parts)


def _matches_any(text: str, keywords: list[str]) -> list[str]:
    hits = []
    for kw in keywords:
        # \b guards short tokens (UK, NAM, CIE…) against substring noise
        if re.search(rf"(?<![A-Za-z]){re.escape(kw)}(?![A-Za-z])", text, re.IGNORECASE):
            hits.append(kw)
    return hits


def _is_sase_relevant(text: str) -> bool:
    return bool(_matches_any(text, _SASE_KEYWORDS))


def _regions_for(text: str) -> list[str]:
    """Regions a window applies to; empty list = global (applies to all)."""
    if not _matches_any(text, _ALL_REGION_KEYWORDS):
        return []
    return [r for r, kws in _REGION_KEYWORDS.items() if _matches_any(text, kws)]


def _fetch(path: str, timeout: tuple[int, int] = _TIMEOUT) -> Any:
    resp = requests.get(f"{_STATUS_BASE}/{path}", timeout=timeout)
    resp.raise_for_status()
    return resp.json()


_INDICATOR_EMOJI = {"minor": "🟡", "major": "🟠", "critical": "🔴"}


def status_banner(days: int = 7) -> list[str]:
    """Markdown banner lines for the NOC dashboard.

    Returns [] when PAN cloud status is healthy with nothing imminent, and
    also on any fetch failure — the banner must never break or slow a
    dashboard, so it uses short timeouts and swallows errors.
    """
    lines: list[str] = []
    try:
        fast = (3, 8)
        status = _fetch("status.json", timeout=fast).get("status", {})
        indicator = status.get("indicator") or "none"
        incidents = [
            i
            for i in _fetch("incidents/unresolved.json", timeout=fast).get("incidents", [])
            if _is_sase_relevant(_text_of(i))
        ]
        if indicator != "none" or incidents:
            emoji = _INDICATOR_EMOJI.get(indicator, "🟡")
            head = f"> {emoji} **PAN cloud status: {status.get('description', indicator)}**"
            if incidents:
                names = "; ".join(str(i.get("name", ""))[:70] for i in incidents[:2])
                head += f" — {len(incidents)} unresolved SASE incident(s): {names}"
            lines.append(head)

        horizon = datetime.now(UTC) + timedelta(days=days)
        wins = []
        for m in _fetch("scheduled-maintenances/upcoming.json", timeout=fast).get(
            "scheduled_maintenances", []
        ):
            if not _is_sase_relevant(_text_of(m)):
                continue
            sched = str(m.get("scheduled_for") or "")
            try:
                starts = datetime.fromisoformat(sched.replace("Z", "+00:00"))
            except ValueError:
                continue
            if starts <= horizon:
                wins.append((starts, m))
        if wins:
            wins.sort(key=lambda x: x[0])
            starts, first = wins[0]
            more = f" (+{len(wins) - 1} more within {days}d)" if len(wins) > 1 else ""
            lines.append(
                f"> 🔧 Next SASE maintenance: {first.get('name')} — "
                f"{starts.strftime('%Y-%m-%d %H:%M UTC')}{more}"
            )
    except Exception as exc:
        logger.debug("status_banner_failed", error=str(exc))
        return []
    return lines


def register_service_status_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register PAN cloud service-status tools."""

    @mcp.tool()
    def scm_service_maintenance(
        tenant_id: str = "",
        days: int = 14,
        all_tenants: bool = False,
        include_all_products: bool = False,
    ) -> str:
        """Upcoming PAN cloud maintenance windows relevant to your tenants.

        Pulls scheduled (and in-progress) maintenance from the public
        status.paloaltonetworks.com API, keeps windows for the SASE/SCM
        product families this server manages, and matches each window
        against tenant regions (TenantConfig.insights_region: eu/us/uk/
        sg/au). Windows with no regional wording are treated as global.
        Also reports the page's overall status indicator and any
        unresolved incidents touching SASE products, so planned works and
        live degradations arrive in one view.

        No credentials are used — this is a public status feed and works
        even when tenant APIs are down (that being rather the point).

        Args:
            tenant_id: Match windows for this tenant's region only.
            days: Look-ahead horizon in days (default 14).
            all_tenants: Group matching windows per configured tenant.
            include_all_products: Skip the SASE product filter (include
                Prisma Cloud, Cortex, etc.).

        Returns:
            JSON with `overall_status`, `unresolved_incidents`, and
            `maintenance_windows` (optionally per tenant).
        """
        try:
            from ..config.settings import load_all_tenant_configs

            status = _fetch("status.json").get("status", {})
            incidents_raw = _fetch("incidents/unresolved.json").get("incidents", [])
            upcoming = _fetch("scheduled-maintenances/upcoming.json").get(
                "scheduled_maintenances", []
            )
            active = _fetch("scheduled-maintenances/active.json").get("scheduled_maintenances", [])

            horizon = datetime.now(UTC) + timedelta(days=days)
            windows: list[dict[str, Any]] = []
            for m in active + upcoming:
                text = _text_of(m)
                if not include_all_products and not _is_sase_relevant(text):
                    continue
                sched_for = str(m.get("scheduled_for") or "")
                try:
                    starts = datetime.fromisoformat(sched_for.replace("Z", "+00:00"))
                except ValueError:
                    starts = None
                if starts and starts > horizon and m.get("status") != "in_progress":
                    continue
                windows.append(
                    {
                        "name": m.get("name"),
                        "status": m.get("status"),
                        "scheduled_for": m.get("scheduled_for"),
                        "scheduled_until": m.get("scheduled_until"),
                        "components": [c.get("name") for c in m.get("components") or []],
                        "regions": _regions_for(text) or ["global"],
                        "link": m.get("shortlink"),
                    }
                )
            windows.sort(key=lambda w: w.get("scheduled_for") or "")

            incidents = []
            for i in incidents_raw:
                text = _text_of(i)
                if not include_all_products and not _is_sase_relevant(text):
                    continue
                incidents.append(
                    {
                        "name": i.get("name"),
                        "impact": i.get("impact"),
                        "status": i.get("status"),
                        "updated_at": i.get("updated_at"),
                        "regions": _regions_for(text) or ["global"],
                        "link": i.get("shortlink"),
                    }
                )

            result: dict[str, Any] = {
                "overall_status": status.get("description"),
                "indicator": status.get("indicator"),
                "horizon_days": days,
                "unresolved_incidents": incidents,
            }

            def _for_region(region: str) -> list[dict[str, Any]]:
                return [w for w in windows if w["regions"] == ["global"] or region in w["regions"]]

            cfgs = load_all_tenant_configs()
            if all_tenants and cfgs:
                per_tenant = {}
                for name, tc in cfgs.items():
                    ws = _for_region(tc.insights_region)
                    per_tenant[name] = {
                        "region": tc.insights_region,
                        "windows": ws,
                        "count": len(ws),
                    }
                result["tenants"] = per_tenant
            elif tenant_id and tenant_id in cfgs:
                region = cfgs[tenant_id].insights_region
                result["tenant"] = tenant_id
                result["region"] = region
                result["maintenance_windows"] = _for_region(region)
            else:
                result["maintenance_windows"] = windows
            return _fmt(result)
        except requests.RequestException as exc:
            return f"Error: status.paloaltonetworks.com unreachable: {exc}"
        except Exception as exc:
            return f"Error: {exc}"
