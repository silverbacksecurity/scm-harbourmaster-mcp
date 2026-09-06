"""
Service Provider Interconnect (SPI) — read-only visibility tools.

SPI lets service providers attach their backbone directly to Prisma Access
(native-IP / non-IPsec on-ramp) and steer tenant egress via the SP network.
API family: pan.dev `sase/mt-interconnect` (multitenant — requires an MSP
role on the service account; plain tenant credentials typically get 403).

Plumbing scaffolded by scripts/gen_tool_from_spec.py from pan.dev
@ 06430c92c453, then consolidated into a single view-based tool so the
seven collection endpoints don't add seven tools to the server.
"""

from __future__ import annotations

import json
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..audit.extractor import _bearer_session_for
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool

logger = get_logger(__name__)

_MAX_CHARS = 15000
_BASE = "https://api.sase.paloaltonetworks.com/mt/sp-interconnect"

_VIEWS: dict[str, str] = {
    "summary": f"{_BASE}/interconnects/summary",
    "interconnects": f"{_BASE}/interconnects",
    "physical-connections": f"{_BASE}/interconnects/physical-connections",
    "regions": f"{_BASE}/regions",
    "region-connections": f"{_BASE}/regions/physical-connections",
    "settings": f"{_BASE}/settings",
    "ip-pool-usage": f"{_BASE}/monitor/ip-pool-usage",
}


def _get_json(client: Any, url: str, params: dict[str, Any]) -> tuple[int, Any]:
    """GET url with a fresh bearer session; return (status, parsed-or-text)."""
    session = _bearer_session_for(client)
    resp = session.get(
        url, params={k: v for k, v in params.items() if v not in (None, "")}, timeout=(5, 30)
    )
    try:
        return resp.status_code, resp.json()
    except Exception:
        return resp.status_code, (resp.text or "")[:500]


def _render(title: str, url: str, status: int, data: Any) -> str:
    if status in (401, 403):
        return (
            f"# {title}\n\n⚠️ HTTP {status} — the service account lacks access to `{url}`. "
            f"SP Interconnect is a multitenant (MSP) API: the account needs an MSP role, "
            f"and the TSG must be enrolled in SPI."
        )
    if status == 404:
        return f"# {title}\n\nHTTP 404 — SP Interconnect is not provisioned for this tenant."
    if status >= 500:
        return (
            f"# {title}\n\nHTTP {status} — PAN backend error from `{url}`. This "
            f"multitenant API may require an MSP-mode service account; the upstream "
            f"service failed to process the request (response body suppressed)."
        )
    if status != 200:
        return f"# {title}\n\nHTTP {status} from `{url}`:\n\n{data}"
    items = data.get("data", data.get("items", data)) if isinstance(data, dict) else data
    count = len(items) if isinstance(items, list) else 1
    body = json.dumps(items, indent=2, default=str)
    if len(body) > _MAX_CHARS:
        body = body[:_MAX_CHARS] + "\n… (truncated)"
    return f"# {title} ({count})\n\n```json\n{body}\n```"


def register_spi_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register SP Interconnect read-only tools."""
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_spi_status(
        client: Any,
        view: str = "summary",
        interconnect_id: str = "",
        cloud_provider: str = "",
        usage: str = "",
        include_default_interconnect: bool = False,
        include_tenants_associated: bool = False,
    ) -> str:
        """Service Provider Interconnect (SPI) inventory and status.

        SPI attaches a service-provider backbone directly to Prisma Access
        (native-IP on-ramp, no IPsec) and steers tenant egress through the SP
        network. This tool reads the multitenant SPI API — the service account
        needs an MSP role; a 403 means the account or TSG is not SPI-enrolled.

        Args:
            view: What to show —
                "summary"              interconnect roll-up (default)
                "interconnects"        all interconnects
                "physical-connections" physical connections across interconnects
                "regions"              SPI-capable regions
                "region-connections"   physical connections per region
                "settings"             SPI tenant settings
                "ip-pool-usage"        monitor: IP pool consumption
            tenant_id: SCM tenant ID (MSSP mode).
            interconnect_id: Filter ip-pool-usage to one interconnect.
            cloud_provider: Filter regions view by cloud provider.
            usage: Summary view usage filter.
            include_default_interconnect: interconnects view — include default.
            include_tenants_associated: interconnects view — include tenant associations.

        Returns:
            Markdown with a JSON payload, or an actionable message on 4xx.
        """
        url = _VIEWS.get(view)
        if url is None:
            return f"Unknown view {view!r}. Valid views: {', '.join(sorted(_VIEWS))}"
        params: dict[str, Any] = {}
        if view == "interconnects":
            params = {
                "includeDefaultInterconnect": include_default_interconnect or None,
                "includeTenantsAssociated": include_tenants_associated or None,
            }
        elif view == "summary":
            params = {"usage": usage}
        elif view == "regions":
            params = {"cloudProvider": cloud_provider}
        elif view == "ip-pool-usage":
            params = {"interconnectId": interconnect_id}
        status, data = _get_json(client, url, params)
        logger.info("spi_status", view=view, status=status)
        return _render(f"SP Interconnect — {view}", url, status, data)
