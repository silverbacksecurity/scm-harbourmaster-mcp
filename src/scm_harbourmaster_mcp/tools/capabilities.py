"""MCP tool for per-tenant API capability probing — ``mssp_tenant_capabilities``.

Probe logic, classification and the shared cache live in
``utils/capabilities.py`` so report tools can consult the cache without
importing a tool module.
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from ..utils.capabilities import (
    canonical_tenant_id,
    probe_tenant_capabilities,
    render_capabilities_markdown,
)
from ..utils.tool_decorator import scm_tool


def register_capability_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register ``mssp_tenant_capabilities``."""
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def mssp_tenant_capabilities(client: Any, tenant_id: str, refresh: bool = False) -> str:
        """Probe which API families a tenant's service account can actually use.

        Sends one cheap, read-only request per API family (SCM config jobs,
        allocated egress IPs, licences, Incidents, Insights, ADEM, Compliance
        Center, Enterprise DLP, Email DLP, ZTNA Connector, SSPM, IAM, Tenancy,
        SD-WAN sites and audit log) and classifies each as available,
        forbidden (403 RBAC), unprovisioned (not licensed/enabled) or error
        (inconclusive). Results are cached per tenant for 6 hours.

        Run this before a long report: scm_asbuilt_report and scm_msr_report
        skip sections the cache marks forbidden/unprovisioned and disclose the
        skip, instead of discovering the 403 mid-run. mssp_tenant_dashboard
        shows the cached summary per tenant.

        Args:
            tenant_id: SCM tenant ID (TSG ID). Omit for the default tenant.
            refresh: Re-probe even when a cached result exists.

        Returns:
            Markdown table of capability results.
        """
        results, probed_at, from_cache = probe_tenant_capabilities(
            client, tenant_id, refresh=refresh
        )
        return render_capabilities_markdown(
            canonical_tenant_id(tenant_id), results, probed_at, from_cache
        )
