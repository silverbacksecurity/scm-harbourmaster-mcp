"""
MCP tools for SCM Network resources.

Covers: security zones, NAT rules, static routes, BGP, interfaces,
        IKE gateways, IPSec tunnels, DNS servers.
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from ..utils.formatting import format_result as _fmt
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool

logger = get_logger(__name__)


def register_network_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register all SCM Network tools onto the MCP server."""
    tool = scm_tool(get_client)

    # ── Security Zones ──────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_zone_list(client: Any, folder: str, limit: int = 200) -> str:
        """List security zones in a SCM folder.

        Args:
            folder: SCM folder.
            tenant_id: SCM tenant ID.
            limit: Maximum results.
        """
        # SecurityZone.list() has no real `limit` kwarg — slice client-side.
        results = client.security_zone.list(folder=folder)[: max(0, limit)]
        return _fmt(results)

    # ── NAT Rules ───────────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_nat_rule_list(
        client: Any,
        folder: str,
        limit: int = 200,
        position: str = "pre",
    ) -> str:
        """List NAT rules in a SCM folder.

        Args:
            folder: SCM folder.
            tenant_id: SCM tenant ID.
            limit: Maximum results.
            position: Rule position — 'pre' or 'post'.
        """
        # NatRule.list() has no real `limit` kwarg — slice client-side.
        results = client.nat_rule.list(folder=folder, position=position)[: max(0, limit)]
        return _fmt(results)

    @mcp.tool()
    @tool
    def scm_nat_rule_get(client: Any, name: str, folder: str) -> str:
        """Fetch a single NAT rule by name.

        Args:
            name: NAT rule name.
            folder: SCM folder.
            tenant_id: SCM tenant ID.
        """
        obj = client.nat_rule.fetch(name=name, folder=folder)
        return _fmt(obj)

    # ── IKE / IPSec ─────────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_ike_gateway_list(client: Any, folder: str, limit: int = 200) -> str:
        """List IKE gateways in a SCM folder.

        Args:
            folder: SCM folder.
            tenant_id: SCM tenant ID.
            limit: Maximum results.
        """
        # IKEGateway.list() does not accept a limit kwarg — slice client-side.
        results = client.ike_gateway.list(folder=folder)[: max(0, limit)]
        return _fmt(results)

    @mcp.tool()
    @tool
    def scm_ipsec_tunnel_list(client: Any, folder: str, limit: int = 200) -> str:
        """List IPSec tunnels in a SCM folder.

        Args:
            folder: SCM folder.
            tenant_id: SCM tenant ID.
            limit: Maximum results.
        """
        # IPsecTunnel.list() has no real `limit` kwarg — slice client-side.
        results = client.ipsec_tunnel.list(folder=folder)[: max(0, limit)]
        return _fmt(results)

    # ── DNS Servers ─────────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_dns_server_list(client: Any, folder: str, limit: int = 200) -> str:
        """List internal DNS servers for the tenant.

        Internal DNS servers are a deployment-global resource (not folder-scoped),
        so the ``folder`` argument is accepted for interface consistency but not
        used to filter results.

        Args:
            folder: SCM folder (unused — kept for interface consistency).
            tenant_id: SCM tenant ID.
            limit: Maximum results.
        """
        # SDK accessor is `internal_dns_server`; its list() has no limit kwarg.
        results = client.internal_dns_server.list()[: max(0, limit)]
        return _fmt(results)
