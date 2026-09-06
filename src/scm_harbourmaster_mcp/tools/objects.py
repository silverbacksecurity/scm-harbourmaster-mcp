"""
MCP tools for SCM Objects resources.

Covers: addresses, address groups, services, service groups, tags,
        applications, application groups, application filters,
        external dynamic lists (EDLs), HIP objects, HIP profiles.
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from ..utils.formatting import format_result as _fmt
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool

logger = get_logger(__name__)


def register_object_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register all SCM Objects tools onto the MCP server."""
    tool = scm_tool(get_client)

    # ── Addresses ──────────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_address_list(client: Any, folder: str, limit: int = 200, name_filter: str = "") -> str:
        """List address objects in a SCM folder.

        Args:
            folder: SCM folder (customer context for MSSP).
            tenant_id: SCM tenant ID; uses default tenant when omitted.
            limit: Maximum number of results.
            name_filter: Substring filter on address name.
        """
        results = client.address.list(folder=folder)
        if name_filter:
            results = [r for r in results if name_filter.lower() in r.name.lower()]
        return _fmt(results[: max(0, limit)])

    @mcp.tool()
    @tool
    def scm_address_get(client: Any, name: str, folder: str) -> str:
        """Fetch a single address object by name.

        Args:
            name: Address object name.
            folder: SCM folder.
            tenant_id: SCM tenant ID.
        """
        obj = client.address.fetch(name=name, folder=folder)
        return _fmt(obj)

    @mcp.tool()
    @tool
    def scm_address_create(
        client: Any,
        name: str,
        folder: str,
        ip_netmask: str = "",
        fqdn: str = "",
        ip_range: str = "",
        description: str = "",
    ) -> str:
        """Create an address object in SCM.

        Provide exactly one of ip_netmask, fqdn, or ip_range.

        Args:
            name: Object name.
            folder: SCM folder.
            ip_netmask: CIDR notation (e.g. 10.0.0.0/8).
            fqdn: Fully qualified domain name.
            ip_range: IP range (e.g. 10.0.0.1-10.0.0.100).
            description: Optional description.
            tenant_id: SCM tenant ID.
        """
        payload: dict[str, Any] = {"name": name, "folder": folder}
        if ip_netmask:
            payload["ip_netmask"] = ip_netmask
        elif fqdn:
            payload["fqdn"] = fqdn
        elif ip_range:
            payload["ip_range"] = ip_range
        else:
            return "Error: supply one of ip_netmask, fqdn, or ip_range"
        if description:
            payload["description"] = description
        obj = client.address.create(payload)
        logger.info("address_created", name=name, folder=folder)
        return _fmt(obj)

    @mcp.tool()
    @tool
    def scm_address_delete(client: Any, name: str, folder: str) -> str:
        """Delete an address object by name.

        Args:
            name: Address object name.
            folder: SCM folder.
            tenant_id: SCM tenant ID.
        """
        obj = client.address.fetch(name=name, folder=folder)
        client.address.delete(obj.id)
        logger.info("address_deleted", name=name, folder=folder)
        return f"Deleted address '{name}' from folder '{folder}'"

    # ── Address Groups ──────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_address_group_list(client: Any, folder: str, limit: int = 200) -> str:
        """List address groups in a SCM folder.

        Args:
            folder: SCM folder.
            tenant_id: SCM tenant ID.
            limit: Maximum number of results.
        """
        results = client.address_group.list(folder=folder)[: max(0, limit)]
        return _fmt(results)

    # ── Services ────────────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_service_list(client: Any, folder: str, limit: int = 200) -> str:
        """List service objects in a SCM folder.

        Args:
            folder: SCM folder.
            tenant_id: SCM tenant ID.
            limit: Maximum number of results.
        """
        results = client.service.list(folder=folder)[: max(0, limit)]
        return _fmt(results)

    # ── Tags ────────────────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_tag_list(client: Any, folder: str, limit: int = 200) -> str:
        """List tags in a SCM folder.

        Args:
            folder: SCM folder.
            tenant_id: SCM tenant ID.
            limit: Maximum number of results.
        """
        results = client.tag.list(folder=folder)[: max(0, limit)]
        return _fmt(results)

    # ── External Dynamic Lists ──────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_edl_list(client: Any, folder: str, limit: int = 200) -> str:
        """List external dynamic lists (EDLs) in a SCM folder.

        Args:
            folder: SCM folder.
            tenant_id: SCM tenant ID.
            limit: Maximum number of results.
        """
        results = client.external_dynamic_list.list(folder=folder)[: max(0, limit)]
        return _fmt(results)
