"""
MCP tools for SCM Setup resources and MSSP tenant management.

Covers: folders (tenant hierarchy), snippets, devices, variables,
        and MSSP-specific tenant lifecycle helpers.
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from ..auth.oauth import evict_tenant, list_loaded_tenants
from ..utils.formatting import format_result as _fmt
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool

logger = get_logger(__name__)


def register_setup_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register SCM Setup and MSSP management tools."""
    tool = scm_tool(get_client)

    # ── Folders ─────────────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_folder_list(client: Any, limit: int = 200) -> str:
        """List SCM folders (represents the tenant/customer hierarchy).

        Args:
            tenant_id: SCM tenant ID.
            limit: Maximum results.
        """
        results = client.folder.list()[: max(0, limit)]
        return _fmt(results)

    @mcp.tool()
    @tool
    def scm_folder_get(client: Any, name: str) -> str:
        """Fetch a single SCM folder by name.

        Args:
            name: Folder name.
            tenant_id: SCM tenant ID.
        """
        obj = client.folder.fetch(name=name)
        return _fmt(obj)

    # ── Devices ─────────────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_device_list(client: Any, folder: str, limit: int = 200) -> str:
        """List devices (firewalls, Panorama) onboarded to SCM.

        Args:
            folder: SCM folder.
            tenant_id: SCM tenant ID.
            limit: Maximum results.
        """
        results = client.device.list()[: max(0, limit)]
        return _fmt(results)

    # ── Snippets ─────────────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_snippet_list(client: Any, limit: int = 200) -> str:
        """List configuration snippets available in SCM.

        Args:
            tenant_id: SCM tenant ID.
            limit: Maximum results.
        """
        results = client.snippet.list()[: max(0, limit)]
        return _fmt(results)

    # ── MSSP Tenant Management ──────────────────────────────────────────────

    @mcp.tool()
    def mssp_list_tenants() -> str:
        """List all MSSP tenant IDs that currently have active SCM clients.

        Returns which tenants are loaded and ready without needing
        re-authentication.
        """
        tenants = list_loaded_tenants()
        if not tenants:
            return "No tenants currently loaded."
        return "\n".join(f"- {t}" for t in tenants)

    @mcp.tool()
    def mssp_evict_tenant(tenant_id: str) -> str:
        """Remove a tenant's cached SCM client (forces re-authentication on next use).

        Use this after rotating OAuth2 credentials for a customer tenant.

        Args:
            tenant_id: SCM tenant ID to evict.
        """
        removed = evict_tenant(tenant_id)
        if removed:
            logger.info("tenant_evicted", tenant_id=tenant_id)
            return f"Tenant '{tenant_id}' evicted; next request will re-authenticate."
        return f"Tenant '{tenant_id}' was not loaded."
