"""
MCP resources: expose tenant/folder context as browsable resources.

Resources follow the URI scheme:
  scm://tenants                  — index of all configured tenants
  scm://tenants/{tenant_id}      — tenant details
  scm://tenants/{tenant_id}/folders  — folder list for that tenant
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from ..auth.oauth import get_client_for_tenant, list_loaded_tenants
from ..utils.errors import handle_scm_exception
from ..utils.logging import get_logger

logger = get_logger(__name__)


def register_tenant_resources(mcp: FastMCP) -> None:
    """Register tenant/folder MCP resources."""

    @mcp.resource("scm://tenants")
    def list_tenants_resource() -> str:
        """Index of all loaded SCM tenants."""
        tenants = list_loaded_tenants()
        return json.dumps({"tenants": tenants}, indent=2)

    @mcp.resource("scm://tenants/{tenant_id}")
    def tenant_detail_resource(tenant_id: str) -> str:
        """Details for a single SCM tenant."""
        try:
            client = get_client_for_tenant(tenant_id)
            # Try to return a basic descriptor; the Scm object holds tenant_id
            return json.dumps(
                {
                    "tenant_id": tenant_id,
                    "status": "authenticated",
                    "scm_client_type": type(client).__name__,
                },
                indent=2,
            )
        except Exception as exc:
            return json.dumps({"tenant_id": tenant_id, "error": handle_scm_exception(exc)})

    @mcp.resource("scm://tenants/{tenant_id}/folders")
    def tenant_folders_resource(tenant_id: str) -> str:
        """List SCM folders for a given tenant."""
        try:
            client = get_client_for_tenant(tenant_id)
            folders = client.folder.list()
            data = [f.model_dump() if hasattr(f, "model_dump") else f for f in folders]
            return json.dumps(data, indent=2, default=str)
        except Exception as exc:
            return json.dumps({"error": handle_scm_exception(exc)})
