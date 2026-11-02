"""
MCP tools for SCM Setup resources and MSSP tenant management.

Covers: folders (tenant hierarchy), snippets, devices, variables,
        and MSSP-specific tenant lifecycle helpers.
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from ..auth.oauth import evict_tenant, get_scm_client, list_loaded_tenants
from ..config.settings import load_all_tenant_configs
from ..utils.errors import handle_scm_exception
from ..utils.formatting import format_result as _fmt
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool

logger = get_logger(__name__)

# Device fields matched against a scm_device_find query.
_DEVICE_MATCH_FIELDS = ("serial_number", "id", "name", "display_name", "hostname")


def _device_matches(device: Any, query: str) -> bool:
    """True when *query* (case-insensitive) is a substring of a device identifier."""
    wanted = query.casefold()
    return any(wanted in str(getattr(device, f, "") or "").casefold() for f in _DEVICE_MATCH_FIELDS)


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

    @mcp.tool()
    def scm_device_find(query: str, tenant_id: str = "", all_tenants: bool = True) -> str:
        """Find a firewall or Panorama by serial number, name or hostname.

        Searches each tenant's full SCM device inventory (every folder, not
        just ngfw-shared) for devices whose serial number, name, display name
        or hostname contains *query* (case-insensitive). Use it to answer
        "which tenant is this serial onboarded to?" and to confirm a newly
        associated firewall has reached SCM.

        A device missing from every tenant has not reached SCM yet: check its
        device association to the right TSG, device certificate, licence and
        cloud-management connection.

        Args:
            query: Serial number (e.g. "012345678901") or part of a device name.
            tenant_id: Search only this tenant when all_tenants is False.
            all_tenants: Search every configured tenant (default True).

        Returns:
            Markdown table of matches plus per-tenant search coverage.
        """
        # Imported here, not at module level: setup reloads before ops (core toolset).
        from .ops import _gather_parallel

        query = (query or "").strip()
        if len(query) < 3:
            return "Error: query must be at least 3 characters (a serial number or device name)."

        failed: list[tuple[str, str]] = []
        targets: list[tuple[str, Any]] = []
        if all_tenants:
            for key, tc in load_all_tenant_configs().items():
                label = f"{tc.label or key} ({tc.tenant_id})"
                try:
                    targets.append((label, get_scm_client(tc)))
                except Exception as exc:
                    failed.append((label, handle_scm_exception(exc, tenant=key)))
        else:
            try:
                targets.append((tenant_id or "default tenant", get_client(tenant_id)))
            except Exception as exc:
                return f"Error: {handle_scm_exception(exc, tenant=tenant_id)}"

        results = _gather_parallel(targets, lambda _label, client: client.device.list(), timeout=45)

        rows: list[str] = []
        searched = 0
        for label, ok, payload in results:
            if not ok:
                reason = handle_scm_exception(payload) if payload else "timed out"
                failed.append((label, reason))
                continue
            searched += 1
            for d in payload or []:
                if not _device_matches(d, query):
                    continue
                is_connected = getattr(d, "is_connected", None)
                connected = "?" if is_connected is None else "✅ yes" if is_connected else "❌ no"
                rows.append(
                    f"| {label} | `{getattr(d, 'serial_number', None) or getattr(d, 'id', '')}` "
                    f"| {getattr(d, 'display_name', None) or getattr(d, 'name', None) or '—'} "
                    f"| {getattr(d, 'model', None) or '—'} "
                    f"| {getattr(d, 'folder', None) or '—'} | {connected} "
                    f"| {getattr(d, 'software_version', None) or '—'} |"
                )

        lines = [f"## Device search — `{query}`", ""]
        if rows:
            lines += [
                f"**{len(rows)} match(es)** across {searched} tenant(s) searched.",
                "",
                "| Tenant | Serial | Name | Model | Folder | Connected | PAN-OS |",
                "|---|---|---|---|---|---|---|",
                *rows,
            ]
        else:
            lines.append(
                f"No device matching `{query}` in {searched} tenant(s) searched. If it was "
                "just added, check its device association to the right TSG, device "
                "certificate and cloud-management connection."
            )
        if failed:
            lines += ["", f"**Not searched ({len(failed)}):**"]
            lines += [f"- {label}: {reason}" for label, reason in failed]
        return "\n".join(lines)

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
