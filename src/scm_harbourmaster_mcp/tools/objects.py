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
from ..utils.write_safety import (
    DRY_RUN_HINT,
    audit_write,
    dump_model,
    normalize_ticket_ref,
    ticket_ref_error,
)

logger = get_logger(__name__)


def _try_fetch(resource: Any, name: str, folder: str) -> Any:
    """Fetch an object by name for a dry-run preview; ``None`` when absent or unreadable."""
    try:
        return resource.fetch(name=name, folder=folder)
    except Exception:
        return None


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
        tenant_id: str,
        name: str,
        folder: str,
        ip_netmask: str = "",
        fqdn: str = "",
        ip_range: str = "",
        description: str = "",
        dry_run: bool = True,
        ticket_ref: str = "",
    ) -> str:
        """Create an address object in SCM.

        Provide exactly one of ip_netmask, fqdn, or ip_range.

        **Write safety (SSR pattern):** ``dry_run=True`` by default returns the
        planned payload and any existing object of the same name without
        writing; ``ticket_ref`` is mandatory. Commit is a separate
        ``scm_commit`` step.

        Args:
            name: Object name.
            folder: SCM folder.
            ip_netmask: CIDR notation (e.g. 10.0.0.0/8).
            fqdn: Fully qualified domain name.
            ip_range: IP range (e.g. 10.0.0.1-10.0.0.100).
            description: Optional description.
            dry_run: If True (default), preview the change without applying it.
            ticket_ref: Mandatory change-ticket reference (never sent to SCM).
            tenant_id: SCM tenant ID.
        """
        err = ticket_ref_error(ticket_ref)
        if err:
            return f"Error: {err}"
        ticket_ref = normalize_ticket_ref(ticket_ref)

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

        if dry_run:
            existing = _try_fetch(client.address, name, folder)
            return _fmt(
                {
                    "action": "create",
                    "dry_run": True,
                    "ticket_ref": ticket_ref,
                    "planned_payload": payload,
                    "existing_object": dump_model(existing),
                    "hint": DRY_RUN_HINT,
                }
            )

        audit_write("scm_address_create", ticket_ref, tenant_id, name=name, folder=folder)
        obj = client.address.create(payload)
        logger.info("address_created", name=name, folder=folder, ticket_ref=ticket_ref)
        return _fmt(
            {
                "action": "create",
                "applied": True,
                "ticket_ref": ticket_ref,
                "result": dump_model(obj),
            }
        )

    @mcp.tool()
    @tool
    def scm_address_delete(
        client: Any,
        tenant_id: str,
        name: str,
        folder: str,
        dry_run: bool = True,
        ticket_ref: str = "",
    ) -> str:
        """Delete an address object by name.

        **Write safety (SSR pattern):** ``dry_run=True`` by default fetches and
        returns the object that would be deleted without deleting it;
        ``ticket_ref`` is mandatory. Commit is a separate ``scm_commit`` step.

        Args:
            name: Address object name.
            folder: SCM folder.
            dry_run: If True (default), preview the deletion without applying it.
            ticket_ref: Mandatory change-ticket reference (never sent to SCM).
            tenant_id: SCM tenant ID.
        """
        err = ticket_ref_error(ticket_ref)
        if err:
            return f"Error: {err}"
        ticket_ref = normalize_ticket_ref(ticket_ref)

        obj = client.address.fetch(name=name, folder=folder)
        if dry_run:
            return _fmt(
                {
                    "action": "delete",
                    "dry_run": True,
                    "ticket_ref": ticket_ref,
                    "current_state": dump_model(obj),
                    "hint": DRY_RUN_HINT,
                }
            )

        audit_write(
            "scm_address_delete", ticket_ref, tenant_id, name=name, folder=folder, id=str(obj.id)
        )
        client.address.delete(obj.id)
        logger.info("address_deleted", name=name, folder=folder, ticket_ref=ticket_ref)
        return f"Deleted address '{name}' from folder '{folder}' (ticket_ref: {ticket_ref})"

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
