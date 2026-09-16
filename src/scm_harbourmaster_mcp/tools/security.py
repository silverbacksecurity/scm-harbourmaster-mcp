"""
MCP tools for SCM Security Services resources.

Covers: security rules, anti-spyware profiles, URL filtering profiles,
        vulnerability protection, DNS security, decryption profiles,
        wildfire analysis.
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


def register_security_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register all SCM Security tools onto the MCP server."""
    tool = scm_tool(get_client)

    # ── Security Rules ──────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_security_rule_list(
        client: Any, folder: str, limit: int = 200, position: str = "pre"
    ) -> str:
        """List security policy rules in a SCM folder.

        Args:
            folder: SCM folder.
            tenant_id: SCM tenant ID.
            limit: Maximum number of results.
            position: Rule position — 'pre' or 'post'.
        """
        results = client.security_rule.list(folder=folder, rulebase=position)[: max(0, limit)]
        return _fmt(results)

    @mcp.tool()
    @tool
    def scm_security_rule_get(client: Any, name: str, folder: str) -> str:
        """Fetch a single security rule by name.

        Args:
            name: Rule name.
            folder: SCM folder.
            tenant_id: SCM tenant ID.
        """
        obj = client.security_rule.fetch(name=name, folder=folder)
        return _fmt(obj)

    @mcp.tool()
    @tool
    def scm_security_rule_create(
        client: Any,
        tenant_id: str,
        name: str,
        folder: str,
        action: str,
        source_zones: list[str],
        destination_zones: list[str],
        source_addresses: list[str] | None = None,
        destination_addresses: list[str] | None = None,
        applications: list[str] | None = None,
        services: list[str] | None = None,
        profile_setting: dict[str, Any] | None = None,
        description: str = "",
        disabled: bool = False,
        dry_run: bool = True,
        ticket_ref: str = "",
    ) -> str:
        """Create a security policy rule.

        **Write safety (SSR pattern):** ``dry_run=True`` by default returns the
        planned rule and any existing rule of the same name without writing;
        ``ticket_ref`` is mandatory. Commit is a separate ``scm_commit`` step.

        Args:
            name: Rule name.
            folder: SCM folder.
            action: 'allow' or 'deny'.
            source_zones: Source security zones.
            destination_zones: Destination security zones.
            source_addresses: Source addresses/groups (default: ['any']).
            destination_addresses: Destination addresses/groups (default: ['any']).
            applications: Application names (default: ['any']).
            services: Services (default: ['application-default']).
            profile_setting: Security profile group dict.
            description: Optional description.
            disabled: Whether the rule is disabled.
            dry_run: If True (default), preview the change without applying it.
            ticket_ref: Mandatory change-ticket reference (never sent to SCM).
            tenant_id: SCM tenant ID.
        """
        err = ticket_ref_error(ticket_ref)
        if err:
            return f"Error: {err}"
        ticket_ref = normalize_ticket_ref(ticket_ref)

        payload: dict[str, Any] = {
            "name": name,
            "folder": folder,
            "action": action,
            "from": source_zones,
            "to": destination_zones,
            "source": source_addresses or ["any"],
            "destination": destination_addresses or ["any"],
            "application": applications or ["any"],
            "service": services or ["application-default"],
            "disabled": disabled,
        }
        if description:
            payload["description"] = description
        if profile_setting:
            payload["profile_setting"] = profile_setting

        if dry_run:
            try:
                existing = client.security_rule.fetch(name=name, folder=folder)
            except Exception:
                existing = None
            return _fmt(
                {
                    "action": "create",
                    "dry_run": True,
                    "ticket_ref": ticket_ref,
                    "planned_payload": payload,
                    "existing_rule": dump_model(existing),
                    "hint": DRY_RUN_HINT,
                }
            )

        audit_write("scm_security_rule_create", ticket_ref, tenant_id, name=name, folder=folder)
        obj = client.security_rule.create(payload)
        logger.info(
            "security_rule_created", name=name, folder=folder, action=action, ticket_ref=ticket_ref
        )
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
    def scm_security_rule_delete(
        client: Any,
        tenant_id: str,
        name: str,
        folder: str,
        dry_run: bool = True,
        ticket_ref: str = "",
    ) -> str:
        """Delete a security rule by name.

        **Write safety (SSR pattern):** ``dry_run=True`` by default fetches and
        returns the rule that would be deleted without deleting it;
        ``ticket_ref`` is mandatory. Commit is a separate ``scm_commit`` step.

        Args:
            name: Rule name.
            folder: SCM folder.
            dry_run: If True (default), preview the deletion without applying it.
            ticket_ref: Mandatory change-ticket reference (never sent to SCM).
            tenant_id: SCM tenant ID.
        """
        err = ticket_ref_error(ticket_ref)
        if err:
            return f"Error: {err}"
        ticket_ref = normalize_ticket_ref(ticket_ref)

        obj = client.security_rule.fetch(name=name, folder=folder)
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
            "scm_security_rule_delete",
            ticket_ref,
            tenant_id,
            name=name,
            folder=folder,
            id=str(obj.id),
        )
        client.security_rule.delete(obj.id)
        logger.info("security_rule_deleted", name=name, folder=folder, ticket_ref=ticket_ref)
        return f"Deleted security rule '{name}' from folder '{folder}' (ticket_ref: {ticket_ref})"

    # ── Security Profiles ───────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_anti_spyware_profile_list(client: Any, folder: str, limit: int = 200) -> str:
        """List anti-spyware profiles in a SCM folder.

        Args:
            folder: SCM folder.
            tenant_id: SCM tenant ID.
            limit: Maximum results.
        """
        results = client.anti_spyware_profile.list(folder=folder)[: max(0, limit)]
        return _fmt(results)

    @mcp.tool()
    @tool
    def scm_url_category_list(client: Any, folder: str, limit: int = 200) -> str:
        """List URL filtering categories in a SCM folder.

        Args:
            folder: SCM folder.
            tenant_id: SCM tenant ID.
            limit: Maximum results.
        """
        results = client.url_category.list(folder=folder)[: max(0, limit)]
        return _fmt(results)
