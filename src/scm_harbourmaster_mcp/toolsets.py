"""
Toolset filtering — load only the tool groups a client actually needs.

The server registers ~165 tools, and every one of them lands in every MCP
client's context window. Toolsets let an operator trim that down:

    # settings.toml
    enabled_toolsets = ["sdwan", "ops"]
    read_only = true

    # or on the command line / environment
    uv run scm-mcp --toolsets sdwan,ops --read-only
    SCM_MCP_ENABLED_TOOLSETS=sdwan,ops SCM_MCP_READ_ONLY=true uv run scm-mcp

An empty / absent ``enabled_toolsets`` means "everything" (the historical
behaviour). The ``core`` toolset (tenant/folder discovery) plus ``scm_reload``
and ``scm_restart`` are always registered regardless of the filter.

This module is pure data + helpers with no tool imports, so it is safe to
import from ``server.py`` and from tests without registering anything.
Toolsets map to the *names* of the ``register_*`` functions in ``server.py``;
the server resolves the names at call time so hot-reload keeps working.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

# Always registered, whatever the filter says.
CORE_TOOLSET = "core"

# Tools registered outside ``register_all_tools`` that must never be filtered.
ALWAYS_ON_TOOLS: frozenset[str] = frozenset({"scm_reload", "scm_restart"})

# toolset name -> register_* function names in server.py.
# Every registrar belongs to exactly one toolset (enforced by unit test).
TOOLSETS: dict[str, tuple[str, ...]] = {
    CORE_TOOLSET: ("register_setup_tools",),
    "objects": ("register_object_tools", "register_config_index_tools"),
    "security": (
        "register_security_tools",
        "register_ssr_tools",
        "register_policy_optimizer_tools",
        "register_config_cleanup_tools",
        "register_dns_security_tools",
    ),
    "network": (
        "register_network_tools",
        "register_config_orch_tools",
        "register_site_management_tools",
    ),
    "deployment": ("register_deployment_tools",),
    "audit": ("register_audit_tools",),
    "compliance": (
        "register_compliance_tools",
        "register_ai_advisor_tools",
        "register_aiops_tools",
    ),
    "ncsc": ("register_ncsc_tools",),
    "posture": ("register_posture_tools",),
    "insights": (
        "register_insights_tools",
        "register_cdl_logforwarding_tools",
        "register_mt_monitor_tools",
        "register_adem_tools",
    ),
    "mssp": (
        "register_mssp_tools",
        "register_region_tools",
        "register_capability_tools",
        "register_msr_tools",
        "register_spi_tools",
        "register_csp_licensing_tools",
    ),
    "sase": (
        "register_casb_dlp_tools",
        "register_pab_tools",
        "register_pab_transfer_tools",
        "register_pab_msp_tools",
    ),
    "ngfw": ("register_ngfw_airs_tools", "register_adnsr_tools"),
    "dlp": ("register_dlp_tools", "register_email_dlp_tools"),
    "sdwan": ("register_sdwan_tools",),
    "ops": (
        "register_ops_tools",
        "register_cert_transfer_tools",
        "register_tenant_copy_tools",
        "register_service_status_tools",
    ),
    "planner": ("register_planner_tools",),
}

# Convenience profiles: a name that expands to several toolsets.
PROFILES: dict[str, tuple[str, ...]] = {
    # Dashboards, incidents, service health, analytics — day-to-day NOC view.
    "noc": ("ops", "posture", "insights", "mssp"),
    # Governance / risk / compliance reporting.
    "grc": ("audit", "compliance", "ncsc", "posture"),
    # Policy and object administration.
    "config": ("objects", "security", "network", "deployment"),
}

ALL_TOOLSETS = "all"


class UnknownToolsetError(ValueError):
    """Raised when a configured toolset / profile name is not recognised."""


def parse_toolset_names(value: Any) -> list[str]:
    """Normalise a toolset setting (list, comma-separated string, or None)."""
    if value is None:
        return []
    if isinstance(value, str) and value.strip().startswith("["):
        try:
            value = json.loads(value)
        except ValueError as exc:
            raise UnknownToolsetError(f"enabled_toolsets is not valid JSON: {value!r}") from exc
    if isinstance(value, str):
        items: Iterable[Any] = value.split(",")
    elif isinstance(value, Iterable):
        items = value
    else:
        raise UnknownToolsetError(f"enabled_toolsets must be a list or string, got {value!r}")
    return [str(v).strip().lower() for v in items if str(v).strip()]


def resolve_toolsets(names: Iterable[str] | str | None) -> list[str]:
    """Expand toolset / profile names into a sorted list of toolset names.

    Empty input, or any occurrence of ``"all"``, selects every toolset.
    ``core`` is always included. Unknown names raise ``UnknownToolsetError``
    listing the valid choices, so a typo fails loudly at startup instead of
    silently hiding tools.
    """
    requested = parse_toolset_names(names)
    if not requested or ALL_TOOLSETS in requested:
        return sorted(TOOLSETS)

    selected: set[str] = {CORE_TOOLSET}
    unknown: list[str] = []
    for name in requested:
        if name in TOOLSETS:
            selected.add(name)
        elif name in PROFILES:
            selected.update(PROFILES[name])
        else:
            unknown.append(name)
    if unknown:
        raise UnknownToolsetError(
            f"Unknown toolset(s): {', '.join(unknown)}. "
            f"Valid toolsets: {', '.join(sorted(TOOLSETS))}. "
            f"Profiles: {', '.join(sorted(PROFILES))}. Use '{ALL_TOOLSETS}' for everything."
        )
    return sorted(selected)


def registrars_for(toolsets: Iterable[str]) -> frozenset[str]:
    """Return the register_* function names covered by the given toolsets."""
    return frozenset(r for ts in toolsets for r in TOOLSETS[ts])


def _is_write_tool(name: str) -> bool:
    """Decide whether a tool can mutate state (for ``read_only``).

    Sourced from the Planner tool manifest — the single read/write
    classification every registered tool already has — rather than a
    name/schema heuristic that could drift from it (and did: the heuristic
    missed ``scm_compliance_framework`` until the parity test caught it).
    Unknown tools raise ``UnknownToolError`` so read-only mode fails loudly
    instead of silently exposing an unclassified write path.
    """
    from .utils.tool_annotations import tool_access  # lazy: avoid import cycles

    return tool_access(name) == "write"
