"""MCP ToolAnnotations for every registered tool — one central classification.

The read/write split is NOT duplicated here: it comes from the Planner tool
manifest (``resources/tools_manifest.yaml``), which already classifies every
registered tool with ``access: read | write`` and is coverage-tested against
the live registry. This module layers the MCP-hint details on top:

* ``readOnlyHint``    — ``access == "read"`` (w.r.t. SCM / the managed estate;
  report tools that only save a local file still count as read-only).
* ``destructiveHint`` — write tools in :data:`DESTRUCTIVE_TOOLS` (can delete,
  overwrite or discard existing state). Other writes are additive/updating.
* ``idempotentHint``  — true for reads and for :data:`IDEMPOTENT_WRITE_TOOLS`.
* ``openWorldHint``   — false only for :data:`CLOSED_WORLD_TOOLS` (tools that
  touch nothing but this server's own process state / job store).
* ``title``           — derived from the tool name.

Annotations are applied centrally after registration by
:func:`apply_tool_annotations` (called from ``register_all_tools`` so hot
reload re-applies them). ``tests/unit/test_tool_annotations.py`` fails when a
registered tool has no classification, or when these sets drift from the
manifest.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from mcp.types import ToolAnnotations

from .logging import get_logger

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

logger = get_logger(__name__)

Access = Literal["read", "write"]

# Write tools that can delete, overwrite or discard existing state.
DESTRUCTIVE_TOOLS: frozenset[str] = frozenset(
    {
        "scm_address_delete",
        "scm_security_rule_delete",
        "scm_config_rollback",  # replaces candidate config with an older version
        "scm_config_push_track",  # rollback_on_failure reloads an older version
        "scm_config_clone",  # on_conflict="overwrite" replaces target objects
        "scm_gp_copy",  # replaces target agent profiles and Mobile Users locations
        "scm_compliance_framework",  # action=delete
        "scm_config_orch_remote_networks",  # action=delete
        "scm_config_orch_bandwidth",  # action=delete
        "scm_config_orch_profiles",  # action=delete
        "scm_site_management",  # action=delete (force deletes claimed sites)
        "scm_ssr_execute",  # action=remove drops entries from managed objects
        "scm_planner_run",  # may execute approved write tools, including deletes
        "mssp_evict_tenant",  # drops a cached tenant client
        "scm_restart",  # terminates the server process
    }
)

# Write tools whose repeat call with the same arguments has no further effect.
IDEMPOTENT_WRITE_TOOLS: frozenset[str] = frozenset(
    {
        "scm_ssr_execute",  # already_present / already_absent semantics
        "scm_address_delete",
        "scm_security_rule_delete",
        "mssp_evict_tenant",
        "scm_reload",
        "scm_cert_copy",  # same-name certs in the target are skipped
        "scm_pab_restore",  # same-name objects in the target are skipped
        "scm_decryption_rule_copy",  # same-name rules in the target are skipped
    }
)

# Tools that never reach SCM or any other external system.
CLOSED_WORLD_TOOLS: frozenset[str] = frozenset(
    {
        "scm_reload",
        "scm_restart",
        "mssp_evict_tenant",
        "mssp_list_tenants",
        "scm_planner_status",
        "scm_planner_result",
        "scm_asbuilt_result",
        "scm_config_index_result",
        "scm_drift_result",
    }
)

_TITLE_WORDS = {
    "scm": "SCM",
    "mssp": "MSSP",
    "sdwan": "SD-WAN",
    "dlp": "DLP",
    "ncsc": "NCSC",
    "nist": "NIST",
    "bpa": "BPA",
    "aiops": "AIOps",
    "ai": "AI",
    "adem": "ADEM",
    "adnsr": "ADNSR",
    "airs": "AIRS",
    "casb": "CASB",
    "cdl": "CDL",
    "csp": "CSP",
    "dns": "DNS",
    "dspt": "DSPT",
    "edl": "EDL",
    "gp": "GP",
    "ike": "IKE",
    "ipsec": "IPsec",
    "ipfix": "IPFIX",
    "ir": "IR",
    "iso27001": "ISO 27001",
    "msr": "MSR",
    "mt": "MT",
    "nat": "NAT",
    "ngfw": "NGFW",
    "pab": "PAB",
    "qos": "QoS",
    "rca": "RCA",
    "saas": "SaaS",
    "snmp": "SNMP",
    "spi": "SPI",
    "spn": "SPN",
    "ssr": "SSR",
    "tls": "TLS",
    "url": "URL",
    "wan": "WAN",
    "ip": "IP",
    "bgp": "BGP",
    "ztna": "ZTNA",
    "asbuilt": "AS-BUILT",
}


def tool_access(name: str) -> Access:
    """Return ``"read"`` or ``"write"`` for a registered tool.

    Sourced from the Planner manifest; raises
    :class:`~scm_harbourmaster_mcp.planner.manifest.UnknownToolError` for tools
    the manifest does not classify.
    """
    from ..planner.manifest import load_manifest  # lazy: avoid import cycles

    return "write" if load_manifest().policy(name).access == "write" else "read"


def tool_title(name: str) -> str:
    """Human-readable title derived from the tool name."""
    return " ".join(_TITLE_WORDS.get(w, w.capitalize()) for w in name.split("_"))


def annotations_for(name: str) -> ToolAnnotations:
    """Build the MCP ToolAnnotations for one tool (raises on unknown tools)."""
    read_only = tool_access(name) == "read"
    return ToolAnnotations(
        title=tool_title(name),
        readOnlyHint=read_only,
        destructiveHint=False if read_only else name in DESTRUCTIVE_TOOLS,
        idempotentHint=True if read_only else name in IDEMPOTENT_WRITE_TOOLS,
        openWorldHint=name not in CLOSED_WORLD_TOOLS,
    )


def apply_tool_annotations(mcp: FastMCP) -> list[str]:
    """Attach annotations to every tool currently registered on ``mcp``.

    Returns the names of tools that could not be classified (left without
    annotations and logged) — the unit test keeps this list empty.
    """
    from ..planner.manifest import UnknownToolError

    unclassified: list[str] = []
    for tool in mcp._tool_manager.list_tools():
        try:
            tool.annotations = annotations_for(tool.name)
        except UnknownToolError:
            unclassified.append(tool.name)
    if unclassified:
        logger.warning("tool_annotations_missing", tools=sorted(unclassified))
    return unclassified
