"""
SCM Harbourmaster server entry point.

Exposes Palo Alto Networks Strata Cloud Manager operations as MCP tools
and resources, with MSSP multi-tenant support via folder-based isolation.

Usage:
    uv run scm-mcp                   # stdio transport (Claude Desktop / IDE)
    uv run scm-mcp --transport sse   # SSE transport (HTTP)
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, Any

from mcp.server.fastmcp import FastMCP

from .auth.oauth import get_scm_client, list_loaded_tenants, register_tenant_key
from .config.settings import TenantConfig, get_settings
from .dashboard import instrument_server, register_dashboard
from .resources.tenant import register_tenant_resources
from .tools.adem import register_adem_tools
from .tools.adnsr import register_adnsr_tools
from .tools.ai_advisor import register_ai_advisor_tools
from .tools.aiops import register_aiops_tools
from .tools.audit import register_audit_tools
from .tools.capabilities import register_capability_tools
from .tools.cdl_logforwarding import register_cdl_logforwarding_tools
from .tools.cert_transfer import register_cert_transfer_tools
from .tools.compliance import register_compliance_tools
from .tools.config_cleanup import register_config_cleanup_tools
from .tools.config_index_tools import register_config_index_tools
from .tools.config_orch import register_config_orch_tools
from .tools.csp_licensing import register_csp_licensing_tools
from .tools.deployment import register_deployment_tools
from .tools.dlp import register_dlp_tools
from .tools.dns_security import register_dns_security_tools
from .tools.email_dlp import register_email_dlp_tools
from .tools.insights import register_insights_tools
from .tools.msr import register_msr_tools
from .tools.mssp import register_casb_dlp_tools, register_mssp_tools, register_ngfw_airs_tools
from .tools.mt_interconnect import register_spi_tools
from .tools.mt_monitor import register_mt_monitor_tools
from .tools.ncsc_baseline import register_ncsc_tools
from .tools.network import register_network_tools
from .tools.objects import register_object_tools
from .tools.ops import register_ops_tools
from .tools.pab import register_pab_tools
from .tools.pab_msp import register_pab_msp_tools
from .tools.planner_tools import register_planner_tools
from .tools.policy_optimizer import register_policy_optimizer_tools
from .tools.posture import register_posture_tools
from .tools.reload import register_reload_tool
from .tools.sdwan import register_sdwan_tools
from .tools.security import register_security_tools
from .tools.service_status import register_service_status_tools
from .tools.setup import register_setup_tools
from .tools.site_management import register_site_management_tools
from .tools.ssr import register_ssr_tools
from .toolsets import (
    ALWAYS_ON_TOOLS,
    PROFILES,
    TOOLSETS,
    UnknownToolsetError,
    _is_write_tool,
    registrars_for,
    resolve_toolsets,
)
from .utils.logging import configure_logging, get_logger
from .utils.tool_annotations import apply_tool_annotations
from .utils.tool_decorator import install_tenant_resolution

if TYPE_CHECKING:
    from scm.client import Scm

logger = get_logger(__name__)

mcp = FastMCP(name="scm-harbourmaster-mcp")


def _build_client_resolver(settings: object) -> Callable[..., Any]:
    """
    Return a callable that resolves a TenantConfig → Scm client.

    In single-tenant mode the default credentials are always used.
    In MSSP mode the tenant_id argument selects among pre-loaded tenants; it
    may be the TSG ID, the settings.toml section key or the tenant label
    (resolved by ``get_client_for_tenant``).
    """
    from .config.settings import Settings  # avoid circular at module level

    s: Settings = settings  # type: ignore[assignment]

    def resolve(tenant_id: str = "") -> Scm:
        if s.mssp_mode and tenant_id:
            from .auth.oauth import get_client_for_tenant

            return get_client_for_tenant(tenant_id)
        # Fall back to the default / single-tenant credentials
        return get_scm_client(s.default_tenant())

    return resolve


def _load_mssp_tenants_from_dynaconf(settings: object) -> None:
    """
    Pre-load all tenants declared in settings.toml under [tenants.*].

    Expected format in settings.toml:
    ```toml
    [tenants.acme]
    tenant_id = "..."
    client_id = "..."
    client_secret = "..."
    default_folder = "Acme-Corp"
    label = "Acme Corp"
    ```
    """
    try:
        from dynaconf import Dynaconf  # type: ignore[import-untyped]

        # Load each file separately then deep-merge so secrets overlay settings
        # without replacing the entire tenant table.
        base = Dynaconf(envvar_prefix="SCM_MCP", settings_files=["settings.toml"], load_dotenv=True)
        secrets = Dynaconf(
            envvar_prefix="SCM_MCP", settings_files=[".secrets.toml"], load_dotenv=False
        )

        base_tenants: dict[str, Any] = dict(base.get("tenants") or {})
        secret_tenants: dict[str, Any] = dict(secrets.get("tenants") or {})

        # Merge: start with base, overlay secrets key-by-key
        tenants_raw: dict[str, Any] = {}
        all_keys = set(base_tenants) | set(secret_tenants)
        for key in all_keys:
            merged = dict(base_tenants.get(key) or {})
            merged.update(secret_tenants.get(key) or {})
            tenants_raw[key] = merged

        # A [tenants.*] section that exists only in .secrets.toml (no matching
        # settings.toml entry) can never be applied — almost always a name typo.
        # Flag it loudly so it isn't silently dropped.
        for orphan in set(secret_tenants) - set(base_tenants):
            logger.warning(
                "tenant_secret_section_orphaned",
                tenant_label=orphan,
                hint="no matching [tenants.*] in settings.toml — check for a typo",
            )

        for name, cfg in tenants_raw.items():
            try:
                tc = TenantConfig(**cfg)
                # Keep the section key so tools accept it as a tenant_id alias.
                register_tenant_key(name, tc.tenant_id)
                get_scm_client(tc)
                logger.info("tenant_preloaded", tenant_label=name, tenant_id=tc.tenant_id)
            except Exception as exc:
                logger.warning("tenant_preload_failed", tenant_label=name, error=str(exc))
    except ImportError:
        pass
    except Exception as exc:
        logger.warning("dynaconf_tenant_load_failed", error=str(exc))


def _registrars(
    get_client: Callable[..., Any],
    get_settings: Callable[[], Any],
) -> dict[str, Callable[[FastMCP], None]]:
    """Map each register_* function name to a call, in tool listing order.

    Built per call (not at import) so the lambdas resolve module globals at
    registration time — hot reload patches those globals, and ``scm_reload``
    must pick up the fresh registrars. Keys are what ``toolsets.TOOLSETS`` uses.
    """
    return {
        "register_object_tools": lambda m: register_object_tools(m, get_client),
        "register_security_tools": lambda m: register_security_tools(m, get_client),
        "register_ssr_tools": lambda m: register_ssr_tools(m, get_client),
        "register_network_tools": lambda m: register_network_tools(m, get_client),
        "register_deployment_tools": lambda m: register_deployment_tools(m, get_client),
        "register_setup_tools": lambda m: register_setup_tools(m, get_client),
        "register_audit_tools": lambda m: register_audit_tools(m, get_client),
        "register_cdl_logforwarding_tools": lambda m: register_cdl_logforwarding_tools(
            m, get_client
        ),
        "register_compliance_tools": lambda m: register_compliance_tools(m, get_client),
        "register_config_cleanup_tools": lambda m: register_config_cleanup_tools(m, get_client),
        "register_config_index_tools": lambda m: register_config_index_tools(m, get_client),
        "register_policy_optimizer_tools": lambda m: register_policy_optimizer_tools(m, get_client),
        "register_config_orch_tools": lambda m: register_config_orch_tools(m, get_client),
        "register_site_management_tools": lambda m: register_site_management_tools(m, get_client),
        "register_mssp_tools": lambda m: register_mssp_tools(m, get_client, get_settings),
        "register_capability_tools": lambda m: register_capability_tools(m, get_client),
        "register_casb_dlp_tools": lambda m: register_casb_dlp_tools(m, get_client),
        "register_ngfw_airs_tools": lambda m: register_ngfw_airs_tools(m, get_client),
        "register_dlp_tools": lambda m: register_dlp_tools(m, get_client),
        "register_dns_security_tools": lambda m: register_dns_security_tools(m, get_client),
        "register_email_dlp_tools": lambda m: register_email_dlp_tools(m, get_client),
        "register_sdwan_tools": lambda m: register_sdwan_tools(m, get_client),
        "register_ncsc_tools": lambda m: register_ncsc_tools(m, get_client),
        "register_ai_advisor_tools": lambda m: register_ai_advisor_tools(m, get_client),
        "register_aiops_tools": lambda m: register_aiops_tools(m, get_client),
        "register_posture_tools": lambda m: register_posture_tools(m, get_client),
        "register_adnsr_tools": lambda m: register_adnsr_tools(m, get_client),
        "register_ops_tools": lambda m: register_ops_tools(m, get_client),
        "register_cert_transfer_tools": lambda m: register_cert_transfer_tools(m, get_client),
        "register_msr_tools": lambda m: register_msr_tools(m, get_client),
        "register_spi_tools": lambda m: register_spi_tools(m, get_client),
        "register_pab_msp_tools": lambda m: register_pab_msp_tools(m, get_client),
        "register_pab_tools": lambda m: register_pab_tools(m, get_client),
        "register_service_status_tools": lambda m: register_service_status_tools(m, get_client),
        "register_planner_tools": lambda m: register_planner_tools(m, get_client),
        "register_insights_tools": lambda m: register_insights_tools(m, get_client),
        "register_mt_monitor_tools": lambda m: register_mt_monitor_tools(m, get_client),
        "register_adem_tools": lambda m: register_adem_tools(m, get_client),
        "register_csp_licensing_tools": lambda m: register_csp_licensing_tools(m),
    }


def remove_write_tools(mcp: FastMCP) -> list[str]:
    """Drop every tool ``_is_write_tool`` flags (read-only mode); return removed names."""
    tm = mcp._tool_manager
    removed: list[str] = []
    for tool in list(tm.list_tools()):
        if tool.name in ALWAYS_ON_TOOLS:
            continue
        if _is_write_tool(tool.name):
            tm.remove_tool(tool.name)
            removed.append(tool.name)
    return removed


def register_all_tools(
    mcp: FastMCP,
    get_client: Callable[..., Any],
    get_settings: Callable[[], Any],
    toolsets: Iterable[str] | None = None,
    read_only: bool = False,
) -> None:
    """Register every MCP tool except the hot-reload tool itself.

    Kept separate from ``create_server`` so ``scm_reload`` can re-run it after a
    hot reload — re-decorating the tools replaces the closures FastMCP registered
    at startup, so edits to a tool's own body actually take effect.

    Args:
        toolsets: Toolset / profile names to register (see ``toolsets.py``).
            ``None`` or empty registers everything; ``core`` is always included.
            Unknown names raise ``UnknownToolsetError``.
        read_only: When true, remove write-capable tools after registration.
    """
    wanted = registrars_for(resolve_toolsets(toolsets))
    for name, register in _registrars(get_client, get_settings).items():
        if name in wanted:
            register(mcp)

    if read_only:
        remove_write_tools(mcp)

    # Every tool taking tenant_id accepts TSG ID, settings key or label.
    install_tenant_resolution(mcp)

    # MCP ToolAnnotations (read-only / destructive / idempotent hints) are
    # applied centrally here so hot reload re-applies them too.
    apply_tool_annotations(mcp)


def create_server(
    toolsets: Iterable[str] | str | None = None,
    read_only: bool | None = None,
) -> FastMCP:
    """Initialise the MCP server with tools and resources registered.

    Args:
        toolsets: Toolset / profile names overriding ``settings.enabled_toolsets``
            (e.g. from ``--toolsets``). ``None`` falls back to settings.
        read_only: Overrides ``settings.read_only`` when not ``None``.
    """
    settings = get_settings()
    configure_logging(level=settings.log_level, json_logs=settings.log_json)

    # Resolve the filter up-front so a typo fails before any auth work.
    requested = settings.enabled_toolsets if toolsets is None else toolsets
    active_toolsets = resolve_toolsets(requested)
    ro = settings.read_only if read_only is None else read_only

    logger.info(
        "server_starting",
        name=settings.server_name,
        mssp_mode=settings.mssp_mode,
    )

    get_client = _build_client_resolver(settings)

    # Pre-load MSSP tenants if configured
    if settings.mssp_mode:
        _load_mssp_tenants_from_dynaconf(settings)
        loaded = list_loaded_tenants()
        logger.info("tenants_loaded", count=len(loaded), tenant_ids=loaded)
    else:
        # Eagerly validate default credentials on startup
        try:
            get_scm_client(settings.default_tenant())
            logger.info("default_tenant_authenticated", tenant_id=settings.scm_tenant_id)
        except Exception as exc:
            logger.warning("default_tenant_auth_skipped", reason=str(exc))

    # Register tools (all except the reload tool itself), honouring the
    # toolset filter and read-only mode.
    def _register() -> None:
        register_all_tools(mcp, get_client, get_settings, toolsets=active_toolsets, read_only=ro)

    _register()
    logger.info(
        "toolsets_active",
        toolsets=active_toolsets,
        filtered=len(active_toolsets) < len(TOOLSETS),
        read_only=ro,
        tool_count=len(mcp._tool_manager.list_tools()),
    )

    # The hot-reload tool can re-run register_all_tools so edits to a tool's own
    # body go live without a full process restart. The same filter is re-applied.
    register_reload_tool(mcp, reregister=_register)

    # Register resources
    register_tenant_resources(mcp)

    # Live interaction feed — instrument call_tool + register /dashboard routes
    instrument_server(mcp)
    register_dashboard(mcp)

    return mcp


def main() -> None:
    parser = argparse.ArgumentParser(description="SCM Harbourmaster server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="MCP transport (default: stdio)",
    )
    parser.add_argument("--host", default="127.0.0.1", help="SSE host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="SSE port (default: 8000)")
    parser.add_argument(
        "--toolsets",
        default=None,
        help=(
            "Comma-separated toolsets/profiles to load (overrides enabled_toolsets). "
            f"Toolsets: {', '.join(sorted(TOOLSETS))}. Profiles: {', '.join(sorted(PROFILES))}. "
            "Default: all."
        ),
    )
    parser.add_argument(
        "--read-only",
        action="store_true",
        default=None,
        help="Hide write-capable tools (overrides read_only setting).",
    )
    args = parser.parse_args()

    try:
        server = create_server(toolsets=args.toolsets, read_only=args.read_only)
    except UnknownToolsetError as exc:
        parser.error(str(exc))

    if args.transport == "sse":
        logger.info("transport_sse", host=args.host, port=args.port)
        server.run(transport="sse", host=args.host, port=args.port)  # type: ignore[call-arg]
    else:
        logger.info("transport_stdio")
        server.run(transport="stdio")


if __name__ == "__main__":
    main()
