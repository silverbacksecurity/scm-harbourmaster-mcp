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
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from mcp.server.fastmcp import FastMCP

from .auth.oauth import get_scm_client, list_loaded_tenants
from .config.settings import TenantConfig, get_settings
from .dashboard import instrument_server, register_dashboard
from .resources.tenant import register_tenant_resources
from .tools.adem import register_adem_tools
from .tools.adnsr import register_adnsr_tools
from .tools.ai_advisor import register_ai_advisor_tools
from .tools.aiops import register_aiops_tools
from .tools.audit import register_audit_tools
from .tools.cdl_logforwarding import register_cdl_logforwarding_tools
from .tools.compliance import register_compliance_tools
from .tools.config_cleanup import register_config_cleanup_tools
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
from .utils.logging import configure_logging, get_logger

if TYPE_CHECKING:
    from scm.client import Scm

logger = get_logger(__name__)

mcp = FastMCP(name="scm-harbourmaster-mcp")


def _build_client_resolver(settings: object) -> Callable[..., Any]:
    """
    Return a callable that resolves a TenantConfig → Scm client.

    In single-tenant mode the default credentials are always used.
    In MSSP mode the tenant_id argument selects among pre-loaded tenants.
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
                get_scm_client(tc)
                logger.info("tenant_preloaded", tenant_label=name, tenant_id=tc.tenant_id)
            except Exception as exc:
                logger.warning("tenant_preload_failed", tenant_label=name, error=str(exc))
    except ImportError:
        pass
    except Exception as exc:
        logger.warning("dynaconf_tenant_load_failed", error=str(exc))


def register_all_tools(
    mcp: FastMCP,
    get_client: Callable[..., Any],
    get_settings: Callable[[], Any],
) -> None:
    """Register every MCP tool except the hot-reload tool itself.

    Kept separate from ``create_server`` so ``scm_reload`` can re-run it after a
    hot reload — re-decorating the tools replaces the closures FastMCP registered
    at startup, so edits to a tool's own body actually take effect.
    """
    register_object_tools(mcp, get_client)
    register_security_tools(mcp, get_client)
    register_ssr_tools(mcp, get_client)
    register_network_tools(mcp, get_client)
    register_deployment_tools(mcp, get_client)
    register_setup_tools(mcp, get_client)
    register_audit_tools(mcp, get_client)
    register_cdl_logforwarding_tools(mcp, get_client)
    register_compliance_tools(mcp, get_client)
    register_config_cleanup_tools(mcp, get_client)
    register_policy_optimizer_tools(mcp, get_client)
    register_config_orch_tools(mcp, get_client)
    register_site_management_tools(mcp, get_client)
    register_mssp_tools(mcp, get_client, get_settings)
    register_casb_dlp_tools(mcp, get_client)
    register_ngfw_airs_tools(mcp, get_client)
    register_dlp_tools(mcp, get_client)
    register_dns_security_tools(mcp, get_client)
    register_email_dlp_tools(mcp, get_client)
    register_sdwan_tools(mcp, get_client)
    register_ncsc_tools(mcp, get_client)
    register_ai_advisor_tools(mcp, get_client)
    register_aiops_tools(mcp, get_client)
    register_posture_tools(mcp, get_client)
    register_adnsr_tools(mcp, get_client)
    register_ops_tools(mcp, get_client)
    register_msr_tools(mcp, get_client)
    register_spi_tools(mcp, get_client)
    register_pab_msp_tools(mcp, get_client)
    register_pab_tools(mcp, get_client)
    register_service_status_tools(mcp, get_client)
    register_planner_tools(mcp, get_client)
    register_insights_tools(mcp, get_client)
    register_mt_monitor_tools(mcp, get_client)
    register_adem_tools(mcp, get_client)
    register_csp_licensing_tools(mcp)


def create_server() -> FastMCP:
    """Initialise the MCP server with all tools and resources registered."""
    settings = get_settings()
    configure_logging(level=settings.log_level, json_logs=settings.log_json)

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

    # Register tools (all except the reload tool itself)
    register_all_tools(mcp, get_client, get_settings)

    # The hot-reload tool can re-run register_all_tools so edits to a tool's own
    # body go live without a full process restart.
    register_reload_tool(mcp, reregister=lambda: register_all_tools(mcp, get_client, get_settings))

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
    args = parser.parse_args()

    server = create_server()

    if args.transport == "sse":
        logger.info("transport_sse", host=args.host, port=args.port)
        server.run(transport="sse", host=args.host, port=args.port)  # type: ignore[call-arg]
    else:
        logger.info("transport_stdio")
        server.run(transport="stdio")


if __name__ == "__main__":
    main()
