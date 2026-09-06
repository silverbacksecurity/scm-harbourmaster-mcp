"""
Pydantic-settings configuration with multi-tenant MSSP support.

Priority (highest to lowest):
  1. Environment variables (SCM_*)
  2. .secrets.toml (dynaconf, git-ignored)
  3. settings.toml (dynaconf)
  4. .env file
"""

from __future__ import annotations

import functools
from typing import Any, Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from ..utils.logging import get_logger

logger = get_logger(__name__)

ServiceTier = Literal["gold", "silver", "bronze"]


class TenantConfig(BaseSettings):
    """Per-tenant SCM credentials, folder context, and MSSP service tier."""

    model_config = SettingsConfigDict(populate_by_name=True)

    tenant_id: str = Field(..., description="SCM tenant/TSG ID")
    client_id: str = Field(..., description="OAuth2 client ID")
    client_secret: SecretStr = Field(..., description="OAuth2 client secret")
    # Folder is the MSSP customer context within SCM
    default_folder: str = Field("Shared", description="Default SCM folder for this tenant")
    label: str = Field("", description="Human-readable customer name")

    # ── MSSP commercial fields ──────────────────────────────────────────────
    tier: ServiceTier = Field(
        "bronze",
        description=(
            "MSSP service tier: gold (full CAF v4.0), silver (CE Plus), bronze (CE baseline)"
        ),
    )
    service_term_years: int = Field(
        1,
        description="Contract term in years (1, 2, or 3)",
        ge=1,
        le=3,
    )
    account_ref: str = Field("", description="CRM / ticketing system account reference")

    # ── Operational / regional fields ───────────────────────────────────────
    insights_region: str = Field(
        "eu",
        description=(
            "Prisma Access Insights X-PANW-Region header value for this tenant. "
            "Common values: eu, us, uk, sg, au. NL/DE/FR tenants → eu."
        ),
    )
    sdwan_only: bool = Field(
        False,
        description=(
            "True for tenants that run Prisma SD-WAN without Prisma Access. "
            "Skips PA-specific extraction (Remote Networks, Mobile Users, etc.) "
            "and defaults include_sdwan=True in AS-BUILT generation."
        ),
    )
    prisma_access_api_key: SecretStr | None = Field(
        None,
        description=(
            "Prisma Access Datapath API key for retrieving public egress IP addresses. "
            "Obtained from the Prisma Access admin portal under Settings → Service Setup → "
            "Prisma Access API Key.  When set, the AS-BUILT §8.1 Public Egress IP section "
            "is populated via POST https://api.prod.datapath.prismaaccess.com/getPrismaAccessIP/v2 "
            "instead of the SCM infrastructure API (which requires a separate OAuth scope)."
        ),
    )

    # ── SSR (Simple Service Requests) ───────────────────────────────────────
    ssr_objects: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "SSR-managed object names keyed by type. Maps operation type to the "
            "SCM object name the SSR tool is allowed to edit (e.g. "
            '{url_allow_list: "SSR-Allow-List", ssl_decrypt_exclude_rule: "SSR-Decrypt-Exclude"}). '
            "The tool only touches these named objects — it never edits a rulebase directly."
        ),
    )

    @field_validator("tenant_id", "client_id")
    @classmethod
    def not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("must not be empty")
        return v.strip()


class Settings(BaseSettings):
    """
    Global server settings.  Tenant credentials are loaded separately
    via dynaconf so multiple tenants can be configured in settings.toml
    without polluting the main environment.
    """

    model_config = SettingsConfigDict(
        env_prefix="SCM_MCP_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Server ─────────────────────────────────────────────────────────────
    server_name: str = Field("scm-harbourmaster-mcp", description="MCP server name")
    log_level: str = Field("INFO", description="Logging level")
    log_json: bool = Field(True, description="Emit structured JSON logs")

    # ── Default (single-tenant) SCM credentials ────────────────────────────
    # For MSSP mode these are superseded by the per-tenant configs in
    # settings.toml / .secrets.toml.
    scm_client_id: str = Field("", description="Default SCM OAuth2 client ID")
    scm_client_secret: SecretStr = Field(
        SecretStr(""), description="Default SCM OAuth2 client secret"
    )
    scm_tenant_id: str = Field("", description="Default SCM tenant/TSG ID")
    scm_default_folder: str = Field("Shared", description="Default SCM folder")

    # ── CSP (Customer Support Portal) — Software NGFW flexible licensing ───
    # A single global credential per CSP account (unlike scm_client_id/secret
    # above, this is not per-managed-tenant). Generated in CSP → Account
    # Management → OAuth API Management → fwflex-service scope.
    csp_client_id: str = Field("", description="CSP OAuth2 client ID (fwflex-service scope)")
    csp_client_secret: SecretStr = Field(
        SecretStr(""), description="CSP OAuth2 client secret (fwflex-service scope)"
    )

    # ── AI advisor ─────────────────────────────────────────────────────────
    anthropic_api_key: SecretStr = Field(
        SecretStr(""),
        description=(
            "Anthropic API key for AI compliance advisor. Also read from ANTHROPIC_API_KEY env var."
        ),
    )
    ai_advisor_model: str = Field(
        "claude-sonnet-4-6",
        description="Claude model ID to use for compliance advice generation.",
    )

    # ── WAN IP enrichment ──────────────────────────────────────────────────
    ip_enrichment_provider: str = Field(
        "ripe",
        description=(
            "IP-intelligence provider for WAN IP enrichment (enrich=true on "
            "the WAN IP tools): 'ripe' (stat.ripe.net, free, no key, HTTPS, "
            "ASN/holder/netname — recommended default), 'ip-api' (ip-api.com "
            "free batch tier, no key, HTTP-only, rate-limited), or 'ipinfo' "
            "(ipinfo.io, HTTPS, optional token for higher rate limits)."
        ),
    )
    ipinfo_token: SecretStr = Field(
        SecretStr(""),
        description="ipinfo.io API token — optional, raises rate limits and accuracy.",
    )

    # ── MSSP ───────────────────────────────────────────────────────────────
    mssp_mode: bool = Field(
        False,
        description=(
            "Enable MSSP multi-tenant mode.  When true the active tenant is "
            "resolved from the `tenant` tool argument rather than the defaults."
        ),
    )
    mssp_name: str = Field(
        "MSSP",
        description="MSSP operator name shown in report and discovery headers.",
    )

    def default_tenant(self) -> TenantConfig:
        return TenantConfig(
            tenant_id=self.scm_tenant_id,
            client_id=self.scm_client_id,
            client_secret=self.scm_client_secret,
            default_folder=self.scm_default_folder,
        )

    @classmethod
    def from_dynaconf(cls, extra: dict[str, Any] | None = None) -> Settings:
        """Build Settings, optionally merging values from dynaconf."""
        try:
            from dynaconf import Dynaconf  # type: ignore[import-untyped]

            d = Dynaconf(
                envvar_prefix="SCM_MCP",
                settings_files=["settings.toml", ".secrets.toml"],
                environments=True,
                load_dotenv=True,
            )
            raw = {k.lower(): v for k, v in d.as_dict().items()}
            # settings.toml uses short keys; map to Settings field names
            overrides: dict[str, Any] = {}
            for k, v in raw.items():
                if k == "tenant_id":
                    overrides["scm_tenant_id"] = v
                elif k == "client_id":
                    overrides["scm_client_id"] = v
                elif k == "client_secret":
                    overrides["scm_client_secret"] = v
                else:
                    overrides[k] = v
        except Exception:
            overrides = {}
        if extra:
            overrides.update(extra)
        return cls(**overrides)


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings.from_dynaconf()


def load_all_tenant_configs() -> dict[str, TenantConfig]:
    """Merge settings.toml + .secrets.toml `[tenants.*]` sections into TenantConfig objects.

    Secrets overlay base settings key-by-key per tenant so a customer's OAuth2
    credentials in the git-ignored .secrets.toml can be layered onto its
    non-secret metadata (folder, tier, label, ...) in the checked-in
    settings.toml. A tenant block that fails validation is skipped rather than
    aborting the whole load.
    """
    try:
        from dynaconf import Dynaconf  # type: ignore[import-untyped]
    except ImportError:
        return {}

    base = Dynaconf(envvar_prefix="SCM_MCP", settings_files=["settings.toml"], load_dotenv=True)
    secrets = Dynaconf(envvar_prefix="SCM_MCP", settings_files=[".secrets.toml"], load_dotenv=False)
    base_tenants: dict[str, Any] = dict(base.get("tenants") or {})
    secret_tenants: dict[str, Any] = dict(secrets.get("tenants") or {})

    result: dict[str, TenantConfig] = {}
    for key in set(base_tenants) | set(secret_tenants):
        merged = dict(base_tenants.get(key) or {})
        merged.update(secret_tenants.get(key) or {})
        try:
            result[key] = TenantConfig(**merged)
        except Exception as exc:
            logger.warning("tenant_config_invalid", tenant=key, error=str(exc))
    return result
