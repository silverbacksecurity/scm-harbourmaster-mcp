"""
SCM OAuth2 client management with per-tenant caching.

Each tenant gets its own Scm client instance (which manages its own token
lifecycle).  Clients are cached for the lifetime of the process; under MSSP
multi-tenant mode the active client is selected by tenant_id at call time.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from pydantic import SecretStr
from scm.client import Scm

from ..utils.errors import AuthenticationError, TenantNotFoundError
from ..utils.logging import get_logger

if TYPE_CHECKING:
    from ..config.settings import TenantConfig

logger = get_logger(__name__)

_lock = threading.Lock()
_clients: dict[str, Scm] = {}
_tenant_configs: dict[str, TenantConfig] = {}  # mirrors _clients; stores config metadata


class TenantCredentials:
    """Thin wrapper that resolves a TenantConfig to an Scm client."""

    def __init__(self, config: TenantConfig) -> None:
        self.config = config

    def client(self) -> Scm:
        return get_scm_client(self.config)


def get_scm_client(config: TenantConfig) -> Scm:
    """Return a cached Scm client for the given tenant, creating one if needed."""
    tenant_id = config.tenant_id
    with _lock:
        if tenant_id not in _clients:
            logger.info("initializing_scm_client", tenant_id=tenant_id, label=config.label)
            try:
                client = Scm(
                    client_id=config.client_id,
                    client_secret=config.client_secret.get_secret_value()
                    if isinstance(config.client_secret, SecretStr)
                    else config.client_secret,
                    tsg_id=tenant_id,
                )
            except Exception as exc:
                raise AuthenticationError(
                    f"Failed to authenticate tenant {tenant_id!r}: {exc}"
                ) from exc
            _clients[tenant_id] = client
            _tenant_configs[tenant_id] = config
        return _clients[tenant_id]


def get_client_for_tenant(tenant_id: str) -> Scm:
    """
    Look up a pre-cached client by tenant_id.

    Raises TenantNotFoundError if the tenant was never initialised.
    """
    with _lock:
        client = _clients.get(tenant_id)
    if client is None:
        raise TenantNotFoundError(f"Tenant {tenant_id!r} is not configured or not yet loaded.")
    return client


def list_loaded_tenants() -> list[str]:
    with _lock:
        return list(_clients.keys())


def get_tenant_meta(tenant_id: str) -> TenantConfig | None:
    """Return the cached TenantConfig for a loaded tenant, or None."""
    with _lock:
        return _tenant_configs.get(tenant_id)


def evict_tenant(tenant_id: str) -> bool:
    """Remove a cached client (e.g. after credential rotation)."""
    with _lock:
        return _clients.pop(tenant_id, None) is not None


_SUBSCRIPTION_API = "https://api.sase.paloaltonetworks.com/subscription/v1/licenses"


def fetch_licenses(client: Scm) -> list[dict]:
    """Retrieve all subscription licences for the TSG bound to *client*.

    Reuses the OAuth session the Scm client already holds, refreshing the
    token first if it has expired or is expiring soon.
    Returns the raw list of licence bundle dicts from the Subscription
    Service API, or [] on non-2xx / missing session.
    """
    session = getattr(client, "session", None)
    if session is None:
        return []

    # Refresh token if expired or about to expire
    oauth = getattr(client, "oauth_client", None)
    if oauth is not None:
        try:
            if oauth.is_expired or oauth.token_expires_soon:
                oauth.refresh_token()
                logger.info("fetch_licenses_token_refreshed")
        except Exception as exc:
            logger.warning("fetch_licenses_token_refresh_failed", error=str(exc))

    resp = session.get(_SUBSCRIPTION_API, timeout=(5, 15))
    if resp.status_code != 200:
        logger.warning("fetch_licenses_failed", status=resp.status_code)
        return []
    data = resp.json()
    return data if isinstance(data, list) else data.get("items", [])
