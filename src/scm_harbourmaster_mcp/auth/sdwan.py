"""
Prisma SD-WAN client management.

Uses the same service-account credentials (client_id / client_secret / tsg_id)
as the SCM OAuth2 client — no additional credentials required.

Clients are cached per tsg_id for the lifetime of the process.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any

from ..utils.errors import AuthenticationError
from ..utils.logging import get_logger

if TYPE_CHECKING:
    from ..config.settings import TenantConfig

logger = get_logger(__name__)

_lock = threading.Lock()
_clients: dict[str, Any] = {}


def get_sdwan_client(
    client_id_or_tenant: str | TenantConfig,
    client_secret: str | None = None,
    tsg_id: str | None = None,
) -> Any:
    """
    Return a cached prisma_sase.API client, authenticating with service-account
    credentials if needed.

    Accepts either a TenantConfig object as the sole argument, or the three
    positional strings (client_id, client_secret, tsg_id).

    Raises AuthenticationError on failure.
    """
    # Duck-type check instead of isinstance so that hot-reloads of config.settings
    # (which create a new TenantConfig class) don't break cached TenantConfig instances.
    if hasattr(client_id_or_tenant, "client_id") and hasattr(client_id_or_tenant, "tenant_id"):
        tc = client_id_or_tenant
        client_id = tc.client_id  # type: ignore[union-attr]
        client_secret = tc.client_secret.get_secret_value()  # type: ignore[union-attr]
        tsg_id = tc.tenant_id  # type: ignore[union-attr]
    else:
        client_id = client_id_or_tenant
        if client_secret is None or tsg_id is None:
            raise ValueError(
                "client_secret and tsg_id are required when not passing a TenantConfig"
            )
    with _lock:
        if tsg_id not in _clients:
            try:
                import prisma_sase  # type: ignore[import-untyped]
            except ImportError as exc:
                raise AuthenticationError(
                    "prisma-sase package not installed — run: uv add prisma-sase"
                ) from exc

            sdk = prisma_sase.API(update_check=False)
            logger.info("sdwan_client_init", tsg_id=tsg_id)
            ok = sdk.interactive.login_secret(
                client_id=client_id,
                client_secret=client_secret,
                tsg_id=tsg_id,
            )
            if not ok:
                raise AuthenticationError(f"Prisma SD-WAN authentication failed for TSG {tsg_id!r}")
            logger.info("sdwan_client_ready", tsg_id=tsg_id)
            _clients[tsg_id] = sdk
        return _clients[tsg_id]


def safe_items(response: Any) -> list[dict[str, Any]]:
    """Extract the items list from a prisma-sase response object."""
    if response is None or not getattr(response, "sdk_status", False):
        return []
    content = getattr(response, "sdk_content", {}) or {}
    return list(content.get("items", [content] if content else []))
