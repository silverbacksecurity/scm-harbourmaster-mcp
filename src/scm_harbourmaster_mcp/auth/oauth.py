"""
SCM OAuth2 client management with per-tenant caching.

Each tenant gets its own Scm client instance (which manages its own token
lifecycle).  Clients are cached for the lifetime of the process; under MSSP
multi-tenant mode the active client is selected by tenant_id at call time.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
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
_tenant_keys: dict[str, str] = {}  # settings.toml [tenants.<key>] section name -> TSG ID


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
    Look up a pre-cached client by tenant.

    *tenant_id* may be the numeric TSG ID, the settings.toml ``[tenants.<key>]``
    section name, or the tenant's ``label`` (see :func:`resolve_tenant_id`).

    Raises TenantNotFoundError if the tenant was never initialised (the message
    lists the valid tenants) or if a label matches more than one tenant.
    """
    tsg = resolve_tenant_id(tenant_id, strict=True)
    with _lock:
        client = _clients.get(tsg)
    if client is None:
        raise TenantNotFoundError(
            f"Tenant {tenant_id!r} is not configured or not yet loaded. "
            f"Valid tenants: {_describe_known(_known_tenants(include_configured=True))}"
        )
    return client


def list_loaded_tenants() -> list[str]:
    with _lock:
        return list(_clients.keys())


def get_tenant_meta(tenant_id: str) -> TenantConfig | None:
    """Return the cached TenantConfig for a loaded tenant, or None.

    Accepts any form :func:`resolve_tenant_id` understands; an ambiguous
    value returns None rather than raising.
    """
    try:
        tsg = resolve_tenant_id(tenant_id)
    except TenantNotFoundError:
        return None
    with _lock:
        return _tenant_configs.get(tsg)


# ── Tenant identifier resolution ─────────────────────────────────────────────
#
# Callers (humans and LLMs alike) naturally name a tenant by its settings.toml
# section key or its human label rather than the numeric TSG ID the SCM API
# needs. Every client/metadata lookup funnels through resolve_tenant_id so all
# three forms work everywhere, instead of each tool module re-inventing it.


def register_tenant_key(key: str, tenant_id: str) -> None:
    """Remember that settings.toml ``[tenants.<key>]`` maps to *tenant_id*."""
    if key and tenant_id:
        with _lock:
            _tenant_keys[key] = tenant_id


def _norm(value: str) -> str:
    """Case-insensitive, whitespace-tolerant comparison key."""
    return " ".join(str(value).split()).casefold()


@dataclass
class _KnownTenant:
    keys: set[str] = field(default_factory=set)
    label: str = ""


def _known_tenants(include_configured: bool) -> dict[str, _KnownTenant]:
    """Map TSG ID -> section keys + label, from the caches and optionally settings."""
    known: dict[str, _KnownTenant] = {}
    with _lock:
        for tsg, cfg in _tenant_configs.items():
            known.setdefault(tsg, _KnownTenant()).label = getattr(cfg, "label", "") or ""
        for tsg in _clients:
            known.setdefault(tsg, _KnownTenant())
        for key, tsg in _tenant_keys.items():
            known.setdefault(tsg, _KnownTenant()).keys.add(key)
    if include_configured:
        try:
            from ..config.settings import load_all_tenant_configs

            configured = load_all_tenant_configs()
        except Exception as exc:
            logger.warning("tenant_resolver_config_load_failed", error=str(exc))
            configured = {}
        for key, cfg in configured.items():
            tsg = str(getattr(cfg, "tenant_id", "") or "")
            if not tsg:
                continue
            entry = known.setdefault(tsg, _KnownTenant())
            entry.keys.add(key)
            entry.label = entry.label or (getattr(cfg, "label", "") or "")
    return known


def _describe_known(known: dict[str, _KnownTenant]) -> str:
    """Render tenants as ``key / Label (tsg)`` for error messages."""
    if not known:
        return "(none configured)"
    parts = []
    for tsg, entry in sorted(known.items()):
        names = sorted(entry.keys)
        if entry.label and _norm(entry.label) not in {_norm(k) for k in names}:
            names.append(entry.label)
        parts.append(f"{' / '.join(names)} ({tsg})" if names else tsg)
    return ", ".join(parts)


def _match(value: str, known: dict[str, _KnownTenant]) -> str | None:
    """Return the TSG ID *value* names, or None if nothing matches.

    Precedence: TSG ID, then section key, then label. A value naming more than
    one tenant within the winning tier raises TenantNotFoundError.
    """
    if value in known:
        return value
    wanted = _norm(value)
    tiers = (
        [tsg for tsg in known if _norm(tsg) == wanted],
        [tsg for tsg, e in known.items() if any(_norm(k) == wanted for k in e.keys)],
        [tsg for tsg, e in known.items() if e.label and _norm(e.label) == wanted],
    )
    for hits in tiers:
        if len(hits) == 1:
            return hits[0]
        if len(hits) > 1:
            candidates = {tsg: known[tsg] for tsg in hits}
            raise TenantNotFoundError(
                f"Tenant {value!r} is ambiguous; it matches {len(hits)} tenants: "
                f"{_describe_known(candidates)}. Pass the numeric tenant_id instead."
            )
    return None


def resolve_tenant_id(value: str, *, strict: bool = False) -> str:
    """Canonicalise a tenant reference to its numeric TSG ID.

    Accepts the TSG ID itself, the settings.toml ``[tenants.<key>]`` section
    name, or the tenant's ``label`` — case-insensitive and whitespace-tolerant.
    Loaded tenants are checked first; settings.toml is only read on a miss.

    An empty value returns "" (the caller's default tenant). A value matching
    several tenants always raises TenantNotFoundError listing the candidates.
    An unrecognised value is returned stripped but otherwise unchanged (so
    single-tenant mode and not-yet-loaded TSG IDs keep working), unless
    *strict* is set, tenants are configured and the value is not a bare
    numeric ID — then TenantNotFoundError lists the valid tenants.
    """
    raw = str(value or "").strip()
    if not raw:
        return ""
    with _lock:
        if raw in _clients or raw in _tenant_configs:
            return raw
    hit = _match(raw, _known_tenants(include_configured=False))
    if hit is not None:
        return hit
    known = _known_tenants(include_configured=True)
    hit = _match(raw, known)
    if hit is not None:
        return hit
    if strict and known and not raw.isdigit():
        raise TenantNotFoundError(
            f"Tenant {raw!r} is not configured. Valid tenants: {_describe_known(known)}"
        )
    return raw


def find_tenant_config(value: str) -> TenantConfig | None:
    """Return the TenantConfig for *value* (any accepted form), or None.

    Prefers the loaded-client cache, then falls back to settings.toml so a
    tenant whose SCM client never initialised (e.g. SD-WAN-only) still
    resolves. Raises TenantNotFoundError only for an ambiguous value.
    """
    tsg = resolve_tenant_id(value)
    if not tsg:
        return None
    with _lock:
        cfg = _tenant_configs.get(tsg)
    if cfg is not None:
        return cfg
    try:
        from ..config.settings import load_all_tenant_configs

        configured = load_all_tenant_configs()
    except Exception:
        return None
    return next(
        (c for c in configured.values() if str(getattr(c, "tenant_id", "")) == tsg),
        None,
    )


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
