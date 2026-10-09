"""Gateway API keys: storage, lookup and minting.

Keys live in ``.secrets.toml`` as SHA-256 hashes, never in clear::

    [gateway_keys.noc-deepseek]
    key_sha256 = "…"               # from: python -m scm_harbourmaster_mcp.gateway.keys new
    access = "read"                # read | write (write also needs SCM_MCP_HTTP_REST_WRITE=1)
    tenants = ["1234567890"]       # TSG IDs, settings keys or labels; ["*"] = every tenant
    toolsets = ["noc"]             # toolset / profile names, required
    rate_per_minute = 60           # optional, default 60
    llm_provider = "deepseek"      # optional; checked against a tenant's allowed_llm_providers

A gateway key is valid on ``/v1`` only. ``SCM_MCP_HTTP_API_KEY`` and Entra
tokens are not accepted there, so ``/v1`` access is always scoped.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import secrets
import sys
from dataclasses import dataclass
from typing import Any

from ..toolsets import UnknownToolsetError, resolve_toolsets
from ..utils.logging import get_logger

logger = get_logger(__name__)

ALL_TENANTS = "*"
KEY_PREFIX = "hmg_"
DEFAULT_RATE_PER_MINUTE = 60


class KeyConfigError(ValueError):
    """A ``[gateway_keys.*]`` entry is malformed."""


@dataclass(frozen=True)
class GatewayKey:
    key_id: str
    key_sha256: str
    access: str
    tenants: tuple[str, ...]
    toolsets: tuple[str, ...]
    rate_per_minute: int = DEFAULT_RATE_PER_MINUTE
    llm_provider: str = ""

    @property
    def all_tenants(self) -> bool:
        return ALL_TENANTS in self.tenants

    @property
    def can_write(self) -> bool:
        return self.access == "write"


def hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def parse_key(key_id: str, entry: Any) -> GatewayKey:
    """Validate one ``[gateway_keys.<key_id>]`` table. Raises KeyConfigError."""
    if not isinstance(entry, dict):
        raise KeyConfigError(f"gateway_keys.{key_id}: must be a table")
    e = {str(k).lower(): v for k, v in entry.items()}
    digest = str(e.get("key_sha256") or "").strip().lower()
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise KeyConfigError(f"gateway_keys.{key_id}: key_sha256 must be a SHA-256 hex digest")
    access = str(e.get("access") or "read").strip().lower()
    if access not in ("read", "write"):
        raise KeyConfigError(f"gateway_keys.{key_id}: access must be 'read' or 'write'")
    tenants = tuple(str(t).strip() for t in (e.get("tenants") or []) if str(t).strip())
    if not tenants:
        raise KeyConfigError(f'gateway_keys.{key_id}: tenants is required (use ["*"] for all)')
    raw_toolsets = e.get("toolsets") or []
    if not raw_toolsets:
        raise KeyConfigError(f"gateway_keys.{key_id}: toolsets is required")
    try:
        toolsets = tuple(resolve_toolsets(raw_toolsets))
    except UnknownToolsetError as exc:
        raise KeyConfigError(f"gateway_keys.{key_id}: {exc}") from exc
    try:
        raw_rate = e.get("rate_per_minute")
        rate = DEFAULT_RATE_PER_MINUTE if raw_rate in (None, "") else int(raw_rate)
    except (TypeError, ValueError) as exc:
        raise KeyConfigError(f"gateway_keys.{key_id}: rate_per_minute must be an integer") from exc
    if rate < 1:
        raise KeyConfigError(f"gateway_keys.{key_id}: rate_per_minute must be at least 1")
    return GatewayKey(
        key_id=key_id,
        key_sha256=digest,
        access=access,
        tenants=tenants,
        toolsets=toolsets,
        rate_per_minute=rate,
        llm_provider=str(e.get("llm_provider") or "").strip().lower(),
    )


def load_keys(raw: dict[str, Any] | None = None) -> dict[str, GatewayKey]:
    """Load every gateway key. A malformed entry is skipped and logged, never fatal."""
    if raw is None:
        from dynaconf import Dynaconf  # type: ignore[import-untyped]

        settings = Dynaconf(
            envvar_prefix="SCM_MCP",
            settings_files=["settings.toml", ".secrets.toml"],
            load_dotenv=False,
        )
        raw = dict(settings.get("gateway_keys") or {})
    keys: dict[str, GatewayKey] = {}
    for key_id, entry in (raw or {}).items():
        try:
            keys[str(key_id)] = parse_key(str(key_id), dict(entry))
        except (KeyConfigError, TypeError, ValueError) as exc:
            logger.error("gateway_key_invalid", key_id=str(key_id), error=str(exc))
    return keys


def authenticate(provided: str | None, keys: dict[str, GatewayKey]) -> GatewayKey | None:
    """Return the key matching *provided*, comparing every hash in constant time."""
    if not provided:
        return None
    digest = hash_key(provided.strip())
    match: GatewayKey | None = None
    for key in keys.values():
        if hmac.compare_digest(digest, key.key_sha256):
            match = key
    return match


def main(argv: list[str] | None = None) -> int:
    """``python -m scm_harbourmaster_mcp.gateway.keys new --id <name> …``"""
    ap = argparse.ArgumentParser(description="Mint a gateway API key")
    sub = ap.add_subparsers(dest="cmd", required=True)
    new = sub.add_parser("new", help="generate a key and print its .secrets.toml entry")
    new.add_argument("--id", required=True, help="key name, e.g. noc-deepseek")
    new.add_argument("--tenants", required=True, help='comma-separated tenants, or "*"')
    new.add_argument("--toolsets", required=True, help="comma-separated toolsets/profiles")
    new.add_argument("--access", choices=("read", "write"), default="read")
    new.add_argument("--llm-provider", default="")
    args = ap.parse_args(argv)

    raw = KEY_PREFIX + secrets.token_urlsafe(32)
    tenants = [t.strip() for t in args.tenants.split(",") if t.strip()]
    toolsets = [t.strip() for t in args.toolsets.split(",") if t.strip()]
    entry = {
        "key_sha256": hash_key(raw),
        "access": args.access,
        "tenants": tenants,
        "toolsets": toolsets,
    }
    if args.llm_provider:
        entry["llm_provider"] = args.llm_provider
    parse_key(args.id, entry)  # fail now on a bad toolset, not at server start

    def _toml(v: Any) -> str:
        return "[" + ", ".join(f'"{x}"' for x in v) + "]" if isinstance(v, list) else f'"{v}"'

    print(f"API key (shown once, give it to the client): {raw}\n", file=sys.stderr)
    print(f"[gateway_keys.{args.id}]")
    for k, v in entry.items():
        print(f"{k} = {_toml(v)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
