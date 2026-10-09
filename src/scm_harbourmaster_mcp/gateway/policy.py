"""What a gateway key may see and call. Everything here fails closed.

``allowed_tools`` decides visibility and ``check_call`` the per-call
arguments. ``GET /v1/tools`` and ``POST /v1/tools/{name}/call`` both go
through ``allowed_tools``, so the two can't disagree.

A tool is visible to a key only when:

* it is in one of the key's toolsets and not in :data:`NEVER_REST`;
* the manifest classifies it (unknown access or scope → hidden);
* it is a read tool, or the key has ``access = "write"`` and
  ``SCM_MCP_HTTP_REST_WRITE`` is on;
* for a key limited to some tenants: the tool is ``scope: tenant``, takes a
  ``tenant_id`` (tools without one run on the default tenant or read shared
  job stores by ID), and has no tenant-like parameter this module doesn't
  know how to check.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Mapping
from typing import Any

from ..toolsets import TOOLSETS
from .keys import GatewayKey

# Never callable over REST, whatever the key says: they push or roll back
# config on the firewalls, run other tools with approvals (scm_planner_run
# takes approved_write_tools=["scm_commit"]), or control this process.
NEVER_REST: frozenset[str] = frozenset(
    {
        "scm_commit",
        "scm_config_push_track",
        "scm_config_rollback",
        "scm_planner_run",
        "scm_restart",
        "scm_reload",
        "mssp_evict_tenant",
    }
)

# Parameters that name a file on the server. Refused over REST: a remote
# caller must not choose paths to write (save_to, output_dir) or read
# another tenant's backups (backup_file*). Kept complete by a registry scan
# in tests/unit/test_gateway.py.
PATH_PARAMS: frozenset[str] = frozenset(
    {
        "save_to",
        "output_dir",
        "backup_file",
        "backup_file_a",
        "backup_file_b",
        "source_backup_file",
    }
)

# Parameters that select a tenant; each value must be one the key may use.
TENANT_PARAMS: frozenset[str] = frozenset({"tenant_id", "target_tenant_id", "tsg_id"})

# Parameters that widen a call to several or all tenants. A key limited to
# some tenants may not set them.
CROSS_TENANT_PARAMS: frozenset[str] = frozenset(
    {"all_tenants", "include_tenants_associated", "tenants", "tenant_scope"}
)

# Tenant-sounding parameters that select nothing (display text only).
TENANT_DISPLAY_PARAMS: frozenset[str] = frozenset({"tenant_label"})

_TENANTISH = re.compile(r"tenant|tsg", re.IGNORECASE)


class GatewayDenied(Exception):
    """A request the gateway refuses. ``status`` is the HTTP status to return."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def rest_writes_enabled() -> bool:
    return os.getenv("SCM_MCP_HTTP_REST_WRITE", "").lower() in ("1", "true", "yes")


def tools_by_toolset(mcp: Any) -> dict[str, frozenset[str]]:
    """toolset → names of the tools *mcp* has registered.

    Every tool is defined inside its ``register_*`` function, so its
    ``__qualname__`` names the registrar (``register_sdwan_tools.<locals>.…``),
    and ``TOOLSETS`` maps registrars to toolsets. Nothing is re-registered.
    A tool whose registrar isn't in ``TOOLSETS`` is in no toolset, so no key
    can see it.
    """
    owner = {reg: ts for ts, regs in TOOLSETS.items() for reg in regs}
    out: dict[str, set[str]] = {}
    for tool in mcp._tool_manager.list_tools():
        registrar = getattr(tool.fn, "__qualname__", "").split(".<locals>", 1)[0]
        toolset = owner.get(registrar)
        if toolset:
            out.setdefault(toolset, set()).add(tool.name)
    return {ts: frozenset(names) for ts, names in out.items()}


def _policy(name: str) -> Any | None:
    from ..planner.manifest import UnknownToolError, load_manifest

    try:
        return load_manifest().policy(name)
    except UnknownToolError:
        return None


def _unhandled_tenant_params(schema: Mapping[str, Any]) -> list[str]:
    known = TENANT_PARAMS | CROSS_TENANT_PARAMS | TENANT_DISPLAY_PARAMS
    props = (schema or {}).get("properties") or {}
    return [p for p in props if _TENANTISH.search(p) and p not in known]


def tool_visible(
    key: GatewayKey,
    name: str,
    schema: Mapping[str, Any],
    toolset_map: Mapping[str, frozenset[str]],
) -> bool:
    if name in NEVER_REST:
        return False
    in_scope = any(name in toolset_map.get(ts, frozenset()) for ts in key.toolsets)
    if not in_scope:
        return False
    policy = _policy(name)
    if policy is None or policy.access not in ("read", "write"):
        return False
    if policy.access == "write" and not (key.can_write and rest_writes_enabled()):
        return False
    if not key.all_tenants:
        if policy.scope != "tenant":
            return False
        if "tenant_id" not in ((schema or {}).get("properties") or {}):
            return False
        if _unhandled_tenant_params(schema):
            return False
    return True


def allowed_tools(
    key: GatewayKey, tools: Iterable[Any], toolset_map: Mapping[str, frozenset[str]]
) -> dict[str, Any]:
    """name → MCP Tool for every tool *key* may see and call."""
    return {t.name: t for t in tools if tool_visible(key, t.name, t.inputSchema or {}, toolset_map)}


def _canonical(value: str) -> str:
    from ..auth.oauth import resolve_tenant_id

    try:
        return resolve_tenant_id(value, strict=True)
    except Exception as exc:  # TenantNotFoundError and friends
        raise GatewayDenied(403, f"tenant not permitted: {value}") from exc


def _default_tenant() -> str:
    """The TSG ID an empty ``tenant_id`` runs against ("" when none is set)."""
    from ..config.settings import get_settings

    try:
        return str(get_settings().scm_tenant_id or "")
    except Exception:
        return ""


def _tenants_refusing(provider: str) -> list[str]:
    """Loaded tenants whose ``allowed_llm_providers`` excludes *provider*."""
    from ..auth.oauth import list_loaded_tenants

    refusing = []
    for tenant in list_loaded_tenants():
        allowed = _allowed_llm_providers(tenant)
        if allowed is not None and provider not in allowed:
            refusing.append(tenant)
    return refusing


def _allowed_llm_providers(tenant_id: str) -> list[str] | None:
    """A tenant's ``allowed_llm_providers`` list, or None when it sets none."""
    from ..auth.oauth import get_tenant_meta

    cfg = get_tenant_meta(tenant_id)
    raw = getattr(cfg, "allowed_llm_providers", None) if cfg is not None else None
    return None if raw is None else [str(p).strip().lower() for p in raw]


def check_call(
    key: GatewayKey,
    schema: Mapping[str, Any],
    arguments: Mapping[str, Any],
    scope: str = "tenant",
) -> tuple[dict[str, Any], list[str]]:
    """Check one call's arguments. Returns (arguments to run with, tenants touched).

    Tenant values are replaced by their canonical TSG ID, so the value that
    was checked is the value the tool runs with. *scope* is the tool's
    manifest scope (``tenant`` or ``cross_tenant``).
    """
    args = dict(arguments)
    props = (schema or {}).get("properties") or {}

    unknown = sorted(set(args) - set(props))
    if unknown:
        raise GatewayDenied(400, f"unknown argument(s): {', '.join(unknown)}")

    used_paths = sorted(p for p in PATH_PARAMS if args.get(p) not in (None, ""))
    if used_paths:
        raise GatewayDenied(
            403, f"file-path parameters are not available over REST: {', '.join(used_paths)}"
        )

    touched: list[str] = []
    if key.all_tenants:
        for p in TENANT_PARAMS & set(args):
            if args[p]:
                args[p] = _canonical(str(args[p])) or str(args[p])
                touched.append(args[p])
        if "tenant_id" in props and not args.get("tenant_id") and _default_tenant():
            touched.append(_default_tenant())  # what an empty tenant_id runs against
        spans_tenants = (
            scope != "tenant"
            or "tenant_id" not in props
            or any(args.get(p) for p in CROSS_TENANT_PARAMS)
        )
        if spans_tenants:
            refusing = _tenants_refusing(key.llm_provider)
            if refusing:
                raise GatewayDenied(
                    403,
                    f"LLM provider '{key.llm_provider or 'unspecified'}' is not allowed by "
                    f"tenant(s) {', '.join(sorted(refusing))}, so this key can't make "
                    "calls that span or default across tenants",
                )
    else:
        widening = sorted(p for p in CROSS_TENANT_PARAMS if args.get(p))
        if widening:
            raise GatewayDenied(
                403, f"this key is limited to specific tenants: {', '.join(widening)}"
            )
        permitted = {_canonical(t) for t in key.tenants}
        for p in sorted(TENANT_PARAMS & set(props)):
            value = str(args.get(p) or "").strip()
            if not value:
                if p != "tenant_id":
                    continue  # optional selectors (tsg_id) default to tenant_id
                if len(key.tenants) != 1:
                    raise GatewayDenied(400, "tenant_id is required for this key")
                value = key.tenants[0]
            canonical = _canonical(value)
            if not canonical or canonical not in permitted:
                raise GatewayDenied(403, f"tenant not permitted: {value}")
            args[p] = canonical
            touched.append(canonical)
        if not touched:  # fail closed: a limited key always names its tenant
            raise GatewayDenied(400, "tenant_id is required for this key")

    for tenant in touched:
        allowed = _allowed_llm_providers(tenant)
        if allowed is not None and key.llm_provider not in allowed:
            raise GatewayDenied(
                403,
                f"tenant {tenant} does not allow LLM provider "
                f"'{key.llm_provider or 'unspecified'}'",
            )
    return args, touched
