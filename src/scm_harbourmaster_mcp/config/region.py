"""One place to decide which X-PANW-Region a tenant's requests carry.

Several SASE APIs (Prisma Access Insights, the multitenant Monitor/agg API,
the Compliance Center) select a *data region* with the ``X-PANW-Region``
header, and none of them reject a wrong one: a missing, misspelled or
wrongly-cased value is answered with HTTP 200 and an empty-looking payload.
A tenant configured ``insights_region = "eu"`` whose data actually lives in
``uk`` therefore produces reports full of zeroes rather than an error.

Every header sender resolves the value through :func:`resolve_region`, in
this order:

  1. ``explicit`` — a per-call override (a tool's ``region=`` argument) or an
     API-specific setting the caller owns (``compliance_region``);
  2. the tenant's ``region`` in settings.toml (``[tenants.<key>] region``);
  3. the region detected by ``mssp_detect_region`` for this tenant, cached in
     process memory;
  4. ``default`` — the caller's pre-existing fallback (usually the tenant's
     ``insights_region`` mapped to a header value, else ``europe``).

The result is always normalised to a lowercase header value: the settings
shorthand ``eu``/``us`` becomes ``europe``/``americas``, and case is folded
because the APIs only answer to lowercase codes.

This module has no HTTP code; the probing lives in ``tools/region_detect.py``.
It also contains the format-preserving settings.toml edit used by
``mssp_detect_region(persist=True)``.
"""

from __future__ import annotations

import os
import re
import tempfile
import threading
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# settings.toml shorthand -> X-PANW-Region header value. `uk`, `sg`, `au` and
# the rest are the same in both vocabularies.
REGION_ALIASES: dict[str, str] = {"eu": "europe", "us": "americas"}

# Every X-PANW-Region value this codebase has seen documented or working:
# Insights (europe, americas, uk, sg, au), Compliance Center (americas,
# europe, uk, au) and the CDL-backed multitenant Monitor API (adds de, ca, jp,
# in). Also the candidate list mssp_detect_region probes, in that order.
KNOWN_REGIONS: tuple[str, ...] = ("americas", "europe", "uk", "de", "au", "sg", "jp", "in", "ca")

_detected: dict[str, str] = {}
_detected_lock = threading.Lock()


def normalise_region(value: str | None) -> str:
    """Lowercase, trim and map settings shorthand to a header value.

    Unknown values pass through (lowercased) so a region added upstream keeps
    working before :data:`KNOWN_REGIONS` learns about it.
    """
    v = (value or "").strip().lower()
    return REGION_ALIASES.get(v, v)


def known_region(value: str | None) -> str:
    """Normalised header value if it is a known region, else ""."""
    v = normalise_region(value)
    return v if v in KNOWN_REGIONS else ""


# ── Tenant lookup ─────────────────────────────────────────────────────────────


def find_tenant(tenant_id: str) -> tuple[str, Any]:
    """(settings key, TenantConfig) for a TSG id or settings key, else ("", None).

    Matches the ``[tenants.<key>]`` name as well as ``tenant_id`` because tools
    are called with either. An empty ``tenant_id`` matches nothing — callers
    that want "the first configured tenant" decide that themselves.
    """
    if not tenant_id:
        return "", None
    try:
        from . import settings as _settings

        cfgs = _settings.load_all_tenant_configs()
    except Exception:
        cfgs = {}
    if tenant_id in cfgs:
        return tenant_id, cfgs[tenant_id]
    for key, tc in cfgs.items():
        if str(getattr(tc, "tenant_id", "")) == tenant_id:
            return key, tc
    try:
        from ..auth.oauth import get_tenant_meta

        meta = get_tenant_meta(tenant_id)
    except Exception:
        meta = None
    return ("", meta) if meta is not None else ("", None)


def _cache_keys(tenant_id: str, tc: Any) -> list[str]:
    keys = [tenant_id] if tenant_id else []
    tsg = str(getattr(tc, "tenant_id", "") or "") if tc is not None else ""
    if tsg and tsg not in keys:
        keys.append(tsg)
    return keys


# ── Detection cache ───────────────────────────────────────────────────────────


def remember_detected_region(tenant_id: str, region: str) -> None:
    """Cache a detected region for *tenant_id* (and its TSG id, if it is a key)."""
    region = normalise_region(region)
    if not tenant_id or not region:
        return
    _, tc = find_tenant(tenant_id)
    with _detected_lock:
        for key in _cache_keys(tenant_id, tc):
            _detected[key] = region


def detected_region(tenant_id: str) -> str:
    """The cached detected region for *tenant_id*, or ""."""
    if not tenant_id:
        return ""
    with _detected_lock:
        return _detected.get(tenant_id, "")


def forget_detected_region(tenant_id: str = "") -> None:
    """Drop one tenant's cached detection, or every tenant's when empty."""
    with _detected_lock:
        if not tenant_id:
            _detected.clear()
            return
        _detected.pop(tenant_id, None)
    _, tc = find_tenant(tenant_id)
    with _detected_lock:
        for key in _cache_keys(tenant_id, tc):
            _detected.pop(key, None)


# ── Resolution ────────────────────────────────────────────────────────────────


def resolve_region_with_source(
    tenant_id: str, *, explicit: str = "", default: str = ""
) -> tuple[str, str]:
    """(header value, source) where source is override/configured/detected/default/none."""
    if explicit.strip():
        return normalise_region(explicit), "override"
    _, tc = find_tenant(tenant_id)
    configured = normalise_region(getattr(tc, "region", "") if tc is not None else "")
    if configured:
        return configured, "configured"
    for k in _cache_keys(tenant_id, tc):
        cached = detected_region(k)
        if cached:
            return cached, "detected"
    if default.strip():
        return normalise_region(default), "default"
    return "", "none"


def resolve_region(tenant_id: str, *, explicit: str = "", default: str = "") -> str:
    """X-PANW-Region header value for *tenant_id* — see the module docstring for order."""
    return resolve_region_with_source(tenant_id, explicit=explicit, default=default)[0]


def insights_default(tenant_id: str, fallback: str = "europe") -> str:
    """The tenant's ``insights_region`` as a header value — the legacy default."""
    _, tc = find_tenant(tenant_id)
    return known_region(getattr(tc, "insights_region", "") if tc is not None else "") or fallback


# ── settings.toml persistence ─────────────────────────────────────────────────


@dataclass
class PersistPlan:
    """What writing ``region`` into a tenant's settings.toml block would change."""

    path: Path
    tenant_key: str
    region: str
    ok: bool
    message: str
    old_line: str = ""
    new_line: str = ""
    new_text: str = field(default="", repr=False)


_TABLE_HEADER = re.compile(r"^\s*\[")
_KV_LINE = re.compile(r"^(\s*)([A-Za-z0-9_\-]+)(\s*)=")
_REGION_LINE = re.compile(r"""^(\s*region\s*=\s*)("[^"]*"|'[^']*'|[^\s#]+)(.*)$""")


def _section_header_pattern(tenant_key: str) -> re.Pattern[str]:
    k = re.escape(tenant_key)
    return re.compile(rf"""^\s*\[\s*tenants\s*\.\s*(?:{k}|"{k}"|'{k}')\s*\]\s*(?:#.*)?$""")


def plan_region_persist(tenant_key: str, region: str, path: Path) -> PersistPlan:
    """Work out a minimal, format-preserving edit that sets ``region`` for one tenant.

    Only the tenant's own ``[tenants.<key>]`` table is touched: an existing
    ``region =`` line has its value replaced (indentation, alignment and any
    trailing comment kept); otherwise one line is added after the table's last
    key, aligned with its neighbours. The edit is verified by parsing the file
    before and after — the only permitted difference is that one key.
    """
    region = normalise_region(region)
    plan = PersistPlan(path=path, tenant_key=tenant_key, region=region, ok=False, message="")
    if path.name == ".secrets.toml":
        plan.message = "refusing to edit .secrets.toml — region belongs in settings.toml"
        return plan
    if region not in KNOWN_REGIONS:
        plan.message = f"refusing to write unknown region {region!r}"
        return plan
    if not path.is_file():
        plan.message = f"{path} does not exist"
        return plan

    raw = path.read_bytes().decode("utf-8")
    newline = "\r\n" if "\r\n" in raw else "\n"
    lines = raw.splitlines()
    header = _section_header_pattern(tenant_key)
    start = next((i for i, line in enumerate(lines) if header.match(line)), None)
    if start is None:
        plan.message = (
            f"no [tenants.{tenant_key}] table in {path.name} — add the tenant there "
            "first (a tenant defined only in .secrets.toml is never edited)"
        )
        return plan
    end = next(
        (i for i in range(start + 1, len(lines)) if _TABLE_HEADER.match(lines[i])), len(lines)
    )

    new_value = f'"{region}"'
    region_idx = next((i for i in range(start + 1, end) if _REGION_LINE.match(lines[i])), None)
    if region_idx is not None:
        m = _REGION_LINE.match(lines[region_idx])
        assert m is not None
        plan.old_line = lines[region_idx]
        plan.new_line = f"{m.group(1)}{new_value}{m.group(3)}"
        lines[region_idx] = plan.new_line
    else:
        kv_idx = [i for i in range(start + 1, end) if _KV_LINE.match(lines[i])]
        indent, width = "", len("region ")
        if kv_idx:
            m = _KV_LINE.match(lines[kv_idx[0]])
            assert m is not None
            indent = m.group(1)
            width = max(len(m.group(2)) + len(m.group(3)), len("region "))
        plan.new_line = f"{indent}{'region'.ljust(width)}= {new_value}"
        lines.insert((kv_idx[-1] + 1) if kv_idx else start + 1, plan.new_line)

    new_text = newline.join(lines) + (newline if raw.endswith(("\n", "\r\n")) else "")

    try:
        before = tomllib.loads(raw)
        after = tomllib.loads(new_text)
    except tomllib.TOMLDecodeError as exc:
        plan.message = f"{path.name} does not parse as TOML ({exc}) — not editing it"
        return plan
    expected = _with_region(before, tenant_key, region)
    if after != expected:
        plan.message = "edit verification failed (parsed result differs) — not editing"
        return plan

    if plan.old_line == plan.new_line:
        plan.ok = True
        plan.message = f"[tenants.{tenant_key}] already has region = {new_value}"
        plan.new_text = raw
        return plan
    plan.ok = True
    plan.new_text = new_text
    verb = "replace" if plan.old_line else "add"
    plan.message = f"{verb} `{plan.new_line.strip()}` in [tenants.{tenant_key}] of {path}"
    return plan


def _with_region(doc: dict[str, Any], tenant_key: str, region: str) -> dict[str, Any]:
    tenants = dict(doc.get("tenants") or {})
    block = dict(tenants.get(tenant_key) or {})
    block["region"] = region
    tenants[tenant_key] = block
    return {**doc, "tenants": tenants}


def write_region_setting(plan: PersistPlan) -> None:
    """Atomically write a verified :class:`PersistPlan`, keeping the file's mode."""
    if not plan.ok:
        raise ValueError(plan.message)
    path = plan.path
    mode = path.stat().st_mode & 0o7777
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(plan.new_text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
