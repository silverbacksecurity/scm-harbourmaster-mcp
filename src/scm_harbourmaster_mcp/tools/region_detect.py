"""mssp_detect_region — find which data region holds a tenant's data.

The region-scoped SASE APIs answer a wrong ``X-PANW-Region`` with HTTP 200
and an empty payload, so a wrong region is indistinguishable from "no data"
at the call site. Rather than fixing that tool by tool, this probes every
known region once against two cheap, read-only, region-sensitive sources and
reports what each returned:

  * **Compliance Center** — ``/overall-compliance/{framework}`` carries an
    explicit ``data_available`` flag per product (definitions are global, so
    one framework id from ``/summaries`` is enough for every region);
  * **Prisma Access Insights** — ``location_rn_status`` and
    ``location_mu_status``, which list the tenant's locations when the region
    is right and nothing when it is not.

Exactly one region with data is a detection: it is cached in process memory
and every X-PANW-Region sender picks it up via ``config.region.resolve_region``
(below an explicit settings.toml ``region``). No region, or more than one, is
reported as such and never guessed. ``persist=True`` writes the detected value
into the tenant's ``[tenants.<key>]`` table in settings.toml; the default is a
dry run that shows the line it would write.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..config.region import (
    KNOWN_REGIONS,
    find_tenant,
    forget_detected_region,
    insights_default,
    plan_region_persist,
    remember_detected_region,
    resolve_region_with_source,
    write_region_setting,
)
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool

logger = get_logger(__name__)

# Insights resources probed per region. Both accept an empty body (unlike the
# bandwidth family, which 400s without a time window) and both return one row
# per location, so an empty list in one region and rows in another is exactly
# the signal wanted. Two, because an RN-only or MU-only tenant has one empty.
_INSIGHTS_PROBES = ("locations/location_rn_status", "locations/location_mu_status")

_MAX_WORKERS = 4


@dataclass
class RegionProbe:
    """What one region returned for one tenant."""

    region: str
    compliance: str = "—"
    insights: str = "—"
    has_data: bool = False


@dataclass
class Detection:
    """Outcome of probing every candidate region for one tenant."""

    tenant_id: str
    status: str  # "detected" | "ambiguous" | "none"
    region: str
    hits: list[str]
    probes: list[RegionProbe] = field(default_factory=list)
    detected_at: float = field(default_factory=time.time)


_detections: dict[str, Detection] = {}
_detections_lock = threading.Lock()


def reset_detections() -> None:
    """Forget every cached detection (tests; also clears the shared region cache)."""
    with _detections_lock:
        _detections.clear()
    forget_detected_region()


# ── Probes ────────────────────────────────────────────────────────────────────


def _probe_insights(client: Any, tsg_id: str, region: str) -> tuple[str, int]:
    """(verdict, row count) from the Insights location resources in *region*."""
    from .insights import _INSIGHTS_BASE_V3, _insights_call

    session = getattr(client, "session", None)
    if session is None:
        return "no session", 0
    rows = 0
    statuses: list[int] = []
    for resource in _INSIGHTS_PROBES:
        status, body = _insights_call(
            session, f"{_INSIGHTS_BASE_V3}/query/{resource}", tsg_id, None, region, (5, 15)
        )
        statuses.append(status)
        if status == 200 and isinstance(body, dict):
            data = body.get("data")
            rows += len(data) if isinstance(data, list) else 0
    if 200 not in statuses:
        return f"HTTP {statuses[0]}", 0
    return (f"{rows} rows" if rows else "empty"), rows


def _probe_region(client: Any, tsg_id: str, region: str, framework_id: str) -> RegionProbe:
    from .compliance import compliance_probe

    probe = RegionProbe(region=region)
    rows = 0
    try:
        if framework_id:
            probe.compliance, _ = compliance_probe(client, region, framework_id)
    except Exception as exc:
        probe.compliance = f"error: {str(exc)[:60]}"
    try:
        probe.insights, rows = _probe_insights(client, tsg_id, region)
    except Exception as exc:
        probe.insights = f"error: {str(exc)[:60]}"
    probe.has_data = probe.compliance == "data" or rows > 0
    return probe


def probe_regions(
    client: Any, tsg_id: str, regions: tuple[str, ...] = KNOWN_REGIONS
) -> list[RegionProbe]:
    """Probe every region; results come back in *regions* order."""
    from .compliance import compliance_probe
    from .insights import _refresh_token

    _refresh_token(client)
    if not regions:
        return []

    # The first region also discovers a framework id for the rest to reuse.
    first = RegionProbe(region=regions[0])
    framework_id = ""
    try:
        first.compliance, framework_id = compliance_probe(client, regions[0])
    except Exception as exc:
        first.compliance = f"error: {str(exc)[:60]}"
    try:
        first.insights, rows = _probe_insights(client, tsg_id, regions[0])
    except Exception as exc:
        first.insights, rows = f"error: {str(exc)[:60]}", 0
    first.has_data = first.compliance == "data" or rows > 0

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        rest = list(pool.map(lambda r: _probe_region(client, tsg_id, r, framework_id), regions[1:]))
    if not framework_id:
        # No framework to ask about — every region gets the same explanation.
        for p in rest:
            p.compliance = first.compliance
    return [first, *rest]


def classify(tenant_id: str, probes: list[RegionProbe]) -> Detection:
    """Exactly one region with data is a detection; zero or several are reported."""
    hits = [p.region for p in probes if p.has_data]
    if len(hits) == 1:
        return Detection(tenant_id, "detected", hits[0], hits, probes)
    return Detection(tenant_id, "ambiguous" if hits else "none", "", hits, probes)


def detect_region(client: Any, tsg_id: str, refresh: bool = False) -> tuple[Detection, bool]:
    """(detection, from_cache). Only an unambiguous detection feeds resolve_region."""
    if not refresh:
        with _detections_lock:
            cached = _detections.get(tsg_id)
        if cached is not None:
            return cached, True

    detection = classify(tsg_id, probe_regions(client, tsg_id))
    with _detections_lock:
        _detections[tsg_id] = detection
    if detection.status == "detected":
        remember_detected_region(tsg_id, detection.region)
    else:
        # A re-probe that no longer finds one region must not leave an old
        # detection steering every request.
        forget_detected_region(tsg_id)
    logger.info(
        "region_detection",
        tenant_id=tsg_id,
        status=detection.status,
        region=detection.region,
        hits=detection.hits,
    )

    # Compliance keeps its own per-process resolution cache; drop it so the
    # new answer applies to the next Compliance call.
    from .compliance import _reset_region_cache

    _reset_region_cache()
    return detection, False


def settings_path() -> Path:
    """The settings.toml dynaconf loads (relative to the server's working dir)."""
    return Path("settings.toml").resolve()


# ── Report ────────────────────────────────────────────────────────────────────


def render_report(detection: Detection, from_cache: bool, tenant_key: str, persist: bool) -> str:
    tsg = detection.tenant_id
    lines = [f"## Data region — tenant `{tsg or 'default'}`", ""]
    if detection.status == "detected":
        lines.append(f"**Result:** detected `{detection.region}` — the only region holding data.")
    elif detection.status == "ambiguous":
        lines.append(
            f"**Result:** ambiguous — data in {', '.join(f'`{h}`' for h in detection.hits)}. "
            "Not cached and not persisted: pick the right one and set `region` in "
            "settings.toml by hand."
        )
    else:
        lines.append(
            "**Result:** no region returned data. Either nothing is assessed/connected "
            "yet, or the service account lacks the read roles (see HTTP 403s below). "
            "Nothing cached or persisted."
        )

    stamp = datetime.fromtimestamp(detection.detected_at, UTC).strftime("%Y-%m-%d %H:%M UTC")
    if from_cache:
        lines.append(f"_Cached result from {stamp} — pass `refresh=True` to re-probe._")
    else:
        lines.append(f"_Probed {len(detection.probes)} regions at {stamp}._")

    region, source = resolve_region_with_source(tsg, default=insights_default(tsg))
    lines += [
        "",
        f"**Region requests now use:** `{region or '—'}` ({source}). "
        "Order: settings `region` > detected > insights_region.",
        "",
        "| Region | Compliance | Insights (RN+MU locations) | Data |",
        "|---|---|---|---|",
    ]
    for p in detection.probes:
        mark = "**yes**" if p.has_data else "no"
        lines.append(f"| `{p.region}` | {p.compliance} | {p.insights} | {mark} |")

    lines += ["", "### settings.toml"]
    if detection.status != "detected":
        lines.append("Nothing to write — only an unambiguous detection is persisted.")
        return "\n".join(lines)
    if not tenant_key:
        lines.append(
            "This tenant has no `[tenants.<key>]` table in settings.toml (it may be the "
            "default single-tenant credentials) — nothing can be written."
        )
        return "\n".join(lines)

    plan = plan_region_persist(tenant_key, detection.region, settings_path())
    if not plan.ok:
        lines.append(f"Not written: {plan.message}.")
        return "\n".join(lines)
    if plan.old_line == plan.new_line:
        lines.append(f"Already set: {plan.message}.")
        return "\n".join(lines)
    if not persist:
        change = f"`{plan.old_line.strip()}` → " if plan.old_line else ""
        lines.append(
            f"Dry run — would {plan.message.split(' ', 1)[0]} {change}`{plan.new_line.strip()}` "
            f"in `[tenants.{tenant_key}]` of `{plan.path}`. "
            "Re-run with `persist=True` to write it (no other line changes)."
        )
        return "\n".join(lines)
    write_region_setting(plan)
    logger.info("region_persisted", tenant=tenant_key, region=detection.region)
    lines.append(f"Written: {plan.message}.")
    return "\n".join(lines)


# ── Tool ──────────────────────────────────────────────────────────────────────


def register_region_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register mssp_detect_region."""
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def mssp_detect_region(
        client: Any, tenant_id: str, persist: bool = False, refresh: bool = False
    ) -> str:
        """Detect which data region (X-PANW-Region) holds a tenant's data.

        Region-scoped APIs (Insights, Monitor, Compliance) answer a wrong region
        with HTTP 200 and an empty payload, so a tenant whose data lives in `uk`
        but is configured `eu` silently reports nothing. This probes every known
        region (americas, europe, uk, de, au, sg, jp, in, ca) with read-only
        calls — Compliance `data_available` and Insights RN/MU location lists —
        and shows a region -> result table.

        Exactly one region with data is cached for this server process and used
        by every region-scoped tool unless settings.toml sets `region`
        explicitly. No data, or data in more than one region, is reported and
        never guessed.

        Args:
            tenant_id: SCM tenant ID (TSG) or settings.toml tenant key.
            persist: Write `region = "<code>"` into this tenant's
                [tenants.<key>] table in settings.toml. Default False is a dry
                run showing the exact line. Never touches .secrets.toml.
            refresh: Re-probe even if a detection is already cached.
        """
        key, tc = find_tenant(tenant_id)
        tsg = str(getattr(tc, "tenant_id", "") or "") if tc is not None else tenant_id
        if not tsg:
            tsg = str(getattr(client, "tsg_id", "") or "")
            key, tc = find_tenant(tsg)
        if tc is not None and not key:
            key, _ = find_tenant(str(getattr(tc, "tenant_id", "")))
        detection, from_cache = detect_region(client, tsg, refresh=refresh)
        return render_report(detection, from_cache, key, persist)
