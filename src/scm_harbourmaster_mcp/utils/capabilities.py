"""Per-tenant API capability probe — find RBAC/licence gaps before a report does.

Long multi-section reports (AS-BUILT, MSR) used to discover missing
permissions mid-run: ``allocated_ips`` 403s on a view-only admin, Insights
``tunnel_list`` 403s, SD-WAN audit-log 403s, Email DLP 400s on an
unprovisioned tenant. :func:`probe_tenant_capabilities` sends one cheap,
read-only request per API family and classifies each as:

  available      2xx — the family answers for this service account
  forbidden      403 — RBAC: the role lacks this permission
  unprovisioned  404/424 (plus family-specific codes such as Email DLP 400 or
                 SSPM 500) — the product isn't licensed/enabled on the tenant
  error          anything else (401, 5xx, transport) — inconclusive

Results are cached per tenant for :data:`CAPABILITY_TTL_SECONDS`. Report
tools consult the cache through :func:`capability_skip_reason` and skip a
section up front when it is known to be forbidden/unprovisioned; they never
trigger a probe themselves, so a tenant that was never probed behaves exactly
as before.

Probes are strictly read-only: GETs, plus POSTs only to documented
query/search endpoints (Insights ``/resource/query/``, Incidents search) that
have no GET equivalent. :func:`assert_read_only` enforces that.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from .family_probe import _bearer_session, probe_endpoint
from .logging import get_logger

logger = get_logger(__name__)

AVAILABLE = "available"
FORBIDDEN = "forbidden"
UNPROVISIONED = "unprovisioned"
ERROR = "error"

CAPABILITY_TTL_SECONDS = 6 * 3600
_PROBE_TIMEOUT = (4.0, 10.0)
_MAX_WORKERS = 6

_SASE = "https://api.sase.paloaltonetworks.com"
_STRATA = "https://api.strata.paloaltonetworks.com"

# Non-GET probes are allowed only against these read-only query/search paths.
_READ_ONLY_POST_MARKERS = ("/resource/query/", "/incidents/v1/search")

_STATUS_ICON = {AVAILABLE: "✅", FORBIDDEN: "⛔", UNPROVISIONED: "➖", ERROR: "⚠️"}


@dataclass(frozen=True)
class CapabilitySpec:
    """One API family and the single cheap request that proves access to it."""

    family: str
    label: str
    url: str
    method: str = "GET"
    params: dict[str, Any] | None = None
    headers: dict[str, str] | None = None
    json_body: Any = None
    unprovisioned_statuses: frozenset[int] = frozenset({404, 424})
    transport: str = "scm"  # "scm" = SCM OAuth bearer; "sdwan" = prisma-sase session
    used_by: str = ""


@dataclass
class CapabilityResult:
    """Classification of one family for one tenant."""

    family: str
    label: str
    status: str
    http_status: int
    detail: str = ""
    method: str = "GET"
    url: str = ""
    used_by: str = ""


@dataclass
class _CacheEntry:
    probed_at: float
    results: dict[str, CapabilityResult] = field(default_factory=dict)


_cache: dict[str, _CacheEntry] = {}
_cache_lock = threading.Lock()


# ── Probe catalogue ──────────────────────────────────────────────────────────


def capability_specs(tsg_id: str, insights_region: str = "europe") -> list[CapabilitySpec]:
    """The probe for every family, parameterised for one tenant.

    Paths mirror the calls the extractors and report tools actually make, so a
    probe verdict predicts what the report section would hit.
    """
    tenant_hdr = {"Prisma-Tenant": tsg_id} if tsg_id else {}
    return [
        CapabilitySpec(
            "config_jobs",
            "SCM config — jobs",
            f"{_SASE}/sse/config/v1/jobs",
            params={"limit": 1},
            used_by="AS-BUILT change history, MSR §4",
        ),
        CapabilitySpec(
            "allocated_ips",
            "Prisma Access infrastructure — allocated egress IPs",
            f"{_SASE}/sse/config/v1/infrastructure/allocated-ips",
            used_by="AS-BUILT §9.1 egress IPs",
        ),
        CapabilitySpec(
            "licensing",
            "Subscription licences",
            f"{_SASE}/subscription/v1/licenses",
            used_by="AS-BUILT licences, MSR §6",
        ),
        CapabilitySpec(
            "incidents",
            "Incidents (search)",
            f"{_STRATA}/incidents/v1/search",
            method="POST",
            json_body={},
            used_by="MSR §3",
        ),
        CapabilitySpec(
            "insights",
            "Prisma Access Insights v3 — tunnel_list",
            f"{_SASE}/insights/v3.0/resource/query/tunnels/tunnel_list",
            method="POST",
            json_body={},
            headers={"X-PANW-Region": insights_region, **tenant_hdr},
            used_by="AS-BUILT Insights sections, MSR §7-8",
        ),
        CapabilitySpec(
            "adem",
            "Autonomous DEM telemetry",
            f"{_SASE}/adem/telemetry/v2/measure/agent/score",
            params={
                "timerange": "last_3_day",
                "endpoint-type": "muAgent",
                "response-type": "summary",
            },
            headers={"prisma-tenant": tsg_id} if tsg_id else None,
            used_by="AS-BUILT §7.1, MSR §9",
        ),
        CapabilitySpec(
            "compliance",
            "Compliance Center — framework summaries",
            f"{_STRATA}/posture/compliance-frameworks/v1/summaries",
            params={"product": "all"},
            used_by="MSR §5",
        ),
        CapabilitySpec(
            "enterprise_dlp",
            "Enterprise DLP — data patterns",
            "https://api.dlp.paloaltonetworks.com/v2/api/data-patterns",
            params={"page": 0, "size": 1},
            used_by="AS-BUILT extended DLP",
        ),
        CapabilitySpec(
            "email_dlp",
            "Email DLP — incidents",
            "https://api.us-west1.email.dlp.paloaltonetworks.com/incident/api/v1/incidents",
            unprovisioned_statuses=frozenset({400, 404, 424}),
            used_by="scm_email_dlp_incidents",
        ),
        CapabilitySpec(
            "ztna_connector",
            "ZTNA Connector — licence",
            f"{_SASE}/sse/connector/v2.0/api/license",
            used_by="AS-BUILT extended ZTNA",
        ),
        CapabilitySpec(
            "sspm",
            "SaaS Security Posture (SSPM) — apps",
            f"{_STRATA}/sspm/api/v1/apps",
            unprovisioned_statuses=frozenset({404, 424, 500}),
            used_by="AS-BUILT SSPM",
        ),
        CapabilitySpec(
            "iam",
            "IAM — roles",
            f"{_SASE}/iam/v1/roles",
            used_by="AS-BUILT IAM roles/access policies",
        ),
        CapabilitySpec(
            "tenancy",
            "Tenancy — managed tenants",
            f"{_SASE}/tenancy/v1/tenants",
            used_by="AS-BUILT managed tenants",
        ),
        CapabilitySpec(
            "sdwan",
            "Prisma SD-WAN — sites",
            "/sdwan/v4.13/api/sites",
            transport="sdwan",
            used_by="AS-BUILT §4 (include_sdwan)",
        ),
        CapabilitySpec(
            "sdwan_auditlog",
            "Prisma SD-WAN — audit log",
            "/sdwan/v2.1/api/auditlog",
            transport="sdwan",
            used_by="sdwan_audit_logs",
        ),
    ]


def known_families() -> list[str]:
    """Every family name a probe covers (stable order)."""
    return [s.family for s in capability_specs("")]


def assert_read_only(spec: CapabilitySpec) -> None:
    """Refuse any probe that is not a GET or an allow-listed read-only query POST."""
    method = spec.method.upper()
    if method == "GET":
        return
    if method == "POST" and any(m in spec.url for m in _READ_ONLY_POST_MARKERS):
        return
    raise ValueError(f"capability probe {spec.family!r} is not read-only: {method} {spec.url}")


def classify_status(status: int, spec: CapabilitySpec) -> str:
    """Map an HTTP status to available / forbidden / unprovisioned / error."""
    if 200 <= status < 300:
        return AVAILABLE
    if status == 403:
        return FORBIDDEN
    if status in spec.unprovisioned_statuses:
        return UNPROVISIONED
    return ERROR


def _describe(status_label: str, http_status: int, detail: str) -> str:
    if http_status == -1:
        return f"transport error: {detail}" if detail else "transport error"
    base = {
        AVAILABLE: "ok",
        FORBIDDEN: "RBAC — the service account's role lacks this permission",
        UNPROVISIONED: "not licensed / not enabled on this tenant",
        ERROR: "unauthorised — token or OAuth scope" if http_status == 401 else "inconclusive",
    }[status_label]
    return base


# ── Tenant resolution ────────────────────────────────────────────────────────


def _tenant_configs() -> dict[str, Any]:
    try:
        from ..config.settings import load_all_tenant_configs

        return load_all_tenant_configs()
    except Exception:
        return {}


def canonical_tenant_id(tenant_id: str) -> str:
    """Normalise a tenant reference (TSG id, settings key, label or "") to a cache key."""
    if tenant_id:
        with _cache_lock:
            if tenant_id in _cache:
                return tenant_id
        cfgs = _tenant_configs()
        if tenant_id in cfgs:
            return str(cfgs[tenant_id].tenant_id)
        for tc in cfgs.values():
            if getattr(tc, "label", None) == tenant_id:
                return str(tc.tenant_id)
        return tenant_id
    try:
        from ..auth.oauth import list_loaded_tenants

        loaded = list_loaded_tenants()
        if loaded:
            return str(loaded[0])
    except Exception:
        pass
    cfgs = _tenant_configs()
    if cfgs:
        return str(next(iter(cfgs.values())).tenant_id)
    return "default"


def _insights_region_for(tsg_id: str) -> str:
    try:
        from ..tools.insights import REGION_MAP

        tc = next((c for c in _tenant_configs().values() if c.tenant_id == tsg_id), None)
        if tc is not None:
            return REGION_MAP.get(tc.insights_region, "europe")
    except Exception:
        pass
    return "europe"


def _default_sdwan_session_factory(tsg_id: str) -> tuple[Any, str]:
    """Return (requests-like session, controller base URL) for the tenant's SD-WAN SDK."""
    from ..auth.oauth import get_tenant_meta
    from ..auth.sdwan import get_sdwan_client

    tc = get_tenant_meta(tsg_id)
    if tc is None:
        tc = next((c for c in _tenant_configs().values() if c.tenant_id == tsg_id), None)
    if tc is None:
        raise ValueError(f"tenant {tsg_id!r} is not configured for SD-WAN")
    sdk = get_sdwan_client(tc)
    base = str(getattr(sdk, "base_url", "") or getattr(sdk, "controller", "") or _SASE)
    return sdk._session, base


# ── Probing + cache ──────────────────────────────────────────────────────────


def _run_probe(
    spec: CapabilitySpec, scm_session: Any, sdwan: tuple[Any, str] | Exception | None
) -> CapabilityResult:
    assert_read_only(spec)
    url = spec.url
    if spec.transport == "sdwan":
        if isinstance(sdwan, Exception) or sdwan is None:
            return CapabilityResult(
                spec.family,
                spec.label,
                ERROR,
                -1,
                f"SD-WAN client unavailable: {sdwan}",
                spec.method,
                url,
                spec.used_by,
            )
        session, base = sdwan
        url = f"{base.rstrip('/')}{spec.url}"
    else:
        session = scm_session

    code, detail = probe_endpoint(
        session,
        url,
        method=spec.method,
        params=spec.params,
        headers=spec.headers,
        json_body=spec.json_body,
        timeout=_PROBE_TIMEOUT,
    )
    label = classify_status(code, spec)
    note = _describe(label, code, detail)
    if label == ERROR and detail and code != -1:
        note = f"{note}: {detail[:160]}"
    return CapabilityResult(
        spec.family, spec.label, label, code, note, spec.method, url, spec.used_by
    )


def probe_tenant_capabilities(
    client: Any,
    tenant_id: str = "",
    *,
    refresh: bool = False,
    sdwan_session_factory: Callable[[str], tuple[Any, str]] | None = None,
    families: list[str] | None = None,
) -> tuple[dict[str, CapabilityResult], float, bool]:
    """Probe (or return cached) capabilities for a tenant.

    Returns ``(results, probed_at_epoch, from_cache)``.
    """
    key = canonical_tenant_id(tenant_id)
    if not refresh:
        with _cache_lock:
            entry = _cache.get(key)
            if entry is not None and time.time() - entry.probed_at < CAPABILITY_TTL_SECONDS:
                return dict(entry.results), entry.probed_at, True

    specs = capability_specs(key if key != "default" else "", _insights_region_for(key))
    if families:
        specs = [s for s in specs if s.family in families]
    for spec in specs:
        assert_read_only(spec)

    scm_session = _bearer_session(client)
    sdwan: tuple[Any, str] | Exception | None = None
    if any(s.transport == "sdwan" for s in specs):
        factory = sdwan_session_factory or _default_sdwan_session_factory
        try:
            sdwan = factory(key)
        except Exception as exc:
            sdwan = exc

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        results_list = list(pool.map(lambda s: _run_probe(s, scm_session, sdwan), specs))

    results = {r.family: r for r in results_list}
    probed_at = time.time()
    with _cache_lock:
        _cache[key] = _CacheEntry(probed_at=probed_at, results=dict(results))
    logger.info(
        "tenant_capabilities_probed",
        tenant_id=key,
        forbidden=[r.family for r in results_list if r.status == FORBIDDEN],
        unprovisioned=[r.family for r in results_list if r.status == UNPROVISIONED],
    )
    return results, probed_at, False


def get_cached_capabilities(tenant_id: str) -> tuple[dict[str, CapabilityResult], float] | None:
    """Unexpired cached results for a tenant, or None. Never probes."""
    with _cache_lock:
        if not _cache:
            return None
    key = canonical_tenant_id(tenant_id)
    with _cache_lock:
        entry = _cache.get(key)
        if entry is None:
            return None
        if time.time() - entry.probed_at >= CAPABILITY_TTL_SECONDS:
            del _cache[key]
            return None
        return dict(entry.results), entry.probed_at


def has_capability(tenant_id: str, family: str) -> bool | None:
    """True = available, False = forbidden/unprovisioned, None = unknown/not probed."""
    cached = get_cached_capabilities(tenant_id)
    if cached is None:
        return None
    result = cached[0].get(family)
    if result is None or result.status == ERROR:
        return None
    return result.status == AVAILABLE


def capability_skip_reason(tenant_id: str, family: str) -> str | None:
    """A coverage-disclosure note when a cached probe says *family* is unusable.

    Returns None (run the section as normal) when nothing is cached, the
    family is available, or the probe was inconclusive.
    """
    if has_capability(tenant_id, family) is not False:
        return None
    cached = get_cached_capabilities(tenant_id)
    if cached is None:  # expired between the two lookups
        return None
    result = cached[0][family]
    age_min = max(0, int((time.time() - cached[1]) // 60))
    return (
        f"skipped — capability probe {age_min} min ago found {family} {result.status} "
        f"(HTTP {result.http_status}: {result.detail}). "
        "Re-run mssp_tenant_capabilities(refresh=True) after changing the role/licence."
    )


def clear_capability_cache(tenant_id: str | None = None) -> None:
    """Drop cached results for one tenant, or all tenants when *tenant_id* is None."""
    with _cache_lock:
        if tenant_id is None:
            _cache.clear()
            return
    key = canonical_tenant_id(tenant_id)
    with _cache_lock:
        _cache.pop(key, None)


def capability_counts(results: dict[str, CapabilityResult]) -> dict[str, int]:
    """Count of families per status."""
    counts = {AVAILABLE: 0, FORBIDDEN: 0, UNPROVISIONED: 0, ERROR: 0}
    for r in results.values():
        counts[r.status] = counts.get(r.status, 0) + 1
    return counts


def render_capabilities_markdown(
    tenant_id: str,
    results: dict[str, CapabilityResult],
    probed_at: float,
    from_cache: bool,
) -> str:
    """Markdown table of probe results."""
    counts = capability_counts(results)
    stamp = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(probed_at))
    source = "cached" if from_cache else "live probe"
    lines = [
        f"# API Capabilities — Tenant `{tenant_id}`",
        "",
        f"_{source} at {stamp} · cache TTL {CAPABILITY_TTL_SECONDS // 3600}h · "
        f"{counts[AVAILABLE]} available · {counts[FORBIDDEN]} forbidden · "
        f"{counts[UNPROVISIONED]} unprovisioned · {counts[ERROR]} error_",
        "",
        "| Status | Family | API | Probe | HTTP | Detail | Used by |",
        "|--------|--------|-----|-------|------|--------|---------|",
    ]
    order = {FORBIDDEN: 0, UNPROVISIONED: 1, ERROR: 2, AVAILABLE: 3}
    for r in sorted(results.values(), key=lambda x: (order.get(x.status, 9), x.family)):
        http = str(r.http_status) if r.http_status >= 0 else "—"
        path = r.url.split(".com", 1)[-1] if ".com" in r.url else r.url
        detail = r.detail.replace("|", "\\|").replace("\n", " ")
        lines.append(
            f"| {_STATUS_ICON.get(r.status, '')} {r.status} | `{r.family}` | {r.label} "
            f"| {r.method} `{path}` | {http} | {detail} | {r.used_by or '—'} |"
        )
    lines += [
        "",
        "Report tools (scm_asbuilt_report, scm_msr_report) skip sections whose family is "
        "cached as **forbidden** or **unprovisioned** and disclose the skip in their coverage "
        "notes. **error** results are inconclusive and never cause a skip.",
    ]
    return "\n".join(lines)
