"""
MCP tools for operational visibility and MSSP management.

Tools:
    scm_cert_scan            — scan all tenant certificates, flag expiring <N days
    scm_licence_forecast     — licence expiry and seat utilisation per tenant
    scm_tenant_dashboard     — multi-tenant health traffic-light overview (NOC wallboard)
    scm_spn_bandwidth        — SPN bandwidth allocation, live throughput (Insights v3.0), and risk
    scm_gp_session_summary   — live GP + PA-Agent session counts by country, compute node, and
                               client version; compares against licensed MU seat capacity
    scm_check_updates        — check PyPI + GitHub for SDK / pan.dev updates; no dependencies
"""

from __future__ import annotations

import json as _json
import time
import urllib.error
import urllib.request
from concurrent.futures import ALL_COMPLETED, ThreadPoolExecutor, wait
from datetime import UTC, datetime
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..auth.oauth import fetch_licenses, get_scm_client
from ..config.settings import TenantConfig, load_all_tenant_configs
from ..utils.errors import handle_scm_exception
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool
from ..utils.write_safety import (
    DRY_RUN_HINT,
    audit_write,
    normalize_ticket_ref,
    ticket_ref_error,
)
from .insights import region_header, resolve_region

logger = get_logger(__name__)

_SCM_BASE = "https://api.sase.paloaltonetworks.com/sse/config/v1"
# Relative form of _SCM_BASE for client.get()/client.post(), which prepend the
# host themselves. Certificates and TLS service profiles have no pan-scm-sdk
# resource, so they are reached over raw REST — and they live under /sse/config/v1,
# not /config/v1: the latter 404s on every folder.
_SSE_CONFIG_PATH = "/sse/config/v1"
_INSIGHTS_BASE = "https://api.sase.paloaltonetworks.com/insights/v3.0/resource/query"
_CERT_FOLDERS = ["Shared", "Remote Networks", "Mobile Users", "Service Connections"]


# ── Helpers ──────────────────────────────────────────────────────────────────


def _load_all_tenant_configs() -> dict[str, TenantConfig]:
    """Load all MSSP tenant configs from settings.toml + .secrets.toml."""
    try:
        return load_all_tenant_configs()
    except Exception as exc:
        logger.warning("tenant_config_load_failed", error=str(exc))
        return {}


def _days_until_epoch(epoch_str: str) -> int | None:
    try:
        return (int(epoch_str) - int(time.time())) // 86400
    except (ValueError, TypeError):
        return None


def _parse_expiry_str(exp: str) -> int | None:
    """Parse 'YYYY-MM-DDTHH:MM:SS' or 'YYYY-MM-DD HH:MM:SS' to days remaining."""
    if not exp or exp in ("None", ""):
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(exp.split(".")[0], fmt).replace(tzinfo=UTC)
            return (dt - datetime.now(UTC)).days
        except ValueError:
            continue
    return None


def _status(days: int | None, warn: int = 90) -> str:
    if days is None:
        return "UNKNOWN"
    if days < 0:
        return "EXPIRED"
    if days < 30:
        return "CRITICAL"
    if days < 60:
        return "WARNING"
    if days < warn:
        return "CAUTION"
    return "OK"


_STATUS_EMOJI = {
    "EXPIRED": "🔴",
    "CRITICAL": "🔴",
    "WARNING": "🟡",
    "CAUTION": "🟡",
    "OK": "🟢",
    "UNKNOWN": "⚪",
}


def _nearest_licence_expiry(
    lics: list[dict], include_expired: bool = False
) -> tuple[int | None, str]:
    """Return (days_remaining, 'YYYY-MM-DD') for the most relevant licence expiry.

    Each entry in *lics* is a subscription bundle with a ``licenses`` list, each
    carrying a ``license_expiration`` timestamp.

    By default the result tracks the soonest expiry among *active* (not-yet-
    expired) SKUs, so the figure reflects operational renewal health rather than
    a long-dead trial/legacy SKU (e.g. an old logging_service Production License)
    dragging "days" permanently negative. If a tenant has no active licences
    left, it falls back to the worst (most-expired) SKU so the row still flags
    red. Set ``include_expired=True`` to consider every SKU, expired or not.

    Returns ``(None, "—")`` when no parseable expiry dates are present.
    """
    active_days: int | None = None
    active_exp = "—"
    worst_days: int | None = None
    worst_exp = "—"
    for bundle in lics:
        for sub in bundle.get("licenses", []):
            exp_raw = str(sub.get("license_expiration", ""))
            d = _parse_expiry_str(exp_raw)
            if d is None:
                continue
            if worst_days is None or d < worst_days:
                worst_days, worst_exp = d, exp_raw[:10]
            if d >= 0 and (active_days is None or d < active_days):
                active_days, active_exp = d, exp_raw[:10]

    if include_expired or active_days is None:
        return worst_days, worst_exp
    return active_days, active_exp


def _fetch_certs(session: Any, folder: str) -> list[dict]:
    try:
        r = session.get(
            f"{_SCM_BASE}/certificates",
            params={"folder": folder, "limit": 500},
            timeout=(5, 20),
        )
        if r.status_code == 200:
            d = r.json()
            return d if isinstance(d, list) else d.get("data", [])
    except Exception:
        pass
    return []


def _quick_list(session: Any, path: str, params: dict) -> list[dict]:
    try:
        r = session.get(
            f"{_SCM_BASE}/{path}",
            params={**params, "limit": 500},
            timeout=(4, 12),
        )
        if r.status_code == 200:
            d = r.json()
            return d if isinstance(d, list) else d.get("data", [])
    except Exception:
        pass
    return []


def _gather_parallel(
    targets: list[tuple[str, Any]],
    fn: Any,
    timeout: int = 25,
    max_workers: int = 8,
) -> list[tuple[str, bool, Any]]:
    """Run ``fn(label, client)`` for every target in parallel under a hard
    wall-clock budget.

    Multi-tenant reports otherwise loop tenants serially; a single unhealthy
    tenant (e.g. an endpoint returning 5xx that the SDK session retries with
    backoff) can stall the whole report past the MCP request deadline. Running
    the per-tenant work in a bounded thread pool caps total wall time to roughly
    ``timeout`` seconds and lets laggards degrade gracefully.

    Returns a list aligned to *targets* order. Each entry is
    ``(label, ok, payload)``:
      * ``ok=True``  → fn returned normally; ``payload`` is its return value.
      * ``ok=False`` → fn raised (``payload`` = exception) or timed out
        (``payload`` = None).
    """
    out: list[tuple[str, bool, Any]] = [(lbl, False, None) for (lbl, _c) in targets]
    if not targets:
        return out
    pool = ThreadPoolExecutor(max_workers=min(max_workers, len(targets)))
    try:
        fut_to_idx = {pool.submit(fn, lbl, cl): i for i, (lbl, cl) in enumerate(targets)}
        done, _not_done = wait(fut_to_idx.keys(), timeout=timeout, return_when=ALL_COMPLETED)
        for fut in done:
            i = fut_to_idx[fut]
            lbl = targets[i][0]
            try:
                out[i] = (lbl, True, fut.result())
            except Exception as exc:  # noqa: BLE001 — degrade, don't abort the report
                out[i] = (lbl, False, exc)
        for fut in _not_done:
            fut.cancel()  # best-effort; leaves entry as (label, False, None)
    finally:
        pool.shutdown(wait=False)
    return out


def _insights_query(
    session: Any,
    resource: str,
    tenant_id: str,
    body: dict | None = None,
) -> list[dict]:
    """POST to Insights v3.0 query API; returns data list or [] on any error.

    Returning [] on failure is deliberate — callers treat this as optional
    enrichment — but it used to be silent as well, which hid both a dead
    resource name and a malformed region header for months. Failures are
    logged now; the caller's behaviour is unchanged.
    """
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        # Must be a header value, not a settings key: sending "eu" here (as
        # this did) is accepted and answered with an empty result set.
        "X-PANW-Region": resolve_region(str(tenant_id)),
        "Prisma-Tenant": str(tenant_id),
    }
    try:
        r = session.post(
            f"{_INSIGHTS_BASE}/{resource}",
            json=body or {},
            headers=headers,
            timeout=(5, 20),
        )
        if r.status_code == 200:
            d = r.json()
            return d.get("data", []) if isinstance(d, dict) else (d if isinstance(d, list) else [])
        logger.info(
            "insights_query_failed",
            resource=resource,
            tenant_id=tenant_id,
            status=r.status_code,
            detail=(r.text or "")[:200],
        )
    except Exception as exc:
        logger.info("insights_query_error", resource=resource, tenant_id=tenant_id, error=str(exc))
    return []


# Insights v3.0 candidate resource names for per-SPN bandwidth, tried in order.
# `pa_bandwidth_consumption` was first here until 2026-09-09, when it started
# returning DATA10003 "Invalid resource" — the name is gone upstream, so it
# only ever cost a wasted round-trip before the real candidates were tried.
_SPN_BW_RESOURCES = ("sn_bandwidth", "edge_bandwidth")
# 5-minute rolling window for throughput calculation.
_SPN_BW_WINDOW_SEC = 300


def _insights_spn_throughput(session: Any, tenant_id: str) -> dict[str, dict[str, float]]:
    """Query Insights v3.0 for per-SPN throughput over the last 5 minutes.

    Tries multiple resource names in order; returns the first non-empty result.
    Converts raw byte counters to Mbps using the 5-minute window.

    Returns:
        {spn_name: {"mbps_in": float, "mbps_out": float}} or {} on any failure.
    """
    body: dict[str, Any] = {
        "properties": [
            {"property": "spn_name"},
            {"property": "bytes_in"},
            {"property": "bytes_out"},
        ],
        "filter": {
            "rules": [
                {
                    "property": "event_time",
                    "operator": "last_n_minutes",
                    "values": ["5"],
                }
            ]
        },
    }
    for resource in _SPN_BW_RESOURCES:
        rows = _insights_query(session, resource, tenant_id, body=body)
        if not rows:
            continue

        sample = rows[0]
        spn_key = next(
            (k for k in ("spn_name", "sn_name", "edge_location", "location") if k in sample),
            None,
        )
        in_key = next((k for k in ("bytes_in", "rx_bytes", "inbound_bytes") if k in sample), None)
        out_key = next(
            (k for k in ("bytes_out", "tx_bytes", "outbound_bytes") if k in sample), None
        )
        if not spn_key:
            continue

        result: dict[str, dict[str, float]] = {}
        for row in rows:
            spn = str(row.get(spn_key) or "unknown")
            bytes_in = int(row.get(in_key) or 0) if in_key else 0
            bytes_out = int(row.get(out_key) or 0) if out_key else 0
            result[spn] = {
                "mbps_in": round(bytes_in * 8 / (_SPN_BW_WINDOW_SEC * 1_000_000), 2),
                "mbps_out": round(bytes_out * 8 / (_SPN_BW_WINDOW_SEC * 1_000_000), 2),
            }
        if result:
            logger.info(
                "spn_throughput_fetched",
                resource=resource,
                tenant_id=tenant_id,
                spn_count=len(result),
            )
            return result

    return {}


# ── Update-check helpers ──────────────────────────────────────────────────────

_UA = "scm-harbourmaster-mcp/updatecheck (github.com/silverbacksecurity/scm-harbourmaster-mcp)"
_PYPI_PACKAGES = [
    ("pan-scm-sdk", "pan-scm-sdk"),
    ("prisma-sase", "prisma-sase"),
    ("mcp", "mcp"),
    ("scm-harbourmaster-mcp", "scm-harbourmaster-mcp"),
]


def _http_get_json(url: str, timeout: int = 8) -> Any:
    """GET url, return parsed JSON or None on any error."""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": _UA, "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310  # nosec B310: fixed https URL
            return _json.loads(resp.read())
    except Exception:
        return None


def _pypi_latest(package: str) -> str | None:
    data = _http_get_json(f"https://pypi.org/pypi/{package}/json")
    return data["info"]["version"] if data else None


def _installed_version(dist_name: str) -> str:
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version(dist_name)
    except PackageNotFoundError:
        return "—"


def _parse_semver(v: str) -> tuple[int, ...]:
    """Return (major, minor, patch) for rough comparison; ignore pre-releases."""
    try:
        return tuple(int(x) for x in v.split(".")[:3])
    except Exception:
        return (0, 0, 0)


def _gh_latest_release(owner: str, repo: str) -> dict[str, Any] | None:
    return _http_get_json(f"https://api.github.com/repos/{owner}/{repo}/releases/latest")


def _gh_recent_commits(owner: str, repo: str, path: str, n: int = 5) -> list[dict]:
    data = _http_get_json(
        f"https://api.github.com/repos/{owner}/{repo}/commits?path={path}&per_page={n}"
    )
    return data if isinstance(data, list) else []


_SPEC_EXTS = (".yaml", ".yml", ".json")


def _spec_drift() -> tuple[dict, list[str], list[str], list[str]] | None:
    """Compare the bundled endpoint catalog's spec-file blob SHAs against the
    live pan.dev tree. Returns (catalog_meta, new, changed, removed) file
    lists, or None when the catalog or the GitHub API is unavailable.

    Uses one contents call plus one recursive tree call per spec tree
    (openapi-specs/{sase,scm,access}) — 4 unauthenticated requests total.
    """
    try:
        from ..resources.endpoint_catalog import catalog_meta

        meta = catalog_meta()
    except Exception:
        return None
    if not meta.get("files"):
        return None

    root = _http_get_json(
        "https://api.github.com/repos/PaloAltoNetworks/pan.dev/contents/openapi-specs"
    )
    if not isinstance(root, list):
        return None
    tree_names = {t.split("/", 1)[1] for t in meta.get("trees", [])}
    upstream: dict[str, str] = {}
    for entry in root:
        name = entry.get("name", "")
        if name not in tree_names or entry.get("type") != "dir":
            continue
        tree = _http_get_json(
            f"https://api.github.com/repos/PaloAltoNetworks/pan.dev/git/trees/"
            f"{entry.get('sha', '')}?recursive=1"
        )
        if not isinstance(tree, dict):
            return None
        for item in tree.get("tree", []):
            if item.get("type") == "blob" and item.get("path", "").endswith(_SPEC_EXTS):
                upstream[f"openapi-specs/{name}/{item['path']}"] = item.get("sha", "")

    if not upstream:
        return None
    bundled: dict[str, str] = {
        rel: sha for rel, sha in meta["files"].items() if rel.endswith(_SPEC_EXTS)
    }
    new = sorted(rel for rel in upstream if rel not in bundled)
    changed = sorted(rel for rel, sha in upstream.items() if rel in bundled and bundled[rel] != sha)
    removed = sorted(rel for rel in bundled if rel not in upstream)
    return meta, new, changed, removed


# ── Tool registration ─────────────────────────────────────────────────────────


def _connected_mu_count(client: Any, tsg_id: str, region: str) -> int | None:
    """Live connected mobile-user count via Insights v3.0; None on any failure.

    ``region`` arrives as a settings.toml ``insights_region`` key, so it is
    normalised here rather than going into the header raw.
    """
    session = getattr(client, "session", None)
    if session is None:
        return None
    oauth = getattr(client, "oauth_client", None)
    if oauth is not None:
        try:
            if oauth.is_expired or oauth.token_expires_soon:
                oauth.refresh_token()
        except Exception:
            pass
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-PANW-Region": region_header(region) or "europe",
    }
    if tsg_id:
        headers["Prisma-Tenant"] = tsg_id
    try:
        resp = session.post(
            f"{_INSIGHTS_BASE}/users/agent/connected_user_count",
            json={},
            headers=headers,
            timeout=(5, 15),
        )
        if resp.status_code != 200:
            return None
        items = resp.json().get("data", [])
        val = items[0].get("user_count") if items else None
        return int(val) if val is not None else None
    except Exception:
        return None


# ── Renewal brief helpers (pure — unit-tested without an SCM client) ─────────


def _licence_rows(lics: list[dict]) -> list[dict[str, Any]]:
    """Group licence bundles by (app_id, license_type, expiry date) into rows.

    Grouping uses the expiry *date*, not the full timestamp — the Subscription
    API returns bundles for the same SKU whose expirations differ only in
    seconds, which would otherwise produce duplicate-looking rows and
    repeated talking points.

    Returns rows sorted soonest-expiry-first, each with:
    app, exp, license_type, purchased, remaining, consumed, days.
    """
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}
    for bundle in lics:
        app = bundle.get("app_id", "unknown")
        for sub in bundle.get("licenses", []):
            exp = str(sub.get("license_expiration", ""))
            lic_type = str(sub.get("license_type", ""))
            key = (app, lic_type, exp[:10])
            if key not in groups:
                groups[key] = {
                    "app": app,
                    "exp": exp,
                    "license_type": lic_type,
                    "purchased": 0,
                    "remaining": 0,
                }
            groups[key]["purchased"] += int(sub.get("purchased_size", 0) or 0)
            groups[key]["remaining"] += int(sub.get("remaining_size", 0) or 0)

    rows: list[dict[str, Any]] = []
    for g in groups.values():
        g["consumed"] = g["purchased"] - g["remaining"]
        g["days"] = _parse_expiry_str(g["exp"])
        rows.append(g)
    rows.sort(key=lambda r: r["days"] if r["days"] is not None else 99_999)
    return rows


def _consumption_signal(purchased: int, consumed: int, underuse_pct: int = 40) -> str:
    """Classify seat consumption against contract for renewal conversations.

    Negative consumption (remaining > purchased) happens on pooled parent
    SKUs where the pool exceeds this tenant's purchase — that's a data
    artefact, not underuse, so it's N/A rather than UNDERUSED.
    """
    if purchased <= 0 or consumed < 0:
        return "N/A"
    pct = consumed / purchased * 100
    if pct > 100:
        return "OVERSUBSCRIBED"
    if pct < underuse_pct:
        return "UNDERUSED"
    return "HEALTHY"


def _renewal_talking_points(
    rows: list[dict[str, Any]],
    horizon_days: int,
    underuse_pct: int,
    bw_total_mbps: float,
    bw_locations: int,
    mu_connected: int | None,
    mu_seats: int,
) -> list[str]:
    """Generate the renewal-conversation bullets from consumption rows.

    Each bullet is one talking point: renewal urgency, true-up (oversubscribed),
    downsize risk (underused), and live capacity headroom.
    """
    points: list[str] = []

    for r in rows:
        days = r["days"]
        if days is not None and days < 0:
            points.append(
                f"🔴 `{r['app']}` **expired {-days} day(s) ago** "
                f"({r['exp'][:10]}) — service-impact risk; renew immediately."
            )
        elif days is not None and days <= horizon_days:
            points.append(
                f"🟡 Renew `{r['app']}` within **{days} day(s)** (expires {r['exp'][:10]})."
            )

    for r in rows:
        if (r["days"] is not None and r["days"] < 0) or r["purchased"] <= 0:
            continue
        signal = _consumption_signal(r["purchased"], r["consumed"], underuse_pct)
        pct = r["consumed"] / r["purchased"] * 100
        if signal == "OVERSUBSCRIBED":
            points.append(
                f"📈 `{r['app']}` is consuming **{r['consumed']:,} of {r['purchased']:,}** "
                f"({pct:.0f}%) — over contract; open a true-up / upsell conversation."
            )
        elif signal == "UNDERUSED":
            points.append(
                f"📉 `{r['app']}` is at **{pct:.0f}%** of {r['purchased']:,} contracted — "
                "downsize risk at renewal; confirm rollout plans or right-size the quote."
            )

    if mu_connected is not None and mu_seats > 0:
        mu_pct = mu_connected / mu_seats * 100
        headroom = (
            "near seat capacity — quote additional seats" if mu_pct >= 80 else "healthy headroom"
        )
        points.append(
            f"👤 **{mu_connected:,}** mobile users connected now against "
            f"**{mu_seats:,}** licensed seats ({mu_pct:.0f}% — {headroom})."
        )

    if bw_total_mbps > 0:
        points.append(
            f"🌐 **{bw_total_mbps:,.0f} Mbps** allocated across "
            f"**{bw_locations}** compute location(s)."
        )

    if not points:
        points.append(f"🟢 No renewal risks detected within the next {horizon_days} days.")
    # Same-SKU bundles can still collapse to word-identical bullets — say it once.
    return list(dict.fromkeys(points))


# Fields of a certificate import that carry key material; never echoed.
_CERT_SECRET_FIELDS = frozenset({"key_file", "passphrase", "certificate_file"})
_CERT_FORMATS = ("pem", "pkcs12", "der")
# SCM refuses a longer key passphrase (400 API_I00013, "at most 31 characters").
_CERT_PASSPHRASE_MAX = 31


def _redact_secrets(text: str, payload: dict[str, Any]) -> str:
    for field in _CERT_SECRET_FIELDS:
        value = payload.get(field)
        if value:
            text = text.replace(str(value), f"<{field} redacted>")
    return text


def _describe_cert(cert: Any) -> dict[str, str]:
    from cryptography import x509

    try:
        is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        is_ca = False
    return {
        "Subject": cert.subject.rfc4514_string(),
        "Issuer": cert.issuer.rfc4514_string(),
        "CA": "yes" if is_ca else "no",
        "Serial Number": format(cert.serial_number, "x"),
        "Not Valid Before": cert.not_valid_before_utc.isoformat(),
        "Not Valid After": cert.not_valid_after_utc.isoformat(),
    }


def _prepare_cert_import(
    *, pem: str, private_key_pem: str, certificate_file_b64: str, fmt: str, passphrase: str
) -> tuple[str, str, str, list[dict[str, str]], bool] | str:
    """Validate the inputs and build the import API's base64 fields.

    Returns (certificate_file, key_file, passphrase, per-cert summaries,
    has_key), or an error message. Parsing errors never include key material.

    SCM rejects a key without a passphrase (400 API_I00035) even when the key
    is unencrypted, so an unencrypted PEM key is re-encrypted locally — with
    the caller's passphrase, or a random one — and sent with that passphrase.
    """
    import base64
    import binascii
    import secrets

    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import (
        BestAvailableEncryption,
        Encoding,
        PrivateFormat,
        load_pem_private_key,
        pkcs12,
    )

    if fmt not in _CERT_FORMATS:
        return f"format must be one of {', '.join(_CERT_FORMATS)}"
    if bool(pem.strip()) == bool(certificate_file_b64.strip()):
        return "supply exactly one of pem or certificate_file_b64"
    if len(passphrase) > _CERT_PASSPHRASE_MAX:
        return f"passphrase must be at most {_CERT_PASSPHRASE_MAX} characters (SCM limit)"
    secret = passphrase.encode() if passphrase else None

    if pem.strip():
        if fmt != "pem":
            return "pem input requires format='pem'"
        try:
            certs = x509.load_pem_x509_certificates(pem.strip().encode())
        except ValueError:
            return "pem could not be parsed as one or more PEM certificates"
        key_file = ""
        key_bytes = private_key_pem.strip().encode()
        if key_bytes:
            try:
                plain_key = load_pem_private_key(key_bytes, password=None)
            except TypeError:  # encrypted: sent unchanged once the passphrase opens it
                if not secret:
                    return "private_key_pem is encrypted — pass its passphrase"
                try:
                    load_pem_private_key(key_bytes, password=secret)
                except (ValueError, TypeError):
                    return "private_key_pem could not be loaded (wrong format or passphrase)"
            except ValueError:
                return "private_key_pem could not be loaded (wrong format or passphrase)"
            else:
                passphrase = passphrase or secrets.token_urlsafe(18)  # 24 chars
                key_bytes = plain_key.private_bytes(
                    Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(passphrase.encode())
                )
            key_file = base64.b64encode(key_bytes).decode()
        certificate_file = base64.b64encode(pem.strip().encode()).decode()
        summaries = [_describe_cert(c) for c in certs]
        return certificate_file, key_file, passphrase, summaries, bool(key_file)

    if private_key_pem.strip():
        return "private_key_pem is only used with pem input; a pkcs12 file carries its own key"
    try:
        raw = base64.b64decode(certificate_file_b64.strip(), validate=True)
    except (binascii.Error, ValueError):
        return "certificate_file_b64 is not valid base64"
    if fmt == "pkcs12":
        if not secret:
            return "a pkcs12 import requires passphrase"
        try:
            key, cert, extra = pkcs12.load_key_and_certificates(raw, secret)
        except (ValueError, TypeError):
            return "pkcs12 file could not be opened (wrong passphrase or not PKCS#12)"
        certs = [c for c in [cert, *extra] if c is not None]
        summaries = [_describe_cert(c) for c in certs]
        return certificate_file_b64.strip(), "", passphrase, summaries, key is not None
    if fmt == "der":
        try:
            certs = [x509.load_der_x509_certificate(raw)]
        except ValueError:
            return "der file could not be parsed as a certificate"
        return (
            certificate_file_b64.strip(),
            "",
            passphrase,
            [_describe_cert(c) for c in certs],
            False,
        )
    return "pem format requires the pem argument"


def register_ops_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register operational visibility and MSSP dashboard tools."""
    tool = scm_tool(get_client)
    tool = scm_tool(get_client)
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_cert_scan(
        client: Any, folder: str = "Shared", warn_days: int = 90, all_folders: bool = True
    ) -> str:
        """Scan all SCM certificate objects and flag anything expiring soon.

        Fetches certificates from the SCM config store via the certificates
        REST API and checks each against today's date. Covers CA certificates,
        SSL/TLS inspection certs, IKE certs, and SAML signing certificates
        stored as SCM objects.

        Also lists any IKE gateways configured to use certificate
        authentication (rather than pre-shared keys), so the operator can
        cross-reference gateway names against the certificate table above.

        Args:
            folder: Primary SCM folder to scan (default: Shared).
            tenant_id: SCM tenant ID (MSSP mode). Leave empty for the active
                       single-tenant client.
            warn_days: Highlight certs expiring within this many days
                       (default 90). CRITICAL threshold is always 30 days,
                       WARNING is always 60 days.
            all_folders: Also scan Remote Networks, Mobile Users, Service
                         Connections folders (default: True).

        Returns:
            Markdown report: status summary, full cert table sorted by expiry,
            and IKE gateway cert-auth cross-reference.
        """

        session = getattr(client, "session", None)
        if session is None:
            return "Error: no HTTP session available on SCM client."

        # Collect certs from all relevant folders, deduplicate by cert ID
        scan_folders = [folder] + ([f for f in _CERT_FOLDERS if f != folder] if all_folders else [])
        seen: set[str] = set()
        certs: list[dict] = []
        for f in scan_folders:
            for c in _fetch_certs(session, f):
                cid = str(c.get("id", c.get("name", "")))
                if cid not in seen:
                    seen.add(cid)
                    certs.append(c)

        if not certs:
            return (
                f"No certificate objects found in folders: {', '.join(scan_folders)}.\n"
                "If this tenant uses only pre-shared key IKE authentication the cert "
                "store may be empty — that is normal."
            )

        # Enrich each cert with computed fields
        rows: list[dict] = []
        for c in certs:
            days = _days_until_epoch(c.get("expiry_epoch", ""))
            # Shorten issuer DN to just the CN= component
            issuer_dn = c.get("issuer", "")
            issuer_cn = next(
                (p[3:] for p in issuer_dn.split("/") if p.startswith("CN=")),
                issuer_dn[:50],
            )
            rows.append(
                {
                    "name": c.get("name", "?"),
                    "cn": c.get("common_name", c.get("name", "?")),
                    "type": "CA" if c.get("ca") else "Leaf",
                    "issuer_cn": issuer_cn,
                    "expires": c.get("not_valid_after", "?"),
                    "days": days,
                    "status": _status(days, warn_days),
                    "location": c.get("snippet") or c.get("folder") or "?",
                }
            )

        rows.sort(key=lambda r: r["days"] if r["days"] is not None else 99_999)

        # Status counts
        counts: dict[str, int] = {}
        for r in rows:
            counts[r["status"]] = counts.get(r["status"], 0) + 1

        flagged = sum(counts.get(s, 0) for s in ("EXPIRED", "CRITICAL", "WARNING", "CAUTION"))
        ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

        lines: list[str] = [
            "## Certificate Expiry Scan",
            "",
            f"**Certificates scanned:** {len(certs)}  "
            f"| **Flagged (≤ {warn_days} days):** {flagged}  "
            f"| **Generated:** {ts}",
            "",
        ]

        # Inline status badges
        badges = [
            f"{_STATUS_EMOJI[s]} {s}: {counts[s]}"
            for s in ("EXPIRED", "CRITICAL", "WARNING", "CAUTION", "OK")
            if s in counts
        ]
        lines.append("  ".join(badges))
        lines.append("")

        # Certificate table
        lines += [
            "| Certificate | Type | Common Name | Issuer CN | Expires (GMT) | Days | Status | Location |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for r in rows:
            emoji = _STATUS_EMOJI.get(r["status"], "")
            days_s = str(r["days"]) if r["days"] is not None else "?"
            lines.append(
                f"| `{r['name']}` | {r['type']} | {r['cn']} | {r['issuer_cn']} "
                f"| {r['expires']} | {days_s} | {emoji} {r['status']} | {r['location']} |"
            )

        # IKE gateways using cert auth — quick REST pull, no full snapshot needed
        gw_data = _quick_list(session, "ike-gateways", {"folder": "Remote Networks"})
        cert_gws = [
            gw for gw in gw_data if (gw.get("authentication") or {}).get("certificate") is not None
        ]
        if cert_gws:
            lines += [
                "",
                "### IKE Gateways Using Certificate Authentication",
                "",
                "| Gateway | Local Certificate | Version | Peer |",
                "|---|---|---|---|",
            ]
            for gw in cert_gws:
                cert_ref = gw.get("authentication", {}).get("certificate") or {}
                local_cert = (
                    (cert_ref.get("local_certificate") or {}).get("name", "?")
                    if isinstance(cert_ref, dict)
                    else "?"
                )
                version = (gw.get("protocol") or {}).get("version", "?")
                peer = (
                    (gw.get("peer_address") or {}).get("ip")
                    or (gw.get("peer_address") or {}).get("fqdn")
                    or "dynamic"
                )
                lines.append(f"| `{gw['name']}` | `{local_cert}` | {version} | {peer} |")
        else:
            lines += [
                "",
                "> All IKE gateways use pre-shared key authentication "
                "— no cert-auth gateways found.",
            ]

        return "\n".join(lines)

    @mcp.tool()
    def scm_cert_lifecycle(
        tenant_id: str = "",
        warn_days: int = 90,
        all_tenants: bool = False,
    ) -> str:
        """Multi-tenant TLS certificate lifecycle dashboard.

        Sweeps all SCM certificate objects across one or all MSSP tenants.
        Identifies SSL inspection CA certificates — these are the most critical
        to monitor because expiry silently disables SSL decryption with no
        user-visible error. Produces per-tenant expiry detail and a cross-tenant
        summary table for the MSSP morning brief.

        SSL Inspection CA detection: any CA-type certificate (ca=true) whose
        name or CN contains 'ssl', 'inspect', 'decrypt', 'forward-proxy',
        or 'intercept' is flagged as a probable SSL inspection CA.

        Args:
            tenant_id: SCM tenant ID. Leave empty for the active tenant.
            warn_days: Days threshold for CAUTION status (default 90).
            all_tenants: If True (MSSP mode), sweep all configured MSSP tenants.
        """
        try:
            targets: list[tuple[str, Any]] = []
            if all_tenants:
                for key, tc in _load_all_tenant_configs().items():
                    try:
                        targets.append((tc.label or key, get_scm_client(tc)))
                    except Exception as exc:
                        logger.warning("cert_lifecycle_auth_failed", tenant=key, error=str(exc))
                        targets.append((tc.label or key, None))
            else:
                client = get_client(tenant_id)
                targets = [(tenant_id or "active tenant", client)]
        except Exception as exc:
            return f"Error: {handle_scm_exception(exc)}"

        ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        _SSL_INSPECT_KEYWORDS = frozenset(
            {"ssl", "inspect", "decrypt", "forward-proxy", "intercept", "tls-ca"}
        )

        def _is_ssl_inspect_ca(cert: dict[str, Any]) -> bool:
            if not cert.get("ca"):
                return False
            name_lower = (cert.get("name", "") + " " + cert.get("common_name", "")).lower()
            return any(kw in name_lower for kw in _SSL_INSPECT_KEYWORDS)

        # Summary table data: (label, total, critical+expired, ssl_ca_critical, worst_days)
        summary_rows: list[dict[str, Any]] = []
        detail_sections: list[str] = []
        multi = len(targets) > 1

        def _section(label: str, client: Any) -> tuple[dict[str, Any] | None, str]:
            if client is None:
                return (
                    {
                        "label": label,
                        "total": 0,
                        "flagged": 0,
                        "ssl_ca_critical": 0,
                        "worst": None,
                        "status": "ERR",
                    },
                    f"### {label}\n\n> ⚠️ Authentication failed — skipped.\n",
                )

            session = getattr(client, "session", None)
            if session is None:
                return (None, f"### {label}\n\n> No HTTP session available.\n")

            # Collect certs across all standard folders
            seen: set[str] = set()
            certs: list[dict[str, Any]] = []
            for folder in _CERT_FOLDERS:
                for c in _fetch_certs(session, folder):
                    cid = str(c.get("id", c.get("name", "")))
                    if cid not in seen:
                        seen.add(cid)
                        certs.append(c)

            if not certs:
                return (
                    {
                        "label": label,
                        "total": 0,
                        "flagged": 0,
                        "ssl_ca_critical": 0,
                        "worst": None,
                        "status": "OK",
                    },
                    f"### {label}\n\n> No certificate objects found. "
                    "Tenant may use only pre-shared key authentication.\n",
                )

            rows: list[dict[str, Any]] = []
            for c in certs:
                days = _days_until_epoch(c.get("expiry_epoch", ""))
                issuer_dn = c.get("issuer", "")
                issuer_cn = next(
                    (p[3:] for p in issuer_dn.split("/") if p.startswith("CN=")),
                    issuer_dn[:40],
                )
                rows.append(
                    {
                        "name": c.get("name", "?"),
                        "cn": c.get("common_name", c.get("name", "?"))[:30],
                        "type": "CA" if c.get("ca") else "Leaf",
                        "ssl_ca": _is_ssl_inspect_ca(c),
                        "issuer_cn": issuer_cn[:30],
                        "expires": c.get("not_valid_after", "?"),
                        "days": days,
                        "status": _status(days, warn_days),
                        "location": c.get("snippet") or c.get("folder") or "?",
                    }
                )

            rows.sort(key=lambda r: r["days"] if r["days"] is not None else 99_999)
            flagged = [
                r for r in rows if r["status"] in ("EXPIRED", "CRITICAL", "WARNING", "CAUTION")
            ]
            ssl_ca_critical = [
                r for r in rows if r["ssl_ca"] and r["status"] in ("EXPIRED", "CRITICAL")
            ]
            worst_days = rows[0]["days"] if rows else None
            worst_status = rows[0]["status"] if rows else "OK"

            summary_row = {
                "label": label,
                "total": len(certs),
                "flagged": len(flagged),
                "ssl_ca_critical": len(ssl_ca_critical),
                "worst": worst_days,
                "status": worst_status,
            }

            sec: list[str] = []
            if multi:
                sec.append(f"### {label}")
                sec.append("")

            if ssl_ca_critical:
                sec.append(
                    "🔴 **CRITICAL: SSL Inspection CA certificate(s) expiring — SSL decryption will silently stop!**"
                )
                sec.append("")

            counts: dict[str, int] = {}
            for r in rows:
                counts[r["status"]] = counts.get(r["status"], 0) + 1
            badges = [
                f"{_STATUS_EMOJI[s]} {s}: {counts[s]}"
                for s in ("EXPIRED", "CRITICAL", "WARNING", "CAUTION", "OK")
                if s in counts
            ]
            sec.append("  ".join(badges))
            sec.append("")
            sec += [
                "| Certificate | Type | SSL-Inspect CA | Expires | Days | Status | Location |",
                "|---|---|---|---|---|---|---|",
            ]
            for r in rows:
                emoji = _STATUS_EMOJI.get(r["status"], "")
                days_s = str(r["days"]) if r["days"] is not None else "?"
                ssl_flag = "🔑 YES" if r["ssl_ca"] else "—"
                sec.append(
                    f"| `{r['name']}` | {r['type']} | {ssl_flag} "
                    f"| {r['expires']} | {days_s} | {emoji} {r['status']} | {r['location']} |"
                )
            sec.append("")
            return (summary_row, "\n".join(sec))

        for label, ok, payload in _gather_parallel(targets, _section):
            if not ok or payload is None:
                detail_sections.append(f"### {label}\n\n> ⏱ Slow/skipped — exceeded poll budget.\n")
                summary_rows.append(
                    {
                        "label": label,
                        "total": 0,
                        "flagged": 0,
                        "ssl_ca_critical": 0,
                        "worst": None,
                        "status": "ERR",
                    }
                )
                continue
            summary_row, detail = payload
            if summary_row is not None:
                summary_rows.append(summary_row)
            detail_sections.append(detail)

        lines: list[str] = [
            "## Certificate Lifecycle Dashboard",
            "",
            f"**Generated:** {ts}  |  **Warn threshold:** {warn_days} days",
            "",
        ]

        # Cross-tenant summary table (only when multiple tenants)
        if len(targets) > 1 and summary_rows:
            lines += [
                "### Cross-Tenant Summary",
                "",
                "| Tenant | Certs | Flagged | SSL-CA Critical | Worst Expiry (days) | Status |",
                "|---|---|---|---|---|---|",
            ]
            for s in summary_rows:
                emoji = _STATUS_EMOJI.get(s["status"], "⚪")
                worst = str(s["worst"]) if s["worst"] is not None else "—"
                lines.append(
                    f"| {s['label']} | {s['total']} | {s['flagged']} "
                    f"| {s['ssl_ca_critical']} | {worst} | {emoji} {s['status']} |"
                )
            lines.append("")
            lines.append("---")
            lines.append("")

        lines.extend(detail_sections)
        lines += [
            "---",
            "",
            "**SSL Inspection CA** — a CA-type cert whose name/CN suggests use as an SSL "
            "Forward Proxy CA. If this expires, decryption silently stops with no alert.",
            "Run `scm_cert_import` to upload replacement certs or `scm_tls_profile_manager` "
            "to review TLS inspection profiles.",
        ]
        return "\n".join(lines)

    @mcp.tool()
    @tool
    def scm_cert_import(
        client: Any,
        tenant_id: str,
        name: str,
        pem: str = "",
        folder: str = "Shared",
        is_ca: bool = False,
        private_key_pem: str = "",
        certificate_file_b64: str = "",
        format: str = "pem",
        passphrase: str = "",
        dry_run: bool = True,
        ticket_ref: str = "",
    ) -> str:
        """Import a certificate (optionally with its private key) into an SCM folder.

        Uses the certificate import API (``POST /sse/config/v1/certificates:import``).
        Use it to deploy an SSL inspection CA (forward-trust needs the private
        key), replace an expiring cert, or add a trusted root CA.

        Supply ONE of:
          - ``pem``: PEM certificate text (a chain of several blocks is fine),
            plus ``private_key_pem`` when the key is needed (and ``passphrase``
            if that key is encrypted); ``format`` stays ``pem``.
          - ``certificate_file_b64``: base64 of a binary file with
            ``format="pkcs12"`` (certificate + key, needs ``passphrase``) or
            ``format="der"``.

        Private keys and passphrases are never echoed, logged or written to
        the audit log. Importing a CA does not make it the decryption
        forward-trust certificate — select that in SSL decryption settings.
        After import, run scm_commit to activate the new certificate.

        Args:
            name: Certificate object name in SCM (e.g. "SSL-Inspect-CA-2026").
            pem: PEM certificate text (the -----BEGIN CERTIFICATE----- block(s)).
            folder: SCM folder to import into (default: Shared).
            is_ca: Deprecated and ignored — the import API has no CA flag; SCM
                reads CA status from the certificate itself.
            private_key_pem: PEM private key for ``pem`` imports (optional).
            certificate_file_b64: Base64 file content for pkcs12/der imports.
            format: ``pem`` (default), ``pkcs12`` or ``der``.
            passphrase: Key/PKCS#12 passphrase (required for pkcs12 and for an
                encrypted pem key). An unencrypted pem key is encrypted locally
                before sending — SCM rejects a key without a passphrase.
            dry_run: If True (default), parse and describe the certificate
                without importing it.
            ticket_ref: Mandatory change-ticket reference (never sent to SCM).
            tenant_id: SCM tenant ID. Defaults to the configured default tenant.

        **Write safety (SSR pattern):** ``dry_run=True`` by default;
        ``ticket_ref`` is mandatory.
        """
        err = ticket_ref_error(ticket_ref)
        if err:
            return f"Error: {err}"
        ticket_ref = normalize_ticket_ref(ticket_ref)

        prepared = _prepare_cert_import(
            pem=pem,
            private_key_pem=private_key_pem,
            certificate_file_b64=certificate_file_b64,
            fmt=format,
            passphrase=passphrase,
        )
        if isinstance(prepared, str):
            return f"Error: {prepared}"
        certificate_file, key_file, passphrase, summaries, has_key = prepared

        if dry_run:
            lines = [
                "## Certificate Import — DRY-RUN",
                "",
                "| Field | Value |",
                "|---|---|",
                f"| Name | `{name}` |",
                f"| Folder | `{folder}` |",
                f"| Format | {format} |",
                f"| Private key | {'included' if has_key else 'not included'} |",
                f"| Ticket ref | {ticket_ref} |",
            ]
            for i, summary in enumerate(summaries, 1):
                prefix = f"Cert {i} " if len(summaries) > 1 else ""
                lines += [f"| {prefix}{k} | {v} |" for k, v in summary.items()]
            lines += [
                "",
                "Would POST to `/sse/config/v1/certificates:import` "
                "(certificate, key and passphrase not echoed here).",
                "",
                DRY_RUN_HINT,
            ]
            return "\n".join(lines)

        payload: dict[str, Any] = {
            "name": name,
            "folder": folder,
            "certificate_file": certificate_file,
            "format": format,
        }
        if key_file:
            payload["key_file"] = key_file
        if passphrase:
            payload["passphrase"] = passphrase

        audit_write(
            "scm_cert_import",
            ticket_ref,
            tenant_id,
            name=name,
            folder=folder,
            format=format,
            private_key=has_key,
        )
        try:
            result = client.post(f"{_SSE_CONFIG_PATH}/certificates:import", json=payload)
        except Exception as exc:
            return f"Error: certificate import failed: {_redact_secrets(str(exc), payload)}"

        logger.info(
            "cert_imported",
            name=name,
            folder=folder,
            format=format,
            private_key=has_key,
            tenant_id=tenant_id,
        )

        import json as _json

        shown = (
            {k: v for k, v in result.items() if k not in _CERT_SECRET_FIELDS}
            if isinstance(result, dict)
            else {"result": str(result)}
        )
        return (
            f"✅ Certificate `{name}` imported into folder `{folder}`"
            f"{' with its private key' if has_key else ''}.\n\n"
            + _json.dumps(shown, indent=2, default=str)
            + f"\n\nRun `scm_commit(folders=['{folder}'], ticket_ref=..., dry_run=False)` to activate."
        )

    @mcp.tool()
    @tool
    def scm_tls_profile_manager(
        client: Any,
        tenant_id: str,
        action: str = "list",
        name: str = "",
        min_version: str = "tls1-2",
        max_version: str = "tls1-3",
        cert_profile: str = "",
        folder: str = "Shared",
        dry_run: bool = True,
        ticket_ref: str = "",
    ) -> str:
        """List or create TLS service profiles for SSL inspection configuration.

        TLS service profiles define which TLS versions and cipher suites are
        permitted in SSL Forward Proxy inspection. They are referenced by
        decryption profiles, which are in turn applied by decryption rules.

        action='list'   — list all TLS service profiles for this tenant
        action='create' — create a new profile (requires name parameter)

        Created profiles default to TLS 1.2 minimum, TLS 1.3 maximum —
        the NCSC/CE-recommended baseline that blocks legacy TLS.

        Args:
            action: 'list' or 'create'.
            name: Profile name (required for create).
            min_version: Minimum TLS version ('tls1-2' or 'tls1-3'). Default: 'tls1-2'.
            max_version: Maximum TLS version ('tls1-2' or 'tls1-3'). Default: 'tls1-3'.
            cert_profile: Optional certificate profile name for client cert validation.
            folder: SCM folder (default: Shared).
            dry_run: For action='create': if True (default), return the planned
                profile without creating it.
            ticket_ref: Mandatory change-ticket reference for action='create'
                (never sent to SCM).
            tenant_id: SCM tenant ID. Defaults to the configured default tenant.

        **Write safety (SSR pattern):** ``action='create'`` is a write —
        ``dry_run=True`` by default and ``ticket_ref`` is mandatory.
        ``action='list'`` is read-only and needs neither.
        """
        import json as _json

        if action == "list":
            result = client.get(
                f"{_SSE_CONFIG_PATH}/tls-service-profiles",
                params={"folder": folder, "limit": 200},
            )
            profiles: list[dict[str, Any]] = []
            if isinstance(result, dict):
                profiles = result.get("data", [])
            elif isinstance(result, list):
                profiles = result

            if not profiles:
                return (
                    f"No TLS service profiles found in folder `{folder}`.\n\n"
                    "Create one with `scm_tls_profile_manager(action='create', name='...')`."
                )

            lines = [
                f"## TLS Service Profiles — {folder} ({tenant_id or 'default tenant'})",
                "",
                f"Total: {len(profiles)}",
                "",
                "| Name | Min TLS | Max TLS | Cert Profile | Auth |",
                "|---|---|---|---|---|",
            ]
            for p in profiles:
                pname = p.get("name", "?")
                proto = p.get("protocol_settings") or p.get("protocol") or {}
                if isinstance(proto, dict):
                    min_v = proto.get("min_version", proto.get("min-version", "—"))
                    max_v = proto.get("max_version", proto.get("max-version", "—"))
                else:
                    min_v = max_v = "—"
                cp = p.get("certificate_profile", "—")
                auth = p.get("client_authentication", [])
                auth_s = (
                    ", ".join(a.get("name", str(a)) for a in auth)
                    if isinstance(auth, list)
                    else str(auth)
                )
                lines.append(f"| `{pname}` | {min_v} | {max_v} | {cp} | {auth_s or '—'} |")
            return "\n".join(lines)

        elif action == "create":
            err = ticket_ref_error(ticket_ref)
            if err:
                return f"Error: {err}"
            ticket_ref = normalize_ticket_ref(ticket_ref)
            if not name:
                return "Error: `name` is required when action='create'."

            payload: dict[str, Any] = {
                "name": name,
                "folder": folder,
                "protocol_settings": {
                    "min_version": min_version,
                    "max_version": max_version,
                    "auth_algo_sha1": False,
                    "auth_algo_sha256": True,
                    "auth_algo_sha384": True,
                    "enc_algo_3des": False,
                    "enc_algo_rc4": False,
                    "enc_algo_aes_128_cbc": False,
                    "enc_algo_aes_256_cbc": True,
                    "enc_algo_aes_128_gcm": True,
                    "enc_algo_aes_256_gcm": True,
                },
            }
            if cert_profile:
                payload["certificate_profile"] = cert_profile

            if dry_run:
                return (
                    f"## TLS Service Profile Create — DRY-RUN — `{name}`\n\n"
                    f"Ticket ref: {ticket_ref}\n\n"
                    "Would POST to `{_SSE_CONFIG_PATH}/tls-service-profiles`:\n\n"
                    f"```json\n{_json.dumps(payload, indent=2)}\n```\n\n{DRY_RUN_HINT}"
                )

            audit_write("scm_tls_profile_manager", ticket_ref, tenant_id, name=name, folder=folder)
            result = client.post(f"{_SSE_CONFIG_PATH}/tls-service-profiles", json=payload)
            logger.info(
                "tls_profile_created",
                name=name,
                folder=folder,
                min_version=min_version,
                max_version=max_version,
                tenant_id=tenant_id,
            )

            detail = (
                _json.dumps(
                    result if isinstance(result, dict) else {"result": str(result)},
                    indent=2,
                    default=str,
                )
                if result
                else ""
            )

            return (
                f"✅ TLS service profile `{name}` created in folder `{folder}`.\n\n"
                f"Settings: TLS {min_version} — {max_version}, strong ciphers only "
                "(AES-256-GCM, AES-128-GCM, SHA-256/384; no 3DES, RC4, SHA-1).\n"
                + (f"\n```json\n{detail}\n```\n" if detail else "")
                + f"\nRun `scm_commit(folders=['{folder}'], ticket_ref=..., dry_run=False)` to activate."
            )
        else:
            return f"Error: unknown action '{action}'. Use 'list' or 'create'."

    # ─────────────────────────────────────────────────────────────────────────

    @mcp.tool()
    def scm_licence_forecast(
        tenant_id: str = "",
        warn_days: int = 90,
        all_tenants: bool = False,
    ) -> str:
        """Forecast licence expiry dates and seat utilisation.

        Pulls subscription licence data from the PAN Subscription Service API
        and groups entries by product (app_id), reporting the earliest expiry
        per product and seat consumption. Useful for proactive renewals and
        to catch oversubscribed licence pools before users are impacted.

        Seat utilisation is calculated as:
            consumed = purchased_size − remaining_size
            % used   = consumed / purchased_size × 100

        Args:
            tenant_id: SCM tenant ID (MSSP mode). Leave empty for the active
                       single-tenant client.
            warn_days: Flag licences expiring within this many days (default 90).
                       CRITICAL is always <30 days, WARNING is always <60 days.
            all_tenants: If True (MSSP mode), scan every configured tenant and
                         produce a combined forecast. Overrides tenant_id.

        Returns:
            Markdown table(s) with expiry status, days remaining, and
            seat utilisation per product per tenant.
        """
        try:
            targets: list[tuple[str, Any]] = []
            if all_tenants:
                for key, tc in _load_all_tenant_configs().items():
                    try:
                        targets.append((tc.label, get_scm_client(tc)))
                    except Exception as exc:
                        logger.warning("lic_forecast_auth_failed", tenant=key, error=str(exc))
                        targets.append((tc.label, None))
            else:
                client = get_client(tenant_id)
                targets = [(tenant_id or "active tenant", client)]
        except Exception as exc:
            return f"Error: {handle_scm_exception(exc)}"

        ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        lines: list[str] = [
            "## Licence Expiry Forecast",
            "",
            f"**Generated:** {ts}  | **Warn threshold:** {warn_days} days",
            "",
        ]

        multi = len(targets) > 1

        def _section(label: str, client: Any) -> tuple[list[str], bool]:
            out: list[str] = []
            if client is None:
                out += [f"### {label}", "", "> ⚠️ Authentication failed — skipped.", ""]
                return out, True

            lics = fetch_licenses(client)
            if not lics:
                out += [f"### {label}", "", "> No licence data returned.", ""]
                return out, True

            section_ok = True
            # Aggregate: (app_id, expiry_str) → totals
            groups: dict[tuple[str, str], dict[str, Any]] = {}
            for bundle in lics:
                app = bundle.get("app_id", "unknown")
                for sub in bundle.get("licenses", []):
                    exp = str(sub.get("license_expiration", ""))
                    key: tuple[str, str] = (app, exp)
                    if key not in groups:
                        groups[key] = {
                            "app": app,
                            "exp": exp,
                            "lic_type": sub.get("license_type", ""),
                            "purchased": 0,
                            "remaining": 0,
                        }
                    groups[key]["purchased"] += int(sub.get("purchased_size", 0) or 0)
                    groups[key]["remaining"] += int(sub.get("remaining_size", 0) or 0)

            rows = sorted(
                groups.values(),
                key=lambda x: _parse_expiry_str(x["exp"]) or 99_999,
            )

            if multi:
                out.append(f"### {label}")
                out.append("")

            out += [
                "| Product | Expires | Days | Allocated | Consumed | % Used | Status |",
                "|---|---|---|---|---|---|---|",
            ]
            for row in rows:
                days = _parse_expiry_str(row["exp"])
                st = _status(days, warn_days)
                if st != "OK":
                    section_ok = False
                emoji = _STATUS_EMOJI.get(st, "")
                days_s = str(days) if days is not None else "?"
                purchased = row["purchased"]
                remaining = row["remaining"]
                consumed = purchased - remaining
                if purchased > 0:
                    pct_val = consumed / purchased * 100
                    pct = f"{pct_val:.0f}%"
                    if consumed > purchased:
                        pct = f"**{pct} ⚠️ oversubscribed**"
                else:
                    pct = "—"
                out.append(
                    f"| `{row['app']}` | {row['exp'][:19]} | {days_s} "
                    f"| {purchased:,} | {consumed:,} | {pct} | {emoji} {st} |"
                )
            out.append("")
            return out, section_ok

        all_ok = True
        for label, ok, payload in _gather_parallel(targets, _section):
            if not ok or payload is None:
                lines += [f"### {label}", "", "> ⏱ Slow/skipped — exceeded poll budget.", ""]
                all_ok = False
                continue
            sec_lines, sec_ok = payload
            lines += sec_lines
            all_ok = all_ok and sec_ok

        if all_ok and targets:
            lines.insert(4, "> 🟢 All licences are within normal thresholds.\n")

        return "\n".join(lines)

    # ─────────────────────────────────────────────────────────────────────────

    @mcp.tool()
    def scm_renewal_brief(
        tenant_id: str = "",
        all_tenants: bool = False,
        horizon_days: int = 180,
        underuse_pct: int = 40,
    ) -> str:
        """Generate a renewal-conversation brief: licences vs actual consumption.

        Combines three data sources into one commercial view per tenant:
        subscription licences (contracted seats, consumption, expiry) from the
        Subscription Service API, bandwidth allocations per compute location
        from SCM config, and the live connected mobile-user count from the
        Insights v3.0 API.

        The brief flags where consumption contradicts the contract — products
        running OVERSUBSCRIBED (true-up / upsell conversation) or UNDERUSED
        (downsize risk at renewal) — lists everything expiring within the
        horizon, and generates ready-to-use talking points for the renewal
        or QBR conversation.

        Args:
            tenant_id: SCM tenant ID (MSSP mode). Leave empty for the active
                       single-tenant client.
            all_tenants: If True (MSSP mode), produce a combined brief for
                         every configured tenant. Overrides tenant_id.
            horizon_days: Renewal window — licences expiring within this many
                          days are listed and raised as talking points
                          (default 180).
            underuse_pct: Consumption below this percentage of contracted
                          seats is flagged UNDERUSED (default 40).

        Returns:
            Markdown brief per tenant: renewal window table, consumption vs
            contract table, capacity snapshot, and talking points.
        """
        # label → (tsg_id for the Prisma-Tenant header, Insights region)
        metas: dict[str, tuple[str, str]] = {}
        try:
            targets: list[tuple[str, Any]] = []
            if all_tenants:
                for key, tc in _load_all_tenant_configs().items():
                    label = tc.label or key
                    metas[label] = (tc.tenant_id, tc.insights_region)
                    try:
                        targets.append((label, get_scm_client(tc)))
                    except Exception as exc:
                        logger.warning("renewal_brief_auth_failed", tenant=key, error=str(exc))
                        targets.append((label, None))
            else:
                client = get_client(tenant_id)
                label = tenant_id or "active tenant"
                # tenant_id may arrive as a section key or (canonicalised) TSG ID.
                own_cfgs = _load_all_tenant_configs()
                own_tc = own_cfgs.get(tenant_id) or next(
                    (c for c in own_cfgs.values() if c.tenant_id == tenant_id), None
                )
                metas[label] = (
                    own_tc.tenant_id if own_tc is not None else tenant_id,
                    own_tc.insights_region if own_tc is not None else "eu",
                )
                targets = [(label, client)]
        except Exception as exc:
            return f"Error: {handle_scm_exception(exc)}"

        multi = len(targets) > 1
        ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        lines: list[str] = [
            "# Renewal Brief",
            "",
            f"**Generated:** {ts}  |  **Horizon:** {horizon_days} days  |  "
            f"**Underuse threshold:** {underuse_pct}%",
            "",
        ]

        def _section(label: str, client: Any) -> list[str]:
            out: list[str] = [f"## {label}", ""] if multi else []
            if client is None:
                out += ["> ⚠️ Authentication failed — skipped.", ""]
                return out

            tsg_id, region = metas.get(label, ("", "eu"))
            rows = _licence_rows(fetch_licenses(client))
            if not rows:
                out += ["> No licence data returned.", ""]
                return out

            # Bandwidth allocations (global resource; folder is ignored)
            try:
                bw_rows = [
                    b.model_dump() if hasattr(b, "model_dump") else b
                    for b in client.bandwidth_allocation.list()
                ]
            except Exception as exc:
                logger.warning("renewal_brief_bw_failed", tenant=label, error=str(exc))
                bw_rows = []
            bw_total = sum(float(b.get("allocated_bandwidth") or 0) for b in bw_rows)

            mu_connected = _connected_mu_count(client, tsg_id, region)
            # Active PAE mobile-user seat pool (same filter as scm_mobile_user_stats)
            mu_seats = sum(
                r["purchased"]
                for r in rows
                if r["app"] == "prisma_access_edition"
                and "MU" in str(r["license_type"]).upper()
                and (r["days"] is None or r["days"] >= 0)
            )

            # ── Renewal window ────────────────────────────────────────────
            expiring = [r for r in rows if r["days"] is None or r["days"] <= horizon_days]
            out.append(f"### Renewal Window (next {horizon_days} days)")
            out.append("")
            if expiring:
                out += [
                    "| Product | Type | Expires | Days | Status |",
                    "|---|---|---|---|---|",
                ]
                for r in expiring:
                    st = _status(r["days"], horizon_days)
                    emoji = _STATUS_EMOJI.get(st, "")
                    days_s = str(r["days"]) if r["days"] is not None else "?"
                    out.append(
                        f"| `{r['app']}` | {r['license_type']} | {r['exp'][:10]} "
                        f"| {days_s} | {emoji} {st} |"
                    )
            else:
                out.append(f"🟢 Nothing expires within {horizon_days} days.")
            out.append("")

            # ── Consumption vs contract ───────────────────────────────────
            seat_rows = [r for r in rows if r["purchased"] > 0]
            if seat_rows:
                out.append("### Consumption vs Contract")
                out.append("")
                out += [
                    "| Product | Contracted | Consumed | % Used | Signal |",
                    "|---|---|---|---|---|",
                ]
                _signal_emoji = {
                    "OVERSUBSCRIBED": "📈",
                    "UNDERUSED": "📉",
                    "HEALTHY": "🟢",
                    "N/A": "⚪",
                }
                for r in seat_rows:
                    signal = _consumption_signal(r["purchased"], r["consumed"], underuse_pct)
                    # Negative consumption = pooled parent SKU artefact; a
                    # percentage would be misleading noise.
                    pct_s = (
                        f"{r['consumed'] / r['purchased'] * 100:.0f}%"
                        if r["consumed"] >= 0
                        else "—"
                    )
                    out.append(
                        f"| `{r['app']}` | {r['purchased']:,} | {r['consumed']:,} "
                        f"| {pct_s} | {_signal_emoji.get(signal, '')} {signal} |"
                    )
                out.append("")

            # ── Capacity snapshot ─────────────────────────────────────────
            out.append("### Capacity Snapshot")
            out.append("")
            if bw_rows:
                out.append(
                    f"- Bandwidth: **{bw_total:,.0f} Mbps** allocated across "
                    f"**{len(bw_rows)}** compute location(s): "
                    + ", ".join(f"`{b.get('name')}`" for b in bw_rows[:15])
                    + (" …" if len(bw_rows) > 15 else "")
                )
            else:
                out.append("- Bandwidth: no allocations found (no Remote Networks capacity).")
            if mu_connected is not None:
                seats_s = f" of **{mu_seats:,}** licensed seats" if mu_seats else ""
                out.append(f"- Mobile users connected now: **{mu_connected:,}**{seats_s}.")
            else:
                out.append("- Mobile users connected now: unavailable (Insights API).")
            out.append("")

            # ── Talking points ────────────────────────────────────────────
            out.append("### Talking Points")
            out.append("")
            out += [
                f"- {p}"
                for p in _renewal_talking_points(
                    rows,
                    horizon_days,
                    underuse_pct,
                    bw_total,
                    len(bw_rows),
                    mu_connected,
                    mu_seats,
                )
            ]
            out.append("")
            return out

        for label, ok, payload in _gather_parallel(targets, _section, timeout=40):
            if not ok or payload is None:
                lines += [f"## {label}", "", "> ⏱ Slow/skipped — exceeded poll budget.", ""]
                continue
            lines += payload

        return "\n".join(lines)

    # ─────────────────────────────────────────────────────────────────────────

    @mcp.tool()
    def scm_tenant_dashboard(include_expired: bool = False) -> str:
        """Multi-tenant NOC health dashboard — traffic-light overview of all tenants.

        Performs a fast, lightweight data pull for every configured MSSP tenant
        and returns a single Markdown table suitable for a NOC wallboard or
        morning health check. No full snapshot extraction is run — only targeted
        REST calls for rule counts, remote networks, IKE tunnels, and licences.

        Columns:
            Tenant        — tenant label from settings.toml
            Rules         — security rule count (pre-rulebase, Shared folder)
            RNs           — remote network (branch) count
            Tunnels       — IKE gateway count
            PAB           — Prisma Access Browser: enrolled users/devices and the
                            share of devices passing all posture checks (screen
                            lock + disk encryption + firewall); — if unprovisioned
            Nearest Expiry — soonest licence expiry date (see include_expired)
            Days          — days until that expiry
            Lic           — licence RAG status
            Errors        — API call failures during this poll
            RAG           — overall tenant health (🔴 / 🟡 / 🟢)

        Args:
            include_expired: When False (default), already-expired SKUs are
                excluded from the nearest-expiry calculation so the RAG reflects
                operational licence health — i.e. the soonest renewal among
                *active* licences — rather than being dragged permanently
                negative by a long-dead trial/legacy SKU (e.g. an old
                logging_service Production License). A tenant whose licences are
                *all* expired still falls back to its worst expired SKU and flags
                red. Set True to compute the nearest expiry across every SKU.

        Returns:
            Markdown table with one row per tenant.
        """
        tenant_cfgs = _load_all_tenant_configs()
        if not tenant_cfgs:
            return (
                "No MSSP tenants configured. "
                "Set `mssp_mode = true` in settings.toml and add `[tenants.*]` blocks."
            )

        ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

        # PAN cloud status banner — fetched concurrently with the tenant rows
        # from the public statuspage feed; status_banner() returns [] when
        # healthy or unreachable, so it can never break or block the dashboard.
        from .service_status import status_banner

        banner_pool = ThreadPoolExecutor(max_workers=1)
        banner_fut = banner_pool.submit(status_banner)

        lines: list[str] = [
            "## MSSP Tenant Health Dashboard",
            "",
            f"**Generated:** {ts}  | **Tenants:** {len(tenant_cfgs)}",
            "",
            "| Tenant | Rules | RNs | Tunnels | PAB | Nearest Expiry | Days | Lic | Errors | RAG |",
            "|---|---|---|---|---|---|---|---|---|---|",
        ]

        # Build each tenant's row in parallel under a hard wall-clock budget.
        # The per-tenant pulls are independent and I/O-bound, so a single
        # unhealthy tenant (e.g. an endpoint returning 5xx that the SDK session
        # retries with backoff) can no longer block the whole dashboard — it
        # simply renders as a degraded "slow/skipped" row while the rest report
        # normally. This mirrors the bounded-parallel pattern in extractor.py.
        def _row(tc: TenantConfig) -> str:
            try:
                client = get_scm_client(tc)
            except Exception:
                return f"| **{tc.label}** | — | — | — | — | — | — | ⚪ | Auth failed | 🔴 |"

            session = getattr(client, "session", None)
            rules = _quick_list(
                session, "security-rules", {"folder": tc.default_folder, "position": "pre"}
            )
            rns = _quick_list(session, "remote-networks", {"folder": "Remote Networks"})
            tunnels = _quick_list(session, "ike-gateways", {"folder": "Remote Networks"})

            # Nearest licence expiry — by default excludes already-expired SKUs
            # so the RAG tracks active renewal health rather than a long-dead
            # legacy SKU.  See _nearest_licence_expiry for the full rationale.
            try:
                lics = fetch_licenses(client)
            except Exception:
                lics = []
            min_days, min_exp_str = _nearest_licence_expiry(lics, include_expired)

            # PAB posture — single-page pulls; unprovisioned tenants show "—"
            pab = "—"
            try:
                from .pab import _get_json as _pab_get
                from .pab import _posture_ok

                st_u, ub = _pab_get(client, "users", {"limit": 200})
                st_d, db = _pab_get(client, "devices", {"limit": 200})
                if st_u == 200 and isinstance(ub, dict):
                    pab_users = ub.get("data") or []
                    devs = (db.get("data") or []) if st_d == 200 and isinstance(db, dict) else []
                    if pab_users or devs:
                        ok = sum(
                            1
                            for d in devs
                            if _posture_ok(d.get("screenLockStatus"))
                            and _posture_ok(d.get("diskEncryptionStatus"))
                            and _posture_ok(d.get("firewallStatus"))
                        )
                        pct = f" ({round(100 * ok / len(devs))}%✓)" if devs else ""
                        pab = f"{len(pab_users)}u/{len(devs)}d{pct}"
            except Exception:
                pass

            lic_st = _status(min_days)
            lic_emoji = _STATUS_EMOJI.get(lic_st, "⚪")
            days_s = str(min_days) if min_days is not None else "?"

            # Overall RAG — red if expired, amber if expiring soon
            if min_days is not None and min_days < 0:
                rag = "🔴"
            elif min_days is not None and min_days < 60:
                rag = "🟡"
            else:
                rag = "🟢"

            return (
                f"| **{tc.label}** | {len(rules)} | {len(rns)} | {len(tunnels)} | {pab} "
                f"| {min_exp_str} | {days_s} | {lic_emoji} {lic_st} | 0 | {rag} |"
            )

        _DASH_TIMEOUT = 25  # seconds — overall wall-clock budget for the poll
        rows_by_label: dict[str, str] = {}
        pool = ThreadPoolExecutor(max_workers=min(8, len(tenant_cfgs)))
        try:
            fut_to_label = {pool.submit(_row, tc): tc.label for tc in tenant_cfgs.values()}
            done, not_done = wait(
                fut_to_label.keys(), timeout=_DASH_TIMEOUT, return_when=ALL_COMPLETED
            )
            for fut in done:
                label = fut_to_label[fut]
                try:
                    rows_by_label[label] = fut.result()
                except Exception:
                    rows_by_label[label] = (
                        f"| **{label}** | — | — | — | — | — | — | ⚪ | Error | 🔴 |"
                    )
            for fut in not_done:
                label = fut_to_label[fut]
                fut.cancel()
                rows_by_label[label] = (
                    f"| **{label}** | — | — | — | — | — | — | ⏱ | Slow/skipped | 🟡 |"
                )
        finally:
            pool.shutdown(wait=False)

        try:
            banner = banner_fut.result(timeout=5)
        except Exception:
            banner = []
        finally:
            banner_pool.shutdown(wait=False)
        if banner:
            # Slot the banner between the Generated line and the table header.
            lines[4:4] = [*banner, ""]

        # Preserve the configured tenant order.
        for tc in tenant_cfgs.values():
            lines.append(
                rows_by_label.get(
                    tc.label, f"| **{tc.label}** | — | — | — | — | — | — | ⚪ | No data | 🔴 |"
                )
            )

        lines += ["", f"> Data pulled live at {ts}. Slow tenants shown as ⏱; re-run to refresh."]
        if not include_expired:
            lines.append(
                "> ℹ Nearest Expiry excludes already-expired SKUs (active licence health). "
                "Call with `include_expired=True` to count expired/legacy SKUs."
            )
        return "\n".join(lines)

    # ─────────────────────────────────────────────────────────────────────────

    @mcp.tool()
    def scm_spn_bandwidth(
        tenant_id: str = "",
        all_tenants: bool = False,
        risk_threshold_low: int = 5,
        risk_threshold_med: int = 10,
    ) -> str:
        """SPN bandwidth allocation, live throughput, and oversubscription risk.

        Fetches configured bandwidth allocations (Mbps) per SPN region and
        cross-references them against the remote networks (branches) connected to
        each SPN.  Also queries the Prisma Access Insights API for live per-SPN
        throughput (Mbps in/out, 5-minute rolling average) and shows utilisation
        percentage against the configured allocation.

        Risk thresholds (configurable):
            HIGH    — per-branch share < risk_threshold_low Mbps (default 5)
            MEDIUM  — per-branch share < risk_threshold_med Mbps (default 10)
            LOW     — per-branch share >= risk_threshold_med Mbps
            UNALLOCATED — SPN has branches but no bandwidth-allocation entry

        Live throughput is fetched from the Insights v3.0 API using the same
        OAuth session as the SCM config API.  If the tenant's token scope does not
        include Insights access the throughput columns are omitted and the report
        falls back to allocation-only mode automatically.

        Args:
            tenant_id: SCM tenant ID (MSSP mode). Leave empty for the active tenant.
            all_tenants: If True, report across all configured MSSP tenants.
            risk_threshold_low: Per-branch Mbps below which risk is HIGH (default 5).
            risk_threshold_med: Per-branch Mbps below which risk is MEDIUM (default 10).

        Returns:
            Markdown report: per-SPN allocation + live throughput table, branch
            roster, QoS config, aggregate totals, and oversubscription risk summary.
        """
        try:
            targets: list[tuple[str, Any]] = []
            if all_tenants:
                for key, tc in _load_all_tenant_configs().items():
                    try:
                        targets.append((tc.label, get_scm_client(tc)))
                    except Exception as exc:
                        logger.warning("spn_bw_auth_failed", tenant=key, error=str(exc))
                        targets.append((tc.label, None))
            else:
                targets = [(tenant_id or "active tenant", get_client(tenant_id))]
        except Exception as exc:
            return f"Error: {handle_scm_exception(exc)}"

        ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        lines: list[str] = [
            "## SPN Bandwidth Allocation & Oversubscription Risk",
            "",
            f"**Generated:** {ts}",
            f"> Risk thresholds — HIGH: <{risk_threshold_low} Mbps/branch  "
            f"| MEDIUM: <{risk_threshold_med} Mbps/branch  | LOW: ≥{risk_threshold_med} Mbps/branch",
            "",
        ]

        # Prefetch each tenant's network data in parallel under a wall-clock
        # budget so one slow/unhealthy tenant can't stall the whole sweep. The
        # rendering below is pure CPU and stays serial.
        def _fetch(label: str, client: Any) -> dict[str, Any] | None:
            session = getattr(client, "session", None) if client is not None else None
            if session is None:
                return None
            tid = ""
            try:
                token_data = getattr(session, "token", None) or {}
                tid = str(token_data.get("tsg_id", "") or "")
            except Exception:
                pass
            return {
                "throughput": _insights_spn_throughput(session, tid),
                "allocs": _quick_list(
                    session, "bandwidth-allocations", {"folder": "Remote Networks"}
                ),
                "rns": _quick_list(session, "remote-networks", {"folder": "Remote Networks"}),
            }

        _fetched = _gather_parallel(targets, _fetch)
        multi = len(targets) > 1

        for (label, client), (_lbl, _ok, _payload) in zip(targets, _fetched, strict=False):
            if client is None:
                lines.append(f"### {label}\n\n> ⚠️ Authentication failed — skipped.\n")
                continue
            if not _ok:
                lines.append(f"### {label}\n\n> ⏱ Slow/skipped — exceeded poll budget.\n")
                continue
            if _payload is None:
                lines.append(f"### {label}\n\n> ⚠️ No HTTP session available.\n")
                continue

            # Live throughput from Insights v3.0 (graceful fallback when absent)
            throughput: dict[str, dict] = _payload["throughput"]
            live_data = bool(throughput)
            allocs_raw = _payload["allocs"]
            rns_raw = _payload["rns"]

            if multi:
                lines.append(f"### {label}")
                lines.append("")

            if not allocs_raw and not rns_raw:
                lines.append("> No bandwidth allocations or remote networks found.\n")
                continue

            # Build SPN → allocation lookup
            spn_alloc: dict[str, dict] = {}
            region_alloc: dict[str, dict] = {}
            for a in allocs_raw:
                region_alloc[a["name"]] = a
                for spn in a.get("spn_name_list", []):
                    spn_alloc[spn] = a

            # Build SPN → branches lookup
            spn_branches: dict[str, list[dict]] = {}
            for rn in rns_raw:
                spn = rn.get("spn_name") or "unassigned"
                spn_branches.setdefault(spn, []).append(rn)

            # Union of all SPNs (some may have branches but no allocation)
            all_spns = sorted(set(list(spn_alloc.keys()) + list(spn_branches.keys())))

            # ── Per-SPN summary table ──────────────────────────────────────
            lines.append("#### SPN Allocation Summary")
            lines.append("")
            if live_data:
                lines += [
                    "| SPN | Region | Allocated (Mbps) | Branches | Mbps/Branch"
                    " | In (Mbps) | Out (Mbps) | Util% | QoS | Risk |",
                    "|---|---|---|---|---|---|---|---|---|---|",
                ]
            else:
                lines += [
                    "| SPN | Region | Allocated (Mbps) | Branches | Mbps/Branch | QoS | Risk |",
                    "|---|---|---|---|---|---|---|",
                ]

            grand_alloc = 0
            grand_branches = 0
            high_risk_spns: list[str] = []
            med_risk_spns: list[str] = []

            for spn in all_spns:
                alloc = spn_alloc.get(spn, {})
                branches = spn_branches.get(spn, [])
                mbps = alloc.get("allocated_bandwidth", 0)
                n_branches = len(branches)
                region_name = alloc.get("name", "—")

                if n_branches == 0:
                    per_branch_s = "—"
                    risk = "—"
                    risk_emoji = "⚪"
                elif mbps == 0:
                    per_branch_s = "0"
                    risk = "UNALLOCATED"
                    risk_emoji = "🔴"
                    high_risk_spns.append(spn)
                else:
                    per_branch = mbps / n_branches
                    per_branch_s = f"{per_branch:.1f}"
                    if per_branch < risk_threshold_low:
                        risk = "HIGH"
                        risk_emoji = "🔴"
                        high_risk_spns.append(spn)
                    elif per_branch < risk_threshold_med:
                        risk = "MEDIUM"
                        risk_emoji = "🟡"
                        med_risk_spns.append(spn)
                    else:
                        risk = "LOW"
                        risk_emoji = "🟢"

                qos = alloc.get("qos", {})
                qos_s = (
                    f"✓ ({qos.get('guaranteed_ratio', '?')}% guaranteed)"
                    if qos.get("enabled")
                    else "✗ disabled"
                )

                grand_alloc += mbps
                grand_branches += n_branches

                if live_data:
                    tp = throughput.get(spn, {})
                    mbps_in = tp.get("mbps_in", 0.0)
                    mbps_out = tp.get("mbps_out", 0.0)
                    util_pct = (
                        f"{round((mbps_in + mbps_out) / mbps * 100, 1)}%" if mbps > 0 else "—"
                    )
                    lines.append(
                        f"| `{spn}` | {region_name} | {mbps} | {n_branches}"
                        f" | {per_branch_s} | {mbps_in} | {mbps_out}"
                        f" | {util_pct} | {qos_s} | {risk_emoji} {risk} |"
                    )
                else:
                    lines.append(
                        f"| `{spn}` | {region_name} | {mbps} | {n_branches} "
                        f"| {per_branch_s} | {qos_s} | {risk_emoji} {risk} |"
                    )

            # Totals row
            grand_per = f"{grand_alloc / grand_branches:.1f}" if grand_branches > 0 else "—"
            if live_data:
                lines += [
                    f"| **TOTAL** | | **{grand_alloc}** | **{grand_branches}**"
                    f" | **{grand_per}** | | | | | |",
                    "",
                ]
            else:
                lines += [
                    f"| **TOTAL** | | **{grand_alloc}** | **{grand_branches}** "
                    f"| **{grand_per}** | | |",
                    "",
                ]

            # ── Branch roster per SPN ──────────────────────────────────────
            lines.append("#### Branch Roster by SPN")
            lines.append("")
            for spn in all_spns:
                branches = spn_branches.get(spn, [])
                if not branches:
                    continue
                alloc = spn_alloc.get(spn, {})
                mbps = alloc.get("allocated_bandwidth", 0)
                lines.append(f"**`{spn}`** — {mbps} Mbps shared across {len(branches)} branches")
                lines.append("")
                lines += [
                    "| Branch | Region | Licence Type | ECMP | Subnets |",
                    "|---|---|---|---|---|",
                ]
                for rn in sorted(branches, key=lambda x: x.get("name", "")):
                    subnets = ", ".join(rn.get("subnets") or ["—"])
                    ecmp = "✓" if rn.get("ecmp_load_balancing") == "enable" else "✗"
                    lines.append(
                        f"| `{rn['name']}` | {rn.get('region', '—')} "
                        f"| {rn.get('license_type', '—')} | {ecmp} | {subnets} |"
                    )
                lines.append("")

            # ── Risk summary ───────────────────────────────────────────────
            if high_risk_spns or med_risk_spns:
                lines.append("#### ⚠️ Oversubscription Risk Summary")
                lines.append("")
                if high_risk_spns:
                    lines.append(
                        f"🔴 **HIGH risk SPNs** — per-branch share < {risk_threshold_low} Mbps or unallocated:  "
                    )
                    for s in high_risk_spns:
                        lines.append(f"  - `{s}`")
                    lines.append("")
                if med_risk_spns:
                    lines.append(
                        f"🟡 **MEDIUM risk SPNs** — per-branch share {risk_threshold_low}–{risk_threshold_med} Mbps:  "
                    )
                    for s in med_risk_spns:
                        lines.append(f"  - `{s}`")
                    lines.append("")
                lines.append(
                    "_Recommendation: increase `allocated_bandwidth` for flagged regions "
                    "via SCM → Remote Networks → Bandwidth Allocation, or reduce branch "
                    "count per SPN by adding a second compute location in that region._"
                )
                lines.append("")
            else:
                lines.append("🟢 All SPNs are within acceptable per-branch bandwidth thresholds.\n")

            if live_data:
                lines += [
                    f"> Live throughput figures are 5-minute rolling averages from the "
                    f"Prisma Access Insights API, fetched at {ts}.  "
                    f"Util% = (In + Out) / Allocated.",
                    "",
                ]
            else:
                lines += [
                    "> **Note:** Live throughput data was not available from the Prisma Access "
                    "Insights API for this tenant (the token may lack the `pa-insights` scope). "
                    "This report shows *configured allocation* only.  "
                    "Contact your PAN account team to enable Insights access.",
                    "",
                ]

        return "\n".join(lines)

    @mcp.tool()
    @tool
    def scm_gp_session_summary(client: Any, tenant_id: str) -> str:
        """Live GlobalProtect and Prisma Access Agent session summary.

        Queries the Prisma Access Insights API for current connected mobile-user
        session counts and breaks them down by:
          - Country of origin (client-side GeoIP)
          - Compute node / PA edge location
          - Client type: GlobalProtect vs Prisma Access Agent
          - GP client version distribution

        Compares the live connected count against the licensed MU seat count and
        shows utilisation as a percentage.

        **Privacy:** Only aggregate counts are returned — no usernames, IP addresses,
        or device identifiers appear in the output.

        Args:
            tenant_id: SCM tenant ID (MSSP mode). Leave empty for the active session.

        Returns:
            Markdown report: headline utilisation, country table, compute-node table,
            agent-type and GP-version breakdown.  Sections that return no data from
            the Insights API are omitted rather than shown as empty tables.
        """

        session = client.session

        # Extract numeric TSG ID from the JWT token (tsg_id claim)
        tid = tenant_id  # fallback: user-supplied value
        try:
            token_data = getattr(session, "token", None) or {}
            tid = str(token_data.get("tsg_id", "") or tenant_id)
        except Exception:
            pass

        # Resolve label from cached tenant metadata when possible
        from ..auth.oauth import get_tenant_meta as _get_meta

        meta = _get_meta(tid) if tid else None
        label = (meta.label if meta else None) or tid or "default tenant"

        lines: list[str] = [f"# GP & Mobile-User Session Summary — {label}", ""]

        # ── 1. Total connected vs licensed ───────────────────────────────────
        total_data = _insights_query(session, "gp_mobileusers/connected_user_count", tid)
        total_connected: int = total_data[0].get("user_count", 0) if total_data else 0

        # PA Agent sessions (Prisma Access Agent, distinct from GP client)
        pa_agent_data = _insights_query(session, "users/agent/connected_user_count", tid)
        pa_agent_count: int = pa_agent_data[0].get("user_count", 0) if pa_agent_data else 0

        # Licensed MU seat count from Subscription API
        licensed_mu = 0
        try:
            lics = fetch_licenses(client)
            for bundle in lics:
                for lic in bundle.get("licenses", []):
                    sku = (lic.get("license_type") or "").upper()
                    app = (bundle.get("app_id") or "").lower()
                    if "mu" in sku and "prisma_access" in app:
                        purchased = int(lic.get("purchased_size") or 0)
                        if purchased > licensed_mu:
                            licensed_mu = purchased
        except Exception:
            pass

        utilisation_pct = round(total_connected / licensed_mu * 100, 1) if licensed_mu > 0 else None
        util_str = f"{utilisation_pct}%" if utilisation_pct is not None else "N/A (no licence data)"
        util_icon = (
            "🔴"
            if utilisation_pct and utilisation_pct >= 90
            else "🟡"
            if utilisation_pct and utilisation_pct >= 70
            else "🟢"
        )

        lines += [
            "## Utilisation",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Connected sessions (total) | **{total_connected}** |",
            f"| — GlobalProtect client | {total_connected - pa_agent_count} |",
            f"| — Prisma Access Agent | {pa_agent_count} |",
            f"| Licensed MU seats | {licensed_mu if licensed_mu else '—'} |",
            f"| Utilisation | {util_icon} {util_str} |",
            "",
        ]

        # ── 2. By country ────────────────────────────────────────────────────
        country_data = _insights_query(
            session, "gp_mobileusers/current_connected_user_global_map", tid
        )
        if country_data:
            # Field names vary; try common candidates
            sample = country_data[0]
            country_key = next(
                (k for k in ("country_name", "geoip_from_country_name", "country") if k in sample),
                None,
            )
            count_key = next(
                (k for k in ("user_count", "count", "active_users") if k in sample),
                None,
            )
            if country_key and count_key:
                rows = sorted(country_data, key=lambda x: int(x.get(count_key) or 0), reverse=True)
                lines += [
                    "## Connected Users by Country",
                    "",
                    "| Country | Sessions |",
                    "|---------|----------|",
                ]
                for row in rows:
                    c = row.get(country_key) or "Unknown"
                    n = int(row.get(count_key) or 0)
                    lines.append(f"| {c} | {n} |")
                lines.append("")

        # ── 3. By compute node ────────────────────────────────────────────────
        node_data = _insights_query(
            session, "gp_mobileusers/current_connected_user_pa_location_map", tid
        )
        if node_data:
            sample = node_data[0]
            loc_key = next(
                (
                    k
                    for k in (
                        "pa_location",
                        "edge_location_display_name",
                        "compute_location",
                        "location",
                    )
                    if k in sample
                ),
                None,
            )
            count_key = next(
                (k for k in ("user_count", "count", "active_users") if k in sample),
                None,
            )
            if loc_key and count_key:
                rows = sorted(node_data, key=lambda x: int(x.get(count_key) or 0), reverse=True)
                lines += [
                    "## Connected Users by Compute Node",
                    "",
                    "| PA Location | Sessions |",
                    "|-------------|----------|",
                ]
                for row in rows:
                    loc = row.get(loc_key) or "Unknown"
                    n = int(row.get(count_key) or 0)
                    lines.append(f"| {loc} | {n} |")
                lines.append("")

        # ── 4. Agent type + GP version (from per-session list) ───────────────
        session_rows = _insights_query(
            session,
            "user_list_gp",
            tid,
            body={
                "properties": [
                    {"property": "client_gp_version"},
                    {"property": "user_type"},
                    {"property": "platform_type"},
                    {"property": "edge_location_display_name"},
                ],
                "filter": {
                    "rules": [
                        {
                            "property": "connection_state",
                            "operator": "equals",
                            "values": ["connected"],
                        }
                    ]
                },
                "timeRange": {"last": {"hours": 2}},
                "count": 5000,
            },
        )

        if session_rows:
            # Agent-type breakdown
            agent_counts: dict[str, int] = {}
            version_counts: dict[str, int] = {}
            platform_counts: dict[str, int] = {}

            for row in session_rows:
                agent = row.get("user_type") or "Unknown"
                agent_counts[agent] = agent_counts.get(agent, 0) + 1

                ver = row.get("client_gp_version") or "Unknown"
                version_counts[ver] = version_counts.get(ver, 0) + 1

                plat = row.get("platform_type") or "Unknown"
                platform_counts[plat] = platform_counts.get(plat, 0) + 1

            lines += [
                "## Client Agent Type",
                "",
                "| Agent Type | Sessions |",
                "|------------|----------|",
            ]
            for atype, cnt in sorted(agent_counts.items(), key=lambda x: -x[1]):
                lines.append(f"| {atype} | {cnt} |")
            lines.append("")

            if any(v != "Unknown" for v in version_counts):
                lines += [
                    "## GP Client Version Distribution",
                    "",
                    "| Version | Sessions |",
                    "|---------|----------|",
                ]
                for ver, cnt in sorted(version_counts.items(), key=lambda x: -x[1])[:15]:
                    lines.append(f"| {ver} | {cnt} |")
                lines.append("")

            if any(p != "Unknown" for p in platform_counts):
                lines += [
                    "## Client OS Platform",
                    "",
                    "| Platform | Sessions |",
                    "|----------|----------|",
                ]
                for plat, cnt in sorted(platform_counts.items(), key=lambda x: -x[1]):
                    lines.append(f"| {plat} | {cnt} |")
                lines.append("")

        # ── 5. Empty-state message ────────────────────────────────────────────
        if total_connected == 0:
            lines += [
                "> **No active mobile-user sessions at this time.**  ",
                "> Country, compute-node, and version breakdowns will appear here when users connect.",
                "",
            ]

        lines.append(
            f"*Snapshot taken {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')} "
            f"via Prisma Access Insights API.*"
        )
        return "\n".join(lines)

    @mcp.tool()
    def scm_check_updates() -> str:
        """Check for SDK, dependency, and pan.dev API documentation updates.

        Queries PyPI for the latest published versions of all Python packages
        used by this server and compares them against installed versions.
        Also checks GitHub for the latest pan-scm-sdk release notes and
        recent commits to the SCM OpenAPI specs on pan.dev.

        No credentials required — reads PyPI and public GitHub APIs only.
        Uses `urllib.request` from the standard library; no new dependencies.

        Returns:
            Markdown report with:
              • Package version table (installed vs latest, update flag)
              • pan-scm-sdk latest release notes excerpt
              • Recent pan.dev SCM OpenAPI spec commit log
        """
        lines: list[str] = ["# SDK & API Update Check", ""]
        now_str = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

        # ── 1. PyPI package versions ──────────────────────────────────────────
        lines += [
            "## Package Versions",
            "",
            "| Package | Installed | Latest | Status |",
            "|---------|-----------|--------|--------|",
        ]
        any_update = False
        for dist_name, _ in _PYPI_PACKAGES:
            installed = _installed_version(dist_name)
            latest = _pypi_latest(dist_name) or "unavailable"
            if latest == "unavailable" or installed == "—":
                status = "⚪ unknown"
            elif _parse_semver(latest) > _parse_semver(installed):
                status = "🟡 **update available**"
                any_update = True
            else:
                status = "🟢 up to date"
            lines.append(f"| `{dist_name}` | {installed} | {latest} | {status} |")

        lines.append("")
        if any_update:
            lines += [
                "> **Updates available.** Run `uv sync` (or `uv add <package>==<version>`) "
                "to upgrade, then use `scm_reload` or `scm_restart` to apply.",
                "",
            ]
        else:
            lines += ["> All packages are up to date.", ""]

        # ── 2. pan-scm-sdk GitHub release notes ──────────────────────────────
        lines += ["## pan-scm-sdk Latest Release", ""]
        release = _gh_latest_release("cdot65", "pan-scm-sdk")
        if release:
            tag = release.get("tag_name", "?")
            pub = (release.get("published_at") or "")[:10]
            body = (release.get("body") or "").strip()
            # Truncate long release notes
            if len(body) > 1200:
                body = body[:1200] + "\n\n_[truncated — full notes on GitHub]_"
            lines += [
                f"**{tag}** — {pub}",
                "",
                body or "_No release notes._",
                "",
            ]
        else:
            lines += ["_GitHub API unavailable or rate-limited._", ""]

        # ── 3. pan.dev SCM OpenAPI spec recent changes ────────────────────────
        lines += ["## pan.dev — Recent SCM API Changes", ""]
        commits = _gh_recent_commits("PaloAltoNetworks", "pan.dev", "openapi-specs/scm", n=8)
        if commits:
            lines += [
                "| Date | Author | Message |",
                "|------|--------|---------|",
            ]
            for c in commits:
                commit = c.get("commit", {})
                date = (commit.get("author", {}).get("date") or "")[:10]
                author = (commit.get("author", {}).get("name") or "?")[:25]
                msg = (commit.get("message") or "").split("\n")[0][:90]
                lines.append(f"| {date} | {author} | {msg} |")
            lines.append("")
        else:
            lines += ["_GitHub API unavailable or no recent changes._", ""]

        # ── 4. OpenAPI spec drift vs bundled endpoint catalog ─────────────────
        lines += ["## pan.dev — OpenAPI Spec Drift (vs bundled endpoint catalog)", ""]
        drift = _spec_drift()
        if drift is None:
            lines += ["_Bundled catalog missing or GitHub API unavailable._", ""]
        else:
            meta, new, changed, removed = drift
            lines.append(
                f"Catalog generated {meta['generated_at'][:10]} from pan.dev "
                f"`{meta['pan_dev_commit'][:12]}` — {meta['total_paths']} endpoints, "
                f"{len(meta['families'])} families."
            )
            lines.append("")
            if not (new or changed or removed):
                lines += ["🟢 Upstream specs unchanged — catalog is current.", ""]
            else:
                lines += [
                    f"🟡 Upstream drift: **{len(new)} new**, **{len(changed)} changed**, "
                    f"**{len(removed)} removed** spec file(s):",
                    "",
                    "| Status | Spec file |",
                    "|--------|-----------|",
                ]
                for label, group in (("new", new), ("changed", changed), ("removed", removed)):
                    for rel in group[:10]:
                        lines.append(f"| {label} | `{rel}` |")
                lines += [
                    "",
                    "Regenerate with: `uv run --with pyyaml python "
                    "scripts/gen_endpoint_catalog.py`",
                    "",
                ]

        lines.append(f"*Checked {now_str}*")
        return "\n".join(lines)

    # ── Device Summary ──────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_device_summary(
        client: Any,
        tenant_id: str,
        folder: str = "ngfw-shared",
    ) -> str:
        """Device inventory health summary — count by model, connection, HA state.

        Queries ``GET /config/setup/v1/devices`` and aggregates:
          - Total device count
          - Connected vs offline split
          - HA state breakdown (active / passive / standalone / unknown)
          - Count per model

        Args:
            folder: SCM folder to query (default: "ngfw-shared").
            tenant_id: SCM tenant ID (MSSP mode).

        Returns:
            Markdown report with summary table and per-model breakdown.
        """

        from ..auth.oauth import get_tenant_meta as _get_meta

        meta = _get_meta(tenant_id) if tenant_id else None
        label = (meta.label if meta else None) or tenant_id or "default tenant"

        lines: list[str] = [f"# Device Inventory Summary — {label}", ""]

        all_devices: list[dict] = []
        for fld in (folder, "Shared", "All"):
            try:
                results = list(client.device.list(folder=fld, limit=1000))
                all_devices.extend(
                    [d.model_dump() if hasattr(d, "model_dump") else d for d in results]
                )
            except Exception:
                pass

        if not all_devices:
            lines.append("_No devices found in any folder._")
            return "\n".join(lines)

        total = len(all_devices)
        connected = sum(1 for d in all_devices if d.get("is_connected") or d.get("connected"))
        offline = total - connected

        lines.extend(
            [
                "| Metric | Count |",
                "|--------|-------|",
                f"| **Total Devices** | **{total}** |",
                f"| Connected | {connected} ({round(connected / total * 100, 1) if total else 0}%) |",
                f"| Offline | {offline} ({round(offline / total * 100, 1) if total else 0}%) |",
                "",
            ]
        )

        # HA state breakdown
        ha_states: dict[str, int] = {}
        for d in all_devices:
            state = d.get("ha_state") or d.get("haState") or "standalone"
            ha_states[state] = ha_states.get(state, 0) + 1

        if ha_states:
            lines.extend(
                [
                    "## HA State Breakdown",
                    "",
                    "| State | Count |",
                    "|-------|-------|",
                ]
            )
            for state, count in sorted(ha_states.items(), key=lambda x: -x[1]):
                icon = {"active": "🟢", "passive": "🟡", "standalone": "⚪"}.get(state, "🔵")
                lines.append(f"| {icon} {state} | {count} |")
            lines.append("")

        # Per-model breakdown
        models: dict[str, int] = {}
        for d in all_devices:
            model = d.get("model") or d.get("family") or "Unknown"
            models[model] = models.get(model, 0) + 1

        if models:
            lines.extend(
                [
                    "## Per-Model Breakdown",
                    "",
                    "| Model | Count |",
                    "|-------|-------|",
                ]
            )
            for model, count in sorted(models.items(), key=lambda x: -x[1]):
                lines.append(f"| {model} | {count} |")
            lines.append("")

        # Software versions
        versions: dict[str, int] = {}
        for d in all_devices:
            ver = (
                d.get("software_version")
                or d.get("sw_version")
                or d.get("softwareVersion")
                or "Unknown"
            )
            versions[ver] = versions.get(ver, 0) + 1

        if versions:
            lines.extend(
                [
                    "## Software Versions",
                    "",
                    "| Version | Count |",
                    "|---------|-------|",
                ]
            )
            for ver, count in sorted(versions.items(), key=lambda x: -x[1]):
                lines.append(f"| {ver} | {count} |")
            lines.append("")

        lines.append(f"*Queried folders: {folder}, Shared, All — {total} device(s) found*")
        return "\n".join(lines)

    # ── User Count ──────────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_user_count(client: Any, tenant_id: str) -> str:
        """Live connected user count across Prisma Access and NGFW.

        Queries the Prisma Access Insights v3.0 API for current connected
        user counts, split between GlobalProtect mobile users (Prisma Access)
        and Prisma Access Agent users (NGFW-managed endpoints).

        Also pulls the licensed Mobile User seat count for utilisation %.

        Args:
            tenant_id: SCM tenant ID (MSSP mode).

        Returns:
            Markdown report: headline total, GP vs Agent split, licensed
            capacity and utilisation percentage.
        """

        session = client.session

        tid = tenant_id
        try:
            token_data = getattr(session, "token", None) or {}
            tid = str(token_data.get("tsg_id", "") or tenant_id)
        except Exception:
            pass

        from ..auth.oauth import get_tenant_meta as _get_meta

        meta = _get_meta(tid) if tid else None
        label = (meta.label if meta else None) or tid or "default tenant"

        lines: list[str] = [f"# Connected User Count — {label}", ""]

        # GP mobile users (Prisma Access)
        gp_data = _insights_query(session, "gp_mobileusers/connected_user_count", tid)
        gp_count: int = gp_data[0].get("user_count", 0) if gp_data else 0

        # PA Agent users (NGFW + Prisma Access agent-based)
        agent_data = _insights_query(session, "users/agent/connected_user_count", tid)
        agent_count: int = agent_data[0].get("user_count", 0) if agent_data else 0

        total_connected = gp_count + agent_count

        # Licensed MU seat count
        licensed_mu = 0
        try:
            lics = fetch_licenses(client)
            for bundle in lics:
                for lic in bundle.get("licenses", []):
                    sku = (lic.get("license_type") or "").upper()
                    app = (bundle.get("app_id") or "").lower()
                    if "mu" in sku and "prisma_access" in app:
                        purchased = int(lic.get("purchased_size") or 0)
                        if purchased > licensed_mu:
                            licensed_mu = purchased
        except Exception:
            pass

        utilisation_pct = round(total_connected / licensed_mu * 100, 1) if licensed_mu > 0 else None
        util_str = f"{utilisation_pct}%" if utilisation_pct is not None else "N/A"

        lines.extend(
            [
                "| Metric | Count |",
                "|--------|-------|",
                f"| **Total Connected Users** | **{total_connected}** |",
                f"| GlobalProtect (Prisma Access) | {gp_count} |",
                f"| PA Agent (NGFW) | {agent_count} |",
                f"| Licensed MU Seats | {licensed_mu} |",
                f"| Utilisation | {util_str} |",
                "",
            ]
        )

        if utilisation_pct is not None:
            if utilisation_pct >= 90:
                lines.append("⚠️ **High utilisation** — consider adding MU licences.")
            elif utilisation_pct >= 70:
                lines.append("⚡ **Moderate utilisation** — monitor trends.")
            else:
                lines.append("✅ Ample capacity available.")

        return "\n".join(lines)
