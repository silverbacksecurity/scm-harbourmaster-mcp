"""
Public IP enrichment ("whatsmyip"-style reverse lookup) for the WAN IP tools.

Given public IPs already resolved by the WAN IP summaries, looks up
ISP/organisation, ASN, reverse DNS, and IP geolocation from an external
IP-intelligence provider and returns normalised records. Strictly additive:
failures degrade to warnings and per-IP error entries instead of raising, so
enrichment can never break the base WAN IP output.

Providers:
  - "ip-api"  (default, no key) — ip-api.com free batch endpoint. The free
    tier is HTTP-only and rate-limited (~15 batch requests/min); only the
    bare IP addresses are sent.
  - "ipinfo"  — ipinfo.io over HTTPS, one request per IP. Optional token
    (`ipinfo_token` in settings / SCM_MCP_IPINFO_TOKEN) raises rate limits.
  - "ripe"    — stat.ripe.net, free and unauthenticated, no key. ASN/holder/
    netname only — no reverse DNS or geolocation. Looked up once per unique
    /24 (v4) or /48 (v6) prefix rather than per IP, since RIPE data is
    announced per prefix and every IP in it would return an identical
    record; each prefix uses a 5s connect/read timeout.

Enrichment sends tenant public IPs to a third-party service, so it is
opt-in per tool call (`enrich=true`) and never runs by default. Results are
cached for `_CACHE_TTL` (30 days — ISP/geo assignments rarely change) and
persisted to a local JSON file so repeated report runs — including AS-BUILT
re-runs in fresh server processes — don't re-hit provider rate limits.
Cache I/O failures degrade to in-process-only caching, never errors.
"""

from __future__ import annotations

import ipaddress
import json
import os
import threading
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import requests

from .logging import get_logger

logger = get_logger(__name__)

_CACHE_TTL = 30 * 24 * 3600  # ISP/geo assignments rarely change
_cache: dict[tuple[str, str], tuple[float, dict[str, Any]]] = {}
_cache_lock = threading.Lock()
_disk_loaded = False


def _cache_path() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "scm-harbourmaster-mcp" / "ipenrich.json"


def _load_disk_cache() -> None:
    """Merge the persisted cache into memory, once per process."""
    global _disk_loaded
    if _disk_loaded:
        return
    _disk_loaded = True
    try:
        raw = json.loads(_cache_path().read_text())
    except FileNotFoundError:
        return
    except Exception as exc:
        logger.debug("ipenrich_cache_load_failed", error=str(exc))
        return
    now = time.time()
    for key, entry in raw.items():
        provider, _, ip = key.partition("|")
        ts = entry.get("ts", 0)
        if ip and now - ts < _CACHE_TTL:
            _cache.setdefault((provider, ip), (ts, entry.get("record", {})))


def _save_disk_cache() -> None:
    """Persist the in-memory cache atomically; failures are non-fatal."""
    try:
        path = _cache_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            f"{provider}|{ip}": {"ts": ts, "record": rec}
            for (provider, ip), (ts, rec) in _cache.items()
        }
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload))
        tmp.replace(path)
    except Exception as exc:
        logger.debug("ipenrich_cache_save_failed", error=str(exc))


_IP_API_FIELDS = "status,message,query,reverse,isp,org,as,asname,city,regionName,country,lat,lon"
_IP_API_BATCH_URL = "http://ip-api.com/batch"
_IPINFO_URL = "https://ipinfo.io/{ip}/json"
_RIPE_PREFIX_OVERVIEW_URL = "https://stat.ripe.net/data/prefix-overview/data.json"
_RIPE_WHOIS_URL = "https://stat.ripe.net/data/whois/data.json"
_TIMEOUT = (5, 15)
_RIPE_TIMEOUT = (5, 5)


def is_rfc1918(ip: str) -> bool:
    """True if `ip` is a private address (RFC1918 or equivalent, e.g. IPv6 ULA).

    Used to flag circuits marked used_for="public" whose live-bound address
    is actually private — usually an upstream NAT the interface config
    doesn't know about, or a mislabelled circuit. Invalid input returns
    False rather than raising.
    """
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def global_ips(raw: Iterable[str]) -> list[str]:
    """Normalise candidate addresses to unique, globally-routable IPs.

    Accepts bare IPs or CIDR-suffixed interface addresses ("203.0.113.5/30").
    RFC1918/loopback/link-local/etc. are dropped — there is nothing an
    external provider can say about them. Order-preserving dedupe.
    """
    seen: list[str] = []
    for item in raw:
        candidate = str(item or "").strip().split("/")[0]
        if not candidate:
            continue
        try:
            addr = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if addr.is_global and str(addr) not in seen:
            seen.append(str(addr))
    return seen


def enrich_public_ips(
    ips: Iterable[str],
    provider: str = "",
    token: str = "",
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Look up ISP/ASN/rDNS/geo for each globally-routable IP.

    Returns ({ip: record}, warnings) and never raises. Records are
    normalised across providers:
      {ip, reverse_dns, isp, org, asn, as_name,
       city, region, country, latitude, longitude, source}

    provider/token default to the server settings (`ip_enrichment_provider`,
    `ipinfo_token`); provider falls back to "ip-api" if settings are
    unavailable.
    """
    targets = global_ips(ips)
    if not targets:
        return {}, []

    if not provider or (provider == "ipinfo" and not token):
        s_provider, s_token = _settings_provider()
        provider = provider or s_provider
        token = token or s_token

    now = time.time()
    results: dict[str, dict[str, Any]] = {}
    misses: list[str] = []
    with _cache_lock:
        _load_disk_cache()
        for ip in targets:
            hit = _cache.get((provider, ip))
            if hit and now - hit[0] < _CACHE_TTL:
                results[ip] = hit[1]
            else:
                misses.append(ip)

    warnings: list[str] = []
    if misses:
        try:
            if provider == "ipinfo":
                fetched, warnings = _lookup_ipinfo(misses, token)
            elif provider == "ip-api":
                fetched, warnings = _lookup_ip_api(misses)
            elif provider == "ripe":
                fetched, warnings = _lookup_ripe(misses)
            else:
                return results, [f"unknown ip_enrichment_provider {provider!r}"]
        except Exception as exc:
            logger.debug("ip_enrichment_failed", provider=provider, error=str(exc))
            return results, [f"ip enrichment via {provider} failed: {exc}"]
        with _cache_lock:
            for ip, rec in fetched.items():
                _cache[(provider, ip)] = (now, rec)
                results[ip] = rec
            if fetched:
                _save_disk_cache()

    return results, warnings


def _settings_provider() -> tuple[str, str]:
    try:
        from ..config.settings import get_settings

        s = get_settings()
        return s.ip_enrichment_provider, s.ipinfo_token.get_secret_value()
    except Exception:
        return "ip-api", ""


def _lookup_ip_api(ips: list[str]) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """ip-api.com batch lookup — up to 100 IPs per POST."""
    records: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []
    for start in range(0, len(ips), 100):
        chunk = ips[start : start + 100]
        resp = requests.post(
            _IP_API_BATCH_URL,
            params={"fields": _IP_API_FIELDS},
            json=chunk,
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        for row in resp.json():
            ip = row.get("query", "")
            if row.get("status") != "success":
                warnings.append(f"{ip}: {row.get('message', 'lookup failed')}")
                continue
            records[ip] = {
                "ip": ip,
                "reverse_dns": row.get("reverse", ""),
                "isp": row.get("isp", ""),
                "org": row.get("org", ""),
                "asn": (row.get("as", "") or "").split(" ")[0],
                "as_name": row.get("asname", ""),
                "city": row.get("city", ""),
                "region": row.get("regionName", ""),
                "country": row.get("country", ""),
                "latitude": row.get("lat"),
                "longitude": row.get("lon"),
                "source": "ip-api.com",
            }
    return records, warnings


def _lookup_ipinfo(ips: list[str], token: str) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """ipinfo.io lookup — one HTTPS GET per IP; token optional."""
    records: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []
    for ip in ips:
        resp = requests.get(
            _IPINFO_URL.format(ip=ip),
            params={"token": token} if token else None,
            timeout=_TIMEOUT,
        )
        if resp.status_code != 200:
            warnings.append(f"{ip}: ipinfo.io HTTP {resp.status_code}")
            continue
        row = resp.json()
        # org arrives as "AS15169 Google LLC"; loc as "51.5074,-0.1278"
        org_raw = row.get("org", "") or ""
        asn, _, org_name = org_raw.partition(" ")
        if not asn.startswith("AS"):
            asn, org_name = "", org_raw
        lat: float | None = None
        lon: float | None = None
        loc = row.get("loc", "") or ""
        if "," in loc:
            try:
                lat_s, lon_s = loc.split(",", 1)
                lat, lon = float(lat_s), float(lon_s)
            except ValueError:
                pass
        records[ip] = {
            "ip": ip,
            "reverse_dns": row.get("hostname", ""),
            "isp": org_name,
            "org": org_name,
            "asn": asn,
            "as_name": org_name,
            "city": row.get("city", ""),
            "region": row.get("region", ""),
            "country": row.get("country", ""),
            "latitude": lat,
            "longitude": lon,
            "source": "ipinfo.io",
        }
    return records, warnings


def _ripe_prefix_key(ip: str) -> str:
    """Group key for RIPE lookups: the /24 (v4) or /48 (v6) containing `ip`."""
    addr = ipaddress.ip_address(ip)
    prefixlen = 24 if addr.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{prefixlen}", strict=False))


def _whois_field(records: list[list[dict[str, Any]]], key: str) -> str:
    """First value for `key` across RIPE whois's nested RPSL object groups."""
    for group in records:
        for item in group:
            if str(item.get("key", "")).lower() == key:
                return str(item.get("value") or "")
    return ""


def _lookup_ripe(ips: list[str]) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """stat.ripe.net lookup — free, unauthenticated ASN/holder/netname only.

    One prefix-overview + one whois GET per unique /24 (v4) or /48 (v6)
    prefix (RIPE data is announced per prefix, so every IP in it shares the
    same record) rather than per IP. Each prefix gets its own 5s
    connect/read timeout and degrades independently: a timeout or HTTP
    error on one prefix drops only that prefix's IPs (as a warning) and
    does not affect the others or raise.
    """
    records: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []
    groups: dict[str, list[str]] = {}
    for ip in ips:
        groups.setdefault(_ripe_prefix_key(ip), []).append(ip)

    for prefix, members in groups.items():
        representative = members[0]
        try:
            overview = requests.get(
                _RIPE_PREFIX_OVERVIEW_URL,
                params={"resource": representative},
                timeout=_RIPE_TIMEOUT,
            )
            whois = requests.get(
                _RIPE_WHOIS_URL, params={"resource": representative}, timeout=_RIPE_TIMEOUT
            )
            if overview.status_code != 200 or whois.status_code != 200:
                warnings.append(
                    f"{prefix}: ripe.net HTTP {overview.status_code}/{whois.status_code}"
                )
                continue
            o_data = overview.json().get("data") or {}
            w_data = whois.json().get("data") or {}
        except Exception as exc:
            warnings.append(f"{prefix}: ripe.net lookup failed: {exc}")
            continue

        asns = o_data.get("asns") or []
        first_asn = asns[0] if asns else {}
        asn = f"AS{first_asn['asn']}" if first_asn.get("asn") is not None else ""
        holder = str(first_asn.get("holder", "") or "")
        block = o_data.get("block") or {}
        w_records = w_data.get("records") or []
        netname = _whois_field(w_records, "netname")
        descr = _whois_field(w_records, "descr")
        country = _whois_field(w_records, "country")

        record = {
            "ip": "",
            "reverse_dns": "",
            "isp": netname or holder,
            "org": descr or block.get("desc", "") or netname,
            "asn": asn,
            "as_name": holder,
            "city": "",
            "region": "",
            "country": country,
            "latitude": None,
            "longitude": None,
            "source": "ripe.net",
            "netname": netname,
            "ripe_block": block.get("resource", ""),
        }
        for ip in members:
            rec = dict(record)
            rec["ip"] = ip
            records[ip] = rec
    return records, warnings
