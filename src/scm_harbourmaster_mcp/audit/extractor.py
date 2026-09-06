"""
Pull a full AuditSnapshot from SCM for a given folder/tenant.

Each resource type is fetched independently; failures are recorded as
extraction_errors rather than aborting the whole snapshot so partial
data still produces useful findings.
"""

from __future__ import annotations

import contextlib
import logging
import re
import threading
import time
import warnings
import xml.etree.ElementTree as ET
from concurrent.futures import ALL_COMPLETED, ThreadPoolExecutor, wait
from typing import Any

from ..resources.endpoint_catalog import find_endpoint
from ..utils.logging import get_logger
from .models import AuditSnapshot

# The pan-scm-sdk logs at ERROR for expected 404 responses (e.g. infrastructure_settings
# not present on a tenant). Silence the SDK's own loggers — our extractor records
# errors via snap.extraction_errors which is the right channel for operators.
# Set both the parent and the noisy child explicitly: child loggers with their own
# level set don't inherit from the parent in Python's logging hierarchy.
logging.getLogger("scm").setLevel(logging.CRITICAL)
logging.getLogger("scm.config.mobile_agent.infrastructure_settings").setLevel(logging.CRITICAL)
logging.getLogger("scm.config.mobile_agent.agent_profiles").setLevel(logging.CRITICAL)
logging.getLogger("scm.config.mobile_agent.tunnel_profiles").setLevel(logging.CRITICAL)

logger = get_logger(__name__)

_LIMIT = 1000  # fetch up to 1000 objects per resource type


def _dump(obj: Any) -> dict[str, Any]:
    if hasattr(obj, "model_dump"):
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=UserWarning, module="pydantic")
            try:
                # mode="json" flattens enums to their wire values (e.g.
                # OperatingSystem.ANY → "any") so reports never render reprs.
                return obj.model_dump(mode="json")
            except Exception:
                return obj.model_dump()
    return dict(obj)


def _safe_list(client: Any, attr: str, snap: AuditSnapshot, **kwargs: Any) -> list[dict[str, Any]]:
    """Call client.<attr>.list(**kwargs), return list of dicts. Log errors."""
    try:
        resource = getattr(client, attr)
        results = resource.list(**kwargs)
        return [_dump(r) for r in results]
    except AttributeError:
        snap.extraction_errors.append(f"SDK attribute not found: client.{attr}")
        return []
    except Exception as exc:
        snap.extraction_errors.append(f"{attr}: {exc}")
        logger.warning("extraction_error", resource=attr, error=str(exc))
        return []


_FOLDER_DOES_NOT_EXIST = ("doesn't exist", "does not exist", "API_I00013")


def _safe_list_multifolder(
    client: Any,
    attr: str,
    snap: AuditSnapshot,
    folders: list[str],
    **extra_kwargs: Any,
) -> list[dict[str, Any]]:
    """Try listing a resource across multiple folders, merging results by id/name."""
    seen: set[str] = set()
    combined: list[dict[str, Any]] = []
    for folder in folders:
        try:
            resource = getattr(client, attr)
            results = resource.list(folder=folder, **extra_kwargs)
            for r in results:
                item = _dump(r)
                key = item.get("id") or item.get("name") or str(item)
                if key not in seen:
                    seen.add(key)
                    combined.append(item)
        except AttributeError:
            snap.extraction_errors.append(f"SDK attribute not found: client.{attr}")
            return combined
        except Exception as exc:
            err = str(exc)
            if any(marker in err for marker in _FOLDER_DOES_NOT_EXIST):
                continue  # folder not present for this resource — try next
            snap.extraction_errors.append(f"{attr} ({folder}): {exc}")
            logger.warning("extraction_error", resource=attr, folder=folder, error=err)
    return combined


# Mobile-agent resources live under a different API version tree than the
# standard /config/v1 base.  Values that start with "https://" are treated as
# full absolute URLs in the Pydantic-validation fallback inside _safe().
_SCM_MOBILE_AGENT_BASE = "https://api.sase.paloaltonetworks.com/config/mobile-agent/v1"
_SCM_SSE_BASE = "https://api.sase.paloaltonetworks.com/sse/config/v1"

# SDK client attribute → SCM REST path.
# Absolute URL (https://…) = used verbatim.
# Relative path = appended to _SCM_CONFIG_BASE.
_REST_PATH_OVERRIDE: dict[str, str] = {
    # Mobile-agent resources live under a different API version tree
    "agent_profile": f"{_SCM_MOBILE_AGENT_BASE}/agent-profiles",
    "tunnel_profile": f"{_SCM_MOBILE_AGENT_BASE}/tunnel-profiles",
    "auth_setting": f"{_SCM_MOBILE_AGENT_BASE}/authentication-settings",
    "forwarding_profile": f"{_SCM_MOBILE_AGENT_BASE}/forwarding-profiles",
    # SASE connectivity resources live under /sse/config/v1
    "remote_network": f"{_SCM_SSE_BASE}/remote-networks",
    "service_connection": f"{_SCM_SSE_BASE}/service-connections",
    "bandwidth_allocation": f"{_SCM_SSE_BASE}/bandwidth-allocations",
}


_SNAPSHOT_CACHE_TTL = 120  # seconds
_snapshot_cache: dict[tuple[str, str, int], tuple[float, AuditSnapshot]] = {}
_snapshot_cache_lock = threading.Lock()


def extract_snapshot(
    client: Any, folder: str, tenant_id: str, fresh: bool = False
) -> AuditSnapshot:
    """
    Pull all auditable SCM config for a folder into an AuditSnapshot.

    A single extraction fans out ~30 parallel API calls and can take a couple
    of minutes on a large tenant. Several independent tools (BPA, NCSC/DSPT/
    ISO27001 gap checks, decrypt-policy audit, tier assess/report, the AS-BUILT
    report) each pull a snapshot for the same (tenant, folder); a short-TTL
    cache lets a back-to-back compliance sweep reuse one extraction instead of
    repeating the full API fan-out per tool.

    fresh=True skips the cache read (the result still refreshes the cache) —
    required by callers that compare against an earlier snapshot, where a
    cache hit would diff a snapshot with itself.
    """
    cache_key = (tenant_id, folder, id(client))
    now = time.monotonic()
    if not fresh:
        with _snapshot_cache_lock:
            cached = _snapshot_cache.get(cache_key)
            if cached is not None and now - cached[0] < _SNAPSHOT_CACHE_TTL:
                return cached[1]

    snap = _extract_snapshot_uncached(client, folder, tenant_id)

    with _snapshot_cache_lock:
        _snapshot_cache[cache_key] = (now, snap)
    return snap


def _extract_snapshot_uncached(client: Any, folder: str, tenant_id: str) -> AuditSnapshot:
    """
    Pull all auditable SCM config for a folder into an AuditSnapshot.

    API calls are fired in parallel via ThreadPoolExecutor so the total wall
    time is bounded by the slowest single call rather than the sum of all calls.
    """
    snap = AuditSnapshot(folder=folder, tenant_id=tenant_id)
    errors_lock = threading.Lock()

    def _safe(attr: str, **kwargs: Any) -> list[dict[str, Any]]:
        try:
            resource = getattr(client, attr)
            results = resource.list(**kwargs)
            return [_dump(r) for r in results]
        except AttributeError:
            with errors_lock:
                snap.extraction_errors.append(f"SDK attribute not found: client.{attr}")
            return []
        except Exception as exc:
            err = str(exc)
            # SDK model too strict for tenant data (e.g. name with spaces, extra fields).
            # Fall back to raw REST so we don't lose all items because of one bad record.
            if "validation error" in err.lower():
                session = getattr(client, "session", None)
                if session is not None:
                    url = _rest_fallback_url(client, attr)
                    try:
                        raw = _rest_list(session, url, dict(kwargs))
                        if raw:
                            logger.info("sdk_validation_fallback", resource=attr, count=len(raw))
                            return raw
                    except Exception:
                        pass
            # Folder-not-found is expected when a resource type isn't provisioned
            # in this folder (e.g. no Remote Networks in a Mobile-Users-only tenant).
            # Silently skip — these are not actionable errors for the operator.
            if any(m in err for m in _FOLDER_DOES_NOT_EXIST):
                logger.debug("extraction_folder_not_found", resource=attr, error=err[:120])
                return []
            # 5xx errors are SCM backend failures — record them but don't
            # count as user-visible warnings (operator can't act on them).
            exc_status = _exc_status(exc)
            is_server_error = exc_status is not None and exc_status >= 500
            if not is_server_error and "500" not in err and "max retries" not in err.lower():
                with errors_lock:
                    snap.extraction_errors.append(f"{attr}: {exc}")
                logger.warning("extraction_error", resource=attr, error=str(exc))
            else:
                logger.debug("extraction_transient_error", resource=attr, error=err[:200])
            return []

    def _safe_mf(attr: str, folders: list[str], **extra: Any) -> list[dict[str, Any]]:
        seen: set[str] = set()
        combined: list[dict[str, Any]] = []
        for f in folders:
            try:
                resource = getattr(client, attr)
                for r in resource.list(folder=f, **extra):
                    item = _dump(r)
                    key = item.get("id") or item.get("name") or str(item)
                    if key not in seen:
                        seen.add(key)
                        combined.append(item)
            except AttributeError:
                with errors_lock:
                    snap.extraction_errors.append(f"SDK attribute not found: client.{attr}")
                break
            except Exception as exc:
                err = str(exc)
                if any(m in err for m in _FOLDER_DOES_NOT_EXIST):
                    continue
                exc_status = _exc_status(exc)
                is_transient = (
                    (exc_status is not None and exc_status >= 500)
                    or "500" in err
                    or "max retries" in err.lower()
                )
                if is_transient:
                    logger.debug(
                        "extraction_transient_error", resource=attr, folder=f, error=err[:200]
                    )
                else:
                    with errors_lock:
                        snap.extraction_errors.append(f"{attr} ({f}): {exc}")
                    logger.warning("extraction_error", resource=attr, folder=f, error=err)
        return combined

    kw = {"folder": folder, "limit": _LIMIT}
    kw_nolimit = {"folder": folder}
    _rn = {"folder": "Remote Networks", "limit": _LIMIT}
    _sc = {"folder": "Service Connections", "limit": _LIMIT}
    _mu = {"folder": "Mobile Users", "limit": _LIMIT}
    _mu_nolimit = {"folder": "Mobile Users"}
    _log_folders = [folder, "Remote Networks", "Mobile Users", "Service Connections"]
    _rn_nolimit = {"folder": "Remote Networks"}

    # Security rules live across the folder hierarchy.  Querying a child folder
    # returns all inherited rules from parent folders too, but MU- and RN-specific
    # rules only appear when those folders are queried directly.  Dedup by rule id
    # and inject _folder / _position so the report can show provenance.
    _rule_folders = [folder, "Remote Networks", "Mobile Users"]

    def _safe_nat_rules_multifolder(position: str) -> list[dict[str, Any]]:
        seen_ids: set[str] = set()
        combined: list[dict[str, Any]] = []
        for f in _rule_folders:
            for rule in _safe("nat_rule", folder=f, position=position, limit=_LIMIT):
                rid = rule.get("id") or rule.get("name", "")
                if rid not in seen_ids:
                    seen_ids.add(rid)
                    rule.setdefault("_folder", rule.get("folder") or f)
                    rule["_position"] = position
                    combined.append(rule)
        return combined

    def _safe_rules_multifolder(position: str) -> list[dict[str, Any]]:
        seen_ids: set[str] = set()
        combined: list[dict[str, Any]] = []
        for f in _rule_folders:
            # SecurityRule.list()'s rulebase-selector kwarg is `rulebase`, not
            # `position` — passing `position` is silently swallowed into **filters
            # and always returns the default "pre" rulebase (see also security.py).
            for rule in _safe("security_rule", folder=f, rulebase=position, limit=_LIMIT):
                rid = rule.get("id") or rule.get("name", "")
                if rid not in seen_ids:
                    seen_ids.add(rid)
                    # SCM returns the defining folder on each rule object.
                    # Fall back to the query folder if the field is absent.
                    rule.setdefault("_folder", rule.get("folder") or f)
                    rule["_position"] = position
                    combined.append(rule)
        return combined

    # IKE Gateways: SDK Pydantic model drops local_address (e.g. {"interface": "vlan"})
    # which is required for a complete AS-BUILT and for config backup/restore.
    def _fetch_ike_gateways_rest() -> list[dict[str, Any]]:
        session = getattr(client, "session", None)
        if session is None:
            return _safe("ike_gateway", **_rn_nolimit)
        url = f"{_SCM_API_HOST}/config/network/v1/ike-gateways"
        try:
            return _rest_list(session, url, {"folder": "Remote Networks"})
        except Exception as exc:
            with errors_lock:
                snap.extraction_errors.append(f"ike_gateway (REST): {exc}")
            return _safe("ike_gateway", **_rn_nolimit)

    # IPSec Tunnels: SDK Pydantic model drops tunnel_interface (e.g. "tunnel")
    # which is required for a complete AS-BUILT and for config backup/restore.
    def _fetch_ipsec_tunnels_rest() -> list[dict[str, Any]]:
        session = getattr(client, "session", None)
        if session is None:
            return _safe("ipsec_tunnel", **_rn)
        url = f"{_SCM_API_HOST}/config/network/v1/ipsec-tunnels"
        try:
            return _rest_list(session, url, {"folder": "Remote Networks", "limit": str(_LIMIT)})
        except Exception as exc:
            with errors_lock:
                snap.extraction_errors.append(f"ipsec_tunnel (REST): {exc}")
            return _safe("ipsec_tunnel", **_rn)

    # GP agent profiles: bypass the SDK Pydantic model (v0.15.0 rejects newer
    # fields like dem-agent, cdl-log, can-change-portal, client-upgrade) and
    # fetch raw dicts via REST so all configured fields are captured.
    def _fetch_agent_profiles_rest() -> list[dict[str, Any]]:
        session = getattr(client, "session", None)
        if session is None:
            return _safe("agent_profile", **_mu_nolimit)
        url = f"{_SCM_MOBILE_AGENT_BASE}/agent-profiles"
        try:
            return _rest_list(session, url, {"folder": "Mobile Users"})
        except Exception as exc:
            with errors_lock:
                snap.extraction_errors.append(f"agent_profile (REST): {exc}")
            return []

    logger.info("audit_extraction_start", folder=folder, tenant_id=tenant_id)

    # Pre-warm SDK module imports sequentially so ThreadPoolExecutor threads
    # don't race on Python's _ModuleLock (lazy imports are not thread-safe).
    _sdk_attrs = [
        "address",
        "address_group",
        "service",
        "service_group",
        "tag",
        "external_dynamic_list",
        "application",
        "application_group",
        "hip_object",
        "hip_profile",
        "anti_spyware_profile",
        "vulnerability_protection_profile",
        "url_category",
        "wildfire_antivirus_profile",
        "dns_security_profile",
        "decryption_profile",
        "file_blocking_profile",
        "log_forwarding_profile",
        "syslog_server_profile",
        "http_server_profile",
        "security_rule",
        "nat_rule",
        "decryption_rule",
        "app_override_rule",
        "security_zone",
        "ike_gateway",
        "ipsec_tunnel",
        "zone_protection_profile",
        "remote_network",
        "service_connection",
        "bandwidth_allocation",
        "internal_dns_server",
        "auth_setting",
        "forwarding_profile",
        "agent_profile",
        "tunnel_profile",
        "authentication_profile",
        "saml_server_profile",
        "radius_server_profile",
        "ldap_server_profile",
        "ike_crypto_profile",
        "ipsec_crypto_profile",
        "qos_profile",
        "url_access_profile",
    ]
    for _attr in _sdk_attrs:
        with contextlib.suppress(Exception):
            getattr(client, _attr)  # triggers lazy module import, no network call

    # Build a flat task list: (snap_attr, callable)
    tasks: list[tuple[str, Any]] = [
        # Objects
        ("addresses", lambda: _safe("address", **kw)),
        ("address_groups", lambda: _safe("address_group", **kw)),
        ("services", lambda: _safe("service", **kw)),
        ("service_groups", lambda: _safe("service_group", **kw)),
        ("tags", lambda: _safe("tag", **kw)),
        ("edls", lambda: _safe("external_dynamic_list", **kw)),
        # "applications" omitted from parallel pool — the SCM applications API
        # returns thousands of built-in predefined apps and consistently exceeds
        # the 22s parallel timeout.  Custom app objects are fetched post-pool.
        ("application_groups", lambda: _safe("application_group", **kw)),
        ("hip_objects", lambda: _safe("hip_object", **kw)),
        ("hip_profiles", lambda: _safe("hip_profile", **kw_nolimit)),
        # Security profiles
        ("anti_spyware_profiles", lambda: _safe("anti_spyware_profile", **kw)),
        ("vulnerability_profiles", lambda: _safe("vulnerability_protection_profile", **kw)),
        ("url_categories", lambda: _safe("url_category", **kw)),
        ("wildfire_profiles", lambda: _safe("wildfire_antivirus_profile", **kw)),
        ("dns_security_profiles", lambda: _safe("dns_security_profile", **kw)),
        ("decryption_profiles", lambda: _safe("decryption_profile", **kw)),
        ("file_blocking_profiles", lambda: _safe("file_blocking_profile", **kw)),
        # Logging
        (
            "log_forwarding_profiles",
            lambda: _safe_mf("log_forwarding_profile", _log_folders, limit=_LIMIT),
        ),
        ("syslog_profiles", lambda: _safe_mf("syslog_server_profile", _log_folders, limit=_LIMIT)),
        ("http_server_profiles", lambda: _safe("http_server_profile", **kw)),
        # Policy rules — multi-folder with provenance tagging (_folder, _position)
        ("security_rules_pre", lambda: _safe_rules_multifolder("pre")),
        ("security_rules_post", lambda: _safe_rules_multifolder("post")),
        ("nat_rules_pre", lambda: _safe_nat_rules_multifolder("pre")),
        ("nat_rules_post", lambda: _safe_nat_rules_multifolder("post")),
        ("decryption_rules", lambda: _safe("decryption_rule", **kw)),
        ("app_override_rules", lambda: _safe("app_override_rule", **kw)),
        # Network
        ("zones", lambda: _safe_mf("security_zone", _log_folders, limit=_LIMIT)),
        ("ike_gateways", _fetch_ike_gateways_rest),
        ("ipsec_tunnels", _fetch_ipsec_tunnels_rest),
        ("zone_protection_profiles", lambda: _safe("zone_protection_profile", **kw)),
        # Deployment
        ("remote_networks", lambda: _safe("remote_network", **_rn)),
        ("service_connections", lambda: _safe("service_connection", **_sc)),
        ("bandwidth_allocations", lambda: _safe("bandwidth_allocation", **_rn)),
        ("internal_dns_servers", lambda: _safe("internal_dns_server", **_rn)),
        # Mobile Agent (SDK v0.15.0 resources use "Mobile Users" folder scope)
        ("mobile_agent_auth_settings", lambda: _safe("auth_setting", **_mu)),
        ("mobile_agent_agent_profiles", _fetch_agent_profiles_rest),
        ("mobile_agent_tunnel_profiles", lambda: _safe("tunnel_profile", **_mu_nolimit)),
        ("forwarding_profiles", lambda: _safe("forwarding_profile", **_mu_nolimit)),
        (
            "forwarding_profile_destinations",
            lambda: (
                _rest_list(
                    getattr(client, "session", None),
                    f"{_SCM_MOBILE_AGENT_BASE}/forwarding-profile-destinations",
                    {"limit": str(_LIMIT)},
                )
                if getattr(client, "session", None)
                else []
            ),
        ),
        (
            "forwarding_profile_regional_proxies",
            lambda: (
                _rest_list(
                    getattr(client, "session", None),
                    f"{_SCM_MOBILE_AGENT_BASE}/forwarding-profile-regional-and-custom-proxies",
                    {"limit": str(_LIMIT)},
                )
                if getattr(client, "session", None)
                else []
            ),
        ),
        (
            "forwarding_profile_source_apps",
            lambda: (
                _rest_list(
                    getattr(client, "session", None),
                    f"{_SCM_MOBILE_AGENT_BASE}/forwarding-profile-source-applications",
                    {"limit": str(_LIMIT)},
                )
                if getattr(client, "session", None)
                else []
            ),
        ),
        (
            "forwarding_profile_user_locations",
            lambda: (
                _rest_list(
                    getattr(client, "session", None),
                    f"{_SCM_MOBILE_AGENT_BASE}/forwarding-profile-user-locations",
                    {"limit": str(_LIMIT)},
                )
                if getattr(client, "session", None)
                else []
            ),
        ),
        # Identity
        ("authentication_profiles", lambda: _safe("authentication_profile", **kw)),
        ("saml_server_profiles", lambda: _safe("saml_server_profile", **kw)),
        ("radius_server_profiles", lambda: _safe("radius_server_profile", **kw)),
        ("ldap_server_profiles", lambda: _safe("ldap_server_profile", **kw)),
        # Policy rules (additional)
        (
            "pbf_rules",
            lambda: (
                _rest_list(
                    getattr(client, "session", None),
                    f"{_SCM_API_HOST}/config/network/v1/pbf-rules",
                    {"folder": folder, "limit": str(_LIMIT)},
                )
                if getattr(client, "session", None)
                else []
            ),
        ),
        (
            "authentication_rules",
            lambda: (
                _rest_list(
                    getattr(client, "session", None),
                    f"{_SCM_API_HOST}/sse/config/v1/authentication-rules",
                    {"folder": folder, "limit": str(_LIMIT)},
                )
                if getattr(client, "session", None)
                else []
            ),
        ),
        (
            "schedules",
            lambda: (
                _rest_list(
                    getattr(client, "session", None),
                    f"{_SCM_API_HOST}/config/objects/v1/schedules",
                    {"folder": folder, "limit": str(_LIMIT)},
                )
                if getattr(client, "session", None)
                else []
            ),
        ),
        # Network extended (new)
        (
            "interface_mgmt_profiles",
            lambda: (
                _rest_list(
                    getattr(client, "session", None),
                    f"{_SCM_API_HOST}/config/network/v1/interface-management-profiles",
                    {"folder": "Remote Networks", "limit": str(_LIMIT)},
                )
                if getattr(client, "session", None)
                else []
            ),
        ),
        (
            "bgp_filtering_profiles",
            lambda: (
                _rest_list(
                    getattr(client, "session", None),
                    f"{_SCM_API_HOST}/config/network/v1/bgp-filtering-profiles",
                    {"folder": "Remote Networks", "limit": str(_LIMIT)},
                )
                if getattr(client, "session", None)
                else []
            ),
        ),
        (
            "ospf_auth_profiles",
            lambda: (
                _rest_list(
                    getattr(client, "session", None),
                    f"{_SCM_API_HOST}/config/network/v1/ospf-auth-profiles",
                    {"folder": "Remote Networks", "limit": str(_LIMIT)},
                )
                if getattr(client, "session", None)
                else []
            ),
        ),
        # Network extended (existing)
        ("ike_crypto_profiles", lambda: _safe("ike_crypto_profile", **_rn_nolimit)),
        ("ipsec_crypto_profiles", lambda: _safe("ipsec_crypto_profile", **_rn)),
        ("qos_profiles", lambda: _safe("qos_profile", **_rn)),
        ("url_access_profiles", lambda: _safe("url_access_profile", **kw)),
    ]

    # Run all list tasks in parallel.
    # We use wait(timeout=22) instead of as_completed() so slow API calls on cold
    # tenants don't blow the MCP tool's 30-second deadline.  Any futures that don't
    # complete in time are cancelled (best-effort) and logged as skipped.
    # shutdown(wait=False) returns immediately — background threads will still finish
    # but the caller is unblocked so the MCP response can be sent in time.
    #
    # max_workers=8: PAN SCM REST API rate-limits per token. 20 simultaneous
    # connections routinely triggers throttling on cold tenants; 8 keeps burst
    # traffic well under the ~60 req/min soft threshold while still parallelising
    # the ~55 tasks across ~3 waves instead of 1.
    _PARALLEL_TIMEOUT = 22  # seconds
    pool = ThreadPoolExecutor(max_workers=8)
    try:
        future_to_attr = {pool.submit(fn): attr for attr, fn in tasks}
        done, not_done = wait(
            future_to_attr.keys(), timeout=_PARALLEL_TIMEOUT, return_when=ALL_COMPLETED
        )
        for future in done:
            attr = future_to_attr[future]
            try:
                setattr(snap, attr, future.result())
            except Exception as exc:
                with errors_lock:
                    snap.extraction_errors.append(f"{attr}_future: {exc}")
        for future in not_done:
            attr = future_to_attr[future]
            future.cancel()
            logger.warning("extraction_task_timeout", resource=attr)
            # Don't surface these as extraction_errors — they're performance noise,
            # not config errors, and the AS-BUILT renders fine with empty lists.
    finally:
        pool.shutdown(wait=False)

    # Singletons (serial — each is a single call, with per-call timeout).
    # Default is 15s; slow resources (applications, network_location) use
    # a longer allowance because they paginate over thousands of entries.
    _SINGLETON_TIMEOUT_DEFAULT = 15  # seconds
    _SINGLETON_TIMEOUT_SLOW = 120  # for applications / network_location

    def _singleton(label: str, fn: Any, timeout: int | None = None) -> Any:
        """Call fn() with a hard timeout; suppress 5xx/max-retries as transient."""
        _t = timeout if timeout is not None else _SINGLETON_TIMEOUT_DEFAULT
        with ThreadPoolExecutor(max_workers=1) as _sp:
            _fut = _sp.submit(fn)
            try:
                return _fut.result(timeout=_t)
            except TimeoutError:
                logger.warning("extraction_singleton_timeout", resource=label)
                return None
            except Exception as exc:
                err = str(exc)
                exc_status = _exc_status(exc)
                is_transient = (
                    (exc_status is not None and exc_status >= 500)
                    or "500" in err
                    or "max retries" in err.lower()
                )
                if is_transient:
                    logger.debug("extraction_transient_error", resource=label, error=err[:200])
                else:
                    snap.extraction_errors.append(f"{label}: {exc}")
                    logger.warning("extraction_error", resource=label, error=err)
                return None

    # Custom application objects only — the SCM applications API returns
    # 3000+ predefined PAN app-id entries alongside tenant-defined apps.
    # We filter post-fetch to apps whose folder matches the queried folder
    # (predefined apps have folder="predefined" or no folder field).
    def _fetch_custom_apps() -> list[dict[str, Any]]:
        all_apps = _safe("application", **kw)
        # Predefined PANW app-id entries have snippet="predefined"; exclude them
        # so only tenant-defined custom applications are captured.
        return [a for a in all_apps if a.get("snippet") != "predefined"]

    apps = _singleton("applications", _fetch_custom_apps, timeout=_SINGLETON_TIMEOUT_SLOW)
    if apps is not None:
        snap.applications = apps

    locs = _singleton(
        "network_location", lambda: client.network_location.list(), timeout=_SINGLETON_TIMEOUT_SLOW
    )
    if locs is not None:
        snap.network_locations = [_dump(r) for r in locs]

    bgp = _singleton("bgp_routing", lambda: client.bgp_routing.get())
    if bgp is not None:
        snap.bgp_routing_config = _dump(bgp)

    gs = _singleton("global_settings", lambda: client.global_settings.get())
    if gs is not None:
        snap.mobile_agent_global_settings = _dump(gs)

    def _infra_fetch() -> list[dict]:
        try:
            infra = client.infrastructure_settings.list(folder="Mobile Users")
            return [_dump(r) for r in infra]
        except TypeError:
            for name in ("Default", "GP Cluster", ""):
                try:
                    infra = client.infrastructure_settings.fetch(name=name, folder="Mobile Users")
                    return [_dump(infra)] if infra else []
                except Exception:
                    continue
            return []

    infra_result = _singleton("infrastructure_settings", _infra_fetch)
    if infra_result is not None:
        snap.mobile_agent_infrastructure = infra_result

    # GP agent versions — available and activated client builds
    _sess = getattr(client, "session", None)
    if _sess is not None:
        try:
            rv = _sess.get(
                f"{_SCM_MOBILE_AGENT_BASE}/agent-versions",
                params={"folder": "Mobile Users"},
                timeout=(4, 10),
            )
            if rv.status_code == 200:
                snap.mobile_agent_versions = rv.json().get("agent_versions", [])
        except Exception:
            pass

    # SCM management structure — folders, snippets, labels (tenant-wide, no folder scope)
    folders = _singleton("scm_folders", lambda: client.folder.list())
    if folders is not None:
        snap.scm_folders = [_dump(r) for r in folders]

    snippets = _singleton("scm_snippets", lambda: client.snippet.list())
    if snippets is not None:
        snap.scm_snippets = [_dump(r) for r in snippets]
        # Enrich each snippet with full detail (folders, enable_prefix, prefix)
        # and object counts for custom snippets, via direct REST calls.
        # Detail fetches run with bounded parallelism (4 workers) to avoid
        # hammering the API immediately after the main extraction pool.
        _STRATA = "https://api.strata.paloaltonetworks.com"
        _sess = getattr(client, "session", None)
        if _sess is not None:
            _SNIPPET_OBJECT_TYPES = [
                ("security_rules", "/sse/config/v1/security-rules"),
                ("addresses", "/config/objects/v1/addresses"),
                ("address_groups", "/config/objects/v1/address-groups"),
                ("url_categories", "/config/objects/v1/url-categories"),
                ("security_profiles", "/config/profiles/v1/security-profile-groups"),
                ("url_profiles", "/config/profiles/v1/url-filtering-profiles"),
                ("dns_sec_profiles", "/config/profiles/v1/dns-security-profiles"),
            ]

            def _enrich_snippet(s: dict[str, Any]) -> dict[str, Any]:
                sid = s.get("id")
                if not sid:
                    return s
                try:
                    rd = _sess.get(f"{_STRATA}/config/setup/v1/snippets/{sid}", timeout=(3, 8))
                    if rd.ok:
                        detail = rd.json()
                        s = {**s, **{k: v for k, v in detail.items() if v is not None}}
                except Exception:
                    pass
                # Fetch object counts only for custom snippets (type not predefined/readonly)
                stype = s.get("type")
                sname = s.get("name", "")
                if (
                    stype not in ("predefined", "readonly")
                    and sname
                    and sname != "predefined-snippet"
                ):
                    obj_counts: dict[str, int] = {}
                    for obj_key, obj_path in _SNIPPET_OBJECT_TYPES:
                        try:
                            ro = _sess.get(
                                f"{_STRATA}{obj_path}",
                                params={"snippet": sname, "limit": "1"},
                                timeout=(3, 8),
                            )
                            if ro.ok:
                                obj_counts[obj_key] = ro.json().get("total", 0)
                        except Exception:
                            pass
                    if obj_counts:
                        s = {**s, "object_counts": obj_counts}
                return s

            # 4 workers: enough to pipeline the detail fetches without spiking
            # request rate (28 snippets → ~7 waves of 4, one round-trip each).
            with ThreadPoolExecutor(max_workers=4) as _sp:
                snap.scm_snippets = list(_sp.map(_enrich_snippet, snap.scm_snippets))

    labels = _singleton("scm_labels", lambda: client.label.list())
    if labels is not None:
        snap.scm_labels = [_dump(r) for r in labels]

    logger.info(
        "audit_extraction_complete",
        folder=folder,
        rules=len(snap.all_security_rules),
        errors=len(snap.extraction_errors),
    )
    return snap


def extract_licenses(client: Any, snap: AuditSnapshot) -> AuditSnapshot:
    """
    Fetch subscription licences via the Subscription Service API and attach
    them to *snap*.  Failures are non-fatal and appended to extraction_errors.
    """
    try:
        from ..auth.oauth import fetch_licenses

        snap.licenses = fetch_licenses(client)
        logger.info("licenses_extracted", count=len(snap.licenses))
    except Exception as exc:
        snap.extraction_errors.append(f"licenses: {exc}")
        logger.warning("license_extraction_error", error=str(exc))
    return snap


_SCM_API_HOST = "https://api.sase.paloaltonetworks.com"
_SCM_CONFIG_BASE = f"{_SCM_API_HOST}/config/v1"
_ZTNA_BASE = f"{_SCM_API_HOST}/sse/connector/v2.0/api"
_BROWSER_BASE = f"{_SCM_API_HOST}/seb-api/v1"


_NOT_LICENSED_STATUSES = frozenset({401, 403, 404, 424})


def _exc_status(exc: Exception) -> int | None:
    """Extract HTTP status code from a requests/httpx HTTPError, or None."""
    resp = getattr(exc, "response", None)
    return getattr(resp, "status_code", None)


def _rest_list(
    session: Any, url: str, params: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """GET *url* and return the items list. Returns [] for not-licensed/not-found responses.

    Retries once on HTTP 429 (Too Many Requests) after honouring the Retry-After
    header (or a 10-second default) so callers are insulated from transient
    rate-limit bursts without needing their own backoff logic.
    """
    import time as _time

    for attempt in range(2):
        try:
            resp = session.get(url, params=params, timeout=(4, 15))
        except Exception as exc:
            if _exc_status(exc) in _NOT_LICENSED_STATUSES:
                return []
            raise
        if resp.status_code == 429:
            if attempt == 0:
                retry_after = int(resp.headers.get("Retry-After", "10"))
                _time.sleep(min(retry_after, 30))
                continue
            return []
        if resp.status_code in _NOT_LICENSED_STATUSES:
            return []
        resp.raise_for_status()
        data: Any = resp.json()
        if isinstance(data, list):
            return list(data)
        # Common SCM pagination envelope
        return list(data.get("data", data.get("items", [])))
    return []


def _rest_fallback_url(client: Any, attr: str) -> str:
    """Resolve the REST URL for an SDK resource (used by _safe() and the
    standalone list tools).

    Resolution order: explicit override → the SDK resource's own ENDPOINT →
    the bundled pan.dev endpoint catalog → naive slug as a last resort."""
    path = _REST_PATH_OVERRIDE.get(attr)
    if path is None:
        resource_obj = getattr(client, attr, None)
        path = getattr(resource_obj, "ENDPOINT", None)
    if path is None:
        catalog_url = find_endpoint(attr)
        if catalog_url:
            return catalog_url
        path = "/" + attr.replace("_", "-") + "s"
    return path if path.startswith("https://") else f"{_SCM_API_HOST}{path}"


def list_with_rest_fallback(client: Any, attr: str, **params: Any) -> list[Any]:
    """Call the SDK ``client.<attr>.list(**params)``; on a Pydantic *validation*
    error, fall back to raw REST so callers capture the same records the AS-BUILT
    snapshot does.

    The SDK's strict response models drop records that carry fields the model
    omits (e.g. an IPSec tunnel's ``tunnel_interface``) or reject an object whose
    name breaks the SDK name pattern (e.g. spaces). The extractor already works
    around this in ``_safe``; this exposes the same behaviour to the standalone
    list tools. Returns SDK model objects on the happy path, or raw dicts from
    the REST fallback — both are accepted by the tools' ``_fmt`` serialiser.
    """
    resource = getattr(client, attr)
    try:
        return list(resource.list(**params))
    except Exception as exc:
        if "validation error" not in str(exc).lower():
            raise
        session = getattr(client, "session", None)
        url = _rest_fallback_url(client, attr)
        if session is None or url is None:
            raise
        logger.info("sdk_validation_fallback_tool", resource=attr)
        return _rest_list(session, url, {k: str(v) for k, v in params.items()})


def extract_casb_dlp(client: Any, snap: AuditSnapshot, folder: str) -> AuditSnapshot:
    """
    Fetch DLP data-filtering profiles, data objects, and CASB SaaS tenant
    restrictions via direct SCM Config REST calls (not in pan-scm-sdk).
    Failures are non-fatal.
    """
    session = getattr(client, "session", None)
    if session is None:
        snap.extraction_errors.append("casb_dlp: Scm client has no .session")
        return snap

    params = {"folder": folder, "limit": 1000}

    for attr, path in [
        ("data_filtering_profiles", "/data-filtering-profiles"),
        ("data_objects", "/data-objects"),
        ("saas_tenant_restrictions", "/saas-tenant-restrictions"),
    ]:
        try:
            items = _rest_list(session, f"{_SCM_CONFIG_BASE}{path}", params)
            setattr(snap, attr, items)
            logger.info("casb_dlp_extracted", resource=attr, count=len(items))
        except Exception as exc:
            snap.extraction_errors.append(f"{attr}: {exc}")
            logger.warning("casb_dlp_error", resource=attr, error=str(exc))

    return snap


def _bearer_session_for(client: Any) -> Any:
    """Return a plain requests.Session with a fresh Bearer token.

    ``client.session`` is a requests_oauthlib.OAuth2Session which raises
    oauthlib.oauth2.TokenExpiredError for direct HTTP calls outside the SDK's
    own request wrappers.  We extract the current bearer token (refreshing first
    if expired) and build a standard requests.Session so SSE/SEB API calls
    work reliably.
    """
    import requests as _requests

    oauth = getattr(client, "oauth_client", None)
    if oauth is not None:
        import contextlib

        with contextlib.suppress(Exception):
            if oauth.is_expired:  # @property — no parentheses
                oauth.refresh_token()

    token = None
    sdk_session = getattr(client, "session", None)
    if sdk_session is not None:
        raw = getattr(sdk_session, "token", None)
        if raw:
            token = raw.get("access_token")

    sess = _requests.Session()
    if token:
        sess.headers["Authorization"] = f"Bearer {token}"
    return sess


def extract_ztna_connectors(client: Any, snap: AuditSnapshot) -> AuditSnapshot:
    """
    Fetch ZTNA Connector and Connector Group inventory via /sse/connector/v2.0/api/.
    Returns 424 if ZTNA Connector is not licensed/enabled — treated as empty, non-fatal.
    """
    session = _bearer_session_for(client)

    # Quick licence check
    try:
        chk = session.get(f"{_ZTNA_BASE}/license", timeout=(4, 6))
        if chk.status_code == 424:
            logger.info("ztna_connector_not_licensed")
            return snap
    except Exception:
        pass

    for attr, path in [
        ("ztna_connectors", "/connectors"),
        ("ztna_connector_groups", "/connector-groups"),
    ]:
        try:
            items = _rest_list(session, f"{_ZTNA_BASE}{path}")
            setattr(snap, attr, items)
            logger.info("ztna_extracted", resource=attr, count=len(items))
        except Exception as exc:
            snap.extraction_errors.append(f"{attr}: {exc}")
            logger.warning("ztna_error", resource=attr, error=str(exc))

    return snap


def extract_browser(client: Any, snap: AuditSnapshot) -> AuditSnapshot:
    """
    Fetch Prisma Browser (RBI) configuration via /seb/api/v1/.
    Covers device/user/application groups plus the newer Users, Devices,
    Applications, Plugins, and User Requests endpoints added June 2026.
    Returns 403/404 if not licensed — treated as empty, non-fatal.
    """
    session = _bearer_session_for(client)

    for attr, path in [
        ("browser_device_groups", "/device-groups"),
        ("browser_user_groups", "/user-groups"),
        ("browser_application_groups", "/application-groups"),
        ("browser_users", "/users"),
        ("browser_devices", "/devices"),
        ("browser_applications", "/applications"),
        ("browser_plugins", "/applications/plugins"),
        ("browser_user_requests", "/user-requests"),
    ]:
        try:
            items = _rest_list(session, f"{_BROWSER_BASE}{path}")
            setattr(snap, attr, items)
            logger.info("browser_extracted", resource=attr, count=len(items))
        except Exception as exc:
            snap.extraction_errors.append(f"{attr}: {exc}")
            logger.warning("browser_error", resource=attr, error=str(exc))

    return snap


_CDL_BASE = "https://api.sase.paloaltonetworks.com/logging-service/logforwarding/v1"


def extract_cdl(client: Any, snap: Any) -> Any:
    """
    Fetch CDL / Strata Logging Service log forwarding profiles
    (syslog, HTTPS, email) via the Log Forwarding API.
    Returns 404 if CDL is not activated for this tenant — non-fatal.

    Note: CDL instance configuration (storage quota, retention policy, region)
    is only available via hub.paloaltonetworks.com — there is no public REST API
    for CDL instance metadata.
    """
    session = getattr(client, "session", None)
    if session is None:
        snap.extraction_errors.append("cdl: Scm client has no .session")
        return snap

    for attr, path in [
        ("cdl_syslog_profiles", "/syslog-profiles"),
        ("cdl_https_profiles", "/https-profiles"),
        ("cdl_email_profiles", "/email-profiles"),
    ]:
        try:
            items = _rest_list(session, f"{_CDL_BASE}{path}")
            setattr(snap, attr, items)
            logger.info("cdl_extracted", resource=attr, count=len(items))
        except Exception as exc:
            snap.extraction_errors.append(f"{attr}: {exc}")
            logger.warning("cdl_error", resource=attr, error=str(exc))

    return snap


_AIRS_BASE = "https://api.sase.paloaltonetworks.com/aisec"
_DLP_BASE = "https://api.dlp.paloaltonetworks.com"
_ADEM_BASE = "https://api.sase.paloaltonetworks.com/adem/telemetry/v2"
_PRISMA_DATAPATH_BASE = "https://api.prod.datapath.prismaaccess.com"


def extract_adem(client: Any, snap: AuditSnapshot) -> AuditSnapshot:
    """
    Fetch live ADEM experience telemetry from the Autonomous DEM API.

    Base URL: https://api.sase.paloaltonetworks.com/adem/telemetry/v2
    Auth:     Same OAuth 2.0 bearer token as SCM (client.session).
    Header:   prisma-tenant: <tsg_id>

    Fetches per endpoint type (muAgent = Mobile Users, rnAgent = Remote Networks):
      /measure/application/score  (response-type=distribution)
          → good/fair/poor client count distribution per app
      /measure/application/score  (response-type=grouped-summary&group=Entity.user)
          → per-user score collection (used to build per-app summary)
      /measure/agent/score        (response-type=summary + distribution)
          → aggregate agent experience summary + health distribution

    Valid response-type values (from API): summary, timeseries, distribution,
    grouped-summary, grouped-timeseries, grouped-distribution.
    Valid group values: Entity.user, Entity.endpoint (used with grouped-* types).

    Results are stored in snap.adem_app_scores and snap.adem_agent_summary.
    These are operational telemetry, not configuration — the ADEM monitoring
    config (tested apps, thresholds) has no public read API.

    The default window is last_3_day. Low-activity tenants (e.g. a lab
    tenant whose test user hasn't logged in for a few days) come back
    completely empty at that window even though the ADEM API has data —
    it's just outside the last 3 days. When the 3-day pass finds nothing,
    we retry once at last_30_day and record which window actually produced
    data in snap.adem_timerange_used so the report can say so accurately
    instead of claiming "last 3 days" over an empty section.

    Ref: https://pan.dev/access/docs/adem/
    """
    session = getattr(client, "session", None)
    if session is None:
        snap.adem_errors.append("adem: Scm client has no .session")
        return snap

    tsg_id = snap.tenant_id
    headers = {"prisma-tenant": tsg_id}

    def _adem_get(path: str, params: dict[str, str]) -> dict[str, Any] | None:
        try:
            resp = session.get(
                f"{_ADEM_BASE}{path}", headers=headers, params=params, timeout=(5, 20)
            )
            if resp.status_code == 401:
                snap.adem_errors.append(
                    f"adem{path}: 401 Unauthorised — the service account may lack "
                    "the ADEM OAuth scope. Ensure ADEM is licensed and the service "
                    "account has the 'adem' scope in the Prisma Access portal."
                )
                return None
            # 400 = unsupported param combo for this endpoint type; 403/404 = not provisioned
            if resp.status_code in (400, 403, 404):
                logger.debug("adem_request_skipped", path=path, status=resp.status_code)
                return None
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            snap.adem_errors.append(f"adem{path}: {exc}")
            logger.warning("adem_request_error", path=path, error=str(exc))
            return None

    def _run(timerange: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        # ── Application score distribution + per-user grouped summary ──────
        app_scores: list[dict[str, Any]] = []
        for ep_type in ("muAgent", "rnAgent"):
            ep_label = "Mobile Users" if ep_type == "muAgent" else "Remote Networks"

            # Distribution: good/fair/poor client counts
            dist = _adem_get(
                "/measure/application/score",
                {
                    "timerange": timerange,
                    "endpoint-type": ep_type,
                    "response-type": "distribution",
                },
            )
            if dist and dist.get("distribution"):
                d = dist["distribution"]
                clients = d.get("clients") or 0
                if clients and clients > 0:
                    app_scores.append(
                        {
                            "app_name": f"All Applications ({ep_label})",
                            "endpoint_type": ep_type,
                            "score": d.get("score"),
                            "clients_good": d.get("good") or 0,
                            "clients_fair": d.get("fair") or 0,
                            "clients_poor": d.get("poor") or 0,
                            "total_clients": clients,
                            "_type": "distribution",
                        }
                    )

            # Per-user grouped summary — collection[] has one entry per user
            grouped = _adem_get(
                "/measure/application/score",
                {
                    "timerange": timerange,
                    "endpoint-type": ep_type,
                    "response-type": "grouped-summary",
                    "group": "Entity.user",
                },
            )
            if grouped:
                collection = grouped.get("collection") or []
                for item in collection[:50]:  # cap at 50 users
                    user = (
                        item.get("entityValue") or item.get("user") or item.get("name") or "Unknown"
                    )
                    score_data = item.get("score") or item.get("average") or item.get("data") or {}
                    score_val = (
                        score_data.get("score") if isinstance(score_data, dict) else score_data
                    )
                    app_scores.append(
                        {
                            "app_name": user,
                            "endpoint_type": ep_type,
                            "score": score_val,
                            "_type": "user",
                            "ep_label": ep_label,
                        }
                    )

        # ── Agent score summary + distribution ──────────────────────────────
        agent_summary: dict[str, Any] = {}
        for ep_type in ("muAgent", "rnAgent"):
            summary = _adem_get(
                "/measure/agent/score",
                {"timerange": timerange, "endpoint-type": ep_type, "response-type": "summary"},
            )
            if summary is None:
                continue
            dist = _adem_get(
                "/measure/agent/score",
                {"timerange": timerange, "endpoint-type": ep_type, "response-type": "distribution"},
            )
            dist_data = (dist or {}).get("distribution") or {}
            agent_summary[ep_type] = {
                "row_count": summary.get("rowCount", 0),
                "start_time": summary.get("startTime"),
                "end_time": summary.get("endTime"),
                "classifier": (dist or {}).get("classifier", ""),
                "clients": dist_data.get("clients", 0),
                "clients_good": dist_data.get("good"),
                "clients_fair": dist_data.get("fair"),
                "clients_poor": dist_data.get("poor"),
                "score": dist_data.get("score"),
            }

        return app_scores, agent_summary

    def _has_data(app_scores: list[dict[str, Any]], agent_summary: dict[str, Any]) -> bool:
        if app_scores:
            return True
        return any((d.get("clients") or 0) > 0 for d in agent_summary.values())

    errors_before = len(snap.adem_errors)
    app_scores, agent_summary = _run("last_3_day")
    timerange_used = "last_3_day"

    # Low-activity tenants (e.g. a lab tenant whose test user hasn't logged
    # in for a few days) come back empty at the 3-day window even though
    # ADEM has data further back. Retry once at 30 days before giving up —
    # but only if the empty result wasn't itself caused by a real API error
    # (401/etc), which retrying at a wider window won't fix.
    if not _has_data(app_scores, agent_summary) and len(snap.adem_errors) == errors_before:
        wider_app_scores, wider_agent_summary = _run("last_30_day")
        if _has_data(wider_app_scores, wider_agent_summary):
            app_scores, agent_summary = wider_app_scores, wider_agent_summary
            timerange_used = "last_30_day"

    snap.adem_app_scores = app_scores
    snap.adem_agent_summary = agent_summary
    snap.adem_timerange_used = timerange_used

    logger.info(
        "adem_extracted",
        app_entries=len(snap.adem_app_scores),
        agent_types=list(snap.adem_agent_summary),
        errors=len(snap.adem_errors),
        timerange_used=timerange_used,
    )
    return snap


# Maps datapath serviceType values → label used in snap.prisma_egress_ips address_type
_DATAPATH_SVC_MAP: dict[str, str] = {
    "gp_gateway": "gp_gw_lbs_ips",
    "gp_portal": "gp_portal_lbs_ips",
    "remote_network": "rn_lbs_ips",
    "clean_pipe": "sc_lbs_ips",
    "swg_proxy": "sc_lbs_ips",
}


def extract_egress_ips_datapath(api_key: str, snap: AuditSnapshot) -> AuditSnapshot:
    """
    Fetch Prisma Access public egress IPs from the dedicated Datapath API.

    Endpoint: POST https://api.prod.datapath.prismaaccess.com/getPrismaAccessIP/v2
    Auth:     Header 'header-api-key: <prisma_access_api_key>'
              (NOT an SCM OAuth token — obtained from the Prisma Access admin portal
               under Settings → Service Setup → Prisma Access API Key)

    The response contains per-zone address_details entries with fields:
      serviceType   — gp_gateway | gp_portal | remote_network | clean_pipe | swg_proxy
      address       — public IP
      addressType   — active | reserved | service_ip
      node_name     — list of node identifiers
      allow_listed  — bool; True = already in PAN's published IP list

    Results are normalised into snap.prisma_egress_ips using the same schema as
    extract_allocated_ips so the report renderer doesn't need two code paths.

    Ref: github.com/PaloAltoNetworks/prisma-access-ip-api-client
    """
    import requests as _requests

    url = f"{_PRISMA_DATAPATH_BASE}/getPrismaAccessIP/v2"
    headers = {"header-api-key": api_key, "Content-Type": "application/json"}
    payload = {"serviceType": "all", "addrType": "all", "location": "all"}

    try:
        resp = _requests.post(url, headers=headers, json=payload, timeout=(5, 30))
        if resp.status_code == 401:
            snap.extraction_errors.append(
                "egress_ips_datapath: 401 Unauthorised — the Prisma Access API key is "
                "invalid or expired.  Regenerate it in the admin portal under "
                "Settings → Service Setup → Prisma Access API Key."
            )
            logger.warning("egress_ips_datapath_auth_error")
            return snap
        if resp.status_code == 403:
            snap.extraction_errors.append(
                "egress_ips_datapath: 403 Access Denied — the API key may lack permission "
                "to query egress IPs.  Ensure the key has the Network Operator or "
                "Network Admin role in the Prisma Access portal."
            )
            logger.warning("egress_ips_datapath_forbidden")
            return snap
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        snap.extraction_errors.append(f"egress_ips_datapath: {exc}")
        logger.warning("egress_ips_datapath_error", error=str(exc))
        return snap

    if data.get("status") not in ("success", None):
        snap.extraction_errors.append(
            f"egress_ips_datapath: API returned status={data.get('status')} — "
            f"message={data.get('message', 'no message')}"
        )
        return snap

    entries: list[dict[str, Any]] = []
    for zone_obj in data.get("result") or []:
        zone = zone_obj.get("zone", "")
        for detail in zone_obj.get("address_details") or []:
            svc = detail.get("serviceType", "")
            addr_type = _DATAPATH_SVC_MAP.get(svc, svc)
            node_names = detail.get("node_name") or []
            node_str = " / ".join(node_names) if isinstance(node_names, list) else str(node_names)
            entries.append(
                {
                    "zone": zone,
                    "node_name": node_str,
                    "address_type": addr_type,
                    "service_type": svc,
                    "address_kind": detail.get("addressType", ""),
                    "allow_listed": detail.get("allow_listed", False),
                    "ip_address_list": [detail["address"]] if detail.get("address") else [],
                    "_source": "datapath",
                }
            )

    snap.prisma_egress_ips = entries
    logger.info("egress_ips_datapath_extracted", count=len(entries))
    return snap


def extract_allocated_ips(client: Any, snap: AuditSnapshot) -> AuditSnapshot:
    """
    Fetch Prisma Access allocated public egress IP addresses.

    Endpoint: GET /config/v1/infrastructure/allocated-ips
    Auth:     Same OAuth 2.0 bearer token as SCM.

    The response contains per-zone, per-node IP lists classified by address type:
      gp_gw_lbs_ips    — GlobalProtect Gateway (Mobile Users egress)
      gp_portal_lbs_ips — GlobalProtect Portal IPs
      sc_lbs_ips        — Service Connection egress IPs
      rn_lbs_ips        — Remote Network egress IPs
      panw_ddns_ips     — Dynamic DNS host IPs

    Results are stored as a flat list in snap.prisma_egress_ips so they can be
    rendered directly in §9.1 of the AS-BUILT without post-processing.

    Ref: https://pan.dev/scm/api/config/prisma-access-config/get-infrastructure-allocated-ips/
    """
    session = getattr(client, "session", None)
    if session is None:
        snap.extraction_errors.append("allocated_ips: Scm client has no .session")
        return snap

    # Correct path is under the SSE config base, not the standard config/v1 base.
    url = f"{_SCM_SSE_BASE}/infrastructure/allocated-ips"

    try:
        resp = session.get(url, timeout=(5, 15))
        if resp.status_code == 403:
            # OPA policy denial — view_only_admin is not sufficient for the
            # /infrastructure/* SSE path.  The service account needs 'superuser'
            # or a dedicated Prisma Access infrastructure role in SCM IAM.
            snap.extraction_errors.append(
                "allocated_ips: 403 Access Denied. The 'view_only_admin' role does "
                "not cover GET /sse/config/v1/infrastructure/*. Assign 'superuser' "
                "or a Prisma Access infrastructure role to the service account in "
                "SCM → Settings → Identity & Access Management."
            )
            logger.warning("allocated_ips_permission_denied", url=url)
            return snap
        if resp.status_code in _NOT_LICENSED_STATUSES:
            logger.info("allocated_ips_not_found", status=resp.status_code)
            return snap
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        if _exc_status(exc) in _NOT_LICENSED_STATUSES:
            logger.info("allocated_ips_not_found", status=_exc_status(exc))
            return snap
        snap.extraction_errors.append(f"allocated_ips: {exc}")
        logger.warning("allocated_ips_error", error=str(exc))
        return snap

    # Normalise the response — PAN returns several possible shapes depending on API version
    entries: list[dict[str, Any]] = []

    if isinstance(data, list):
        entries = data

    elif isinstance(data, dict):
        # Shape 1: {"data": [...]}
        if "data" in data:
            raw = data["data"]
            if isinstance(raw, list):
                entries = raw
            # Shape 2: {"data": {"zones": [...]}}
            elif isinstance(raw, dict) and "zones" in raw:
                for zone_obj in raw["zones"]:
                    zone = zone_obj.get("zone", zone_obj.get("name", ""))
                    for node in zone_obj.get("nodes", []):
                        entries.append(
                            {
                                "zone": zone,
                                "node_name": node.get("node_name", node.get("name", "")),
                                "address_type": node.get("address_type", ""),
                                "node_type": node.get("node_type", ""),
                                "ip_address_list": node.get(
                                    "addresses", node.get("ip_address_list", [])
                                ),
                            }
                        )

        # Shape 3: {"zones": [...]}  (top-level zones array)
        elif "zones" in data:
            for zone_obj in data["zones"]:
                zone = zone_obj.get("zone", zone_obj.get("name", ""))
                for node in zone_obj.get("nodes", []):
                    entries.append(
                        {
                            "zone": zone,
                            "node_name": node.get("node_name", node.get("name", "")),
                            "address_type": node.get("address_type", ""),
                            "node_type": node.get("node_type", ""),
                            "ip_address_list": node.get(
                                "addresses", node.get("ip_address_list", [])
                            ),
                        }
                    )

        # Shape 4: {"result": {"entry": [...]}}  (legacy Panorama-style)
        elif "result" in data:
            for entry in data["result"].get("entry") or []:
                zone = entry.get("@name", entry.get("name", ""))
                addr_type = entry.get("address-type", entry.get("address_type", ""))
                ip_list = entry.get("ip-list", entry.get("ip_address_list", {}))
                if isinstance(ip_list, dict):
                    ips = ip_list.get("entry", ip_list.get("member", []))
                elif isinstance(ip_list, list):
                    ips = ip_list
                else:
                    ips = [str(ip_list)] if ip_list else []
                entries.append(
                    {
                        "zone": zone,
                        "node_name": zone,
                        "address_type": addr_type,
                        "node_type": "",
                        "ip_address_list": ips,
                    }
                )

    snap.prisma_egress_ips = entries
    logger.info("allocated_ips_extracted", count=len(entries))
    return snap


def extract_insights(
    client: Any,
    snap: AuditSnapshot,
    region: str = "eu",
) -> AuditSnapshot:
    """
    Fetch live operational data from the Prisma Access Insights v3.0 API
    and attach it to *snap*.

    All failures are non-fatal; errors are appended to snap.insights_errors
    (not snap.extraction_errors) so operators can distinguish config-pull
    failures from Insights API failures.

    Parameters
    ----------
    client:
        Authenticated Scm client (uses client.session for HTTP calls).
    snap:
        The AuditSnapshot to populate.
    region:
        X-PANW-Region header value (default ``"eu"``).
    """
    try:
        from .insights_extractor import extract_insights as _do_extract

        result = _do_extract(client, tenant_id=snap.tenant_id, region=region)
        snap.insights_connected_mu_count = result.connected_mu_count
        snap.insights_rn_status = result.location_rn_status
        snap.insights_sc_status = result.location_sc_status
        snap.insights_mu_status = result.location_mu_status
        snap.insights_rn_bandwidth = result.location_rn_bandwidth
        snap.insights_sc_bandwidth = result.location_sc_bandwidth
        snap.insights_tunnel_list = result.tunnel_list
        snap.insights_alerts = result.active_alerts
        snap.insights_errors = result.errors
        logger.info(
            "insights_extraction_complete",
            mu_count=result.connected_mu_count,
            rn_status=len(result.location_rn_status),
            sc_status=len(result.location_sc_status),
            tunnels=len(result.tunnel_list),
            alerts=len(result.active_alerts),
            errors=len(result.errors),
        )
    except Exception as exc:
        snap.insights_errors.append(f"insights_extractor: {exc}")
        logger.warning("insights_extraction_failed", error=str(exc))
    return snap


def extract_enterprise_dlp(client: Any, snap: AuditSnapshot, company_id: str = "") -> AuditSnapshot:
    """
    Fetch Enterprise DLP resources from the PAN Enterprise DLP v2 API.

    Base URL: https://api.dlp.paloaltonetworks.com
    Auth:     Same OAuth 2.0 bearer token as SCM (reuses client.session).

    Endpoints (v2 API — no company ID required, tenant resolved from bearer token):
      GET /v2/api/data-patterns          — ML/regex/EDM patterns (predefined + custom)
      GET /v2/api/data-profiles          — DLP profiles (composed of patterns)
      GET /v2/api/data-filtering-profiles — data-filtering profiles used in policy
      GET /v2/api/dictionaries           — custom keyword/phrase dictionaries
      GET /v2/api/document-types         — ML document type classifiers
      GET /v2/api/edm-datasets           — Exact Data Match datasets
      GET /v2/api/ocr                    — OCR enablement settings per service

    Pagination: Spring-style { content: [...], total_pages, number }
    All return 404/401/403 if Enterprise DLP is not licensed — non-fatal.

    Ref: https://pan.dev/dlp/api/
    """
    session = getattr(client, "session", None)
    if session is None:
        snap.extraction_errors.append("enterprise_dlp: Scm client has no .session")
        return snap

    def _dlp_list(path: str) -> list[dict[str, Any]]:
        """Fetch all pages from a DLP v2 paginated endpoint."""
        items: list[dict[str, Any]] = []
        page = 0
        while True:
            resp = session.get(
                f"{_DLP_BASE}{path}",
                params={"page": page, "size": 200},
                timeout=(5, 20),
            )
            if resp.status_code in _NOT_LICENSED_STATUSES:
                return []
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, list):
                items.extend(data)
                break
            content = data.get("content") or []
            items.extend(content)
            if data.get("last", True) or not content:
                break
            page += 1
        return items

    # Derive tenant_id from first successful call for snap.dlp_company_id
    _tenant_id_set = False

    for attr, path in [
        ("dlp_data_patterns", "/v2/api/data-patterns"),
        ("dlp_data_profiles", "/v2/api/data-profiles"),
        ("dlp_filtering_profiles", "/v2/api/data-filtering-profiles"),
        ("dlp_dictionaries", "/v2/api/dictionaries"),
        ("dlp_document_types", "/v2/api/document-types"),
        ("dlp_edm_datasets", "/v2/api/edm-datasets"),
        ("dlp_ocr_settings", "/v2/api/ocr"),
    ]:
        try:
            items = _dlp_list(path)
            if items and not _tenant_id_set:
                snap.dlp_company_id = str(items[0].get("tenant_id", ""))
                _tenant_id_set = True
            setattr(snap, attr, items)
            logger.info("enterprise_dlp_extracted", resource=attr, count=len(items))
        except Exception as exc:
            if _exc_status(exc) in _NOT_LICENSED_STATUSES:
                logger.info("enterprise_dlp_not_licensed", resource=attr, status=_exc_status(exc))
                continue
            snap.extraction_errors.append(f"{attr}: {exc}")
            logger.warning("enterprise_dlp_error", resource=attr, error=str(exc))

    if not _tenant_id_set:
        logger.info("enterprise_dlp_not_licensed_or_inaccessible")

    return snap


def extract_iot_security(client: Any, snap: AuditSnapshot) -> AuditSnapshot:
    """
    Fetch IoT Security (Enterprise IoT / OT Security, formerly Zingbox) device inventory,
    alerts and sites.

    Base URL: https://api.strata.paloaltonetworks.com/iot/pub/v1|v2/
    Auth:     Same SASE OAuth 2.0 bearer token (reuses client.session).

    Endpoints:
      GET /iot/pub/v1/device/list   — device inventory with profile/risk/category (v1)
      GET /iot/pub/v2/device/list   — richer device data (SCM customers, may 403)
      GET /iot/pub/v1/alert/list    — active security alerts
      GET /iot/pub/v1/site          — IoT site definitions with subnet assignments

    404 {"code":404,"message":"Error: IoT tenant with TSG id ... is not found"}
        → IoT Security not licensed for this tenant — non-fatal, snap.iot_licensed stays False.
    403 → endpoint requires elevated role — silently skipped.
    """
    session = getattr(client, "session", None)
    if session is None:
        return snap

    base = (
        getattr(client, "api_base_url", None) or "https://api.strata.paloaltonetworks.com"
    ).rstrip("/")
    _IOT = f"{base}/iot/pub"

    def _iot_get(path: str, params: dict | None = None) -> tuple[int, Any]:
        try:
            r = session.get(f"{_IOT}{path}", params=params or {}, timeout=(5, 20))
            return r.status_code, r.json()
        except Exception as exc:
            logger.warning("iot_security_request_error", path=path, error=str(exc))
            return 0, {}

    # Check if licensed — probe with a minimal device request
    status, body = _iot_get("/v1/device/list", {"pagelength": 1})
    if status == 404:
        logger.info("iot_security_not_licensed", tenant_id=snap.tenant_id)
        return snap
    if status not in (200, 206):
        logger.warning("iot_security_probe_failed", status=status)
        return snap

    snap.iot_licensed = True
    snap.iot_devices_total = body.get("total", 0)

    # Fetch full device inventory — try v2 first (richer), fall back to v1
    devices: list[dict[str, Any]] = []
    page_size = 500
    # v2 attempt
    s2, b2 = _iot_get("/v2/device/list", {"pagelength": page_size})
    if s2 == 200:
        devices = b2.get("devices", [])
        snap.iot_devices_total = b2.get("total", snap.iot_devices_total)
        # paginate if needed
        offset = len(devices)
        while offset < snap.iot_devices_total:
            _, bp = _iot_get("/v2/device/list", {"pagelength": page_size, "offset": offset})
            chunk = bp.get("devices", [])
            if not chunk:
                break
            devices.extend(chunk)
            offset += len(chunk)
    else:
        # v1 fallback
        devices = body.get("devices", [])
        offset = len(devices)
        while body.get("has_more"):
            _, body = _iot_get(
                "/v1/device/list", {"detail": "true", "pagelength": page_size, "offset": offset}
            )
            chunk = body.get("devices", [])
            if not chunk:
                break
            devices.extend(chunk)
            offset += len(chunk)

    snap.iot_devices = devices
    logger.info(
        "iot_security_extracted",
        resource="devices",
        count=len(devices),
        total=snap.iot_devices_total,
    )

    # Alerts
    sa, ba = _iot_get("/v1/alert/list", {"pagelength": 200})
    if sa == 200:
        alerts = ba.get("items", [])
        snap.iot_alerts = alerts
        snap.iot_alerts_total = ba.get("total", len(alerts))
        logger.info("iot_security_extracted", resource="alerts", count=len(alerts))

    # Sites
    ss, bs = _iot_get("/v1/site")
    if ss == 200:
        snap.iot_sites = bs.get("list", [])
        logger.info("iot_security_extracted", resource="sites", count=len(snap.iot_sites))

    # Vulnerabilities (groupby=device gives per-device summary)
    sv, bv = _iot_get("/v1/vulnerability/list", {"pagelength": 500, "groupby": "vulnerability"})
    if sv == 200:
        vuln_items = bv.get("items", {})
        if isinstance(vuln_items, dict):
            vuln_items = vuln_items.get("items", [])
        snap.iot_vulnerabilities = vuln_items if isinstance(vuln_items, list) else []
        logger.info(
            "iot_security_extracted",
            resource="vulnerabilities",
            count=len(snap.iot_vulnerabilities),
            total=bv.get("total", 0),
        )

    # Policy recommendations (requires customerid = TSG ID)
    sp, bp = _iot_get(
        "/v1/policy/recommendation", {"customerid": snap.tenant_id, "pagelength": 200}
    )
    if sp == 200:
        snap.iot_policy_recommendations = bp.get("policies", [])
        logger.info(
            "iot_security_extracted",
            resource="policy_recommendations",
            count=len(snap.iot_policy_recommendations),
        )

    return snap


_NGFW_BASE = "https://api.sase.paloaltonetworks.com"


def extract_ngfw_devices(client: Any, snap: Any) -> Any:
    """
    Fetch NGFW managed devices onboarded to SCM.

    Device inventory:
      Tries client.device.list() across multiple folders (ngfw-shared, All,
      and the tenant's own folder) and deduplicates by serial number so that
      devices registered in custom folders are also captured.

    HA pairs:
      Queries GET /config/ngfw/v1/ha-devices (SCM NGFW Device Config REST API)
      to retrieve HA pair membership and role (active/passive/standalone).
      Falls back silently if the endpoint returns 404 or the tenant has no HA.
    """
    # ── Device inventory ─────────────────────────────────────────────────────
    seen_serials: set[str] = set()
    all_devices: list[dict] = []

    _folders_to_try = ["ngfw-shared", "All", snap.folder]
    for folder in dict.fromkeys(_folders_to_try):  # preserve order, deduplicate
        try:
            devices = client.device.list(folder=folder, limit=1000)
            for d in devices:
                dumped = _dump(d)
                serial = dumped.get("serial_number") or dumped.get("serial") or dumped.get("id", "")
                if serial and serial not in seen_serials:
                    seen_serials.add(serial)
                    all_devices.append(dumped)
        except AttributeError:
            snap.extraction_errors.append(
                "ngfw_devices: client.device not available in SDK version"
            )
            break
        except Exception as exc:
            if (
                any(m in str(exc) for m in _FOLDER_DOES_NOT_EXIST)
                or "404" in str(exc)
                or "not found" in str(exc).lower()
            ):
                continue
            snap.extraction_errors.append(f"ngfw_devices[{folder}]: {exc}")
            logger.warning("ngfw_devices_error", folder=folder, error=str(exc))

    snap.ngfw_devices = all_devices
    logger.info("ngfw_devices_extracted", count=len(snap.ngfw_devices))

    # ── HA pairs via NGFW Device Config REST API ─────────────────────────────
    session = getattr(client, "session", None)
    if session:
        try:
            resp = session.get(
                f"{_NGFW_BASE}/config/ngfw/v1/ha-devices",
                timeout=(4, 10),
            )
            if resp.status_code == 200:
                data = resp.json()
                items = data if isinstance(data, list) else data.get("data", data.get("items", []))
                snap.ngfw_ha_pairs = items if isinstance(items, list) else []
                logger.info("ngfw_ha_pairs_extracted", count=len(snap.ngfw_ha_pairs))
            # 404 = no HA configured — not an error
        except Exception as exc:
            logger.debug("ngfw_ha_pairs_unavailable", error=str(exc))

    return snap


def extract_ngfw_routing(client: Any, snap: Any) -> Any:
    """
    Fetch logical routers and BGP profiles for NGFW managed devices.

    Logical routers (virtual-routers in PAN-OS) live under device-specific
    folders (e.g. "ngfw-shared"), not the Prisma Access folder hierarchy.
    This function derives those folders from snap.ngfw_devices and queries:

      GET /config/network/v1/logical-routers?folder=<ngfw-folder>
      GET /config/network/v1/bgp-address-family-profiles?folder=<ngfw-folder>
      GET /config/network/v1/bgp-redistribution-profiles?folder=<ngfw-folder>
      GET /config/network/v1/bgp-auth-profiles?folder=<ngfw-folder>
      GET /config/network/v1/bgp-route-maps?folder=<ngfw-folder>

    Each logical router carries full VRF config including BGP peer groups and
    peers (router_id, local_as, peer_group[].peer[]) when configured.

    Prerequisite: extract_ngfw_devices() must have run first so snap.ngfw_devices
    is populated. Falls back gracefully to querying "ngfw-shared" if no devices.

    Note: Prisma Access BGP (bgp_routing_config) is already extracted by the
    main extractor. This function only handles NGFW device routing config.
    """
    session = getattr(client, "session", None)
    if session is None:
        return snap

    # Derive NGFW-specific folders from device list; always include "ngfw-shared"
    ngfw_folders: list[str] = ["ngfw-shared"]
    for dev in snap.ngfw_devices:
        f = dev.get("folder") or ""
        if f and f not in ngfw_folders:
            ngfw_folders.append(f)

    _base = _SCM_API_HOST
    _resources: list[tuple[str, str, str]] = [
        ("ngfw_logical_routers", "/config/network/v1/logical-routers", "logical_router"),
        (
            "ngfw_bgp_address_family_profiles",
            "/config/network/v1/bgp-address-family-profiles",
            "bgp_address_family_profile",
        ),
        (
            "ngfw_bgp_redistribution_profiles",
            "/config/network/v1/bgp-redistribution-profiles",
            "bgp_redistribution_profile",
        ),
        ("ngfw_bgp_auth_profiles", "/config/network/v1/bgp-auth-profiles", "bgp_auth_profile"),
        ("ngfw_bgp_route_maps", "/config/network/v1/bgp-route-maps", "bgp_route_map"),
    ]

    for snap_attr, endpoint_path, _label in _resources:
        seen_ids: set[str] = set()
        combined: list[dict[str, Any]] = []
        for folder in ngfw_folders:
            try:
                resp = session.get(
                    f"{_base}{endpoint_path}",
                    params={"folder": folder, "limit": str(_LIMIT)},
                    timeout=(5, 20),
                )
                if resp.status_code in (400, 404):
                    continue
                resp.raise_for_status()
                for item in resp.json().get("data", []):
                    uid = item.get("id") or item.get("name", "")
                    if uid and uid not in seen_ids:
                        seen_ids.add(uid)
                        combined.append(item)
            except Exception as exc:
                snap.extraction_errors.append(f"{_label}[{folder}]: {exc}")
                logger.warning("ngfw_routing_error", resource=_label, folder=folder, error=str(exc))
        setattr(snap, snap_attr, combined)

    logger.info(
        "ngfw_routing_extracted",
        logical_routers=len(snap.ngfw_logical_routers),
        bgp_af_profiles=len(snap.ngfw_bgp_address_family_profiles),
        bgp_redist_profiles=len(snap.ngfw_bgp_redistribution_profiles),
        bgp_route_maps=len(snap.ngfw_bgp_route_maps),
    )
    return snap


# NGFW Operations API — same prefix used by scm_ngfw_local_config_get (tools/adnsr.py).
# 403 = TSG lacks the NGFW Operations entitlement; treated as best-effort, not fatal.
_NGFW_OPS_BASE = "https://api.strata.paloaltonetworks.com/sse/config/v1"

_IFACE_NAME_RE = re.compile(r"^(ethernet\d+/\d+|ae\d+|ha\d+)(\.\d+)?$")


def parse_ngfw_interface_ips(xml_text: str) -> list[dict[str, Any]]:
    """
    Parse a PAN-OS running-config XML for physical/aggregate interface L3 addressing.

    Best-effort: PAN-OS config trees vary by vsys/template-stack structure, so
    this walks the whole tree for `<entry name="ethernetX/Y">` / `<entry
    name="aeN">` nodes with a `<layer3>` child, rather than a single rigid
    XPath tied to one vsys layout.

    Note: this reflects *configuration*, not live operational state. A DHCP-
    configured interface is reported with addressing="dhcp" but no IP — the
    actual leased address isn't visible via this endpoint (there is no
    NGFW equivalent of the SD-WAN interfaces_status API for that).
    """
    try:
        # xml_text is our own tenant's running-config, fetched via an authenticated
        # SCM session — not attacker-controlled, so XXE isn't a real risk here.
        root = ET.fromstring(xml_text)  # noqa: S314  # nosec B314: trusted first-party API response
    except ET.ParseError:
        return []

    # zone assignment can live under //vsys/entry/zone or shared/zone
    iface_zone: dict[str, str] = {}
    for zone_entry in root.iter("entry"):
        zone_name = zone_entry.get("name")
        layer3 = zone_entry.find("./network/layer3")
        if not zone_name or layer3 is None:
            continue
        for member in layer3.findall("member"):
            if member.text:
                iface_zone[member.text.strip()] = zone_name

    results: list[dict[str, Any]] = []
    for entry in root.iter("entry"):
        name = entry.get("name")
        if not name or not _IFACE_NAME_RE.match(name):
            continue
        layer3 = entry.find("layer3")
        if layer3 is None:
            continue

        addresses = [
            ip_entry.get("name")
            for ip_entry in layer3.findall("./ip/entry")
            if ip_entry.get("name")
        ]
        addressing = "static" if addresses else ""
        dhcp_block = layer3.find("dhcp-client")
        if dhcp_block is not None and (dhcp_block.findtext("enable", "") or "").strip() == "yes":
            addressing = "dhcp"

        if not addressing:
            continue  # no L3 addressing configured on this interface

        results.append(
            {
                "interface": name,
                "zone": iface_zone.get(name, ""),
                "addressing": addressing,
                "ip_addresses": addresses,
            }
        )
    return results


def extract_ngfw_interface_ips(client: Any, snap: AuditSnapshot) -> AuditSnapshot:
    """
    Best-effort extraction of NGFW managed-device interface IP addressing.

    Fetches each device's running-config XML via the NGFW Operations API
    (same endpoint as `scm_ngfw_local_config_get`) and parses it for
    interface-level L3 addressing. Devices that 403/404 (no entitlement, or
    device not yet synced) are skipped without aborting the rest.

    Prerequisite: extract_ngfw_devices() must have run first.
    """
    session = getattr(client, "session", None)
    if session is None or not snap.ngfw_devices:
        return snap

    results: list[dict[str, Any]] = []
    for dev in snap.ngfw_devices:
        serial = dev.get("serial_number") or dev.get("serial")
        if not serial:
            continue
        try:
            resp = session.get(
                f"{_NGFW_OPS_BASE}/local-config/running",
                params={"serial": serial},
                timeout=(10, 30),
            )
            if resp.status_code in (403, 404):
                continue
            resp.raise_for_status()
            ct = resp.headers.get("Content-Type", "")
            xml_text = resp.text
            if "xml" not in ct and not xml_text.strip().startswith("<?xml"):
                data = resp.json()
                dl_url = data.get("download-url") or data.get("url") or data.get("config_url")
                if not dl_url:
                    continue
                xml_text = session.get(dl_url, timeout=(10, 60)).text
        except Exception as exc:
            snap.extraction_errors.append(f"ngfw_interface_ips[{serial}]: {exc}")
            logger.debug("ngfw_interface_ips_failed", serial=serial, error=str(exc))
            continue

        for rec in parse_ngfw_interface_ips(xml_text):
            rec["device_name"] = dev.get("name", serial)
            rec["serial_number"] = serial
            results.append(rec)

    snap.ngfw_interface_ips = results
    logger.info("ngfw_interface_ips_extracted", count=len(results))
    return snap


def extract_airs(client: Any, snap: Any) -> Any:
    """
    Fetch Prisma AIRS (AI Runtime Security) config via the management API.

    Base URL: https://api.sase.paloaltonetworks.com/aisec
    Auth:     Same OAuth 2.0 bearer token as SCM (reuses client.session).
    TSG ID:   Taken from snap.tenant_id — required for per-TSG list endpoints.

    Endpoints:
      GET /v1/mgmt/customerapp/tsg/{tsgId} — customer apps  (response key: customer_apps)
      GET /v1/mgmt/profiles/tsg/{tsgId}    — AI sec profiles (response key: ai_profiles)
      GET /v1/mgmt/deploymentprofiles       — deployment profiles (response key: deployment_profiles)

    All return 404/424 if AIRS is not licensed/activated — non-fatal.

    Response schemas confirmed from cdot65/prisma-airs-sdk:
      - Customer app fields: app_name, cloud_provider, environment, status, ai_agent_framework
      - Security profile fields: profile_name, profile_id, revision, active
      - Deployment profile fields: dp_name, auth_code, status, expiration_date

    Ref: https://pan.dev/prisma-airs/api/airuntimesecurity/prismaairsmanagementapi/
    """
    session = getattr(client, "session", None)
    if session is None:
        snap.extraction_errors.append("airs: Scm client has no .session")
        return snap

    tsg_id = snap.tenant_id

    _endpoints = [
        # (snap_attr, url_path, response_list_key)
        ("airs_apps", f"/v1/mgmt/customerapp/tsg/{tsg_id}", "customer_apps"),
        ("airs_security_profiles", f"/v1/mgmt/profiles/tsg/{tsg_id}", "ai_profiles"),
        ("airs_deployment_profiles", "/v1/mgmt/deploymentprofiles", "deployment_profiles"),
    ]

    for attr, url_path, list_key in _endpoints:
        try:
            resp = session.get(f"{_AIRS_BASE}{url_path}", timeout=(4, 10))
            if resp.status_code in _NOT_LICENSED_STATUSES:
                logger.info("airs_not_licensed", resource=attr, status=resp.status_code)
                continue
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, list):
                items = data
            else:
                items = data.get(list_key, data.get("data", data.get("items", []))) or []
            setattr(snap, attr, items)
            logger.info("airs_extracted", resource=attr, count=len(items))
        except Exception as exc:
            if _exc_status(exc) in _NOT_LICENSED_STATUSES:
                logger.info("airs_not_licensed", resource=attr, status=_exc_status(exc))
                continue
            snap.extraction_errors.append(f"{attr}: {exc}")
            logger.warning("airs_error", resource=attr, error=str(exc))

    return snap


_SSPM_BASE = "https://api.strata.paloaltonetworks.com/sspm/api/v1"


def extract_sspm(client: Any, snap: AuditSnapshot) -> AuditSnapshot:
    """
    Fetch SaaS Security Posture Management (SSPM) data.

    Base URL: https://api.strata.paloaltonetworks.com/sspm/api/v1
    Auth:     Same SASE OAuth bearer token as SCM (reuses client.session).

    Endpoints used:
      GET /apps          — onboarded SaaS applications (empty list = licensed but nothing onboarded)
      GET /apps/{id}/configs — per-app misconfiguration findings
      GET /catalog/apps  — full catalog of 178 supported apps

    500 = not licensed / service unavailable (treated as unlicensed, non-fatal).
    """
    session = _bearer_session_for(client)

    try:
        r = session.get(f"{_SSPM_BASE}/apps", timeout=(5, 20))
        if r.status_code == 500:
            logger.info("sspm_not_licensed", status=500)
            return snap
        r.raise_for_status()
        body = r.json()
        apps = body.get("items", body) if isinstance(body, dict) else body
        snap.sspm_apps = apps if isinstance(apps, list) else []
        snap.sspm_licensed = True
        logger.info("sspm_apps_extracted", count=len(snap.sspm_apps))
    except Exception as exc:
        if _exc_status(exc) == 500:
            logger.info("sspm_not_licensed", status=500)
            return snap
        snap.extraction_errors.append(f"sspm_apps: {exc}")
        logger.warning("sspm_error", resource="apps", error=str(exc))
        return snap

    # Per-app misconfiguration findings (inject into each app dict)
    for app in snap.sspm_apps:
        app_id = app.get("app_id") or app.get("id")
        if not app_id:
            continue
        try:
            cr = session.get(f"{_SSPM_BASE}/apps/{app_id}/configs", timeout=(5, 20))
            if cr.status_code == 200:
                cb = cr.json()
                configs = cb.get("items", cb) if isinstance(cb, dict) else cb
                app["_configs"] = configs if isinstance(configs, list) else []
        except Exception:
            app["_configs"] = []

    # Catalog — supported apps with their verticals/features
    try:
        cr = session.get(f"{_SSPM_BASE}/catalog/apps", timeout=(5, 30))
        if cr.status_code == 200:
            snap.sspm_catalog = cr.json() if isinstance(cr.json(), list) else []
            logger.info("sspm_catalog_extracted", count=len(snap.sspm_catalog))
    except Exception as exc:
        snap.extraction_errors.append(f"sspm_catalog: {exc}")
        logger.warning("sspm_error", resource="catalog", error=str(exc))

    return snap


_IDENTITY_SSPM_BASE = "https://api.strata.paloaltonetworks.com/sspm/identity/v1"


def extract_identity_sspm(client: Any, snap: AuditSnapshot) -> AuditSnapshot:
    """
    Fetch Identity-SSPM data — connected IdPs and NHI posture.

    Base URL: https://api.strata.paloaltonetworks.com/sspm/identity/v1
    Auth:     Same SASE OAuth bearer token.

    Returns 404 if Identity-SSPM is not provisioned — non-fatal.
    Only /idps is broadly accessible; other endpoints (saas-instances, feature-state)
    return 404 or timeout on non-provisioned tenants.
    """
    session = _bearer_session_for(client)

    try:
        r = session.get(f"{_IDENTITY_SSPM_BASE}/idps", timeout=(5, 15))
        if r.status_code == 404:
            logger.info("identity_sspm_not_provisioned")
            return snap
        if r.status_code == 500:
            logger.info("identity_sspm_not_licensed", status=500)
            return snap
        r.raise_for_status()
        body = r.json()
        snap.identity_sspm_idps = body.get("items", body) if isinstance(body, dict) else body
        if not isinstance(snap.identity_sspm_idps, list):
            snap.identity_sspm_idps = []
        snap.identity_sspm_licensed = True
        logger.info("identity_sspm_extracted", idps=len(snap.identity_sspm_idps))
    except Exception as exc:
        status = _exc_status(exc)
        if status in (404, 500):
            logger.info("identity_sspm_not_provisioned", status=status)
            return snap
        snap.extraction_errors.append(f"identity_sspm: {exc}")
        logger.warning("identity_sspm_error", error=str(exc))

    return snap


_APP_ACCL_INSIGHTS = "https://api.sase.paloaltonetworks.com/insights/v3.0"


def extract_app_acceleration(client: Any, snap: AuditSnapshot) -> AuditSnapshot:
    """
    Fetch App Acceleration telemetry via Prisma Access Insights v3.0.

    Resource: accelerated_applications
    Endpoints: applications_count, accelerated_application_list, performance_boost,
               users_count, better_response_time, total_data_transfer

    Returns 500 if App Acceleration is not activated on the tenant — non-fatal.
    Auth: Same SASE OAuth bearer token.
    """
    session = _bearer_session_for(client)

    def _accl_query(metric: str, query: dict | None = None) -> dict:
        payload = {
            "resource": "accelerated_applications",
            "query": query or {"count": 200},
        }
        try:
            r = session.post(
                f"{_APP_ACCL_INSIGHTS}/resource/query/accelerated_applications/{metric}",
                json=payload,
                timeout=(5, 20),
            )
            if r.status_code in (500, 503):
                return {}
            r.raise_for_status()
            return r.json()
        except Exception:
            return {}

    # Probe with count first
    count_body = _accl_query("applications_count")
    if not count_body:
        logger.info("app_accl_not_activated")
        return snap

    snap.app_accl_licensed = True
    snap.app_accl_stats["applications_count"] = count_body

    # App list
    apps_body = _accl_query("accelerated_application_list")
    if apps_body:
        data = apps_body.get("data", apps_body.get("items", []))
        snap.app_accl_apps = data if isinstance(data, list) else []
        snap.app_accl_stats["performance_boost"] = _accl_query("performance_boost")
        snap.app_accl_stats["users_count"] = _accl_query("users_count")
        snap.app_accl_stats["total_data_transfer"] = _accl_query("total_data_transfer")

    logger.info("app_accl_extracted", apps=len(snap.app_accl_apps))
    return snap


def extract_traffic_steering(client: Any, snap: AuditSnapshot) -> AuditSnapshot:
    """
    Fetch Traffic Steering Rules via /sse/config/v1/traffic-steering-rules.

    Traffic steering rules control how Prisma Access routes traffic — e.g.
    direct internet access (DIA), backhaul steering, or split tunnelling overrides.
    Auth: Same SCM session (OAuth2Session).
    """
    session = getattr(client, "session", None)
    if session is None:
        return snap

    base = (
        getattr(client, "api_base_url", None) or "https://api.strata.paloaltonetworks.com"
    ).rstrip("/")
    try:
        items = _rest_list(session, f"{base}/sse/config/v1/traffic-steering-rules")
        snap.traffic_steering_rules = items
        logger.info("traffic_steering_extracted", count=len(items))
    except Exception as exc:
        if _exc_status(exc) in _NOT_LICENSED_STATUSES:
            logger.info("traffic_steering_not_available")
        else:
            snap.extraction_errors.append(f"traffic_steering_rules: {exc}")
            logger.warning("traffic_steering_error", error=str(exc))

    return snap


def extract_pab_tenant(client: Any, snap: AuditSnapshot) -> AuditSnapshot:
    """
    Fetch Prisma Browser (PAB) MSSP tenant metadata:
      GET /mt/pab/tenant/region      — list of provisioned regions
      GET /mt/pab/tenant/licenses    — PAB licence entitlements
      GET /mt/pab/tenant/directories — enrolled AD/LDAP directories

    Auth: Same SASE OAuth bearer token.
    Returns 404 if PAB is not provisioned — non-fatal.
    """
    session = _bearer_session_for(client)
    SASE = "https://api.sase.paloaltonetworks.com"

    for attr, path, extractor in [
        (
            "pab_tenant_regions",
            "/mt/pab/tenant/region",
            lambda b: b.get("data", {}).get("regions", []) if isinstance(b, dict) else [],
        ),
        (
            "pab_tenant_licenses",
            "/mt/pab/tenant/licenses",
            lambda b: b.get("data", []) if isinstance(b, dict) else [],
        ),
        (
            "pab_tenant_directories",
            "/mt/pab/tenant/directories",
            lambda b: b.get("data", []) if isinstance(b, dict) else [],
        ),
    ]:
        try:
            r = session.get(f"{SASE}{path}", timeout=(5, 15))
            if r.status_code in (404, 403):
                continue
            r.raise_for_status()
            setattr(snap, attr, extractor(r.json()))  # type: ignore[operator]
        except Exception as exc:
            if _exc_status(exc) not in _NOT_LICENSED_STATUSES:
                snap.extraction_errors.append(f"pab_{attr}: {exc}")
                logger.warning("pab_tenant_error", resource=attr, error=str(exc))

    if snap.pab_tenant_regions or snap.pab_tenant_directories:
        logger.info(
            "pab_tenant_extracted",
            regions=snap.pab_tenant_regions,
            directories=snap.pab_tenant_directories,
        )
    return snap


def extract_sdwan_snapshot(sdwan_client: Any, snap: AuditSnapshot) -> AuditSnapshot:
    """
    Pull Prisma SD-WAN config into an existing AuditSnapshot.

    Called separately from extract_snapshot because it requires a different
    client (prisma-sase SDK).  Failures are appended to snap.extraction_errors.
    """
    from ..auth.sdwan import safe_items

    def _sdwan_list(method_name: str, **kwargs: Any) -> list[dict[str, Any]]:
        try:
            method = getattr(sdwan_client.get, method_name)
            resp = method(**kwargs)
            return safe_items(resp)
        except Exception as exc:
            snap.extraction_errors.append(f"sdwan_{method_name}: {exc}")
            logger.warning("sdwan_extraction_error", resource=method_name, error=str(exc))
            return []

    logger.info("sdwan_extraction_start")

    snap.sdwan_sites = _sdwan_list("sites")
    snap.sdwan_elements = _sdwan_list("elements")
    snap.sdwan_wan_networks = _sdwan_list("wannetworks")
    snap.sdwan_path_groups = _sdwan_list("pathgroups")
    snap.sdwan_policy_sets = _sdwan_list("networkpolicysets")
    snap.sdwan_priority_policy_sets = _sdwan_list("prioritypolicysets")
    # hubclusters, spokeclusters, bgppeers all require site_id (and element_id for bgppeers).
    # The cluster objects returned by the API do not include site_id or site_name, so we
    # inject _queried_site_id / _queried_site_name from the outer loop for display purposes.
    hub_clusters: list[dict[str, Any]] = []
    spoke_clusters: list[dict[str, Any]] = []
    bgp_peers: list[dict[str, Any]] = []
    for _site in snap.sdwan_sites:
        _sid = _site.get("id")
        if not _sid:
            continue
        _sname = _site.get("name", str(_sid))
        for _hc in _sdwan_list("hubclusters", site_id=_sid):
            _hc["_queried_site_id"] = _sid
            _hc["_queried_site_name"] = _sname
            hub_clusters.append(_hc)
        for _sc in _sdwan_list("spokeclusters", site_id=_sid):
            _sc["_queried_site_id"] = _sid
            _sc["_queried_site_name"] = _sname
            spoke_clusters.append(_sc)
        for _elem in snap.sdwan_elements:
            if _elem.get("site_id") == _sid:
                _eid = _elem.get("id")
                if _eid:
                    bgp_peers.extend(_sdwan_list("bgppeers", site_id=_sid, element_id=_eid))
    snap.sdwan_hub_clusters = hub_clusters
    snap.sdwan_spoke_clusters = spoke_clusters
    snap.sdwan_bgp_peers = bgp_peers

    # Collect WAN interfaces across all sites
    wan_ifaces: list[dict[str, Any]] = []
    for site in snap.sdwan_sites:
        site_id = site.get("id")
        if site_id:
            ifaces = _sdwan_list("waninterfaces", site_id=site_id)
            for iface in ifaces:
                iface["_site_name"] = site.get("name", "")
            wan_ifaces.extend(ifaces)
    snap.sdwan_wan_interfaces = wan_ifaces

    wan_ips, wan_ip_errors = extract_sdwan_wan_ips(
        sdwan_client, snap.sdwan_sites, snap.sdwan_elements
    )
    snap.sdwan_wan_ips = wan_ips
    snap.extraction_errors.extend(wan_ip_errors)

    detected_ips, detected_ip_errors = extract_sdwan_detected_public_ips(
        sdwan_client, snap.sdwan_sites, snap.sdwan_elements
    )
    snap.sdwan_detected_public_ips = detected_ips
    snap.extraction_errors.extend(detected_ip_errors)

    # VPN overlay topology (direct REST — not in SDK)
    try:
        from ..audit.sdwan_topo import build_topology, topology_to_mermaid

        snap.sdwan_vpn_links = build_topology(
            sdwan_client,
            sites=snap.sdwan_sites,
            wan_interfaces=snap.sdwan_wan_interfaces,
            wan_networks=snap.sdwan_wan_networks,
        )
        snap.sdwan_topology_mermaid = topology_to_mermaid(
            snap.sdwan_vpn_links,
            snap.sdwan_sites,
            snap.sdwan_wan_networks,
            wan_ips=snap.sdwan_wan_ips,
        )
    except Exception as exc:
        snap.extraction_errors.append(f"sdwan_topology: {exc}")
        logger.warning("sdwan_topology_failed", error=str(exc))

    logger.info(
        "sdwan_extraction_complete",
        sites=len(snap.sdwan_sites),
        elements=len(snap.sdwan_elements),
        wan_interfaces=len(snap.sdwan_wan_interfaces),
        wan_ips=len(snap.sdwan_wan_ips),
        vpn_links=len(snap.sdwan_vpn_links),
    )
    return snap


def extract_sdwan_wan_ips(
    sdwan_client: Any,
    sites: list[dict[str, Any]],
    elements: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    """
    Resolve the live public/private WAN IP address bound to each SD-WAN
    element's internet- or MPLS-facing interface.

    Per element: GET interfaces (config) to find ports marked
    used_for="public"/"private", then GET interfaces_status for just those
    interfaces to read the live-bound ipv4_addresses — this works for both
    statically-addressed and DHCP-assigned circuits (the config object alone
    doesn't carry the DHCP-leased address).

    Each record also resolves the circuit it belongs to: the interface's
    site_wan_interface_ids → site WAN interface (`circuit_name`) → WAN
    network (`wan_network`) — the configured ISP/circuit label that the
    drift check compares against the observed ISP.

    Snapshot-independent (takes plain sites/elements lists) so both the full
    audit extraction pipeline and the standalone `sdwan_*` MCP tools can share
    it. Returns (wan_ip_records, error_strings) — never raises.
    """
    from ..auth.sdwan import safe_items

    site_by_id = {s.get("id"): s for s in sites if s.get("id")}
    wan_ips: list[dict[str, Any]] = []
    errors: list[str] = []

    try:
        network_names = {
            n.get("id"): n.get("name", "") for n in safe_items(sdwan_client.get.wannetworks())
        }
    except Exception as exc:
        network_names = {}
        errors.append(f"sdwan_wannetworks: {exc}")
    circuit_by_site: dict[str, dict[str, dict[str, Any]]] = {}

    def _circuit(site_id: str, iface: dict[str, Any]) -> tuple[str, str]:
        """Resolve (circuit_name, wan_network) for a WAN-facing interface."""
        swi_ids = iface.get("site_wan_interface_ids") or []
        if not swi_ids:
            return "", ""
        if site_id not in circuit_by_site:
            try:
                circuit_by_site[site_id] = {
                    w["id"]: w
                    for w in safe_items(sdwan_client.get.waninterfaces(site_id=site_id))
                    if w.get("id")
                }
            except Exception as exc:
                circuit_by_site[site_id] = {}
                errors.append(f"sdwan_waninterfaces[{site_id}]: {exc}")
        swi = circuit_by_site[site_id].get(swi_ids[0], {})
        return swi.get("name", ""), network_names.get(swi.get("network_id"), "")

    for elem in elements:
        site_id = elem.get("site_id")
        element_id = elem.get("id")
        if not site_id or not element_id:
            continue
        try:
            ifaces = safe_items(sdwan_client.get.interfaces(site_id=site_id, element_id=element_id))
        except Exception as exc:
            errors.append(f"sdwan_interfaces[{element_id}]: {exc}")
            continue

        for iface in ifaces:
            used_for = iface.get("used_for")
            iface_id = iface.get("id")
            if used_for not in ("public", "private") or not iface_id:
                continue
            try:
                status_items = safe_items(
                    sdwan_client.get.interfaces_status(
                        site_id=site_id, element_id=element_id, interface_id=iface_id
                    )
                )
            except Exception as exc:
                errors.append(f"sdwan_interfaces_status[{iface_id}]: {exc}")
                continue
            status = status_items[0] if status_items else {}
            circuit_name, wan_network = _circuit(site_id, iface)
            wan_ips.append(
                {
                    "site_id": site_id,
                    "site_name": site_by_id.get(site_id, {}).get("name", site_id),
                    "element_id": element_id,
                    "element_name": elem.get("name", element_id),
                    "interface_name": iface.get("name", ""),
                    "used_for": used_for,
                    "circuit_name": circuit_name,
                    "wan_network": wan_network,
                    "config_type": (iface.get("ipv4_config") or {}).get("type", ""),
                    "operational_state": status.get("operational_state", ""),
                    "ipv4_addresses": status.get("ipv4_addresses") or [],
                    "ipv6_addresses": status.get("ipv6_addresses") or [],
                }
            )
    return wan_ips, errors


def extract_sdwan_detected_public_ips(
    sdwan_client: Any,
    sites: list[dict[str, Any]],
    elements: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Resolve each SD-WAN element's post-NAT public IP, per element status.

    Reads `config_and_events_from` from the element's operational status —
    the post-NAT source address the cloud controller sees the ION's
    config/events connection arriving from. The only API-visible source
    when the WAN interface itself holds an RFC1918 address behind an
    upstream NAT (there is no remote-exec on IONs). Caveat: it reflects
    whichever circuit the controller connection rides (normally the
    primary internet circuit), so a multi-WAN branch shows one NAT IP,
    not one per circuit.

    Snapshot-independent (plain sites/elements lists) so both the full
    audit extraction pipeline and the standalone `sdwan_wan_ip_summary`
    MCP tool share it. Returns (records, error_strings) — never raises.
    """
    from ..auth.sdwan import safe_items

    site_by_id = {s.get("id"): s for s in sites if s.get("id")}
    detected: list[dict[str, Any]] = []
    errors: list[str] = []

    for elem in elements:
        eid = elem.get("id")
        if not eid:
            continue
        try:
            status_items = safe_items(sdwan_client.get.element_status(element_id=eid))
        except Exception as exc:
            errors.append(f"sdwan_element_status[{eid}]: {exc}")
            continue
        status = status_items[0] if status_items else {}
        public_ip = status.get("config_and_events_from") or ""
        # SD-WAN parks unclaimed/unassigned elements under site_id "1"
        elem_site_id = elem.get("site_id")
        site_name = (
            "(unassigned)"
            if elem_site_id == "1"
            else site_by_id.get(elem_site_id, {}).get("name", elem_site_id)
        )
        detected.append(
            {
                "site_id": elem_site_id,
                "site_name": site_name,
                "element_id": eid,
                "element_name": elem.get("name", eid),
                "connected": elem.get("connected"),
                "detected_public_ip": public_ip,
            }
        )
    return detected, errors


_DRIFT_GEO_KM = 500  # IP geolocation is city-accurate at best; be conservative
_DRIFT_STOPWORDS = frozenset(
    [
        "internet",
        "wan",
        "broadband",
        "circuit",
        "fibre",
        "fiber",
        "mpls",
        "lte",
        "5g",
        "public",
        "private",
        "primary",
        "secondary",
        "backup",
        "link",
        "network",
        "isp",
        "net",
        "line",
        "dia",
    ]
)


def _drift_tokens(text: str) -> set[str]:
    import re as _re

    return {
        t
        for t in _re.split(r"[^a-z0-9]+", text.lower())
        if len(t) >= 2 and t not in _DRIFT_STOPWORDS
    }


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    import math

    rlat1, rlat2 = math.radians(lat1), math.radians(lat2)
    dlat, dlon = rlat2 - rlat1, math.radians(lon2 - lon1)
    a = math.sin(dlat / 2) ** 2 + math.cos(rlat1) * math.cos(rlat2) * math.sin(dlon / 2) ** 2
    return 2 * 6371 * math.asin(math.sqrt(a))


def annotate_wan_ip_drift(wan_ips: list[dict[str, Any]]) -> int:
    """Flag enriched WAN IP records whose observed ISP/geo contradicts config.

    Two advisory checks per record that has `enrichment` attached:

    - **isp_label**: no token overlap between the configured WAN network /
      circuit name and the observed ISP/org/AS name — the circuit may be
      patched or labelled wrong. Token-based, so it can false-positive on
      labels that never mention the provider; it is a prompt to verify, not
      a verdict.
    - **geo**: IP geolocates > ~500 km from the site's configured
      coordinates (needs `site_location` on the record) — solid signal the
      address or the circuit documentation is wrong.

    Mutates records in place (adds `drift: [reasons]`); returns the number
    of records flagged. Never raises.
    """
    flagged = 0
    for rec in wan_ips:
        enrichments = rec.get("enrichment") or []
        if isinstance(enrichments, dict):
            enrichments = [enrichments]
        if not enrichments:
            continue
        reasons: list[str] = []

        label = " ".join(filter(None, [rec.get("wan_network"), rec.get("circuit_name")]))
        label_tokens = _drift_tokens(label)
        for enr in enrichments:
            observed = " ".join(filter(None, [enr.get("isp"), enr.get("org"), enr.get("as_name")]))
            if label_tokens and observed and not (label_tokens & _drift_tokens(observed)):
                reasons.append(
                    f"isp_label: configured circuit {label!r} vs observed ISP "
                    f"{enr.get('isp') or enr.get('org')!r} ({enr.get('ip')}) share no "
                    "name token — verify patching/labelling"
                )

            loc = rec.get("site_location") or {}
            s_lat, s_lon = loc.get("latitude"), loc.get("longitude")
            e_lat, e_lon = enr.get("latitude"), enr.get("longitude")
            if (
                s_lat is not None
                and s_lon is not None
                and e_lat is not None
                and e_lon is not None
                and (s_lat, s_lon) != (0, 0)
            ):
                km = _haversine_km(s_lat, s_lon, e_lat, e_lon)
                if km > _DRIFT_GEO_KM:
                    reasons.append(
                        f"geo: {enr.get('ip')} geolocates to "
                        f"{enr.get('city') or enr.get('country') or 'unknown'} "
                        f"~{km:.0f} km from the site's configured location"
                    )

        if reasons:
            rec["drift"] = reasons
            flagged += 1
    return flagged


def enrich_wan_ip_records(records: list[dict[str, Any]], ip_fields: tuple[str, ...]) -> list[str]:
    """Attach ISP/ASN/rDNS/geo enrichment to WAN IP-style records in place.

    `ip_fields` names the record keys holding IP lists (or single strings).
    Shared by `sdwan_wan_ip_summary` and the AS-BUILT enrichment pass so both
    produce identically-shaped `enrichment` entries. Returns warnings.
    """
    from ..utils.ipenrich import enrich_public_ips, global_ips

    def _ips(rec: dict[str, Any]) -> list[str]:
        out: list[str] = []
        for field in ip_fields:
            value = rec.get(field)
            if isinstance(value, str):
                out.append(value)
            elif isinstance(value, list):
                out.extend(value)
        return out

    candidates = [ip for rec in records for ip in _ips(rec)]
    by_ip, warnings = enrich_public_ips(candidates)
    for rec in records:
        matches = [by_ip[ip] for ip in global_ips(_ips(rec)) if ip in by_ip]
        if matches:
            rec["enrichment"] = matches
    return warnings


_SASE_IAM_BASE = "https://api.sase.paloaltonetworks.com/iam/v1"
_SASE_MONITOR_BASE = "https://api.sase.paloaltonetworks.com/mt/monitor/v1/agg"


def extract_iam_roles(client: Any, snap: AuditSnapshot) -> AuditSnapshot:
    """
    Fetch IAM roles from api.sase.paloaltonetworks.com/iam/v1/roles.

    Returns all predefined and custom roles for the tenant, each with
    name, label, permissions count, and permission_sets.
    """
    session = _bearer_session_for(client)
    try:
        r = session.get(f"{_SASE_IAM_BASE}/roles", timeout=(5, 15))
        if r.status_code in _NOT_LICENSED_STATUSES:
            logger.info("iam_not_accessible", status=r.status_code)
            return snap
        if r.status_code == 200:
            snap.iam_roles = r.json().get("items", [])
            logger.info("iam_roles_extracted", count=len(snap.iam_roles))
    except Exception as exc:
        snap.extraction_errors.append(f"iam_roles: {exc}")
        logger.warning("iam_extraction_error", error=str(exc))
    return snap


def extract_mt_monitor_alerts(client: Any, snap: AuditSnapshot) -> AuditSnapshot:
    """
    Fetch recent MT Monitor aggregate alerts.

    POST https://api.sase.paloaltonetworks.com/mt/monitor/v1/agg/alerts
    Returns last 500 alerts across the tenant (data=[]) when no active alerts.
    """
    session = _bearer_session_for(client)
    try:
        r = session.post(
            f"{_SASE_MONITOR_BASE}/alerts",
            json={"query": {"count": 500}},
            timeout=(5, 20),
        )
        if r.status_code in _NOT_LICENSED_STATUSES:
            logger.info("mt_monitor_not_accessible", status=r.status_code)
            return snap
        if r.status_code == 200:
            body = r.json()
            snap.mt_monitor_alerts = body.get("data", [])
            logger.info("mt_monitor_alerts_extracted", count=len(snap.mt_monitor_alerts))
    except Exception as exc:
        snap.extraction_errors.append(f"mt_monitor_alerts: {exc}")
        logger.warning("mt_monitor_extraction_error", error=str(exc))
    return snap


_SASE_TENANCY_BASE = "https://api.sase.paloaltonetworks.com/tenancy/v1"


def extract_iam_access_policies(client: Any, snap: AuditSnapshot) -> AuditSnapshot:
    """
    Fetch IAM access policies (principal → role → resource scope).

    GET /iam/v1/access-policies  — returns who has what role on what resource.
    GET /iam/v1/service-accounts — returns service accounts registered in the tenant.

    Requires the OAuth token to have IAM read scope (super-user or IAM admin role).
    """
    session = _bearer_session_for(client)
    try:
        r = session.get(f"{_SASE_IAM_BASE}/access-policies", timeout=(5, 15))
        if r.status_code == 200:
            snap.iam_access_policies = r.json().get("items", [])
            logger.info("iam_access_policies_extracted", count=len(snap.iam_access_policies))
        elif r.status_code not in _NOT_LICENSED_STATUSES:
            snap.extraction_errors.append(f"iam_access_policies: HTTP {r.status_code}")
    except Exception as exc:
        snap.extraction_errors.append(f"iam_access_policies: {exc}")
        logger.warning("iam_access_policies_error", error=str(exc))

    try:
        r = session.get(f"{_SASE_IAM_BASE}/service-accounts", timeout=(5, 15))
        if r.status_code == 200:
            snap.iam_service_accounts = r.json().get("items", [])
            logger.info("iam_service_accounts_extracted", count=len(snap.iam_service_accounts))
        elif r.status_code not in _NOT_LICENSED_STATUSES:
            snap.extraction_errors.append(f"iam_service_accounts: HTTP {r.status_code}")
    except Exception as exc:
        snap.extraction_errors.append(f"iam_service_accounts: {exc}")
        logger.warning("iam_service_accounts_error", error=str(exc))

    return snap


def extract_managed_tenants(client: Any, snap: AuditSnapshot) -> AuditSnapshot:
    """
    Fetch the list of managed sub-tenants visible to the authenticated SP/super-user.

    GET /tenancy/v1/tenants  — available when the OAuth token belongs to an SP-level
    account with Tenant Management permissions.  Returns each sub-tenant's TSG ID,
    display name, and status.  Returns an empty list (not an error) for tenant-level
    credentials that don't have visibility above their own TSG.
    """
    session = _bearer_session_for(client)
    try:
        r = session.get(f"{_SASE_TENANCY_BASE}/tenants", timeout=(5, 15))
        if r.status_code == 200:
            body = r.json()
            # Response may be {"items": [...]} or a flat list
            items = body.get("items") or (body if isinstance(body, list) else [])
            snap.managed_tenants = items
            logger.info("managed_tenants_extracted", count=len(snap.managed_tenants))
        elif r.status_code in _NOT_LICENSED_STATUSES:
            logger.info("managed_tenants_not_accessible", status=r.status_code)
        else:
            snap.extraction_errors.append(f"managed_tenants: HTTP {r.status_code}")
    except Exception as exc:
        snap.extraction_errors.append(f"managed_tenants: {exc}")
        logger.warning("managed_tenants_error", error=str(exc))
    return snap
