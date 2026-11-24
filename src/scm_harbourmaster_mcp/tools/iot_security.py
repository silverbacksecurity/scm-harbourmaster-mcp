"""Read-only Enterprise IoT / Device Security tool: ``scm_iot``.

One tool over the IoT Security public API (``/iot/pub`` on
``api.strata.paloaltonetworks.com``, SCM bearer token, no region header), so a
single slot in its domain's tool cap covers every read.  It never writes: the
API's tag, alert-resolve, bulk-update and rule endpoints are not exposed.

Actions:

  * ``summary`` - licence state plus counts by category, vertical, risk level
    and site, and the alert, vulnerability, site and subnet totals.
  * ``devices`` - the v2 device inventory with a compact field set, optional
    site/sort parameters and client-side filters.
  * ``device`` - one device or multi-interface device, by ``ip`` or ``mac``.
  * ``alerts`` / ``vulnerabilities`` - active (or resolved) alerts and
    vulnerability instances.
  * ``policy_recommendations`` - activated policy rule recommendations.
  * ``sites`` / ``subnets`` / ``tags`` / ``profile_mapping`` - supporting lists.

API behaviour found on live tenants (2026-11):

  * An unlicensed tenant answers 404 ``IoT tenant with TSG id ... is not
    found``.  That is reported as ``licensed: false``, not as an error.
  * ``v1/device/list`` returns the page size as ``total``; only
    ``v2/device/list`` carries the real total, so devices use v2.
  * ``policy/recommendation`` and ``profile/mapping`` need ``customerid`` set
    to the TSG ID, and ``tag/list`` needs ``source``; omitting them is a 400
    (``tenantid: undefined`` for policy recommendations).
  * Limits are 60 requests a minute (180 for ``profile/mapping``); a 429 is
    reported as such.

The shapes of alert, vulnerability and policy items are passed through as
returned: no lab tenant has any, so they have not been seen.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..utils import scm_rest
from ..utils.formatting import format_result as _fmt
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool

logger = get_logger(__name__)

_BASE = "https://api.strata.paloaltonetworks.com/iot/pub"
_PAGE = 1000  # the API's maximum page length
_SCAN_CAP = 2000  # devices read for a summary or a client-side filter
_MAX_LIMIT = 1000

ACTIONS = (
    "summary",
    "devices",
    "device",
    "alerts",
    "vulnerabilities",
    "policy_recommendations",
    "sites",
    "subnets",
    "tags",
    "profile_mapping",
)

# Response keys kept per device when ``fields`` is not given.  These are
# response keys, not projection names: the API rejects ``ml_risk_level`` and
# ``site_name`` as projection fields although every device carries them.
DEVICE_FIELDS = (
    "name",
    "ip",
    "MAC",
    "category",
    "profile",
    "profile_type",
    "profile_vertical",
    "ml_risk_level",
    "ml_risk_score",
    "site_name",
    "zone",
    "firstseen",
    "latest_device_time",
    "id",
)


class IotError(Exception):
    """An IoT API call failed in a way the caller should see."""


def _iot_get(client: Any, path: str, params: dict[str, Any] | None = None) -> Any:
    """GET one IoT endpoint and return the parsed body.

    Raises :class:`IotError` on a transport failure or a non-2xx status.  The
    unlicensed 404 raises :class:`NotLicensed` so callers can report it.
    """
    scm_rest.refresh_token(client)
    session = scm_rest.bearer_session(client)
    res = scm_rest.request(session, "GET", f"{_BASE}{path}", params=params, timeout=(10, 40))
    if res.status == -1:
        raise IotError(f"request failed: {res.error}")
    if res.ok:
        return res.data if res.data is not None else {}
    detail = ""
    if isinstance(res.data, dict):
        detail = str(res.data.get("message") or res.data.get("error") or res.data)[:300]
    else:
        detail = res.text
    if res.status == 404 and "not found" in detail.lower() and "iot tenant" in detail.lower():
        raise NotLicensed(detail)
    if res.status == 429:
        raise IotError("rate limited (60 requests a minute); retry shortly")
    if res.status in (401, 403):
        raise IotError(
            f"HTTP {res.status}: access denied for this endpoint or role. {detail}".strip()
        )
    raise IotError(f"HTTP {res.status}: {detail}".strip())


class NotLicensed(IotError):
    """The tenant has no IoT Security licence."""


def _tsg(client: Any, tenant_id: str) -> str:
    """The TSG ID the API wants as ``customerid``."""
    auth = getattr(getattr(client, "oauth_client", None), "auth_request", None)
    tsg = getattr(auth, "tsg_id", None)
    return str(tsg or tenant_id or "")


def _clamp(limit: int) -> int:
    return max(1, min(int(limit), _MAX_LIMIT))


def _items(body: Any, *keys: str) -> list[Any]:
    """The first list found under ``keys`` in an object body, or a bare list."""
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for key in keys:
            if isinstance(body.get(key), list):
                return body[key]
    return []


def _fields(fields: str) -> tuple[str, tuple[str, ...] | None]:
    """``(projection, keep)`` for a ``fields`` value.

    Empty: no projection, keep the compact key set.  ``all``: no projection,
    keep everything.  A list: sent as the API ``projection`` (valid names come
    from ``device/attributes``), nothing trimmed.
    """
    value = fields.strip()
    if not value:
        return "", DEVICE_FIELDS
    if value.lower() == "all":
        return "", None
    names = [f.strip() for f in value.split(",") if f.strip()]
    if len(names) > 50:
        raise IotError("fields: the API accepts at most 50 field names")
    return ",".join(names), None


def _trim(devices: list[Any], keep: tuple[str, ...] | None) -> list[Any]:
    if keep is None:
        return devices
    return [{k: d[k] for k in keep if k in d} if isinstance(d, dict) else d for d in devices]


def _first(value: Any) -> Any:
    return value[0] if isinstance(value, list) and value else value


def _matches(device: dict[str, Any], filters: dict[str, str]) -> bool:
    for key, wanted in filters.items():
        if not wanted:
            continue
        w = wanted.lower()
        if key == "text":
            hay = " ".join(
                str(_first(device.get(f)) or "")
                for f in ("name", "ip", "MAC", "profile", "ouiVendor")
            ).lower()
            if w not in hay:
                return False
        elif w not in str(device.get(key) or "").lower():
            return False
    return True


def _scan_devices(
    client: Any, params: dict[str, Any], cap: int
) -> tuple[list[dict[str, Any]], int | None, bool]:
    """Read up to ``cap`` devices page by page; ``(rows, total, truncated)``."""
    rows: list[dict[str, Any]] = []
    total: int | None = None
    while len(rows) < cap:
        body = _iot_get(
            client, "/v2/device/list", {**params, "pagelength": _PAGE, "offset": len(rows)}
        )
        page = [d for d in _items(body, "devices") if isinstance(d, dict)]
        if isinstance(body, dict) and isinstance(body.get("total"), int):
            total = body["total"]
        rows.extend(page)
        if len(page) < _PAGE or (total is not None and len(rows) >= total):
            break
    truncated = total is not None and len(rows) < total
    return rows[:cap], total, truncated


def _action_devices(
    client: Any,
    *,
    limit: int,
    offset: int,
    fields: str,
    site: str,
    sort_field: str,
    sort_direction: str,
    category: str,
    profile: str,
    risk_level: str,
    text: str,
) -> dict[str, Any]:
    params: dict[str, Any] = {}
    projection, keep = _fields(fields)
    if projection:
        params["projection"] = projection
    if site:
        params["site_names"] = site
    if sort_field:
        params["sortfield"] = sort_field
        params["sortdirection"] = sort_direction or "desc"
    filters = {
        "category": category,
        "profile": profile,
        "ml_risk_level": risk_level,
        "text": text,
    }
    limit = _clamp(limit)
    if not any(filters.values()):
        body = _iot_get(
            client, "/v2/device/list", {**params, "pagelength": limit, "offset": offset}
        )
        devices = _items(body, "devices")
        total = body.get("total") if isinstance(body, dict) else None
        return {
            "licensed": True,
            "total": total,
            "returned": len(devices),
            "offset": offset,
            "has_more": bool(body.get("has_more")) if isinstance(body, dict) else False,
            "devices": _trim(devices, keep),
        }
    scanned, total, truncated = _scan_devices(client, params, _SCAN_CAP)
    hits = [d for d in scanned if _matches(d, filters)]
    page = hits[offset : offset + limit]
    out: dict[str, Any] = {
        "licensed": True,
        "total": total,
        "scanned": len(scanned),
        "matched": len(hits),
        "returned": len(page),
        "offset": offset,
        "devices": _trim(page, keep),
    }
    if truncated:
        out["warning"] = (
            f"only the first {len(scanned)} of {total} devices were scanned for the filters; "
            "narrow with site or sort to reach the rest"
        )
    return out


def _count(rows: list[dict[str, Any]], field: str) -> dict[str, int]:
    counter = Counter(str(_first(r.get(field)) or "unknown") for r in rows)
    return dict(counter.most_common())


def _action_summary(client: Any, tenant_id: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    errors: dict[str, str] = {}
    rows, total, truncated = _scan_devices(client, {}, _SCAN_CAP)
    out["licensed"] = True
    out["devices"] = {
        "total": total if total is not None else len(rows),
        "scanned": len(rows),
        "by_category": _count(rows, "category"),
        "by_vertical": _count(rows, "profile_vertical"),
        "by_profile_type": _count(rows, "profile_type"),
        "by_risk_level": _count(rows, "ml_risk_level"),
        "by_site": _count(rows, "site_name"),
    }
    if truncated:
        out["devices"]["warning"] = f"counts cover the first {len(rows)} of {total} devices"

    def probe(name: str, path: str, params: dict[str, Any], pick: Any) -> None:
        try:
            out[name] = pick(_iot_get(client, path, params))
        except IotError as exc:
            errors[name] = str(exc)

    probe("alerts_active", "/v1/alert/list", {"pagelength": 1}, lambda b: b.get("total", 0))
    probe(
        "vulnerabilities",
        "/v1/vulnerability/list",
        {"groupby": "vulnerability", "pagelength": 1},
        lambda b: {"total": b.get("total", 0), "instances": b.get("totalInstances", 0)},
    )
    probe("sites", "/v1/site", {}, lambda b: len(_items(b, "list")))
    probe("subnets", "/v1/subnet", {}, lambda b: b.get("total", len(_items(b, "subnets"))))
    if errors:
        out["errors"] = errors
    return out


def run(
    client: Any,
    tenant_id: str,
    action: str,
    *,
    ip: str = "",
    mac: str = "",
    fields: str = "",
    site: str = "",
    sort_field: str = "",
    sort_direction: str = "",
    category: str = "",
    profile: str = "",
    risk_level: str = "",
    text: str = "",
    resolved: str = "no",
    severity: str = "",
    status: str = "",
    name: str = "",
    group_by: str = "vulnerability",
    include_device_ids: bool = False,
    stime: str = "",
    tag_source: str = "tenant",
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """Dispatch one action; raises :class:`IotError` / :class:`NotLicensed`."""
    limit = _clamp(limit)
    offset = max(0, int(offset))
    if action == "summary":
        return _action_summary(client, tenant_id)
    if action == "devices":
        return _action_devices(
            client,
            limit=limit,
            offset=offset,
            fields=fields,
            site=site,
            sort_field=sort_field,
            sort_direction=sort_direction,
            category=category,
            profile=profile,
            risk_level=risk_level,
            text=text,
        )
    if action == "device":
        if bool(ip) == bool(mac):
            raise IotError("device: give exactly one of ip or mac")
        params: dict[str, Any] = {"deviceAlertSummary": "yes"}
        params["ip" if ip else "mac"] = ip or mac
        projection, _ = _fields(fields)
        if projection:
            params["projection"] = projection
        return {"licensed": True, **_iot_get(client, "/v2/device/search", params)}
    if action == "alerts":
        params = {"pagelength": limit, "offset": offset, "resolved": resolved or "no"}
        if stime:
            params["stime"] = stime
        body = _iot_get(client, "/v1/alert/list", params)
        items = _items(body, "items")
        return {
            "licensed": True,
            "total": body.get("total") if isinstance(body, dict) else None,
            "returned": len(items),
            "alerts": items,
        }
    if action == "vulnerabilities":
        if group_by not in ("vulnerability", "device"):
            raise IotError("group_by must be 'vulnerability' or 'device'")
        params = {"groupby": group_by, "pagelength": limit, "offset": offset}
        for key, value in (
            ("severity", severity),
            ("status", status),
            ("name", name),
            ("stime", stime),
        ):
            if value:
                params[key] = value
        if include_device_ids:
            params["includeDeviceIdList"] = "yes"
        body = _iot_get(client, "/v1/vulnerability/list", params)
        return {"licensed": True, **(body if isinstance(body, dict) else {"items": body})}
    if action == "policy_recommendations":
        params = {"customerid": _tsg(client, tenant_id), "pagelength": limit, "offset": offset}
        if profile:
            params["profile"] = profile
        body = _iot_get(client, "/v1/policy/recommendation", params)
        policies = _items(body, "policies")
        return {
            "licensed": True,
            "total": body.get("total") if isinstance(body, dict) else None,
            "policies": policies,
        }
    if action == "sites":
        sites = _items(_iot_get(client, "/v1/site"), "list")
        return {"licensed": True, "total": len(sites), "sites": sites[offset : offset + limit]}
    if action == "subnets":
        body = _iot_get(client, "/v1/subnet")
        subnets = _items(body, "subnets")
        return {
            "licensed": True,
            "total": len(subnets),
            "subnets": subnets[offset : offset + limit],
        }
    if action == "tags":
        if tag_source not in ("tenant", "predefined"):
            raise IotError("tag_source must be 'tenant' or 'predefined'")
        body = _iot_get(client, "/v1/tag/list", {"source": tag_source})
        return {"licensed": True, "source": tag_source, **(body if isinstance(body, dict) else {})}
    if action == "profile_mapping":
        body = _iot_get(client, "/v1/profile/mapping", {"customerid": _tsg(client, tenant_id)})
        rows = [r for r in _items(body, "mapping") if isinstance(r, dict)]
        needle = (name or profile).lower()
        if needle:
            rows = [r for r in rows if needle in str(r.get("profile", "")).lower()]
        if category:
            rows = [r for r in rows if category.lower() in str(r.get("category", "")).lower()]
        return {
            "licensed": True,
            "matched": len(rows),
            "mapping": rows[offset : offset + limit],
        }
    raise IotError(f"unknown action {action!r}; use one of {', '.join(ACTIONS)}")


def register_iot_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register the IoT Security tool."""
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_iot(
        client: Any,
        tenant_id: str,
        action: str = "summary",
        ip: str = "",
        mac: str = "",
        fields: str = "",
        site: str = "",
        sort_field: str = "",
        sort_direction: str = "",
        category: str = "",
        profile: str = "",
        risk_level: str = "",
        text: str = "",
        resolved: str = "no",
        severity: str = "",
        status: str = "",
        name: str = "",
        group_by: str = "vulnerability",
        include_device_ids: bool = False,
        stime: str = "",
        tag_source: str = "tenant",
        limit: int = 100,
        offset: int = 0,
    ) -> str:
        """Read Enterprise IoT / Device Security data (read-only).

        An unlicensed tenant returns ``licensed: false``. Limit: 60 requests a
        minute, and ``summary`` makes several.

        Actions:
          * ``summary`` - device counts by category, vertical, risk and site, plus alert, vulnerability, site and subnet totals.
          * ``devices`` - inventory. ``fields`` is empty for a compact key set,
            ``all`` for every key, or a comma-separated API projection (max 50
            names from the device attributes list; some response keys such as
            ``ml_risk_level`` are not valid projection names);
            ``site``, ``sort_field`` and ``sort_direction`` go to the API;
            ``category``, ``profile``, ``risk_level`` and ``text`` (name, IP,
            MAC, profile, vendor) filter client-side over the first 2000
            devices and say when that truncates.
          * ``device`` - one device by ``ip`` or ``mac``, with alert summary.
          * ``alerts`` - active alerts (``resolved=yes`` for resolved);
            ``stime`` sets the start of the time range.
          * ``vulnerabilities`` - ``group_by`` is ``vulnerability`` or
            ``device``; filters ``severity``, ``status``, ``name``;
            ``include_device_ids`` adds the affected device IDs.
          * ``policy_recommendations`` - activated rule recommendations,
            optionally for one ``profile``.
          * ``sites``, ``subnets`` - supporting lists.
          * ``tags`` - ``tag_source`` is ``tenant`` or ``predefined``.
          * ``profile_mapping`` - device profile to category and vertical;
            ``name`` or ``profile`` filters by profile, ``category`` by category.

        Args:
            tenant_id: SCM tenant ID.
            action: One of the actions above.
            limit: Maximum items returned (1-1000).
            offset: Items to skip.
        """
        try:
            return _fmt(
                run(
                    client,
                    tenant_id,
                    action,
                    ip=ip,
                    mac=mac,
                    fields=fields,
                    site=site,
                    sort_field=sort_field,
                    sort_direction=sort_direction,
                    category=category,
                    profile=profile,
                    risk_level=risk_level,
                    text=text,
                    resolved=resolved,
                    severity=severity,
                    status=status,
                    name=name,
                    group_by=group_by,
                    include_device_ids=include_device_ids,
                    stime=stime,
                    tag_source=tag_source,
                    limit=limit,
                    offset=offset,
                )
            )
        except NotLicensed as exc:
            return _fmt({"licensed": False, "detail": str(exc)})
        except IotError as exc:
            return _fmt({"error": str(exc)})
