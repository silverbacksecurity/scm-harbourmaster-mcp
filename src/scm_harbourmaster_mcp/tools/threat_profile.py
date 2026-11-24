"""MCP tool for anti-spyware and vulnerability-protection profiles.

``scm_threat_profile`` lists, reads and (dry-run first) writes profiles at
``config/security/v1/anti-spyware-profiles`` and
``config/security/v1/vulnerability-protection-profiles``.

Everything goes over raw REST (``client.get/post``, ``scm_rest.put_object``),
never through pan-scm-sdk models, because pan-scm-sdk 0.15.1:

* cannot parse a profile that carries a threat exception with an ``action``;
* drops or mis-names aliased fields.  The API's vulnerability-rule field is
  ``vendor_id`` (the SDK alias ``vendor-id`` is rejected with "missing
  'vendor-id'").

Live-proven API behaviour this tool is built around (SSR work, 2026-11-13):

* a vulnerability-profile PUT without ``folder`` returns 200 and changes
  nothing, so the container stays in the PUT body and every update is read
  back;
* an empty ``threat_exception`` list is rejected, so a cleared list is sent by
  omitting the field (the read-back reports whether SCM really cleared it);
* an anti-spyware exception PUT only accepts exception IDs already seen in a
  created profile (create accepts any ID).

Field names and enums were checked against the pan.dev SCM security-services
OpenAPI spec and the pan-scm-sdk 0.15.1 models.  Nothing here is live-verified.

**Write safety (SSR pattern):** ``dry_run=True`` by default, ``ticket_ref``
mandatory for writes (dry runs included), logged and never sent in a body.
Commit is a separate ``scm_commit`` step.
"""

from __future__ import annotations

import json
import re
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..audit import clone_preflight
from ..utils import scm_rest
from ..utils.formatting import format_result as _fmt
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool
from ..utils.write_safety import (
    DRY_RUN_HINT,
    audit_write,
    normalize_ticket_ref,
    ticket_ref_error,
)
from .file_blocking import COMMIT_HINT, _items, _scope

logger = get_logger(__name__)

# Containers whose objects are inherited by many folders/snippets/devices.
INHERITED_TOP_FOLDERS = frozenset({"All", "Shared", "Prisma Access", "Global"})
# Common child containers scanned in addition for a top-level folder.
CHILD_FOLDERS = ("Mobile Users", "Remote Networks")


def api_folder(folder: str) -> str:
    """Folder name as the config API accepts it in a query (reuses the clone alias map)."""
    return clone_preflight._API_FOLDER_ALIASES.get(folder, folder)


def is_inherited_scope(scope: dict[str, str]) -> bool:
    """True for a top-level folder or a snippet (inherited by containers we cannot enumerate)."""
    return scope.get("folder") in INHERITED_TOP_FOLDERS or "snippet" in scope


def scan_scopes(scope: dict[str, str]) -> list[tuple[str, dict[str, str]]]:
    """(label, API query scope) pairs a reference scan covers.

    The profile's own container comes first (folder alias applied); a
    top-level folder adds the common child folders.
    """
    own = dict(scope)
    if "folder" in own:
        own["folder"] = api_folder(own["folder"])
    out = [("", own)]
    if scope.get("folder") in INHERITED_TOP_FOLDERS:
        out.extend((child, {"folder": child}) for child in CHILD_FOLDERS)
    return out


def unscanned_scope_notice(scope: dict[str, str]) -> str:
    """Why the scan is incomplete for an inherited container ('' when it is not)."""
    if not is_inherited_scope(scope):
        return ""
    kind, value = next(iter(scope.items()))
    children = (
        f"; also scanned child folders {list(CHILD_FOLDERS)}"
        if scope.get("folder") in INHERITED_TOP_FOLDERS
        else ""
    )
    return (
        f"profile is in the inherited {kind} {value!r}{children}; custom folders, other "
        "snippets and devices that inherit it cannot be enumerated, so the reference "
        "scan is incomplete"
    )


def scope_refusal(scope: dict[str, str], acknowledge: bool) -> str:
    """Refusal reason for a real delete in an inherited container ('' = allowed)."""
    notice = unscanned_scope_notice(scope)
    if notice and not acknowledge:
        return f"{notice}; pass acknowledge_unscanned_scope=True to delete anyway"
    return ""


def is_blank(value: Any) -> bool:
    """None, '' and a missing key all mean 'not set'."""
    return value is None or value == ""


def pair_named(first: list[Any], second: list[Any]) -> list[tuple[Any, Any]] | None:
    """Pair two lists of named dicts by name (order-insensitive).

    None when the lists are not all uniquely named dicts or the name sets differ.
    """
    if not first and not second:
        return []
    for items in (first, second):
        if not all(isinstance(i, dict) and isinstance(i.get("name"), str) for i in items):
            return None
    a = {i["name"]: i for i in first}
    b = {i["name"]: i for i in second}
    if len(a) != len(first) or len(b) != len(second) or set(a) != set(b):
        return None
    return [(a[n], b[n]) for n in a]


_GROUPS_URL = f"{scm_rest.SSE_CONFIG_V1}/profile-groups"
_PAGE = 200
_SCOPE_KEYS = ("folder", "snippet", "device")
_ACTIONS = ("list", "get", "create", "update", "delete")

# kind -> REST base path, SDK attribute (for the ENDPOINT used by put_object),
# the field a profile group uses to reference it, and the name pattern.
_KINDS: dict[str, dict[str, Any]] = {
    "anti_spyware": {
        "label": "anti-spyware",
        "base": "/config/security/v1/anti-spyware-profiles",
        "sdk_attr": "anti_spyware_profile",
        "group_field": "spyware",
        "name_re": re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-. ]*$"),
    },
    "vulnerability": {
        "label": "vulnerability-protection",
        "base": "/config/security/v1/vulnerability-protection-profiles",
        "sdk_attr": "vulnerability_protection_profile",
        "group_field": "vulnerability",
        "name_re": re.compile(r"^[a-zA-Z0-9._-]+$"),
    },
}

# Action keys (spec: oneOf, exactly one).  Anti-spyware RULES have no "default".
_ACTION_KEYS_RULE = {
    "anti_spyware": (
        "allow",
        "alert",
        "drop",
        "reset_client",
        "reset_server",
        "reset_both",
        "block_ip",
    ),
    "vulnerability": (
        "default",
        "allow",
        "alert",
        "drop",
        "reset_client",
        "reset_server",
        "reset_both",
        "block_ip",
    ),
}
_ACTION_KEYS_EXCEPTION = _ACTION_KEYS_RULE["vulnerability"]  # spec: default + the rest, both kinds
_TRACK_BY_BLOCK = ("source-and-destination", "source")
_TRACK_BY_TIME = ("source", "destination", "source-and-destination")
_PACKET_CAPTURE = ("disable", "single-packet", "extended-capture")
_SEVERITY = ("critical", "high", "medium", "low", "informational", "any")
_HOSTS = ("any", "client", "server")

_CATEGORIES = {
    "anti_spyware": frozenset(
        [
            "adns-adtracking",
            "adns-benign",
            "adns-c2",
            "adns-ddns",
            "adns-dnsmisconfig",
            "adns-grayware",
            "adns-hijacking",
            "adns-malware",
            "adns-new-domain",
            "adns-parked",
            "adns-phishing",
            "adns-proxy",
            "adware",
            "any",
            "autogen",
            "backdoor",
            "botnet",
            "browser-hijack",
            "command-and-control",
            "cryptominer",
            "data-theft",
            "dns",
            "dns-adtracking",
            "dns-benign",
            "dns-c2",
            "dns-ddns",
            "dns-grayware",
            "dns-malware",
            "dns-new-domain",
            "dns-parked",
            "dns-phishing",
            "dns-proxy",
            "dns-security",
            "dns-wildfire",
            "domain-edl",
            "downloader",
            "fraud",
            "hacktool",
            "inline-cloud-c2",
            "keylogger",
            "net-worm",
            "p2p-communication",
            "phishing-kit",
            "post-exploitation",
            "spyware",
            "tls-fingerprint",
            "webshell",
        ]
    ),
    "vulnerability": frozenset(
        [
            "any",
            "app-id-change",
            "brute-force",
            "code-execution",
            "code-obfuscation",
            "command-execution",
            "dos",
            "exploit-kit",
            "info-leak",
            "inline-cloud-exploit",
            "insecure-credentials",
            "overflow",
            "phishing",
            "protocol-anomaly",
            "scan",
            "sql-injection",
        ]
    ),
}

_RULE_KEYS = {
    "anti_spyware": frozenset(
        {"name", "action", "packet_capture", "severity", "category", "threat_name"}
    ),
    "vulnerability": frozenset(
        {
            "name",
            "action",
            "packet_capture",
            "severity",
            "category",
            "threat_name",
            "cve",
            "host",
            "vendor_id",
        }
    ),
}
_EXC_KEYS = {
    "anti_spyware": frozenset({"name", "action", "packet_capture", "exempt_ip", "notes"}),
    # SCM silently drops ``notes`` on vulnerability exceptions (live 2026-11-20).
    "vulnerability": frozenset({"name", "action", "packet_capture", "exempt_ip", "time_attribute"}),
}


# ---------------------------------------------------------------------------
# Pre-validation
# ---------------------------------------------------------------------------


def _norm_action(value: Any, allowed: tuple[str, ...], label: str) -> tuple[Any, str]:
    """Return (action dict, error).  Accepts ``{"alert": {}}`` or a bare ``"reset-both"``."""
    if isinstance(value, str):
        value = {value.strip().replace("-", "_"): {}}
    if not isinstance(value, dict) or len(value) != 1:
        return None, f"{label}: action must name exactly one of {list(allowed)}"
    key, params = next(iter(value.items()))
    if key not in allowed:
        return None, f"{label}: action {key!r} not one of {list(allowed)}"
    if key == "block_ip":
        params = params or {}
        if not isinstance(params, dict) or set(params) - {"track_by", "duration"}:
            return None, f"{label}: block_ip takes only track_by and duration"
        if "track_by" in params and params["track_by"] not in _TRACK_BY_BLOCK:
            return None, f"{label}: block_ip.track_by not one of {list(_TRACK_BY_BLOCK)}"
        if "duration" in params and (
            not isinstance(params["duration"], int)
            or isinstance(params["duration"], bool)
            or not 1 <= params["duration"] <= 3600
        ):
            return None, f"{label}: block_ip.duration must be an integer 1-3600"
        return {key: dict(params)}, ""
    if params not in ({}, None):
        return None, f"{label}: action {key!r} takes no parameters"
    return {key: {}}, ""


def _str_list(value: Any, label: str, field: str) -> tuple[list[str], str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not value or not all(isinstance(v, str) and v for v in value):
        return [], f"{label}: {field} must be a non-empty list of strings"
    return list(value), ""


def _parse_list(raw: str, what: str) -> tuple[list[Any], str]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return [], f"{what} is not valid JSON: {exc}"
    if not isinstance(data, list) or not all(isinstance(d, dict) for d in data):
        return [], f"{what} must be a JSON list of objects"
    return data, ""


def parse_rules(kind: str, raw: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Validate ``rules_json`` for *kind*; returns (rules with API field names, errors)."""
    data, err = _parse_list(raw, "rules_json")
    if err:
        return [], [err]
    errors: list[str] = []
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    allowed_keys = _RULE_KEYS[kind]
    for i, rule in enumerate(data):
        label = f"rule {i + 1} ({rule.get('name')!r})"
        if "vendor-id" in rule:
            errors.append(f"{label}: the API field is 'vendor_id', not 'vendor-id'")
            continue
        extra = set(rule) - allowed_keys
        if extra:
            errors.append(
                f"{label}: unknown field(s) {sorted(extra)}; allowed {sorted(allowed_keys)}"
            )
            continue
        name = rule.get("name")
        if not isinstance(name, str) or not name:
            errors.append(f"{label}: name is required")
            continue
        if name in seen:
            errors.append(f"{label}: duplicate rule name")
            continue
        seen.add(name)
        new: dict[str, Any] = {"name": name}
        sev, serr = _str_list(rule.get("severity"), label, "severity")
        if serr:
            errors.append(serr)
        elif set(sev) - set(_SEVERITY):
            errors.append(f"{label}: severity values must be from {list(_SEVERITY)}")
        else:
            new["severity"] = sev
        cat = rule.get("category", "any")
        if cat not in _CATEGORIES[kind]:
            errors.append(f"{label}: category {cat!r} is not valid for {kind} profiles")
        else:
            new["category"] = cat
        threat = rule.get("threat_name", "any")
        if not isinstance(threat, str) or (kind == "anti_spyware" and len(threat) < 3):
            errors.append(f"{label}: threat_name must be a string (anti-spyware: min 3 characters)")
        else:
            new["threat_name"] = threat
        if "packet_capture" in rule or kind == "vulnerability":
            pc = rule.get("packet_capture", "disable")
            if pc not in _PACKET_CAPTURE:
                errors.append(f"{label}: packet_capture not one of {list(_PACKET_CAPTURE)}")
            else:
                new["packet_capture"] = pc
        if "action" in rule:
            act, aerr = _norm_action(rule["action"], _ACTION_KEYS_RULE[kind], label)
            if aerr:
                errors.append(aerr)
            else:
                new["action"] = act
        if kind == "vulnerability":
            host = rule.get("host", "any")
            if host not in _HOSTS:
                errors.append(f"{label}: host not one of {list(_HOSTS)}")
            else:
                new["host"] = host
            for field in ("cve", "vendor_id"):
                vals, verr = _str_list(rule.get(field, ["any"]), label, field)
                if verr:
                    errors.append(verr)
                else:
                    new[field] = vals
        out.append(new)
    return ([] if errors else out), errors


def parse_exceptions(kind: str, raw: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Validate ``threat_exceptions_json`` for *kind*."""
    data, err = _parse_list(raw, "threat_exceptions_json")
    if err:
        return [], [err]
    errors: list[str] = []
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    allowed_keys = _EXC_KEYS[kind]
    for i, exc in enumerate(data):
        label = f"threat exception {i + 1} ({exc.get('name')!r})"
        extra = set(exc) - allowed_keys
        if kind == "vulnerability" and "notes" in extra:
            errors.append(
                f"{label}: notes is not supported for vulnerability exceptions "
                "(SCM silently discards it); remove it"
            )
            continue
        if extra:
            errors.append(
                f"{label}: unknown field(s) {sorted(extra)}; allowed {sorted(allowed_keys)}"
            )
            continue
        name = exc.get("name")
        if isinstance(name, int) and not isinstance(name, bool):
            name = str(name)
        if not isinstance(name, str) or not name:
            errors.append(f"{label}: name (the threat ID) is required")
            continue
        if name in seen:
            errors.append(f"{label}: duplicate threat ID")
            continue
        seen.add(name)
        new: dict[str, Any] = {"name": name}
        pc = exc.get("packet_capture", "disable" if kind == "anti_spyware" else None)
        if pc is not None:
            if pc not in _PACKET_CAPTURE:
                errors.append(f"{label}: packet_capture not one of {list(_PACKET_CAPTURE)}")
            else:
                new["packet_capture"] = pc
        if "action" in exc:
            act, aerr = _norm_action(exc["action"], _ACTION_KEYS_EXCEPTION, label)
            if aerr:
                errors.append(aerr)
            else:
                new["action"] = act
        if "exempt_ip" in exc:
            ips = exc["exempt_ip"]
            if not isinstance(ips, list) or not ips:
                errors.append(f"{label}: exempt_ip must be a non-empty list")
            else:
                new["exempt_ip"] = [{"name": i} if isinstance(i, str) else i for i in ips]
                if not all(
                    isinstance(i, dict) and isinstance(i.get("name"), str) for i in new["exempt_ip"]
                ):
                    errors.append(f"{label}: exempt_ip entries must be strings or {{'name': ip}}")
        if "notes" in exc:
            if not isinstance(exc["notes"], str):
                errors.append(f"{label}: notes must be a string")
            else:
                new["notes"] = exc["notes"]
        if "time_attribute" in exc:
            ta = exc["time_attribute"]
            problem = ""
            if not isinstance(ta, dict) or set(ta) - {"interval", "threshold", "track_by"}:
                problem = "time_attribute takes interval, threshold and track_by"
            elif "interval" in ta and not (
                isinstance(ta["interval"], int)
                and not isinstance(ta["interval"], bool)
                and 1 <= ta["interval"] <= 3600
            ):
                problem = "time_attribute.interval must be an integer 1-3600"
            elif "threshold" in ta and not (
                isinstance(ta["threshold"], int)
                and not isinstance(ta["threshold"], bool)
                and 1 <= ta["threshold"] <= 65535
            ):
                problem = "time_attribute.threshold must be an integer 1-65535"
            elif "track_by" in ta and ta["track_by"] not in _TRACK_BY_TIME:
                problem = f"time_attribute.track_by not one of {list(_TRACK_BY_TIME)}"
            if problem:
                errors.append(f"{label}: {problem}")
            else:
                new["time_attribute"] = dict(ta)
        out.append(new)
    return ([] if errors else out), errors


# ---------------------------------------------------------------------------
# REST helpers (raw dicts; the SDK is not involved)
# ---------------------------------------------------------------------------


def _is_missing(exc: Exception) -> bool:
    return scm_rest.exc_status(exc) == 404 or type(exc).__name__ == "ObjectNotPresentError"


def _fetch(client: Any, base: str, name: str, scope: dict[str, str]) -> dict[str, Any] | None:
    try:
        body = client.get(base, params={"name": name, **scope})
    except Exception as exc:
        if _is_missing(exc):
            return None
        raise
    for item in _items(body):
        if item.get("id") and item.get("name") == name:
            return item
    return None


def _fetch_by_id(client: Any, base: str, profile_id: str) -> dict[str, Any] | None:
    try:
        body = client.get(f"{base}/{profile_id}")
    except Exception as exc:
        if _is_missing(exc):
            return None
        raise
    items = _items(body)
    return items[0] if items and items[0].get("id") else None


def _list_all(client: Any, base: str, scope: dict[str, str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    while True:
        body = client.get(base, params={**scope, "limit": str(_PAGE), "offset": str(len(rows))})
        if isinstance(body, list):
            return [r for r in body if isinstance(r, dict)]
        page = [r for r in (body or {}).get("data", []) if isinstance(r, dict)]
        rows.extend(page)
        total = (body or {}).get("total")
        if len(page) < _PAGE or (isinstance(total, int) and len(rows) >= total):
            return rows


def _reference_check(
    client: Any, kind: str, name: str, scope: dict[str, str]
) -> tuple[dict[str, Any], str]:
    """Profile groups that list *name*: the profile's own container (folder alias
    applied) plus Mobile Users and Remote Networks for a top-level folder.

    Returns (report, lookup_error).  The report states what was and was not
    scanned; a delete is refused when the lookup failed (fail closed).
    """
    field = _KINDS[kind]["group_field"]
    targets = scan_scopes(scope)
    scanned = [
        f"profile groups in {next(iter(q), 'folder')} {next(iter(q.values()), '')!r} "
        f"(field {field!r})"
        for _label, q in targets
    ]
    report: dict[str, Any] = {
        "scanned": "; ".join(scanned),
        "not_scanned": [
            "profile groups in other folders, snippets or devices that inherit this profile",
            "security rules (the SDK model attaches profiles to rules via profile groups only)",
            "any object outside SCM (for example a Panorama or NGFW local config)",
        ],
        "referenced_by": [],
    }
    try:
        scm_rest.refresh_token(client)
        session = scm_rest.bearer_session(client)
        names: list[str] = []
        for label, query in targets:
            offset = 0
            while True:
                resp = session.get(
                    _GROUPS_URL,
                    params={**query, "limit": _PAGE, "offset": offset},
                    timeout=clone_preflight._TIMEOUT,
                )
                if resp.status_code != 200:
                    return report, f"profile-group lookup failed: HTTP {resp.status_code}"
                raw = _items(resp.json())
                for row in raw:
                    if not row.get("name"):
                        continue
                    value = row.get(field)
                    listed = [value] if isinstance(value, str) else (value or [])
                    if name in listed:
                        names.append(f"{row['name']} (in {label})" if label else str(row["name"]))
                # page on the raw length: nameless rows must not end paging early
                if len(raw) < _PAGE:
                    break
                offset += _PAGE
        report["referenced_by"] = sorted(set(names))
        notice = unscanned_scope_notice(scope)
        if notice:
            report["unscanned_scope_warning"] = notice
        return report, ""
    except Exception as exc:
        return report, f"profile-group lookup failed: {str(exc)[:200]}"


def _canon(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def _covers(want: Any, got: Any) -> bool:
    """True when every value in *want* is present in *got* (extra server fields allowed).

    Lists of named dicts compare by name (order-insensitive); ''/None/missing are equal.
    """
    if isinstance(want, dict):
        return isinstance(got, dict) and all(
            is_blank(got.get(k)) if is_blank(v) else (k in got and _covers(v, got[k]))
            for k, v in want.items()
        )
    if isinstance(want, list):
        if not isinstance(got, list) or len(want) != len(got):
            return False
        pairs = pair_named(want, got)
        if pairs is not None:
            return all(_covers(w, g) for w, g in pairs)
        if all(not isinstance(w, dict | list) for w in want):
            return sorted(map(str, want)) == sorted(map(str, got))
        return all(_covers(w, g) for w, g in zip(want, got, strict=True))
    return want == got or (is_blank(want) and is_blank(got))


def _diff(before: list[dict[str, Any]], after: list[dict[str, Any]]) -> dict[str, list[str]]:
    old = {str(r.get("name")): _canon(r) for r in before}
    new = {str(r.get("name")): _canon(r) for r in after}
    return {
        "added": sorted(set(new) - set(old)),
        "removed": sorted(set(old) - set(new)),
        "changed": sorted(n for n in set(old) & set(new) if old[n] != new[n]),
    }


def _verify(stored: dict[str, Any] | None, body: dict[str, Any]) -> bool:
    """Does the stored profile reflect everything sent in *body*?"""
    if stored is None:
        return False
    if not _covers({k: v for k, v in body.items() if k != "threat_exception"}, stored):
        return False
    want_exc = body.get("threat_exception") or []
    got_exc = stored.get("threat_exception") or []
    return _covers(want_exc, got_exc) if want_exc else not got_exc


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_threat_profile_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register the anti-spyware / vulnerability-protection profile tool."""
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_threat_profile(
        client: Any,
        tenant_id: str,
        kind: str = "anti_spyware",
        action: str = "list",
        folder: str = "",
        snippet: str = "",
        device: str = "",
        name: str = "",
        profile_id: str = "",
        description: str | None = None,
        rules_json: str = "",
        threat_exceptions_json: str = "",
        dry_run: bool = True,
        ticket_ref: str = "",
        limit: int = 200,
        acknowledge_unscanned_scope: bool = False,
    ) -> str:
        """List and manage anti-spyware and vulnerability-protection profiles.

        ``kind`` is ``anti_spyware`` (config/security/v1/anti-spyware-profiles)
        or ``vulnerability`` (config/security/v1/vulnerability-protection-profiles).

        Actions:
          * ``list`` - profiles in a folder/snippet/device (optional ``name``
            substring filter).
          * ``get`` - one profile (raw API fields, including threat exceptions)
            by ``profile_id``, or ``name`` + container.
          * ``create`` - new profile from ``rules_json`` (required for
            vulnerability, optional for anti-spyware) and optional
            ``threat_exceptions_json``.
          * ``update`` - ``rules_json`` REPLACES the whole rules list,
            ``threat_exceptions_json`` REPLACES the whole exception list
            (``[]`` clears it), ``description`` replaces the description.
            Anything not passed is preserved exactly as read from SCM,
            including fields this tool does not edit (``cloud_inline_analysis``,
            ``inline_exception_*``, ``mica_engine_spyware_enabled``).  The result
            is read back and reported as ``verified``.
          * ``delete`` - remove a profile; refused while a profile group in the
            same container lists it, and refused if that lookup fails.  The
            result lists what the reference check scanned and did NOT scan
            (other folders/snippets, security rules, non-SCM configs).

        ``rules_json`` is a JSON list of rule objects.  Fields (pan.dev spec):
        ``name``, ``action``, ``severity`` (required list of critical, high,
        medium, low, informational, any), ``category`` (default any),
        ``threat_name`` (default any; anti-spyware min 3 chars),
        ``packet_capture`` (disable, single-packet, extended-capture).
        Vulnerability rules also take ``cve`` (list), ``host`` (any, client,
        server) and ``vendor_id`` (list; the API field is ``vendor_id``, NOT
        ``vendor-id``; defaults ["any"]).  ``action`` is an object naming one
        action, e.g. ``{"alert": {}}`` or ``{"block_ip": {"track_by": "source",
        "duration": 300}}``; allow, alert, drop, reset_client, reset_server,
        reset_both, block_ip (vulnerability rules and all exceptions also accept
        default).  A bare string such as ``"reset-both"`` is accepted.

        ``threat_exceptions_json`` is a JSON list of ``{"name": <threat id>,
        "action", "packet_capture", "exempt_ip": [ip, ...], "notes" (anti-spyware
        only; SCM discards it on vulnerability exceptions)}`` plus
        ``time_attribute`` ``{"interval" 1-3600, "threshold" 1-65535,
        "track_by"}`` for vulnerability profiles.  Anti-spyware exceptions
        default packet_capture to disable.  Known API limit: an anti-spyware
        exception PUT only accepts threat IDs already seen in a created profile;
        the dry run warns when an update adds new IDs, and the read-back shows
        whether SCM accepted it.

        **Write safety (SSR pattern):** ``dry_run=True`` by default; a dry run
        reads only and returns the planned request.  ``ticket_ref`` is
        mandatory for every write action (dry runs included), is logged, and is
        never sent to SCM.  The container stays in the PUT body (a vulnerability
        PUT without it silently does nothing).  No commit is performed: run
        scm_commit.

        Args:
            kind: anti_spyware (default) or vulnerability.
            action: list (default), get, create, update or delete.
            folder: Folder container (pass only one of folder, snippet, device).
            snippet: Snippet container.
            device: Device container.
            name: Profile name (create/update/delete/get target; list filter).
            profile_id: Profile UUID (get/update/delete).
            description: Profile description (create/update).
            rules_json: JSON list of rules (create; update replaces all rules).
            threat_exceptions_json: JSON list of threat exceptions (create; update
                replaces all; "[]" clears).
            dry_run: If True (default), preview a write without applying it.
            ticket_ref: Mandatory change-ticket reference for writes.
            acknowledge_unscanned_scope: delete only.  A profile in a top-level folder
                (All, Shared, Prisma Access, Global) or a snippet is inherited by
                containers that cannot all be enumerated.  Mobile Users and Remote
                Networks are scanned for a top-level folder, but the scan stays incomplete,
                so a real delete is refused unless this is True.  Dry runs show the
                warning and the refusal reason.
            limit: Maximum rows returned by list.
            tenant_id: SCM tenant ID.
        """
        if kind not in _KINDS:
            return f"Error: unknown kind {kind!r} - use one of: {', '.join(_KINDS)}"
        if action not in _ACTIONS:
            return f"Error: unknown action {action!r} - use one of: {', '.join(_ACTIONS)}"
        scope, err = _scope(folder, snippet, device)
        if err:
            return f"Error: {err}"
        spec = _KINDS[kind]
        base: str = spec["base"]
        label: str = spec["label"]

        if action == "list":
            if not scope:
                return "Error: list needs one of folder, snippet or device"
            rows = _list_all(client, base, scope)
            if name:
                rows = [r for r in rows if name.lower() in str(r.get("name", "")).lower()]
            return _fmt(
                {"kind": kind, "scope": scope, "total": len(rows), "items": rows[: max(0, limit)]}
            )
        if action == "get":
            if profile_id:
                item = _fetch_by_id(client, base, profile_id.strip())
            elif name and scope:
                item = _fetch(client, base, name, scope)
            else:
                return "Error: get needs profile_id, or name with one of folder/snippet/device"
            if item is None:
                return f"Error: {label} profile not found"
            return _fmt({"kind": kind, "item": item})

        err = ticket_ref_error(ticket_ref)
        if err:
            return f"Error: {err}"
        ticket_ref = normalize_ticket_ref(ticket_ref)

        if action == "create":
            return _create(
                client, tenant_id, kind, scope, name, description,
                rules_json, threat_exceptions_json, dry_run, ticket_ref,
            )  # fmt: skip

        if profile_id.strip():
            current = _fetch_by_id(client, base, profile_id.strip())
        elif name and scope:
            current = _fetch(client, base, name, scope)
        else:
            return f"Error: {action} needs profile_id, or name with one of folder/snippet/device"
        if current is None:
            return f"Error: {label} profile not found"
        if action == "update":
            return _update(
                client, tenant_id, kind, current, description,
                rules_json, threat_exceptions_json, dry_run, ticket_ref,
            )  # fmt: skip
        return _delete(
            client, tenant_id, kind, current, dry_run, ticket_ref, acknowledge_unscanned_scope
        )


def _create(
    client: Any,
    tenant_id: str,
    kind: str,
    scope: dict[str, str],
    name: str,
    description: str | None,
    rules_json: str,
    exceptions_json: str,
    dry_run: bool,
    ticket_ref: str,
) -> str:
    spec = _KINDS[kind]
    base: str = spec["base"]
    if not scope:
        return "Error: create needs one of folder, snippet or device"
    if not spec["name_re"].match(name or ""):
        return (
            f"Error: name does not match the {spec['label']} name pattern {spec['name_re'].pattern}"
        )
    rules: list[dict[str, Any]] = []
    if rules_json:
        rules, errors = parse_rules(kind, rules_json)
        if errors:
            return "Error: invalid rules_json:\n  - " + "\n  - ".join(errors)
    elif kind == "vulnerability":
        return "Error: a vulnerability profile needs rules_json (at least one rule)"
    exceptions: list[dict[str, Any]] = []
    if exceptions_json:
        exceptions, errors = parse_exceptions(kind, exceptions_json)
        if errors:
            return "Error: invalid threat_exceptions_json:\n  - " + "\n  - ".join(errors)
    if _fetch(client, base, name, scope) is not None:
        return f"Error: profile {name!r} already exists in {next(iter(scope.values()))}; use action=update"
    body: dict[str, Any] = {"name": name, **scope}
    if rules:
        body["rules"] = rules
    if exceptions:
        body["threat_exception"] = exceptions
    if description:
        body["description"] = description
    if dry_run:
        return _fmt(
            {
                "kind": kind,
                "action": "create",
                "dry_run": True,
                "ticket_ref": ticket_ref,
                "request": {"method": "POST", "path": base, "body": body},
                "exists": False,
                "hint": DRY_RUN_HINT,
            }
        )
    audit_write("scm_threat_profile", ticket_ref, tenant_id, action=f"create {kind}", path=base)
    result = client.post(base, json=body)
    stored = _fetch(client, base, name, scope)
    verified = _verify(stored, body)
    out: dict[str, Any] = {
        "kind": kind,
        "action": "create",
        "applied": True,
        "ticket_ref": ticket_ref,
        "result": result,
        "verified": verified,
        "hint": COMMIT_HINT,
    }
    if not verified:
        out["warning"] = "read-back does not match the request; check the profile with action=get"
    return _fmt(out)


def _update(
    client: Any,
    tenant_id: str,
    kind: str,
    current: dict[str, Any],
    description: str | None,
    rules_json: str,
    exceptions_json: str,
    dry_run: bool,
    ticket_ref: str,
) -> str:
    spec = _KINDS[kind]
    base: str = spec["base"]
    if not rules_json and not exceptions_json and description is None:
        return (
            "Error: update needs rules_json, threat_exceptions_json (the full new list; "
            "[] clears it) and/or description"
        )
    rules_before = [r for r in current.get("rules") or [] if isinstance(r, dict)]
    exc_before = [e for e in current.get("threat_exception") or [] if isinstance(e, dict)]
    rules_after, exc_after = rules_before, exc_before
    if rules_json:
        rules_after, errors = parse_rules(kind, rules_json)
        if errors:
            return "Error: invalid rules_json:\n  - " + "\n  - ".join(errors)
        if kind == "vulnerability" and not rules_after:
            return "Error: a vulnerability profile needs at least one rule"
    if exceptions_json:
        exc_after, errors = parse_exceptions(kind, exceptions_json)
        if errors:
            return "Error: invalid threat_exceptions_json:\n  - " + "\n  - ".join(errors)

    data = {**current}
    if rules_json:
        if rules_after:
            data["rules"] = rules_after
        else:
            data.pop("rules", None)  # anti-spyware only; an empty list is not sent
    if exceptions_json:
        if exc_after:
            data["threat_exception"] = exc_after
        else:
            # SCM rejects an empty list; omitting the field is what clears it.
            data.pop("threat_exception", None)
    if description is not None:
        data["description"] = description
    path = f"{base}/{current['id']}"
    body = scm_rest.put_payload(spec["sdk_attr"], data)

    warnings: list[str] = []
    new_ids = sorted({e["name"] for e in exc_after} - {str(e.get("name")) for e in exc_before})
    if kind == "anti_spyware" and exceptions_json and new_ids:
        warnings.append(
            f"anti-spyware exception IDs {new_ids} are new to this profile; the API only "
            "accepted IDs already seen in a created profile on a PUT (live-proven), so this "
            "may be rejected or ignored; the read-back reports which"
        )
    if exceptions_json and not exc_after and exc_before:
        warnings.append(
            "clearing works by omitting threat_exception (an empty list is rejected); the "
            "read-back reports whether SCM really cleared it"
        )
    summary: dict[str, Any] = {
        "kind": kind,
        "action": "update",
        "ticket_ref": ticket_ref,
        "rule_diff": _diff(rules_before, rules_after),
        "threat_exception_diff": _diff(exc_before, exc_after),
        "preserved": sorted(
            k for k in current if k not in {"id", "rules", "threat_exception", "description"}
        ),
    }
    if warnings:
        summary["warnings"] = warnings
    if dry_run:
        return _fmt(
            {
                **summary,
                "dry_run": True,
                "request": {"method": "PUT", "path": path, "body": body},
                "hint": DRY_RUN_HINT,
            }
        )
    audit_write("scm_threat_profile", ticket_ref, tenant_id, action=f"update {kind}", path=path)
    result = scm_rest.put_object(client, spec["sdk_attr"], data)
    # A PUT can answer 200 and change nothing: read it back and compare.
    verified = _verify(_fetch_by_id(client, base, str(current["id"])), body)
    out = {**summary, "applied": True, "result": result, "verified": verified, "hint": COMMIT_HINT}
    if not verified:
        out["warning"] = "read-back does not match the update; the API may have ignored it"
    return _fmt(out)


def _delete(
    client: Any,
    tenant_id: str,
    kind: str,
    current: dict[str, Any],
    dry_run: bool,
    ticket_ref: str,
    acknowledge_unscanned_scope: bool = False,
) -> str:
    base: str = _KINDS[kind]["base"]
    scope = {k: str(current[k]) for k in _SCOPE_KEYS if current.get(k)}
    check, lookup_err = _reference_check(client, kind, str(current.get("name")), scope)
    path = f"{base}/{current['id']}"
    refs = check["referenced_by"]
    if refs:
        return (
            f"Error: profile {current.get('name')!r} is referenced by profile group(s) {refs}; "
            f"remove it from them first. Scanned: {check['scanned']}. "
            f"Not scanned: {'; '.join(check['not_scanned'])}"
        )
    if lookup_err:
        check["warning"] = lookup_err
        if not dry_run:
            return (
                f"Error: {lookup_err}; refusing to delete without a reference check "
                "(run a dry run to see the details)"
            )
    refusal = scope_refusal(scope, acknowledge_unscanned_scope)
    if refusal:
        check["would_refuse"] = refusal
        if not dry_run:
            return f"Error: delete refused: {refusal}. Scanned: {check['scanned']}"
    if dry_run:
        return _fmt(
            {
                "kind": kind,
                "action": "delete",
                "dry_run": True,
                "ticket_ref": ticket_ref,
                "request": {"method": "DELETE", "path": path},
                "current": current,
                "reference_check": check,
                "hint": DRY_RUN_HINT,
            }
        )
    audit_write("scm_threat_profile", ticket_ref, tenant_id, action=f"delete {kind}", path=path)
    result = client.delete(path)
    return _fmt(
        {
            "kind": kind,
            "action": "delete",
            "applied": True,
            "ticket_ref": ticket_ref,
            "result": result,
            "reference_check": check,
            "hint": COMMIT_HINT,
        }
    )
