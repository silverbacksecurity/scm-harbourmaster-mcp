"""One MCP tool for the simpler security-profile types.

``scm_security_profile`` lists, reads and (dry-run first) writes four profile
types through a small per-kind spec table, so a single tool (and a single slot
in its domain's tool cap) covers them:

  * ``wildfire_antivirus`` (alias ``antivirus``) - ``/wildfire-anti-virus-profiles``.
    SCM has no separate antivirus endpoint: the "WildFire and anti-virus"
    profile is the one object, so both kind names resolve to it.
  * ``url_access`` - ``/url-access-profiles``
  * ``decryption`` - ``/decryption-profiles``
  * ``zone_protection`` - ``/zone-protection-profiles`` (network API)

File-blocking, anti-spyware and vulnerability profiles have their own tools.

Request bodies are API-shaped (``config_json``) and validated against a key
whitelist taken from the pan.dev OpenAPI specs and the pan-scm-sdk models
(unknown keys are rejected, never guessed).  Reads and writes go over raw REST
because pan-scm-sdk 0.15.1 drops aliased fields (a URL profile's ``continue``).

**Write safety (SSR pattern):** ``dry_run=True`` by default, ``ticket_ref``
mandatory for every write action (dry runs included), logged and never sent in
a body.  Commit is a separate ``scm_commit`` step.
"""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
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
from .threat_profile import (
    api_folder,
    is_blank,
    pair_named,
    scan_scopes,
    scope_refusal,
    unscanned_scope_notice,
)

logger = get_logger(__name__)

_HOST = "https://api.sase.paloaltonetworks.com"
_PROFILE_GROUPS_URL = f"{_HOST}/sse/config/v1/profile-groups"
_DECRYPTION_RULES_URL = f"{_HOST}/config/security/v1/decryption-rules"
_ZONES_URL = f"{_HOST}/config/network/v1/zones"
_URL_CATEGORIES_URL = f"{_HOST}/config/security/v1/url-filtering-categories"
_CUSTOM_URL_CATEGORIES_URL = f"{_HOST}/config/security/v1/url-categories"
_PAGE = 200

_ACTIONS_READ = ("list", "get")
_ACTIONS_WRITE = ("create", "update", "delete")
_ACTIONS = _ACTIONS_READ + _ACTIONS_WRITE
_SCOPE_KEYS = ("folder", "snippet", "device")
COMMIT_HINT = "Not committed: run scm_commit to push the change."

# ---------------------------------------------------------------------------
# Body schema: a tiny node DSL (type, constraints), one tree per kind.
# Taken from the pan.dev security/network OpenAPI specs, cross-checked with
# the pan-scm-sdk models (which add a few fields the specs omit).
# ---------------------------------------------------------------------------

Node = tuple[Any, ...]


def B() -> Node:  # noqa: N802 - schema constructors read as type names
    return ("b",)


def Int(lo: int | None = None, hi: int | None = None) -> Node:
    return ("i", lo, hi)


def S(
    enum: tuple[str, ...] | None = None, max_len: int | None = None, pattern: str | None = None
) -> Node:
    return ("s", enum, max_len, pattern)


def L(item: Node) -> Node:
    return ("l", item)


def Obj(fields: dict[str, Node], required: tuple[str, ...] = ()) -> Node:
    return ("o", fields, required)


def X(fields: dict[str, Node]) -> Node:
    """An object with exactly one of *fields* set (replaced whole on update)."""
    return ("x", fields)


def _bools(*names: str) -> dict[str, Node]:
    return {n: B() for n in names}


_ANY_OBJ: Node = Obj({})  # an empty object: ``{}`` carries the meaning
_STR_LIST = L(S())

# -- wildfire / anti-virus ---------------------------------------------------
_WF_RULE = Obj(
    {
        "name": S(),
        "analysis": S(("public-cloud", "private-cloud")),
        "application": _STR_LIST,
        "direction": S(("download", "upload", "both")),
        "file_type": _STR_LIST,
    },
    required=("name", "application", "direction", "file_type"),
)
_WILDFIRE_SCHEMA: dict[str, Node] = {
    "name": S(pattern=r"^[a-zA-Z0-9._-]+$"),
    "description": S(),
    "packet_capture": B(),
    "mlav_exception": L(
        Obj({"name": S(), "description": S(), "filename": S()}, required=("name", "filename"))
    ),
    "rules": L(_WF_RULE),
    "threat_exception": L(Obj({"name": S(), "notes": S()}, required=("name",))),
}

# -- URL access ---------------------------------------------------------------
_URL_LISTS = ("alert", "allow", "block", "continue", "redirect")
_URL_SCHEMA: dict[str, Node] = {
    "name": S(),
    "description": S(max_len=255),
    **{k: _STR_LIST for k in _URL_LISTS},
    "cloud_inline_cat": B(),
    "local_inline_cat": B(),
    "credential_enforcement": Obj(
        {
            **{k: _STR_LIST for k in ("alert", "allow", "block", "continue")},
            "log_severity": S(),
            "mode": X(
                {
                    "disabled": _ANY_OBJ,
                    "domain_credentials": _ANY_OBJ,
                    "ip_user": _ANY_OBJ,
                    "group_mapping": S(),
                }
            ),
        }
    ),
    "mlav_category_exception": _STR_LIST,
    **_bools(
        "log_container_page_only",
        "log_http_hdr_referer",
        "log_http_hdr_user_agent",
        "log_http_hdr_xff",
        "safe_search_enforcement",
    ),
}

# -- decryption ---------------------------------------------------------------
_SSL_VERSIONS_MAX = ("sslv3", "tls1-0", "tls1-1", "tls1-2", "tls1-3", "max")
_DECRYPTION_SCHEMA: dict[str, Node] = {
    "name": S(pattern=r"^[A-Za-z0-9]{1}[A-Za-z0-9_\-\.\s]{0,}$"),
    "ssl_forward_proxy": Obj(
        _bools(
            "auto_include_altname",
            "block_client_cert",
            "block_expired_certificate",
            "block_timeout_cert",
            "block_tls13_downgrade_no_resource",
            "block_unknown_cert",
            "block_unsupported_cipher",
            "block_unsupported_version",
            "block_untrusted_issuer",
            "restrict_cert_exts",
            "strip_alpn",
        )
    ),
    "ssl_inbound_proxy": Obj(
        _bools(
            "block_if_hsm_unavailable",
            "block_if_no_resource",
            "block_unsupported_cipher",
            "block_unsupported_version",
        )
    ),
    "ssl_no_proxy": Obj(_bools("block_expired_certificate", "block_untrusted_issuer")),
    "ssl_protocol_settings": Obj(
        {
            **_bools(
                "auth_algo_md5",
                "auth_algo_sha1",
                "auth_algo_sha256",
                "auth_algo_sha384",
                "enc_algo_3des",
                "enc_algo_aes_128_cbc",
                "enc_algo_aes_128_gcm",
                "enc_algo_aes_256_cbc",
                "enc_algo_aes_256_gcm",
                "enc_algo_chacha20_poly1305",
                "enc_algo_rc4",
                "keyxchg_algo_dhe",
                "keyxchg_algo_ecdhe",
                "keyxchg_algo_rsa",
            ),
            "max_version": S(_SSL_VERSIONS_MAX),
            "min_version": S(("sslv3", "tls1-0", "tls1-1", "tls1-2", "tls1-3")),
        }
    ),
}

# -- zone protection ----------------------------------------------------------
_RATE = Int(0, 2000000)
_RED = Obj(
    {"alarm_rate": _RATE, "activate_rate": _RATE, "maximal_rate": _RATE},
    required=("alarm_rate", "activate_rate", "maximal_rate"),
)
_FLOOD = Obj({"enable": B(), "red": _RED})
_YES_NO_GLOBAL = S(("global", "yes", "no"))
_ZONE_SCHEMA: dict[str, Node] = {
    "name": S(max_len=31),
    "description": S(max_len=255),
    "flood": Obj(
        {
            # the SDK model also carries syn_cookies, which the spec omits
            "tcp_syn": Obj({"enable": B(), "red": _RED, "syn_cookies": _RED}),
            "udp": _FLOOD,
            "sctp_init": _FLOOD,
            "icmp": _FLOOD,
            "icmpv6": _FLOOD,
            "other_ip": _FLOOD,
        }
    ),
    "scan": L(
        Obj(
            {
                "name": S(("8001", "8002", "8003", "8006")),
                "action": X(
                    {
                        "allow": _ANY_OBJ,
                        "alert": _ANY_OBJ,
                        "block": _ANY_OBJ,
                        "block_ip": Obj(
                            {
                                "track_by": S(("source-and-destination", "source")),
                                "duration": Int(1, 3600),
                            },
                            required=("track_by", "duration"),
                        ),
                    }
                ),
                "interval": Int(2, 65535),
                "threshold": Int(2, 65535),
            },
            required=("name",),
        )
    ),
    "scan_white_list": L(Obj({"name": S(), "ipv4": S(), "ipv6": S()}, required=("name",))),
    **_bools(
        "spoofed_ip_discard",
        "strict_ip_check",
        "fragmented_traffic_discard",
        "strict_source_routing_discard",
        "loose_source_routing_discard",
        "timestamp_discard",
        "record_route_discard",
        "security_discard",
        "stream_id_discard",
        "unknown_option_discard",
        "malformed_option_discard",
        "mismatched_overlapping_tcp_segment_discard",
        "tcp_handshake_discard",
        "tcp_syn_with_data_discard",
        "tcp_synack_with_data_discard",
        "tcp_timestamp_strip",
        "tcp_fast_open_and_data_strip",
        "icmp_ping_zero_id_discard",
        "icmp_frag_discard",
        "icmp_large_packet_discard",
        "discard_icmp_embedded_error",
        "suppress_icmp_timeexceeded",
        "suppress_icmp_needfrag",
    ),
    "reject_non_syn_tcp": _YES_NO_GLOBAL,
    "asymmetric_path": S(("global", "drop", "bypass")),
    "mptcp_option_strip": _YES_NO_GLOBAL,
    "ipv6": Obj(
        {
            **_bools(
                "routing_header_0",
                "routing_header_1",
                "routing_header_3",
                "routing_header_4_252",
                "routing_header_253",
                "routing_header_254",
                "routing_header_255",
                "ipv4_compatible_address",
                "options_invalid_ipv6_discard",
                "reserved_field_set_discard",
                "anycast_source",
                "needless_fragment_hdr",
                "icmpv6_too_big_small_mtu_discard",
            ),
            "filter_ext_hdr": Obj(_bools("hop_by_hop_hdr", "routing_hdr", "dest_option_hdr")),
            "ignore_inv_pkt": Obj(
                _bools("dest_unreach", "pkt_too_big", "time_exceeded", "param_problem", "redirect")
            ),
        }
    ),
    "non_ip_protocol": Obj(
        {
            "list_type": S(("exclude", "include")),
            "protocol": L(
                Obj(
                    {"name": S(), "ether_type": S(), "enable": B()},
                    required=("name", "ether_type"),
                )
            ),
        }
    ),
    "l2_sec_group_tag_protection": Obj(
        {"tags": L(Obj({"name": S(), "tag": S(), "enable": B()}, required=("name", "tag")))}
    ),
}


# ---------------------------------------------------------------------------
# Per-kind spec table
# ---------------------------------------------------------------------------

# (names referencing the profile, error).  Scans the profile's own container.
RefScan = Callable[[Any, str, dict[str, str]], tuple[list[str], str]]


@dataclass(frozen=True)
class Spec:
    kind: str
    label: str
    path: str
    sdk_attr: str
    schema: dict[str, Node]
    # Top-level keys create must supply besides the name
    required: tuple[str, ...]
    # Keys the API returns but rejects/ignores on PUT
    readonly: frozenset[str]
    ref_scan: RefScan
    # What the reference check covers (stated in every delete response)
    ref_scope: str
    name_max: int | None = None
    # The API's name pattern is the schema's; kept here for the error text only
    name_hint: str = ""


def _paged_names(
    client: Any,
    url: str,
    params: dict[str, Any],
    extract: Callable[[dict[str, Any]], list[str]],
) -> tuple[list[str], str]:
    """Names produced by *extract* across every page of a list call, or ([], error)."""
    try:
        scm_rest.refresh_token(client)
        session = scm_rest.bearer_session(client)
        names: list[str] = []
        offset = 0
        while True:
            res = scm_rest.request(
                session,
                "GET",
                url,
                params={**params, "limit": _PAGE, "offset": offset},
                timeout=clone_preflight._TIMEOUT,
            )
            if res.status != 200:
                return [], f"HTTP {res.status}{(': ' + res.error) if res.error else ''}"
            page = _items(res.data)
            for row in page:
                names.extend(extract(row))
            if len(page) < _PAGE:
                return sorted(set(names)), ""
            offset += _PAGE
    except Exception as exc:
        return [], str(exc)[:200]


def _scan_all(spec: Spec, client: Any, name: str, scope: dict[str, str]) -> tuple[list[str], str]:
    """Run the kind's scan over the own container (alias applied) and the child folders."""
    found: list[str] = []
    for label, query in scan_scopes(scope):
        names, err = spec.ref_scan(client, name, query)
        found.extend(f"{n} (in {label})" if label else n for n in names)
        if err:
            return sorted(set(found)), err
    return sorted(set(found)), ""


def _group_scan(field: str) -> RefScan:
    def scan(client: Any, name: str, scope: dict[str, str]) -> tuple[list[str], str]:
        def extract(row: dict[str, Any]) -> list[str]:
            value = row.get(field)
            members = [value] if isinstance(value, str) else (value or [])
            return [str(row["name"])] if name in members and row.get("name") else []

        names, err = _paged_names(client, _PROFILE_GROUPS_URL, scope, extract)
        return names, f"profile-group lookup failed: {err}" if err else ""

    return scan


def _decryption_rule_scan(client: Any, name: str, scope: dict[str, str]) -> tuple[list[str], str]:
    found: list[str] = []
    for position in ("pre", "post"):

        def extract(row: dict[str, Any], position: str = position) -> list[str]:
            if row.get("profile") == name and row.get("name"):
                return [f"{row['name']} ({position})"]
            return []

        names, err = _paged_names(
            client, _DECRYPTION_RULES_URL, {**scope, "position": position}, extract
        )
        if err:
            return [], f"decryption-rule lookup ({position}) failed: {err}"
        found.extend(names)
    return sorted(found), ""


def _zone_scan(client: Any, name: str, scope: dict[str, str]) -> tuple[list[str], str]:
    def extract(row: dict[str, Any]) -> list[str]:
        net = row.get("network")
        if isinstance(net, dict) and net.get("zone_protection_profile") == name and row.get("name"):
            return [str(row["name"])]
        return []

    names, err = _paged_names(client, _ZONES_URL, scope, extract)
    return names, f"security-zone lookup failed: {err}" if err else ""


_WILDFIRE_SPEC = Spec(
    kind="wildfire_antivirus",
    label="WildFire and anti-virus profile",
    path="/config/security/v1/wildfire-anti-virus-profiles",
    sdk_attr="wildfire_antivirus_profile",
    schema=_WILDFIRE_SCHEMA,
    # Only ``name`` is required: the live API accepts a profile without rules
    # (201, 2026-11-20), as the pan.dev spec says; the SDK model is stricter.
    required=(),
    readonly=frozenset({"override_loc", "override_type", "override_id"}),
    ref_scan=_group_scan("virus_and_wildfire_analysis"),
    ref_scope=(
        "profile groups (virus_and_wildfire_analysis) in the same container (plus Mobile "
        "Users and Remote Networks for a top-level folder); other folders, snippets and "
        "devices, and any non-SCM config are not scanned (security rules reference profiles "
        "via profile groups only)"
    ),
    name_hint="A-Z a-z 0-9 . _ -",
)

SPECS: dict[str, Spec] = {
    "wildfire_antivirus": _WILDFIRE_SPEC,
    "url_access": Spec(
        kind="url_access",
        label="URL access profile",
        path="/config/security/v1/url-access-profiles",
        sdk_attr="url_access_profile",
        schema=_URL_SCHEMA,
        required=(),
        readonly=frozenset(),
        ref_scan=_group_scan("url_filtering"),
        ref_scope=(
            "profile groups (url_filtering) in the same container (plus Mobile Users "
            "and Remote Networks for a top-level folder); other folders, snippets and "
            "devices, and any non-SCM config are not scanned (security rules reference "
            "profiles via profile groups only)"
        ),
    ),
    "decryption": Spec(
        kind="decryption",
        label="decryption profile",
        path="/config/security/v1/decryption-profiles",
        sdk_attr="decryption_profile",
        schema=_DECRYPTION_SCHEMA,
        required=(),
        readonly=frozenset(),
        ref_scan=_decryption_rule_scan,
        ref_scope=(
            "decryption rules (profile field, pre and post rulebases) in the same "
            "container (plus Mobile Users and Remote Networks for a top-level folder); "
            "other folders, snippets and devices are not scanned"
        ),
        name_hint="start with A-Z a-z 0-9, then letters, digits, space . _ -",
    ),
    "zone_protection": Spec(
        kind="zone_protection",
        label="zone protection profile",
        path="/config/network/v1/zone-protection-profiles",
        sdk_attr="zone_protection_profile",
        schema=_ZONE_SCHEMA,
        required=(),
        readonly=frozenset(),
        ref_scan=_zone_scan,
        ref_scope=(
            "security zones (network.zone_protection_profile) in the same container "
            "(plus Mobile Users and Remote Networks for a top-level folder); the zones API "
            "lists nothing for the Prisma Access folders, so a profile there is never seen "
            "as referenced"
        ),
        name_max=31,
    ),
}
# SCM has one "WildFire and anti-virus" endpoint; "antivirus" is the same object.
KIND_ALIASES: dict[str, str] = {"antivirus": "wildfire_antivirus"}
KINDS = (*SPECS, *KIND_ALIASES)

_CONTAINER_KEYS = frozenset(_SCOPE_KEYS)
_FORBIDDEN_BODY_KEYS = _CONTAINER_KEYS | {"id"}


def resolve_kind(kind: str) -> Spec | None:
    key = (kind or "").strip().lower()
    return SPECS.get(KIND_ALIASES.get(key, key))


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _check(
    node: Node, value: Any, path: str, errs: list[str], *, strict: bool, null_ok: bool
) -> None:
    """Append every problem with *value* against *node* (type, enum, keys).

    ``strict`` enforces required keys (create); ``null_ok`` lets None through
    (update uses it to unset a key).
    """
    if value is None:
        if not null_ok:
            errs.append(f"{path}: null is only allowed on update (it removes the key)")
        return
    kind = node[0]
    if kind == "b":
        if not isinstance(value, bool):
            errs.append(f"{path}: must be true/false")
    elif kind == "i":
        if isinstance(value, bool) or not isinstance(value, int):
            errs.append(f"{path}: must be an integer")
        else:
            _, lo, hi = node
            if (lo is not None and value < lo) or (hi is not None and value > hi):
                errs.append(f"{path}: {value} outside {lo}..{hi}")
    elif kind == "s":
        _, enum, max_len, pattern = node
        if not isinstance(value, str):
            errs.append(f"{path}: must be a string")
        elif enum is not None and value not in enum:
            errs.append(f"{path}: {value!r} not one of {list(enum)}")
        elif max_len is not None and len(value) > max_len:
            errs.append(f"{path}: longer than {max_len} characters")
        elif pattern is not None and not re.match(pattern, value):
            errs.append(f"{path}: {value!r} does not match {pattern}")
    elif kind == "l":
        if not isinstance(value, list):
            errs.append(f"{path}: must be a list")
            return
        for i, item in enumerate(value):
            _check(node[1], item, f"{path}[{i}]", errs, strict=strict, null_ok=False)
    elif kind == "o":
        _check_object(node[1], node[2], value, path, errs, strict=strict, null_ok=null_ok)
    elif kind == "x":
        if not isinstance(value, dict):
            errs.append(f"{path}: must be an object")
            return
        keys = sorted(value)
        unknown = [k for k in keys if k not in node[1]]
        if unknown:
            errs.append(f"{path}: unknown keys {unknown}; allowed {sorted(node[1])}")
        elif len(keys) != 1:
            errs.append(f"{path}: set exactly one of {sorted(node[1])}")
        else:
            _check(
                node[1][keys[0]],
                value[keys[0]],
                f"{path}.{keys[0]}",
                errs,
                strict=strict,
                null_ok=False,
            )


def _check_object(
    fields: dict[str, Node],
    required: tuple[str, ...],
    value: Any,
    path: str,
    errs: list[str],
    *,
    strict: bool,
    null_ok: bool,
) -> None:
    if not isinstance(value, dict):
        errs.append(f"{path}: must be an object")
        return
    unknown = sorted(set(value) - set(fields))
    if unknown:
        errs.append(f"{path}: unknown keys {unknown}; allowed {sorted(fields)}")
    if strict:
        errs.extend(f"{path}.{k}: required" for k in required if value.get(k) is None)
    for key, sub in value.items():
        if key in fields:
            _check(fields[key], sub, f"{path}.{key}", errs, strict=strict, null_ok=null_ok)


def parse_config(spec: Spec, config_json: str, *, create: bool) -> tuple[dict[str, Any], list[str]]:
    """The validated body fragment and every problem found (not just the first)."""
    if not config_json.strip():
        return {}, ["config_json is required"]
    try:
        body = json.loads(config_json)
    except json.JSONDecodeError as exc:
        return {}, [f"config_json is not valid JSON: {exc}"]
    if not isinstance(body, dict):
        return {}, ["config_json must be a JSON object"]
    errs: list[str] = []
    forbidden = sorted(set(body) & _FORBIDDEN_BODY_KEYS)
    if forbidden:
        errs.append(
            f"config_json must not contain {forbidden}: pass the container as the "
            "folder/snippet/device argument; the id is addressed by name or profile_id"
        )
    fields = {k: v for k, v in spec.schema.items() if k != "name"}
    if "name" in body:
        _check(spec.schema["name"], body["name"], "name", errs, strict=create, null_ok=False)
    rest = {k: v for k, v in body.items() if k not in _FORBIDDEN_BODY_KEYS and k != "name"}
    _check_object(
        fields, spec.required, rest, "config_json", errs, strict=create, null_ok=not create
    )
    if create:
        errs.extend(f"config_json.{k}: required" for k in spec.required if body.get(k) is None)
    else:
        errs.extend(
            f"config_json.{k}: required, cannot be removed with null"
            for k in spec.required
            if k in body and body[k] is None
        )
    return body, errs


def _name_error(spec: Spec, name: str) -> str:
    errs: list[str] = []
    if not isinstance(name, str) or not name.strip():
        return "name is required"
    _check(spec.schema["name"], name, "name", errs, strict=False, null_ok=False)
    if not errs and spec.name_max is not None and len(name) > spec.name_max:
        errs.append(f"name: longer than {spec.name_max} characters")
    if errs:
        hint = f" ({spec.name_hint})" if spec.name_hint else ""
        return "; ".join(errs) + hint
    return ""


# ---------------------------------------------------------------------------
# Merge / diff / read-back helpers
# ---------------------------------------------------------------------------


def _merge(base: dict[str, Any], delta: dict[str, Any], fields: dict[str, Node]) -> dict[str, Any]:
    """*delta* over *base*: objects merge by key, lists/scalars/one-of objects
    replace, None removes the key."""
    out = copy.deepcopy(base)
    for key, value in delta.items():
        node = fields.get(key)
        if value is None:
            out.pop(key, None)
        elif (
            node is not None
            and node[0] == "o"
            and isinstance(value, dict)
            and isinstance(out.get(key), dict)
        ):
            out[key] = _merge(out[key], value, node[1])
        else:
            out[key] = copy.deepcopy(value)
    return out


def _covers(stored: Any, expected: Any) -> bool:
    """True when *stored* holds everything in *expected* (extra stored keys,
    such as server defaults, are fine).  Lists of named dicts compare by name
    (order-insensitive); ''/None/missing are equal."""
    if isinstance(expected, dict):
        return isinstance(stored, dict) and all(
            is_blank(stored.get(k)) if is_blank(v) else _covers(stored.get(k), v)
            for k, v in expected.items()
        )
    if isinstance(expected, list):
        if not isinstance(stored, list) or len(stored) != len(expected):
            return False
        pairs = pair_named(stored, expected)
        if pairs is not None:
            return all(_covers(s, e) for s, e in pairs)
        if all(not isinstance(e, dict | list) for e in expected):
            return sorted(map(str, stored)) == sorted(map(str, expected))
        return all(_covers(s, e) for s, e in zip(stored, expected, strict=True))
    return stored == expected or (is_blank(stored) and is_blank(expected))


def _diff(before: dict[str, Any], after: dict[str, Any]) -> dict[str, list[str]]:
    return {
        "added": sorted(set(after) - set(before)),
        "removed": sorted(set(before) - set(after)),
        "changed": sorted(k for k in set(before) & set(after) if before[k] != after[k]),
    }


def _url_categories_in(delta: dict[str, Any]) -> list[str]:
    cats: list[str] = []
    for key in _URL_LISTS:
        if isinstance(delta.get(key), list):
            cats.extend(str(c) for c in delta[key])
    cred = delta.get("credential_enforcement")
    if isinstance(cred, dict):
        for key in ("alert", "allow", "block", "continue"):
            if isinstance(cred.get(key), list):
                cats.extend(str(c) for c in cred[key])
    return sorted(set(cats))


def _category_warnings(client: Any, scope: dict[str, str], delta: dict[str, Any]) -> list[str]:
    """Warnings for URL categories the tenant's catalogues do not list.

    url-filtering-categories is the full category list (not just custom ones).
    A name can also be a URL-type EDL, so these are warnings, not errors.
    """
    wanted = _url_categories_in(delta)
    if not wanted:
        return []
    try:
        scm_rest.refresh_token(client)
        session = scm_rest.bearer_session(client)
        folder = api_folder(scope.get("folder") or "All")
        known: set[str] = set()
        for url in (_URL_CATEGORIES_URL, _CUSTOM_URL_CATEGORIES_URL):
            rows, err = clone_preflight.list_rows(session, url, folder)
            if err:
                return [f"URL category check skipped: {err}"]
            known.update(str(r.get("value") or r.get("name")) for r in rows)
    except Exception as exc:
        return [f"URL category check skipped: {str(exc)[:200]}"]
    missing = [c for c in wanted if c not in known]
    if not missing:
        return []
    return [
        f"categories not found in the tenant's category lists: {missing} "
        "(a URL-type EDL name is also valid; the API decides)"
    ]


# ---------------------------------------------------------------------------
# REST helpers
# ---------------------------------------------------------------------------


def _scope(folder: str, snippet: str, device: str) -> tuple[dict[str, str], str]:
    given = {
        k: v.strip() for k, v in (("folder", folder), ("snippet", snippet), ("device", device))
    }
    given = {k: v for k, v in given.items() if v}
    if len(given) > 1:
        return {}, "pass only one of folder, snippet or device"
    return given, ""


def _items(body: Any) -> list[dict[str, Any]]:
    if isinstance(body, dict) and isinstance(body.get("data"), list):
        items = body["data"]
    elif isinstance(body, list):
        items = body
    else:
        items = [body]
    return [i for i in items if isinstance(i, dict)]


def _is_missing(exc: Exception) -> bool:
    return scm_rest.exc_status(exc) == 404 or type(exc).__name__ == "ObjectNotPresentError"


def _fetch(client: Any, spec: Spec, name: str, scope: dict[str, str]) -> dict[str, Any] | None:
    """The profile called *name* in *scope* as the raw API dict, or None."""
    try:
        body = client.get(spec.path, params={"name": name, **scope})
    except Exception as exc:
        if _is_missing(exc):
            return None
        raise
    for item in _items(body):
        if item.get("id") and item.get("name") == name:
            return item
    return None


def _fetch_by_id(client: Any, spec: Spec, profile_id: str) -> dict[str, Any] | None:
    try:
        body = client.get(f"{spec.path}/{profile_id}")
    except Exception as exc:
        if _is_missing(exc):
            return None
        raise
    items = _items(body)
    return items[0] if items and items[0].get("id") else None


def _list_all(client: Any, spec: Spec, scope: dict[str, str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    while True:
        body = client.get(
            spec.path, params={**scope, "limit": str(_PAGE), "offset": str(len(rows))}
        )
        if isinstance(body, list):
            return [r for r in body if isinstance(r, dict)]
        page = [r for r in (body or {}).get("data", []) if isinstance(r, dict)]
        rows.extend(page)
        total = (body or {}).get("total")
        if len(page) < _PAGE or (isinstance(total, int) and len(rows) >= total):
            return rows


def _summary(row: dict[str, Any]) -> dict[str, Any]:
    keep = ("id", "name", "description", *_SCOPE_KEYS)
    return {k: row[k] for k in keep if row.get(k) is not None}


# ---------------------------------------------------------------------------
# Write paths
# ---------------------------------------------------------------------------


def _create(
    client: Any,
    tenant_id: str,
    spec: Spec,
    scope: dict[str, str],
    name: str,
    config_json: str,
    dry_run: bool,
    ticket_ref: str,
    skip_category_check: bool,
) -> str:
    if not scope:
        return "Error: create needs one of folder, snippet or device"
    body, errs = parse_config(spec, config_json, create=True)
    if body.get("name") and name and body["name"] != name:
        errs.append("name argument and config_json name disagree")
    name = name or str(body.get("name") or "")
    name_err = _name_error(spec, name)
    if name_err:
        errs.append(name_err)
    if errs:
        return f"Error: invalid {spec.kind} profile:\n  - " + "\n  - ".join(dict.fromkeys(errs))
    if _fetch(client, spec, name, scope) is not None:
        return (
            f"Error: {spec.label} {name!r} already exists in {next(iter(scope.values()))}; "
            "use action=update"
        )
    request_body: dict[str, Any] = {**body, "name": name, **scope}
    warnings = (
        _category_warnings(client, scope, body)
        if spec.kind == "url_access" and not skip_category_check
        else []
    )
    if dry_run:
        return _fmt(
            {
                "kind": spec.kind,
                "action": "create",
                "dry_run": True,
                "ticket_ref": ticket_ref,
                "request": {"method": "POST", "path": spec.path, "body": request_body},
                "validation": {"ok": True, "warnings": warnings},
                "exists": False,
                "hint": DRY_RUN_HINT,
            }
        )
    audit_write(
        "scm_security_profile",
        ticket_ref,
        tenant_id,
        kind=spec.kind,
        action="create",
        path=spec.path,
    )
    result = client.post(spec.path, json=request_body)
    out: dict[str, Any] = {
        "kind": spec.kind,
        "action": "create",
        "applied": True,
        "ticket_ref": ticket_ref,
        "result": result,
        "validation": {"ok": True, "warnings": warnings},
        "hint": COMMIT_HINT,
    }
    stored = _fetch(client, spec, name, scope)
    out["verified"] = stored is not None and _covers(stored, body)
    if not out["verified"]:
        out["warning"] = (
            "read-back does not match the request; the API may have altered or ignored it"
        )
    return _fmt(out)


def _update(
    client: Any,
    tenant_id: str,
    spec: Spec,
    current: dict[str, Any],
    config_json: str,
    dry_run: bool,
    ticket_ref: str,
    skip_category_check: bool,
) -> str:
    delta, errs = parse_config(spec, config_json, create=False)
    if not errs and "name" in delta and delta["name"] != current.get("name"):
        errs.append("renaming is not supported: omit name from config_json")
    if not errs and not [k for k in delta if k != "name"]:
        errs.append("config_json has nothing to change")
    if errs:
        return f"Error: invalid {spec.kind} update:\n  - " + "\n  - ".join(dict.fromkeys(errs))
    delta = {k: v for k, v in delta.items() if k != "name"}
    fields = {k: v for k, v in spec.schema.items() if k != "name"}
    merged = _merge(current, delta, fields)
    data = {k: v for k, v in merged.items() if k not in spec.readonly}
    path = f"{spec.path}/{current['id']}"
    body = scm_rest.put_payload(spec.sdk_attr, data)
    warnings = (
        _category_warnings(
            client, {k: str(current[k]) for k in _SCOPE_KEYS if current.get(k)}, delta
        )
        if spec.kind == "url_access" and not skip_category_check
        else []
    )
    diff = _diff(current, merged)
    validation = {"ok": True, "warnings": warnings}
    if dry_run:
        return _fmt(
            {
                "kind": spec.kind,
                "action": "update",
                "dry_run": True,
                "ticket_ref": ticket_ref,
                "request": {"method": "PUT", "path": path, "body": body},
                "diff": diff,
                "validation": validation,
                "hint": DRY_RUN_HINT,
            }
        )
    audit_write(
        "scm_security_profile", ticket_ref, tenant_id, kind=spec.kind, action="update", path=path
    )
    result = client.put(path, json=body)
    # A PUT can answer 200 and change nothing: read it back and compare.
    stored = _fetch_by_id(client, spec, str(current["id"]))
    verified = stored is not None and _covers(stored, delta)
    out: dict[str, Any] = {
        "kind": spec.kind,
        "action": "update",
        "applied": True,
        "ticket_ref": ticket_ref,
        "result": result,
        "diff": diff,
        "validation": validation,
        "verified": verified,
        "hint": COMMIT_HINT,
    }
    if not verified:
        out["warning"] = "read-back does not match the update; the API may have ignored it"
    return _fmt(out)


def _delete(
    client: Any,
    tenant_id: str,
    spec: Spec,
    current: dict[str, Any],
    dry_run: bool,
    ticket_ref: str,
    acknowledge_unscanned_scope: bool = False,
) -> str:
    scope = {k: str(current[k]) for k in _SCOPE_KEYS if current.get(k)}
    refs, lookup_err = _scan_all(spec, client, str(current.get("name")), scope)
    check: dict[str, Any] = {"reference_check": spec.ref_scope, "referenced_by": refs}
    if lookup_err:
        check["warning"] = lookup_err
    notice = unscanned_scope_notice(scope)
    refusal = scope_refusal(scope, acknowledge_unscanned_scope)
    if notice:
        check["unscanned_scope_warning"] = notice
    if refusal:
        check["would_refuse"] = refusal
    if refs:
        return (
            f"Error: {spec.label} {current.get('name')!r} is referenced by {refs}; "
            f"remove the reference first (checked: {spec.ref_scope})"
        )
    if lookup_err and not dry_run:
        return (
            f"Error: cannot confirm {current.get('name')!r} is unused ({lookup_err}); "
            f"delete refused. Checked: {spec.ref_scope}. Dry run still works."
        )
    if refusal and not dry_run:
        return f"Error: delete refused: {refusal}. Checked: {spec.ref_scope}"
    path = f"{spec.path}/{current['id']}"
    if dry_run:
        return _fmt(
            {
                "kind": spec.kind,
                "action": "delete",
                "dry_run": True,
                "ticket_ref": ticket_ref,
                "request": {"method": "DELETE", "path": path},
                "current": current,
                **check,
                "hint": DRY_RUN_HINT,
            }
        )
    audit_write(
        "scm_security_profile", ticket_ref, tenant_id, kind=spec.kind, action="delete", path=path
    )
    result = client.delete(path)
    return _fmt(
        {
            "kind": spec.kind,
            "action": "delete",
            "applied": True,
            "ticket_ref": ticket_ref,
            "result": result,
            **check,
            "hint": COMMIT_HINT,
        }
    )


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_security_profile_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register the generic security-profile tool."""
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_security_profile(
        client: Any,
        tenant_id: str,
        kind: str,
        action: str = "list",
        folder: str = "",
        snippet: str = "",
        device: str = "",
        name: str = "",
        profile_id: str = "",
        config_json: str = "",
        dry_run: bool = True,
        ticket_ref: str = "",
        skip_category_check: bool = False,
        acknowledge_unscanned_scope: bool = False,
        limit: int = 200,
    ) -> str:
        """List and manage antivirus, URL access, decryption and zone protection profiles.

        Kinds: ``wildfire_antivirus`` (alias ``antivirus``: SCM has one
        "WildFire and anti-virus" profile type), ``url_access``, ``decryption``,
        ``zone_protection``.  Anti-spyware, vulnerability and file-blocking
        profiles have their own tools.

        Actions:
          * ``list`` - profiles in a folder/snippet/device (optional ``name``
            substring filter); summary rows, use ``get`` for the full body.
          * ``get`` - one profile by ``profile_id``, or ``name`` + container.
          * ``create`` - new profile from ``config_json``.
          * ``update`` - merge ``config_json`` into the existing profile.
            Unspecified fields are kept; objects merge key by key, lists and
            one-of objects (credential_enforcement.mode, scan[].action)
            replace, and a null value removes that key.
          * ``delete`` - refused while a referencing object exists (the
            response states exactly what was scanned) or when the lookup fails.

        ``config_json`` is an API-shaped JSON object.  Keys are validated
        against the API schema: unknown keys, wrong types and bad enum values
        are all reported together.  Do not put id, folder, snippet or device
        in it; ``name`` may be given there or as the ``name`` argument.
        Top-level fields per kind:
          * wildfire_antivirus: description, packet_capture, mlav_exception
            [{name, description, filename}], rules [{name, analysis
            public-cloud|private-cloud, application[], direction
            download|upload|both, file_type[]}], threat_exception [{name,
            notes}].  Name: letters, digits, . _ - (no spaces).
          * url_access: description, alert/allow/block/continue/redirect
            (category name lists), cloud_inline_cat, local_inline_cat,
            credential_enforcement {alert, allow, block, continue, log_severity,
            mode}, mlav_category_exception, log_container_page_only,
            log_http_hdr_referer, log_http_hdr_user_agent, log_http_hdr_xff,
            safe_search_enforcement.  Category names are checked against the
            tenant's category lists (warning only).
          * decryption: ssl_forward_proxy, ssl_inbound_proxy, ssl_no_proxy,
            ssl_protocol_settings (all objects of true/false flags;
            min_version/max_version are strings such as tls1-2).
          * zone_protection: description, flood {tcp_syn, udp, sctp_init, icmp,
            icmpv6, other_ip}, scan, scan_white_list, many *_discard / *_strip
            flags, reject_non_syn_tcp and mptcp_option_strip (global|yes|no),
            asymmetric_path (global|drop|bypass), ipv6, non_ip_protocol,
            l2_sec_group_tag_protection.  Name max 31 characters.

        **Write safety (SSR pattern):** ``dry_run=True`` by default; a dry run
        reads only and returns the planned request.  ``ticket_ref`` is
        mandatory for every write action (dry runs included), is logged, and
        is never sent to SCM.  Writes are read back (``verified``).  No commit
        is performed: run scm_commit.

        Args:
            kind: wildfire_antivirus (or antivirus), url_access, decryption, zone_protection.
            action: list (default), get, create, update or delete.
            folder: Folder container (pass only one of folder, snippet, device).
            snippet: Snippet container.
            device: Device container.
            name: Profile name (create/update/delete/get target; list filter).
            profile_id: Profile UUID (get/update/delete).
            config_json: JSON object with the profile settings (create, update).
            dry_run: If True (default), preview a write without applying it.
            ticket_ref: Mandatory change-ticket reference for writes.
            skip_category_check: url_access only: skip the URL category lookup.
            acknowledge_unscanned_scope: delete only.  A profile in a top-level folder
                (All, Shared, Prisma Access, Global) or a snippet is inherited by
                containers that cannot all be enumerated.  Mobile Users and Remote
                Networks are scanned for a top-level folder, but the scan stays incomplete,
                so a real delete is refused unless this is True.  Dry runs show the
                warning and the refusal reason.
            limit: Maximum rows returned by list.
            tenant_id: SCM tenant ID.
        """
        spec = resolve_kind(kind)
        if spec is None:
            return f"Error: unknown kind {kind!r} - use one of: {', '.join(KINDS)}"
        if action not in _ACTIONS:
            return f"Error: unknown action {action!r} - use one of: {', '.join(_ACTIONS)}"
        scope, err = _scope(folder, snippet, device)
        if err:
            return f"Error: {err}"

        if action == "list":
            if not scope:
                return "Error: list needs one of folder, snippet or device"
            rows = _list_all(client, spec, scope)
            if name:
                rows = [r for r in rows if name.lower() in str(r.get("name", "")).lower()]
            shown = [_summary(r) for r in rows[: max(0, limit)]]
            return _fmt({"kind": spec.kind, "scope": scope, "total": len(rows), "items": shown})
        if action == "get":
            if profile_id:
                item = _fetch_by_id(client, spec, profile_id.strip())
            elif name and scope:
                item = _fetch(client, spec, name, scope)
            else:
                return "Error: get needs profile_id, or name with one of folder/snippet/device"
            if item is None:
                return f"Error: {spec.label} not found"
            return _fmt({"kind": spec.kind, "item": item})

        err = ticket_ref_error(ticket_ref)
        if err:
            return f"Error: {err}"
        ticket_ref = normalize_ticket_ref(ticket_ref)

        if action == "create":
            return _create(
                client,
                tenant_id,
                spec,
                scope,
                name,
                config_json,
                dry_run,
                ticket_ref,
                skip_category_check,
            )

        # update / delete need the existing profile
        if profile_id.strip():
            current = _fetch_by_id(client, spec, profile_id.strip())
        elif name and scope:
            current = _fetch(client, spec, name, scope)
        else:
            return f"Error: {action} needs profile_id, or name with one of folder/snippet/device"
        if current is None:
            return f"Error: {spec.label} not found"
        if action == "update":
            return _update(
                client,
                tenant_id,
                spec,
                current,
                config_json,
                dry_run,
                ticket_ref,
                skip_category_check,
            )
        return _delete(
            client, tenant_id, spec, current, dry_run, ticket_ref, acknowledge_unscanned_scope
        )
