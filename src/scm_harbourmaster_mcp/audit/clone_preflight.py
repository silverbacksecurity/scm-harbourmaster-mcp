"""
Reference preflight for scm_config_clone.

SCM accepts dangling references at create time and only rejects them when the
candidate config is pushed: one push (tens of minutes) per bad reference, and
push validation reports only the first one.  The preflight resolves every name
reference in the objects a clone will push before any write, so the clone dry
run reports all of them at once.

A reference resolves when the name is a keyword ("any", "application-default"),
an object already visible from the target folder (its own and inherited,
predefined content included), an object the clone itself creates, or PAN
predefined content carried in the backup.

Findings from the live restore that motivated this:
  * The applications API lists leaf App-IDs only.  Container apps ("zoom",
    "ms-office365", "dns") are never rows of their own, and a by-name GET
    404s for them, but every child names its container in ``container`` — so
    the catalogue is leaf names plus container values.
  * The backup's own ``applications`` list is the SOURCE tenant's catalogue,
    and a retired App-ID may still exist there; applications resolve against
    the target only.
  * A list call the service account may not read (DLP, AI Security) returns
    403.  Those references are "unverifiable", never "missing".
  * An enabled decrypt rule fails the push unless the target selects a
    forward-trust certificate, and certificates are not cloned.
  * The zones API lists nothing for the Prisma Access folders, whose rules
    use the built-in zones "trust" and "untrust"; those two are keywords.
  * The regions list holds the predefined countries and reserved ranges, so
    region names resolve from it.  IP literals in address fields resolve
    as themselves.

The same reference table drives the name_prefix rewrite in the cloner
(:func:`rewrite_references`), so the check and the rewrite cannot disagree.
"""

from __future__ import annotations

import ipaddress
import re
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from ..utils.logging import get_logger

logger = get_logger(__name__)

_HOST = "https://api.sase.paloaltonetworks.com"
_OBJECTS = f"{_HOST}/config/objects/v1"
_SECURITY = f"{_HOST}/config/security/v1"
_NETWORK = f"{_HOST}/config/network/v1"
_SSE = f"{_HOST}/sse/config/v1"
# The applications list takes ~18s per 1000-row page (~11 pages: every App-ID
# comes back twice), slowing to ~40s a page under concurrency; a 5000-row page
# 502s at the gateway.  Pages after the first are fetched in parallel.
_TIMEOUT = (5, 120)
_PAGE = 1000
_MAX_PAGES = 40
_PAGE_WORKERS = 10
_SOURCE_WORKERS = 6

# The config API reports the Prisma Access container as "Shared" on objects,
# but only accepts "Prisma Access" as a folder query parameter.
_API_FOLDER_ALIASES = {"Shared": "Prisma Access"}
_FOLDER_DOES_NOT_EXIST = ("doesn't exist", "does not exist", "API_I00013")

MISSING_REFERENCE_MODES = ("fail", "skip_object", "strip_member")
MISSING_TRUST_CERT_MODES = ("fail", "disable_rule", "skip_object")

# URL category lists on a URL access profile.  The predefined best-practice
# profile lists every predefined category, which gives the catalogue.
_URL_ACTION_LISTS = ("alert", "allow", "block", "continue", "override")


def _names(row: dict[str, Any]) -> Iterable[str]:
    return [row["name"]] if row.get("name") else []


def _app_names(row: dict[str, Any]) -> Iterable[str]:
    return [n for n in (row.get("name"), row.get("container")) if n]


def _category_values(row: dict[str, Any]) -> Iterable[str]:
    # url-filtering-categories rows are {"value": ..., "type": ...}
    return [str(row["value"])] if row.get("value") else []


def _url_profile_categories(row: dict[str, Any]) -> Iterable[str]:
    out: list[str] = []
    for key in _URL_ACTION_LISTS:
        value = row.get(key)
        if isinstance(value, list):
            out.extend(str(v) for v in value)
    return out


@dataclass(frozen=True)
class _Kind:
    label: str
    # (list URL, row → names).  An empty tuple means no read API is wired.
    sources: tuple[tuple[str, Callable[[dict[str, Any]], Iterable[str]]], ...]
    keywords: frozenset[str] = frozenset()


KINDS: dict[str, _Kind] = {
    "application": _Kind(
        "application",
        (
            (f"{_OBJECTS}/applications", _app_names),
            (f"{_OBJECTS}/application-groups", _names),
            (f"{_OBJECTS}/application-filters", _names),
        ),
        frozenset({"any"}),
    ),
    "service": _Kind(
        "service",
        ((f"{_OBJECTS}/services", _names), (f"{_OBJECTS}/service-groups", _names)),
        frozenset({"any", "application-default"}),
    ),
    "category": _Kind(
        "URL category",
        (
            (f"{_SECURITY}/url-categories", _names),
            # Every predefined PAN-DB category; the best-practice profile
            # below misses some (e.g. scanning-activity)
            (f"{_SECURITY}/url-filtering-categories", _category_values),
            (f"{_SECURITY}/url-access-profiles", _url_profile_categories),
            # URL-type EDLs are valid in a rule's category field
            (f"{_OBJECTS}/external-dynamic-lists", _names),
        ),
        frozenset({"any"}),
    ),
    "hip": _Kind(
        "HIP profile",
        ((f"{_OBJECTS}/hip-profiles", _names),),
        frozenset({"any", "no-hip"}),
    ),
    "profile_group": _Kind("profile group", ((f"{_SSE}/profile-groups", _names),)),
    "spyware": _Kind("anti-spyware profile", ((f"{_SECURITY}/anti-spyware-profiles", _names),)),
    "vulnerability": _Kind(
        "vulnerability profile",
        ((f"{_SECURITY}/vulnerability-protection-profiles", _names),),
    ),
    "virus_and_wildfire_analysis": _Kind(
        "WildFire/antivirus profile", ((f"{_SECURITY}/wildfire-anti-virus-profiles", _names),)
    ),
    "url_filtering": _Kind("URL access profile", ((f"{_SECURITY}/url-access-profiles", _names),)),
    "file_blocking": _Kind(
        "file blocking profile", ((f"{_SECURITY}/file-blocking-profiles", _names),)
    ),
    "dns_security": _Kind(
        "DNS security profile", ((f"{_SECURITY}/dns-security-profiles", _names),)
    ),
    "data_filtering": _Kind(
        "data filtering profile", ((f"{_SSE}/data-filtering-profiles", _names),)
    ),
    "saas_security": _Kind("SaaS security profile", ()),
    "ai_security": _Kind("AI security profile", ()),
    "decryption_profile": _Kind(
        "decryption profile", ((f"{_SECURITY}/decryption-profiles", _names),)
    ),
    "log_setting": _Kind(
        "log forwarding profile", ((f"{_OBJECTS}/log-forwarding-profiles", _names),)
    ),
    "address": _Kind(
        "address",
        (
            (f"{_OBJECTS}/addresses", _names),
            (f"{_OBJECTS}/address-groups", _names),
            # IP-type EDLs are valid in source/destination
            (f"{_OBJECTS}/external-dynamic-lists", _names),
            # Custom regions plus the predefined countries and reserved ranges
            (f"{_OBJECTS}/regions", _names),
        ),
        frozenset({"any"}),
    ),
    # Prisma Access rules use the built-in trust/untrust zones, which the
    # zones API does not list for its folders.
    "zone": _Kind("zone", ((f"{_NETWORK}/zones", _names),), frozenset({"any", "trust", "untrust"})),
    "tag": _Kind("tag", ((f"{_OBJECTS}/tags", _names),)),
}

# Backup keys whose objects, once cloned, satisfy references of these kinds.
# Custom applications are absent: the cloner does not push them.
PROVIDES: dict[str, tuple[str, ...]] = {
    "tags": ("tag",),
    "addresses": ("address",),
    "address_groups": ("address",),
    "zones": ("zone",),
    "application_groups": ("application",),
    "application_filters": ("application",),
    "services": ("service",),
    "service_groups": ("service",),
    "url_categories": ("category",),
    # An EDL is a URL list (categories) or an IP list (addresses)
    "edls": ("category", "address"),
    "hip_profiles": ("hip",),
    "profile_groups": ("profile_group",),
    "anti_spyware_profiles": ("spyware",),
    "vulnerability_profiles": ("vulnerability",),
    "wildfire_profiles": ("virus_and_wildfire_analysis",),
    "url_access_profiles": ("url_filtering",),
    "file_blocking_profiles": ("file_blocking",),
    "dns_security_profiles": ("dns_security",),
    "decryption_profiles": ("decryption_profile",),
    "log_forwarding_profiles": ("log_setting",),
}

_PROFILE_GROUP_FIELDS = (
    "spyware",
    "vulnerability",
    "virus_and_wildfire_analysis",
    "url_filtering",
    "file_blocking",
    "dns_security",
    "data_filtering",
    "saas_security",
    "ai_security",
)


@dataclass(frozen=True)
class _Ref:
    # Dotted path for nested fields.  Backups hold SDK field names, so a
    # rule's zones are under "from_"/"to_".
    field: str
    kind: str
    # Dropping a member narrows what the object matches.  Only safe for group
    # members and allow rules — see _can_strip.
    strippable: bool = False
    # The value is a tag-match expression ("'web' and not 'old'") rather than
    # a name or list of names.
    expression: bool = False


_TAG = _Ref("tag", "tag")
_ZONES = (_Ref("from_", "zone", True), _Ref("to_", "zone", True))
_ADDRESSES = (_Ref("source", "address", True), _Ref("destination", "address", True))


def _fixed(refs: Iterable[_Ref]) -> tuple[_Ref, ...]:
    """The same references, none strippable."""
    return tuple(_Ref(r.field, r.kind, False, r.expression) for r in refs)


_SECURITY_RULE_REFS = (
    *_ZONES,
    *_ADDRESSES,
    _Ref("application", "application", True),
    _Ref("service", "service", True),
    _Ref("category", "category", True),
    _Ref("source_hip", "hip", True),
    _Ref("destination_hip", "hip", True),
    _Ref("profile_setting.group", "profile_group"),
    _Ref("log_setting", "log_setting"),
    _TAG,
)

# Changing which traffic a NAT rule translates, or where to, is never safe,
# so nothing in a NAT rule is strippable.
_NAT_RULE_REFS = (
    *_fixed(_ZONES),
    *_fixed(_ADDRESSES),
    _Ref("service", "service"),
    _Ref("source_translation.dynamic_ip_and_port.translated_address", "address"),
    _Ref("source_translation.dynamic_ip.translated_address", "address"),
    _Ref("source_translation.static_ip.translated_address", "address"),
    _Ref("destination_translation.translated_address", "address"),
    _TAG,
)

REFERENCE_FIELDS: dict[str, tuple[_Ref, ...]] = {
    "addresses": (_TAG,),
    "address_groups": (
        _Ref("static", "address", True),
        _Ref("dynamic.filter", "tag", expression=True),
        _TAG,
    ),
    "services": (_TAG,),
    "service_groups": (_Ref("members", "service", True), _TAG),
    "application_groups": (_Ref("members", "application", True),),
    "profile_groups": tuple(_Ref(f, f) for f in _PROFILE_GROUP_FIELDS),
    # Removing a category from a block list loosens the profile
    "url_access_profiles": tuple(
        _Ref(f, "category") for f in ("alert", "allow", "block", "continue_", "continue")
    ),
    "security_rules_pre": _SECURITY_RULE_REFS,
    "security_rules_post": _SECURITY_RULE_REFS,
    "nat_rules_pre": _NAT_RULE_REFS,
    "nat_rules_post": _NAT_RULE_REFS,
    "nat_rules": _NAT_RULE_REFS,
    # Removing a match criterion from a decryption rule changes what gets
    # decrypted in either direction, so nothing there is strippable.
    "decryption_rules": (
        *_fixed(_ZONES),
        *_fixed(_ADDRESSES),
        _Ref("service", "service"),
        _Ref("category", "category"),
        _Ref("source_hip", "hip"),
        _Ref("destination_hip", "hip"),
        _Ref("profile", "decryption_profile"),
        _Ref("log_setting", "log_setting"),
        _TAG,
    ),
    "app_override_rules": (
        *_fixed(_ZONES),
        *_fixed(_ADDRESSES),
        _Ref("application", "application"),
        _TAG,
    ),
}

_SECURITY_RULE_KEYS = frozenset({"security_rules_pre", "security_rules_post"})
_RULE_KEYS = _SECURITY_RULE_KEYS | {
    "nat_rules_pre",
    "nat_rules_post",
    "nat_rules",
    "decryption_rules",
    "app_override_rules",
}
_GROUP_KEYS = frozenset({"application_groups", "service_groups", "address_groups"})
# Group key → the rule fields its members can stand in for
_GROUP_FIELDS = {
    "application_groups": ("application",),
    "service_groups": ("service",),
    "address_groups": ("source", "destination"),
}

# A tag expression: quoted names, parentheses, operators, bare names
_EXPR_TOKEN = re.compile(r"'[^']*'|\"[^\"]*\"|[()]|[^\s()]+")
_EXPR_OPERATORS = frozenset({"and", "or", "not"})


def _expression_names(expr: str) -> list[str]:
    names = []
    for token in _EXPR_TOKEN.findall(expr):
        if token in "()" or token.lower() in _EXPR_OPERATORS:
            continue
        names.append(token[1:-1] if token[0] in "'\"" else token)
    return [n for n in names if n]


def _rewrite_expression(expr: str, renames: dict[str, str]) -> str:
    def swap(m: re.Match[str]) -> str:
        token = m.group(0)
        quoted = token[0] in "'\""
        name = token[1:-1] if quoted else token
        if token in "()" or token.lower() in _EXPR_OPERATORS or name not in renames:
            return token
        new = renames[name]
        quote = token[0] if quoted else "'"
        return f"{quote}{new}{quote}" if quoted or " " in new else new

    return _EXPR_TOKEN.sub(swap, expr)


def is_ip_literal(value: str) -> bool:
    """An address field value that is an IP, network or range, not a name."""
    parts = value.split("-")
    try:
        if len(parts) == 2:
            ipaddress.ip_address(parts[0])
            ipaddress.ip_address(parts[1])
        else:
            ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return True


def _values(obj: dict[str, Any], path: str) -> list[str]:
    value: Any = obj
    for part in path.split("."):
        if not isinstance(value, dict):
            return []
        value = value.get(part)
    if isinstance(value, list):
        return [str(v) for v in value if v not in (None, "")]
    if isinstance(value, str) and value:
        return [value]
    return []


def _ref_values(obj: dict[str, Any], ref: _Ref) -> list[str]:
    values = _values(obj, ref.field)
    if ref.expression:
        return [n for v in values for n in _expression_names(v)]
    return values


def rewrite_references(
    key: str, obj: dict[str, Any], renames: dict[str, dict[str, str]]
) -> dict[str, Any]:
    """Point *obj*'s references at renamed objects, in place.

    *renames* maps kind → old name → new name, for the objects a clone
    creates under a ``name_prefix``.  Only the fields in REFERENCE_FIELDS
    are rewritten.
    """
    for ref in REFERENCE_FIELDS.get(key, ()):
        names = renames.get(ref.kind)
        if not names:
            continue
        *parents, leaf = ref.field.split(".")
        holder: Any = obj
        for part in parents:
            holder = holder.get(part) if isinstance(holder, dict) else None
        if not isinstance(holder, dict) or leaf not in holder:
            continue
        value = holder[leaf]
        if ref.expression and isinstance(value, str):
            holder[leaf] = _rewrite_expression(value, names)
        elif isinstance(value, list):
            holder[leaf] = [names.get(v, v) if isinstance(v, str) else v for v in value]
        elif isinstance(value, str):
            holder[leaf] = names.get(value, value)
    return obj


def _is_predefined(obj: dict[str, Any]) -> bool:
    return any(str(obj.get(f) or "").startswith("predefined") for f in ("snippet", "override_loc"))


# Snippet types SCM gives PAN-supplied snippets (Web-Security-Default,
# hip-default, Auto-VPN-Default-Snippet, ...).  "predefined-snippet" itself
# lists with a null type, so the name test above still applies.
PAN_SNIPPET_TYPES = frozenset({"predefined", "readonly"})


def pan_snippet(obj: dict[str, Any], snippet_types: dict[str, str] | None = None) -> str:
    """The PAN snippet *obj* comes from, or "" for the customer's own content.

    *snippet_types* maps snippet name → SCM snippet type.  Objects from PAN
    snippets are never cloned: the snippet is already in the target tenant.
    Only "predefined-snippet" content is visible from every folder; the other
    PAN snippets apply to the folders they are associated with.
    """
    if _is_predefined(obj):
        return str(obj.get("snippet") or obj.get("override_loc"))
    name = str(obj.get("snippet") or "")
    return name if name and (snippet_types or {}).get(name) in PAN_SNIPPET_TYPES else ""


# ── Target inventory ─────────────────────────────────────────────────────────


@dataclass
class TargetInventory:
    """Names visible from the target folder, per reference kind."""

    folder: str
    names: dict[str, set[str]] = field(default_factory=dict)
    # kind → why at least one of its sources could not be read
    unreadable: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


def _error_text(resp: Any) -> str:
    try:
        body = resp.json()
    except Exception:
        body = None
    if isinstance(body, dict):
        errors = body.get("_errors") or []
        if errors and isinstance(errors[0], dict):
            first = errors[0]
            details = first.get("details")
            if isinstance(details, dict) and details.get("message"):
                return f"HTTP {resp.status_code}: {details['message']}"
            return f"HTTP {resp.status_code}: {first.get('message') or first.get('code')}"
    return f"HTTP {resp.status_code}: {str(getattr(resp, 'text', ''))[:200]}"


def _get(session: Any, url: str, params: dict[str, Any]) -> Any:
    for attempt in range(2):
        resp = session.get(url, params=params, timeout=_TIMEOUT)
        if resp.status_code == 429 and attempt == 0:
            time.sleep(min(int(resp.headers.get("Retry-After", "10")), 30))
            continue
        return resp
    return resp


def _page(session: Any, url: str, folder: str, offset: int) -> tuple[Any, str]:
    """(response body, error) for one page."""
    try:
        resp = _get(session, url, {"folder": folder, "limit": _PAGE, "offset": offset})
    except Exception as exc:
        return None, str(exc)[:200]
    if resp.status_code != 200:
        return None, _error_text(resp)
    return resp.json(), ""


def _page_rows(body: Any) -> list[dict[str, Any]]:
    page = body.get("data", []) if isinstance(body, dict) else body
    return [r for r in page if isinstance(r, dict)] if isinstance(page, list) else []


def _list_rows(session: Any, url: str, folder: str) -> tuple[list[dict[str, Any]], str]:
    """Every row of a paginated list call, or ([], error) when it fails."""
    body, err = _page(session, url, folder, 0)
    if err:
        return [], err
    rows = _page_rows(body)
    total = body.get("total") if isinstance(body, dict) else None
    if len(rows) < _PAGE:
        return rows, ""
    if isinstance(total, int):
        offsets = list(range(_PAGE, min(total, _PAGE * _MAX_PAGES), _PAGE))
        with ThreadPoolExecutor(max_workers=_PAGE_WORKERS) as pool:
            pages = list(pool.map(lambda o: _page(session, url, folder, o), offsets))
        for page_body, page_err in pages:
            if page_err:
                return [], page_err
            rows.extend(_page_rows(page_body))
        return rows, "" if total <= _PAGE * _MAX_PAGES else f"stopped after {_MAX_PAGES} pages"
    # No total reported: walk pages until a short one
    for offset in range(_PAGE, _PAGE * _MAX_PAGES, _PAGE):
        page_body, err = _page(session, url, folder, offset)
        if err:
            return [], err
        page = _page_rows(page_body)
        rows.extend(page)
        if len(page) < _PAGE:
            return rows, ""
    return rows, f"stopped after {_MAX_PAGES} pages"


def fetch_target_inventory(session: Any, target_folder: str) -> TargetInventory:
    """Read every reference catalogue visible from *target_folder*.

    List calls on a folder return its own objects plus everything inherited,
    predefined snippets included.  A folder that does not exist yet (a clone
    into a new folder) falls back to "All", which holds the predefined and
    tenant-wide content every folder inherits.
    """
    folder = _API_FOLDER_ALIASES.get(target_folder, target_folder)
    inv = TargetInventory(folder=folder)
    cache: dict[str, tuple[list[dict[str, Any]], str]] = {}

    def rows(url: str) -> tuple[list[dict[str, Any]], str]:
        if url not in cache:
            cache[url] = _list_rows(session, url, inv.folder)
        return cache[url]

    _, probe_err = rows(f"{_OBJECTS}/services")
    if probe_err and any(m in probe_err for m in _FOLDER_DOES_NOT_EXIST):
        inv.notes.append(
            f"Target folder `{target_folder}` does not exist yet — references were checked "
            "against the tenant-wide `All` folder."
        )
        inv.folder = "All"
        cache.clear()

    urls = sorted({url for spec in KINDS.values() for url, _ in spec.sources} - set(cache))
    with ThreadPoolExecutor(max_workers=_SOURCE_WORKERS) as pool:
        for url, fetched in zip(
            urls, pool.map(lambda u: _list_rows(session, u, inv.folder), urls), strict=True
        ):
            cache[url] = fetched

    for kind, spec in KINDS.items():
        found: set[str] = set()
        if not spec.sources:
            inv.unreadable[kind] = "no list API for this profile type"
        for url, extract in spec.sources:
            items, err = rows(url)
            if err:
                inv.unreadable[kind] = f"{url.rsplit('/', 1)[-1]}: {err}"
                continue
            for row in items:
                found.update(extract(row))
        inv.names[kind] = found
    logger.info(
        "clone_preflight_inventory",
        folder=inv.folder,
        counts={k: len(v) for k, v in inv.names.items()},
        unreadable=sorted(inv.unreadable),
    )
    return inv


# ── Reference check ──────────────────────────────────────────────────────────


@dataclass
class RefIssue:
    referrer_type: str
    referrer: str
    field: str
    kind: str
    name: str
    status: str  # "missing" | "unverifiable"
    detail: str = ""
    action: str = ""  # "", "skipped", "stripped"


@dataclass
class PreflightResult:
    target_folder: str
    on_missing_reference: str
    issues: list[RefIssue] = field(default_factory=list)
    # (backup key, object name) → reason
    skip: dict[tuple[str, str], str] = field(default_factory=dict)
    # (backup key, object name) → field → names to drop
    strip: dict[tuple[str, str], dict[str, set[str]]] = field(default_factory=dict)
    disable: set[tuple[str, str]] = field(default_factory=set)
    trust_state: str = ""
    decrypt_rules: list[str] = field(default_factory=list)
    block_reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    unreadable: dict[str, str] = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        return bool(self.block_reasons)

    @property
    def missing(self) -> list[RefIssue]:
        return [i for i in self.issues if i.status == "missing"]

    @property
    def unverifiable(self) -> list[RefIssue]:
        return [i for i in self.issues if i.status == "unverifiable"]

    def to_markdown(self, dry_run: bool) -> list[str]:
        lines = ["\n## Reference preflight\n"]
        lines.append(
            f"References checked against target folder `{self.target_folder}` "
            f"(`on_missing_reference={self.on_missing_reference}`)."
        )
        lines += [f"\n{n}" for n in self.notes]
        if self.blocked:
            verb = "A real run would stop here" if dry_run else "Nothing was pushed"
            lines.append(f"\n**❌ Blocked — {verb}:**")
            lines += [f"- {r}" for r in self.block_reasons]
        if not self.issues and not self.warnings and not self.decrypt_rules:
            lines.append("\n✅ Every reference resolves.")
            return lines
        lines.append(
            f"\n**Missing:** {len(self.missing)}  |  **Unverifiable:** {len(self.unverifiable)}"
        )
        if self.issues:
            lines.append("\n| Referenced by | Field | Name | Status | Action |")
            lines.append("|---|---|---|---|---|")
            for i in self.issues:
                detail = f" — {i.detail}" if i.detail else ""
                lines.append(
                    f"| {i.referrer_type} `{i.referrer}` | {i.field} | "
                    f"{KINDS[i.kind].label} `{i.name}` | {i.status}{detail} | {i.action or '—'} |"
                )
        if self.unreadable:
            lines.append("\n**Unreadable catalogues** (references to these are unverifiable):")
            lines += [f"- {KINDS[k].label}: {why}" for k, why in sorted(self.unreadable.items())]
        if self.decrypt_rules:
            lines.append(
                f"\n**Forward-trust certificate ({self.trust_state}):** enabled decrypt rules "
                + ", ".join(f"`{n}`" for n in self.decrypt_rules)
            )
        if self.warnings:
            lines.append("")
            lines += [f"- ⚠️ {w}" for w in self.warnings]
        return lines


def _can_strip(key: str, obj: dict[str, Any], ref: _Ref) -> bool:
    if not ref.strippable:
        return False
    if key in _SECURITY_RULE_KEYS:
        # Narrowing a deny/drop/reset rule lets through what the source denied,
        # and dropping a member of a negated list widens the rule.
        if ref.field in ("source", "destination") and obj.get(f"negate_{ref.field}"):
            return False
        return str(obj.get("action") or "") == "allow"
    return key in _GROUP_KEYS


def check_references(
    resources: dict[str, Any],
    planned_keys: list[str],
    inventory: TargetInventory,
    *,
    name_prefix: str = "",
    on_missing_reference: str = "fail",
    trust_state: Callable[[], str] | None = None,
    on_missing_trust_cert: str = "fail",
    snippet_types: dict[str, str] | None = None,
) -> PreflightResult:
    """Resolve every reference in the objects of *planned_keys*.

    *planned_keys* are the backup keys the clone will push, in push order.
    *trust_state* returns the target's forward-trust state ("configured",
    "missing" or "unknown"); it is only called when an enabled decrypt rule
    would be pushed.  *snippet_types* (snippet name → SCM type) marks objects
    from PAN snippets, which the clone does not create.
    """
    result = PreflightResult(
        target_folder=inventory.folder,
        on_missing_reference=on_missing_reference,
        notes=list(inventory.notes),
    )

    def objects(key: str) -> list[dict[str, Any]]:
        value = resources.get(key) or []
        return [o for o in value if isinstance(o, dict) and not pan_snippet(o, snippet_types)]

    # Names the clone creates, by kind (as named in the target)
    created: dict[str, dict[str, tuple[str, str]]] = {}
    for key in planned_keys:
        for kind in PROVIDES.get(key, ()):
            for obj in objects(key):
                name = str(obj.get("name", ""))
                created.setdefault(kind, {})[f"{name_prefix}{name}"] = (key, name)
    # PAN predefined content is in every tenant.  Applications are excluded:
    # the backup's catalogue is the source tenant's content version.
    # Other PAN snippets reach only the folders they are associated with, so
    # their objects resolve against the target inventory like any other.
    predefined: dict[str, set[str]] = {}
    in_pan_snippet: dict[str, dict[str, str]] = {}
    for key, kinds in PROVIDES.items():
        for obj in resources.get(key) or []:
            if not (isinstance(obj, dict) and obj.get("name")):
                continue
            snippet = pan_snippet(obj, snippet_types)
            for kind in kinds:
                if _is_predefined(obj):
                    predefined.setdefault(kind, set()).add(str(obj["name"]))
                elif snippet:
                    in_pan_snippet.setdefault(kind, {})[str(obj["name"])] = snippet

    def resolve(kind: str, name: str) -> tuple[str, str]:
        if name in KINDS[kind].keywords or name in predefined.get(kind, set()):
            return "", ""
        if kind == "address" and is_ip_literal(name):
            return "", ""
        # The cloner rewrites a reference to the copy it creates, so that copy
        # wins over a same-named object already in the target.
        owner = created.get(kind, {}).get(f"{name_prefix}{name}")
        if owner and owner not in result.skip:
            return "", ""
        if name in inventory.names.get(kind, set()):
            return "", ""
        if owner:
            return "missing", f"skipped by preflight: {result.skip[owner]}"
        hint = ""
        snippet = in_pan_snippet.get(kind, {}).get(name)
        if snippet:
            hint = (
                f"from PAN snippet `{snippet}` in the source, which the target folder "
                "does not see — associate the snippet with the target folder"
            )
        elif kind == "application":
            hint = (
                "no App-ID, application group or application filter of that name in the "
                "target (a retired App-ID, or a custom application, which the clone does "
                "not create)"
            )
        if kind in inventory.unreadable:
            return "unverifiable", inventory.unreadable[kind]
        return "missing", hint

    # Re-run until skips stop cascading: a skipped group turns every
    # reference to it into a missing one.
    for _ in range(sum(len(objects(k)) for k in planned_keys) + 1):
        result.issues = []
        result.strip = {}
        new_skip = False
        for key in planned_keys:
            refs = REFERENCE_FIELDS.get(key)
            if not refs:
                continue
            for obj in objects(key):
                oid = (key, str(obj.get("name", "")))
                obj_issues: list[tuple[_Ref, RefIssue]] = []
                for ref in refs:
                    for name in _ref_values(obj, ref):
                        status, detail = resolve(ref.kind, name)
                        if status:
                            obj_issues.append(
                                (
                                    ref,
                                    RefIssue(
                                        key, oid[1], ref.field, ref.kind, name, status, detail
                                    ),
                                )
                            )
                result.issues += [i for _, i in obj_issues]
                missing = [(ref, i) for ref, i in obj_issues if i.status == "missing"]
                if not missing or on_missing_reference == "fail":
                    continue
                if oid in result.skip:
                    for _, i in missing:
                        i.action = "skipped"
                    continue
                skip_reason = ""
                strips: dict[str, set[str]] = {}
                if on_missing_reference == "skip_object":
                    skip_reason = "unresolved reference"
                else:
                    for ref, i in missing:
                        if not _can_strip(key, obj, ref):
                            why = (
                                f"stripping would narrow a `{obj.get('action')}` rule"
                                if ref.strippable
                                else "dropping it would loosen policy"
                            )
                            skip_reason = f"`{i.name}` in {ref.field}: {why}"
                            break
                        strips.setdefault(ref.field, set()).add(i.name)
                    for fld, bad in strips.items():
                        if not skip_reason and not set(_values(obj, fld)) - bad:
                            skip_reason = f"{fld} would be empty after stripping"
                if skip_reason:
                    result.skip[oid] = skip_reason
                    new_skip = True
                    for _, i in missing:
                        i.action = "skipped"
                else:
                    result.strip[oid] = strips
                    for _, i in missing:
                        i.action = "stripped"
        if not new_skip:
            break

    if result.missing and on_missing_reference == "fail":
        result.block_reasons.append(
            f"{len(result.missing)} unresolved reference(s). Fix them in the target, or rerun "
            "with on_missing_reference='skip_object' or 'strip_member'."
        )
    result.unreadable = {
        k: why for k, why in inventory.unreadable.items() if any(i.kind == k for i in result.issues)
    }

    # A stripped group narrows every rule that uses it.  That is only safe
    # for an allow rule matching on the group directly.
    for key, name in result.strip:
        if key not in _GROUP_KEYS:
            continue
        users = []
        for rk in _RULE_KEYS & set(planned_keys):
            for r in objects(rk):
                rname = str(r.get("name"))
                if (rk, rname) in result.skip:
                    continue
                fields = [f for f in _GROUP_FIELDS[key] if name in _values(r, f)]
                safe = rk in _SECURITY_RULE_KEYS and str(r.get("action") or "") == "allow"
                negated = any(r.get(f"negate_{f}") for f in fields)
                if fields and (not safe or negated):
                    users.append(rname)
        if users:
            result.warnings.append(
                f"Stripped group `{name}` is used by rule(s) "
                + ", ".join(f"`{u}`" for u in users)
                + " that are not plain allow rules — they will match differently than in "
                "the source (a deny or NAT rule covers less; a negated match covers more)."
            )

    _check_decrypt_prerequisite(result, objects, planned_keys, trust_state, on_missing_trust_cert)
    return result


def _check_decrypt_prerequisite(
    result: PreflightResult,
    objects: Callable[[str], list[dict[str, Any]]],
    planned_keys: list[str],
    trust_state: Callable[[], str] | None,
    mode: str,
) -> None:
    if "decryption_rules" not in planned_keys or trust_state is None:
        return
    enabled = [
        str(r.get("name"))
        for r in objects("decryption_rules")
        if r.get("action") == "decrypt"
        and not r.get("disabled")
        and ("decryption_rules", str(r.get("name"))) not in result.skip
    ]
    if not enabled:
        return
    state = trust_state()
    result.trust_state = state
    if state == "configured":
        return
    result.decrypt_rules = enabled
    why = (
        "the target has no forward-trust certificate selected"
        if state == "missing"
        else "the target's SSL decryption settings are unreadable, so the certificate was not checked"
    )
    if mode == "disable_rule":
        result.disable.update(("decryption_rules", n) for n in enabled)
        result.warnings.append(
            f"{len(enabled)} enabled decrypt rule(s) will be created disabled: {why}."
        )
    elif mode == "skip_object":
        for n in enabled:
            result.skip[("decryption_rules", n)] = "no forward-trust certificate"
        result.warnings.append(f"{len(enabled)} enabled decrypt rule(s) skipped: {why}.")
    elif state == "missing":
        result.block_reasons.append(
            f"{len(enabled)} enabled decrypt rule(s), but {why} — the push would fail with "
            "'forward decrypt trust cert is not configured'. Select one in SSL decryption "
            "settings, or rerun with on_missing_trust_cert='disable_rule' or 'skip_object'."
        )
    else:
        result.warnings.append(
            f"{len(enabled)} enabled decrypt rule(s): {why}. If none is selected the push "
            "fails — consider on_missing_trust_cert='disable_rule'."
        )
