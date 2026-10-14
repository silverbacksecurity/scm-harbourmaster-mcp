"""PAN-OS / Panorama XML export → scm_config_backup-shaped dict.

``scm_panorama_migrate`` turns an offline config export into the same JSON
``scm_config_backup`` writes, then hands it to ``clone_config``.  The clone
already owns the dependency-ordered push, the reference preflight,
``on_conflict``, ``name_prefix`` and the report, so this module only
translates.

Sources: a Panorama export (one device group, plus its parent device groups
and ``shared``) or a standalone firewall export (one vsys plus ``shared``).
Objects resolve nearest scope first, as PAN-OS does: a device-group object
hides a ``shared`` object of the same name.  Rules keep PAN-OS evaluation
order: shared pre → ancestor pre → device-group pre, then device-group post →
ancestor post → shared post.

Conversion is generic: PAN-OS XML and the SCM API share their field names
(hyphens become underscores, ``<member>`` lists become lists, ``<entry>``
lists become lists of named dicts).  Each object is validated against the
pan-scm-sdk create model; fields the model doesn't have are dropped and
reported, and an object that still doesn't validate is reported and left
out.  Nothing is dropped silently: every gap is a :class:`PlanItem`.

Parsing uses defusedxml (no DTDs, no entity expansion).  Not written against
any real customer export: the fixtures in tests are synthetic.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Set
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any
from xml.etree.ElementTree import Element

import defusedxml.ElementTree as SafeET
from pydantic import BaseModel, ValidationError
from scm.models.network.nat_rules import NatRuleCreateModel
from scm.models.objects.address import AddressCreateModel
from scm.models.objects.address_group import AddressGroupCreateModel
from scm.models.objects.application_group import ApplicationGroupCreateModel
from scm.models.objects.external_dynamic_lists import ExternalDynamicListsCreateModel
from scm.models.objects.service import ServiceCreateModel
from scm.models.objects.service_group import ServiceGroupCreateModel
from scm.models.objects.tag import TagCreateModel
from scm.models.security.anti_spyware_profiles import AntiSpywareProfileCreateModel
from scm.models.security.app_override_rules import AppOverrideRuleCreateModel
from scm.models.security.decryption_profiles import DecryptionProfileCreateModel
from scm.models.security.decryption_rules import DecryptionRuleCreateModel
from scm.models.security.file_blocking_profiles import FileBlockingProfileCreateModel
from scm.models.security.security_rules import SecurityRuleCreateModel
from scm.models.security.url_access_profiles import URLAccessProfileCreateModel
from scm.models.security.url_categories import URLCategoriesCreateModel
from scm.models.security.vulnerability_protection_profiles import (
    VulnerabilityProfileCreateModel,
)
from scm.models.security.wildfire_antivirus_profiles import WildfireAvProfileCreateModel

# Panorama exports run to tens of MB; anything far beyond is not a config.
MAX_XML_BYTES = 256 * 1024 * 1024

# Revalidation rounds after stripping nested fields a model forbids
_MAX_STRIP_ROUNDS = 5

# PlanItem.action values
GENERATED = "generated"  # created by the migration (profile groups for rules)
MANUAL = "manual"  # needs a person: SCM has no API for it
DROPPED = "dropped"  # a field or reference left out; the object is migrated
UNSUPPORTED = "unsupported"  # the whole object or section is not migrated
OVERRIDDEN = "overridden"  # hidden by a nearer scope's object of the same name
INVALID = "invalid"  # failed SDK validation; not migrated
REVIEW = "review"  # migrated, but its meaning changed — check before pushing

# Plan sections, in report order
_ACTION_TITLES = {
    REVIEW: "Migrated with a change in meaning: review before pushing",
    MANUAL: "Needs doing by hand in SCM",
    UNSUPPORTED: "Not migrated",
    INVALID: "Failed validation (not migrated)",
    DROPPED: "Fields or references left out",
    GENERATED: "Generated",
    OVERRIDDEN: "Hidden by a nearer scope",
}

# PAN-OS tag colour codes → SCM colour names (pan-scm-sdk Colors)
TAG_COLORS = {
    "color1": "Red",
    "color2": "Green",
    "color3": "Blue",
    "color4": "Yellow",
    "color5": "Copper",
    "color6": "Orange",
    "color7": "Purple",
    "color8": "Gray",
    "color9": "Light Green",
    "color10": "Cyan",
    "color11": "Light Gray",
    "color12": "Blue Gray",
    "color13": "Lime",
    "color14": "Black",
    "color15": "Gold",
    "color16": "Brown",
    "color17": "Olive",
    "color19": "Maroon",
    "color20": "Red-Orange",
    "color21": "Yellow-Orange",
    "color22": "Forest Green",
    "color23": "Turquoise Blue",
    "color24": "Azure Blue",
    "color25": "Cerulean Blue",
    "color26": "Midnight Blue",
    "color27": "Medium Blue",
    "color28": "Cobalt Blue",
    "color29": "Violet Blue",
    "color30": "Blue Violet",
    "color31": "Medium Violet",
    "color32": "Medium Rose",
    "color33": "Lavender",
    "color34": "Orchid",
    "color35": "Thistle",
    "color36": "Peach",
    "color37": "Salmon",
    "color38": "Magenta",
    "color39": "Red Violet",
    "color40": "Mahogany",
    "color41": "Burnt Sienna",
    "color42": "Chestnut",
}

# PAN-OS profile-group / rule profile type → SCM profile-group field.  None:
# not migrated (antivirus has no SCM API; data filtering is SCM DLP).
PROFILE_TYPES: dict[str, str | None] = {
    "spyware": "spyware",
    "vulnerability": "vulnerability",
    "url-filtering": "url_filtering",
    "file-blocking": "file_blocking",
    "wildfire-analysis": "virus_and_wildfire_analysis",
    "virus": None,
    "data-filtering": None,
}


class PanosImportError(ValueError):
    """The file is not a usable PAN-OS config export."""


@dataclass
class PlanItem:
    kind: str  # backup key, or the PAN-OS section for unsupported ones
    name: str
    action: str
    reason: str


@dataclass
class Conversion:
    backup: dict[str, Any]
    items: list[PlanItem] = field(default_factory=list)
    # "Panorama device group `dg`" / "firewall vsys `vsys1`"
    source: str = ""
    # Scope labels, nearest first
    scopes: list[str] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        return {k: len(v) for k, v in self.backup["resources"].items() if v}


# ── Parsing ─────────────────────────────────────────────────────────────────


def load_xml(path: str | Path) -> Element:
    """Parse a config export safely; raises PanosImportError."""
    p = Path(path)
    if not p.is_file():
        raise PanosImportError(f"{path}: not a file")
    size = p.stat().st_size
    if size > MAX_XML_BYTES:
        raise PanosImportError(f"{path}: {size} bytes is over the {MAX_XML_BYTES} byte limit")
    try:
        root = SafeET.parse(str(p), forbid_dtd=True).getroot()
    except SafeET.ParseError as exc:
        raise PanosImportError(f"{path}: not well-formed XML ({exc})") from exc
    except Exception as exc:  # defusedxml raises its own types for DTDs/entities
        raise PanosImportError(f"{path}: refused ({type(exc).__name__}: {exc})") from exc
    if root is None or root.tag != "config":
        tag = root.tag if root is not None else "none"
        raise PanosImportError(f"{path}: root element is <{tag}>, expected <config>")
    return root


def _key(tag: str) -> str:
    return tag.replace("-", "_")


def _value(el: Element) -> Any:
    """Generic PAN-OS XML → SCM JSON value."""
    kids = list(el)
    if not kids:
        text = (el.text or "").strip()
        return text if text else {}
    if all(k.tag == "member" for k in kids):
        return [(k.text or "").strip() for k in kids]
    if all(k.tag == "entry" for k in kids):
        return [_entry(k) for k in kids]
    return {_key(k.tag): _value(k) for k in kids}


def _entry(el: Element) -> dict[str, Any]:
    out: dict[str, Any] = {"name": el.get("name", "")}
    if len(el):
        v = _value(el)
        if isinstance(v, dict):
            out.update(v)
    return out


def _members(el: Element | None) -> list[str]:
    return [(m.text or "").strip() for m in el.findall("member")] if el is not None else []


# ── Scopes ──────────────────────────────────────────────────────────────────


@dataclass
class _Scope:
    label: str
    el: Element


def _named(parent: Element | None, path: str) -> dict[str, Element]:
    if parent is None:
        return {}
    return {e.get("name", ""): e for e in parent.findall(path)}


def _parent_dg(root: Element, name: str) -> str:
    for path in (
        "readonly/devices/entry/device-group/entry",
        "readonly/dg-meta-data/dg-info/entry",
    ):
        for e in root.findall(path):
            if e.get("name") == name:
                return (e.findtext("parent-dg") or "").strip()
    return ""


def _scopes(root: Element, device_group: str, vsys: str) -> tuple[str, list[_Scope]]:
    """(source label, scopes nearest first, ending with shared)."""
    dev = root.find("devices/entry")
    groups = _named(dev, "device-group/entry")
    shared = root.find("shared")
    tail = [_Scope("shared", shared)] if shared is not None else []
    if groups:
        if vsys:
            raise PanosImportError("this is a Panorama export: pass device_group, not vsys")
        if not device_group:
            raise PanosImportError(
                "Panorama export: pass device_group (one of: " + ", ".join(sorted(groups)) + ")"
            )
        if device_group not in groups:
            raise PanosImportError(
                f"device group `{device_group}` not found (have: " + ", ".join(sorted(groups)) + ")"
            )
        chain = [device_group]
        while True:
            parent = _parent_dg(root, chain[-1])
            if not parent or parent in chain or parent not in groups:
                break
            chain.append(parent)
        scopes = [_Scope(f"device group `{dg}`", groups[dg]) for dg in chain]
        return f"Panorama device group `{device_group}`", scopes + tail
    systems = _named(dev, "vsys/entry")
    if not systems:
        raise PanosImportError("no device groups or vsys found: not a Panorama or firewall export")
    if device_group:
        raise PanosImportError("this is a firewall export: pass vsys, not device_group")
    vsys = vsys or "vsys1"
    if vsys not in systems:
        raise PanosImportError(f"vsys `{vsys}` not found (have: {', '.join(sorted(systems))})")
    return f"firewall vsys `{vsys}`", [_Scope(f"vsys `{vsys}`", systems[vsys]), *tail]


# ── Validation ──────────────────────────────────────────────────────────────


@cache
def _model_fields(model: type[BaseModel]) -> frozenset[str]:
    aliases = {f.alias for f in model.model_fields.values() if f.alias}
    return frozenset(model.model_fields) | aliases


def _errors(exc: ValidationError) -> str:
    parts = []
    for e in exc.errors()[:3]:
        loc = ".".join(str(x) for x in e["loc"])
        parts.append(f"{loc}: {e['msg']}")
    more = f" (+{exc.error_count() - 3} more)" if exc.error_count() > 3 else ""
    return "; ".join(parts) + more


def _validate(
    spec: type[BaseModel] | Set[str],
    key: str,
    obj: dict[str, Any],
    items: list[PlanItem],
) -> dict[str, Any] | None:
    """Drop fields the model lacks (reported), validate, return the SDK-shaped
    dict without the container, or None (reported) when it doesn't validate.

    *spec* is the SDK create model, or for kinds pushed over REST the set of
    API keys allowed.  *obj* is consumed: nested fields are stripped in place.
    """
    name = str(obj.get("name") or "")
    known = _model_fields(spec) if isinstance(spec, type) else spec
    extra = sorted(k for k in obj if k not in known)
    if extra:
        items.append(PlanItem(key, name, DROPPED, "not in SCM: " + ", ".join(extra)))
        obj = {k: v for k, v in obj.items() if k in known}
    if not isinstance(spec, type):
        return obj
    model = spec
    # Nested keys a model forbids are stripped and the object validated again,
    # so one unknown field (a newer PAN-OS option, say) doesn't cost the whole
    # object.  Any other error keeps it out.
    stripped: list[str] = []
    for _ in range(_MAX_STRIP_ROUNDS):
        try:
            m = model.model_validate({**obj, "folder": "migration"})
            break
        except ValidationError as exc:
            extra_locs = [e["loc"] for e in exc.errors() if e["type"] == "extra_forbidden"]
            if len(extra_locs) != exc.error_count() or not all(
                _remove(obj, loc) for loc in extra_locs
            ):
                items.append(PlanItem(key, name, INVALID, _errors(exc)))
                return None
            stripped += [_loc_path(loc) for loc in extra_locs]
    else:
        items.append(PlanItem(key, name, INVALID, "too many unknown nested fields"))
        return None
    out = m.model_dump(mode="json", exclude_unset=True, exclude_none=True)
    out.pop("folder", None)
    # Nested models that ignore unknown keys drop them without an error
    lost = sorted(set(stripped) | (_paths(obj) - _paths(out)))
    if lost:
        items.append(
            PlanItem(
                key,
                name,
                REVIEW,
                "nested fields not in SCM, left out: " + ", ".join(lost),
            )
        )
    return out


def _remove(obj: Any, loc: tuple[Any, ...]) -> bool:
    """Delete the key at a pydantic error location; False when it isn't there."""
    cur = obj
    for part in loc[:-1]:
        in_dict = isinstance(cur, dict) and part in cur
        in_list = isinstance(cur, list) and isinstance(part, int) and part < len(cur)
        if not (in_dict or in_list):
            return False
        cur = cur[part]
    if isinstance(cur, dict) and loc and loc[-1] in cur:
        del cur[loc[-1]]
        return True
    return False


def _loc_path(loc: tuple[Any, ...]) -> str:
    return ".".join("[]" if isinstance(x, int) else str(x) for x in loc).replace(".[]", "[]")


def _paths(value: Any, prefix: str = "") -> set[str]:
    """Nested key paths of a JSON value (list items share their parent's path)."""
    out: set[str] = set()
    if isinstance(value, dict):
        for k, v in value.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            if prefix:
                out.add(path)
            out |= _paths(v, path)
    elif isinstance(value, list):
        for v in value:
            out |= _paths(v, prefix + "[]")
    return out


# ── Per-kind fixups (run before validation) ─────────────────────────────────


Fixup = Callable[[dict[str, Any], list[PlanItem]], None]


def _fix_tag(o: dict[str, Any], items: list[PlanItem]) -> None:
    code = o.pop("color", None)
    if code:
        color = TAG_COLORS.get(str(code))
        if color:
            o["color"] = color
        else:
            items.append(PlanItem("tags", o["name"], DROPPED, f"colour `{code}` has no SCM name"))


def _fix_service(o: dict[str, Any], items: list[PlanItem]) -> None:
    for proto in ("tcp", "udp"):
        p = (o.get("protocol") or {}).get(proto)
        if not isinstance(p, dict):
            continue
        if p.pop("source_port", None):
            items.append(
                PlanItem(
                    "services",
                    o["name"],
                    REVIEW,
                    "source port dropped: SCM services match destination ports only, "
                    "so this service now matches any source port",
                )
            )
        override = p.pop("override", None)
        if isinstance(override, dict) and isinstance(override.get("yes"), dict):
            p["override"] = override["yes"]


def _fix_edl(o: dict[str, Any], items: list[PlanItem]) -> None:
    for spec in (o.get("type") or {}).values():
        if isinstance(spec, dict) and isinstance(spec.get("auth"), dict):
            spec.pop("auth")
            items.append(
                PlanItem(
                    "edls",
                    o["name"],
                    MANUAL,
                    "list credentials not migrated (the export holds them encrypted "
                    "with the device master key): set them in SCM",
                )
            )


# Application filters go over REST in the clone, in the API's own field names
# (pan-scm-sdk's model says sub_category and has no tagging, the tag match).
_APP_FILTER_LISTS = {
    "category",
    "subcategory",
    "technology",
    "saas_certifications",
    "saas_risk",
    "exclude",
}
_APP_FILTER_FLAGS = {
    "evasive",
    "excessive_bandwidth_use",
    "used_by_malware",
    "transfers_files",
    "has_known_vulnerabilities",
    "tunnels_other_apps",
    "prone_to_misuse",
    "pervasive",
    "is_saas",
    "new_appid",
}
_APP_FILTER_KEYS = frozenset({"name", "risk", "tagging", *_APP_FILTER_LISTS, *_APP_FILTER_FLAGS})


def _yes(value: Any) -> bool:
    return str(value).strip().lower() in ("yes", "true")


def _fix_app_filter(o: dict[str, Any], items: list[PlanItem]) -> None:
    for k in _APP_FILTER_FLAGS & set(o):
        o[k] = _yes(o[k])
    if "risk" in o:
        try:
            o["risk"] = [int(r) for r in o["risk"]]
        except (TypeError, ValueError):
            items.append(PlanItem("application_filters", o["name"], DROPPED, "risk not numeric"))
            o.pop("risk")
    tagging = o.get("tagging")
    if isinstance(tagging, dict) and "no_tag" in tagging:
        o["tagging"] = {"no_tag": _yes(tagging["no_tag"])}


def _fix_spyware(o: dict[str, Any], items: list[PlanItem]) -> None:
    if o.pop("botnet_domains", None):
        items.append(
            PlanItem(
                "anti_spyware_profiles",
                o["name"],
                DROPPED,
                "DNS policy (botnet-domains) not migrated: SCM keeps it in a DNS "
                "Security profile (see scm_create_dns_security_snippet)",
            )
        )


def _fix_url(o: dict[str, Any], items: list[PlanItem]) -> None:
    for scope in (o, o.get("credential_enforcement")):
        if isinstance(scope, dict) and "continue" in scope:
            scope["continue_"] = scope.pop("continue")
    if o.pop("override", None):
        items.append(
            PlanItem(
                "url_access_profiles",
                o["name"],
                REVIEW,
                "categories set to `override` not migrated: SCM has no override "
                "action, so they fall back to the default (allow)",
            )
        )


_RULE_DROPS = {
    "target": "device targeting (SCM scopes by folder)",
    "uuid": "",
    "group_tag": "",
    "option": "",
    "qos": "QoS marking",
    "hip_profiles": "legacy HIP profiles (use source_hip)",
}


def _fix_rule(key: str, kind: str, o: dict[str, Any], items: list[PlanItem]) -> bool:
    """Rename and drop rule fields before validation; False skips the rule."""
    for xml_key, scm_key in (("from", "from_"), ("to", "to_")):
        if xml_key in o:
            o[scm_key] = o.pop(xml_key)
    for k, why in _RULE_DROPS.items():
        if k in o:
            o.pop(k)
            if why:
                items.append(PlanItem(key, o["name"], DROPPED, why))
    if o.pop("schedule", None):
        items.append(
            PlanItem(
                key,
                o["name"],
                REVIEW,
                "schedule dropped (schedules aren't migrated): the rule is now always active",
            )
        )
    rule_type = o.pop("rule_type", None)
    if rule_type and rule_type != "universal":
        items.append(
            PlanItem(
                key,
                o["name"],
                REVIEW,
                f"rule type `{rule_type}` isn't in SCM: migrated as universal",
            )
        )
    if kind == "decryption":
        # PAN-OS 10+ names the logging fields after the handshake
        for xml_key, scm_key in (
            ("log_successful_tls_handshakes", "log_success"),
            ("log_failed_tls_handshakes", "log_fail"),
        ):
            if xml_key in o:
                o[scm_key] = o.pop(xml_key)
    if kind == "nat" and o.pop("dynamic_destination_translation", None):
        items.append(PlanItem(key, o["name"], UNSUPPORTED, "dynamic destination translation"))
        return False
    return True


# Object kinds: backup key → (path under the scope, SDK model or, for kinds
# the clone pushes over REST, the API's own keys, fixup)
_OBJECTS: list[tuple[str, str, type[BaseModel] | Set[str], Fixup | None]] = [
    ("tags", "tag/entry", TagCreateModel, _fix_tag),
    ("addresses", "address/entry", AddressCreateModel, None),
    ("address_groups", "address-group/entry", AddressGroupCreateModel, None),
    ("services", "service/entry", ServiceCreateModel, _fix_service),
    ("service_groups", "service-group/entry", ServiceGroupCreateModel, None),
    ("edls", "external-list/entry", ExternalDynamicListsCreateModel, _fix_edl),
    ("url_categories", "profiles/custom-url-category/entry", URLCategoriesCreateModel, None),
    ("application_groups", "application-group/entry", ApplicationGroupCreateModel, None),
    ("application_filters", "application-filter/entry", _APP_FILTER_KEYS, _fix_app_filter),
    (
        "anti_spyware_profiles",
        "profiles/spyware/entry",
        AntiSpywareProfileCreateModel,
        _fix_spyware,
    ),
    (
        "vulnerability_profiles",
        "profiles/vulnerability/entry",
        VulnerabilityProfileCreateModel,
        None,
    ),
    ("url_access_profiles", "profiles/url-filtering/entry", URLAccessProfileCreateModel, _fix_url),
    (
        "file_blocking_profiles",
        "profiles/file-blocking/entry",
        FileBlockingProfileCreateModel,
        None,
    ),
    ("wildfire_profiles", "profiles/wildfire-analysis/entry", WildfireAvProfileCreateModel, None),
    ("decryption_profiles", "profiles/decryption/entry", DecryptionProfileCreateModel, None),
]

# Rule kinds: PAN-OS rulebase section → (backup key for pre, for post, model)
_RULES: dict[str, tuple[str, str | None, type[BaseModel]]] = {
    "security": ("security_rules_pre", "security_rules_post", SecurityRuleCreateModel),
    "nat": ("nat_rules_pre", "nat_rules_post", NatRuleCreateModel),
    # The clone pushes decryption and app-override rules to pre only
    "decryption": ("decryption_rules", None, DecryptionRuleCreateModel),
    "application-override": ("app_override_rules", None, AppOverrideRuleCreateModel),
}

# Sections not migrated, reported once per scope with their entry count
_UNSUPPORTED_SECTIONS = {
    "application": "custom applications (scm_config_clone doesn't create them yet)",
    "schedule": "schedules",
    "profiles/hip-objects": "HIP objects",
    "profiles/hip-profiles": "HIP profiles",
    "hip-objects": "HIP objects",
    "hip-profiles": "HIP profiles",
    "dynamic-user-group": "dynamic user groups",
    "region": "custom regions",
    "log-settings/profiles": "log forwarding profiles (rules keep the name; create it in SCM)",
    "profiles/data-filtering": "data filtering profiles (SCM uses DLP)",
    "profiles/dos-protection": "DoS protection profiles",
    "profiles/data-objects": "data patterns",
    "profiles/sdwan-path-quality": "SD-WAN profiles",
    "profiles/gtp": "GTP profiles",
    "profiles/sctp": "SCTP profiles",
    "threats": "custom threat signatures",
}
_UNSUPPORTED_RULEBASES = {
    "pbf": "policy-based forwarding rules",
    "qos": "QoS rules",
    "dos": "DoS protection rules",
    "authentication": "authentication rules",
    "tunnel-inspect": "tunnel inspection rules",
    "sdwan": "SD-WAN rules",
    "network-packet-broker": "network packet broker rules",
}


# ── Conversion ──────────────────────────────────────────────────────────────


def _resolve(scopes: list[_Scope], path: str, key: str, items: list[PlanItem]) -> Iterator[Element]:
    """Entries at *path*, nearest scope first; a name already seen is hidden
    by the nearer copy (reported)."""
    seen: dict[str, str] = {}
    for sc in scopes:
        for el in sc.el.findall(path):
            name = el.get("name", "")
            if name in seen:
                items.append(
                    PlanItem(key, name, OVERRIDDEN, f"{sc.label} copy hidden by {seen[name]}")
                )
                continue
            seen[name] = sc.label
            yield el


def convert(
    root: Element, *, device_group: str = "", vsys: str = "", include_rules: bool = True
) -> Conversion:
    """Translate one device group or vsys into a backup dict."""
    source, scopes = _scopes(root, device_group, vsys)
    items: list[PlanItem] = []
    resources: dict[str, list[dict[str, Any]]] = {}

    # Objects: nearest scope wins
    for key, path, spec, fix in _OBJECTS:
        out: list[dict[str, Any]] = []
        for el in _resolve(scopes, path, key, items):
            obj = _entry(el)
            if fix:
                fix(obj, items)
            v = _validate(spec, key, obj, items)
            if v is not None:
                out.append(v)
        if out:
            resources[key] = out

    # Antivirus profiles: SCM has no API for a standalone AV profile
    for sc in scopes:
        for el in sc.el.findall("profiles/virus/entry"):
            items.append(
                PlanItem(
                    "virus",
                    el.get("name", ""),
                    MANUAL,
                    "antivirus profiles can't be created over the SCM API: use a "
                    "WildFire and antivirus profile, created in SCM",
                )
            )

    groups = _profile_groups(scopes, items)
    if include_rules:
        rules = _rules(scopes, items, groups)
        resources.update(rules)
    if groups.out:
        resources["profile_groups"] = groups.out

    _unsupported(scopes, items)
    label = device_group or vsys or "vsys1"
    backup = {
        "backup_version": "1",
        "folder": label,
        "migrated_from": source,
        "resources": resources,
        # No snippet_types: no PAN snippets in a PAN-OS export
    }
    return Conversion(backup, items, source, [s.label for s in scopes])


@dataclass
class _Groups:
    out: list[dict[str, Any]] = field(default_factory=list)
    names: set[str] = field(default_factory=set)
    # Generated groups: profile tuple → group name
    by_profiles: dict[tuple[tuple[str, tuple[str, ...]], ...], str] = field(default_factory=dict)


def _profile_fields(
    kind: str, name: str, profiles: dict[str, list[str]], items: list[PlanItem]
) -> dict[str, list[str]]:
    """PAN-OS profile type → SCM group field; reports what can't go."""
    out: dict[str, list[str]] = {}
    for ptype, members in profiles.items():
        if not members:
            continue
        xml_type = ptype.replace("_", "-")
        scm = PROFILE_TYPES.get(xml_type)
        if scm:
            out[scm] = members
        elif xml_type == "virus":
            items.append(
                PlanItem(
                    kind,
                    name,
                    MANUAL,
                    f"antivirus profile {', '.join(members)} not migrated: add a WildFire "
                    "and antivirus profile to the group in SCM",
                )
            )
        else:
            items.append(
                PlanItem(kind, name, DROPPED, f"{ptype} profile {', '.join(members)} not migrated")
            )
    return out


def _profile_groups(scopes: list[_Scope], items: list[PlanItem]) -> _Groups:
    groups = _Groups()
    for el in _resolve(scopes, "profile-group/entry", "profile_groups", items):
        name = el.get("name", "")
        profiles = {k.tag: _members(k) for k in el if k.tag != "description"}
        obj: dict[str, Any] = {"name": name}
        desc = el.findtext("description")
        if desc:
            obj["description"] = desc.strip()
        obj.update(_profile_fields("profile_groups", name, profiles, items))
        groups.out.append(obj)
        groups.names.add(name)
    return groups


def _rule_profiles(key: str, o: dict[str, Any], groups: _Groups, items: list[PlanItem]) -> None:
    """profile-setting → {"group": [...]}; individual profiles become a generated group."""
    ps = o.pop("profile_setting", None)
    if not isinstance(ps, dict):
        return
    if ps.get("group"):
        o["profile_setting"] = {"group": list(ps["group"])}
        return
    profiles = ps.get("profiles")
    if not isinstance(profiles, dict):
        return
    fields = _profile_fields(key, o["name"], profiles, items)
    if not fields:
        return
    sig = tuple(sorted((k, tuple(v)) for k, v in fields.items()))
    name = groups.by_profiles.get(sig)
    if name is None:
        base = f"{o['name']}-profiles"[:63]
        name, n = base, 2
        while name in groups.names:
            suffix = f"-{n}"
            name, n = base[: 63 - len(suffix)] + suffix, n + 1
        groups.by_profiles[sig] = name
        groups.names.add(name)
        groups.out.append({"name": name, **fields})
        items.append(
            PlanItem(
                "profile_groups",
                name,
                GENERATED,
                f"from the individual profiles on rule `{o['name']}` (SCM rules take groups only)",
            )
        )
    o["profile_setting"] = {"group": [name]}


def _rules(
    scopes: list[_Scope], items: list[PlanItem], groups: _Groups
) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    seen: dict[tuple[str, str], str] = {}
    # (rulebase container, position): PAN-OS evaluation order across scopes
    order = (
        [(sc, "pre-rulebase", "pre") for sc in reversed(scopes)]
        + [(sc, "rulebase", "pre") for sc in scopes]  # firewall vsys
        + [(sc, "post-rulebase", "post") for sc in scopes]
    )

    for sc, container, position in order:
        base = sc.el.find(container)
        if base is None:
            continue
        for section in base:
            if section.tag == "default-security-rules":
                for el in section.findall("rules/entry"):
                    items.append(
                        PlanItem(
                            "default-security-rules",
                            el.get("name", ""),
                            MANUAL,
                            f"{sc.label} overrides a default rule: set intrazone/interzone "
                            "defaults in the SCM folder's rulebase",
                        )
                    )
                continue
            if section.tag in _UNSUPPORTED_RULEBASES:
                n = len(section.findall("rules/entry"))
                if n:
                    items.append(
                        PlanItem(
                            section.tag,
                            f"{n} rule(s)",
                            UNSUPPORTED,
                            f"{_UNSUPPORTED_RULEBASES[section.tag]} in {sc.label} {container}",
                        )
                    )
                continue
            spec = _RULES.get(section.tag)
            if spec is None:
                continue
            pre_key, post_key, model = spec
            key = pre_key if position == "pre" else post_key
            if key is None:
                n = len(section.findall("rules/entry"))
                if n:
                    items.append(
                        PlanItem(
                            section.tag,
                            f"{n} rule(s)",
                            UNSUPPORTED,
                            f"post-rulebase {section.tag} rules in {sc.label}: the clone "
                            "pushes these to pre only",
                        )
                    )
                continue
            for el in section.findall("rules/entry"):
                o = _entry(el)
                name = o["name"]
                kind = section.tag
                if (kind, name) in seen:
                    items.append(
                        PlanItem(
                            key,
                            name,
                            INVALID,
                            f"duplicate rule name (also in {seen[(kind, name)]})",
                        )
                    )
                    continue
                seen[(kind, name)] = sc.label
                if not _fix_rule(key, kind, o, items):
                    continue
                if kind == "security":
                    _rule_profiles(key, o, groups, items)
                v = _validate(model, key, o, items)
                if v is not None:
                    out.setdefault(key, []).append(v)
    return out


def _unsupported(scopes: list[_Scope], items: list[PlanItem]) -> None:
    for sc in scopes:
        for path, what in _UNSUPPORTED_SECTIONS.items():
            n = len(sc.el.findall(f"{path}/entry"))
            if n:
                items.append(
                    PlanItem(
                        path,
                        f"{n} entr{'y' if n == 1 else 'ies'}",
                        UNSUPPORTED,
                        f"{what} in {sc.label}",
                    )
                )


def plan_markdown(conv: Conversion) -> list[str]:
    """The migration-plan section of the report."""
    lines = [
        "## Migration plan\n",
        f"**Source:** {conv.source}  ",
        f"**Scopes (nearest first):** {', '.join(conv.scopes)}\n",
        "| Backup key | Objects |",
        "|---|---|",
    ]
    for key, n in sorted(conv.counts().items()):
        lines.append(f"| `{key}` | {n} |")
    for action, title in _ACTION_TITLES.items():
        rows = [i for i in conv.items if i.action == action]
        if not rows:
            continue
        lines += [
            f"\n### {title} ({len(rows)})\n",
            "| Kind | Name | Detail |",
            "|---|---|---|",
        ]
        lines += [f"| `{i.kind}` | `{i.name}` | {i.reason} |" for i in rows]
    return lines
