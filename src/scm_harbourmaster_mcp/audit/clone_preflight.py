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

  * NGFW network config (cloner include_network) references interfaces,
    which a folder cannot see when they are set on a firewall, so an
    interface that resolves nowhere is "unverifiable".  Access and prefix
    lists answer 500 on every tenant probed and are unverifiable too.
  * BFD, routing timer, BGP dampening, monitor and NetFlow profiles are
    neither backed up nor listable (vr-bfd-profiles is in the spec but
    404s), so references to them are always "unverifiable".  A legacy
    virtual router's own inline dampening profiles still resolve.

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
    # NGFW network config kinds are only read when the clone pushes network
    # config (cloner include_network), so other clones skip their list calls.
    network: bool = False
    # Why the kind is unverifiable when it has no sources
    no_api: str = "no list API for this profile type"
    # When set, a name that resolves nowhere is "unverifiable" for this
    # reason instead of "missing".
    unverified_reason: str = ""


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

# ── NGFW network config (cloner include_network) ────────────────────────────

# Profile fields that say "use none" or "inherit from the peer group" rather
# than naming a profile.
_NETWORK_KEYWORDS = frozenset({"none", "None", "inherit"})
_INTERFACE_PATHS = (
    "ethernet-interfaces",
    "aggregate-interfaces",
    "layer3-subinterfaces",
    "layer2-subinterfaces",
    "loopback-interfaces",
    "tunnel-interfaces",
    "vlan-interfaces",
)
# Backup key → the kind its names provide (also the reference kind)
_NETWORK_PROFILE_KINDS: dict[str, tuple[str, str, str]] = {
    # backup key: (kind, label, /config/network/v1 path)
    "interface_management_profiles": (
        "interface_management_profile",
        "interface management profile",
        "interface-management-profiles",
    ),
    "route_community_lists": ("community_list", "community list", "route-community-lists"),
    "route_path_access_lists": (
        "as_path_access_list",
        "AS-path access list",
        "route-path-access-lists",
    ),
    "bgp_auth_profiles": ("bgp_auth_profile", "BGP auth profile", "bgp-auth-profiles"),
    "bgp_route_maps": ("bgp_route_map", "BGP route map", "bgp-route-maps"),
    "bgp_route_map_redistributions": (
        "route_map_redistribution",
        "redistribution route map",
        "bgp-route-map-redistributions",
    ),
    "bgp_address_family_profiles": (
        "bgp_address_family_profile",
        "BGP address-family profile",
        "bgp-address-family-profiles",
    ),
    "bgp_filtering_profiles": (
        "bgp_filtering_profile",
        "BGP filtering profile",
        "bgp-filtering-profiles",
    ),
    "bgp_redistribution_profiles": (
        "bgp_redistribution_profile",
        "BGP redistribution profile",
        "bgp-redistribution-profiles",
    ),
    "ospf_auth_profiles": ("ospf_auth_profile", "OSPF auth profile", "ospf-auth-profiles"),
    "logical_routers": ("logical_router", "logical router", "logical-routers"),
    "virtual_routers": ("virtual_router", "virtual router", "virtual-routers"),
}
_LIST_500 = (
    "{} answers 500 on every tenant probed, so it is neither backed up nor listable — "
    "check it exists in the target by hand"
)
_NOT_LISTED = "{} are not backed up and have no list API — check it exists in the target by hand"
KINDS.update(
    {
        kind: _Kind(label, ((f"{_NETWORK}/{path}", _names),), _NETWORK_KEYWORDS, network=True)
        for kind, label, path in _NETWORK_PROFILE_KINDS.values()
    }
)
KINDS.update(
    {
        # Interfaces set on one firewall are only visible per device, never
        # from a folder, so an interface the target folder does not list may
        # still exist on the firewall: unverifiable, not missing.
        "interface": _Kind(
            "interface",
            tuple((f"{_NETWORK}/{p}", _names) for p in _INTERFACE_PATHS),
            _NETWORK_KEYWORDS,
            network=True,
            unverified_reason=(
                "not in the target folder or the clone; interfaces set on a firewall "
                "are not visible from a folder"
            ),
        ),
        "access_list": _Kind(
            "access list", (), network=True, no_api=_LIST_500.format("route-access-lists")
        ),
        "prefix_list": _Kind(
            "prefix list", (), network=True, no_api=_LIST_500.format("route-prefix-lists")
        ),
        # Profiles the network backup does not hold, so the clone never
        # creates them, and which no list API serves: unverifiable.
        "bfd_profile": _Kind(
            "BFD profile",
            (),
            _NETWORK_KEYWORDS | {"default"},
            network=True,
            no_api=(
                "BFD profiles are not backed up; logical-router ones have no list API and "
                "vr-bfd-profiles answers 404 on every tenant probed — check it exists in the "
                "target by hand"
            ),
        ),
        "timer_profile": _Kind(
            "routing timer profile",
            (),
            _NETWORK_KEYWORDS,
            network=True,
            no_api=_NOT_LISTED.format("BGP, OSPF, OSPFv3 and RIP timer profiles"),
        ),
        "dampening_profile": _Kind(
            "BGP dampening profile",
            (),
            _NETWORK_KEYWORDS,
            network=True,
            no_api=_NOT_LISTED.format("Logical-router BGP dampening profiles"),
        ),
        "monitor_profile": _Kind(
            "monitor profile",
            (),
            _NETWORK_KEYWORDS | {"default"},
            network=True,
            no_api=_NOT_LISTED.format("Monitor profiles"),
        ),
        "netflow_profile": _Kind(
            "NetFlow profile",
            (),
            _NETWORK_KEYWORDS,
            network=True,
            no_api=_NOT_LISTED.format("NetFlow server profiles"),
        ),
    }
)

# Interface backup keys.  Their names are hardware or variable names
# (ethernet1/1, ae1, ethernet1/1.100, tunnel.1, $outside), so name_prefix
# never renames them.  DHCP rows are named after the interface they serve.
INTERFACE_KEYS = frozenset(
    {
        "ethernet_interfaces",
        "aggregate_interfaces",
        "layer3_subinterfaces",
        "layer2_subinterfaces",
        "loopback_interfaces",
        "tunnel_interfaces",
        "vlan_interfaces",
    }
)
UNRENAMED_KEYS = INTERFACE_KEYS | {"dhcp_interfaces"}


def device_row(obj: dict[str, Any]) -> str:
    """The firewall serial of a device-scoped backup row, or "".

    The network backup reads interfaces per firewall (``?device=<serial>``);
    those rows carry the serial and no folder, and are never pushed into a
    folder.
    """
    return "" if obj.get("folder") else str(obj.get("device") or "")


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
    **{key: (kind,) for key, (kind, _, _) in _NETWORK_PROFILE_KINDS.items()},
    **{key: ("interface",) for key in INTERFACE_KEYS},
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
    # Dotted path to names the object defines itself that also satisfy the
    # reference (a router's inline auth profiles).  Those are never checked
    # against the target nor renamed.
    local: str = ""


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


# ── NGFW network config references ───────────────────────────────────────────
# Paths are the API's field names (the network backup is read over REST) and
# step into lists (see holders).  None is strippable: dropping an interface
# or a route map changes routing.  From the R3 network-services, logical- and
# virtual-router specs.  BFD, timer, dampening, monitor and NetFlow profiles
# are checked but always unverifiable (see KINDS).  A static route's
# path_monitor holds its destinations inline and names no profile.  Not
# checked: OSPF area auth, OSPFv3 and RIP auth, and the OSPF/OSPFv3/RIP
# redistribution routing profiles, certificates, schedules and multicast,
# which the clone neither creates nor lists.

_IMP = "interface_management_profile"


def _refs(prefix: str, fields: Iterable[tuple[str, str]]) -> tuple[_Ref, ...]:
    return tuple(_Ref(f"{prefix}{f}", kind) for f, kind in fields)


# A route map entry's match/set fields (BGP route maps, and the
# redistribution route maps whose OSPF variants drop the "ipv4." level)
_ROUTE_MAP_FIELDS: tuple[tuple[str, str], ...] = (
    ("match.as_path_access_list", "as_path_access_list"),
    ("match.regular_community", "community_list"),
    ("match.large_community", "community_list"),
    ("match.extended_community", "community_list"),
    ("match.interface", "interface"),
    *(
        (f"match.{af}{target}.{lst}", kind)
        for af in ("ipv4.", "")
        for target in ("address", "next_hop", "route_source")
        for lst, kind in (("access_list", "access_list"), ("prefix_list", "prefix_list"))
    ),
    ("set.remove_regular_community", "community_list"),
    ("set.remove_large_community", "community_list"),
)

_BGP_FILTER_FIELDS: tuple[tuple[str, str], ...] = (
    ("filter_list.inbound", "as_path_access_list"),
    ("filter_list.outbound", "as_path_access_list"),
    ("inbound_network_filters.distribute_list", "access_list"),
    ("inbound_network_filters.prefix_list", "prefix_list"),
    ("outbound_network_filters.distribute_list", "access_list"),
    ("outbound_network_filters.prefix_list", "prefix_list"),
    ("route_maps.inbound", "bgp_route_map"),
    ("route_maps.outbound", "bgp_route_map"),
    ("conditional_advertisement.exist.advertise_map", "bgp_route_map"),
    ("conditional_advertisement.exist.exist_map", "bgp_route_map"),
    ("conditional_advertisement.non_exist.advertise_map", "bgp_route_map"),
    ("conditional_advertisement.non_exist.non_exist_map", "bgp_route_map"),
    ("unsuppress_map", "bgp_route_map"),
)

_STATIC_ROUTES = ("routing_table.ip.static_route.", "routing_table.ipv6.static_route.")
_AF = ("ipv4", "ipv6")
_LR_OSPF_AUTH = "vrf.ospf.auth_profile.name"
# Legacy virtual routers define their BGP dampening profiles inline
_VR_DAMPENING = "protocol.bgp.dampening_profile.name"
_BFD = "bfd.profile"
# A static route's BFD profile, under either router's routing table
_STATIC_BFD = tuple(f"{p}{_BFD}" for p in _STATIC_ROUTES)
_NETFLOW = _Ref("netflow_profile", "netflow_profile")

NETWORK_REFERENCE_FIELDS: dict[str, tuple[_Ref, ...]] = {
    "ethernet_interfaces": (
        _Ref("layer3.interface_management_profile", _IMP),
        _Ref("aggregate_group", "interface"),
        *(
            _Ref(f"{mode}.netflow_profile", "netflow_profile")
            for mode in ("layer2", "layer3", "tap")
        ),
    ),
    "aggregate_interfaces": (
        _Ref("layer3.interface_management_profile", _IMP),
        *(_Ref(f"{mode}.netflow_profile", "netflow_profile") for mode in ("layer2", "layer3")),
    ),
    "layer3_subinterfaces": (
        _Ref("interface_management_profile", _IMP),
        _Ref("parent_interface", "interface"),
        _NETFLOW,
    ),
    "layer2_subinterfaces": (_Ref("parent_interface", "interface"),),
    "loopback_interfaces": (_Ref("interface_management_profile", _IMP), _NETFLOW),
    "tunnel_interfaces": (_Ref("interface_management_profile", _IMP), _NETFLOW),
    "vlan_interfaces": (_Ref("interface_management_profile", _IMP), _NETFLOW),
    # A DHCP server/relay row is named after the interface it runs on
    "dhcp_interfaces": (_Ref("name", "interface"),),
    "bgp_route_maps": _refs("route_map.", _ROUTE_MAP_FIELDS),
    "bgp_route_map_redistributions": tuple(
        ref
        for src in ("bgp", "ospf", "connected_static")
        for dst in ("bgp", "ospf", "rib")
        if src != dst
        for ref in _refs(f"{src}.{dst}.route_map.", _ROUTE_MAP_FIELDS)
    ),
    "bgp_address_family_profiles": tuple(
        _Ref(f"ipv4.{cast}.default_originate_map", "bgp_route_map")
        for cast in ("unicast", "multicast")
    ),
    "bgp_filtering_profiles": tuple(
        ref
        for cast in ("unicast", "multicast")
        for ref in _refs(f"ipv4.{cast}.", _BGP_FILTER_FIELDS)
    ),
    "bgp_redistribution_profiles": tuple(
        _Ref(f"ipv4.unicast.{src}.route_map", "route_map_redistribution")
        for src in ("static", "ospf", "connected")
    ),
    "logical_routers": (
        _Ref("vrf.interface", "interface"),
        *(
            _Ref(f"vrf.bgp.peer_group.address_family.{af}", "bgp_address_family_profile")
            for af in _AF
        ),
        *(
            _Ref(f"vrf.bgp.peer_group.filtering_profile.{af}", "bgp_filtering_profile")
            for af in _AF
        ),
        _Ref("vrf.bgp.peer_group.connection_options.authentication", "bgp_auth_profile"),
        _Ref("vrf.bgp.peer_group.peer.connection_options.authentication", "bgp_auth_profile"),
        # A peer that does not inherit its group's profiles names its own
        *(
            _Ref(f"vrf.bgp.peer_group.peer.inherit.no.{fld}.{af}", kind)
            for fld, kind in (
                ("address_family", "bgp_address_family_profile"),
                ("filtering_profile", "bgp_filtering_profile"),
            )
            for af in _AF
        ),
        _Ref("vrf.bgp.peer_group.peer.local_address.interface", "interface"),
        *(
            _Ref(f"vrf.bgp.redistribution_profile.{af}.unicast", "bgp_redistribution_profile")
            for af in _AF
        ),
        *(
            _Ref(f"vrf.rib_filter.{af}.{proto}.route_map", "route_map_redistribution")
            for af in _AF
            for proto in ("static", "bgp", "ospf", "rip")
        ),
        _Ref("vrf.ospf.area.interface.name", "interface"),
        _Ref("vrf.ospf.area.interface.authentication", "ospf_auth_profile", local=_LR_OSPF_AUTH),
        _Ref("vrf.ospf.area.virtual_link.authentication", "ospf_auth_profile", local=_LR_OSPF_AUTH),
        *(_Ref(f"vrf.{p}interface", "interface") for p in _STATIC_ROUTES),
        *(_Ref(f"vrf.{p}nexthop.next_lr", "logical_router") for p in _STATIC_ROUTES),
        *(
            _Ref(f"vrf.{p}", "bfd_profile")
            for p in (
                *(f"{proto}.global_{_BFD}" for proto in ("bgp", "ospf", "ospfv3", "rip")),
                f"bgp.peer_group.peer.{_BFD}",
                f"ospf.area.interface.{_BFD}",
                f"ospf.area.virtual_link.{_BFD}",
                f"rip.interface.{_BFD}",
                *_STATIC_BFD,
            )
        ),
        *(
            _Ref(f"vrf.{p}", "timer_profile")
            for p in (
                "bgp.peer_group.connection_options.timers",
                "bgp.peer_group.peer.connection_options.timers",
                *(
                    f"{proto}.{t}"
                    for proto in ("ospf", "ospfv3")
                    for t in ("global_if_timer", "spf_timer")
                ),
                "ospf.area.interface.timing",
                "ospf.area.virtual_link.timing",
                "rip.global_timer",
            )
        ),
        *(
            _Ref(f"vrf.bgp.{p}", "dampening_profile")
            for p in (
                "peer_group.connection_options.dampening",
                "peer_group.peer.connection_options.dampening",
                "policy.import.rules.action.allow.dampening",
            )
        ),
    ),
    # Legacy virtual routers define their auth profiles inline
    "virtual_routers": (
        _Ref("interface", "interface"),
        _Ref("protocol.bgp.peer_group.peer.local_address.interface", "interface"),
        *(_Ref(f"{p}interface", "interface") for p in _STATIC_ROUTES),
        *(_Ref(f"{p}nexthop.next_vr", "virtual_router") for p in _STATIC_ROUTES),
        *(
            _Ref(p, "bfd_profile")
            for p in (
                *(f"protocol.{proto}.global_{_BFD}" for proto in ("bgp", "ospf", "ospfv3", "rip")),
                f"protocol.bgp.peer_group.peer.{_BFD}",
                *(
                    f"protocol.{proto}.area.{link}.{_BFD}"
                    for proto in ("ospf", "ospfv3")
                    for link in ("interface", "virtual_link")
                ),
                f"protocol.rip.interface.{_BFD}",
                *_STATIC_BFD,
            )
        ),
        _Ref(
            "protocol.bgp.policy.import.rules.action.allow.dampening",
            "dampening_profile",
            local=_VR_DAMPENING,
        ),
    ),
    "gre_tunnels": (
        _Ref("tunnel_interface", "interface"),
        _Ref("local_address.interface", "interface"),
    ),
    "pbf_rules": (
        _Ref("from.zone", "zone"),
        _Ref("from.interface", "interface"),
        *_fixed(_ADDRESSES),
        _Ref("service", "service"),
        _Ref("application", "application"),
        _Ref("action.forward.egress_interface", "interface"),
        _Ref("action.forward.monitor.profile", "monitor_profile"),
        _TAG,
    ),
}
REFERENCE_FIELDS.update(NETWORK_REFERENCE_FIELDS)

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


def holders(obj: Any, parents: Iterable[str]) -> list[dict[str, Any]]:
    """The dicts reached from *obj* along *parents*, stepping into lists.

    A list on the way fans out to each of its dict items, so the network
    config's nested lists (a router's ``vrf[].bgp.peer_group[]``, a route
    map's ``route_map[].match``) are reached by a plain dotted path.
    """
    level: list[Any] = [obj]
    for part in parents:
        nxt: list[Any] = []
        for item in level:
            value = item.get(part) if isinstance(item, dict) else None
            nxt.extend(value if isinstance(value, list) else [value])
        level = nxt
    out: list[dict[str, Any]] = []
    for item in level:
        if isinstance(item, list):
            out.extend(i for i in item if isinstance(i, dict))
        elif isinstance(item, dict):
            out.append(item)
    return out


def _values(obj: dict[str, Any], path: str) -> list[str]:
    *parents, leaf = path.split(".")
    out: list[str] = []
    for holder in holders(obj, parents):
        value = holder.get(leaf)
        if isinstance(value, list):
            out.extend(str(v) for v in value if v not in (None, "") and not isinstance(v, dict))
        elif isinstance(value, str) and value:
            out.append(value)
    return out


def _ref_values(obj: dict[str, Any], ref: _Ref) -> list[str]:
    values = _values(obj, ref.field)
    if ref.expression:
        values = [n for v in values for n in _expression_names(v)]
    if ref.local:
        own = set(_values(obj, ref.local))
        values = [v for v in values if v not in own]
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
        if ref.local:
            # A name the object defines itself (a router's inline auth
            # profile) is not a reference to the cloned object.
            own = set(_values(obj, ref.local))
            names = {k: v for k, v in names.items() if k not in own}
        *parents, leaf = ref.field.split(".")
        for holder in holders(obj, parents):
            if leaf not in holder:
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


def fetch_target_inventory(
    session: Any, target_folder: str, *, network: bool = False
) -> TargetInventory:
    """Read every reference catalogue visible from *target_folder*.

    List calls on a folder return its own objects plus everything inherited,
    predefined snippets included.  A folder that does not exist yet (a clone
    into a new folder) falls back to "All", which holds the predefined and
    tenant-wide content every folder inherits.  The NGFW network catalogues
    are read only with *network* (a clone that pushes network config).
    """
    kinds = {k: spec for k, spec in KINDS.items() if network or not spec.network}
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

    urls = sorted({url for spec in kinds.values() for url, _ in spec.sources} - set(cache))
    with ThreadPoolExecutor(max_workers=_SOURCE_WORKERS) as pool:
        for url, fetched in zip(
            urls, pool.map(lambda u: _list_rows(session, u, inv.folder), urls), strict=True
        ):
            cache[url] = fetched

    for kind, spec in kinds.items():
        found: set[str] = set()
        if not spec.sources:
            inv.unreadable[kind] = spec.no_api
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
        # Device-scoped rows are never pushed (see device_row)
        value = resources.get(key) or []
        return [
            o
            for o in value
            if isinstance(o, dict) and not pan_snippet(o, snippet_types) and not device_row(o)
        ]

    # Names the clone creates, by kind (as named in the target).  Interfaces
    # keep their names under a prefix.
    created: dict[str, dict[str, tuple[str, str]]] = {}
    for key in planned_keys:
        prefix = "" if key in UNRENAMED_KEYS else name_prefix
        for kind in PROVIDES.get(key, ()):
            for obj in objects(key):
                name = str(obj.get("name", ""))
                created.setdefault(kind, {})[f"{prefix}{name}"] = (key, name)
    # Interfaces the source set only on a firewall, which the clone skips
    device_only: dict[str, str] = {}
    for key in INTERFACE_KEYS & set(planned_keys):
        for obj in resources.get(key) or []:
            if isinstance(obj, dict) and obj.get("name") and device_row(obj):
                device_only.setdefault(str(obj["name"]), device_row(obj))
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
        target_name = name if kind == "interface" else f"{name_prefix}{name}"
        owner = created.get(kind, {}).get(target_name)
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
        elif kind == "interface" and name in device_only:
            hint = (
                f"set only on firewall `{device_only[name]}` in the source — device-scoped, "
                "not cloned into a folder"
            )
        if kind in inventory.unreadable:
            return "unverifiable", inventory.unreadable[kind]
        reason = KINDS[kind].unverified_reason
        if reason:
            return "unverifiable", hint or reason
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
                            if ref.strippable:
                                why = f"stripping would narrow a `{obj.get('action')}` rule"
                            elif key in NETWORK_REFERENCE_FIELDS:
                                why = "dropping it would change routing or forwarding"
                            else:
                                why = "dropping it would loosen policy"
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
