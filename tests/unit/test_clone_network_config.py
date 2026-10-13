"""Restoring NGFW network config from a backup (cloner include_network).

No network: SDK resources and the REST session are fakes.  All names are
placeholders.  Network rows hold the API's field names (the backup reads
them over REST), so a PBF rule's zones are under ``from``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scm_harbourmaster_mcp.audit import cloner
from scm_harbourmaster_mcp.audit.clone_preflight import (
    KINDS,
    NETWORK_REFERENCE_FIELDS,
    PROVIDES,
    UNRENAMED_KEYS,
    TargetInventory,
    check_references,
    fetch_target_inventory,
    rewrite_references,
)
from scm_harbourmaster_mcp.audit.extractor import NETWORK_CONFIG_RESOURCES

NET = "https://api.sase.paloaltonetworks.com/config/network/v1"
ENC = "-AQ==c2VjcmV0"  # an encrypted blob as the backup holds it

# ── Fakes ─────────────────────────────────────────────────────────────────────


class Resp:
    def __init__(self, status: int, body: Any) -> None:
        self.status_code = status
        self.ok = status < 400
        self._body = body
        self.text = json.dumps(body)
        self.content = self.text.encode()
        self.headers: dict[str, str] = {}

    def json(self) -> Any:
        return self._body


class Session:
    """Records REST writes; list GETs answer from *rows* by URL suffix."""

    def __init__(self, rows: dict[str, list[dict[str, Any]]] | None = None) -> None:
        self.rows = rows or {}
        self.calls: list[tuple[str, str, Any]] = []

    def post(self, url: str, json: Any = None, timeout: Any = None) -> Resp:
        self.calls.append(("POST", url, json))
        return Resp(201, {"id": "new"})

    def get(self, url: str, params: Any = None, timeout: Any = None) -> Resp:
        self.calls.append(("GET", url, params))
        for suffix, rows in self.rows.items():
            if url.endswith(suffix):
                return Resp(200, {"data": rows, "total": len(rows)})
        return Resp(200, {"data": [], "total": 0})

    def put(self, url: str, json: Any = None, timeout: Any = None) -> Resp:
        self.calls.append(("PUT", url, json))
        return Resp(200, json)

    def posts(self) -> list[tuple[str, Any]]:
        return [(url.removeprefix(f"{NET}/"), body) for m, url, body in self.calls if m == "POST"]


class SdkResource:
    def __init__(self, log: list[str], name: str) -> None:
        self._log = log
        self._name = name

    def create(self, data: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        self._log.append(self._name)
        return data


class Client:
    """SDK resources by attribute plus a REST session."""

    def __init__(self, session: Session | None = None) -> None:
        self.session = session or Session()
        self.sdk_calls: list[str] = []

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_") or name == "api_base_url":
            raise AttributeError(name)
        return SdkResource(self.sdk_calls, name)


def _backup(tmp_path: Path, resources: dict[str, list[dict[str, Any]]]) -> str:
    path = tmp_path / "backup.json"
    path.write_text(json.dumps({"backup_version": "1", "folder": "All", "resources": resources}))
    return str(path)


def _row(name: str, folder: str = "fw-a", **fields: Any) -> dict[str, Any]:
    return {"id": f"id-{name}", "name": name, "folder": folder, **fields}


def _router(name: str = "lr-1", **vrf: Any) -> dict[str, Any]:
    return _row(name, vrf=[{"name": "default", "interface": ["ethernet1/1"], **vrf}])


# One object of every network key, wired together by reference
def _estate() -> dict[str, list[dict[str, Any]]]:
    return {
        "interface_management_profiles": [_row("mgmt-ping", ping=True)],
        "aggregate_interfaces": [_row("ae1", layer3={"ip": [{"name": "192.0.2.1/24"}]})],
        "ethernet_interfaces": [
            _row("ethernet1/1", layer3={"interface_management_profile": "mgmt-ping"}),
            _row("ethernet1/2", aggregate_group="ae1"),
            _row("$outside", layer3={"interface_management_profile": "mgmt-ping"}),
        ],
        "layer3_subinterfaces": [_row("ethernet1/1.10", parent_interface="ethernet1/1", tag=10)],
        "layer2_subinterfaces": [_row("ae1.20", parent_interface="ae1", vlan_tag="20")],
        "loopback_interfaces": [_row("loopback.1", interface_management_profile="mgmt-ping")],
        "tunnel_interfaces": [_row("tunnel.1")],
        "vlan_interfaces": [_row("vlan.30")],
        "dhcp_interfaces": [_row("ethernet1/1.10", server={"mode": "auto"})],
        "route_community_lists": [_row("comm-1", type={"regular": {}})],
        "route_path_access_lists": [_row("aspath-1", aspath_entry=[])],
        "bgp_auth_profiles": [_row("bgp-auth", secret=ENC)],
        "bgp_route_maps": [
            _row(
                "rm-in",
                route_map=[
                    {
                        "name": 10,
                        "action": "permit",
                        "match": {
                            "regular_community": "comm-1",
                            "as_path_access_list": "aspath-1",
                        },
                    }
                ],
            )
        ],
        "bgp_route_map_redistributions": [
            _row(
                "redist-map",
                connected_static={"bgp": {"route_map": [{"name": 10, "action": "permit"}]}},
            )
        ],
        "bgp_address_family_profiles": [
            _row("af-1", ipv4={"unicast": {"default_originate_map": "rm-in"}})
        ],
        "bgp_filtering_profiles": [
            _row("filt-1", ipv4={"unicast": {"route_maps": {"inbound": "rm-in"}}})
        ],
        "bgp_redistribution_profiles": [
            _row("redist-1", ipv4={"unicast": {"connected": {"route_map": "redist-map"}}})
        ],
        "ospf_auth_profiles": [_row("ospf-auth", md5=[{"name": 1, "key": ENC}])],
        "logical_routers": [
            _router(
                bgp={
                    "peer_group": [
                        {
                            "name": "pg-1",
                            "address_family": {"ipv4": "af-1"},
                            "filtering_profile": {"ipv4": "filt-1"},
                            "connection_options": {"authentication": "bgp-auth"},
                        }
                    ],
                    "redistribution_profile": {"ipv4": {"unicast": "redist-1"}},
                },
                ospf={
                    "area": [
                        {
                            "name": "0.0.0.0",
                            "interface": [{"name": "ethernet1/1", "authentication": "ospf-auth"}],
                        }
                    ]
                },
            )
        ],
        "virtual_routers": [],
        "gre_tunnels": [_row("gre-1", tunnel_interface="tunnel.1")],
        "pbf_rules": [
            _row(
                "pbf-1",
                **{"from": {"zone": ["zone-in"]}},
                source=["any"],
                destination=["any"],
                action={"forward": {"egress_interface": "ethernet1/2"}},
            )
        ],
    }


# ── Coverage and ordering ─────────────────────────────────────────────────────


def test_every_backed_up_network_key_has_one_place_in_the_push_order() -> None:
    order = (
        cloner._NETWORK_INTERFACE_ORDER + cloner._NETWORK_ROUTING_ORDER + cloner._NETWORK_RULE_ORDER
    )
    assert len(order) == len(set(order))
    assert set(order) == set(NETWORK_CONFIG_RESOURCES) == set(cloner.NETWORK_KEYS)
    assert set(NETWORK_REFERENCE_FIELDS) <= set(NETWORK_CONFIG_RESOURCES)
    # Every renameable key provides a reference kind the preflight knows
    for key in NETWORK_CONFIG_RESOURCES:
        for kind in PROVIDES.get(key, ()):
            assert KINDS[kind].network or kind in {"zone", "address"}, kind


def test_network_objects_push_in_dependency_order(tmp_path: Path) -> None:
    resources = {
        **_estate(),
        "zones": [{"name": "zone-in", "folder": "fw-a"}],
        "security_rules_pre": [{"name": "allow-1", "folder": "fw-a"}],
        "tags": [{"name": "t", "folder": "fw-a"}],
    }
    report = cloner.clone_config(
        Client(), _backup(tmp_path, resources), "dst", include_network=True
    )
    order = list(dict.fromkeys(r.resource_type for r in report.results))
    assert order == [
        "tags",
        "interface_management_profiles",
        "aggregate_interfaces",
        "ethernet_interfaces",
        "layer3_subinterfaces",
        "layer2_subinterfaces",
        "loopback_interfaces",
        "tunnel_interfaces",
        "vlan_interfaces",
        "dhcp_interfaces",
        "zones",
        "route_community_lists",
        "route_path_access_lists",
        "bgp_auth_profiles",
        "bgp_route_maps",
        "bgp_route_map_redistributions",
        "bgp_address_family_profiles",
        "bgp_filtering_profiles",
        "bgp_redistribution_profiles",
        "ospf_auth_profiles",
        "logical_routers",
        "gre_tunnels",
        "security_rules_pre",
        "pbf_rules",
    ]
    assert {r.status for r in report.results} == {"dry_run"}


def test_network_objects_are_posted_to_their_rest_endpoint(tmp_path: Path) -> None:
    client = Client()
    resources = {"logical_routers": [_router()], "tunnel_interfaces": [_row("tunnel.1")]}
    report = cloner.clone_config(
        client, _backup(tmp_path, resources), "dst", include_network=True, dry_run=False
    )
    assert [r.status for r in report.results] == ["created", "created"]
    posts = client.session.posts()
    assert [path for path, _ in posts] == ["tunnel-interfaces", "logical-routers"]
    # System fields and the source folder are gone; the target folder is set
    assert posts[0][1] == {"name": "tunnel.1", "folder": "dst"}
    assert posts[1][1]["folder"] == "dst" and "id" not in posts[1][1]


# ── Opt-in ───────────────────────────────────────────────────────────────────


def test_network_config_is_not_cloned_by_default(tmp_path: Path) -> None:
    client = Client()
    resources = {**_estate(), "tags": [{"name": "t", "folder": "fw-a"}]}
    report = cloner.clone_config(client, _backup(tmp_path, resources), "dst", dry_run=False)
    assert [r.resource_type for r in report.results] == ["tags"]
    assert client.session.calls == []


def test_naming_a_network_key_in_resource_filter_plans_only_that_key(tmp_path: Path) -> None:
    report = cloner.clone_config(
        Client(),
        _backup(tmp_path, _estate()),
        "dst",
        resource_filter={"gre_tunnels", "tunnel_interfaces"},
    )
    assert [(r.resource_type, r.name) for r in report.results] == [
        ("tunnel_interfaces", "tunnel.1"),
        ("gre_tunnels", "gre-1"),
    ]


def test_skip_rules_also_drops_pbf_rules(tmp_path: Path) -> None:
    report = cloner.clone_config(
        Client(), _backup(tmp_path, _estate()), "dst", include_network=True, skip_rules=True
    )
    assert "pbf_rules" not in {r.resource_type for r in report.results}
    assert "logical_routers" in {r.resource_type for r in report.results}


# ── Rows that are never pushed ───────────────────────────────────────────────


def test_device_scoped_rows_are_reported_not_pushed(tmp_path: Path) -> None:
    client = Client()
    resources = {
        "ethernet_interfaces": [
            _row("ethernet1/1"),
            {"id": "if-2", "name": "ethernet1/2", "folder": None, "device": "SER1"},
            # A folder template resolved for one firewall keeps the template's id
            {"id": "id-ethernet1/1", "name": "ethernet1/1", "device": "SER1"},
        ]
    }
    report = cloner.clone_config(
        client, _backup(tmp_path, resources), "dst", include_network=True, dry_run=False
    )
    statuses = [(r.name, r.status) for r in report.results]
    assert statuses == [
        ("ethernet1/1", "created"),
        ("ethernet1/2", "device_row"),
        ("ethernet1/1", "device_row"),
    ]
    assert "SER1" in report.results[1].detail
    assert [body["name"] for _, body in client.session.posts()] == ["ethernet1/1"]
    assert report.device_rows == 2
    assert "| Skipped (set on a firewall, not a folder) | 2 |" in report.to_markdown()


def test_snippet_placeholder_pbf_rows_are_not_cloned(tmp_path: Path) -> None:
    resources = {"pbf_rules": [_row("example-snippet"), *_estate()["pbf_rules"]]}
    report = cloner.clone_config(
        Client(), _backup(tmp_path, resources), "dst", include_network=True
    )
    assert [(r.name, r.status) for r in report.results] == [
        ("example-snippet", "not_cloned"),
        ("pbf-1", "dry_run"),
    ]


def test_same_name_from_two_firewall_folders_pushes_the_first(tmp_path: Path) -> None:
    resources = {"logical_routers": [_row("lr-1", "fw-a"), _row("lr-1", "fw-b"), _row("lr-2")]}
    report = cloner.clone_config(
        Client(), _backup(tmp_path, resources), "dst", include_network=True
    )
    assert [r.status for r in report.results] == ["dry_run", "not_cloned", "dry_run"]
    assert "fw-a" in report.results[1].detail and "fw-b" in report.results[1].detail
    assert len(report.warnings) == 1 and "firewall folder" in report.warnings[0]


def test_pan_snippet_network_objects_are_predefined(tmp_path: Path) -> None:
    path = tmp_path / "backup.json"
    path.write_text(
        json.dumps(
            {
                "resources": {
                    "bgp_address_family_profiles": [_row("af-pan", "All", snippet="pan-default")]
                },
                "snippet_types": {"pan-default": "predefined"},
            }
        )
    )
    report = cloner.clone_config(Client(), str(path), "dst", include_network=True)
    assert [r.status for r in report.results] == ["predefined"]


# ── Secrets ──────────────────────────────────────────────────────────────────


def test_secrets_become_placeholders_and_are_reported(tmp_path: Path) -> None:
    client = Client()
    resources = {
        "bgp_auth_profiles": [_row("bgp-auth", secret=ENC)],
        "ospf_auth_profiles": [
            _row("ospf-md5", md5=[{"name": 1, "key": ENC, "preferred": True}]),
            _row("ospf-simple", password=ENC),
        ],
        "ethernet_interfaces": [
            _row(
                "ethernet1/3",
                layer3={"pppoe": {"username": "isp-user", "password": ENC}},
            )
        ],
        "logical_routers": [
            _router(
                ospf={"auth_profile": [{"name": "inline", "password": ENC}]},
                ospfv3={"auth_profile": [{"name": "v3", "esp": {"encryption": {"key": ENC}}}]},
            )
        ],
        "virtual_routers": [
            _row("vr-1", protocol={"bgp": {"auth_profile": [{"name": "a", "secret": ENC}]}})
        ],
        # Same field names outside a credential scope are left alone
        "gre_tunnels": [_row("gre-1", key="not-a-secret", tunnel_interface="tunnel.1")],
    }
    report = cloner.clone_config(
        client, _backup(tmp_path, resources), "dst", include_network=True, dry_run=False
    )
    bodies = {body["name"]: body for _, body in client.session.posts()}
    placeholder = cloner.SECRET_PLACEHOLDER
    assert bodies["bgp-auth"]["secret"] == placeholder
    assert bodies["ospf-md5"]["md5"] == [{"name": 1, "key": placeholder, "preferred": True}]
    assert bodies["ospf-simple"]["password"] == placeholder
    assert bodies["ethernet1/3"]["layer3"]["pppoe"] == {
        "username": "isp-user",
        "password": placeholder,
    }
    vrf = bodies["lr-1"]["vrf"][0]
    assert vrf["ospf"]["auth_profile"][0] == {"name": "inline", "password": placeholder}
    assert vrf["ospfv3"]["auth_profile"][0]["esp"]["encryption"]["key"] == placeholder
    assert bodies["vr-1"]["protocol"]["bgp"]["auth_profile"][0]["secret"] == placeholder
    assert bodies["gre-1"]["key"] == "not-a-secret"
    assert ENC not in json.dumps(list(bodies.values()))
    # OSPF simple passwords are at most 8 characters
    assert len(placeholder) <= 8

    assert report.secret_warnings == [
        "ethernet_interfaces `ethernet1/3`: layer3.pppoe.password",
        "bgp_auth_profiles `bgp-auth`: secret",
        "ospf_auth_profiles `ospf-md5`: md5[].key",
        "ospf_auth_profiles `ospf-simple`: password",
        "logical_routers `lr-1`: vrf[].ospf.auth_profile[].password, "
        "vrf[].ospfv3.auth_profile[].esp.encryption.key",
        "virtual_routers `vr-1`: protocol.bgp.auth_profile[].secret",
    ]
    md = report.to_markdown()
    assert "Network Secret Placeholders" in md
    assert "IKE gateways" not in md


def test_dry_run_reports_secret_placeholders_too(tmp_path: Path) -> None:
    resources = {"bgp_auth_profiles": [_row("bgp-auth", secret=ENC)]}
    report = cloner.clone_config(
        Client(), _backup(tmp_path, resources), "dst", include_network=True, name_prefix="C_"
    )
    assert report.secret_warnings == ["bgp_auth_profiles `C_bgp-auth`: secret"]


# ── name_prefix ──────────────────────────────────────────────────────────────


def test_prefix_renames_profiles_and_routers_but_never_interfaces(tmp_path: Path) -> None:
    client = Client()
    resources = {**_estate(), "zones": [{"name": "zone-in", "folder": "fw-a"}]}
    resources["logical_routers"][0]["vrf"][0]["routing_table"] = {
        "ip": {"static_route": [{"name": "to-lr2", "nexthop": {"next_lr": "lr-2"}}]}
    }
    resources["logical_routers"].append(_router("lr-2"))
    cloner.clone_config(
        client,
        _backup(tmp_path, resources),
        "dst",
        name_prefix="C_",
        include_network=True,
        dry_run=False,
    )
    bodies: dict[tuple[str, str], Any] = {
        (path, body["name"]): body for path, body in client.session.posts()
    }
    names = {name for _, name in bodies}
    # Interfaces keep hardware and variable names; everything else is renamed
    for iface in ("ethernet1/1", "$outside", "ae1", "ethernet1/1.10", "loopback.1", "tunnel.1"):
        assert iface in names and f"C_{iface}" not in names
    for obj in ("mgmt-ping", "comm-1", "bgp-auth", "rm-in", "af-1", "lr-1", "gre-1", "pbf-1"):
        assert f"C_{obj}" in names, obj

    eth = bodies[("ethernet-interfaces", "ethernet1/1")]
    assert eth["layer3"]["interface_management_profile"] == "C_mgmt-ping"
    assert bodies[("ethernet-interfaces", "ethernet1/2")]["aggregate_group"] == "ae1"
    assert bodies[("layer3-subinterfaces", "ethernet1/1.10")]["parent_interface"] == "ethernet1/1"
    assert bodies[("loopback-interfaces", "loopback.1")]["interface_management_profile"] == (
        "C_mgmt-ping"
    )

    rm = bodies[("bgp-route-maps", "C_rm-in")]["route_map"][0]["match"]
    assert rm == {"regular_community": "C_comm-1", "as_path_access_list": "C_aspath-1"}
    af = bodies[("bgp-address-family-profiles", "C_af-1")]
    assert af["ipv4"]["unicast"]["default_originate_map"] == "C_rm-in"
    filt = bodies[("bgp-filtering-profiles", "C_filt-1")]
    assert filt["ipv4"]["unicast"]["route_maps"]["inbound"] == "C_rm-in"
    redist = bodies[("bgp-redistribution-profiles", "C_redist-1")]
    assert redist["ipv4"]["unicast"]["connected"]["route_map"] == "C_redist-map"

    vrf = bodies[("logical-routers", "C_lr-1")]["vrf"][0]
    assert vrf["name"] == "default"
    assert vrf["interface"] == ["ethernet1/1"]
    pg = vrf["bgp"]["peer_group"][0]
    assert pg["name"] == "pg-1"
    assert pg["address_family"] == {"ipv4": "C_af-1"}
    assert pg["filtering_profile"] == {"ipv4": "C_filt-1"}
    assert pg["connection_options"] == {"authentication": "C_bgp-auth"}
    assert vrf["bgp"]["redistribution_profile"] == {"ipv4": {"unicast": "C_redist-1"}}
    area_if = vrf["ospf"]["area"][0]["interface"][0]
    assert area_if == {"name": "ethernet1/1", "authentication": "C_ospf-auth"}
    route = vrf["routing_table"]["ip"]["static_route"][0]
    assert route["nexthop"] == {"next_lr": "C_lr-2"}

    assert bodies[("gre-tunnels", "C_gre-1")]["tunnel_interface"] == "tunnel.1"
    pbf = bodies[("pbf-rules", "C_pbf-1")]
    assert pbf["from"] == {"zone": ["C_zone-in"]}
    assert pbf["action"] == {"forward": {"egress_interface": "ethernet1/2"}}


def test_inline_router_auth_profile_is_not_renamed() -> None:
    """A router's own ospf auth_profile shadows a cloned one of that name."""
    router = _router(
        ospf={
            "auth_profile": [{"name": "shared-name"}],
            "area": [
                {
                    "interface": [
                        {"name": "ethernet1/1", "authentication": "shared-name"},
                        {"name": "ethernet1/2", "authentication": "global-only"},
                    ]
                }
            ],
        }
    )
    renames = {
        "ospf_auth_profile": {"shared-name": "C_shared-name", "global-only": "C_global-only"}
    }
    rewrite_references("logical_routers", router, renames)
    area = router["vrf"][0]["ospf"]["area"][0]["interface"]
    assert [i["authentication"] for i in area] == ["shared-name", "C_global-only"]


def test_interface_keys_are_unrenamed() -> None:
    assert {
        "ethernet_interfaces",
        "aggregate_interfaces",
        "layer3_subinterfaces",
        "layer2_subinterfaces",
        "loopback_interfaces",
        "tunnel_interfaces",
        "vlan_interfaces",
        "dhcp_interfaces",
    } == UNRENAMED_KEYS


# ── Preflight ────────────────────────────────────────────────────────────────


def _inv(**names: set[str]) -> TargetInventory:
    return TargetInventory(folder="dst", names=dict(names))


def test_preflight_flags_profiles_missing_from_backup_and_target() -> None:
    resources = {
        "logical_routers": [
            _router(
                bgp={
                    "peer_group": [
                        {
                            "name": "pg-1",
                            "connection_options": {"authentication": "absent-auth"},
                            "address_family": {"ipv4": "none"},
                            "peer": [
                                {
                                    "name": "p1",
                                    "connection_options": {"authentication": "inherit"},
                                    "inherit": {"no": {"filtering_profile": {"ipv4": "in-target"}}},
                                }
                            ],
                        }
                    ]
                }
            )
        ],
        "ethernet_interfaces": [_row("ethernet1/1")],
    }
    result = check_references(
        resources,
        ["ethernet_interfaces", "logical_routers"],
        _inv(bgp_filtering_profile={"in-target"}, bgp_auth_profile=set()),
    )
    assert [(i.kind, i.name, i.status) for i in result.issues] == [
        ("bgp_auth_profile", "absent-auth", "missing")
    ]
    assert result.blocked and not result.skip


def test_preflight_skip_object_cascades_to_dependants() -> None:
    resources = {
        "bgp_route_maps": [
            _row("rm-1", route_map=[{"name": 10, "match": {"regular_community": "gone"}}])
        ],
        "bgp_filtering_profiles": [
            _row("filt-1", ipv4={"unicast": {"route_maps": {"inbound": "rm-1"}}})
        ],
    }
    result = check_references(
        resources,
        ["bgp_route_maps", "bgp_filtering_profiles"],
        _inv(community_list=set(), bgp_route_map=set()),
        on_missing_reference="strip_member",
    )
    assert result.skip == {
        ("bgp_route_maps", "rm-1"): "`gone` in route_map.match.regular_community: "
        "dropping it would change routing or forwarding",
        ("bgp_filtering_profiles", "filt-1"): "`rm-1` in ipv4.unicast.route_maps.inbound: "
        "dropping it would change routing or forwarding",
    }


def test_preflight_interfaces_are_unverifiable_not_missing() -> None:
    resources = {
        "ethernet_interfaces": [
            _row("ethernet1/1"),
            {"id": "x", "name": "ethernet1/4", "device": "SER1"},
        ],
        "gre_tunnels": [
            _row("gre-1", tunnel_interface="tunnel.9", local_address={"interface": "ethernet1/4"})
        ],
        "logical_routers": [_router()],
    }
    result = check_references(
        resources,
        ["ethernet_interfaces", "logical_routers", "gre_tunnels"],
        _inv(interface=set()),
    )
    found = {(i.name, i.status): i.detail for i in result.issues}
    # ethernet1/1 is cloned; the others cannot be seen from a folder
    assert set(found) == {("tunnel.9", "unverifiable"), ("ethernet1/4", "unverifiable")}
    assert "SER1" in found[("ethernet1/4", "unverifiable")]
    assert not result.blocked


def test_preflight_device_rows_neither_provide_nor_get_checked() -> None:
    resources = {
        "ethernet_interfaces": [
            {"id": "x", "name": "ethernet1/1", "device": "SER1", "layer3": {}},
            {
                "id": "y",
                "name": "ethernet1/2",
                "device": "SER1",
                "layer3": {"interface_management_profile": "absent"},
            },
        ]
    }
    result = check_references(
        resources, ["ethernet_interfaces"], _inv(interface_management_profile=set())
    )
    assert result.issues == []


def test_preflight_lists_without_an_api_are_unverifiable() -> None:
    session = Session()
    inv = fetch_target_inventory(session, "dst", network=True)
    assert "500" in inv.unreadable["access_list"]
    resources = {
        "bgp_route_maps": [
            _row("rm-1", route_map=[{"match": {"ipv4": {"address": {"access_list": "acl-1"}}}}])
        ]
    }
    result = check_references(resources, ["bgp_route_maps"], inv)
    assert [(i.name, i.status) for i in result.issues] == [("acl-1", "unverifiable")]
    assert not result.blocked


def test_network_catalogues_are_read_only_for_network_clones() -> None:
    session = Session()
    fetch_target_inventory(session, "dst")
    assert not any("/config/network/v1/logical-routers" in url for _, url, _ in session.calls)
    session = Session({"/logical-routers": [{"name": "lr-t"}]})
    inv = fetch_target_inventory(session, "dst", network=True)
    assert inv.names["logical_router"] == {"lr-t"}
    assert "ethernet1/1" not in inv.names["interface"]


def test_clone_preflight_reads_network_catalogues_only_with_network(tmp_path: Path) -> None:
    session = Session()
    client = Client(session)
    client.oauth_client = None  # type: ignore[attr-defined]
    src = _backup(tmp_path, {"logical_routers": [_router()], "tags": [{"name": "t"}]})

    import scm_harbourmaster_mcp.audit.extractor as extractor

    real = extractor._bearer_session_for
    extractor._bearer_session_for = lambda c: session  # type: ignore[assignment]
    try:
        cloner.clone_config(client, src, "dst", on_missing_reference="fail")
        plain = [url for m, url, _ in session.calls if m == "GET"]
        session.calls.clear()
        report = cloner.clone_config(
            client, src, "dst", on_missing_reference="fail", include_network=True
        )
    finally:
        extractor._bearer_session_for = real
    with_net = [url for m, url, _ in session.calls if m == "GET"]
    assert not any(u.endswith("/logical-routers") for u in plain)
    assert any(u.endswith("/logical-routers") for u in with_net)
    # The router's interface is not in the (empty) target: unverifiable
    assert report.preflight is not None
    assert [(i.kind, i.status) for i in report.preflight.issues] == [("interface", "unverifiable")]
