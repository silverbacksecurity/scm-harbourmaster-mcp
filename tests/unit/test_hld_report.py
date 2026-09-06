"""Unit tests for the Prisma SASE HLD AS-IS report builder."""

from __future__ import annotations

import pytest

from scm_harbourmaster_mcp.audit.asbuilt_report import _NA, _nested
from scm_harbourmaster_mcp.audit.asbuilt_report import AsBuiltReportBuilder as HLDReportBuilder
from scm_harbourmaster_mcp.audit.models import AuditSnapshot

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def empty_snap() -> AuditSnapshot:
    """Snapshot with no SCM data — all ⚠️ placeholder paths."""
    return AuditSnapshot(folder="Test-Folder", tenant_id="tsg-test-0001")


@pytest.fixture()
def rn_snap() -> AuditSnapshot:
    """Snapshot with two Remote Networks."""
    snap = AuditSnapshot(folder="Acme-Corp", tenant_id="tsg-acme-123")
    snap.remote_networks = [
        {
            "name": "London-HQ",
            "region": "europe-west",
            "spn_name": "eu-spn1",
            "ipsec_tunnel": "tunnel-london",
            "secondary_ipsec_tunnel": "tunnel-london-bk",
            "subnets": ["10.1.0.0/24", "10.1.1.0/24"],
            "ecmp_load_balancing": False,
            "license_type": "FWAAS-AGGREGATE",
        },
        {
            "name": "NYC-Office",
            "region": "us-east",
            "spn_name": "us-east-spn1",
            "ipsec_tunnel": "tunnel-nyc",
            "secondary_ipsec_tunnel": "",
            "subnets": ["10.2.0.0/24"],
            "ecmp_load_balancing": True,
            "license_type": "FWAAS-AGGREGATE",
        },
    ]
    snap.ike_gateways = [
        {
            "name": "tunnel-london",
            "peer_address": {"ip": "1.2.3.4"},
            "version": 2,
            "local_id": {"type": "ipaddr", "value": "5.6.7.8"},
        }
    ]
    snap.ipsec_tunnels = [{"name": "tunnel-london", "auto_key": {"ike_gateway": "tunnel-london"}}]
    return snap


@pytest.fixture()
def full_snap() -> AuditSnapshot:
    """Snapshot with all resource types populated."""
    snap = AuditSnapshot(folder="Acme-Corp", tenant_id="tsg-acme-123")

    snap.remote_networks = [
        {
            "name": "London-HQ",
            "region": "europe-west",
            "spn_name": "eu-spn1",
            "ipsec_tunnel": "tunnel-london",
            "secondary_ipsec_tunnel": "",
            "subnets": ["10.1.0.0/24"],
            "ecmp_load_balancing": False,
            "license_type": "FWAAS-AGGREGATE",
        }
    ]
    snap.service_connections = [
        {
            "name": "Corp-DC-London",
            "region": "europe-west",
            "ipsec_tunnel": "scn-dc-london",
            "secondary_ipsec_tunnel": "",
            "subnets": ["10.0.0.0/16"],
            "onboarding_type": "bgp",
            "nat_pool": "",
            "backup_SC": "",
        }
    ]
    snap.network_locations = [
        {
            "value": "europe-west",
            "display": "EU West",
            "region": "europe-west",
            "aggregate_region": "EMEA",
            "continent": "Europe",
        },
        {
            "value": "us-east",
            "display": "US East",
            "region": "us-east",
            "aggregate_region": "AMER",
            "continent": "North America",
        },
    ]
    snap.bandwidth_allocations = [
        {
            "name": "europe-west",
            "allocated_bandwidth": 500,
            "spn_name_list": ["eu-spn1", "eu-spn2"],
            "qos": {"enabled": True},
        }
    ]
    snap.bgp_routing_config = {
        "routing_preference": "hot-potato",
        "backbone_routing": "enabled",
        "accept_route_over_SC": True,
        "outbound_routes_for_services": True,
        "add_host_route_to_ike_peer": False,
        "withdraw_static_route": False,
    }
    snap.mobile_agent_infrastructure = [
        {
            "name": "Default",
            "portal_hostname": "gp.acme.com",
            "ip_pools": ["192.168.100.0/24"],
            "static_ip_pools": ["192.168.200.0/28"],
            "ipv6": False,
            "enable_wins": False,
            "udp_queries": True,
        }
    ]
    snap.mobile_agent_global_settings = {"agent_version": "6.2", "manual_gateway": False}
    snap.mobile_agent_auth_settings = [
        {
            "name": "gp-auth",
            "authentication_profile": "saml-entra",
            "os": ["windows", "macos"],
            "user_credential_or_client_cert_required": True,
        }
    ]
    snap.forwarding_profiles = [
        {"name": "default-fp", "type": "global", "definition_method": "auto", "description": ""}
    ]
    snap.authentication_profiles = [
        {
            "name": "saml-entra",
            "method": {"saml": {"server_profile": "Entra-ID"}},
            "multi_factor_auth": {"enable": True},
            "single_sign_on": {},
            "user_domain": "acme.com",
        }
    ]
    snap.saml_server_profiles = [
        {
            "name": "Entra-ID",
            "entity_id": "https://sts.windows.net/abc-123",
            "sso_url": "https://login.microsoftonline.com/abc-123/saml2",
            "want_auth_requests_signed": True,
            "validate_idp_certificate": True,
            "folder": "Acme-Corp",
            "id": "sp-001",
        }
    ]
    snap.hip_profiles = [
        {
            "name": "corp-compliant",
            "description": "Corp managed devices",
            "match": [{"key": "is-managed", "value": "yes"}],
        }
    ]
    snap.hip_objects = [{"name": "win11-check", "description": "Windows 11 posture check"}]
    snap.anti_spyware_profiles = [
        {"name": "best-practice", "description": "PAN best practice anti-spyware"}
    ]
    snap.vulnerability_profiles = [{"name": "best-practice-vuln", "description": ""}]
    snap.wildfire_profiles = [{"name": "best-practice-wf", "description": ""}]
    snap.decryption_profiles = [{"name": "no-decrypt-exceptions", "description": ""}]
    snap.decryption_rules = [{"name": "decrypt-all-ssl", "action": "decrypt", "description": ""}]
    snap.url_access_profiles = [
        {"name": "block-malicious", "description": "Block malware/phishing categories"}
    ]
    snap.syslog_profiles = [
        {
            "name": "splunk-syslog",
            "servers": [
                {
                    "name": "splunk-hec",
                    "server": "10.0.1.10",
                    "port": 514,
                    "transport": "TLS",
                    "format": "LEEF",
                }
            ],
        }
    ]
    snap.http_server_profiles = [
        {
            "name": "cdl-http",
            "server": [
                {
                    "name": "cdl-endpoint",
                    "address": "cdn.paloaltonetworks.com",
                    "port": 443,
                    "protocol": "HTTPS",
                }
            ],
        }
    ]
    snap.log_forwarding_profiles = [
        {"name": "forward-to-splunk", "description": "Forward all logs to Splunk"}
    ]
    snap.ike_crypto_profiles = [
        {
            "name": "Suite-B-GCM-128",
            "dh_group": ["group19"],
            "encryption": ["aes-128-gcm"],
            "hash": ["sha256"],
            "lifetime": {"hours": 8},
        }
    ]
    snap.ipsec_crypto_profiles = [
        {"name": "Suite-B-GCM-128", "esp": {"encryption": ["aes-128-gcm"]}, "dh_group": "group19"}
    ]
    snap.security_rules_pre = [
        {
            "name": "allow-internal",
            "source": ["trust"],
            "destination": ["untrust"],
            "application": ["ssl", "web-browsing"],
            "action": "allow",
            "profile_setting": {"group": ["strict-profile"]},
            "source_zones": ["trust"],
            "destination_zones": ["untrust"],
        }
    ]
    snap.qos_profiles = [
        {"name": "realtime-qos", "description": "VoIP and video priority", "id": "qos-001"}
    ]
    snap.extraction_errors = ["some_resource: Connection timeout"]
    return snap


def _build(snap: AuditSnapshot, **kwargs: str) -> str:
    """Convenience: build HLD markdown from snap."""
    defaults = {"customer_name": "Acme Corp", "mssp_name": "TestMSSP", "doc_version": "1.0"}
    defaults.update(kwargs)
    return HLDReportBuilder(snap, **defaults).to_markdown()  # type: ignore[arg-type]


# ── Section 1: Document Control ───────────────────────────────────────────────


class TestDocumentControl:
    def test_customer_name_in_header(self, empty_snap: AuditSnapshot) -> None:
        md = _build(empty_snap, customer_name="Beta Ltd")
        assert "Beta Ltd" in md

    def test_mssp_name_in_header(self, empty_snap: AuditSnapshot) -> None:
        md = _build(empty_snap, mssp_name="CyberGuard MSSP")
        assert "CyberGuard MSSP" in md

    def test_doc_version_in_header(self, empty_snap: AuditSnapshot) -> None:
        md = _build(empty_snap, doc_version="2.3")
        assert "2.3" in md

    def test_tenant_id_in_document_control(self, empty_snap: AuditSnapshot) -> None:
        md = _build(empty_snap)
        assert "tsg-test-0001" in md

    def test_folder_in_document_control(self, empty_snap: AuditSnapshot) -> None:
        md = _build(empty_snap)
        assert "Test-Folder" in md

    def test_change_history_table_present(self, empty_snap: AuditSnapshot) -> None:
        md = _build(empty_snap)
        assert "Change History" in md
        assert "Initial AS-BUILT" in md

    def test_folder_used_as_customer_name_when_not_set(self, empty_snap: AuditSnapshot) -> None:
        md = HLDReportBuilder(empty_snap).to_markdown()
        assert "Test-Folder" in md


# ── Section 2: Architecture ───────────────────────────────────────────────────


class TestArchitectureDiagram:
    def test_mermaid_block_present(self, empty_snap: AuditSnapshot) -> None:
        md = _build(empty_snap)
        assert "```mermaid" in md
        assert "graph TB" in md

    def test_prisma_access_cloud_node_present(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "Prisma Access" in md
        assert "PAN SASE Fabric" in md

    def test_rn_nodes_use_name_as_id(self, rn_snap: AuditSnapshot) -> None:
        md = _build(rn_snap)
        # Hyphens and spaces in names become underscores in Mermaid node IDs
        assert "RN_London_HQ" in md
        assert "RN_NYC_Office" in md

    def test_rn_nodes_show_region(self, rn_snap: AuditSnapshot) -> None:
        md = _build(rn_snap)
        assert "europe-west" in md
        assert "us-east" in md

    def test_rn_edges_use_ipsec_label(self, rn_snap: AuditSnapshot) -> None:
        md = _build(rn_snap)
        assert "IPSec" in md
        assert "BGP" in md

    def test_scn_nodes_appear_in_diagram(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "SCN_Corp_DC_London" in md

    def test_mu_nodes_appear_in_diagram(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "MU_Default" in md

    def test_mu_portal_hostname_in_diagram(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "gp.acme.com" in md

    def test_scm_manages_pa_edge(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "SCM" in md
        assert "manages" in md

    def test_no_rn_group_when_empty(self, empty_snap: AuditSnapshot) -> None:
        md = _build(empty_snap)
        assert "Remote Networks (Branch Sites)" not in md

    def test_no_scn_group_when_empty(self, empty_snap: AuditSnapshot) -> None:
        md = _build(empty_snap)
        # The Mermaid diagram subgraph is omitted when empty; the exec summary row still shows
        assert "subgraph SCN_GROUP" not in md

    def test_compute_locations_in_diagram(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "EU West" in md or "europe-west" in md

    def test_rn_subnet_shown_in_diagram(self, rn_snap: AuditSnapshot) -> None:
        md = _build(rn_snap)
        assert "10.1.0.0/24" in md


class TestComputeLocations:
    def test_locations_table_populated(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "EU West" in md
        assert "EMEA" in md
        assert "Europe" in md

    def test_locations_warning_when_empty(self, empty_snap: AuditSnapshot) -> None:
        md = _build(empty_snap)
        assert "Manual input required" in md

    def test_bandwidth_table_populated(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "500" in md  # allocated bandwidth
        assert "eu-spn1" in md


# ── Section 3: Prisma Access Infrastructure ──────────────────────────────────


class TestRemoteNetworks:
    def test_rn_table_shows_all_sites(self, rn_snap: AuditSnapshot) -> None:
        md = _build(rn_snap)
        assert "London-HQ" in md
        assert "NYC-Office" in md

    def test_rn_table_shows_spn(self, rn_snap: AuditSnapshot) -> None:
        md = _build(rn_snap)
        assert "eu-spn1" in md
        assert "us-east-spn1" in md

    def test_rn_table_shows_primary_tunnel(self, rn_snap: AuditSnapshot) -> None:
        md = _build(rn_snap)
        assert "tunnel-london" in md
        assert "tunnel-nyc" in md

    def test_rn_secondary_tunnel_shown(self, rn_snap: AuditSnapshot) -> None:
        md = _build(rn_snap)
        assert "tunnel-london-bk" in md

    def test_rn_ecmp_shown(self, rn_snap: AuditSnapshot) -> None:
        md = _build(rn_snap)
        assert "Yes" in md  # NYC-Office has ECMP

    def test_ike_gateway_peer_ip_in_tunnel_detail(self, rn_snap: AuditSnapshot) -> None:
        md = _build(rn_snap)
        assert "1.2.3.4" in md

    def test_rn_warning_when_empty(self, empty_snap: AuditSnapshot) -> None:
        md = _build(empty_snap)
        assert "No Remote Networks found" in md

    def test_bgp_routing_config_rendered(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "hot-potato" in md
        assert "BGP Routing Configuration" in md

    def test_qos_profiles_shown(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "realtime-qos" in md


class TestServiceConnections:
    def test_scn_table_shows_name_region(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "Corp-DC-London" in md
        assert "europe-west" in md

    def test_scn_table_shows_subnets(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "10.0.0.0/16" in md

    def test_scn_onboarding_type_shown(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "bgp" in md

    def test_scn_warning_when_empty(self, empty_snap: AuditSnapshot) -> None:
        md = _build(empty_snap)
        assert "No Service Connections found" in md


class TestMobileUsers:
    def test_portal_hostname_shown(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "gp.acme.com" in md

    def test_ip_pools_shown(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "192.168.100.0/24" in md

    def test_static_ip_pools_shown(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "192.168.200.0/28" in md

    def test_global_settings_agent_version(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "6.2" in md

    def test_auth_settings_profile_shown(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "saml-entra" in md

    def test_auth_settings_os_shown(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "windows" in md

    def test_forwarding_profiles_shown(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "default-fp" in md

    def test_mu_warning_when_empty(self, empty_snap: AuditSnapshot) -> None:
        md = _build(empty_snap)
        assert "Mobile agent infrastructure settings not found" in md


# ── Section 4: SD-WAN Placeholders ───────────────────────────────────────────


class TestSDWanPlaceholders:
    def test_sdwan_section_present(self, empty_snap: AuditSnapshot) -> None:
        md = _build(empty_snap)
        assert "Prisma SD-WAN" in md

    def test_sdwan_fallback_noted(self, empty_snap: AuditSnapshot) -> None:
        md = _build(empty_snap)
        assert "SD-WAN data not available" in md
        assert "Prisma SD-WAN portal" in md

    def test_sdwan_has_ion_inventory_table(self, empty_snap: AuditSnapshot) -> None:
        md = _build(empty_snap)
        assert "Edge Device Inventory" in md
        assert "ION Model" in md

    def test_sdwan_ha_section_present(self, empty_snap: AuditSnapshot) -> None:
        md = _build(empty_snap)
        assert "High Availability" in md


class TestSDWanWanIpEnrichmentAndDetectedIps:
    """§4.2.1 RFC1918 flagging and §8.1.4 detected-public-IP/ISP attribution."""

    def test_rfc1918_flagged_on_public_circuit(self, empty_snap: AuditSnapshot) -> None:
        empty_snap.sdwan_sites = [{"id": "site-1", "name": "Branch-1"}]
        empty_snap.sdwan_elements = [{"id": "elem-1", "site_id": "site-1", "name": "ION-1"}]
        empty_snap.sdwan_wan_ips = [
            {
                "site_name": "Branch-1",
                "element_name": "ION-1",
                "interface_name": "1",
                "used_for": "public",
                "wan_network": "ISP2",
                "circuit_name": "ISP2-HUB-01",
                "config_type": "static",
                "operational_state": "up",
                "ipv4_addresses": ["10.100.202.9/29"],
                "ipv6_addresses": [],
            }
        ]
        md = _build(empty_snap)
        assert "10.100.202.9/29 ⚠️ RFC1918" in md

    def test_private_circuit_not_flagged(self, empty_snap: AuditSnapshot) -> None:
        empty_snap.sdwan_sites = [{"id": "site-1", "name": "Branch-1"}]
        empty_snap.sdwan_elements = [{"id": "elem-1", "site_id": "site-1", "name": "ION-1"}]
        empty_snap.sdwan_wan_ips = [
            {
                "site_name": "Branch-1",
                "element_name": "ION-1",
                "interface_name": "2",
                "used_for": "private",
                "operational_state": "up",
                "ipv4_addresses": ["10.1.1.1/24"],
                "ipv6_addresses": [],
            }
        ]
        md = _build(empty_snap)
        assert "10.1.1.1/24 ⚠️ RFC1918" not in md
        assert "10.1.1.1/24" in md

    def test_no_sdwan_renders_without_error(self, empty_snap: AuditSnapshot) -> None:
        md = _build(empty_snap)  # must not raise (no KeyError etc.)
        assert "Live WAN IP Addresses" in md

    def test_section_8_1_4_absent_without_sdwan(self, empty_snap: AuditSnapshot) -> None:
        md = _build(empty_snap)
        assert "8.1.4 SD-WAN Detected Public IPs" not in md

    def test_section_8_1_4_stub_when_sdwan_but_no_detected_data(
        self, empty_snap: AuditSnapshot
    ) -> None:
        empty_snap.sdwan_sites = [{"id": "site-1", "name": "Branch-1"}]
        md = _build(empty_snap)
        assert "8.1.4 SD-WAN Detected Public IPs" in md
        assert "No detected public IP data returned" in md

    def test_section_8_1_4_shows_isp_and_nat_mismatch(self, empty_snap: AuditSnapshot) -> None:
        empty_snap.sdwan_sites = [{"id": "site-1", "name": "Branch-1"}]
        empty_snap.sdwan_elements = [{"id": "elem-1", "site_id": "site-1", "name": "HUB ION 1"}]
        empty_snap.sdwan_wan_ips = [
            {
                "element_id": "elem-1",
                "used_for": "public",
                "ipv4_addresses": ["10.100.202.9/29"],
            }
        ]
        empty_snap.sdwan_detected_public_ips = [
            {
                "site_name": "Branch-1",
                "element_id": "elem-1",
                "element_name": "HUB ION 1",
                "connected": True,
                "detected_public_ip": "31.121.13.73",
                "enrichment": [
                    {
                        "ip": "31.121.13.73",
                        "isp": "BT-UK-AS British Telecommunications PLC",
                        "asn": "AS2856",
                        "netname": "BTNET-CUSTOMER",
                    }
                ],
            }
        ]
        md = _build(empty_snap)
        assert "31.121.13.73" in md
        assert "AS2856" in md
        assert "BTNET-CUSTOMER" in md
        assert "NAT/CGNAT" in md  # configured 10.100.202.9 != detected 31.121.13.73

    def test_section_8_1_4_match_when_configured_equals_detected(
        self, empty_snap: AuditSnapshot
    ) -> None:
        empty_snap.sdwan_sites = [{"id": "site-1", "name": "Branch-1"}]
        empty_snap.sdwan_elements = [{"id": "elem-1", "site_id": "site-1", "name": "HUB ION 1"}]
        empty_snap.sdwan_wan_ips = [
            {"element_id": "elem-1", "used_for": "public", "ipv4_addresses": ["31.121.13.73/29"]}
        ]
        empty_snap.sdwan_detected_public_ips = [
            {
                "site_name": "Branch-1",
                "element_id": "elem-1",
                "element_name": "HUB ION 1",
                "connected": True,
                "detected_public_ip": "31.121.13.73",
            }
        ]
        md = _build(empty_snap)
        assert "matches configured WAN IP" in md


class TestSection42ProviderAsFromEnrichment:
    """§4.2 'Provider AS' column cross-references §4.2.1 wan_ips enrichment,
    since the live wannetworks API never populates provider_as_n itself."""

    def test_provider_as_from_wan_ip_enrichment_when_provider_as_n_empty(
        self, empty_snap: AuditSnapshot
    ) -> None:
        empty_snap.sdwan_wan_networks = [{"name": "ISP2", "type": "publicwan", "provider_as_n": ""}]
        empty_snap.sdwan_wan_ips = [
            {
                "site_name": "Branch-1",
                "element_name": "ION-1",
                "interface_name": "1",
                "used_for": "public",
                "wan_network": "ISP2",
                "operational_state": "up",
                "ipv4_addresses": ["31.121.13.73/29"],
                "ipv6_addresses": [],
                "enrichment": [
                    {
                        "isp": "British Telecommunications PLC",
                        "asn": "AS2856",
                    }
                ],
            }
        ]
        md = _build(empty_snap)
        assert "British Telecommunications PLC (AS2856)" in md

    def test_provider_as_falls_back_to_manual_input_without_enrichment(
        self, empty_snap: AuditSnapshot
    ) -> None:
        empty_snap.sdwan_wan_networks = [{"name": "ISP2", "type": "publicwan", "provider_as_n": ""}]
        empty_snap.sdwan_wan_ips = [
            {
                "site_name": "Branch-1",
                "element_name": "ION-1",
                "interface_name": "1",
                "used_for": "public",
                "wan_network": "ISP2",
                "operational_state": "up",
                "ipv4_addresses": ["31.121.13.73/29"],
                "ipv6_addresses": [],
                # no "enrichment" key at all — enrichment was never run.
            }
        ]
        md = _build(empty_snap)
        assert _NA in md

    def test_provider_as_n_preferred_over_enrichment_when_present(
        self, empty_snap: AuditSnapshot
    ) -> None:
        empty_snap.sdwan_wan_networks = [
            {"name": "ISP2", "type": "publicwan", "provider_as_n": "64512"}
        ]
        empty_snap.sdwan_wan_ips = [
            {
                "site_name": "Branch-1",
                "element_name": "ION-1",
                "interface_name": "1",
                "used_for": "public",
                "wan_network": "ISP2",
                "operational_state": "up",
                "ipv4_addresses": ["31.121.13.73/29"],
                "ipv6_addresses": [],
                "enrichment": [
                    {
                        "isp": "British Telecommunications PLC",
                        "asn": "AS2856",
                    }
                ],
            }
        ]
        md = _build(empty_snap)
        section_42 = md.split("4.2 Underlay WAN Configuration", 1)[1].split(
            "4.2.1 Live WAN IP Addresses", 1
        )[0]
        assert "64512" in section_42
        assert "British Telecommunications PLC (AS2856)" not in section_42

    def test_no_crash_when_wan_networks_present_but_wan_ips_empty(
        self, empty_snap: AuditSnapshot
    ) -> None:
        empty_snap.sdwan_wan_networks = [{"name": "ISP2", "type": "publicwan", "provider_as_n": ""}]
        md = _build(empty_snap)  # must not raise
        assert "4.2 Underlay WAN Configuration" in md
        assert _NA in md

    def test_no_crash_when_wan_networks_empty(self, empty_snap: AuditSnapshot) -> None:
        empty_snap.sdwan_wan_ips = [
            {
                "site_name": "Branch-1",
                "element_name": "ION-1",
                "interface_name": "1",
                "used_for": "public",
                "wan_network": "ISP2",
                "operational_state": "up",
                "ipv4_addresses": ["31.121.13.73/29"],
                "ipv6_addresses": [],
                "enrichment": [{"isp": "British Telecommunications PLC", "asn": "AS2856"}],
            }
        ]
        md = _build(empty_snap)  # must not raise
        assert "4.2 Underlay WAN Configuration" in md


# ── Section 5: SSE & Zero Trust ──────────────────────────────────────────────


class TestSSEPolicies:
    def test_threat_prevention_profiles_shown(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "best-practice" in md

    def test_vulnerability_profiles_shown(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "best-practice-vuln" in md

    def test_wildfire_profiles_shown(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "best-practice-wf" in md

    def test_file_blocking_profiles_shown(self, full_snap: AuditSnapshot) -> None:
        full_snap.file_blocking_profiles = [{"name": "block-executables", "description": ""}]
        md = _build(full_snap)
        assert "block-executables" in md

    def test_decryption_profiles_shown(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "no-decrypt-exceptions" in md

    def test_decryption_rules_shown(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "decrypt-all-ssl" in md

    def test_url_access_profiles_shown(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "block-malicious" in md

    def test_casb_placeholder_present(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "SaaS Security" in md
        assert "Manual input required" in md

    def test_ztna_rules_shown(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "allow-internal" in md

    def test_ztna_truncates_beyond_20_rules(self, full_snap: AuditSnapshot) -> None:
        full_snap.security_rules_pre = [
            {
                "name": f"rule-{i}",
                "source": ["trust"],
                "destination": ["untrust"],
                "application": ["any"],
                "action": "allow",
                "source_zones": ["trust"],
                "destination_zones": ["untrust"],
            }
            for i in range(25)
        ]
        md = _build(full_snap)
        assert "Showing first 20 of 25" in md


# ── Section 6: Identity & Posture ────────────────────────────────────────────


class TestIdentityPosture:
    def test_cie_placeholder_present(self, empty_snap: AuditSnapshot) -> None:
        md = _build(empty_snap)
        assert "Cloud Identity Engine" in md
        assert "Manual input required" in md

    def test_auth_profile_method_shown(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "saml-entra" in md
        assert "saml" in md.lower()

    def test_auth_profile_mfa_shown(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "True" in md  # MFA enabled

    def test_saml_profile_entity_id_shown(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "https://sts.windows.net/abc-123" in md

    def test_saml_profile_sso_url_shown(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "login.microsoftonline.com" in md

    def test_hip_profiles_shown(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "corp-compliant" in md
        assert "Corp managed devices" in md

    def test_hip_objects_shown(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "win11-check" in md

    def test_hip_not_present_when_empty(self, empty_snap: AuditSnapshot) -> None:
        md = _build(empty_snap)
        assert "No HIP profiles found" in md

    def test_auth_warning_when_no_profiles(self, empty_snap: AuditSnapshot) -> None:
        md = _build(empty_snap)
        assert "No authentication profiles found" in md


# ── Section 7: Observability ─────────────────────────────────────────────────


class TestObservability:
    def test_adem_placeholder_present(self, empty_snap: AuditSnapshot) -> None:
        md = _build(empty_snap)
        assert "ADEM" in md
        assert "Manual input required" in md

    def test_adem_3day_window_labeled_when_used(self, empty_snap: AuditSnapshot) -> None:
        empty_snap.adem_agent_summary = {"muAgent": {"clients": 5, "score": 90}}
        empty_snap.adem_timerange_used = "last_3_day"
        md = _build(empty_snap)
        assert "last 3 days" in md
        assert "Fell back" not in md

    def test_adem_30day_fallback_noted_when_used(self, empty_snap: AuditSnapshot) -> None:
        empty_snap.adem_agent_summary = {"muAgent": {"clients": 5, "score": 90}}
        empty_snap.adem_timerange_used = "last_30_day"
        md = _build(empty_snap)
        assert "last 30 days" in md
        assert "hasn't logged in recently" in md

    def test_cdl_placeholder_present(self, empty_snap: AuditSnapshot) -> None:
        md = _build(empty_snap)
        assert "Cortex Data Lake" in md

    def test_log_forwarding_profile_shown(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "forward-to-splunk" in md

    def test_syslog_server_shown(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "splunk-hec" in md
        assert "10.0.1.10" in md

    def test_syslog_transport_shown(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "TLS" in md

    def test_http_server_profile_shown(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "cdl-http" in md
        assert "cdn.paloaltonetworks.com" in md

    def test_soar_placeholder_present(self, empty_snap: AuditSnapshot) -> None:
        md = _build(empty_snap)
        assert "SOAR" in md
        assert "Manual input required" in md


# ── Section 8: MSSP Service Model ────────────────────────────────────────────


class TestMsspServiceModel:
    def test_raci_table_present(self, empty_snap: AuditSnapshot) -> None:
        pytest.skip("RACI section removed in AsBuiltReportBuilder restructure")

    def test_raci_mssp_column_uses_mssp_name(self, empty_snap: AuditSnapshot) -> None:
        md = _build(empty_snap, mssp_name="NetShield MSSP")
        assert "NetShield MSSP" in md  # mssp_name still appears in document header

    def test_macd_table_present(self, empty_snap: AuditSnapshot) -> None:
        pytest.skip("MACD/Change Management section removed in AsBuiltReportBuilder restructure")

    def test_itsm_placeholder_present(self, empty_snap: AuditSnapshot) -> None:
        pytest.skip("ITSM section removed in AsBuiltReportBuilder restructure")

    def test_sla_matrix_all_priorities(self, empty_snap: AuditSnapshot) -> None:
        pytest.skip("SLA matrix section removed in AsBuiltReportBuilder restructure")

    def test_p1_response_time_present(self, empty_snap: AuditSnapshot) -> None:
        pytest.skip("P1 response time section removed in AsBuiltReportBuilder restructure")


# ── Section 9: Appendices ────────────────────────────────────────────────────


class TestAppendices:
    def test_rn_subnets_in_appendix(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        # subnet appears in both section 3 detail and appendix 9.1
        assert md.count("10.1.0.0/24") >= 2

    def test_scn_subnets_in_appendix(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert md.count("10.0.0.0/16") >= 2

    def test_mu_ip_pools_in_appendix(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert md.count("192.168.100.0/24") >= 2

    def test_egress_ip_whitelist_placeholder(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "allocated-ips" in md
        assert "whitelist" in md.lower() or "Whitelist" in md

    def test_licence_inventory_placeholder(self, empty_snap: AuditSnapshot) -> None:
        md = _build(empty_snap)
        assert "Licence Inventory" in md or "License Inventory" in md
        assert "Customer Support Portal" in md or "CSP" in md

    def test_service_account_registry_present(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "gp-auth" in md  # from mobile_agent_auth_settings in §3.3.3

    def test_saml_profile_in_service_accounts(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "Entra-ID" in md
        assert "SAML IdP" in md

    def test_ike_crypto_profiles_in_appendix(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "Suite-B-GCM-128" in md
        assert "group19" in md
        assert "aes-128-gcm" in md

    def test_ipsec_crypto_profiles_in_appendix(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "IPSec Crypto" in md

    def test_extraction_errors_section_present(self, full_snap: AuditSnapshot) -> None:
        md = _build(full_snap)
        assert "Extraction Errors" in md
        assert "some_resource: Connection timeout" in md

    def test_no_extraction_errors_section_when_clean(self, empty_snap: AuditSnapshot) -> None:
        md = _build(empty_snap)
        # "Data Extraction Errors" heading still appears in ToC/exec summary
        # but no error list content should appear
        assert "some_resource" not in md


# ── Section integrity ─────────────────────────────────────────────────────────


class TestAllSectionsPresent:
    """Verify every required section heading appears in the output."""

    REQUIRED_HEADINGS = [
        "1. Document Control",
        "2. Deployed Prisma SASE Architecture",
        "2.1 AS-BUILT Architecture Diagram",
        "2.2 Management Plane Configuration",
        "2.3 Compute Locations",
        "3. Prisma Access: Infrastructure",
        "3.1 Remote Networks",
        "3.2 Service Connections",
        "3.3 Mobile Users",
        "4. Prisma SD-WAN",
        "4.1 Edge Device Inventory",
        "4.2 Underlay WAN",
        "4.3 App-Defined Routing",
        "4.4 High Availability",
        "5. Security Service Edge",
        "5.1 Threat Prevention",
        "5.2 Secure Web Gateway",
        "5.3 SaaS Security",
        "5.4 Zero Trust",
        "6. Identity",
        "6.1 Cloud Identity Engine",
        "6.2 Authentication Profiles",
        "6.3 Host Information Profile",
        "7. Observability",
        "7.1 Autonomous Digital Experience",
        "7.2 Cortex Data Lake",
        "7.3 Log Forwarding",
        "7.5 SOAR",
        "8. Appendices",
        "8.1 Subnets",
        "8.2 Hardware",
        "8.4 VPN Crypto",
    ]

    @pytest.mark.parametrize("heading", REQUIRED_HEADINGS)
    def test_heading_present(self, heading: str, empty_snap: AuditSnapshot) -> None:
        md = _build(empty_snap)
        assert heading in md, f"Missing heading: {heading!r}"


# ── Edge cases ────────────────────────────────────────────────────────────────


class TestEdgeCases:
    def test_name_with_dots_becomes_safe_mermaid_id(self) -> None:
        snap = AuditSnapshot(folder="test", tenant_id="t-1")
        snap.remote_networks = [
            {
                "name": "site.01.uk",
                "region": "uk",
                "spn_name": "spn",
                "ipsec_tunnel": "tun",
                "subnets": [],
                "ecmp_load_balancing": False,
            }
        ]
        md = _build(snap)
        assert "RN_site_01_uk" in md

    def test_rn_with_no_subnets_does_not_crash(self) -> None:
        snap = AuditSnapshot(folder="test", tenant_id="t-1")
        snap.remote_networks = [
            {
                "name": "no-subnets",
                "region": "us-east",
                "spn_name": "spn",
                "ipsec_tunnel": "tun",
                "subnets": [],
                "ecmp_load_balancing": False,
            }
        ]
        md = _build(snap)
        assert "no-subnets" in md

    def test_scn_with_no_nat_pool_shows_dash(self) -> None:
        snap = AuditSnapshot(folder="test", tenant_id="t-1")
        snap.service_connections = [
            {
                "name": "dc-1",
                "region": "us-east",
                "ipsec_tunnel": "scn-tun",
                "subnets": [],
                "onboarding_type": "static",
                "nat_pool": "",
            }
        ]
        md = _build(snap)
        assert "—" in md  # dash for empty nat pool

    def test_more_than_8_locations_truncated_in_diagram(self) -> None:
        snap = AuditSnapshot(folder="test", tenant_id="t-1")
        snap.network_locations = [
            {
                "value": f"loc-{i}",
                "display": f"Location {i}",
                "region": f"region-{i}",
                "aggregate_region": "AMER",
                "continent": "North America",
            }
            for i in range(12)
        ]
        md = _build(snap)
        # Diagram only shows first 8
        assert "LOC_loc_0" in md
        assert "LOC_loc_7" in md
        assert "LOC_loc_8" not in md

    def test_syslog_profile_with_no_servers_does_not_crash(self) -> None:
        snap = AuditSnapshot(folder="test", tenant_id="t-1")
        snap.syslog_profiles = [{"name": "empty-profile", "servers": []}]
        md = _build(snap)
        assert "empty-profile" in md

    def test_mu_infra_with_no_ip_pools_shows_placeholder(self) -> None:
        snap = AuditSnapshot(folder="test", tenant_id="t-1")
        snap.mobile_agent_infrastructure = [
            {
                "name": "Default",
                "portal_hostname": "",
                "ip_pools": [],
                "static_ip_pools": [],
                "ipv6": False,
                "enable_wins": False,
                "udp_queries": False,
            }
        ]
        md = _build(snap)
        assert "Manual input required" in md

    def test_auth_profile_with_no_mfa_key_does_not_crash(self) -> None:
        snap = AuditSnapshot(folder="test", tenant_id="t-1")
        snap.authentication_profiles = [
            {
                "name": "basic-auth",
                "method": {"local-database": {}},
                "user_domain": "",
                "single_sign_on": None,
            }
        ]
        md = _build(snap)
        assert "basic-auth" in md

    def test_multiple_extraction_errors_all_listed(self) -> None:
        snap = AuditSnapshot(folder="test", tenant_id="t-1")
        snap.extraction_errors = ["resource_a: timeout", "resource_b: 403 forbidden"]
        md = _build(snap)
        assert "resource_a: timeout" in md
        assert "resource_b: 403 forbidden" in md

    def test_empty_snap_produces_valid_markdown(self, empty_snap: AuditSnapshot) -> None:
        md = _build(empty_snap)
        # Must start with an H1
        assert md.lstrip().startswith("# ")
        # Must have multiple sections
        assert md.count("\n## ") >= 8


# ── _nested helper ────────────────────────────────────────────────────────────


class TestNestedHelper:
    def test_simple_key(self) -> None:
        assert _nested({"a": "v"}, "a") == "v"

    def test_two_levels(self) -> None:
        assert _nested({"a": {"b": "deep"}}, "a", "b") == "deep"

    def test_missing_key_returns_default(self) -> None:
        assert _nested({"a": 1}, "b") == ""
        assert _nested({"a": 1}, "b", default="fallback") == "fallback"

    def test_intermediate_none_returns_default(self) -> None:
        assert _nested({"a": None}, "a", "b") == ""

    def test_intermediate_non_dict_returns_default(self) -> None:
        assert _nested({"a": "string"}, "a", "b") == ""

    def test_integer_value_returned_as_string(self) -> None:
        assert _nested({"a": {"b": 42}}, "a", "b") == "42"
