"""Shared data models for the audit engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Status(StrEnum):
    FAIL = "fail"
    PASS = "pass"
    WARN = "warn"
    SKIP = "skip"  # could not evaluate (missing data / unsupported config)


@dataclass
class Finding:
    """A single audit finding from a BPA or NCSC check."""

    check_id: str
    title: str
    severity: Severity
    status: Status
    description: str
    remediation: str
    affected_objects: list[str] = field(default_factory=list)
    # Cross-references
    pan_bpa_ref: str = ""  # e.g. "BPA-SR-001"
    ncsc_refs: list[str] = field(default_factory=list)  # e.g. ["CAF-B2.b", "CE-FW-3", "10S-NS"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "status": self.status.value,
            "description": self.description,
            "remediation": self.remediation,
            "affected_objects": self.affected_objects,
            "pan_bpa_ref": self.pan_bpa_ref,
            "ncsc_refs": self.ncsc_refs,
        }


@dataclass
class AuditSnapshot:
    """
    Flat snapshot of SCM config pulled from the SDK for a single folder/tenant.

    Each field holds a list of Pydantic model dicts (via model_dump()) so the
    check engine can work purely with plain Python dicts — no SDK imports needed.
    """

    folder: str
    tenant_id: str

    # Objects
    addresses: list[dict[str, Any]] = field(default_factory=list)
    address_groups: list[dict[str, Any]] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)
    service_groups: list[dict[str, Any]] = field(default_factory=list)
    tags: list[dict[str, Any]] = field(default_factory=list)
    edls: list[dict[str, Any]] = field(default_factory=list)
    applications: list[dict[str, Any]] = field(default_factory=list)
    application_groups: list[dict[str, Any]] = field(default_factory=list)
    hip_objects: list[dict[str, Any]] = field(default_factory=list)
    hip_profiles: list[dict[str, Any]] = field(default_factory=list)

    # Security profiles
    anti_spyware_profiles: list[dict[str, Any]] = field(default_factory=list)
    vulnerability_profiles: list[dict[str, Any]] = field(default_factory=list)
    url_categories: list[dict[str, Any]] = field(default_factory=list)
    wildfire_profiles: list[dict[str, Any]] = field(default_factory=list)
    dns_security_profiles: list[dict[str, Any]] = field(default_factory=list)
    decryption_profiles: list[dict[str, Any]] = field(default_factory=list)
    file_blocking_profiles: list[dict[str, Any]] = field(default_factory=list)

    # Logging
    log_forwarding_profiles: list[dict[str, Any]] = field(default_factory=list)
    syslog_profiles: list[dict[str, Any]] = field(default_factory=list)

    # Policy rules
    security_rules_pre: list[dict[str, Any]] = field(default_factory=list)
    security_rules_post: list[dict[str, Any]] = field(default_factory=list)
    nat_rules_pre: list[dict[str, Any]] = field(default_factory=list)
    nat_rules_post: list[dict[str, Any]] = field(default_factory=list)
    # Legacy flat field kept for backwards compatibility — use all_nat_rules property
    nat_rules: list[dict[str, Any]] = field(default_factory=list)
    decryption_rules: list[dict[str, Any]] = field(default_factory=list)
    app_override_rules: list[dict[str, Any]] = field(default_factory=list)
    pbf_rules: list[dict[str, Any]] = field(default_factory=list)
    authentication_rules: list[dict[str, Any]] = field(default_factory=list)
    schedules: list[dict[str, Any]] = field(default_factory=list)

    # Network
    zones: list[dict[str, Any]] = field(default_factory=list)
    ike_gateways: list[dict[str, Any]] = field(default_factory=list)
    ipsec_tunnels: list[dict[str, Any]] = field(default_factory=list)
    zone_protection_profiles: list[dict[str, Any]] = field(default_factory=list)
    interface_mgmt_profiles: list[dict[str, Any]] = field(default_factory=list)
    bgp_filtering_profiles: list[dict[str, Any]] = field(default_factory=list)
    ospf_auth_profiles: list[dict[str, Any]] = field(default_factory=list)

    # Deployment
    remote_networks: list[dict[str, Any]] = field(default_factory=list)
    service_connections: list[dict[str, Any]] = field(default_factory=list)
    network_locations: list[dict[str, Any]] = field(default_factory=list)
    bandwidth_allocations: list[dict[str, Any]] = field(default_factory=list)
    bgp_routing_config: dict[str, Any] = field(default_factory=dict)
    internal_dns_servers: list[dict[str, Any]] = field(default_factory=list)

    # Mobile Agent / GlobalProtect
    mobile_agent_infrastructure: list[dict[str, Any]] = field(default_factory=list)
    mobile_agent_global_settings: dict[str, Any] = field(default_factory=dict)
    mobile_agent_auth_settings: list[dict[str, Any]] = field(default_factory=list)
    # SDK v0.15.0: GP Agent Profiles (connect method, tunnel MTU, app-settings)
    mobile_agent_agent_profiles: list[dict[str, Any]] = field(default_factory=list)
    # SDK v0.15.0: GP Tunnel Profiles (tunnel settings per profile)
    mobile_agent_tunnel_profiles: list[dict[str, Any]] = field(default_factory=list)
    mobile_agent_versions: list[str] = field(default_factory=list)
    forwarding_profiles: list[dict[str, Any]] = field(default_factory=list)
    # Forwarding profile sub-resources (explicit proxy, PAC file, regional proxies)
    forwarding_profile_destinations: list[dict[str, Any]] = field(default_factory=list)
    forwarding_profile_regional_proxies: list[dict[str, Any]] = field(default_factory=list)
    forwarding_profile_source_apps: list[dict[str, Any]] = field(default_factory=list)
    forwarding_profile_user_locations: list[dict[str, Any]] = field(default_factory=list)

    # Identity & Authentication
    authentication_profiles: list[dict[str, Any]] = field(default_factory=list)
    saml_server_profiles: list[dict[str, Any]] = field(default_factory=list)
    radius_server_profiles: list[dict[str, Any]] = field(default_factory=list)
    ldap_server_profiles: list[dict[str, Any]] = field(default_factory=list)

    # Network - extended
    ike_crypto_profiles: list[dict[str, Any]] = field(default_factory=list)
    ipsec_crypto_profiles: list[dict[str, Any]] = field(default_factory=list)
    qos_profiles: list[dict[str, Any]] = field(default_factory=list)
    url_access_profiles: list[dict[str, Any]] = field(default_factory=list)

    # Logging - extended
    http_server_profiles: list[dict[str, Any]] = field(default_factory=list)

    # Prisma SD-WAN (populated separately via prisma-sase SDK)
    sdwan_sites: list[dict[str, Any]] = field(default_factory=list)
    sdwan_elements: list[dict[str, Any]] = field(default_factory=list)
    sdwan_wan_interfaces: list[dict[str, Any]] = field(default_factory=list)
    sdwan_wan_networks: list[dict[str, Any]] = field(default_factory=list)
    sdwan_path_groups: list[dict[str, Any]] = field(default_factory=list)
    sdwan_policy_sets: list[dict[str, Any]] = field(default_factory=list)
    sdwan_priority_policy_sets: list[dict[str, Any]] = field(default_factory=list)
    sdwan_hub_clusters: list[dict[str, Any]] = field(default_factory=list)
    sdwan_spoke_clusters: list[dict[str, Any]] = field(default_factory=list)
    sdwan_bgp_peers: list[dict[str, Any]] = field(default_factory=list)
    sdwan_vpn_links: list[dict[str, Any]] = field(
        default_factory=list
    )  # resolved connection records
    sdwan_topology_mermaid: str = ""  # pre-built diagram
    sdwan_wan_ips: list[dict[str, Any]] = field(
        default_factory=list
    )  # live public/private WAN IPs per element interface
    sdwan_detected_public_ips: list[dict[str, Any]] = field(
        default_factory=list
    )  # post-NAT public IP per element, from element status config_and_events_from

    # NGFW managed-device WAN/internet-facing interface IPs (parsed from local
    # running-config XML via the NGFW Operations API — best-effort, requires entitlement)
    ngfw_interface_ips: list[dict[str, Any]] = field(default_factory=list)

    # Subscription licences (populated via Subscription Service API)
    licenses: list[dict[str, Any]] = field(default_factory=list)

    # CASB / DLP (populated via direct SCM Config REST calls)
    data_filtering_profiles: list[dict[str, Any]] = field(default_factory=list)
    data_objects: list[dict[str, Any]] = field(default_factory=list)
    saas_tenant_restrictions: list[dict[str, Any]] = field(default_factory=list)

    # ZTNA Connector (populated via /sse/connector/v2.0/api/)
    ztna_connectors: list[dict[str, Any]] = field(default_factory=list)
    ztna_connector_groups: list[dict[str, Any]] = field(default_factory=list)

    # Prisma Browser / RBI (populated via /seb/api/v1/)
    browser_device_groups: list[dict[str, Any]] = field(default_factory=list)
    browser_application_groups: list[dict[str, Any]] = field(default_factory=list)
    browser_user_groups: list[dict[str, Any]] = field(default_factory=list)
    # New endpoints added June 2026
    browser_users: list[dict[str, Any]] = field(default_factory=list)
    browser_devices: list[dict[str, Any]] = field(default_factory=list)
    browser_applications: list[dict[str, Any]] = field(default_factory=list)
    browser_plugins: list[dict[str, Any]] = field(default_factory=list)
    browser_user_requests: list[dict[str, Any]] = field(default_factory=list)

    # CDL / Strata Logging Service — log forwarding profiles (via /logging-service/logforwarding/v1/)
    cdl_syslog_profiles: list[dict[str, Any]] = field(default_factory=list)
    cdl_https_profiles: list[dict[str, Any]] = field(default_factory=list)
    cdl_email_profiles: list[dict[str, Any]] = field(default_factory=list)

    # SCM Management Structure (via /config/setup/v1/ — tenant-scoped, no folder param)
    scm_folders: list[dict[str, Any]] = field(default_factory=list)
    scm_snippets: list[dict[str, Any]] = field(default_factory=list)
    scm_labels: list[dict[str, Any]] = field(default_factory=list)

    # NGFW Managed Devices (via SCM SDK client.device.list / /config/v1/devices)
    ngfw_devices: list[dict[str, Any]] = field(default_factory=list)
    # NGFW HA pairs (via /config/ngfw/v1/ha-devices REST API)
    ngfw_ha_pairs: list[dict[str, Any]] = field(default_factory=list)
    # NGFW Routing — Logical Routers and BGP profiles (NGFW-scoped, not Prisma Access)
    ngfw_logical_routers: list[dict[str, Any]] = field(default_factory=list)
    ngfw_bgp_address_family_profiles: list[dict[str, Any]] = field(default_factory=list)
    ngfw_bgp_redistribution_profiles: list[dict[str, Any]] = field(default_factory=list)
    ngfw_bgp_auth_profiles: list[dict[str, Any]] = field(default_factory=list)
    ngfw_bgp_route_maps: list[dict[str, Any]] = field(default_factory=list)

    # Prisma AIRS — AI Runtime Security (via /aisec/v1/mgmt/ management API)
    airs_apps: list[dict[str, Any]] = field(default_factory=list)
    airs_security_profiles: list[dict[str, Any]] = field(default_factory=list)
    airs_deployment_profiles: list[dict[str, Any]] = field(default_factory=list)

    # IoT Security / Enterprise IoT / OT Security (formerly Zingbox)
    # via api.strata.paloaltonetworks.com/iot/pub/v1+v2 — same SASE OAuth token
    iot_devices: list[dict[str, Any]] = field(default_factory=list)
    iot_devices_total: int = 0  # total from API (may exceed fetched page)
    iot_alerts: list[dict[str, Any]] = field(default_factory=list)
    iot_alerts_total: int = 0
    iot_sites: list[dict[str, Any]] = field(default_factory=list)
    iot_licensed: bool = False  # False = not licensed / 404 from API
    iot_vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    iot_policy_recommendations: list[dict[str, Any]] = field(default_factory=list)

    # Enterprise DLP (via api.dlp.paloaltonetworks.com — ML-based, SaaS/Cloud SWG DLP)
    dlp_company_id: str = ""
    dlp_data_patterns: list[dict[str, Any]] = field(default_factory=list)
    dlp_data_profiles: list[dict[str, Any]] = field(default_factory=list)
    # Enterprise DLP v2 API additional resources
    dlp_filtering_profiles: list[dict[str, Any]] = field(default_factory=list)
    dlp_dictionaries: list[dict[str, Any]] = field(default_factory=list)
    dlp_document_types: list[dict[str, Any]] = field(default_factory=list)
    dlp_edm_datasets: list[dict[str, Any]] = field(default_factory=list)
    dlp_ocr_settings: list[dict[str, Any]] = field(default_factory=list)

    # SaaS Security Posture Management (via api.strata.paloaltonetworks.com/sspm/api/v1/)
    # same SASE OAuth token — covers posture, NHI, activity, third-party app discovery
    sspm_apps: list[dict[str, Any]] = field(default_factory=list)  # onboarded apps
    sspm_catalog: list[dict[str, Any]] = field(default_factory=list)  # supported app catalog
    sspm_licensed: bool = False  # False = 500/no apps; True = API reachable

    # Identity-SSPM (via api.strata.paloaltonetworks.com/sspm/identity/v1/)
    # NHI / identity posture: connected IdPs, MFA gaps, dormant accounts
    identity_sspm_idps: list[dict[str, Any]] = field(default_factory=list)
    identity_sspm_licensed: bool = False  # False = 404 / not provisioned

    # App Acceleration (via Insights v3.0 accelerated_applications resource)
    # 500 = feature not activated; populated when add_app_accl licence is active
    app_accl_apps: list[dict[str, Any]] = field(default_factory=list)
    app_accl_stats: dict[str, Any] = field(default_factory=dict)
    app_accl_licensed: bool = False

    # Traffic Steering Rules (via /sse/config/v1/traffic-steering-rules)
    traffic_steering_rules: list[dict[str, Any]] = field(default_factory=list)

    # Prisma Browser MSP tenant info (via api.sase.paloaltonetworks.com/mt/pab/)
    pab_tenant_regions: list[str] = field(default_factory=list)
    pab_tenant_directories: list[str] = field(default_factory=list)
    pab_tenant_licenses: list[dict[str, Any]] = field(default_factory=list)

    # Prisma Access Allocated Public IPs (via /config/v1/infrastructure/allocated-ips)
    # Each entry: {zone, node_name, address_type, node_type, ip_address_list: [...]}
    prisma_egress_ips: list[dict[str, Any]] = field(default_factory=list)

    # Autonomous DEM — live experience telemetry (muAgent + rnAgent). Default
    # window is last 3 days; extract_adem retries at last_30_day if that
    # comes back empty (e.g. low-activity lab tenants) — see
    # adem_timerange_used for which window actually produced the data below.
    adem_app_scores: list[dict[str, Any]] = field(default_factory=list)
    adem_agent_summary: dict[str, Any] = field(default_factory=dict)
    adem_errors: list[str] = field(default_factory=list)
    adem_timerange_used: str = "last_3_day"

    # Prisma Access Insights — live operational data (populated via Insights v3.0 API)
    # connected_mu_count: -1 = not retrieved, 0+ = live count from Insights API
    insights_connected_mu_count: int = -1
    insights_rn_status: list[dict[str, Any]] = field(default_factory=list)
    insights_sc_status: list[dict[str, Any]] = field(default_factory=list)
    insights_mu_status: list[dict[str, Any]] = field(default_factory=list)
    insights_rn_bandwidth: list[dict[str, Any]] = field(default_factory=list)
    insights_sc_bandwidth: list[dict[str, Any]] = field(default_factory=list)
    insights_tunnel_list: list[dict[str, Any]] = field(default_factory=list)
    insights_alerts: list[dict[str, Any]] = field(default_factory=list)
    insights_errors: list[str] = field(default_factory=list)

    # IAM (via api.sase.paloaltonetworks.com/iam/v1/)
    iam_roles: list[dict[str, Any]] = field(default_factory=list)
    iam_access_policies: list[dict[str, Any]] = field(default_factory=list)
    iam_service_accounts: list[dict[str, Any]] = field(default_factory=list)

    # Managed sub-tenants (SP/super-user level — tenancy/v1/tenants)
    managed_tenants: list[dict[str, Any]] = field(default_factory=list)

    # MT Monitor aggregate alerts (via api.sase.paloaltonetworks.com/mt/monitor/v1/agg/alerts)
    mt_monitor_alerts: list[dict[str, Any]] = field(default_factory=list)

    # Errors encountered during extraction (non-fatal)
    extraction_errors: list[str] = field(default_factory=list)

    @property
    def all_security_rules(self) -> list[dict[str, Any]]:
        return self.security_rules_pre + self.security_rules_post

    @property
    def all_nat_rules(self) -> list[dict[str, Any]]:
        """Combined pre + post NAT rules. Falls back to legacy flat nat_rules if pre/post empty."""
        combined = self.nat_rules_pre + self.nat_rules_post
        return combined if combined else self.nat_rules
