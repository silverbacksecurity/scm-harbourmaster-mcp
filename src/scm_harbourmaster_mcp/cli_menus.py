"""
CLI sub-menus and leaf operations for scm-harbourmaster-mcp.
Merged into cli.py's namespace via exec in cli.py.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich import box
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from .config.settings import TenantConfig

# These are imported from cli.py's namespace at runtime
# console, _print_banner, _menu_table, _section, _get_cli_client,
# _list_and_display, _save_json, _pause, _require_tenant


def _call_mcp_tool(tenant: TenantConfig, register_fn: Any, tool_name: str, **kwargs: Any) -> str:
    """Invoke an @mcp.tool()-decorated function directly, without going through
    the MCP protocol. Registers onto a throwaway FastMCP instance so the CLI can
    reuse the same (tested) business logic as the server tools, scoped to the
    already-authenticated `tenant` rather than a tenant_id lookup."""
    from mcp.server.fastmcp import FastMCP

    from .auth.oauth import get_scm_client

    mcp = FastMCP("cli-internal")
    # Prime the per-tenant config cache: the SD-WAN tools resolve tenant_id
    # through get_tenant_meta(), which is only populated by get_scm_client().
    get_scm_client(tenant)
    register_fn(mcp, lambda tenant_id="": get_scm_client(tenant))
    tool = mcp._tool_manager.get_tool(tool_name)  # noqa: SLF001
    if tool is None:
        raise RuntimeError(f"tool {tool_name!r} is not registered by {register_fn.__name__}")
    return str(tool.fn(**kwargs))


# ── sub-menu: Config & Inventory ──────────────────────────────────────────


def _menu_config_inventory(
    tenant: TenantConfig,
    console,
    _print_banner,
    _menu_table,
    _section,
    _get_cli_client,
    _list_and_display,
    _save_json,
    _pause,
) -> None:
    """Browse SCM objects, network, security policy, connectivity, and deployment.

    Paginated into 5 section pages to avoid a 21-item wall.
    """
    _PAGES = [
        (
            "OBJECTS",
            [
                ("1", "Addresses", "List address objects"),
                ("2", "Address Groups", "List address groups"),
                ("3", "Services", "List service objects"),
                ("4", "Tags", "List tags"),
                ("5", "External Dynamic Lists", "List EDLs"),
            ],
        ),
        (
            "NETWORK",
            [
                ("6", "Zones", "List security zones"),
                ("7", "NAT Rules", "List NAT policy rules"),
                ("8", "IKE Gateways", "List IKE gateways"),
                ("9", "IPSec Tunnels", "List IPSec tunnels"),
                ("10", "DNS Servers", "List internal DNS servers"),
            ],
        ),
        (
            "SECURITY",
            [
                ("11", "Security Rules", "List security policy rules"),
                ("12", "Anti-Spyware Profiles", "List anti-spyware profiles"),
                ("13", "URL Categories", "List URL filtering categories"),
            ],
        ),
        (
            "CONNECTIVITY",
            [
                ("14", "Remote Networks", "List RN branch connections"),
                ("15", "Service Connections", "List SC data-centre connections"),
                ("16", "Bandwidth Allocations", "List compute location bandwidth"),
            ],
        ),
        (
            "DEPLOYMENT",
            [
                ("17", "Folders", "List SCM folder hierarchy"),
                ("18", "Devices", "List managed firewalls / Panorama"),
                ("19", "Snippets", "List configuration snippets"),
                ("20", "Config Versions", "List configuration versions"),
                ("21", "Jobs", "List SCM config jobs / commits"),
            ],
        ),
    ]

    def _draw_section_page(page: int) -> None:
        _print_banner(tenant)
        console.rule(f"[cyan]Config & Inventory[/cyan]  [dim]page {page + 1}/{len(_PAGES)}[/dim]")
        section_name, items = _PAGES[page]
        _section(section_name)
        console.print(_menu_table(items))
        console.print()
        nav = [("0", "Back to Main Menu", "")]
        if page > 0:
            nav.insert(0, ("P", "← Previous Section", _PAGES[page - 1][0]))
        if page < len(_PAGES) - 1:
            nav.insert(0, ("N", f"Next Section → {_PAGES[page + 1][0]}", ""))
        console.print(_menu_table(nav))
        console.print()

    # Build dispatch: choice -> (leaf_fn_args, ...)
    _DISPATCH: dict[str, list[Any]] = {
        "1": [tenant, console, _get_cli_client, _list_and_display, _save_json, _pause],
        "2": [tenant, console, _get_cli_client, _list_and_display, _save_json, _pause],
        "3": [tenant, console, _get_cli_client, _list_and_display, _save_json, _pause],
        "4": [tenant, console, _get_cli_client, _list_and_display, _save_json, _pause],
        "5": [tenant, console, _get_cli_client, _list_and_display, _save_json, _pause],
        "6": [tenant, console, _get_cli_client, _list_and_display, _save_json, _pause],
        "7": [tenant, console, _get_cli_client, _list_and_display, _save_json, _pause],
        "8": [tenant, console, _get_cli_client, _list_and_display, _save_json, _pause],
        "9": [tenant, console, _get_cli_client, _list_and_display, _save_json, _pause],
        "10": [tenant, console, _get_cli_client, _list_and_display, _save_json, _pause],
        "11": [tenant, console, _get_cli_client, _list_and_display, _save_json, _pause],
        "12": [tenant, console, _get_cli_client, _list_and_display, _save_json, _pause],
        "13": [tenant, console, _get_cli_client, _list_and_display, _save_json, _pause],
        "14": [tenant, console, _get_cli_client, _list_and_display, _save_json, _pause],
        "15": [tenant, console, _get_cli_client, _list_and_display, _save_json, _pause],
        "16": [tenant, console, _get_cli_client, _list_and_display, _save_json, _pause],
        "17": [tenant, console, _get_cli_client, _list_and_display, _save_json, _pause],
        "18": [tenant, console, _get_cli_client, _list_and_display, _save_json, _pause],
        "19": [tenant, console, _get_cli_client, _list_and_display, _save_json, _pause],
        "20": [tenant, console, _get_cli_client, _save_json, _pause],
        "21": [tenant, console, _get_cli_client, _save_json, _pause],
    }

    _LEAF: dict[str, Any] = {
        "1": _op_list_addresses,
        "2": _op_list_address_groups,
        "3": _op_list_services,
        "4": _op_list_tags,
        "5": _op_list_edls,
        "6": _op_list_zones,
        "7": _op_list_nat_rules,
        "8": _op_list_ike_gateways,
        "9": _op_list_ipsec_tunnels,
        "10": _op_list_dns_servers,
        "11": _op_list_security_rules,
        "12": _op_list_anti_spyware_profiles,
        "13": _op_list_url_categories,
        "14": _op_list_remote_networks,
        "15": _op_list_service_connections,
        "16": _op_list_bandwidth_allocations,
        "17": _op_list_folders,
        "18": _op_list_devices,
        "19": _op_list_snippets,
        "20": _op_list_config_versions,
        "21": _op_list_jobs,
    }

    page = 0
    while True:
        _draw_section_page(page)
        choice = Prompt.ask("[bold cyan]>[/bold cyan]", default="").strip().upper()

        if choice == "0":
            return
        if choice == "N" and page < len(_PAGES) - 1:
            page += 1
            continue
        if choice == "P" and page > 0:
            page -= 1
            continue

        leaf = _LEAF.get(choice)
        if leaf is not None:
            leaf(*_DISPATCH[choice])


# ── sub-menu: Audit & Compliance ──────────────────────────────────────────


def _menu_audit_compliance(
    tenant: TenantConfig,
    console,
    _print_banner,
    _menu_table,
    _section,
    _op_backup,
    _op_config_diff,
    _op_bpa,
    _op_ncsc,
    _op_dspt,
    _op_audit_report,
    _op_asbuilt_report,
    _pause,
) -> None:
    """Audit, compliance assessment, and reporting operations."""

    def _draw() -> None:
        _print_banner(tenant)
        console.rule("[cyan]Audit & Compliance[/cyan]")
        _section("CONFIG")
        console.print(
            _menu_table(
                [
                    ("1", "Backup Config", "Snapshot Prisma Access + SD-WAN to JSON"),
                    ("2", "Config Diff", "Compare two backup snapshots"),
                    ("3", "Config Clone", "Clone config to new folder/tenant"),
                ]
            )
        )
        console.print()
        _section("ASSESSMENTS")
        console.print(
            _menu_table(
                [
                    ("4", "BPA Assessment", "PAN Best Practice Analysis report"),
                    ("5", "NCSC Compliance", "CAF v4.0 / Cyber Essentials v3.2 / 10 Steps"),
                    ("6", "NIST Compliance", "NIST CSF v2.0 / SP 800-53 Rev 5 gap analysis"),
                    ("7", "DSPT Compliance", "NHS DSPT 2024-25 — Standards 7–10"),
                    ("8", "ISO 27001 Assessment", "ISO 27001:2022 Annex A controls"),
                    ("9", "Decryption Policy Audit", "SSL/TLS decryption deep-dive"),
                ]
            )
        )
        console.print()
        _section("REPORTS")
        console.print(
            _menu_table(
                [
                    ("10", "Audit Report", "Full combined security audit (Markdown / DOCX)"),
                    ("11", "AS-BUILT Report", "AS-BUILT document with live diagrams"),
                    ("12", "AI Compliance Advisor", "Claude-powered remediation playbook"),
                ]
            )
        )
        console.print()
        console.print(_menu_table([("0", "Back", "")]))
        console.print()

    while True:
        _draw()
        choice = Prompt.ask("[bold cyan]>[/bold cyan]", default="").strip()
        if choice == "0":
            return
        elif choice == "1":
            _op_backup(tenant)
        elif choice == "2":
            _op_config_diff(tenant)
        elif choice == "3":
            _op_config_clone(tenant, console, _pause)
        elif choice == "4":
            _op_bpa(tenant)
        elif choice == "5":
            _op_ncsc(tenant)
        elif choice == "6":
            _op_nist(tenant, console, _pause)
        elif choice == "7":
            _op_dspt(tenant)
        elif choice == "8":
            _op_iso27001(tenant, console, _pause)
        elif choice == "9":
            _op_decrypt_audit(tenant, console, _pause)
        elif choice == "10":
            _op_audit_report(tenant)
        elif choice == "11":
            _op_asbuilt_report(tenant)
        elif choice == "12":
            _op_ai_advisor(tenant, console, _pause)


# ── sub-menu: SD-WAN ──────────────────────────────────────────────────────


def _menu_sdwan(
    tenant: TenantConfig, console, _print_banner, _menu_table, _section, _op_sdwan_topology, _pause
) -> None:
    """Prisma SD-WAN inventory, topology, and diagnostics.

    Paginated into 3 section pages to avoid a 21-item wall.
    """
    _PAGES = [
        (
            "INVENTORY",
            [
                ("1", "Sites", "List SD-WAN sites (branches, DCs, hubs)"),
                ("2", "Elements", "List ION elements (physical/virtual appliances)"),
                ("3", "WAN Interfaces", "List WAN interfaces for a site"),
                ("4", "WAN Networks", "List ISP circuit definitions"),
                ("5", "Path Groups", "List circuit groupings for policy"),
                ("6", "Policies", "List SD-WAN policy sets"),
                ("7", "Clusters", "List hub-and-spoke clusters (HA topology)"),
                ("8", "BGP", "List BGP configs and peer status"),
            ],
        ),
        (
            "TOPOLOGY",
            [
                ("9", "Topology Diagram", "Mermaid VPN overlay diagram"),
                ("10", "Topology Summary", "Full topology summary"),
                ("11", "Debug Topology", "Raw JSON from topology API"),
                ("12", "Full Topology Report", "Interactive sub-menu (sites + diagram)"),
                ("13", "Site Map (HTML)", "Interactive Leaflet/OSM map from site geo data"),
            ],
        ),
        (
            "MONITORING",
            [
                ("14", "Events", "Alarm/alert feed with severity summary"),
                ("15", "Software Status", "Per-ION versions + staged upgrade state"),
                ("16", "Link Health", "Per-path LQM latency/jitter/MOS for a site"),
                ("17", "Flows / Top Talkers", "Top sources, destinations, apps for a site"),
                ("18", "App Health", "Healthscore buckets + top-N apps and sites"),
                ("19", "Cellular Modules", "LTE/5G modem, SIM, and signal status"),
                ("20", "WAN IP Summary", "Public/private WAN IPs (optional ISP enrichment)"),
                ("21", "Audit Logs", "Operator/API audit trail (needs write role)"),
            ],
        ),
    ]

    def _draw_section_page(page: int) -> None:
        _print_banner(tenant)
        console.rule(f"[cyan]Prisma SD-WAN[/cyan]  [dim]page {page + 1}/{len(_PAGES)}[/dim]")
        section_name, items = _PAGES[page]
        _section(section_name)
        console.print(_menu_table(items))
        console.print()
        nav = [("0", "Back to Main Menu", "")]
        if page > 0:
            nav.insert(0, ("P", "← Previous Section", _PAGES[page - 1][0]))
        if page < len(_PAGES) - 1:
            nav.insert(0, ("N", f"Next Section → {_PAGES[page + 1][0]}", ""))
        console.print(_menu_table(nav))
        console.print()

    page = 0
    while True:
        _draw_section_page(page)
        choice = Prompt.ask("[bold cyan]>[/bold cyan]", default="").strip().upper()

        if choice == "0":
            return
        if choice == "N" and page < len(_PAGES) - 1:
            page += 1
            continue
        if choice == "P" and page > 0:
            page -= 1
            continue

        if choice == "1":
            _op_sdwan_list_sites(tenant, console, _pause)
        elif choice == "2":
            _op_sdwan_list_elements(tenant, console, _pause)
        elif choice == "3":
            _op_sdwan_list_wan_ifaces(tenant, console, _pause)
        elif choice == "4":
            _op_sdwan_list_wan_networks(tenant, console, _pause)
        elif choice == "5":
            _op_sdwan_list_path_groups(tenant, console, _pause)
        elif choice == "6":
            _op_sdwan_list_policies(tenant, console, _pause)
        elif choice == "7":
            _op_sdwan_list_clusters(tenant, console, _pause)
        elif choice == "8":
            _op_sdwan_list_bgp(tenant, console, _pause)
        elif choice == "9":
            _op_sdwan_topology_diagram(tenant, console, _pause)
        elif choice == "10":
            _op_sdwan_topology_summary(tenant, console, _pause)
        elif choice == "11":
            _op_sdwan_debug_topology(tenant, console, _pause)
        elif choice == "12":
            _op_sdwan_topology(tenant)
        elif choice == "13":
            _op_sdwan_site_map(tenant, console, _pause)
        elif choice == "14":
            _op_sdwan_monitor(tenant, console, _pause, "sdwan_events", "Fetching events")
        elif choice == "15":
            _op_sdwan_monitor(
                tenant, console, _pause, "sdwan_software_status", "Fetching software status"
            )
        elif choice == "16":
            _op_sdwan_monitor(
                tenant, console, _pause, "sdwan_link_health", "Querying link health", site=True
            )
        elif choice == "17":
            _op_sdwan_monitor(
                tenant, console, _pause, "sdwan_flows", "Aggregating flows", site=True
            )
        elif choice == "18":
            _op_sdwan_monitor(tenant, console, _pause, "sdwan_app_health", "Querying app health")
        elif choice == "19":
            _op_sdwan_monitor(
                tenant, console, _pause, "sdwan_cellular_status", "Querying cellular modules"
            )
        elif choice == "20":
            _op_sdwan_wan_ip_summary(tenant, console, _pause)
        elif choice == "21":
            _op_sdwan_monitor(tenant, console, _pause, "sdwan_audit_logs", "Fetching audit logs")


# ── sub-menu: SSE, DLP & CASB ─────────────────────────────────────────────


def _menu_sse_dlp(
    tenant: TenantConfig, console, _print_banner, _menu_table, _section, _pause
) -> None:
    """Security Service Edge — DLP, CASB, ZTNA, Browser, AIRS."""

    def _draw() -> None:
        _print_banner(tenant)
        console.rule("[cyan]SSE, DLP & CASB[/cyan]")
        _section("DLP")
        console.print(
            _menu_table(
                [
                    ("1", "SCM DLP Profiles", "List inline data-filtering profiles & data objects"),
                    ("2", "Enterprise DLP", "List Enterprise DLP patterns & profiles"),
                    ("3", "DLP Backup", "Export full DLP config as JSON"),
                    ("4", "DLP Restore", "Restore DLP backup to target folder"),
                ]
            )
        )
        console.print()
        _section("CASB & ZERO TRUST")
        console.print(
            _menu_table(
                [
                    ("5", "CASB Restrictions", "List SaaS tenant restrictions"),
                    ("6", "ZTNA Connectors", "List ZTNA connector infrastructure"),
                    ("7", "Prisma Browser", "List RBI / Prisma Browser config"),
                    ("8", "AIRS", "List AI Runtime Security configuration"),
                    ("9", "PAB Inventory", "Browser users, devices & endpoint posture"),
                    ("10", "PAB User Requests", "Pending browser access requests"),
                ]
            )
        )
        console.print()
        console.print(_menu_table([("0", "Back", "")]))
        console.print()

    while True:
        _draw()
        choice = Prompt.ask("[bold cyan]>[/bold cyan]", default="").strip()
        if choice == "0":
            return
        elif choice == "1":
            _op_dlp_list(tenant, console, _pause)
        elif choice == "2":
            _op_dlp_enterprise_list(tenant, console, _pause)
        elif choice == "3":
            _op_dlp_backup(tenant, console, _pause)
        elif choice == "4":
            _op_dlp_restore(tenant, console, _pause)
        elif choice == "5":
            _op_casb_list(tenant, console, _pause)
        elif choice == "6":
            _op_ztna_list(tenant, console, _pause)
        elif choice == "7":
            _op_browser_list(tenant, console, _pause)
        elif choice == "8":
            _op_airs_list(tenant, console, _pause)
        elif choice == "9":
            _op_pab_inventory(tenant, console, _pause)
        elif choice == "10":
            _op_pab_user_requests(tenant, console, _pause)


# ── sub-menu: MSSP Operations ─────────────────────────────────────────────


def _menu_mssp_ops(
    tenant: TenantConfig, console, _print_banner, _menu_table, _section, _pause
) -> None:
    """MSSP dashboards, licences, certificates, and session monitoring."""

    def _draw() -> None:
        _print_banner(tenant)
        console.rule("[cyan]MSSP Operations[/cyan]")
        _section("DASHBOARDS")
        console.print(
            _menu_table(
                [
                    ("1", "Tenant Dashboard", "Multi-tenant NOC traffic-light health view"),
                    ("2", "NOC Health Dashboard", "Cross-tenant health wallboard"),
                ]
            )
        )
        console.print()
        _section("LICENSING")
        console.print(
            _menu_table(
                [
                    ("3", "License Info", "Subscription licence inventory"),
                    ("4", "License Forecast", "Expiry forecast & seat utilisation"),
                ]
            )
        )
        console.print()
        _section("MONITORING")
        console.print(
            _menu_table(
                [
                    ("5", "Mobile User Stats", "Allocation & logged-in user count"),
                    ("6", "GP Session Summary", "Live GlobalProtect / PA-Agent sessions"),
                    ("7", "SPN Bandwidth", "SPN allocation, throughput, oversubscription risk"),
                    ("8", "User Count", "Live connected user count — GP vs NGFW split"),
                ]
            )
        )
        console.print()
        _section("CERTIFICATES")
        console.print(
            _menu_table(
                [
                    ("9", "Cert Lifecycle", "Multi-tenant TLS certificate dashboard"),
                    ("10", "Cert Scan", "Scan SCM certificate expiry"),
                ]
            )
        )
        console.print()
        _section("TENANTS")
        console.print(
            _menu_table(
                [
                    ("11", "Discover Tenants", "Discover managed sub-tenants"),
                ]
            )
        )
        console.print()
        _section("SYSTEM")
        console.print(
            _menu_table(
                [
                    (
                        "12",
                        "PAN Service Status",
                        "Upcoming maintenance + incidents per tenant region",
                    ),
                    (
                        "13",
                        "Cross-Tenant Analytics",
                        "Apps/threats/connectivity/incidents across tenants",
                    ),
                ]
            )
        )
        console.print()
        console.print(_menu_table([("0", "Back", "")]))
        console.print()

    while True:
        _draw()
        choice = Prompt.ask("[bold cyan]>[/bold cyan]", default="").strip()
        if choice == "0":
            return
        elif choice == "1":
            _op_mssp_tenant_dashboard(tenant, console, _pause)
        elif choice == "2":
            _op_noc_dashboard(tenant, console, _pause)
        elif choice == "3":
            _op_license_info(tenant, console, _pause)
        elif choice == "4":
            _op_license_forecast(tenant, console, _pause)
        elif choice == "5":
            _op_mobile_user_stats(tenant, console, _pause)
        elif choice == "6":
            _op_gp_session_summary(tenant, console, _pause)
        elif choice == "7":
            _op_spn_bandwidth(tenant, console, _pause)
        elif choice == "8":
            _op_user_count(tenant, console, _pause)
        elif choice == "9":
            _op_cert_lifecycle(tenant, console, _pause)
        elif choice == "10":
            _op_cert_scan(tenant, console, _pause)
        elif choice == "11":
            _op_discover_tenants(tenant, console, _pause)
        elif choice == "12":
            _op_service_maintenance(tenant, console, _pause)
        elif choice == "13":
            _op_mt_analytics(tenant, console, _pause)


# ── sub-menu: Posture & Incidents ──────────────────────────────────────────


def _menu_posture_noc(
    tenant: TenantConfig, console, _print_banner, _menu_table, _section, _op_incidents, _pause
) -> None:
    """Security posture, incident management, and TLS configuration."""

    def _draw() -> None:
        _print_banner(tenant)
        console.rule("[cyan]Posture, Incidents & NOC[/cyan]")
        _section("POSTURE")
        console.print(
            _menu_table(
                [
                    ("1", "Posture Report", "SCM Posture Management best-practice findings"),
                    (
                        "2",
                        "SaaS Posture (SSPM)",
                        "App misconfigs, IdP posture — export/import JSON",
                    ),
                    (
                        "3",
                        "Compliance Center",
                        "Framework scores, controls, benchmark monitoring",
                    ),
                ]
            )
        )
        console.print()
        _section("INCIDENTS")
        console.print(
            _menu_table(
                [
                    ("4", "Incident Search", "Search SCM security incidents"),
                    ("5", "Incident Summary", "Cross-tenant incident NOC dashboard"),
                ]
            )
        )
        console.print()
        _section("TLS & CERTS")
        console.print(
            _menu_table(
                [
                    ("6", "TLS Profile Manager", "List / create TLS service profiles"),
                ]
            )
        )
        console.print()
        console.print(_menu_table([("0", "Back", "")]))
        console.print()

    while True:
        _draw()
        choice = Prompt.ask("[bold cyan]>[/bold cyan]", default="").strip()
        if choice == "0":
            return
        elif choice == "1":
            _op_posture_report(tenant, console, _pause)
        elif choice == "2":
            _op_saas_posture(tenant, console, _pause)
        elif choice == "3":
            _op_compliance_center(tenant, console, _pause)
        elif choice == "4":
            _op_incidents(tenant)
        elif choice == "5":
            _op_incident_summary(tenant, console, _pause)
        elif choice == "6":
            _op_tls_profile_manager(tenant, console, _pause)


# ── sub-menu: NCSC / NIST Remediation ─────────────────────────────────────


def _menu_remediation(
    tenant: TenantConfig, console, _print_banner, _menu_table, _section, _pause
) -> None:
    """NCSC and NIST compliance remediation, baselines, and gap analysis."""

    def _draw() -> None:
        _print_banner(tenant)
        console.rule("[cyan]NCSC / NIST Remediation[/cyan]")
        _section("BASELINES")
        console.print(
            _menu_table(
                [
                    ("1", "Apply NCSC Baseline", "Create NCSC profiles and deny-all rule"),
                    ("2", "Attach NCSC Profiles", "Create profile group and attach to rules"),
                ]
            )
        )
        console.print()
        _section("SNIPPETS")
        console.print(
            _menu_table(
                [
                    ("3", "Create NCSC Snippet", "NCSC baseline as reusable snippet"),
                    ("4", "Create NIST Snippet", "NIST baseline as reusable snippet"),
                ]
            )
        )
        console.print()
        _section("GAP ANALYSIS")
        console.print(
            _menu_table(
                [
                    ("5", "NCSC Gap Analysis", "Compare live config vs NCSC baseline"),
                    ("6", "NIST Gap Analysis", "Compare live config vs NIST baseline"),
                ]
            )
        )
        console.print()
        _section("AI")
        console.print(
            _menu_table(
                [
                    (
                        "7",
                        "AI Compliance Advisor",
                        "Claude-powered executive summary & remediation",
                    ),
                ]
            )
        )
        console.print()
        console.print(_menu_table([("0", "Back", "")]))
        console.print()

    while True:
        _draw()
        choice = Prompt.ask("[bold cyan]>[/bold cyan]", default="").strip()
        if choice == "0":
            return
        elif choice == "1":
            _op_apply_ncsc(tenant, console, _pause)
        elif choice == "2":
            _op_attach_ncsc(tenant, console, _pause)
        elif choice == "3":
            _op_create_ncsc_snippet(tenant, console, _pause)
        elif choice == "4":
            _op_create_nist_snippet(tenant, console, _pause)
        elif choice == "5":
            _op_ncsc_gap(tenant, console, _pause)
        elif choice == "6":
            _op_nist_gap(tenant, console, _pause)
        elif choice == "7":
            _op_ai_advisor(tenant, console, _pause)


# ── sub-menu: Config Lifecycle ────────────────────────────────────────────


def _menu_config_lifecycle(
    tenant: TenantConfig,
    console,
    _print_banner,
    _menu_table,
    _section,
    _op_config_diff,
    _op_aiops_bpa,
    _pause,
) -> None:
    """Config diff, clone, push, rollback, commit, and extended operations."""

    def _draw() -> None:
        _print_banner(tenant)
        console.rule("[cyan]Config Lifecycle[/cyan]")
        _section("COMPARISON & MIGRATION")
        console.print(
            _menu_table(
                [
                    ("1", "Config Diff", "Compare two backup snapshots"),
                    ("2", "Config Clone", "Clone config to new folder/tenant"),
                ]
            )
        )
        console.print()
        _section("DEPLOYMENT")
        console.print(
            _menu_table(
                [
                    ("3", "Commit", "Commit pending SCM changes"),
                    ("4", "Push & Track", "Push candidate with async job tracking"),
                    ("5", "Config Rollback", "Load previous version to candidate"),
                ]
            )
        )
        console.print()
        _section("EXTENDED")
        console.print(
            _menu_table(
                [
                    ("6", "AIOps BPA", "PAN AIOps Best Practice Assessment (XML upload)"),
                    ("7", "ADNSR Profiles", "List Advanced DNS Security profiles"),
                ]
            )
        )
        console.print()
        _section("NGFW")
        console.print(
            _menu_table(
                [
                    ("8", "NGFW Devices", "List NGFW managed devices"),
                    ("9", "Device Summary", "Device health — count, connected/offline, HA, models"),
                    ("10", "Local Config List", "List NGFW local config versions"),
                    ("11", "Local Config Get", "Fetch NGFW XML config"),
                ]
            )
        )
        console.print()
        console.print(_menu_table([("0", "Back", "")]))
        console.print()

    while True:
        _draw()
        choice = Prompt.ask("[bold cyan]>[/bold cyan]", default="").strip()
        if choice == "0":
            return
        elif choice == "1":
            _op_config_diff(tenant)
        elif choice == "2":
            _op_config_clone(tenant, console, _pause)
        elif choice == "3":
            _op_commit(tenant, console, _pause)
        elif choice == "4":
            _op_config_push(tenant, console, _pause)
        elif choice == "5":
            _op_config_rollback(tenant, console, _pause)
        elif choice == "6":
            _op_aiops_bpa(tenant)
        elif choice == "7":
            _op_adnsr_list(tenant, console, _pause)
        elif choice == "8":
            _op_ngfw_devices(tenant, console, _pause)
        elif choice == "9":
            _op_device_summary(tenant, console, _pause)
        elif choice == "10":
            _op_ngfw_local_config_list(tenant, console, _pause)
        elif choice == "11":
            _op_ngfw_local_config_get(tenant, console, _pause)


# ── leaf operations: Config & Inventory ────────────────────────────────────


def _op_list_addresses(
    tenant: TenantConfig, console, _get_cli_client, _list_and_display, _save_json, _pause
) -> None:
    client = _get_cli_client(tenant)
    if not client:
        return
    folder = tenant.default_folder or "Shared"
    results = _list_and_display(
        client, "address", folder, "Address Objects", ["name", "ip_netmask", "fqdn", "description"]
    )
    if results:
        out = _save_json(results, "addresses", tenant.tenant_id)
        if out:
            console.print(f"[dim]Saved: {out}[/dim]")
    _pause()


def _op_list_address_groups(
    tenant, console, _get_cli_client, _list_and_display, _save_json, _pause
) -> None:
    client = _get_cli_client(tenant)
    if not client:
        return
    folder = tenant.default_folder or "Shared"
    results = _list_and_display(
        client, "address_group", folder, "Address Groups", ["name", "description"]
    )
    if results:
        out = _save_json(results, "address_groups", tenant.tenant_id)
        if out:
            console.print(f"[dim]Saved: {out}[/dim]")
    _pause()


def _op_list_services(
    tenant, console, _get_cli_client, _list_and_display, _save_json, _pause
) -> None:
    client = _get_cli_client(tenant)
    if not client:
        return
    folder = tenant.default_folder or "Shared"
    results = _list_and_display(
        client, "service", folder, "Service Objects", ["name", "protocol", "port", "description"]
    )
    if results:
        out = _save_json(results, "services", tenant.tenant_id)
        if out:
            console.print(f"[dim]Saved: {out}[/dim]")
    _pause()


def _op_list_tags(tenant, console, _get_cli_client, _list_and_display, _save_json, _pause) -> None:
    client = _get_cli_client(tenant)
    if not client:
        return
    folder = tenant.default_folder or "Shared"
    results = _list_and_display(client, "tag", folder, "Tags", ["name", "color"])
    if results:
        out = _save_json(results, "tags", tenant.tenant_id)
        if out:
            console.print(f"[dim]Saved: {out}[/dim]")
    _pause()


def _op_list_edls(tenant, console, _get_cli_client, _list_and_display, _save_json, _pause) -> None:
    client = _get_cli_client(tenant)
    if not client:
        return
    folder = tenant.default_folder or "Shared"
    results = _list_and_display(
        client,
        "external_dynamic_list",
        folder,
        "External Dynamic Lists",
        ["name", "type", "description"],
    )
    if results:
        out = _save_json(results, "edls", tenant.tenant_id)
        if out:
            console.print(f"[dim]Saved: {out}[/dim]")
    _pause()


def _op_list_zones(tenant, console, _get_cli_client, _list_and_display, _save_json, _pause) -> None:
    client = _get_cli_client(tenant)
    if not client:
        return
    folder = tenant.default_folder or "Shared"
    results = _list_and_display(
        client, "security_zone", folder, "Security Zones", ["name", "description"]
    )
    if results:
        out = _save_json(results, "zones", tenant.tenant_id)
        if out:
            console.print(f"[dim]Saved: {out}[/dim]")
    _pause()


def _op_list_nat_rules(
    tenant, console, _get_cli_client, _list_and_display, _save_json, _pause
) -> None:
    client = _get_cli_client(tenant)
    if not client:
        return
    folder = tenant.default_folder or "Shared"
    results: list[Any] = []
    for pos in ("pre", "post"):
        results += _list_and_display(
            client,
            "nat_rule",
            folder,
            f"NAT Rules ({pos})",
            ["name", "source", "destination", "service"],
            position=pos,
        )
    if results:
        out = _save_json(results, "nat_rules", tenant.tenant_id)
        if out:
            console.print(f"[dim]Saved: {out}[/dim]")
    _pause()


def _op_list_ike_gateways(
    tenant, console, _get_cli_client, _list_and_display, _save_json, _pause
) -> None:
    client = _get_cli_client(tenant)
    if not client:
        return
    folder = tenant.default_folder or "Shared"
    results = _list_and_display(
        client,
        "ike_gateway",
        folder,
        "IKE Gateways",
        ["name", "peer_address", "ike_version", "authentication"],
    )
    if results:
        out = _save_json(results, "ike_gateways", tenant.tenant_id)
        if out:
            console.print(f"[dim]Saved: {out}[/dim]")
    _pause()


def _op_list_ipsec_tunnels(
    tenant, console, _get_cli_client, _list_and_display, _save_json, _pause
) -> None:
    client = _get_cli_client(tenant)
    if not client:
        return
    folder = tenant.default_folder or "Shared"
    results = _list_and_display(
        client,
        "ipsec_tunnel",
        folder,
        "IPSec Tunnels",
        ["name", "ike_gateway", "ipsec_crypto_profile"],
    )
    if results:
        out = _save_json(results, "ipsec_tunnels", tenant.tenant_id)
        if out:
            console.print(f"[dim]Saved: {out}[/dim]")
    _pause()


def _op_list_dns_servers(
    tenant, console, _get_cli_client, _list_and_display, _save_json, _pause
) -> None:
    client = _get_cli_client(tenant)
    if not client:
        return
    folder = tenant.default_folder or "Shared"
    results = _list_and_display(
        client, "internal_dns_server", folder, "DNS Servers", ["name", "domain_name"]
    )
    if results:
        out = _save_json(results, "dns_servers", tenant.tenant_id)
        if out:
            console.print(f"[dim]Saved: {out}[/dim]")
    _pause()


def _op_list_security_rules(
    tenant, console, _get_cli_client, _list_and_display, _save_json, _pause
) -> None:
    client = _get_cli_client(tenant)
    if not client:
        return
    folder = tenant.default_folder or "Shared"
    results: list[Any] = []
    for pos in ("pre", "post"):
        results += _list_and_display(
            client,
            "security_rule",
            folder,
            f"Security Rules ({pos})",
            ["name", "from_", "to_", "source", "destination", "action"],
            position=pos,
        )
    if results:
        out = _save_json(results, "security_rules", tenant.tenant_id)
        if out:
            console.print(f"[dim]Saved: {out}[/dim]")
    _pause()


def _op_list_anti_spyware_profiles(
    tenant, console, _get_cli_client, _list_and_display, _save_json, _pause
) -> None:
    client = _get_cli_client(tenant)
    if not client:
        return
    folder = tenant.default_folder or "Shared"
    results = _list_and_display(
        client, "anti_spyware_profile", folder, "Anti-Spyware Profiles", ["name", "description"]
    )
    if results:
        out = _save_json(results, "anti_spyware_profiles", tenant.tenant_id)
        if out:
            console.print(f"[dim]Saved: {out}[/dim]")
    _pause()


def _op_list_url_categories(
    tenant, console, _get_cli_client, _list_and_display, _save_json, _pause
) -> None:
    client = _get_cli_client(tenant)
    if not client:
        return
    folder = tenant.default_folder or "Shared"
    results = _list_and_display(
        client, "url_category", folder, "URL Categories", ["name", "description"]
    )
    if results:
        out = _save_json(results, "url_categories", tenant.tenant_id)
        if out:
            console.print(f"[dim]Saved: {out}[/dim]")
    _pause()


def _op_list_remote_networks(
    tenant, console, _get_cli_client, _list_and_display, _save_json, _pause
) -> None:
    client = _get_cli_client(tenant)
    if not client:
        return
    # Remote Network objects always live in the "Remote Networks" folder — the SDK
    # rejects any other folder value.
    folder = "Remote Networks"
    results = _list_and_display(
        client, "remote_network", folder, "Remote Networks", ["name", "region", "spn_name"]
    )
    if results:
        out = _save_json(results, "remote_networks", tenant.tenant_id)
        if out:
            console.print(f"[dim]Saved: {out}[/dim]")
    _pause()


def _op_list_service_connections(
    tenant, console, _get_cli_client, _list_and_display, _save_json, _pause
) -> None:
    client = _get_cli_client(tenant)
    if not client:
        return
    folder = tenant.default_folder or "Shared"
    results = _list_and_display(
        client,
        "service_connection",
        folder,
        "Service Connections",
        ["name", "region", "onboarding_type"],
    )
    if results:
        out = _save_json(results, "service_connections", tenant.tenant_id)
        if out:
            console.print(f"[dim]Saved: {out}[/dim]")
    _pause()


def _op_list_bandwidth_allocations(
    tenant, console, _get_cli_client, _list_and_display, _save_json, _pause
) -> None:
    client = _get_cli_client(tenant)
    if not client:
        return
    folder = tenant.default_folder or "Shared"
    results = _list_and_display(
        client,
        "bandwidth_allocation",
        folder,
        "Bandwidth Allocations",
        ["name", "allocated_bandwidth"],
    )
    if results:
        out = _save_json(results, "bandwidth_allocations", tenant.tenant_id)
        if out:
            console.print(f"[dim]Saved: {out}[/dim]")
    _pause()


def _op_list_folders(
    tenant, console, _get_cli_client, _list_and_display, _save_json, _pause
) -> None:
    client = _get_cli_client(tenant)
    if not client:
        return
    results = _list_and_display(client, "folder", "", "SCM Folders", ["name", "folder_type"])
    if results:
        out = _save_json(results, "folders", tenant.tenant_id)
        if out:
            console.print(f"[dim]Saved: {out}[/dim]")
    _pause()


def _op_list_devices(
    tenant, console, _get_cli_client, _list_and_display, _save_json, _pause
) -> None:
    client = _get_cli_client(tenant)
    if not client:
        return
    folder = tenant.default_folder or "Shared"
    results = _list_and_display(
        client,
        "device",
        folder,
        "Managed Devices",
        ["hostname", "serial_number", "model", "sw_version"],
    )
    if results:
        out = _save_json(results, "devices", tenant.tenant_id)
        if out:
            console.print(f"[dim]Saved: {out}[/dim]")
    _pause()


def _op_list_snippets(
    tenant, console, _get_cli_client, _list_and_display, _save_json, _pause
) -> None:
    client = _get_cli_client(tenant)
    if not client:
        return
    results = _list_and_display(
        client, "snippet", "", "SCM Snippets", ["name", "snippet_type", "description"]
    )
    if results:
        out = _save_json(results, "snippets", tenant.tenant_id)
        if out:
            console.print(f"[dim]Saved: {out}[/dim]")
    _pause()


def _op_list_config_versions(tenant, console, _get_cli_client, _save_json, _pause) -> None:
    client = _get_cli_client(tenant)
    if not client:
        return
    with console.status("[cyan]Fetching config versions...[/cyan]"):
        try:
            # No dedicated SDK resource for config versions — use the raw endpoint,
            # matching the scm_config_versions MCP tool (tools/deployment.py).
            cv_base = "/config/operations/v1/config-versions"
            raw = client.get(cv_base)
            results = raw.get("data", []) if isinstance(raw, dict) else []
            # /running reports one running version per scope (e.g. "Remote Networks"),
            # not a single global version.
            running_by_scope: dict[str, Any] = {}
            with contextlib.suppress(Exception):
                running_raw = client.get(f"{cv_base}/running")
                for entry in running_raw.get("data") or []:
                    device = entry.get("device")
                    if device:
                        running_by_scope[device] = entry.get("version")
            t = Table(title="SCM Config Versions", box=box.SIMPLE_HEAD)
            t.add_column("Version", style="cyan")
            t.add_column("Scope")
            t.add_column("Timestamp")
            t.add_column("Description")
            t.add_column("Running")
            for v in results:
                scope = v.get("scope")
                t.add_row(
                    str(v.get("version", "")),
                    str(scope or "—"),
                    str(v.get("created_at") or v.get("timestamp") or v.get("date") or "—"),
                    str(v.get("description") or "—"),
                    "●"
                    if scope and str(running_by_scope.get(scope)) == str(v.get("version"))
                    else "",
                )
            console.print(t)
            if results:
                out = _save_json(results, "config_versions", tenant.tenant_id)
                if out:
                    console.print(f"[dim]Saved: {out}[/dim]")
        except Exception as exc:
            console.print(f"[red]Error: {exc}[/red]")
    _pause()


def _op_list_jobs(tenant, console, _get_cli_client, _save_json, _pause) -> None:
    client = _get_cli_client(tenant)
    if not client:
        return
    with console.status("[cyan]Fetching job history...[/cyan]"):
        try:
            results = list(client.list_jobs(limit=50, offset=0))
            t = Table(title="SCM Configuration Jobs", box=box.SIMPLE_HEAD)
            t.add_column("ID", style="cyan")
            t.add_column("Type")
            t.add_column("Result")
            t.add_column("User")
            t.add_column("Start")
            for j in results:
                t.add_row(
                    str(getattr(j, "id", "")),
                    str(getattr(j, "type_str", getattr(j, "job_type", ""))),
                    str(getattr(j, "result_str", "")),
                    str(getattr(j, "uname", "")),
                    str(getattr(j, "start_ts", "")),
                )
            console.print(t)
            if results:
                out = _save_json(results, "jobs", tenant.tenant_id)
                if out:
                    console.print(f"[dim]Saved: {out}[/dim]")
        except Exception as exc:
            console.print(f"[red]Error: {exc}[/red]")
    _pause()


# ── leaf operations: SD-WAN ────────────────────────────────────────────────


def _op_sdwan_list_sites(tenant, console, _pause) -> None:
    from .auth.sdwan import get_sdwan_client, safe_items

    try:
        sdwan = get_sdwan_client(tenant)
        with console.status("[cyan]Fetching SD-WAN sites...[/cyan]"):
            sites = safe_items(sdwan.get.sites())
        t = Table(title="SD-WAN Sites", box=box.SIMPLE_HEAD)
        t.add_column("Name", style="cyan")
        t.add_column("Site ID")
        t.add_column("Address")
        for s in sites:
            t.add_row(
                str(s.get("name", "")), str(s.get("id", "")), str(s.get("address", "") or "—")
            )
        console.print(t)
        console.print(f"[dim]{len(sites)} site(s)[/dim]")
    except Exception as exc:
        console.print(f"[red]SD-WAN error: {exc}[/red]")
    _pause()


def _op_sdwan_list_elements(tenant, console, _pause) -> None:
    from .auth.sdwan import get_sdwan_client, safe_items

    try:
        sdwan = get_sdwan_client(tenant)
        with console.status("[cyan]Fetching SD-WAN elements...[/cyan]"):
            elements = safe_items(sdwan.get.elements())
        t = Table(title="SD-WAN Elements", box=box.SIMPLE_HEAD)
        t.add_column("Name", style="cyan")
        t.add_column("Element ID")
        t.add_column("Model")
        t.add_column("Site ID")
        for e in elements:
            t.add_row(
                str(e.get("name", "")),
                str(e.get("id", "")),
                str(e.get("model_name", "") or "—"),
                str(e.get("site_id", "")),
            )
        console.print(t)
    except Exception as exc:
        console.print(f"[red]SD-WAN error: {exc}[/red]")
    _pause()


def _op_sdwan_list_wan_ifaces(tenant, console, _pause) -> None:
    from .auth.sdwan import get_sdwan_client, safe_items

    site_id = Prompt.ask("Site ID (blank for all)", default="").strip()
    try:
        sdwan = get_sdwan_client(tenant)
        with console.status("[cyan]Fetching WAN interfaces...[/cyan]"):
            # waninterfaces() is scoped per-site — fan out across all sites if none given.
            site_ids = (
                [site_id]
                if site_id
                else [s["id"] for s in safe_items(sdwan.get.sites()) if s.get("id")]
            )
            ifaces: list[Any] = []
            for sid in site_ids:
                ifaces.extend(safe_items(sdwan.get.waninterfaces(site_id=sid)))
        t = Table(title="SD-WAN WAN Interfaces", box=box.SIMPLE_HEAD)
        t.add_column("Name", style="cyan")
        t.add_column("Site ID")
        t.add_column("Network ID")
        for i in ifaces:
            t.add_row(
                str(i.get("name", "")), str(i.get("site_id", "")), str(i.get("network_id", ""))
            )
        console.print(t)
        console.print(f"[dim]{len(ifaces)} interface(s)[/dim]")
    except Exception as exc:
        console.print(f"[red]SD-WAN error: {exc}[/red]")
    _pause()


def _op_sdwan_list_wan_networks(tenant, console, _pause) -> None:
    from .auth.sdwan import get_sdwan_client, safe_items

    try:
        sdwan = get_sdwan_client(tenant)
        with console.status("[cyan]Fetching WAN networks...[/cyan]"):
            nets = safe_items(sdwan.get.wannetworks())
        t = Table(title="SD-WAN WAN Networks", box=box.SIMPLE_HEAD)
        t.add_column("Name", style="cyan")
        t.add_column("Type")
        t.add_column("Label")
        for n in nets:
            t.add_row(
                str(n.get("name", "")), str(n.get("type", "")), str(n.get("label", "") or "—")
            )
        console.print(t)
    except Exception as exc:
        console.print(f"[red]SD-WAN error: {exc}[/red]")
    _pause()


def _op_sdwan_list_path_groups(tenant, console, _pause) -> None:
    from .auth.sdwan import get_sdwan_client, safe_items

    try:
        sdwan = get_sdwan_client(tenant)
        with console.status("[cyan]Fetching path groups...[/cyan]"):
            groups = safe_items(sdwan.get.pathgroups())
        t = Table(title="SD-WAN Path Groups", box=box.SIMPLE_HEAD)
        t.add_column("Name", style="cyan")
        t.add_column("ID")
        for g in groups:
            t.add_row(str(g.get("name", "")), str(g.get("id", "")))
        console.print(t)
    except Exception as exc:
        console.print(f"[red]SD-WAN error: {exc}[/red]")
    _pause()


def _op_sdwan_list_policies(tenant, console, _pause) -> None:
    from .auth.sdwan import get_sdwan_client, safe_items

    try:
        sdwan = get_sdwan_client(tenant)
        with console.status("[cyan]Fetching policies...[/cyan]"):
            # Policy sets are split by function — there's no single unified endpoint.
            policies: list[Any] = []
            for kind, endpoint in (
                ("network", sdwan.get.networkpolicysets),
                ("priority (QoS)", sdwan.get.prioritypolicysets),
                ("NAT", sdwan.get.natpolicysets),
                ("security", sdwan.get.securitypolicysets),
            ):
                policies.extend({**p, "policyset_type": kind} for p in safe_items(endpoint()))
        t = Table(title="SD-WAN Policies", box=box.SIMPLE_HEAD)
        t.add_column("Name", style="cyan")
        t.add_column("Type")
        for p in policies:
            t.add_row(str(p.get("name", "")), str(p.get("policyset_type", "") or "—"))
        console.print(t)
        console.print(f"[dim]{len(policies)} policy set(s)[/dim]")
    except Exception as exc:
        console.print(f"[red]SD-WAN error: {exc}[/red]")
    _pause()


def _op_sdwan_list_clusters(tenant, console, _pause) -> None:
    from .auth.sdwan import get_sdwan_client, safe_items

    try:
        sdwan = get_sdwan_client(tenant)
        with console.status("[cyan]Fetching clusters...[/cyan]"):
            # Hub and spoke clusters are both scoped per-site.
            sites = safe_items(sdwan.get.sites())
            clusters: list[Any] = []
            for site in sites:
                sid = site.get("id")
                if not sid:
                    continue
                for c in safe_items(sdwan.get.hubclusters(sid)):
                    clusters.append({**c, "cluster_type": "hub"})
                for c in safe_items(sdwan.get.spokeclusters(sid)):
                    clusters.append({**c, "cluster_type": "spoke"})
        t = Table(title="SD-WAN Clusters", box=box.SIMPLE_HEAD)
        t.add_column("Name", style="cyan")
        t.add_column("Type")
        for c in clusters:
            t.add_row(str(c.get("name", "")), str(c.get("cluster_type", "")))
        console.print(t)
        console.print(f"[dim]{len(clusters)} cluster(s)[/dim]")
    except Exception as exc:
        console.print(f"[red]SD-WAN error: {exc}[/red]")
    _pause()


def _op_sdwan_list_bgp(tenant, console, _pause) -> None:
    from .auth.sdwan import get_sdwan_client, safe_items

    try:
        sdwan = get_sdwan_client(tenant)
        with console.status("[cyan]Fetching BGP configs...[/cyan]"):
            # bgpconfigs() is scoped per site + element — fan out across all elements.
            elements = safe_items(sdwan.get.elements())
            bgps: list[Any] = []
            for e in elements:
                sid, eid = e.get("site_id"), e.get("id")
                if sid and eid:
                    # The API doesn't echo site_id/element_id back on each record —
                    # they're implied by the URL — so stamp them in for display.
                    bgps.extend(
                        {**b, "site_id": sid, "element_id": eid}
                        for b in safe_items(sdwan.get.bgpconfigs(site_id=sid, element_id=eid))
                    )
        t = Table(title="SD-WAN BGP", box=box.SIMPLE_HEAD)
        t.add_column("Site ID", style="cyan")
        t.add_column("Element ID")
        t.add_column("ASN")
        for b in bgps:
            t.add_row(
                str(b.get("site_id", "")),
                str(b.get("element_id", "")),
                str(b.get("local_as_num", "") or "—"),
            )
        console.print(t)
        console.print(f"[dim]{len(bgps)} BGP config(s)[/dim]")
    except Exception as exc:
        console.print(f"[red]SD-WAN error: {exc}[/red]")
    _pause()


def _op_sdwan_topology_diagram(tenant, console, _pause) -> None:
    from .audit.sdwan_topo import build_topology, topology_to_mermaid
    from .auth.sdwan import get_sdwan_client, safe_items

    try:
        sdwan = get_sdwan_client(tenant)
        with console.status("[cyan]Fetching sites and WAN interfaces...[/cyan]"):
            sites = safe_items(sdwan.get.sites())
            wan_networks = safe_items(sdwan.get.wannetworks())
            wan_ifaces: list[Any] = []
            for site in sites:
                sid = site.get("id")
                if sid:
                    wan_ifaces.extend(safe_items(sdwan.get.waninterfaces(site_id=sid)))
        with console.status("[cyan]Building SD-WAN topology...[/cyan]"):
            connections = build_topology(sdwan, sites, wan_ifaces, wan_networks)
            mermaid = topology_to_mermaid(connections, sites, wan_networks)
        console.print("\n[bold green]SD-WAN Topology Diagram[/bold green]\n")
        console.print(mermaid)
        ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        out = Path(f"reports/sdwan_topology_{tenant.tenant_id}_{ts}.md")
        out.parent.mkdir(exist_ok=True)
        out.write_text(mermaid)
        console.print(f"\n[dim]Saved: {out}[/dim]")
    except Exception as exc:
        console.print(f"[red]SD-WAN error: {exc}[/red]")
    _pause()


def _op_sdwan_topology_summary(tenant, console, _pause) -> None:
    from .auth.sdwan import get_sdwan_client, safe_items

    try:
        sdwan = get_sdwan_client(tenant)
        with console.status("[cyan]Fetching SD-WAN inventory...[/cyan]"):
            sites = safe_items(sdwan.get.sites())
            elements = safe_items(sdwan.get.elements())
            wan_networks = safe_items(sdwan.get.wannetworks())
            hubs: list[Any] = []
            spokes: list[Any] = []
            for s in sites:
                sid = s.get("id")
                if sid:
                    hubs.extend(safe_items(sdwan.get.hubclusters(sid)))
                    spokes.extend(safe_items(sdwan.get.spokeclusters(sid)))
        payload = {
            "sites": [{"name": s.get("name"), "id": s.get("id")} for s in sites],
            "element_count": len(elements),
            "wan_network_count": len(wan_networks),
            "hub_cluster_count": len(hubs),
            "spoke_cluster_count": len(spokes),
        }
        console.print(Panel(json.dumps(payload, indent=2), title="Topology Summary"))
    except Exception as exc:
        console.print(f"[red]SD-WAN error: {exc}[/red]")
    _pause()


def _op_sdwan_debug_topology(tenant, console, _pause) -> None:
    from .auth.sdwan import get_sdwan_client

    site_id = Prompt.ask("Site ID (filter locally, blank for all)", default="").strip()
    try:
        sdwan = get_sdwan_client(tenant)
        with console.status("[cyan]Fetching raw topology...[/cyan]"):
            resp = sdwan._session.post(  # noqa: SLF001
                f"{sdwan.controller}/sdwan/v4.0/api/anynetlinks/query",
                json={},
            )
            data = resp.json()
            if site_id and isinstance(data, dict):
                items = data.get("items", [])
                data = {
                    **data,
                    "items": [
                        i
                        for i in items
                        if site_id in (str(i.get("ep1_site_id")), str(i.get("ep2_site_id")))
                    ],
                }
        console.print(json.dumps(data, indent=2)[:5000])
    except Exception as exc:
        console.print(f"[red]SD-WAN error: {exc}[/red]")
    _pause()


def _op_sdwan_monitor(
    tenant, console, _pause, tool: str, status: str, *, site: bool = False
) -> None:
    """Generic runner for the JSON-returning SD-WAN monitoring tools."""
    from .tools.sdwan import register_sdwan_tools

    kwargs: dict[str, Any] = {"tenant_id": tenant.tenant_id}
    if site:
        site_id = Prompt.ask("Site ID (see Sites listing)", default="").strip()
        if not site_id:
            console.print("[yellow]Site ID is required for this view.[/yellow]")
            _pause()
            return
        kwargs["site_id"] = site_id
    with console.status(f"[cyan]{status}...[/cyan]"):
        try:
            result = _call_mcp_tool(tenant, register_sdwan_tools, tool, **kwargs)
        except Exception as exc:
            result = f"Error: {exc}"
    if result.lstrip().startswith(("{", "[")):
        console.print_json(result)
    else:
        console.print(f"[red]{result}[/red]" if result.startswith("Error") else result)
    _pause()


def _op_sdwan_wan_ip_summary(tenant, console, _pause) -> None:
    from .tools.sdwan import register_sdwan_tools

    enrich = Prompt.ask("Enrich public IPs via ISP lookup? (y/N)", default="n").strip().lower()
    with console.status("[cyan]Collecting WAN IPs...[/cyan]"):
        try:
            result = _call_mcp_tool(
                tenant,
                register_sdwan_tools,
                "sdwan_wan_ip_summary",
                tenant_id=tenant.tenant_id,
                enrich=enrich in ("y", "yes"),
            )
        except Exception as exc:
            result = f"Error: {exc}"
    if result.lstrip().startswith(("{", "[")):
        console.print_json(result)
    else:
        console.print(f"[red]{result}[/red]" if result.startswith("Error") else result)
    _pause()


def _op_sdwan_site_map(tenant, console, _pause) -> None:
    from .tools.sdwan import register_sdwan_tools

    default = f"reports/sdwan-site-map-{tenant.tenant_id}.html"
    save_to = Prompt.ask("Save map to", default=default).strip()
    with console.status("[cyan]Building site map...[/cyan]"):
        try:
            result = _call_mcp_tool(
                tenant,
                register_sdwan_tools,
                "sdwan_site_map",
                tenant_id=tenant.tenant_id,
                save_to=save_to,
            )
        except Exception as exc:
            result = f"Error: {exc}"
    console.print(f"[red]{result}[/red]" if result.startswith("Error") else result)
    _pause()


# ── leaf operations: SSE, DLP & CASB ───────────────────────────────────────


def _op_dlp_list(tenant, console, _pause) -> None:
    from .auth.oauth import get_scm_client
    from .tools.mssp import _SCM_CONFIG_BASE, _bearer_session, _rest_get

    client = get_scm_client(tenant)
    with console.status("[cyan]Fetching DLP profiles...[/cyan]"):
        try:
            # data-filtering-profiles / data-objects are SCM Config REST-only —
            # not exposed as pan-scm-sdk resources.
            session = _bearer_session(client)
            folder = tenant.default_folder or "All"
            params = {"folder": folder, "limit": 1000}
            data_profiles = _rest_get(
                session, f"{_SCM_CONFIG_BASE}/data-filtering-profiles", params
            )
            data_objects = _rest_get(session, f"{_SCM_CONFIG_BASE}/data-objects", params)
            console.print(
                f"[green]✓[/green] Data profiles: {len(data_profiles)}, Data objects: {len(data_objects)}"
            )
            if data_profiles:
                t = Table(title="SCM DLP Data Profiles", box=box.SIMPLE_HEAD)
                t.add_column("Name", style="cyan")
                t.add_column("Description")
                for p in data_profiles:
                    t.add_row(str(p.get("name", "")), str(p.get("description", "") or "—"))
                console.print(t)
        except Exception as exc:
            console.print(f"[red]Error: {exc}[/red]")
    _pause()


def _op_dlp_enterprise_list(tenant, console, _pause) -> None:
    from .auth.oauth import get_scm_client
    from .tools.dlp import _dlp_company_id, _dlp_list_patterns, _dlp_list_profiles
    from .tools.mssp import _bearer_session

    client = get_scm_client(tenant)
    with console.status("[cyan]Fetching Enterprise DLP...[/cyan]"):
        try:
            session = _bearer_session(client)
            cid = _dlp_company_id(session)
            if not cid:
                console.print(
                    "[yellow]Could not resolve Enterprise DLP company ID — "
                    "tenant may not have Enterprise DLP licensed.[/yellow]"
                )
            else:
                patterns = _dlp_list_patterns(session, cid)
                profiles = _dlp_list_profiles(session, cid)
                console.print(
                    f"[green]✓[/green] Company {cid} — "
                    f"Data patterns: {len(patterns)}, Data profiles: {len(profiles)}"
                )
        except Exception as exc:
            console.print(f"[yellow]Enterprise DLP not available: {exc}[/yellow]")
    _pause()


def _op_dlp_backup(tenant, console, _pause) -> None:
    from .auth.oauth import get_scm_client
    from .tools.mssp import _SCM_CONFIG_BASE, _bearer_session, _rest_get

    client = get_scm_client(tenant)
    folder = tenant.default_folder or "All"
    console.print(f"[cyan]Backing up DLP config from folder [bold]{folder}[/bold]...[/cyan]")
    try:
        session = _bearer_session(client)
        params = {"folder": folder, "limit": 1000}
        payload = {
            "data_profiles": _rest_get(
                session, f"{_SCM_CONFIG_BASE}/data-filtering-profiles", params
            ),
            "data_objects": _rest_get(session, f"{_SCM_CONFIG_BASE}/data-objects", params),
        }
        ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        out = Path("backups") / f"dlp_backup_{tenant.tenant_id}_{ts}.json"
        out.parent.mkdir(exist_ok=True)
        out.write_text(json.dumps(payload, indent=2, default=str))
        console.print(f"[green]✓[/green] DLP backup saved: {out}")
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
    _pause()


def _op_dlp_restore(tenant, console, _pause) -> None:
    backup_file = Prompt.ask("Backup JSON file path", default="").strip()
    if not backup_file or not Path(backup_file).exists():
        console.print("[red]File not found.[/red]")
        _pause()
        return
    target_folder = Prompt.ask("Target folder", default=tenant.default_folder or "All").strip()
    dry_run = Prompt.ask("Dry run?", default="yes").strip().lower() in ("yes", "y", "true")
    try:
        payload = json.loads(Path(backup_file).read_text())
        console.print(
            f"[yellow]Dry run — {len(payload.get('data_profiles', []))} profiles, "
            f"{len(payload.get('data_objects', []))} objects → [bold]{target_folder}[/bold][/yellow]"
        )
        if not dry_run:
            console.print(
                "[red]Live DLP restore not yet implemented in CLI — use MCP tool dlp_restore[/red]"
            )
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
    _pause()


def _op_casb_list(tenant, console, _pause) -> None:
    from .auth.oauth import get_scm_client
    from .tools.mssp import _SCM_CONFIG_BASE, _bearer_session, _rest_get

    client = get_scm_client(tenant)
    with console.status("[cyan]Fetching CASB SaaS restrictions...[/cyan]"):
        try:
            # SaaS tenant restrictions are SCM Config REST-only, not a pan-scm-sdk resource.
            session = _bearer_session(client)
            folder = tenant.default_folder or "All"
            results = _rest_get(
                session,
                f"{_SCM_CONFIG_BASE}/saas-tenant-restrictions",
                {"folder": folder, "limit": 1000},
            )
            t = Table(title="CASB SaaS Tenant Restrictions", box=box.SIMPLE_HEAD)
            t.add_column("Name", style="cyan")
            t.add_column("Applications")
            t.add_column("Action")
            for r in results:
                apps = ", ".join(r.get("applications", [])[:5]) or "—"
                t.add_row(str(r.get("name", "")), apps, str(r.get("action", "") or "—"))
            console.print(t)
            if not results:
                console.print("[yellow]No CASB restrictions found (or not licensed).[/yellow]")
        except Exception as exc:
            console.print(f"[yellow]CASB not available: {exc}[/yellow]")
    _pause()


def _op_ztna_list(tenant, console, _pause) -> None:
    from .auth.oauth import get_scm_client
    from .tools.mssp import _ZTNA_BASE, _bearer_session, _rest_get

    client = get_scm_client(tenant)
    with console.status("[cyan]Fetching ZTNA connectors...[/cyan]"):
        try:
            session = _bearer_session(client)
            connectors = _rest_get(session, f"{_ZTNA_BASE}/connectors")
            groups = _rest_get(session, f"{_ZTNA_BASE}/connector-groups")
            t = Table(title="ZTNA Connectors", box=box.SIMPLE_HEAD)
            t.add_column("Name", style="cyan")
            t.add_column("Region")
            for z in connectors:
                t.add_row(str(z.get("name", "")), str(z.get("region", "") or "—"))
            console.print(t)
            console.print(f"[dim]{len(connectors)} connector(s), {len(groups)} group(s)[/dim]")
            if not connectors and not groups:
                console.print("[yellow]ZTNA Connector not enabled for this tenant.[/yellow]")
        except Exception as exc:
            console.print(f"[yellow]ZTNA connectors not available: {exc}[/yellow]")
    _pause()


def _op_pab_inventory(tenant, console, _pause) -> None:
    from .tools.pab import register_pab_tools

    view = Prompt.ask(
        "View",
        choices=["summary", "users", "devices", "user_groups", "device_groups"],
        default="summary",
    )
    with console.status("[cyan]Fetching PAB inventory...[/cyan]"):
        try:
            result = _call_mcp_tool(
                tenant,
                register_pab_tools,
                "scm_pab_inventory",
                tenant_id=tenant.tenant_id,
                view=view,
            )
        except Exception as exc:
            result = f"Error: {exc}"
    if result.lstrip().startswith(("{", "[")):
        console.print_json(result)
    else:
        console.print(f"[red]{result}[/red]" if result.startswith("Error") else result)
    _pause()


def _op_pab_user_requests(tenant, console, _pause) -> None:
    from .tools.pab import register_pab_tools

    with console.status("[cyan]Fetching PAB user requests...[/cyan]"):
        try:
            result = _call_mcp_tool(
                tenant,
                register_pab_tools,
                "scm_pab_user_requests",
                tenant_id=tenant.tenant_id,
            )
        except Exception as exc:
            result = f"Error: {exc}"
    if result.lstrip().startswith(("{", "[")):
        console.print_json(result)
    else:
        console.print(f"[red]{result}[/red]" if result.startswith("Error") else result)
    _pause()


def _op_browser_list(tenant, console, _pause) -> None:
    from .auth.oauth import get_scm_client
    from .tools.mssp import _BROWSER_BASE, _bearer_session, _rest_get

    client = get_scm_client(tenant)
    with console.status("[cyan]Fetching Prisma Browser config...[/cyan]"):
        try:
            session = _bearer_session(client)
            device_groups = _rest_get(session, f"{_BROWSER_BASE}/device-groups")
            user_groups = _rest_get(session, f"{_BROWSER_BASE}/user-groups")
            app_groups = _rest_get(session, f"{_BROWSER_BASE}/application-groups")
            users = _rest_get(session, f"{_BROWSER_BASE}/users")
            devices = _rest_get(session, f"{_BROWSER_BASE}/devices")
            total = (
                len(device_groups) + len(user_groups) + len(app_groups) + len(users) + len(devices)
            )
            console.print(
                f"[green]✓[/green] Users: {len(users)}, Devices: {len(devices)}, "
                f"Device groups: {len(device_groups)}, User groups: {len(user_groups)}, "
                f"App groups: {len(app_groups)}"
            )
            if total == 0:
                console.print("[yellow]Prisma Browser not licensed for this tenant.[/yellow]")
        except Exception as exc:
            console.print(f"[yellow]Prisma Browser not available: {exc}[/yellow]")
    _pause()


def _op_airs_list(tenant, console, _pause) -> None:
    from .auth.oauth import get_scm_client
    from .tools.mssp import _NOT_LICENSED_STATUSES, _bearer_session, _exc_status

    _AIRS_BASE = "https://api.sase.paloaltonetworks.com/aisec"

    def _fetch(session, url, list_key):
        try:
            resp = session.get(url, timeout=(4, 10))
        except Exception as exc:
            if _exc_status(exc) in _NOT_LICENSED_STATUSES:
                return None
            raise
        if resp.status_code in _NOT_LICENSED_STATUSES:
            return None
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, list) else (data.get(list_key) or [])

    client = get_scm_client(tenant)
    with console.status("[cyan]Fetching AIRS config...[/cyan]"):
        try:
            session = _bearer_session(client)
            tsg_id = tenant.tenant_id
            apps = _fetch(
                session, f"{_AIRS_BASE}/v1/mgmt/customerapp/tsg/{tsg_id}", "customer_apps"
            )
            profiles = _fetch(session, f"{_AIRS_BASE}/v1/mgmt/profiles/tsg/{tsg_id}", "ai_profiles")
            deploys = _fetch(
                session, f"{_AIRS_BASE}/v1/mgmt/deploymentprofiles", "deployment_profiles"
            )
            if apps is None and profiles is None and deploys is None:
                console.print("[yellow]Prisma AIRS is not activated for this tenant.[/yellow]")
            else:
                console.print(
                    f"[green]✓[/green] Customer apps: {len(apps or [])}, "
                    f"AI security profiles: {len(profiles or [])}, "
                    f"Deployment profiles: {len(deploys or [])}"
                )
        except Exception as exc:
            console.print(f"[yellow]AIRS not available: {exc}[/yellow]")
    _pause()


# ── leaf operations: MSSP Operations ───────────────────────────────────────


def _op_mt_analytics(tenant, console, _pause) -> None:
    from .tools.mt_monitor import register_mt_monitor_tools

    view = Prompt.ask(
        "View", choices=["apps", "threats", "connectivity", "incidents"], default="apps"
    )
    with console.status("[cyan]Querying cross-tenant analytics...[/cyan]"):
        try:
            result = _call_mcp_tool(
                tenant,
                register_mt_monitor_tools,
                "scm_mt_analytics",
                tenant_id=tenant.tenant_id,
                view=view,
                days=30,
            )
        except Exception as exc:
            result = f"Error: {exc}"
    if result.lstrip().startswith(("{", "[")):
        console.print_json(result)
    else:
        console.print(f"[red]{result}[/red]" if result.startswith("Error") else result)
    _pause()


def _op_service_maintenance(tenant, console, _pause) -> None:
    from .tools.service_status import register_service_status_tools

    with console.status("[cyan]Fetching PAN service status...[/cyan]"):
        try:
            result = _call_mcp_tool(
                tenant,
                register_service_status_tools,
                "scm_service_maintenance",
                all_tenants=True,
            )
        except Exception as exc:
            result = f"Error: {exc}"
    if result.lstrip().startswith(("{", "[")):
        console.print_json(result)
    else:
        console.print(f"[red]{result}[/red]" if result.startswith("Error") else result)
    _pause()


def _op_mssp_tenant_dashboard(tenant, console, _pause) -> None:
    from .tools.ops import register_ops_tools

    with console.status("[cyan]Building tenant dashboard...[/cyan]"):
        try:
            result = _call_mcp_tool(tenant, register_ops_tools, "scm_tenant_dashboard")
            console.print(Markdown(result))
        except Exception as exc:
            console.print(f"[red]Error: {exc}[/red]")
    _pause()


def _op_noc_dashboard(tenant, console, _pause) -> None:
    from .tools.ops import register_ops_tools

    with console.status("[cyan]Building NOC health dashboard...[/cyan]"):
        try:
            result = _call_mcp_tool(
                tenant, register_ops_tools, "scm_tenant_dashboard", include_expired=True
            )
            console.print(Markdown(result))
        except Exception as exc:
            console.print(f"[red]Error: {exc}[/red]")
    _pause()


def _op_license_info(tenant, console, _pause) -> None:
    from .auth.oauth import fetch_licenses, get_scm_client

    client = get_scm_client(tenant)
    with console.status("[cyan]Fetching licences...[/cyan]"):
        try:
            licenses = fetch_licenses(client)
            if licenses:
                t = Table(title="Subscription Licences", box=box.SIMPLE_HEAD)
                t.add_column("Product", style="cyan")
                t.add_column("SKU")
                t.add_column("Qty")
                t.add_column("Expiry")
                for lic in licenses:
                    t.add_row(
                        str(lic.get("product", "") or lic.get("description", "")),
                        str(lic.get("sku", "") or lic.get("name", "")),
                        str(lic.get("quantity", "") or lic.get("total", "")),
                        str(lic.get("expiry_date", "") or "—"),
                    )
                console.print(t)
                out = _save_json_static(licenses, "licenses", tenant.tenant_id, console)
                if out:
                    console.print(f"[dim]Saved: {out}[/dim]")
            else:
                console.print("[yellow]No licences found.[/yellow]")
        except Exception as exc:
            console.print(f"[red]Error: {exc}[/red]")
    _pause()


def _op_license_forecast(tenant, console, _pause) -> None:
    with console.status("[cyan]Forecasting licence expiry...[/cyan]"):
        try:
            from .tools.ops import register_ops_tools

            result = _call_mcp_tool(tenant, register_ops_tools, "scm_licence_forecast")
            console.print(Markdown(result))
        except Exception as exc:
            console.print(f"[red]Error: {exc}[/red]")
    _pause()


def _op_mobile_user_stats(tenant, console, _pause) -> None:
    from .auth.oauth import get_scm_client

    client = get_scm_client(tenant)
    with console.status("[cyan]Fetching mobile user stats...[/cyan]"):
        try:
            session = getattr(client, "session", None)
            if session:
                resp = session.get(
                    "https://api.sase.paloaltonetworks.com/sse/config/v1/mobile-agent/infrastructure-settings"
                )
                if resp.status_code == 200:
                    console.print(json.dumps(resp.json(), indent=2)[:3000])
                else:
                    console.print(f"[yellow]Mobile user API returned {resp.status_code}[/yellow]")
            else:
                console.print("[yellow]No HTTP session available[/yellow]")
        except Exception as exc:
            console.print(f"[yellow]Mobile user stats not available: {exc}[/yellow]")
    _pause()


def _op_gp_session_summary(tenant, console, _pause) -> None:
    from .auth.oauth import get_scm_client

    client = get_scm_client(tenant)
    with console.status("[cyan]Fetching GP session summary...[/cyan]"):
        try:
            session = getattr(client, "session", None)
            if session:
                resp = session.get(
                    "https://api.sase.paloaltonetworks.com/sse/config/v1/mobile-agent/sessions"
                )
                if resp.status_code == 200:
                    console.print(json.dumps(resp.json(), indent=2)[:3000])
                else:
                    console.print(f"[yellow]GP session API returned {resp.status_code}[/yellow]")
            else:
                console.print("[yellow]No HTTP session available[/yellow]")
        except Exception as exc:
            console.print(f"[yellow]GP session summary not available: {exc}[/yellow]")
    _pause()


def _op_user_count(tenant, console, _pause) -> None:
    """Live connected user count via Insights API — GP vs PA Agent split."""
    from .auth.oauth import get_scm_client

    client = get_scm_client(tenant)
    tid = tenant.tenant_id
    with console.status("[cyan]Querying connected user count...[/cyan]"):
        try:
            session = getattr(client, "session", None)
            if not session:
                console.print("[red]No HTTP session available.[/red]")
                _pause()
                return

            # GP mobile users
            gp_resp = session.post(
                "https://api.sase.paloaltonetworks.com/insights/v3.0/resource/query/gp_mobileusers/connected_user_count",
                json={},
                headers={
                    "Content-Type": "application/json",
                    "X-PANW-Region": "eu",
                    "Prisma-Tenant": str(tid),
                },
                timeout=(5, 20),
            )
            gp_count = 0
            if gp_resp.status_code == 200:
                gp_data = gp_resp.json()
                gp_count = (gp_data.get("data", [{}]) or [{}])[0].get("user_count", 0)

            # PA Agent users
            agent_resp = session.post(
                "https://api.sase.paloaltonetworks.com/insights/v3.0/resource/query/users/agent/connected_user_count",
                json={},
                headers={
                    "Content-Type": "application/json",
                    "X-PANW-Region": "eu",
                    "Prisma-Tenant": str(tid),
                },
                timeout=(5, 20),
            )
            agent_count = 0
            if agent_resp.status_code == 200:
                agent_data = agent_resp.json()
                agent_count = (agent_data.get("data", [{}]) or [{}])[0].get("user_count", 0)

            total = gp_count + agent_count

            t = Table(title=f"Connected User Count — {tenant.label}", box=box.SIMPLE_HEAD)
            t.add_column("Metric", style="cyan")
            t.add_column("Count", style="bold")
            t.add_row("Total Connected", str(total))
            t.add_row("GlobalProtect (Prisma Access)", str(gp_count))
            t.add_row("PA Agent (NGFW)", str(agent_count))
            console.print(t)

            # Try for licensed MU seats
            try:
                from .auth.oauth import fetch_licenses

                lics = fetch_licenses(client)
                licensed = 0
                for bundle in lics:
                    for lic in bundle.get("licenses", []):
                        sku = (lic.get("license_type") or "").upper()
                        app = (bundle.get("app_id") or "").lower()
                        if "mu" in sku and "prisma_access" in app:
                            purchased = int(lic.get("purchased_size") or 0)
                            if purchased > licensed:
                                licensed = purchased
                if licensed > 0:
                    util = round(total / licensed * 100, 1)
                    console.print(
                        f"\n[dim]Licensed MU seats: {licensed} — Utilisation: {util}%[/dim]"
                    )
                    if util >= 90:
                        console.print("[red]⚠ High utilisation — consider adding licences.[/red]")
            except Exception:
                pass

        except Exception as exc:
            console.print(f"[yellow]User count unavailable: {exc}[/yellow]")
    _pause()


def _op_spn_bandwidth(tenant, console, _pause) -> None:
    from .auth.oauth import get_scm_client

    client = get_scm_client(tenant)
    with console.status("[cyan]Fetching SPN bandwidth...[/cyan]"):
        try:
            results = list(
                client.bandwidth_allocation.list(
                    folder=tenant.default_folder or "Shared", limit=200
                )
            )
            if results:
                t = Table(title="SPN Bandwidth Allocations", box=box.SIMPLE_HEAD)
                t.add_column("Location", style="cyan")
                t.add_column("Allocated BW (Mbps)")
                t.add_column("SPN Nodes")
                for r in results:
                    t.add_row(
                        str(getattr(r, "name", "")),
                        str(getattr(r, "allocated_bandwidth", "")),
                        str(getattr(r, "spn_nodes", "")),
                    )
                console.print(t)
            else:
                console.print("[yellow]No bandwidth allocations found.[/yellow]")
        except Exception as exc:
            console.print(f"[red]Error: {exc}[/red]")
    _pause()


def _op_cert_lifecycle(tenant, console, _pause) -> None:
    from .auth.oauth import get_scm_client

    client = get_scm_client(tenant)
    with console.status("[cyan]Scanning certificate lifecycle...[/cyan]"):
        try:
            results = list(client.certificate.list(folder="All", limit=500))
            if results:
                now = datetime.now(UTC)
                t = Table(title="TLS Certificate Lifecycle", box=box.SIMPLE_HEAD)
                t.add_column("Name", style="cyan")
                t.add_column("Subject")
                t.add_column("Expiry")
                t.add_column("Status")
                for cert in results:
                    expiry_str = str(getattr(cert, "not_valid_after", "") or "—")
                    status = "●"
                    if expiry_str and expiry_str != "—":
                        try:
                            expiry = datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
                            days_left = (expiry - now).days
                            if days_left < 0:
                                status = "[red]✗ EXPIRED[/red]"
                            elif days_left < 30:
                                status = f"[yellow]⚠ {days_left}d[/yellow]"
                            elif days_left < 90:
                                status = f"[dim]⚠ {days_left}d[/dim]"
                            else:
                                status = f"[green]● {days_left}d[/green]"
                        except (ValueError, TypeError):
                            pass
                    t.add_row(
                        str(getattr(cert, "name", "")),
                        str(
                            getattr(cert, "common_name", "") or getattr(cert, "subject", "") or "—"
                        ),
                        expiry_str,
                        status,
                    )
                console.print(t)
                console.print(f"[dim]{len(results)} certificate(s)[/dim]")
            else:
                console.print("[yellow]No certificates found.[/yellow]")
        except Exception as exc:
            console.print(f"[red]Error: {exc}[/red]")
    _pause()


def _op_cert_scan(tenant, console, _pause) -> None:
    _op_cert_lifecycle(tenant, console, _pause)


def _op_discover_tenants(tenant, console, _pause) -> None:
    from .auth.oauth import get_scm_client

    client = get_scm_client(tenant)
    with console.status("[cyan]Discovering managed tenants...[/cyan]"):
        try:
            session = getattr(client, "session", None)
            if session:
                resp = session.get("https://api.sase.paloaltonetworks.com/tenancy/v1/tenants")
                if resp.status_code == 200:
                    data = resp.json()
                    tenants_list = data.get("data", [])
                    t = Table(title="Managed Tenants", box=box.SIMPLE_HEAD)
                    t.add_column("Name", style="cyan")
                    t.add_column("TSG ID")
                    t.add_column("Status")
                    for tn in tenants_list:
                        t.add_row(
                            str(tn.get("name", "")),
                            str(tn.get("tsg_id", "")),
                            str(tn.get("status", "")),
                        )
                    console.print(t)
                else:
                    console.print(f"[yellow]Tenancy API returned {resp.status_code}[/yellow]")
            else:
                console.print("[yellow]No HTTP session available[/yellow]")
        except Exception as exc:
            console.print(f"[yellow]Tenant discovery not available: {exc}[/yellow]")
    _pause()


# ── leaf operations: Posture & Incidents ───────────────────────────────────


def _op_saas_posture(tenant, console, _pause) -> None:
    from .tools.posture import register_posture_tools

    load_from = Prompt.ask("Import from JSON export (blank = live API)", default="").strip()
    save_to = ""
    if not load_from:
        save_to = Prompt.ask(
            "Export snapshot to (blank = don't export)",
            default="",
        ).strip()
    with console.status("[cyan]Building SaaS posture summary...[/cyan]"):
        try:
            result = _call_mcp_tool(
                tenant,
                register_posture_tools,
                "scm_saas_posture",
                tenant_id=tenant.tenant_id,
                save_to=save_to,
                load_from=load_from,
            )
        except Exception as exc:
            result = f"Error: {exc}"
    if result.startswith("Error"):
        console.print(f"[red]{result}[/red]")
    else:
        console.print(Markdown(result))
    _pause()


def _op_compliance_center(tenant, console, _pause) -> None:
    from .tools.compliance import register_compliance_tools

    console.print()
    console.print("[bold]Compliance Center — Select Action:[/bold]")
    console.print()
    actions_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    actions_table.add_column(style="cyan", width=4)
    actions_table.add_column(width=24)
    actions_table.add_column(style="dim")
    for num, title, desc in [
        ("1", "List Frameworks", "Browse framework definitions"),
        ("2", "Summaries", "Scores, revision state, benchmark status"),
        ("3", "Scores", "Overall/industry scores by product + category"),
        ("4", "Controls", "Per-control pass/fail detail with severity"),
        ("5", "Timeline", "30-day / 1-year score trend"),
        ("6", "Assessed Configs", "Check, assessment & exception counts"),
        ("7", "Benchmark Monitoring", "Live BPC monitoring data"),
        ("8", "Framework Detail", "Full framework JSON"),
    ]:
        actions_table.add_row(num, title, desc)
    console.print(actions_table)
    action_choice = Prompt.ask("Action", default="1").strip()
    action_map = {
        "1": "list-frameworks",
        "2": "summaries",
        "3": "scores",
        "4": "controls",
        "5": "timeline",
        "6": "assessed",
        "7": "benchmark-monitoring",
        "8": "framework-detail",
    }
    action = action_map.get(action_choice, "list-frameworks")
    kwargs: dict[str, Any] = {"action": action, "tenant_id": tenant.tenant_id}

    if action in ("scores", "controls", "timeline", "assessed", "framework-detail"):
        fw_id = Prompt.ask("Framework ID", default="").strip()
        if fw_id:
            kwargs["framework_id"] = fw_id
    if action in ("summaries", "scores", "timeline", "controls", "assessed"):
        prod = Prompt.ask("Product filter (sase/ngfw/all, blank=all)", default="").strip()
        if prod:
            kwargs["product"] = prod

    with console.status(f"[cyan]Running Compliance Center: {action}...[/cyan]"):
        try:
            result = _call_mcp_tool(
                tenant,
                register_compliance_tools,
                "scm_compliance_center",
                **kwargs,
            )
        except Exception as exc:
            result = f"Error: {exc}"
    if result.startswith("Error"):
        console.print(f"[red]{result}[/red]")
    else:
        console.print(Markdown(result))
    _pause()


def _op_posture_report(tenant, console, _pause) -> None:
    from .auth.oauth import get_scm_client

    client = get_scm_client(tenant)
    folder = tenant.default_folder or "Shared"
    with console.status("[cyan]Fetching posture report...[/cyan]"):
        try:
            session = getattr(client, "session", None)
            if session:
                # Matches scm_posture_report's confirmed endpoint (tools/posture.py).
                resp = session.get(
                    "https://api.strata.paloaltonetworks.com/posture/v1/reports",
                    params={"folder": folder},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    items = data.get("data", [])
                    console.print(f"[green]✓[/green] Posture findings: {len(items)}")
                elif resp.status_code == 403:
                    console.print(
                        "[yellow]Posture Management is not licensed for this tenant.[/yellow]"
                    )
                else:
                    console.print(f"[yellow]Posture API returned {resp.status_code}[/yellow]")
            else:
                console.print("[yellow]No HTTP session available[/yellow]")
        except Exception as exc:
            console.print(f"[yellow]Posture report not available: {exc}[/yellow]")
    _pause()


def _op_incident_summary(tenant, console, _pause) -> None:
    from .auth.oauth import get_scm_client

    client = get_scm_client(tenant)
    with console.status("[cyan]Fetching incident summary...[/cyan]"):
        try:
            session = getattr(client, "session", None)
            if session:
                # The search endpoint rejects unknown body fields (e.g. days/limit)
                # with repeated 500s — matches scm_incident_search's json={} call.
                resp = session.post(
                    "https://api.strata.paloaltonetworks.com/incidents/v1/search",
                    json={},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    items = data.get("data") or []
                    sev_counts: dict[str, int] = {}
                    for inc in items:
                        sev = str(inc.get("severity", "unknown"))
                        sev_counts[sev] = sev_counts.get(sev, 0) + 1
                    console.print(
                        Panel(
                            "\n".join(
                                f"[bold]{s.upper()}[/bold]: {c}"
                                for s, c in sorted(sev_counts.items())
                            )
                            or "[green]No incidents found.[/green]",
                            title=f"Incident Summary — {len(items)} total",
                        )
                    )
                else:
                    console.print(f"[yellow]Incidents API returned {resp.status_code}[/yellow]")
            else:
                console.print("[yellow]No HTTP session available[/yellow]")
        except Exception as exc:
            console.print(f"[yellow]Incident summary not available: {exc}[/yellow]")
    _pause()


def _op_tls_profile_manager(tenant, console, _pause) -> None:
    from .auth.oauth import get_scm_client
    from .cli import _exc_str

    client = get_scm_client(tenant)
    folder = tenant.default_folder or "Shared"
    with console.status("[cyan]Fetching TLS profiles...[/cyan]"):
        try:
            # No pan-scm-sdk resource for TLS service profiles — raw Config REST API,
            # matching the scm_tls_profile_manager MCP tool (tools/ops.py).
            result = client.get(
                "/config/v1/tls-service-profiles", params={"folder": folder, "limit": 200}
            )
            if isinstance(result, dict):
                results = result.get("data", [])
            elif isinstance(result, list):
                results = result
            else:
                results = []
            t = Table(title="TLS Service Profiles", box=box.SIMPLE_HEAD)
            t.add_column("Name", style="cyan")
            t.add_column("Min Version")
            t.add_column("Max Version")
            for r in results:
                proto = r.get("protocol_settings") or r.get("protocol") or {}
                t.add_row(
                    str(r.get("name", "")),
                    str(proto.get("min_version", "—")),
                    str(proto.get("max_version", "—")),
                )
            console.print(t)
            if not results:
                console.print(
                    f"[yellow]No TLS service profiles found in folder '{folder}'.[/yellow]"
                )
        except Exception as exc:
            console.print(f"[yellow]TLS profiles not available: {_exc_str(exc)}[/yellow]")
    _pause()


# ── leaf operations: Remediation ───────────────────────────────────────────


def _op_apply_ncsc(tenant, console, _pause) -> None:
    from .cli import _exc_str

    folder = tenant.default_folder or "Shared"
    dry_run = Prompt.ask("Dry run?", default="yes").strip().lower() in ("yes", "y", "true")
    ticket_ref = Prompt.ask("Change ticket reference (mandatory)", default="").strip()
    with console.status(f"[cyan]Applying NCSC baseline to [bold]{folder}[/bold]...[/cyan]"):
        try:
            from .tools.ncsc_baseline import register_ncsc_tools

            result = _call_mcp_tool(
                tenant,
                register_ncsc_tools,
                "scm_apply_ncsc_baseline",
                folder=folder,
                dry_run=dry_run,
                ticket_ref=ticket_ref,
            )
            console.print(result)
        except Exception as exc:
            console.print(f"[red]Error: {_exc_str(exc)}[/red]")
    _pause()


def _op_attach_ncsc(tenant, console, _pause) -> None:
    from .cli import _exc_str

    folder = tenant.default_folder or "Shared"
    dry_run = Prompt.ask("Dry run?", default="yes").strip().lower() in ("yes", "y", "true")
    ticket_ref = Prompt.ask("Change ticket reference (mandatory)", default="").strip()
    with console.status(f"[cyan]Attaching NCSC profiles in [bold]{folder}[/bold]...[/cyan]"):
        try:
            from .tools.ncsc_baseline import register_ncsc_tools

            result = _call_mcp_tool(
                tenant,
                register_ncsc_tools,
                "scm_attach_ncsc_profiles",
                folder=folder,
                dry_run=dry_run,
                ticket_ref=ticket_ref,
            )
            console.print(result)
        except Exception as exc:
            console.print(f"[red]Error: {_exc_str(exc)}[/red]")
    _pause()


def _op_create_ncsc_snippet(tenant, console, _pause) -> None:
    from .cli import _exc_str

    dry_run = Prompt.ask("Dry run?", default="yes").strip().lower() in ("yes", "y", "true")
    ticket_ref = Prompt.ask("Change ticket reference (mandatory)", default="").strip()
    with console.status("[cyan]Creating NCSC snippet...[/cyan]"):
        try:
            from .tools.ncsc_baseline import register_ncsc_tools

            result = _call_mcp_tool(
                tenant,
                register_ncsc_tools,
                "scm_create_ncsc_snippet",
                dry_run=dry_run,
                ticket_ref=ticket_ref,
            )
            console.print(result)
        except Exception as exc:
            console.print(f"[red]Error: {_exc_str(exc)}[/red]")
    _pause()


def _op_create_nist_snippet(tenant, console, _pause) -> None:
    from .cli import _exc_str

    dry_run = Prompt.ask("Dry run?", default="yes").strip().lower() in ("yes", "y", "true")
    ticket_ref = Prompt.ask("Change ticket reference (mandatory)", default="").strip()
    with console.status("[cyan]Creating NIST snippet...[/cyan]"):
        try:
            from .tools.ncsc_baseline import register_ncsc_tools

            result = _call_mcp_tool(
                tenant,
                register_ncsc_tools,
                "scm_create_nist_snippet",
                dry_run=dry_run,
                ticket_ref=ticket_ref,
            )
            console.print(result)
        except Exception as exc:
            console.print(f"[red]Error: {_exc_str(exc)}[/red]")
    _pause()


def _op_ncsc_gap(tenant, console, _pause) -> None:
    from .cli import _exc_str

    folder = tenant.default_folder or "Shared"
    with console.status(f"[cyan]Running NCSC gap analysis in [bold]{folder}[/bold]...[/cyan]"):
        try:
            from .tools.ncsc_baseline import register_ncsc_tools

            result = _call_mcp_tool(tenant, register_ncsc_tools, "scm_ncsc_gap", folder=folder)
            console.print(result)
        except Exception as exc:
            console.print(f"[red]Error: {_exc_str(exc)}[/red]")
    _pause()


def _op_nist_gap(tenant, console, _pause) -> None:
    from .cli import _exc_str

    folder = tenant.default_folder or "Shared"
    with console.status(f"[cyan]Running NIST gap analysis in [bold]{folder}[/bold]...[/cyan]"):
        try:
            from .tools.ncsc_baseline import register_ncsc_tools

            result = _call_mcp_tool(tenant, register_ncsc_tools, "scm_nist_gap", folder=folder)
            console.print(result)
        except Exception as exc:
            console.print(f"[red]Error: {_exc_str(exc)}[/red]")
    _pause()


def _op_ai_advisor(tenant, console, _pause) -> None:
    from .cli import _exc_str

    folder = tenant.default_folder or "Shared"
    framework = Prompt.ask("Framework", default="both").strip()
    with console.status(f"[cyan]Running AI compliance advisor for [bold]{folder}[/bold]...[/cyan]"):
        try:
            from .tools.ai_advisor import register_ai_advisor_tools

            result = _call_mcp_tool(
                tenant,
                register_ai_advisor_tools,
                "scm_ai_compliance_advisor",
                folder=folder,
                framework=framework,
                tenant_label=tenant.label,
            )
            console.print(result)
        except Exception as exc:
            console.print(f"[red]Error: {_exc_str(exc)}[/red]")
    _pause()


# ── leaf operations: Config Lifecycle ──────────────────────────────────────


def _backup_meta(path: Path) -> tuple[str, str]:
    """(tenant label or id, folder) read from the head of a backup file.

    The metadata keys are written before "resources", so a short read avoids
    parsing multi-hundred-MB snapshots just to build the picker.
    """
    try:
        head = path.read_text(errors="ignore")[:1024]
    except OSError:
        return "—", "—"
    meta = {}
    for key in ("tenant_id", "label", "folder"):
        m = re.search(rf'"{key}"\s*:\s*"([^"]*)"', head)
        if m:
            meta[key] = m.group(1)
    return meta.get("label") or meta.get("tenant_id") or "—", meta.get("folder") or "—"


def _pick_backup_file(
    console,
    _pause,
    *,
    pattern: str = "scm_backup_*.json",
    title: str = "Available Backups",
    limit: int = 20,
) -> Path | None:
    """Numbered picker over the backup directory, with a typed-path fallback."""
    backup_dir = Path(os.getenv("SCM_MCP_BACKUP_DIR", "backups"))
    found = sorted(backup_dir.glob(pattern), key=lambda f: f.stat().st_mtime, reverse=True)
    backups = found[:limit]

    if backups:
        console.print()
        t = Table(title=title, box=box.SIMPLE_HEAD, border_style="dim")
        t.add_column("#", style="dim", width=4)
        t.add_column("File", style="cyan")
        t.add_column("Tenant", style="white")
        t.add_column("Folder", style="white")
        t.add_column("Created", style="dim")
        t.add_column("Size", justify="right", style="dim")
        for idx, f in enumerate(backups, 1):
            label, folder = _backup_meta(f)
            stat = f.stat()
            t.add_row(
                str(idx),
                f.name,
                label,
                folder,
                datetime.fromtimestamp(stat.st_mtime, UTC).strftime("%Y-%m-%d %H:%M"),
                f"{stat.st_size // 1024} KB",
            )
        console.print(t)
        if len(found) > len(backups):
            console.print(f"[dim]Showing {len(backups)} most recent of {len(found)}.[/dim]")
        console.print()
        raw = Prompt.ask("Select # (or type a file path)", default="1").strip()
    else:
        console.print(f"\n[yellow]No backups matching {pattern} in {backup_dir}/[/yellow]")
        console.print("[dim]Run Backup Config first, or type a path to a backup JSON.[/dim]\n")
        raw = Prompt.ask("Backup JSON path", default="").strip()

    if not raw:
        console.print("[red]Nothing selected.[/red]")
        _pause()
        return None

    if raw.isdigit() and backups:
        try:
            return backups[int(raw) - 1]
        except IndexError:
            console.print(f"[red]Invalid selection — pick 1-{len(backups)}.[/red]")
            _pause()
            return None

    # Typed path: accept absolute/relative, a bare filename in the backup dir,
    # and either form with the .json suffix left off.
    candidates = [Path(raw), backup_dir / raw, Path(f"{raw}.json"), backup_dir / f"{raw}.json"]
    for cand in candidates:
        if cand.is_file():
            return cand
    console.print(f"[red]File not found: {raw}[/red]")
    _pause()
    return None


def _op_config_clone(tenant, console, _pause) -> None:
    source = _pick_backup_file(console, _pause, title="Source Backups")
    if source is None:
        return

    target_folder = Prompt.ask("Target folder", default=tenant.default_folder or "Shared").strip()
    if not target_folder:
        console.print("[red]Target folder required.[/red]")
        _pause()
        return
    name_prefix = Prompt.ask("Name prefix (blank for none)", default="").strip()
    include_deployment = Prompt.ask(
        "Include deployment objects (IKE/IPSec/RN/SC)?", default="no"
    ).strip().lower() in ("yes", "y", "true")
    dry_run = Prompt.ask("Dry run?", default="yes").strip().lower() in ("yes", "y", "true")

    if not dry_run and not Confirm.ask(
        f"\n[bold yellow]Push cloned objects into {target_folder} on {tenant.label}?[/bold yellow]",
        default=False,
    ):
        console.print("[dim]Clone cancelled.[/dim]")
        _pause()
        return

    with console.status("[cyan]Cloning config...[/cyan]"):
        try:
            from .audit.cloner import clone_config

            # A dry run makes no API calls, so don't force an auth round-trip.
            client = None
            if not dry_run:
                from .auth.oauth import get_scm_client

                client = get_scm_client(tenant)
            report = clone_config(
                client,
                source_backup_file=str(source),
                target_folder=target_folder,
                name_prefix=name_prefix,
                include_deployment=include_deployment,
                dry_run=dry_run,
            )
            report.target_tenant_id = tenant.tenant_id
            console.print(Markdown(report.to_markdown()))
        except Exception as exc:
            console.print(f"[red]Error: {exc}[/red]")
    _pause()


def _op_commit(tenant, console, _pause) -> None:
    from .auth.oauth import get_scm_client

    client = get_scm_client(tenant)
    folders_input = Prompt.ask(
        "Folders to commit (comma-separated)", default=tenant.default_folder or "Shared"
    ).strip()
    folders = [f.strip() for f in folders_input.split(",") if f.strip()]
    desc = Prompt.ask("Description", default="CLI commit").strip()
    if not Confirm.ask(
        f"\n[bold yellow]Commit {len(folders)} folder(s) to {tenant.label}?[/bold yellow]",
        default=False,
    ):
        console.print("[dim]Commit cancelled.[/dim]")
        return
    with console.status(f"[cyan]Committing {len(folders)} folder(s)...[/cyan]"):
        try:
            client.commit(folders=folders, description=desc)
            console.print(f"[green]✓[/green] Commit submitted for: {', '.join(folders)}")
        except Exception as exc:
            console.print(f"[red]Error: {exc}[/red]")
    _pause()


def _op_config_push(tenant, console, _pause) -> None:
    from .cli import _exc_str

    folders_input = Prompt.ask(
        "Folders to push (comma-separated)", default=tenant.default_folder or "Shared"
    ).strip()
    folders = [f.strip() for f in folders_input.split(",") if f.strip()]
    desc = Prompt.ask("Description", default="CLI push").strip()
    ticket_ref = Prompt.ask("Change ticket reference (mandatory)", default="").strip()
    if not ticket_ref:
        console.print("[red]A change ticket reference is required.[/red]")
        _pause()
        return
    if not Confirm.ask(
        f"\n[bold yellow]Push {len(folders)} folder(s) to {tenant.label}?[/bold yellow]",
        default=False,
    ):
        console.print("[dim]Push cancelled.[/dim]")
        return
    with console.status(f"[cyan]Pushing {len(folders)} folder(s)...[/cyan]"):
        try:
            from .tools.deployment import register_deployment_tools

            result = _call_mcp_tool(
                tenant,
                register_deployment_tools,
                "scm_config_push_track",
                folders=folders,
                description=desc,
                # The Confirm prompt above is the human approval for this push.
                dry_run=False,
                ticket_ref=ticket_ref,
            )
            console.print(result)
        except Exception as exc:
            console.print(f"[red]Error: {_exc_str(exc)}[/red]")
    _pause()


def _op_config_rollback(tenant, console, _pause) -> None:
    from .cli import _exc_str

    version_str = Prompt.ask("Version number to load", default="").strip()
    if not version_str:
        console.print("[red]Version required.[/red]")
        _pause()
        return
    commit_now = Prompt.ask("Commit immediately?", default="no").strip().lower() in (
        "yes",
        "y",
        "true",
    )
    ticket_ref = Prompt.ask("Change ticket reference (mandatory)", default="").strip()
    if not ticket_ref:
        console.print("[red]A change ticket reference is required.[/red]")
        _pause()
        return
    if not Confirm.ask(
        f"\n[bold red]Rollback {tenant.label} to version {version_str}?[/bold red]",
        default=False,
    ):
        console.print("[dim]Rollback cancelled.[/dim]")
        return
    try:
        version = int(version_str)
    except ValueError:
        console.print("[red]Invalid version number.[/red]")
        _pause()
        return
    with console.status(f"[cyan]Loading version {version}...[/cyan]"):
        try:
            from .tools.deployment import register_deployment_tools

            result = _call_mcp_tool(
                tenant,
                register_deployment_tools,
                "scm_config_rollback",
                version=version,
                commit_immediately=commit_now,
                # The Confirm prompt above is the human approval for this rollback.
                dry_run=False,
                ticket_ref=ticket_ref,
            )
            console.print(result)
        except Exception as exc:
            console.print(f"[red]Error: {_exc_str(exc)}[/red]")
    _pause()


def _op_adnsr_list(tenant, console, _pause) -> None:
    from .cli import _exc_str

    folder = tenant.default_folder or "Shared"
    with console.status("[cyan]Fetching ADNSR profiles...[/cyan]"):
        try:
            from .tools.adnsr import register_adnsr_tools

            result = _call_mcp_tool(
                tenant, register_adnsr_tools, "scm_adnsr_list", resource="profiles", folder=folder
            )
            console.print(result)
        except Exception as exc:
            console.print(f"[yellow]ADNSR not available: {_exc_str(exc)}[/yellow]")
    _pause()


def _op_ngfw_devices(tenant, console, _pause) -> None:
    from .auth.oauth import get_scm_client

    client = get_scm_client(tenant)
    folder = tenant.default_folder or "ngfw-shared"
    with console.status(f"[cyan]Fetching NGFW devices from [bold]{folder}[/bold]...[/cyan]"):
        try:
            results = list(client.device.list(folder=folder, limit=200))
            t = Table(title="NGFW Managed Devices", box=box.SIMPLE_HEAD)
            t.add_column("Hostname", style="cyan")
            t.add_column("Serial")
            t.add_column("Model")
            t.add_column("SW Version")
            t.add_column("HA State")
            for d in results:
                t.add_row(
                    str(getattr(d, "hostname", "")),
                    str(getattr(d, "serial_number", "")),
                    str(getattr(d, "model", "")),
                    str(getattr(d, "sw_version", "")),
                    str(getattr(d, "ha_state", "") or "—"),
                )
            console.print(t)
            if results:
                out = _save_json_static(results, "ngfw_devices", tenant.tenant_id, console)
                if out:
                    console.print(f"[dim]Saved: {out}[/dim]")
        except Exception as exc:
            console.print(f"[red]Error: {exc}[/red]")
    _pause()


def _op_device_summary(tenant, console, _pause) -> None:
    """Device inventory health summary — count by model, connection, HA state."""
    from .auth.oauth import get_scm_client

    client = get_scm_client(tenant)
    with console.status("[cyan]Querying device inventory...[/cyan]"):
        try:
            all_devices = []
            for folder in ("ngfw-shared", "Shared", "All"):
                try:
                    results = list(client.device.list(folder=folder, limit=1000))
                    all_devices.extend(
                        [d.model_dump() if hasattr(d, "model_dump") else d for d in results]
                    )
                except Exception:
                    pass

            if not all_devices:
                console.print("[yellow]No devices found in any folder.[/yellow]")
                _pause()
                return

            total = len(all_devices)
            connected = sum(1 for d in all_devices if d.get("is_connected") or d.get("connected"))
            offline = total - connected

            # Summary panel
            console.print(
                Panel(
                    f"[bold]Total Devices:[/bold] {total}\n"
                    f"[green]● Connected:[/green] {connected} ({round(connected / total * 100, 1)}%)\n"
                    f"[red]● Offline:[/red] {offline} ({round(offline / total * 100, 1)}%)",
                    title=f"Device Inventory — {tenant.label}",
                )
            )

            # HA state breakdown
            ha_states: dict[str, int] = {}
            for d in all_devices:
                state = d.get("ha_state") or d.get("haState") or "standalone"
                ha_states[state] = ha_states.get(state, 0) + 1
            if ha_states:
                t_ha = Table(title="HA State Breakdown", box=box.SIMPLE_HEAD)
                t_ha.add_column("State", style="cyan")
                t_ha.add_column("Count")
                icons = {"active": "🟢", "passive": "🟡", "standalone": "⚪"}
                for state, count in sorted(ha_states.items(), key=lambda x: -x[1]):
                    t_ha.add_row(f"{icons.get(state, '🔵')} {state}", str(count))
                console.print(t_ha)

            # Per-model breakdown
            models: dict[str, int] = {}
            for d in all_devices:
                model = d.get("model") or d.get("family") or "Unknown"
                models[model] = models.get(model, 0) + 1
            if models:
                t_m = Table(title="Per-Model Breakdown", box=box.SIMPLE_HEAD)
                t_m.add_column("Model", style="cyan")
                t_m.add_column("Count")
                for model, count in sorted(models.items(), key=lambda x: -x[1]):
                    t_m.add_row(model, str(count))
                console.print(t_m)

            console.print(f"[dim]{total} device(s) across ngfw-shared, Shared, All[/dim]")

        except Exception as exc:
            console.print(f"[red]Error: {exc}[/red]")
    _pause()


def _op_ngfw_local_config_list(tenant, console, _pause) -> None:
    from .cli import _exc_str

    serial = Prompt.ask("Device serial number", default="").strip()
    if not serial:
        console.print("[red]Serial number required.[/red]")
        _pause()
        return
    with console.status(f"[cyan]Fetching local config versions for {serial}...[/cyan]"):
        try:
            from .tools.adnsr import register_adnsr_tools

            result = _call_mcp_tool(
                tenant, register_adnsr_tools, "scm_ngfw_local_config_list", serial=serial
            )
            console.print(result)
        except Exception as exc:
            console.print(f"[red]Error: {_exc_str(exc)}[/red]")
    _pause()


def _op_ngfw_local_config_get(tenant, console, _pause) -> None:
    from .cli import _exc_str

    serial = Prompt.ask("Device serial number", default="").strip()
    if not serial:
        console.print("[red]Serial number required.[/red]")
        _pause()
        return
    version = Prompt.ask("Version", default="running").strip()
    with console.status(f"[cyan]Fetching config {version} for {serial}...[/cyan]"):
        try:
            from .tools.adnsr import register_adnsr_tools

            result = _call_mcp_tool(
                tenant,
                register_adnsr_tools,
                "scm_ngfw_local_config_get",
                serial=serial,
                version=version,
            )
            console.print(result[:5000])
        except Exception as exc:
            console.print(f"[red]Error: {_exc_str(exc)}[/red]")
    _pause()


# ── leaf operations: Audit & Compliance extras ─────────────────────────────


def _op_nist(tenant, console, _pause) -> None:
    from .cli import _exc_str

    folder = tenant.default_folder or "Shared"
    with console.status(f"[cyan]Running NIST assessment on [bold]{folder}[/bold]...[/cyan]"):
        try:
            # No standalone NIST CSF/SP 800-53 scoring exists — scm_nist_gap is the
            # only tested NIST assessment capability, shared with the Remediation menu.
            from .tools.ncsc_baseline import register_ncsc_tools

            result = _call_mcp_tool(tenant, register_ncsc_tools, "scm_nist_gap", folder=folder)
            console.print(result)
        except Exception as exc:
            console.print(f"[red]Error: {_exc_str(exc)}[/red]")
    _pause()


def _op_iso27001(tenant, console, _pause) -> None:
    from .cli import _exc_str

    folder = tenant.default_folder or "Shared"
    with console.status(f"[cyan]Running ISO 27001 assessment on [bold]{folder}[/bold]...[/cyan]"):
        try:
            from .tools.audit import register_audit_tools

            result = _call_mcp_tool(
                tenant, register_audit_tools, "scm_iso27001_assess", folder=folder
            )
            console.print(result)
        except Exception as exc:
            console.print(f"[red]Error: {_exc_str(exc)}[/red]")
    _pause()


def _op_decrypt_audit(tenant, console, _pause) -> None:
    from .audit.extractor import extract_snapshot
    from .auth.oauth import get_scm_client

    client = get_scm_client(tenant)
    folder = tenant.default_folder or "Shared"
    with console.status(f"[cyan]Auditing decryption policy in [bold]{folder}[/bold]...[/cyan]"):
        try:
            snap = extract_snapshot(client, folder, tenant.tenant_id)
            dr_count = len(snap.decryption_rules)
            dp_count = len(snap.decryption_profiles)
            console.print(
                Panel(
                    f"Decryption Rules: [bold]{dr_count}[/bold]\n"
                    f"Decryption Profiles: [bold]{dp_count}[/bold]\n"
                    f"Config Status: {'[green]✓ Decryption configured[/green]' if dr_count > 0 else '[yellow]⚠ No decryption rules found[/yellow]'}",
                    title="SSL/TLS Decryption Audit",
                )
            )
        except Exception as exc:
            console.print(f"[red]Error: {exc}[/red]")
    _pause()


# ── Static helper for leaf operations that don't have access to closures ───


def _save_json_static(data: Any, prefix: str, tenant_id: str, console) -> Path | None:
    try:
        backup_dir = Path("backups")
        backup_dir.mkdir(exist_ok=True)
        ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        out = backup_dir / f"{prefix}_{tenant_id}_{ts}.json"
        if data and hasattr(data[0], "model_dump"):
            payload = [d.model_dump() for d in data]
        else:
            payload = data
        out.write_text(json.dumps(payload, indent=2, default=str))
        return out
    except Exception as exc:
        console.print(f"[yellow]⚠ Could not save JSON: {exc}[/yellow]")
        return None
