"""
Prisma SASE AS-IS AS-BUILT report builder.

Generates a fully-structured Markdown AS-BUILT covering:
  Section 1  — Document Control
  Section 2  — Deployed Prisma SASE Architecture (As-Built)
  Section 3  — Prisma Access: Infrastructure & Connectivity
  Section 4  — Prisma SD-WAN (Edge Implemented Design)
  Section 5  — Security Service Edge (SSE) & Zero Trust Policies
  Section 6  — Identity, Context & Endpoint Posture
  Section 7  — Observability, Telemetry & Security Integrations
  Section 8  — Appendices & Reference Data

Sections that cannot be fully derived from the SCM API are clearly
marked ⚠️ with placeholder text and guidance on what to add manually.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from .models import AuditSnapshot
from .pan_references import (
    MERMAID_ENTERPRISE_RA,
    MERMAID_MSSP_HIERARCHY,
    MERMAID_PA_ROUTING,
    MERMAID_SDWAN_DUAL_HUB,
    REFERENCE_LIBRARY,
    format_ref_links,
    get_refs_for_section,
)

_NA = "_⚠️ Manual input required_"


class AsBuiltReportBuilder:
    """Build a Prisma SASE AS-BUILT from a full AuditSnapshot."""

    def __init__(
        self,
        snap: AuditSnapshot,
        customer_name: str = "",
        mssp_name: str = "MSSP",
        doc_version: str = "1.0",
        sdwan_only: bool = False,
        jobs: list[dict[str, Any]] | None = None,
    ) -> None:
        self.snap = snap
        self.customer = customer_name or snap.folder
        self.mssp = mssp_name
        self.version = doc_version
        self.sdwan_only = sdwan_only
        self.jobs = jobs or []
        self.generated_at = datetime.now(UTC).isoformat()
        _date_stamp = datetime.now(UTC).strftime("%Y%m%d")
        _uid = uuid.uuid4().hex[:8].upper()
        self.doc_id = f"ASBUILT-{_date_stamp}-{_uid}"
        self._lines: list[str] = []

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _h(self, level: int, text: str) -> None:
        self._lines.append(f"{'#' * level} {text}\n")

    def _p(self, text: str = "") -> None:
        self._lines.append(text)

    def _table(self, headers: list[str], rows: list[list[str]]) -> None:
        def _cell(c: Any) -> str:
            if c is None:
                return "—"
            s = str(c)
            return "—" if s in ("", "None", "[]", "{}") else s

        self._p("| " + " | ".join(headers) + " |")
        self._p("|" + "|".join("---" for _ in headers) + "|")
        for row in rows:
            self._p("| " + " | ".join(_cell(c) for c in row) + " |")
        self._p()

    def _note(self, text: str) -> None:
        self._p(f"> **Note:** {text}")
        self._p()

    def _warn(self, text: str) -> None:
        self._p(f"> ⚠️ **Manual input required:** {text}")
        self._p()

    def _refs(self, section_tag: str) -> None:
        """Emit a 'Reference Architecture Docs' callout for a given section."""
        refs = get_refs_for_section(section_tag)
        if refs:
            self._p(format_ref_links(refs))
            self._p()

    # ── Cover / Title block ───────────────────────────────────────────────────

    def _page_break(self) -> None:
        """Emit an HTML page-break div (renders in pandoc PDF / browser print)."""
        self._p('<div style="page-break-before: always;"></div>')
        self._p()

    # ── Table of Contents ─────────────────────────────────────────────────────

    def _toc(self) -> None:
        self._h(2, "Table of Contents")
        toc = [
            ("Executive Summary", "#executive-summary"),
            ("1. Document Control", "#1-document-control"),
            ("   1.1 Change History", "#11-change-history"),
            ("   1.2 SCM Management Structure", "#12-scm-management-structure"),
            ("   1.3 Managed Tenant Roster", "#13-managed-tenant-roster"),
            (
                "2. Deployed Prisma SASE Architecture",
                "#2-deployed-prisma-sase-architecture-as-built",
            ),
            ("   2.1 AS-BUILT Architecture Diagram", "#21-as-built-architecture-diagram"),
            ("   2.2 Management Plane Configuration", "#22-management-plane-configuration"),
            (
                "   2.3 Compute Locations & Regional Strategy",
                "#23-compute-locations--regional-strategy",
            ),
            ("   2.4 Data Sovereignty & Residency", "#24-data-sovereignty--residency"),
            (
                "3. Prisma Access: Infrastructure & Connectivity",
                "#3-prisma-access-infrastructure--connectivity",
            ),
            ("   3.1 Remote Networks", "#31-remote-networks-rn"),
            ("   3.2 Service Connections", "#32-service-connections-scn"),
            ("   3.3 Mobile Users (GlobalProtect)", "#33-mobile-users-mu"),
            ("   3.4 NGFW Managed Device Inventory", "#34-ngfw-managed-device-inventory"),
            (
                "4. Prisma SD-WAN (Edge Implemented Design)",
                "#4-prisma-sd-wan-edge-implemented-design",
            ),
            (
                "5. Security Service Edge (SSE) & Zero Trust Policies",
                "#5-security-service-edge-sse--zero-trust-policies",
            ),
            ("   5.1 Threat Prevention (FWaaS)", "#51-threat-prevention-fwaas"),
            ("   5.2 Secure Web Gateway (SWG)", "#52-secure-web-gateway-swg"),
            (
                "   5.3 SaaS Security (CASB) & DLP",
                "#53-saas-security-casb--data-loss-prevention-dlp",
            ),
            (
                "   5.4 Zero Trust Network Access & ZTNA Connector",
                "#54-zero-trust-network-access--secure-agentless-access-pra--ztna-connector",
            ),
            ("   5.5 Prisma Browser / RBI", "#55-prisma-browser--security-edge-broker-rbi"),
            ("   5.6 Prisma AIRS — AI Runtime Security", "#56-prisma-airs--ai-runtime-security"),
            ("   5.7 Traffic Steering Rules", "#57-traffic-steering-rules"),
            ("6. Identity, Context & Endpoint Posture", "#6-identity-context--endpoint-posture"),
            ("   6.1 Cloud Identity Engine", "#61-cloud-identity-engine-cie"),
            ("   6.2 Authentication Profiles", "#62-authentication-profiles"),
            (
                "   6.3 Host Information Profile (HIP) Checks",
                "#63-host-information-profile-hip-checks",
            ),
            ("   6.4 IoT / OT Security", "#64-iot-security--ot-security-device-id"),
            ("   6.5 IAM RBAC Roles", "#65-iam-rbac-roles"),
            ("   6.6 IAM Access Policies & Admins", "#66-iam-access-policies--admins"),
            (
                "7. Observability, Telemetry & Security Integrations",
                "#7-observability-telemetry--security-integrations",
            ),
            ("   7.1 ADEM", "#71-autonomous-digital-experience-management-adem"),
            (
                "   7.2 Cortex Data Lake / Strata Logging Service",
                "#72-cortex-data-lake-cdl--strata-logging-service",
            ),
            (
                "   7.3 Log Forwarding, SIEM & Syslog",
                "#73-log-forwarding-siem--syslog-integrations",
            ),
            ("   7.4 MT Monitor Alerts", "#74-mt-monitor--active-alerts"),
            ("8. Appendices & Reference Data", "#8-appendices--reference-data"),
            ("   8.1 Subnets, IP Pools & Egress IPs", "#81-subnets-ip-pools--public-egress-ips"),
            ("   8.2 Hardware & License Inventory", "#82-hardware--license-inventory"),
            ("   8.3 External Dynamic Lists", "#83-external-dynamic-lists-edl-inventory"),
            ("   8.4 VPN Crypto Profile Reference", "#84-vpn-crypto-profile-reference"),
            ("   8.5 Data Extraction Errors", "#85-data-extraction-errors"),
            (
                "   8.6 Appendix D — PAN Reference Architecture Library",
                "#86-appendix-d--pan-reference-architecture-library",
            ),
            (
                "   8.7 Appendix E — SCM Configuration Change History",
                "#87-appendix-e--scm-configuration-change-history",
            ),
            (
                "   8.8 Appendix F — PAN Reference Architecture Diagrams",
                "#88-appendix-f--pan-reference-architecture-diagrams",
            ),
        ]
        for label, anchor in toc:
            indent = "  " if label.startswith("   ") else ""
            clean = label.strip()
            self._p(f"{indent}- [{clean}]({anchor})")
        self._p()

    # ── Executive Summary ─────────────────────────────────────────────────────

    def _exec_summary(self) -> None:
        snap = self.snap

        # Derive key statistics from snapshot
        total_rules = len(snap.all_security_rules)
        nat_rules = len(snap.all_nat_rules)
        decrypt_rules = len(snap.decryption_rules)
        remote_networks = len(snap.remote_networks)
        service_connections = len(snap.service_connections)
        zones = len(snap.zones)
        addresses = len(snap.addresses)
        edls = len(snap.edls)
        ike_gateways = len(snap.ike_gateways)
        ipsec_tunnels = len(snap.ipsec_tunnels)
        ngfw_devices = len(snap.ngfw_devices)
        sdwan_sites = len(snap.sdwan_sites)
        mu_connected = snap.insights_connected_mu_count
        extraction_errors = len(snap.extraction_errors)
        licenses = len(snap.licenses)

        # Classify deployment type
        has_pa = bool(remote_networks or service_connections or snap.mobile_agent_infrastructure)
        has_sdwan = bool(sdwan_sites or snap.sdwan_elements)
        has_ngfw = bool(ngfw_devices)
        deployment_type_parts = []
        if has_pa:
            deployment_type_parts.append("Prisma Access (SASE)")
        if has_sdwan:
            deployment_type_parts.append("Prisma SD-WAN")
        if has_ngfw:
            deployment_type_parts.append(f"NGFW ({ngfw_devices} device(s))")
        deployment_type = (
            " + ".join(deployment_type_parts) if deployment_type_parts else "Prisma Access"
        )

        # Connectivity health
        rn_detail = f"{remote_networks} branch(es)" if remote_networks else "None"
        sc_detail = f"{service_connections} DC connection(s)" if service_connections else "None"
        mu_detail = (
            f"{mu_connected} users connected (live)"
            if mu_connected >= 0
            else (
                "GlobalProtect configured" if snap.mobile_agent_infrastructure else "Not configured"
            )
        )

        self._h(2, "Executive Summary")
        self._p(
            f"This document is the **As-Built technical record** of the Palo Alto Networks "
            f"Prisma SASE deployment managed by **{self.mssp}** for **{self.customer}**. "
            f"It was auto-generated directly from the live Strata Cloud Manager (SCM) "
            f"configuration on **{self.generated_at[:10]}** and reflects the current "
            f"deployed state at the time of generation."
        )
        self._p()
        self._p(
            "**Purpose:** This AS-BUILT serves as the definitive point-in-time reference for "
            "the security architecture — covering network connectivity, security policy, "
            "identity controls, data sovereignty, observability, and management structure. "
            "It is intended for use by security architects, network engineers, compliance "
            "auditors, and service management teams responsible for the day-to-day operation "
            "and governance of this deployment."
        )
        self._p()
        self._p(
            "**Living Document:** This report should be regenerated after any significant "
            "configuration change or at least quarterly. The Document ID and generation "
            f"timestamp (`{self.doc_id}`) uniquely identify this snapshot for audit trail purposes. "
            "Sections marked ⚠️ contain placeholder text where data could not be automatically "
            "derived and require manual completion before the document is finalised."
        )
        self._p()

        # Key stats table
        self._h(3, "Deployment at a Glance")
        self._table(
            ["Category", "Metric", "Value"],
            [
                ["Deployment", "Type", deployment_type],
                ["Deployment", "SCM Folder", snap.folder],
                ["Deployment", "SCM Tenant ID", snap.tenant_id],
                ["Deployment", "Report Generated", self.generated_at[:10]],
                ["Connectivity", "Remote Networks (Branches)", rn_detail],
                ["Connectivity", "Service Connections (Data Centres)", sc_detail],
                ["Connectivity", "Mobile Users (GlobalProtect)", mu_detail],
                [
                    "Connectivity",
                    "SD-WAN Sites",
                    str(sdwan_sites) if sdwan_sites else "Not deployed",
                ],
                [
                    "Connectivity",
                    "NGFW Managed Devices",
                    str(ngfw_devices) if ngfw_devices else "Not enrolled",
                ],
                ["Policy", "Security Rules", str(total_rules)],
                ["Policy", "NAT Rules", str(nat_rules)],
                ["Policy", "Decryption Rules", str(decrypt_rules)],
                ["Policy", "Network Zones", str(zones)],
                ["Objects", "Address Objects", str(addresses)],
                ["Objects", "External Dynamic Lists", str(edls)],
                ["Objects", "IKE Gateways / IPSec Tunnels", f"{ike_gateways} / {ipsec_tunnels}"],
                ["Licences", "Active Licence Records", str(licenses) if licenses else "See §8.2"],
                [
                    "Quality",
                    "Extraction Errors (non-fatal)",
                    str(extraction_errors) if extraction_errors else "None",
                ],
            ],
        )
        self._p()

        # Scope and limitations
        self._h(3, "Scope & Limitations")
        self._p(
            "This document covers configuration objects visible within the SCM folder "
            f"`{snap.folder}` and the associated tenant `{snap.tenant_id}`. "
            "The following items are **out of scope** for automated generation and must be "
            "completed manually:"
        )
        self._p()
        self._p(
            "- **Classification and handling:** Document sensitivity classification (OFFICIAL, "
            "RESTRICTED, etc.) must be set by the document owner in §1.\n"
            "- **SCM and CDL tenant regions:** Not exposed via API; verify via "
            "[hub.paloaltonetworks.com](https://hub.paloaltonetworks.com) (see §2.4).\n"
            "- **Business context:** Service descriptions, SLA commitments, escalation contacts, "
            "and change management procedures are not configurable in SCM.\n"
            "- **Physical / on-premises infrastructure:** CPE device makes/models, rack locations, "
            "and WAN circuit details must be sourced from CMDB or site surveys.\n"
            "- **Network diagrams:** The Mermaid topology in §2.1 is auto-generated from "
            "SCM config; for presentation-quality diagrams, export and refine manually."
        )
        self._p()

        update_note = (
            f"**How to update this document:** Run `scm_asbuilt_report(folder='{snap.folder}', "  # nosec B608: markdown text, not SQL
            f"tenant_id='{snap.tenant_id}')` in the MCP interface to regenerate from live config. "
            "To save to file, add `save_to='filename.md'`. "
            "Alternatively, use the CLI: select **A — Generate AS-BUILT Report** from the main menu."
        )
        self._note(update_note)

    # ── Section 1: Document Control ───────────────────────────────────────────

    def _section_1(self) -> None:
        self._h(1, f"Prisma SASE AS-IS AS-BUILT — {self.customer}")
        self._p(f"**Document Version:** {self.version}  ")
        self._p(f"**Document ID:** `{self.doc_id}`  ")
        self._p(f"**Generated:** {self.generated_at}  ")
        self._p(f"**Scope:** Folder `{self.snap.folder}` | Tenant `{self.snap.tenant_id}`  ")
        self._p(f"**Prepared by:** {self.mssp}  ")
        self._p()

        self._h(2, "1. Document Control")
        self._table(
            ["Field", "Value"],
            [
                ["Customer", self.customer],
                ["MSSP", self.mssp],
                ["SCM Tenant ID", self.snap.tenant_id],
                ["SCM Folder", self.snap.folder],
                ["Document ID", f"`{self.doc_id}`"],
                ["Report Version", self.version],
                ["Generated At (UTC)", self.generated_at],
                ["Classification", _NA],
            ],
        )

        self._h(3, "1.1 Change History")
        self._table(
            ["Version", "Date", "Author", "Change"],
            [
                [
                    "1.0",
                    self.generated_at[:10],
                    self.mssp,
                    "Initial AS-BUILT (auto-generated from live SCM config)",
                ]
            ],
        )
        self._p()

        # 1.2 SCM Management Structure
        snap = self.snap
        if snap.scm_folders or snap.scm_snippets:
            self._h(3, "1.2 SCM Management Structure")
            self._p(
                "The Strata Cloud Manager (SCM) organises configuration through a "
                "**folder hierarchy** and **snippets** (reusable configuration templates). "
                "Folders define the management scope — config applied to a parent folder "
                "is inherited by all children. Snippets are attached to folders and inject "
                "PAN-recommended or custom configuration at that scope level."
            )

        if snap.scm_folders:
            self._h(4, "Folder Hierarchy")
            # Build parent → children map to sort by depth
            children: dict[str, list[dict[str, Any]]] = {}
            for f in snap.scm_folders:
                p = f.get("parent") or ""
                children.setdefault(p, []).append(f)

            def _folder_rows(parent: str, depth: int) -> list[list[str]]:
                rows: list[list[str]] = []
                for f in sorted(children.get(parent, []), key=lambda x: x.get("name", "")):
                    indent = "    " * depth  # non-breaking spaces
                    display = f.get("display_name") or f.get("name", "—")
                    name = f.get("name", "—")
                    folder_type = f.get("type", "—")
                    snippets_applied = ", ".join(f.get("snippets") or []) or "—"
                    labels_applied = ", ".join(str(lb) for lb in (f.get("labels") or [])) or "—"
                    rows.append(
                        [
                            f"{indent}{display}",
                            name,
                            folder_type,
                            snippets_applied,
                            labels_applied,
                        ]
                    )
                    rows.extend(_folder_rows(name, depth + 1))
                return rows

            rows = _folder_rows("", 0)
            self._table(
                ["Display Name", "Internal Name", "Type", "Snippets Applied", "Labels"],
                rows,
            )
            self._note(
                "**Folder types:** `container` = management scope grouping · "
                "`cloud` = Prisma Access managed service (PA/MU/RN/SC) · "
                "`on-prem` = physical/virtual NGFW device registered to SCM."
            )

        if snap.scm_snippets:
            self._h(4, "Snippet Inventory")
            self._p(
                "Snippets are reusable configuration containers attached to folders. "
                "PANW supplies **predefined** best-practice templates and **readonly** "
                "system snippets. Tenant-defined **custom** snippets are the primary "
                "vehicle for MSSP-managed shared policy delivery."
            )

            # Split into predefined/readonly vs custom
            predefined_snips = [
                s for s in snap.scm_snippets if s.get("type") in ("predefined", "readonly")
            ]
            custom_snips = [
                s
                for s in snap.scm_snippets
                if s.get("type") not in ("predefined", "readonly")
                and s.get("name") not in ("predefined-snippet",)
            ]

            if predefined_snips:
                self._h(5, "Active PANW Predefined & System Snippets")
                rows = []
                for s in sorted(
                    predefined_snips,
                    key=lambda x: (x.get("type", ""), x.get("display_name") or x.get("name", "")),
                ):
                    folders_list = s.get("folders") or []
                    folder_names = (
                        ", ".join(f.get("name", "?") for f in folders_list) if folders_list else "—"
                    )
                    rows.append(
                        [
                            s.get("display_name") or s.get("name", "—"),
                            s.get("type", "custom"),
                            folder_names,
                            (s.get("description") or "")[:70],
                        ]
                    )
                self._table(
                    ["Display Name / Snippet", "Type", "Attached Folder(s)", "Description"], rows
                )
                self._note(
                    "`predefined` = PAN best-practice template (e.g. O365, Gen-AI, Internet Access) · "
                    "`readonly` = auto-provisioned system snippet (Auto-VPN, HIP defaults)."
                )

            if custom_snips:
                self._h(5, "Custom (Tenant-Defined) Snippets")
                rows = []
                for s in sorted(custom_snips, key=lambda x: x.get("name", "")):
                    folders_list = s.get("folders") or []
                    folder_names = (
                        ", ".join(f.get("name", "?") for f in folders_list) if folders_list else "—"
                    )
                    prefix_info = s.get("prefix") or (
                        "enabled" if s.get("enable_prefix") else "disabled"
                    )
                    obj_counts = s.get("object_counts") or {}
                    obj_summary = (
                        " · ".join(
                            f"{v} {k.replace('_', ' ')}" for k, v in obj_counts.items() if v > 0
                        )
                        or "—"
                    )
                    rows.append(
                        [
                            s.get("name", "—"),
                            folder_names,
                            prefix_info,
                            obj_summary,
                            (s.get("description") or "")[:60],
                        ]
                    )
                self._table(
                    ["Snippet Name", "Attached Folder(s)", "Name Prefix", "Objects", "Description"],
                    rows,
                )
                self._note(
                    "**Name Prefix** — when enabled, all objects in the snippet are prefixed (e.g. `btgld-`) "
                    "to prevent naming conflicts when the snippet is shared across multiple customer folders. "
                    "**Objects** shows counts of config objects stored inside the snippet scope."
                )
            else:
                self._note(
                    "No custom snippets defined. Custom snippets enable MSSP-managed shared policy "
                    "delivery — a single snippet can be attached to multiple customer folders so "
                    "updates propagate automatically on the next config push."
                )

        if snap.scm_labels:
            self._h(4, "Labels")
            rows = [[lb.get("name", "—"), lb.get("description") or "—"] for lb in snap.scm_labels]
            self._table(["Label Name", "Description"], rows)

        # 1.3 Managed Tenant Roster (SP/super-user only)
        self._h(3, "1.3 Managed Tenant Roster")
        self._p(
            "_Sub-tenants visible to the SP/super-user credential used for this report. "
            "Each row is a managed customer TSG — the TSG ID is the authoritative "
            "identifier for API calls, IAM policies, and Insights queries. "
            "Ref: [Prisma SASE Tenancy API](https://pan.dev/sase/api/tenancy/)_"
        )
        if snap.managed_tenants:
            rows = []
            for t in sorted(snap.managed_tenants, key=lambda x: x.get("display_name", "")):
                tsg = t.get("id") or t.get("tsg_id") or t.get("tenant_id") or "—"
                name = t.get("display_name") or t.get("name") or "—"
                status = t.get("status") or t.get("state") or "—"
                ttype = t.get("tenant_type") or t.get("type") or "—"
                rows.append([f"`{tsg}`", name, status, ttype])
            self._table(["TSG ID", "Display Name", "Status", "Type"], rows)
            self._p(f"_Total managed tenants: {len(snap.managed_tenants)}_")
        else:
            self._p(
                "_Not available — credential does not have SP/super-user Tenancy API access "
                "(HTTP 403). To populate this section, use a Service Provider credential "
                "that has permission to list managed tenants._"
            )

    # ── Section 2: Deployed Prisma SASE Architecture ──────────────────────────

    def _active_locations(self) -> list[dict[str, Any]]:
        """Catalog locations actually referenced by RNs, SCs, or bandwidth
        allocations — the SCM locations API returns the full global catalog,
        not what this tenant deployed."""
        snap = self.snap
        used: set[str] = set()
        for rn in snap.remote_networks:
            if rn.get("region"):
                used.add(rn["region"])
            if rn.get("spn_name"):
                used.add(rn["spn_name"])
        for sc in snap.service_connections:
            if sc.get("region"):
                used.add(sc["region"])
        for ba in snap.bandwidth_allocations:
            if ba.get("name"):
                used.add(ba["name"])
            for spn in ba.get("spn_name_list") or []:
                used.add(spn)
        return [
            loc
            for loc in snap.network_locations
            if (loc.get("value") in used or loc.get("display") in used or loc.get("region") in used)
        ]

    def _build_architecture_diagram(self) -> str:
        snap = self.snap
        lines = ["```mermaid", "graph TB"]

        # Prisma Access cloud fabric
        lines.append('    subgraph PA["☁️ Prisma Access — PAN SASE Fabric"]')
        lines.append(f'        SCM["🖥️ Strata Cloud Manager\\nTenant: {snap.tenant_id}"]')

        # Compute locations in use by this deployment (full catalog if none matched)
        _diagram_locs = self._active_locations() or snap.network_locations
        for loc in _diagram_locs[:8]:
            loc_id = loc.get("value", "").replace("-", "_").replace(".", "_")
            loc_name = loc.get("display", loc.get("value", "unknown"))
            region = loc.get("region", "")
            label = f"{loc_name}\\n({region})" if region and region != loc_name else loc_name
            lines.append(f'        LOC_{loc_id}["📍 {label}"]')

        lines.append("    end")
        lines.append("")

        # Remote Networks (branches)
        if snap.remote_networks:
            lines.append('    subgraph RN_GROUP["🏢 Remote Networks (Branch Sites)"]')
            for rn in snap.remote_networks:
                name = rn.get("name", "unknown")
                safe_id = name.replace("-", "_").replace(" ", "_").replace(".", "_")
                region = rn.get("region", "")
                spn = rn.get("spn_name", "")
                subnets = ", ".join((rn.get("subnets") or [])[:2])
                label_parts = [name]
                if region:
                    label_parts.append(f"Region: {region}")
                if spn:
                    label_parts.append(f"SPN: {spn}")
                if subnets:
                    label_parts.append(f"Subnets: {subnets}")
                label = "\\n".join(label_parts)
                lines.append(f'        RN_{safe_id}["🏢 {label}"]')
            lines.append("    end")
            lines.append("")

            # Connect RNs to PA
            for rn in snap.remote_networks:
                name = rn.get("name", "unknown")
                safe_id = name.replace("-", "_").replace(" ", "_").replace(".", "_")
                lines.append(f'    RN_{safe_id} -->|"IPSec · BGP"| PA')

        # Service Connections (DCs)
        if snap.service_connections:
            lines.append("")
            lines.append('    subgraph SCN_GROUP["🏭 Service Connections (Data Centres)"]')
            for sc in snap.service_connections:
                name = sc.get("name", "unknown")
                safe_id = name.replace("-", "_").replace(" ", "_").replace(".", "_")
                region = sc.get("region", "")
                subnets = ", ".join((sc.get("subnets") or [])[:2])
                label_parts = [name]
                if region:
                    label_parts.append(f"Region: {region}")
                if subnets:
                    label_parts.append(f"Subnets: {subnets}")
                label = "\\n".join(label_parts)
                lines.append(f'        SCN_{safe_id}["🏭 {label}"]')
            lines.append("    end")
            lines.append("")

            for sc in snap.service_connections:
                name = sc.get("name", "unknown")
                safe_id = name.replace("-", "_").replace(" ", "_").replace(".", "_")
                lines.append(f'    SCN_{safe_id} <-->|"IPSec · BGP"| PA')

        # Mobile Users
        if snap.mobile_agent_infrastructure:
            lines.append("")
            lines.append('    subgraph MU_GROUP["👥 Mobile Users (GlobalProtect)"]')
            for infra in snap.mobile_agent_infrastructure:
                name = infra.get("name", "GlobalProtect")
                safe_id = name.replace("-", "_").replace(" ", "_")
                portal = infra.get("portal_hostname", "")
                pools = infra.get("ip_pools", [])
                pool_str = ", ".join(str(p) for p in pools[:2]) if pools else ""
                label_parts = [name]
                if portal:
                    label_parts.append(f"Portal: {portal}")
                if pool_str:
                    label_parts.append(f"IP Pool: {pool_str}")
                label = "\\n".join(label_parts)
                lines.append(f'        MU_{safe_id}["👥 {label}"]')
            lines.append("    end")
            lines.append("")

            for infra in snap.mobile_agent_infrastructure:
                name = infra.get("name", "GlobalProtect")
                safe_id = name.replace("-", "_").replace(" ", "_")
                lines.append(f'    MU_{safe_id} -->|"SSL-VPN · TLS"| PA')

        # SCM manages PA
        lines.append("")
        lines.append("    SCM -.->|manages| PA")
        lines.append("```")
        return "\n".join(lines)

    def _section_2(self) -> None:
        snap = self.snap
        self._h(2, "2. Deployed Prisma SASE Architecture (As-Built)")

        # 2.1 Architecture Diagram
        self._h(3, "2.1 AS-BUILT Architecture Diagram")
        self._p(
            "_Auto-generated from live SCM configuration. Refresh by re-running `scm_asbuilt_report`._"
        )
        self._p()
        self._p(self._build_architecture_diagram())
        self._note(
            "See **Appendix F** for the PAN reference architecture diagrams "
            "(Enterprise SASE topology, Prisma Access routing, SD-WAN dual-hub, MSSP hierarchy)."
        )

        # 2.2 Management Plane
        self._h(3, "2.2 Management Plane Configuration")
        self._table(
            ["Parameter", "Value"],
            [
                ["Management Platform", "Strata Cloud Manager (SCM)"],
                ["Tenant ID (TSG)", snap.tenant_id],
                ["SCM Folder", snap.folder],
                ["Folders configured", str(len([snap.folder]))],
                ["RBAC configuration", _NA],
                ["SCM Region", _NA],
            ],
        )

        # 2.3 Compute Locations
        self._h(3, "2.3 Compute Locations & Regional Strategy")
        # Locations actually in use by RNs, SCs, or BAs (shared with §2.1 diagram)
        _active_locs = self._active_locations()

        if _active_locs:
            rows = []
            for loc in _active_locs:
                # Count how many RNs/SCs use this location
                _val = loc.get("value", "")
                _rn_count = sum(
                    1
                    for rn in snap.remote_networks
                    if rn.get("region") == _val or rn.get("spn_name") == _val
                )
                _sc_count = sum(1 for sc in snap.service_connections if sc.get("region") == _val)
                rows.append(
                    [
                        loc.get("display", loc.get("value", "")),
                        loc.get("value", ""),
                        loc.get("aggregate_region", ""),
                        loc.get("continent", ""),
                        str(_rn_count) if _rn_count else "—",
                        str(_sc_count) if _sc_count else "—",
                    ]
                )
            self._table(
                ["Location Name", "API Value", "Aggregate Region", "Continent", "RNs", "SCs"],
                rows,
            )
        elif snap.network_locations:
            # API returned locations but none matched — fall back to showing all
            rows = []
            for loc in snap.network_locations:
                rows.append(
                    [
                        loc.get("display", loc.get("value", "")),
                        loc.get("value", ""),
                        loc.get("aggregate_region", ""),
                        loc.get("continent", ""),
                    ]
                )
            self._table(
                ["Location Name", "API Value", "Aggregate Region", "Continent"],
                rows,
            )
        else:
            self._warn(
                "Network locations could not be retrieved. Populate from SCM → Infrastructure → Locations."
            )

        if snap.bandwidth_allocations:
            self._h(4, "Bandwidth Allocations")
            rows = []
            for ba in snap.bandwidth_allocations:
                spns = ", ".join(ba.get("spn_name_list") or [])
                qos = ba.get("qos")
                if isinstance(qos, dict):
                    qos = ", ".join(f"{k}: {v}" for k, v in qos.items() if v is not None)
                rows.append([ba.get("name", ""), str(ba.get("allocated_bandwidth", "")), spns, qos])
            self._table(["Location", "Allocated BW (Mbps)", "SPN Nodes", "QoS"], rows)
        self._p()

    # ── Section 2.5: Data Sovereignty & Residency ─────────────────────────────

    def _section_2b(self) -> None:
        """§2.4 Data Sovereignty & Residency — auto-derived where possible."""
        snap = self.snap

        self._h(3, "2.4 Data Sovereignty & Residency")
        self._p(
            "This section documents where each Palo Alto Networks cloud service processes "
            "and retains data. Organisations with UK or EU data-residency requirements should "
            "verify all components are mapped to compliant regions before going live."
        )
        self._p()

        # ── WildFire ──────────────────────────────────────────────────────────
        self._h(4, "2.4.1 Advanced WildFire Cloud Submission Endpoint")

        # Classify known WildFire regional clouds: host → (location, region, uk_eu_compliant)
        _WF_REGIONS: dict[str, tuple[str, str, bool]] = {
            "wildfire.paloaltonetworks.com": ("United States", "US", False),
            "eu.wildfire.paloaltonetworks.com": ("Netherlands", "EU", True),
            "uk.wildfire.paloaltonetworks.com": ("United Kingdom", "UK", True),
            "de.wildfire.paloaltonetworks.com": ("Germany", "EU", True),
            "fr.wildfire.paloaltonetworks.com": ("France", "EU", True),
            "jp.wildfire.paloaltonetworks.com": ("Japan", "APAC", False),
            "sg.wildfire.paloaltonetworks.com": ("Singapore", "APAC", False),
            "au.wildfire.paloaltonetworks.com": ("Australia", "APAC", False),
            "ca.wildfire.paloaltonetworks.com": ("Canada", "Americas", False),
            "in.wildfire.paloaltonetworks.com": ("India", "APAC", False),
            "ch.wildfire.paloaltonetworks.com": ("Switzerland", "EU", True),
            "pl.wildfire.paloaltonetworks.com": ("Poland", "EU", True),
            "it.wildfire.paloaltonetworks.com": ("Italy", "EU", True),
            "es.wildfire.paloaltonetworks.com": ("Spain", "EU", True),
            "kr.wildfire.paloaltonetworks.com": ("South Korea", "APAC", False),
            "za.wildfire.paloaltonetworks.com": ("South Africa", "Africa", False),
            "br.wildfire.paloaltonetworks.com": ("Brazil", "Americas", False),
            "sa.wildfire.paloaltonetworks.com": ("Saudi Arabia", "Middle East", False),
            "il.wildfire.paloaltonetworks.com": ("Israel", "Middle East", False),
            "qa.wildfire.paloaltonetworks.com": ("Qatar", "Middle East", False),
            "id.wildfire.paloaltonetworks.com": ("Indonesia", "APAC", False),
            "tw.wildfire.paloaltonetworks.com": ("Taiwan", "APAC", False),
        }

        # Tenant-level WildFire cloud setting note (API endpoint requires elevated RBAC —
        # accessible only via SCM UI: Prisma Access → Infrastructure → Settings → WildFire)
        self._p(
            "> **Tenant-level WildFire Cloud Region** is configured under "
            "**Prisma Access → Infrastructure → Settings → WildFire** in the SCM UI. "
            "This setting determines which regional cloud receives `public-cloud` "
            "submissions from all WildFire AV profiles. "
            "The API endpoint (`/config/deployment/v1/wildfire`) requires Infrastructure "
            "Admin role — verify the setting manually and record it below."
        )
        self._p()

        # Per-profile analysis mode — SCM stores per-rule analysis as a string:
        #   "public-cloud"   → use tenant-level WildFire cloud (Infrastructure → Settings)
        #   "private-cloud"  → submit to on-prem WildFire appliance
        #   "<hostname-url>" → submit directly to that regional cloud (overrides tenant setting)
        # Build map: profile_name → set of unique analysis values across all rules
        _wf_profile_modes: dict[str, set[str]] = {}
        _wf_cloud_map: dict[str, str] = {}  # profile_name → explicit URL (if any)
        for wf in snap.wildfire_profiles:
            pname = wf.get("name", "")
            modes: set[str] = set()
            for rule in wf.get("rules") or []:
                analysis = rule.get("analysis") or ""
                if analysis:
                    modes.add(str(analysis))
                    # If it looks like a hostname URL, record it
                    if "wildfire.paloaltonetworks.com" in str(analysis):
                        host = str(analysis).removeprefix("https://").split("/")[0]
                        _wf_cloud_map[pname] = host
            # Also check legacy top-level cloud field (older SDK models)
            legacy = wf.get("analysis") or {}
            if isinstance(legacy, dict):
                lcloud = legacy.get("cloud") or ""
                if lcloud:
                    modes.add(lcloud)
                    if "wildfire.paloaltonetworks.com" in lcloud:
                        _wf_cloud_map[pname] = lcloud.removeprefix("https://").split("/")[0]
            if modes:
                _wf_profile_modes[pname] = modes

        if _wf_profile_modes:
            rows = []
            for pname in sorted(_wf_profile_modes):
                modes = _wf_profile_modes[pname]
                folder = next(
                    (
                        wf.get("folder") or wf.get("snippet") or "—"
                        for wf in snap.wildfire_profiles
                        if wf.get("name") == pname
                    ),
                    "—",
                )
                for mode in sorted(modes):
                    if "wildfire.paloaltonetworks.com" in mode:
                        host = mode.removeprefix("https://").split("/")[0]
                        loc, region, uk_eu = _WF_REGIONS.get(host, ("Unknown", "Unknown", False))
                        compliant = (
                            "✅ UK"
                            if "uk.wildfire" in host
                            else ("✅ EU" if uk_eu else "⚠️ Non-UK/EU")
                        )
                        rows.append([pname, folder, mode, loc, region, compliant])
                    elif mode == "private-cloud":
                        rows.append(
                            [
                                pname,
                                folder,
                                "private-cloud (on-prem WF)",
                                "On-premises",
                                "—",
                                "Depends on appliance location",
                            ]
                        )
                    else:
                        rows.append(
                            [
                                pname,
                                folder,
                                f"{mode} → see tenant setting above",
                                "See Infrastructure Settings",
                                "—",
                                "⚠️ Verify tenant setting",
                            ]
                        )
            self._table(
                [
                    "WildFire Profile",
                    "Folder/Snippet",
                    "Analysis Mode",
                    "Hosted In",
                    "Region",
                    "UK/EU Compliant",
                ],
                rows,
            )
        else:
            self._p(
                "_No WildFire AV profiles found — Advanced WildFire may not be licensed "
                "or profiles are configured via snippets not visible in this folder scope._"
            )
            self._p()

        self._note(
            "PAN WildFire regional clouds are fully independent. Samples submitted to "
            "`uk.wildfire.paloaltonetworks.com` remain within the United Kingdom. "
            "Profiles set to `public-cloud` delegate the actual region to the tenant-level "
            "Infrastructure setting. See: [Advanced WildFire Public Cloud]"
            "(https://docs.paloaltonetworks.com/advanced-wildfire/administration/"
            "advanced-wildfire-overview/advanced-wildfire-deployments/advanced-wildfire-global-cloud)."
        )

        # ── DNS Security ──────────────────────────────────────────────────────
        self._h(4, "2.4.2 Advanced DNS Security Cloud Lookups")
        self._p(
            "> **Cloud Region:** Advanced DNS Security lookup queries are sent to PAN cloud "
            "infrastructure. There is no per-profile regional endpoint — the data-residency "
            "region follows your **CDL/SLS region** (see §2.4.4). "
            "Verify DNS telemetry residency in the same location as your CDL instance."
        )
        self._p()
        if snap.dns_security_profiles:
            # One row per profile × category — action and log_level live on each category entry
            rows = []
            for dp in snap.dns_security_profiles:
                pname = dp.get("name", "")
                folder = dp.get("folder") or dp.get("snippet") or "—"
                botnet = dp.get("botnet_domains") or {}
                cats = botnet.get("dns_security_categories") or []
                if cats:
                    for c in cats:
                        if not isinstance(c, dict):
                            continue
                        cat_name = c.get("name", "—").replace("pan-dns-sec-", "")
                        action = c.get("action") or "default"
                        log_level = c.get("log_level") or "default"
                        pcap = c.get("packet_capture") or "—"
                        rows.append([pname, folder, cat_name, action, log_level, pcap])
                else:
                    rows.append([pname, folder, "—", "—", "—", "—"])
            self._table(
                [
                    "Profile",
                    "Folder/Snippet",
                    "DNS Category",
                    "Action",
                    "Log Level",
                    "Packet Capture",
                ],
                rows,
            )
        else:
            self._p("_No DNS Security profiles configured._")
            self._p()
        self._note(
            "DNS Security category names are shortened (prefix `pan-dns-sec-` removed). "
            "Common categories: `cc` (C2), `malware`, `phishing`, `recent` (newly registered), "
            "`grayware`, `parked`, `proxy`, `ddns`, `adtracking`. "
            "Data residency follows CDL/SLS region — no separate regional endpoint configurable."
        )

        # ── SCM Tenant Region ─────────────────────────────────────────────────
        self._h(4, "2.4.3 Strata Cloud Manager (SCM) Tenant Region")
        self._table(
            ["Parameter", "Value"],
            [
                ["SCM Tenant ID (TSG)", snap.tenant_id],
                ["SCM Tenant Region", _NA],
                ["Management Plane Location", _NA],
            ],
        )
        self._note(
            "The SCM tenant region is not exposed via the Configuration API. "
            "To verify your region: log in to [hub.paloaltonetworks.com](https://hub.paloaltonetworks.com), "
            "navigate to **Strata Cloud Manager → Settings → Tenant Info**, and confirm the "
            "region shown matches your sovereignty requirements. "
            "Alternatively, inspect the `x-panw-region` HTTP response header on any "
            "SCM API call. "
            "Supported regions include `us`, `eu`, `uk`, `sg`, `au`, `jp`."
        )

        # ── CDL / SLS Region ──────────────────────────────────────────────────
        self._h(4, "2.4.4 Cortex Data Lake (CDL) / Strata Logging Service Region")
        self._table(
            ["Parameter", "Value"],
            [
                ["CDL Instance Region", _NA],
                ["Log Retention Location", _NA],
                [
                    "SLS Log Forwarding Profiles",
                    str(
                        len(snap.cdl_syslog_profiles)
                        + len(snap.cdl_https_profiles)
                        + len(snap.cdl_email_profiles)
                    ),
                ],
            ],
        )
        self._note(
            "The CDL/SLS region is only visible via the Customer Support Portal or Hub. "
            "Navigate to [hub.paloaltonetworks.com](https://hub.paloaltonetworks.com) → "
            "**Strata Logging Service → Settings** to confirm data residency. "
            "For UK/EU sovereignty, the CDL instance must be provisioned in the EU or UK region. "
            "See: [Strata Logging Service Admin Guide]"
            "(https://docs.paloaltonetworks.com/strata-logging-service)."
        )

        # ── ATP ───────────────────────────────────────────────────────────────
        self._h(4, "2.4.5 Advanced Threat Prevention (ATP) Cloud")
        self._p(
            "> **Cloud Region:** Advanced Threat Prevention has no per-profile regional endpoint. "
            "Inline cloud analysis payload data is sent to PAN's global ATP cloud, with "
            "data residency governed by your **SCM tenant region** (see §2.4.3). "
            "The tenant-level ATP cloud configuration (`/config/deployment/v1/advanced-threat-prevention`) "
            "requires Infrastructure Admin role — verify with your PAN account team."
        )
        self._p()
        if snap.anti_spyware_profiles:
            rows = []
            for atp in snap.anti_spyware_profiles:
                pname = atp.get("name", "")
                folder = atp.get("folder") or atp.get("snippet") or "—"
                cloud_inline = atp.get("cloud_inline_analysis") or False
                mica = atp.get("mica_engine_spyware_enabled") or []
                mica_names = (
                    "; ".join(
                        m.get("name", "")
                        .replace(" detector", "")
                        .replace(" Command and Control", " C2")
                        for m in mica
                        if isinstance(m, dict)
                    )
                    or "—"
                )
                mica_actions = (
                    "; ".join(
                        sorted(
                            {m.get("inline_policy_action", "") for m in mica if isinstance(m, dict)}
                            - {""}
                        )
                    )
                    or "—"
                )
                rows.append(
                    [
                        pname,
                        folder,
                        "✓ Enabled" if cloud_inline else "—",
                        str(len(mica)) if mica else "—",
                        mica_names[:80] + ("…" if len(mica_names) > 80 else ""),
                        mica_actions,
                    ]
                )
            self._table(
                [
                    "Profile",
                    "Folder/Snippet",
                    "Inline Cloud Analysis",
                    "MICA Detectors",
                    "MICA Detector Names",
                    "MICA Action(s)",
                ],
                rows,
            )
        else:
            self._p("_No Anti-Spyware / ATP profiles configured._")
            self._p()
        self._note(
            "**Inline Cloud Analysis** (ATP): sends unknown payloads to cloud for real-time verdict. "
            "**MICA** (ML Inline Cloud Analytics): per-protocol ML detectors for C2, encrypted threats. "
            "Both require the Advanced Threat Prevention licence. "
            "Data residency follows SCM tenant region — no independent regional selection."
        )

        # ── Enterprise DLP ───────────────────────────────────────────────────
        self._h(4, "2.4.6 Enterprise DLP Cloud Region")
        self._p(
            "> **Cloud Region:** Enterprise DLP has two layers with distinct data-residency:\n"
            "> - **SCM Inline DLP** (`data-filtering-profiles`): file/pattern inspection is performed "
            "by the Prisma Access data plane inline — data residency follows your **PA deployment region** / **CDL region** (see §2.4.4).\n"
            "> - **Enterprise DLP** (`api.dlp.paloaltonetworks.com`): ML-based SaaS/Cloud SWG DLP — "
            "data is processed in the Enterprise DLP cloud instance provisioned for your tenant. "
            "The region is set at instance creation and is not configurable post-provisioning. "
            "The API endpoint (`/config/deployment/v1/enterprise-dlp`) requires Infrastructure Admin role — "
            "verify the instance region in **Hub → Enterprise DLP → Settings**."
        )
        self._p()
        # Show what we could extract: inline DLP profiles and Enterprise DLP licensing status
        _has_inline_dlp = bool(snap.data_filtering_profiles or snap.data_objects)
        _has_enterprise_dlp = bool(
            snap.dlp_company_id or snap.dlp_data_patterns or snap.dlp_data_profiles
        )
        self._table(
            ["DLP Layer", "Status", "Cloud Region Source", "Verify At"],
            [
                [
                    "SCM Inline DLP (data-filtering-profiles)",
                    f"{'✓ ' + str(len(snap.data_filtering_profiles)) + ' profile(s)' if snap.data_filtering_profiles else '— Not configured / not accessible'}",
                    "Prisma Access data plane (follows CDL region)",
                    "§2.4.4 CDL/SLS Region",
                ],
                [
                    "Enterprise DLP (ML-based SaaS/Cloud SWG)",
                    f"{'✓ Company ID: ' + snap.dlp_company_id if snap.dlp_company_id else '— Not licensed or not accessible'}",
                    "Enterprise DLP instance region (set at provisioning)",
                    "Hub → Enterprise DLP → Settings",
                ],
            ],
        )
        if _has_inline_dlp:
            self._p(
                f"SCM Inline DLP has {len(snap.data_filtering_profiles)} filtering profile(s) "
                f"and {len(snap.data_objects)} data object(s) — see §5.3 for full DLP configuration detail."
            )
        self._note(
            "Enterprise DLP inspection content (payload fragments) may be retained in the DLP cloud for "
            "incident review. Confirm the DLP instance region matches your data-sovereignty requirements. "
            "Supported Enterprise DLP regions: US, EU, UK, APAC. "
            "See: [Enterprise DLP Admin Guide](https://docs.paloaltonetworks.com/enterprise-dlp)."
        )

        # ── Compliance Summary ────────────────────────────────────────────────
        self._h(4, "2.4.7 Data Sovereignty Compliance Checklist")
        self._p(
            "The table below summarises the as-built data-residency posture. "
            "Items marked ⚠️ require manual verification or remediation."
        )
        self._p()

        # Derive WildFire verdict for data-residency summary
        _wf_explicit_hosts = set(_wf_cloud_map.values())  # profiles with explicit regional URL
        _wf_public_cloud_count = sum(
            1 for modes in _wf_profile_modes.values() if "public-cloud" in modes
        )
        _wf_all_uk_eu = (
            all(_WF_REGIONS.get(h, ("", "", False))[2] for h in _wf_explicit_hosts)
            if _wf_explicit_hosts
            else False
        )
        if _wf_explicit_hosts and _wf_all_uk_eu and _wf_public_cloud_count == 0:
            _wf_status = "✅ UK/EU"
            _wf_location = "; ".join(sorted(_wf_explicit_hosts))
            _wf_note = "No action required."
        elif _wf_explicit_hosts and not _wf_all_uk_eu:
            _wf_status = "⚠️ Non-UK/EU explicit cloud"
            _wf_location = "; ".join(sorted(_wf_explicit_hosts))
            _wf_note = (
                "See §2.4.1. Reconfigure to `uk.wildfire.paloaltonetworks.com` for UK sovereignty."
            )
        else:
            _wf_status = "⚠️ Verify tenant setting"
            _wf_location = f"Tenant Infrastructure Setting ({_wf_public_cloud_count} profile(s) use public-cloud)"
            _wf_note = (
                "See §2.4.1. Verify tenant WildFire cloud region in SCM: "
                "Prisma Access → Infrastructure → Settings → WildFire."
            )

        self._table(
            ["Component", "Configured Location", "UK/EU Compliant?", "Notes / Action Required"],
            [
                [
                    "Advanced WildFire",
                    _wf_location,
                    _wf_status,
                    _wf_note,
                ],
                [
                    "DNS Security Cloud Lookups",
                    "Follows CDL/SLS region",
                    "⚠️ Verify CDL region",
                    "Ensure CDL is provisioned in UK/EU region (see §2.4.4).",
                ],
                [
                    "SCM Management Plane",
                    _NA,
                    "⚠️ Manual check required",
                    "Verify via hub.paloaltonetworks.com → Tenant Info or x-panw-region header.",
                ],
                [
                    "Cortex Data Lake (CDL/SLS)",
                    _NA,
                    "⚠️ Manual check required",
                    "Verify via hub.paloaltonetworks.com → Strata Logging Service → Settings.",
                ],
                [
                    "Prisma Access Compute",
                    "See §2.4",
                    "✅ Configurable" if snap.network_locations else "⚠️ Verify",
                    "Ensure RNs/SCs are pinned to UK/EU SPNs. See §2.3 Compute Locations.",
                ],
                [
                    "Advanced Threat Prevention",
                    "Follows SCM tenant region",
                    "⚠️ Verify SCM region",
                    "Confirm SCM tenant is provisioned in UK/EU region (see §2.4.3).",
                ],
                [
                    "Enterprise DLP (ML-based)",
                    "Enterprise DLP instance region",
                    "⚠️ Verify DLP instance region",
                    "See §2.4.6. Verify in Hub → Enterprise DLP → Settings. EU/UK instance required for sovereignty.",
                ],
                [
                    "SCM Inline DLP (data-filtering)",
                    "Follows Prisma Access data plane / CDL",
                    "⚠️ Verify CDL region",
                    "Inline DLP processes data in PA data plane — same residency as CDL (see §2.4.4).",
                ],
                [
                    "Prisma AIRS (AI Runtime Security)",
                    "Follows SCM tenant region",
                    "⚠️ Verify SCM region",
                    "AIRS management plane follows the SCM/SASE tenant region.",
                ],
            ],
        )
        self._note(
            "**UK Data Sovereignty:** Palo Alto Networks offers a dedicated UK WildFire cloud "
            "(`uk.wildfire.paloaltonetworks.com`), UK Prisma Access compute locations "
            "(London), and UK/EU CDL instances. Work with your PAN account team to confirm "
            "all CDSS services are routed to UK infrastructure. "
            "Reference: [Prisma SASE Data Residency](https://www.paloaltonetworks.com/resources/"
            "datasheets/prisma-sase-data-residency)."
        )
        self._p()

    # ── Section 3: Prisma Access Infrastructure ───────────────────────────────

    def _section_3(self) -> None:
        snap = self.snap
        self._h(2, "3. Prisma Access: Infrastructure & Connectivity")
        self._note(
            "**Key routing fact:** Mobile Users cannot reach Remote Networks directly — "
            "traffic is hairpinned through the SC-CAN (Service Connection Corporate Access Node). "
            "A Service Connection is mandatory to enable MU↔RN communication. "
            "See **Appendix F** for the Prisma Access internal routing reference diagram."
        )

        # 3.1 Remote Networks
        self._h(3, "3.1 Remote Networks (RN)")
        if snap.remote_networks:
            rows = []
            for rn in snap.remote_networks:
                name = rn.get("name", "")
                region = rn.get("region", "")
                spn = rn.get("spn_name", "")
                tunnel = rn.get("ipsec_tunnel", "")
                sec_tunnel = rn.get("secondary_ipsec_tunnel", "")
                subnets = ", ".join(rn.get("subnets") or [])
                ecmp = "Yes" if rn.get("ecmp_load_balancing") else "No"
                lic = rn.get("license_type", "")
                rows.append(
                    [name, region, spn, tunnel, sec_tunnel or "—", subnets or "—", ecmp, lic]
                )
            self._table(
                [
                    "Branch Name",
                    "Region",
                    "SPN Node",
                    "Primary IPSec Tunnel",
                    "Secondary Tunnel",
                    "Subnets",
                    "ECMP",
                    "License",
                ],
                rows,
            )
        else:
            self._warn("No Remote Networks found in this folder.")

        # 3.1.2 RN Live Status from Insights API
        if snap.insights_rn_status:
            self._h(4, "3.1.2 Remote Network Live Status (Insights API)")
            rows = []
            for entry in snap.insights_rn_status:
                name = entry.get("name", entry.get("site_name", entry.get("rn_name", "—")))
                region = entry.get("region", entry.get("location", "—"))
                state = entry.get("state", entry.get("status", entry.get("tunnel_state", "—")))
                icon = (
                    "✅"
                    if str(state).lower() in ("up", "connected", "active", "1", "true")
                    else (
                        "❌"
                        if str(state).lower() in ("down", "disconnected", "0", "false")
                        else "⚠️"
                    )
                )
                bw_alloc = entry.get("bandwidth_allocated", entry.get("allocated_bw", "—"))
                bw_used = entry.get(
                    "bandwidth_consumed", entry.get("consumed_bw", entry.get("throughput", "—"))
                )
                rows.append([name, region, f"{icon} {state}", str(bw_alloc), str(bw_used)])
            self._table(
                ["Branch Name", "Region", "Live State", "Allocated BW (Mbps)", "Current BW (Mbps)"],
                rows,
            )
        elif snap.insights_rn_bandwidth:
            self._h(4, "3.1.2 Remote Network Bandwidth (Insights API)")
            rows = []
            for entry in snap.insights_rn_bandwidth:
                name = entry.get("name", entry.get("rn_name", "—"))
                region = entry.get("region", "—")
                alloc = entry.get("bandwidth_allocated", entry.get("allocated", "—"))
                used = entry.get(
                    "bandwidth_consumed", entry.get("consumed", entry.get("throughput", "—"))
                )
                rows.append([name, region, str(alloc), str(used)])
            self._table(["Branch Name", "Region", "Allocated BW (Mbps)", "Current BW (Mbps)"], rows)

        # RN tunnels detail
        if snap.remote_networks:
            self._h(4, "3.1.1 WAN Connectivity & IPSec Tunnel Detail")
            # Lookup chain: RN.ipsec_tunnel → IPSec tunnel.auto_key.ike_gateway[0].name → IKE gw.peer_address.ip
            ike_by_name = {g.get("name"): g for g in snap.ike_gateways}
            ipsec_by_name = {t.get("name"): t for t in snap.ipsec_tunnels}

            rows = []
            for rn in snap.remote_networks:
                name = rn.get("name", "")
                for tunnel_key in ("ipsec_tunnel", "secondary_ipsec_tunnel"):
                    tunnel_name = rn.get(tunnel_key, "")
                    if not tunnel_name:
                        continue
                    ipsec = ipsec_by_name.get(tunnel_name, {})
                    # Resolve IKE gateway via IPSec tunnel's auto_key reference
                    ike_gw_raw = (ipsec.get("auto_key") or {}).get("ike_gateway") or []
                    # SDK returns either a list of dicts or a plain string depending on version
                    if isinstance(ike_gw_raw, list):
                        first = ike_gw_raw[0] if ike_gw_raw else {}
                        ike_gw_name = (
                            first.get("name", "") if isinstance(first, dict) else str(first)
                        )
                    else:
                        ike_gw_name = str(ike_gw_raw) if ike_gw_raw else ""
                    ike = ike_by_name.get(ike_gw_name, {})
                    ipsec_crypto = (ipsec.get("auto_key") or {}).get(
                        "ipsec_crypto_profile", "—"
                    ) or "—"
                    peer_ip = (
                        _nested(ike, "peer_address", "ip")
                        or _nested(ike, "peer_address", "fqdn")
                        or _NA
                    )
                    peer_id = _nested(ike, "peer_id", "id") or "—"
                    ike_crypto = (
                        _nested(ike, "protocol", "ikev2", "ike_crypto_profile")
                        or _nested(ike, "protocol", "ikev1", "ike_crypto_profile")
                        or "—"
                    )
                    ike_ver = (ike.get("protocol") or {}).get("version", "ikev2-preferred")
                    auth_type = (
                        "PSK"
                        if (ike.get("authentication") or {}).get("pre_shared_key")
                        else (
                            "Certificate"
                            if (ike.get("authentication") or {}).get("certificate")
                            else _NA
                        )
                    )
                    label = "Primary" if tunnel_key == "ipsec_tunnel" else "Secondary"
                    rows.append(
                        [
                            name,
                            label,
                            tunnel_name,
                            ike_gw_name or "—",
                            peer_ip,
                            peer_id,
                            ike_ver,
                            ike_crypto,
                            ipsec_crypto,
                            auth_type,
                        ]
                    )
            if rows:
                self._table(
                    [
                        "Branch",
                        "Link",
                        "IPSec Tunnel",
                        "IKE Gateway",
                        "Peer WAN IP / FQDN",
                        "Peer ID",
                        "IKE Version",
                        "IKE Crypto",
                        "IPSec Crypto",
                        "Auth",
                    ],
                    rows,
                )
            self._note(
                "BGP peer IP addresses (branch CPE ↔ Prisma Access) are not exposed via the SCM API. "
                "Obtain these from your CPE device configs or from Prisma Access → Remote Networks → tunnel detail in the portal."
            )

        # BGP Routing
        if snap.bgp_routing_config:
            self._h(4, "3.1.3 BGP Routing Configuration (Global)")
            bgp = snap.bgp_routing_config
            _orts = bgp.get("outbound_routes_for_services")
            rows = [
                ["Routing Preference", bgp.get("routing_preference")],
                ["Backbone Routing", bgp.get("backbone_routing")],
                ["Accept Routes over SC", bgp.get("accept_route_over_SC")],
                [
                    "Outbound Routes for Services",
                    ", ".join(_orts) if isinstance(_orts, list) else _orts,
                ],
                ["Add Host Route to IKE Peer", bgp.get("add_host_route_to_ike_peer")],
                ["Withdraw Static Route", bgp.get("withdraw_static_route")],
            ]
            self._table(["Parameter", "Value"], rows)

        # QoS profiles linked to RNs
        if snap.qos_profiles:
            self._h(4, "3.1.4 QoS Profiles")
            rows = []
            for qos in snap.qos_profiles:
                rows.append(
                    [
                        qos.get("name", ""),
                        str(qos.get("description", "") or ""),
                        str(qos.get("id", "")),
                    ]
                )
            self._table(["Profile Name", "Description", "ID"], rows)

        # 3.1.5 IKE Gateway & IPSec Tunnel Inventory (raw REST — complete field set)
        if snap.ike_gateways or snap.ipsec_tunnels:
            self._h(4, "3.1.5 IKE Gateway & IPSec Tunnel Inventory")
            self._p(
                "Full inventory retrieved via raw REST (`/config/network/v1/ike-gateways` and "
                "`/config/network/v1/ipsec-tunnels`). The SDK Pydantic model omits "
                "`local_address` and `tunnel_interface`; these are captured here for a "
                "complete AS-BUILT record."
            )

        if snap.ike_gateways:
            self._h(5, "IKE Gateways")
            rows = []
            for gw in snap.ike_gateways:
                local_iface = _nested(gw, "local_address", "interface") or "—"
                local_ip = _nested(gw, "local_address", "ip", "ip_address") or "—"
                local_addr = local_ip if local_ip != "—" else local_iface
                peer = (
                    _nested(gw, "peer_address", "ip")
                    or _nested(gw, "peer_address", "fqdn")
                    or (
                        "dynamic"
                        if (gw.get("peer_address") or {}).get("dynamic") is not None
                        else "—"
                    )
                )
                peer_id_type = _nested(gw, "peer_id", "type") or "—"
                peer_id_val = _nested(gw, "peer_id", "id") or "—"
                peer_id = f"{peer_id_val} ({peer_id_type})" if peer_id_val != "—" else "—"
                proto = gw.get("protocol") or {}
                version = proto.get("version") or "ikev2-preferred"
                ike_crypto = (
                    _nested(proto, "ikev2", "ike_crypto_profile")
                    or _nested(proto, "ikev1", "ike_crypto_profile")
                    or "—"
                )
                auth = gw.get("authentication") or {}
                auth_type = (
                    "PSK"
                    if auth.get("pre_shared_key")
                    else ("Certificate" if auth.get("certificate") else "—")
                )
                nat_t = str(_nested(gw, "protocol_common", "nat_traversal", "enable") or "—")
                frag = str(_nested(gw, "protocol_common", "fragmentation", "enable") or "—")
                rows.append(
                    [
                        gw.get("name", "—"),
                        local_addr,
                        peer,
                        peer_id,
                        version,
                        ike_crypto,
                        auth_type,
                        nat_t,
                        frag,
                    ]
                )
            self._table(
                [
                    "Gateway Name",
                    "Local Address/Iface",
                    "Peer Address",
                    "Peer ID",
                    "IKE Version",
                    "IKE Crypto Profile",
                    "Auth",
                    "NAT-T",
                    "Fragment",
                ],
                rows,
            )

        if snap.ipsec_tunnels:
            self._h(5, "IPSec Tunnels")
            rows = []
            for t in snap.ipsec_tunnels:
                tunnel_iface = t.get("tunnel_interface") or "—"
                auto_key = t.get("auto_key") or {}
                ike_gw_raw = auto_key.get("ike_gateway") or []
                if isinstance(ike_gw_raw, list):
                    ike_gw_name = (
                        (
                            ike_gw_raw[0].get("name", "")
                            if ike_gw_raw and isinstance(ike_gw_raw[0], dict)
                            else str(ike_gw_raw[0])
                        )
                        if ike_gw_raw
                        else "—"
                    )
                else:
                    ike_gw_name = str(ike_gw_raw) if ike_gw_raw else "—"
                ipsec_crypto = auto_key.get("ipsec_crypto_profile") or "—"
                proxy_ids = auto_key.get("proxy_id") or []
                proxy_str = (
                    "; ".join(
                        f"{p.get('local', '?')}↔{p.get('remote', '?')}({p.get('protocol', 'any')})"
                        for p in proxy_ids
                        if isinstance(p, dict)
                    )
                    or "—"
                )
                anti_replay = str(t.get("anti_replay", "—"))
                monitor = (t.get("tunnel_monitor") or {}).get("enable")
                monitor_str = str(monitor) if monitor is not None else "—"
                rows.append(
                    [
                        t.get("name", "—"),
                        tunnel_iface,
                        ike_gw_name,
                        ipsec_crypto,
                        proxy_str,
                        anti_replay,
                        monitor_str,
                    ]
                )
            self._table(
                [
                    "Tunnel Name",
                    "Tunnel Interface",
                    "IKE Gateway",
                    "IPSec Crypto Profile",
                    "Proxy IDs (local↔remote)",
                    "Anti-Replay",
                    "Tunnel Monitor",
                ],
                rows,
            )

        # 3.2 Service Connections
        self._h(3, "3.2 Service Connections (SCN)")
        if snap.service_connections:
            rows = []
            for sc in snap.service_connections:
                name = sc.get("name", "")
                region = sc.get("region", "")
                tunnel = sc.get("ipsec_tunnel", "")
                sec_tunnel = sc.get("secondary_ipsec_tunnel", "")
                subnets = ", ".join(sc.get("subnets") or [])
                nat_pool = sc.get("nat_pool", "")
                onboard_raw = sc.get("onboarding_type", "")
                onboard = (
                    onboard_raw.value
                    if hasattr(onboard_raw, "value")
                    else str(onboard_raw)
                    if onboard_raw
                    else ""
                )
                rows.append(
                    [
                        name,
                        region,
                        tunnel,
                        sec_tunnel or "—",
                        subnets or "—",
                        nat_pool or "—",
                        onboard,
                    ]
                )
            self._table(
                [
                    "SCN Name",
                    "Region",
                    "Primary Tunnel",
                    "Secondary Tunnel",
                    "Subnets",
                    "NAT Pool",
                    "Onboarding Type",
                ],
                rows,
            )
            self._note(
                "SCNs provide inbound access from Prisma Access to customer Data Centres. Each SCN appears as a BGP peer to the DC."
            )
        else:
            self._warn("No Service Connections found in this folder.")

        # 3.2.1 SC Live Status from Insights API
        if snap.insights_sc_status:
            self._h(4, "3.2.1 Service Connection Live Status (Insights API)")
            rows = []
            for entry in snap.insights_sc_status:
                name = entry.get("name", entry.get("sc_name", "—"))
                region = entry.get("region", entry.get("location", "—"))
                state = entry.get("state", entry.get("status", entry.get("tunnel_state", "—")))
                icon = (
                    "✅"
                    if str(state).lower() in ("up", "connected", "active", "1", "true")
                    else (
                        "❌"
                        if str(state).lower() in ("down", "disconnected", "0", "false")
                        else "⚠️"
                    )
                )
                bw_alloc = entry.get("bandwidth_allocated", entry.get("allocated_bw", "—"))
                bw_used = entry.get(
                    "bandwidth_consumed", entry.get("consumed_bw", entry.get("throughput", "—"))
                )
                rows.append([name, region, f"{icon} {state}", str(bw_alloc), str(bw_used)])
            self._table(
                ["SC Name", "Region", "Live State", "Allocated BW (Mbps)", "Current BW (Mbps)"],
                rows,
            )
        elif snap.insights_sc_bandwidth:
            self._h(4, "3.2.1 Service Connection Bandwidth (Insights API)")
            rows = []
            for entry in snap.insights_sc_bandwidth:
                name = entry.get("name", entry.get("sc_name", "—"))
                region = entry.get("region", "—")
                alloc = entry.get("bandwidth_allocated", entry.get("allocated", "—"))
                used = entry.get(
                    "bandwidth_consumed", entry.get("consumed", entry.get("throughput", "—"))
                )
                rows.append([name, region, str(alloc), str(used)])
            self._table(["SC Name", "Region", "Allocated BW (Mbps)", "Current BW (Mbps)"], rows)

        # 3.3 Mobile Users
        self._h(3, "3.3 Mobile Users (MU)")
        if snap.mobile_agent_infrastructure:
            for infra in snap.mobile_agent_infrastructure:
                name = infra.get("name", "Default")
                self._h(4, f"3.3.1 Infrastructure: {name}")
                portal = infra.get("portal_hostname", "")
                ip_pools = infra.get("ip_pools", [])
                static_pools = infra.get("static_ip_pools", [])
                rows = [
                    ["Portal Hostname", portal or _NA],
                    [
                        "IP Pools (Dynamic)",
                        ", ".join(str(p) for p in ip_pools) if ip_pools else _NA,
                    ],
                    [
                        "Static IP Pools",
                        ", ".join(str(p) for p in static_pools) if static_pools else "None",
                    ],
                    ["IPv6 Enabled", str(infra.get("ipv6", False))],
                    ["UDP Queries", str(infra.get("udp_queries", False))],
                    ["WINS Enabled", str(infra.get("enable_wins", False))],
                ]
                self._table(["Parameter", "Value"], rows)
        else:
            self._warn(
                "Mobile agent infrastructure settings not found. Verify the 'Mobile Users' folder is accessible."
            )

        if snap.mobile_agent_global_settings:
            gs = snap.mobile_agent_global_settings
            self._h(4, "3.3.2 Global Settings")
            _mgw = gs.get("manual_gateway", _NA)
            if isinstance(_mgw, dict):
                _mgw = ", ".join(f"{k}: {v}" for k, v in _mgw.items() if v is not None)
            self._table(
                ["Parameter", "Value"],
                [
                    ["Agent Version", str(gs.get("agent_version", _NA))],
                    ["Manual Gateway", _mgw],
                ],
            )

        if snap.mobile_agent_auth_settings:
            self._h(4, "3.3.3 Authentication Settings")
            rows = []
            for a in snap.mobile_agent_auth_settings:
                rows.append(
                    [
                        a.get("name", ""),
                        a.get("authentication_profile", ""),
                        ", ".join(a.get("os", []))
                        if isinstance(a.get("os"), list)
                        else str(a.get("os", "")),
                        str(a.get("user_credential_or_client_cert_required", "")),
                    ]
                )
            self._table(["Name", "Auth Profile", "OS", "Cert/Credential Required"], rows)

        self._h(4, "3.3.4 Forwarding Profiles")
        self._p(
            "GlobalProtect Forwarding Profiles define how mobile user traffic is forwarded "
            "through Prisma Access — either via IPSec tunnel (default), an Explicit Proxy / "
            "PAC file, or a regional/custom proxy server. A forwarding profile is assigned "
            "per user or device group via the GP Agent Profile."
        )
        self._p()
        if snap.forwarding_profiles:

            def _fp_type_str(fp: dict) -> str:
                t = fp.get("type", "")
                if isinstance(t, dict):
                    key = next(iter(t), "unknown")
                    return key.replace("_", " ").title()
                if hasattr(t, "value"):
                    return t.value
                return str(t) if t else "—"

            def _fp_detail(fp: dict) -> str:
                t = fp.get("type", {})
                if isinstance(t, dict):
                    key = next(iter(t), "")
                    inner = t.get(key, {}) if isinstance(t.get(key), dict) else {}
                    if key == "pac_file":
                        url = (
                            inner.get("pac_file_url")
                            or inner.get("url")
                            or t.get("pac_file_url")
                            or "—"
                        )
                        return f"PAC URL: `{url}`"
                    if key == "global_protect_proxy":
                        server = inner.get("server") or "—"
                        port = inner.get("port") or ""
                        return f"Proxy: {server}{':' + str(port) if port else ''}"
                return "—"

            rows = []
            for fp in snap.forwarding_profiles:
                dm = fp.get("definition_method", "")
                if hasattr(dm, "value"):
                    dm = dm.value
                rows.append(
                    [
                        fp.get("name", ""),
                        _fp_type_str(fp),
                        str(dm) or "—",
                        _fp_detail(fp),
                        fp.get("description", "") or "—",
                    ]
                )
            self._table(
                ["Profile Name", "Type", "Definition Method", "Proxy / PAC Detail", "Description"],
                rows,
            )

            # Regional / custom proxies
            if snap.forwarding_profile_regional_proxies:
                self._h(5, "Regional & Custom Proxy Servers")
                rp_rows = []
                for rp in snap.forwarding_profile_regional_proxies:
                    name = rp.get("name") or "—"
                    rp_type = rp.get("type") or "—"
                    if hasattr(rp_type, "value"):
                        rp_type = rp_type.value
                    p1 = rp.get("proxy_1") or {}
                    p2 = rp.get("proxy_2") or {}
                    proxy1 = f"{p1.get('server', '—')}:{p1.get('port', '')}" if p1 else "—"
                    proxy2 = f"{p2.get('server', '—')}:{p2.get('port', '')}" if p2 else "—"
                    fallback = rp.get("fallback_option") or "—"
                    if hasattr(fallback, "value"):
                        fallback = fallback.value
                    rp_rows.append([name, str(rp_type), proxy1, proxy2, str(fallback)])
                self._table(
                    ["Proxy Name", "Type", "Primary Proxy", "Secondary Proxy", "Fallback"],
                    rp_rows,
                )

            # Forwarding profile destinations (split-tunnel inclusions/exclusions)
            if snap.forwarding_profile_destinations:
                self._h(5, "Forwarding Profile Destinations (Split-Tunnel)")
                dest_rows = []
                for d in snap.forwarding_profile_destinations[:30]:
                    name = d.get("name") or "—"
                    action = d.get("action") or d.get("type") or "—"
                    if hasattr(action, "value"):
                        action = action.value
                    dest = d.get("destination") or d.get("ip_network") or d.get("fqdn") or "—"
                    profile = d.get("forwarding_profile") or "—"
                    dest_rows.append([name, str(action), str(dest), str(profile)])
                self._table(["Name", "Action", "Destination", "Profile"], dest_rows)
                if len(snap.forwarding_profile_destinations) > 30:
                    self._p(
                        f"_Showing first 30 of {len(snap.forwarding_profile_destinations)} destinations._"
                    )

            # Source applications (per-app proxy steering)
            if snap.forwarding_profile_source_apps:
                self._h(5, "Source Application Steering")
                sa_rows = []
                for s in snap.forwarding_profile_source_apps[:20]:
                    name = s.get("name") or "—"
                    apps = ", ".join((s.get("applications") or s.get("app") or [])[:5]) or "—"
                    profile = s.get("forwarding_profile") or "—"
                    action = s.get("action") or "—"
                    sa_rows.append([name, apps, str(action), str(profile)])
                self._table(["Name", "Applications", "Action", "Profile"], sa_rows)

            # User location steering
            if snap.forwarding_profile_user_locations:
                self._h(5, "User Location-Based Steering")
                ul_rows = []
                for u in snap.forwarding_profile_user_locations[:20]:
                    name = u.get("name") or "—"
                    loc = u.get("location") or u.get("network") or "—"
                    profile = u.get("forwarding_profile") or "—"
                    ul_rows.append([name, str(loc), str(profile)])
                self._table(["Name", "Location / Network", "Profile"], ul_rows)
        else:
            self._note(
                "No Forwarding Profiles configured. Forwarding Profiles are required to enable "
                "Explicit Proxy or PAC file-based traffic steering for GlobalProtect mobile users. "
                "Without a forwarding profile, all traffic tunnels via IPSec (default). "
                "Configure via Strata Cloud Manager → Mobile Users → Forwarding Profiles."
            )

        if snap.mobile_agent_agent_profiles:
            self._h(4, "3.3.5 GP Agent Profiles")
            rows = []

            def _gp_cfg(profile: dict, key: str) -> str:
                """Extract a value from gp_app_config.config[] or top-level fields."""
                cfg_list = (profile.get("gp_app_config") or {}).get("config") or []
                for item in cfg_list:
                    if item.get("name") == key:
                        vals = item.get("value", [])
                        return ", ".join(vals) if isinstance(vals, list) else str(vals)
                app = profile.get("app_settings") or {}
                return str(
                    app.get(key.replace("-", "_")) or profile.get(key.replace("-", "_")) or "—"
                )

            for ap in snap.mobile_agent_agent_profiles:
                connect_method = _gp_cfg(ap, "connect-method")
                tunnel_mtu = _gp_cfg(ap, "tunnel-mtu")
                dem_agent = _gp_cfg(ap, "dem-agent")
                cdl_log = _gp_cfg(ap, "cdl-log")
                os_list = ap.get("os") or []
                os_str = (
                    ", ".join(
                        (o.get("name") or o) if isinstance(o, dict) else str(o) for o in os_list
                    )
                    or "any"
                )
                rows.append(
                    [
                        ap.get("name", ""),
                        connect_method or _NA,
                        tunnel_mtu or _NA,
                        dem_agent or "—",
                        cdl_log or "—",
                        os_str,
                        ap.get("description", "") or "—",
                    ]
                )
            self._table(
                [
                    "Profile Name",
                    "Connect Method",
                    "Tunnel MTU",
                    "ADEM Agent",
                    "CDL Log",
                    "OS",
                    "Description",
                ],
                rows,
            )
            self._note(
                "Connect Method: `pre-logon` (machine auth before login), "
                "`user-logon` (always-on after login), `on-demand`. "
                "Always-on (`user-logon`) is required for NCSC CAF compliance. "
                "ADEM Agent: `install-with-user-control` or `install-no-user-control` "
                "enables Digital Experience Monitoring on endpoints."
            )

        if snap.mobile_agent_tunnel_profiles:
            self._h(4, "3.3.6 GP Tunnel Profiles (SDK v0.15.0)")
            rows = []
            for tp in snap.mobile_agent_tunnel_profiles:
                rows.append(
                    [
                        tp.get("name", ""),
                        tp.get("protocol", _NA),
                        str(tp.get("port", _NA)),
                        tp.get("description", "") or "—",
                    ]
                )
            self._table(["Profile Name", "Protocol", "Port", "Description"], rows)

        # 3.3.7 Connected Mobile Users (Insights API live count)
        if snap.insights_connected_mu_count >= 0:
            self._h(4, "3.3.7 Connected Mobile Users — Live Count (Insights API)")
            icon = "✅" if snap.insights_connected_mu_count > 0 else "ℹ️"
            self._table(
                ["Metric", "Value"],
                [
                    ["Currently Connected Users", f"{icon} {snap.insights_connected_mu_count}"],
                    ["Data Source", "Prisma Access Insights v3.0 API (live)"],
                ],
            )
            if snap.insights_mu_status:
                self._h(5, "Per-Location MU Status")
                rows = []
                for entry in snap.insights_mu_status:
                    location = entry.get("name", entry.get("location", entry.get("node_name", "—")))
                    state = entry.get("state", entry.get("status", "—"))
                    mu_count = entry.get(
                        "connected_users", entry.get("user_count", entry.get("count", "—"))
                    )
                    icon_loc = "✅" if str(state).lower() in ("up", "active", "available") else "⚠️"
                    rows.append([location, f"{icon_loc} {state}", str(mu_count)])
                self._table(["PA Location", "GP Gateway State", "Connected Users"], rows)
        # 3.3.8 GP Agent Versions
        if snap.mobile_agent_versions:
            self._h(4, "3.3.8 GP Agent Versions")
            activated = [v for v in snap.mobile_agent_versions if "activated" in v.lower()]
            available = [v for v in snap.mobile_agent_versions if "activated" not in v.lower()]
            self._table(
                ["State", "Versions"],
                [
                    ["Activated", ", ".join(v.strip() for v in activated) if activated else _NA],
                    ["Available", ", ".join(v.strip() for v in available) if available else _NA],
                ],
            )
            self._note(
                "The activated version is deployed to endpoints during next tunnel establishment. "
                "Versions listed without '(activated)' are available for rollout via the GP portal."
            )
        self._p()

        # 3.4 NGFW Managed Device Inventory
        self._h(3, "3.4 NGFW Managed Device Inventory")
        snap = self.snap

        if not snap.ngfw_devices:
            self._warn(
                "No NGFW devices returned. Either no NGFWs are onboarded to SCM, or the "
                "report was generated without `include_extended=True`. For NGFW tenants, "
                "run with the extended flag or query `scm_ngfw_device_list` directly."
            )
            self._table(
                [
                    "Hostname",
                    "Serial Number",
                    "Model",
                    "SW Version",
                    "HA State",
                    "Connected",
                    "Folder",
                    "Auth Key",
                ],
                [[_NA, _NA, _NA, _NA, _NA, _NA, _NA, _NA]],
            )
            self._p("> **📎 Reference:** <https://pan.dev/scm/api/config/ngfw/setup/list-devices/>")
            self._p()
            return  # nothing more to render

        # ── 3.4.1 Device Inventory Table ─────────────────────────────────────
        self._h(4, "3.4.1 Device Inventory")
        rows = []
        for d in snap.ngfw_devices:
            connected = d.get("is_connected") or d.get("connected")
            rows.append(
                [
                    d.get("name", "—"),
                    d.get("serial_number", _NA),
                    d.get("model", _NA),
                    d.get("sw_version", _NA),
                    d.get("ha_state", "standalone"),
                    "✅" if connected else "❌",
                    d.get("folder", _NA),
                    d.get("auth_key", "—"),
                ]
            )
        self._table(
            [
                "Hostname",
                "Serial Number",
                "Model",
                "SW Version",
                "HA State",
                "Connected",
                "Folder",
                "Auth Key",
            ],
            rows,
        )
        self._p("> **📎 Reference:** <https://pan.dev/scm/api/config/ngfw/setup/list-devices/>")
        self._p()

        # ── 3.4.2 Connectivity Health ─────────────────────────────────────────
        self._h(4, "3.4.2 Connectivity Health")
        _total = len(snap.ngfw_devices)
        _connected = sum(
            1 for d in snap.ngfw_devices if d.get("is_connected") or d.get("connected")
        )
        _disconnected = _total - _connected
        _pct = int(100 * _connected / _total) if _total else 0
        _health_icon = "✅" if _pct == 100 else ("⚠️" if _pct >= 80 else "❌")
        self._table(
            ["Metric", "Value"],
            [
                ["Total Devices", str(_total)],
                ["Connected", f"✅ {_connected}"],
                ["Disconnected", f"❌ {_disconnected}" if _disconnected else "—"],
                ["Connection Rate", f"{_health_icon} {_pct}%"],
            ],
        )
        if _disconnected:
            _dc_names = [
                d.get("name", d.get("serial_number", "unknown"))
                for d in snap.ngfw_devices
                if not (d.get("is_connected") or d.get("connected"))
            ]
            self._note(
                f"**{_disconnected} device(s) are disconnected from SCM:** "
                + ", ".join(f"`{n}`" for n in _dc_names)
                + ". Disconnected devices cannot receive config pushes or content updates. "
                "Verify network connectivity to `api.sase.paloaltonetworks.com:443` and "
                "that the device certificate is valid."
            )

        # ── 3.4.3 PAN-OS Version Analysis ────────────────────────────────────
        self._h(4, "3.4.3 PAN-OS Version Analysis")
        from collections import Counter

        _versions: Counter = Counter()
        for d in snap.ngfw_devices:
            v = d.get("sw_version") or "Unknown"
            _versions[v] += 1

        _version_rows = []
        for ver, count in sorted(_versions.items(), key=lambda x: x[0], reverse=True):
            _version_rows.append(
                [ver, str(count), "⚠️ Verify EoL status" if ver == "Unknown" else "—"]
            )
        self._table(["PAN-OS Version", "Device Count", "Notes"], _version_rows)

        if len(_versions) > 1:
            self._note(
                f"**Mixed PAN-OS versions detected across {len(_versions)} distinct releases.** "
                "Best practice requires all HA pair members to run the same PAN-OS version. "
                "Mixed versions across the fleet increase operational complexity and may cause "
                "inconsistent security behaviour. Plan a coordinated upgrade to a single "
                "supported release. "
                "See: [PAN-OS End-of-Life Summary](https://www.paloaltonetworks.com/services/"
                "support/end-of-life-announcements/end-of-life-summary)."
            )
        else:
            self._note(
                "All devices are running the same PAN-OS version — version uniformity is confirmed. "
                "Verify the version is not End-of-Life using the "
                "[PAN-OS EoL Summary](https://www.paloaltonetworks.com/services/support/"
                "end-of-life-announcements/end-of-life-summary)."
            )

        # ── 3.4.4 HA Pair Summary ────────────────────────────────────────────
        self._h(4, "3.4.4 High Availability (HA) Configuration")

        # Build HA pairs from device list (by ha_state field) and/or ha_pairs data
        _ha_devices = [
            d
            for d in snap.ngfw_devices
            if d.get("ha_state") and d.get("ha_state") not in ("standalone", "", None)
        ]
        _standalone = [
            d
            for d in snap.ngfw_devices
            if not d.get("ha_state") or d.get("ha_state") == "standalone"
        ]

        if snap.ngfw_ha_pairs:
            # Use API-supplied HA pair data if available
            ha_rows = []
            for pair in snap.ngfw_ha_pairs:
                active = pair.get("active_device") or pair.get("primary") or {}
                passive = pair.get("passive_device") or pair.get("secondary") or {}
                ha_rows.append(
                    [
                        pair.get("name", "—"),
                        active.get("name", active.get("serial", "—"))
                        if isinstance(active, dict)
                        else str(active),
                        passive.get("name", passive.get("serial", "—"))
                        if isinstance(passive, dict)
                        else str(passive),
                        pair.get("ha_mode", pair.get("mode", "A/P")),
                        pair.get("sync_state", "—"),
                    ]
                )
            self._table(
                ["Pair Name", "Active Device", "Passive Device", "HA Mode", "Sync State"],
                ha_rows,
            )
        elif _ha_devices:
            # Infer pairs from ha_state field
            _active = [d for d in _ha_devices if "active" in (d.get("ha_state") or "").lower()]
            _passive = [d for d in _ha_devices if "passive" in (d.get("ha_state") or "").lower()]
            ha_rows = []
            for i, a in enumerate(_active):
                p = _passive[i] if i < len(_passive) else {}
                ha_rows.append(
                    [
                        f"Pair {i + 1}",
                        a.get("name", a.get("serial_number", "—")),
                        p.get("name", p.get("serial_number", "—")) if p else _NA,
                        "Active/Passive",
                        "—",
                    ]
                )
            self._table(
                ["Pair", "Active Device", "Passive Device", "HA Mode", "Sync State"],
                ha_rows,
            )
            self._note(
                "HA pair membership inferred from `ha_state` field on device objects. "
                "For authoritative HA sync state, check "
                "[SCM → Devices → Device Details → HA Status]"
                "(https://pan.dev/scm/api/config/ngfw/device/list-ha-devices/)."
            )
        else:
            self._p(
                f"_All {_total} device(s) are configured as **standalone** (no HA). "
                "For production deployments, Active/Passive HA is recommended to meet "
                "NCSC CAF B3 (Availability) and Cyber Essentials firewall resilience requirements._"
            )
            self._p()

        if _standalone and _ha_devices:
            _sa_names = [d.get("name", d.get("serial_number", "?")) for d in _standalone]
            self._note(
                f"**{len(_standalone)} standalone device(s)** alongside HA-paired devices: "
                + ", ".join(f"`{n}`" for n in _sa_names)
                + ". Verify these are intentionally standalone (e.g. branch firewalls) "
                "rather than HA pairs with a missing peer."
            )

        # ── 3.4.5 NGFW Config Management Notes ───────────────────────────────
        self._h(4, "3.4.5 SCM-Managed Configuration Notes")
        self._table(
            ["Best Practice", "Recommendation", "Reference"],
            [
                [
                    "Config Management",
                    "All policy and object config should be managed exclusively via SCM. "
                    "Avoid direct device CLI/GUI changes — they create config drift.",
                    "[SCM NGFW Config](https://pan.dev/scm/api/config/ngfw/)",
                ],
                [
                    "Content Updates",
                    "Configure automatic content DB updates (Threats, Apps & Threats, WildFire) "
                    "via SCM Update Schedule. Minimum: daily recurring at a maintenance window.",
                    "[Update Schedule Settings](https://pan.dev/scm/api/config/ngfw/device/list-update-schedule-settings/)",
                ],
                [
                    "HA Upgrade Path",
                    "For HA pairs: upgrade passive first, fail over, then upgrade active. "
                    "Both members must run identical PAN-OS within 30 minutes of each other.",
                    "[PAN-OS Upgrade Guide](https://docs.paloaltonetworks.com/pan-os/upgrade)",
                ],
                [
                    "Commit & Push",
                    "After config changes in SCM, use `scm_commit` followed by a Push to Device "
                    "to deploy. Verify job completion via `scm_job_status`.",
                    "[SCM Config Operations](https://pan.dev/scm/api/config/ngfw/operations/)",
                ],
                [
                    "Log Forwarding",
                    "Ensure each device has a Log Forwarding profile assigned to security rules "
                    "directing traffic/threat logs to CDL/SLS.",
                    "[CDL Log Forwarding](https://docs.paloaltonetworks.com/strata-logging-service)",
                ],
            ],
        )
        self._p()

        # ── 3.4.6 NGFW Logical Routers & BGP ────────────────────────────────
        if (
            snap.ngfw_logical_routers
            or snap.ngfw_bgp_address_family_profiles
            or snap.ngfw_bgp_redistribution_profiles
        ):
            self._h(4, "3.4.6 Logical Routers & BGP Configuration")
            self._p(
                "Logical routers (virtual routers in PAN-OS) are retrieved from NGFW device "
                "folders via `GET /config/network/v1/logical-routers`. Each router can contain "
                "multiple VRFs. BGP is configured at the VRF level — peer groups, peers, "
                "admin distances, and redistribution rules are all captured here."
            )

        if snap.ngfw_logical_routers:
            for lr in snap.ngfw_logical_routers:
                lr_name = lr.get("name", "—")
                routing_stack = lr.get("routing_stack") or "—"
                folder = lr.get("folder") or lr.get("snippet") or "—"
                self._h(5, f"Logical Router: {lr_name}")
                self._table(
                    ["Parameter", "Value"],
                    [
                        ["Routing Stack", routing_stack],
                        ["Folder / Snippet", folder],
                    ],
                )

                for vrf in lr.get("vrf") or []:
                    vrf_name = vrf.get("name", "default")
                    self._h(6, f"VRF: {vrf_name}")

                    # Interfaces
                    interfaces = vrf.get("interface") or []
                    if interfaces:
                        self._p(f"**Interfaces:** {', '.join(str(i) for i in interfaces)}")

                    # Admin distances
                    ad = vrf.get("admin_dists") or {}
                    if any(v is not None for v in ad.values()):
                        ad_rows = [
                            [k.replace("_", " ").title(), str(v)]
                            for k, v in ad.items()
                            if v is not None
                        ]
                        if ad_rows:
                            self._table(["Protocol", "Admin Distance"], ad_rows)

                    # Static routes
                    routing_table = vrf.get("routing_table") or {}
                    ip_routes = (routing_table.get("ip") or {}).get("static_routes") or []
                    if ip_routes:
                        self._h(6, "Static Routes (IPv4)")
                        sr_rows = []
                        for sr in ip_routes:
                            sr_rows.append(
                                [
                                    sr.get("name", "—"),
                                    sr.get("destination") or "—",
                                    sr.get("nexthop_type")
                                    or ("ip" if sr.get("nexthop", {}) else "—"),
                                    str(
                                        _nested(sr, "nexthop", "ip_address")
                                        or _nested(sr, "nexthop", "next_vr")
                                        or "—"
                                    ),
                                    sr.get("interface") or "—",
                                    str(sr.get("metric") or "—"),
                                ]
                            )
                        self._table(
                            [
                                "Name",
                                "Destination",
                                "Nexthop Type",
                                "Nexthop",
                                "Interface",
                                "Metric",
                            ],
                            sr_rows,
                        )

                    # BGP configuration
                    bgp = vrf.get("bgp") or {}
                    if bgp and bgp.get("enable") is not False:
                        self._h(6, "BGP")
                        bgp_info = [
                            ["Enabled", str(bgp.get("enable", "—"))],
                            ["Router ID", bgp.get("router_id") or "—"],
                            ["Local AS", bgp.get("local_as") or "—"],
                            ["Install Routes", str(bgp.get("install_route", "—"))],
                            ["Graceful Shutdown", str(bgp.get("graceful_shutdown", "—"))],
                            ["Reject Default Route", str(bgp.get("reject_default_route", "—"))],
                            ["ECMP Multi-AS", str(bgp.get("ecmp_multi_as", "—"))],
                        ]
                        self._table(["Parameter", "Value"], [r for r in bgp_info if r[1] != "—"])

                        # BGP Peer Groups and Peers
                        for pg in bgp.get("peer_group") or []:
                            pg_name = pg.get("name", "—")
                            pg_type = list((pg.get("type") or {}).keys())
                            pg_type_str = pg_type[0] if pg_type else "—"
                            self._h(6, f"Peer Group: {pg_name} ({pg_type_str})")
                            peers = pg.get("peer") or []
                            if peers:
                                peer_rows = []
                                for p in peers:
                                    peer_addr = (
                                        _nested(p, "peer_address", "ip")
                                        or _nested(p, "peer_address", "fqdn")
                                        or "—"
                                    )
                                    local_iface = _nested(p, "local_address", "interface") or "—"
                                    peer_rows.append(
                                        [
                                            p.get("name", "—"),
                                            peer_addr,
                                            p.get("peer_as") or "—",
                                            local_iface,
                                            str(p.get("enable", "—")),
                                            p.get("peering_type") or "—",
                                        ]
                                    )
                                self._table(
                                    [
                                        "Peer Name",
                                        "Peer IP/FQDN",
                                        "Peer AS",
                                        "Local Interface",
                                        "Enabled",
                                        "Type",
                                    ],
                                    peer_rows,
                                )
                            else:
                                self._p("_No peers configured in this peer group._")

                        # Advertised networks
                        adv_nets = bgp.get("advertise_network") or {}
                        ipv4_nets = (adv_nets.get("ipv4") or {}).get("unicast") or []
                        if ipv4_nets:
                            self._p(
                                f"**Advertised Networks (IPv4):** {', '.join(str(n.get('exact_match') or n) for n in ipv4_nets)}"
                            )

                    elif not bgp:
                        self._p("_BGP not configured on this VRF._")

        # BGP support profiles (shared across all logical routers)
        if snap.ngfw_bgp_redistribution_profiles:
            self._h(5, "BGP Redistribution Profiles")
            rows = []
            for p in snap.ngfw_bgp_redistribution_profiles:
                ipv4 = p.get("ipv4") or {}
                unicast = ipv4.get("unicast") or {}
                sources = ", ".join(
                    k for k, v in unicast.items() if v and isinstance(v, dict) and v.get("enable")
                )
                rows.append(
                    [p.get("name", "—"), p.get("folder") or p.get("snippet") or "—", sources or "—"]
                )
            self._table(["Profile Name", "Folder / Snippet", "IPv4 Sources Enabled"], rows)

        if snap.ngfw_bgp_address_family_profiles:
            self._h(5, "BGP Address Family Profiles")
            rows = []
            for p in snap.ngfw_bgp_address_family_profiles:
                ipv4 = (p.get("ipv4") or {}).get("unicast") or {}
                ipv6 = (p.get("ipv6") or {}).get("unicast") or {}
                rows.append(
                    [
                        p.get("name", "—"),
                        p.get("folder") or p.get("snippet") or "—",
                        str(ipv4.get("enable", "—")),
                        str(ipv6.get("enable", "—")),
                    ]
                )
            self._table(["Profile Name", "Folder / Snippet", "IPv4 Unicast", "IPv6 Unicast"], rows)

        if snap.ngfw_bgp_auth_profiles:
            self._h(5, "BGP Auth Profiles")
            rows = [
                [p.get("name", "—"), p.get("folder") or p.get("snippet") or "—"]
                for p in snap.ngfw_bgp_auth_profiles
            ]
            self._table(["Profile Name", "Folder / Snippet"], rows)

        if snap.ngfw_bgp_route_maps:
            self._h(5, "BGP Route Maps")
            rows = [
                [p.get("name", "—"), p.get("folder") or p.get("snippet") or "—"]
                for p in snap.ngfw_bgp_route_maps
            ]
            self._table(["Route Map Name", "Folder / Snippet"], rows)

        # ── 3.4.7 WAN / Internet-Facing Interface IP Addresses ────────────────
        self._h(4, "3.4.7 WAN / Internet-Facing Interface IP Addresses")
        if snap.ngfw_interface_ips:
            self._p(
                "_Parsed from each device's running-config via the NGFW Operations API. "
                "Shows the **configured** address — a DHCP-configured interface reports "
                "`dhcp` addressing without the live-leased IP, since this endpoint reflects "
                "configuration rather than live operational state._"
            )
            enriched = any(rec.get("enrichment") for rec in snap.ngfw_interface_ips)
            rows = []
            for rec in snap.ngfw_interface_ips:
                ips = ", ".join(rec.get("ip_addresses") or []) or "—"
                row = [
                    rec.get("device_name") or _NA,
                    rec.get("interface") or _NA,
                    rec.get("zone") or "—",
                    rec.get("addressing") or _NA,
                    ips,
                ]
                if enriched:
                    enr = rec.get("enrichment") or []
                    row += [
                        ", ".join(
                            f"{e.get('isp') or e.get('org') or '—'} ({e.get('asn') or '—'})"
                            for e in enr
                        )
                        or "—",
                        ", ".join(
                            ", ".join(filter(None, [e.get("city"), e.get("country")])) or "—"
                            for e in enr
                        )
                        or "—",
                    ]
                rows.append(row)
            headers = ["Device", "Interface", "Zone", "Addressing", "IP Address(es)"]
            if enriched:
                headers += ["Observed ISP (ASN)", "IP Geolocation"]
            self._table(headers, rows)
        else:
            self._note(
                "No interface IP data returned. This requires the **NGFW Operations "
                "entitlement** on the TSG (same requirement as `scm_ngfw_local_config_get`) "
                "— contact your PAN account team to enable it, or populate manually."
            )
        self._p()

    # ── Section 3.5: PA Operational Summary (Insights) ───────────────────────

    def _section_3b(self) -> None:
        """§3.5 Prisma Access Operational Status — live data from Insights API."""
        snap = self.snap

        # Only render if we have any Insights data at all
        has_insights = (
            snap.insights_connected_mu_count >= 0
            or snap.insights_tunnel_list
            or snap.insights_rn_status
            or snap.insights_sc_status
            or snap.insights_alerts
        )
        if not has_insights:
            return  # silently skip if Insights wasn't queried

        self._h(3, "3.5 Prisma Access Operational Status (Live — Insights API)")
        self._p(
            "_Live operational data sourced from the Prisma Access Insights v3.0 API. "
            "Re-run `scm_asbuilt_report` with `include_insights=True` to refresh. "
            "Ref: [Insights API](https://pan.dev/sase/api/insights/insights-api/)_"
        )
        self._p()

        # Summary health table
        _rn_up = sum(
            1
            for e in snap.insights_rn_status
            if str(e.get("state", e.get("status", ""))).lower() in ("up", "connected", "active")
        )
        _sc_up = sum(
            1
            for e in snap.insights_sc_status
            if str(e.get("state", e.get("status", ""))).lower() in ("up", "connected", "active")
        )
        _tunnel_up = sum(
            1
            for t in snap.insights_tunnel_list
            if str(t.get("state", t.get("status", t.get("tunnel_state", "")))).lower()
            in ("up", "active", "connected")
        )
        _mu_str = (
            str(snap.insights_connected_mu_count) if snap.insights_connected_mu_count >= 0 else "—"
        )
        self._table(
            ["Component", "Live Status"],
            [
                [
                    "Remote Networks",
                    f"✅ {_rn_up}/{len(snap.insights_rn_status)} up"
                    if snap.insights_rn_status
                    else "— (no data)",
                ],
                [
                    "Service Connections",
                    f"✅ {_sc_up}/{len(snap.insights_sc_status)} up"
                    if snap.insights_sc_status
                    else "— (no data)",
                ],
                [
                    "IPSec Tunnels",
                    f"✅ {_tunnel_up}/{len(snap.insights_tunnel_list)} up"
                    if snap.insights_tunnel_list
                    else "— (no data)",
                ],
                ["Connected Mobile Users", _mu_str],
                [
                    "Active Alerts",
                    f"⚠️ {len(snap.insights_alerts)}" if snap.insights_alerts else "✅ None",
                ],
            ],
        )

        # Tunnel health detail
        if snap.insights_tunnel_list:
            self._h(4, "3.5.1 IPSec Tunnel Health")
            rows = []
            for t in snap.insights_tunnel_list[:50]:  # cap at 50 rows
                name = t.get("name", t.get("tunnel_name", t.get("id", "—")))
                state = t.get("state", t.get("status", t.get("tunnel_state", "—")))
                icon = (
                    "✅"
                    if str(state).lower() in ("up", "active", "connected")
                    else (
                        "❌" if str(state).lower() in ("down", "disconnected", "inactive") else "⚠️"
                    )
                )
                peer = t.get("peer_ip", t.get("remote_peer", t.get("peer_address", "—")))
                location = t.get("location", t.get("node", t.get("spn_name", "—")))
                rn_site = t.get("site", t.get("rn_name", t.get("remote_network", "—")))
                rows.append([name, f"{icon} {state}", peer, location, rn_site])
            self._table(
                ["Tunnel Name", "State", "Peer IP", "PA Location", "Remote Network / Site"],
                rows,
            )
            if len(snap.insights_tunnel_list) > 50:
                self._p(
                    f"_Showing 50 of {len(snap.insights_tunnel_list)} tunnels. "
                    "Full list available via `scm_mobile_user_stats`._"
                )
            self._p()

        # Active alerts detail
        if snap.insights_alerts:
            self._h(4, "3.5.2 Active Alerts")
            rows = []
            for alert in snap.insights_alerts[:30]:
                severity = alert.get("severity", alert.get("priority", "—"))
                sev_icon = (
                    "🔴"
                    if str(severity).lower() in ("critical", "high")
                    else ("🟡" if str(severity).lower() == "medium" else "🔵")
                )
                name = alert.get("name", alert.get("alert_name", alert.get("type", "—")))
                desc = (alert.get("description", alert.get("message", "")) or "")[:100]
                location = alert.get("location", alert.get("site", alert.get("resource", "—")))
                ts = alert.get("created_time", alert.get("timestamp", alert.get("time", "—")))
                rows.append([f"{sev_icon} {severity}", name, location, desc or "—", str(ts)])
            self._table(
                ["Severity", "Alert Name", "Location / Resource", "Description", "Timestamp"],
                rows,
            )
            if len(snap.insights_alerts) > 30:
                self._p(f"_Showing 30 of {len(snap.insights_alerts)} active alerts._")
            self._p()
        elif snap.insights_connected_mu_count >= 0:
            # We got Insights data but no alerts — explicitly confirm clean state
            self._p("✅ _No active alerts from the Insights API at the time of report generation._")
            self._p()

        # Insights errors (if any)
        if snap.insights_errors:
            self._note(
                "Some Insights API calls returned errors: "
                + "; ".join(f"`{e}`" for e in snap.insights_errors[:5])
                + (
                    f" (+{len(snap.insights_errors) - 5} more)"
                    if len(snap.insights_errors) > 5
                    else ""
                )
            )

    # ── Section 3c: PBF Rules, Authentication Rules, Schedules ───────────────

    def _section_3c(self) -> None:
        """§3.6 Policy-Based Forwarding Rules / §3.7 Authentication Rules / §3.8 Schedules."""
        snap = self.snap
        has_content = snap.pbf_rules or snap.authentication_rules or snap.schedules

        if not has_content:
            return

        # 3.6 Policy-Based Forwarding (PBF) Rules
        if snap.pbf_rules:
            custom = [r for r in snap.pbf_rules if r.get("folder", "") != "All"]
            self._h(3, "3.6 Policy-Based Forwarding (PBF) Rules")
            self._p(
                "_PBF rules steer specific traffic flows to alternate next-hops or interfaces, "
                "bypassing standard routing. Used for office365 split-tunnelling and RBI/SWG redirect._"
            )
            if custom:
                rows = []
                for r in custom:
                    rows.append(
                        [
                            r.get("name", "—"),
                            r.get("folder", "—"),
                            r.get("description", "") or "—",
                        ]
                    )
                self._table(["Rule Name", "Folder", "Description"], rows)
            else:
                self._p(
                    f"_{len(snap.pbf_rules)} PBF rule(s) found (all are system-default 'All' folder rules)._"
                )

        # 3.7 Authentication Rules
        if snap.authentication_rules:
            custom_auth = [
                r
                for r in snap.authentication_rules
                if r.get("folder", "") not in ("All", "Prisma Access")
            ]
            self._h(3, "3.7 Authentication Rules")
            self._p(
                "_Authentication rules apply authentication enforcement policies (captive portal, "
                "multi-factor, Kerberos) on matched traffic before allowing access._"
            )
            if custom_auth:
                rows = []
                for r in custom_auth:
                    rows.append(
                        [
                            r.get("name", "—"),
                            r.get("folder", "—"),
                            r.get("authentication_profile", "") or "—",
                            r.get("description", "") or "—",
                        ]
                    )
                self._table(["Rule Name", "Folder", "Auth Profile", "Description"], rows)
            else:
                self._p(
                    f"_{len(snap.authentication_rules)} authentication rule(s) found "
                    f"(all are system-default)._"
                )

        # 3.8 Schedules
        if snap.schedules:
            self._h(3, "3.8 Schedules")
            rows = []
            for s in snap.schedules:
                stype = s.get("schedule_type", {})
                if isinstance(stype, dict):
                    recurring = stype.get("recurring") or {}
                    sched_str = (
                        next(iter(recurring), "non-recurring") if recurring else "non-recurring"
                    )
                else:
                    sched_str = str(stype) if stype else "—"
                rows.append(
                    [
                        s.get("name", "—"),
                        s.get("folder", "—"),
                        sched_str,
                        s.get("description", "") or "—",
                    ]
                )
            self._table(["Schedule Name", "Folder", "Type", "Description"], rows)

    # ── Section 4: Prisma SD-WAN ──────────────────────────────────────────────

    def _section_4(self) -> None:
        snap = self.snap
        has_sdwan = bool(snap.sdwan_sites or snap.sdwan_elements)

        self._h(2, "4. Prisma SD-WAN (Edge Implemented Design)")

        if not has_sdwan:
            self._note(
                "SD-WAN data not available — run `scm_asbuilt_report` with `include_sdwan=True` "
                "or populate sections below manually from the Prisma SD-WAN portal "
                "(prisma.sase.paloaltonetworks.com)."
            )
        else:
            self._p(
                f"_Auto-generated from live Prisma SD-WAN API. "
                f"{len(snap.sdwan_sites)} sites · {len(snap.sdwan_elements)} ION elements · "
                f"{len(snap.sdwan_vpn_links)} VPN overlay connections._"
            )

        # 4.0 VPN Overlay Topology Diagram
        if snap.sdwan_topology_mermaid:
            self._h(3, "4.0 VPN Overlay Topology")
            self._p(
                "_Auto-generated from live VPN link adjacency data. "
                "Green ✅ = tunnel UP, amber ⚠️ = degraded, red ❌ = down._"
            )
            self._p(f"```mermaid\n{snap.sdwan_topology_mermaid}\n```")
            self._p()

        # 4.1 Edge Device Inventory
        self._h(3, "4.1 Edge Device Inventory & Baseline Configuration")
        if snap.sdwan_elements:
            # Build site name lookup
            site_name: dict[str, str] = {
                s.get("id", ""): s.get("name", "") for s in snap.sdwan_sites
            }
            rows = [
                [
                    site_name.get(e.get("site_id", ""), e.get("site_id") or _NA) or _NA,
                    e.get("name") or _NA,
                    e.get("model_name") or _NA,
                    e.get("serial_number") or _NA,
                    e.get("software_version") or e.get("sw_version") or _NA,
                    str(e.get("connected", _NA)),
                    e.get("role") or _NA,
                ]
                for e in snap.sdwan_elements
            ]
            self._table(
                [
                    "Site",
                    "Element Name",
                    "ION Model",
                    "Serial Number",
                    "SW Version",
                    "Connected",
                    "Role",
                ],
                rows,
            )
        else:
            self._table(
                [
                    "Site Name",
                    "ION Model",
                    "Serial Number",
                    "SW Version",
                    "NTP Server",
                    "DNS Server",
                    "DHCP Scope",
                ],
                [[_NA, _NA, _NA, _NA, _NA, _NA, _NA]],
            )

        # 4.2 Underlay WAN Configuration
        self._h(3, "4.2 Underlay WAN Configuration")
        if snap.sdwan_wan_networks:
            # The live wannetworks API never populates provider_as_n, so fall back to
            # the ISP/ASN enrichment already computed for §4.2.1 (snap.sdwan_wan_ips),
            # keyed by matching wan_network name to this network's name. Degrades
            # gracefully to the manual-input stub when no enrichment was run.
            network_isp: dict[str, str] = {}
            for w in snap.sdwan_wan_ips:
                wn = w.get("wan_network")
                if not wn or wn in network_isp:
                    continue
                enr = w.get("enrichment") or []
                if not enr:
                    continue
                isp_str = ", ".join(
                    dict.fromkeys(
                        f"{e.get('isp') or e.get('org') or '—'} ({e.get('asn') or '—'})"
                        for e in enr
                    )
                )
                if isp_str:
                    network_isp[wn] = isp_str
            rows = [
                [
                    n.get("name", _NA),
                    n.get("type", _NA),
                    str(n.get("provider_as_n", ""))
                    or network_isp.get(n.get("name", ""), "")
                    or _NA,
                ]
                for n in snap.sdwan_wan_networks
            ]
            self._table(["Network Name", "Type", "Provider AS"], rows)
            self._p()
        if snap.sdwan_wan_interfaces:
            rows = [
                [
                    i.get("name") or _NA,
                    i.get("type") or _NA,
                    str(i.get("link_bw_up", "")) or _NA,
                    str(i.get("link_bw_down", "")) or _NA,
                    "Yes" if i.get("bwc_enabled") else "No",
                    "Yes" if i.get("lqm_enabled") else "No",
                ]
                for i in snap.sdwan_wan_interfaces
            ]
            self._table(
                ["Interface Name", "Type", "BW Up (Mbps)", "BW Down (Mbps)", "BWC", "LQM"],
                rows,
            )
        else:
            self._table(
                [
                    "Site",
                    "ISP Link",
                    "Circuit Type",
                    "Static IP / DHCP",
                    "Bandwidth (Up/Down)",
                    "LTE Backup",
                ],
                [[_NA, _NA, _NA, _NA, _NA, _NA]],
            )

        # 4.2.1 Live WAN IP Addresses
        self._h(3, "4.2.1 Live WAN IP Addresses")
        if snap.sdwan_wan_ips:
            self._p(
                "_Live-bound IP address per internet/MPLS-facing interface, read from "
                "element interface status (covers both static and DHCP-assigned circuits)._"
            )
            from ..utils.ipenrich import is_rfc1918

            def _fmt_addrs(addrs: list[str], is_public: bool) -> str:
                out = []
                for a in addrs:
                    if is_public and is_rfc1918(a.split("/")[0]):
                        out.append(f"{a} ⚠️ RFC1918")
                    else:
                        out.append(a)
                return ", ".join(out) or "—"

            enriched = any(w.get("enrichment") for w in snap.sdwan_wan_ips)
            rows = []
            drift_notes: list[str] = []
            for w in snap.sdwan_wan_ips:
                is_public = w.get("used_for") == "public"
                v4 = _fmt_addrs(w.get("ipv4_addresses") or [], is_public)
                v6 = _fmt_addrs(w.get("ipv6_addresses") or [], is_public)
                state = w.get("operational_state") or _NA
                state_icon = "✅" if state == "up" else ("❌" if state == "down" else "—")
                circuit = w.get("wan_network") or w.get("circuit_name") or "—"
                row = [
                    w.get("site_name") or _NA,
                    w.get("element_name") or _NA,
                    w.get("interface_name") or _NA,
                    w.get("used_for") or _NA,
                    circuit,
                    w.get("config_type") or _NA,
                    f"{state_icon} {state}",
                    v4,
                    v6,
                ]
                if enriched:
                    enr = w.get("enrichment") or []
                    isp = (
                        ", ".join(
                            f"{e.get('isp') or e.get('org') or '—'} ({e.get('asn') or '—'})"
                            for e in enr
                        )
                        or "—"
                    )
                    geo = (
                        ", ".join(
                            ", ".join(filter(None, [e.get("city"), e.get("country")])) or "—"
                            for e in enr
                        )
                        or "—"
                    )
                    drift = w.get("drift") or []
                    row += [isp, geo, "⚠️" if drift else "—"]
                    for reason in drift:
                        drift_notes.append(
                            f"**{w.get('site_name')} / {w.get('interface_name')}** — {reason}"
                        )
                rows.append(row)
            headers = [
                "Site",
                "Element",
                "Interface",
                "Used For",
                "Circuit / WAN Network",
                "Addressing",
                "State",
                "IPv4 Address(es)",
                "IPv6 Address(es)",
            ]
            if enriched:
                headers += ["Observed ISP (ASN)", "IP Geolocation", "Drift"]
            self._table(headers, rows)
            if drift_notes:
                self._p("**Drift flags** _(advisory — verify circuit patching/labelling)_:")
                for note in drift_notes:
                    self._p(f"- ⚠️ {note}")
        else:
            self._note(
                "No live WAN IP data returned. Either no interfaces are marked "
                "used_for=public/private, or the SD-WAN API session lacks visibility "
                "into interface status. Run `sdwan_wan_ip_summary` directly to check."
            )
        self._p()

        # 4.3 App-Defined Routing
        self._h(3, "4.3 App-Defined Routing (Policy Sets)")
        if snap.sdwan_policy_sets or snap.sdwan_priority_policy_sets:
            if snap.sdwan_policy_sets:
                self._h(4, "Network Policy Sets (Path Selection)")
                rows = [
                    [
                        p.get("name", _NA),
                        p.get("description", "") or "—",
                        "Yes" if p.get("defaultrule_policyset") else "No",
                    ]
                    for p in snap.sdwan_policy_sets
                ]
                self._table(["Policy Set Name", "Description", "Default Rule Set"], rows)
            if snap.sdwan_priority_policy_sets:
                self._h(4, "Priority Policy Sets (QoS)")
                rows = [
                    [p.get("name", _NA), p.get("description", "") or "—"]
                    for p in snap.sdwan_priority_policy_sets
                ]
                self._table(["Policy Set Name", "Description"], rows)
        else:
            self._table(
                ["Policy Name", "Application", "Path Selection", "SLA Class", "QoS Priority"],
                [[_NA, _NA, _NA, _NA, _NA]],
            )

        # 4.4 High Availability
        self._h(3, "4.4 High Availability")
        if snap.sdwan_hub_clusters or snap.sdwan_spoke_clusters:
            site_name = {s.get("id", ""): s.get("name", "") for s in snap.sdwan_sites}
            if snap.sdwan_hub_clusters:
                self._h(4, "Hub Clusters")
                rows = []
                for h in snap.sdwan_hub_clusters:
                    # peer_sites is the SD-WAN API field; members/elements may be null
                    peer_sites = h.get("peer_sites") or []
                    peer_names = (
                        ", ".join(site_name.get(str(ps), str(ps)) for ps in peer_sites) or _NA
                    )
                    site_label = h.get("_queried_site_name") or site_name.get(
                        str(h.get("site_id", "")), _NA
                    )
                    rows.append(
                        [
                            h.get("name", _NA),
                            site_label,
                            str(len(peer_sites)),
                            peer_names,
                        ]
                    )
                self._table(["Cluster Name", "DC Site", "Peer Site Count", "Peer Sites"], rows)
            if snap.sdwan_spoke_clusters:
                self._h(4, "Spoke Clusters")
                rows = []
                for s in snap.sdwan_spoke_clusters:
                    peer_sites = s.get("peer_sites") or []
                    site_label = s.get("_queried_site_name") or site_name.get(
                        str(s.get("site_id", "")), _NA
                    )
                    rows.append(
                        [
                            s.get("name", _NA),
                            site_label,
                            str(len(peer_sites)),
                        ]
                    )
                self._table(["Cluster Name", "Site", "Peer Site Count"], rows)
        else:
            self._table(
                [
                    "Site",
                    "HA Mode",
                    "Primary ION",
                    "Secondary ION",
                    "Failover Trigger",
                    "Failover Time",
                ],
                [[_NA, _NA, _NA, _NA, _NA, _NA]],
            )
        self._p()

    # ── Section 5: SSE & Zero Trust Policies ─────────────────────────────────

    def _section_5(self) -> None:
        snap = self.snap
        self._h(2, "5. Security Service Edge (SSE) & Zero Trust Policies")

        def _rule_str(val: object) -> str:
            """Unwrap SDK enums (e.g. SecurityRuleAction, NatType) to plain strings."""
            if hasattr(val, "value"):
                return str(val.value)
            return str(val) if val is not None else "—"

        # 5.1 Threat Prevention
        self._h(3, "5.1 Threat Prevention (FWaaS)")
        if snap.anti_spyware_profiles:
            rows = [
                [p.get("name", ""), p.get("description", "") or "—"]
                for p in snap.anti_spyware_profiles
            ]
            self._table(["Profile Name", "Description"], rows)
        else:
            self._p("_No anti-spyware profiles found._")

        if snap.vulnerability_profiles:
            self._h(4, "Vulnerability Protection Profiles")
            rows = [
                [p.get("name", ""), p.get("description", "") or "—"]
                for p in snap.vulnerability_profiles
            ]
            self._table(["Profile Name", "Description"], rows)

        if snap.wildfire_profiles:
            self._h(4, "WildFire Profiles")
            rows = [
                [p.get("name", ""), p.get("description", "") or "—"] for p in snap.wildfire_profiles
            ]
            self._table(["Profile Name", "Description"], rows)

        if snap.file_blocking_profiles:
            self._h(4, "File Blocking Profiles")
            rows = [
                [p.get("name", ""), p.get("description", "") or "—"]
                for p in snap.file_blocking_profiles
            ]
            self._table(["Profile Name", "Description"], rows)

        # Security Policy Rulebase — all pre then post rules across all folders
        if snap.all_security_rules:
            self._h(4, "Security Policy Rulebase")
            self._p(
                "Rules are shown in enforcement order: Pre-rules (inherited from Shared "
                "down through the folder hierarchy) before Post-rules. The **Folder** "
                "column shows where each rule is *defined* — rules from `Shared` apply "
                "to all contexts; `Prisma Access` rules apply to PA traffic; `Mobile Users` "
                "and `Remote Networks` rules apply only to those respective contexts."
            )
            rows = []
            for r in snap.security_rules_pre + snap.security_rules_post:
                src_addr = ", ".join((r.get("source") or [])[:2]) or "any"
                dst_addr = ", ".join((r.get("destination") or [])[:2]) or "any"
                apps = ", ".join((r.get("application") or [])[:3]) or "any"
                action = _rule_str(r.get("action"))
                pos = r.get("_position", "—")
                src_folder = r.get("_folder") or r.get("folder") or "—"
                profile_grp = (
                    (r.get("profile_setting") or {}).get("group", [None])[0]
                    if (r.get("profile_setting") or {}).get("group")
                    else "—"
                )
                disabled = " *(disabled)*" if r.get("disabled") else ""
                rows.append(
                    [
                        f"{r.get('name', '—')}{disabled}",
                        pos.capitalize(),
                        src_folder,
                        src_addr,
                        dst_addr,
                        apps,
                        action,
                        profile_grp or "—",
                    ]
                )
            self._table(
                [
                    "Rule Name",
                    "Position",
                    "Defined In",
                    "Source",
                    "Destination",
                    "Applications",
                    "Action",
                    "Security Profile",
                ],
                rows,
            )
            pre_count = len(snap.security_rules_pre)
            post_count = len(snap.security_rules_post)
            self._p(
                f"**{len(snap.all_security_rules)} rules total** "
                f"({pre_count} pre-rules · {post_count} post-rules)"
            )
        else:
            self._h(4, "Security Policy Rulebase")
            self._p("_No security rules found in this folder or its sub-contexts._")

        # NAT Policy Rulebase
        self._h(4, "NAT Policy Rulebase")
        nat_rules = snap.all_nat_rules
        if nat_rules:

            def _nat_translation(r: dict[str, Any]) -> str:
                """Summarise source + destination translation into one compact string."""
                parts: list[str] = []
                src_t_raw = r.get("source_translation")
                src_t = src_t_raw if isinstance(src_t_raw, dict) else {}
                if src_t:
                    if src_t.get("dynamic_ip_and_port"):
                        dip = src_t["dynamic_ip_and_port"]
                        iface = dip.get("interface_address") or {}
                        addrs = dip.get("translated_address") or []
                        if addrs:
                            parts.append(f"SNAT→{', '.join(addrs)}")
                        elif iface.get("interface"):
                            parts.append(f"SNAT→{iface['interface']}")
                        else:
                            parts.append("SNAT dynamic-ip-and-port")
                    elif src_t.get("dynamic_ip"):
                        dip = src_t["dynamic_ip"]
                        addrs = dip.get("translated_address") or []
                        parts.append(
                            f"SNAT dynamic→{', '.join(addrs)}" if addrs else "SNAT dynamic-ip"
                        )
                    elif src_t.get("static_ip"):
                        sip = src_t["static_ip"]
                        addr = sip.get("translated_address", "")
                        bidir = " (bidir)" if sip.get("bi_directional") else ""
                        parts.append(f"SNAT static→{addr}{bidir}")
                dst_t_raw = r.get("destination_translation")
                dst_t = dst_t_raw if isinstance(dst_t_raw, dict) else {}
                if dst_t and (dst_t.get("translated_address") or dst_t.get("translated_port")):
                    addr = dst_t.get("translated_address", "")
                    port = dst_t.get("translated_port", "")
                    dst_str = addr
                    if port:
                        dst_str = f"{addr}:{port}" if addr else f"port→{port}"
                    parts.append(f"DNAT→{dst_str}")
                return " · ".join(parts) if parts else "—"

            rows = []
            for r in nat_rules:
                state = "✗ disabled" if r.get("disabled") else "●"
                from_zones = ", ".join(r.get("from_") or r.get("from") or ["any"])
                to_zones = ", ".join(r.get("to_") or r.get("to") or ["any"])
                sources = ", ".join(r.get("source") or ["any"])
                dests = ", ".join(r.get("destination") or ["any"])
                folder = r.get("_folder") or r.get("folder") or "—"
                pos = r.get("_position", "pre")
                rows.append(
                    [
                        r.get("name", "—"),
                        _rule_str(r.get("nat_type", "ipv4")),
                        f"{from_zones} → {to_zones}",
                        f"{sources} / {dests}",
                        r.get("service") or "any",
                        _nat_translation(r),
                        folder,
                        f"{pos} / {state}",
                    ]
                )
            self._table(
                [
                    "Name",
                    "Type",
                    "From → To Zone",
                    "Source / Dest",
                    "Service",
                    "Translation",
                    "Folder",
                    "Pos / State",
                ],
                rows,
            )
            pre_count = len(snap.nat_rules_pre)
            post_count = len(snap.nat_rules_post)
            self._p(
                f"**{len(nat_rules)} NAT rules** "
                f"({pre_count} pre · {post_count} post). "
                "Prisma Access platform default rules (default, hip-default, optional-default) "
                "are inherited from the 'All' folder and provide baseline NAT behaviour."
            )
        else:
            self._p("_No NAT rules found._")

        # 5.2 SWG
        self._h(3, "5.2 Secure Web Gateway (SWG)")
        if snap.url_access_profiles:
            rows = [
                [p.get("name", ""), p.get("description", "") or "—"]
                for p in snap.url_access_profiles
            ]
            self._table(["URL Access Profile", "Description"], rows)

        if snap.decryption_profiles:
            self._h(4, "SSL/TLS Decryption Profiles")
            rows = [
                [p.get("name", ""), p.get("description", "") or "—"]
                for p in snap.decryption_profiles
            ]
            self._table(["Decryption Profile", "Description"], rows)

        if snap.decryption_rules:
            self._h(4, "Decryption Rules")
            rows = []
            for r in snap.decryption_rules:
                rows.append(
                    [r.get("name", ""), r.get("action", ""), r.get("description", "") or "—"]
                )
            self._table(["Rule Name", "Action", "Description"], rows)

        # 5.3 CASB / DLP
        self._h(3, "5.3 SaaS Security (CASB) & Data Loss Prevention (DLP)")
        self._p(
            "This section documents the as-built DLP posture across two complementary layers: "
            "**SCM inline DLP** (data-filtering-profiles enforced by Prisma Access on network traffic) "
            "and **Enterprise DLP** (ML-based, cloud-native DLP for SaaS apps and Cloud SWG). "
            "Use `dlp_backup` / `dlp_restore` MCP tools to back up and redeploy this configuration "
            "across tenants."
        )
        self._p()

        # ── 5.3.1 SCM Inline DLP ─────────────────────────────────────────────
        self._h(4, "5.3.1 SCM Inline DLP — Data Objects")

        if snap.data_objects:
            rows = []
            for o in snap.data_objects:
                ptype = list(o.get("pattern_type", {}).keys())[0] if o.get("pattern_type") else "—"
                rows.append([o.get("name", "—"), ptype, o.get("description", "") or "—"])
            self._table(["Name", "Pattern Type", "Description"], rows)
        else:
            self._p(
                "_No SCM data objects found. Data objects define regex or predefined patterns "
                "used by data-filtering profiles. Configure via SCM → Security Services → "
                "Data Filtering → Data Objects._"
            )
            self._p()

        self._h(4, "5.3.2 SCM Inline DLP — Data Filtering Profiles")

        if snap.data_filtering_profiles:
            rows = []
            for p in snap.data_filtering_profiles:
                dc = p.get("data_capture") or {}
                rules = dc.get("rules") or []
                patterns = ", ".join(r.get("name", "") for r in rules) or "—"
                alert_thr = dc.get("alert_threshold", "—")
                block_thr = dc.get("block_threshold", "—")
                rows.append(
                    [
                        p.get("name", "—"),
                        p.get("description", "") or "—",
                        patterns,
                        str(alert_thr),
                        str(block_thr),
                    ]
                )
            self._table(
                [
                    "Profile Name",
                    "Description",
                    "Data Patterns",
                    "Alert Threshold",
                    "Block Threshold",
                ],
                rows,
            )
        else:
            self._warn(
                "No SCM data-filtering profiles found in this folder. "
                "Configure DLP profiles via Security Services → Data Filtering in SCM, "
                "then attach them to security rules to inspect data in transit."
            )
            self._table(
                ["Profile Name", "Type", "Data Patterns", "Alert Threshold", "Block Threshold"],
                [[_NA, "Data Filtering", _NA, _NA, _NA]],
            )

        # ── 5.3.3 DLP Rule Coverage ───────────────────────────────────────────
        self._h(4, "5.3.3 DLP Rule Coverage — Security Rules with Data Filtering")
        _dlp_rules = [
            r for r in snap.all_security_rules if (r.get("profile_setting") or {}).get("group")
        ]
        if _dlp_rules:
            rows = []
            for r in _dlp_rules:
                profile_grp = str(
                    r.get("profile_setting", {}).get("group", ["—"])[0]
                    if isinstance(r.get("profile_setting", {}).get("group"), list)
                    else r.get("profile_setting", {}).get("group", "—")
                )
                src = ", ".join(r.get("source", [])[:3]) or "any"
                dst = ", ".join(r.get("destination", [])[:3]) or "any"
                action_str = r.get("action", "—")
                if hasattr(action_str, "value"):
                    action_str = action_str.value
                rows.append([r.get("name", "—"), src, dst, action_str, profile_grp])
            self._table(
                ["Rule Name", "Source", "Destination", "Action", "Security Profile Group"], rows
            )
        else:
            self._p(
                "_No security rules with explicit DLP profile groups found. "
                "To enforce inline DLP, create a security profile group that includes a "
                "data-filtering profile and attach it to the relevant security rules._"
            )
            self._p()

        # ── 5.3.4 Enterprise DLP — overview ──────────────────────────────────
        self._h(4, "5.3.4 Enterprise DLP — Overview")
        _dlp_licensed = bool(
            snap.dlp_company_id
            or snap.dlp_data_patterns
            or snap.dlp_data_profiles
            or snap.dlp_filtering_profiles
        )
        if _dlp_licensed:
            self._p(
                f"Enterprise DLP tenant ID: `{snap.dlp_company_id or '—'}`. "
                f"API: `api.dlp.paloaltonetworks.com/v2/api/`. "
                "No region endpoint is exposed via the API — verify instance region in "
                "**Hub → Enterprise DLP → Settings**."
            )
            self._table(
                ["Resource", "Count"],
                [
                    ["Data Patterns (predefined + custom)", str(len(snap.dlp_data_patterns))],
                    ["Data Profiles", str(len(snap.dlp_data_profiles))],
                    [
                        "Data-Filtering Profiles (policy-linked)",
                        str(len(snap.dlp_filtering_profiles)),
                    ],
                    ["Custom Dictionaries", str(len(snap.dlp_dictionaries))],
                    ["Document Type Classifiers", str(len(snap.dlp_document_types))],
                    ["EDM Datasets", str(len(snap.dlp_edm_datasets))],
                ],
            )
            # OCR settings
            if snap.dlp_ocr_settings:
                ocr_rows = []
                for o in snap.dlp_ocr_settings:
                    svc = o.get("service_name") or "—"
                    enabled = o.get("ocr_enablement")
                    ocr_rows.append([svc, "✓ Enabled" if enabled else "— Not enabled"])
                self._table(["Service", "OCR Enablement"], ocr_rows)
        else:
            self._p(
                "_Enterprise DLP not licensed or not accessible for this tenant. "
                "If licensed, ensure the service account has **DLP Incident Administrator** "
                "or **Superuser** role with Enterprise DLP app access._"
            )
            self._p()

        # ── 5.3.5 Enterprise DLP — Data Patterns ─────────────────────────────
        self._h(4, "5.3.5 Enterprise DLP — Data Patterns")
        if snap.dlp_data_patterns:
            # Show enabled/custom patterns — predefined disabled ones are just catalogue noise
            active = [
                p
                for p in snap.dlp_data_patterns
                if p.get("status") != "disabled" or p.get("type") == "custom"
            ]
            disabled_count = len(snap.dlp_data_patterns) - len(active)
            if disabled_count:
                self._p(
                    f"_{len(snap.dlp_data_patterns)} total patterns ({disabled_count} predefined-disabled hidden)._"
                )
            rows = []
            for p in sorted(
                active, key=lambda x: (0 if x.get("type") == "custom" else 1, x.get("name", ""))
            ):
                technique = (
                    (p.get("detection_config") or {}).get("technique") or p.get("type") or "—"
                )
                tags = p.get("tags") or {}
                geo = ", ".join(tags.get("geography") or []) or "—"
                rows.append(
                    [
                        p.get("name", "—"),
                        p.get("type") or "—",
                        technique,
                        p.get("status") or "—",
                        geo,
                        (p.get("description") or "—")[:60],
                    ]
                )
            self._table(
                ["Pattern Name", "Type", "Technique", "Status", "Geography Tags", "Description"],
                rows,
            )
        elif _dlp_licensed:
            self._p("_No Enterprise DLP data patterns found._")
            self._p()
        else:
            self._warn(
                "Enterprise DLP data patterns not retrieved (not licensed or insufficient permissions). "
                "Ref: https://pan.dev/dlp/api/"
            )

        # ── 5.3.6 Enterprise DLP — Data Profiles ─────────────────────────────
        self._h(4, "5.3.6 Enterprise DLP — Data Profiles")
        if snap.dlp_data_profiles:
            rows = []
            for p in snap.dlp_data_profiles:
                rows.append(
                    [
                        p.get("name", "—"),
                        p.get("id") or p.get("profile_id") or "—",
                        p.get("profile_type") or p.get("type") or "—",
                        p.get("profile_status") or p.get("status") or "active",
                        (p.get("description") or "—")[:60],
                    ]
                )
            self._table(["Profile Name", "ID", "Type", "Status", "Description"], rows)
        elif _dlp_licensed:
            self._p("_No Enterprise DLP data profiles found._")
            self._p()
        else:
            self._p("_Enterprise DLP data profiles not retrieved (see §5.3.4 above)._")
            self._p()

        # ── 5.3.7 Enterprise DLP — Dictionaries & Document Types ─────────────
        if snap.dlp_dictionaries or snap.dlp_document_types:
            self._h(4, "5.3.7 Enterprise DLP — Dictionaries & Document Types")
            if snap.dlp_dictionaries:
                rows = []
                for d in snap.dlp_dictionaries:
                    rows.append(
                        [
                            d.get("name", "—"),
                            d.get("type") or "custom",
                            str(len(d.get("phrases") or d.get("terms") or [])) or "—",
                            (d.get("description") or "—")[:60],
                        ]
                    )
                self._table(["Dictionary Name", "Type", "Terms", "Description"], rows)
            if snap.dlp_document_types:
                rows = []
                for d in snap.dlp_document_types:
                    rows.append(
                        [
                            d.get("name", "—"),
                            (d.get("detection_config") or {}).get("technique") or "ml",
                            d.get("status") or "—",
                            (d.get("description") or "—")[:60],
                        ]
                    )
                self._table(["Document Type", "Technique", "Status", "Description"], rows)

        if snap.dlp_edm_datasets:
            self._h(4, "5.3.8 Enterprise DLP — Exact Data Match (EDM) Datasets")
            rows = []
            for d in snap.dlp_edm_datasets:
                rows.append(
                    [
                        d.get("name", "—"),
                        d.get("status") or "—",
                        str(d.get("record_count") or "—"),
                        (d.get("description") or "—")[:60],
                    ]
                )
            self._table(["Dataset Name", "Status", "Records", "Description"], rows)

        # ── 5.3.x CASB — SaaS Tenant Restrictions ────────────────────────────
        _casb_section = (
            "5.3.9"
            if (snap.dlp_dictionaries or snap.dlp_document_types or snap.dlp_edm_datasets)
            else "5.3.7"
        )
        self._h(4, f"{_casb_section} CASB — SaaS Tenant Restrictions")

        if snap.saas_tenant_restrictions:
            rows = []
            for r in snap.saas_tenant_restrictions:
                apps = ", ".join((r.get("applications") or [])[:5]) or "—"
                rows.append(
                    [
                        r.get("name", "—"),
                        apps,
                        r.get("action", "—"),
                        r.get("description", "") or "—",
                    ]
                )
            self._table(["Policy Name", "Applications", "Action", "Description"], rows)
        else:
            self._warn(
                "No SaaS tenant restrictions configured. "
                "Define sanctioned/unsanctioned application controls in SCM "
                "→ Security Services → SaaS Security."
            )
            self._table(
                ["Policy Name", "Type (Inline/API)", "Applications", "DLP Profile", "Action"],
                [[_NA, _NA, _NA, _NA, _NA]],
            )

        # ── MSSP DLP Management note ──────────────────────────────────────────
        self._note(
            "**MSSP DLP Backup & Redeployment:** Use the `dlp_backup` MCP tool to export "
            "the full DLP configuration (SCM data objects, data-filtering profiles, "
            "Enterprise DLP patterns and profiles) as a JSON backup. "
            "Use `dlp_restore` to provision that configuration on a new tenant/folder. "
            "This enables consistent DLP policies across all MSSP-managed tenants. "
            "Ref: <https://pan.dev/dlp/api/>"
        )

        # ── §5.3.x SSPM ───────────────────────────────────────────────────────
        _sspm_section = (
            "5.3.10"
            if (snap.dlp_dictionaries or snap.dlp_document_types or snap.dlp_edm_datasets)
            else "5.3.8"
        )
        self._h(4, f"{_sspm_section} SaaS Security Posture Management (SSPM)")
        self._p(
            "SSPM continuously monitors onboarded SaaS applications for misconfigurations "
            "and enforces security best practices. It also tracks Non-Human Identities (NHI) "
            "such as service accounts and OAuth tokens, discovers third-party app connections, "
            "and provides AI agent security posture scanning for apps like Microsoft Copilot, "
            "Salesforce Agentforce, and Atlassian Rovo."
        )
        self._p()

        if not snap.sspm_licensed:
            self._p(
                "_SSPM is not reachable or not licensed for this tenant. "
                "The API returned a server error (HTTP 500) or was unavailable during extraction. "
                "Verify the SSPM licence is active at "
                "[hub.paloaltonetworks.com](https://hub.paloaltonetworks.com) "
                "and that the service account has SSPM access. "
                "If licensed, the tenant may need to be provisioned in the SSPM service._"
            )
            self._p()
        elif not snap.sspm_apps:
            self._p(
                "_SSPM is licensed and reachable but **no SaaS applications have been onboarded** "
                "for posture scanning. To onboard applications, navigate to "
                "SaaS Security → Posture Management → Applications in the SCM console._"
            )
            from collections import Counter

            if snap.sspm_catalog:
                verticals = Counter()
                features = Counter()
                for app in snap.sspm_catalog:
                    for v in app.get("verticals") or []:
                        verticals[v] += 1
                    for f in app.get("features") or []:
                        features[f] += 1
                self._table(
                    ["Capability", "Supported App Count"],
                    [
                        ["Total supported apps in catalog", str(len(snap.sspm_catalog))],
                        ["Posture/misconfiguration scanning (SCAN)", str(features.get("SCAN", 0))],
                        ["Non-Human Identity (NHI) tracking", str(features.get("IDENTITY_NHI", 0))],
                        [
                            "User activity monitoring",
                            str(
                                features.get("ACTIVITY", 0)
                                + features.get("IDENTITY_NHI_ACTIVITY", 0)
                            ),
                        ],
                        ["Third-party app discovery", str(features.get("THIRD_PARTY_APPS", 0))],
                        ["AI Agent security scanning", str(features.get("AGENT_SCAN", 0))],
                        ["Automated remediation", str(features.get("REMEDIATE", 0))],
                        ["Risky account detection", str(features.get("RISKY_ACCOUNTS", 0))],
                    ],
                )
                self._note(
                    "**Recommended onboarding targets:** Office 365, Google Workspace, Okta, "
                    "Salesforce, Zoom, Slack Enterprise, GitHub, ServiceNow, Jira, and Microsoft "
                    "Entra ID provide the broadest posture + NHI coverage. AI-enabled apps like "
                    "Microsoft Copilot, ChatGPT Enterprise, and Salesforce Agentforce can also "
                    "be scanned via the AGENT_SCAN capability."
                )
            self._p()
        else:
            from collections import Counter

            total_misconfigs = sum(len(a.get("_configs") or []) for a in snap.sspm_apps)
            self._table(
                ["Metric", "Value"],
                [
                    ["Onboarded SaaS Applications", str(len(snap.sspm_apps))],
                    ["Total Misconfigurations Found", str(total_misconfigs)],
                ],
            )
            # App summary table
            app_rows = []
            for app in snap.sspm_apps:
                name = app.get("display_name") or app.get("app_name") or app.get("name") or "—"
                status = app.get("status") or app.get("connection_status") or "—"
                verticals = ", ".join(app.get("verticals") or []) or "—"
                configs = app.get("_configs") or []
                misconfigs = len(configs)
                critical = sum(
                    1 for c in configs if (c.get("severity") or "").lower() in ("critical", "high")
                )
                app_rows.append([name, status, verticals, str(misconfigs), str(critical)])
            self._table(
                ["Application", "Status", "Verticals", "Misconfigs", "High/Critical"],
                app_rows,
            )
            if total_misconfigs > 0:
                self._warn(
                    f"{total_misconfigs} misconfiguration(s) detected across SSPM-monitored apps. "
                    "Review and remediate via SaaS Security → Posture Management → Findings."
                )

        # ── §5.3.x+1 Identity-SSPM ────────────────────────────────────────────
        _id_sspm_section = (
            "5.3.11"
            if (snap.dlp_dictionaries or snap.dlp_document_types or snap.dlp_edm_datasets)
            else "5.3.9"
        )
        self._h(4, f"{_id_sspm_section} Identity-SSPM — IdP Posture & NHI")
        self._p(
            "Identity-SSPM monitors connected Identity Providers (IdPs) and tracks Non-Human "
            "Identities (NHIs) — service accounts, OAuth tokens, API keys, and machine credentials "
            "that authenticate to SaaS and cloud services. Gaps in IdP posture (e.g. missing MFA "
            "enforcement, dormant accounts, privileged NHIs) are surfaced as security findings."
        )
        self._p()

        if not snap.identity_sspm_licensed:
            self._p(
                "_Identity-SSPM is not provisioned for this tenant. "
                "The API returned HTTP 404 during extraction. "
                "Identity-SSPM is provisioned separately from SSPM posture — verify at "
                "[hub.paloaltonetworks.com](https://hub.paloaltonetworks.com) "
                "that the Identity-SSPM feature is active and the service account has access._"
            )
        elif not snap.identity_sspm_idps:
            self._p(
                "_Identity-SSPM is licensed and reachable but **no IdPs have been connected**. "
                "To connect an IdP for MFA posture and NHI tracking, navigate to "
                "SaaS Security → Identity → Identity Providers in the SCM console._"
            )
            self._table(
                ["Capability", "Description"],
                [
                    ["MFA Gap Detection", "Identify users without MFA enabled per IdP policy"],
                    [
                        "Dormant Account Detection",
                        "Flag inactive accounts not cleaned up after offboarding",
                    ],
                    ["NHI Posture", "Track OAuth tokens, service accounts, and API keys"],
                    ["Privileged Access Review", "Surface over-privileged machine identities"],
                ],
            )
        else:
            rows = []
            for idp in snap.identity_sspm_idps:
                name = idp.get("name") or idp.get("idp_name") or "—"
                idp_type = idp.get("type") or idp.get("idp_type") or "—"
                status = idp.get("status") or idp.get("connection_status") or "—"
                users = idp.get("total_users") or idp.get("user_count") or "—"
                rows.append([name, idp_type, status, str(users)])
            self._table(["IdP Name", "Type", "Status", "Total Users"], rows)
        self._p()

        # 5.4 Zero Trust Network Access — PRA (Secure Agentless Access) + ZTNA Connector
        self._h(3, "5.4 Zero Trust Network Access — Secure Agentless Access (PRA) & ZTNA Connector")

        # Detect PRA licence — snap.licenses is a list of bundles; each bundle has a
        # "licenses" sub-array where app_id = feature code (e.g. "add_pra") and
        # license_type = SKU string (e.g. "NFRPRAPAE").
        def _active_lics(snap_: Any) -> list[dict]:
            from datetime import date as _date

            today = _date.today()
            result = []
            for bundle in getattr(snap_, "licenses", []):
                for lic in bundle.get("licenses", []):
                    exp_raw = lic.get("license_expiration", "")
                    try:
                        # Dates arrive as "YYYY-MM-DD" or "YYYY-MM-DDTHH:MM:SS..."
                        exp_date = _date.fromisoformat(exp_raw[:10])
                        if exp_date >= today:
                            result.append(lic)
                    except Exception:
                        result.append(lic)  # unknown expiry — include it
            return result

        all_lics = _active_lics(snap)

        self._h(4, "Secure Agentless Access (Privileged Remote Access)")
        self._p(
            "Prisma Access **Secure Agentless Access** (formerly Privileged Remote Access / PRA) "
            "provides browser-based, clientless access to infrastructure targets — SSH, RDP, VNC, "
            "and HTTPS web applications — without requiring a GlobalProtect agent on the end-user "
            "device. Access is proxied through Prisma Access and secured by policy, MFA, and "
            "session recording."
        )

        # Check licence table for add_pra
        pra_lic = next((lic for lic in all_lics if lic.get("app_id") == "add_pra"), None)

        if pra_lic:
            self._table(
                ["Item", "Detail"],
                [
                    ["**Status**", "✅ Licensed & Active"],
                    [
                        "**Licence SKU**",
                        f"`add_pra` / `{pra_lic.get('license_type', '—')}` ({pra_lic.get('purchased_size', '—')} seats)",
                    ],
                    ["**Access Method**", "Browser-based agentless (no endpoint agent required)"],
                    ["**Supported Protocols**", "SSH · RDP · VNC · HTTPS web apps"],
                    [
                        "**Configuration**",
                        "Strata Cloud Manager → Remote Access → Secure Agentless Access",
                    ],
                ],
            )
            self._p()
            self._note(
                "PRA application targets, access policies, and session-recording settings are "
                "configured in the SCM portal. Populate the table below with deployed application "
                "definitions once confirmed with the customer."
            )
            self._table(
                [
                    "Application Name",
                    "Target Protocol",
                    "Target Host / IP",
                    "Auth Method",
                    "Session Recording",
                ],
                [[_NA, _NA, _NA, _NA, _NA]],
            )
        else:
            self._warn(
                "Secure Agentless Access (PRA) does not appear to be licensed for this tenant. "
                "Enable via Prisma Access → Remote Access → Secure Agentless Access if required."
            )

        self._h(4, "ZTNA Connector (App Connector VMs)")
        self._p(
            "ZTNA Connector deploys lightweight connector VMs co-located with private applications "
            "in data centres or cloud environments, providing agent-based ZTNA 2.0 access."
        )

        if snap.ztna_connector_groups or snap.ztna_connectors:
            self._h(5, f"Connector Groups ({len(snap.ztna_connector_groups)})")
            if snap.ztna_connector_groups:
                rows = []
                for g in snap.ztna_connector_groups:
                    n_conn = len(g.get("connector_ids", []))
                    rows.append(
                        [
                            g.get("name", "—"),
                            g.get("region", "—"),
                            str(n_conn),
                            g.get("description", "") or "—",
                        ]
                    )
                self._table(["Group Name", "Region", "Connectors", "Description"], rows)

            self._h(5, f"Connectors ({len(snap.ztna_connectors)})")
            if snap.ztna_connectors:
                rows = []
                for c in snap.ztna_connectors:
                    rows.append(
                        [
                            c.get("name", "—"),
                            c.get("status", "—"),
                            c.get("version", "—"),
                            c.get("connector_group_name", "—"),
                            c.get("last_checkin", "—"),
                        ]
                    )
                self._table(["Name", "Status", "Version", "Group", "Last Check-in"], rows)
            else:
                self._p("_No connectors deployed yet._")
        else:
            self._note(
                "ZTNA Connector (app connector VMs) is not currently enabled for this tenant. "
                "If agent-based private app access is required in future, deploy connector agents "
                "in data-centre/cloud segments via Prisma Access → Remote Access → ZTNA Connector."
            )

        # ZTNA security rules — zone-scoped rules across all folder contexts
        ztna_rules = [
            r
            for r in snap.all_security_rules
            if r.get("destination_zones") or r.get("source_zones")
        ]
        if ztna_rules:
            self._h(4, "ZTNA Security Rules")
            rows = []
            for r in ztna_rules[:20]:
                src = ", ".join(r.get("source", [])[:3])
                dst = ", ".join(r.get("destination", [])[:3])
                apps = ", ".join(r.get("application", [])[:3])
                action = _rule_str(r.get("action"))
                profile = str(
                    r.get("profile_setting", {}).get("group", ["—"])[0]
                    if r.get("profile_setting")
                    else "—"
                )
                pos = r.get("_position", "—").capitalize()
                src_folder = r.get("_folder") or r.get("folder") or "—"
                rows.append(
                    [
                        r.get("name", ""),
                        pos,
                        src_folder,
                        src or "any",
                        dst or "any",
                        apps or "any",
                        action,
                        profile,
                    ]
                )
            self._table(
                [
                    "Rule Name",
                    "Position",
                    "Defined In",
                    "Source",
                    "Destination",
                    "Applications",
                    "Action",
                    "Security Profile",
                ],
                rows,
            )
            if len(ztna_rules) > 20:
                self._p(f"_Showing first 20 of {len(ztna_rules)} zone-scoped rules._")
        else:
            self._p("_No zone-scoped security rules found._")

        # 5.5 Prisma Browser / Security Edge Broker (RBI)
        self._h(3, "5.5 Prisma Browser / Security Edge Broker (RBI)")

        # Detect RBI activity: SEB licence OR rbi snippet applied to any folder
        # all_lics was built above in §5.4; safe to reference it here.
        seb_lic = next((lic for lic in all_lics if lic.get("app_id") == "seb"), None)
        # Detect rbi snippet by looking for a security or decryption rule named "rbi"
        rbi_snippet_active = any(
            r.get("name", "").lower() == "rbi"
            for r in list(snap.all_security_rules) + list(getattr(snap, "decryption_rules", []))
        )

        if seb_lic or rbi_snippet_active:
            status_icon = "✅"
            sku_detail = (
                f"`seb` / `{seb_lic.get('license_type', '—')}` ({seb_lic.get('purchased_size', '—')} seats)"
                if seb_lic
                else "—"
            )
            self._table(
                ["Item", "Detail"],
                [
                    ["**Status**", f"{status_icon} Licensed & Active"],
                    ["**Licence SKU**", sku_detail],
                    [
                        "**Traffic Steering**",
                        "`rbi` snippet applied — decryption and security rules active"
                        if rbi_snippet_active
                        else _NA,
                    ],
                    ["**Access Method**", "Browser-based remote isolation via Prisma Access SPN"],
                    ["**Configuration**", "Strata Cloud Manager → Prisma Access Browser"],
                ],
            )
            self._p()

        if (
            snap.browser_device_groups
            or snap.browser_user_groups
            or snap.browser_application_groups
        ):
            if snap.browser_user_groups:
                self._h(4, f"User Groups ({len(snap.browser_user_groups)})")
                rows = [
                    [g.get("name", "—"), g.get("description", "") or "—"]
                    for g in snap.browser_user_groups
                ]
                self._table(["Group Name", "Description"], rows)

            if snap.browser_device_groups:
                self._h(4, f"Device Groups ({len(snap.browser_device_groups)})")
                rows = [
                    [g.get("name", "—"), g.get("description", "") or "—"]
                    for g in snap.browser_device_groups
                ]
                self._table(["Group Name", "Description"], rows)

            if snap.browser_application_groups:
                self._h(4, f"Application Groups ({len(snap.browser_application_groups)})")
                rows = [
                    [g.get("name", "—"), g.get("description", "") or "—"]
                    for g in snap.browser_application_groups
                ]
                self._table(["Group Name", "Description"], rows)
        elif not (seb_lic or rbi_snippet_active):
            self._warn(
                "No Prisma Browser (RBI) configuration found. "
                "If Remote Browser Isolation is required, ensure the Prisma Browser licence "
                "is enabled and configure policies via Strata Cloud Manager "
                "→ Prisma Access Browser."
            )
            self._table(
                ["Component", "Status", "Notes"],
                [
                    ["Prisma Browser Licence", _NA, "Verify in Subscription Service"],
                    ["Device Groups", _NA, "Define managed/unmanaged device groups"],
                    ["User Groups", _NA, "Assign user population to RBI policies"],
                    ["Application Groups", _NA, "Define sanctioned apps for isolation"],
                ],
            )
        else:
            self._note(
                "Prisma Browser device/user group configuration is managed via the Prisma Browser "
                "Management console. Populate this section with defined groups once confirmed "
                "with the customer."
            )
            self._table(
                ["Component", "Status", "Notes"],
                [
                    [
                        "Device Groups",
                        _NA,
                        "Define managed/unmanaged device groups in Prisma Browser",
                    ],
                    ["User Groups", _NA, "Assign user population to RBI policies"],
                    ["Application Groups", _NA, "Define sanctioned apps for isolation"],
                ],
            )

        # PAB-MSP tenant metadata (MSSP multi-tenant Browser provisioning)
        if snap.pab_tenant_regions or snap.pab_tenant_directories or snap.pab_tenant_licenses:
            self._h(4, "PAB-MSP Tenant Provisioning")
            self._p(
                "Prisma Browser MSP (PAB-MSP) provides MSSP-specific management APIs for "
                "multi-tenant Browser deployments, allowing MSPs to inspect per-tenant "
                "provisioning state, directory enrolment, and licence assignments."
            )
            rows: list[list[str]] = []
            if snap.pab_tenant_regions:
                rows.append(["Provisioned Regions", ", ".join(snap.pab_tenant_regions)])
            if snap.pab_tenant_directories:
                rows.append(["Enrolled Directories", ", ".join(snap.pab_tenant_directories)])
            rows.append(["PAB Licences Active", str(len(snap.pab_tenant_licenses))])
            self._table(["Item", "Value"], rows)
            if snap.pab_tenant_licenses:
                lic_rows = []
                for lic in snap.pab_tenant_licenses:
                    lic_rows.append(
                        [
                            lic.get("name") or lic.get("license_name") or "—",
                            str(lic.get("quantity") or lic.get("seats") or "—"),
                            lic.get("status") or "—",
                        ]
                    )
                self._table(["Licence", "Quantity", "Status"], lic_rows)

        self._p()

        # 5.6 Prisma AIRS
        self._h(3, "5.6 Prisma AIRS — AI Runtime Security")
        self._p(
            "Prisma AIRS (AI Runtime Security) provides inline API-based inspection of "
            "prompts and responses for AI applications, protecting against prompt injection, "
            "sensitive data loss, insecure outputs, and AI agentic threats."
        )
        self._p()
        if snap.airs_apps or snap.airs_security_profiles or snap.airs_deployment_profiles:
            if snap.airs_apps:
                self._h(4, f"Customer Applications ({len(snap.airs_apps)})")
                rows = [
                    [
                        a.get("app_name", "—"),
                        a.get("cloud_provider", _NA),
                        a.get("environment", _NA),
                        a.get("ai_agent_framework", _NA),
                        a.get("status", _NA),
                    ]
                    for a in snap.airs_apps
                ]
                self._table(
                    ["App Name", "Cloud Provider", "Environment", "AI Agent Framework", "Status"],
                    rows,
                )

            if snap.airs_security_profiles:
                self._h(4, f"AI Security Profiles ({len(snap.airs_security_profiles)})")
                rows = [
                    [
                        p.get("profile_name", "—"),
                        p.get("profile_id", _NA),
                        str(p.get("revision", _NA)),
                        "✓" if p.get("active") else "✗",
                    ]
                    for p in snap.airs_security_profiles
                ]
                self._table(["Profile Name", "Profile ID", "Revision", "Active"], rows)

            if snap.airs_deployment_profiles:
                self._h(4, f"Deployment Profiles ({len(snap.airs_deployment_profiles)})")
                rows = [
                    [
                        dp.get("dp_name", "—"),
                        dp.get("auth_code", _NA),
                        dp.get("status", _NA),
                        dp.get("expiration_date", _NA),
                    ]
                    for dp in snap.airs_deployment_profiles
                ]
                self._table(["Profile Name", "Auth Code", "Status", "Expiration Date"], rows)
        else:
            self._warn(
                "No Prisma AIRS configuration found. This section is populated when "
                "`include_extended=True` is set and the tenant has a Prisma AIRS licence. "
                "If AIRS is not yet deployed, complete the table below manually."
            )
            self._table(
                ["Component", "Status", "Notes"],
                [
                    ["Prisma AIRS Licence", _NA, "Verify in Subscription Service"],
                    ["Customer Applications", _NA, "AI apps registered for API inspection"],
                    ["AI Security Profiles", _NA, "Prompt injection / data loss rules"],
                    ["Deployment Profiles", _NA, "Inline / async deployment mode"],
                ],
            )
        self._p(
            "> **📎 Reference:** <https://pan.dev/prisma-airs/api/airuntimesecurity/prismaairsmanagementapi/>"
        )
        self._p()

        # 5.7 Traffic Steering Rules
        self._h(3, "5.7 Traffic Steering Rules")
        self._p(
            "Traffic Steering Rules control how Prisma Access routes user traffic — enabling "
            "Direct Internet Access (DIA) for specific traffic categories, backhaul steering "
            "to on-premises firewalls, or split-tunnel overrides on a per-policy basis. "
            "Rules are evaluated before main security policy and can be scoped by user group, "
            "application, or destination."
        )
        self._p()
        if snap.traffic_steering_rules:
            rows = []
            for r in snap.traffic_steering_rules[:30]:
                name = r.get("name") or "—"
                action = r.get("action") or r.get("steering_action") or "—"
                if isinstance(action, dict):
                    action = action.get("steering_preference") or action.get("type") or str(action)
                apps = ", ".join((r.get("applications") or r.get("application") or [])[:3]) or "any"
                folder = r.get("folder") or r.get("snippet") or "—"
                position = r.get("position") or "—"
                rows.append([name, folder, position, apps, str(action)])
            self._table(
                ["Rule Name", "Folder", "Position", "Applications", "Steering Action"], rows
            )
            if len(snap.traffic_steering_rules) > 30:
                self._p(f"_Showing first 30 of {len(snap.traffic_steering_rules)} rules._")
        else:
            self._note(
                "No Traffic Steering Rules are currently configured. "
                "Add rules via Strata Cloud Manager → Security Services → "
                "Traffic Steering if Direct Internet Access or backhaul steering is required."
            )
        self._p()

        # 5.8 App Acceleration
        self._h(3, "5.8 App Acceleration")
        self._p(
            "App Acceleration (add_app_accl) optimises performance for SaaS and cloud-hosted "
            "applications by selecting the fastest Prisma Access path using ADEM telemetry. "
            "Performance improvements (response time, data transfer, user counts) are tracked "
            "via Prisma Access Insights."
        )
        self._p()
        if snap.app_accl_licensed:
            app_count_body = snap.app_accl_stats.get("applications_count", {})
            app_count = (
                app_count_body.get("data", {}).get("count", 0)
                if isinstance(app_count_body, dict)
                else 0
            )
            perf_body = snap.app_accl_stats.get("performance_boost", {})
            perf = (
                perf_body.get("data", {}).get("performance_boost", _NA)
                if isinstance(perf_body, dict)
                else _NA
            )
            users_body = snap.app_accl_stats.get("users_count", {})
            users = (
                users_body.get("data", {}).get("users_count", _NA)
                if isinstance(users_body, dict)
                else _NA
            )
            xfer_body = snap.app_accl_stats.get("total_data_transfer", {})
            xfer = (
                xfer_body.get("data", {}).get("total_data_transfer", _NA)
                if isinstance(xfer_body, dict)
                else _NA
            )
            self._table(
                ["Metric", "Value"],
                [
                    ["Accelerated Applications", str(app_count)],
                    ["Active Users", str(users)],
                    ["Performance Boost", str(perf)],
                    ["Total Data Transfer", str(xfer)],
                ],
            )
            if snap.app_accl_apps:
                rows = []
                for app in snap.app_accl_apps[:20]:
                    app_name = app.get("app_name") or app.get("name") or "—"
                    app_type = app.get("category") or app.get("app_type") or "—"
                    boost = app.get("performance_boost") or app.get("boost") or "—"
                    rows.append([app_name, app_type, str(boost)])
                self._table(["Application", "Category", "Performance Boost"], rows)
        else:
            self._note(
                "App Acceleration is not currently activated on this tenant. "
                "The Insights API returned HTTP 500 during extraction, indicating the "
                "`add_app_accl` add-on is not active. Contact your Palo Alto Networks "
                "account team to enable App Acceleration."
            )
            acc_lic = next(
                (
                    lic
                    for bundle in getattr(snap, "licenses", [])
                    for lic in bundle.get("licenses", [])
                    if lic.get("app_id") == "add_app_accl"
                ),
                None,
            )
            if acc_lic:
                self._table(
                    ["Item", "Detail"],
                    [
                        ["Licence App ID", "`add_app_accl`"],
                        ["Licence Type", acc_lic.get("license_type") or "—"],
                        ["Status", "Licensed but not yet activated (API returns HTTP 500)"],
                    ],
                )
        self._p()

    # ── Section 6: Identity, Context & Endpoint Posture ──────────────────────

    def _section_6(self) -> None:
        snap = self.snap
        self._h(2, "6. Identity, Context & Endpoint Posture")

        # 6.1 CIE
        self._h(3, "6.1 Cloud Identity Engine (CIE)")
        self._warn(
            "CIE configuration is managed at the Strata Cloud Manager tenant level. "
            "Document the IdP connection (Entra ID / Okta / LDAP) and directory sync settings."
        )
        self._table(
            ["Parameter", "Value"],
            [
                ["Identity Provider", _NA],
                ["CIE Tenant ID", _NA],
                ["Directory Sync Method", _NA],
                ["Group Sync Enabled", _NA],
                ["Sync Frequency", _NA],
            ],
        )

        # 6.2 Authentication Profiles
        self._h(3, "6.2 Authentication Profiles")
        if snap.authentication_profiles:
            rows = []
            for ap in snap.authentication_profiles:
                method = ap.get("method", {})
                method_type = list(method.keys())[0] if method else "—"
                mfa = str(
                    ap.get("multi_factor_auth", {}).get("enable", False)
                    if ap.get("multi_factor_auth")
                    else False
                )
                sso = str(
                    ap.get("single_sign_on", {}).get("kerberos_keytab", "")
                    if ap.get("single_sign_on")
                    else "—"
                )
                rows.append(
                    [ap.get("name", ""), method_type, mfa, ap.get("user_domain", "") or "—", sso]
                )
            self._table(["Profile Name", "Method", "MFA Enabled", "User Domain", "SSO"], rows)
        else:
            self._warn("No authentication profiles found in this folder.")

        if snap.saml_server_profiles:
            self._h(4, "SAML IdP Profiles")
            rows = []
            for sp in snap.saml_server_profiles:
                rows.append(
                    [
                        sp.get("name", ""),
                        sp.get("entity_id", ""),
                        sp.get("sso_url", "") or "—",
                        str(sp.get("want_auth_requests_signed", False)),
                        str(sp.get("validate_idp_certificate", False)),
                    ]
                )
            self._table(
                ["Profile Name", "Entity ID", "SSO URL", "Sign Requests", "Validate Cert"], rows
            )

        if snap.radius_server_profiles:
            self._h(4, "RADIUS Server Profiles")
            rows = [
                [p.get("name", ""), p.get("description", "") or "—"]
                for p in snap.radius_server_profiles
            ]
            self._table(["Profile Name", "Description"], rows)

        # 6.3 HIP Checks
        self._h(3, "6.3 Host Information Profile (HIP) Checks")
        if snap.hip_profiles:
            rows = []
            for hp in snap.hip_profiles:
                match_count = len(hp.get("match", []) if isinstance(hp.get("match"), list) else [])
                rows.append(
                    [hp.get("name", ""), hp.get("description", "") or "—", str(match_count)]
                )
            self._table(["HIP Profile", "Description", "Match Rules"], rows)
        else:
            self._p("_No HIP profiles found._")

        if snap.hip_objects:
            self._h(4, "HIP Objects")
            rows = [[o.get("name", ""), o.get("description", "") or "—"] for o in snap.hip_objects]
            self._table(["HIP Object", "Description"], rows)
        self._p()

        # ── 6.4 IoT / OT / Device-ID ────────────────────────────────────────
        self._h(3, "6.4 IoT Security / OT Security (Device-ID)")
        self._p(
            "Palo Alto Networks Enterprise IoT Security (formerly Zingbox) uses ML to "
            "automatically identify and profile every device on the network — IT, IoT, OT/ICS, "
            "medical, and building automation. Device profiles feed directly into Prisma Access "
            "**Device-ID** policy to enforce zero-trust access based on device type and risk."
        )
        self._p()

        if not snap.iot_licensed:
            self._p(
                "_Enterprise IoT Security is **not licensed** for this tenant "
                "(API returned 404 for TSG ID `" + snap.tenant_id + "`). "
                "To enable: license Enterprise IoT Security from the hub and ensure "
                "the service account has IoT Security access._"
            )
            self._p()
        else:
            # ── Summary ──────────────────────────────────────────────────────
            from collections import Counter

            devices = snap.iot_devices
            total = snap.iot_devices_total

            cats = Counter(d.get("category") or "Unknown" for d in devices)
            verticals = Counter(d.get("profile_vertical") or "Unknown" for d in devices)
            risk = Counter(
                d.get("risk_level") or d.get("ml_risk_level") or "Unknown" for d in devices
            )
            epp = Counter(
                d.get("endpoint_protection") or d.get("epp_safety") or "unknown" for d in devices
            )

            self._table(
                ["Metric", "Value"],
                [
                    ["Total Devices Discovered", str(total)],
                    ["Devices Retrieved", str(len(devices))],
                    ["Active Security Alerts", str(snap.iot_alerts_total)],
                    ["IoT Sites", str(len(snap.iot_sites))],
                ],
            )

            # ── Risk Distribution ─────────────────────────────────────────
            if risk:
                self._h(4, "6.4.1 Device Risk Distribution")
                risk_order = ["Critical", "High", "Medium", "Low", "Unknown"]
                risk_rows = [[lvl, str(risk.get(lvl, 0))] for lvl in risk_order if risk.get(lvl)]
                other = {k: v for k, v in risk.items() if k not in risk_order}
                for k, v in sorted(other.items()):
                    risk_rows.append([k, str(v)])
                self._table(["Risk Level", "Device Count"], risk_rows)

            # ── Category & Vertical Breakdown ────────────────────────────
            self._h(4, "6.4.2 Device Category & Vertical Breakdown")
            rows = []
            for cat, count in cats.most_common(20):
                rows.append([cat, str(count)])
            self._table(["Category", "Count"], rows)

            if len(verticals) > 1 or list(verticals.keys()) != ["Unknown"]:
                vert_rows = [[v, str(c)] for v, c in verticals.most_common()]
                self._table(["Industry Vertical", "Count"], vert_rows)

            # ── Endpoint Protection Coverage ──────────────────────────────
            if epp:
                self._h(4, "6.4.3 Endpoint Protection Coverage")
                epp_rows = [[k, str(v)] for k, v in epp.most_common()]
                self._table(["Endpoint Protection Status", "Device Count"], epp_rows)
                unprotected = epp.get("not_protected", 0) + epp.get("none", 0)
                if unprotected:
                    self._warn(
                        f"{unprotected} device(s) have no endpoint protection. "
                        "Consider deploying Cortex XDR or enforcing HIP checks "
                        "to restrict unprotected device access."
                    )

            # ── Profile Inventory (top 20) ────────────────────────────────
            self._h(4, "6.4.4 Device Profile Inventory")
            profiles = Counter(d.get("profile") or "Unknown" for d in devices)
            profile_rows = []
            for profile, count in profiles.most_common(20):
                # find a sample device for this profile
                sample = next(
                    (d for d in devices if (d.get("profile") or "Unknown") == profile), {}
                )
                vertical = sample.get("profile_vertical") or sample.get("profile_type") or "—"
                iot_type = sample.get("profile_type") or "—"
                profile_rows.append([profile, str(count), vertical, iot_type])
            self._table(
                ["Device Profile", "Count", "Vertical", "Profile Type"],
                profile_rows,
            )

            # ── Active Alerts ─────────────────────────────────────────────
            if snap.iot_alerts:
                self._h(4, "6.4.5 Active IoT Security Alerts")
                alert_rows = []
                for a in snap.iot_alerts[:50]:
                    sev = a.get("severity") or a.get("type") or "—"
                    name = a.get("name") or a.get("alertName") or a.get("alert_name") or "—"
                    dev = a.get("deviceid") or a.get("hostname") or "—"
                    profile = a.get("profile") or "—"
                    ts = (a.get("date") or a.get("timestamp") or "—")[:19]
                    alert_rows.append([sev, name, dev, profile, ts])
                self._table(
                    ["Severity", "Alert Name", "Device", "Profile", "Timestamp"],
                    alert_rows,
                )
            else:
                self._p("_No active IoT security alerts._")
                self._p()

            # ── Sites ─────────────────────────────────────────────────────
            if snap.iot_sites:
                self._h(4, "6.4.6 IoT Security Sites")
                site_rows = []
                for s in snap.iot_sites:
                    name = s.get("external_id") or s.get("siteid") or "—"
                    subnets = ", ".join((s.get("subnetsList") or [])[:5])
                    if len(s.get("subnetsList") or []) > 5:
                        subnets += f" (+{len(s['subnetsList']) - 5} more)"
                    site_rows.append([name, subnets])
                self._table(["Site Name", "Subnets"], site_rows)

            # 6.4.7 Vulnerability Posture
            if snap.iot_vulnerabilities is not None:
                self._h(4, "6.4.7 Vulnerability Posture")
                if snap.iot_vulnerabilities:
                    from collections import Counter as _Counter

                    sev_dist: _Counter = _Counter()
                    for v in snap.iot_vulnerabilities:
                        sev = (v.get("severity") or v.get("risk") or "unknown").lower()
                        sev_dist[sev] += 1
                    sev_rows = [[k.capitalize(), str(c)] for k, c in sev_dist.most_common()]
                    self._table(["Severity", "Count"], sev_rows)
                    vuln_rows = []
                    for v in snap.iot_vulnerabilities[:20]:
                        cve = v.get("cve_id") or v.get("cve") or v.get("name") or "—"
                        sev = (v.get("severity") or v.get("risk") or "—").capitalize()
                        devs = v.get("affected_devices") or v.get("device_count") or "—"
                        desc = (v.get("description") or v.get("summary") or "")[:80] or "—"
                        vuln_rows.append([cve, sev, str(devs), desc])
                    self._table(
                        ["CVE / Vuln", "Severity", "Affected Devices", "Description"], vuln_rows
                    )
                    if len(snap.iot_vulnerabilities) > 20:
                        self._p(
                            f"_Showing first 20 of {len(snap.iot_vulnerabilities)} vulnerabilities._"
                        )
                else:
                    self._p("_No active vulnerabilities detected across IoT/OT devices._")

            # 6.4.8 Policy Recommendations
            if snap.iot_policy_recommendations is not None:
                self._h(4, "6.4.8 IoT Policy Recommendations")
                if snap.iot_policy_recommendations:
                    rec_rows = []
                    for rec in snap.iot_policy_recommendations[:20]:
                        name = rec.get("name") or rec.get("policy_name") or "—"
                        action = rec.get("action") or rec.get("rule_action") or "—"
                        devices = rec.get("device_count") or rec.get("devices") or "—"
                        app = (
                            ", ".join((rec.get("applications") or rec.get("apps") or [])[:3]) or "—"
                        )
                        rec_rows.append([name, str(action), str(devices), app])
                    self._table(
                        ["Policy Name", "Recommended Action", "Device Count", "Applications"],
                        rec_rows,
                    )
                    self._note(
                        "These policy recommendations are auto-generated by IoT Security based on "
                        "observed device behaviour. Review and apply via IoT Security → Policy → "
                        "Recommendations to enforce least-privilege access for discovered devices."
                    )
                else:
                    self._p(
                        "_No policy recommendations generated — device behaviour patterns are still learning._"
                    )

            self._note(
                "**Device-ID Policy:** IoT device profiles are automatically available in "
                "Prisma Access security policy via Device-ID. Create security rules that "
                "reference `device-category`, `device-profile`, or `device-vendor` to enforce "
                "least-privilege access for IoT/OT devices — e.g. restrict medical devices to "
                "only the clinical subnets they need. "
                "See: [IoT Security Admin Guide]"
                "(https://docs.paloaltonetworks.com/iot)."
            )
        self._p()

        # 6.5 IAM RBAC Roles
        self._h(3, "6.5 IAM RBAC Roles")
        self._p(
            "_Predefined and custom roles available in this tenant's IAM. "
            "Roles control what each service account or user can read/write via the SCM "
            "and SASE APIs. Ref: [IAM Role API](https://pan.dev/sase/api/iam/)_"
        )
        if snap.iam_roles:
            rows = []
            for role in sorted(snap.iam_roles, key=lambda r: r.get("name", "")):
                n_perms = len(role.get("permissions", []))
                n_ps = len(role.get("permission_sets", []))
                scope_str = (
                    f"{n_perms} permissions, {n_ps} permission-sets" if n_perms or n_ps else "—"
                )
                rows.append(
                    [
                        role.get("name", "—"),
                        role.get("label", "") or "—",
                        scope_str,
                    ]
                )
            self._table(["Role Name", "Label", "Scope Summary"], rows)
        else:
            self._p("_No IAM roles retrieved._")
        self._p()

        # 6.6 IAM Access Policies & Admins
        self._h(3, "6.6 IAM Access Policies & Admins")
        self._p(
            "_Who has access to this tenant and with what role. "
            "Includes human users, federated identities, and service accounts "
            "bound via access policies. "
            "Ref: [IAM Access Policy API](https://pan.dev/sase/api/iam/)_"
        )
        if snap.iam_access_policies or snap.iam_service_accounts:
            if snap.iam_access_policies:
                self._h(4, "Access Policies (Principal → Role → Scope)")
                # Group by principal_type for clarity
                humans = [
                    p
                    for p in snap.iam_access_policies
                    if (p.get("principal_type") or p.get("type") or "").lower()
                    not in ("service_account", "serviceaccount", "service-account")
                ]
                svc = [p for p in snap.iam_access_policies if p not in humans]

                def _policy_rows(policies: list[dict[str, Any]]) -> list[list[str]]:
                    rows = []
                    for p in sorted(policies, key=lambda x: x.get("principal", "")):
                        principal = p.get("principal") or p.get("email") or "—"
                        ptype = p.get("principal_type") or p.get("type") or "User"
                        role = p.get("role") or p.get("role_name") or "—"
                        scope = p.get("resource") or p.get("resource_scope") or "All"
                        rows.append([principal, ptype, role, scope])
                    return rows

                if humans:
                    self._p("**Human / Federated Users**")
                    self._table(
                        ["Principal (Email/ID)", "Type", "Role", "Resource Scope"],
                        _policy_rows(humans),
                    )
                if svc:
                    self._p("**Service Account Policies**")
                    self._table(
                        ["Principal (Email/ID)", "Type", "Role", "Resource Scope"],
                        _policy_rows(svc),
                    )
                self._p(f"_Total access policies: {len(snap.iam_access_policies)}_")
            else:
                self._p("_Access policies not retrieved (requires IAM read permission)._")

            if snap.iam_service_accounts:
                self._h(4, "Registered Service Accounts")
                self._p(
                    "_Service accounts registered in SCM IAM. These are the machine "
                    "identities used by automation, MCP servers, and integrations._"
                )
                rows = []
                for sa in sorted(snap.iam_service_accounts, key=lambda x: x.get("name", "")):
                    name = sa.get("name") or "—"
                    cid = sa.get("client_id") or "—"
                    contact = sa.get("contact_email") or sa.get("description") or "—"
                    created = (sa.get("created_at") or "—")[:10]
                    rows.append([name, f"`{cid}`", contact, created])
                self._table(["Name", "Client ID", "Contact / Purpose", "Created"], rows)
                self._p(f"_Total service accounts: {len(snap.iam_service_accounts)}_")
        else:
            self._p(
                "_Access policies and service accounts not retrieved — "
                "credential does not have IAM read permission (HTTP 403). "
                "Grant the `iam_read` or equivalent role to populate this section._"
            )

    # ── Section 7: Observability & Integrations ───────────────────────────────

    def _section_7(self) -> None:
        snap = self.snap
        self._h(2, "7. Observability, Telemetry & Security Integrations")

        # 7.1 ADEM
        self._h(3, "7.1 Autonomous Digital Experience Management (ADEM)")

        # Agent enable/disable state is captured in GP Agent Profiles (§3.3.5).
        # Live experience scores come from the ADEM Telemetry API (include_adem=True).
        # ADEM monitoring configuration (tested apps, thresholds, groups) has no
        # public API and must be verified manually in the Prisma Access portal.

        def _score_band(s: object) -> str:
            if s is None:
                return "—"
            try:
                v = float(s)  # type: ignore[arg-type]
                if v >= 80:
                    return f"{v:.0f} ✓ Good"
                if v >= 60:
                    return f"{v:.0f} ⚠ Fair"
                return f"{v:.0f} ✗ Poor"
            except (TypeError, ValueError):
                return str(s)

        _adem_tried = snap.adem_app_scores or snap.adem_agent_summary or snap.adem_errors
        if _adem_tried:
            _window_label = (
                "last 3 days" if snap.adem_timerange_used == "last_3_day" else "last 30 days"
            )
            self._p(
                f"Live experience telemetry from the ADEM API "
                f"(`/adem/telemetry/v2`, {_window_label}). "
                "Scores 0–100; ✓ Good ≥80 · ⚠ Fair 60–79 · ✗ Poor <60."
            )
            if snap.adem_timerange_used != "last_3_day":
                self._note(
                    "No ADEM activity in the last 3 days, so this section falls back to "
                    "a 30-day window — typical for lab/low-activity tenants where the "
                    "test user hasn't logged in recently."
                )
            self._p()

            # Agent health summary per endpoint type
            if snap.adem_agent_summary:
                rows = []
                for ep_type, d in snap.adem_agent_summary.items():
                    ep_label = "Mobile Users" if ep_type == "muAgent" else "Remote Networks"
                    clients = d.get("clients") or 0
                    if clients and clients > 0:
                        rows.append(
                            [
                                ep_label,
                                _score_band(d.get("score")),
                                str(clients),
                                str(d.get("clients_good") or "—"),
                                str(d.get("clients_fair") or "—"),
                                str(d.get("clients_poor") or "—"),
                            ]
                        )
                if rows:
                    self._h(4, "Agent Health Summary")
                    self._table(
                        ["Endpoint Type", "Avg Score", "Total Agents", "Good", "Fair", "Poor"],
                        rows,
                    )
                    self._p()

            # App distribution entries
            dist_entries = [e for e in snap.adem_app_scores if e.get("_type") == "distribution"]
            if dist_entries:
                self._h(4, "Application Experience Distribution")
                rows = []
                for e in dist_entries:
                    rows.append(
                        [
                            e.get("app_name", "—"),
                            _score_band(e.get("score")),
                            str(e.get("total_clients") or "—"),
                            str(e.get("clients_good") or "—"),
                            str(e.get("clients_fair") or "—"),
                            str(e.get("clients_poor") or "—"),
                        ]
                    )
                self._table(
                    ["Scope", "Avg Score", "Total Clients", "Good", "Fair", "Poor"],
                    rows,
                )
                self._p()

            # Per-user scores (when agents are connected)
            user_entries = [e for e in snap.adem_app_scores if e.get("_type") == "user"]
            if user_entries:
                self._h(4, "Per-User Experience Scores")
                rows = []
                for e in user_entries[:30]:
                    rows.append(
                        [
                            e.get("app_name", "—"),
                            e.get("ep_label", "—"),
                            _score_band(e.get("score")),
                        ]
                    )
                self._table(["User", "Endpoint Type", "Score"], rows)
                if len(user_entries) > 30:
                    self._p(f"_… {len(user_entries) - 30} more users omitted._")
                self._p()

            if not dist_entries and not user_entries:
                self._p(
                    f"_No ADEM telemetry data for the {_window_label} "
                    "(checked both the 3-day and 30-day windows) — "
                    "no agents were connected or reporting during this period._"
                )

            for err in snap.adem_errors:
                self._warn(err)

            self._note(
                "ADEM monitoring configuration (tested apps, thresholds, groups) is "
                "managed in the **Prisma Access portal → ADEM → Settings** — "
                "no public API exposes this config. Verify and document below manually."
            )
        else:
            # ── include_adem not set — manual placeholder ────────────────────
            self._note(
                "Run with `include_adem=True` to populate this section with live "
                "ADEM experience scores from the Telemetry API (last 3 days). "
                "No extra credentials required — uses the same SCM OAuth token."
            )
            self._warn(
                "ADEM monitoring configuration (tested apps, thresholds, groups) is "
                "managed in the **Prisma Access portal → ADEM → Settings** and has no "
                "public read API. Document below manually."
            )
            self._table(
                [
                    "Profile Name",
                    "Scope",
                    "Endpoints Monitored",
                    "SLA Threshold",
                    "Alert Destination",
                ],
                [[_NA, _NA, _NA, _NA, _NA]],
            )

        # 7.2 CDL
        self._h(3, "7.2 Cortex Data Lake (CDL) / Strata Logging Service")
        self._warn(
            "CDL instance configuration (region, retention, quota) is not available via a "
            "public REST API and must be recorded manually from the Palo Alto Networks hub "
            "console. See footnotes for direct links."
        )
        self._table(
            ["Parameter", "Value"],
            [
                ["CDL Region", _NA],
                ["Log Retention (days)", _NA],
                ["Storage Quota (GB)", _NA],
                ["Activated Subscriptions", _NA],
            ],
        )
        lines = snap.cdl_syslog_profiles or snap.cdl_https_profiles or snap.cdl_email_profiles
        if lines:
            self._h(4, "CDL Log Forwarding Profiles (Live)")
            if snap.cdl_syslog_profiles:
                self._h(5, "Syslog Profiles")
                rows = [
                    [
                        p.get("name", ""),
                        p.get("server", "") or _NA,
                        str(p.get("port", 514)),
                        p.get("transport", _NA),
                        p.get("format", _NA),
                    ]
                    for p in snap.cdl_syslog_profiles
                ]
                self._table(["Profile Name", "Server", "Port", "Transport", "Format"], rows)
            if snap.cdl_https_profiles:
                self._h(5, "HTTPS Profiles")
                rows = [
                    [
                        p.get("name", ""),
                        p.get("uri", "") or _NA,
                        str(p.get("port", 443)),
                        p.get("protocol", _NA),
                    ]
                    for p in snap.cdl_https_profiles
                ]
                self._table(["Profile Name", "URI / Endpoint", "Port", "Protocol"], rows)
            if snap.cdl_email_profiles:
                self._h(5, "Email Profiles")
                rows = [
                    [
                        p.get("name", ""),
                        p.get("gateway", "") or _NA,
                        p.get("from", _NA),
                        p.get("to", _NA),
                    ]
                    for p in snap.cdl_email_profiles
                ]
                self._table(["Profile Name", "Gateway", "From", "To"], rows)
        else:
            self._warn(
                "No CDL log forwarding profiles returned by API — either not configured "
                "or the tenant does not have CDL log forwarding activated."
            )
        self._p("> **📎 Manual Reference Links**")
        self._p(
            "> - CDL instance overview (quota, region, retention): <https://hub.paloaltonetworks.com> → *Cortex Data Lake* → *Settings*"
        )
        self._p(
            "> - Log forwarding setup guide: <https://docs.paloaltonetworks.com/strata-logging-service/administration/forward-logs>"
        )
        self._p("> - SLS API reference: <https://pan.dev/sase/api/log-forwarding/>")
        self._p()

        # 7.3 Log Forwarding
        self._h(3, "7.3 Log Forwarding, SIEM & Syslog Integrations")
        if snap.log_forwarding_profiles:
            rows = [
                [p.get("name", ""), p.get("description", "") or "—"]
                for p in snap.log_forwarding_profiles
            ]
            self._table(["Log Forwarding Profile", "Description"], rows)

        if snap.syslog_profiles:
            self._h(4, "Syslog Destinations")
            rows = []
            for sp in snap.syslog_profiles:
                servers = sp.get("servers", []) or []
                for srv in servers if isinstance(servers, list) else []:
                    rows.append(
                        [
                            sp.get("name", ""),
                            srv.get("name", "") if isinstance(srv, dict) else str(srv),
                            srv.get("server", "") if isinstance(srv, dict) else _NA,
                            str(srv.get("port", 514) if isinstance(srv, dict) else 514),
                            srv.get("transport", "") if isinstance(srv, dict) else _NA,
                            srv.get("format", "") if isinstance(srv, dict) else _NA,
                        ]
                    )
                if not servers:
                    rows.append([sp.get("name", ""), "—", _NA, "514", _NA, _NA])
            if rows:
                self._table(
                    ["Profile", "Server Name", "IP/Hostname", "Port", "Transport", "Format"], rows
                )

        if snap.http_server_profiles:
            self._h(4, "HTTP/CDL Log Forwarding Profiles")
            rows = []
            for hp in snap.http_server_profiles:
                servers = hp.get("server", []) or []
                for srv in servers if isinstance(servers, list) else []:
                    rows.append(
                        [
                            hp.get("name", ""),
                            srv.get("name", "") if isinstance(srv, dict) else "",
                            srv.get("address", "") if isinstance(srv, dict) else _NA,
                            str(srv.get("port", 443) if isinstance(srv, dict) else 443),
                            srv.get("protocol", "") if isinstance(srv, dict) else _NA,
                        ]
                    )
                if not servers:
                    rows.append([hp.get("name", ""), "—", _NA, "443", _NA])
            if rows:
                self._table(["Profile", "Endpoint Name", "Address", "Port", "Protocol"], rows)

        # 7.4 MT Monitor Alerts
        self._h(3, "7.4 MT Monitor — Active Alerts")
        self._p(
            "_MT Monitor alerts surface operational events (tunnel failures, PA node degradation, "
            "license warnings) from `api.sase.paloaltonetworks.com/mt/monitor/v1/agg/alerts`. "
            "Ref: [MT Monitor API](https://pan.dev/sase/api/mt-monitor/)_"
        )
        if snap.mt_monitor_alerts:
            rows = []
            for a in snap.mt_monitor_alerts[:50]:
                sev = a.get("severity") or a.get("type") or "—"
                name = a.get("name") or a.get("alertName") or a.get("event_name") or "—"
                msg = (a.get("message") or a.get("description") or "")[:80] or "—"
                ts = (a.get("timestamp") or a.get("time") or a.get("created_at") or "—")[:19]
                rows.append([sev, name, msg, ts])
            self._table(["Severity", "Alert Name", "Message", "Timestamp"], rows)
            if len(snap.mt_monitor_alerts) > 50:
                self._note(f"{len(snap.mt_monitor_alerts)} total alerts — table shows first 50.")
        else:
            self._p("_No active MT Monitor alerts — tenant is operating normally._")
        self._p()

        # 7.5 SOAR
        self._h(3, "7.5 SOAR & Automated Response")
        self._warn(
            "SOAR integration details (playbooks, webhook endpoints, auto-response rules) "
            "are configured in the SOAR platform and require manual documentation."
        )
        self._table(
            [
                "SOAR Platform",
                "Integration Type",
                "Trigger Event",
                "Automated Action",
                "Playbook Name",
            ],
            [[_NA, _NA, _NA, _NA, _NA]],
        )
        self._p()

    # ── Section 8: Appendices ─────────────────────────────────────────────────

    def _section_8(self) -> None:
        snap = self.snap
        self._h(2, "8. Appendices & Reference Data")

        # 9.1 IP Reference — PA-specific subsections suppressed for SD-WAN-only
        self._h(3, "8.1 Subnets, IP Pools & Public Egress IPs")

        if not self.sdwan_only:
            self._h(4, "Remote Network Subnets (Branch → Prisma Access)")
            if snap.remote_networks:
                rows = []
                for rn in snap.remote_networks:
                    for subnet in rn.get("subnets") or []:
                        rows.append(
                            [rn.get("name", ""), rn.get("region", ""), subnet, "Remote Network"]
                        )
                if rows:
                    self._table(["Site Name", "Region", "Subnet", "Type"], rows)
                else:
                    self._p("_No subnets recorded on Remote Networks._")

            self._h(4, "Service Connection Subnets (DC → Prisma Access)")
            if snap.service_connections:
                rows = []
                for sc in snap.service_connections:
                    for subnet in sc.get("subnets") or []:
                        rows.append(
                            [sc.get("name", ""), sc.get("region", ""), subnet, "Service Connection"]
                        )
                if rows:
                    self._table(["SCN Name", "Region", "Subnet", "Type"], rows)

            self._h(4, "Mobile User IP Pools")
            if snap.mobile_agent_infrastructure:
                rows = []
                for infra in snap.mobile_agent_infrastructure:
                    for pool in infra.get("ip_pools", []):
                        rows.append([infra.get("name", ""), str(pool), "Dynamic"])
                    for pool in infra.get("static_ip_pools", []):
                        rows.append([infra.get("name", ""), str(pool), "Static"])
                if rows:
                    self._table(["Configuration", "IP Pool / Subnet", "Type"], rows)

            self._h(4, "Public Egress IP Addresses (Whitelist Reference)")
        self._p(
            "Sourced from the Prisma Access Allocated IPs API "
            "(`GET /config/v1/infrastructure/allocated-ips`). "
            "These addresses must be whitelisted at customer firewalls, partner networks, "
            "and any destination that enforces source-IP allowlisting."
        )
        self._p()

        # Friendly label map for address_type codes returned by the API
        _ADDR_TYPE_LABELS: dict[str, tuple[str, str]] = {
            "gp_gw_lbs_ips": ("GlobalProtect Gateway", "Mobile Users → internet egress"),
            "gp_portal_lbs_ips": ("GlobalProtect Portal", "Portal IP — client connects here"),
            "sc_lbs_ips": ("Service Connection", "DC/HQ — corporate access node"),
            "rn_lbs_ips": ("Remote Network", "Branch → Prisma Access"),
            "panw_ddns_ips": ("Dynamic DNS", "DDNS hostname resolution IPs"),
            "ipsec_lbs_ips": ("IPSec Endpoint", "IKE/IPSec termination IPs"),
            "mu_n_lbs_ips": ("Mobile Users (N-LBS)", "Mobile Users — northbound LBS"),
        }

        if snap.prisma_egress_ips:
            _via_datapath = any(e.get("_source") == "datapath" for e in snap.prisma_egress_ips)
            if _via_datapath:
                # Datapath API entries have per-IP rows with address_kind + allow_listed
                rows = []
                for entry in snap.prisma_egress_ips:
                    addr_type = entry.get("address_type", "")
                    label, purpose = _ADDR_TYPE_LABELS.get(addr_type, (addr_type or "—", "—"))
                    zone = entry.get("zone", "—")
                    node = entry.get("node_name", "")
                    ips = entry.get("ip_address_list", [])
                    ip_str = ", ".join(str(ip) for ip in ips) if ips else "—"
                    location = f"{zone} / {node}" if node and node != zone else zone
                    addr_kind = entry.get("address_kind", "—") or "—"
                    allow_listed = "Yes" if entry.get("allow_listed") else "No"
                    rows.append([location, label, ip_str, addr_kind, allow_listed, purpose])
                self._table(
                    [
                        "Compute Location / Node",
                        "Service Type",
                        "Public Egress IP",
                        "IP Kind",
                        "PAN-Listed",
                        "Purpose",
                    ],
                    rows,
                )
                self._note(
                    f"**{len(snap.prisma_egress_ips)} egress IP record(s)** retrieved live from "
                    "`POST api.prod.datapath.prismaaccess.com/getPrismaAccessIP/v2`. "
                    "**PAN-Listed = Yes** means the IP is already in PAN's published allowlist. "
                    "Re-run `scm_asbuilt_report` to refresh after infrastructure changes."
                )
            else:
                rows = []
                for entry in snap.prisma_egress_ips:
                    addr_type = entry.get("address_type", "")
                    label, purpose = _ADDR_TYPE_LABELS.get(addr_type, (addr_type or "—", "—"))
                    zone = entry.get("zone", "—")
                    node = entry.get("node_name", "")
                    ips = entry.get("ip_address_list", [])
                    ip_str = ", ".join(str(ip) for ip in ips) if ips else "—"
                    location = f"{zone} / {node}" if node and node != zone else zone
                    rows.append([location, label, ip_str, purpose])
                self._table(
                    ["Compute Location / Node", "Address Type", "Public Egress IPs", "Purpose"],
                    rows,
                )
                self._note(
                    f"**{len(snap.prisma_egress_ips)} IP allocation record(s)** retrieved live from "
                    "`GET /sse/config/v1/infrastructure/allocated-ips`. "
                    "Re-run `scm_asbuilt_report` to refresh after infrastructure changes or new "
                    "compute location deployments."
                )
        else:
            self._warn(
                "Public egress IPs could not be retrieved automatically. "
                "To enable live retrieval, add `prisma_access_api_key` for this tenant in "
                "`.secrets.toml` — obtain the key from the Prisma Access admin portal under "
                "**Settings → Service Setup → Prisma Access API Key**. "
                "Without the key, populate the table below manually."
            )
            self._table(
                [
                    "Compute Location",
                    "Service Type",
                    "Public Egress IP",
                    "IP Kind",
                    "PAN-Listed",
                    "Purpose",
                ],
                [[_NA, _NA, _NA, _NA, _NA, "Whitelist at customer firewalls / partner networks"]],
            )

        # 8.1.4 SD-WAN Detected Public IPs & ISP Attribution
        if snap.sdwan_sites or snap.sdwan_elements:
            self._h(4, "8.1.4 SD-WAN Detected Public IPs & ISP Attribution")
            if snap.sdwan_detected_public_ips:
                self._p(
                    "_Post-NAT public IP per ION element, read from element status "
                    "(`config_and_events_from`) — the address the cloud controller sees the "
                    "element's config/events connection arriving from. This is the real public "
                    "egress IP for branches whose WAN interface itself holds an RFC1918 address "
                    "behind an upstream NAT._"
                )
                configured_by_element: dict[str, list[str]] = {}
                for w in snap.sdwan_wan_ips:
                    if w.get("used_for") != "public":
                        continue
                    configured_by_element.setdefault(w.get("element_id", ""), []).extend(
                        w.get("ipv4_addresses") or []
                    )

                enriched = any(d.get("enrichment") for d in snap.sdwan_detected_public_ips)
                rows = []
                for d in snap.sdwan_detected_public_ips:
                    detected_ip = d.get("detected_public_ip") or ""
                    connected = d.get("connected")
                    status = (
                        "✅ Connected"
                        if connected
                        else ("❌ Disconnected" if connected is False else "—")
                    )
                    configured = configured_by_element.get(d.get("element_id", ""), [])
                    if not detected_ip:
                        match = "—"
                    elif any(detected_ip == c.split("/")[0] for c in configured):
                        match = "✓ matches configured WAN IP"
                    elif configured:
                        match = f"⚠️ NAT/CGNAT — configured circuit shows {', '.join(configured)}"
                    else:
                        match = "—"
                    row = [
                        d.get("site_name") or _NA,
                        d.get("element_name") or _NA,
                        detected_ip or "—",
                        status,
                    ]
                    if enriched:
                        enr = d.get("enrichment") or []
                        isp = (
                            ", ".join(
                                f"{e.get('isp') or e.get('org') or '—'} ({e.get('asn') or '—'})"
                                for e in enr
                            )
                            or "—"
                        )
                        netname = ", ".join(filter(None, (e.get("netname") for e in enr))) or "—"
                        row += [isp, netname]
                    row.append(match)
                    rows.append(row)
                headers = ["Site", "ION", "Detected Public IP", "Status"]
                if enriched:
                    headers += ["Observed ISP (ASN)", "Netname"]
                headers.append("vs Configured WAN IP")
                self._table(headers, rows)
            else:
                self._note(
                    "No detected public IP data returned. Run `sdwan_wan_ip_summary` directly "
                    "to check element status visibility."
                )

        # 9.2 Hardware & License Inventory
        self._h(3, "8.2 Hardware & License Inventory")

        # License type per RN is available from the SCM API — skip for SD-WAN-only
        if not self.sdwan_only and (snap.remote_networks or snap.service_connections):
            self._h(4, "Deployed Connectivity Objects (from SCM)")
            rows = []
            for rn in snap.remote_networks:
                rows.append(
                    [
                        rn.get("name", ""),
                        "Remote Network",
                        rn.get("license_type", "—") or "—",
                        rn.get("region", "—"),
                        rn.get("spn_name", "—") or "—",
                    ]
                )
            for sc in snap.service_connections:
                rows.append(
                    [
                        sc.get("name", ""),
                        "Service Connection",
                        (lambda v: v.value if hasattr(v, "value") else str(v) if v else "—")(
                            sc.get("onboarding_type")
                        ),
                        sc.get("region", "—"),
                        "—",
                    ]
                )
            self._table(["Name", "Type", "License Type / Onboarding", "Region", "SPN"], rows)

        if snap.licenses:
            from datetime import UTC
            from datetime import datetime as _dt

            self._h(4, "Subscription Licences (live — Subscription Service API)")
            _now = _dt.now(UTC)
            _warn_days = 90
            lic_rows: list[list[str]] = []
            _seen_lics: set[tuple[str, str, str]] = set()
            for bundle in snap.licenses:
                for lic in bundle.get("licenses", []):
                    # Normalise expiry to YYYY-MM-DD (first 10 chars) so that
                    # bundles with different time-of-day suffixes don't escape dedup
                    _exp_norm = (lic.get("license_expiration") or "")[:10]
                    _dedup_key = (
                        lic.get("app_id", ""),
                        lic.get("license_type", ""),
                        _exp_norm,
                    )
                    if _dedup_key in _seen_lics:
                        continue
                    _seen_lics.add(_dedup_key)
                    exp_raw = lic.get("license_expiration", "")
                    try:
                        exp_dt = _dt.fromisoformat(exp_raw.replace(" ", "T"))
                        if exp_dt.tzinfo is None:
                            exp_dt = exp_dt.replace(tzinfo=UTC)
                        delta = exp_dt - _now
                        if delta.total_seconds() < 0:
                            status = "❌ Expired"
                        elif delta.days <= _warn_days:
                            status = f"⚠️ {delta.days}d"
                        else:
                            status = "✅ Active"
                        exp_str = exp_dt.strftime("%Y-%m-%d")
                    except Exception:
                        exp_str = exp_raw or "—"
                        status = "—"
                    consumed = lic.get("purchased_size", 0) - (lic.get("remaining_size") or 0)
                    lic_rows.append(
                        [
                            status,
                            lic.get("app_id", "—"),
                            lic.get("license_type", "—"),
                            str(lic.get("purchased_size", "—")),
                            str(consumed),
                            exp_str,
                        ]
                    )
            # Sort: expired first, then by expiry date
            lic_rows.sort(key=lambda r: (0 if "Expired" in r[0] else 1, r[5]))
            self._table(
                ["Status", "Product", "SKU", "Qty", "Consumed", "Expiry"],
                lic_rows,
            )
        else:
            self._note(
                "Subscription licence data not available. "
                "Obtain from: **Customer Support Portal** → support.paloaltonetworks.com → Assets → Subscriptions, "
                "or call `scm_license_info` separately."
            )
            self._table(
                ["Subscription", "SKU", "Qty", "Expiry", "Consumed / Allocated"],
                [
                    [
                        "Prisma Access — Remote Networks",
                        _NA,
                        _NA,
                        _NA,
                        f"{len(snap.remote_networks)} RNs deployed",
                    ],
                    ["Prisma Access — Mobile Users", _NA, _NA, _NA, _NA],
                    [
                        "Prisma Access — Service Connections",
                        _NA,
                        _NA,
                        _NA,
                        f"{len(snap.service_connections)} SCs deployed",
                    ],
                    ["Prisma SD-WAN", _NA, _NA, _NA, _NA],
                    ["WildFire", _NA, _NA, _NA, _NA],
                    ["URL Filtering (PANDB)", _NA, _NA, _NA, _NA],
                    ["Strata Logging Service", _NA, _NA, _NA, _NA],
                ],
            )

        # 8.3 External Dynamic Lists (EDL) Inventory
        self._h(3, "8.3 External Dynamic Lists (EDL) Inventory")
        if snap.edls:
            self._p(
                "_EDLs are used in security policy rules to match traffic against dynamically "
                "updated IP, URL, or domain feeds. PANW predefined feeds are hosted by Palo Alto "
                "Networks and updated automatically. Custom and snippet-based feeds are pulled "
                "from external URLs on a configured schedule. "
                "Ref: [SCM EDL API](https://pan.dev/scm/api/config/objects/external-dynamic-lists/)_"
            )

            def _edl_type_key(e: dict) -> str:
                t = e.get("type")
                if isinstance(t, dict):
                    return next(iter(t), "unknown")
                if hasattr(t, "value"):
                    return t.value
                return ""  # None/null — catalog-only entry, no type

            def _edl_inner(e: dict) -> dict:
                t = e.get("type")
                if isinstance(t, dict):
                    key = next(iter(t), "")
                    inner = t.get(key)
                    return inner if isinstance(inner, dict) else {}
                return {}

            def _edl_url(e: dict) -> str:
                inner = _edl_inner(e)
                return inner.get("url") or inner.get("feed_url") or "—"

            def _edl_refresh(e: dict) -> str:
                inner = _edl_inner(e)
                rec = inner.get("recurring") or {}
                if isinstance(rec, dict) and rec:
                    freq = next(iter(rec), None)
                    if freq:
                        slot = rec.get(freq) or {}
                        at = (
                            slot.get("at") or slot.get("hour") or ""
                            if isinstance(slot, dict)
                            else ""
                        )
                        return f"{freq} @ {at}:00" if at else freq
                return "—"

            def _edl_scope(e: dict) -> str:
                folder = e.get("folder")
                snippet = e.get("snippet")
                parts = []
                if folder:
                    parts.append(f"folder: {folder}")
                if snippet and snippet != "predefined":
                    parts.append(f"snippet: {snippet}")
                elif snippet == "predefined":
                    parts.append("predefined catalog")
                return ", ".join(parts) or "—"

            # Skip raw catalog entries (snippet=predefined, type=None) — they duplicate
            # the activated instances that have full type+folder context.
            active_edls = [e for e in snap.edls if _edl_type_key(e)]

            # Partition: external URL feeds vs PANW predefined IP/URL lists
            ext_feeds = [e for e in active_edls if _edl_type_key(e) in ("ip", "url", "domain")]
            panw_feeds = [e for e in active_edls if _edl_type_key(e).startswith("predefined")]

            _PANW_LABELS = {
                "panw-known-ip-list": "Known malicious IPs (C2, malware distribution, exploit kits)",
                "panw-highrisk-ip-list": "High-risk IPs (threat advisory feeds — not confirmed malicious)",
                "panw-bulletproof-ip-list": "Bulletproof hosting provider IPs (limited content restrictions)",
                "panw-torexit-ip-list": "Tor exit node IPs (anonymous relay infrastructure)",
                "panw-auth-portal-exclude-list": "Authentication portal exclude list (bypass captive portal)",
            }

            if ext_feeds:
                self._h(4, "8.3.1 External URL / IP / Domain Feeds")
                rows = []
                for e in ext_feeds:
                    url = _edl_url(e)
                    url_disp = (url[:68] + "…") if len(url) > 68 else url
                    inner = _edl_inner(e)
                    desc = (inner.get("description") or e.get("description") or "")[:60] or "—"
                    rows.append(
                        [
                            e.get("name", "—"),
                            _edl_type_key(e),
                            url_disp,
                            _edl_refresh(e),
                            _edl_scope(e),
                            desc,
                        ]
                    )
                self._table(
                    ["Name", "Type", "Feed URL", "Refresh", "Scope", "Description"],
                    rows,
                )
                # Note if any are M365 feeds from the office365 snippet
                m365 = [e for e in ext_feeds if "saasedl.paloaltonetworks.com" in _edl_url(e)]
                if m365:
                    self._note(
                        f"{len(m365)} M365 feed(s) sourced from "
                        "`saasedl.paloaltonetworks.com/feeds/m365/` (Office 365 snippet). "
                        "These are referenced in PBF rules for Office 365 split-tunnelling and "
                        "are auto-updated by Palo Alto Networks when Microsoft publishes changes."
                    )

            if panw_feeds:
                self._h(4, "8.3.2 PANW Predefined Threat Intelligence Feeds")
                rows = []
                for e in panw_feeds:
                    feed_ref = _edl_url(e)
                    desc = _PANW_LABELS.get(
                        feed_ref, e.get("display_name") or e.get("description") or "—"
                    )
                    rows.append(
                        [
                            e.get("name", "—"),
                            feed_ref,
                            _edl_scope(e),
                            desc[:80],
                        ]
                    )
                self._table(
                    ["Name", "Feed Reference", "Scope", "Purpose"],
                    rows,
                )
                self._note(
                    "PANW predefined feeds are updated continuously by the Palo Alto Networks "
                    "threat intelligence team. No URL configuration is required — Prisma Access "
                    "resolves the feed reference internally from `updates.paloaltonetworks.com`. "
                    "Reference these in Deny rules to block known-bad IPs at the perimeter."
                )

            if not ext_feeds and not panw_feeds:
                self._p("_No active EDL feeds found in the extracted folder scope._")
            self._p()
        else:
            self._p("_No EDL objects configured in the extracted folder scope._")
        self._p()

        # IKE/IPSec crypto reference — not applicable for SD-WAN-only tenants
        if self.sdwan_only:
            # Still render extraction errors for SD-WAN-only tenants before returning
            if snap.extraction_errors:
                self._h(3, "8.4 Data Extraction Errors")
                self._p(
                    "The following resources could not be retrieved (SDK error or missing permissions):"
                )
                self._p()
                for err in snap.extraction_errors:
                    self._p(f"- `{err}`")
                self._p()
            return

        self._h(3, "8.4 VPN Crypto Profile Reference")

        # Build sets of profile names that are actually referenced
        _used_ike_crypto: set[str] = set()
        for gw in snap.ike_gateways:
            proto = gw.get("protocol") or {}
            for ver in ("ikev2", "ikev1"):
                ref = (proto.get(ver) or {}).get("ike_crypto_profile")
                if ref:
                    _used_ike_crypto.add(ref)

        _used_ipsec_crypto: set[str] = set()
        for tun in snap.ipsec_tunnels:
            ref = (tun.get("auto_key") or {}).get("ipsec_crypto_profile")
            if ref:
                _used_ipsec_crypto.add(ref)

        _active_ike = [p for p in snap.ike_crypto_profiles if p.get("name") in _used_ike_crypto]
        _active_ipsec = [
            p for p in snap.ipsec_crypto_profiles if p.get("name") in _used_ipsec_crypto
        ]

        _show_ike = _active_ike or snap.ike_crypto_profiles
        if _show_ike:
            if not _active_ike:
                self._p("_IKE crypto profiles (none referenced by a configured IKE gateway):_")
            rows = []
            for p in _show_ike:
                dh_raw = p.get("dh_group", [])
                dh = ", ".join(dh_raw) if isinstance(dh_raw, list) else str(dh_raw)
                enc_raw = p.get("encryption", [])
                enc = ", ".join(enc_raw) if isinstance(enc_raw, list) else str(enc_raw)
                hsh_raw = p.get("hash", [])
                hsh = ", ".join(hsh_raw) if isinstance(hsh_raw, list) else str(hsh_raw)
                lt = str(
                    p.get("lifetime", {}).get("hours", "")
                    if isinstance(p.get("lifetime"), dict)
                    else p.get("lifetime", "")
                )
                rows.append([p.get("name", ""), dh, enc, hsh, lt])
            self._table(
                ["IKE Crypto Profile", "DH Group", "Encryption", "Hash", "Lifetime (h)"], rows
            )
        else:
            self._p("_No IKE crypto profiles found._")
            self._p()

        _show_ipsec = _active_ipsec or snap.ipsec_crypto_profiles
        if _show_ipsec:
            self._h(4, "IPSec Crypto Profiles")
            if not _active_ipsec:
                self._p("_IPSec crypto profiles (none referenced by a configured IPSec tunnel):_")

            def _esp_str(p: dict) -> str:
                """Render the esp sub-dict cleanly, handling Pydantic enum values."""
                esp = p.get("esp") or {}
                if not isinstance(esp, dict):
                    return str(esp)
                enc = esp.get("encryption") or []
                auth = esp.get("authentication") or []

                # Each item may be a string or a Pydantic StrEnum — .value always works
                def _val(x: Any) -> str:
                    return x.value if hasattr(x, "value") else str(x)

                enc_str = ", ".join(_val(e) for e in enc) if enc else "—"
                auth_str = ", ".join(_val(a) for a in auth) if auth else "—"
                return f"enc: {enc_str} / auth: {auth_str}"

            def _dh_str(p: dict) -> str:
                dh = p.get("dh_group", "")
                return dh.value if hasattr(dh, "value") else str(dh) if dh else "none"

            rows = []
            for p in _show_ipsec:
                rows.append([p.get("name", ""), _esp_str(p), _dh_str(p)])
            self._table(["IPSec Crypto Profile", "ESP", "PFS DH Group"], rows)

        # Extraction errors — rendered after VPN crypto so numbering is sequential
        if snap.extraction_errors:
            self._h(3, "8.5 Data Extraction Errors")
            self._p(
                "The following resources could not be retrieved (SDK error or missing permissions):"
            )
            self._p()
            for err in snap.extraction_errors:
                self._p(f"- `{err}`")
            self._p()

        # Appendix D — PAN Reference Architecture Library
        self._h(3, "8.6 Appendix D — PAN Reference Architecture Library")
        self._p(
            "The following Palo Alto Networks reference architecture documents, deployment "
            "guides, and blueprints are relevant to this AS-BUILT. Reference architecture diagrams "
            "are in **Appendix F** (§8.7). All documents are publicly accessible without login "
            "unless noted."
        )
        self._p()

        type_labels = {
            "reference_architecture": "🏛️ Reference Architecture",
            "deployment_guide": "🔧 Deployment Guide",
            "design_guide": "📐 Design Guide",
            "admin_doc": "📖 Admin Guide",
            "blog": "📝 Blog / Tech Brief",
            "datasheet": "📄 Datasheet",
        }

        # Group by section relevance
        by_section: dict[str, list[Any]] = {}
        section_order = ["§2", "§3", "§4", "§5", "§6", "§7", "§8"]
        section_labels = {
            "§2": "Architecture Overview",
            "§3": "Prisma Access",
            "§4": "Prisma SD-WAN",
            "§5": "SSE & Zero Trust",
            "§6": "Identity & Endpoint",
            "§7": "Observability",
            "§8": "MSSP / Multi-Tenant",
        }
        for ref in REFERENCE_LIBRARY:
            for sec in ref.sections:
                by_section.setdefault(sec, []).append(ref)

        rows = []
        for sec in section_order:
            for ref in by_section.get(sec, []):
                rows.append(
                    [
                        f"[{ref.title}]({ref.url})",
                        type_labels.get(ref.doc_type, ref.doc_type),
                        section_labels.get(sec, sec),
                    ]
                )
        self._table(["Document", "Type", "AS-BUILT Section"], rows)
        self._p()

        # Appendix E — SCM Commit History
        self._appendix_commit_history()

        # Appendix F — Reference Architecture Diagrams
        self._appendix_reference_diagrams()

    def _appendix_commit_history(self) -> None:
        """Appendix E — SCM configuration change history from job audit log."""
        self._h(3, "8.7 Appendix E — SCM Configuration Change History")
        self._p(
            "The table below shows the last 20 configuration commits recorded in the "
            "SCM job audit log for this tenant. Each row represents a commit or push "
            "job, showing who triggered the change and what it contained."
        )
        self._p()

        jobs = self.jobs
        if not jobs:
            self._note(
                "No SCM job history available. This section is populated automatically "
                "when the AS-BUILT is generated with an active SCM session."
            )
            return

        # Summary stats
        users: set[str] = set()
        dates: list[str] = []
        for j in jobs:
            u = j.get("user", "").strip()
            if u:
                users.add(u)
            ts = j.get("start_ts", "") or j.get("end_ts", "")
            if ts:
                dates.append(str(ts)[:10])

        oldest = min(dates) if dates else "—"
        newest = max(dates) if dates else "—"
        total = len(jobs)
        self._p(
            f"**Summary:** {total} jobs shown | "
            f"**Contributors:** {len(users)} unique user(s) | "
            f"**Period:** {oldest} → {newest}"
        )
        self._p()

        rows = []
        for j in jobs[:20]:
            ts = str(j.get("start_ts", j.get("end_ts", "—")))
            date_str = ts[:19].replace("T", " ") if len(ts) >= 10 else ts
            str(j.get("job_id", ""))
            rows.append(
                [
                    date_str,
                    j.get("user", "—"),
                    j.get("type", "—"),
                    j.get("result", "—"),
                    (j.get("description", "") or "")[:80] or "—",
                ]
            )

        self._table(["Date (UTC)", "User", "Type", "Result", "Description"], rows)
        self._p()

        # Mini change-frequency note
        if len(jobs) >= 20:
            self._note(
                "Only the 20 most recent jobs are shown. "
                "Use `scm_list_jobs` to retrieve additional history."
            )

    def _appendix_reference_diagrams(self) -> None:
        """Appendix F — PAN reference architecture Mermaid diagrams."""
        self._h(3, "8.8 Appendix F — PAN Reference Architecture Diagrams")
        self._p(
            "The diagrams below are the canonical Palo Alto Networks reference architectures "
            "for Prisma SASE, Prisma Access, Prisma SD-WAN, and the MSSP multi-tenant hierarchy. "
            "Use these to compare the AS-IS deployment (§2.1) against the PAN recommended design "
            "and identify architectural gaps."
        )
        self._p()

        # F.1 Enterprise SASE Reference Topology
        self._h(4, "F.1 Enterprise SASE — Secure & Resilient Connectivity Reference Topology")
        self._p(
            "_Canonical Palo Alto Networks Prisma SASE + SD-WAN reference topology. "
            "Source: [Secure and Resilient Enterprise Connectivity RA]"
            "(https://www.paloaltonetworks.com/resources/reference-architectures/"
            "sec-enterprise-connectivity-prisma-sdwan)._"
        )
        self._p(f"```mermaid\n{MERMAID_ENTERPRISE_RA}\n```")
        self._p()

        # F.2 Prisma Access Internal Routing
        self._h(4, "F.2 Prisma Access Internal Routing & Service Connection Architecture")
        self._p(
            "_How traffic flows between Mobile Users, Remote Networks, and the Data Centre "
            "via Prisma Access processing nodes. "
            "Source: [Prisma Access Service Connections Admin Guide]"
            "(https://docs.paloaltonetworks.com/prisma-access/administration/"
            "prisma-access-service-connections/"
            "use-a-service-connection-to-enable-access-between-mobile-users-and-remote-networks)._"
        )
        self._p(f"```mermaid\n{MERMAID_PA_ROUTING}\n```")
        self._p()

        # F.3 SD-WAN Dual-Hub Reference Topology
        self._h(4, "F.3 Prisma SD-WAN — Dual-Hub High Availability Reference Topology")
        self._p(
            "_PAN recommended dual-hub design: up to 4 hubs (on-prem ION DC + Prisma Access "
            "Cloud Nodes). Each branch maintains VPN paths to both hubs for resilience. "
            "Source: [Prisma SD-WAN Branch HA Topologies]"
            "(https://docs.paloaltonetworks.com/prisma/prisma-sd-wan/prisma-sd-wan-admin/"
            "prisma-sd-wan-branch-high-availability/branch-ha-topologies-platforms)._"
        )
        self._p(f"```mermaid\n{MERMAID_SDWAN_DUAL_HUB}\n```")
        self._p()

        # F.4 MSSP Multi-Tenant Hierarchy
        self._h(4, "F.4 Prisma SASE MSSP Multi-Tenant Hierarchy")
        self._p(
            "_Canonical PAN multi-tenant hierarchy for MSSPs: TSP → SP → End Tenant. "
            "Source: [Strata Multitenant Cloud Manager]"
            "(https://docs.paloaltonetworks.com/sase/prisma-sase-multitenant-platform/"
            "access-multitenant-platform) | "
            "[SP Network Attach blog]"
            "(https://www.paloaltonetworks.com/blog/sase/"
            "seamless-service-provider-network-attach-with-prisma-sase/)._"
        )
        self._p(f"```mermaid\n{MERMAID_MSSP_HIERARCHY}\n```")
        self._p()

    # ── Entry point ──────────────────────────────────────────────────────────

    def to_markdown(self) -> str:
        self._lines = []
        self._section_1()  # H1 title + metadata block + §1 Document Control
        self._page_break()
        self._toc()  # Table of Contents
        self._page_break()
        self._exec_summary()  # Executive Summary
        self._page_break()
        self._section_2()
        if not self.sdwan_only:
            # §2b covers PA data-residency topics (WildFire, CDL, SCM region,
            # ATP, CASB) — not applicable for SD-WAN-only deployments.
            self._section_2b()
            self._page_break()
            # §3 / §3b: Prisma Access infrastructure (RNs, SCs, Mobile Users,
            # GlobalProtect, Insights live data) — not applicable.
            self._section_3()
            self._section_3b()
            self._section_3c()
        self._page_break()
        self._section_4()
        if not self.sdwan_only:
            self._page_break()
            # §5: SSE / Zero Trust (security policy, threat prevention,
            # WildFire, URL filtering, ZTNA rules) — not applicable.
            self._section_5()
            self._page_break()
            # §6: Identity & Posture (auth profiles, SAML IdPs, HIP checks)
            # — not applicable for SD-WAN-only tenants.
            self._section_6()
        self._page_break()
        self._section_7()
        self._page_break()
        self._section_8()
        return "\n".join(self._lines)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _nested(obj: dict[str, Any], *keys: str, default: str = "") -> str:
    """Safely traverse nested dict keys."""
    cur: Any = obj
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k)
        if cur is None:
            return default
    return str(cur)
