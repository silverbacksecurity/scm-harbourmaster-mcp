"""
Curated library of Palo Alto Networks publicly available reference architecture
documents, deployment guides, and blueprints for Prisma SASE.

Each entry links to a specific section of the AS-BUILT and provides:
  - title / description
  - public URL (no login required)
  - type: reference_architecture | deployment_guide | design_guide |
           admin_doc | blog | datasheet
  - tags for filtering

Used by AsBuiltReportBuilder to embed "See also" callouts and Appendix D.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class RefDoc:
    title: str
    url: str
    doc_type: str  # reference_architecture | deployment_guide | design_guide | admin_doc | blog | datasheet
    description: str
    sections: tuple[str, ...]  # AS-BUILT sections this doc is relevant to ("all", "§2", "§3", etc.)
    tags: tuple[str, ...] = field(default_factory=tuple)


# ─────────────────────────────────────────────────────────────────────────────
# Reference Architecture Library
# ─────────────────────────────────────────────────────────────────────────────

REFERENCE_LIBRARY: list[RefDoc] = [
    # ── Flagship Enterprise Connectivity RA ───────────────────────────────────
    RefDoc(
        title="Secure and Resilient Enterprise Connectivity Using Prisma SD-WAN and Prisma Access — Design Guide",
        url="https://www.paloaltonetworks.com/resources/guides/sec-enterprise-connectivity-prisma-sdwan-design",
        doc_type="design_guide",
        description=(
            "Canonical design guide for integrating Prisma SD-WAN with Prisma Access. "
            "Covers dynamic path selection, multi-path routing, ION branch devices connecting "
            "to Prisma Access Compute Nodes as SD-WAN hubs (up to 4 hubs), secure internet "
            "access, and Strata Cloud Manager centralisation."
        ),
        sections=("§2", "§3", "§4"),
        tags=("sd-wan", "prisma-access", "enterprise", "flagship"),
    ),
    RefDoc(
        title="Secure and Resilient Enterprise Connectivity Using Prisma SD-WAN and Prisma Access — Deployment Guide",
        url="https://www.paloaltonetworks.com/resources/guides/sec-enterprise-connectivity-prisma-sdwan-deployment",
        doc_type="deployment_guide",
        description=(
            "Step-by-step deployment guide: SD-WAN site onboarding, Prisma Access Service "
            "Connection, Remote Networks, Mobile Users, Secure Internet Access, and "
            "Strata Logging Service integration. 122 pages, Oct 2025."
        ),
        sections=("§3", "§4"),
        tags=("sd-wan", "prisma-access", "deployment", "flagship"),
    ),
    RefDoc(
        title="Secure and Resilient Enterprise Connectivity — Reference Architecture Hub",
        url="https://www.paloaltonetworks.com/resources/reference-architectures/sec-enterprise-connectivity-prisma-sdwan",
        doc_type="reference_architecture",
        description=(
            "Hub page for the full enterprise connectivity reference architecture series "
            "including design, deployment, and solution guides."
        ),
        sections=("§2", "§3", "§4"),
        tags=("sd-wan", "prisma-access", "enterprise", "flagship"),
    ),
    # ── Prisma Access Administration ──────────────────────────────────────────
    RefDoc(
        title="Prisma Access Overview",
        url="https://docs.paloaltonetworks.com/prisma-access/administration/prisma-access-overview",
        doc_type="admin_doc",
        description=(
            "Canonical component definitions: MU-SPN (Mobile User Security Processing Nodes), "
            "RN-SPN (Remote Network SPNs), SC-CAN (Service Connection Corporate Access Nodes), "
            "and their traffic routing relationships."
        ),
        sections=("§2", "§3"),
        tags=("prisma-access", "architecture", "components"),
    ),
    RefDoc(
        title="Prisma Access Remote Networks",
        url="https://docs.paloaltonetworks.com/prisma-access/administration/prisma-access-remote-networks",
        doc_type="admin_doc",
        description=(
            "Fully-meshed Remote Networks configuration. Cloud NGFW auto-deployed per region. "
            "BGP (eBGP to CPE) and static routing. IPSec tunnel setup and BGP peer configuration."
        ),
        sections=("§3",),
        tags=("prisma-access", "remote-networks", "ipsec", "bgp"),
    ),
    RefDoc(
        title="Prisma Access Service Connections",
        url="https://docs.paloaltonetworks.com/prisma-access/administration/prisma-access-service-connections",
        doc_type="admin_doc",
        description=(
            "Service connections act as the mandatory hub for Mobile Users↔Remote Networks "
            "traffic. SC-CANs peer via iBGP internally. "
            "Includes routing between mobile users and remote networks."
        ),
        sections=("§3",),
        tags=("prisma-access", "service-connections", "bgp", "hub-spoke"),
    ),
    RefDoc(
        title="Use a Service Connection to Enable Access Between Mobile Users and Remote Networks",
        url="https://docs.paloaltonetworks.com/prisma-access/administration/prisma-access-service-connections/use-a-service-connection-to-enable-access-between-mobile-users-and-remote-networks",
        doc_type="admin_doc",
        description=(
            "Definitive reference for hub-spoke routing via SC-CAN. Mobile Users form IPSec "
            "tunnels to the nearest SC-CAN. Remote networks peer via iBGP internally with "
            "SC-CANs. Without a Service Connection, mobile users cannot reach remote networks."
        ),
        sections=("§3",),
        tags=("prisma-access", "service-connections", "mobile-users", "remote-networks", "routing"),
    ),
    RefDoc(
        title="Prisma Access Mobile Users",
        url="https://docs.paloaltonetworks.com/prisma-access/administration/prisma-access-mobile-users/enable-mobile-users-to-access-corporate-resources",
        doc_type="admin_doc",
        description=(
            "GlobalProtect agent and clientless VPN configuration for mobile users. "
            "Portal and gateway setup, split/full tunnel, and IP pool allocation."
        ),
        sections=("§3", "§6"),
        tags=("prisma-access", "mobile-users", "globalprotect", "gp"),
    ),
    RefDoc(
        title="Prisma Access Advanced Deployments",
        url="https://docs.paloaltonetworks.com/prisma-access/administration/prisma-access-advanced-deployments",
        doc_type="admin_doc",
        description=(
            "Advanced topology patterns: explicit proxy, Dedicated Service Connections, "
            "ECMP load balancing, and multi-region redundancy."
        ),
        sections=("§3",),
        tags=("prisma-access", "advanced", "ecmp", "redundancy"),
    ),
    # ── Prisma SD-WAN ─────────────────────────────────────────────────────────
    RefDoc(
        title="Prisma SD-WAN Branch High Availability",
        url="https://docs.paloaltonetworks.com/prisma-sd-wan/administration/prisma-sd-wan-branch-high-availability",
        doc_type="admin_doc",
        description=(
            "Branch HA: Active/backup ION pair; fail-to-wire; automatic failover; "
            "one HA group per site, max 2 ION devices; full WAN capacity maintained on failover."
        ),
        sections=("§4",),
        tags=("sd-wan", "ha", "branch", "failover"),
    ),
    RefDoc(
        title="Prisma SD-WAN Branch HA Topologies and Platforms",
        url="https://docs.paloaltonetworks.com/prisma/prisma-sd-wan/prisma-sd-wan-admin/prisma-sd-wan-branch-high-availability/branch-ha-topologies-platforms",
        doc_type="admin_doc",
        description=(
            "Dual-hub topology: up to 4 hubs (any mix of PAN-OS on-prem + Prisma Access "
            "cloud hubs). Branches negotiate VPN to both hubs. Full-mesh, partial-mesh, "
            "and hub-and-spoke VPN topology options."
        ),
        sections=("§4",),
        tags=("sd-wan", "ha", "dual-hub", "topology"),
    ),
    RefDoc(
        title="Prisma SD-WAN Data Center Routing",
        url="https://docs.paloaltonetworks.com/prisma/prisma-sd-wan/prisma-sd-wan-admin/prisma-sd-wan-branch-and-data-center-routing/prisma-sd-wan-data-center-routing",
        doc_type="admin_doc",
        description=(
            "DC routing: BGP and static routes, prefix redistribution, DC ION as SD-WAN hub. "
            "ION devices maintain SD-WAN VPNs for 72 hours if controller is unreachable."
        ),
        sections=("§4",),
        tags=("sd-wan", "dc", "routing", "bgp"),
    ),
    # ── ZTNA ──────────────────────────────────────────────────────────────────
    RefDoc(
        title="Securing Private Applications for Mobile Users Using ZTNA Connector",
        url="https://docs.paloaltonetworks.com/prisma-access/administration/ztna-connector-in-prisma-access",
        doc_type="admin_doc",
        description=(
            "Connector VMs (AWS/GCP/Azure/ESXi/KVM) co-located with private apps → IPSec to "
            "nearest Prisma Access location. Connector Groups for redundancy (up to 4 connectors). "
            "Agentless and agent-based access modes."
        ),
        sections=("§5", "§6"),
        tags=("ztna", "zero-trust", "connector", "private-apps"),
    ),
    RefDoc(
        title="Securing Internet Access for Mobile Users — Tunnel Mode",
        url="https://www.paloaltonetworks.com/resources/reference-architectures",
        doc_type="reference_architecture",
        description=(
            "GlobalProtect + Prisma Access SPN with split or full tunnel. "
            "Canonical reference for mobile user internet security."
        ),
        sections=("§5", "§6"),
        tags=("mobile-users", "internet-access", "swg", "tunnel"),
    ),
    RefDoc(
        title="Zero Trust Network Access 2.0",
        url="https://www.paloaltonetworks.com/sase/ztna",
        doc_type="reference_architecture",
        description=(
            "PAN ZTNA 2.0 principles: continuous trust verification, least-privilege access, "
            "deep and ongoing inspection, security for all apps (cloud-native, private, SaaS)."
        ),
        sections=("§5", "§6"),
        tags=("ztna", "zero-trust", "ztna-2.0"),
    ),
    # ── MSSP / Multi-Tenant ───────────────────────────────────────────────────
    RefDoc(
        title="Strata Multitenant Cloud Manager",
        url="https://docs.paloaltonetworks.com/sase/prisma-sase-multitenant-platform/access-multitenant-platform",
        doc_type="admin_doc",
        description=(
            "Multi-tenant hierarchy: TSP (Tenant Service Provider) → SP (Service Provider) → "
            "End Tenant. Aggregated monitoring, per-tenant and shared interconnect, traffic "
            "isolation per SP, bulk policy deployment, centralised licence/upgrade management."
        ),
        sections=("§8",),
        tags=("mssp", "multi-tenant", "tsp", "sp", "hierarchy"),
    ),
    RefDoc(
        title="Seamless Service Provider Network Attach with Prisma SASE",
        url="https://www.paloaltonetworks.com/blog/sase/seamless-service-provider-network-attach-with-prisma-sase/",
        doc_type="blog",
        description=(
            "Per-SP network attach, SP-level interconnects, multi-SP isolation patterns. "
            "Practical MSSP deployment guidance for Prisma SASE (Feb 2025)."
        ),
        sections=("§8",),
        tags=("mssp", "multi-tenant", "sp", "network-attach"),
    ),
    RefDoc(
        title="Prisma SASE for Managed Service Providers",
        url="https://www.paloaltonetworks.com/resources/datasheets/prisma-sase-for-msps",
        doc_type="datasheet",
        description=(
            "Hierarchical multi-tenancy, single-pane-of-glass dashboard, open APIs, IAM, "
            "scalable API Gateway. Commercial positioning for MSSP."
        ),
        sections=("§8",),
        tags=("mssp", "msp", "datasheet"),
    ),
    # ── Observability ─────────────────────────────────────────────────────────
    RefDoc(
        title="Strata Logging Service (Cloud Delivered Logging)",
        url="https://docs.paloaltonetworks.com/strata-logging-service",
        doc_type="admin_doc",
        description=(
            "Cloud-delivered logging for Prisma Access and NGFW. Log forwarding, "
            "Cortex Data Lake integration, log retention, and query API."
        ),
        sections=("§7",),
        tags=("logging", "cdl", "observability", "cortex"),
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Reference topology Mermaid diagrams
# (canonical PAN recommended patterns — separate from AS-IS config)
# ─────────────────────────────────────────────────────────────────────────────

# Prisma SASE + SD-WAN enterprise reference topology
MERMAID_ENTERPRISE_RA = """\
graph TB
    subgraph PA["☁️ Prisma Access — Security Processing Layer"]
        MU_SPN["MU-SPN\nMobile User Security\nProcessing Node"]
        RN_SPN["RN-SPN\nRemote Network Security\nProcessing Node"]
        SC_CAN["SC-CAN\nService Connection\nCorporate Access Node"]
        MU_SPN <-->|"iBGP internal"| SC_CAN
        RN_SPN <-->|"iBGP internal"| SC_CAN
    end

    subgraph BRANCH["🏢 SD-WAN Branch Sites"]
        ION1["ION Device\n(Branch 1)"]
        ION2["ION Device\n(Branch 2)"]
    end

    subgraph DC["🏭 Data Centre"]
        DC_ION["ION Hub / DC Router"]
        APP["📦 Private Applications"]
        DC_ION --- APP
    end

    MU["💻 Mobile Users\n(GlobalProtect)"]
    INET["🌐 Internet / SaaS"]

    MU -->|"SSL-VPN / IPSec\nGlobalProtect"| MU_SPN
    ION1 -->|"IPSec + BGP\n(Underlay: MPLS / Internet)"| RN_SPN
    ION2 -->|"IPSec + BGP\n(Underlay: MPLS / Internet)"| RN_SPN
    SC_CAN <-->|"IPSec + BGP"| DC_ION
    MU_SPN -->|"Inspected"| INET
    RN_SPN -->|"Inspected"| INET

    SCM["🖥️ Strata Cloud Manager"] -.->|"manages"| PA
    SCM -.->|"manages"| ION1
    SCM -.->|"manages"| ION2"""

# Prisma Access internal routing reference (MU ↔ RN via SC)
MERMAID_PA_ROUTING = """\
graph LR
    MU["💻 Mobile User\nGlobalProtect"] -->|"IPSec / SSL-VPN"| MU_SPN["MU-SPN"]
    RN["🏢 Remote Network\nBranch CPE"] -->|"IPSec + eBGP"| RN_SPN["RN-SPN"]
    ZTNA["🔒 ZTNA Connector VM\n(co-located with app)"] -->|"IPSec auto-tunnel"| MU_SPN
    ZTNA --- APP["📦 Private App"]

    MU_SPN <-->|"iBGP"| SC_CAN["SC-CAN\nService Connection"]
    RN_SPN <-->|"iBGP"| SC_CAN
    SC_CAN <-->|"IPSec + eBGP"| DC["🏭 HQ / Data Centre"]"""

# SD-WAN dual-hub reference topology
MERMAID_SDWAN_DUAL_HUB = """\
graph TB
    subgraph HUB_LAYER["☁️ Hub Layer (up to 4 hubs)"]
        HUB1["🏭 Hub 1 — DC ION\n(PAN-OS on-prem)"]
        HUB2["☁️ Hub 2 — Prisma Access CN\n(Cloud hub)"]
    end

    subgraph BRANCH1["🏢 Branch A"]
        PRI_A["ION Primary\n(Active)"]
        SEC_A["ION Backup\n(HA standby)"]
        PRI_A <-->|"HA sync"| SEC_A
    end

    subgraph BRANCH2["🏢 Branch B"]
        PRI_B["ION Primary"]
    end

    PRI_A -->|"VPN — Internet"| HUB1
    PRI_A -->|"VPN — Internet"| HUB2
    PRI_B -->|"VPN — MPLS"| HUB1
    PRI_B -->|"VPN — Internet"| HUB2"""

# MSSP multi-tenant hierarchy
MERMAID_MSSP_HIERARCHY = """\
graph TD
    TSP["🏛️ TSP — Tenant Service Provider\n(PAN Cloud Infra)"]
    SP1["🏢 SP — Service Provider\n(MSSP / Tier-1 Partner)"]
    SP2["🏢 SP — Another Service Provider"]

    T1["👤 End Tenant A"]
    T2["👤 End Tenant B"]
    T3["👤 End Tenant C"]
    T4["👤 End Tenant D"]

    TSP --> SP1
    TSP --> SP2
    SP1 --> T1
    SP1 --> T2
    SP2 --> T3
    SP2 --> T4

    SCM["🖥️ Strata Cloud Manager\n(Aggregated single-pane view)"] -.->|"manages all"| TSP"""


def get_refs_for_section(section_tag: str) -> list[RefDoc]:
    """Return all reference documents relevant to a given AS-BUILT section tag."""
    return [r for r in REFERENCE_LIBRARY if section_tag in r.sections or "all" in r.sections]


def format_ref_links(refs: list[RefDoc]) -> str:
    """Format a list of RefDocs as a Markdown 'See also' block."""
    if not refs:
        return ""
    lines = ["> **📚 Reference Architecture Docs**"]
    for r in refs:
        icon = {
            "reference_architecture": "🏛️",
            "deployment_guide": "🔧",
            "design_guide": "📐",
            "admin_doc": "📖",
            "blog": "📝",
            "datasheet": "📄",
        }.get(r.doc_type, "🔗")
        lines.append(f"> - {icon} [{r.title}]({r.url})")
    return "\n".join(lines)
