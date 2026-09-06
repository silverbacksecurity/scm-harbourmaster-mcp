"""
Prisma SD-WAN topology builder.

Uses the Anynet Links API (POST /sdwan/v4.0/api/anynetlinks/query) to retrieve
VPN overlay adjacency between sites. Each anynet link record contains:

  ep1_site_id / ep2_site_id        — the two SD-WAN sites connected
  ep1_wan_interface_id             — WAN circuit on the source side
  admin_up                         — administrative state
  type                             — AUTO-PUBLIC | AUTO-PRIVATE | STATIC

Auth is reused from the prisma-sase SDK session; no re-login needed.
"""

from __future__ import annotations

from typing import Any

from ..utils.logging import get_logger

logger = get_logger(__name__)

_ANYNETLINKS_QUERY_PATH = "/sdwan/v4.0/api/anynetlinks/query"
_VPN_STATUS_PATH = "/sdwan/v2.2/api/vpnlinks/{vid}/status"
_MAX_WORKERS = 10


def _controller(sdk: Any) -> str:
    return str(sdk.controller)


def _session(sdk: Any) -> Any:
    return sdk._session  # noqa: SLF001


def fetch_vpn_link_status(sdk: Any, vpn_link_id: str) -> dict[str, Any]:
    """Fetch health status for a single VPN link ID."""
    url = _controller(sdk) + _VPN_STATUS_PATH.format(vid=vpn_link_id)
    try:
        resp = _session(sdk).get(url)
        if resp.status_code == 200:
            return dict(resp.json())
    except Exception as exc:
        logger.debug("sdwan_vpn_status_failed", vid=vpn_link_id, error=str(exc))
    return {}


def build_topology(
    sdk: Any,
    sites: list[dict[str, Any]],
    wan_interfaces: list[dict[str, Any]],
    wan_networks: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Fetch the full VPN overlay topology and return a list of resolved
    connection records suitable for Mermaid diagram generation.

    Uses POST /sdwan/v4.0/api/anynetlinks/query which returns all site-to-site
    anynet links with ep1_site_id / ep2_site_id directly.

    Each connection record:
    {
        "source_site_id": str,
        "source_site_name": str,
        "source_site_role": str,        # hub | spoke
        "target_site_id": str,
        "target_site_name": str,
        "target_site_role": str,
        "wan_type": str,                # AUTO-PUBLIC | AUTO-PRIVATE
        "wan_network_name": str,
        "vpn_link_ids": [str],
        "status": str,                  # up | down
        "active": bool,
        "usable": bool,
    }
    """
    site_by_id: dict[str, dict[str, Any]] = {s["id"]: s for s in sites if "id" in s}
    wif_by_id: dict[str, dict[str, Any]] = {w["id"]: w for w in wan_interfaces if "id" in w}
    net_by_id: dict[str, str] = {n["id"]: n.get("name", n["id"]) for n in wan_networks if "id" in n}

    logger.info("sdwan_topo_fetch_start", site_count=len(site_by_id))

    # Query all anynet links in one call
    url = _controller(sdk) + _ANYNETLINKS_QUERY_PATH
    anynet_links: list[dict[str, Any]] = []
    try:
        resp = _session(sdk).post(url, json={})
        if resp.status_code == 200:
            body = resp.json() or {}
            anynet_links = body.get("items", [])
            logger.info("sdwan_anynetlinks_query", count=len(anynet_links))
        else:
            logger.warning(
                "sdwan_anynetlinks_query_failed",
                status=resp.status_code,
                body=resp.text[:300],
            )
    except Exception as exc:
        logger.warning("sdwan_anynetlinks_query_error", error=str(exc))

    # De-duplicate (ep1↔ep2 pairs can appear from both directions in status queries)
    seen: set[frozenset[str]] = set()
    connections: list[dict[str, Any]] = []

    for lnk in anynet_links:
        src_site_id = str(lnk.get("ep1_site_id") or "")
        dst_site_id = str(lnk.get("ep2_site_id") or "")
        if not src_site_id or not dst_site_id or src_site_id == dst_site_id:
            continue
        key = frozenset([src_site_id, dst_site_id])
        if key in seen:
            continue
        seen.add(key)

        src_site = site_by_id.get(src_site_id, {})
        dst_site = site_by_id.get(dst_site_id, {})

        # WAN type from ep1 WAN interface
        wif_id = str(lnk.get("ep1_wan_interface_id") or "")
        wif = wif_by_id.get(wif_id, {})
        network_id = wif.get("network_id", "")
        link_type = lnk.get("type", "AUTO-PUBLIC")  # AUTO-PUBLIC | AUTO-PRIVATE | STATIC
        wan_type = "publicwan" if "PUBLIC" in link_type else "privatewan"
        wan_net_name = net_by_id.get(network_id, network_id or wan_type)

        admin_up = bool(lnk.get("admin_up", True))
        status = "up" if admin_up else "down"

        connections.append(
            {
                "source_site_id": src_site_id,
                "source_site_name": src_site.get("name", src_site_id),
                "source_site_role": (src_site.get("element_cluster_role") or "spoke").lower(),
                "target_site_id": dst_site_id,
                "target_site_name": dst_site.get("name", dst_site_id),
                "target_site_role": (dst_site.get("element_cluster_role") or "spoke").lower(),
                "wan_type": wan_type,
                "wan_network_name": wan_net_name,
                "vpn_link_ids": [],
                "status": status,
                "active": admin_up,
                "usable": admin_up,
            }
        )

    logger.info("sdwan_topo_complete", connections=len(connections))
    return connections


def topology_to_mermaid(
    connections: list[dict[str, Any]],
    sites: list[dict[str, Any]],
    wan_networks: list[dict[str, Any]],
    wan_ips: list[dict[str, Any]] | None = None,
) -> str:
    """
    Convert topology connections into a Mermaid graph TB diagram.

    Layout: Hubs at top → WAN clouds in middle → Spokes at bottom

    wan_ips (optional): records from `_extract_sdwan_wan_ips`, used to annotate
    each site node with its live public/private WAN IP address(es).
    """
    if not connections and not sites:
        return ""

    lines: list[str] = ["graph TB"]

    site_by_id = {s["id"]: s for s in sites if "id" in s}

    # site_id -> ["1.2.3.4 (public)", ...] for node-label annotation
    ips_by_site: dict[str, list[str]] = {}
    for rec in wan_ips or []:
        sid = rec.get("site_id")
        addrs = rec.get("ipv4_addresses") or []
        if not sid or not addrs:
            continue
        for addr in addrs:
            ips_by_site.setdefault(sid, []).append(f"{addr} ({rec.get('used_for', '')})")

    # Collect which WAN networks actually appear in connections
    active_wan_nets: dict[str, str] = {}  # network_name → sanitised_id
    for c in connections:
        name = c["wan_network_name"] or c["wan_type"]
        if name not in active_wan_nets:
            san = name.upper().replace(" ", "_").replace("-", "_").replace("/", "_")
            active_wan_nets[name] = f"WAN_{san}"

    # Collect sites, split by role
    hub_ids: list[str] = []
    spoke_ids: list[str] = []
    other_ids: list[str] = []

    all_site_ids: set[str] = {c["source_site_id"] for c in connections} | {
        c["target_site_id"] for c in connections
    }
    for sid in site_by_id:
        all_site_ids.add(sid)

    for sid in all_site_ids:
        site = site_by_id.get(sid, {})
        role = (site.get("element_cluster_role") or "spoke").lower()
        if role == "hub":
            hub_ids.append(sid)
        elif role == "spoke":
            spoke_ids.append(sid)
        else:
            other_ids.append(sid)

    def _site_node(sid: str) -> str:
        site = site_by_id.get(sid, {})
        name = site.get("name", sid)
        addr = site.get("address") or {}
        city = addr.get("city", "") or addr.get("country", "")
        label = f"{name}\n({city})" if city else name
        site_ips = ips_by_site.get(sid)
        if site_ips:
            label += "\n" + "\n".join(site_ips[:2])  # cap at 2 lines to keep nodes readable
        safe_id = sid.replace("-", "_")
        role = (site.get("element_cluster_role") or "spoke").lower()
        icon = "🏭" if role == "hub" else "🏢"
        return f'    {safe_id}["{icon} {label}"]'

    # WAN cloud subgraph (only if there are connections)
    if active_wan_nets:
        lines.append('    subgraph WAN_CLOUD["☁️ WAN Networks"]')
        for net_name, net_id in active_wan_nets.items():
            lines.append(f'        {net_id}["☁️ {net_name}"]')
        lines.append("    end")
        lines.append("")

    # Hub sites subgraph
    if hub_ids:
        lines.append('    subgraph HUBS["🏭 Hub / DC Sites"]')
        for sid in hub_ids:
            lines.append(_site_node(sid))
        lines.append("    end")
        lines.append("")

    # Spoke / branch sites subgraph
    spoke_all = spoke_ids + other_ids
    if spoke_all:
        lines.append('    subgraph BRANCHES["🏢 Branch Sites"]')
        for sid in spoke_all:
            lines.append(_site_node(sid))
        lines.append("    end")
        lines.append("")

    # Edges — route through WAN cloud nodes
    seen_edges: set[tuple[str, str, str]] = set()
    for c in connections:
        src = c["source_site_id"].replace("-", "_")
        dst = c["target_site_id"].replace("-", "_")
        net_id = active_wan_nets.get(c["wan_network_name"] or c["wan_type"], "WAN_OTHER")
        status = c["status"]
        status_icon = "✅" if status == "up" else ("⚠️" if status == "degraded" else "❌")
        label = f"{c['wan_network_name'] or c['wan_type']} · {status_icon}"

        edge1 = (src, net_id, label)
        if edge1 not in seen_edges:
            seen_edges.add(edge1)
            lines.append(f'    {src} -->|"{label}"| {net_id}')

        edge2 = (net_id, dst, label)
        if edge2 not in seen_edges:
            seen_edges.add(edge2)
            lines.append(f'    {net_id} -->|"{label}"| {dst}')

    return "\n".join(lines)
