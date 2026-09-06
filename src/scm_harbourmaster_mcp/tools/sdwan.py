"""
MCP tools for Prisma SD-WAN.

Uses the prisma-sase SDK (same service-account credentials as SCM).
All tools gracefully degrade if prisma-sase is not installed or auth fails.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..auth.oauth import get_tenant_meta, list_loaded_tenants
from ..auth.sdwan import get_sdwan_client, safe_items
from ..utils.formatting import format_result as _fmt
from ..utils.logging import get_logger

logger = get_logger(__name__)

# Standalone Leaflet/OSM page; __SITES_JSON__ is replaced with the marker
# data and __TITLE__ with the page title at generation time.
_SITE_MAP_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
  html, body { height: 100%; margin: 0; font-family: system-ui, sans-serif; }
  #map { height: 100%; }
  .legend { background: #fff; padding: 8px 12px; border-radius: 6px;
            box-shadow: 0 1px 4px rgba(0,0,0,.3); font-size: 13px; }
  .legend .dot { display: inline-block; width: 10px; height: 10px;
                 border-radius: 50%; margin-right: 6px; }
  .popup h3 { margin: 0 0 4px; font-size: 14px; }
  .popup ul { margin: 4px 0; padding-left: 18px; }
</style>
</head>
<body>
<div id="map"></div>
<script>
const sites = __SITES_JSON__;
const map = L.map("map");
L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
  maxZoom: 18,
  attribution: "&copy; OpenStreetMap contributors",
}).addTo(map);
const bounds = [];
for (const s of sites) {
  const isHub = ["HUB", "DC"].some((r) => (s.role || "").includes(r));
  const color = isHub ? "#c0392b" : "#2471a3";
  const m = L.circleMarker([s.lat, s.lon], {
    radius: isHub ? 9 : 7, color, fillColor: color, fillOpacity: 0.85,
  }).addTo(map);
  const elems = s.elements.map(
    (e) => `<li>${e.name} (${e.model}) ${e.connected ? "✅" : "❌"}</li>`
  ).join("");
  const circuits = s.circuits.map((c) => `<li>${c}</li>`).join("");
  m.bindPopup(`<div class="popup"><h3>${s.name}</h3>
    <em>${s.role || "branch"}</em><br>${s.address || ""}
    ${elems ? "<b>Elements</b><ul>" + elems + "</ul>" : ""}
    ${circuits ? "<b>Circuits</b><ul>" + circuits + "</ul>" : ""}</div>`);
  m.bindTooltip(s.name);
  bounds.push([s.lat, s.lon]);
}
map.fitBounds(bounds, { padding: [40, 40] });
const legend = L.control({ position: "bottomleft" });
legend.onAdd = () => {
  const div = L.DomUtil.create("div", "legend");
  div.innerHTML = `<span class="dot" style="background:#c0392b"></span>Hub / DC<br>
                   <span class="dot" style="background:#2471a3"></span>Branch`;
  return div;
};
legend.addTo(map);
</script>
</body>
</html>
"""


def register_sdwan_tools(mcp: FastMCP, get_scm_client_credentials: Any) -> None:
    """Register Prisma SD-WAN MCP tools."""

    def _sdwan(tenant_id: str = "") -> Any:
        """Resolve SD-WAN client for a tenant.

        Accepts either the numeric TSG id (looked up in the auth cache) or a
        settings.toml tenant key (e.g. "my-lab-tenant"), so callers don't need
        to know which form the other tools use.
        """
        tid = tenant_id or (list_loaded_tenants() or [""])[0]
        tc = get_tenant_meta(tid)
        if tc is None:
            try:
                from ..config.settings import load_all_tenant_configs

                cfgs = load_all_tenant_configs()
                tc = cfgs.get(tid) or next((c for c in cfgs.values() if c.tenant_id == tid), None)
            except Exception:
                tc = None
        if tc is None:
            raise ValueError(
                f"Tenant {tid!r} is not loaded. Check settings.toml and restart the server."
            )
        return get_sdwan_client(tc)

    def _iso(dt: datetime) -> str:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def _window(hours: int) -> tuple[str, str]:
        now = datetime.now(UTC)
        return _iso(now - timedelta(hours=hours)), _iso(now)

    def _api_error(label: str, resp: Any) -> str:
        """Render a prisma-sase error response as a readable message."""
        code = getattr(resp, "status_code", "?")
        body = (getattr(resp, "text", "") or "")[:300]
        if code == 403:
            return (
                f"{label}: HTTP 403 — the service account's role does not include "
                "this permission (same RBAC class as the known allocated_ips 403; "
                "needs a broader read role, e.g. Insights/monitor read)."
            )
        return f"{label}: HTTP {code} {body}".rstrip()

    def _name_maps(sdk: Any) -> tuple[dict[str, str], dict[str, str]]:
        """Return {site_id: name} and {element_id: name} lookup maps."""
        site_names = {
            s["id"]: s.get("name", s["id"]) for s in safe_items(sdk.get.sites()) if s.get("id")
        }
        elem_names = {
            e["id"]: e.get("name") or e["id"] for e in safe_items(sdk.get.elements()) if e.get("id")
        }
        return site_names, elem_names

    # ── Sites ─────────────────────────────────────────────────────────────────

    @mcp.tool()
    def sdwan_list_sites(tenant_id: str = "", site_id: str = "") -> str:
        """List Prisma SD-WAN sites (branches, data centres, hub sites).

        Returns name, address, geo location (latitude/longitude), site type
        (branch/dc/hub), element count, admin state, and WAN interface count
        for each site.

        Args:
            tenant_id: SCM tenant ID (MSSP mode).
            site_id: Optional specific site ID to fetch.

        Returns:
            JSON array of site objects.
        """
        try:
            sdk = _sdwan(tenant_id)
            resp = sdk.get.sites(site_id=site_id or None)
            sites = safe_items(resp)
            summary = [
                {
                    "id": s.get("id"),
                    "name": s.get("name"),
                    "description": s.get("description", ""),
                    "address": s.get("address", {}),
                    "location": s.get("location", {}),
                    "element_cluster_role": s.get("element_cluster_role"),
                    "service_binding": s.get("service_binding"),
                    "admin_state": s.get("admin_state"),
                    "network_policysetstack_id": s.get("network_policysetstack_id"),
                    "priority_policysetstack_id": s.get("priority_policysetstack_id"),
                }
                for s in sites
            ]
            return _fmt({"total": len(summary), "sites": summary})
        except Exception as exc:
            return f"Error: {exc}"

    # ── Elements (ION devices) ────────────────────────────────────────────────

    @mcp.tool()
    def sdwan_list_elements(
        tenant_id: str = "",
        site_id: str = "",
        element_id: str = "",
    ) -> str:
        """List Prisma SD-WAN ION elements (physical or virtual appliances).

        Returns model, serial, software version, site assignment, HA role,
        and connected state for each element.

        Args:
            tenant_id: SCM tenant ID (MSSP mode).
            site_id: Filter to a specific site ID.
            element_id: Fetch a specific element by ID.

        Returns:
            JSON array of element objects.
        """
        try:
            sdk = _sdwan(tenant_id)
            # Get.elements() only accepts `element_id` — it has no server-side
            # site_id filter, so fetch everything and filter client-side.
            resp = sdk.get.elements(element_id=element_id or None)
            elements = safe_items(resp)
            if site_id:
                elements = [e for e in elements if e.get("site_id") == site_id]
            summary = [
                {
                    "id": e.get("id"),
                    "name": e.get("name"),
                    "site_id": e.get("site_id"),
                    "model_name": e.get("model_name"),
                    "serial_number": e.get("serial_number"),
                    # the elements API names this field software_version
                    "sw_version": e.get("software_version") or e.get("sw_version"),
                    "hw_id": e.get("hw_id"),
                    "admin_state": e.get("admin_state"),
                    "connected": e.get("connected"),
                    "role": e.get("role"),
                    "cluster_insertion_mode": e.get("cluster_insertion_mode"),
                }
                for e in elements
            ]
            return _fmt({"total": len(summary), "elements": summary})
        except Exception as exc:
            return f"Error: {exc}"

    # ── WAN Interfaces ────────────────────────────────────────────────────────

    @mcp.tool()
    def sdwan_list_wan_interfaces(
        tenant_id: str = "",
        site_id: str = "",
        element_id: str = "",
    ) -> str:
        """List Prisma SD-WAN WAN interfaces for a site or element.

        Returns interface name, type (public/private), circuit, bandwidth,
        network label, and link quality for each WAN interface.

        Args:
            tenant_id: SCM tenant ID (MSSP mode).
            site_id: Required — site ID to query.
            element_id: Optional — filter to a specific element.

        Returns:
            JSON array of WAN interface objects.
        """
        try:
            sdk = _sdwan(tenant_id)
            if not site_id:
                return "Error: site_id is required — use sdwan_list_sites to find site IDs"
            resp = sdk.get.waninterfaces(site_id=site_id)
            ifaces = safe_items(resp)
            if element_id:
                ifaces = [i for i in ifaces if i.get("element_id") == element_id]
            summary = [
                {
                    "id": i.get("id"),
                    "name": i.get("name"),
                    "type": i.get("type"),
                    "network_id": i.get("network_id"),
                    "label_id": i.get("label_id"),
                    "bwc_enabled": i.get("bwc_enabled"),
                    "link_bw_down": i.get("link_bw_down"),
                    "link_bw_up": i.get("link_bw_up"),
                    "lqm_enabled": i.get("lqm_enabled"),
                }
                for i in ifaces
            ]
            return _fmt({"site_id": site_id, "total": len(summary), "wan_interfaces": summary})
        except Exception as exc:
            return f"Error: {exc}"

    # ── WAN IP Summary ───────────────────────────────────────────────────────

    @mcp.tool()
    def sdwan_wan_ip_summary(
        tenant_id: str = "",
        site_id: str = "",
        enrich: bool = False,
    ) -> str:
        """Report the live public/private WAN IP address bound to each ION element.

        For every element (or just those at `site_id` if given), inspects each
        interface marked used_for="public" or "private" in its config and reads
        the live-bound IP from the interface's operational status — this covers
        both static and DHCP-assigned WAN circuits, which the config object
        alone cannot show for DHCP. Each record carries the site's configured
        street address and geo location (latitude/longitude).

        Also reports each element's **detected public IP** (`detected_public_ips`
        section): the post-NAT source address the cloud controller sees the
        ION's config/events connection arriving from (element status
        `config_and_events_from`). For branches whose WAN interface holds an
        RFC1918 address behind an upstream NAT, this is the real public egress
        IP — no on-device lookup needed. Caveat: it reflects the circuit the
        controller connection rides (normally the primary internet circuit),
        so a multi-WAN branch shows one NAT IP, not one per circuit.

        With enrich=true, each public WAN IP and detected public IP is
        additionally looked up against an external IP-intelligence provider
        (whatsmyip-style reverse lookup: ISP, organisation, ASN, reverse DNS,
        and IP geolocation) so circuit provider and location can be verified
        against what is configured. Note this sends the tenant's public IPs
        to a third-party service (`ip_enrichment_provider` in settings,
        default ip-api.com) — hence opt-in, never on by default. Lookups are
        cached on disk for 30 days, so repeat runs stay off provider rate
        limits. Enriched records then get advisory `drift` flags: observed
        ISP vs the circuit's configured WAN network / circuit name
        (`wan_network`/`circuit_name`, both now on every record), and IP
        geolocation vs the site's configured coordinates (>500 km flags).

        Use this to populate a WAN IP inventory table/diagram for AS-BUILT
        documentation, or to spot circuits that are down or missing an address.

        Args:
            tenant_id: SCM tenant ID (MSSP mode).
            site_id: Optional — limit to elements at this site.
            enrich: Look up ISP/ASN/rDNS/geo for each public WAN IP.

        Returns:
            JSON with `wan_ips` records ({site_name, site_address, site_location,
            element_name, interface_name, used_for, operational_state,
            ipv4_addresses, ipv6_addresses[, enrichment]}) and
            `detected_public_ips` ({site_name, element_name, detected_public_ip,
            connected[, enrichment]}).
        """
        try:
            from ..audit.extractor import extract_sdwan_detected_public_ips, extract_sdwan_wan_ips

            sdk = _sdwan(tenant_id)
            sites = safe_items(sdk.get.sites())
            elements = safe_items(sdk.get.elements())
            if site_id:
                sites = [s for s in sites if s.get("id") == site_id]
                elements = [e for e in elements if e.get("site_id") == site_id]

            wan_ips, errors = extract_sdwan_wan_ips(sdk, sites, elements)

            site_geo = {
                s.get("id"): {
                    "address": s.get("address") or {},
                    "location": s.get("location") or {},
                }
                for s in sites
                if s.get("id")
            }
            for rec in wan_ips:
                geo = site_geo.get(rec.get("site_id"), {})
                rec["site_address"] = geo.get("address", {})
                rec["site_location"] = geo.get("location", {})

            detected, detected_errors = extract_sdwan_detected_public_ips(sdk, sites, elements)
            errors = errors + detected_errors

            drift_flagged = 0
            if enrich:
                from ..audit.extractor import annotate_wan_ip_drift, enrich_wan_ip_records

                enrich_warnings = enrich_wan_ip_records(
                    wan_ips, ("ipv4_addresses", "ipv6_addresses")
                ) + enrich_wan_ip_records(detected, ("detected_public_ip",))
                errors = errors + [f"enrichment: {w}" for w in enrich_warnings]
                drift_flagged = annotate_wan_ip_drift(wan_ips)

            result: dict[str, Any] = {
                "total": len(wan_ips),
                "wan_ips": wan_ips,
                "detected_public_ips": detected,
            }
            if drift_flagged:
                result["drift_flagged"] = drift_flagged
            if errors:
                result["warnings"] = errors
            return _fmt(result)
        except Exception as exc:
            return f"Error: {exc}"

    # ── WAN Networks & Labels ─────────────────────────────────────────────────

    @mcp.tool()
    def sdwan_list_wan_networks(tenant_id: str = "") -> str:
        """List Prisma SD-WAN WAN networks (ISP circuit definitions).

        Returns network name, type (publicwan/privatewan/lte), and provider info.

        Args:
            tenant_id: SCM tenant ID (MSSP mode).

        Returns:
            JSON array of WAN network objects.
        """
        try:
            sdk = _sdwan(tenant_id)
            resp = sdk.get.wannetworks()
            networks = safe_items(resp)
            labels_resp = sdk.get.waninterfacelabels()
            labels = safe_items(labels_resp)
            return _fmt(
                {
                    "wan_networks": [
                        {
                            "id": n.get("id"),
                            "name": n.get("name"),
                            "type": n.get("type"),
                            "provider_as_n": n.get("provider_as_n"),
                        }
                        for n in networks
                    ],
                    "wan_labels": [
                        {
                            "id": lbl.get("id"),
                            "name": lbl.get("name"),
                            "description": lbl.get("description"),
                        }
                        for lbl in labels
                    ],
                }
            )
        except Exception as exc:
            return f"Error: {exc}"

    # ── Path Groups ───────────────────────────────────────────────────────────

    @mcp.tool()
    def sdwan_list_path_groups(tenant_id: str = "") -> str:
        """List Prisma SD-WAN path groups (circuit groupings for policy selection).

        Args:
            tenant_id: SCM tenant ID (MSSP mode).

        Returns:
            JSON array of path group objects.
        """
        try:
            sdk = _sdwan(tenant_id)
            resp = sdk.get.pathgroups()
            groups = safe_items(resp)
            return _fmt(
                {
                    "total": len(groups),
                    "path_groups": [
                        {
                            "id": g.get("id"),
                            "name": g.get("name"),
                            "description": g.get("description"),
                            "paths": g.get("paths", []),
                        }
                        for g in groups
                    ],
                }
            )
        except Exception as exc:
            return f"Error: {exc}"

    # ── Policies ──────────────────────────────────────────────────────────────

    @mcp.tool()
    def sdwan_list_policies(tenant_id: str = "", policy_type: str = "network") -> str:
        """List Prisma SD-WAN policy sets.

        Args:
            tenant_id: SCM tenant ID (MSSP mode).
            policy_type: 'network' (path selection), 'priority' (QoS),
                         'security' (NGFW), or 'all'.

        Returns:
            JSON policy set summary.
        """
        try:
            sdk = _sdwan(tenant_id)
            result: dict[str, Any] = {}

            pt = policy_type.lower()
            if pt in ("network", "all"):
                resp = sdk.get.networkpolicysets()
                result["network_policy_sets"] = [
                    {
                        "id": p.get("id"),
                        "name": p.get("name"),
                        "description": p.get("description"),
                        "defaultrule_policyset": p.get("defaultrule_policyset"),
                    }
                    for p in safe_items(resp)
                ]
            if pt in ("priority", "all"):
                resp = sdk.get.prioritypolicysets()
                result["priority_policy_sets"] = [
                    {"id": p.get("id"), "name": p.get("name"), "description": p.get("description")}
                    for p in safe_items(resp)
                ]
            if pt in ("security", "all"):
                resp = sdk.get.securitypolicysets()
                result["security_policy_sets"] = [
                    {"id": p.get("id"), "name": p.get("name"), "description": p.get("description")}
                    for p in safe_items(resp)
                ]

            return _fmt(result)
        except Exception as exc:
            return f"Error: {exc}"

    # ── Hub / Spoke Clusters ──────────────────────────────────────────────────

    @mcp.tool()
    def sdwan_list_clusters(tenant_id: str = "") -> str:
        """List Prisma SD-WAN hub and spoke clusters (HA topology).

        Args:
            tenant_id: SCM tenant ID (MSSP mode).

        Returns:
            JSON summary of hub clusters and spoke clusters.
        """
        try:
            sdk = _sdwan(tenant_id)
            _sites = safe_items(sdk.get.sites())
            hubs: list[dict[str, Any]] = []
            spokes: list[dict[str, Any]] = []
            for _s in _sites:
                _sid = _s.get("id")
                if _sid:
                    hubs.extend(safe_items(sdk.get.hubclusters(_sid)))
                    spokes.extend(safe_items(sdk.get.spokeclusters(_sid)))
            return _fmt(
                {
                    "hub_clusters": [
                        {
                            "id": h.get("id"),
                            "name": h.get("name"),
                            "site_id": h.get("site_id"),
                            "members": h.get("members", []),
                        }
                        for h in hubs
                    ],
                    "spoke_clusters": [
                        {
                            "id": s.get("id"),
                            "name": s.get("name"),
                            "site_id": s.get("site_id"),
                            "members": s.get("members", []),
                        }
                        for s in spokes
                    ],
                }
            )
        except Exception as exc:
            return f"Error: {exc}"

    # ── BGP ───────────────────────────────────────────────────────────────────

    @mcp.tool()
    def sdwan_list_bgp(tenant_id: str = "", site_id: str = "", element_id: str = "") -> str:
        """List Prisma SD-WAN BGP configurations and peer status.

        Args:
            tenant_id: SCM tenant ID (MSSP mode).
            site_id: Filter to a specific site.
            element_id: Filter to a specific element.

        Returns:
            JSON BGP configs and peer summary.
        """
        try:
            sdk = _sdwan(tenant_id)
            if site_id and element_id:
                configs_resp = sdk.get.bgpconfigs(site_id=site_id, element_id=element_id)
                peers_resp = sdk.get.bgppeers(site_id=site_id, element_id=element_id)
            else:
                configs_resp = sdk.get.bgpconfigs(site_id=site_id or None, element_id=None)
                peers_resp = sdk.get.bgppeers(site_id=site_id or None, element_id=None)

            configs = safe_items(configs_resp)
            peers = safe_items(peers_resp)
            return _fmt(
                {
                    "bgp_configs": [
                        {
                            "id": c.get("id"),
                            "site_id": c.get("site_id"),
                            "element_id": c.get("element_id"),
                            "local_as_num": c.get("local_as_num"),
                            "router_id": c.get("router_id"),
                            "holdtime": c.get("holdtime"),
                        }
                        for c in configs
                    ],
                    "bgp_peers": [
                        {
                            "id": p.get("id"),
                            "name": p.get("name"),
                            "peer_ip": p.get("peer_ip"),
                            "peer_as_num": p.get("peer_as_num"),
                            "site_id": p.get("site_id"),
                            "admin_state": p.get("admin_state"),
                        }
                        for p in peers
                    ],
                }
            )
        except Exception as exc:
            return f"Error: {exc}"

    # ── VPN Overlay Topology Diagram ─────────────────────────────────────────

    @mcp.tool()
    def sdwan_topology_diagram(tenant_id: str = "", save_to: str = "") -> str:
        """Generate a Mermaid VPN overlay topology diagram for Prisma SD-WAN.

        Queries the SD-WAN controller topology API (POST /sdwan/v3.6/api/topology)
        to retrieve actual VPN adjacency between sites, then fetches per-link
        health status. Outputs a Mermaid graph TB diagram showing:

          - Hub / DC sites and branch sites as subgraph nodes
          - WAN cloud networks (Internet, MPLS, LTE) as intermediate cloud nodes
          - VPN tunnel edges with circuit type and UP/DOWN/degraded status icons
            ✅ UP  ⚠️ degraded  ❌ down

        Suitable for embedding directly in GitHub Markdown, Confluence, or the
        Prisma SASE AS-BUILT (Section 4).

        Args:
            tenant_id: SCM tenant ID (MSSP mode).
            save_to: Optional file path to write the diagram to (e.g. topology.md).

        Returns:
            Mermaid diagram as a fenced code block string.
        """
        try:
            from ..audit.extractor import extract_sdwan_wan_ips
            from ..audit.sdwan_topo import build_topology, topology_to_mermaid
            from ..auth.sdwan import safe_items

            sdk = _sdwan(tenant_id)

            sites = safe_items(sdk.get.sites())
            wan_networks = safe_items(sdk.get.wannetworks())
            elements = safe_items(sdk.get.elements())

            # Collect WAN interfaces across all sites
            wan_ifaces: list[dict[str, Any]] = []
            for site in sites:
                sid = site.get("id")
                if sid:
                    resp = sdk.get.waninterfaces(site_id=sid)
                    wan_ifaces.extend(safe_items(resp))

            connections = build_topology(sdk, sites, wan_ifaces, wan_networks)
            wan_ips, _wan_ip_errors = extract_sdwan_wan_ips(sdk, sites, elements)
            diagram = topology_to_mermaid(connections, sites, wan_networks, wan_ips=wan_ips)

            if not diagram:
                return "No VPN topology data returned — check SD-WAN credentials and site configuration."

            output = f"```mermaid\n{diagram}\n```\n\n**{len(connections)} VPN connections** across {len(sites)} sites."

            if save_to:
                from pathlib import Path

                Path(save_to).write_text(output)
                return f"Topology diagram saved to: {save_to}\n\n{output}"

            return output
        except Exception as exc:
            return f"Error: {exc}"

    # ── Debug: raw topology endpoint ─────────────────────────────────────────

    @mcp.tool()
    def sdwan_debug_topology(tenant_id: str = "", site_id: str = "") -> str:
        """Return the raw JSON from POST /sdwan/v3.6/api/topology for one site.

        Used to inspect the actual API response structure so field names can
        be verified against what build_topology expects.

        Args:
            tenant_id: SCM tenant ID (MSSP mode).
            site_id: Site ID to query. If omitted, uses the first site found.

        Returns:
            Raw JSON response (first 8 KB) plus the VPN links query result.
        """
        try:
            sdk = _sdwan(tenant_id)
            sites = safe_items(sdk.get.sites())
            if not sites:
                return "No sites found"
            sid = site_id or str(sites[0].get("id", ""))
            site_name = next((s.get("name") for s in sites if str(s.get("id")) == sid), sid)

            # 1. Topology POST
            url = str(sdk.controller) + "/sdwan/v3.6/api/topology"
            payload = {"nodes": [sid]}
            resp = sdk._session.post(url, json=payload)  # noqa: SLF001
            topo_raw = (
                resp.json()
                if resp.status_code == 200
                else {"http_error": resp.status_code, "body": resp.text[:500]}
            )

            # 2. VPN links query (alternate endpoint)
            vpn_url = str(sdk.controller) + "/sdwan/v2.0/api/vpnlinks/query"
            vpn_resp = sdk._session.post(vpn_url, json={})  # noqa: SLF001
            vpn_raw = (
                vpn_resp.json()
                if vpn_resp.status_code == 200
                else {"http_error": vpn_resp.status_code, "body": vpn_resp.text[:500]}
            )

            return _fmt(
                {
                    "site_queried": {"id": sid, "name": site_name},
                    "topology_endpoint": url,
                    "topology_payload": payload,
                    "topology_response_keys": list(topo_raw.keys())
                    if isinstance(topo_raw, dict)
                    else type(topo_raw).__name__,
                    "topology_response": topo_raw,
                    "vpnlinks_query_keys": list(vpn_raw.keys())
                    if isinstance(vpn_raw, dict)
                    else type(vpn_raw).__name__,
                    "vpnlinks_sample": vpn_raw
                    if not isinstance(vpn_raw, dict)
                    else {k: v[:3] if isinstance(v, list) else v for k, v in vpn_raw.items()},
                }
            )[:8000]
        except Exception as exc:
            import traceback

            return f"Error: {exc}\n{traceback.format_exc()}"

    # ── Topology Summary ──────────────────────────────────────────────────────

    @mcp.tool()
    def sdwan_topology(tenant_id: str = "") -> str:
        """Generate a full Prisma SD-WAN topology summary.

        Pulls sites, elements, WAN networks, hub/spoke clusters, and policy
        sets to produce a single structured overview of the SD-WAN deployment.

        Args:
            tenant_id: SCM tenant ID (MSSP mode).

        Returns:
            JSON topology summary with site and element inventory.
        """
        try:
            sdk = _sdwan(tenant_id)

            sites = safe_items(sdk.get.sites())
            elements = safe_items(sdk.get.elements())
            networks = safe_items(sdk.get.wannetworks())
            labels = safe_items(sdk.get.waninterfacelabels())
            hubs: list[dict[str, Any]] = []
            spokes: list[dict[str, Any]] = []
            for _s in sites:
                _sid = _s.get("id")
                if _sid:
                    hubs.extend(safe_items(sdk.get.hubclusters(_sid)))
                    spokes.extend(safe_items(sdk.get.spokeclusters(_sid)))
            net_policies = safe_items(sdk.get.networkpolicysets())
            pri_policies = safe_items(sdk.get.prioritypolicysets())

            # Build site → elements map
            elem_by_site: dict[str, list[dict[str, Any]]] = {}
            for e in elements:
                sid = e.get("site_id", "unassigned")
                elem_by_site.setdefault(sid, []).append(
                    {
                        "id": e.get("id"),
                        "name": e.get("name"),
                        "model": e.get("model_name"),
                        "serial": e.get("serial_number"),
                        "sw_version": e.get("software_version") or e.get("sw_version"),
                        "connected": e.get("connected"),
                        "role": e.get("role"),
                    }
                )

            site_inventory = [
                {
                    "id": s.get("id"),
                    "name": s.get("name"),
                    "role": s.get("element_cluster_role"),
                    # address may be explicitly null (not just absent), so `or {}`
                    # guards against 'NoneType' object has no attribute 'get'.
                    "address": (s.get("address") or {}).get("city", "")
                    + ", "
                    + (s.get("address") or {}).get("country", ""),
                    "elements": elem_by_site.get(s.get("id", ""), []),
                }
                for s in sites
            ]

            return _fmt(
                {
                    "summary": {
                        "total_sites": len(sites),
                        "total_elements": len(elements),
                        "total_wan_networks": len(networks),
                        "hub_clusters": len(hubs),
                        "spoke_clusters": len(spokes),
                        "network_policy_sets": len(net_policies),
                        "priority_policy_sets": len(pri_policies),
                    },
                    "wan_networks": [
                        {"name": n.get("name"), "type": n.get("type")} for n in networks
                    ],
                    "wan_labels": [{"name": lbl.get("name")} for lbl in labels],
                    "sites": site_inventory,
                }
            )
        except Exception as exc:
            return f"Error: {exc}"

    # ── Site Map (HTML) ───────────────────────────────────────────────────────

    @mcp.tool()
    def sdwan_site_map(tenant_id: str = "", save_to: str = "") -> str:
        """Generate an interactive HTML map of SD-WAN sites from their geo data.

        Plots every site that has configured coordinates (see
        sdwan_list_sites `location`) on a Leaflet/OpenStreetMap map — DC/hub
        sites in red, branches in blue — with a popup per site showing its
        role, street address, ION elements (name, model, connected state),
        and WAN circuits. Complements the Mermaid topology diagram (which has
        no geographic layout) for AS-BUILT §4 and customer workshops.

        The generated file is standalone HTML but loads the Leaflet library
        and OSM map tiles from the internet when opened — tile requests
        reveal the mapped area to the tile server, so treat the file like
        the site list itself.

        Args:
            tenant_id: SCM tenant ID (MSSP mode).
            save_to: Output path (default: sdwan-site-map-<tenant>.html in
                     the current directory).

        Returns:
            Path of the written HTML file plus a summary of mapped/skipped
            sites.
        """
        try:
            import json as _json
            from pathlib import Path

            sdk = _sdwan(tenant_id)
            sites = safe_items(sdk.get.sites())
            elements = safe_items(sdk.get.elements())
            networks = {n.get("id"): n.get("name", "") for n in safe_items(sdk.get.wannetworks())}

            elems_by_site: dict[str, list[dict[str, Any]]] = {}
            for e in elements:
                elems_by_site.setdefault(e.get("site_id", ""), []).append(e)

            markers: list[dict[str, Any]] = []
            skipped: list[str] = []
            for s in sites:
                loc = s.get("location") or {}
                lat, lon = loc.get("latitude"), loc.get("longitude")
                if lat in (None, 0) and lon in (None, 0):
                    skipped.append(s.get("name", s.get("id", "?")))
                    continue
                addr = s.get("address") or {}
                addr_str = ", ".join(
                    str(v)
                    for v in (
                        addr.get("street"),
                        addr.get("city"),
                        addr.get("post_code"),
                        addr.get("country"),
                    )
                    if v
                )
                circuits: list[str] = []
                try:
                    for w in safe_items(sdk.get.waninterfaces(site_id=s.get("id"))):
                        net = networks.get(w.get("network_id"), "")
                        label = w.get("name", "")
                        circuits.append(f"{label} ({net})" if net else label)
                except Exception:  # noqa: S110 — map still renders without circuits
                    pass
                markers.append(
                    {
                        "name": s.get("name", ""),
                        "role": (s.get("element_cluster_role") or "").upper(),
                        "lat": lat,
                        "lon": lon,
                        "address": addr_str,
                        "elements": [
                            {
                                "name": e.get("name") or e.get("id"),
                                "model": e.get("model_name", ""),
                                "connected": bool(e.get("connected")),
                            }
                            for e in elems_by_site.get(s.get("id", ""), [])
                        ],
                        "circuits": circuits,
                    }
                )

            if not markers:
                return (
                    "No sites have configured coordinates — set each site's location "
                    "in Strata Cloud Manager, or check sdwan_list_sites output."
                )

            tid = tenant_id or (list_loaded_tenants() or ["tenant"])[0]
            out_path = Path(save_to or f"sdwan-site-map-{tid}.html")
            title = f"Prisma SD-WAN Sites — {tid}"
            html = _SITE_MAP_TEMPLATE.replace("__TITLE__", title).replace(
                "__SITES_JSON__", _json.dumps(markers)
            )
            out_path.write_text(html)

            summary = f"Site map written to {out_path} — {len(markers)} sites mapped"
            if skipped:
                summary += f", {len(skipped)} without coordinates skipped: {', '.join(skipped)}"
            return summary
        except Exception as exc:
            return f"Error: {exc}"

    # ── Events / Alarms ───────────────────────────────────────────────────────

    @mcp.tool()
    def sdwan_events(
        tenant_id: str = "",
        hours: int = 24,
        category: str = "all",
        severity: str = "",
        site_id: str = "",
        code: str = "",
        include_cleared: bool = True,
        max_events: int = 50,
    ) -> str:
        """List Prisma SD-WAN events (alarms and alerts) with a severity summary.

        Queries the controller event feed (POST events/query) for the last
        `hours` hours, newest first. Each event carries its event code,
        human-readable display name and category (resolved from the tenant's
        event-code catalog), severity, priority, cleared/acknowledged/standing
        state, and the site and element it fired on.

        The `summary` section counts events by severity and by code, and
        highlights how many are still active (not cleared) — a quick NOC
        health read without paging through the raw feed.

        Args:
            tenant_id: SCM tenant ID (MSSP mode).
            hours: Look-back window in hours (default 24).
            category: 'alarm', 'alert', or 'all'.
            severity: Comma-separated filter, e.g. 'critical,major'.
            site_id: Limit to events at this site.
            code: Comma-separated event-code filter,
                  e.g. 'DEVICEHW_INTERFACE_DOWN'.
            include_cleared: Include events that have already cleared
                             (set False for active-issues-only).
            max_events: Maximum events to return (default 50).

        Returns:
            JSON with `summary` (counts by severity/code, active count) and
            `events` (trimmed records, newest first).
        """
        try:
            sdk = _sdwan(tenant_id)
            start_time, end_time = _window(hours)

            query: dict[str, Any] = {}
            cat = category.lower()
            query["type"] = ["alarm", "alert"] if cat == "all" else [cat]
            if site_id:
                query["site"] = [site_id]
            if code:
                query["code"] = [c.strip() for c in code.split(",") if c.strip()]

            payload: dict[str, Any] = {
                "limit": {
                    "count": max(max_events, 1),
                    "sort_on": "time",
                    "sort_order": "descending",
                },
                "view": {"summary": False},
                "severity": [s.strip() for s in severity.split(",") if s.strip()],
                "query": query,
                "start_time": start_time,
                "end_time": end_time,
            }
            resp = sdk.post.events_query(payload)
            if not getattr(resp, "sdk_status", False):
                return f"Error: {_api_error('events_query', resp)}"
            content = getattr(resp, "sdk_content", {}) or {}
            events = list(content.get("items", []))
            total_count = content.get("total_count")

            if not include_cleared:
                events = [e for e in events if not e.get("cleared")]

            # Resolve event codes to display names and site/element IDs to names
            code_meta = {
                c.get("code"): c for c in safe_items(sdk.get.eventcodes()) if c.get("code")
            }
            site_names, elem_names = _name_maps(sdk)

            by_severity: dict[str, int] = {}
            by_code: dict[str, int] = {}
            active = 0
            trimmed: list[dict[str, Any]] = []
            for e in events:
                sev = e.get("severity", "unknown")
                by_severity[sev] = by_severity.get(sev, 0) + 1
                ecode = e.get("code", "unknown")
                by_code[ecode] = by_code.get(ecode, 0) + 1
                if not e.get("cleared"):
                    active += 1
                meta = code_meta.get(ecode, {})
                trimmed.append(
                    {
                        "id": e.get("id"),
                        "time": e.get("time"),
                        "code": ecode,
                        "display_name": meta.get("display_name", ecode),
                        "event_category": meta.get("category"),
                        "type": e.get("type"),
                        "severity": sev,
                        "priority": e.get("priority"),
                        "cleared": e.get("cleared"),
                        "acknowledged": e.get("acknowledged"),
                        "standing": e.get("standing"),
                        "site_name": site_names.get(e.get("site_id"), e.get("site_id")),
                        "element_name": elem_names.get(e.get("element_id"), e.get("element_id")),
                        "entity_ref": e.get("entity_ref"),
                        "info": e.get("info"),
                        "correlation_id": e.get("correlation_id"),
                    }
                )

            return _fmt(
                {
                    "window_hours": hours,
                    "summary": {
                        "returned": len(trimmed),
                        "total_in_window": total_count,
                        "active_not_cleared": active,
                        "by_severity": by_severity,
                        "by_code": dict(
                            sorted(by_code.items(), key=lambda kv: kv[1], reverse=True)
                        ),
                    },
                    "events": trimmed,
                }
            )
        except Exception as exc:
            return f"Error: {exc}"

    # ── Audit Log ─────────────────────────────────────────────────────────────

    @mcp.tool()
    def sdwan_audit_logs(tenant_id: str = "", hours: int = 24, limit: int = 50) -> str:
        """List Prisma SD-WAN audit-log entries (who changed what, and when).

        Queries the controller audit log (POST auditlog/query) for the last
        `hours` hours, newest first. Each entry records the operator, the
        request (method + resource URI), and the response code — the trail
        for config-change forensics and compliance evidence.

        Note: requires an audit-log read permission on the service account;
        view-only roles typically get HTTP 403 (reported gracefully).

        Args:
            tenant_id: SCM tenant ID (MSSP mode).
            hours: Look-back window in hours (default 24).
            limit: Maximum entries to return (default 50).

        Returns:
            JSON array of audit entries, or a clear RBAC message on 403.
        """
        try:
            sdk = _sdwan(tenant_id)
            since_ms = int((datetime.now(UTC) - timedelta(hours=hours)).timestamp() * 1000)
            payload = {
                "limit": limit,
                "query_params": {"request_ts": {"gte": since_ms}},
                "sort_params": {"request_ts": "desc"},
            }
            resp = sdk.post.query_auditlog(payload)
            if not getattr(resp, "sdk_status", False):
                return f"Error: {_api_error('auditlog_query', resp)}"
            entries = list((getattr(resp, "sdk_content", {}) or {}).get("items", []))

            preferred = (
                "operator_email",
                "operator_id",
                "request_ts",
                "request_type",
                "request_uri",
                "resource_uri",
                "request_method",
                "response_code",
                "source_ip",
                "session_key_c",
                "id",
            )
            trimmed = [
                {k: e[k] for k in preferred if k in e} or e  # fall back to full record
                for e in entries
            ]
            return _fmt({"window_hours": hours, "total": len(trimmed), "audit_logs": trimmed})
        except Exception as exc:
            return f"Error: {exc}"

    # ── Software / Upgrade Status ─────────────────────────────────────────────

    @mcp.tool()
    def sdwan_software_status(tenant_id: str = "", element_id: str = "") -> str:
        """Report ION software versions, pending upgrades, and upgrade jobs.

        For each element (or just `element_id`): the running software version,
        the machine inventory record it maps to (model, serial, claim state),
        and the element's software status — active vs staged upgrade image,
        download progress, upgrade state, rollback version, and any scheduled
        download/upgrade window. Also lists in-flight upgrade jobs
        (upgrade_status query) and a version histogram across the estate,
        so version drift is visible at a glance.

        Args:
            tenant_id: SCM tenant ID (MSSP mode).
            element_id: Limit to a specific element.

        Returns:
            JSON with `version_histogram`, `elements` (per-element software
            state), `machines_unclaimed`, and `upgrade_jobs`.
        """
        try:
            sdk = _sdwan(tenant_id)
            elements = safe_items(sdk.get.elements())
            if element_id:
                elements = [e for e in elements if e.get("id") == element_id]
            site_names, _ = _name_maps(sdk)

            machines = safe_items(sdk.get.machines())
            machine_by_element = {
                m.get("em_element_id"): m for m in machines if m.get("em_element_id")
            }

            warnings: list[str] = []
            records: list[dict[str, Any]] = []
            histogram: dict[str, int] = {}
            for e in elements:
                eid = e.get("id")
                ver = e.get("software_version") or e.get("sw_version") or "unknown"
                histogram[ver] = histogram.get(ver, 0) + 1
                rec: dict[str, Any] = {
                    "element_id": eid,
                    "element_name": e.get("name") or eid,
                    "site_name": site_names.get(e.get("site_id") or "", e.get("site_id")),
                    "model": e.get("model_name"),
                    "serial": e.get("serial_number"),
                    "connected": e.get("connected"),
                    "sw_version": ver,
                }
                m = machine_by_element.get(eid)
                if m:
                    rec["machine_state"] = m.get("machine_state")
                    rec["image_version"] = m.get("image_version")
                try:
                    statuses = safe_items(sdk.get.software_status(eid))
                except Exception as exc:  # per-element degrade, keep the sweep going
                    warnings.append(f"software_status[{eid}]: {exc}")
                    statuses = []
                if statuses:
                    s = max(statuses, key=lambda x: x.get("_updated_on_utc") or 0)
                    rec["software_status"] = {
                        "active_version": s.get("active_version"),
                        "upgrade_pending": bool(
                            s.get("upgrade_image_id")
                            and s.get("upgrade_image_id") != s.get("active_image_id")
                        ),
                        "upgrade_state": s.get("upgrade_state"),
                        "download_percent": s.get("download_percent"),
                        "rollback_version": s.get("rollback_version"),
                        "failure_info": s.get("failure_info"),
                        "scheduled_download": s.get("scheduled_download"),
                        "scheduled_upgrade": s.get("scheduled_upgrade"),
                    }
                records.append(rec)

            unclaimed = [
                {
                    "machine_id": m.get("id"),
                    "serial": m.get("sl_no"),
                    "model": m.get("model_name"),
                    "machine_state": m.get("machine_state"),
                    "image_version": m.get("image_version"),
                    "connected": m.get("connected"),
                }
                for m in machines
                if m.get("machine_state") != "claimed"
            ]

            jobs_resp = sdk.post.query_upgrade_status({"limit": 25})
            if getattr(jobs_resp, "sdk_status", False):
                jobs = list((getattr(jobs_resp, "sdk_content", {}) or {}).get("items", []))
            else:
                jobs = []
                warnings.append(_api_error("upgrade_status_query", jobs_resp))

            result: dict[str, Any] = {
                "total_elements": len(records),
                "version_histogram": histogram,
                "elements": records,
                "machines_unclaimed": unclaimed,
                "upgrade_jobs": jobs,
            }
            if warnings:
                result["warnings"] = warnings
            return _fmt(result)
        except Exception as exc:
            return f"Error: {exc}"

    # ── Policy Rules (path / QoS / NAT / security) ────────────────────────────

    @mcp.tool()
    def sdwan_policy_rules(
        tenant_id: str = "",
        policy_type: str = "path",
        policy_set_id: str = "",
    ) -> str:
        """List Prisma SD-WAN policy sets, stacks, and the rules inside them.

        Complements sdwan_list_policies (set names only) with the actual rule
        contents — what traffic each rule matches and what it does:

          - 'path'     — network policy: which WAN paths an app may use
                         (active/backup path labels, service context)
          - 'qos'      — priority policy: priority level and DSCP per app
          - 'nat'      — NAT policy: source/destination NAT actions, zones,
                         pools, ports
          - 'security' — NGFW security policy: zone-to-zone allow/deny rules,
                         apps, prefixes, security-profile group
          - 'security_legacy' — original (pre-NGFW) security policy rules

        Rules for every set are fetched when the tenant has ≤8 sets of that
        type; otherwise pass `policy_set_id` to pick one (set list is always
        returned, so the IDs are one call away).

        Args:
            tenant_id: SCM tenant ID (MSSP mode).
            policy_type: 'path', 'qos', 'nat', 'security', or 'security_legacy'.
            policy_set_id: Fetch rules for this specific policy set only.

        Returns:
            JSON with `policy_sets`, `policy_set_stacks`, and `rules_by_set`.
        """
        try:
            sdk = _sdwan(tenant_id)
            pt = policy_type.lower()

            registry: dict[str, tuple[str, str, str | None]] = {
                "path": ("networkpolicysets", "networkpolicyrules", "networkpolicysetstacks"),
                "qos": ("prioritypolicysets", "prioritypolicyrules", "prioritypolicysetstacks"),
                "nat": ("natpolicysets", "natpolicyrules", "natpolicysetstacks"),
                "security": (
                    "ngfwsecuritypolicysets",
                    "ngfwsecuritypolicyrules",
                    "ngfwsecuritypolicysetstacks",
                ),
                "security_legacy": ("securitypolicysets", "securitypolicyrules", None),
            }
            if pt not in registry:
                return f"Error: unknown policy_type {policy_type!r} — use one of {sorted(registry)}"
            sets_name, rules_name, stacks_name = registry[pt]
            api: dict[str, Any] = {
                "sets": getattr(sdk.get, sets_name),
                "rules": getattr(sdk.get, rules_name),
                "stacks": getattr(sdk.get, stacks_name) if stacks_name else None,
            }

            psets = safe_items(api["sets"]())
            set_summaries = [
                {
                    "id": p.get("id"),
                    "name": p.get("name"),
                    "description": p.get("description"),
                    "default": p.get("defaultrule_policyset", p.get("default_policysetstack")),
                }
                for p in psets
            ]

            stacks: list[dict[str, Any]] = []
            if api["stacks"] is not None:
                stacks = [
                    {
                        "id": s.get("id"),
                        "name": s.get("name"),
                        "policyset_ids": s.get("policyset_ids", []),
                        "default": s.get("default_policysetstack"),
                    }
                    for s in safe_items(api["stacks"]())
                ]

            warnings: list[str] = []
            rules_by_set: dict[str, list[dict[str, Any]]] = {}
            note = ""
            if policy_set_id:
                targets = [p for p in psets if p.get("id") == policy_set_id]
                if not targets:
                    return f"Error: policy set {policy_set_id!r} not found in {pt} sets"
            elif len(psets) <= 8:
                targets = psets
            else:
                targets = []
                note = (
                    f"{len(psets)} {pt} policy sets — pass policy_set_id to fetch "
                    "rules for one of them."
                )

            rule_trimmers: dict[str, Any] = {
                "path": lambda r: {
                    "name": r.get("name"),
                    "order": r.get("order_number"),
                    "enabled": r.get("enabled"),
                    "app_def_ids": r.get("app_def_ids"),
                    "paths_allowed": r.get("paths_allowed"),
                    "service_context": r.get("service_context"),
                },
                "qos": lambda r: {
                    "name": r.get("name"),
                    "order": r.get("order_number"),
                    "enabled": r.get("enabled"),
                    "priority_number": r.get("priority_number"),
                    "dscp": r.get("dscp"),
                    "app_def_ids": r.get("app_def_ids"),
                },
                "nat": lambda r: {
                    "name": r.get("name"),
                    "enabled": r.get("enabled"),
                    "protocol": r.get("protocol"),
                    "actions": r.get("actions"),
                    "source_zone_id": r.get("source_zone_id"),
                    "destination_zone_id": r.get("destination_zone_id"),
                    "source_prefixes_id": r.get("source_prefixes_id"),
                    "destination_prefixes_id": r.get("destination_prefixes_id"),
                    "source_ports": r.get("source_ports"),
                    "destination_ports": r.get("destination_ports"),
                },
                "security": lambda r: {
                    "name": r.get("name"),
                    "action": r.get("action"),
                    "enabled": r.get("enabled"),
                    "app_def_ids": r.get("app_def_ids"),
                    "source_zone_ids": r.get("source_zone_ids"),
                    "destination_zone_ids": r.get("destination_zone_ids"),
                    "source_prefix_ids": r.get("source_prefix_ids"),
                    "destination_prefix_ids": r.get("destination_prefix_ids"),
                    "services": r.get("services"),
                    "security_profile_group_id": r.get("security_profile_group_id"),
                },
                "security_legacy": lambda r: {
                    "name": r.get("name"),
                    "action": r.get("action"),
                    "enabled": r.get("enabled"),
                    "application_ids": r.get("application_ids"),
                    "source_filter_ids": r.get("source_filter_ids"),
                    "destination_filter_ids": r.get("destination_filter_ids"),
                },
            }
            trim = rule_trimmers[pt]
            for p in targets:
                sid = p.get("id")
                if not sid:
                    continue
                try:
                    rules_by_set[p.get("name") or sid] = [
                        {"id": r.get("id"), **trim(r)} for r in safe_items(api["rules"](sid))
                    ]
                except Exception as exc:
                    warnings.append(f"rules[{sid}]: {exc}")

            result: dict[str, Any] = {
                "policy_type": pt,
                "total_sets": len(psets),
                "policy_sets": set_summaries,
                "policy_set_stacks": stacks,
                "rules_by_set": rules_by_set,
            }
            if note:
                result["note"] = note
            if warnings:
                result["warnings"] = warnings
            return _fmt(result)
        except Exception as exc:
            return f"Error: {exc}"

    # ── Link Health / Performance ─────────────────────────────────────────────

    @mcp.tool()
    def sdwan_link_health(
        tenant_id: str = "",
        site_id: str = "",
        hours: int = 3,
        interval: str = "5min",
        include_bandwidth: bool = True,
        max_paths: int = 6,
    ) -> str:
        """Report link quality (latency, jitter, MOS) and bandwidth for a site.

        Lists every VPN overlay path (anynet link) touching the site with its
        admin state and endpoints, then queries the monitor API for link
        quality metrics per path over the last `hours` hours — LqmLatency and
        LqmJitter in milliseconds plus LqmMos voice quality score — and, with
        include_bandwidth, site-level ingress/egress BandwidthUsage in Mbps.
        Datapoints are reduced to min/avg/max per series so the answer stays
        readable; empty series mean LQM probing is disabled or the path was
        idle in the window.

        The monitor API accepts only one path per LQM request, so admin-up
        paths are queried first, capped at `max_paths` (raise it to cover
        more paths at the cost of extra API calls).

        Args:
            tenant_id: SCM tenant ID (MSSP mode).
            site_id: Required — site to report on (see sdwan_list_sites).
            hours: Look-back window in hours (default 3).
            interval: Datapoint interval: '5min', '1hour', or '1day'.
            include_bandwidth: Also query site-level bandwidth usage.
            max_paths: Cap on paths queried for LQM (default 6).

        Returns:
            JSON with `paths` (anynet links at the site), `link_quality`
            (min/avg/max per metric per path), and `bandwidth` (site-level).
        """
        try:
            if not site_id:
                return "Error: site_id is required — use sdwan_list_sites to find site IDs"
            sdk = _sdwan(tenant_id)
            start_time, end_time = _window(hours)
            site_names, _ = _name_maps(sdk)

            links_resp = sdk.post.anynetlinks_query({"limit": 256})
            if not getattr(links_resp, "sdk_status", False):
                return f"Error: {_api_error('anynetlinks_query', links_resp)}"
            links = [
                lnk
                for lnk in (getattr(links_resp, "sdk_content", {}) or {}).get("items", [])
                if site_id in (lnk.get("ep1_site_id"), lnk.get("ep2_site_id"))
            ]
            paths: list[dict[str, Any]] = []
            for lnk in links:
                remote_id = (
                    lnk.get("ep2_site_id")
                    if lnk.get("ep1_site_id") == site_id
                    else lnk.get("ep1_site_id")
                )
                paths.append(
                    {
                        "path_id": lnk.get("id"),
                        "name": lnk.get("name"),
                        "type": lnk.get("type"),
                        "admin_up": lnk.get("admin_up"),
                        "ep1_site": site_names.get(lnk.get("ep1_site_id"), lnk.get("ep1_site_id")),
                        "ep2_site": site_names.get(lnk.get("ep2_site_id"), lnk.get("ep2_site_id")),
                        "remote_site": site_names.get(remote_id, remote_id),
                    }
                )

            def _reduce(resp: Any, extra: dict[str, Any] | None = None) -> list[dict[str, Any]]:
                """Collapse monitor-API series into min/avg/max summaries."""
                out: list[dict[str, Any]] = []
                for metric in (resp.json() or {}).get("metrics", []):
                    for series in metric.get("series", []):
                        for data in series.get("data", []):
                            values = [
                                dp.get("value")
                                for dp in data.get("datapoints", [])
                                if dp.get("value") is not None
                            ]
                            out.append(
                                {
                                    **(extra or {}),
                                    "metric": series.get("name"),
                                    "unit": series.get("unit"),
                                    "view": series.get("view"),
                                    "datapoints": len(data.get("datapoints", [])),
                                    "min": min(values) if values else None,
                                    "avg": round(sum(values) / len(values), 2) if values else None,
                                    "max": max(values) if values else None,
                                }
                            )
                return out

            warnings: list[str] = []
            link_quality: list[dict[str, Any]] = []
            # LQM requests take exactly one path, and latency (round-trip)
            # rejects the direction view that jitter requires — so each path
            # needs two monitor calls. Query admin-up paths first.
            lqm_targets = sorted(paths, key=lambda p: not p.get("admin_up"))[:max_paths]
            base = {"start_time": start_time, "end_time": end_time, "interval": interval}
            # LqmMos only supports unit "count"; LqmPacketLoss is rejected
            # with METRIC_UNIT_NOT_SUPPORTED for every documented unit, so
            # it is deliberately absent here.
            lqm_calls = [
                # round-trip latency rejects the direction view the
                # directional metrics (jitter, MOS) require — two calls
                (
                    {},
                    [{"name": "LqmLatency", "statistics": ["average"], "unit": "milliseconds"}],
                ),
                (
                    {"individual": "direction"},
                    [
                        {"name": "LqmJitter", "statistics": ["average"], "unit": "milliseconds"},
                        {"name": "LqmMos", "statistics": ["average"], "unit": "count"},
                    ],
                ),
            ]
            for p in lqm_targets:
                pid = p["path_id"]
                tag = {"path_id": pid, "remote_site": p["remote_site"]}
                for view, metrics in lqm_calls:
                    lqm_resp = sdk.post.monitor_metrics(
                        {
                            **base,
                            "metrics": metrics,
                            "view": view,
                            "filter": {"site": [site_id], "path": [pid]},
                        }
                    )
                    if getattr(lqm_resp, "sdk_status", False):
                        link_quality.extend(_reduce(lqm_resp, extra=tag))
                    else:
                        warnings.append(_api_error(f"monitor_metrics[lqm {pid}]", lqm_resp))

            bandwidth: list[dict[str, Any]] = []
            if include_bandwidth:
                bw_payload = {
                    "start_time": start_time,
                    "end_time": end_time,
                    "interval": interval,
                    "metrics": [
                        {"name": "BandwidthUsage", "statistics": ["average"], "unit": "Mbps"}
                    ],
                    "view": {"individual": "direction"},
                    "filter": {"site": [site_id]},
                }
                bw_resp = sdk.post.monitor_metrics(bw_payload)
                if getattr(bw_resp, "sdk_status", False):
                    bandwidth = _reduce(bw_resp)
                else:
                    warnings.append(_api_error("monitor_metrics[bandwidth]", bw_resp))

            result: dict[str, Any] = {
                "site_id": site_id,
                "site_name": site_names.get(site_id, site_id),
                "window_hours": hours,
                "total_paths": len(paths),
                "paths": paths,
                "link_quality": link_quality,
                "bandwidth": bandwidth,
            }
            if warnings:
                result["warnings"] = warnings
            return _fmt(result)
        except Exception as exc:
            return f"Error: {exc}"

    def _app_names(sdk: Any) -> dict[str, str]:
        """Return {appdef_id: display name} for resolving flow/top-N app IDs."""
        return {
            a["id"]: a.get("display_name") or a.get("name") or a["id"]
            for a in safe_items(sdk.get.appdefs())
            if a.get("id")
        }

    # ── Flows (top talkers) ───────────────────────────────────────────────────

    @mcp.tool()
    def sdwan_flows(
        tenant_id: str = "",
        site_id: str = "",
        hours: int = 1,
        top: int = 10,
        max_flows: int = 500,
    ) -> str:
        """Top talkers for a site from the SD-WAN flow log.

        Queries the flow records the site's IONs reported over the last
        `hours` hours and aggregates them client-side into top sources, top
        destinations, and top applications by bytes, plus a per-path-type
        byte breakdown and a count of dropped flows (flow_action=flow_drop).
        Application IDs are resolved to display names via appdefs.

        The flow monitor accepts exactly one site per request; an idle site
        legitimately returns zero flows.

        Args:
            tenant_id: SCM tenant ID (MSSP mode).
            site_id: Required — site to report on (see sdwan_list_sites).
            hours: Look-back window in hours (default 1).
            top: How many entries per top-talker list (default 10).
            max_flows: Flow records to request from the API (default 500).

        Returns:
            JSON with `total_flows`, `dropped_flows`, `top_sources`,
            `top_destinations`, `top_applications`, and `path_types`.
        """
        try:
            if not site_id:
                return "Error: site_id is required — use sdwan_list_sites to find site IDs"
            sdk = _sdwan(tenant_id)
            start_time, end_time = _window(hours)
            resp = sdk.post.monitor_flows(
                {
                    "start_time": start_time,
                    "end_time": end_time,
                    "filter": {"site": [site_id]},
                    "debug_level": "all",
                    "page_size": max_flows,
                }
            )
            if not getattr(resp, "sdk_status", False):
                return f"Error: {_api_error('monitor_flows', resp)}"
            flows = ((resp.json() or {}).get("flows") or {}).get("items", [])
            app_names = _app_names(sdk)
            site_names, _ = _name_maps(sdk)

            def _rank(key_fn: Any) -> list[dict[str, Any]]:
                groups: dict[str, dict[str, int]] = {}
                for f in flows:
                    key = key_fn(f)
                    g = groups.setdefault(key, {"flows": 0, "bytes": 0})
                    g["flows"] += 1
                    g["bytes"] += (f.get("bytes_c2s") or 0) + (f.get("bytes_s2c") or 0)
                ranked = sorted(groups.items(), key=lambda kv: kv[1]["bytes"], reverse=True)
                return [{"key": k, **v} for k, v in ranked[:top]]

            result = {
                "site_id": site_id,
                "site_name": site_names.get(site_id, site_id),
                "window_hours": hours,
                "total_flows": len(flows),
                "dropped_flows": sum(1 for f in flows if f.get("flow_action") == "flow_drop"),
                "top_sources": _rank(lambda f: f.get("source_ip", "?")),
                "top_destinations": _rank(
                    lambda f: f"{f.get('destination_ip', '?')}:{f.get('destination_port', '')}"
                ),
                "top_applications": _rank(
                    lambda f: app_names.get(f.get("app_id"), f.get("app_id") or "?")
                ),
                "path_types": _rank(lambda f: f.get("path_type") or "?"),
            }
            return _fmt(result)
        except Exception as exc:
            return f"Error: {exc}"

    # ── Application health / top-N ────────────────────────────────────────────

    _TOPN_BASES = (
        "traffic_volume",
        "transaction_failure",
        "initiation_failure",
        "tcp_flow",
        "udp_flow",
        "audio_traffic_volume",
        "video_traffic_volume",
        "ingress_audio_pkt_loss",
        "egress_audio_pkt_loss",
        "ingress_video_pkt_loss",
        "egress_video_pkt_loss",
        "ingress_audio_jitter",
        "egress_audio_jitter",
        "ingress_video_jitter",
        "egress_video_jitter",
        "ingress_audio_mos",
        "egress_audio_mos",
    )

    @mcp.tool()
    def sdwan_app_health(
        tenant_id: str = "",
        site_id: str = "",
        hours: int = 24,
        basis: str = "traffic_volume",
    ) -> str:
        """Tenant/site application health: healthscore buckets and top-N.

        Reports three views over the last `hours` hours:
        - `healthscore`: how many sites, circuits, and anynet links fall in
          each health bucket (good/fair/poor/others).
        - `top_applications`: top 10 apps by `basis` (default traffic
          volume; media bases like egress_audio_mos target voice/video),
          scoped to `site_id` when given, app IDs resolved to names.
        - `top_sites`: top 10 sites by the same basis (tenant-wide view,
          only included when site_id is not set).
        Per-app healthscore detail is also queried; many tenants return no
        datapoints unless app monitoring is enabled.

        Args:
            tenant_id: SCM tenant ID (MSSP mode).
            site_id: Optional site to scope the top-apps view to.
            hours: Look-back window in hours (default 24).
            basis: Top-N ranking basis (traffic_volume, tcp_flow, udp_flow,
                transaction_failure, or media bases like egress_audio_mos).

        Returns:
            JSON with `healthscore`, `top_applications`, `top_sites`, and
            `app_healthscores`.
        """
        try:
            if basis not in _TOPN_BASES:
                return f"Error: basis must be one of {', '.join(_TOPN_BASES)}"
            sdk = _sdwan(tenant_id)
            start_time, end_time = _window(hours)
            site_names, _ = _name_maps(sdk)
            warnings: list[str] = []

            healthscore: dict[str, dict[str, int]] = {}
            for hs_type in ("Site", "Circuit", "AnynetLink"):
                hs_resp = sdk.post.monitor_aggregates_healthscore(
                    {
                        "start_time": start_time,
                        "end_time": end_time,
                        "healthscore_type": hs_type,
                        "aggregation": "avg",
                    }
                )
                if getattr(hs_resp, "sdk_status", False):
                    healthscore[hs_type] = {
                        item.get("health", "?"): item.get("count", 0)
                        for item in (hs_resp.json() or {}).get("items", [])
                    }
                else:
                    warnings.append(_api_error(f"healthscore[{hs_type}]", hs_resp))

            def _topn(kind: str) -> list[str]:
                tn_resp = sdk.post.monitor_topn(
                    {
                        "start_time": start_time,
                        "end_time": end_time,
                        "topn_basis": basis,
                        "top_n": {"type": kind, "limit": 10},
                        "filter": {"site": [site_id]} if site_id and kind == "app" else {},
                    }
                )
                if not getattr(tn_resp, "sdk_status", False):
                    warnings.append(_api_error(f"topn[{kind}]", tn_resp))
                    return []
                return ((tn_resp.json() or {}).get("top_n") or {}).get("items", [])

            app_names = _app_names(sdk)
            top_apps = [{"app": app_names.get(a, a), "id": a} for a in _topn("app")]
            top_sites = (
                [] if site_id else [{"site": site_names.get(s, s), "id": s} for s in _topn("site")]
            )

            app_hs_resp = sdk.post.monitor_applicationsummary_query(
                {
                    "start_time": start_time,
                    "end_time": end_time,
                    "interval": "1hour",
                    "metrics": ["ApplicationHealthscore"],
                    "view": "app",
                    "filter": {"site": [site_id]} if site_id else {},
                }
            )
            app_healthscores: list[dict[str, Any]] = []
            if getattr(app_hs_resp, "sdk_status", False):
                body = app_hs_resp.json() or {}
                resp_rows = body.get("response")
                rows = resp_rows if isinstance(resp_rows, list) else []
                app_healthscores = [
                    {
                        "app": app_names.get(r.get("app_id") or "", r.get("app_id")),
                        "healthscore_avg": r.get("application_healthscore_avg"),
                        "site": site_names.get(r.get("site_id"), r.get("site_id")),
                        "duration": r.get("duration"),
                    }
                    for r in rows
                ]
            else:
                warnings.append(_api_error("applicationsummary", app_hs_resp))

            result: dict[str, Any] = {
                "window_hours": hours,
                "basis": basis,
                "healthscore": healthscore,
                "top_applications": top_apps,
                "top_sites": top_sites,
                "app_healthscores": app_healthscores,
            }
            if not app_healthscores:
                result["app_healthscores_note"] = (
                    "no per-app healthscore datapoints in the window — normal unless "
                    "application monitoring/probes are enabled on the tenant"
                )
            if warnings:
                result["warnings"] = warnings
            return _fmt(result)
        except Exception as exc:
            return f"Error: {exc}"

    # ── Cellular modules ──────────────────────────────────────────────────────

    @mcp.tool()
    def sdwan_cellular_status(tenant_id: str = "", element_id: str = "") -> str:
        """Status of cellular (LTE/5G) modules across ION elements.

        Joins each configured cellular module to its live status: modem
        state, carrier, radio technology, signal strength, network/packet
        registration, active SIM and per-slot SIM state, and active
        firmware. Elements without cellular modules simply don't appear.

        Args:
            tenant_id: SCM tenant ID (MSSP mode).
            element_id: Optional — only modules on this element.

        Returns:
            JSON array of cellular module objects with element/site names.
        """
        try:
            sdk = _sdwan(tenant_id)
            cfg_resp = sdk.post.cellular_modules_query({})
            if not getattr(cfg_resp, "sdk_status", False):
                return f"Error: {_api_error('cellular_modules_query', cfg_resp)}"
            status_resp = sdk.post.cellular_modules_status_query({})
            status_by_module: dict[str, dict[str, Any]] = {}
            warnings: list[str] = []
            if getattr(status_resp, "sdk_status", False):
                status_by_module = {
                    s.get("cellular_module_id"): s
                    for s in (status_resp.json() or {}).get("items", [])
                }
            else:
                warnings.append(_api_error("cellular_modules_status_query", status_resp))

            site_names, elem_names = _name_maps(sdk)
            elem_sites = {
                e.get("id"): site_names.get(e.get("site_id") or "", e.get("site_id"))
                for e in safe_items(sdk.get.elements())
            }

            modules: list[dict[str, Any]] = []
            for cfg in (cfg_resp.json() or {}).get("items", []):
                eid = cfg.get("element_id")
                if element_id and eid != element_id:
                    continue
                st = status_by_module.get(cfg.get("id"), {})
                active_fw = next(
                    (f.get("fw_version") for f in st.get("firmware", []) if f.get("active")),
                    None,
                )
                modules.append(
                    {
                        "module_id": cfg.get("id"),
                        "name": cfg.get("name"),
                        "element": elem_names.get(eid, eid),
                        "site": elem_sites.get(eid),
                        "radio_on": cfg.get("radio_on"),
                        "gps_enabled": cfg.get("gps_enable"),
                        "primary_sim": cfg.get("primary_sim"),
                        "model": st.get("model_name"),
                        "manufacturer": st.get("manufacturer"),
                        "imei": st.get("imei"),
                        "modem_state": st.get("modem_state"),
                        "carrier": st.get("carrier"),
                        "technology": st.get("technology"),
                        "signal_strength": st.get("signal_strength_indicator"),
                        "network_registration": st.get("network_registration_state"),
                        "packet_service": st.get("packet_service_state"),
                        "activation_state": st.get("activation_state"),
                        "roaming": (st.get("network_state") or {}).get("roaming"),
                        "active_sim": st.get("active_sim"),
                        "sims": [
                            {
                                "slot": s.get("slot_number"),
                                "present": s.get("present"),
                                "carrier": s.get("carrier"),
                                "pin_state": s.get("pin_state"),
                            }
                            for s in st.get("sim", [])
                        ],
                        "firmware": active_fw,
                    }
                )
            result: dict[str, Any] = {"total": len(modules), "modules": modules}
            if warnings:
                result["warnings"] = warnings
            return _fmt(result)
        except Exception as exc:
            return f"Error: {exc}"

    # ── SD-WAN Depth Round 3 ───────────────────────────────────────────────

    @mcp.tool()
    def sdwan_app_qos(
        tenant_id: str = "",
        application_name: str = "",
        metric: str = "",
        hours: int = 24,
    ) -> str:
        """Application QoS aggregates — per-app latency, jitter, loss, MOS.

        Queries the SD-WAN monitor API for application-level QoS metrics.
        When ``application_name`` is set, scopes to one application; otherwise
        returns aggregate data across all applications.

        Uses the monitor/v2.0 application/qos aggregate endpoint.  Metric names
        are API-defined (e.g. ``LatencyMs``, ``JitterMs``, ``PacketLossPct``,
        ``MOS``) — pass ``metric`` to scope to one, or omit for all.

        Args:
            tenant_id:        TSG ID or settings key. Omit for default tenant.
            application_name: Scope to one application (optional).
            metric:           Scope to one metric name (optional).
            hours:            Time window in hours (default 24).

        Returns:
            JSON: per-application QoS aggregates with site/element context.
        """
        try:
            sdk = _sdwan(tenant_id)
            start, end = _window(hours)
            payload: dict[str, Any] = {
                "time_range": {"start": start, "end": end},
            }
            if application_name:
                payload["application_name"] = application_name
            if metric:
                payload["metric"] = metric

            # Try SDK method; fall back to raw REST
            try:
                resp = sdk.post.monitor_aggregates_application_qos(payload)
                items = safe_items(resp)
            except (AttributeError, TypeError):
                try:
                    resp = sdk._session.post(
                        f"{sdk.base_url}/sdwan/monitor/v2.0/api/monitor/aggregates/application/qos",
                        json=payload,
                        timeout=(10, 30),
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    items = data.get("items", [])
                except Exception as exc2:
                    return _fmt(
                        {
                            "error": "qos_aggregates_failed",
                            "detail": str(exc2)[:300],
                            "hint": "QoS aggregate API may require a different service-account role.",
                        }
                    )
            site_names, elem_names = _name_maps(sdk)
        except Exception as exc:
            return f"Error: {exc}"

        enriched: list[dict[str, Any]] = []
        for item in items:
            enriched.append(
                {
                    "application": item.get("application_name", item.get("application", "?")),
                    "site": site_names.get(item.get("site_id", ""), item.get("site_id")),
                    "element": elem_names.get(item.get("element_id", ""), item.get("element_id")),
                    "metrics": {
                        k: v
                        for k, v in item.items()
                        if k not in ("application_name", "application", "site_id", "element_id")
                    },
                }
            )

        return _fmt(
            {
                "total": len(enriched),
                "time_window_hours": hours,
                "metric_filter": metric or "all",
                "app_filter": application_name or "all",
                "aggregates": enriched,
            }
        )

    @mcp.tool()
    def sdwan_interface_status(
        tenant_id: str = "",
        site_id: str = "",
        element_id: str = "",
        interface_id: str = "",
    ) -> str:
        """Interface operational status sweep for SD-WAN elements.

        Queries interface status across all elements (or scoped by site/element).
        Returns port state, speed, duplex, and authentication status for each
        interface.  Uses the ``interfaces/status/query`` and ``interfaces/query``
        endpoints (v2.0/v4.20).

        Args:
            tenant_id:    TSG ID or settings key. Omit for default tenant.
            site_id:      Scope to one site (optional).
            element_id:   Scope to one element (optional).
            interface_id: Fetch a single interface's detailed status (optional).

        Returns:
            JSON: interface status list with port operational state.
        """
        try:
            sdk = _sdwan(tenant_id)
            site_names, elem_names = _name_maps(sdk)

            payload: dict[str, Any] = {}
            if site_id:
                payload["site_id"] = site_id
            if element_id:
                payload["element_id"] = element_id
            if interface_id:
                payload["interface_id"] = interface_id

            warnings: list[str] = []
            items: list[dict[str, Any]] = []

            # Try v4.20 interfaces/query first
            for version, path in [
                ("v4.20", "/sdwan/v4.20/api/interfaces/query"),
                ("v2.0", "/sdwan/v2.0/api/interfaces/status/query"),
            ]:
                try:
                    resp = sdk._session.post(
                        f"{sdk.base_url}{path}",
                        json=payload,
                        timeout=(10, 30),
                    )
                    if resp.status_code == 403:
                        warnings.append(_api_error(f"interfaces/query {version}", resp))
                        continue
                    resp.raise_for_status()
                    data = resp.json()
                    items = data.get("items", [])
                    if items:
                        break
                except Exception:
                    continue

            # Fallback: list interfaces via GET per element
            if not items and not interface_id and element_id:
                try:
                    resp = sdk.get.elements()
                    elements = safe_items(resp)
                    target = [e for e in elements if e.get("id") == element_id]
                    if not target:
                        return _fmt(
                            {
                                "total": 0,
                                "interfaces": [],
                                "hint": f"element_id {element_id!r} not found in this tenant.",
                            }
                        )
                    for elem in target:
                        try:
                            if_resp = sdk._session.get(
                                f"{sdk.base_url}/sdwan/v4.20/api/sites/{elem.get('site_id')}/"
                                f"elements/{elem['id']}/interfaces",
                                timeout=(10, 20),
                            )
                            if if_resp.status_code == 200:
                                items = if_resp.json().get("items", [])
                                break
                        except Exception:
                            continue
                except Exception:
                    pass
        except Exception as exc:
            return f"Error: {exc}"

        enriched: list[dict[str, Any]] = []
        for iface in items:
            enriched.append(
                {
                    "interface_id": iface.get("id"),
                    "name": iface.get("name"),
                    "element": elem_names.get(iface.get("element_id", ""), iface.get("element_id")),
                    "site": site_names.get(iface.get("site_id", ""), iface.get("site_id")),
                    "type": iface.get("type"),
                    "admin_state": iface.get("admin_up"),
                    "oper_state": iface.get("operational_status", iface.get("link_state")),
                    "speed_mbps": iface.get("speed"),
                    "duplex": iface.get("duplex"),
                    "mtu": iface.get("mtu"),
                    "mac": iface.get("mac_address"),
                }
            )

        result: dict[str, Any] = {"total": len(enriched), "interfaces": enriched}
        if warnings:
            result["warnings"] = warnings
        return _fmt(result)

    @mcp.tool()
    def sdwan_ipfix_config(
        tenant_id: str = "",
        resource: str = "profiles",
        action: str = "list",
        resource_id: str = "",
        site_id: str = "",
        element_id: str = "",
    ) -> str:
        """Read IPFIX configuration (profiles, collector/filter contexts, templates, prefixes).

        Lists IPFIX configuration resources for a tenant.  Read-only by default.
        Create/update/delete operations are gated behind the Planner write-approval
        check and require ``action`` to be explicitly set.

        Resource types: ``profiles``, ``collector_contexts``, ``filter_contexts``,
        ``templates``, ``global_prefixes``, ``local_prefixes``, ``element_ipfix``.

        Args:
            tenant_id:   TSG ID or settings key. Omit for default tenant.
            resource:    IPFIX resource type (default: profiles).
            action:      ``list`` (default) or ``get`` with resource_id.
            resource_id: Fetch a single resource by ID (optional).
            site_id:     Required when resource is element_ipfix.
            element_id:  Required when resource is element_ipfix.

        Returns:
            JSON: IPFIX configuration summary.
        """
        _VALID_IPFIX = {
            "profiles": "ipfixprofiles",
            "collector_contexts": "ipfixcollectorcontexts",
            "filter_contexts": "ipfixfiltercontexts",
            "templates": "ipfixtemplates",
            "global_prefixes": "ipfixglobalprefixes",
            "local_prefixes": "ipfixlocalprefixes",
            "element_ipfix": None,  # handled separately
        }
        if resource not in _VALID_IPFIX:
            return _fmt(
                {"error": f"Unknown resource: {resource!r}. Use one of: {', '.join(_VALID_IPFIX)}"}
            )

        try:
            sdk = _sdwan(tenant_id)

            # Per-element IPFIX
            if resource == "element_ipfix":
                if not site_id or not element_id:
                    return _fmt(
                        {
                            "error": "site_id and element_id are required for resource='element_ipfix'"
                        }
                    )
                try:
                    resp = sdk._session.get(
                        f"{sdk.base_url}/sdwan/v2.0/api/sites/{site_id}/elements/{element_id}/ipfix",
                        timeout=(10, 20),
                    )
                    if resp.status_code == 403:
                        return _fmt(
                            {
                                "resource": resource,
                                "available": False,
                                "hint": _api_error("element_ipfix", resp),
                            }
                        )
                    resp.raise_for_status()
                    data = resp.json()
                    items = data.get("items", [])
                except Exception as exc:
                    return f"Error: {exc}"

                return _fmt(
                    {
                        "resource": resource,
                        "site_id": site_id,
                        "element_id": element_id,
                        "total": len(items),
                        "configs": items,
                    }
                )

            # Collection resources — element_ipfix (the only None value) returned above
            endpoint = _VALID_IPFIX[resource]
            assert endpoint is not None
            sdk_method = getattr(sdk.get, endpoint, None)
            if sdk_method:
                resp = sdk_method()
                items = safe_items(resp)
            else:
                resp = sdk._session.get(
                    f"{sdk.base_url}/sdwan/v2.0/api/{endpoint}",
                    timeout=(10, 20),
                )
                resp.raise_for_status()
                items = resp.json().get("items", [])

            # Detail fetch
            if resource_id and action == "get":
                item = next((i for i in items if i.get("id") == resource_id), None)
                if item is None:
                    return _fmt({"error": f"Resource {resource_id!r} not found in {resource}"})
                return _fmt({"resource": resource, "resource_id": resource_id, "config": item})

        except Exception as exc:
            return f"Error: {exc}"

        return _fmt(
            {
                "resource": resource,
                "total": len(items),
                "configs": items,
            }
        )

    @mcp.tool()
    def sdwan_snmp_config(
        tenant_id: str = "",
        element_id: str = "",
        site_id: str = "",
        resource: str = "agents",
    ) -> str:
        """Read SNMP configuration (agents and trap destinations) per element.

        Lists SNMP agent config (community strings, listeners) and trap
        destinations for SD-WAN elements.  Write operations are deferred
        behind the Planner write-approval gate.

        Args:
            tenant_id:  TSG ID or settings key. Omit for default tenant.
            element_id: Element ID (optional — lists all if omitted).
            site_id:    Site ID (optional — scopes element lookup).
            resource:   ``agents`` (default) or ``traps``.

        Returns:
            JSON: SNMP configuration summary.
        """
        if resource not in ("agents", "traps"):
            return _fmt({"error": f"Unknown resource: {resource!r}. Use 'agents' or 'traps'."})

        endpoint = "snmpagents" if resource == "agents" else "snmptraps"

        try:
            sdk = _sdwan(tenant_id)
            site_names, elem_names = _name_maps(sdk)

            elements = safe_items(sdk.get.elements())
            if element_id:
                elements = [e for e in elements if e.get("id") == element_id]
            if site_id:
                elements = [e for e in elements if e.get("site_id") == site_id]

            warnings: list[str] = []
            all_configs: list[dict[str, Any]] = []

            for elem in elements[:50]:  # cap at 50 elements
                eid = elem["id"]
                sid = elem.get("site_id", "")
                try:
                    resp = sdk._session.get(
                        f"{sdk.base_url}/sdwan/v2.1/api/sites/{sid}/elements/{eid}/{endpoint}",
                        timeout=(10, 20),
                    )
                    if resp.status_code == 403:
                        warnings.append(
                            _api_error(f"snmp {resource} for {elem.get('name', eid)}", resp)
                        )
                        continue
                    resp.raise_for_status()
                    data = resp.json()
                    for item in data.get("items", []) or []:
                        all_configs.append(
                            {
                                "id": item.get("id"),
                                "name": item.get("name"),
                                "element": elem_names.get(eid, eid),
                                "site": site_names.get(sid, sid),
                                "config": {
                                    k: v for k, v in item.items() if k not in ("id", "name")
                                },
                            }
                        )
                except Exception:
                    continue

        except Exception as exc:
            return f"Error: {exc}"

        result: dict[str, Any] = {
            "resource": resource,
            "total": len(all_configs),
            "configs": all_configs,
        }
        if warnings:
            result["warnings"] = warnings
        return _fmt(result)

    @mcp.tool()
    def sdwan_event_correlation(
        tenant_id: str = "",
        policy_set_id: str = "",
        site_id: str = "",
        element_id: str = "",
        action: str = "list",
    ) -> str:
        """Read event correlation policy sets, rules, and triggered correlation events.

        Lists event correlation policy sets and their rules.  When ``site_id`` or
        ``element_id`` is set, queries correlation events triggered for that scope.

        Write operations (create/update/delete policy sets and rules) are gated
        behind the Planner write-approval check.

        Args:
            tenant_id:     TSG ID or settings key. Omit for default tenant.
            policy_set_id: Fetch a single policy set's rules (optional).
            site_id:       Query correlation events for a site (optional).
            element_id:    Query correlation events for an element (optional).
            action:        ``list`` (default) or ``events`` (correlation events query).

        Returns:
            JSON: correlation policy sets, rules, and/or events.
        """
        try:
            sdk = _sdwan(tenant_id)
            site_names, elem_names = _name_maps(sdk)

            # Correlation events query
            if action == "events":
                scope = "sites" if site_id else "elements" if element_id else "interfaces"
                scope_id = site_id or element_id or ""
                if not scope_id:
                    return _fmt({"error": "site_id or element_id required for action='events'"})

                try:
                    url = f"{sdk.base_url}/sdwan/v2.0/api/{scope}/correlationevents/query"
                    resp = sdk._session.post(
                        url,
                        json={"scope_id": scope_id},
                        timeout=(10, 30),
                    )
                    if resp.status_code == 403:
                        return _fmt(
                            {
                                "action": "events",
                                "available": False,
                                "hint": _api_error("correlationevents", resp),
                            }
                        )
                    resp.raise_for_status()
                    events = resp.json().get("items", [])
                except Exception as exc:
                    return _fmt({"error": "correlation_events_failed", "detail": str(exc)[:300]})

                return _fmt(
                    {
                        "action": "events",
                        "total": len(events),
                        "events": events,
                    }
                )

            # List policy sets
            resp = sdk.get.eventcorrelationpolicysets()
            sets = safe_items(resp)

            if policy_set_id:
                sets = [s for s in sets if s.get("id") == policy_set_id]
                if not sets:
                    return _fmt({"error": f"Policy set {policy_set_id!r} not found"})

                # Fetch rules for this set
                rules: list[dict] = []
                try:
                    rules_resp = sdk._session.get(
                        f"{sdk.base_url}/sdwan/v2.0/api/eventcorrelationpolicysets/"
                        f"{policy_set_id}/eventcorrelationpolicyrules",
                        timeout=(10, 20),
                    )
                    rules_resp.raise_for_status()
                    rules = rules_resp.json().get("items", [])
                except Exception:
                    pass

                return _fmt(
                    {
                        "policy_set": sets[0],
                        "rules": rules,
                    }
                )

        except Exception as exc:
            return f"Error: {exc}"

        return _fmt(
            {
                "total": len(sets),
                "policy_sets": sets,
            }
        )

    @mcp.tool()
    def sdwan_perf_mgmt(
        tenant_id: str = "",
        resource: str = "policy_sets",
    ) -> str:
        """Read performance management configuration (policy sets, threshold profiles, probe configs).

        Lists performance management policy sets for a tenant.  Use ``resource``
        to select the sub-resource type.

        Args:
            tenant_id: TSG ID or settings key. Omit for default tenant.
            resource:  ``policy_sets`` (default), ``threshold_profiles``, or
                       ``probe_configs``.

        Returns:
            JSON: performance management configuration.
        """
        _PERF_PATHS = {
            "policy_sets": "perfmgmtpolicysets",
            "threshold_profiles": "perfmgmtprofiles",
            "probe_configs": "perfmgmtprobeconfigs",
        }
        if resource not in _PERF_PATHS:
            return _fmt(
                {"error": f"Unknown resource: {resource!r}. Use one of: {', '.join(_PERF_PATHS)}"}
            )

        try:
            sdk = _sdwan(tenant_id)
            endpoint = _PERF_PATHS[resource]

            # Try SDK method first
            sdk_method = getattr(sdk.get, endpoint, None)
            if sdk_method:
                resp = sdk_method()
                items = safe_items(resp)
            else:
                resp = sdk._session.get(
                    f"{sdk.base_url}/sdwan/v2.0/api/{endpoint}",
                    timeout=(10, 20),
                )
                if resp.status_code == 403:
                    return _fmt(
                        {
                            "resource": resource,
                            "available": False,
                            "hint": _api_error(endpoint, resp),
                        }
                    )
                resp.raise_for_status()
                items = resp.json().get("items", [])

        except Exception as exc:
            return f"Error: {exc}"

        return _fmt(
            {
                "resource": resource,
                "total": len(items),
                "configs": items,
            }
        )

    @mcp.tool()
    def sdwan_events_summary(
        tenant_id: str = "",
        hours: int = 24,
        category: str = "",
    ) -> str:
        """Aggregated event summary — counts by severity, category, and type.

        A lighter alternative to ``sdwan_events`` (which returns individual event
        records).  Uses the POST ``/events/summary`` endpoint for dashboard/SIEM
        consumption.

        Args:
            tenant_id: TSG ID or settings key. Omit for default tenant.
            hours:     Time window in hours (default 24).
            category:  Filter by event category (optional).

        Returns:
            JSON: event counts by severity and category.
        """
        try:
            sdk = _sdwan(tenant_id)
            start, end = _window(hours)

            payload: dict[str, Any] = {
                "time_range": {"start": start, "end": end},
            }
            if category:
                payload["category"] = category

            # Try v2.1 first, fall back to v2.0
            for version in ("v2.1", "v2.0"):
                try:
                    resp = sdk._session.post(
                        f"{sdk.base_url}/sdwan/{version}/api/events/summary",
                        json=payload,
                        timeout=(10, 30),
                    )
                    if resp.status_code == 403:
                        return _fmt(
                            {
                                "available": False,
                                "hint": _api_error(f"events/summary {version}", resp),
                            }
                        )
                    resp.raise_for_status()
                    data = resp.json()
                    return _fmt(
                        {
                            "time_window_hours": hours,
                            "category_filter": category or "all",
                            "summary": data,
                        }
                    )
                except Exception:
                    continue

            return _fmt(
                {
                    "available": False,
                    "hint": "events/summary endpoint not reachable — may require a broader service-account role.",
                }
            )

        except Exception as exc:
            return f"Error: {exc}"
