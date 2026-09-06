"""Unit tests for WAN IP extraction: NGFW running-config XML parsing and the
SD-WAN topology mermaid IP annotation. Pure functions, no I/O.
"""

from __future__ import annotations

from scm_harbourmaster_mcp.audit.extractor import parse_ngfw_interface_ips
from scm_harbourmaster_mcp.audit.sdwan_topo import topology_to_mermaid

_SAMPLE_XML = """<?xml version="1.0"?>
<config version="10.2.0">
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/1">
              <layer3>
                <ip>
                  <entry name="203.0.113.5/30"/>
                </ip>
              </layer3>
            </entry>
            <entry name="ethernet1/2">
              <layer3>
                <dhcp-client>
                  <enable>yes</enable>
                </dhcp-client>
              </layer3>
            </entry>
            <entry name="ethernet1/3">
              <layer2/>
            </entry>
          </ethernet>
          <aggregate-ethernet>
            <entry name="ae1">
              <layer3>
                <ip>
                  <entry name="198.51.100.9/29"/>
                  <entry name="198.51.100.10/29"/>
                </ip>
              </layer3>
            </entry>
          </aggregate-ethernet>
        </interface>
      </network>
      <vsys>
        <entry name="vsys1">
          <zone>
            <entry name="untrust">
              <network>
                <layer3>
                  <member>ethernet1/1</member>
                  <member>ethernet1/2</member>
                </layer3>
              </network>
            </entry>
            <entry name="dmz">
              <network>
                <layer3>
                  <member>ae1</member>
                </layer3>
              </network>
            </entry>
          </zone>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>
"""


class TestParseNgfwInterfaceIps:
    def test_static_interface(self) -> None:
        result = parse_ngfw_interface_ips(_SAMPLE_XML)
        by_iface = {r["interface"]: r for r in result}
        assert by_iface["ethernet1/1"]["addressing"] == "static"
        assert by_iface["ethernet1/1"]["ip_addresses"] == ["203.0.113.5/30"]
        assert by_iface["ethernet1/1"]["zone"] == "untrust"

    def test_dhcp_interface_has_no_leased_ip(self) -> None:
        result = parse_ngfw_interface_ips(_SAMPLE_XML)
        by_iface = {r["interface"]: r for r in result}
        assert by_iface["ethernet1/2"]["addressing"] == "dhcp"
        assert by_iface["ethernet1/2"]["ip_addresses"] == []

    def test_aggregate_ethernet_multiple_ips(self) -> None:
        result = parse_ngfw_interface_ips(_SAMPLE_XML)
        by_iface = {r["interface"]: r for r in result}
        assert by_iface["ae1"]["ip_addresses"] == [
            "198.51.100.9/29",
            "198.51.100.10/29",
        ]
        assert by_iface["ae1"]["zone"] == "dmz"

    def test_layer2_interface_excluded(self) -> None:
        result = parse_ngfw_interface_ips(_SAMPLE_XML)
        assert "ethernet1/3" not in {r["interface"] for r in result}

    def test_malformed_xml_returns_empty(self) -> None:
        assert parse_ngfw_interface_ips("<not valid xml") == []

    def test_empty_xml_returns_empty(self) -> None:
        assert parse_ngfw_interface_ips("<config></config>") == []


class TestTopologyMermaidWanIps:
    def test_site_node_annotated_with_ip(self) -> None:
        sites = [{"id": "s1", "name": "Branch-1", "element_cluster_role": "spoke"}]
        connections = [
            {
                "source_site_id": "s1",
                "target_site_id": "s1",
                "wan_network_name": "Internet",
                "wan_type": "AUTO-PUBLIC",
                "status": "up",
            }
        ]
        wan_ips = [{"site_id": "s1", "ipv4_addresses": ["203.0.113.5/30"], "used_for": "public"}]
        diagram = topology_to_mermaid(connections, sites, [], wan_ips=wan_ips)
        assert "203.0.113.5/30" in diagram

    def test_no_wan_ips_still_renders(self) -> None:
        sites = [{"id": "s1", "name": "Branch-1", "element_cluster_role": "spoke"}]
        diagram = topology_to_mermaid([], sites, [], wan_ips=None)
        assert "Branch-1" in diagram


class TestAnnotateWanIpDrift:
    def _rec(self, **over: object) -> dict:
        base = {
            "site_name": "Branch-1",
            "interface_name": "1",
            "wan_network": "ACME-INET-1",
            "circuit_name": "Branch-1 Internet",
            "site_location": {"latitude": 51.5, "longitude": -0.12},
            "enrichment": [
                {
                    "ip": "8.8.8.8",
                    "isp": "Acme Group",
                    "org": "Acme Telecom",
                    "as_name": "ACMENET",
                    "city": "London",
                    "country": "United Kingdom",
                    "latitude": 51.51,
                    "longitude": -0.13,
                }
            ],
        }
        base.update(over)
        return base

    def test_matching_isp_and_geo_not_flagged(self) -> None:
        from scm_harbourmaster_mcp.audit.extractor import annotate_wan_ip_drift

        rec = self._rec()  # "acme" token matches, IP ~1 km from site
        assert annotate_wan_ip_drift([rec]) == 0
        assert "drift" not in rec

    def test_isp_label_mismatch_flagged(self) -> None:
        from scm_harbourmaster_mcp.audit.extractor import annotate_wan_ip_drift

        rec = self._rec(wan_network="Vodafone-MPLS", circuit_name="")
        assert annotate_wan_ip_drift([rec]) == 1
        assert any("isp_label" in r for r in rec["drift"])

    def test_geo_mismatch_flagged_beyond_500km(self) -> None:
        from scm_harbourmaster_mcp.audit.extractor import annotate_wan_ip_drift

        rec = self._rec(site_location={"latitude": 40.4, "longitude": -3.7})  # Madrid
        assert annotate_wan_ip_drift([rec]) == 1
        assert any("geo:" in r for r in rec["drift"])
        assert any("km from the site" in r for r in rec["drift"])

    def test_stopword_only_label_never_flags_isp(self) -> None:
        from scm_harbourmaster_mcp.audit.extractor import annotate_wan_ip_drift

        # "Internet" is a stopword — no meaningful tokens, so no isp_label flag
        rec = self._rec(wan_network="Internet", circuit_name="")
        assert annotate_wan_ip_drift([rec]) == 0

    def test_unenriched_records_skipped(self) -> None:
        from scm_harbourmaster_mcp.audit.extractor import annotate_wan_ip_drift

        rec = self._rec(enrichment=[])
        assert annotate_wan_ip_drift([rec]) == 0

    def test_missing_site_location_skips_geo_check(self) -> None:
        from scm_harbourmaster_mcp.audit.extractor import annotate_wan_ip_drift

        rec = self._rec(site_location={})
        assert annotate_wan_ip_drift([rec]) == 0


class TestEnrichWanIpRecords:
    def test_attaches_enrichment_by_field(self, monkeypatch: object) -> None:
        import scm_harbourmaster_mcp.utils.ipenrich as ipenrich
        from scm_harbourmaster_mcp.audit.extractor import enrich_wan_ip_records

        def _fake_enrich(ips: object, provider: str = "", token: str = "") -> tuple[dict, list]:
            return {"8.8.8.8": {"ip": "8.8.8.8", "isp": "Example"}}, ["one warning"]

        monkeypatch.setattr(ipenrich, "enrich_public_ips", _fake_enrich)  # type: ignore[attr-defined]
        records = [
            {"ipv4_addresses": ["8.8.8.8/30"], "ipv6_addresses": []},
            {"ipv4_addresses": ["10.0.0.1"], "ipv6_addresses": []},
            {"detected_public_ip": "8.8.8.8"},
        ]
        warnings = enrich_wan_ip_records(records[:2], ("ipv4_addresses", "ipv6_addresses"))
        warnings += enrich_wan_ip_records(records[2:], ("detected_public_ip",))
        assert records[0]["enrichment"][0]["isp"] == "Example"
        assert "enrichment" not in records[1]  # private IP → no match
        assert records[2]["enrichment"][0]["ip"] == "8.8.8.8"
        assert warnings == ["one warning", "one warning"]


class _FakeStatusResp:
    def __init__(self, content: dict, ok: bool = True) -> None:
        self.sdk_status = ok
        self.sdk_content = content


class _GetNamespace:
    def __init__(self, by_element: dict) -> None:
        self._by_element = by_element

    def element_status(self, element_id: str) -> _FakeStatusResp:
        if element_id not in self._by_element:
            raise RuntimeError(f"no status for {element_id}")
        return _FakeStatusResp(self._by_element[element_id])


class _FakeSdwanClient:
    def __init__(self, by_element: dict) -> None:
        self.get = _GetNamespace(by_element)


class TestExtractSdwanDetectedPublicIps:
    def test_maps_detected_ip_per_element(self) -> None:
        from scm_harbourmaster_mcp.audit.extractor import extract_sdwan_detected_public_ips

        sites = [{"id": "site-1", "name": "Branch-1"}]
        elements = [{"id": "elem-1", "site_id": "site-1", "name": "ION-1", "connected": True}]
        client = _FakeSdwanClient({"elem-1": {"config_and_events_from": "31.121.13.73"}})

        detected, errors = extract_sdwan_detected_public_ips(client, sites, elements)
        assert errors == []
        assert detected == [
            {
                "site_id": "site-1",
                "site_name": "Branch-1",
                "element_id": "elem-1",
                "element_name": "ION-1",
                "connected": True,
                "detected_public_ip": "31.121.13.73",
            }
        ]

    def test_unassigned_site_id_marked(self) -> None:
        from scm_harbourmaster_mcp.audit.extractor import extract_sdwan_detected_public_ips

        elements = [{"id": "elem-2", "site_id": "1", "name": "ION-2", "connected": False}]
        client = _FakeSdwanClient({"elem-2": {"config_and_events_from": "203.0.113.9"}})

        detected, errors = extract_sdwan_detected_public_ips(client, [], elements)
        assert errors == []
        assert detected[0]["site_name"] == "(unassigned)"
        assert detected[0]["connected"] is False

    def test_element_status_error_collected_not_raised(self) -> None:
        from scm_harbourmaster_mcp.audit.extractor import extract_sdwan_detected_public_ips

        elements = [{"id": "elem-3", "site_id": "site-1", "name": "ION-3"}]
        client = _FakeSdwanClient({})  # element_status raises for unknown id

        detected, errors = extract_sdwan_detected_public_ips(client, [], elements)
        assert detected == []
        assert len(errors) == 1 and "elem-3" in errors[0]

    def test_missing_element_id_skipped(self) -> None:
        from scm_harbourmaster_mcp.audit.extractor import extract_sdwan_detected_public_ips

        detected, errors = extract_sdwan_detected_public_ips(_FakeSdwanClient({}), [], [{}])
        assert detected == []
        assert errors == []
