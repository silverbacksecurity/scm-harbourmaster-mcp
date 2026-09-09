"""Local config search index: flattening, IP containment, and the search tools.

No network — every test builds an AuditSnapshot by hand and indexes it into a
tmp_path SQLite database.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.audit import config_index as ci
from scm_harbourmaster_mcp.audit.models import AuditSnapshot
from scm_harbourmaster_mcp.tools import config_index_tools as cit


# Dummy TSG IDs only — a real tenant id in a tracked test file is a customer
# identifier, and the public-mirror leak guard sources tenant keys and labels
# from settings.toml, not numeric ids, so it would not catch one here.
def _snapshot(tenant_id: str = "1234567890", folder: str = "Prisma Access") -> AuditSnapshot:
    snap = AuditSnapshot(tenant_id=tenant_id, folder=folder)
    snap.addresses = [
        {
            "id": "a1",
            "name": "srv-payments-db",
            "folder": "ngfw-shared",
            "ip_netmask": "10.20.5.7/32",
            "description": "Cardholder data environment primary",
            "tag": ["pci", "prod"],
        },
        {
            "id": "a2",
            "name": "net-branch-uk",
            "folder": "ngfw-shared",
            "ip_netmask": "10.20.0.0/16",
        },
        {
            "id": "a3",
            "name": "svc-vendor-portal",
            "folder": "ngfw-shared",
            "fqdn": "portal.example.net",
        },
        {
            "id": "a4",
            "name": "pool-guest",
            "folder": "ngfw-shared",
            "ip_range": "192.0.2.10-192.0.2.50",
        },
    ]
    snap.address_groups = [
        {
            "id": "g1",
            "name": "grp-pci-servers",
            "folder": "ngfw-shared",
            "static": ["srv-payments-db", "net-branch-uk"],
        }
    ]
    snap.services = [
        {
            "id": "s1",
            "name": "svc-tcp-8443",
            "folder": "ngfw-shared",
            "protocol": {"tcp": {"port": "8443"}},
        }
    ]
    snap.security_rules_pre = [
        {
            "id": "r1",
            "name": "allow-pci-out",
            "folder": "ngfw-shared",
            "source": ["grp-pci-servers"],
            "destination": ["any"],
            "application": ["ssl", "web-browsing"],
            "action": "allow",
        }
    ]
    # Vendor App-ID content shipped into every tenant, plus one the customer
    # actually defined — only the latter belongs in a default search.
    snap.applications = [
        {
            "id": "p1",
            "name": "100bao",
            "snippet": "predefined-snippet",
            "folder": "All",
            "description": "Chinese P2P file-sharing program",
        },
        {
            "id": "c1",
            "name": "app-payments-api",
            "folder": "ngfw-shared",
            "description": "In-house payments API",
        },
    ]
    # Telemetry section — must never be indexed.
    snap.insights_alerts = [{"id": "i1", "name": "tunnel-down-alert"}]
    return snap


@pytest.fixture
def index_dir(tmp_path: Path) -> Path:
    return tmp_path / "index"


# ── Indexing ──────────────────────────────────────────────────────────────────


def test_index_snapshot_counts_objects_and_ranges(index_dir):
    stats = ci.index_snapshot(_snapshot(), index_dir=index_dir, tenant_label="lab")

    # 4 addresses + 1 group + 1 service + 1 rule + 1 customer-defined application
    assert stats.object_count == 8
    assert stats.predefined_skipped == 1
    assert stats.type_count == 5
    assert stats.ip_range_count >= 3  # /32, /16, and the 192.0.2.10-50 range
    assert Path(stats.db_path).exists()


def test_telemetry_sections_are_never_indexed(index_dir):
    ci.index_snapshot(_snapshot(), index_dir=index_dir)
    hits, _ = ci.search("tunnel-down-alert", index_dir=index_dir)
    assert hits == []
    assert "insights_alerts" not in ci.INDEXABLE_FIELDS
    assert "browser_users" not in ci.INDEXABLE_FIELDS
    assert "addresses" in ci.INDEXABLE_FIELDS
    assert "security_rules_pre" in ci.INDEXABLE_FIELDS


def test_reindex_replaces_rather_than_duplicates(index_dir):
    ci.index_snapshot(_snapshot(), index_dir=index_dir)
    first, _ = ci.search("srv-payments-db", index_dir=index_dir)
    ci.index_snapshot(_snapshot(), index_dir=index_dir)
    second, _ = ci.search("srv-payments-db", index_dir=index_dir)

    assert [h.name for h in first] == [h.name for h in second]
    status = ci.index_status(index_dir=index_dir)
    assert len(status) == 1
    assert status[0]["object_count"] == 8


def test_reindex_leaves_other_tenants_alone(index_dir):
    ci.index_snapshot(_snapshot(tenant_id="1111111111"), index_dir=index_dir, tenant_label="a")
    ci.index_snapshot(_snapshot(tenant_id="2222222222"), index_dir=index_dir, tenant_label="b")
    ci.index_snapshot(_snapshot(tenant_id="1111111111"), index_dir=index_dir, tenant_label="a")

    hits, _ = ci.search("srv-payments-db", index_dir=index_dir)
    assert {h.tenant_id for h in hits} == {"1111111111", "2222222222"}


def test_dropped_object_disappears_on_reindex(index_dir):
    ci.index_snapshot(_snapshot(), index_dir=index_dir)
    trimmed = _snapshot()
    trimmed.addresses = [a for a in trimmed.addresses if a["name"] != "svc-vendor-portal"]
    ci.index_snapshot(trimmed, index_dir=index_dir)

    hits, _ = ci.search("svc-vendor-portal", index_dir=index_dir)
    assert hits == []


def test_predefined_app_signatures_are_skipped_by_default(index_dir):
    ci.index_snapshot(_snapshot(), index_dir=index_dir)

    vendor, _ = ci.search("100bao", index_dir=index_dir)
    customer, _ = ci.search("app-payments-api", index_dir=index_dir)

    assert vendor == []
    assert [h.name for h in customer] == ["app-payments-api"]


def test_predefined_app_signatures_are_searchable_when_asked_for(index_dir):
    stats = ci.index_snapshot(_snapshot(), index_dir=index_dir, include_predefined=True)
    assert stats.predefined_skipped == 0
    assert stats.object_count == 9

    hidden, _ = ci.search("100bao", index_dir=index_dir)
    shown, _ = ci.search("100bao", index_dir=index_dir, include_predefined=True)

    assert hidden == []  # indexed, but still filtered out of a default search
    assert [h.name for h in shown] == ["100bao"]


# ── Text search ───────────────────────────────────────────────────────────────


def test_search_by_name_fragment(index_dir):
    ci.index_snapshot(_snapshot(), index_dir=index_dir)
    hits, mode = ci.search("payments", index_dir=index_dir)

    assert mode == "fts"
    by_name = {h.name: h for h in hits}
    assert {"srv-payments-db", "app-payments-api"} <= set(by_name)
    assert by_name["srv-payments-db"].scope == "ngfw-shared"
    assert by_name["srv-payments-db"].summary == "10.20.5.7/32"


def test_search_also_returns_objects_that_reference_the_match(index_dir):
    """Member lists are flattened, so searching an object name also surfaces
    its referrers — a poor man's where-used until the edge graph lands."""
    ci.index_snapshot(_snapshot(), index_dir=index_dir)
    hits, _ = ci.search("srv-payments-db", index_dir=index_dir)

    assert {(h.obj_type, h.name) for h in hits} == {
        ("addresses", "srv-payments-db"),
        ("address_groups", "grp-pci-servers"),
    }


def test_search_matches_description_and_tag(index_dir):
    ci.index_snapshot(_snapshot(), index_dir=index_dir)

    by_desc, _ = ci.search("cardholder", index_dir=index_dir)
    by_tag, _ = ci.search("pci", index_dir=index_dir)

    assert [h.name for h in by_desc] == ["srv-payments-db"]
    # tagged objects, plus the group and rule carrying "pci" in their names
    assert {h.name for h in by_tag} == {
        "srv-payments-db",
        "grp-pci-servers",
        "allow-pci-out",
    }


def test_search_finds_rule_by_referenced_member(index_dir):
    """A rule's member lists are flattened into the index, so a group name finds it."""
    ci.index_snapshot(_snapshot(), index_dir=index_dir)
    hits, _ = ci.search("grp-pci-servers", index_dir=index_dir)

    names = {(h.obj_type, h.name) for h in hits}
    assert ("security_rules_pre", "allow-pci-out") in names
    assert ("address_groups", "grp-pci-servers") in names


def test_like_fallback_finds_mid_token_fragment(index_dir):
    """FTS5 tokenizes on non-alphanumerics, so 'ayment' has no ranked match."""
    ci.index_snapshot(_snapshot(), index_dir=index_dir)
    hits, mode = ci.search("ayment", index_dir=index_dir)

    assert mode == "like"
    assert "srv-payments-db" in {h.name for h in hits}


def test_search_survives_fts_syntax_in_the_query(index_dir):
    ci.index_snapshot(_snapshot(), index_dir=index_dir)
    for hostile in ['payments" OR name:*', "NEAR(a b", "*", '"""']:
        hits, _ = ci.search(hostile, index_dir=index_dir)
        assert isinstance(hits, list)  # no sqlite3.OperationalError


def test_search_without_an_index_returns_no_index(tmp_path):
    hits, mode = ci.search("anything", index_dir=tmp_path / "nothing")
    assert (hits, mode) == ([], "no-index")


def test_search_filters_by_type_and_folder(index_dir):
    ci.index_snapshot(_snapshot(), index_dir=index_dir)

    typed, _ = ci.search("pci", index_dir=index_dir, obj_types=["address_groups"])
    assert [h.name for h in typed] == ["grp-pci-servers"]

    wrong_folder, _ = ci.search("pci", index_dir=index_dir, folder="Mobile Users")
    assert wrong_folder == []


def test_search_respects_limit(index_dir):
    ci.index_snapshot(_snapshot(), index_dir=index_dir)
    hits, _ = ci.search("ngfw-shared", index_dir=index_dir, limit=2)
    assert len(hits) == 2


# ── IP containment ────────────────────────────────────────────────────────────


def test_host_query_finds_every_covering_range(index_dir):
    ci.index_snapshot(_snapshot(), index_dir=index_dir)
    hits, mode = ci.search("10.20.5.7", index_dir=index_dir)

    assert mode == "ip"
    names = {h.name for h in hits}
    # The /32 itself, the /16 that contains it, and the group + rule whose
    # flattened text carries those literals.
    assert {"srv-payments-db", "net-branch-uk"} <= names
    assert hits[0].name == "srv-payments-db"  # most specific range first


def test_cidr_query_finds_ranges_inside_it(index_dir):
    ci.index_snapshot(_snapshot(), index_dir=index_dir)
    hits, mode = ci.search("10.20.0.0/16", index_dir=index_dir)

    assert mode == "ip"
    assert {"srv-payments-db", "net-branch-uk"} <= {h.name for h in hits}
    assert any(h.matched_cidr for h in hits)


def test_ip_outside_every_range_returns_nothing(index_dir):
    ci.index_snapshot(_snapshot(), index_dir=index_dir)
    hits, _ = ci.search("172.31.99.1", index_dir=index_dir)
    assert hits == []


def test_ip_range_form_is_indexed_as_a_range(index_dir):
    ci.index_snapshot(_snapshot(), index_dir=index_dir)
    inside, mode = ci.search("192.0.2.25", index_dir=index_dir)
    outside, _ = ci.search("192.0.2.99", index_dir=index_dir)

    assert mode == "ip"
    assert [h.name for h in inside] == ["pool-guest"]
    assert outside == []


def test_ipv6_ranges_use_the_same_containment_path(index_dir):
    snap = AuditSnapshot(tenant_id="1234567890", folder="Prisma Access")
    snap.addresses = [{"id": "v6", "name": "net-v6-core", "ip_netmask": "2001:db8:abcd::/48"}]
    ci.index_snapshot(snap, index_dir=index_dir)

    inside, mode = ci.search("2001:db8:abcd::1", index_dir=index_dir)
    outside, _ = ci.search("2001:db8:ffff::1", index_dir=index_dir)

    assert mode == "ip"
    assert [h.name for h in inside] == ["net-v6-core"]
    assert outside == []


def test_version_strings_are_not_mistaken_for_addresses():
    ranges = ci.extract_ip_ranges({"name": "x", "software_version": "6.2.1", "count": 10})
    assert ranges == []


def test_hex_bounds_sort_as_integers():
    """Fixed-width hex is what lets TEXT BETWEEN act as numeric containment."""
    lo = ci.parse_ip_query("10.0.0.1")
    hi = ci.parse_ip_query("172.16.0.1")
    assert lo is not None and hi is not None
    assert lo[1] < hi[1]
    assert len(lo[1]) == 8
    v6 = ci.parse_ip_query("2001:db8::/32")
    assert v6 is not None and len(v6[1]) == 32


# ── LIKE-only host (no FTS5) ──────────────────────────────────────────────────


def test_index_and_search_work_without_fts5(index_dir, monkeypatch):
    """A SQLite build without FTS5 must still index and search, via LIKE."""
    monkeypatch.setattr(
        ci,
        "_FTS_SCHEMA",
        "CREATE VIRTUAL TABLE IF NOT EXISTS objects_fts USING fts5_absent(x);",
    )

    stats = ci.index_snapshot(_snapshot(), index_dir=index_dir)
    assert stats.fts is False
    assert stats.object_count == 8

    hits, mode = ci.search("payments", index_dir=index_dir)
    assert mode == "like"
    assert "srv-payments-db" in {h.name for h in hits}

    ip_hits, ip_mode = ci.search("10.20.5.7", index_dir=index_dir)
    assert ip_mode == "ip"
    assert "srv-payments-db" in {h.name for h in ip_hits}


# ── MCP tools ─────────────────────────────────────────────────────────────────


@pytest.fixture
def tools(index_dir, monkeypatch) -> FastMCP:
    monkeypatch.setattr(ci, "_DEFAULT_INDEX_DIR", index_dir)
    mcp = FastMCP("test")
    cit.register_config_index_tools(mcp, lambda tenant_id="": object())
    return mcp


def _call(mcp: FastMCP, name: str, **kwargs: Any) -> str:
    return str(mcp._tool_manager.get_tool(name).fn(**kwargs))


def test_search_tool_guides_when_nothing_is_indexed(tools):
    out = _call(tools, "scm_object_search", query="payments")
    assert "No config index yet" in out
    assert "scm_config_index" in out


def test_index_tool_then_search_tool(tools, monkeypatch):
    monkeypatch.setattr(cit, "extract_snapshot", lambda *a, **k: _snapshot())

    built = _call(tools, "scm_config_index", tenant_id="1234567890", folder="Prisma Access")
    assert "Config Index Built" in built
    assert "8 objects" in built
    assert "1 predefined app signature(s) skipped" in built

    found = _call(tools, "scm_object_search", query="10.20.5.7")
    assert "srv-payments-db" in found
    assert "IP containment" in found
    assert "**Index:**" in found  # staleness footer


def test_search_tool_rejects_unknown_obj_types(tools, monkeypatch):
    monkeypatch.setattr(cit, "extract_snapshot", lambda *a, **k: _snapshot())
    _call(tools, "scm_config_index", tenant_id="1234567890")

    out = _call(tools, "scm_object_search", query="pci", obj_types="addresses,not_a_section")
    assert "Unknown obj_types: not_a_section" in out


def test_search_tool_reports_unindexed_tenant(tools, monkeypatch):
    monkeypatch.setattr(cit, "extract_snapshot", lambda *a, **k: _snapshot())
    _call(tools, "scm_config_index", tenant_id="1234567890")

    out = _call(tools, "scm_object_search", query="pci", tenant_id="9999999999")
    assert "not indexed" in out
    assert "1234567890" in out


def test_search_tool_reports_no_match_without_claiming_absence(tools, monkeypatch):
    monkeypatch.setattr(cit, "extract_snapshot", lambda *a, **k: _snapshot())
    _call(tools, "scm_config_index", tenant_id="1234567890")

    out = _call(tools, "scm_object_search", query="nothing-like-this-exists")
    assert "No matches" in out
    assert "re-run `scm_config_index`" in out


def test_index_tool_reports_per_tenant_failure(tools, monkeypatch):
    def boom(*a: Any, **k: Any) -> AuditSnapshot:
        raise RuntimeError("tenant exploded")

    monkeypatch.setattr(cit, "extract_snapshot", boom)
    out = _call(tools, "scm_config_index", tenant_id="1234567890")
    assert "⚠️" in out
    assert "tenant exploded" in out


def test_cross_tenant_search_labels_each_hit(tools, monkeypatch):
    monkeypatch.setattr(cit, "extract_snapshot", lambda *a, **k: _snapshot("1111111111"))
    _call(tools, "scm_config_index", tenant_id="1111111111")
    monkeypatch.setattr(cit, "extract_snapshot", lambda *a, **k: _snapshot("2222222222"))
    _call(tools, "scm_config_index", tenant_id="2222222222")

    out = _call(tools, "scm_object_search", query="payments")
    assert "Tenant" in out
    assert "1111111111" in out
    assert "2222222222" in out
