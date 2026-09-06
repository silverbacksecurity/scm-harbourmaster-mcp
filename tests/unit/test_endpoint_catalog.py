"""Tests for the bundled pan.dev endpoint catalog and its lookup helpers."""

from __future__ import annotations

from scm_harbourmaster_mcp.resources.endpoint_catalog import (
    catalog_meta,
    find_endpoint,
    load_catalog,
)


def test_catalog_loads_and_has_expected_shape() -> None:
    cat = load_catalog()
    assert cat["pan_dev_commit"]
    assert cat["total_paths"] > 500
    assert "scm/config" in cat["specs"]
    assert cat["file_shas"], "file_shas map must be present for spec-drift checks"


def test_catalog_covers_new_2026_families() -> None:
    families = set(load_catalog()["specs"])
    for fam in ("sase/mt-interconnect", "sase/pab-msp", "sase/config-orch"):
        assert fam in families, f"missing {fam}"


def test_find_endpoint_resolves_sdk_resource_names() -> None:
    # plural slug ("addresses") from a singular-ish SDK attr
    url = find_endpoint("address")
    assert url and url.startswith("https://") and url.endswith("/addresses")

    # underscore attr → hyphenated slug
    url = find_endpoint("internal_dns_server")
    assert url and "internal-dns-server" in url

    # scm/config family must win over legacy /sse/config for shared slugs
    assert "api.strata.paloaltonetworks.com" in (find_endpoint("address") or "")


def test_find_endpoint_unknown_returns_none() -> None:
    assert find_endpoint("definitely_not_a_real_resource_xyz") is None


def test_catalog_meta_summary() -> None:
    meta = catalog_meta()
    assert meta["files"] and all(len(s) == 40 for s in meta["files"].values() if s)
    assert meta["total_paths"] > 500
    assert any(t.endswith("sase") for t in meta["trees"])
