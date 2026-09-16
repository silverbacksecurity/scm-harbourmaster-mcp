"""Security-rule pre/post resolution across container and cloud leaf folders (no network).

Cloud leaf folders (Mobile Users, Remote Networks) ignore the position selector
and return the full effective rulebase for both pre and post; only container
folders filter.  Shapes mirror a live Prisma Access tenant.
"""

from __future__ import annotations

from typing import Any

from scm_harbourmaster_mcp.audit.extractor import _rest_params, resolve_rule_positions


def _r(name: str, folder: str) -> dict[str, Any]:
    return {"id": f"id-{name}", "name": name, "folder": folder}


SHARED_PRE = [_r("block-quic", "Shared"), _r("gp-internet", "Shared")]
SHARED_POST = [_r("trust-untrust", "Shared")]
ALL_POST = [_r("internet-access-default", "All")]
MUC_PRE = [_r("mobile-client", "Mobile Users Container")]
MU_OWN = [_r("mu-casb", "Mobile Users")]
RN_OWN = [_r("rn-outbound", "Remote Networks")]


def _tenant(calls: list[tuple[str, str]]):
    """Fake list_rules for a tenant with Shared, MU Container, MU and RN rules."""
    effective_mu = SHARED_PRE + MUC_PRE + MU_OWN + SHARED_POST + ALL_POST
    effective_rn = SHARED_PRE + RN_OWN + SHARED_POST + ALL_POST
    listings = {
        ("Prisma Access", "pre"): SHARED_PRE,
        ("Prisma Access", "post"): ALL_POST + SHARED_POST,
        ("Mobile Users Container", "pre"): SHARED_PRE + MUC_PRE,
        ("Mobile Users Container", "post"): ALL_POST + SHARED_POST,
        ("All", "pre"): [],
        ("All", "post"): ALL_POST,
        ("Mobile Users", "pre"): effective_mu,
        ("Mobile Users", "post"): effective_mu,
        ("Remote Networks", "pre"): effective_rn,
        ("Remote Networks", "post"): effective_rn,
    }

    def list_rules(folder: str, position: str) -> list[dict[str, Any]]:
        calls.append((folder, position))
        return [dict(r) for r in listings.get((folder, position), [])]

    return list_rules


def _names(rules: list[dict[str, Any]]) -> set[str]:
    return {r["name"] for r in rules}


def test_container_folder_positions_taken_as_reported():
    pre, post = resolve_rule_positions(["Prisma Access"], _tenant([]))
    assert _names(pre) == {"block-quic", "gp-internet"}
    assert _names(post) == {"trust-untrust", "internet-access-default"}


def test_leaf_folders_do_not_leak_every_rule_into_post():
    pre, post = resolve_rule_positions(
        ["Mobile Users", "Remote Networks", "Mobile Users"], _tenant([])
    )
    assert _names(post) == {"trust-untrust", "internet-access-default"}
    assert _names(pre) == {"block-quic", "gp-internet", "mobile-client", "mu-casb", "rn-outbound"}


def test_leaf_query_probes_defining_container_via_shared_alias():
    calls: list[tuple[str, str]] = []
    resolve_rule_positions(["Mobile Users"], _tenant(calls))
    assert ("Prisma Access", "post") in calls
    assert ("Shared", "post") not in calls


def test_leaf_own_rule_after_known_post_rule_is_post():
    shared_pre, shared_post = _r("p1", "Shared"), _r("p9", "Shared")
    own_pre, own_post = _r("own-pre", "Mobile Users"), _r("own-post", "Mobile Users")
    effective = [shared_pre, own_pre, shared_post, own_post]
    listings = {
        ("Mobile Users", "pre"): effective,
        ("Mobile Users", "post"): effective,
        ("Prisma Access", "pre"): [shared_pre],
        ("Prisma Access", "post"): [shared_post],
    }
    pre, post = resolve_rule_positions(
        ["Mobile Users"], lambda f, p: [dict(r) for r in listings.get((f, p), [])]
    )
    assert _names(pre) == {"p1", "own-pre"}
    assert _names(post) == {"p9", "own-post"}


def test_rules_deduplicated_and_tagged():
    pre, post = resolve_rule_positions(["Prisma Access", "Mobile Users"], _tenant([]))
    names = [r["name"] for r in pre + post]
    assert len(names) == len(set(names))
    mu = next(r for r in pre if r["name"] == "mu-casb")
    assert mu["_folder"] == "Mobile Users" and mu["_position"] == "pre"
    assert all(r["_position"] == "post" for r in post)


def test_rest_params_translates_rulebase_to_position():
    assert _rest_params({"folder": "x", "rulebase": "post", "limit": 5}) == {
        "folder": "x",
        "position": "post",
        "limit": 5,
    }
    assert _rest_params({"folder": "x"}) == {"folder": "x"}
