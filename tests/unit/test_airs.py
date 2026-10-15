"""Tests for utils/airs.py — AIRS fetch gate, pagination, changes, devices and risks."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock

from scm_harbourmaster_mcp.utils.airs import (
    AirsInventory,
    airs_changes,
    airs_dashboard_cell,
    airs_devices,
    airs_sections,
    assess_airs,
    fetch_airs,
    fetch_airs_devices,
    render_sections_markdown,
    risk_headline,
)

NOW = datetime(2026, 10, 14, tzinfo=UTC)


def _resp(status: int, data: Any = None) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.json.return_value = data
    if status >= 400:
        r.raise_for_status.side_effect = RuntimeError(f"HTTP {status}")
    return r


def _session(routes: dict[str, Any]) -> MagicMock:
    """routes: URL suffix -> response, or callable(params) -> response. Unknown → 401."""
    session = MagicMock()

    def get(url: str, params: Any = None, timeout: Any = None) -> Any:
        for suffix, resp in routes.items():
            if url.endswith(suffix):
                return resp if isinstance(resp, MagicMock) else resp(params or {})
        return _resp(401)

    session.get.side_effect = get
    return session


class TestFetch:
    def test_unprovisioned_gate_stops_after_profiles(self) -> None:
        s = _session({"/deploymentprofiles": _resp(200, {"deployment_profiles": []})})
        inv = fetch_airs(s)
        assert not inv.provisioned and not inv.licensed
        assert inv.refused == {"profiles": 401}
        assert s.get.call_count == 2

    def test_paginates_on_next_offset(self) -> None:
        def profiles(params: dict[str, Any]) -> Any:
            if params.get("offset", 0) == 0:
                full = [{"profile_name": "a"}] * 100
                return _resp(200, {"ai_profiles": full, "next_offset": 100})
            return _resp(200, {"ai_profiles": [{"profile_name": "b"}], "next_offset": 100})

        s = _session(
            {
                "/deploymentprofiles": _resp(200, {"deployment_profiles": [{"dp_name": "d"}]}),
                "/profiles": profiles,
                "/customerapps": _resp(200, {"customer_apps": []}),
                "/topics": _resp(200, {"custom_topics": []}),
                "/apikeys": _resp(200, {"api_keys": []}),
            }
        )
        inv = fetch_airs(s)
        assert inv.provisioned and inv.licensed
        # A short page stops the loop even though next_offset is present.
        assert len(inv.profiles) == 101 and inv.profiles[-1]["profile_name"] == "b"
        profile_calls = [c for c in s.get.call_args_list if c.args[0].endswith("/profiles")]
        assert len(profile_calls) == 2
        assert all(c.kwargs["params"]["latest"] == "true" for c in profile_calls)

    def test_partial_refusal_and_errors(self) -> None:
        s = _session(
            {
                "/deploymentprofiles": _resp(200, {"deployment_profiles": [{"dp_name": "d"}]}),
                "/profiles": _resp(403),
                "/customerapps": _resp(500),
                "/topics": _resp(200, [{"topic_name": "t"}]),
            }
        )
        inv = fetch_airs(s)
        assert inv.provisioned
        assert inv.refused == {"profiles": 403, "api_keys": 401}
        assert "apps" in inv.errors
        assert inv.topics == [{"topic_name": "t"}]


class TestChangesAndDevices:
    def test_changes_newest_first(self) -> None:
        inv = AirsInventory(
            profiles=[
                {
                    "profile_name": "p",
                    "updated_by": "u@x",
                    "last_modified_ts": "2026-10-01T00:00:00Z",
                }
            ],
            topics=[{"topic_name": "t", "created_by": "c@x", "created_ts": "2026-10-05T00:00:00Z"}],
            apps=[{"app_name": "silent"}],
        )
        rows = airs_changes(inv)
        assert [(r["name"], r["who"], r["action"]) for r in rows] == [
            ("t", "c@x", "created"),
            ("p", "u@x", "updated"),
        ]

    def test_devices_match_auth_code_or_feature(self) -> None:
        inv = AirsInventory(deployment_profiles=[{"dp_name": "dp", "auth_code": "AC"}])
        devices = [
            {"hostname": "a", "installed_licenses": [{"feature": "Other", "authcode": "AC"}]},
            {
                "name": "b",
                "installedLicenses": [{"feature": "AI Runtime Security", "expired": "yes"}],
            },
            {"name": "c", "installedLicenses": [{"feature": "Threat Prevention"}]},
        ]
        got = airs_devices(devices, inv)
        assert [(d["name"], d["deployment_profile"], d["expired"]) for d in got] == [
            ("a", "dp", False),
            ("b", "—", True),
        ]


def _profile(**cfg: Any) -> dict[str, Any]:
    return {
        "profile_name": "p",
        "active": True,
        "policy": {"ai-security-profiles": [{"model-configuration": cfg}]},
    }


class TestRisks:
    def test_unprovisioned_has_no_risks(self) -> None:
        assert assess_airs(AirsInventory(), now=NOW) == []

    def test_profile_and_licence_rules(self) -> None:
        inv = AirsInventory(
            provisioned=True,
            deployment_profiles=[{"dp_name": "d", "expiration_date": "2026-11-01"}],
            profiles=[
                _profile(
                    **{
                        "model-protection": [
                            {
                                "name": "prompt-injection",
                                "action": "allow",
                                "toxic-category-list": [{"category": "hate", "action": "allow"}],
                                "topic-list": [{"action": "block", "topic": [{"topic_id": "T1"}]}],
                            }
                        ],
                        "latency": {"inline-timeout-action": "allow"},
                    }
                ),
                {"profile_name": "off", "active": False, "policy": {}},
            ],
            topics=[
                {"topic_name": "used", "topic_id": "T1"},
                {"topic_name": "spare", "topic_id": "T2"},
            ],
        )
        findings = [(r.severity, r.finding) for r in assess_airs(inv, now=NOW)]
        text = "\n".join(f for _, f in findings)
        assert ("MEDIUM", "Deployment profile `d` expires in 18 days.") in findings
        assert "lets through (allow/alert): prompt-injection" in text
        assert "allows toxic categories: hate" in text
        assert "fails open" in text
        assert "`p` has no data-protection" in text
        assert "`off` is inactive" in text
        assert "`off` has no model protection" not in text  # inactive: gaps skipped
        assert "`spare` is not used" in text and "`used` is not used" not in text
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        ranks = [order[sev] for sev, _ in findings]
        assert ranks == sorted(ranks)  # most severe first

    def test_licensed_without_profiles_keys_apps_devices(self) -> None:
        inv = AirsInventory(
            provisioned=True,
            deployment_profiles=[{"dp_name": "d", "expiration_date": "2025-01-01"}],
            api_keys=[
                {
                    "api_key_name": "old",
                    "expiration": "2026-01-01T00:00:00Z",
                    "rotation_time_interval": 30,
                },
                {"api_key_name": "soon", "expiration": "2026-10-20T00:00:00Z"},
                {"api_key_name": "gone", "revoked": True},
            ],
            apps=[{"app_name": "orphan"}],
        )
        risks = assess_airs(inv, [{"name": "fw", "expired": True}], now=NOW)
        text = "\n".join(f"{r.severity} {r.finding}" for r in risks)
        assert "HIGH Deployment profile `d` expired" in text
        assert "MEDIUM AIRS is licensed but no AI security profiles exist." in text
        assert "LOW API key `old` expired" in text
        assert "MEDIUM API key `soon` expires in 6 days." in text
        assert "LOW API key `soon` has no rotation interval." in text
        assert "gone" not in text
        assert "LOW Customer app `orphan` has no API key." in text
        assert "HIGH Firewall `fw` has an expired AIRS licence." in text

    def test_dashboard_cell(self) -> None:
        assert airs_dashboard_cell(AirsInventory(), []) == "—"
        inv = AirsInventory(provisioned=True, profiles=[{}], apps=[{}, {}])
        assert airs_dashboard_cell(inv, []) == "1p/2a"
        risks = assess_airs(inv, now=NOW)
        assert airs_dashboard_cell(inv, risks).startswith("1p/2a 🔴")

    def test_dashboard_cell_counts_expired_device_licence(self) -> None:
        inv = AirsInventory(
            provisioned=True,
            deployment_profiles=[{"dp_name": "d", "auth_code": "AC"}],
            profiles=[
                _profile(
                    **{
                        "model-protection": [{"name": "x", "action": "block"}],
                        "data-protection": {"x": 1},
                    }
                )
            ],
        )
        s = _session(
            {
                "/devices": _resp(
                    200,
                    {
                        "data": [
                            {
                                "name": "fw",
                                "installedLicenses": [{"authcode": "AC", "expired": "yes"}],
                            }
                        ]
                    },
                )
            }
        )
        devices = fetch_airs_devices(s, inv)
        assert [d["name"] for d in devices] == ["fw"]
        assert airs_dashboard_cell(inv, assess_airs(inv, now=NOW)) == "1p/0a"
        assert airs_dashboard_cell(inv, assess_airs(inv, devices, now=NOW)) == "1p/0a 🔴1"


class TestReviewFixes:
    def test_failed_later_page_keeps_first_page(self) -> None:
        def profiles(params: dict[str, Any]) -> Any:
            if params.get("offset", 0) == 0:
                full = [{"profile_name": "a"}] * 100
                return _resp(200, {"ai_profiles": full, "next_offset": 100})
            return _resp(500)

        s = _session(
            {
                "/deploymentprofiles": _resp(200, {"deployment_profiles": [{"dp_name": "d"}]}),
                "/profiles": profiles,
            }
        )
        inv = fetch_airs(s)
        assert len(inv.profiles) == 100
        assert inv.errors["profiles"].startswith("page 2:")
        assert not inv.complete("profiles")

    def test_errored_profiles_do_not_claim_none_exist(self) -> None:
        inv = AirsInventory(
            provisioned=True,
            deployment_profiles=[{"dp_name": "d"}],
            errors={"profiles": "boom"},
            topics=[{"topic_name": "t", "topic_id": "T"}],
        )
        text = " ".join(r.finding for r in assess_airs(inv, now=NOW))
        assert "no AI security profiles" not in text
        assert "not used by any profile" not in text

    def test_max_pages_marks_truncated(self) -> None:
        s = _session(
            {
                "/deploymentprofiles": _resp(200, {"deployment_profiles": [{"dp_name": "d"}]}),
                "/profiles": _resp(
                    200, {"ai_profiles": [{"profile_name": "a"}] * 100, "next_offset": 100}
                ),
                "/customerapps": _resp(
                    200, {"customer_apps": [{"app_name": "x"}], "next_offset": 100}
                ),
            }
        )
        inv = fetch_airs(s, max_pages=1)
        assert "profiles" in inv.truncated
        # One short page is complete, not truncated.
        assert airs_dashboard_cell(inv, []) == "100+p/1a"

    def test_403_is_forbidden_not_unprovisioned(self) -> None:
        s = _session(
            {
                "/deploymentprofiles": _resp(200, {"deployment_profiles": []}),
                "/profiles": _resp(403),
            }
        )
        inv = fetch_airs(s)
        assert inv.forbidden and not inv.provisioned
        assert airs_dashboard_cell(inv, []) == "⛔ RBAC"
        assert not fetch_airs(_session({"/deploymentprofiles": _resp(200, {})})).forbidden

    def test_change_time_converted_to_utc(self) -> None:
        inv = AirsInventory(
            profiles=[
                {
                    "profile_name": "p",
                    "updated_by": "u",
                    "last_modified_ts": "2026-10-14T10:00:00+05:00",
                }
            ]
        )
        assert airs_changes(inv)[0]["when"] == "2026-10-14 05:00 UTC"

    def test_feature_match_not_attributed_to_codeless_profile(self) -> None:
        inv = AirsInventory(
            deployment_profiles=[{"dp_name": "A"}, {"dp_name": "B", "auth_code": "X1"}]
        )
        got = airs_devices(
            [{"name": "fw", "installedLicenses": [{"feature": "AI Runtime Security"}]}], inv
        )
        assert got[0]["deployment_profile"] == "—"

    def test_device_pull_pages(self) -> None:
        def devices(params: dict[str, Any]) -> Any:
            off = int(params.get("offset", 0))
            page = [{"name": f"d{off + i}"} for i in range(1000 if off == 0 else 3)]
            return _resp(200, {"data": page, "total": 1003})

        s = _session({"/devices": devices})
        inv = AirsInventory()
        fetch_airs_devices(s, inv)
        assert s.get.call_count == 2

    def test_cells_escaped_and_headline(self) -> None:
        inv = AirsInventory(
            provisioned=True,
            topics=[{"topic_name": "a|b", "description": "line1\nline2 | x"}],
        )
        md = "\n".join(render_sections_markdown(airs_sections(inv, None, [])))
        assert "| a\\|b |" in md
        assert "line1 line2 \\| x" in md
        assert "Firewalls Licensed" not in md  # devices=None omits the table
        risks = assess_airs(
            AirsInventory(
                provisioned=True,
                deployment_profiles=[{"dp_name": "d", "expiration_date": "2020-01-01"}],
            ),
            now=NOW,
        )
        assert risk_headline(risks).startswith("**AIRS risks:** 🔴 1 high")
        assert risk_headline([]) == "**AIRS risks:** none found."


class TestSecondReviewFixes:
    def test_topic_used_only_by_inactive_profile_is_not_unused(self) -> None:
        inv = AirsInventory(
            provisioned=True,
            profiles=[
                {
                    "profile_name": "off",
                    "active": False,
                    "policy": {
                        "ai-security-profiles": [
                            {
                                "model-configuration": {
                                    "model-protection": [
                                        {
                                            "name": "x",
                                            "action": "block",
                                            "topic-list": [{"topic": [{"topic_id": "T"}]}],
                                        }
                                    ]
                                }
                            }
                        ]
                    },
                }
            ],
            topics=[{"topic_name": "t", "topic_id": "T"}],
        )
        assert "not used" not in " ".join(r.finding for r in assess_airs(inv, now=NOW))

    def test_dashboard_cell_errors_are_not_unprovisioned(self) -> None:
        inv = AirsInventory(errors={"deployment_profiles": "timeout", "profiles": "500"})
        assert airs_dashboard_cell(inv, []) == "⚠️ error"

    def test_errored_gate_still_fetches_other_lists(self) -> None:
        s = _session(
            {
                "/deploymentprofiles": _resp(500),
                "/profiles": _resp(500),
                "/customerapps": _resp(200, {"customer_apps": [{"app_name": "a"}]}),
            }
        )
        inv = fetch_airs(s)
        assert inv.provisioned
        assert [a["app_name"] for a in inv.apps] == ["a"]
        assert set(inv.errors) == {"deployment_profiles", "profiles"}


class TestThirdReviewFixes:
    def test_api_key_value_is_never_kept(self) -> None:
        s = _session(
            {
                "/deploymentprofiles": _resp(200, {"deployment_profiles": [{"dp_name": "d"}]}),
                "/profiles": _resp(200, {"ai_profiles": []}),
                "/apikeys": _resp(
                    200,
                    {
                        "api_keys": [
                            {"api_key_name": "k", "api_key": "SECRET", "api_key_last8": "12345678"}
                        ]
                    },
                ),
            }
        )
        inv = fetch_airs(s)
        assert inv.api_keys == [{"api_key_name": "k", "api_key_last8": "12345678"}]
        md = "\n".join(render_sections_markdown(airs_sections(inv, None, [])))
        assert "SECRET" not in md

    def test_unexpected_shape_marks_list_incomplete(self) -> None:
        s = _session(
            {
                "/deploymentprofiles": _resp(200, {"deployment_profiles": [{"dp_name": "d"}]}),
                "/profiles": _resp(200, {"ai_profiles": []}),
                "/topics": _resp(200, {"custom_topics": 5}),
            }
        )
        inv = fetch_airs(s)
        assert "topics" in inv.errors and not inv.complete("topics")

    def test_note_after_table_is_not_a_row(self) -> None:
        inv = AirsInventory(
            provisioned=True, topics=[{"topic_name": "t"}], errors={"topics": "page 2: x"}
        )
        md = render_sections_markdown(airs_sections(inv, None, []))
        i = md.index("_Incomplete — page 2: x_")
        assert md[i - 1] == ""

    def test_dlp_only_profile_is_medium_not_high(self) -> None:
        inv = AirsInventory(
            provisioned=True,
            profiles=[
                _profile(
                    **{
                        "data-protection": {
                            "data-leak-detection": {"member": [], "action": "block"}
                        }
                    }
                )
            ],
        )
        r = [x for x in assess_airs(inv, now=NOW) if "no model protection" in x.finding]
        assert r[0].severity == "MEDIUM"
        bare = AirsInventory(provisioned=True, profiles=[_profile()])
        r = [x for x in assess_airs(bare, now=NOW) if "no model protection" in x.finding]
        assert r[0].severity == "HIGH"

    def test_quick_device_pull_is_one_page(self) -> None:
        s = _session({"/devices": _resp(200, {"data": [{"name": "a"}], "total": 5000})})
        fetch_airs_devices(s, AirsInventory(), quick=True)
        assert s.get.call_count == 1


class TestFourthReviewFixes:
    def test_refused_deployment_profiles_is_an_error_not_unprovisioned(self) -> None:
        inv = fetch_airs(_session({}))  # every call 401: a bad token
        assert not inv.provisioned
        assert "deployment_profiles" in inv.errors
        assert airs_dashboard_cell(inv, []) == "⚠️ error"

    def test_policy_level_dlp_and_url_only_profiles(self) -> None:
        dlp = {
            "profile_name": "dlp",
            "active": True,
            "policy": {
                "dlp-data-profiles": [{"name": "d"}],
                "ai-security-profiles": [{"model-configuration": {}}],
            },
        }
        url_only = _profile(**{"app-protection": {"block-url-category": {"member": ["x"]}}})
        risks = assess_airs(AirsInventory(provisioned=True, profiles=[dlp, url_only]), now=NOW)
        text = " ".join(f"{r.severity} {r.finding}" for r in risks)
        assert "`dlp` has no data-protection" not in text
        assert "HIGH" not in text

    def test_alert_counts_as_permissive(self) -> None:
        p = _profile(**{"model-protection": [{"name": "prompt-injection", "action": "alert"}]})
        text = " ".join(
            r.finding for r in assess_airs(AirsInventory(provisioned=True, profiles=[p]), now=NOW)
        )
        assert "lets through (allow/alert): prompt-injection" in text

    def test_malformed_entries_do_not_raise(self) -> None:
        p = {
            "profile_name": "odd",
            "active": True,
            "policy": {
                "ai-security-profiles": [
                    "junk",
                    {
                        "model-configuration": {
                            "model-protection": [
                                None,
                                {
                                    "name": "x",
                                    "action": "block",
                                    "topic-list": ["s", {"topic": ["t"]}],
                                },
                            ],
                            "latency": "fast",
                        }
                    },
                ]
            },
        }
        assess_airs(
            AirsInventory(provisioned=True, profiles=[p, {"profile_name": "n", "policy": None}]),
            now=NOW,
        )

    def test_device_list_refusal_raises(self) -> None:
        import pytest

        with pytest.raises(RuntimeError):
            fetch_airs_devices(_session({"/devices": _resp(403)}), AirsInventory())


class TestFinalReviewFixes:
    def test_deployment_profiles_404_is_unprovisioned(self) -> None:
        inv = fetch_airs(_session({"/deploymentprofiles": _resp(404)}))
        assert not inv.provisioned and not inv.errors

    def test_full_page_without_next_offset_is_truncated(self) -> None:
        s = _session(
            {
                "/deploymentprofiles": _resp(200, {"deployment_profiles": [{"dp_name": "d"}]}),
                "/profiles": _resp(200, {"ai_profiles": [{"profile_name": "a"}] * 100}),
            }
        )
        assert "profiles" in fetch_airs(s).truncated

    def test_data_key_fallback(self) -> None:
        s = _session(
            {
                "/deploymentprofiles": _resp(200, {"data": [{"dp_name": "d"}]}),
                "/profiles": _resp(200, {"items": [{"profile_name": "p"}]}),
            }
        )
        inv = fetch_airs(s)
        assert inv.licensed and inv.profiles == [{"profile_name": "p"}]
