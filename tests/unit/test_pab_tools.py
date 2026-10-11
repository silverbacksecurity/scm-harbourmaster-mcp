"""Tests for tenant-level Prisma Access Browser tools (tools/pab.py).

No network — the bearer session is replaced with a fake serving canned
/seb-api/v1 responses shaped like the live API (captured from a
provisioned lab tenant).
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

import scm_harbourmaster_mcp.tools.pab as pab_mod

USERS_P1 = {
    "pageInfo": {"hasNextPage": True, "cursor": "CUR2"},
    "data": [
        {
            "email": "a@example.com",
            "name": "A",
            "status": "active",
            "provider": "scm",
            "firstSeen": "2026-02-05T11:30:40Z",
            "lastSeen": "2026-05-21T14:58:44Z",
            "userGroups": ["g1"],
            "deviceIds": ["d1", "d2"],
        }
    ],
}
USERS_P2 = {
    "pageInfo": {"hasNextPage": False, "cursor": ""},
    "data": [
        {"email": "b@example.com", "name": "B", "status": "suspended", "deviceIds": []},
    ],
}
DEVICES = {
    "pageInfo": {"hasNextPage": False, "cursor": ""},
    "data": [
        {
            "hostname": "MAC-1",
            "status": "active",
            "osType": "macOS",
            "osDisplayName": "macOS 15.7.4",
            "model": "MacBookPro18,1",
            "serialNumber": "S1",
            "arch": "arm64",
            "lastSeen": "2026-03-12T12:51:21Z",
            "screenLockStatus": "ScreenLockStatusEnabled",
            "diskEncryptionStatus": "DiskEncryptionStatusEnabled",
            "firewallStatus": "FireWallStatusEnabled",
        },
        {
            "hostname": "WIN-1",
            "status": "active",
            "osType": "windows",
            "screenLockStatus": "ScreenLockStatusEnabled",
            "diskEncryptionStatus": "DiskEncryptionStatusDisabled",
            "firewallStatus": "FireWallStatusDisabled",
        },
    ],
}
APPS = {
    "data": [
        {
            "name": "GitHub",
            "type": "catalog",
            "category": "Management",
            "catalog_name": "github",
            "urls": ["*://github.com/*"],
        }
    ]
}
CATEGORIES = {"data": ["Analytics", "Management"]}
EMPTY = {"pageInfo": {"hasNextPage": False, "cursor": ""}, "data": []}


class FakeResp:
    def __init__(self, status: int, body: Any):
        self.status_code = status
        self._body = body
        self.text = json.dumps(body) if not isinstance(body, str) else body

    def json(self) -> Any:
        if isinstance(self._body, str):
            raise ValueError("not json")
        return self._body


def make_session(routes: dict[str, Any], calls: list[dict] | None = None) -> Any:
    class S:
        def get(self, url: str, params: Any = None, timeout: Any = None) -> FakeResp:
            path = url.split("/seb-api/v1/")[1]
            if calls is not None:
                calls.append({"path": path, "params": dict(params or {})})
            hit = routes.get(path)
            if hit is None:
                return FakeResp(404, "")
            if callable(hit):
                hit = hit(dict(params or {}))
            status, body = hit if isinstance(hit, tuple) else (200, hit)
            return FakeResp(status, body)

    return S()


@pytest.fixture
def tools(monkeypatch: pytest.MonkeyPatch) -> Any:
    def _make(routes: dict[str, Any], calls: list[dict] | None = None) -> dict[str, Any]:
        monkeypatch.setattr(pab_mod, "_bearer_session_for", lambda c: make_session(routes, calls))
        mcp = FastMCP("test")
        pab_mod.register_pab_tools(mcp, lambda tenant_id="": object())
        return {name: t.fn for name, t in mcp._tool_manager._tools.items()}

    return _make


def test_summary_counts_and_posture(tools: Any) -> None:
    t = tools({"users": USERS_P2, "devices": DEVICES})
    data = json.loads(t["scm_pab_inventory"](view="summary"))
    assert data["users_total"] == 1
    assert data["users_by_status"] == {"suspended": 1}
    assert data["devices_by_os"] == {"macOS": 1, "windows": 1}
    assert data["device_posture_enabled"] == {
        "screen_lock": 2,
        "disk_encryption": 1,
        "firewall": 1,
    }


def test_users_pagination_follows_cursor(tools: Any) -> None:
    calls: list[dict] = []

    def users(params: dict) -> Any:
        return USERS_P2 if params.get("cursor") == "CUR2" else USERS_P1

    t = tools({"users": users}, calls)
    data = json.loads(t["scm_pab_inventory"](view="users", limit=10))
    assert data["total"] == 2
    assert [u["email"] for u in data["users"]] == ["a@example.com", "b@example.com"]
    assert data["users"][0]["device_count"] == 2
    assert calls[1]["params"]["cursor"] == "CUR2"


def test_devices_view_maps_posture_bools(tools: Any) -> None:
    t = tools({"devices": DEVICES})
    data = json.loads(t["scm_pab_inventory"](view="devices"))
    mac = data["devices"][0]
    assert mac["os"] == "macOS 15.7.4"
    assert mac["screen_lock"] and mac["disk_encryption"] and mac["firewall"]
    win = data["devices"][1]
    assert win["screen_lock"] and not win["disk_encryption"] and not win["firewall"]


def test_summary_flags_unprovisioned(tools: Any) -> None:
    t = tools(
        {
            "users": EMPTY,
            "devices": EMPTY,
            "applications": (500, {"error_message": "userdeviceent: tenant not found"}),
        }
    )
    data = json.loads(t["scm_pab_inventory"](view="summary"))
    assert data["users_total"] == 0
    assert "not provisioned" in data["note"]


def test_inventory_bad_view(tools: Any) -> None:
    t = tools({})
    assert "view must be one of" in t["scm_pab_inventory"](view="bogus")


def test_apps_filters_and_categories(tools: Any) -> None:
    calls: list[dict] = []
    t = tools({"applications": APPS, "applications/categories": CATEGORIES}, calls)
    data = json.loads(t["scm_pab_apps"](view="apps", name="github", app_type="catalog"))
    assert data["applications"][0]["name"] == "GitHub"
    assert calls[0]["params"]["name"] == "github"
    assert calls[0]["params"]["type"] == "catalog"
    cats = json.loads(t["scm_pab_apps"](view="categories"))
    assert cats["categories"] == ["Analytics", "Management"]


def test_apps_unprovisioned_graceful_note(tools: Any) -> None:
    t = tools({"applications": (404, "")})
    data = json.loads(t["scm_pab_apps"](view="apps"))
    assert data["total"] == 0 and data["applications"] == []
    assert "not provisioned" in data["note"]


def test_apps_403_still_errors(tools: Any) -> None:
    t = tools({"applications": (403, "")})
    out = t["scm_pab_apps"](view="apps")
    assert out.startswith("Error:") and "Super User" in out


def test_user_requests_filters(tools: Any) -> None:
    calls: list[dict] = []
    reqs = {
        "pageInfo": {"hasNextPage": False, "cursor": ""},
        "data": [{"id": "r1", "status": "pending"}],
    }
    t = tools({"user-requests": reqs}, calls)
    data = json.loads(t["scm_pab_user_requests"](status="pending"))
    assert data["total"] == 1
    assert calls[0]["params"]["request.status"] == "pending"


def test_rbac_hint_on_403(tools: Any) -> None:
    t = tools({"users": (403, ""), "devices": EMPTY})
    data = json.loads(t["scm_pab_inventory"](view="users"))
    assert any("Super User or View-Only" in w for w in data["warnings"])


# ── scm_pab_policy ──────────────────────────────────────────────────────────
# Shaped from the published spec: the policy endpoints answered 403 "not yet
# available" on every provisioned lab tenant when this tool was written.

CV_ACTIVE = {"configurationVersion": {"id": "0CV" + "A" * 26, "status": "active", "number": 7}}
SECURITY_P1 = {
    "pageInfo": {"hasNextPage": True, "cursor": "CUR2"},
    "metadata": CV_ACTIVE,
    "data": [
        # Out of order on purpose: the tool sorts by position.
        {
            "id": "r2",
            "type": "Rule",
            "name": "Block dev tools",
            "position": 3,
            "mode": "disabled",
            "evaluationOrder": 2,
            "section": {"id": "s1", "name": "Baseline"},
        },
        {"id": "s1", "type": "Section", "name": "Baseline", "position": 1},
        {
            "id": "r1",
            "type": "Rule",
            "name": "Force HTTPS",
            "position": 2,
            "mode": "active",
            "evaluationOrder": 1,
            "section": {"id": "s1", "name": "Baseline"},
        },
    ],
}
SECURITY_P2 = {
    "pageInfo": {"hasNextPage": False, "cursor": None},
    "data": [
        {
            "id": "r3",
            "type": "Rule",
            "name": "Default",
            "position": 4,
            "mode": "active",
            "evaluationOrder": 3,
            "section": None,
        },
    ],
}
NOT_YET = (403, {"error": {"code": "FORBIDDEN", "message": "This endpoint is not yet available"}})
INTERNAL = (500, {"error": {"code": "INTERNAL_ERROR", "message": "An unexpected error occurred"}})


def _security(params: dict) -> Any:
    return SECURITY_P2 if params.get("cursor") == "CUR2" else SECURITY_P1


def test_policy_rulebase_groups_sections_in_order(tools: Any) -> None:
    calls: list[dict] = []
    t = tools({"policy/security": _security}, calls)
    data = json.loads(t["scm_pab_policy"](policy="security"))
    rb = data["rulebases"][0]
    assert rb["policy"] == "security"
    assert rb["configuration_version"]["number"] == 7
    assert rb["rules_total"] == 3
    assert rb["rules_by_mode"] == {"active": 2, "disabled": 1}
    assert [s["name"] for s in rb["sections"]] == ["Baseline"]
    assert [r["id"] for r in rb["sections"][0]["rules"]] == ["r1", "r2"]
    assert [r["id"] for r in rb["unsectioned_rules"]] == ["r3"]
    assert calls[0]["params"]["configurationVersion"] == "active"
    assert calls[1]["params"]["cursor"] == "CUR2"


def test_policy_filters_and_draft_version(tools: Any) -> None:
    calls: list[dict] = []
    t = tools({"policy/sign-in": SECURITY_P2}, calls)
    t["scm_pab_policy"](
        policy="sign_in", configuration_version="draft", name="Default", mode="monitor"
    )
    assert calls[0]["path"] == "policy/sign-in"
    assert calls[0]["params"]["configurationVersion"] == "draft"
    assert calls[0]["params"]["name"] == "Default"
    assert calls[0]["params"]["mode"] == ["monitor"]


def test_policy_all_fetches_four_rulebases(tools: Any) -> None:
    calls: list[dict] = []
    routes = {
        f"policy/{p}": SECURITY_P2
        for p in ("access-and-data", "security", "customization", "sign-in")
    }
    t = tools(routes, calls)
    data = json.loads(t["scm_pab_policy"]())
    assert [rb["policy"] for rb in data["rulebases"]] == [
        "access_and_data",
        "security",
        "customization",
        "sign_in",
    ]


def test_policy_include_details_fetches_each_rule(tools: Any) -> None:
    calls: list[dict] = []
    detail = {
        "id": "r3",
        "name": "Default",
        "mode": "active",
        "scope": {"users": "all"},
        "controls": {"forceHttps": {"enabled": True}},
        "metadata": {},
    }
    t = tools({"policy/security": SECURITY_P2, "policy/security/rules/r3": detail}, calls)
    data = json.loads(
        t["scm_pab_policy"](policy="security", include_details=True, configuration_version="draft")
    )
    rule = data["rulebases"][0]["unsectioned_rules"][0]
    assert rule["detail"] == {
        "scope": {"users": "all"},
        "controls": {"forceHttps": {"enabled": True}},
    }
    assert calls[1]["params"] == {"configurationVersion": "draft"}


def test_policy_not_yet_available_collapses_to_note(tools: Any) -> None:
    routes = {
        f"policy/{p}": NOT_YET for p in ("access-and-data", "security", "customization", "sign-in")
    }
    t = tools(routes)
    data = json.loads(t["scm_pab_policy"]())
    assert data["rulebases"] == []
    assert "not enabled it yet" in data["note"]


def test_policy_unprovisioned_500_hint(tools: Any) -> None:
    t = tools({"policy/security": INTERNAL})
    data = json.loads(t["scm_pab_policy"](policy="security"))
    assert "not provisioned" in data["note"]


def test_policy_rule_view(tools: Any) -> None:
    t = tools({"policy/access-and-data/rules/r9": {"id": "r9", "name": "X", "access": {}}})
    data = json.loads(t["scm_pab_policy"](view="rule", policy="access_and_data", rule_id="r9"))
    assert data["rule"]["id"] == "r9"
    assert "needs rule_id" in t["scm_pab_policy"](view="rule", policy="all", rule_id="r9")
    assert t["scm_pab_policy"](view="rule", policy="security", rule_id="nope").startswith("Error:")


def test_policy_bad_args(tools: Any) -> None:
    t = tools({})
    assert "policy must be" in t["scm_pab_policy"](policy="bogus")
    assert "view must be one of" in t["scm_pab_policy"](view="bogus")


def test_pending_changes_counts_by_type(tools: Any) -> None:
    changes = {
        "pageInfo": {"hasNextPage": False},
        "data": [
            {
                "entityId": "e1",
                "entityType": "securityRule",
                "name": "A",
                "operation": "updated",
                "lastUpdatedBy": "admin@example.com",
            },
            {
                "entityId": "e2",
                "entityType": "securityRule",
                "name": "B",
                "operation": "created",
                "lastUpdatedBy": "admin@example.com",
            },
            {
                "entityId": "e3",
                "entityType": "deviceGroup",
                "name": "C",
                "operation": "deleted",
                "lastUpdatedBy": "admin@example.com",
            },
        ],
    }
    t = tools({"configuration-management/draft/pending-changes": changes})
    data = json.loads(t["scm_pab_policy"](view="pending_changes"))
    assert data["total"] == 3
    assert data["by_entity_type"] == {"securityRule": 2, "deviceGroup": 1}
    assert data["pending_changes"][2]["operation"] == "deleted"


def test_integrations_providers_shape(tools: Any) -> None:
    idp = {
        "providers": [
            {
                "id": "p1",
                "displayName": "Entra",
                "type": "entraId",
                "status": "connected",
                "entraId": {"tenantId": "t-placeholder", "clientId": "c-placeholder"},
            }
        ]
    }
    t = tools({"integrations/idp-application-sync": idp, "integrations/cloud-storage": NOT_YET})
    data = json.loads(t["scm_pab_policy"](view="integrations"))
    assert data["idp_application_sync"] == [
        {"display_name": "Entra", "type": "entraId", "status": "connected", "id": "p1"}
    ]
    assert data["cloud_storage"] == []
    assert "not enabled it yet" in data["warnings"][0]
