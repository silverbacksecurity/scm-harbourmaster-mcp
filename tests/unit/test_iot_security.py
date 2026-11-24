"""scm_iot: licence handling, paging, filters and parameter rules (mocked REST)."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.tools import iot_security as iot
from scm_harbourmaster_mcp.utils import scm_rest

TSG = "1234567890"


def _device(i: int, **over: Any) -> dict[str, Any]:
    return {
        "id": f"id-{i}",
        "name": f"dev-{i}",
        "ip": f"10.0.0.{i % 250}",
        "MAC": f"aa:bb:cc:dd:ee:{i % 100:02x}",
        "category": "Camera" if i % 2 else "generic",
        "profile": "Axis IP Camera" if i % 2 else "Transient Device",
        "profile_type": "IoT" if i % 2 else "Non_IoT",
        "profile_vertical": "Office",
        "ml_risk_level": "High" if i % 5 == 0 else "Low",
        "ml_risk_score": i,
        "site_name": "Default Site",
        "extra_noise": "x",
        **over,
    }


class Api:
    """Fake IoT API behind ``scm_rest.request``."""

    def __init__(
        self, devices: list[dict[str, Any]], status: dict[str, tuple[int, Any]] | None = None
    ):
        self.devices = devices
        self.status = status or {}
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def request(self, session: Any, method: str, url: str, **kw: Any) -> scm_rest.RestResult:
        path = url.removeprefix(iot._BASE)
        params = dict(kw.get("params") or {})
        self.calls.append((path, params))
        if path in self.status:
            code, body = self.status[path]
            return scm_rest.RestResult(code, data=body)
        if path == "/v2/device/list":
            off, n = int(params.get("offset", 0)), int(params.get("pagelength", 1000))
            page = self.devices[off : off + n]
            return scm_rest.RestResult(
                200,
                data={
                    "devices": page,
                    "total": len(self.devices),
                    "has_more": off + n < len(self.devices),
                },
            )
        if path == "/v1/alert/list":
            return scm_rest.RestResult(200, data={"items": [], "total": 3})
        if path == "/v1/vulnerability/list":
            return scm_rest.RestResult(200, data={"items": {}, "total": 4, "totalInstances": 9})
        if path == "/v1/site":
            return scm_rest.RestResult(200, data={"list": [{"siteid": "0"}, {"siteid": "1"}]})
        if path == "/v1/subnet":
            return scm_rest.RestResult(
                200, data={"subnets": [{"prefix": "10.0.0.0/8"}], "total": 1}
            )
        if path == "/v1/policy/recommendation":
            return scm_rest.RestResult(200, data={"policies": [], "total": 0})
        if path == "/v1/profile/mapping":
            return scm_rest.RestResult(
                200,
                data={
                    "mapping": [
                        {"profile": "Axis IP Camera", "category": "Camera", "vertical": "Office"},
                        {"profile": "HP Printer", "category": "Printer", "vertical": "Office"},
                    ]
                },
            )
        return scm_rest.RestResult(404, data={"message": "no such path"})


@pytest.fixture
def client() -> Any:
    return SimpleNamespace(
        oauth_client=SimpleNamespace(auth_request=SimpleNamespace(tsg_id=TSG)), session=None
    )


def _install(monkeypatch: pytest.MonkeyPatch, api: Api) -> Api:
    monkeypatch.setattr(scm_rest, "request", api.request)
    monkeypatch.setattr(scm_rest, "refresh_token", lambda c: None)
    monkeypatch.setattr(scm_rest, "bearer_session", lambda c: object())
    return api


def _tool(client: Any) -> Any:
    mcp = FastMCP("test")
    iot.register_iot_tools(mcp, lambda tenant_id="": client)
    return mcp._tool_manager.get_tool("scm_iot").fn


def _j(out: str) -> dict[str, Any]:
    return json.loads(out)


def test_unlicensed_404_is_reported_not_raised(
    monkeypatch: pytest.MonkeyPatch, client: Any
) -> None:
    msg = {"code": 404, "message": "Error: IoT tenant with TSG id 1 is not found"}
    api = _install(monkeypatch, Api([], {"/v2/device/list": (404, msg)}))
    out = _j(_tool(client)(tenant_id=TSG, action="devices"))
    assert out["licensed"] is False
    assert "not found" in out["detail"]
    assert api.calls


def test_other_errors_are_errors(monkeypatch: pytest.MonkeyPatch, client: Any) -> None:
    _install(
        monkeypatch, Api([], {"/v1/site": (429, {}), "/v1/subnet": (403, {"message": "nope"})})
    )
    fn = _tool(client)
    assert "rate limited" in _j(fn(tenant_id=TSG, action="sites"))["error"]
    assert "access denied" in _j(fn(tenant_id=TSG, action="subnets"))["error"]
    # a 404 that is not the licence message is not "unlicensed"
    _install(monkeypatch, Api([], {"/v1/site": (404, {"message": "no such path"})}))
    assert "error" in _j(fn(tenant_id=TSG, action="sites"))


def test_devices_default_is_compact_and_uses_v2_total(
    monkeypatch: pytest.MonkeyPatch, client: Any
) -> None:
    api = _install(monkeypatch, Api([_device(i) for i in range(1, 8)]))
    out = _j(_tool(client)(tenant_id=TSG, action="devices", limit=3, offset=2))
    assert out["total"] == 7
    assert out["returned"] == 3
    assert out["has_more"] is True
    assert [d["name"] for d in out["devices"]] == ["dev-3", "dev-4", "dev-5"]
    assert "extra_noise" not in out["devices"][0]
    path, params = api.calls[0]
    assert path == "/v2/device/list"
    assert params["pagelength"] == 3
    assert params["offset"] == 2
    assert "projection" not in params


def test_fields_all_and_projection(monkeypatch: pytest.MonkeyPatch, client: Any) -> None:
    api = _install(monkeypatch, Api([_device(1)]))
    fn = _tool(client)
    assert "extra_noise" in _j(fn(tenant_id=TSG, action="devices", fields="all"))["devices"][0]
    fn(tenant_id=TSG, action="devices", fields="name,ip")
    assert api.calls[-1][1]["projection"] == "name,ip"
    too_many = ",".join(f"f{i}" for i in range(51))
    assert "at most 50" in _j(fn(tenant_id=TSG, action="devices", fields=too_many))["error"]


def test_client_side_filters(monkeypatch: pytest.MonkeyPatch, client: Any) -> None:
    _install(monkeypatch, Api([_device(i) for i in range(1, 21)]))
    fn = _tool(client)
    out = _j(fn(tenant_id=TSG, action="devices", category="camera", risk_level="high", limit=50))
    assert out["scanned"] == 20
    assert {d["name"] for d in out["devices"]} == {"dev-5", "dev-15"}
    assert _j(fn(tenant_id=TSG, action="devices", text="aa:bb:cc:dd:ee:0a"))["matched"] == 1
    paged = _j(fn(tenant_id=TSG, action="devices", category="camera", limit=2, offset=1))
    assert paged["matched"] == 10
    assert paged["returned"] == 2


def test_filter_scan_is_capped_and_says_so(monkeypatch: pytest.MonkeyPatch, client: Any) -> None:
    monkeypatch.setattr(iot, "_SCAN_CAP", 2000)
    api = _install(monkeypatch, Api([_device(i) for i in range(2500)]))
    out = _j(_tool(client)(tenant_id=TSG, action="devices", text="dev-"))
    assert out["scanned"] == 2000
    assert out["total"] == 2500
    assert "first 2000 of 2500" in out["warning"]
    assert len([c for c in api.calls if c[0] == "/v2/device/list"]) == 2


def test_summary_counts_and_errors_do_not_abort(
    monkeypatch: pytest.MonkeyPatch, client: Any
) -> None:
    _install(
        monkeypatch,
        Api([_device(i) for i in range(1, 11)], {"/v1/subnet": (500, {"message": "boom"})}),
    )
    out = _j(_tool(client)(tenant_id=TSG, action="summary"))
    assert out["licensed"] is True
    assert out["devices"]["total"] == 10
    assert out["devices"]["by_category"] == {"Camera": 5, "generic": 5}
    assert out["devices"]["by_risk_level"] == {"Low": 8, "High": 2}
    assert out["alerts_active"] == 3
    assert out["vulnerabilities"] == {"total": 4, "instances": 9}
    assert out["sites"] == 2
    assert "subnets" not in out
    assert "boom" in out["errors"]["subnets"]


def test_device_needs_exactly_one_of_ip_or_mac(
    monkeypatch: pytest.MonkeyPatch, client: Any
) -> None:
    api = _install(monkeypatch, Api([]))
    fn = _tool(client)
    assert "exactly one" in _j(fn(tenant_id=TSG, action="device"))["error"]
    assert "exactly one" in _j(fn(tenant_id=TSG, action="device", ip="1.1.1.1", mac="aa"))["error"]
    assert not api.calls


def test_customerid_comes_from_the_tsg_and_name_filters_mapping(
    monkeypatch: pytest.MonkeyPatch, client: Any
) -> None:
    api = _install(monkeypatch, Api([]))
    fn = _tool(client)
    fn(tenant_id="some-label", action="policy_recommendations", profile="Axis IP Camera")
    path, params = api.calls[-1]
    assert path == "/v1/policy/recommendation"
    assert params["customerid"] == TSG
    assert params["profile"] == "Axis IP Camera"
    out = _j(fn(tenant_id=TSG, action="profile_mapping", name="printer"))
    assert out["matched"] == 1
    assert api.calls[-1][1]["customerid"] == TSG


def test_vulnerability_and_tag_parameters(monkeypatch: pytest.MonkeyPatch, client: Any) -> None:
    api = _install(monkeypatch, Api([], {"/v1/tag/list": (200, {"tags": [], "totalTags": 0})}))
    fn = _tool(client)
    fn(tenant_id=TSG, action="vulnerabilities", severity="High", include_device_ids=True)
    params = api.calls[-1][1]
    assert params["groupby"] == "vulnerability"
    assert params["severity"] == "High"
    assert params["includeDeviceIdList"] == "yes"
    assert "group_by" in _j(fn(tenant_id=TSG, action="vulnerabilities", group_by="x"))["error"]
    fn(tenant_id=TSG, action="tags")
    assert api.calls[-1][1] == {"source": "tenant"}
    assert "tag_source" in _j(fn(tenant_id=TSG, action="tags", tag_source="x"))["error"]


def test_unknown_action_and_limit_clamp(monkeypatch: pytest.MonkeyPatch, client: Any) -> None:
    api = _install(monkeypatch, Api([_device(1)]))
    fn = _tool(client)
    assert "unknown action" in _j(fn(tenant_id=TSG, action="nope"))["error"]
    fn(tenant_id=TSG, action="devices", limit=99999)
    assert api.calls[-1][1]["pagelength"] == 1000
    fn(tenant_id=TSG, action="devices", limit=0)
    assert api.calls[-1][1]["pagelength"] == 1
