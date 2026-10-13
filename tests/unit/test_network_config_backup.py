"""NGFW network config in the config backup (extract_network_config, no network)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.audit import extractor as extractor_mod
from scm_harbourmaster_mcp.audit.extractor import (
    NETWORK_CONFIG_RESOURCES,
    OBJECT_CONFIG_RESOURCES,
    backup_resource_payload,
    backup_snapshot,
    extract_network_config,
)
from scm_harbourmaster_mcp.audit.models import AuditSnapshot
from scm_harbourmaster_mcp.tools import audit as audit_mod

NET = "https://api.sase.paloaltonetworks.com/config/network/v1"
OBJ = "https://api.sase.paloaltonetworks.com/config/objects/v1"
DEVICES = "https://api.sase.paloaltonetworks.com/config/setup/v1/devices"


class Resp:
    def __init__(self, status: int, body: Any = None) -> None:
        self.status_code = status
        self._body = body if body is not None else {}

    @property
    def ok(self) -> bool:
        return self.status_code < 400

    def json(self) -> Any:
        return self._body

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class Session:
    """Answers GETs from {(path, folder or device): rows}; else empty."""

    def __init__(
        self,
        rows: dict[tuple[str, str], list[dict[str, Any]]],
        status: dict[str, int] | None = None,
        devices: list[dict[str, Any]] | None = None,
    ) -> None:
        self.rows = rows
        self.status = status or {}
        self.devices = devices or []
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def get(self, url: str, params: dict[str, Any] | None = None, timeout: Any = None) -> Resp:
        params = params or {}
        self.calls.append((url, params))
        if url == DEVICES:
            return Resp(200, {"data": self.devices})
        path = url.removeprefix(f"{NET}/").removeprefix(f"{OBJ}/")
        if path in self.status:
            return Resp(self.status[path])
        rows = self.rows.get((path, params.get("folder") or params["device"]), [])
        start, limit = int(params["offset"]), int(params["limit"])
        return Resp(200, {"data": rows[start : start + limit], "total": len(rows)})


class Client:
    def __init__(self, session: Session) -> None:
        self.session = session


def _snap(folder: str = "All") -> AuditSnapshot:
    return AuditSnapshot(folder=folder, tenant_id="1234567890")


def test_every_key_is_set_and_empty_by_default() -> None:
    snap = extract_network_config(Client(Session({})), _snap("Remote Networks"), "Remote Networks")
    assert set(snap.network_config) == {*NETWORK_CONFIG_RESOURCES, *OBJECT_CONFIG_RESOURCES}
    assert all(v == [] for v in snap.network_config.values())
    assert snap.extraction_errors == []


def test_device_folders_are_walked_for_all_and_deduplicated() -> None:
    shared = {"id": "pbf-1", "name": "pbf-shared", "folder": "All"}
    session = Session(
        {
            ("logical-routers", "fw-a"): [{"id": "lr-a", "name": "lr", "folder": "fw-a"}],
            ("logical-routers", "fw-b"): [{"id": "lr-b", "name": "lr", "folder": "fw-b"}],
            # Inherited objects come back from every folder query
            ("pbf-rules", "All"): [shared],
            ("pbf-rules", "fw-a"): [shared],
            ("pbf-rules", "fw-b"): [shared, {"id": "pbf-2", "name": "pbf-b", "folder": "fw-b"}],
        },
        devices=[{"name": "fw1", "folder": "fw-a"}, {"name": "fw2", "folder": "fw-b"}],
    )
    snap = extract_network_config(Client(session), _snap(), "All")
    assert [r["id"] for r in snap.network_config["logical_routers"]] == ["lr-a", "lr-b"]
    assert [r["id"] for r in snap.network_config["pbf_rules"]] == ["pbf-1", "pbf-2"]


def test_a_device_folder_backup_does_not_walk_other_folders() -> None:
    session = Session({}, devices=[{"id": "SER1", "folder": "fw-a"}])
    extract_network_config(Client(session), _snap("fw-b"), "fw-b")
    scopes = {
        tuple(sorted(p.items() - {("limit", "1000"), ("offset", "0")})) for _, p in session.calls
    }
    assert scopes == {(), (("folder", "fw-b"),)}


def test_interfaces_are_read_per_device() -> None:
    """Device-only interfaces and each device's resolved template are kept."""
    template = {"id": "if-1", "name": "$outside", "folder": "fw-a"}
    session = Session(
        {
            ("ethernet-interfaces", "fw-a"): [template],
            ("ethernet-interfaces", "SER1"): [
                {"id": "if-1", "name": "ethernet1/1", "device": "SER1"},
                {"id": "if-2", "name": "ethernet1/9", "device": "SER1"},
            ],
            ("ethernet-interfaces", "SER2"): [
                {"id": "if-1", "name": "ethernet1/1", "device": "SER2"},
            ],
        },
        devices=[
            {"id": "SER1", "folder": "fw-a"},
            {"id": "SER2", "folder": "fw-a"},
            {"id": "SER3", "folder": "fw-other"},
        ],
    )
    snap = extract_network_config(Client(session), _snap("fw-a"), "fw-a")
    rows = snap.network_config["ethernet_interfaces"]
    assert [(r["id"], r.get("device")) for r in rows] == [
        ("if-1", None),
        ("if-1", "SER1"),
        ("if-2", "SER1"),
        ("if-1", "SER2"),
    ]
    devices_read = {p.get("device") for _, p in session.calls} - {None}
    assert devices_read == {"SER1", "SER2"}
    # Only interfaces are read per device
    routers = [p for url, p in session.calls if url.endswith("/logical-routers")]
    assert all("device" not in p for p in routers)


def test_snapshot_devices_are_used_before_the_api() -> None:
    session = Session({})
    snap = _snap()
    snap.ngfw_devices = [{"id": "SER1", "folder": "fw-a"}]
    extract_network_config(Client(session), snap, "All")
    assert not any(url == DEVICES for url, _ in session.calls)
    assert {p.get("folder") for _, p in session.calls} == {"All", "fw-a", None}


def test_pages_until_total(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(extractor_mod, "_LIMIT", 2)
    rows = [{"id": f"eth-{i}", "name": f"ethernet1/{i}"} for i in range(5)]
    session = Session({("ethernet-interfaces", "fw-a"): rows})
    snap = extract_network_config(Client(session), _snap("fw-a"), "fw-a")
    assert snap.network_config["ethernet_interfaces"] == rows
    offsets = [p["offset"] for url, p in session.calls if url.endswith("/ethernet-interfaces")]
    assert offsets == ["0", "2", "4"]


def test_unavailable_resources_are_empty_and_failures_recorded() -> None:
    session = Session({}, status={"virtual-routers": 404, "gre-tunnels": 400, "pbf-rules": 500})
    snap = extract_network_config(Client(session), _snap("fw-a"), "fw-a")
    assert snap.network_config["virtual_routers"] == []
    assert snap.network_config["gre_tunnels"] == []
    assert snap.network_config["pbf_rules"] == []
    assert snap.extraction_errors == ["pbf_rules[fw-a]: HTTP 500"]


def test_backup_snapshot_leaves_the_cached_snapshot_untouched() -> None:
    cached = _snap("fw-a")
    cached.extraction_errors = ["earlier"]
    session = Session(
        {("gre-tunnels", "fw-a"): [{"id": "gre-1", "name": "gre"}]}, status={"pbf-rules": 500}
    )
    snap = backup_snapshot(Client(session), cached, "fw-a")
    assert snap.network_config["gre_tunnels"] == [{"id": "gre-1", "name": "gre"}]
    assert snap.extraction_errors == ["earlier", "pbf_rules[fw-a]: HTTP 500"]
    assert cached.network_config == {}
    assert cached.extraction_errors == ["earlier"]


def test_payload_carries_network_keys_without_clashing() -> None:
    snap = _snap()
    snap.network_config = {"logical_routers": [{"name": "lr"}]}
    snap.zones = [{"name": "trust"}]
    payload = backup_resource_payload(snap)
    assert payload["logical_routers"] == [{"name": "lr"}]
    assert payload["ethernet_interfaces"] == []
    assert payload["zones"] == [{"name": "trust"}]


def test_mcp_backup_writes_network_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    session = Session(
        {("logical-routers", "fw-a"): [{"id": "lr-a", "name": "lr", "folder": "fw-a"}]},
        devices=[{"name": "fw1", "folder": "fw-a"}],
    )
    monkeypatch.setattr(audit_mod, "extract_snapshot", lambda *a, **k: _snap())
    mcp = FastMCP("test")
    audit_mod.register_audit_tools(mcp, lambda tenant_id="": Client(session))

    out = mcp._tool_manager.get_tool("scm_config_backup").fn(tenant_id="1234567890", folder="All")

    path = Path(out.split("Backup written to: ")[1].splitlines()[0])
    resources = json.loads(path.read_text())["resources"]
    assert resources["logical_routers"] == [{"id": "lr-a", "name": "lr", "folder": "fw-a"}]
    assert set(NETWORK_CONFIG_RESOURCES) <= set(resources)
    assert "logical_routers: 1" in out


def test_diff_and_clone_tolerate_network_keys(tmp_path: Path) -> None:
    """The diff indexes the new list keys; the cloner leaves them alone."""
    from scm_harbourmaster_mcp.audit import cloner

    snap = _snap()
    snap.network_config = {"ethernet_interfaces": [{"name": "ethernet1/1", "folder": "fw-a"}]}
    assert audit_mod._index_backup_resources(backup_resource_payload(snap)["ethernet_interfaces"])

    backup = tmp_path / "b.json"
    backup.write_text(json.dumps({"resources": backup_resource_payload(snap)}))
    created: list[str] = []

    class Resource:
        def create(self, data: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
            created.append(data["name"])
            return data

    class CloneClient:
        def __getattr__(self, name: str) -> Resource:
            return Resource()

    cloner.clone_config(CloneClient(), str(backup), "dst", dry_run=False)
    assert created == []


def test_application_tags_are_read_from_the_objects_api() -> None:
    tag = {"id": "at-1", "name": "app-synthetic", "folder": "fw-a", "tags": ["sanctioned"]}
    session = Session({("application-tags", "fw-a"): [tag]})
    snap = extract_network_config(Client(session), _snap("fw-a"), "fw-a")
    assert snap.network_config["application_tags"] == [tag]
    urls = {url for url, _ in session.calls}
    assert f"{OBJ}/application-tags" in urls
    assert f"{NET}/application-tags" not in urls
    assert backup_resource_payload(snap)["application_tags"] == [tag]
