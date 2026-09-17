"""scm_pab_backup / scm_pab_restore against an in-memory Browser Management API."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.tools import pab_transfer
from scm_harbourmaster_mcp.tools.pab_transfer import register_pab_transfer_tools

TICKET = "CHG-PAB-1"
SRC, DST = "1000000001", "1000000002"
CATALOG_APP = "0AP00000000000000000000000CAT"


def _resp(status: int, body: Any) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.json.return_value = body
    r.text = json.dumps(body)
    return r


class FakeBrowserApi:
    """One tenant's /seb-api/v1 state; records every POST."""

    def __init__(self, **state: list[dict[str, Any]]) -> None:
        self.state: dict[str, list[dict[str, Any]]] = {
            "applications/type/custom": [],
            "applications/type/private": [],
            "applications/type/non-web": [],
            "applications/type/localdesktopcustom": [],
            "applications/plugins": [],
            "application-groups": [],
            "device-groups": [],
            "user-groups": [],
            "users": [],
        }
        self.state.update(state)
        self.posts: list[tuple[str, dict[str, Any]]] = []
        self.fail_get: set[str] = set()
        self.session = MagicMock()
        self.session.get.side_effect = self._get
        self.session.post.side_effect = self._post
        self._next = 0

    def _path(self, url: str) -> str:
        return url.split("/seb-api/v1/", 1)[1]

    def _get(self, url: str, params: dict[str, Any], timeout: Any) -> MagicMock:
        path = self._path(url)
        if path in self.fail_get:
            return _resp(403, {"error": {"message": "forbidden"}})
        if path == "applications/plugins":
            assert "limit" not in params  # the endpoint rejects it
        return _resp(200, {"data": self.state[path], "pageInfo": {"hasNextPage": False}})

    def _post(self, url: str, json: dict[str, Any], timeout: Any) -> MagicMock:  # noqa: A002
        path = self._path(url)
        self.posts.append((path, json))
        self._next += 1
        return _resp(201, {"id": f"NEW{self._next}"})


@pytest.fixture
def source() -> FakeBrowserApi:
    return FakeBrowserApi(
        **{
            "applications/type/custom": [
                {
                    "id": "SRC-APP-1",
                    "name": "Intranet",
                    "type": "custom",
                    "urls": ["intra.example"],
                    "metadata": {"createdTime": "x"},
                    "catalog_name": None,
                },
            ],
            "applications/plugins": [
                {
                    "id": "P1",
                    "applicationId": "SRC-APP-1",
                    "plugin": {"links": [{"urlPattern": "*"}]},
                    "createTime": "x",
                    "updateTime": "x",
                },
            ],
            "application-groups": [
                {"id": "G1", "name": "Business Apps", "applications": ["SRC-APP-1", CATALOG_APP]},
                {"id": "G2", "name": "Microsoft 365", "applications": [CATALOG_APP]},
            ],
            "device-groups": [
                {
                    "id": "D1",
                    "name": "Managed Laptops",
                    "platform": "Desktop Browser",
                    "attributes": {"diskEncryption": {"enabled": True}},
                    "devices": ["dev1"],
                    "createdBy": "someone",
                },
            ],
            "user-groups": [{"id": "U1", "name": "Finance"}],
            "users": [
                {"id": "src-u1", "email": "Alice@example.com", "userGroups": [{"id": "U1"}]},
                {"id": "src-u2", "email": "bob@example.com", "userGroups": ["U1"]},
                {"id": "src-u3", "email": "carol@example.com", "userGroups": []},
            ],
        }
    )


@pytest.fixture
def target() -> FakeBrowserApi:
    return FakeBrowserApi(
        **{
            "application-groups": [
                {"id": "T-G2", "name": "Microsoft 365", "applications": [CATALOG_APP]}
            ],
            "users": [{"id": "dst-alice", "email": "alice@example.com"}],
        }
    )


def _tools(api: FakeBrowserApi, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setattr(pab_transfer, "_bearer_session_for", lambda client: api.session)
    mcp = FastMCP("test-pab-transfer")
    register_pab_transfer_tools(mcp, lambda tenant_id="": MagicMock())
    return {
        name: mcp._tool_manager.get_tool(name).fn for name in ("scm_pab_backup", "scm_pab_restore")
    }  # noqa: SLF001


def _backup(source: FakeBrowserApi, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    out = _tools(source, monkeypatch)["scm_pab_backup"](tenant_id=SRC, output_dir=str(tmp_path))
    assert "alice@example.com" not in out.lower()  # emails stay in the file
    (path,) = tmp_path.glob("pab_backup_*.json")
    return path


def test_backup_file_contents(
    source: FakeBrowserApi, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    data = json.loads(_backup(source, monkeypatch, tmp_path).read_text())
    assert data["backup_version"] == "pab-1.0" and data["source_tenant"] == SRC
    assert [a["name"] for a in data["applications"]] == ["Intranet"]
    assert len(data["plugins"]) == 1 and len(data["application_groups"]) == 2
    assert data["user_groups"] == [
        {"name": "Finance", "id": "U1", "member_emails": ["alice@example.com", "bob@example.com"]}
    ]
    assert data["errors"] == {}
    assert source.posts == []


def test_restore_dry_run_writes_nothing(
    source: FakeBrowserApi, target: FakeBrowserApi, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = _backup(source, monkeypatch, tmp_path)
    out = _tools(target, monkeypatch)["scm_pab_restore"](
        tenant_id=DST, backup_file=str(path), ticket_ref=TICKET
    )
    assert "DRY-RUN" in out and "**Would create:** 5" in out and "**Skipped:** 1" in out
    assert "1/2 members enrolled in target" in out
    assert target.posts == []


def test_restore_creates_in_order_with_remapped_ids(
    source: FakeBrowserApi, target: FakeBrowserApi, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = _backup(source, monkeypatch, tmp_path)
    out = _tools(target, monkeypatch)["scm_pab_restore"](
        tenant_id=DST, backup_file=str(path), ticket_ref=TICKET, dry_run=False, publish=True
    )
    paths = [p for p, _ in target.posts]
    assert paths == [
        "applications/type/custom",
        "applications/NEW1/plugins",
        "application-groups",
        "device-groups",
        "user-groups",
        "configuration-management/draft/publish",
    ]
    bodies = dict(target.posts)
    assert bodies["applications/type/custom"] == {
        "name": "Intranet",
        "type": "custom",
        "urls": ["intra.example"],
    }
    assert bodies["applications/NEW1/plugins"] == {"plugin": {"links": [{"urlPattern": "*"}]}}
    assert bodies["application-groups"] == {
        "name": "Business Apps",
        "applications": ["NEW1", CATALOG_APP],
    }
    assert bodies["device-groups"] == {
        "name": "Managed Laptops",
        "platform": "Desktop Browser",
        "attributes": {"diskEncryption": {"enabled": True}},
    }
    assert bodies["user-groups"] == {"name": "Finance", "userIds": ["dst-alice"]}
    assert "**Created:** 5" in out and "Draft published." in out
    assert "`Microsoft 365` | skipped — exists in target" in out


def test_existing_app_is_reused_not_recreated(
    source: FakeBrowserApi, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = _backup(source, monkeypatch, tmp_path)
    target = FakeBrowserApi(**{"applications/type/custom": [{"id": "DST-APP", "name": "Intranet"}]})
    _tools(target, monkeypatch)["scm_pab_restore"](
        tenant_id=DST, backup_file=str(path), ticket_ref=TICKET, dry_run=False
    )
    bodies = dict(target.posts)
    assert "applications/type/custom" not in bodies
    assert "applications/DST-APP/plugins" in bodies
    business = next(b for path_, b in target.posts if b.get("name") == "Business Apps")
    assert business["applications"] == ["DST-APP", CATALOG_APP]


def test_unreadable_target_aborts_before_any_write(
    source: FakeBrowserApi, target: FakeBrowserApi, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = _backup(source, monkeypatch, tmp_path)
    target.fail_get.add("device-groups")
    out = _tools(target, monkeypatch)["scm_pab_restore"](
        tenant_id=DST, backup_file=str(path), ticket_ref=TICKET, dry_run=False
    )
    assert "Restore aborted" in out and "HTTP 403" in out
    assert target.posts == []


def test_restore_input_validation(
    target: FakeBrowserApi, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    restore = _tools(target, monkeypatch)["scm_pab_restore"]
    assert "ticket_ref is mandatory" in restore(tenant_id=DST, backup_file="x.json")
    assert "not found" in restore(
        tenant_id=DST, backup_file=str(tmp_path / "nope.json"), ticket_ref=TICKET
    )
    other = tmp_path / "other.json"
    other.write_text(json.dumps({"backup_version": "1.0"}))
    assert "not a scm_pab_backup file" in restore(
        tenant_id=DST, backup_file=str(other), ticket_ref=TICKET
    )
    assert target.posts == []
