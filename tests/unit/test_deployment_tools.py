"""Tests for deployment tools: commit, push tracking, rollback, config versions (no network)."""

from __future__ import annotations

import functools
import inspect
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.tools import deployment as dep

TENANT = "1234567890"
_CV = "/config/operations/v1/config-versions"


def _tools(client: Any) -> dict[str, Any]:
    mcp = FastMCP("test")
    dep.register_deployment_tools(mcp, lambda tenant_id="": client)
    return {name: _gated(t.fn) for name, t in mcp._tool_manager._tools.items()}


def _gated(fn: Any) -> Any:
    """Default the write-safety args so tests exercise the apply path.

    Write tools default to ``dry_run=True`` and require ``ticket_ref``; the
    dry-run contract itself is covered in ``test_write_safety.py``.
    """
    if "ticket_ref" not in inspect.signature(fn).parameters:
        return fn
    return functools.partial(fn, ticket_ref="CHG-TEST", dry_run=False)


def _ago(**delta: int) -> str:
    return (datetime.now(UTC) - timedelta(**delta)).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── helpers ────────────────────────────────────────────────────────────────


class TestHelpers:
    def test_age_formats(self) -> None:
        assert dep._age(None) == "—"
        assert dep._age(_ago(days=2, hours=3)).startswith("2d 3h")
        assert dep._age(_ago(hours=5, minutes=10)).startswith("5h 1")
        assert dep._age(_ago(minutes=7)) in {"7m ago", "6m ago", "8m ago"}
        assert dep._age("not-a-date") == "not-a-date"

    def test_cv_get_swallows_errors_and_non_dicts(self) -> None:
        client = MagicMock()
        client.get.return_value = {"data": []}
        assert dep._cv_get(client, "/x") == {"data": []}
        client.get.return_value = ["list"]
        assert dep._cv_get(client, "/x") == {}
        client.get.side_effect = RuntimeError("500")
        assert dep._cv_get(client, "/x") == {}


# ── simple list/get/commit tools ───────────────────────────────────────────


class TestSimpleTools:
    def test_remote_networks_always_use_fixed_container(self) -> None:
        client = MagicMock()
        client.remote_network.list.return_value = [{"name": f"rn{i}"} for i in range(5)]
        tools = _tools(client)
        out = tools["scm_remote_network_list"](tenant_id=TENANT, folder="ignored", limit=2)
        client.remote_network.list.assert_called_once_with(folder="Remote Networks")
        assert "rn1" in out and "rn2" not in out

        tools["scm_remote_network_get"](tenant_id=TENANT, name="rn0", folder="ignored")
        client.remote_network.fetch.assert_called_once_with(name="rn0", folder="Remote Networks")

    def test_service_connection_and_bandwidth_limit(self) -> None:
        client = MagicMock()
        client.service_connection.list.return_value = [{"name": "sc1"}, {"name": "sc2"}]
        client.bandwidth_allocation.list.return_value = [{"name": "bw1"}]
        tools = _tools(client)
        assert "sc2" not in tools["scm_service_connection_list"](folder="x", limit=1)
        assert "bw1" in tools["scm_bandwidth_allocation_list"](folder="x")
        # a negative limit is clamped to zero rather than slicing from the end
        assert json.loads(tools["scm_bandwidth_allocation_list"](folder="x", limit=-3)) == []

    def test_commit_defaults_description_and_is_sync(self) -> None:
        client = MagicMock()
        client.commit.return_value = {"job_id": "7"}
        _tools(client)["scm_commit"](tenant_id=TENANT, folders=["Mobile Users"])
        kwargs = client.commit.call_args.kwargs
        assert kwargs["folders"] == ["Mobile Users"]
        assert kwargs["sync"] is True and kwargs["timeout"] == 300
        assert "scm-harbourmaster-mcp" in kwargs["description"]

    def test_commit_default_scope_is_service_account(self) -> None:
        client = MagicMock()
        client.commit.return_value = {"job_id": "7"}
        _tools(client)["scm_commit"](tenant_id=TENANT, folders=["Shared"])
        assert client.commit.call_args.kwargs["admin"] is None
        client.post.assert_not_called()

    def test_commit_named_admins_are_passed_through(self) -> None:
        client = MagicMock()
        client.commit.return_value = {"job_id": "7"}
        _tools(client)["scm_commit"](
            tenant_id=TENANT, folders=["Shared"], admin="svc@example.com, ops@example.com"
        )
        assert client.commit.call_args.kwargs["admin"] == ["svc@example.com", "ops@example.com"]

    def test_commit_all_admins_omits_admin_field(self) -> None:
        client = MagicMock()
        client.post.return_value = {"success": True, "job_id": "22"}
        out = _tools(client)["scm_commit"](tenant_id=TENANT, folders=["Shared"], admin="ALL")
        client.commit.assert_not_called()
        (path,) = client.post.call_args.args
        assert path == "/config/operations/v1/config-versions/candidate:push"
        assert client.post.call_args.kwargs["json"] == {
            "folders": ["Shared"],
            "description": "Committed via scm-harbourmaster-mcp",
        }
        client.wait_for_job.assert_called_once_with("22", timeout=300)
        assert "22" in out

    def test_commit_all_cannot_mix_with_named_admins(self) -> None:
        client = MagicMock()
        out = _tools(client)["scm_commit"](tenant_id=TENANT, folders=["x"], admin="all,a@b.c")
        assert out.startswith("Error:")
        client.commit.assert_not_called()
        client.post.assert_not_called()

    def test_commit_dry_run_shows_admin_scope(self) -> None:
        client = MagicMock()
        fn = _tools(client)["scm_commit"]
        out = fn.func(tenant_id=TENANT, folders=["Shared"], ticket_ref="CHG-1")
        assert "this service account's own changes only" in out
        client.commit.assert_not_called()

    def test_commit_error_is_normalised(self) -> None:
        client = MagicMock()
        client.commit.side_effect = RuntimeError("commit locked")
        out = _tools(client)["scm_commit"](tenant_id=TENANT, folders=["x"])
        assert out == "Error: [RuntimeError] commit locked"

    def test_job_status(self) -> None:
        client = MagicMock()
        client.get_job_status.return_value = {"status": "FIN"}
        assert "FIN" in _tools(client)["scm_job_status"](job_id="42")
        client.get_job_status.assert_called_once_with("42")


class TestListJobs:
    def test_filters_and_caps_limit(self) -> None:
        jobs = [
            SimpleNamespace(
                id="1",
                type_str="CommitAndPush",
                result_str="OK",
                uname="admin@example.com",
                description="change",
                start_ts="t0",
                end_ts="t1",
                percent=100,
                parent_id=None,
            ),
            SimpleNamespace(id="2", type_str="NGFW_Push", result_str="FAIL"),
        ]
        client = MagicMock()
        client.list_jobs.return_value = SimpleNamespace(data=jobs, total=9)
        out = json.loads(_tools(client)["scm_list_jobs"](limit=999, offset=5, job_type="commit"))
        client.list_jobs.assert_called_once_with(limit=200, offset=5)
        assert out["total"] == 9 and out["showing"] == 1 and out["offset"] == 5
        assert out["jobs"][0]["user"] == "admin@example.com"

    def test_no_jobs(self) -> None:
        client = MagicMock()
        client.list_jobs.return_value = object()  # no .data attribute
        out = json.loads(_tools(client)["scm_list_jobs"]())
        assert out == {"total": 0, "jobs": [], "note": "No jobs found."}


# ── scm_config_versions ────────────────────────────────────────────────────


class TestConfigVersions:
    def test_marks_running_version_per_scope(self) -> None:
        client = MagicMock()

        def _get(path: str) -> Any:
            if path.endswith("/running"):
                return {
                    "data": [
                        {"device": "Mobile Users", "version": 12},
                        {"device": "007951000123456", "version": 11},
                        {"version": 99},  # no device -> ignored
                    ]
                }
            return {
                "total": 3,
                "data": [
                    {
                        "id": 12,
                        "version": "192-external",
                        "created_at": _ago(hours=1),
                        "created_by": "long.admin.name@example.com",
                        "description": "x" * 60,
                        "scope": "Mobile Users, Remote Networks",
                    },
                    {"id": 11, "ngfw_scope": "007951000123456", "admin": "ops"},
                    {"version": "10", "scope": "Remote Networks"},
                ],
            }

        client.get.side_effect = _get
        out = _tools(client)["scm_config_versions"](tenant_id=TENANT)
        lines = out.splitlines()
        row12 = next(line for line in lines if line.startswith("12 "))
        row11 = next(line for line in lines if line.startswith("11 "))
        row10 = next(line for line in lines if line.startswith("10 "))
        assert row12.endswith("◀ running") and row11.endswith("◀ running")
        assert "running" not in row10
        # admin column is sized to content, not clipped
        assert "long.admin.name@example.com" in row12
        # description truncated to 40 chars
        assert "x" * 41 not in out
        assert "Total versions: 3" in out
        assert "Mobile Users=12" in out
        assert f"Config Versions — {TENANT}" in out

    def test_no_versions(self) -> None:
        client = MagicMock()
        client.get.side_effect = lambda p: (
            {"data": [{"device": "Mobile Users", "version": 4}]} if p.endswith("running") else {}
        )
        out = _tools(client)["scm_config_versions"](tenant_id="")
        assert "No config versions found" in out
        assert "Running versions: Mobile Users=4" in out

        client.get.side_effect = RuntimeError("down")
        assert "Running versions: unknown" in _tools(client)["scm_config_versions"]()


# ── scm_config_push_track ──────────────────────────────────────────────────


def _job(result: str, **extra: Any) -> SimpleNamespace:
    start = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    fields: dict[str, Any] = {
        "result_str": result,
        "status_str": "FIN",
        "percent": 100,
        "details": "",
        "summary": "",
        "start_ts": start,
        "end_ts": start + timedelta(seconds=125),
    }
    fields.update(extra)
    return SimpleNamespace(**fields)


class TestPushTrack:
    def _client(self, job: Any) -> MagicMock:
        client = MagicMock()
        client.commit.return_value = SimpleNamespace(job_id="job-1")
        client.wait_for_job.return_value = SimpleNamespace(data=[job]) if job else None
        client.get.return_value = {
            "data": [
                {"device": "Mobile Users", "version": 20},
                {"device": "Remote Networks", "version": 21},
            ]
        }
        return client

    def test_success(self) -> None:
        client = self._client(_job("OK", summary="pushed", details='{"warnings": []}'))
        out = _tools(client)["scm_config_push_track"](
            tenant_id=TENANT, folders=["Mobile Users"], timeout=60
        )
        assert "✅ Config Push — OK" in out
        assert "| Duration | 2m 5s |" in out
        assert "**Summary:** pushed" in out
        assert '"warnings": []' in out
        assert client.commit.call_args.kwargs["sync"] is False
        client.wait_for_job.assert_called_once_with("job-1", timeout=60, poll_interval=10)
        client.post.assert_not_called()

    def test_failure_rolls_back_only_pushed_scopes(self) -> None:
        client = self._client(_job("FAIL", details="not json", end_ts=None))
        out = _tools(client)["scm_config_push_track"](
            tenant_id=TENANT, folders=["Mobile Users"], rollback_on_failure=True
        )
        assert "❌ Config Push — FAIL" in out
        assert "**Details:** not json" in out
        assert "| Duration | — |" in out
        client.post.assert_called_once_with(f"{_CV}/20:load")
        assert "Auto-rollback triggered**: Mobile Users → v20" in out

    def test_failure_rollback_errors_and_skips(self) -> None:
        client = self._client(_job("FAIL"))
        client.post.side_effect = RuntimeError("load refused")
        out = _tools(client)["scm_config_push_track"](
            tenant_id=TENANT, folders=["Mobile Users"], rollback_on_failure=True
        )
        assert "Auto-rollback FAILED** for: Mobile Users: load refused" in out

        client = self._client(_job("FAIL"))
        out = _tools(client)["scm_config_push_track"](
            tenant_id=TENANT, folders=["Prisma Access"], rollback_on_failure=True
        )
        assert "Auto-rollback skipped" in out

    def test_no_status_timeout_and_error(self) -> None:
        client = self._client(None)
        out = _tools(client)["scm_config_push_track"](tenant_id=TENANT, folders=["x"], timeout=5)
        assert "status could not be retrieved within 5s" in out

        client.wait_for_job.side_effect = TimeoutError()
        out = _tools(client)["scm_config_push_track"](tenant_id=TENANT, folders=["x"], timeout=5)
        assert "timed out after 5s" in out

        client.commit.side_effect = RuntimeError("no candidate")
        out = _tools(client)["scm_config_push_track"](tenant_id=TENANT, folders=["x"])
        assert out == "Error: [RuntimeError] no candidate"

    def test_short_duration_in_seconds(self) -> None:
        start = datetime(2026, 1, 1, tzinfo=UTC)
        client = self._client(_job("OK", start_ts=start, end_ts=start + timedelta(seconds=42)))
        assert "| Duration | 42s |" in _tools(client)["scm_config_push_track"](
            tenant_id=TENANT, folders=["x"]
        )


# ── scm_config_rollback ────────────────────────────────────────────────────


class TestRollback:
    @pytest.mark.parametrize(
        "ver_info",
        [
            [{"created_at": "2026-01-01T00:00:00Z", "description": "good", "created_by": "ops"}],
            {"timestamp": "2026-01-01T00:00:00Z", "description": "good", "admin": "ops"},
        ],
    )
    def test_load_only(self, ver_info: Any) -> None:
        client = MagicMock()
        client.get.return_value = ver_info
        out = _tools(client)["scm_config_rollback"](tenant_id=TENANT, version=17)
        client.post.assert_called_once_with(f"{_CV}/17:load")
        client.commit.assert_not_called()
        assert "Version 17 Loaded to Candidate" in out
        assert "| Original description | good |" in out
        assert "| Original admin | ops |" in out
        assert "No changes have been pushed yet" in out

    def test_commit_immediately(self) -> None:
        client = MagicMock()
        client.get.side_effect = RuntimeError("metadata unavailable")
        client.commit.return_value = SimpleNamespace(job_id="job-9")
        out = _tools(client)["scm_config_rollback"](
            tenant_id=TENANT, version=3, commit_immediately=True
        )
        assert "unknown date" in out
        assert "Committed immediately** — Job ID: `job-9`" in out
        kwargs = client.commit.call_args.kwargs
        assert kwargs["folders"] == ["all"]
        assert kwargs["description"] == "Rollback to version 3 via scm-harbourmaster-mcp"

    def test_load_failure_is_normalised(self) -> None:
        client = MagicMock()
        client.get.return_value = {}
        client.post.side_effect = RuntimeError("version not found")
        out = _tools(client)["scm_config_rollback"](tenant_id=TENANT, version=999)
        assert out == "Error: [RuntimeError] version not found"
