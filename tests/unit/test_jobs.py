"""Unit tests for the shared background-job store (utils/jobs.py)."""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.tools import audit as audit_tools
from scm_harbourmaster_mcp.tools import config_index_tools
from scm_harbourmaster_mcp.tools import reload as reload_mod
from scm_harbourmaster_mcp.utils import jobs
from scm_harbourmaster_mcp.utils.jobs import JobStore


class TestJobStore:
    def test_create_get_update(self) -> None:
        store = JobStore()
        jid = store.create(folder="Lab")
        job = store.get(jid)
        assert len(jid) == 8 and job["status"] == "running" and job["folder"] == "Lab"
        assert job["result"] is None and job["error"] is None
        store.update(jid, status="done", result="report")
        assert store.get(jid)["result"] == "report"

    def test_get_returns_a_copy(self) -> None:
        store = JobStore()
        jid = store.create()
        store.get(jid)["status"] = "tampered"
        assert store.get(jid)["status"] == "running"

    def test_unknown_job(self) -> None:
        store = JobStore()
        assert store.get("nope") == {}
        store.update("nope", status="done")  # no KeyError for a pruned job
        assert "nope" not in store

    def test_prune_keeps_running_jobs(self) -> None:
        store = JobStore(ttl=60)
        running, done = store.create(), store.create()
        store.update(done, status="done")
        fresh = store.create()
        store.update(fresh, status="done")
        old = time.time() - 61
        store.update(running, started_at=old)
        store.update(done, started_at=old)
        store.prune()
        assert running in store and fresh in store and done not in store

    def test_update_after_prune_is_harmless(self) -> None:
        # The old stores raised KeyError in the worker thread here.
        store = JobStore(ttl=60)
        jid = store.create()
        store.update(jid, status="error", started_at=time.time() - 61)
        store.prune()
        store.update(jid, status="done", result="late")
        assert jid not in store

    def test_concurrent_creates_are_unique(self) -> None:
        store = JobStore()
        ids: list[str] = []

        def make() -> None:
            for _ in range(200):
                ids.append(store.create())

        threads = [threading.Thread(target=make) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(set(ids)) == len(ids) == len(store) == 800

    def test_not_found_names_no_jobs(self) -> None:
        assert jobs.not_found("Job", "abc") == (
            "Job `abc` not found (finished jobs expire after 1 hour)."
        )

    def test_survives_hot_reload(self) -> None:
        assert "scm_harbourmaster_mcp.utils.jobs" in reload_mod._RELOAD_EXCLUDED


def _tools() -> dict[str, Any]:
    mcp = FastMCP("test")
    audit_tools.register_audit_tools(mcp, lambda tenant_id="": None)
    config_index_tools.register_config_index_tools(mcp, lambda tenant_id="": None)
    return {name: t.fn for name, t in mcp._tool_manager._tools.items()}


@pytest.mark.parametrize(
    ("store", "tool"),
    [
        (jobs.ASBUILT_JOBS, "scm_asbuilt_result"),
        (jobs.ASBUILT_JOBS, "scm_asbuilt_verify"),
        (jobs.DRIFT_JOBS, "scm_drift_result"),
        (jobs.INDEX_JOBS, "scm_config_index_result"),
    ],
)
def test_result_tools_never_list_other_tenants_jobs(store: JobStore, tool: str) -> None:
    other = store.create(tenant_id="9999999999")
    try:
        out = _tools()[tool](job_id="deadbeef")
    finally:
        store.clear()
    assert "not found" in out
    assert other not in out and "Active jobs" not in out
