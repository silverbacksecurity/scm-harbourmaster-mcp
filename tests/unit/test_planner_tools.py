"""Planner Phase 3b conversational-tool tests.

The run tool is exercised with a fake engine injected through the module's
test seam, so no Anthropic call happens; status/result are pure reads over
the PlanStore. Registration coverage is enforced separately by
test_planner_manifest.py (the tools must have manifest entries).
"""

from __future__ import annotations

import asyncio
import time

from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.planner import PlanStore
from scm_harbourmaster_mcp.planner.engine import PlanDraft, RevisionDraft, StepDraft
from scm_harbourmaster_mcp.tools import planner_tools
from scm_harbourmaster_mcp.tools.audit import register_audit_tools
from scm_harbourmaster_mcp.tools.planner_tools import register_planner_tools


class FakeEngine:
    def generate_plan(self, goal, tenant_scope, catalog):
        return PlanDraft(
            rationale="fake",
            steps=[StepDraft(domain="licensing", tool="scm_license_info", params_json="{}")],
        )

    def revise(self, plan, failed_step, catalog):
        return RevisionDraft(done=True)

    def synthesize(self, plan):
        return "# Fake Report\n\nOne step, all fine."


def _call(mcp: FastMCP, tool: str, **args) -> str:
    result = asyncio.run(mcp.call_tool(tool, args))
    blocks = result[0] if isinstance(result, tuple) else result
    return "\n".join(getattr(b, "text", str(b)) for b in blocks)


def _mcp_with_planner(tmp_path, monkeypatch) -> FastMCP:
    monkeypatch.setattr(planner_tools, "_engine_factory", FakeEngine)
    monkeypatch.setenv("SCM_MCP_PLAN_DIR", str(tmp_path))
    # PlanStore reads the env at import-default time; patch the module default
    monkeypatch.setattr(planner_tools, "PlanStore", lambda: PlanStore(plan_dir=tmp_path))
    mcp = FastMCP("planner-tools-test")
    # A real read tool for the plan to execute (license_info hits get_client;
    # our fake get_client returns None and the tool returns an Error string —
    # which the executor records as a failed step; that's fine for the test).
    register_audit_tools(mcp, get_client=lambda tid="": None)
    register_planner_tools(mcp, get_client=lambda tid="": None)
    return mcp


class TestConversationalTools:
    def test_run_returns_plan_id_and_polling_instructions(self, tmp_path, monkeypatch):
        mcp = _mcp_with_planner(tmp_path, monkeypatch)
        out = _call(mcp, "scm_planner_run", goal="check licences")
        assert "Planner run `plan-" in out
        assert "scm_planner_status" in out and "scm_planner_result" in out
        assert "Read-only run" in out  # no approved_write_tools → read-only note

    def test_run_names_approved_write_tools(self, tmp_path, monkeypatch):
        mcp = _mcp_with_planner(tmp_path, monkeypatch)
        out = _call(mcp, "scm_planner_run", goal="commit it", approved_write_tools=["scm_commit"])
        assert "Approved write tools this run: ['scm_commit']" in out

    def test_status_and_result_after_completion(self, tmp_path, monkeypatch):
        mcp = _mcp_with_planner(tmp_path, monkeypatch)
        out = _call(mcp, "scm_planner_run", goal="check licences")
        plan_id = out.split("`")[1]

        # the background thread finishes quickly with the fake engine
        store = PlanStore(plan_dir=tmp_path)
        for _ in range(100):
            p = store.load(plan_id)
            if p is not None and p.status.value != "running":
                break
            time.sleep(0.05)

        status = _call(mcp, "scm_planner_status", plan_id=plan_id)
        assert plan_id in status
        assert "scm_license_info" in status

        listing = _call(mcp, "scm_planner_status")
        assert plan_id in listing

        result = _call(mcp, "scm_planner_result", plan_id=plan_id)
        # engine synthesis or the mechanical fallback — either is a report
        assert "Report" in result or "Plan " in result

    def test_status_of_unknown_plan(self, tmp_path, monkeypatch):
        mcp = _mcp_with_planner(tmp_path, monkeypatch)
        assert "No plan" in _call(mcp, "scm_planner_status", plan_id="plan-nope")
        assert "No plan" in _call(mcp, "scm_planner_result", plan_id="plan-nope")
