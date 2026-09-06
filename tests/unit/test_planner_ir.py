"""Planner Phase 3c IR-trigger tests.

Pins alert classification, the spec's tunnel-down template, the invariant
that every template step is a manifest-classified READ tool (a triage run
must never be able to reach a write tool), and the end-to-end run through
the PlannerLoop including the scm_ir_trigger MCP tool surface.
"""

from __future__ import annotations

import asyncio
import time

from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.planner import PlanStore, load_manifest
from scm_harbourmaster_mcp.planner.ir import (
    GENERIC_CLASS,
    INCIDENT_CLASSES,
    classify_alert,
    run_ir_trigger,
    triage_steps,
)
from scm_harbourmaster_mcp.planner.schema import PlanStatus, TriggerType
from scm_harbourmaster_mcp.tools import planner_tools
from scm_harbourmaster_mcp.tools.planner_tools import register_planner_tools


class FakeBackend:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []

    def call(self, tool, params):
        self.calls.append((tool, params))
        return "🟢 fine"


class TestClassifyAlert:
    def test_tunnel_keywords(self) -> None:
        assert classify_alert({"message": "IPSec tunnel down on branch-12"}) == "tunnel-down"
        assert classify_alert({"name": "IKE negotiation failure"}) == "tunnel-down"

    def test_cert_and_licence(self) -> None:
        assert classify_alert({"message": "Certificate gp-portal expiring"}) == "cert-expiry"
        assert classify_alert({"description": "License seat pool exhausted"}) == "licence-expiry"

    def test_config_and_connectivity(self) -> None:
        assert classify_alert({"message": "Unexpected commit by unknown admin"}) == "config-change"
        assert classify_alert({"message": "High latency and packet loss"}) == (
            "connectivity-degraded"
        )

    def test_unknown_falls_back_to_generic(self) -> None:
        assert classify_alert({"message": "something odd happened"}) == GENERIC_CLASS

    def test_empty_payload_is_generic(self) -> None:
        assert classify_alert({}) == GENERIC_CLASS

    def test_classification_is_case_insensitive(self) -> None:
        assert classify_alert({"message": "TUNNEL DOWN"}) == "tunnel-down"


class TestTriageTemplates:
    def test_tunnel_down_matches_the_epic_spec(self) -> None:
        tools = [s.tool for s in triage_steps("tunnel-down", "123", "tunnel down")]
        # the ROADMAP's worked example, plus the RCA correlator
        assert tools == [
            "sdwan_wan_ip_summary",
            "scm_ike_gateway_list",
            "scm_list_jobs",
            "sdwan_events",
            "scm_incident_rca",
        ]

    def test_every_class_uses_only_manifest_classified_read_tools(self) -> None:
        # THE safety invariant: no template may name a write tool — even
        # though the executor would deny it, the template must not try.
        manifest = load_manifest()
        for incident_class in INCIDENT_CLASSES:
            for step in triage_steps(incident_class, "123", "sym"):
                policy = manifest.policy(step.tool)  # raises if unclassified
                assert policy.access == "read", f"{incident_class}: {step.tool} is a write tool"

    def test_params_carry_tenant_and_symptom(self) -> None:
        steps = triage_steps("generic", "999", "weird outage")
        rca = next(s for s in steps if s.tool == "scm_incident_rca")
        params = rca.params()
        assert params["tenant_id"] == "999"
        assert params["symptom"] == "weird outage"
        assert params["include_drift"] is False  # triage stays fast


class TestRunIrTrigger:
    def test_end_to_end_through_the_loop(self, tmp_path) -> None:
        backend = FakeBackend()
        store = PlanStore(plan_dir=tmp_path)
        plan = run_ir_trigger(
            backend, store, {"message": "IPSec tunnel down on branch-12"}, tenant_id="123"
        )
        assert plan.status == PlanStatus.COMPLETED
        assert plan.trigger_type == TriggerType.IR_WEBHOOK
        assert plan.goal.startswith("IR triage (tunnel-down):")
        assert plan.trigger_payload["message"] == "IPSec tunnel down on branch-12"
        assert [c[0] for c in backend.calls][0] == "sdwan_wan_ip_summary"
        # persisted + report written
        assert store.load(plan.plan_id) is not None
        assert plan.final_report_ref


class TestIrTriggerTool:
    def _mcp(self, tmp_path, monkeypatch) -> FastMCP:
        monkeypatch.setattr(planner_tools, "PlanStore", lambda: PlanStore(plan_dir=tmp_path))
        mcp = FastMCP("ir-tool-test")

        # register fake target tools the triage template will call
        @mcp.tool()
        def scm_incident_summary(tenant_id: str = "", all_tenants: bool = True) -> str:
            return "🟢 no incidents"

        @mcp.tool()
        def scm_list_jobs(tenant_id: str = "", limit: int = 50, offset: int = 0) -> str:
            return "no jobs"

        @mcp.tool()
        def scm_incident_rca(
            tenant_id: str = "",
            symptom: str = "",
            lookback_hours: int = 24,
            include_drift: bool = True,
        ) -> str:
            return "# RCA\nno candidates"

        register_planner_tools(mcp, get_client=lambda tid="": None)
        return mcp

    def _call(self, mcp: FastMCP, tool: str, **args) -> str:
        result = asyncio.run(mcp.call_tool(tool, args))
        blocks = result[0] if isinstance(result, tuple) else result
        return "\n".join(getattr(b, "text", str(b)) for b in blocks)

    def test_invalid_json_is_a_clear_error(self, tmp_path, monkeypatch) -> None:
        mcp = self._mcp(tmp_path, monkeypatch)
        out = self._call(mcp, "scm_ir_trigger", alert_json="{nope")
        assert out.startswith("Error: invalid JSON")

    def test_non_object_alert_rejected(self, tmp_path, monkeypatch) -> None:
        mcp = self._mcp(tmp_path, monkeypatch)
        out = self._call(mcp, "scm_ir_trigger", alert_json='["a", "b"]')
        assert "must be a JSON object" in out

    def test_trigger_returns_class_and_plan_id(self, tmp_path, monkeypatch) -> None:
        mcp = self._mcp(tmp_path, monkeypatch)
        out = self._call(
            mcp,
            "scm_ir_trigger",
            alert_json='{"message": "something odd happened"}',  # generic class
            tenant_id="123",
        )
        assert "incident class: **generic**" in out
        assert "scm_planner_status" in out
        # the background run persists and completes against the fake tools
        plan_id = out.split("`")[1]
        store = PlanStore(plan_dir=tmp_path)
        for _ in range(100):
            p = store.load(plan_id)
            if p is not None and p.status != PlanStatus.RUNNING:
                break
            time.sleep(0.05)
        assert p is not None
        assert p.trigger_type == TriggerType.IR_WEBHOOK
