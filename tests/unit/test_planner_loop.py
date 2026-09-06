"""Planner Phase 2 loop tests — fake engine + fake backend, real manifest.

Pins the loop invariants from the epic: persistence on every state change,
write-approval enforcement at runtime, max-2-retries, bounded revision,
resume-after-crash, and the always-finish-with-a-report guarantee.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scm_harbourmaster_mcp.planner import (
    PlannerLoop,
    PlanStatus,
    PlanStore,
    StepExecutor,
    StepStatus,
    load_manifest,
)
from scm_harbourmaster_mcp.planner.engine import PlanDraft, RevisionDraft, StepDraft
from scm_harbourmaster_mcp.planner.schema import Plan, PlanStep, TriggerType


def _draft(tool: str, domain: str = "operational_health", params: dict | None = None) -> StepDraft:
    return StepDraft(domain=domain, tool=tool, params_json=json.dumps(params or {}))


class FakeEngine:
    """Scriptable engine: fixed plan, scriptable revisions, canned report."""

    def __init__(self, plan_steps, revisions=None, report="# Report\n\nAll good."):
        self.plan_steps = plan_steps
        self.revisions = list(revisions or [])
        self.report = report
        self.revise_calls = 0

    def generate_plan(self, goal, tenant_scope, catalog):
        return PlanDraft(rationale="scripted", steps=self.plan_steps)

    def revise(self, plan, failed_step, catalog):
        self.revise_calls += 1
        if self.revisions:
            return self.revisions.pop(0)
        return RevisionDraft(done=True)

    def synthesize(self, plan):
        return self.report


class FakeBackend:
    """Scriptable backend: map of tool → list of successive results (or exception)."""

    def __init__(self, script: dict[str, list]):
        self.script = {k: list(v) for k, v in script.items()}
        self.calls: list[tuple[str, dict]] = []

    def call(self, tool_name, params):
        self.calls.append((tool_name, params))
        outcomes = self.script.get(tool_name, ["ok-result"])
        outcome = outcomes.pop(0) if len(outcomes) > 1 else outcomes[0]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


@pytest.fixture()
def manifest():
    return load_manifest()


def _loop(tmp_path: Path, manifest, engine, backend, approve=None, **kw) -> PlannerLoop:
    store = PlanStore(plan_dir=tmp_path)
    executor = StepExecutor(manifest, backend, approve_write=approve)
    return PlannerLoop(manifest, engine, executor, store, **kw)


class TestHappyPath:
    def test_two_read_steps_complete_with_report(self, tmp_path, manifest):
        engine = FakeEngine([_draft("scm_license_info"), _draft("scm_cert_scan")])
        backend = FakeBackend({})
        loop = _loop(tmp_path, manifest, engine, backend)

        plan = loop.run("check licences and certs", TriggerType.SCHEDULED)

        assert plan.status == PlanStatus.COMPLETED
        assert [s.status for s in plan.steps] == [StepStatus.OK, StepStatus.OK]
        assert Path(plan.final_report_ref).read_text().startswith("# Report")
        # persisted plan matches in-memory state
        reloaded = PlanStore(plan_dir=tmp_path).load(plan.plan_id)
        assert reloaded is not None and reloaded.status == PlanStatus.COMPLETED

    def test_audit_trail_records_every_step(self, tmp_path, manifest):
        engine = FakeEngine([_draft("scm_license_info")])
        loop = _loop(tmp_path, manifest, engine, FakeBackend({}))
        plan = loop.run("audit test")
        events = [e["event"] for e in loop.store.read_audit(plan.plan_id)]
        assert events[0] == "run_started"
        assert "plan_generated" in events
        assert "step_started" in events and "step_finished" in events
        assert events[-1] == "run_finished"


class TestSafetyRails:
    def test_write_step_without_approver_is_skipped(self, tmp_path, manifest):
        engine = FakeEngine([_draft("scm_commit", domain="config_change")])
        backend = FakeBackend({})
        loop = _loop(tmp_path, manifest, engine, backend)  # no approver

        plan = loop.run("commit the changes")

        assert plan.steps[0].status == StepStatus.SKIPPED
        assert "human approval" in plan.steps[0].result_summary
        assert backend.calls == []  # the tool was NEVER executed
        assert plan.status == PlanStatus.COMPLETED_PARTIAL

    def test_write_step_with_approval_executes(self, tmp_path, manifest):
        engine = FakeEngine([_draft("scm_commit", domain="config_change")])
        backend = FakeBackend({"scm_commit": ["committed"]})
        loop = _loop(tmp_path, manifest, engine, backend, approve=lambda t, p: True)
        plan = loop.run("commit the changes")
        assert plan.steps[0].status == StepStatus.OK
        assert backend.calls == [("scm_commit", {})]

    def test_denying_approver_skips_and_never_calls(self, tmp_path, manifest):
        engine = FakeEngine([_draft("scm_restart", domain="operational_health")])
        backend = FakeBackend({})
        loop = _loop(tmp_path, manifest, engine, backend, approve=lambda t, p: False)
        plan = loop.run("restart the server")
        assert plan.steps[0].status == StepStatus.SKIPPED
        assert backend.calls == []

    def test_unknown_tool_skipped_at_intake(self, tmp_path, manifest):
        engine = FakeEngine([_draft("scm_tool_that_does_not_exist")])
        backend = FakeBackend({})
        loop = _loop(tmp_path, manifest, engine, backend)
        plan = loop.run("use a hallucinated tool")
        assert plan.steps[0].status == StepStatus.SKIPPED
        assert "no manifest entry" in plan.steps[0].result_summary
        assert backend.calls == []


class TestFailurePolicy:
    def test_retry_policy_gets_two_retries_then_succeeds(self, tmp_path, manifest):
        engine = FakeEngine([_draft("scm_license_info")])
        backend = FakeBackend(
            {"scm_license_info": ["Error: transient", "Error: transient", "fine"]}
        )
        loop = _loop(tmp_path, manifest, engine, backend)
        plan = loop.run("licences")
        assert plan.steps[0].status == StepStatus.OK
        assert plan.steps[0].retries == 2

    def test_exhausted_retries_mark_failed_and_run_is_partial(self, tmp_path, manifest):
        engine = FakeEngine([_draft("scm_license_info"), _draft("scm_cert_scan")])
        backend = FakeBackend({"scm_license_info": ["Error: down"]})
        loop = _loop(tmp_path, manifest, engine, backend)
        plan = loop.run("licences then certs")
        assert plan.steps[0].status == StepStatus.FAILED
        assert plan.steps[1].status == StepStatus.OK  # loop continued past the failure
        assert plan.status == PlanStatus.COMPLETED_PARTIAL

    def test_fallback_policy_annotates_documented_failure_mode(self, tmp_path, manifest):
        engine = FakeEngine([_draft("scm_remote_network_list", domain="deployment")])
        backend = FakeBackend({"scm_remote_network_list": ["Error: validation error"]})
        loop = _loop(tmp_path, manifest, engine, backend)
        plan = loop.run("list remote networks")
        assert plan.steps[0].status == StepStatus.FAILED
        assert "scm_ike_gateway_list" in plan.steps[0].result_summary  # fallback named

    def test_revision_adds_fallback_step_after_failure(self, tmp_path, manifest):
        engine = FakeEngine(
            [_draft("scm_remote_network_list", domain="deployment")],
            revisions=[
                RevisionDraft(
                    done=False,
                    reason="use documented fallback",
                    add_steps=[_draft("scm_ike_gateway_list", domain="deployment")],
                )
            ],
        )
        backend = FakeBackend({"scm_remote_network_list": ["Error: validation error"]})
        loop = _loop(tmp_path, manifest, engine, backend)
        plan = loop.run("list remote networks")
        assert [s.tool for s in plan.steps] == ["scm_remote_network_list", "scm_ike_gateway_list"]
        assert plan.steps[1].status == StepStatus.OK
        assert len(plan.revision_history) == 1

    def test_revisions_are_bounded(self, tmp_path, manifest):
        # Every added step fails too; revision keeps proposing more.
        endless = RevisionDraft(
            done=False, reason="try again", add_steps=[_draft("scm_license_info")]
        )
        engine = FakeEngine(
            [_draft("scm_license_info")],
            revisions=[endless.model_copy(deep=True) for _ in range(50)],
        )
        backend = FakeBackend({"scm_license_info": ["Error: always down"]})
        loop = _loop(tmp_path, manifest, engine, backend, max_revisions=3)
        plan = loop.run("flapping tool")
        assert engine.revise_calls <= 4  # bounded, not 50
        assert plan.status == PlanStatus.COMPLETED_PARTIAL


class TestAlwaysFinishWithReport:
    def test_engine_failure_at_generation_still_produces_report(self, tmp_path, manifest):
        class ExplodingEngine(FakeEngine):
            def generate_plan(self, *a, **k):
                raise RuntimeError("api down")

        loop = _loop(tmp_path, manifest, ExplodingEngine([]), FakeBackend({}))
        plan = loop.run("anything")
        assert plan.status == PlanStatus.FAILED
        assert Path(plan.final_report_ref).exists()
        assert "plan generation failed" in Path(plan.final_report_ref).read_text()

    def test_synthesis_failure_degrades_to_fallback_report(self, tmp_path, manifest):
        class NoSynthEngine(FakeEngine):
            def synthesize(self, plan):
                raise RuntimeError("refused")

        engine = NoSynthEngine([_draft("scm_license_info")])
        loop = _loop(tmp_path, manifest, engine, FakeBackend({}))
        plan = loop.run("licences")
        report = Path(plan.final_report_ref).read_text()
        assert "Generated mechanically" in report
        assert "scm_license_info" in report


class TestResume:
    def test_resume_reruns_only_unfinished_steps(self, tmp_path, manifest):
        store = PlanStore(plan_dir=tmp_path)
        # Simulate a crash: step 1 done, step 2 was mid-flight (RUNNING), step 3 pending.
        plan = Plan(trigger_type=TriggerType.SCHEDULED, goal="resume me")
        plan.steps = [
            PlanStep(
                step_id="s1",
                domain="licensing",
                tool="scm_license_info",
                status=StepStatus.OK,
                result_summary="done pre-crash",
            ),
            PlanStep(
                step_id="s2", domain="certificates", tool="scm_cert_scan", status=StepStatus.RUNNING
            ),
            PlanStep(step_id="s3", domain="licensing", tool="scm_licence_forecast"),
        ]
        store.save(plan)

        engine = FakeEngine([])
        backend = FakeBackend({})
        executor = StepExecutor(load_manifest(), backend)
        loop = PlannerLoop(load_manifest(), engine, executor, store)
        resumed = loop.resume(plan.plan_id)

        assert resumed.status == PlanStatus.COMPLETED
        assert resumed.steps[0].result_summary == "done pre-crash"  # untouched
        called = [c[0] for c in backend.calls]
        assert called == ["scm_cert_scan", "scm_licence_forecast"]  # s1 NOT re-run

    def test_resume_of_terminal_plan_is_a_noop(self, tmp_path, manifest):
        store = PlanStore(plan_dir=tmp_path)
        plan = Plan(trigger_type=TriggerType.SCHEDULED, goal="done", status=PlanStatus.COMPLETED)
        store.save(plan)
        loop = _loop(tmp_path, manifest, FakeEngine([]), FakeBackend({}))
        loop.store = store
        assert loop.resume(plan.plan_id).status == PlanStatus.COMPLETED

    def test_resume_unknown_plan_raises(self, tmp_path, manifest):
        loop = _loop(tmp_path, manifest, FakeEngine([]), FakeBackend({}))
        with pytest.raises(FileNotFoundError):
            loop.resume("plan-nope")


class TestStepDraftParams:
    def test_params_json_round_trip(self):
        d = _draft("scm_license_info", params={"tenant_id": "123"})
        assert d.params() == {"tenant_id": "123"}

    def test_malformed_params_json_degrades_to_empty(self):
        d = StepDraft(domain="licensing", tool="scm_license_info", params_json="{not json")
        assert d.params() == {}
