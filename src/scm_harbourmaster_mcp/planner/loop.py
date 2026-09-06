"""
Planner Phase 2 — the loop.

Trigger → Plan generation → Execute step → Observe → Revise → repeat →
Synthesis → Report. One loop; the three trigger surfaces (scheduled,
conversational, IR webhook) are just different callers of `run()`.

Loop invariants (from the epic):
  - Every state change persists to disk before the loop proceeds — plans
    survive an MCP server restart and resume via `resume(plan_id)`.
  - The run ALWAYS finishes with a report, partial if necessary. Engine
    failures, backend crashes, and refusals degrade to a generated
    fallback report — never to a silent abort.
  - Revisions are bounded (max_revisions) so a flapping failure can't
    loop forever.
  - Steps whose tool isn't in the manifest are skipped at intake — the
    executor would refuse them anyway, but catching them at plan time
    keeps the audit trail clean.
"""

from __future__ import annotations

from typing import Any

from ..utils.logging import get_logger
from .engine import PlanningEngine, StepDraft, build_catalog
from .executor import StepExecutor
from .manifest import Manifest, UnknownToolError
from .schema import Plan, PlanStatus, PlanStep, Revision, StepStatus, TriggerType
from .store import PlanStore

logger = get_logger(__name__)


class PlannerLoop:
    def __init__(
        self,
        manifest: Manifest,
        engine: PlanningEngine,
        executor: StepExecutor,
        store: PlanStore,
        max_revisions: int = 5,
        max_steps: int = 30,
    ) -> None:
        self.manifest = manifest
        self.engine = engine
        self.executor = executor
        self.store = store
        self.max_revisions = max_revisions
        self.max_steps = max_steps

    # ── intake ────────────────────────────────────────────────────────────

    def _intake_steps(self, plan: Plan, drafts: list[StepDraft]) -> None:
        """Validate drafted steps against the manifest and append them."""
        for draft in drafts:
            if len(plan.steps) >= self.max_steps:
                self.store.audit(plan.plan_id, "step_dropped_max_steps", tool=draft.tool)
                break
            step = PlanStep(
                step_id=f"s{len(plan.steps) + 1}",
                domain=draft.domain,
                tool=draft.tool,
                params=draft.params(),
            )
            try:
                self.manifest.policy(draft.tool)
            except UnknownToolError:
                step.status = StepStatus.SKIPPED
                step.result_summary = "skipped at intake: tool has no manifest entry"
                self.store.audit(plan.plan_id, "step_refused_unknown_tool", tool=draft.tool)
            plan.steps.append(step)

    # ── public API ────────────────────────────────────────────────────────

    def run(
        self,
        goal: str,
        trigger_type: TriggerType = TriggerType.CONVERSATIONAL,
        trigger_payload: dict[str, Any] | None = None,
        tenant_scope: str | list[str] = "all",
        persona: str = "",
    ) -> Plan:
        plan = Plan(
            trigger_type=trigger_type,
            trigger_payload=trigger_payload or {},
            tenant_scope=tenant_scope,
            persona=persona,
            goal=goal,
        )
        self.store.save(plan)
        self.store.audit(plan.plan_id, "run_started", goal=goal, trigger=trigger_type.value)

        catalog = build_catalog(self.manifest)
        try:
            draft = self.engine.generate_plan(goal, str(tenant_scope), catalog)
            self._intake_steps(plan, draft.steps)
            self.store.audit(plan.plan_id, "plan_generated", steps=len(plan.steps))
        except Exception as exc:
            self.store.audit(plan.plan_id, "plan_generation_failed", error=str(exc))
            plan.status = PlanStatus.FAILED
            self._finish(plan, note=f"plan generation failed: {exc}")
            return plan

        self.store.save(plan)
        return self._execute(plan, catalog)

    def resume(self, plan_id: str) -> Plan:
        """Continue a persisted plan after a restart. Completed steps stay done."""
        plan = self.store.load(plan_id)
        if plan is None:
            raise FileNotFoundError(f"no persisted plan {plan_id!r}")
        if plan.status != PlanStatus.RUNNING:
            return plan  # already terminal — nothing to resume
        # A step left RUNNING by a crash is unfinished — re-queue it.
        for step in plan.steps:
            if step.status == StepStatus.RUNNING:
                step.status = StepStatus.PENDING
                step.result_summary = ""
        self.store.audit(plan.plan_id, "run_resumed")
        return self._execute(plan, build_catalog(self.manifest))

    # ── the loop ──────────────────────────────────────────────────────────

    def _execute(self, plan: Plan, catalog: str) -> Plan:
        revisions = 0
        try:
            while (step := plan.next_pending()) is not None:
                self.store.audit(
                    plan.plan_id,
                    "step_started",
                    step_id=step.step_id,
                    tool=step.tool,
                    params=step.params,
                )
                self.store.save(plan)  # persist RUNNING transition-to-be
                self.executor.execute(step)
                self.store.save(plan)
                self.store.audit(
                    plan.plan_id,
                    "step_finished",
                    step_id=step.step_id,
                    tool=step.tool,
                    status=step.status.value,
                    retries=step.retries,
                    result_summary=step.result_summary[:400],
                )

                if step.status == StepStatus.FAILED and revisions < self.max_revisions:
                    revisions += self._maybe_revise(plan, step, catalog)
        except Exception as exc:  # loop-level crash — partial report, never silent
            logger.error("planner_loop_crashed", plan_id=plan.plan_id, error=str(exc))
            self.store.audit(plan.plan_id, "loop_crashed", error=str(exc))
            plan.status = PlanStatus.FAILED
            self._finish(plan, note=f"loop crashed: {exc}")
            return plan

        counts = plan.counts
        plan.status = (
            PlanStatus.COMPLETED
            if counts.get("failed", 0) == 0 and counts.get("skipped", 0) == 0
            else PlanStatus.COMPLETED_PARTIAL
        )
        self._finish(plan)
        return plan

    def _maybe_revise(self, plan: Plan, failed_step: PlanStep, catalog: str) -> int:
        """Ask the engine whether to revise after a failure. Returns 1 if revised."""
        try:
            rev = self.engine.revise(plan, failed_step, catalog)
        except Exception as exc:
            self.store.audit(plan.plan_id, "revision_failed", error=str(exc))
            return 0
        if rev.done and not rev.add_steps and not rev.skip_step_ids:
            return 0
        for step in plan.steps:
            if step.step_id in rev.skip_step_ids and step.status == StepStatus.PENDING:
                step.status = StepStatus.SKIPPED
                step.result_summary = f"skipped by revision: {rev.reason}"
        self._intake_steps(plan, rev.add_steps)
        plan.revision_history.append(
            Revision(
                reason=rev.reason or f"step {failed_step.step_id} failed",
                change=(
                    f"skipped {len(rev.skip_step_ids)} step(s), added {len(rev.add_steps)} step(s)"
                ),
            )
        )
        self.store.save(plan)
        self.store.audit(
            plan.plan_id,
            "plan_revised",
            reason=rev.reason,
            skipped=rev.skip_step_ids,
            added=[s.tool for s in rev.add_steps],
        )
        return 1

    # ── synthesis & report ────────────────────────────────────────────────

    def _finish(self, plan: Plan, note: str = "") -> None:
        """Synthesize the report — or degrade to the fallback — and persist."""
        report = ""
        if plan.steps and plan.status != PlanStatus.FAILED:
            try:
                report = self.engine.synthesize(plan)
            except Exception as exc:
                self.store.audit(plan.plan_id, "synthesis_failed", error=str(exc))
        if not report:
            report = self._fallback_report(plan, note)
        path = self.store.save_report(plan.plan_id, report)
        plan.final_report_ref = str(path)
        self.store.save(plan)
        self.store.audit(plan.plan_id, "run_finished", status=plan.status.value, report=str(path))

    @staticmethod
    def _fallback_report(plan: Plan, note: str) -> str:
        """Mechanical partial report — the always-available floor."""
        lines = [
            f"# Plan {plan.plan_id} — {plan.status.value.upper()}",
            "",
            f"**Goal:** {plan.goal}",
            f"**Trigger:** {plan.trigger_type.value}  |  **Tenant scope:** {plan.tenant_scope}",
        ]
        if note:
            lines += ["", f"> ⚠️ {note}"]
        lines += ["", "## Steps", ""]
        for s in plan.steps:
            icon = {"ok": "✅", "failed": "🔴", "skipped": "⏭️"}.get(s.status.value, "⏸️")
            lines.append(f"### {icon} {s.step_id}: `{s.tool}` — {s.status.value}")
            if s.result_summary:
                lines.append(f"{s.result_summary}")
            lines.append("")
        lines.append(
            "_Generated mechanically (reasoning-engine synthesis unavailable); "
            "step results above are verbatim tool output summaries._"
        )
        return "\n".join(lines)
