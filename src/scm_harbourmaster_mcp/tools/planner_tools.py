"""
Planner Phase 3b — the conversational trigger surface, as MCP tools.

Any chat client connected to this server (Claude Desktop over stdio,
Copilot Studio over the Streamable transport, a Slack/Teams bridge posting
into either) becomes the copilot frontend: an operator states a goal in
natural language, scm_planner_run feeds it into the SAME PlannerLoop as
every other trigger, and the conversation follows progress through
scm_planner_status and collects the synthesis through scm_planner_result.

Write-tool approval in a conversation is the operator naming the tools:
scm_planner_run(approved_write_tools=["scm_commit"]) is the explicit human
approval the Phase 1 hard rule requires — scoped to this run, default
empty, and anything not named is denied by the executor, never executed.

Runs execute on a daemon thread (plan generation is an LLM call and steps
take minutes) — the tool returns the plan_id immediately, exactly like the
scm_asbuilt_report job pattern.
"""

from __future__ import annotations

import threading
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..planner import PlannerLoop, PlanStore, StepExecutor, load_manifest
from ..planner.backend import InProcessBackend
from ..planner.schema import PlanStatus, TriggerType
from ..utils.logging import get_logger

logger = get_logger(__name__)

# Test seam: replaced with a fake in unit tests; ClaudeEngine in production.
_engine_factory: Any = None


def _make_engine() -> Any:
    if _engine_factory is not None:
        return _engine_factory()
    from ..planner.engine import ClaudeEngine

    return ClaudeEngine()


def register_planner_tools(mcp: FastMCP, get_client: Any) -> None:  # noqa: ARG001
    """Register the conversational Planner tools.

    get_client is unused (the loop reaches tools through the server itself
    via InProcessBackend) but kept for register-signature uniformity.
    """
    store = PlanStore()

    @mcp.tool()
    def scm_planner_run(
        goal: str,
        tenant_scope: str = "all",
        approved_write_tools: list[str] | None = None,
        persona: str = "conversational-operator",
    ) -> str:
        """Run an autonomous Planner agent against a natural-language goal.

        The Planner (Claude as reasoning engine) decomposes the goal into an
        ordered plan of MCP tool calls from this server's manifest, executes
        them, revises on failures, and synthesizes an operator report. The
        plan, every tool call, and every result persist under plans/ with a
        full audit trail.

        SAFETY: write tools are NEVER executed unless you name them in
        approved_write_tools — that list is your explicit, per-run human
        approval. Anything not named is skipped, not run. Read-only goals
        need no approval at all.

        Requires anthropic_api_key in .secrets.toml (same credential as
        scm_ai_compliance_advisor).

        Args:
            goal: The operator intent, in natural language (e.g. "check
                  which tenants have certificates expiring this quarter
                  and summarize per customer").
            tenant_scope: Tenant TSG id, or "all" for estate-wide goals.
                          Informs planning only — each step's params still
                          name their tenant explicitly.
            approved_write_tools: Write tools this run MAY execute (e.g.
                  ["scm_commit"]). Default none — fully read-only.
            persona: Recorded on the plan for audit.

        Returns:
            The plan_id and polling instructions. The run continues in the
            background; call scm_planner_status(plan_id) for progress and
            scm_planner_result(plan_id) for the final report.
        """
        approved = set(approved_write_tools or [])
        manifest = load_manifest()
        engine = _make_engine()
        executor = StepExecutor(
            manifest,
            InProcessBackend(mcp),
            approve_write=(lambda tool, params: tool in approved) if approved else None,
        )
        loop = PlannerLoop(manifest, engine, executor, store)

        # Create the plan record synchronously so the id exists before we
        # return; the loop re-saves over it as it progresses.
        result: dict[str, str] = {}
        started = threading.Event()

        def _run() -> None:
            plan = loop.run(
                goal=goal,
                trigger_type=TriggerType.CONVERSATIONAL,
                trigger_payload={"approved_write_tools": sorted(approved)},
                tenant_scope=tenant_scope,
                persona=persona,
            )
            result["plan_id"] = plan.plan_id
            started.set()

        # loop.run persists the plan (and its id) before the first LLM call,
        # but we need the id here — so run() on the thread and grab the id
        # from the store's newest plan after the loop's initial save.
        before = set(store.list_plans())
        thread = threading.Thread(target=_run, daemon=True, name="planner-conversational")
        thread.start()
        # Wait briefly for the initial persist (not the whole run).
        import time as _time

        plan_id = ""
        for _ in range(50):  # up to 5s for the initial save
            new = set(store.list_plans()) - before
            if new:
                plan_id = sorted(new)[0]
                break
            if started.is_set():
                plan_id = result.get("plan_id", "")
                break
            _time.sleep(0.1)

        if not plan_id:
            return (
                "Planner run started but the plan record has not appeared yet — "
                "call scm_planner_status() (no plan_id) shortly to list runs."
            )
        write_note = (
            f"Approved write tools this run: {sorted(approved)}"
            if approved
            else "Read-only run: every write tool is denied by default."
        )
        logger.info("planner_conversational_started", plan_id=plan_id, goal=goal[:120])
        return (
            f"Planner run `{plan_id}` started for goal: {goal}\n\n{write_note}\n\n"
            f'Follow progress:  scm_planner_status(plan_id="{plan_id}")\n'
            f'Final report:     scm_planner_result(plan_id="{plan_id}")'
        )

    @mcp.tool()
    def scm_planner_status(plan_id: str = "") -> str:
        """Show a Planner run's live progress, or list recent runs.

        Args:
            plan_id: The plan to inspect. Empty = list all persisted runs.

        Returns:
            Step-by-step progress (status, retries, result summaries) for
            one run, or the run list with statuses.
        """
        if not plan_id:
            ids = store.list_plans()
            if not ids:
                return "No planner runs recorded."
            lines = ["## Planner Runs", ""]
            for pid in ids[-20:]:
                p = store.load(pid)
                if p is None:
                    continue
                lines.append(
                    f"- `{pid}` [{p.status.value}] {p.goal[:80]} "
                    f"({p.counts.get('ok', 0)} ok / {p.counts.get('failed', 0)} failed)"
                )
            return "\n".join(lines)

        plan = store.load(plan_id)
        if plan is None:
            return f"No plan `{plan_id}` found."
        lines = [
            f"## Plan `{plan.plan_id}` — {plan.status.value.upper()}",
            "",
            f"**Goal:** {plan.goal}",
            f"**Trigger:** {plan.trigger_type.value}  |  **Scope:** {plan.tenant_scope}  |  "
            f"**Updated:** {plan.updated_at}",
            "",
        ]
        for s in plan.steps:
            mark = {
                "ok": "✅",
                "failed": "🔴",
                "skipped": "⏭️",
                "running": "▶️",
                "pending": "⏸️",
            }.get(s.status.value, "?")
            lines.append(f"- {mark} {s.step_id} `{s.tool}` [{s.status.value}]")
            if s.result_summary:
                lines.append(f"  - {s.result_summary[:200]}")
        if plan.revision_history:
            lines.append("")
            lines.append(f"Revisions: {len(plan.revision_history)}")
        if plan.status != PlanStatus.RUNNING and plan.final_report_ref:
            lines.append("")
            lines.append(f'Report ready: scm_planner_result(plan_id="{plan.plan_id}")')
        return "\n".join(lines)

    @mcp.tool()
    def scm_planner_result(plan_id: str) -> str:
        """Fetch a completed Planner run's synthesized report.

        Args:
            plan_id: The plan whose report to fetch.

        Returns:
            The final Markdown report, or a status message if still running.
        """
        plan = store.load(plan_id)
        if plan is None:
            return f"No plan `{plan_id}` found."
        if plan.status == PlanStatus.RUNNING:
            done = sum(1 for s in plan.steps if s.status.value in ("ok", "failed", "skipped"))
            return (
                f"Plan `{plan_id}` still running ({done}/{len(plan.steps)} steps done) — "
                f'check scm_planner_status(plan_id="{plan_id}").'
            )
        if plan.final_report_ref:
            from pathlib import Path

            path = Path(plan.final_report_ref)
            if path.exists():
                return path.read_text()
        return f"Plan `{plan_id}` finished ({plan.status.value}) but no report file was found."

    @mcp.tool()
    def scm_ir_trigger(alert_json: str, tenant_id: str = "", folder: str = "Prisma Access") -> str:
        """Trigger incident-response triage from an alert payload.

        Classifies the alert into an incident class (tunnel-down,
        cert-expiry, licence-expiry, config-change, connectivity-degraded,
        or generic) and runs that class's pre-built READ-ONLY triage template
        through the Planner loop — e.g. tunnel-down runs the SD-WAN WAN-IP
        summary, IKE gateway list, recent job audit, SD-WAN events, and the
        incident root-cause correlator. Templates cannot execute write tools
        under any input: the triage executor has no approver.

        This is the same surface the HTTP transport exposes at
        POST /webhook/ir for MT Monitor alert bridges.

        Args:
            alert_json: The alert as a JSON object string — fields like
                message/name/category/description drive classification
                (e.g. '{"message": "IPSec tunnel down on branch-12"}').
            tenant_id: SCM tenant ID the alert concerns.
            folder: SCM folder for config-scoped triage steps.

        Returns:
            The plan_id, detected incident class, and polling instructions
            (scm_planner_status / scm_planner_result).
        """
        import json as _json

        from ..planner.ir import start_ir_run

        try:
            alert = _json.loads(alert_json or "{}")
            if not isinstance(alert, dict):
                return "Error: alert_json must be a JSON object."
        except _json.JSONDecodeError as exc:
            return f"Error: invalid JSON in alert_json: {exc}"

        plan_id, incident_class = start_ir_run(
            InProcessBackend(mcp), store, alert, tenant_id, folder
        )
        logger.info("ir_trigger_accepted", plan_id=plan_id, incident_class=incident_class)
        if not plan_id:
            return (
                f"IR triage started (class: {incident_class}) but the plan record has not "
                "appeared yet — call scm_planner_status() shortly to list runs."
            )
        return (
            f"IR triage `{plan_id}` started — incident class: **{incident_class}**\n\n"
            f'Follow progress:  scm_planner_status(plan_id="{plan_id}")\n'
            f'Triage report:    scm_planner_result(plan_id="{plan_id}")'
        )

    @mcp.tool()
    def scm_estate_check(tenants: str = "", concurrency: int = 3) -> str:
        """Run the tier-aware estate check across every configured tenant.

        One trigger fans out per-tenant sub-plans with bounded concurrency
        through the Planner loop. Each tenant's contracted tier scopes its
        check depth — Bronze: licensing + certs + connectivity basics;
        Silver: + BPA posture + change audit; Gold: + NCSC CAF + ISO 27001 +
        DLP/SSPM posture. Cross-tenant anomaly rules then flag patterns
        invisible per-tenant (SD-WAN topology with zero licences, duplicate
        NFR licence sets, provisioned-but-idle tenants).

        Fully read-only: the estate executor has no approver, so no write
        tool can run. Gold-depth tenants take ~2-3 minutes each (one shared
        snapshot extraction feeds all three assessments); the run continues
        in the background and writes plans/estate-<stamp>.md.

        Args:
            tenants: Comma-separated tenant labels to include (default: all
                     configured tenants).
            concurrency: Parallel tenant sub-plans (default 3).

        Returns:
            Launch confirmation with tenant count and where the digest will
            land; follow per-tenant progress via scm_planner_status().
        """
        from ..auth.oauth import get_scm_client
        from ..config.settings import load_all_tenant_configs
        from ..planner.estate import EstateRunner, TenantSpec, default_fact_gatherer

        wanted = {t.strip().lower() for t in tenants.split(",") if t.strip()}
        specs: list[TenantSpec] = []
        for key, tc in load_all_tenant_configs().items():
            label = tc.label or key
            if wanted and label.lower() not in wanted and key.lower() not in wanted:
                continue
            try:
                get_scm_client(tc)
            except Exception as exc:
                logger.warning("estate_tool_auth_failed", tenant=label, error=str(exc))
                continue
            specs.append(TenantSpec(label=label, tenant_id=tc.tenant_id, tier=str(tc.tier)))
        if not specs:
            return "No tenants available (auth failures or filter matched nothing)."

        backend = InProcessBackend(mcp)
        runner = EstateRunner(
            backend=backend,
            store=store,
            gather_facts=default_fact_gatherer(backend),
            concurrency=concurrency,
        )

        def _run() -> None:
            try:
                path, ranked = runner.run(specs)
                logger.info("estate_check_complete", digest=path, findings=len(ranked))
            except Exception as exc:
                logger.error("estate_check_failed", error=str(exc))

        threading.Thread(target=_run, daemon=True, name="planner-estate").start()
        tiers = ", ".join(f"{s.label} ({s.tier})" for s in specs[:8])
        more = f" … +{len(specs) - 8} more" if len(specs) > 8 else ""
        return (
            f"Estate check started across {len(specs)} tenant(s) at tier depth "
            f"({concurrency} concurrent): {tiers}{more}\n\n"
            "Per-tenant sub-plans appear in scm_planner_status() as they run; the "
            "aggregated digest lands at plans/estate-<stamp>.md when complete "
            "(Gold-depth tenants take ~2-3 minutes each)."
        )
