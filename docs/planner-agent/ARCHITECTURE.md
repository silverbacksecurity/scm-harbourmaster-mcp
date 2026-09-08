# Planner Agent — Architecture

> Status: **Phases 1–2 implemented** (2026-07-15). Phase 1: tool manifest +
> safety rails (`scm_harbourmaster_mcp.planner.manifest`, see
> [TOOL_MANIFEST.md](TOOL_MANIFEST.md)). Phase 2: the loop core —
> `planner/schema.py` (the persisted Plan below, as Pydantic models),
> `planner/store.py` (atomic JSON per run under `plans/` + JSONL audit
> trail), `planner/executor.py` (manifest-enforced execution: unknown tools
> refused, writes gated on an approval callback with deny-by-default,
> max-2-retries), `planner/engine.py` (Claude Opus 4.8 via
> `messages.parse()` structured outputs, behind a Protocol so the loop
> tests with fakes), `planner/loop.py` (run/resume with the
> always-finish-with-a-report guarantee), and `planner/backend.py`
> (in-process FastMCP backend; a Streamable-HTTP backend implements the
> same protocol later). Phase 3 trigger surfaces are not built yet — the
> loop is invoked programmatically. See the epic in
> [ROADMAP.md](../../ROADMAP.md) for remaining phases.

The Planner Agent is an agentic orchestration layer above the existing
125-tool scm-harbourmaster-mcp MCP server. It follows the PANW "NetSec Agents on
SCM" taxonomy, extended with an MSSP cross-tenant layer PANW's native
single-tenant model does not cover. One Planner loop; three trigger
surfaces (scheduled/cron, conversational NLQ, IR/webhook) as entry points
into the same loop.

## Taxonomy mapping

| PANW taxonomy layer | PANW meaning (NetSec Agents on SCM) | Our implementation |
| --- | --- | --- |
| **Persona** | The operator role the agent acts as (e.g. NetSec admin) | Service-account identity per run, recorded in the Plan (`persona`); MSSP operator personas map to tenant scope |
| **Planner** | Decomposes intent into a dynamic plan, revises as results arrive | The Planner loop: Trigger → Intent parse → Plan generation → Execute step → Observe → Revise → Synthesis → Report. Claude via the Anthropic API (tool-use) as the reasoning engine |
| **Expert Agents** | Domain specialists (deployment, threat coverage, operational health, posture…) | Domain-scoped sub-plan executors — the Planner delegates a sub-plan to an executor loaded with only that domain's ~15–20 tools (per the tool manifest `domain` field) |
| **Plan** | The persisted, auditable decomposition of intent | Persisted Plan JSON (schema below), stored per run, resumable after MCP server restart |
| **Actions** | The concrete API operations an Expert Agent performs | The existing 125 MCP tools over Streamable transport (reusing the Copilot Studio transport work); `access: write` tools always gated on explicit human approval |
| **Triggers** | What starts a run | Three surfaces into the same loop: (3a) scheduled/cron ops runs, (3b) conversational NLQ via Slack/Teams, (3c) IR webhooks from MT Monitor alerts with pre-built triage templates |
| *(no PANW equivalent)* **MSSP cross-tenant layer** | — (PANW's model is single-tenant) | Estate fan-out (per-tenant sub-plans with bounded concurrency), cross-tenant anomaly rules |

## Plan schema (persisted per run)

Stored as JSON, one document per run, keyed by `plan_id`. Every tool call,
param set, and result summary is persisted against the `plan_id` (full
audit trail). Plans must be resumable after MCP server restart.

```json
{
  "plan_id": "string (unique per run)",
  "trigger_type": "scheduled | conversational | ir_webhook",
  "trigger_payload": {},
  "persona": "service-account identity the run executes as",
  "tenant_scope": "single tenant ID | [list of IDs] | \"all\"",
  "goal": "high-level operator intent, as parsed",
  "steps": [
    {
      "step_id": "string",
      "domain": "deployment | threat_coverage | operational_health | posture_compliance | config_change | licensing | sdwan | certificates | identity | pab | dlp",
      "tool": "MCP tool name",
      "params": {},
      "status": "pending | running | ok | failed | skipped",
      "result_summary": "string",
      "retries": 0,
      "started_at": "ISO 8601 timestamp",
      "finished_at": "ISO 8601 timestamp"
    }
  ],
  "revision_history": [],
  "final_report_ref": "pointer to the synthesized report artifact"
}
```

### Failure policy (loop invariants)

- Max 2 retries per step.
- Validation/schema error → use the manifest's fallback tool
  (see [TOOL_MANIFEST.md](TOOL_MANIFEST.md), `known_failure_modes`).
- Server timeout → mark the step `failed`, continue where the plan allows.
- Always finish with a partial report rather than aborting the run.
- MCP server restart is a first-class scenario: plans resume from persisted
  state; the Planner may invoke `scm_reload`/`scm_restart` as a recovery
  action, with approval (both are `access: write`).

### Safety rails

- `access: write` tools ALWAYS require explicit human approval before
  execution, regardless of trigger type. No config flag can disable this
  in v1.
- Read-only operation for the first month of production use, even where
  approval gates exist.
