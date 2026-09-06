"""
Planner Phase 2 — the reasoning engine.

Claude (via the Anthropic API) generates the initial plan, revises it as
step results arrive, and synthesizes the final report. The engine sits
behind a Protocol so the loop is fully testable with a fake — and so a
different reasoning backend can be swapped in without touching the loop.

Structured outputs: plan and revision drafts come back through
client.messages.parse() with Pydantic models, so malformed plans are an
API-layer validation error rather than a JSON parsing bug. Step params are
carried as a JSON-encoded string field (strict schemas require
additionalProperties: false everywhere, which rules out free-form dicts).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Protocol

from pydantic import BaseModel, Field

from ..utils.logging import get_logger
from .manifest import Manifest

if TYPE_CHECKING:
    from .schema import Plan, PlanStep

logger = get_logger(__name__)

DEFAULT_MODEL = "claude-opus-4-8"
_MAX_TOKENS = 16000


class EngineError(RuntimeError):
    """The reasoning engine could not produce a usable result."""


class StepDraft(BaseModel):
    domain: str
    tool: str
    params_json: str = Field(
        default="{}",
        description="Tool parameters as a JSON-encoded object string",
    )
    why: str = ""

    def params(self) -> dict[str, Any]:
        try:
            parsed = json.loads(self.params_json or "{}")
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}


class PlanDraft(BaseModel):
    rationale: str = ""
    steps: list[StepDraft] = Field(default_factory=list)


class RevisionDraft(BaseModel):
    done: bool = Field(description="True when the plan needs no changes")
    reason: str = ""
    skip_step_ids: list[str] = Field(default_factory=list, description="Pending step_ids to skip")
    add_steps: list[StepDraft] = Field(default_factory=list)


class PlanningEngine(Protocol):
    def generate_plan(self, goal: str, tenant_scope: str, catalog: str) -> PlanDraft: ...

    def revise(self, plan: Plan, failed_step: PlanStep, catalog: str) -> RevisionDraft: ...

    def synthesize(self, plan: Plan) -> str: ...


def build_catalog(manifest: Manifest, domains: list[str] | None = None) -> str:
    """Render the tool catalog the engine plans against.

    One domain's tools per sub-plan is the context rule — pass `domains` to
    scope the catalog; None renders every domain (the Planner's own view).
    """
    from .manifest import VALID_DOMAINS

    lines: list[str] = []
    for domain in sorted(domains or VALID_DOMAINS):
        tools = manifest.domain_tools(domain)
        if not tools:
            continue
        lines.append(f"## {domain}")
        for name in tools:
            p = manifest.policy(name)
            tags = [p.access]
            if p.scope == "cross_tenant":
                tags.append("cross_tenant")
            note = f" — CAUTION: {p.known_failure_modes}" if p.known_failure_modes else ""
            lines.append(f"- {name} [{', '.join(tags)}]{note}")
    return "\n".join(lines)


_PLANNER_SYSTEM = """You are the Planner for an MSSP network-security operations \
platform managing Palo Alto Strata Cloud Manager tenants. You decompose an \
operator goal into an ordered plan of MCP tool calls.

Rules:
- Use ONLY tools from the catalog provided; copy tool names exactly.
- Prefer read tools. Write tools ([write] in the catalog) always require \
explicit human approval at execution time and are skipped if not approved — \
include one only when the goal cannot be met without it, and say so in `why`.
- Heed each tool's CAUTION notes (known failure modes and prerequisites).
- Keep plans minimal: the fewest steps that achieve the goal, in dependency \
order. Most tools take tenant_id and/or folder params; put them in params_json.
- params_json must be a JSON object string, e.g. "{\\"tenant_id\\": \\"123\\"}".
"""


class ClaudeEngine:
    """PlanningEngine backed by the Anthropic API (Claude Opus 4.8)."""

    def __init__(self, model: str = DEFAULT_MODEL, client: Any | None = None) -> None:
        if client is None:
            import anthropic

            # Same credential convention as scm_ai_compliance_advisor:
            # anthropic_api_key in .secrets.toml, else the SDK's own
            # resolution (ANTHROPIC_API_KEY / auth profile).
            api_key = ""
            try:
                from ..config.settings import get_settings

                api_key = get_settings().anthropic_api_key.get_secret_value()
            except Exception:
                api_key = ""
            client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
        self.client = client
        self.model = model

    def _parse(self, system: str, user: str, output_format: type[BaseModel]) -> Any:
        response = self.client.messages.parse(
            model=self.model,
            max_tokens=_MAX_TOKENS,
            thinking={"type": "adaptive"},
            system=system,
            messages=[{"role": "user", "content": user}],
            output_format=output_format,
        )
        if getattr(response, "stop_reason", None) == "refusal":
            raise EngineError("reasoning engine refused the request")
        parsed = getattr(response, "parsed_output", None)
        if parsed is None:
            raise EngineError("reasoning engine returned no parsable output")
        return parsed

    def generate_plan(self, goal: str, tenant_scope: str, catalog: str) -> PlanDraft:
        user = (
            f"Goal: {goal}\n\nTenant scope: {tenant_scope}\n\n"
            f"Tool catalog:\n{catalog}\n\nProduce the plan."
        )
        return self._parse(_PLANNER_SYSTEM, user, PlanDraft)

    def revise(self, plan: Plan, failed_step: PlanStep, catalog: str) -> RevisionDraft:
        user = (
            "A plan step failed. Decide whether to revise the remaining plan.\n\n"
            f"Goal: {plan.goal}\n\n"
            f"Failed step: {failed_step.tool} — {failed_step.result_summary}\n\n"
            f"Current plan state:\n{plan.model_dump_json(indent=2)}\n\n"
            f"Tool catalog:\n{catalog}\n\n"
            "If the failure has a documented fallback tool, add a step using it. "
            "If remaining steps depend on the failed one, skip them. "
            "If the plan is still sound as-is, return done=true."
        )
        return self._parse(_PLANNER_SYSTEM, user, RevisionDraft)

    def synthesize(self, plan: Plan) -> str:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=_MAX_TOKENS,
            thinking={"type": "adaptive"},
            system=(
                "You write the final operator report for a completed MSSP ops plan. "
                "Markdown. Lead with the outcome, then findings per step (cite the "
                "tool), then recommended actions. Failed or skipped steps must be "
                "reported plainly — never imply work happened that didn't."
            ),
            messages=[
                {
                    "role": "user",
                    "content": f"Plan state (JSON):\n{plan.model_dump_json(indent=2)}",
                }
            ],
        )
        if getattr(response, "stop_reason", None) == "refusal":
            raise EngineError("reasoning engine refused synthesis")
        from anthropic.types import TextBlock

        text = "".join(b.text for b in response.content if isinstance(b, TextBlock))
        if not text.strip():
            raise EngineError("reasoning engine returned an empty report")
        return text
