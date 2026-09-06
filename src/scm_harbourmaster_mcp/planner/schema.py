"""
Planner Phase 2 — the persisted Plan schema.

One JSON document per run, keyed by plan_id, exactly as drafted in
docs/planner-agent/ARCHITECTURE.md. Every tool call, param set, and result
summary persists against the plan_id; plans are resumable after an MCP
server restart because every state change is written to disk before the
loop proceeds.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class TriggerType(StrEnum):
    SCHEDULED = "scheduled"
    CONVERSATIONAL = "conversational"
    IR_WEBHOOK = "ir_webhook"


class StepStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    OK = "ok"
    FAILED = "failed"
    SKIPPED = "skipped"


class PlanStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_PARTIAL = "completed_partial"  # finished with failed/skipped steps
    FAILED = "failed"  # loop-level failure; partial report still written


class PlanStep(BaseModel):
    step_id: str
    domain: str
    tool: str
    params: dict[str, Any] = Field(default_factory=dict)
    status: StepStatus = StepStatus.PENDING
    result_summary: str = ""
    retries: int = 0
    started_at: str | None = None
    finished_at: str | None = None


class Revision(BaseModel):
    revised_at: str = Field(default_factory=_now_iso)
    reason: str
    change: str  # human-readable description of what the revision did


class Plan(BaseModel):
    plan_id: str = Field(default_factory=lambda: f"plan-{uuid.uuid4().hex[:12]}")
    trigger_type: TriggerType
    trigger_payload: dict[str, Any] = Field(default_factory=dict)
    persona: str = ""
    tenant_scope: str | list[str] = "all"
    goal: str = ""
    steps: list[PlanStep] = Field(default_factory=list)
    revision_history: list[Revision] = Field(default_factory=list)
    final_report_ref: str = ""
    status: PlanStatus = PlanStatus.RUNNING
    created_at: str = Field(default_factory=_now_iso)
    updated_at: str = Field(default_factory=_now_iso)

    def next_pending(self) -> PlanStep | None:
        return next((s for s in self.steps if s.status == StepStatus.PENDING), None)

    def touch(self) -> None:
        self.updated_at = _now_iso()

    @property
    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for s in self.steps:
            out[s.status.value] = out.get(s.status.value, 0) + 1
        return out
