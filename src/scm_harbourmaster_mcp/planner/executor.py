"""
Planner Phase 2 — manifest-enforced step execution.

The executor is where Phase 1's safety rails become runtime behavior:

  - Tools without a manifest entry are refused (never executed).
  - access: write tools require an approval callback to return True for
    the specific (tool, params) pair. No callback configured means every
    write is DENIED — the safe default is inaction, and nothing in this
    module can flip that without a human-supplied approver.
  - Retry policy comes from the manifest: "retry" gets max 2 retries,
    "fail_fast" (all writes) gets one attempt, "fallback" gets one attempt
    and annotates the failure with the manifest's documented failure mode
    so the Planner's revision step can pick the fallback tool.

Repo convention: MCP tools report failures as returned strings starting
with "Error:" rather than raising — the executor treats those as failures
so retries and revision see them.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Protocol

from ..utils.logging import get_logger
from .manifest import Manifest, UnknownToolError
from .schema import PlanStep, StepStatus

logger = get_logger(__name__)

_MAX_RETRIES = 2  # loop invariant from the epic: max 2 retries per step
_SUMMARY_CHARS = 1200


class ToolBackend(Protocol):
    """Anything that can execute one MCP tool call and return its text."""

    def call(self, tool_name: str, params: dict[str, Any]) -> str: ...


class ApprovalCallback(Protocol):
    """Human approval hook for write tools. Return True to approve."""

    def __call__(self, tool_name: str, params: dict[str, Any]) -> bool: ...


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _summarize(result: str) -> str:
    result = result.strip()
    if len(result) <= _SUMMARY_CHARS:
        return result
    return result[:_SUMMARY_CHARS] + f" … [truncated; {len(result)} chars total]"


class StepExecutor:
    def __init__(
        self,
        manifest: Manifest,
        backend: ToolBackend,
        approve_write: ApprovalCallback | None = None,
    ) -> None:
        self.manifest = manifest
        self.backend = backend
        # None = no approver configured = every write tool is denied.
        self.approve_write = approve_write

    def execute(self, step: PlanStep) -> PlanStep:
        """Run one step in place, mutating status/result/timestamps."""
        step.started_at = _now()
        step.status = StepStatus.RUNNING

        try:
            policy = self.manifest.policy(step.tool)
        except UnknownToolError as exc:
            step.status = StepStatus.FAILED
            step.result_summary = f"refused: {exc}"
            step.finished_at = _now()
            return step

        if self.manifest.requires_approval(step.tool):
            approved = False
            if self.approve_write is not None:
                try:
                    approved = bool(self.approve_write(step.tool, step.params))
                except Exception as exc:  # an erroring approver is a denial
                    logger.warning("approval_hook_error", tool=step.tool, error=str(exc))
                    approved = False
            if not approved:
                step.status = StepStatus.SKIPPED
                step.result_summary = "write tool requires explicit human approval — denied " + (
                    "by approver" if self.approve_write is not None else "(no approver configured)"
                )
                step.finished_at = _now()
                logger.info("planner_write_denied", tool=step.tool)
                return step

        max_attempts = 1 + (_MAX_RETRIES if policy.retry_policy == "retry" else 0)
        last_error = ""
        for attempt in range(max_attempts):
            step.retries = attempt
            try:
                result = self.backend.call(step.tool, step.params)
            except Exception as exc:
                last_error = str(exc)
                continue
            if result.strip().startswith("Error:"):
                last_error = result.strip()
                continue
            step.status = StepStatus.OK
            step.result_summary = _summarize(result)
            step.finished_at = _now()
            return step

        step.status = StepStatus.FAILED
        summary = f"failed after {step.retries + 1} attempt(s): {_summarize(last_error)}"
        if policy.retry_policy == "fallback" and policy.known_failure_modes:
            summary += f" | documented failure mode / fallback: {policy.known_failure_modes}"
        step.result_summary = summary
        step.finished_at = _now()
        logger.warning("planner_step_failed", tool=step.tool, attempts=step.retries + 1)
        return step
