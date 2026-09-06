"""
Planner Phase 2 — plan persistence and audit trail.

Each plan is one JSON file under SCM_MCP_PLAN_DIR (default ./plans,
gitignored). Writes are atomic (tmp + rename) so a crash mid-write can't
corrupt a resumable plan. Alongside each plan sits a JSONL audit log —
one line per event (step start, tool call, result, approval decision,
revision) — the full audit trail required by the epic.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from .schema import Plan

_DEFAULT_PLAN_DIR = Path(os.getenv("SCM_MCP_PLAN_DIR", "plans"))


class PlanStore:
    def __init__(self, plan_dir: Path | None = None) -> None:
        self.plan_dir = plan_dir or _DEFAULT_PLAN_DIR

    def _plan_path(self, plan_id: str) -> Path:
        return self.plan_dir / f"{plan_id}.json"

    def _audit_path(self, plan_id: str) -> Path:
        return self.plan_dir / f"{plan_id}.audit.jsonl"

    def save(self, plan: Plan) -> Path:
        plan.touch()
        self.plan_dir.mkdir(parents=True, exist_ok=True)
        path = self._plan_path(plan.plan_id)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(plan.model_dump_json(indent=2))
        tmp.replace(path)
        return path

    def load(self, plan_id: str) -> Plan | None:
        path = self._plan_path(plan_id)
        if not path.exists():
            return None
        return Plan.model_validate_json(path.read_text())

    def list_plans(self) -> list[str]:
        if not self.plan_dir.exists():
            return []
        return sorted(
            p.stem for p in self.plan_dir.glob("plan-*.json") if not p.name.endswith(".tmp")
        )

    def audit(self, plan_id: str, event: str, **fields: Any) -> None:
        """Append one audit event. Never raises — auditing must not kill a run."""
        try:
            self.plan_dir.mkdir(parents=True, exist_ok=True)
            record = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "event": event,
                **fields,
            }
            with self._audit_path(plan_id).open("a") as fh:
                fh.write(json.dumps(record, default=str) + "\n")
        except OSError:
            pass

    def read_audit(self, plan_id: str) -> list[dict[str, Any]]:
        path = self._audit_path(plan_id)
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    def save_report(self, plan_id: str, report_md: str) -> Path:
        self.plan_dir.mkdir(parents=True, exist_ok=True)
        path = self.plan_dir / f"{plan_id}.report.md"
        path.write_text(report_md)
        return path
