"""scm_panorama_migrate / scm_panorama_migrate_result (tools/panorama_migrate.py)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.tools import panorama_migrate as pm
from scm_harbourmaster_mcp.utils.jobs import MIGRATE_JOBS

PANORAMA = Path(__file__).parent.parent / "fixtures" / "panos" / "panorama.xml"
TICKET = "CHG-1234"


class _Calls:
    def __init__(self, blocked: bool = False) -> None:
        self.clones: list[dict[str, Any]] = []
        self.backups: list[str] = []
        self.blocked = blocked

    def clone(self, client: Any, **kwargs: Any) -> Any:
        self.clones.append(kwargs)
        data = json.loads(Path(kwargs["source_backup_file"]).read_text())
        self.clones[-1]["data"] = data
        return SimpleNamespace(
            to_markdown=lambda: "# clone report",
            target_tenant_id="",
            preflight=SimpleNamespace(blocked=self.blocked),
            created=3,
            results=[],
        )

    def backup(self, client: Any, tenant_id: str, folder: str, output_dir: str = "") -> Any:
        self.backups.append(folder)
        return Path(f"/backups/scm_backup_{folder}.json"), {}


@pytest.fixture
def tools(tmp_path, monkeypatch):
    calls = _Calls()
    monkeypatch.setenv("SCM_MCP_BACKUP_DIR", str(tmp_path))
    monkeypatch.setattr(pm, "clone_config", calls.clone)
    monkeypatch.setattr(pm, "write_config_backup", calls.backup)
    mcp = FastMCP("test-migrate")
    pm.register_panorama_migrate_tools(mcp, lambda tenant_id="": MagicMock())

    def get(name: str) -> Any:
        return mcp._tool_manager.get_tool(name).fn  # noqa: SLF001

    return SimpleNamespace(
        migrate=get("scm_panorama_migrate"),
        result=get("scm_panorama_migrate_result"),
        calls=calls,
        tmp=tmp_path,
    )


def _wait(result: Any, job: str) -> str:
    for _ in range(100):
        out = str(result(job_id=job))
        if "still running" not in out:
            return out
        time.sleep(0.02)
    raise AssertionError("job did not finish")


def test_ticket_ref_is_mandatory(tools):
    out = tools.migrate(xml_path=str(PANORAMA), target_folder="Lab", device_group="dg-branch")
    assert "ticket_ref is mandatory" in out
    assert tools.calls.clones == []


def test_dry_run_writes_the_plan_and_runs_the_clone_dry_run(tools):
    out = tools.migrate(
        xml_path=str(PANORAMA),
        target_folder="Lab",
        device_group="dg-branch",
        ticket_ref=TICKET,
        name_prefix="m-",
    )
    assert "DRY-RUN" in out and "## Migration plan" in out and "# clone report" in out
    [call] = tools.calls.clones
    assert call["dry_run"] is True
    assert call["target_folder"] == "Lab" and call["name_prefix"] == "m-"
    assert call["on_missing_reference"] == "fail"
    assert tools.calls.backups == []
    [plan] = (tools.tmp / "migrations").glob("panos_migration_dg-branch_*.json")
    data = json.loads(plan.read_text())
    assert data["migrated_from"] == "Panorama device group `dg-branch`"
    assert data["plan_items"] and "security_rules_pre" in data["resources"]


def test_apply_backs_up_first_then_pushes_in_the_background(tools):
    out = tools.migrate(
        xml_path=str(PANORAMA),
        target_folder="Lab",
        device_group="dg-branch",
        ticket_ref=TICKET,
        dry_run=False,
    )
    job = out.split("job `")[1].split("`")[0]
    report = _wait(tools.result, job)
    assert tools.calls.backups == ["Lab"]
    # The same dry run first, then the push
    assert [c["dry_run"] for c in tools.calls.clones] == [True, False]
    assert "APPLY" in report and "/backups/scm_backup_Lab.json" in report
    assert "## Next steps" in report


def test_blocked_preflight_refuses_the_apply_before_any_backup(tools):
    tools.calls.blocked = True
    out = tools.migrate(
        xml_path=str(PANORAMA),
        target_folder="Lab",
        device_group="dg-branch",
        ticket_ref=TICKET,
        dry_run=False,
    )
    assert "REFUSED" in out and "Nothing was written" in out and "job `" not in out
    assert tools.calls.backups == []
    assert [c["dry_run"] for c in tools.calls.clones] == [True]


def test_options_and_export_errors_are_checked_before_any_call(tools):
    base = {"xml_path": str(PANORAMA), "target_folder": "Lab", "ticket_ref": TICKET}
    assert "on_conflict must be one of" in tools.migrate(**base, on_conflict="rename")
    assert "on_missing_reference must be one of" in tools.migrate(
        **base, on_missing_reference="ignore"
    )
    assert "pass device_group" in tools.migrate(**base)
    assert "not a file" in tools.migrate(**{**base, "xml_path": str(tools.tmp / "x.xml")})
    assert tools.calls.clones == []


def test_resource_filter_and_include_rules_reach_the_clone(tools):
    tools.migrate(
        xml_path=str(PANORAMA),
        target_folder="Lab",
        device_group="dg-branch",
        ticket_ref=TICKET,
        resource_filter="addresses, address_groups",
        include_rules=False,
    )
    [call] = tools.calls.clones
    assert call["resource_filter"] == {"addresses", "address_groups"}
    assert call["skip_rules"] is True


def test_unknown_job(tools):
    assert "not found" in tools.result(job_id="nope")


def test_blocked_dry_run_says_to_fix_references_not_to_apply(tools):
    tools.calls.blocked = True
    out = tools.migrate(
        xml_path=str(PANORAMA), target_folder="Lab", device_group="dg-branch", ticket_ref=TICKET
    )
    assert "DRY-RUN" in out and "would block an apply" in out
    assert "dry_run=False" not in out


def test_unknown_job_does_not_list_other_jobs(tools):
    other = MIGRATE_JOBS.create()
    try:
        out = tools.result(job_id="nope")
    finally:
        MIGRATE_JOBS.clear()
    assert "not found" in out and other not in out
