"""Unit tests for the Panorama → SCM migration report (audit/migration_report.py)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.audit import migration_report as mr
from scm_harbourmaster_mcp.audit import panos_import as pi
from scm_harbourmaster_mcp.tools import audit as audit_tools
from scm_harbourmaster_mcp.tools import panorama_migrate as pm

PANORAMA = Path(__file__).parent.parent / "fixtures" / "panos" / "panorama.xml"
TENANT = "1234567890"
FOLDER = "Lab"
SCOPES = ["device group `dg-branch`", "device group `dg-parent`", "shared"]


def _item(kind: str, name: str, action: str, reason: str = "why") -> dict[str, Any]:
    return {"kind": kind, "name": name, "action": action, "reason": reason}


def _addr(name: str, ip: str = "10.0.0.1/32", **extra: Any) -> dict[str, Any]:
    return {"name": name, "ip_netmask": ip, **extra}


def _scm(obj: dict[str, Any], **extra: Any) -> dict[str, Any]:
    """An object as an SCM backup holds it: SCM's own fields added."""
    return {**obj, "id": f"id-{obj['name']}", "folder": FOLDER, "snippet": None, **extra}


def _status(rep: mr.MigrationReport) -> dict[tuple[str, str], str]:
    return {(r.kind, r.name or r.target_name): r.status for r in rep.rows}


class TestStatuses:
    def _report(self, pre: dict[str, Any] | None = None) -> mr.MigrationReport:
        plan = {
            "migrated_from": "Panorama device group `dg`",
            "resources": {
                "addresses": [
                    _addr("a-new"),
                    _addr("a-norm"),
                    _addr("a-keep", "10.0.0.9/32"),
                    _addr("a-over", "10.0.0.8/32"),
                    _addr("a-same"),
                    _addr("a-miss"),
                ],
                "tags": [{"name": "t-drop", "color": "Red"}],
                "profile_groups": [{"name": "pg-gen", "spyware": ["as"]}],
            },
            "plan_items": [
                _item("tags", "t-drop", pi.DROPPED, "colour has no SCM name"),
                _item("profile_groups", "pg-gen", pi.GENERATED),
                _item("addresses", "a-hidden", pi.OVERRIDDEN),
                _item("schedule", "1 entry", pi.UNSUPPORTED, "schedules in dg"),
            ],
        }
        if pre is None:
            pre = {
                "folder": FOLDER,
                "resources": {
                    "addresses": [
                        _scm(_addr("a-keep", "10.1.1.1/32")),
                        _scm(_addr("a-over", "10.2.2.2/32")),
                        _scm(_addr("a-same")),
                        _scm(_addr("x-pre")),
                    ]
                },
            }
        post = {
            "folder": FOLDER,
            "resources": {
                "addresses": [
                    _scm(_addr("a-new"), _position=0),
                    _scm(_addr("a-norm", description="added by SCM")),
                    _scm(_addr("a-keep", "10.1.1.1/32")),
                    _scm(_addr("a-over", "10.0.0.8/32")),
                    _scm(_addr("a-same")),
                    _scm(_addr("x-pre")),
                    _scm(_addr("x-outside")),
                ],
                "tags": [_scm({"name": "t-drop", "color": "Red"})],
                "profile_groups": [_scm({"name": "pg-gen", "spyware": ["as"]})],
            },
        }
        # a-norm: SCM holds a field the source set differently
        plan["resources"]["addresses"][1]["description"] = "from panorama"
        return mr.build_report(plan, pre, post, target_folder=FOLDER, tenant_id=TENANT)

    def test_every_status(self) -> None:
        st = _status(self._report())
        assert st[("addresses", "a-new")] == mr.MIGRATED
        assert st[("addresses", "a-norm")] == mr.NORMALISED
        assert st[("addresses", "a-keep")] == mr.KEPT_EXISTING
        assert st[("addresses", "a-over")] == mr.OVERWROTE
        assert st[("addresses", "a-same")] == mr.IDENTICAL
        assert st[("addresses", "a-miss")] == mr.MISSING
        assert st[("tags", "t-drop")] == mr.MIGRATED_CHANGED
        assert st[("profile_groups", "pg-gen")] == mr.CREATED
        assert st[("addresses", "a-hidden")] == mr.HIDDEN
        assert st[("schedule", "1 entry")] == mr.NOT_MIGRATED
        assert st[("addresses", "x-pre")] == mr.PRE_EXISTING
        assert st[("addresses", "x-outside")] == mr.ADDED_OUTSIDE

    def test_dropped_field_is_a_change_even_when_scm_matches_the_translation(self) -> None:
        # The translated tag already lacks the dropped colour, so the snapshots
        # agree; the plan item still makes it "migrated with changes".
        rep = self._report()
        row = next(r for r in rep.rows if r.name == "t-drop")
        assert row.status == mr.MIGRATED_CHANGED and "colour has no SCM name" in row.detail

    def test_scm_side_difference_is_named(self) -> None:
        row = next(r for r in self._report().rows if r.name == "a-norm")
        assert row.detail == "SCM differs in: description"

    def test_without_a_pre_backup_nothing_is_attributed(self) -> None:
        plan = {"resources": {"addresses": [_addr("a")]}, "plan_items": []}
        post = {"resources": {"addresses": [_scm(_addr("a")), _scm(_addr("b"))]}}
        rep = mr.build_report(plan, None, post, target_folder=FOLDER)
        st = _status(rep)
        assert st[("addresses", "a")] == mr.UNATTRIBUTED
        assert ("addresses", "b") not in st  # can't say pre-existing or added
        assert rep.before_counts is None


class TestNamePrefix:
    def test_references_follow_the_rename(self) -> None:
        plan = {
            "resources": {
                "addresses": [_addr("web")],
                "address_groups": [{"name": "grp", "static": ["web"]}],
            },
            "plan_items": [],
        }
        post = {
            "resources": {
                "addresses": [_scm(_addr("mig-web"))],
                "address_groups": [_scm({"name": "mig-grp", "static": ["mig-web"]})],
            }
        }
        pre: dict[str, Any] = {"resources": {}}
        rep = mr.build_report(plan, pre, post, target_folder=FOLDER, name_prefix="mig-")
        st = {(r.kind, r.name): (r.status, r.target_name) for r in rep.rows}
        assert st[("address_groups", "grp")] == (mr.MIGRATED, "mig-grp")
        assert st[("addresses", "web")] == (mr.MIGRATED, "mig-web")

    def test_a_wrong_prefix_shows_as_missing(self) -> None:
        plan = {"resources": {"addresses": [_addr("web")]}, "plan_items": []}
        post = {"resources": {"addresses": [_scm(_addr("mig-web"))]}}
        rep = mr.build_report(plan, {"resources": {}}, post, target_folder=FOLDER)
        assert _status(rep)[("addresses", "web")] == mr.MISSING


class TestRuleOrder:
    def _rep(self, positions: list[int], folder: str = FOLDER) -> list[mr.RuleOrder]:
        names = ["r1", "r2", "r3"]
        plan = {"resources": {"security_rules_pre": [{"name": n} for n in names]}}
        post = {
            "resources": {
                "security_rules_pre": [
                    _scm({"name": n}, _position=p) for n, p in zip(names, positions, strict=True)
                ]
            }
        }
        return mr.build_report(plan, {"resources": {}}, post, target_folder=folder).rule_order

    def test_preserved(self) -> None:
        [ro] = self._rep([0, 1, 2])
        assert ro.preserved is True

    def test_changed(self) -> None:
        [ro] = self._rep([0, 2, 1])
        assert ro.preserved is False and "expected `r2`, found `r3`" in ro.detail

    def test_cloud_leaf_folders_are_not_checked(self) -> None:
        [ro] = self._rep([2, 1, 0], folder="Mobile Users")
        assert ro.preserved is None


class TestImpactCoverage:
    def test_every_unsupported_section_and_rulebase_has_an_impact(self) -> None:
        for key in (*pi._UNSUPPORTED_SECTIONS, *pi._UNSUPPORTED_RULEBASES):
            assert key in mr.SECTION_IMPACT, key

    # One item per PlanItem the importer can emit (see panos_import.PlanItem calls)
    EMITTED = [
        ("addresses", pi.DROPPED, "not in SCM: x"),
        ("addresses", pi.INVALID, "validation error"),
        ("addresses", pi.REVIEW, "nested fields not in SCM, left out: x"),
        ("addresses", pi.OVERRIDDEN, "shared copy hidden by dg"),
        ("tags", pi.DROPPED, "colour `color99` has no SCM name"),
        ("services", pi.REVIEW, "source port dropped: ..."),
        ("edls", pi.MANUAL, "list credentials not migrated ..."),
        ("application_filters", pi.DROPPED, "risk not numeric"),
        ("anti_spyware_profiles", pi.DROPPED, "DNS policy (botnet-domains) not migrated"),
        ("url_access_profiles", pi.REVIEW, "categories set to `override` not migrated"),
        ("security_rules_pre", pi.DROPPED, "device targeting (SCM scopes by folder)"),
        ("security_rules_pre", pi.DROPPED, "QoS marking"),
        ("security_rules_pre", pi.DROPPED, "legacy HIP profiles (use source_hip)"),
        ("security_rules_pre", pi.REVIEW, "schedule dropped (schedules aren't migrated)"),
        ("security_rules_pre", pi.REVIEW, "rule type `intrazone` isn't in SCM"),
        ("security_rules_pre", pi.MANUAL, "antivirus profile av not migrated: add ..."),
        ("security_rules_pre", pi.DROPPED, "file-blocking profile fb not migrated"),
        ("security_rules_pre", pi.INVALID, "duplicate rule name (also in x)"),
        ("nat_rules_pre", pi.UNSUPPORTED, "dynamic destination translation"),
        ("virus", pi.MANUAL, "antivirus profiles can't be created over the SCM API"),
        ("profile_groups", pi.MANUAL, "antivirus profile av not migrated"),
        ("profile_groups", pi.GENERATED, "from the individual profiles on rule `r`"),
        ("default-security-rules", pi.MANUAL, "dg overrides a default rule"),
        ("decryption", pi.UNSUPPORTED, "post-rulebase decryption rules in dg: ..."),
        ("application-override", pi.UNSUPPORTED, "post-rulebase application-override rules"),
    ]

    @pytest.mark.parametrize(("kind", "action", "reason"), EMITTED)
    def test_every_emitted_item_maps_or_is_explicitly_no_impact(
        self, kind: str, action: str, reason: str
    ) -> None:
        item = _item(kind, "n", action, reason)
        assert mr.impact_for(item) is not None or action in mr.NO_IMPACT_ACTIONS

    def test_fixture_items_all_covered(self) -> None:
        conv = pi.convert(pi.load_xml(PANORAMA), device_group="dg-branch")
        for it in conv.items:
            item = it.__dict__
            assert mr.impact_for(item) is not None or it.action in mr.NO_IMPACT_ACTIONS, item

    def test_register_groups_and_marks_unassessed(self) -> None:
        items = [
            _item("schedule", "1 entry", pi.UNSUPPORTED),
            _item("security_rules_pre", "r1", pi.REVIEW, "schedule dropped"),
            _item("security_rules_pre", "r2", pi.REVIEW, "schedule dropped"),
        ]
        rows = mr.impact_register(items)
        sched = [r for r in rows if "always active" in r.impact.finding]
        assert len(sched) == 2  # the section and the rule-level rows
        rule_row = next(r for r in sched if r.subjects[0].startswith("security"))
        assert rule_row.subjects == ["security_rules_pre: r1", "security_rules_pre: r2"]
        assert any(not r.assessed for r in rows) and rows[-1].assessed is False


class TestRender:
    def test_sections_and_sign_off(self) -> None:
        rep = TestStatuses()._report()
        rep.warnings = ["careful"]
        md = mr.render_markdown(rep, {"Plan file": "/p.json"}, "2026-10-15 10:00 UTC")
        for heading in (
            "## 1. Summary",
            "## 2. Panorama as-is",
            "## 3. SCM as-is",
            "## 4. Change audit",
            "## 5. Rule order",
            "## 6. Impact register",
            "### Not assessed from the export",
            "## 7. Sign-off",
        ):
            assert heading in md, heading
        assert "> ⚠️ careful" in md
        assert "| `addresses` | 4 | 7 | +3 |" in md
        assert "### Not in SCM after the push (1)" in md


# ── Tool ─────────────────────────────────────────────────────────────────────


@pytest.fixture
def tool(tmp_path, monkeypatch):
    monkeypatch.setenv("SCM_MCP_BACKUP_DIR", str(tmp_path))
    backups: list[dict[str, Any]] = []

    def fake_backup(client: Any, tenant_id: str, folder: str, output_dir: str = "", **kw: Any):
        backups.append({"tenant_id": tenant_id, "folder": folder, **kw})
        data = {"folder": folder, "tenant_id": tenant_id, "resources": {"addresses": []}}
        return tmp_path / "post.json", data

    monkeypatch.setattr(pm, "write_config_backup", fake_backup)
    mcp = FastMCP("test-report")
    pm.register_panorama_migrate_tools(mcp, lambda tenant_id="": MagicMock())
    fn = mcp._tool_manager.get_tool("scm_migration_report").fn  # noqa: SLF001

    def write(name: str, data: dict[str, Any]) -> str:
        path = tmp_path / name
        path.write_text(json.dumps(data))
        return str(path)

    plan = {
        "migrated_from": "Panorama device group `dg`",
        "resources": {"addresses": [_addr("a")]},
        "plan_items": [],
        "migration": {
            "mode": "apply",
            "target_folder": FOLDER,
            "tenant_id": TENANT,
            "name_prefix": "",
            "on_conflict": "skip",
        },
    }
    pre = {"folder": FOLDER, "tenant_id": TENANT, "resources": {}}
    post = {"folder": FOLDER, "tenant_id": TENANT, "resources": {"addresses": [_scm(_addr("a"))]}}
    plan["migration"]["pre_backup_file"] = write("pre.json", pre)
    return SimpleNamespace(fn=fn, write=write, plan=plan, post=post, backups=backups, tmp=tmp_path)


def test_tool_uses_the_plans_settings_and_saves(tool) -> None:
    out = tool.fn(
        plan_file=tool.write("plan.json", tool.plan),
        post_backup_file=tool.write("post.json", tool.post),
    )
    assert out.startswith("Migration report saved to: ")
    saved = Path(out.split("\n", 1)[0].removeprefix("Migration report saved to: "))
    assert saved.parent == tool.tmp / "migrations" and saved.name.startswith(
        "migration_report_Lab_"
    )
    assert "# Panorama → SCM Migration Report" in saved.read_text()
    assert "| Migrated unchanged | 1 |" in out
    assert tool.backups == []


def test_tool_takes_a_fresh_post_backup(tool) -> None:
    out = tool.fn(plan_file=tool.write("plan.json", tool.plan))
    assert tool.backups == [{"tenant_id": TENANT, "folder": FOLDER, "fresh": True}]
    assert "Not in SCM after the push" in out


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"target_folder": "Other"}, "target_folder `Other` doesn't match the plan"),
        ({"tenant_id": "1111111111"}, "tenant_id `1111111111` doesn't match the plan"),
        ({"name_prefix": "x-"}, "name_prefix `x-` doesn't match"),
    ],
)
def test_tool_refuses_arguments_that_contradict_the_plan(tool, kwargs, message) -> None:
    tool.plan["migration"]["name_prefix"] = "m-"
    out = tool.fn(plan_file=tool.write("plan.json", tool.plan), **kwargs)
    assert out.startswith("Error:") and message in out


def test_tool_refuses_a_backup_of_another_tenant_or_folder(tool) -> None:
    plan_file = tool.write("plan.json", tool.plan)
    other = {**tool.post, "tenant_id": "9999999999"}
    out = tool.fn(plan_file=plan_file, post_backup_file=tool.write("o.json", other))
    assert "belongs to another tenant" in out
    other = {**tool.post, "folder": "Elsewhere"}
    out = tool.fn(plan_file=plan_file, post_backup_file=tool.write("o.json", other))
    assert "is of folder `Elsewhere`" in out


def test_tool_rejects_files_that_are_not_plans(tool) -> None:
    out = tool.fn(plan_file=tool.write("b.json", {"resources": {}}))
    assert "is not a scm_panorama_migrate plan file" in out
    out = tool.fn(plan_file=str(tool.tmp / "nope.json"))
    assert out.startswith("Error: plan_file") and "could not be read" in out


def test_tool_warns_about_dry_run_plans_and_missing_pre_backup(tool) -> None:
    tool.plan["migration"]["mode"] = "dry_run"
    del tool.plan["migration"]["pre_backup_file"]
    out = tool.fn(
        plan_file=tool.write("plan.json", tool.plan),
        post_backup_file=tool.write("post.json", tool.post),
    )
    assert "written by a dry run" in out and "No pre-migration backup" in out


# ── Supporting changes ───────────────────────────────────────────────────────


def test_write_config_backup_can_bypass_the_snapshot_cache(tmp_path, monkeypatch) -> None:
    seen: list[bool] = []

    def fake_extract(client: Any, folder: str, tenant_id: str, fresh: bool = False) -> Any:
        seen.append(fresh)
        return SimpleNamespace(tenant_id=tenant_id, extraction_errors=[])

    monkeypatch.setattr(audit_tools, "extract_snapshot", fake_extract)
    monkeypatch.setattr(audit_tools, "backup_snapshot", lambda c, s, f: s)
    monkeypatch.setattr(audit_tools, "backup_resource_payload", lambda s: {})
    monkeypatch.setattr(audit_tools, "backup_snippet_types", lambda s: {})
    monkeypatch.setattr(audit_tools, "backup_snippets", lambda s: [])
    audit_tools.write_config_backup(MagicMock(), TENANT, FOLDER, str(tmp_path))
    audit_tools.write_config_backup(MagicMock(), TENANT, FOLDER, str(tmp_path), fresh=True)
    assert seen == [False, True]


def test_migrate_records_its_settings_and_pre_backup_in_the_plan(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SCM_MCP_BACKUP_DIR", str(tmp_path))
    report = SimpleNamespace(
        to_markdown=lambda: "", target_tenant_id="", preflight=None, created=0, results=[]
    )
    monkeypatch.setattr(pm, "clone_config", lambda client, **kw: report)
    monkeypatch.setattr(
        pm, "write_config_backup", lambda c, t, f, output_dir="": (Path("/b/pre.json"), {})
    )
    mcp = FastMCP("t")
    pm.register_panorama_migrate_tools(mcp, lambda tenant_id="": MagicMock())
    migrate = mcp._tool_manager.get_tool("scm_panorama_migrate").fn  # noqa: SLF001
    result = mcp._tool_manager.get_tool("scm_panorama_migrate_result").fn  # noqa: SLF001
    out = migrate(
        xml_path=str(PANORAMA),
        target_folder=FOLDER,
        device_group="dg-branch",
        tenant_id=TENANT,
        name_prefix="m-",
        ticket_ref="CHG-1",
        dry_run=False,
    )
    job = out.split("job `", 1)[1].split("`", 1)[0]
    for _ in range(200):
        if "still running" not in str(result(job_id=job)):
            break
        time.sleep(0.02)
    [plan] = (tmp_path / "migrations").glob("panos_migration_*.json")
    rec = json.loads(plan.read_text())["migration"]
    assert rec["mode"] == "apply" and rec["target_folder"] == FOLDER
    assert rec["tenant_id"] == TENANT and rec["name_prefix"] == "m-"
    assert rec["pre_backup_file"] == "/b/pre.json"
    assert rec["scopes"] == SCOPES
