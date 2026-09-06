"""Planner Phase 3a nightly ops tests.

Includes the epic's acceptance tests: the agent must autonomously surface
(1) "NFR licences expiring within 90 days across multiple tenants" and
(2) "licensed-but-unused tenant shell" — both are pinned here against the
mechanical extraction rules, plus ranking (severity then Gold-first tier),
template execution through the real PlannerLoop, and digest rendering.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from scm_harbourmaster_mcp.planner import PlanStore
from scm_harbourmaster_mcp.planner.nightly import (
    Finding,
    NightlyOpsRunner,
    TemplateEngine,
    TenantSpec,
    estate_findings,
    extract_attention_lines,
    licence_findings,
    nightly_steps,
    rank_findings,
)


def _exp(days: int) -> str:
    return (datetime.now(UTC) + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")


def _row(app: str, days: int, lic_type: str = "PAE-MU", purchased: int = 100, consumed: int = 50):
    return {
        "app": app,
        "exp": _exp(days),
        "license_type": lic_type,
        "purchased": purchased,
        "remaining": purchased - consumed,
        "consumed": consumed,
        "days": days,
    }


GOLD = TenantSpec(label="Gold Tenant", tenant_id="111", tier="gold")
BRONZE = TenantSpec(label="Bronze Tenant", tenant_id="222", tier="bronze")


class TestAcceptanceNfrExpiringAcrossTenants:
    def test_nfr_expiring_in_multiple_tenants_raises_estate_critical(self) -> None:
        rows_by_tenant = {
            "Gold Tenant": [_row("prisma_access_edition", 45, "PAE-MU-NFR")],
            "Bronze Tenant": [_row("prisma_access_edition", 60, "EVALMUSCMAIOPSPAE")],
        }
        specs = {"Gold Tenant": GOLD, "Bronze Tenant": BRONZE}
        (f,) = estate_findings(rows_by_tenant, specs)
        assert f.severity == "CRITICAL"
        assert "NFR/eval licences expiring within 90 days across 2 tenants" in f.title
        assert "Gold Tenant" in f.detail and "Bronze Tenant" in f.detail

    def test_single_tenant_expiry_is_not_an_estate_finding(self) -> None:
        rows_by_tenant = {
            "Gold Tenant": [_row("prisma_access_edition", 45, "PAE-MU-NFR")],
            "Bronze Tenant": [_row("logging_service", 400)],
        }
        assert estate_findings(rows_by_tenant, {"Gold Tenant": GOLD, "Bronze Tenant": BRONZE}) == []


class TestAcceptanceUnusedShell:
    def test_active_licences_with_zero_consumption_flag_shell(self) -> None:
        rows = [
            _row("prisma_access_edition", 200, purchased=1000, consumed=0),
            _row("logging_service", 200, purchased=5, consumed=0),
        ]
        findings = licence_findings(GOLD, rows)
        shells = [f for f in findings if "licensed-but-unused tenant shell" in f.title]
        assert len(shells) == 1
        assert shells[0].severity == "MEDIUM"

    def test_any_consumption_means_no_shell_finding(self) -> None:
        rows = [
            _row("prisma_access_edition", 200, purchased=1000, consumed=0),
            _row("logging_service", 200, purchased=5, consumed=1),
        ]
        findings = licence_findings(GOLD, rows)
        assert not any("shell" in f.title for f in findings)

    def test_all_expired_tenant_is_not_a_shell(self) -> None:
        rows = [_row("prisma_access_edition", -400, purchased=1000, consumed=0)]
        findings = licence_findings(GOLD, rows)
        assert not any("shell" in f.title for f in findings)


class TestLicenceFindings:
    def test_expiring_within_horizon_is_one_aggregated_high_with_nfr_marker(self) -> None:
        # Real estates carry many SKUs sharing one expiry — aggregate to ONE finding
        rows = [_row("pae", 30, "PAE-MU-NFR"), _row("pae", 30, "NFR-PA-DLP"), _row("pae", 45)]
        (f,) = licence_findings(GOLD, rows)
        assert f.severity == "HIGH"
        assert "3 licence SKU(s) expiring within 90 days (incl. NFR/eval)" in f.title
        assert "soonest in 30 day(s)" in f.detail

    def test_recently_expired_aggregates_to_one_critical_ancient_ignored(self) -> None:
        findings = licence_findings(GOLD, [_row("pae", -10), _row("pae", -63), _row("old", -400)])
        assert len(findings) == 1
        assert findings[0].severity == "CRITICAL"
        assert "2 licence SKU(s) expired within the last 90 days" in findings[0].title
        assert "worst 63 day(s) ago" in findings[0].detail

    def test_sku_list_is_capped_in_detail(self) -> None:
        rows = [_row("pae", 30, f"SKU-{i}") for i in range(10)]
        (f,) = licence_findings(GOLD, rows)
        assert "+4 more" in f.detail

    def test_healthy_rows_produce_nothing(self) -> None:
        assert licence_findings(GOLD, [_row("pae", 300)]) == []


class TestRanking:
    def test_severity_then_gold_first(self) -> None:
        findings = [
            Finding("HIGH", "b", "", "Bronze Tenant", tier="bronze"),
            Finding("CRITICAL", "c", "", "Bronze Tenant", tier="bronze"),
            Finding("HIGH", "g", "", "Gold Tenant", tier="gold"),
        ]
        ranked = rank_findings(findings)
        assert [f.title for f in ranked] == ["c", "g", "b"]

    def test_estate_findings_lead_their_severity_band(self) -> None:
        # Live-run lesson: "estate" sorted after gold tenant names
        # alphabetically and the acceptance finding fell below the fold.
        findings = [
            Finding("CRITICAL", "tenant-level", "", "BT Gold", tier="gold"),
            Finding("CRITICAL", "estate-level", "", "estate", tier="gold"),
        ]
        ranked = rank_findings(findings)
        assert ranked[0].title == "estate-level"


class TestAttentionLines:
    def test_surfaces_critical_and_expired_lines(self) -> None:
        md = (
            "## Certificate Expiry Scan\n"
            "🔴 EXPIRED: 2  🟢 OK: 10\n"
            "| `gp-cert` | Leaf | vpn.example.net | 2026-05-01 | -75 | 🔴 EXPIRED | Shared |\n"
            "| `root-ca` | CA | ca.example.net | 2030-01-01 | 1200 | 🟢 OK | Shared |\n"
        )
        hits = extract_attention_lines(md)
        assert any("gp-cert" in h for h in hits)
        assert not any("root-ca" in h for h in hits)

    def test_clean_output_yields_nothing(self) -> None:
        assert extract_attention_lines("## All good\n🟢 OK: 12\n") == []


class TestTemplateThroughLoop:
    def test_nightly_template_runs_through_planner_loop(self, tmp_path) -> None:
        spec = TenantSpec(label="Lab", tenant_id="999", tier="gold")

        class FakeBackend:
            def __init__(self):
                self.calls = []

            def call(self, tool, params):
                self.calls.append((tool, params))
                return "🟢 all clear"

        backend = FakeBackend()
        runner = NightlyOpsRunner(
            backend=backend,
            store=PlanStore(plan_dir=tmp_path),
            licence_fetcher=lambda tid: [_row("pae", 45, "PAE-MU-NFR")],
        )
        path, findings = runner.run([spec], include_tier_assess=True)

        called = [c[0] for c in backend.calls]
        assert called == [
            "mssp_tier_assess",
            "scm_cert_scan",
            "scm_license_info",
            "scm_licence_forecast",
            "scm_incident_summary",
            "scm_list_jobs",
        ]
        # tenant_id threaded into every call
        assert all(c[1].get("tenant_id") == "999" for c in backend.calls)
        digest = (tmp_path / path.split("/")[-1]).read_text()
        assert "Nightly Ops Digest" in digest
        assert "Lab (gold)" in digest
        assert any(f.severity == "HIGH" for f in findings)  # the expiring NFR

    def test_no_tier_assess_flag_drops_the_heavy_step(self) -> None:
        steps = nightly_steps(GOLD, include_tier_assess=False)
        assert [s.tool for s in steps][0] == "scm_cert_scan"
        assert all(s.tool != "mssp_tier_assess" for s in steps)

    def test_template_engine_never_revises(self) -> None:
        engine = TemplateEngine([])
        rev = engine.revise(None, None, "")  # type: ignore[arg-type]
        assert rev.done and not rev.add_steps

    def test_failed_check_is_a_reported_line_not_a_crash(self, tmp_path) -> None:
        spec = TenantSpec(label="Flaky", tenant_id="1", tier="silver")

        class FailingBackend:
            def call(self, tool, params):
                if tool == "scm_cert_scan":
                    return "Error: 500 from SCM"
                return "🟢 fine"

        runner = NightlyOpsRunner(
            backend=FailingBackend(),
            store=PlanStore(plan_dir=tmp_path),
            licence_fetcher=lambda tid: [],
        )
        path, _ = runner.run([spec], include_tier_assess=False)
        digest = (tmp_path / path.split("/")[-1]).read_text()
        assert "🔴 `scm_cert_scan`" in digest
        assert "Error: 500 from SCM" in digest

    def test_licence_fetch_failure_degrades_gracefully(self, tmp_path) -> None:
        spec = TenantSpec(label="NoLic", tenant_id="1", tier="bronze")

        class OkBackend:
            def call(self, tool, params):
                return "ok"

        def exploding_fetcher(tid):
            raise RuntimeError("subscription API down")

        runner = NightlyOpsRunner(
            backend=OkBackend(),
            store=PlanStore(plan_dir=tmp_path),
            licence_fetcher=exploding_fetcher,
        )
        path, findings = runner.run([spec], include_tier_assess=False)
        assert findings == []  # no licence findings, but the run completed
        assert "Nightly Ops Digest" in (tmp_path / path.split("/")[-1]).read_text()

    def test_tenants_ordered_gold_first_in_digest(self, tmp_path) -> None:
        class OkBackend:
            def call(self, tool, params):
                return "ok"

        runner = NightlyOpsRunner(
            backend=OkBackend(),
            store=PlanStore(plan_dir=tmp_path),
            licence_fetcher=lambda tid: [],
        )
        path, _ = runner.run([BRONZE, GOLD], include_tier_assess=False)
        digest = (tmp_path / path.split("/")[-1]).read_text()
        assert digest.index("Gold Tenant") < digest.index("Bronze Tenant")
