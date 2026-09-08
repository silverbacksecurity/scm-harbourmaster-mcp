"""Planner Phase 4 estate-layer tests.

Pins the per-tenant check template (all manifest-classified read tools), the
three cross-tenant anomaly rules (including the duplicate-NFR-set pattern
observed live on this estate), the bounded-concurrency fan-out invariant,
and the aggregated digest.
"""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime, timedelta

from scm_harbourmaster_mcp.planner import PlanStore, load_manifest
from scm_harbourmaster_mcp.planner.estate import (
    EstateRunner,
    TenantFacts,
    TenantSpec,
    anomaly_findings,
    estate_steps,
)


def _spec(label: str, tid: str = "1") -> TenantSpec:
    return TenantSpec(label=label, tenant_id=tid)


def _row(days: int, lic_type: str = "PAE-MU", purchased: int = 100, consumed: int = 50):
    exp = (datetime.now(UTC) + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
    return {
        "app": "prisma_access_edition",
        "exp": exp,
        "license_type": lic_type,
        "purchased": purchased,
        "consumed": consumed,
        "days": days,
    }


class TestCheckTemplate:
    def test_template_contents_match_the_spec(self) -> None:
        assert {s.tool for s in estate_steps(_spec("t"))} == {
            "scm_license_info",
            "scm_licence_forecast",
            "scm_cert_scan",
            "scm_ike_gateway_list",
            "scm_bpa_assess",
            "scm_list_jobs",
            "scm_ncsc_assess",
            "scm_iso27001_assess",
            "scm_dlp_list",
            "scm_saas_posture",
        }

    def test_every_tenant_gets_the_same_steps(self) -> None:
        a = [s.tool for s in estate_steps(_spec("a", tid="1"))]
        b = [s.tool for s in estate_steps(_spec("b", tid="2"))]
        assert a == b

    def test_every_step_is_a_manifest_classified_read_tool(self) -> None:
        manifest = load_manifest()
        for step in estate_steps(_spec("t")):
            assert manifest.policy(step.tool).access == "read", step.tool


class TestAnomalyRules:
    def test_sdwan_topology_with_zero_licences(self) -> None:
        facts = [TenantFacts(spec=_spec("SDWAN Lab"), licence_rows=[], sdwan_site_count=16)]
        (f,) = anomaly_findings(facts)
        assert f.severity == "HIGH"
        assert "SD-WAN topology with zero active licences" in f.title

    def test_sdwan_with_licences_is_fine(self) -> None:
        facts = [
            TenantFacts(
                spec=_spec("SDWAN Lab"),
                licence_rows=[_row(200)],
                sdwan_site_count=16,
            )
        ]
        assert anomaly_findings(facts) == []

    def test_unknown_site_count_skips_the_rule(self) -> None:
        facts = [TenantFacts(spec=_spec("t"), licence_rows=[], sdwan_site_count=None)]
        assert anomaly_findings(facts) == []

    def test_duplicate_nfr_sets_across_tenants(self) -> None:
        # The pattern observed live: identical NFR SKU sets on two lab tenants
        nfr_set = [_row(67, "PAE-MU-NFR"), _row(67, "NFR-PA-DLP"), _row(67, "NFRSAASAPI")]
        facts = [
            TenantFacts(spec=_spec("Lab A"), licence_rows=list(nfr_set), job_count=5),
            TenantFacts(spec=_spec("Lab B"), licence_rows=list(nfr_set), job_count=5),
        ]
        findings = anomaly_findings(facts)
        dupes = [f for f in findings if "duplicate NFR licence set" in f.title]
        assert len(dupes) == 1
        assert "Lab A" in dupes[0].detail and "Lab B" in dupes[0].detail
        assert dupes[0].tenant_label == "estate"

    def test_single_stray_eval_licence_is_not_a_set(self) -> None:
        facts = [
            TenantFacts(spec=_spec("A"), licence_rows=[_row(67, "PAE-MU-NFR")]),
            TenantFacts(spec=_spec("B"), licence_rows=[_row(67, "PAE-MU-NFR")]),
        ]
        assert not any("duplicate" in f.title for f in anomaly_findings(facts))

    def test_provisioned_but_idle(self) -> None:
        rows = [_row(200), _row(200, "PAE-RN"), _row(200, "LOGGING")]
        facts = [TenantFacts(spec=_spec("Idle Co"), licence_rows=rows, job_count=0)]
        (f,) = anomaly_findings(facts)
        assert "provisioned-but-idle" in f.title

    def test_active_tenant_is_not_idle(self) -> None:
        rows = [_row(200), _row(200, "PAE-RN"), _row(200, "LOGGING")]
        facts = [TenantFacts(spec=_spec("Busy Co"), licence_rows=rows, job_count=12)]
        assert anomaly_findings(facts) == []


class ConcurrencyTrackingBackend:
    """Counts peak concurrent calls to prove the fan-out bound."""

    def __init__(self):
        self._lock = threading.Lock()
        self.active = 0
        self.peak = 0
        self.calls: list[str] = []

    def call(self, tool, params):
        with self._lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
            self.calls.append(tool)
        time.sleep(0.02)  # hold the slot long enough for overlap to show
        with self._lock:
            self.active -= 1
        return "🟢 fine"


class TestEstateRunner:
    def _runner(self, tmp_path, backend, facts_by_label=None, concurrency=2) -> EstateRunner:
        def gather(spec):
            if facts_by_label and spec.label in facts_by_label:
                return facts_by_label[spec.label]
            return TenantFacts(spec=spec)

        return EstateRunner(
            backend=backend,
            store=PlanStore(plan_dir=tmp_path),
            gather_facts=gather,
            concurrency=concurrency,
        )

    def test_fan_out_respects_the_concurrency_bound(self, tmp_path) -> None:
        backend = ConcurrencyTrackingBackend()
        specs = [_spec(f"T{i}", tid=str(i)) for i in range(6)]
        runner = self._runner(tmp_path, backend, concurrency=2)
        path, _ = runner.run(specs)
        assert backend.peak <= 2
        assert path.endswith(".md")

    def test_digest_orders_tenants_by_name_and_runs_every_check(self, tmp_path) -> None:
        backend = ConcurrencyTrackingBackend()
        specs = [_spec("Zeta Co", "1"), _spec("Alpha Co", "2")]
        runner = self._runner(tmp_path, backend, concurrency=1)
        path, _ = runner.run(specs)
        digest = (tmp_path / path.split("/")[-1]).read_text()
        assert digest.index("Alpha Co") < digest.index("Zeta Co")
        # every tenant runs the full check set
        assert "scm_ncsc_assess" in digest

    def test_anomalies_and_licence_findings_reach_the_digest(self, tmp_path) -> None:
        backend = ConcurrencyTrackingBackend()
        spec = _spec("SDWAN Lab", "1")
        facts = TenantFacts(spec=spec, licence_rows=[], sdwan_site_count=9)
        runner = self._runner(tmp_path, backend, {"SDWAN Lab": facts})
        path, ranked = runner.run([spec])
        assert any("SD-WAN topology with zero active licences" in f.title for f in ranked)
        digest = (tmp_path / path.split("/")[-1]).read_text()
        assert "SD-WAN topology with zero active licences" in digest

    def test_fact_gatherer_failure_degrades_gracefully(self, tmp_path) -> None:
        backend = ConcurrencyTrackingBackend()

        def exploding(spec):
            raise RuntimeError("facts unavailable")

        runner = EstateRunner(
            backend=backend,
            store=PlanStore(plan_dir=tmp_path),
            gather_facts=exploding,
            concurrency=1,
        )
        path, ranked = runner.run([_spec("T")])
        assert path.endswith(".md")  # run completed; rules skipped, no crash
