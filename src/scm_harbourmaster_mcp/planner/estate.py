"""
Planner Phase 4 — the MSSP cross-tenant layer.

The differentiator over PANW's single-tenant model:

  * Estate fan-out — one trigger ("morning estate check") generates a
    per-tenant sub-plan for every loaded tenant and executes them with
    bounded concurrency through the same PlannerLoop; results aggregate
    into one estate digest.
  * Tier-aware depth — each tenant's contracted tier scopes its checks.
    Bronze: licensing + certs + connectivity basics. Silver: + posture
    (BPA) + change audit. Gold: + NCSC CAF + ISO 27001 + DLP/SSPM posture.
    (The BPA/NCSC/ISO steps share one snapshot per tenant via the
    extractor's short-TTL cache, so Gold depth costs one extraction.)
  * Cross-tenant anomaly rules — patterns invisible per-tenant: SD-WAN
    topology with zero licences, duplicate NFR licence sets expiring
    across tenants (observed live on this estate), and
    provisioned-but-idle tenants (full licence bundles, zero config jobs).

Templates are read-only by construction (no approver is wired).
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from ..utils.logging import get_logger
from .engine import StepDraft
from .executor import StepExecutor, ToolBackend
from .loop import PlannerLoop
from .manifest import Manifest, load_manifest
from .nightly import (
    _HORIZON_DAYS,
    Finding,
    TemplateEngine,
    TenantSpec,
    _is_nfr,
    estate_findings,
    extract_attention_lines,
    licence_findings,
    rank_findings,
)
from .schema import Plan, TriggerType
from .store import PlanStore

logger = get_logger(__name__)

TIERS = ("bronze", "silver", "gold")


# ── tier-aware templates ─────────────────────────────────────────────────────


def tier_steps(spec: TenantSpec) -> list[StepDraft]:
    """The tier-scoped check template: bronze ⊂ silver ⊂ gold."""
    steps: list[StepDraft] = []

    def add(domain: str, tool: str, **params: Any) -> None:
        steps.append(StepDraft(domain=domain, tool=tool, params_json=json.dumps(params)))

    tier = spec.tier.lower()

    # Bronze — licensing + certs + connectivity basics (every tenant)
    add("licensing", "scm_license_info", tenant_id=spec.tenant_id)
    add("licensing", "scm_licence_forecast", tenant_id=spec.tenant_id, warn_days=_HORIZON_DAYS)
    add("certificates", "scm_cert_scan", tenant_id=spec.tenant_id, warn_days=_HORIZON_DAYS)
    add(
        "deployment",
        "scm_ike_gateway_list",
        folder="Remote Networks",
        tenant_id=spec.tenant_id,
    )

    # Silver — + posture (BPA) + change audit
    if tier in ("silver", "gold"):
        add("posture_compliance", "scm_bpa_assess", folder=spec.folder, tenant_id=spec.tenant_id)
        add("operational_health", "scm_list_jobs", tenant_id=spec.tenant_id, limit=50)

    # Gold — + full compliance assessments + DLP/SSPM posture
    # (BPA/NCSC/ISO share one snapshot via the extractor's TTL cache.)
    if tier == "gold":
        add("posture_compliance", "scm_ncsc_assess", folder=spec.folder, tenant_id=spec.tenant_id)
        add(
            "posture_compliance",
            "scm_iso27001_assess",
            folder=spec.folder,
            tenant_id=spec.tenant_id,
        )
        add("dlp", "scm_dlp_list", folder="All", tenant_id=spec.tenant_id)
        add("posture_compliance", "scm_saas_posture", tenant_id=spec.tenant_id)

    return steps


# ── cross-tenant anomaly rules (pure) ────────────────────────────────────────


@dataclass
class TenantFacts:
    """Cheap per-tenant facts the anomaly rules run over.

    None means "could not gather" — rules needing that fact skip the tenant
    rather than fabricating a finding.
    """

    spec: TenantSpec
    licence_rows: list[dict[str, Any]] = field(default_factory=list)
    job_count: int | None = None
    sdwan_site_count: int | None = None


def anomaly_findings(facts: list[TenantFacts], horizon: int = _HORIZON_DAYS) -> list[Finding]:
    findings: list[Finding] = []

    # Rule 1 — SD-WAN topology but zero active licences
    for f in facts:
        if f.sdwan_site_count is None:
            continue
        active = [
            r
            for r in f.licence_rows
            if r.get("days") is not None and r["days"] >= 0 and int(r.get("purchased", 0) or 0) > 0
        ]
        if f.sdwan_site_count > 0 and not active:
            findings.append(
                Finding(
                    severity="HIGH",
                    title="SD-WAN topology with zero active licences",
                    detail=(
                        f"{f.sdwan_site_count} SD-WAN site(s) deployed but no active licence "
                        "line — running unlicensed or the entitlement moved elsewhere"
                    ),
                    tenant_label=f.spec.label,
                    tier=f.spec.tier,
                    source="cross-tenant anomaly rules",
                )
            )

    # Rule 2 — duplicate NFR licence sets expiring across tenants
    # (observed live: two lab tenants carrying identical 11-SKU eval sets)
    signatures: dict[frozenset[tuple[str, str]], list[str]] = {}
    for f in facts:
        sig = frozenset(
            (str(r.get("license_type", "")), str(r.get("exp", ""))[:10])
            for r in f.licence_rows
            if _is_nfr(str(r.get("license_type", "")))
            and r.get("days") is not None
            and -horizon <= r["days"] <= horizon
        )
        if len(sig) >= 3:  # a *set* of NFR SKUs, not a stray eval licence
            signatures.setdefault(sig, []).append(f.spec.label)
    for sig, tenants in signatures.items():
        if len(tenants) >= 2:
            findings.append(
                Finding(
                    severity="MEDIUM",
                    title=(
                        f"duplicate NFR licence set ({len(sig)} SKUs) on {len(tenants)} tenants"
                    ),
                    detail=(
                        f"Identical NFR/eval SKU+expiry sets on: {', '.join(sorted(tenants))} — "
                        "likely cloned demo entitlements; renew or retire together"
                    ),
                    tenant_label="estate",
                    tier="gold",
                    source="cross-tenant anomaly rules",
                )
            )

    # Rule 3 — provisioned-but-idle: full licence bundles, zero config jobs
    for f in facts:
        if f.job_count is None:
            continue
        active_lines = [
            r
            for r in f.licence_rows
            if r.get("days") is not None and r["days"] >= 0 and int(r.get("purchased", 0) or 0) > 0
        ]
        if f.job_count == 0 and len(active_lines) >= 3:
            findings.append(
                Finding(
                    severity="MEDIUM",
                    title="provisioned-but-idle tenant (licences, no config activity)",
                    detail=(
                        f"{len(active_lines)} active licence line(s) but zero config jobs "
                        "recorded — paying for a tenant nobody operates"
                    ),
                    tenant_label=f.spec.label,
                    tier=f.spec.tier,
                    source="cross-tenant anomaly rules",
                )
            )

    return findings


# ── estate fan-out runner ────────────────────────────────────────────────────

FactGatherer = Callable[[TenantSpec], TenantFacts]


@dataclass
class EstateResult:
    spec: TenantSpec
    plan: Plan
    attention: dict[str, list[str]] = field(default_factory=dict)


class EstateRunner:
    """One trigger → per-tenant sub-plans with bounded concurrency → digest."""

    def __init__(
        self,
        backend: ToolBackend,
        store: PlanStore,
        gather_facts: FactGatherer,
        manifest: Manifest | None = None,
        concurrency: int = 3,
    ) -> None:
        self.backend = backend
        self.store = store
        self.gather_facts = gather_facts
        self.manifest = manifest or load_manifest()
        self.concurrency = max(1, concurrency)

    def _run_tenant(self, spec: TenantSpec) -> EstateResult:
        engine = TemplateEngine(tier_steps(spec))
        executor = StepExecutor(self.manifest, self.backend, approve_write=None)
        loop = PlannerLoop(self.manifest, engine, executor, self.store)
        plan = loop.run(
            goal=f"estate check ({spec.tier} depth) for {spec.label}",
            trigger_type=TriggerType.SCHEDULED,
            trigger_payload={"surface": "estate", "tier": spec.tier},
            tenant_scope=spec.tenant_id,
            persona="estate-check",
        )
        result = EstateResult(spec=spec, plan=plan)
        for step in plan.steps:
            if step.status.value == "ok":
                hits = extract_attention_lines(step.result_summary)
                if hits:
                    result.attention[step.step_id] = hits
        return result

    def run(self, specs: list[TenantSpec]) -> tuple[str, list[Finding]]:
        """Fan out, gather facts, apply anomaly rules, write the digest."""
        ordered = sorted(specs, key=lambda s: ({"gold": 0, "silver": 1}.get(s.tier, 2), s.label))

        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            results = list(pool.map(self._run_tenant, ordered))
            facts = list(pool.map(self._safe_facts, ordered))

        findings: list[Finding] = []
        rows_by_tenant: dict[str, list[dict[str, Any]]] = {}
        for f in facts:
            rows_by_tenant[f.spec.label] = f.licence_rows
            findings.extend(licence_findings(f.spec, f.licence_rows))
        findings.extend(estate_findings(rows_by_tenant, {s.label: s for s in ordered}))
        findings.extend(anomaly_findings(facts))
        ranked = rank_findings(findings)

        digest = self._render(results, ranked)
        stamp = time.strftime("%Y%m%d-%H%M", time.gmtime())
        self.store.plan_dir.mkdir(parents=True, exist_ok=True)
        path = self.store.plan_dir / f"estate-{stamp}.md"
        path.write_text(digest)
        logger.info("estate_digest_written", path=str(path), findings=len(ranked))
        return str(path), ranked

    def _safe_facts(self, spec: TenantSpec) -> TenantFacts:
        try:
            return self.gather_facts(spec)
        except Exception as exc:
            logger.warning("estate_facts_failed", tenant=spec.label, error=str(exc))
            return TenantFacts(spec=spec)

    @staticmethod
    def _render(results: list[EstateResult], findings: list[Finding]) -> str:
        from .nightly import _SEV_ICON

        generated = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
        lines = [
            "# Estate Check Digest",
            "",
            f"**Generated:** {generated}  |  **Tenants:** {len(results)}  |  "
            f"**Findings:** {len(findings)}",
            "",
        ]
        if findings:
            lines += [
                "## Top Findings (severity, estate first, then tier)",
                "",
                "| # | Sev | Tenant | Tier | Finding |",
                "|---|---|---|---|---|",
            ]
            for i, f in enumerate(findings[:20], 1):
                lines.append(
                    f"| {i} | {_SEV_ICON.get(f.severity, '')} {f.severity} | {f.tenant_label} "
                    f"| {f.tier} | **{f.title}** — {f.detail} |"
                )
            if len(findings) > 20:
                lines.append(f"| … | | | | +{len(findings) - 20} more |")
            lines.append("")
        else:
            lines += ["🟢 **No findings** — the estate is clean at every tier's depth.", ""]

        lines += ["## Per-Tenant Checks (tier depth; Gold first)", ""]
        for r in results:
            counts = r.plan.counts
            ok_all = counts.get("failed", 0) == 0 and counts.get("skipped", 0) == 0
            lines.append(
                f"### {'🟢' if ok_all else '🟡'} {r.spec.label} ({r.spec.tier} depth) — "
                f"{counts.get('ok', 0)} ok / {counts.get('failed', 0)} failed / "
                f"{counts.get('skipped', 0)} skipped"
            )
            for step in r.plan.steps:
                mark = {"ok": "✅", "failed": "🔴", "skipped": "⏭️"}.get(step.status.value, "⏸️")
                lines.append(f"- {mark} `{step.tool}`")
                for hit in r.attention.get(step.step_id, []):
                    lines.append(f"  - ⚠️ {hit}")
            lines.append(f"- 📄 full report: `{r.plan.final_report_ref}`")
            lines.append("")
        return "\n".join(lines)


# ── production fact gatherer + cron entrypoint ───────────────────────────────


def default_fact_gatherer(backend: ToolBackend) -> FactGatherer:
    """Gather the cheap per-tenant facts the anomaly rules need.

    Licences via the Subscription API, job count via the SDK, SD-WAN site
    count via the sdwan_list_sites tool (parsed leniently — None on any
    surprise, which makes the dependent rule skip rather than guess).
    """
    from ..auth.oauth import fetch_licenses, get_client_for_tenant
    from ..tools.ops import _licence_rows

    def gather(spec: TenantSpec) -> TenantFacts:
        facts = TenantFacts(spec=spec)
        client = get_client_for_tenant(spec.tenant_id)
        try:
            facts.licence_rows = _licence_rows(fetch_licenses(client))
        except Exception as exc:
            logger.warning("estate_licence_fetch_failed", tenant=spec.label, error=str(exc))
        try:
            resp = client.list_jobs(limit=10, offset=0)
            facts.job_count = len(resp.data if hasattr(resp, "data") else [])
        except Exception:
            facts.job_count = None
        try:
            out = backend.call("sdwan_list_sites", {"tenant_id": spec.tenant_id})
            data = json.loads(out)
            if isinstance(data, list):
                facts.sdwan_site_count = len(data)
            elif isinstance(data, dict):
                sites = data.get("sites") or data.get("data")
                count = data.get("count") or data.get("total")
                if isinstance(sites, list):
                    facts.sdwan_site_count = len(sites)
                elif isinstance(count, int):
                    facts.sdwan_site_count = count
        except Exception:
            facts.sdwan_site_count = None
        return facts

    return gather


def main(argv: list[str] | None = None) -> int:
    """`scm-planner-estate` — the morning estate check, from cron or a shell."""
    import argparse
    import os

    parser = argparse.ArgumentParser(description="Tier-aware estate check digest")
    parser.add_argument("--tenants", default="", help="Comma-separated labels (default: all)")
    parser.add_argument("--concurrency", type=int, default=3, help="Parallel tenants (default 3)")
    parser.add_argument(
        "--slack-webhook", default=os.getenv("SCM_MCP_SLACK_WEBHOOK", ""), help="Slack delivery"
    )
    args = parser.parse_args(argv)

    from mcp.server.fastmcp import FastMCP

    from ..auth.oauth import get_client_for_tenant, get_scm_client
    from ..config.settings import load_all_tenant_configs
    from ..server import register_all_tools
    from .backend import InProcessBackend

    wanted = {t.strip().lower() for t in args.tenants.split(",") if t.strip()}
    specs: list[TenantSpec] = []
    for key, tc in load_all_tenant_configs().items():
        label = tc.label or key
        if wanted and label.lower() not in wanted and key.lower() not in wanted:
            continue
        try:
            get_scm_client(tc)
        except Exception as exc:
            logger.warning("estate_tenant_auth_failed", tenant=label, error=str(exc))
            continue
        specs.append(TenantSpec(label=label, tenant_id=tc.tenant_id, tier=str(tc.tier)))
    if not specs:
        print("No tenants available (auth failures or filter matched nothing).")
        return 1

    mcp = FastMCP("planner-estate")
    register_all_tools(mcp, lambda tid="": get_client_for_tenant(tid), lambda: None)
    backend = InProcessBackend(mcp)

    runner = EstateRunner(
        backend=backend,
        store=PlanStore(),
        gather_facts=default_fact_gatherer(backend),
        concurrency=args.concurrency,
    )
    path, ranked = runner.run(specs)

    if args.slack_webhook:
        from .nightly import _SEV_ICON, post_slack

        top = "\n".join(
            f"{_SEV_ICON.get(f.severity, '')} [{f.severity}] {f.tenant_label}: {f.title}"
            for f in ranked[:10]
        )
        post_slack(
            args.slack_webhook,
            f"*Estate Check* — {len(ranked)} finding(s) across {len(specs)} tenant(s)\n"
            f"{top or 'all clean'}\nFull digest: {path}",
        )

    print(f"digest: {path}")
    print(f"findings: {len(ranked)}")
    for f in ranked[:10]:
        print(f"  [{f.severity}] {f.tenant_label}: {f.title}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
