"""
Planner Phase 3a — the scheduled ops agent (nightly digest MVP).

Trigger surface #1: cron. An external scheduler (cron/systemd timer) runs
the `scm-planner-nightly` entrypoint; each tenant gets a deterministic
template plan (tier assessment, cert scan, licence expiry, incident
summary, job/change audit) executed through the SAME PlannerLoop as every
other trigger — the template just replaces LLM plan generation with a
fixed check set, because a nightly run's shape is policy, not reasoning.

Output: one estate digest, findings ranked by severity then customer tier
(Gold first), with per-tenant sections and pointers to each tenant's full
plan report. Acceptance rules (from the epic) are computed mechanically
from raw Subscription API rows so they can't be lost to output truncation:

  - "NFR licences expiring within 90 days across multiple tenants"
  - "licensed-but-unused tenant shell" (active seats, zero consumption)

Delivery: digest written under the plan dir; optionally POSTed to a Slack
incoming webhook (SCM_MCP_SLACK_WEBHOOK or --slack-webhook). Email is a
Phase 3a follow-up.
"""

from __future__ import annotations

import json
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..utils.logging import get_logger
from .engine import PlanDraft, RevisionDraft, StepDraft
from .executor import StepExecutor, ToolBackend
from .loop import PlannerLoop
from .manifest import Manifest, load_manifest
from .schema import Plan, PlanStep, TriggerType
from .store import PlanStore

logger = get_logger(__name__)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
TIER_ORDER = {"gold": 0, "silver": 1, "bronze": 2}
_SEV_ICON = {"CRITICAL": "🔴", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "⚪", "INFO": "ℹ️"}
_HORIZON_DAYS = 90
_NFR_MARKERS = ("NFR", "EVAL", "TRIAL")


@dataclass
class TenantSpec:
    label: str
    tenant_id: str  # TSG id — what every tool's tenant_id param takes
    tier: str = "bronze"
    folder: str = "Prisma Access"


@dataclass
class Finding:
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str
    detail: str
    tenant_label: str  # "" or "estate" for cross-tenant findings
    tier: str = "bronze"
    source: str = ""


@dataclass
class TenantResult:
    spec: TenantSpec
    plan: Plan
    attention: dict[str, list[str]] = field(default_factory=dict)  # tool → lines


class TemplateEngine:
    """PlanningEngine that plays back a fixed step template.

    The nightly check set is policy, not reasoning — no LLM call decides
    it. revise() never changes the plan (failed checks are findings, not
    problems to plan around), and synthesize() defers to the loop's
    mechanical report so per-tenant reports stay deterministic.
    """

    def __init__(self, steps: list[StepDraft]) -> None:
        self.steps = steps

    def generate_plan(self, goal: str, tenant_scope: str, catalog: str) -> PlanDraft:
        return PlanDraft(rationale="scheduled-ops template", steps=list(self.steps))

    def revise(self, plan: Plan, failed_step: PlanStep, catalog: str) -> RevisionDraft:
        return RevisionDraft(done=True, reason="template plans are not revised")

    def synthesize(self, plan: Plan) -> str:
        return ""  # falsy → the loop uses its mechanical report, no audit noise


def nightly_steps(spec: TenantSpec, include_tier_assess: bool = True) -> list[StepDraft]:
    steps: list[StepDraft] = []

    def add(domain: str, tool: str, **params: Any) -> None:
        steps.append(StepDraft(domain=domain, tool=tool, params_json=json.dumps(params)))

    if include_tier_assess:
        add(
            "posture_compliance",
            "mssp_tier_assess",
            folder=spec.folder,
            tenant_id=spec.tenant_id,
        )
    add("certificates", "scm_cert_scan", tenant_id=spec.tenant_id, warn_days=_HORIZON_DAYS)
    add("licensing", "scm_license_info", tenant_id=spec.tenant_id)
    add(
        "licensing",
        "scm_licence_forecast",
        tenant_id=spec.tenant_id,
        warn_days=_HORIZON_DAYS,
    )
    add(
        "operational_health",
        "scm_incident_summary",
        tenant_id=spec.tenant_id,
        all_tenants=False,
    )
    add("operational_health", "scm_list_jobs", tenant_id=spec.tenant_id, limit=50)
    return steps


# ── finding extraction (pure) ────────────────────────────────────────────────


def extract_attention_lines(markdown: str, cap: int = 6) -> list[str]:
    """Best-effort: surface the lines a NOC operator would stop on."""
    hits: list[str] = []
    for line in markdown.splitlines():
        stripped = line.strip().strip("|").strip()
        if not stripped or stripped.startswith(("#", "-|", "|-")):
            continue
        if (
            "🔴" in stripped or "CRITICAL" in stripped or "EXPIRED" in stripped
        ) and stripped not in hits:
            hits.append(stripped)
        if len(hits) >= cap:
            break
    return hits


def _is_nfr(license_type: str) -> bool:
    return any(marker in license_type.upper() for marker in _NFR_MARKERS)


def licence_findings(
    spec: TenantSpec, rows: list[dict[str, Any]], horizon: int = _HORIZON_DAYS
) -> list[Finding]:
    """Per-tenant licence findings from raw Subscription API rows.

    Rows are ops._licence_rows() output: app, exp, license_type, purchased,
    consumed, days.
    """
    findings: list[Finding] = []
    # Aggregate per tenant: real estates carry dozens of SKUs sharing one
    # expiry date, and one finding per SKU floods the digest (a live run
    # produced 176 findings estate-wide before this aggregation).
    expired = [r for r in rows if r.get("days") is not None and -horizon <= r["days"] < 0]
    expiring = [r for r in rows if r.get("days") is not None and 0 <= r["days"] <= horizon]

    def _skus(group: list[dict[str, Any]], cap: int = 6) -> str:
        names = [str(r.get("license_type") or r.get("app", "?")) for r in group]
        listed = ", ".join(names[:cap])
        return listed + (f" … +{len(names) - cap} more" if len(names) > cap else "")

    if expired:
        worst = min(r["days"] for r in expired)
        findings.append(
            Finding(
                severity="CRITICAL",
                title=f"{len(expired)} licence SKU(s) expired within the last {horizon} days",
                detail=f"worst {-worst} day(s) ago — {_skus(expired)}",
                tenant_label=spec.label,
                tier=spec.tier,
                source="subscription API",
            )
        )
    if expiring:
        soonest = min(r["days"] for r in expiring)
        nfr = (
            " (incl. NFR/eval)"
            if any(_is_nfr(str(r.get("license_type", ""))) for r in expiring)
            else ""
        )
        findings.append(
            Finding(
                severity="HIGH",
                title=f"{len(expiring)} licence SKU(s) expiring within {horizon} days{nfr}",
                detail=f"soonest in {soonest} day(s) — {_skus(expiring)}",
                tenant_label=spec.label,
                tier=spec.tier,
                source="subscription API",
            )
        )

    seat_rows = [r for r in rows if int(r.get("purchased", 0) or 0) > 0]
    active = [r for r in seat_rows if r.get("days") is not None and r["days"] >= 0]
    if active and all(int(r.get("consumed", 0) or 0) <= 0 for r in seat_rows):
        findings.append(
            Finding(
                severity="MEDIUM",
                title="licensed-but-unused tenant shell",
                detail=(
                    f"{len(active)} active licence line(s) with zero consumption across "
                    "every seat product — paying for capacity nobody uses"
                ),
                tenant_label=spec.label,
                tier=spec.tier,
                source="subscription API",
            )
        )
    return findings


def estate_findings(
    rows_by_tenant: dict[str, list[dict[str, Any]]],
    specs: dict[str, TenantSpec],
    horizon: int = _HORIZON_DAYS,
) -> list[Finding]:
    """Cross-tenant patterns — the acceptance-test findings live here."""
    expiring: dict[str, list[str]] = {}  # tenant label → SKUs expiring in window
    any_nfr = False
    for label, rows in rows_by_tenant.items():
        for r in rows:
            days = r.get("days")
            if days is not None and 0 <= days <= horizon:
                lic = str(r.get("license_type", ""))
                expiring.setdefault(label, []).append(lic)
                any_nfr = any_nfr or _is_nfr(lic)

    findings: list[Finding] = []
    if len(expiring) >= 2:
        kinds = "NFR/eval licences" if any_nfr else "licences"
        tenants = ", ".join(sorted(expiring))
        total = sum(len(v) for v in expiring.values())
        findings.append(
            Finding(
                severity="CRITICAL",
                title=(
                    f"{kinds} expiring within {horizon} days across "
                    f"{len(expiring)} tenants ({total} SKUs)"
                ),
                detail=f"Affected tenants: {tenants}",
                tenant_label="estate",
                tier="gold",  # estate findings always rank first within severity
                source="subscription API",
            )
        )
    return findings


def rank_findings(findings: list[Finding]) -> list[Finding]:
    """Severity first; estate-wide findings lead their severity band;
    then customer tier (Gold first), then tenant name."""
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 9),
            0 if f.tenant_label == "estate" else 1,
            TIER_ORDER.get(f.tier, 9),
            f.tenant_label,
        ),
    )


# ── digest rendering ─────────────────────────────────────────────────────────


def render_digest(
    generated_at: str,
    results: list[TenantResult],
    findings: list[Finding],
) -> str:
    lines = [
        "# Nightly Ops Digest",
        "",
        f"**Generated:** {generated_at}  |  **Tenants checked:** {len(results)}  |  "
        f"**Findings:** {len(findings)}",
        "",
    ]

    if findings:
        lines += [
            "## Top Findings (severity, then tier)",
            "",
            "| # | Sev | Tenant | Tier | Finding |",
            "|---|---|---|---|---|",
        ]
        for i, f in enumerate(findings[:20], 1):
            icon = _SEV_ICON.get(f.severity, "")
            lines.append(
                f"| {i} | {icon} {f.severity} | {f.tenant_label} | {f.tier} "
                f"| **{f.title}** — {f.detail} |"
            )
        if len(findings) > 20:
            lines.append(f"| … | | | | +{len(findings) - 20} more |")
        lines.append("")
    else:
        lines += ["🟢 **No findings** — every check came back clean.", ""]

    lines += ["## Per-Tenant Checks (Gold first)", ""]
    for r in results:
        counts = r.plan.counts
        status = "🟢" if counts.get("failed", 0) == 0 and counts.get("skipped", 0) == 0 else "🟡"
        lines.append(
            f"### {status} {r.spec.label} ({r.spec.tier}) — "
            f"{counts.get('ok', 0)} ok / {counts.get('failed', 0)} failed / "
            f"{counts.get('skipped', 0)} skipped"
        )
        for step in r.plan.steps:
            mark = {"ok": "✅", "failed": "🔴", "skipped": "⏭️"}.get(step.status.value, "⏸️")
            lines.append(f"- {mark} `{step.tool}`")
            for hit in r.attention.get(step.step_id, []):
                lines.append(f"  - ⚠️ {hit}")
            if step.status.value == "failed":
                lines.append(f"  - {step.result_summary[:300]}")
        lines.append(f"- 📄 full report: `{r.plan.final_report_ref}`")
        lines.append("")

    return "\n".join(lines)


def post_slack(webhook_url: str, text: str) -> bool:
    """POST the digest summary to a Slack incoming webhook. Best-effort."""
    if not webhook_url.startswith("https://"):
        logger.warning("nightly_slack_webhook_rejected", reason="not https")
        return False
    try:
        payload = json.dumps({"text": text[:3900]}).encode()
        req = urllib.request.Request(
            webhook_url, data=payload, headers={"Content-Type": "application/json"}
        )
        # Scheme validated https above — file:/custom schemes can't reach here.
        with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310
            return 200 <= resp.status < 300
    except Exception as exc:
        logger.warning("nightly_slack_post_failed", error=str(exc))
        return False


# ── the runner ───────────────────────────────────────────────────────────────

LicenceFetcher = Callable[[str], list[dict[str, Any]]]


class NightlyOpsRunner:
    def __init__(
        self,
        backend: ToolBackend,
        store: PlanStore,
        licence_fetcher: LicenceFetcher,
        manifest: Manifest | None = None,
    ) -> None:
        self.backend = backend
        self.store = store
        self.licence_fetcher = licence_fetcher
        self.manifest = manifest or load_manifest()

    def run(
        self,
        specs: list[TenantSpec],
        include_tier_assess: bool = True,
        slack_webhook: str = "",
    ) -> tuple[str, list[Finding]]:
        """Run the nightly sweep. Returns (digest path, ranked findings)."""
        ordered = sorted(specs, key=lambda s: (TIER_ORDER.get(s.tier, 9), s.label))
        results: list[TenantResult] = []
        findings: list[Finding] = []
        rows_by_tenant: dict[str, list[dict[str, Any]]] = {}

        for spec in ordered:
            engine = TemplateEngine(nightly_steps(spec, include_tier_assess))
            # No approver: the nightly template is read-only by construction,
            # and any drift into a write tool is denied, not executed.
            executor = StepExecutor(self.manifest, self.backend, approve_write=None)
            loop = PlannerLoop(self.manifest, engine, executor, self.store)
            plan = loop.run(
                goal=f"nightly scheduled-ops checks for {spec.label}",
                trigger_type=TriggerType.SCHEDULED,
                trigger_payload={"tenant": spec.label, "tier": spec.tier},
                tenant_scope=spec.tenant_id,
                persona="scheduled-ops",
            )
            result = TenantResult(spec=spec, plan=plan)
            for step in plan.steps:
                if step.status.value == "ok":
                    hits = extract_attention_lines(step.result_summary)
                    if hits:
                        result.attention[step.step_id] = hits
            results.append(result)

            try:
                rows = self.licence_fetcher(spec.tenant_id)
            except Exception as exc:
                logger.warning("nightly_licence_fetch_failed", tenant=spec.label, error=str(exc))
                rows = []
            rows_by_tenant[spec.label] = rows
            findings.extend(licence_findings(spec, rows))

        findings.extend(estate_findings(rows_by_tenant, {s.label: s for s in ordered}))
        ranked = rank_findings(findings)

        generated_at = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
        digest = render_digest(generated_at, results, ranked)
        stamp = time.strftime("%Y%m%d-%H%M", time.gmtime())
        path = self.store.plan_dir / f"nightly-{stamp}.md"
        self.store.plan_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(digest)
        logger.info("nightly_digest_written", path=str(path), findings=len(ranked))

        if slack_webhook:
            top = "\n".join(
                f"{_SEV_ICON.get(f.severity, '')} [{f.severity}] {f.tenant_label}: {f.title}"
                for f in ranked[:10]
            )
            post_slack(
                slack_webhook,
                f"*Nightly Ops Digest* — {len(ranked)} finding(s) "
                f"across {len(results)} tenant(s)\n{top or 'all clean'}\n"
                f"Full digest: {path}",
            )
        return str(path), ranked


# ── cron entrypoint ──────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    """`scm-planner-nightly` — run from cron/systemd. Read-only against tenants."""
    import argparse
    import os

    parser = argparse.ArgumentParser(description="Nightly scheduled-ops digest")
    parser.add_argument(
        "--tenants",
        default="",
        help="Comma-separated tenant labels to include (default: all configured)",
    )
    parser.add_argument(
        "--no-tier-assess",
        action="store_true",
        help="Skip the (slow) full tier assessment step",
    )
    parser.add_argument(
        "--slack-webhook",
        default=os.getenv("SCM_MCP_SLACK_WEBHOOK", ""),
        help="Slack incoming-webhook URL (or SCM_MCP_SLACK_WEBHOOK)",
    )
    args = parser.parse_args(argv)

    from mcp.server.fastmcp import FastMCP

    from ..auth.oauth import fetch_licenses, get_client_for_tenant, get_scm_client
    from ..config.settings import load_all_tenant_configs
    from ..server import register_all_tools
    from ..tools.ops import _licence_rows
    from .backend import InProcessBackend

    configs = load_all_tenant_configs()
    wanted = {t.strip().lower() for t in args.tenants.split(",") if t.strip()}
    specs: list[TenantSpec] = []
    for key, tc in configs.items():
        label = tc.label or key
        if wanted and label.lower() not in wanted and key.lower() not in wanted:
            continue
        try:
            get_scm_client(tc)  # preload; registry is keyed by TSG id
        except Exception as exc:
            logger.warning("nightly_tenant_auth_failed", tenant=label, error=str(exc))
            continue
        specs.append(
            TenantSpec(
                label=label,
                tenant_id=tc.tenant_id,
                tier=str(tc.tier),
                folder="Prisma Access",
            )
        )
    if not specs:
        print("No tenants available (auth failures or filter matched nothing).")
        return 1

    def get_client(tenant_id: str = "") -> Any:
        return get_client_for_tenant(tenant_id)

    mcp = FastMCP("planner-nightly")
    register_all_tools(mcp, get_client, lambda: None)

    def licence_fetcher(tenant_id: str) -> list[dict[str, Any]]:
        return _licence_rows(fetch_licenses(get_client_for_tenant(tenant_id)))

    runner = NightlyOpsRunner(
        backend=InProcessBackend(mcp),
        store=PlanStore(),
        licence_fetcher=licence_fetcher,
    )
    path, ranked = runner.run(
        specs,
        include_tier_assess=not args.no_tier_assess,
        slack_webhook=args.slack_webhook,
    )
    print(f"digest: {path}")
    print(f"findings: {len(ranked)}")
    for f in ranked[:10]:
        print(f"  [{f.severity}] {f.tenant_label}: {f.title}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
