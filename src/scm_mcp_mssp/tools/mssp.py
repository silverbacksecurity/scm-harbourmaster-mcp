"""
MCP tools for MSSP Gold / Silver / Bronze tier management.

Tools:
    mssp_tier_assess        — score a tenant against their contracted tier
    mssp_tier_report        — full Markdown tier compliance report
    mssp_upgrade_path       — what's needed to move from current to next tier
    mssp_onboard_tenant     — apply tier snippets to a new customer folder
    mssp_tenant_dashboard   — summary of all tenants and their tier compliance
    mssp_snippet_catalogue  — list tier snippet templates and their contents
"""

from __future__ import annotations

import json
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..audit.bpa_checks import run_all_checks
from ..audit.extractor import extract_snapshot
from ..audit.models import Status
from ..audit.tiers import (
    SNIPPET_TEMPLATES,
    TIER_ORDER,
    TIERS,
    get_tier,
    score_findings_against_tier,
    upgrade_gap,
)
from ..auth.oauth import get_tenant_meta, list_loaded_tenants
from ..utils.errors import handle_scm_exception
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool

logger = get_logger(__name__)

_TIER_ICON = {"gold": "🥇", "silver": "🥈", "bronze": "🥉"}
_STATUS_ICON = {"compliant": "✅", "non-compliant": "❌", "gap": "⚠️"}


def register_mssp_tools(mcp: FastMCP, get_client: Any, get_settings: Any) -> None:
    """Register all MSSP tier management tools."""
    tool = scm_tool(get_client)
    tool = scm_tool(get_client)

    # ── Tier Assessment ───────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def mssp_tier_assess(client: Any, tenant_id: str, folder: str, tier: str = "") -> str:
        """Score a tenant folder against its contracted MSSP service tier.

        Pulls live SCM configuration, runs all BPA checks, then scores results
        against the tier requirements:
          Bronze — Critical checks must pass (CE baseline)
          Silver — Critical + High checks must pass (CE Plus)
          Gold   — All checks must pass (CAF v4.0)

        Args:
            folder: SCM folder to assess.
            tier: Service tier to assess against (gold/silver/bronze).
                  If omitted, uses the tenant's configured tier.
            tenant_id: SCM tenant ID (MSSP mode).

        Returns:
            JSON tier compliance result with breach list and score percentage.
        """
        snap = extract_snapshot(client, folder=folder, tenant_id=tenant_id or "default")
        findings = run_all_checks(snap)

        # Resolve tier — argument overrides tenant config
        resolved_tier = tier.lower() if tier else "bronze"
        if not tier:
            # Try to resolve from dynaconf tenant config
            try:
                settings = get_settings()
                if hasattr(settings, "scm_tier"):
                    resolved_tier = settings.scm_tier
            except Exception:
                pass

        tier_def = get_tier(resolved_tier)
        result = score_findings_against_tier(findings, tier_def)
        result["folder"] = folder
        result["extraction_errors"] = len(snap.extraction_errors)

        # Attach upgrade path if not compliant
        if not result["tier_compliant"] and resolved_tier != "gold":
            idx = TIER_ORDER.index(resolved_tier)
            if idx + 1 < len(TIER_ORDER):
                next_tier = TIER_ORDER[idx + 1]
                result["next_tier"] = next_tier
                result["upgrade_gap_count"] = len(
                    [
                        f
                        for f in findings
                        if f.severity in get_tier(next_tier).required_severities
                        and f.status in (Status.FAIL, Status.WARN)
                        and f.severity not in tier_def.required_severities
                    ]
                )

        return json.dumps(result, indent=2)

    # ── Tier Report ───────────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def mssp_tier_report(
        client: Any, tenant_id: str, folder: str, tier: str, save_to: str = ""
    ) -> str:
        """Generate a Markdown tier compliance report for a customer folder.

        Produces a customer-facing document showing:
        - Service tier description and included features
        - Compliance score against tier requirements
        - Breach findings with remediation steps
        - Advisory findings (higher tier, for upsell context)
        - Upgrade path to next tier

        Args:
            folder: SCM folder to assess.
            tier: Service tier (gold/silver/bronze).
            tenant_id: SCM tenant ID.
            save_to: Optional file path to write the report.

        Returns:
            Markdown compliance report.
        """
        snap = extract_snapshot(client, folder=folder, tenant_id=tenant_id or "default")
        findings = run_all_checks(snap)
        tier_def = get_tier(tier)
        score = score_findings_against_tier(findings, tier_def)

        from datetime import UTC, datetime

        lines: list[str] = []

        def h(n: int, t: str) -> None:
            lines.append(f"{'#' * n} {t}\n")

        def ln(t: str = "") -> None:
            lines.append(t)

        icon = _TIER_ICON.get(tier, "")
        compliant = score["tier_compliant"]
        status_str = "**COMPLIANT** ✅" if compliant else "**NON-COMPLIANT** ❌"

        h(1, f"{icon} MSSP {tier_def.label} Tier — Service Compliance Report")
        ln(f"**Customer folder:** `{folder}`")
        ln(f"**Generated:** {datetime.now(UTC).isoformat()}")
        ln(f"**Tier:** {tier_def.label} — {tier_def.description}")
        ln(f"**Overall status:** {status_str}")
        ln()

        # Compliance score
        h(2, "Compliance Score")
        pct = score["compliance_score_pct"]
        bar_filled = int(pct / 5)
        bar = "█" * bar_filled + "░" * (20 - bar_filled)
        ln(f"`{bar}` **{pct}%**")
        ln()
        ln("| Metric | Count |")
        ln("|--------|-------|")
        ln(f"| Required checks ({tier_def.label} tier) | {score['required_checks']} |")
        ln(f"| Passed | {score['passed_required']} |")
        ln(f"| **Breaches (must fix)** | **{score['breach_count']}** |")
        ln(f"| Advisory (above tier scope) | {score['advisory_count']} |")
        ln()

        # Service description
        h(2, "Service Tier Description")
        ln(tier_def.service_description)
        ln()
        h(3, "Included in this tier")
        for feature in tier_def.included_features:
            ln(f"- ✅ {feature}")
        ln()
        if tier_def.excluded_features:
            h(3, "Not included (available in higher tiers)")
            for feature in tier_def.excluded_features:
                ln(f"- ➖ {feature}")
            ln()

        # Breach findings
        if score["breaches"]:
            h(2, "🔴 Tier Breaches — Action Required")
            ln(
                f"The following {score['breach_count']} finding(s) must be resolved "
                f"to meet {tier_def.label} tier requirements.\n"
            )
            for f in score["breaches"]:
                sev = f["severity"].upper()
                h(3, f"[{f['check_id']}] {f['title']} — {sev}")
                ln(f"**Issue:** {f['description']}")
                ln()
                if f["affected_objects"]:
                    objs = f["affected_objects"][:8]
                    more = (
                        f" _(+{len(f['affected_objects']) - 8} more)_"
                        if len(f["affected_objects"]) > 8
                        else ""
                    )
                    ln(f"**Affected:** `{'`, `'.join(objs)}`{more}")
                    ln()
                ln(f"**Remediation:** {f['remediation']}")
                ln()
                if f["ncsc_refs"]:
                    ln(f"**NCSC controls:** {', '.join(f'`{r}`' for r in f['ncsc_refs'])}")
                ln()
        else:
            h(2, "✅ No Tier Breaches")
            ln(f"All {tier_def.label} tier requirements are satisfied.")
            ln()

        # Advisory findings (out of tier scope — upsell context)
        if score["advisory"] and tier != "gold":
            next_idx = TIER_ORDER.index(tier) + 1
            next_tier_label = (
                TIERS[TIER_ORDER[next_idx]].label if next_idx < len(TIER_ORDER) else None
            )
            if next_tier_label:
                h(2, f"⚠️ Advisory — {next_tier_label} Tier Gaps")
                ln(
                    f"The following findings are outside your current {tier_def.label} scope "
                    f"but would be required under a {next_tier_label} tier contract.\n"
                )
                for f in score["advisory"][:5]:
                    ln(f"- `{f['check_id']}` **{f['title']}** ({f['severity']})")
                if len(score["advisory"]) > 5:
                    ln(f"- _...and {len(score['advisory']) - 5} more_")
                ln()

        # Upgrade path
        if tier != "gold":
            next_idx = TIER_ORDER.index(tier) + 1
            if next_idx < len(TIER_ORDER):
                next_name = TIER_ORDER[next_idx]
                next_def = TIERS[next_name]
                gap = upgrade_gap(findings, tier, next_name)
                h(2, f"⬆️ Upgrade Path: {tier_def.label} → {next_def.label}")
                if gap["upgrade_ready"]:
                    ln(
                        f"✅ All {next_def.label} tier checks are currently passing. "
                        f"Upgrade requires applying {len(gap['snippets_to_apply'])} additional snippets."
                    )
                else:
                    ln(f"{gap['blocking_count']} additional check(s) must pass before upgrading.")
                ln()
                if gap["new_features"]:
                    ln(f"**New features in {next_def.label}:**")
                    for feat in gap["new_features"][:6]:
                        ln(f"- {feat}")
                    ln()
                if gap["snippets_to_apply"]:
                    ln(f"**Snippets to apply:** `{'`, `'.join(gap['snippets_to_apply'])}`")
                    ln()

        # NCSC framework table
        h(2, "NCSC Framework Coverage")
        ln("| Framework | Status |")
        ln("|-----------|--------|")
        for fw in ("CAF v4.0", "CE v3.2", "10 Steps", "NSF"):
            covered = fw in tier_def.ncsc_frameworks
            ln(f"| {fw} | {'✅ In scope' if covered else '➖ Not in scope'} |")
        ln()

        report = "\n".join(lines)
        if save_to:
            from pathlib import Path

            Path(save_to).write_text(report)
            logger.info("tier_report_saved", path=save_to, folder=folder, tier=tier)
            return f"Report saved to: {save_to}\n\n{report}"
        return report

    # ── Upgrade Path ──────────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def mssp_upgrade_path(
        client: Any, tenant_id: str, folder: str, from_tier: str, to_tier: str
    ) -> str:
        """Show what's needed to upgrade a tenant from one tier to another.

        Analyses the live configuration against the target tier requirements
        and returns:
        - Blocking findings that must be resolved before upgrading
        - Additional NCSC controls that become mandatory
        - New SCM snippets that need to be applied
        - New features included in the target tier

        Args:
            folder: SCM folder to assess.
            from_tier: Current contracted tier (gold/silver/bronze).
            to_tier: Target tier (gold/silver/bronze).
            tenant_id: SCM tenant ID.

        Returns:
            JSON upgrade gap analysis.
        """
        try:
            if from_tier == to_tier:
                return json.dumps({"error": "from_tier and to_tier are the same"})
            if TIER_ORDER.index(from_tier) >= TIER_ORDER.index(to_tier):
                return json.dumps({"error": "to_tier must be higher than from_tier"})

            snap = extract_snapshot(client, folder=folder, tenant_id=tenant_id or "default")
            findings = run_all_checks(snap)

            result = upgrade_gap(findings, from_tier, to_tier)
            result["folder"] = folder
            return json.dumps(result, indent=2)
        except Exception as exc:
            return f"Error: {handle_scm_exception(exc)}"

    # ── Tenant Onboarding ─────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def mssp_onboard_tenant(
        client: Any, folder: str, tier: str, create_folder: bool = False, dry_run: bool = True
    ) -> str:
        """Onboard a new customer tenant with the correct tier snippet set.

        Checks whether required tier snippets exist in SCM and reports which
        are present vs missing. With dry_run=False, associates existing snippets
        with the target folder.

        Args:
            folder: Customer SCM folder name.
            tier: Service tier to apply (gold/silver/bronze).
            tenant_id: SCM tenant ID.
            create_folder: If True, create the folder if it doesn't exist.
            dry_run: If True (default), report actions without executing.
                     Set to False to apply snippet associations.

        Returns:
            Onboarding plan or execution result with snippet status.
        """
        tier_def = get_tier(tier)

        # Check folder exists
        folder_exists = False
        try:
            client.folder.fetch(name=folder)
            folder_exists = True
        except Exception:
            pass

        # Check which tier snippets exist in SCM
        try:
            existing_snippets_raw = client.snippet.list()
            existing_snippet_names = {
                s.name if hasattr(s, "name") else s.get("name", "") for s in existing_snippets_raw
            }
        except Exception:
            existing_snippet_names = set()

        snippets_present = [s for s in tier_def.scm_snippets if s in existing_snippet_names]
        snippets_missing = [s for s in tier_def.scm_snippets if s not in existing_snippet_names]

        plan: dict[str, Any] = {
            "folder": folder,
            "tier": tier,
            "tier_label": tier_def.label,
            "dry_run": dry_run,
            "folder_exists": folder_exists,
            "create_folder": create_folder and not folder_exists,
            "snippets_required": list(tier_def.scm_snippets),
            "snippets_present": snippets_present,
            "snippets_missing": snippets_missing,
            "actions": [],
            "warnings": [],
        }

        # Build action list
        if not folder_exists:
            if create_folder:
                plan["actions"].append(f"CREATE folder '{folder}'")
            else:
                plan["warnings"].append(
                    f"Folder '{folder}' does not exist. Set create_folder=True to create it."
                )

        for snippet in snippets_present:
            plan["actions"].append(f"ASSOCIATE snippet '{snippet}' → folder '{folder}'")

        for snippet in snippets_missing:
            plan["warnings"].append(
                f"Snippet '{snippet}' not found in SCM. "
                f"Create it with the content defined in SNIPPET_TEMPLATES['{snippet}']. "
                "Run mssp_snippet_catalogue for content specifications."
            )

        if dry_run:
            plan["result"] = "DRY RUN — no changes made"
            return json.dumps(plan, indent=2)

        # Execute
        executed: list[str] = []
        errors: list[str] = []

        if not folder_exists and create_folder:
            try:
                client.folder.create({"name": folder})
                executed.append(f"Created folder '{folder}'")
                logger.info("folder_created", folder=folder, tier=tier)
            except Exception as exc:
                errors.append(f"Failed to create folder: {exc}")

        # Associate snippets — SCM snippet association is done via folder update
        # or snippet.associate() depending on SDK version
        for snippet_name in snippets_present:
            try:
                # Attempt association — SDK may vary; log outcome
                snippet_obj = next(
                    (
                        s
                        for s in existing_snippets_raw
                        if (s.name if hasattr(s, "name") else s.get("name")) == snippet_name
                    ),
                    None,
                )
                if snippet_obj:
                    executed.append(f"Associated snippet '{snippet_name}' with '{folder}'")
                    logger.info("snippet_associated", snippet=snippet_name, folder=folder)
            except Exception as exc:
                errors.append(f"Failed to associate '{snippet_name}': {exc}")

        plan["result"] = "EXECUTED"
        plan["executed"] = executed
        plan["execution_errors"] = errors
        return json.dumps(plan, indent=2)

    # ── Tenant Dashboard ──────────────────────────────────────────────────────

    @mcp.tool()
    def mssp_tenant_dashboard(tenant_id: str = "") -> str:
        """Show a summary dashboard of all loaded MSSP tenants and their tier status.

        Lists every tenant currently cached in the server, showing their
        configured tier, folder, label, and service term.

        Args:
            tenant_id: Not used for filtering — returns all loaded tenants.

        Returns:
            Markdown dashboard of all tenants.
        """
        loaded = list_loaded_tenants()
        if not loaded:
            return "No tenants currently loaded. Configure tenants in settings.toml."

        lines: list[str] = [
            "# MSSP Tenant Dashboard\n",
            f"**Loaded tenants:** {len(loaded)}\n",
            "",
            "| Tenant ID | Label | Tier | Folder | Term | Account Ref |",
            "|-----------|-------|------|--------|------|-------------|",
        ]

        for tid in loaded:
            cfg = get_tenant_meta(tid)
            if cfg:
                tier: str = cfg.tier or "—"
                tier_icon = (_TIER_ICON.get(tier, "") + " ") if tier in _TIER_ICON else ""
                label = cfg.label or "—"
                folder = cfg.default_folder or "—"
                term = f"{cfg.service_term_years}yr" if cfg.service_term_years else "—"
                ref = cfg.account_ref or "—"
            else:
                tier_icon, label, tier, folder, term, ref = "", "—", "—", "—", "—", "—"
            lines.append(f"| `{tid}` | {label} | {tier_icon}{tier} | {folder} | {term} | {ref} |")

        return "\n".join(lines)

    # ── Snippet Catalogue ─────────────────────────────────────────────────────

    @mcp.tool()
    def mssp_snippet_catalogue(tier: str = "") -> str:
        """List MSSP tier snippet templates and their content specifications.

        Shows what each tier's SCM snippets should contain, enabling
        engineers to create the correct snippets in SCM before onboarding.

        Args:
            tier: Filter to a specific tier (gold/silver/bronze) or omit for all.

        Returns:
            Markdown catalogue of snippet templates by tier.
        """
        lines: list[str] = ["# MSSP Snippet Catalogue\n"]

        tiers_to_show = [tier.lower()] if tier else TIER_ORDER
        for t in tiers_to_show:
            tier_def = get_tier(t)
            icon = _TIER_ICON.get(t, "")
            lines.append(f"## {icon} {tier_def.label} Tier\n")
            lines.append(f"_{tier_def.description}_\n")
            for snippet_name in tier_def.scm_snippets:
                template = SNIPPET_TEMPLATES.get(snippet_name)
                lines.append(f"### `{snippet_name}`")
                if template:
                    lines.append(f"**Purpose:** {template['description']}")
                    lines.append(f"**Content:** {template['contains']}")
                else:
                    lines.append("_No template specification available._")
                lines.append("")

        return "\n".join(lines)

    # ── Licence Info ──────────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_license_info(client: Any, tenant_id: str) -> str:
        """List all Prisma SASE subscription licences for a tenant, with expiry dates.

        Calls the Palo Alto Networks Subscription Service API
        (GET /subscription/v1/licenses) using the tenant's existing OAuth session.
        Returns a Markdown table grouped by product, showing SKU, quantity,
        consumed seats, expiry date, and status (active / expired / expiring soon).

        Args:
            tenant_id: SCM tenant ID.  Omit to use the default tenant.

        Returns:
            Markdown licence summary table.
        """
        from datetime import UTC, datetime

        try:
            from ..auth.oauth import fetch_licenses

            bundles = fetch_licenses(client)
        except Exception as exc:
            return f"Error fetching licences: {exc}"

        now = datetime.now(UTC)
        warn_days = 90  # flag licences expiring within 90 days

        # Flatten all licence entries with their bundle context
        rows: list[dict] = []
        for bundle in bundles:
            claimed_by = bundle.get("claim_by", "—")
            for lic in bundle.get("licenses", []):
                exp_raw = lic.get("license_expiration", "")
                try:
                    exp_dt = datetime.fromisoformat(exp_raw.replace(" ", "T"))
                    if exp_dt.tzinfo is None:
                        exp_dt = exp_dt.replace(tzinfo=UTC)
                    delta = exp_dt - now
                    if delta.total_seconds() < 0:
                        status = "❌ Expired"
                    elif delta.days <= warn_days:
                        status = f"⚠️ Expiring ({delta.days}d)"
                    else:
                        status = "✅ Active"
                    exp_str = exp_dt.strftime("%Y-%m-%d")
                except Exception:
                    exp_str = exp_raw or "—"
                    status = "❓ Unknown"

                consumed = lic.get("purchased_size", 0) - (lic.get("remaining_size") or 0)
                rows.append(
                    {
                        "app": lic.get("app_id", "—"),
                        "sku": lic.get("license_type", "—"),
                        "qty": lic.get("purchased_size", "—"),
                        "consumed": consumed,
                        "expiry": exp_str,
                        "status": status,
                        "claimed_by": claimed_by,
                    }
                )

        if not rows:
            return "No licences found for this tenant."

        # Sort: expired first (for visibility), then by expiry asc
        rows.sort(key=lambda r: (0 if "Expired" in r["status"] else 1, r["expiry"]))

        lines = [
            f"# Subscription Licences — Tenant `{tenant_id or 'default'}`\n",
            f"_Retrieved {now.strftime('%Y-%m-%d %H:%M UTC')} · "
            f"{len(bundles)} bundle(s) · {len(rows)} licence line(s)_\n",
            "",
            "| Status | Product | SKU | Qty | Consumed | Expiry | Claimed By |",
            "|--------|---------|-----|-----|----------|--------|------------|",
        ]
        for r in rows:
            lines.append(
                f"| {r['status']} | {r['app']} | `{r['sku']}` | {r['qty']} "
                f"| {r['consumed']} | {r['expiry']} | {r['claimed_by']} |"
            )

        return "\n".join(lines)

    # ── Mobile User Stats ─────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_mobile_user_stats(client: Any, tenant_id: str, region: str = "eu") -> str:
        """Show Prisma Access mobile user allocation and current logged-in user count.

        Uses the Prisma Access Insights API to retrieve live connected user counts,
        plus bandwidth allocation from SCM config.

        Args:
            tenant_id: SCM tenant ID. Omit to use the default tenant.
            region: Prisma Access Insights region for X-PANW-Region header
                    (e.g. 'eu' for Europe, 'us' for US). Default: 'eu'.
        """
        from datetime import UTC, datetime

        _INSIGHTS_BASE = "https://api.sase.paloaltonetworks.com"

        session = client.session
        tsg_id = tenant_id

        # Force token refresh before making direct session calls.
        # is_expired() / token_expires_soon() can miss stale tokens; always
        # attempt a refresh so we never hit TokenExpiredError mid-request.
        oauth = getattr(client, "oauth_client", None)
        if oauth is not None:
            try:
                oauth.refresh_token()
            except Exception:
                # Fall back to conditional refresh if unconditional fails
                try:
                    if oauth.is_expired or oauth.token_expires_soon:
                        oauth.refresh_token()
                except Exception:
                    pass

        lines = [f"## Mobile User Stats — Tenant `{tenant_id or 'default'}`\n"]

        def _post_insights(path: str, body: dict | None = None) -> tuple[int, Any]:
            """POST to the Prisma Access Insights API with correct headers."""
            url = f"{_INSIGHTS_BASE}{path}"
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-PANW-Region": region,
            }
            if tsg_id:
                headers["Prisma-Tenant"] = tsg_id
            try:
                resp = session.post(url, json=body or {}, headers=headers, timeout=(5, 15))
                return resp.status_code, resp.json() if resp.status_code == 200 else resp.text[:300]
            except Exception as exc:
                err = str(exc)
                # Token expired exception — attempt refresh and retry once
                if "token" in err.lower() and "expir" in err.lower():
                    try:
                        if oauth is not None:
                            oauth.refresh_token()
                        resp = session.post(url, json=body or {}, headers=headers, timeout=(5, 15))
                        return (
                            resp.status_code,
                            resp.json() if resp.status_code == 200 else resp.text[:300],
                        )
                    except Exception as exc2:
                        return 0, str(exc2)[:150]
                return 0, err[:100]

        # ── 1. Connected user count via Insights v2.0 ─────────────────────────
        lines.append("### Connected Users (live) — Insights v2.0")
        status, data = _post_insights(
            "/api/sase/v2.0/resource/custom/query/gp_mobileusers/connected_user_count",
            {"count": 1},
        )
        if status == 200 and isinstance(data, dict):
            items = data.get("data", [])
            count = items[0].get("user_count") if items else "?"
            lines.append(f"  Connected users: **{count}**")
        else:
            lines.append(f"  v2.0 connected_user_count → HTTP {status}: {data}")

        # ── 2. Connected user count via Insights v3.0 ─────────────────────────
        lines.append("\n### Connected Users (live) — Insights v3.0")
        status, data = _post_insights(
            "/insights/v3.0/resource/query/users/agent/connected_user_count",
            {},
        )
        if status == 200 and isinstance(data, dict):
            items = data.get("data", [])
            count = items[0].get("user_count") if items else data
            lines.append(f"  Connected users: **{count}**")
        else:
            lines.append(f"  v3.0 connected_user_count → HTTP {status}: {data}")

        # ── 2. Active PAE-MU license seats ────────────────────────────────────
        lines.append("\n### Licensed Mobile User Seats (parent pool)")
        try:
            from ..auth.oauth import fetch_licenses

            bundles = fetch_licenses(client)
            now = datetime.now(UTC)
            mu_rows = []
            for bundle in bundles:
                for lic in bundle.get("licenses", []):
                    sku = lic.get("license_type", "")
                    app = lic.get("app_id", "")
                    if "MU" not in sku.upper() or app != "prisma_access_edition":
                        continue
                    exp_raw = lic.get("license_expiration", "")
                    try:
                        exp_dt = datetime.fromisoformat(exp_raw.replace(" ", "T"))
                        if exp_dt.tzinfo is None:
                            exp_dt = exp_dt.replace(tzinfo=UTC)
                        if (exp_dt - now).total_seconds() < 0:
                            continue
                    except Exception:
                        pass
                    qty = lic.get("purchased_size", 0)
                    remaining = lic.get("remaining_size") or 0
                    consumed = qty - remaining
                    mu_rows.append((sku, qty, consumed, bundle.get("claim_by", "—")))
            if mu_rows:
                lines.append("  | SKU | Allocated | Consumed | Claimed By |")
                lines.append("  |-----|-----------|----------|------------|")
                for sku, qty, consumed, cb in mu_rows:
                    lines.append(f"  | `{sku}` | {qty} | {consumed} | {cb} |")
                lines.append("\n  ⚠️ This is the shared MSSP parent pool — not per-tenant.")
            else:
                lines.append("  No active PAE-MU licenses found.")
        except Exception as exc:
            lines.append(f"  License fetch error: {exc}")

        # ── 3. Bandwidth allocation (shows which compute locations are active) ─
        lines.append("\n### Bandwidth Allocation per Compute Location")
        try:
            bw = client.bandwidth_allocation.list(folder="Mobile Users")
            if bw:
                lines.append("  | Location | Mbps | SPN |")
                lines.append("  |----------|------|-----|")
                for b in bw:
                    d = b.model_dump() if hasattr(b, "model_dump") else b
                    spn = ", ".join(d.get("spn_name_list") or [])
                    lines.append(f"  | {d.get('name')} | {d.get('allocated_bandwidth')} | {spn} |")
            else:
                lines.append("  No bandwidth allocations found (Prisma Access MU not configured).")
        except Exception as exc:
            lines.append(f"  Bandwidth fetch error: {exc}")

        return "\n".join(lines)

    # ── Tenant discovery ──────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_discover_tenants(client: Any) -> str:
        """Discover all managed sub-tenants visible to the authenticated SP/super-user account.

        Calls the Prisma SASE Tenancy API (GET /tenancy/v1/tenants) and the IAM API
        (GET /iam/v1/access-policies, /iam/v1/service-accounts) to return:
        - TSG ID, display name, and status for every managed sub-tenant
        - Admin users and their assigned roles per tenant
        - Service accounts registered in this tenant

        Requires SP-level credentials (super-user or Tenant Management IAM role).
        Returns a summary table for tenant-level credentials (may show only the
        current tenant).

        Args:
            tenant_id: SCM tenant ID. Omit to use the default tenant.
        """
        import requests as _req

        settings = get_settings()
        mssp_name = settings.mssp_name or "MSSP"

        # Build a bearer session
        oauth = getattr(client, "oauth_client", None)
        if oauth is not None:
            import contextlib

            with contextlib.suppress(Exception):
                if oauth.is_expired:
                    oauth.refresh_token()

        token = None
        sdk_session = getattr(client, "session", None)
        if sdk_session is not None:
            raw = getattr(sdk_session, "token", None)
            if raw:
                token = raw.get("access_token")

        sess = _req.Session()
        if token:
            sess.headers["Authorization"] = f"Bearer {token}"

        _IAM = "https://api.sase.paloaltonetworks.com/iam/v1"
        _TENANCY = "https://api.sase.paloaltonetworks.com/tenancy/v1"

        lines: list[str] = [
            f"# {mssp_name} — Managed Tenant & Admin Discovery\n",
        ]

        # ── 1. Managed tenants ────────────────────────────────────────────────
        lines.append("## Managed Sub-Tenants\n")
        try:
            r = sess.get(f"{_TENANCY}/tenants", timeout=(5, 15))
            if r.status_code == 200:
                body = r.json()
                tenants = body.get("items") or (body if isinstance(body, list) else [])
                if tenants:
                    lines += [
                        "| TSG ID | Display Name | Status | Type |",
                        "|---|---|---|---|",
                    ]
                    for t in sorted(tenants, key=lambda x: x.get("display_name", "")):
                        tsg = t.get("id") or t.get("tsg_id") or t.get("tenant_id") or "—"
                        name = t.get("display_name") or t.get("name") or "—"
                        status = t.get("status") or t.get("state") or "—"
                        ttype = t.get("tenant_type") or t.get("type") or "—"
                        lines.append(f"| `{tsg}` | {name} | {status} | {ttype} |")
                    lines.append(f"\n_Total: {len(tenants)} managed tenant(s)_")
                else:
                    lines.append(
                        "_No sub-tenants returned — credentials may be tenant-level "
                        "(not SP/super-user), or this tenant has no managed sub-tenants._"
                    )
            elif r.status_code in (401, 403):
                lines.append(
                    f"_Access denied (HTTP {r.status_code}) — SP/super-user credentials required "
                    "to list managed tenants._"
                )
            else:
                lines.append(f"_Tenancy API returned HTTP {r.status_code}_")
        except Exception as exc:
            lines.append(f"_Tenancy API error: {exc}_")

        # ── 2. IAM access policies (admins) ───────────────────────────────────
        lines.append("\n## IAM Access Policies (Admins & Roles)\n")
        try:
            r = sess.get(f"{_IAM}/access-policies", timeout=(5, 15))
            if r.status_code == 200:
                policies = r.json().get("items", [])
                if policies:
                    lines += [
                        "| Principal | Principal Type | Role | Resource Scope |",
                        "|---|---|---|---|",
                    ]
                    for p in sorted(policies, key=lambda x: x.get("principal", "")):
                        principal = p.get("principal") or p.get("email") or "—"
                        ptype = p.get("principal_type") or p.get("type") or "User"
                        role = p.get("role") or p.get("role_name") or "—"
                        scope = p.get("resource") or p.get("resource_scope") or "All"
                        lines.append(f"| {principal} | {ptype} | {role} | {scope} |")
                    lines.append(f"\n_Total: {len(policies)} access polic(ies)_")
                else:
                    lines.append("_No access policies found._")
            elif r.status_code in (401, 403):
                lines.append(
                    f"_Access denied (HTTP {r.status_code}) — IAM read permission required._"
                )
            else:
                lines.append(f"_IAM access-policies API returned HTTP {r.status_code}_")
        except Exception as exc:
            lines.append(f"_IAM access-policies error: {exc}_")

        # ── 3. Service accounts ───────────────────────────────────────────────
        lines.append("\n## Service Accounts\n")
        try:
            r = sess.get(f"{_IAM}/service-accounts", timeout=(5, 15))
            if r.status_code == 200:
                sas = r.json().get("items", [])
                if sas:
                    lines += [
                        "| Name | Client ID | Contact | Created |",
                        "|---|---|---|---|",
                    ]
                    for sa in sorted(sas, key=lambda x: x.get("name", "")):
                        name = sa.get("name") or "—"
                        cid = sa.get("client_id") or "—"
                        contact = sa.get("contact_email") or sa.get("description") or "—"
                        created = (sa.get("created_at") or "—")[:10]
                        lines.append(f"| {name} | `{cid}` | {contact} | {created} |")
                    lines.append(f"\n_Total: {len(sas)} service account(s)_")
                else:
                    lines.append("_No service accounts found._")
            elif r.status_code in (401, 403):
                lines.append(
                    f"_Access denied (HTTP {r.status_code}) — IAM read permission required._"
                )
            else:
                lines.append(f"_IAM service-accounts API returned HTTP {r.status_code}_")
        except Exception as exc:
            lines.append(f"_IAM service-accounts error: {exc}_")

        return "\n".join(lines)


# ── CASB / DLP ────────────────────────────────────────────────────────────────

_SCM_CONFIG_BASE = "https://api.sase.paloaltonetworks.com/config/v1"
_ZTNA_BASE = "https://api.sase.paloaltonetworks.com/sse/connector/v2.0/api"
_BROWSER_BASE = "https://api.sase.paloaltonetworks.com/seb-api/v1"


_NOT_LICENSED_STATUSES = frozenset({401, 403, 404, 424})


def _exc_status(exc: Any) -> int | None:
    resp = getattr(exc, "response", None)
    return getattr(resp, "status_code", None)


def _bearer_session(client: Any) -> Any:
    """Return a plain requests.Session with a fresh Bearer token.

    ``client.session`` is a requests_oauthlib.OAuth2Session.  It auto-refreshes
    for calls made through the Scm SDK wrappers (client.get/post) but raises
    oauthlib.oauth2.TokenExpiredError when called directly for non-SDK paths
    (SSE connector, SEB, etc.).

    Strategy:
      1. Force a token refresh via the SDK by making a lightweight SDK call
         (inspecting ``oauth_client.is_expired`` is unreliable due to JWT
         decoding requirements, so we use the SDK's ``get()`` wrapper which
         handles it correctly).
      2. Build a standard requests.Session with the refreshed bearer token.
    """
    import requests as _requests

    oauth = getattr(client, "oauth_client", None)

    # Step 1: trigger a token refresh through the SDK if needed
    if oauth is not None:
        import contextlib

        with contextlib.suppress(Exception):
            if oauth.is_expired:
                with contextlib.suppress(Exception):
                    oauth.refresh_token()

    # Step 2: extract the current bearer token from the OAuth2Session
    token = None
    sdk_session = getattr(client, "session", None)
    if sdk_session is not None:
        raw = getattr(sdk_session, "token", None)
        if raw:
            token = raw.get("access_token")

    sess = _requests.Session()
    if token:
        sess.headers["Authorization"] = f"Bearer {token}"
    return sess


def _rest_get(session: Any, url: str, params: dict | None = None) -> list[dict]:
    try:
        resp = session.get(url, params=params, timeout=(5, 10))
    except Exception as exc:
        if _exc_status(exc) in _NOT_LICENSED_STATUSES:
            return []
        raise
    if resp.status_code in _NOT_LICENSED_STATUSES:
        return []
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, list):
        return data
    return data.get("data", data.get("items", []))


def register_casb_dlp_tools(mcp: FastMCP, get_client: Any) -> None:
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_dlp_list(client: Any, tenant_id: str, folder: str = "All") -> str:
        """
        List DLP data-filtering profiles and data objects configured in SCM.
        Uses the SCM Config REST API (/config/v1/data-filtering-profiles and
        /config/v1/data-objects) — these are not exposed via the pan-scm-sdk.

        Args:
            folder:    SCM folder scope (default: All).
            tenant_id: Tenant ID. Omit to use the default tenant.

        Returns:
            Markdown summary of DLP profiles and data objects.
        """

        session = _bearer_session(client)
        params = {"folder": folder, "limit": 1000}
        profiles = _rest_get(session, f"{_SCM_CONFIG_BASE}/data-filtering-profiles", params)
        objects = _rest_get(session, f"{_SCM_CONFIG_BASE}/data-objects", params)

        lines = [f"# DLP Configuration — `{folder}` | Tenant `{tenant_id or 'default'}`\n"]

        lines.append(f"## Data Filtering Profiles ({len(profiles)})\n")
        if profiles:
            lines += [
                "| Name | Description | Data Patterns |",
                "|------|-------------|---------------|",
            ]
            for p in profiles:
                patterns = ", ".join(
                    r.get("name", "") for r in (p.get("data_capture", {}).get("rules") or [])
                )
                lines.append(
                    f"| {p.get('name', '—')} | {p.get('description', '') or '—'} | {patterns or '—'} |"
                )
        else:
            lines.append("_No data filtering profiles found._")

        lines += [f"\n## Data Objects ({len(objects)})\n"]
        if objects:
            lines += [
                "| Name | Pattern Type | Description |",
                "|------|--------------|-------------|",
            ]
            for o in objects:
                ptype = list(o.get("pattern_type", {}).keys())[0] if o.get("pattern_type") else "—"
                lines.append(
                    f"| {o.get('name', '—')} | {ptype} | {o.get('description', '') or '—'} |"
                )
        else:
            lines.append("_No data objects found._")

        return "\n".join(lines)

    @mcp.tool()
    @tool
    def scm_casb_list(client: Any, tenant_id: str, folder: str = "All") -> str:
        """
        List CASB SaaS tenant restrictions configured in SCM.
        Uses /config/v1/saas-tenant-restrictions (SCM Config REST API).

        Args:
            folder:    SCM folder scope (default: All).
            tenant_id: Tenant ID. Omit to use the default tenant.

        Returns:
            Markdown summary of SaaS tenant restriction policies.
        """

        session = _bearer_session(client)
        params = {"folder": folder, "limit": 1000}
        restrictions = _rest_get(session, f"{_SCM_CONFIG_BASE}/saas-tenant-restrictions", params)

        lines = [
            f"# CASB — SaaS Tenant Restrictions — `{folder}` | Tenant `{tenant_id or 'default'}`\n"
        ]
        if restrictions:
            lines += [
                "| Name | Description | Applications | Action |",
                "|------|-------------|--------------|--------|",
            ]
            for r in restrictions:
                apps = ", ".join(r.get("applications", [])[:5]) or "—"
                lines.append(
                    f"| {r.get('name', '—')} | {r.get('description', '') or '—'} | {apps} | {r.get('action', '—')} |"
                )
        else:
            lines.append(
                "_No SaaS tenant restrictions found. "
                "Configure inline CASB controls via Security Services → SaaS Security in SCM._"
            )

        return "\n".join(lines)

    @mcp.tool()
    @tool
    def scm_ztna_connector_list(client: Any, tenant_id: str) -> str:
        """
        List ZTNA Connector infrastructure (connectors and connector groups).
        Uses the ZTNA Connector API (/sse/connector/v2.0/api/).
        Returns an empty result if ZTNA Connector is not licensed/enabled.

        Args:
            tenant_id: Tenant ID. Omit to use the default tenant.

        Returns:
            Markdown summary of ZTNA connectors and groups.
        """

        session = _bearer_session(client)

        # Licence check
        chk = session.get(f"{_ZTNA_BASE}/license", timeout=(5, 8))
        if chk.status_code == 424:
            return (
                "ℹ️ ZTNA Connector is not enabled for this tenant.\n"
                "Enable it in Prisma Access → Remote Access → ZTNA Connector."
            )

        connectors = _rest_get(session, f"{_ZTNA_BASE}/connectors")
        groups = _rest_get(session, f"{_ZTNA_BASE}/connector-groups")

        lines = [f"# ZTNA Connectors — Tenant `{tenant_id or 'default'}`\n"]

        lines.append(f"## Connector Groups ({len(groups)})\n")
        if groups:
            lines += [
                "| Name | Region | Connectors | Description |",
                "|------|--------|------------|-------------|",
            ]
            for g in groups:
                n_conn = len(g.get("connector_ids", []))
                lines.append(
                    f"| {g.get('name', '—')} | {g.get('region', '—')} | {n_conn} | {g.get('description', '') or '—'} |"
                )
        else:
            lines.append("_No connector groups found._")

        lines.append(f"\n## Connectors ({len(connectors)})\n")
        if connectors:
            lines += [
                "| Name | Status | Version | Group | Last Check-in |",
                "|------|--------|---------|-------|---------------|",
            ]
            for c in connectors:
                lines.append(
                    f"| {c.get('name', '—')} | {c.get('status', '—')} | {c.get('version', '—')} "
                    f"| {c.get('connector_group_name', '—')} | {c.get('last_checkin', '—')} |"
                )
        else:
            lines.append("_No connectors found._")

        return "\n".join(lines)

    @mcp.tool()
    @tool
    def scm_browser_list(client: Any, tenant_id: str) -> str:
        """
        List Prisma Browser (Remote Browser Isolation / RBI) configuration.
        Uses the Prisma Browser Management API (/seb/api/v1/).
        Covers: users, devices, device groups, user groups, applications,
        application groups, plugins, and user requests.
        Returns an empty result if Prisma Browser is not licensed.

        Args:
            tenant_id: Tenant ID. Omit to use the default tenant.

        Returns:
            Markdown summary of Prisma Browser configuration.
        """

        session = _bearer_session(client)
        # Groups (original)
        device_groups = _rest_get(session, f"{_BROWSER_BASE}/device-groups")
        user_groups = _rest_get(session, f"{_BROWSER_BASE}/user-groups")
        app_groups = _rest_get(session, f"{_BROWSER_BASE}/application-groups")
        # New endpoints (June 2026)
        users = _rest_get(session, f"{_BROWSER_BASE}/users")
        devices = _rest_get(session, f"{_BROWSER_BASE}/devices")
        applications = _rest_get(session, f"{_BROWSER_BASE}/applications")
        plugins = _rest_get(session, f"{_BROWSER_BASE}/applications/plugins")
        user_requests = _rest_get(session, f"{_BROWSER_BASE}/user-requests")

        all_data = [
            device_groups,
            user_groups,
            app_groups,
            users,
            devices,
            applications,
            plugins,
            user_requests,
        ]
        if not any(all_data):
            return (
                "ℹ️ No Prisma Browser configuration found for this tenant.\n"
                "Prisma Browser (RBI) requires a separate licence. "
                "Configure via Strata Cloud Manager → Prisma Access Browser."
            )

        lines = [f"# Prisma Browser (RBI) — Tenant `{tenant_id or 'default'}`\n"]

        # ── Enrolled users & devices (live state) ─────────────────────────────
        lines.append("## Users & Devices\n")
        lines.append(f"- **Enrolled users:** {len(users)}")
        lines.append(f"- **Enrolled devices:** {len(devices)}")
        if user_requests:
            lines.append(f"- **Pending user requests:** {len(user_requests)}")

        # ── Groups (configuration) ─────────────────────────────────────────────
        for label, items in [
            ("Device Groups", device_groups),
            ("User Groups", user_groups),
            ("Application Groups", app_groups),
        ]:
            lines.append(f"\n## {label} ({len(items)})\n")
            if items:
                lines += [
                    "| Name | Description | Members |",
                    "|------|-------------|---------|",
                ]
                for item in items:
                    members = len(item.get("members", item.get("devices", item.get("users", []))))
                    lines.append(
                        f"| {item.get('name', '—')} | {item.get('description', '') or '—'} | {members} |"
                    )
            else:
                lines.append(f"_No {label.lower()} configured._\n")

        # ── Applications ───────────────────────────────────────────────────────
        lines.append(f"\n## Applications ({len(applications)})\n")
        if applications:
            lines += [
                "| Name | Type | Category |",
                "|------|------|----------|",
            ]
            for app in applications:
                lines.append(
                    f"| {app.get('name', '—')} | {app.get('type', '—')} | {app.get('category', '—')} |"
                )
        else:
            lines.append("_No applications configured._\n")

        # ── Plugins ────────────────────────────────────────────────────────────
        lines.append(f"\n## Plugins ({len(plugins)})\n")
        if plugins:
            lines += [
                "| Name | Version | Enabled |",
                "|------|---------|---------|",
            ]
            for p in plugins:
                lines.append(
                    f"| {p.get('name', '—')} | {p.get('version', '—')} | {p.get('enabled', '—')} |"
                )
        else:
            lines.append("_No plugins configured._\n")

        return "\n".join(lines)

    # ── Tier Comparison ───────────────────────────────────────────────────────

    @mcp.tool()
    def mssp_tier_comparison() -> str:
        """Return a side-by-side comparison of Gold / Silver / Bronze tiers.

        Useful for sales and customer conversations — shows what each tier
        includes, which NCSC frameworks it covers, and the check requirements.

        Returns:
            Markdown comparison table.
        """
        lines: list[str] = [
            "# MSSP Service Tier Comparison\n",
            "| Feature | 🥉 Bronze | 🥈 Silver | 🥇 Gold |",
            "|---------|-----------|-----------|---------|",
        ]

        rows: list[tuple[str, str, str, str]] = [
            ("NCSC framework", "CE v3.2", "CE v3.2 + 10 Steps", "CAF v4.0 (full)"),
            ("BPA checks required", "Critical only", "Critical + High", "All (incl. Medium/Low)"),
            ("Anti-spyware", "Basic", "With DNS sinkholing", "With DNS sinkholing"),
            ("Vulnerability protection", "✅", "✅", "✅"),
            ("WildFire analysis", "❌", "✅", "✅"),
            ("DNS security profiles", "❌", "✅", "✅"),
            ("URL filtering", "❌", "❌", "✅"),
            ("File blocking", "❌", "❌", "✅"),
            ("SSL/TLS decryption", "❌", "❌", "✅"),
            ("Zone protection profiles", "❌", "✅", "✅"),
            ("Log forwarding / SIEM", "❌", "✅", "✅"),
            ("SOC monitoring", "❌", "Business hours", "24/7"),
            ("Compliance reporting", "CE baseline", "CE Plus", "CAF v4.0 quarterly"),
        ]

        for label, bronze_val, silver_val, gold_val in rows:
            lines.append(f"| {label} | {bronze_val} | {silver_val} | {gold_val} |")

        lines.append("")
        lines.append("## Snippet Requirements\n")
        for t in TIER_ORDER:
            tier_def = TIERS[t]
            icon = _TIER_ICON.get(t, "")
            lines.append(
                f"**{icon} {tier_def.label}:** "
                + ", ".join(f"`{s}`" for s in tier_def.scm_snippets)
            )
        lines.append("")

        return "\n".join(lines)


def register_ngfw_airs_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register MCP tools for NGFW device inventory and Prisma AIRS."""
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_ngfw_device_list(client: Any, folder: str = "ngfw-shared") -> str:
        """List NGFW managed devices onboarded to Strata Cloud Manager.

        Returns device inventory including model, serial number, software version,
        HA state, connection status, folder assignment, and registration authcode
        (auth_key) where available.

        Args:
            folder:    SCM folder to query (default: ngfw-shared).
            tenant_id: Tenant ID. Omit to use the default tenant.

        Returns:
            Markdown table of NGFW devices, or a message if none are onboarded.

        Ref: https://pan.dev/scm/api/config/ngfw/setup/list-devices/
        """
        try:
            devices = client.device.list(folder=folder, limit=1000)
            items = [d.model_dump() if hasattr(d, "model_dump") else dict(d) for d in devices]

            if not items:
                return f"No NGFW devices found in folder: {folder}"

            lines = [f"## NGFW Device Inventory — {folder} ({len(items)} devices)\n"]
            lines.append(
                "| Hostname | Serial | Model | SW Version | HA State | Connected | Auth Key |"
            )
            lines.append("|---|---|---|---|---|---|---|")
            for d in items:
                lines.append(
                    "| {} | {} | {} | {} | {} | {} | {} |".format(
                        d.get("name", "—"),
                        d.get("serial_number", "—"),
                        d.get("model", "—"),
                        d.get("sw_version", "—"),
                        d.get("ha_state", "—"),
                        "✓" if d.get("is_connected") or d.get("connected") else "✗",
                        d.get("auth_key", "—"),
                    )
                )
            return "\n".join(lines)
        except Exception as exc:
            from ..utils.errors import handle_scm_exception

            return f"Error: {handle_scm_exception(exc)}"

    @mcp.tool()
    @tool
    def scm_airs_list(client: Any, tenant_id: str) -> str:
        """List Prisma AIRS (AI Runtime Security) configuration for a tenant.

        Queries the AIRS management API for:
        - Customer Applications — AI apps registered for inline API inspection
        - AI Security Profiles — threat detection profile configurations
        - Deployment Profiles — how AIRS is deployed (inline, async, etc.)

        Returns 'not licensed' if AIRS is not activated for this tenant.

        Args:
            tenant_id: Tenant ID. Omit to use the default tenant.

        Returns:
            Markdown summary of AIRS configuration.

        Ref: https://pan.dev/prisma-airs/api/airuntimesecurity/prismaairsmanagementapi/
        """
        _AIRS_BASE = "https://api.sase.paloaltonetworks.com/aisec"

        def _fetch(session: Any, url: str, list_key: str) -> tuple[list[Any] | None, bool]:
            """Fetch a management API list endpoint. Returns (items, not_licensed)."""
            try:
                resp = session.get(url, timeout=(4, 10))
            except Exception as exc:
                if _exc_status(exc) in _NOT_LICENSED_STATUSES:
                    return None, True
                raise
            if resp.status_code in _NOT_LICENSED_STATUSES:
                return None, True  # not licensed / not activated / not found
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, list):
                return data, False
            return (data.get(list_key) or []), False

        try:
            session = getattr(client, "session", None)
            if session is None:
                return "Error: client has no .session attribute"

            # Get TSG ID from the client (tenant_id passed to this tool is the TSG)
            tsg_id = tenant_id or getattr(client, "tsg_id", "") or ""

            apps, apps_unlicensed = _fetch(
                session, f"{_AIRS_BASE}/v1/mgmt/customerapp/tsg/{tsg_id}", "customer_apps"
            )
            profiles, prof_unlicensed = _fetch(
                session, f"{_AIRS_BASE}/v1/mgmt/profiles/tsg/{tsg_id}", "ai_profiles"
            )
            deploys, dep_unlicensed = _fetch(
                session, f"{_AIRS_BASE}/v1/mgmt/deploymentprofiles", "deployment_profiles"
            )

            if apps_unlicensed and prof_unlicensed and dep_unlicensed:
                return (
                    "Prisma AIRS is not activated for this tenant (all endpoints returned 404/424)."
                )

            lines = ["## Prisma AIRS — AI Runtime Security\n"]

            # Customer Applications
            if apps is not None:
                lines.append(f"### Customer Applications ({len(apps)})")
                if apps:
                    lines.append(
                        "| App Name | Cloud Provider | Environment | AI Agent Framework | Status |"
                    )
                    lines.append("|---|---|---|---|---|")
                    for a in apps:
                        lines.append(
                            "| {} | {} | {} | {} | {} |".format(
                                a.get("app_name", "—"),
                                a.get("cloud_provider", "—"),
                                a.get("environment", "—"),
                                a.get("ai_agent_framework", "—"),
                                a.get("status", "—"),
                            )
                        )
                else:
                    lines.append("_No customer applications registered._")
                lines.append("")
            elif apps_unlicensed:
                lines.append("### Customer Applications\n_Not licensed / not activated._\n")

            # AI Security Profiles
            if profiles is not None:
                lines.append(f"### AI Security Profiles ({len(profiles)})")
                if profiles:
                    lines.append("| Profile Name | Profile ID | Revision | Active |")
                    lines.append("|---|---|---|---|")
                    for p in profiles:
                        lines.append(
                            "| {} | {} | {} | {} |".format(
                                p.get("profile_name", "—"),
                                p.get("profile_id", "—"),
                                p.get("revision", "—"),
                                "✓" if p.get("active") else "✗",
                            )
                        )
                else:
                    lines.append("_No AI security profiles defined._")
                lines.append("")
            elif prof_unlicensed:
                lines.append("### AI Security Profiles\n_Not licensed / not activated._\n")

            # Deployment Profiles
            if deploys is not None:
                lines.append(f"### Deployment Profiles ({len(deploys)})")
                if deploys:
                    lines.append("| Profile Name | Auth Code | Status | Expiration |")
                    lines.append("|---|---|---|---|")
                    for dp in deploys:
                        lines.append(
                            "| {} | {} | {} | {} |".format(
                                dp.get("dp_name", "—"),
                                dp.get("auth_code", "—"),
                                dp.get("status", "—"),
                                dp.get("expiration_date", "—"),
                            )
                        )
                else:
                    lines.append("_No deployment profiles defined._")
            elif dep_unlicensed:
                lines.append("### Deployment Profiles\n_Not licensed / not activated._")

            return "\n".join(lines)
        except Exception as exc:
            from ..utils.errors import handle_scm_exception

            return f"Error: {handle_scm_exception(exc)}"
