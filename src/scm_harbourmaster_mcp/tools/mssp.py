"""
MCP tools for MSSP tenant estate management.

Tools:
    mssp_tenant_dashboard   — summary of every tenant loaded in the server
    scm_license_info        — subscription licences and expiry per tenant
    scm_mobile_user_stats   — allocation and logged-in mobile-user counts
    scm_discover_tenants    — discover sub-tenants managed from this tenant
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from ..auth.oauth import get_tenant_meta, list_loaded_tenants
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool

logger = get_logger(__name__)

_STATUS_ICON = {"compliant": "✅", "non-compliant": "❌", "gap": "⚠️"}


def register_mssp_tools(mcp: FastMCP, get_client: Any, get_settings: Any) -> None:
    """Register the MSSP tenant estate, licensing, and discovery tools."""
    tool = scm_tool(get_client)

    # ── Tenant Dashboard ──────────────────────────────────────────────────────

    @mcp.tool()
    def mssp_tenant_dashboard(tenant_id: str = "") -> str:
        """Show a summary dashboard of all loaded MSSP tenants.

        Lists every tenant currently cached in the server, showing their
        folder, label, service term, and the cached API-capability summary
        from mssp_tenant_capabilities (never probes — "not probed" until that
        tool has run for the tenant).

        Args:
            tenant_id: Not used for filtering — returns all loaded tenants.

        Returns:
            Markdown dashboard of all tenants.
        """
        from ..utils.capabilities import (
            AVAILABLE,
            FORBIDDEN,
            UNPROVISIONED,
            capability_counts,
            get_cached_capabilities,
        )

        loaded = list_loaded_tenants()
        if not loaded:
            return "No tenants currently loaded. Configure tenants in settings.toml."

        lines: list[str] = [
            "# MSSP Tenant Dashboard\n",
            f"**Loaded tenants:** {len(loaded)}\n",
            "",
            "| Tenant ID | Label | Folder | Term | Account Ref | API Capabilities |",
            "|-----------|-------|--------|------|-------------|------------------|",
        ]
        restricted: list[str] = []

        for tid in loaded:
            cfg = get_tenant_meta(tid)
            if cfg:
                label = cfg.label or "—"
                folder = cfg.default_folder or "—"
                term = f"{cfg.service_term_years}yr" if cfg.service_term_years else "—"
                ref = cfg.account_ref or "—"
            else:
                label, folder, term, ref = "—", "—", "—", "—"

            cached = get_cached_capabilities(tid)
            if cached is None:
                caps = "not probed"
            else:
                results = cached[0]
                counts = capability_counts(results)
                caps = f"{counts[AVAILABLE]}/{len(results)} available"
                blocked = [
                    f"`{r.family}` ({r.status})"
                    for r in results.values()
                    if r.status in (FORBIDDEN, UNPROVISIONED)
                ]
                if blocked:
                    caps += f" · {len(blocked)} restricted"
                    restricted.append(f"- `{tid}`: " + ", ".join(sorted(blocked)))
            lines.append(f"| `{tid}` | {label} | {folder} | {term} | {ref} | {caps} |")

        if restricted:
            lines += [
                "",
                "**Restricted API families (cached probe)** — report sections relying on "
                "these are skipped up front:",
                *restricted,
            ]

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

                # remaining_size can exceed purchased_size on some eval SKUs,
                # which would render a negative consumed count — show n/a.
                consumed: int | str = lic.get("purchased_size", 0) - (
                    lic.get("remaining_size") or 0
                )
                if isinstance(consumed, int) and consumed < 0:
                    consumed = "n/a"
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
    def scm_mobile_user_stats(client: Any, tenant_id: str, region: str = "") -> str:
        """Show Prisma Access mobile user allocation and current logged-in user count.

        Uses the Prisma Access Insights API to retrieve live connected user counts,
        plus bandwidth allocation from SCM config.

        Args:
            tenant_id: SCM tenant ID. Omit to use the default tenant.
            region: X-PANW-Region override (europe, americas, uk, ...; 'eu'/'us'
                    accepted). Default: the tenant's settings `region`, else the
                    region found by mssp_detect_region, else its insights_region.
        """
        from ..config.region import insights_default, resolve_region

        region = resolve_region(tenant_id, explicit=region, default=insights_default(tenant_id))
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
                    consumed: int | str = qty - remaining
                    if isinstance(consumed, int) and consumed < 0:
                        consumed = "n/a"  # remaining > purchased: pooled-SKU artefact
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

    @mcp.tool()
    @tool
    def scm_saa_list(
        client: Any, tenant_id: str, region: str = "", include_sessions: bool = True
    ) -> str:
        """Secure Agentless Access (SAA) status, inventory, active sessions and risks.

        Use this to answer "is Secure Agentless Access set up for this tenant?",
        "which private RDP/SSH/VNC/web apps are published?", "who can reach
        them?", "who is connected right now?" and "are there SAA risks to
        report?". Reads the SAA API:
        - Applications (type, destinations, groups, whether credentials are
          stored — never the credentials themselves)
        - Application groups, application profiles (clipboard/file
          transfer/recording permissions per protocol), access policies
        - Active sessions (user, app, source IP, start, last heartbeat)
        - Recent changes — applications and groups, newest first
        - Risks — dangling policy references, file transfer allowed, no
          session recording, unreachable apps, unpinned SSH host keys, RDP
          without NLA, unused/empty groups, long-running sessions

        SAA routes every request by data region. The region is found by
        probing (the tenant's configured region first), cached for the
        session, and shown in the output. A tenant unknown in every region
        reports "not provisioned" in one line.

        Args:
            tenant_id: Tenant ID. Omit to use the default tenant.
            region: x-panw-region to use (uk, europe, americas, ...). Omit to
                probe. A wrong value is reported, not replaced.
            include_sessions: Include the live active-session list (default True).

        Returns:
            Markdown report.

        Ref: https://pan.dev/scm/api/config/secure_agentless_access/
        """
        from ..utils.airs import render_sections_markdown
        from ..utils.saa import (
            assess_saa,
            fetch_saa,
            not_provisioned_text,
            region_line,
            risk_headline,
            saa_sections,
        )

        try:
            if getattr(client, "session", None) is None:
                return "Error: client has no .session attribute"
            session = _bearer_session(client)
            inv = fetch_saa(session, tenant_id, region, include_sessions)
            if not inv.provisioned:
                return not_provisioned_text(inv, region)

            risks = assess_saa(inv)
            lines = [
                "## Secure Agentless Access\n",
                risk_headline(risks),
                "",
                region_line(inv),
                "",
            ]
            lines += render_sections_markdown(saa_sections(inv, risks, include_sessions))
            return "\n".join(lines).rstrip()
        except Exception as exc:
            from ..utils.errors import handle_scm_exception

            return f"Error: {handle_scm_exception(exc)}"

    @mcp.tool()
    @tool
    def scm_saa_session_disconnect(
        client: Any,
        tenant_id: str,
        ticket_ref: str = "",
        session_ids: list[str] | None = None,
        user_id: str = "",
        app_id: str = "",
        all_sessions: bool = False,
        region: str = "",
        dry_run: bool = True,
    ) -> str:
        """Disconnect live Secure Agentless Access (SAA) sessions — incident response.

        Use this to answer "kick this user off SAA", "end every session to
        this app" or "disconnect everyone now". Pick exactly one target:
        - session_ids: the sessions to end (from scm_saa_list)
        - user_id and/or app_id: every active session for that user (email)
          and/or application id, resolved from the live session list
        - all_sessions=True: every active session in the tenant
          (``:disconnect-all``, asynchronous)

        Write-safety (SSR pattern): dry_run defaults to True and only lists
        the sessions that would be ended plus the exact request. ticket_ref
        is mandatory on every call and is never sent to the API. Sessions
        are re-listed at apply time, so the ids sent may differ from the
        dry run's. Disconnecting does not block the user: they can reconnect
        unless their access policy is changed too.

        SAA routes by data region and answers session calls in ANY region, so
        the region is established by probing applications and groups first;
        without one, nothing is sent.

        Args:
            tenant_id: Tenant ID. Omit to use the default tenant.
            ticket_ref: Change/incident reference (required).
            session_ids: Session ids to disconnect.
            user_id: Disconnect every session of this user (email).
            app_id: Disconnect every session to this application id.
            all_sessions: Disconnect every active session in the tenant.
            region: x-panw-region (uk, europe, americas, ...). Omit to probe.
            dry_run: Preview only (default True). False sends the disconnect.

        Returns:
            Markdown: the matched sessions, the request, and per-session results.

        Ref: https://pan.dev/scm/api/config/secure_agentless_access/
        """
        from ..utils.airs import cell
        from ..utils.saa import (
            DISCONNECT_ALL_PATH,
            DISCONNECT_PATH,
            SAA_BASE,
            SaaInventory,
            disconnect_all_sessions,
            disconnect_sessions,
            find_region,
            list_active_sessions,
            not_provisioned_text,
        )
        from ..utils.write_safety import (
            DRY_RUN_HINT,
            audit_write,
            normalize_ticket_ref,
            ticket_ref_error,
        )

        err = ticket_ref_error(ticket_ref)
        if err:
            return f"Error: {err}"
        ticket = normalize_ticket_ref(ticket_ref)
        ids = list(dict.fromkeys(s.strip() for s in (session_ids or []) if s and s.strip()))
        user_id, app_id = user_id.strip(), app_id.strip()
        modes = [bool(ids), bool(user_id or app_id), bool(all_sessions)]
        if sum(modes) != 1:
            return (
                "Error: pick exactly one target — session_ids, user_id/app_id, or "
                "all_sessions=True."
            )
        mode = "ids" if ids else ("filter" if modes[1] else "all")

        try:
            if getattr(client, "session", None) is None:
                return "Error: client has no .session attribute"
            session = _bearer_session(client)
            found, source, failures = find_region(session, tenant_id, region)
            if not found:
                reason = not_provisioned_text(SaaInventory(probe_failures=failures), region)
                return f"Nothing was disconnected. {reason}"

            live, problem = list_active_sessions(
                session,
                found,
                user_id if mode == "filter" else "",
                app_id if mode == "filter" else "",
            )
            live_ids = [str(s.get("session_id")) for s in live if s.get("session_id")]

            lines = [
                "## Secure Agentless Access — Session Disconnect\n",
                f"**Ticket:** `{ticket}` · **Region:** `{found}` ({source}) · "
                f"**Mode:** {'dry run' if dry_run else 'apply'}",
                "",
            ]
            if problem:
                lines += [f"> ⚠️ Active sessions could not be listed in full: {problem}.", ""]

            if mode == "ids":
                targets = ids
                matched = [s for s in live if str(s.get("session_id")) in set(ids)]
                unknown = [i for i in ids if i not in set(live_ids)]
            else:
                targets, matched, unknown = live_ids, live, []

            what = {
                "ids": f"{len(ids)} session id(s)",
                "filter": " and ".join(
                    f"{k} `{v}`" for k, v in (("user", user_id), ("app", app_id)) if v
                ),
                "all": "every active session",
            }[mode]
            lines.append(f"**Target:** {what}")
            lines.append("")
            lines.append(f"### Matching active sessions ({len(matched)})")
            lines.append("")
            if matched:
                lines.append(
                    "| Session ID | User | App ID | Type | Source IP | Started | Last Heartbeat |"
                )
                lines.append("|---|---|---|---|---|---|---|")
                for s in matched:
                    lines.append(
                        "| "
                        + " | ".join(
                            cell(s.get(k))
                            for k in (
                                "session_id",
                                "user_id",
                                "app_id",
                                "app_type",
                                "source_ip",
                                "start_time",
                                "last_heartbeat",
                            )
                        )
                        + " |"
                    )
            else:
                lines.append("_No matching active sessions._")
            lines.append("")
            if unknown and not problem:
                lines += [
                    f"> {len(unknown)} id(s) are not active now and will be reported "
                    f"404 by the API: {', '.join(f'`{u}`' for u in unknown)}",
                    "",
                ]

            if mode == "filter" and problem:
                lines.append(
                    "Nothing was sent: the session list is incomplete, so the sessions "
                    "matching this filter cannot be resolved safely. Pass session_ids instead."
                )
                return "\n".join(lines).rstrip()
            if mode != "ids" and not targets and not problem:
                lines.append("Nothing to disconnect — no active sessions match.")
                return "\n".join(lines).rstrip()

            lines.append("### Request")
            lines.append("")
            if mode == "all":
                lines.append(f"`POST {SAA_BASE}{DISCONNECT_ALL_PATH}` (no body)")
            else:
                lines.append(
                    f"`POST {SAA_BASE}{DISCONNECT_PATH}` with "
                    f'`{{"session_ids": [...{len(targets)} id(s)]}}`'
                )
            lines.append(f"Header `x-panw-region: {found}`")
            lines.append("")

            if dry_run:
                lines.append(DRY_RUN_HINT)
                return "\n".join(lines).rstrip()

            if mode == "all":
                audit_write(
                    "scm_saa_session_disconnect",
                    ticket,
                    tenant_id,
                    action="disconnect-all",
                    region=found,
                    active_sessions=len(live_ids),
                )
                accepted, error = disconnect_all_sessions(session, found)
                lines.append("### Result")
                lines.append("")
                if accepted:
                    lines.append(
                        "✅ Accepted — SAA is disconnecting every active session "
                        "asynchronously. Re-run scm_saa_list to confirm."
                    )
                else:
                    lines.append(f"❌ Refused: {error}")
                return "\n".join(lines).rstrip()

            outcome = disconnect_sessions(
                session,
                found,
                targets,
                before_post=lambda chunk: audit_write(
                    "scm_saa_session_disconnect",
                    ticket,
                    tenant_id,
                    action="disconnect",
                    region=found,
                    session_ids=chunk,
                ),
            )
            lines.append("### Result")
            lines.append("")
            lines.append(
                f"{'✅' if outcome.disconnected else 'ℹ️'} Disconnected: {len(outcome.disconnected)} · "
                f"not found / already gone: {len(outcome.not_found)}"
                + (f" · other: {len(outcome.other)}" if outcome.other else "")
                + (f" · unconfirmed: {len(outcome.unconfirmed)}" if outcome.unconfirmed else "")
                + (f" · not sent: {len(outcome.failed)}" if outcome.failed else "")
            )
            if outcome.error:
                lines += ["", f"❌ {outcome.error}"]
            rows = (
                [(i, "disconnected") for i in outcome.disconnected]
                + [(i, "not found") for i in outcome.not_found]
                + [(i, f"HTTP {c}") for i, c in outcome.other.items()]
                + [(i, "accepted, no per-session result") for i in outcome.unconfirmed]
                + [(i, "not sent / failed") for i in outcome.failed]
            )
            if rows:
                lines += ["", "| Session ID | Result |", "|---|---|"]
                lines += [f"| {cell(i)} | {r} |" for i, r in rows]
            return "\n".join(lines).rstrip()
        except Exception as exc:
            from ..utils.errors import handle_scm_exception

            return f"Error: {handle_scm_exception(exc)}"


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
    def scm_airs_list(client: Any, tenant_id: str, include_devices: bool = True) -> str:
        """Prisma AIRS (AI Runtime Security) status, inventory, change history and risks.

        Use this to answer "is AIRS enabled/licensed for this tenant?", "what AI
        security profiles exist?", "who changed AIRS?" and "are there any AI
        security risks to report?". Reads the AIRS management API:
        - Licence — deployment profiles (auth code, expiry)
        - Customer applications, AI security profiles, custom topics
        - API keys (name, app, expiry, rotation — never key material)
        - Firewalls carrying an AIRS licence (from the SCM device list)
        - Recent changes — who created/updated each object, newest first
        - Risks — expired/expiring licence or keys, profiles with no model
          protection, detections set to allow, fail-open on timeout, missing
          DLP, unused topics/apps

        A tenant with no deployment profiles whose profile list is refused
        reports "not provisioned" in one line.

        Args:
            tenant_id: Tenant ID. Omit to use the default tenant.
            include_devices: Cross-reference the SCM device list (every page)
                for firewalls licensed for AIRS (default True).

        Returns:
            Markdown report.

        Ref: https://pan.dev/prisma-airs/api/airuntimesecurity/prismaairsmanagementapi/
        """
        from ..utils.airs import (
            airs_sections,
            assess_airs,
            fetch_airs,
            fetch_airs_devices,
            render_sections_markdown,
            risk_headline,
        )

        try:
            if getattr(client, "session", None) is None:
                return "Error: client has no .session attribute"
            # A plain bearer session: the SDK's OAuth2Session raises
            # TokenExpiredError on direct non-SDK calls once the token ages.
            session = _bearer_session(client)

            inv = fetch_airs(session)
            if not inv.provisioned:
                if inv.forbidden:
                    return (
                        "Prisma AIRS: the management API refused the profile list with HTTP 403 "
                        "— the service account's role lacks AIRS permissions (RBAC), so whether "
                        "AIRS is provisioned cannot be determined."
                    )
                if inv.errors:
                    return "Error: " + "; ".join(f"{k}: {v}" for k, v in inv.errors.items())
                return (
                    "Prisma AIRS is not provisioned for this tenant "
                    "(no deployment profiles; the management API refused the profile list)."
                )

            devices: list[dict[str, Any]] | None = None
            device_note = ""
            if include_devices:
                try:
                    devices = fetch_airs_devices(session, inv)
                except Exception as exc:
                    device_note = f"_Device list unavailable: {exc}_"

            risks = assess_airs(inv, devices)
            lines = ["## Prisma AIRS — AI Runtime Security\n", risk_headline(risks), ""]
            if device_note:
                lines += [device_note, ""]
            lines += render_sections_markdown(airs_sections(inv, devices, risks))
            return "\n".join(lines).rstrip()
        except Exception as exc:
            from ..utils.errors import handle_scm_exception

            return f"Error: {handle_scm_exception(exc)}"
