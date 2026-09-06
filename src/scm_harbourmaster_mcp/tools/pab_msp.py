"""
Prisma Access Browser for MSP — cross-tenant reporting tools.

The pan.dev `sase/pab-msp` family (Feb 2026) adds an MSP reporting layer on
top of the per-tenant PAB provisioning API the AS-BUILT extractor already
covers (/mt/pab/tenant/*): per-TSG security event reports and region-level
summaries. Read-only; tenant creation (POST /mt/pab/tenant) is deliberately
not exposed.

Plumbing scaffolded by scripts/gen_tool_from_spec.py from pan.dev
@ 06430c92c453, then consolidated: 8 report endpoints share one tool, the
3 summary endpoints another.
"""

from __future__ import annotations

import json
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..audit.extractor import _bearer_session_for
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool

logger = get_logger(__name__)

_MAX_CHARS = 15000
_BASE = "https://api.sase.paloaltonetworks.com/mt/pab"

_REPORTS = (
    "count",
    "extension_blocked",
    "extension_category",
    "malicious_website",
    "malware_blocked",
    "malware_website",
    "website_blocked",
    "website_category",
)
_SUMMARY_SCOPES: dict[str, str] = {
    "users": f"{_BASE}/summary",
    "tenants": f"{_BASE}/summary/tenants",
    "cie": f"{_BASE}/summary/cie",
}


def _post_json(client: Any, url: str, body: dict[str, Any]) -> tuple[int, Any]:
    """POST a JSON body with a fresh bearer session; return (status, parsed-or-text)."""
    session = _bearer_session_for(client)
    resp = session.post(url, json=body, timeout=(5, 30))
    try:
        return resp.status_code, resp.json()
    except Exception:
        return resp.status_code, (resp.text or "")[:500]


def _get_json(client: Any, url: str) -> tuple[int, Any]:
    """GET with a fresh bearer session; return (status, parsed-or-text)."""
    session = _bearer_session_for(client)
    resp = session.get(url, timeout=(5, 30))
    try:
        return resp.status_code, resp.json()
    except Exception:
        return resp.status_code, (resp.text or "")[:500]


def _render(title: str, url: str, status: int, data: Any) -> str:
    if status in (401, 403):
        return (
            f"# {title}\n\n⚠️ HTTP {status} — the service account lacks access to `{url}`. "
            f"PAB for MSP is a multitenant API: the account needs an MSP role and a "
            f"Prisma Access Browser entitlement."
        )
    if status == 404:
        return f"# {title}\n\nHTTP 404 — Prisma Access Browser is not provisioned here."
    if status >= 500:
        return (
            f"# {title}\n\nHTTP {status} — PAN backend error from `{url}`. This "
            f"multitenant API may require an MSP-mode service account; the upstream "
            f"service failed to process the request (response body suppressed)."
        )
    if status != 200:
        return f"# {title}\n\nHTTP {status} from `{url}`:\n\n{data}"
    items = data.get("data", data.get("items", data)) if isinstance(data, dict) else data
    count = len(items) if isinstance(items, list) else 1
    body = json.dumps(items, indent=2, default=str)
    if len(body) > _MAX_CHARS:
        body = body[:_MAX_CHARS] + "\n… (truncated)"
    return f"# {title} ({count})\n\n```json\n{body}\n```"


def register_pab_msp_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register Prisma Access Browser for MSP reporting tools."""
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_pab_msp_summary(client: Any, scope: str = "tenants", region: str = "europe") -> str:
        """Prisma Access Browser MSP summary — users, tenants, or CIE.

        Region-level roll-ups from the PAB for MSP API (multitenant; the
        service account needs an MSP role and a PAB entitlement — a 403
        message explains what is missing).

        Args:
            scope: "tenants" (per-tenant summary, default), "users"
                   (configured-user counts), or "cie" (Cloud Identity
                   Engine summary).
            region: PAB SLS region identifier — one of: americas, europe,
                    jp, uk, in, sg, ca, id, au, de (default "europe").
            tenant_id: SCM tenant ID (MSSP mode).

        Returns:
            Markdown with a JSON payload, or an actionable message on 4xx.
        """
        url = _SUMMARY_SCOPES.get(scope)
        if url is None:
            return f"Unknown scope {scope!r}. Valid scopes: {', '.join(sorted(_SUMMARY_SCOPES))}"
        status, data = _post_json(client, url, {"region": region})
        logger.info("pab_msp_summary", scope=scope, status=status)
        return _render(f"PAB MSP summary — {scope}", url, status, data)

    @mcp.tool()
    @tool
    def scm_pab_msp_report(
        client: Any, tenant_id: str, report: str = "count", tsg_id: str = ""
    ) -> str:
        """Prisma Access Browser MSP security-event report for one tenant.

        Pulls a PAB security report for a TSG: blocked malware, blocked or
        malicious websites, blocked extensions, and category breakdowns.
        Useful evidence for browser-security controls in CE/NCSC reporting.

        Args:
            report: One of: count, extension_blocked, extension_category,
                    malicious_website, malware_blocked, malware_website,
                    website_blocked, website_category.
            tsg_id: Tenant Service Group to report on. Defaults to tenant_id.
            tenant_id: SCM tenant ID used for auth (MSSP mode).

        Returns:
            Markdown with a JSON payload, or an actionable message on 4xx.
        """
        if report not in _REPORTS:
            return f"Unknown report {report!r}. Valid reports: {', '.join(_REPORTS)}"
        target = tsg_id or tenant_id
        if not target:
            return "A tsg_id (or tenant_id) is required to scope the report."
        url = f"{_BASE}/report/{report}"
        status, data = _post_json(client, url, {"tsg_id": target})
        logger.info("pab_msp_report", report=report, status=status)
        return _render(f"PAB MSP report — {report} ({target})", url, status, data)

    @mcp.tool()
    @tool
    def scm_pab_msp_auth_profile(client: Any) -> str:
        """Prisma Access Browser MSP tenant authentication profile.

        The one path in the already-tooled PAB-for-MSP family with no
        consumer: ``GET /mt/pab/tenant/auth_profile``. Read-only.

        Args:
            tenant_id: SCM tenant ID used for auth (MSSP mode).

        Returns:
            Markdown with a JSON payload, or an actionable message on 4xx.
        """
        url = f"{_BASE}/tenant/auth_profile"
        status, data = _get_json(client, url)
        logger.info("pab_msp_auth_profile", status=status)
        return _render("PAB MSP auth profile", url, status, data)
