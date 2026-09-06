"""
Config Cleanup — read-only rule-usage optimization tools.

New pan.dev API family (`config-cleanup`, first seen in the `scm/config`
spec tree on 2026-08-14 — not yet present as of the 2026-07-14 catalog
snapshot). Currently a single endpoint: zero-hit security/NAT rules, backed
by an async analysis job (``lastAnalysisTime`` / ``status``) rather than a
live per-request computation. No object-usage (address/service) equivalent
has shipped alongside it yet, and it is not present in pan-scm-sdk (0.15.1).

API family: pan.dev `scm/config` (posture-management/posture.yaml),
tag "Config Cleanup". Base URL is `api.strata.paloaltonetworks.com/posture`
— a different host than the usual `api.sase.paloaltonetworks.com`.

Hand-curated (single endpoint — the generic scaffolder wasn't worth running
against the full 1,236-path `scm/config` family for one path).
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
_URL = "https://api.strata.paloaltonetworks.com/posture/config-cleanup/v1/zerohit-rules"


def _get_json(client: Any, params: dict[str, Any]) -> tuple[int, Any]:
    """GET zerohit-rules with a fresh bearer session; return (status, parsed-or-text)."""
    session = _bearer_session_for(client)
    resp = session.get(
        _URL, params={k: v for k, v in params.items() if v not in (None, "")}, timeout=(5, 30)
    )
    try:
        return resp.status_code, resp.json()
    except Exception:
        return resp.status_code, (resp.text or "")[:500]


def _zero_hit_days(rule: dict[str, Any]) -> int:
    """Coerce `days_with_zero_hits` to int for sort purposes; 0 on anything
    that isn't cleanly int-like (missing, None, non-numeric string).

    This is a brand-new upstream API with no SDK-level schema validation —
    the field's type isn't guaranteed consistent across rules in one
    response (e.g. one rule reporting an int, another a numeric string).
    `sorted(..., key=...)` compares every pair of keys it touches, so a bare
    `.get(...) or 0` (no type coercion) raises `TypeError` the moment two
    rules disagree on type — this normalizes first so the sort never can.
    """
    value = rule.get("days_with_zero_hits")
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def _render(status: int, data: Any) -> str:
    title = "Zero-Hit Security Rules"
    if status in (401, 403):
        return (
            f"# {title}\n\n⚠️ HTTP {status} — the service account lacks access to "
            f"`{_URL}`. Config Cleanup is a new SCM API (2026-08); it may require a "
            f"licence/role entitlement not yet granted to this account."
        )
    if status == 404:
        return f"# {title}\n\nHTTP 404 — no data available (manager not found)."
    if status >= 500:
        return f"# {title}\n\nHTTP {status} — upstream backend error (response body suppressed)."
    if status != 200:
        return f"# {title}\n\nHTTP {status} from `{_URL}`:\n\n{data}"

    result = data.get("result", data) if isinstance(data, dict) else data
    if not isinstance(result, dict):
        return f"# {title}\n\nUnexpected response shape:\n\n```json\n{json.dumps(data, indent=2, default=str)}\n```"

    analysis_status = result.get("status", "unknown")
    last_analysis = result.get("lastAnalysisTime", "unknown")
    total = result.get("total", 0)

    # "data" is documented as a list of rule objects, but this is a brand-new
    # upstream API (first seen 2026-08-14) with no SDK-level schema
    # validation — guard against a non-list "data" (e.g. a single dict) or
    # non-dict entries within it, rather than letting sorted()/`.get()` raise
    # deep inside rendering.
    raw_rules = result.get("data")
    shape_warning = ""
    if raw_rules is None:
        rules: list[dict[str, Any]] = []
    elif isinstance(raw_rules, list):
        rules = [r for r in raw_rules if isinstance(r, dict)]
        if len(rules) != len(raw_rules):
            shape_warning = (
                "⚠️ Some entries in the response `data` array were not rule "
                "objects and were skipped."
            )
    else:
        rules = []
        shape_warning = "⚠️ Unexpected response shape — `data` was not a list; showing no rules."

    lines = [f"# {title}", ""]
    if analysis_status == "in_progress":
        lines.append(
            "⏳ **Analysis in progress** — results below may be partial or stale; re-run shortly."
        )
    elif analysis_status == "failed":
        lines.append("⚠️ **Analysis failed** upstream — results below may be stale.")
    lines.append(f"Last analysis: {last_analysis} · Platform: {result.get('platform', '?')}")
    lines.append(f"Total zero-hit rules: **{total}** (showing {len(rules)})")
    if shape_warning:
        lines.append(shape_warning)
    lines.append("")

    if not rules:
        lines.append("No zero-hit rules found.")
        return "\n".join(lines)

    rules_sorted = sorted(rules, key=_zero_hit_days, reverse=True)
    lines += [
        "| Days zero-hit | Rule | Type | Location | Tags |",
        "|---|---|---|---|---|",
    ]
    for r in rules_sorted:
        raw_tags = r.get("tag")
        if isinstance(raw_tags, list):
            # Coerce each element to str — a non-string element (int, None,
            # …) would otherwise crash str.join(), which requires every
            # sequence member to already be a str.
            tags = ", ".join(str(t) for t in raw_tags if t is not None) or "—"
        elif isinstance(raw_tags, str):
            # A plain string "tag" (instead of a list) would otherwise be
            # iterated character-by-character by str.join().
            tags = raw_tags or "—"
        elif raw_tags is None:
            tags = "—"
        else:
            tags = str(raw_tags)
        lines.append(
            f"| {r.get('days_with_zero_hits', '?')} | {r.get('name', '?')} | "
            f"{r.get('type', '?')} | {r.get('location', '?')} | {tags} |"
        )
    body = json.dumps(rules_sorted, indent=2, default=str)
    if len(body) > _MAX_CHARS:
        body = body[:_MAX_CHARS] + "\n… (truncated)"
    lines += ["", "<details><summary>Raw JSON</summary>", "", "```json", body, "```", "</details>"]
    return "\n".join(lines)


def register_config_cleanup_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register Config Cleanup read-only tools."""
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_zerohit_rules(
        client: Any,
        tenant_id: str,
        manager_hostname: str = "SCM",
        location: str = "",
        limit: int = 200,
        offset: int = 0,
    ) -> str:
        """Security/NAT rules with zero traffic hits (rule-usage cleanup candidates).

        New SCM Config Cleanup API (first seen on pan.dev 2026-08-14). Backed by an
        async analysis job — check the returned analysis status/timestamp rather than
        assuming the data is live. Rules-only for now; no address/service object-usage
        equivalent has shipped. Sorted worst-offender first (most days with zero hits).

        Args:
            tenant_id: SCM tenant ID (MSSP mode).
            manager_hostname: "SCM" for Strata Cloud Manager (default), or a Panorama
                hostname for Panorama-managed rules.
            location: Filter by folder (SCM) or device group (Panorama).
            limit: Max rules to return (1-200, default 200).
            offset: Pagination offset.

        Returns:
            Markdown table of zero-hit rules ranked by days_with_zero_hits, or an
            actionable message on 4xx/5xx.
        """
        status, data = _get_json(
            client,
            {
                "manager_hostname": manager_hostname,
                "location": location,
                "limit": limit,
                "offset": offset,
            },
        )
        logger.info("zerohit_rules", tenant_id=tenant_id, status=status)
        return _render(status, data)
