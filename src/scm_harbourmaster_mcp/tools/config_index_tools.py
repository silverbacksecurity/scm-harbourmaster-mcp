"""
MCP tools for the local config search index — the Global Find replacement.

Tools:
    scm_config_index   — build/refresh the searchable index for a tenant+folder
    scm_object_search  — search indexed config across tenants by text or IP

The index is a local SQLite database (SCM_MCP_INDEX_DIR, default ./index) built
from the same ``extract_snapshot`` fan-out that feeds the audit, BPA and
AS-BUILT tools, so indexing costs one extraction and no new API surface.

Why an index at all: SCM's Global Search live-queries the control plane, is
scoped to a single tenant, and matches strings only. Searching a local copy is
instant, spans every managed tenant in one query, and can answer containment
questions ("what covers 10.20.5.7?") that string matching cannot.
"""

from __future__ import annotations

import threading
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..audit.config_index import (
    INDEXABLE_FIELDS,
    Hit,
    IndexStats,
    index_snapshot,
    index_status,
    search,
)
from ..audit.extractor import extract_snapshot
from ..auth.oauth import get_scm_client
from ..config.settings import load_all_tenant_configs
from ..utils.errors import handle_scm_exception
from ..utils.logging import get_logger

logger = get_logger(__name__)

_MAX_CHARS = 15000

# Background job store for the all-tenants index sweep, mirroring the drift
# sentinel's shape (jobs expire after 1 hour).
_INDEX_JOBS: dict[str, dict[str, Any]] = {}
_JOBS_LOCK = threading.Lock()
_JOB_TTL = 3600


def _prune_jobs() -> None:
    cutoff = time.time() - _JOB_TTL
    with _JOBS_LOCK:
        for jid in [j for j, meta in _INDEX_JOBS.items() if meta["started_at"] < cutoff]:
            del _INDEX_JOBS[jid]


def _age(indexed_at: float) -> str:
    """Human age of an index entry — staleness is the one risk of a local copy."""
    seconds = max(0, int(time.time() - indexed_at))
    if seconds < 90:
        return f"{seconds}s ago"
    minutes = seconds // 60
    if minutes < 90:
        return f"{minutes}m ago"
    hours = minutes // 60
    return f"{hours}h ago" if hours < 48 else f"{hours // 24}d ago"


def _render_stats(results: list[dict[str, Any]], ts: str) -> str:
    lines = ["## Config Index Built", "", f"**Indexed:** {ts}", ""]
    total = 0
    for r in results:
        if r.get("error"):
            lines.append(f"- ⚠️ {r['label']}: {r['error']}")
            continue
        st: IndexStats = r["stats"]
        total += st.object_count
        mode = "FTS5" if st.fts else "LIKE (no FTS5 in this SQLite build)"
        skipped = (
            f", {st.predefined_skipped} predefined app signature(s) skipped"
            if st.predefined_skipped
            else ""
        )
        lines.append(
            f"- ✅ **{r['label']}** — {st.object_count} objects across {st.type_count} "
            f"type(s), {st.ip_range_count} address range(s){skipped}, "
            f"{st.elapsed:.1f}s  [{mode}]"
        )
    lines += [
        "",
        f"**Total indexed:** {total} object(s).",
        "",
        'Search it with `scm_object_search(query="...")` — text, or an IP/CIDR for '
        "containment matching. Re-run this tool after a commit to refresh.",
    ]
    return "\n".join(lines)


def _render_hits(hits: list[Hit], query: str, mode: str, cross_tenant: bool) -> str:
    mode_note = {
        "ip": "IP containment — objects whose address range overlaps the query",
        "fts": "ranked full-text",
        "like": "substring (no ranked match)",
    }.get(mode, mode)
    lines = [
        f"## Object Search — `{query}`",
        "",
        f"**{len(hits)} match(es)**  |  **Match mode:** {mode_note}",
        "",
    ]
    by_type: dict[str, list[Hit]] = {}
    for hit in hits:
        by_type.setdefault(hit.obj_type, []).append(hit)

    for obj_type in sorted(by_type):
        group = by_type[obj_type]
        lines.append(f"### {obj_type.replace('_', ' ')} ({len(group)})")
        lines.append("")
        header = "| Name | Scope |" + (" Tenant |" if cross_tenant else "")
        divider = "|---|---|" + ("---|" if cross_tenant else "")
        lines.append(header + " Detail |")
        lines.append(divider + "---|")
        for hit in group:
            tenant_cell = f" {hit.tenant_label or hit.tenant_id} |" if cross_tenant else ""
            detail = hit.summary or ""
            if hit.matched_cidr:
                detail = f"`{hit.matched_cidr}` — {detail}" if detail else f"`{hit.matched_cidr}`"
            detail = detail.replace("|", "\\|")  # keep the markdown table intact
            lines.append(f"| `{hit.name}` | {hit.scope or hit.folder} |{tenant_cell} {detail} |")
        lines.append("")

    out = "\n".join(lines)
    return (
        out if len(out) <= _MAX_CHARS else out[:_MAX_CHARS] + "\n\n…truncated — narrow the query."
    )


def register_config_index_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register local config-index build and search tools.

    None of these take a ``client`` parameter: the two index builders resolve
    their own per-tenant clients for the all-tenants sweep, and the search tool
    never touches the API at all — so they are plain ``@mcp.tool()`` rather than
    ``@scm_tool``-wrapped.
    """

    def _index_one(
        label: str,
        tsg_id: str,
        client: Any,
        auth_error: str | None,
        folder: str,
        include_predefined: bool,
    ) -> dict[str, Any]:
        """Index one tenant's folder. Never raises — a sweep must not abort on one tenant."""
        result: dict[str, Any] = {"label": label, "error": None}
        try:
            if client is None:
                result["error"] = f"authentication failed: {auth_error}"
                return result
            snap = extract_snapshot(client, folder, tsg_id)
            result["stats"] = index_snapshot(
                snap, tenant_label=label, include_predefined=include_predefined
            )
        except Exception as exc:
            logger.warning("index_tenant_failed", tenant=label, error=str(exc))
            result["error"] = handle_scm_exception(exc)
        return result

    def _targets(tenant_id: str, all_tenants: bool) -> list[tuple[str, str, Any, str | None]]:
        """Resolve (label, tsg_id, client, auth_error) per tenant to index."""
        if not all_tenants:
            tsg = tenant_id or "default"
            return [(tsg, tsg, get_client(tenant_id), None)]
        targets: list[tuple[str, str, Any, str | None]] = []
        for key, tc in load_all_tenant_configs().items():
            label = tc.label or key
            try:
                targets.append((label, tc.tenant_id, get_scm_client(tc), None))
            except Exception as exc:
                logger.warning("index_auth_failed", tenant=key, error=str(exc))
                targets.append((label, tc.tenant_id, None, str(exc)))
        return targets

    @mcp.tool()
    def scm_config_index(
        folder: str = "Prisma Access",
        tenant_id: str = "",
        all_tenants: bool = False,
        include_predefined: bool = False,
    ) -> str:
        """Build or refresh the local search index over a tenant's SCM config.

        Extracts a full config snapshot and flattens it into a local SQLite
        index (SCM_MCP_INDEX_DIR, default ./index) — one row per object across
        addresses, groups, services, tags, EDLs, applications, every security /
        NAT / decryption / authentication rulebase, security profiles, zones,
        VPN, remote networks, and identity config. Address literals found
        anywhere in an object are indexed as ranges so scm_object_search can do
        real CIDR containment.

        Re-running replaces that tenant+folder's index; other tenants are left
        alone. Run it after a commit, or on a schedule alongside
        scm_drift_check, so searches reflect current config — results carry the
        index age so stale answers are visible rather than silent.

        Args:
            folder: SCM folder to index (default "Prisma Access").
            tenant_id: SCM tenant ID (MSSP mode) for a single tenant.
            all_tenants: If True, index every configured tenant in a background
                         job — returns a job ID for scm_config_index_result.
            include_predefined: Also index Palo Alto's shipped App-ID catalogue
                         (~11k signatures, ~25 MB per tenant). Off by default:
                         it is vendor reference data, identical on every tenant,
                         and it would bury the tenant's own config in results.
                         Turn it on only to look up app signatures locally.

        Returns:
            Index summary (single tenant, ~2 min) or a job ID (all tenants).
        """
        try:
            targets = _targets(tenant_id, all_tenants)
            ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

            if not all_tenants:
                label, tsg_id, client, auth_error = targets[0]
                return _render_stats(
                    [_index_one(label, tsg_id, client, auth_error, folder, include_predefined)], ts
                )

            _prune_jobs()
            job_id = uuid.uuid4().hex[:8]
            with _JOBS_LOCK:
                _INDEX_JOBS[job_id] = {
                    "status": "running",
                    "started_at": time.time(),
                    "result": None,
                    "error": None,
                }

            def _run() -> None:
                try:
                    from concurrent.futures import ThreadPoolExecutor

                    with ThreadPoolExecutor(max_workers=3) as pool:
                        results = list(
                            pool.map(
                                lambda t: _index_one(
                                    t[0], t[1], t[2], t[3], folder, include_predefined
                                ),
                                targets,
                            )
                        )
                    with _JOBS_LOCK:
                        _INDEX_JOBS[job_id]["status"] = "done"
                        _INDEX_JOBS[job_id]["result"] = _render_stats(results, ts)
                    logger.info("index_job_complete", job_id=job_id, tenants=len(targets))
                except Exception as exc:
                    logger.error("index_job_failed", job_id=job_id, error=str(exc))
                    with _JOBS_LOCK:
                        _INDEX_JOBS[job_id]["status"] = "error"
                        _INDEX_JOBS[job_id]["error"] = handle_scm_exception(exc)

            threading.Thread(target=_run, daemon=True, name=f"index-{job_id}").start()
            return (
                f"Config index sweep started (job `{job_id}`) across {len(targets)} tenant(s).\n\n"
                f"Each tenant takes ~2 minutes to extract (3 run concurrently). When ready:\n\n"
                f'    scm_config_index_result(job_id="{job_id}")'
            )
        except Exception as exc:
            return f"Error: {handle_scm_exception(exc, tool='scm_config_index')}"

    @mcp.tool()
    def scm_config_index_result(job_id: str) -> str:
        """Retrieve the summary of an all-tenants config index sweep.

        Args:
            job_id: Job ID returned by scm_config_index with all_tenants=True
                    (jobs are kept for 1 hour).

        Returns:
            The index summary, or a status message if the sweep is still running.
        """
        with _JOBS_LOCK:
            job = dict(_INDEX_JOBS.get(job_id, {}))
        if not job:
            active = list(_INDEX_JOBS.keys())
            hint = f"  Active jobs: {active}" if active else "  No active jobs."
            return f"Index job `{job_id}` not found (expires after 1 hour).\n{hint}"
        mins, secs = divmod(int(time.time() - job["started_at"]), 60)
        if job["status"] == "running":
            return f"Index job `{job_id}` still running ({mins}m {secs}s). Check again shortly."
        if job["status"] == "error":
            return f"Index job `{job_id}` failed after {mins}m {secs}s: {job['error']}"
        return str(job["result"])

    @mcp.tool()
    def scm_object_search(
        query: str,
        tenant_id: str = "",
        folder: str = "",
        obj_types: str = "",
        limit: int = 50,
        include_predefined: bool = False,
    ) -> str:
        """Search indexed SCM config across tenants — the Global Find replacement.

        Answers in milliseconds from the local index built by scm_config_index,
        with no API call. Unlike SCM's Global Search it spans every indexed
        tenant at once and understands addresses:

          * Text  — "payments", "log4j", "tcp/8443", a rule or object name
                    fragment, a tag, a description phrase.
          * IP    — "10.20.5.7" or "10.20.0.0/16" does real containment: every
                    object whose address range overlaps the query, however that
                    object happens to spell it. This is the question Global
                    Search cannot answer.

        Results show the object's own scope (folder / snippet / device), so an
        object inherited from a parent folder is distinguishable from a local
        one. Each hit carries a one-line gist — an address's value, a group's
        members, a rule's source → destination and action.

        Run scm_config_index first; searches report the index age so a stale
        answer is visible rather than silent.

        Args:
            query: Free text, or an IP / CIDR for containment matching.
            tenant_id: Restrict to one tenant. Omit to search every indexed tenant.
            folder: Restrict to one SCM folder.
            obj_types: Comma-separated section names to restrict to, e.g.
                       "addresses,address_groups" or "security_rules_pre".
            limit: Maximum hits (1-500, default 50).
            include_predefined: Include Palo Alto's shipped App-ID signatures in
                       results. Off by default so the tenant's own config is not
                       buried; only has an effect if the index was built with
                       scm_config_index(include_predefined=True).

        Returns:
            Markdown results grouped by object type, or guidance if nothing is
            indexed yet.
        """
        try:
            status = index_status()
            if not status:
                return (
                    "No config index yet — nothing to search.\n\n"
                    "Build one first:\n\n"
                    f'    scm_config_index(folder="Prisma Access", tenant_id="{tenant_id}")\n\n'
                    "or `scm_config_index(all_tenants=True)` to index the whole estate."
                )

            requested = [t.strip() for t in obj_types.split(",") if t.strip()]
            unknown = [t for t in requested if t not in INDEXABLE_FIELDS]
            if unknown:
                return (
                    f"Unknown obj_types: {', '.join(unknown)}.\n\n"
                    "Valid sections include: addresses, address_groups, services, "
                    "service_groups, tags, edls, applications, security_rules_pre, "
                    "security_rules_post, nat_rules_pre, nat_rules_post, decryption_rules, "
                    "zones, ike_gateways, ipsec_tunnels, remote_networks, service_connections."
                )

            scoped = [s for s in status if not tenant_id or s["tenant_id"] == tenant_id]
            if tenant_id and not scoped:
                indexed = ", ".join(sorted({s["tenant_id"] for s in status}))
                return (
                    f"Tenant `{tenant_id}` is not indexed. Indexed tenants: {indexed}.\n\n"
                    f'Run `scm_config_index(tenant_id="{tenant_id}")` first.'
                )

            hits, mode = search(
                query,
                tenant_ids=[tenant_id] if tenant_id else None,
                folder=folder,
                obj_types=requested or None,
                limit=limit,
                include_predefined=include_predefined,
            )
            logger.info("object_search", query=query[:80], mode=mode, hits=len(hits))

            covered = ", ".join(
                f"{s['tenant_label'] or s['tenant_id']}/{s['folder']} ({_age(s['indexed_at'])})"
                for s in scoped
            )
            footer = f"\n---\n**Index:** {covered}"

            if not hits:
                return (
                    f"No matches for `{query}`.\n\n"
                    "The index only holds what was present at build time — if the object is "
                    "new, re-run `scm_config_index` for its tenant."
                    f"{footer}"
                )

            cross_tenant = len({h.tenant_id for h in hits}) > 1
            return _render_hits(hits, query, mode, cross_tenant) + footer
        except Exception as exc:
            return f"Error: {handle_scm_exception(exc, tool='scm_object_search')}"
