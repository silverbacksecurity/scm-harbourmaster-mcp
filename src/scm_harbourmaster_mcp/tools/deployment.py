"""
MCP tools for SCM Deployment resources.

Covers: remote networks, service connections, bandwidth allocations,
        auto-scaling, commit/push operations, and config version management.
"""

from __future__ import annotations

import json
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..utils.errors import handle_scm_exception
from ..utils.formatting import format_result as _fmt
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool

logger = get_logger(__name__)

_CV_BASE = "/config/operations/v1/config-versions"


def _cv_get(client: Any, path: str) -> dict[str, Any]:
    """GET a config-version endpoint; returns parsed JSON dict or {} on any error."""
    try:
        result = client.get(path)
        if isinstance(result, dict):
            return result
    except Exception:
        pass
    return {}


def _age(ts: str | None) -> str:
    """Human-readable age from ISO timestamp."""
    if not ts:
        return "—"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        delta = datetime.now(UTC) - dt
        days = delta.days
        hours = delta.seconds // 3600
        if days > 0:
            return f"{days}d {hours}h ago"
        mins = delta.seconds // 60
        return f"{hours}h {mins % 60}m ago" if hours > 0 else f"{mins}m ago"
    except Exception:
        return ts


def register_deployment_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register all SCM Deployment tools onto the MCP server."""
    tool = scm_tool(get_client)
    tool = scm_tool(get_client)
    tool = scm_tool(get_client)

    # ── Remote Networks ─────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_remote_network_list(client: Any, folder: str, limit: int = 200) -> str:
        """List remote networks (branch/SD-WAN connections) in SCM.

        Args:
            folder: SCM folder (unused — remote networks always live in the
                    fixed "Remote Networks" container; kept for interface
                    consistency with the other _list tools).
            tenant_id: SCM tenant ID.
            limit: Maximum results.
        """
        results = client.remote_network.list(folder="Remote Networks")[: max(0, limit)]
        return _fmt(results)

    @mcp.tool()
    @tool
    def scm_remote_network_get(client: Any, name: str, folder: str) -> str:
        """Fetch details for a single remote network.

        Args:
            name: Remote network name.
            folder: SCM folder (unused — see scm_remote_network_list).
            tenant_id: SCM tenant ID.
        """
        obj = client.remote_network.fetch(name=name, folder="Remote Networks")
        return _fmt(obj)

    # ── Service Connections ─────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_service_connection_list(client: Any, folder: str, limit: int = 200) -> str:
        """List service connections (cloud/DC interconnects) in SCM.

        Args:
            folder: SCM folder.
            tenant_id: SCM tenant ID.
            limit: Maximum results.
        """
        results = client.service_connection.list()[: max(0, limit)]
        return _fmt(results)

    # ── Bandwidth Allocations ───────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_bandwidth_allocation_list(client: Any, folder: str, limit: int = 200) -> str:
        """List bandwidth allocations for Prisma Access compute locations.

        Args:
            folder: SCM folder.
            tenant_id: SCM tenant ID.
            limit: Maximum results.
        """
        results = client.bandwidth_allocation.list()[: max(0, limit)]
        return _fmt(results)

    # ── Commit ──────────────────────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_commit(client: Any, folders: list[str], description: str = "", admin: str = "") -> str:
        """Commit pending SCM configuration changes.

        Commits the candidate config for the listed folders.  This is
        the equivalent of 'commit' on a firewall — required after any
        create/update/delete operation to make changes effective.

        Args:
            folders: Folders whose changes to commit.
            description: Commit description / change ticket reference.
            tenant_id: SCM tenant ID.
            admin: Optional admin name to attribute the commit to.
        """
        result = client.commit(
            folders=folders,
            description=description or "Committed via scm-harbourmaster-mcp",
            sync=True,
            timeout=300,
        )
        logger.info("commit_triggered", folders=folders, job_id=getattr(result, "job_id", None))
        return _fmt(result)

    @mcp.tool()
    @tool
    def scm_job_status(client: Any, job_id: str) -> str:
        """Check the status of an asynchronous SCM job (e.g. commit).

        Args:
            job_id: Job ID returned by commit or other async operations.
            tenant_id: SCM tenant ID.
        """
        result = client.get_job_status(job_id)
        return _fmt(result)

    @mcp.tool()
    @tool
    def scm_list_jobs(client: Any, limit: int = 50, offset: int = 0, job_type: str = "") -> str:
        """List SCM configuration jobs (commits, pushes) showing who triggered each one.

        Returns recent jobs ordered newest-first, including the SCM username (uname)
        who triggered each job, the job type, result, timestamps, and description.
        Use this to audit commit history, find who last changed config, or investigate
        failed pushes.

        Job types include: Commit, CommitAndPush, NGFW_Push, PA_Push.
        Result values: OK, FAIL, PENDING, RUNNING.

        Args:
            tenant_id: SCM tenant ID. Defaults to the configured default tenant.
            limit: Maximum jobs to return (default 50, max 200).
            offset: Pagination offset.
            job_type: Optional filter — e.g. "Commit" or "NGFW_Push".
        """
        response = client.list_jobs(limit=min(limit, 200), offset=offset)

        jobs = response.data if hasattr(response, "data") else []

        # Optional client-side type filter (SDK doesn't support server-side type filter)
        if job_type:
            jobs = [
                j for j in jobs if job_type.lower() in (getattr(j, "type_str", "") or "").lower()
            ]

        if not jobs:
            return json.dumps({"total": 0, "jobs": [], "note": "No jobs found."})

        rows = []
        for j in jobs:
            rows.append(
                {
                    "job_id": getattr(j, "id", ""),
                    "type": getattr(j, "type_str", getattr(j, "job_type", "")),
                    "result": getattr(j, "result_str", ""),
                    "user": getattr(j, "uname", ""),
                    "description": getattr(j, "description", ""),
                    "start_ts": str(getattr(j, "start_ts", "")),
                    "end_ts": str(getattr(j, "end_ts", "")),
                    "percent": getattr(j, "percent", ""),
                    "parent_id": getattr(j, "parent_id", None),
                }
            )

        total = getattr(response, "total", len(rows))
        return json.dumps(
            {
                "total": total,
                "showing": len(rows),
                "offset": offset,
                "jobs": rows,
            },
            indent=2,
            default=str,
        )

    # ── Config Version Management ────────────────────────────────────────────

    @mcp.tool()
    @tool
    def scm_config_versions(client: Any, tenant_id: str) -> str:
        """List SCM configuration versions with timestamps, descriptions, and running state.

        Shows the full version history of committed configs for this tenant.
        The running version is the currently active config on Prisma Access.
        Use version numbers with scm_config_rollback to revert to a prior state.

        Args:
            tenant_id: SCM tenant ID. Defaults to the configured default tenant.
        """
        raw = _cv_get(client, _CV_BASE)
        versions: list[dict[str, Any]] = raw.get("data", []) if raw else []

        # Fetch running version per scope (Mobile Users, Remote Networks, ...) to annotate
        running_by_scope: dict[str, Any] = {}
        try:
            running_raw = _cv_get(client, f"{_CV_BASE}/running")
            for entry in running_raw.get("data") or []:
                device = entry.get("device")
                if device:
                    running_by_scope[device] = entry.get("version")
        except Exception:
            pass

        if not versions:
            running_summary = (
                ", ".join(f"{k}={v}" for k, v in running_by_scope.items()) or "unknown"
            )
            return (
                "No config versions found. Config versions are saved after each commit.\n\n"
                f"Running versions: {running_summary}"
            )

        col_w = (12, 24, 10, 40)
        header = (
            f"{'Version':<{col_w[0]}}  {'Committed':<{col_w[1]}}  "
            f"{'Admin':<{col_w[2]}}  {'Description':<{col_w[3]}}"
        )
        sep = "  ".join("─" * w for w in col_w)

        rows = [header, sep]
        for v in versions:
            ver = str(v.get("version", "?"))
            ts = _age(v.get("created_at") or v.get("timestamp") or v.get("date"))
            admin = str(v.get("created_by") or v.get("admin") or v.get("uname") or "—")[: col_w[2]]
            desc = str(v.get("description") or "—")[: col_w[3]]
            scope = v.get("scope")
            flag = (
                " ◀ running"
                if scope and str(running_by_scope.get(scope)) == str(v.get("version"))
                else ""
            )
            rows.append(
                f"{ver:<{col_w[0]}}  {ts:<{col_w[1]}}  {admin:<{col_w[2]}}  {desc:<{col_w[3]}}{flag}"
            )

        lines = [
            f"## Config Versions — {tenant_id or 'default tenant'}",
            "",
            f"Total versions: {raw.get('total', len(versions))}  "
            f"|  Running: {', '.join(f'{k}={v}' for k, v in running_by_scope.items()) or 'unknown'}",
            "",
            "```",
            *rows,
            "```",
            "",
            "Use `scm_config_rollback(version=N)` to load any version back to candidate.",
        ]
        return "\n".join(lines)

    @mcp.tool()
    @tool
    def scm_config_push_track(
        client: Any,
        tenant_id: str,
        folders: list[str],
        description: str = "",
        timeout: int = 300,
        rollback_on_failure: bool = False,
    ) -> str:
        """Push candidate config with async job tracking and optional auto-rollback.

        Unlike scm_commit (which blocks silently), this tool polls the job every
        10 seconds and streams progress, then returns a rich result including
        warnings, affected devices, push duration, and rollback status if used.

        When rollback_on_failure=True, if the push job fails the tool automatically
        loads the last known-good running version back to candidate — so the next
        commit restores the previous state.

        Args:
            folders: Folders whose changes to push (e.g. ["Prisma Access"]).
            description: Commit description or change-ticket reference.
            timeout: Max seconds to wait for the push job (default 300).
            rollback_on_failure: If True, auto-load the previous running version on failure.
            tenant_id: SCM tenant ID. Defaults to the configured default tenant.
        """
        try:
            # Snapshot running version per pushed folder (for rollback capability).
            # The /running endpoint reports one running version per scope
            # (e.g. "Remote Networks", "Mobile Users"), not a single global version.
            rollback_versions: dict[str, Any] = {}
            if rollback_on_failure:
                try:
                    running_raw = _cv_get(client, f"{_CV_BASE}/running")
                    for entry in running_raw.get("data") or []:
                        device = entry.get("device")
                        if device in folders:
                            rollback_versions[device] = entry.get("version")
                except Exception:
                    pass

            desc = description or "Push via scm-harbourmaster-mcp"
            logger.info("config_push_start", folders=folders, tenant_id=tenant_id, desc=desc)

            # Start push async
            push_result = client.commit(
                folders=folders,
                description=desc,
                sync=False,
            )
            job_id = getattr(push_result, "job_id", None) or str(push_result)
            logger.info("config_push_job_started", job_id=job_id, tenant_id=tenant_id)

            # Poll until complete
            final = client.wait_for_job(job_id, timeout=timeout, poll_interval=10)

            if not final or not final.data:
                return f"Push job {job_id} started but status could not be retrieved within {timeout}s."

            job = final.data[0]
            result_str = job.result_str  # "OK" | "FAIL"
            status_str = job.status_str  # "FIN" | etc.
            percent = job.percent
            details = job.details or ""
            summary = job.summary or ""
            duration_s = ""
            if job.start_ts and job.end_ts:
                secs = int((job.end_ts - job.start_ts).total_seconds())
                duration_s = f"{secs}s" if secs < 60 else f"{secs // 60}m {secs % 60}s"

            success = result_str == "OK"
            icon = "✅" if success else "❌"
            logger.info(
                "config_push_complete",
                job_id=job_id,
                result=result_str,
                percent=percent,
                duration=duration_s,
                tenant_id=tenant_id,
            )

            rollback_note = ""
            if not success and rollback_on_failure:
                if rollback_versions:
                    loaded: list[str] = []
                    failed: list[str] = []
                    for scope, ver in rollback_versions.items():
                        try:
                            client.post(f"{_CV_BASE}/{ver}:load")
                            loaded.append(f"{scope} → v{ver}")
                        except Exception as rb_exc:
                            failed.append(f"{scope}: {rb_exc}")
                    if loaded:
                        rollback_note = (
                            f"\n\n**Auto-rollback triggered**: {', '.join(loaded)} "
                            "loaded to candidate. Run `scm_commit` to restore the previous config."
                        )
                    if failed:
                        rollback_note += f"\n\n**Auto-rollback FAILED** for: {'; '.join(failed)}"
                    logger.warning(
                        "config_push_rollback",
                        job_id=job_id,
                        rollback_versions=rollback_versions,
                        tenant_id=tenant_id,
                    )
                else:
                    rollback_note = "\n\n**Auto-rollback skipped**: could not determine running version before push."

            lines = [
                f"## {icon} Config Push — {result_str}",
                "",
                "| Field | Value |",
                "|---|---|",
                f"| Job ID | `{job_id}` |",
                f"| Status | {status_str} ({percent}%) |",
                f"| Result | **{result_str}** |",
                f"| Duration | {duration_s or '—'} |",
                f"| Folders | {', '.join(folders)} |",
                f"| Description | {desc} |",
            ]
            if summary:
                lines += ["", f"**Summary:** {summary}"]
            if details and details != "{}":
                # Try to pretty-print JSON details
                try:
                    det = json.loads(details) if isinstance(details, str) else details
                    lines += ["", "**Details:**", "```json", json.dumps(det, indent=2), "```"]
                except Exception:
                    lines += ["", f"**Details:** {details}"]
            if rollback_note:
                lines.append(rollback_note)

            return "\n".join(lines)

        except TimeoutError:
            return (
                f"Push job timed out after {timeout}s. "
                "Use `scm_job_status` with the job ID to check completion, "
                "or `scm_list_jobs` to find the job."
            )
        except Exception as exc:
            return f"Error: {handle_scm_exception(exc, tool='scm_config_push_track', tenant_id=tenant_id)}"

    @mcp.tool()
    @tool
    def scm_config_rollback(
        client: Any,
        tenant_id: str,
        version: int,
        commit_immediately: bool = False,
        description: str = "",
    ) -> str:
        """Load a previous SCM config version back to candidate for recommit.

        This is a two-phase safety operation:
          1. Load — copies the specified version into the candidate config
          2. Commit — optional; if commit_immediately=True, commits the candidate right away

        Run `scm_config_versions` first to see the version history.

        Args:
            version: The config version number to roll back to.
            commit_immediately: If True, commit the loaded version immediately after loading.
            description: Commit description when commit_immediately=True.
            tenant_id: SCM tenant ID. Defaults to the configured default tenant.
        """
        ver_info: dict[str, Any] = {}
        with suppress(Exception):
            raw_ver = client.get(f"{_CV_BASE}/{version}")
            if isinstance(raw_ver, list) and raw_ver:
                ver_info = raw_ver[0]
            elif isinstance(raw_ver, dict):
                ver_info = raw_ver

        ver_date = (
            ver_info.get("created_at")
            or ver_info.get("timestamp")
            or ver_info.get("date")
            or "unknown date"
        )
        ver_desc = ver_info.get("description") or "—"
        ver_admin = ver_info.get("created_by") or ver_info.get("admin") or "—"

        # Load the version to candidate
        logger.info(
            "config_rollback_start",
            version=version,
            tenant_id=tenant_id,
            commit_immediately=commit_immediately,
        )
        client.post(f"{_CV_BASE}/{version}:load")
        logger.info("config_rollback_loaded", version=version, tenant_id=tenant_id)

        lines = [
            f"## Config Rollback — Version {version} Loaded to Candidate",
            "",
            "| Field | Value |",
            "|---|---|",
            f"| Version | {version} |",
            f"| Originally committed | {_age(str(ver_date))} ({ver_date}) |",
            f"| Original description | {ver_desc} |",
            f"| Original admin | {ver_admin} |",
        ]

        if commit_immediately:
            desc = description or f"Rollback to version {version} via scm-harbourmaster-mcp"
            commit_result = client.commit(
                folders=["all"],
                description=desc,
                sync=True,
                timeout=300,
            )
            job_id = getattr(commit_result, "job_id", "—")
            logger.info(
                "config_rollback_committed",
                version=version,
                job_id=job_id,
                tenant_id=tenant_id,
            )
            lines += [
                "",
                f"✅ **Committed immediately** — Job ID: `{job_id}`",
                f"Description: _{desc}_",
            ]
        else:
            lines += [
                "",
                "✅ Version loaded to candidate. **No changes have been pushed yet.**",
                "",
                "Next steps:",
                "1. Review the candidate config in the SCM UI if desired",
                "2. Run `scm_commit(folders=[...])` to push the rollback to Prisma Access",
                "   or `scm_config_push_track(folders=[...])` for tracked push with rollback protection",
            ]

        return "\n".join(lines)
