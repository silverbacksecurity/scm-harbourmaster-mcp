"""
MCP tools for migrating a Panorama device group or a firewall vsys into SCM.

Tools:
    scm_panorama_migrate         — dry run (synchronous) or apply (background job)
    scm_panorama_migrate_result  — the apply job's report

The export is translated into a config backup (``audit/panos_import.py``) and
pushed with ``clone_config``, so the migration gets the clone's dependency
order, reference preflight, ``on_conflict`` and ``name_prefix`` handling.
The translated backup is written next to the other backups
(``backups/migrations/``) as the migration plan's record.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..audit.clone_preflight import MISSING_REFERENCE_MODES
from ..audit.cloner import ON_CONFLICT_MODES, CloneReport, clone_config
from ..audit.panos_import import Conversion, PanosImportError, convert, load_xml, plan_markdown
from ..utils.errors import handle_scm_exception
from ..utils.logging import get_logger
from ..utils.paths import backup_dir
from ..utils.write_safety import audit_write, normalize_ticket_ref, ticket_ref_error
from .audit import write_config_backup

logger = get_logger(__name__)

# Apply jobs, kept for 1 hour like the other background jobs (a running job
# is never pruned: its thread still writes to its entry)
_MIGRATE_JOBS: dict[str, dict[str, Any]] = {}
_JOBS_LOCK = threading.Lock()
_JOB_TTL = 3600


def _prune_jobs() -> None:
    cutoff = time.time() - _JOB_TTL
    with _JOBS_LOCK:
        for jid in [
            j
            for j, meta in _MIGRATE_JOBS.items()
            if meta["started_at"] < cutoff and meta["status"] != "running"
        ]:
            del _MIGRATE_JOBS[jid]


def _write_plan(conv: Conversion) -> str:
    """Write the translated backup under backups/migrations/; returns its path."""
    out = backup_dir() / "migrations"
    out.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC)
    label = str(conv.backup["folder"]).replace("/", "_").replace(" ", "-")
    path = out / f"panos_migration_{label}_{now:%Y%m%dT%H%M%SZ}.json"
    data = {
        **conv.backup,
        "generated_at": now.isoformat(),
        "plan_items": [i.__dict__ for i in conv.items],
    }
    path.write_text(json.dumps(data, indent=2, default=str))
    return str(path)


_FIX_REFERENCES = (
    "Fix the missing references, or re-run with "
    "on_missing_reference='skip_object' or 'strip_member'."
)


def _blocked(report: CloneReport) -> bool:
    return report.preflight is not None and report.preflight.blocked


def _render(
    conv: Conversion,
    plan_path: str,
    target_folder: str,
    mode: str,
    report: CloneReport,
    pre: list[str] | None = None,
    post: list[str] | None = None,
) -> str:
    """Header, *pre* lines, the migration plan, the clone report, *post* lines."""
    return "\n".join(
        [
            f"# Panorama → SCM migration — {mode}",
            "",
            f"**Source:** {conv.source}  ",
            f"**Target folder:** `{target_folder}`  ",
            f"**Translated backup:** `{plan_path}`",
            "",
            *(pre or []),
            *plan_markdown(conv),
            "",
            report.to_markdown(),
            *(post or []),
        ]
    )


def _next_steps(backup_path: str, target_folder: str) -> list[str]:
    return [
        "\n## Next steps\n",
        f"1. Compare with the pre-migration backup: `scm_config_diff` against `{backup_path}`.",
        f"2. Check the result: `scm_bpa_assess(folder='{target_folder}')` and "
        f"`scm_rule_shadow_audit(folder='{target_folder}')`.",
        "3. Work through the plan's review, manual and not-migrated items.",
        "4. Nothing is committed: push with `scm_commit` when ready. To undo, "
        f"restore `{backup_path}` with `scm_config_clone(on_conflict='overwrite')` "
        "and delete the migrated objects.",
    ]


def register_panorama_migrate_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register the Panorama/PAN-OS migration tools onto the MCP server."""

    @mcp.tool()
    def scm_panorama_migrate(
        xml_path: str,
        target_folder: str,
        device_group: str = "",
        vsys: str = "",
        tenant_id: str = "",
        name_prefix: str = "",
        on_conflict: str = "skip",
        on_missing_reference: str = "fail",
        include_rules: bool = True,
        resource_filter: str = "",
        dry_run: bool = True,
        ticket_ref: str = "",
    ) -> str:
        """Migrate a Panorama device group or a firewall vsys into an SCM folder.

        Reads an offline config export (Panorama: Panorama > Setup > Operations >
        Export named Panorama configuration snapshot; firewall: Device > Setup >
        Operations > Export named configuration snapshot).
        No Panorama or firewall API access is needed.

        One device group plus everything it inherits (parent device groups and
        Panorama `shared`) goes into one SCM folder.  A name defined at several
        levels resolves to the nearest, as PAN-OS does.  Rules keep PAN-OS
        evaluation order: shared pre → parent pre → device-group pre, then
        device-group post → parent post → shared post.

        Migrated: tags, addresses, address groups, services, service groups,
        EDLs, custom URL categories, application groups and filters,
        anti-spyware, vulnerability, URL filtering, file blocking, WildFire and
        decryption profiles, profile groups, and security (pre/post), NAT
        (pre/post), decryption and application-override rules.

        Handled explicitly, never silently (each is a row in the plan):
          * Rules with individual profiles get a generated profile group
            (SCM rules take groups only); identical sets share one group.
          * Antivirus profiles can't be created over the SCM API — manual.
          * Schedules, device targeting, legacy HIP profiles and rule types
            other than universal are dropped and flagged for review.
          * Service source ports, URL `override` categories and EDL
            credentials are dropped and flagged.
          * Custom applications, HIP objects, log forwarding profiles, PBF and
            other rulebases are listed as not migrated.
          * Any object that fails pan-scm-sdk validation is listed with the error.

        dry_run=True (default) translates the export, writes the translated
        backup to backups/migrations/, and runs scm_config_clone's dry run with
        the reference preflight against the target — returns at once.
        dry_run=False runs the same check, refuses at once if the preflight
        would block, otherwise backs up the target folder and pushes in a
        background job: poll scm_panorama_migrate_result(job_id).  Nothing is
        committed or pushed to devices.

        Args:
            xml_path: Path to the exported config XML on the server.
            target_folder: Existing SCM folder to migrate into.
            device_group: Panorama device group (Panorama exports).
            vsys: Firewall vsys (firewall exports; default vsys1).
            tenant_id: Target tenant (default: the default tenant).
            name_prefix: Optional prefix for every migrated object name;
                references are rewritten to match.
            on_conflict: 'skip' (default) or 'overwrite' an object of the same
                name in the target.
            on_missing_reference: 'fail' (default), 'skip_object' or
                'strip_member' — the clone preflight's handling of references
                the target can't resolve.
            include_rules: False migrates objects and profiles only.
            resource_filter: Optional comma-separated backup keys to migrate
                (e.g. "addresses,address_groups").
            dry_run: If True (default) preview; False applies in the background.
            ticket_ref: Mandatory change-ticket reference (never sent to SCM).

        **Write safety (SSR pattern):** ``dry_run=True`` by default;
        ``ticket_ref`` is mandatory.
        """
        err = ticket_ref_error(ticket_ref)
        if err:
            return f"Error: {err}"
        ticket_ref = normalize_ticket_ref(ticket_ref)
        if on_conflict not in ON_CONFLICT_MODES:
            return f"Error: on_conflict must be one of {', '.join(ON_CONFLICT_MODES)}"
        if on_missing_reference not in MISSING_REFERENCE_MODES:
            return (
                f"Error: on_missing_reference must be one of {', '.join(MISSING_REFERENCE_MODES)}"
            )
        if not target_folder:
            return "Error: target_folder is required"
        filt = {k.strip() for k in resource_filter.split(",") if k.strip()} or None

        try:
            conv = convert(
                load_xml(xml_path),
                device_group=device_group,
                vsys=vsys,
                include_rules=include_rules,
            )
        except PanosImportError as exc:
            return f"Error: {exc}"
        plan_path = _write_plan(conv)
        logger.info(
            "panos_migration_translated",
            source=conv.source,
            plan=plan_path,
            objects=sum(conv.counts().values()),
            items=len(conv.items),
        )

        def _clone(client: Any, dry: bool) -> CloneReport:
            report = clone_config(
                client,
                source_backup_file=plan_path,
                target_folder=target_folder,
                name_prefix=name_prefix,
                on_conflict=on_conflict,
                dry_run=dry,
                skip_rules=not include_rules,
                resource_filter=filt,
                on_missing_reference=on_missing_reference,
            )
            report.target_tenant_id = tenant_id
            return report

        try:
            client = get_client(tenant_id)
            # The apply runs the same dry run first: a blocked preflight is
            # refused before the (slow) target backup, not inside the job.
            report = _clone(client, True)
            if dry_run:
                if _blocked(report):
                    advice = "The reference preflight would block an apply. " + _FIX_REFERENCES
                else:
                    advice = (
                        "Re-run with `dry_run=False` and the same `ticket_ref` to apply "
                        "(a backup of the target folder is taken first)."
                    )
                return _render(
                    conv,
                    plan_path,
                    target_folder,
                    "DRY-RUN",
                    report,
                    post=["", "No changes written. " + advice],
                )
            if _blocked(report):
                return _render(
                    conv,
                    plan_path,
                    target_folder,
                    "REFUSED",
                    report,
                    pre=[
                        "**Nothing was written:** the reference preflight would block the "
                        "push. " + _FIX_REFERENCES,
                        "",
                    ],
                )

            audit_write(
                "scm_panorama_migrate",
                ticket_ref,
                tenant_id,
                xml_path=xml_path,
                source=conv.source,
                target_folder=target_folder,
            )
        except Exception as exc:
            return f"Error: {handle_scm_exception(exc, tool='scm_panorama_migrate')}"

        _prune_jobs()
        job_id = uuid.uuid4().hex[:8]
        with _JOBS_LOCK:
            _MIGRATE_JOBS[job_id] = {
                "status": "running",
                "stage": "backing up the target folder",
                "started_at": time.time(),
                "result": None,
                "error": None,
            }

        def _run() -> None:
            try:
                backup_path, _ = write_config_backup(client, tenant_id, target_folder)
                with _JOBS_LOCK:
                    _MIGRATE_JOBS[job_id]["stage"] = "pushing"
                applied = _clone(client, False)
                if _blocked(applied):
                    # The target changed between the check and the push
                    post = [
                        "\n**Nothing was written:** the reference preflight blocked the "
                        "push. " + _FIX_REFERENCES
                    ]
                else:
                    post = _next_steps(str(backup_path), target_folder)
                result = _render(
                    conv,
                    plan_path,
                    target_folder,
                    "APPLY",
                    applied,
                    pre=[f"**Pre-migration backup:** `{backup_path}`", ""],
                    post=post,
                )
                with _JOBS_LOCK:
                    _MIGRATE_JOBS[job_id]["status"] = "done"
                    _MIGRATE_JOBS[job_id]["result"] = result
                logger.info(
                    "panos_migration_applied",
                    job_id=job_id,
                    created=applied.created,
                    failed=sum(1 for r in applied.results if r.status == "failed"),
                )
            except Exception as exc:
                logger.error("panos_migration_failed", job_id=job_id, error=str(exc))
                with _JOBS_LOCK:
                    _MIGRATE_JOBS[job_id]["status"] = "error"
                    _MIGRATE_JOBS[job_id]["error"] = handle_scm_exception(exc)

        threading.Thread(target=_run, daemon=True, name=f"panos-migrate-{job_id}").start()
        return (
            f"Migration of {conv.source} into `{target_folder}` started (job `{job_id}`).\n\n"
            "It backs up the target folder first, then pushes. When ready:\n\n"
            f'    scm_panorama_migrate_result(job_id="{job_id}")'
        )

    @mcp.tool()
    def scm_panorama_migrate_result(job_id: str) -> str:
        """Retrieve the report of a scm_panorama_migrate apply job.

        Args:
            job_id: Job ID returned by scm_panorama_migrate(dry_run=False)
                    (jobs are kept for 1 hour).

        Returns:
            The migration plan and push report, or the job's status if it is
            still running.
        """
        with _JOBS_LOCK:
            job = dict(_MIGRATE_JOBS.get(job_id, {}))
        if not job:
            # Other jobs' IDs aren't listed: on a shared server they may be
            # another tenant's migration
            return f"Migration job `{job_id}` not found (finished jobs expire after 1 hour)."
        mins, secs = divmod(int(time.time() - job["started_at"]), 60)
        if job["status"] == "running":
            return (
                f"Migration job `{job_id}` still running ({mins}m {secs}s, {job['stage']}). "
                "Check again shortly."
            )
        if job["status"] == "error":
            return f"Migration job `{job_id}` failed after {mins}m {secs}s: {job['error']}"
        return str(job["result"])
