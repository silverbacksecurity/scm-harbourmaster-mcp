"""
Shared create path for every ``scm_create_*_snippet`` tool.

``build_and_create_snippet()`` takes a ``SnippetSpec`` and runs the SSR
write-safety flow the NCSC/NIST snippet tools established: mandatory
``ticket_ref``, dry run by default, create the snippet container (an existing
one is reused), then each object in order — "already exists" is a skip, any
other error is a failure that does not stop the run.

With ``associate_folder`` set (off by default) a clean apply also associates
the snippet with that folder through ``PUT /config/setup/v1/folders/{id}``,
the same call the config cloner uses (``audit.cloner._associate_snippets``).
"""

from __future__ import annotations

from typing import Any

from ..audit.cloner import _associate_snippets
from ..audit.snippet_blocks import SnippetSpec
from ..utils.logging import get_logger
from ..utils.write_safety import audit_write, normalize_ticket_ref, ticket_ref_error

logger = get_logger(__name__)


def _is_duplicate(msg: str) -> bool:
    low = msg.lower()
    return "already exists" in low or "duplicate" in low


def build_and_create_snippet(
    client: Any,
    spec: SnippetSpec,
    *,
    tool_name: str,
    tenant_id: str,
    description: str,
    dry_run: bool = True,
    ticket_ref: str = "",
    associate_folder: str = "",
) -> str:
    """Create (or dry-run) the snippet described by *spec*; returns Markdown.

    Args:
        client: pan-scm-sdk client for the target tenant.
        spec: Snippet name, ordered payload sections and output wording.
        tool_name: Calling MCP tool, recorded in the write audit log.
        tenant_id: Tenant the write targets (audit log only).
        description: Description for the snippet container.
        dry_run: If True (default) report what WOULD be created; no API calls.
        ticket_ref: Mandatory change-ticket reference (never sent to SCM).
        associate_folder: Optional folder to associate the snippet with after
            a clean apply. Empty (default) leaves association to the operator.
    """
    err = ticket_ref_error(ticket_ref)
    if err:
        return f"Error: {err}"
    ticket_ref = normalize_ticket_ref(ticket_ref)
    snippet_name = spec.snippet
    if not dry_run:
        extra = {"associate_folder": associate_folder} if associate_folder else {}
        audit_write(tool_name, ticket_ref, tenant_id, snippet_name=snippet_name, **extra)

    results: list[str] = []
    created = 0
    skipped = 0
    failed = 0
    mode = "DRY-RUN" if dry_run else "APPLY"
    results.append(f"## {spec.label} Snippet — {mode}: '{snippet_name}'\n")

    # ── Step 1: create snippet container ──────────────────────────────────────
    results.append("### Step 1: Snippet Container")
    snippet_payload = {
        "name": snippet_name,
        "description": description,
        "enable_prefix": False,
    }
    if dry_run:
        results.append(f"  [DRY-RUN] would create snippet '{snippet_name}'")
    else:
        try:
            snip = client.snippet.create(snippet_payload)
            results.append(
                f"  [OK] Created snippet '{snippet_name}' (id={getattr(snip, 'id', '?')})"
            )
        except Exception as exc:
            msg = str(exc)
            if _is_duplicate(msg):
                results.append(f"  [OK] Snippet '{snippet_name}' already exists — continuing")
            else:
                results.append(f"  [FAIL] Could not create snippet: {msg}")
                results.append("\nAborting — snippet container is required.")
                return "\n".join(results)

    # ── Steps 2..n: populate objects ──────────────────────────────────────────

    def _apply(sdk_attr: str, payload: dict[str, Any], display_name: str) -> None:
        nonlocal created, skipped, failed
        if dry_run:
            results.append(f"  [DRY-RUN] would create {display_name}")
            created += 1
            return

        resource = getattr(client, sdk_attr, None)
        if resource is None:
            results.append(f"  [SKIP] {display_name} — SDK attr '{sdk_attr}' not available")
            skipped += 1
            return

        try:
            obj = resource.create(payload)
            results.append(f"  [OK] Created {display_name} (id={getattr(obj, 'id', '?')})")
            created += 1
        except Exception as exc:
            msg = str(exc)
            if _is_duplicate(msg):
                results.append(f"  [SKIP] {display_name} already exists")
                skipped += 1
            else:
                results.append(f"  [FAIL] {display_name}: {msg}")
                failed += 1
                logger.warning(spec.log_event, object=display_name, error=msg)

    step = 1
    for heading, objects in spec.sections:
        step += 1
        results.append(f"\n### Step {step}: {heading}")
        for sdk_attr, payload in objects:
            _apply(sdk_attr, payload, payload["name"])

    # ── Optional: associate with a folder ─────────────────────────────────────
    # None = not requested; True = associated (or already was); False = failed
    associated: bool | None = None
    if associate_folder:
        step += 1
        results.append(f"\n### Step {step}: Folder Association")
        if dry_run:
            results.append(
                f"  [DRY-RUN] would associate snippet '{snippet_name}' "
                f"with folder '{associate_folder}'"
            )
        elif failed:
            # A half-populated snippet must not start flowing into a folder
            results.append(
                f"  [SKIP] Not associating with '{associate_folder}' — {failed} object(s) failed"
            )
        else:
            try:
                added = _associate_snippets(client.session, associate_folder, [snippet_name])
                associated = True
                if added:
                    results.append(
                        f"  [OK] Associated snippet '{snippet_name}' "
                        f"with folder '{associate_folder}'"
                    )
                else:
                    results.append(
                        f"  [OK] Snippet '{snippet_name}' already associated "
                        f"with folder '{associate_folder}'"
                    )
            except Exception as exc:
                associated = False
                msg = str(exc)
                results.append(f"  [FAIL] Could not associate with '{associate_folder}': {msg}")
                logger.warning(
                    "snippet_associate_failed",
                    snippet=snippet_name,
                    folder=associate_folder,
                    error=msg,
                )

    results.append("\n### Summary")
    results.append(f"  Created: {created} | Skipped: {skipped} | Failed: {failed}")

    if dry_run:
        note = f"\n\nNote: {spec.dry_run_note}" if spec.dry_run_note else ""
        results.append(
            "\nNo changes written. Re-run with `dry_run=False` and the same `ticket_ref` to apply."
            + note
        )
    elif failed == 0:
        if associated is None:
            first = "Assign this snippet to tenants/folders via the SCM portal or API"
        elif associated:
            first = (
                f"Push folder '{associate_folder}' to activate: "
                f"`scm_commit(folders=['{associate_folder}'], ticket_ref=..., dry_run=False)`"
            )
        else:
            first = (
                f"Associate this snippet with folder '{associate_folder}' via the SCM portal "
                "(automatic association failed — see above)"
            )
        steps = "\n".join(f"  {i}. {s}" for i, s in enumerate((first, *spec.next_steps), start=1))
        results.append(
            f"\n**{spec.label} snippet '{snippet_name}' created.**\nNext steps:\n{steps}"
        )
    else:
        results.append(f"\n{failed} object(s) failed — see errors above.")

    return "\n".join(results)
