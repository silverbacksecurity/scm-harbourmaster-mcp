"""MCP tool for SSR — Simple Service Requests (restricted customer-change CRUD).

A single machine-first tool (``scm_ssr_execute``) automating the three commonest
MSSP customer change requests:

    * URL allow/block-listing — add/remove URLs in SSR-managed custom URL categories
    * Threat exceptions — include/exclude threat IDs in anti-spyware /
      vulnerability protection profiles
    * SSL decryption exclusions — add/remove URL categories on a no-decrypt rule

Every operation reduces to the same primitive: add or remove an entry in a
designated SSR-managed object.  The tool only touches objects named in the
per-tenant ``ssr_objects`` allowlist (in settings.toml) and never edits a
rulebase.

Contract:
    * Machine-first — always returns JSON
    * Idempotent — re-adding an existing entry returns ``already_present: true``
    * Dry-run by default — ``dry_run=True`` returns a before/after diff
    * Mandatory ``ticket_ref`` — echoed into object descriptions for provenance
    * Commit stays a separate ``scm_commit`` step so the orchestrator owns sign-off
"""

from __future__ import annotations

import json
import re
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..config.settings import load_all_tenant_configs
from ..utils.errors import handle_scm_exception
from ..utils.logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_VALID_OPERATIONS = ("url-allow-list", "url-block-list", "threat-exception", "ssl-decrypt-exclude")
_VALID_ACTIONS = ("add", "remove")

# Loose URL validation — rejects over-broad wildcards and clearly invalid input
_URL_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}$")
_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$")
_THREAT_ID_RE = re.compile(r"^\d{5,}$")  # PAN threat IDs are numeric, typically 5+ digits

_SSR_KEYS = {
    "url-allow-list": "url_allow_list",
    "url-block-list": "url_block_list",
    "threat-exception": "threat_exception_profiles",
    "ssl-decrypt-exclude": "ssl_decrypt_exclude_rule",
}


# ---------------------------------------------------------------------------
# Helpers — config loading
# ---------------------------------------------------------------------------


def _get_ssr_config(tenant_id: str) -> dict[str, str]:
    """Return the ``ssr_objects`` dict for *tenant_id*, or {} if not configured.

    When *tenant_id* is empty the first configured tenant's SSR objects are
    returned (single-tenant fallback). An explicit *tenant_id* that matches
    no configured tenant returns {} — never another tenant's allowlist, which
    would let a change request execute against object names approved for a
    different customer.
    """
    tenants = load_all_tenant_configs()
    if tenant_id:
        for _key, tc in tenants.items():
            if tc.tenant_id == tenant_id:
                return tc.ssr_objects
        return {}
    if tenants:
        first = next(iter(tenants.values()))
        return first.ssr_objects
    return {}


# ---------------------------------------------------------------------------
# Helpers — validation
# ---------------------------------------------------------------------------


def _validate_target(operation: str, target: str) -> str | None:
    """Return an error string if *target* is invalid for *operation*, else None."""
    if not target or not target.strip():
        return "`target` must be non-empty."

    t = target.strip()

    if operation in ("url-allow-list", "url-block-list"):
        # Accept FQDNs, URLs, and bare IPs
        if _IP_RE.match(t):
            return None
        # Strip protocol prefix if present
        clean = re.sub(r"^https?://", "", t)
        clean = clean.split("/")[0]  # just the host part
        if _URL_RE.match(clean):
            return None
        if "*" in t and t.count("*") > 2:
            return "URL contains too many wildcards — over-broad patterns like `*.com` are not allowed."
        if t == "*" or t == "*.*":
            return "Over-broad wildcard `*` is not allowed."
        # Allow single-wildcard FQDNs like *.example.com
        wildcard_re = re.compile(r"^\*\.[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}$")
        if wildcard_re.match(clean):
            return None
        return f"`{t}` does not look like a valid URL, FQDN, or IP address."

    if operation == "threat-exception":
        if not _THREAT_ID_RE.match(t):
            return f"`{t}` does not look like a valid PAN threat ID (expected 5+ digits)."
        return None

    if operation == "ssl-decrypt-exclude":
        # URL category name — just check it's a sensible string
        if len(t) < 2:
            return "SSL decrypt exclusion target (URL category name) must be at least 2 characters."
        return None

    return None


# ---------------------------------------------------------------------------
# Helpers — response builder
# ---------------------------------------------------------------------------


def _response(
    operation: str,
    target: str,
    dry_run: bool,
    ticket_ref: str,
    status: str,
    before: Any = None,
    after: Any = None,
    already_present: bool = False,
    already_absent: bool = False,
    error: str = "",
    commit_required: bool = False,
    extra: dict[str, Any] | None = None,
) -> str:
    """Build the standard SSR JSON response."""
    body: dict[str, Any] = {
        "operation": operation,
        "target": target,
        "dry_run": dry_run,
        "ticket_ref": ticket_ref,
        "status": status,
    }
    if error:
        body["error"] = error
    if before is not None:
        body["before"] = before
    if after is not None:
        body["after"] = after
    body["already_present"] = already_present
    body["already_absent"] = already_absent
    body["commit_required"] = commit_required
    if extra:
        body.update(extra)
    return json.dumps(body, indent=2, default=str)


# ---------------------------------------------------------------------------
# Operation handlers — URL allow/block-list
# ---------------------------------------------------------------------------


def _handle_url_list(
    client: Any,
    folder: str,
    target: str,
    action: str,
    ssr_config: dict[str, str],
    dry_run: bool,
    ticket_ref: str,
    operation: str,
) -> str:
    """Add/remove a URL in an SSR-managed custom URL category."""
    obj_name = ssr_config.get(
        "url_allow_list" if operation == "url-allow-list" else "url_block_list", ""
    )

    if not obj_name:
        return _response(
            operation,
            target,
            dry_run,
            ticket_ref,
            "error",
            error=f"No SSR-managed URL {'allow' if 'allow' in operation else 'block'} list configured. "
            f"Add `url_allow_list` / `url_block_list` to ssr_objects for this tenant.",
        )

    # Fetch current state
    obj = client.url_category.fetch(name=obj_name, folder=folder)
    before_data = obj.model_dump()
    current_list: list[str] = list(before_data.get("list") or [])

    target_clean = target.strip()

    if action == "add":
        if target_clean in current_list:
            return _response(
                operation,
                target,
                dry_run,
                ticket_ref,
                "planned" if dry_run else "applied",
                before=before_data,
                after=before_data,
                already_present=True,
            )
        after_list = sorted(set(current_list + [target_clean]))
        after_data = {**before_data, "list": after_list}
    else:  # remove
        if target_clean not in current_list:
            return _response(
                operation,
                target,
                dry_run,
                ticket_ref,
                "planned" if dry_run else "applied",
                before=before_data,
                after=before_data,
                already_absent=True,
            )
        after_list = [u for u in current_list if u != target_clean]
        after_data = {**before_data, "list": after_list}

    if dry_run:
        return _response(
            operation,
            target,
            dry_run,
            ticket_ref,
            "planned",
            before=before_data,
            after=after_data,
            commit_required=True,
        )

    # Execute
    desc = before_data.get("description") or ""
    note = f"SSR {action}: {target} — {ticket_ref}"
    update_payload = {**after_data, "description": _append_note(desc, note)}

    client.url_category.update(update_payload)
    logger.info("ssr_url_list_applied", operation=operation, target=target, obj=obj_name)

    return _response(
        operation,
        target,
        dry_run,
        ticket_ref,
        "applied",
        before=before_data,
        after=after_data,
        commit_required=True,
    )


# ---------------------------------------------------------------------------
# Operation handlers — threat exception
# ---------------------------------------------------------------------------


def _handle_threat_exception(
    client: Any,
    folder: str,
    target: str,
    action: str,
    ssr_config: dict[str, str],
    dry_run: bool,
    ticket_ref: str,
) -> str:
    """Add/remove a threat exception on SSR-managed anti-spyware + vuln profiles."""
    asp_name = ssr_config.get("anti_spyware_profile", "")
    vp_name = ssr_config.get("vulnerability_protection_profile", "")

    if not asp_name and not vp_name:
        return _response(
            "threat-exception",
            target,
            dry_run,
            ticket_ref,
            "error",
            error="No SSR-managed anti-spyware or vulnerability protection profile configured. "
            "Add `anti_spyware_profile` and/or `vulnerability_protection_profile` to ssr_objects.",
        )

    results: dict[str, Any] = {}
    errors: list[str] = []

    for profile_name, sdk_attr in [
        (asp_name, "anti_spyware_profile"),
        (vp_name, "vulnerability_protection_profile"),
    ]:
        if not profile_name:
            continue

        try:
            resource = getattr(client, sdk_attr)
            profile = resource.fetch(name=profile_name, folder=folder)
            before_data = profile.model_dump()
            exceptions: list[dict[str, Any]] = list(before_data.get("threat_exception") or [])

            if action == "add":
                if any(e.get("name") == target for e in exceptions):
                    results[profile_name] = {"already_present": True, "before": before_data}
                    continue
                new_entry: dict[str, Any] = {"name": target, "action": {"allow": {}}}
                if sdk_attr == "anti_spyware_profile":
                    new_entry["packet_capture"] = "disable"
                exceptions.append(new_entry)
            else:  # remove
                before_len = len(exceptions)
                exceptions = [e for e in exceptions if e.get("name") != target]
                if len(exceptions) == before_len:
                    results[profile_name] = {"already_absent": True, "before": before_data}
                    continue

            after_data = {**before_data, "threat_exception": exceptions}

            if dry_run:
                results[profile_name] = {"before": before_data, "after": after_data}
            else:
                desc = before_data.get("description") or ""
                note = f"SSR threat-exception {action}: {target} — {ticket_ref}"
                update_payload = {**after_data, "description": _append_note(desc, note)}
                resource.update(update_payload)
                logger.info("ssr_threat_applied", profile=profile_name, target=target)
                results[profile_name] = {"before": before_data, "after": after_data}

        except Exception as exc:
            errors.append(f"{profile_name}: {exc}")
            logger.warning("ssr_threat_failed", profile=profile_name, error=str(exc))

    # Machine-first contract: if every configured profile errored, nothing was
    # (or would be) changed — status MUST say so, or an orchestrator reading
    # "applied" would proceed to commit a no-op.
    status = "error" if errors and not results else "planned" if dry_run else "applied"
    already_present = all(r.get("already_present") for r in results.values()) if results else False
    already_absent = all(r.get("already_absent") for r in results.values()) if results else False
    # Consistent with the URL/SSL handlers: True whenever a change was made or
    # is planned — not for pure no-ops (already_present/absent on every profile).
    changed = any(
        "after" in r and not r.get("already_present") and not r.get("already_absent")
        for r in results.values()
    )

    return _response(
        "threat-exception",
        target,
        dry_run,
        ticket_ref,
        status,
        already_present=already_present,
        already_absent=already_absent,
        commit_required=changed,
        extra={"profiles": results, "errors": errors or None},
    )


# ---------------------------------------------------------------------------
# Operation handlers — SSL decrypt exclude
# ---------------------------------------------------------------------------


def _handle_ssl_decrypt(
    client: Any,
    folder: str,
    target: str,
    action: str,
    ssr_config: dict[str, str],
    dry_run: bool,
    ticket_ref: str,
) -> str:
    """Add/remove a URL category on an SSR-managed no-decrypt rule."""
    rule_name = ssr_config.get("ssl_decrypt_exclude_rule", "")

    if not rule_name:
        return _response(
            "ssl-decrypt-exclude",
            target,
            dry_run,
            ticket_ref,
            "error",
            error="No SSR-managed SSL decrypt exclusion rule configured. "
            "Add `ssl_decrypt_exclude_rule` to ssr_objects for this tenant.",
        )

    rule = client.decryption_rule.fetch(name=rule_name, folder=folder)
    before_data = rule.model_dump()
    categories: list[str] = list(before_data.get("category") or [])

    if action == "add":
        if target in categories:
            return _response(
                "ssl-decrypt-exclude",
                target,
                dry_run,
                ticket_ref,
                "planned" if dry_run else "applied",
                before=before_data,
                after=before_data,
                already_present=True,
            )
        after_cats = sorted(set(categories + [target]))
    else:
        if target not in categories:
            return _response(
                "ssl-decrypt-exclude",
                target,
                dry_run,
                ticket_ref,
                "planned" if dry_run else "applied",
                before=before_data,
                after=before_data,
                already_absent=True,
            )
        after_cats = [c for c in categories if c != target]

    after_data = {**before_data, "category": after_cats}

    if dry_run:
        return _response(
            "ssl-decrypt-exclude",
            target,
            dry_run,
            ticket_ref,
            "planned",
            before=before_data,
            after=after_data,
            commit_required=True,
        )

    desc = before_data.get("description") or ""
    note = f"SSR ssl-decrypt {action}: {target} — {ticket_ref}"
    update_payload = {**after_data, "description": _append_note(desc, note)}

    client.decryption_rule.update(update_payload)
    logger.info("ssr_ssl_decrypt_applied", target=target, rule=rule_name)

    return _response(
        "ssl-decrypt-exclude",
        target,
        dry_run,
        ticket_ref,
        "applied",
        before=before_data,
        after=after_data,
        commit_required=True,
    )


# ---------------------------------------------------------------------------
# Helpers — misc
# ---------------------------------------------------------------------------


def _append_note(current: str, note: str) -> str:
    """Append *note* to *current* description, avoiding exact duplicates."""
    if note in current:
        return current
    sep = " | " if current else ""
    return f"{current}{sep}{note}"


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_ssr_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register the SSR tool — ``scm_ssr_execute``."""

    @mcp.tool()
    def scm_ssr_execute(  # noqa: C901
        operation: str,
        target: str,
        ticket_ref: str,
        tenant_id: str = "",
        folder: str = "",
        action: str = "add",
        dry_run: bool = True,
    ) -> str:
        """SSR — Simple Service Request (restricted customer-change CRUD).

        Machine-first, idempotent tool for the three commonest MSSP change
        requests.  Only touches objects named in the per-tenant ``ssr_objects``
        allowlist (settings.toml).  Never edits a rulebase directly.

        **Operations:**

        ``url-allow-list`` — Add/remove a URL in a designated SSR-managed custom
          URL category (``SSR-Allow-List``).

        ``url-block-list`` — Add/remove a URL in a designated SSR-managed custom
          URL category (``SSR-Block-List``).

        ``threat-exception`` — Add/remove a threat ID in the ``threat_exception``
          list of the SSR-managed anti-spyware and/or vulnerability protection
          profiles.

        ``ssl-decrypt-exclude`` — Add/remove a URL category name on the
          SSR-managed no-decrypt rule's ``category`` list.

        **Idempotent guarantees:**
        - Re-adding an existing entry → ``already_present: true``
        - Removing a non-existent entry → ``already_absent: true``
        - Safe under orchestrator retries

        **Dry-run (default):** Returns a before/after diff in JSON. Set
        ``dry_run=False`` to apply changes.  Commit stays a separate
        ``scm_commit`` step — SSR never auto-commits.

        Args:
            operation: One of ``url-allow-list``, ``url-block-list``,
                       ``threat-exception``, ``ssl-decrypt-exclude``.
            target: The URL, threat ID, or URL category name to operate on.
            ticket_ref: Mandatory ticket/change reference (e.g. INC-12345).
                Echoed into object descriptions and returned in the response.
            tenant_id: SCM tenant ID. Defaults to active tenant.
            folder: SCM folder. Defaults to the tenant's default_folder.
            action: ``add`` (default) or ``remove``.
            dry_run: If True (default), return a before/after diff without
                     making changes. Set to False to apply.
        """
        # --- Validate operation ---
        if operation not in _VALID_OPERATIONS:
            return json.dumps(
                {
                    "error": f"Unknown operation `{operation}`. Valid: {', '.join(_VALID_OPERATIONS)}",
                    "status": "error",
                },
                indent=2,
            )

        if action not in _VALID_ACTIONS:
            return json.dumps(
                {
                    "error": f"Unknown action `{action}`. Valid: {', '.join(_VALID_ACTIONS)}",
                    "status": "error",
                },
                indent=2,
            )

        # --- Validate ticket_ref ---
        ticket_ref = ticket_ref.strip()
        if not ticket_ref:
            return json.dumps(
                {
                    "error": "`ticket_ref` is mandatory — provide a ticket or change reference (e.g. INC-12345).",
                    "status": "error",
                },
                indent=2,
            )

        # --- Validate target ---
        target_err = _validate_target(operation, target)
        if target_err:
            return _response(operation, target, dry_run, ticket_ref, "error", error=target_err)

        # --- Load SSR config ---
        ssr_config = _get_ssr_config(tenant_id)
        if not ssr_config:
            return _response(
                operation,
                target,
                dry_run,
                ticket_ref,
                "error",
                error="No SSR configuration found. Add `ssr_objects` to the tenant config in settings.toml.",
            )

        # --- Resolve folder ---
        try:
            client = get_client(tenant_id)
        except Exception as exc:
            return _response(
                operation,
                target,
                dry_run,
                ticket_ref,
                "error",
                error=f"Failed to resolve SCM client: {exc}",
            )

        folder = folder.strip() or _resolve_default_folder(tenant_id)
        if not folder:
            return _response(
                operation,
                target,
                dry_run,
                ticket_ref,
                "error",
                error="No folder specified and no default_folder configured for this tenant.",
            )

        # --- Dispatch ---
        try:
            if operation in ("url-allow-list", "url-block-list"):
                return _handle_url_list(
                    client,
                    folder,
                    target,
                    action,
                    ssr_config,
                    dry_run,
                    ticket_ref,
                    operation,
                )
            if operation == "threat-exception":
                return _handle_threat_exception(
                    client,
                    folder,
                    target,
                    action,
                    ssr_config,
                    dry_run,
                    ticket_ref,
                )
            if operation == "ssl-decrypt-exclude":
                return _handle_ssl_decrypt(
                    client,
                    folder,
                    target,
                    action,
                    ssr_config,
                    dry_run,
                    ticket_ref,
                )
        except Exception as exc:
            return _response(
                operation,
                target,
                dry_run,
                ticket_ref,
                "error",
                error=str(handle_scm_exception(exc, tool="scm_ssr_execute", tenant_id=tenant_id)),
            )

        return _response(operation, target, dry_run, ticket_ref, "error", error="Unreachable")


def _resolve_default_folder(tenant_id: str) -> str:
    """Return the default folder for *tenant_id*.

    An explicit *tenant_id* that matches no configured tenant returns "" (the
    caller errors out) rather than another tenant's folder — the same
    no-cross-tenant-bleed rule as _get_ssr_config.
    """
    tenants = load_all_tenant_configs()
    if tenant_id:
        for tc in tenants.values():
            if tc.tenant_id == tenant_id:
                return tc.default_folder
        return ""
    if tenants:
        return next(iter(tenants.values())).default_folder
    return "Shared"
