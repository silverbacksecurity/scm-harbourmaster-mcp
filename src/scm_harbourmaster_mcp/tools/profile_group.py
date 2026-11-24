"""``scm_profile_group``: CRUD for security profile groups.

A profile group bundles one profile per type (anti-spyware, vulnerability,
WildFire/antivirus, URL access, file blocking, DNS security, data filtering,
SaaS and AI security) so a security rule can reference them with a single
``profile_setting.group`` entry.

Value over raw REST:

  * **Member validation.**  Every profile a create/update names is looked up
    in the group's own container (a folder query also returns inherited and
    predefined profiles).  A name that resolves nowhere is an error; a name
    that cannot be checked (no list API for SaaS/AI security, a 403 on the
    DLP list, a failed lookup, or a well-known predefined name the list did
    not return) is a warning.  ``allow_unresolved_members=True`` downgrades
    the errors to warnings.  In a snippet or device the inherited profiles
    are not listed, so "not found" is only a warning there.
  * **Safe delete.**  Refused while a security rule (pre and post rulebases)
    in the same container uses the group (a top-level folder also scans Mobile
    Users and Remote Networks).  The response states what was and was not
    scanned, and a failed lookup refuses a real delete (a dry run only warns).
    A group in a top-level folder or a snippet is inherited by containers that
    cannot be enumerated, so a real delete there also needs
    ``acknowledge_unscanned_scope=True``.
  * **Merging update.**  Only the member types given are replaced (each is a
    whole list); the rest are kept.  ``null`` removes a type.  Writes are read
    back (``verified``).

Endpoint base: the pan.dev security spec lists ``/config/security/v1`` as
current and ``/sse/config/v1`` as legacy, both serving ``/profile-groups``.
CRUD goes through the SDK client (strata host, ``/config/security/v1``, like
the other profile tools and ``scm_attach_ncsc_profiles``).  The sibling
profile tools' delete scans read ``/sse/config/v1/profile-groups`` instead:
the same objects through the legacy base.

**Write safety (SSR pattern):** ``dry_run=True`` by default, ``ticket_ref``
mandatory for every write action (dry runs included), logged and never sent in
a body.  Commit is a separate ``scm_commit`` step.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..audit import clone_preflight
from ..utils import scm_rest
from ..utils.formatting import format_result as _fmt
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool
from ..utils.write_safety import (
    DRY_RUN_HINT,
    audit_write,
    normalize_ticket_ref,
    ticket_ref_error,
)
from .security_profile import (
    _check,
    _check_object,
    _covers,
    _diff,
    _fetch,
    _fetch_by_id,
    _list_all,
    _merge,
    _paged_names,
    _scope,
    _summary,
)
from .threat_profile import (
    INHERITED_TOP_FOLDERS as INHERITED,
)
from .threat_profile import (
    api_folder,
    scan_scopes,
    scope_refusal,
    unscanned_scope_notice,
)

logger = get_logger(__name__)

_HOST = "https://api.sase.paloaltonetworks.com"
_BASE = "/config/security/v1/profile-groups"
_RULES_URL = f"{_HOST}/config/security/v1/security-rules"
_SDK_ATTR = "profile_group"  # not an SDK resource: no field aliases apply
# The shared _fetch/_list_all helpers only read ``.path``.
_SPEC: Any = SimpleNamespace(path=_BASE)

_ACTIONS_READ = ("list", "get")
_ACTIONS_WRITE = ("create", "update", "delete")
_ACTIONS = _ACTIONS_READ + _ACTIONS_WRITE
_SCOPE_KEYS = ("folder", "snippet", "device")
COMMIT_HINT = "Not committed: run scm_commit to push the change."

# The member fields of the pan.dev ``profile-groups`` schema (each a list of
# profile names); the clone preflight keeps the same list.
MEMBER_FIELDS: tuple[str, ...] = clone_preflight._PROFILE_GROUP_FIELDS
# Names SCM ships as predefined profiles/groups.  A folder list normally
# returns them; if it does not, the name is a warning, never an error.
_PREDEFINED_HINT = frozenset({"default", "strict", "best-practice"})

_FIELDS: dict[str, Any] = {f: ("l", ("s", None, None, r"^\S")) for f in MEMBER_FIELDS}
_FORBIDDEN_BODY_KEYS = frozenset(_SCOPE_KEYS) | {"id"}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def parse_config(config_json: str, *, create: bool) -> tuple[dict[str, Any], list[str]]:
    """The parsed body and every problem found (not just the first)."""
    if not config_json.strip():
        return {}, ["config_json is required"]
    try:
        body = json.loads(config_json)
    except json.JSONDecodeError as exc:
        return {}, [f"config_json is not valid JSON: {exc}"]
    if not isinstance(body, dict):
        return {}, ["config_json must be a JSON object"]
    errs: list[str] = []
    forbidden = sorted(set(body) & _FORBIDDEN_BODY_KEYS)
    if forbidden:
        errs.append(
            f"config_json must not contain {forbidden}: pass the container as the "
            "folder/snippet/device argument; the id is addressed by name or profile_id"
        )
    if "name" in body:
        _check(("s", None, None, None), body["name"], "name", errs, strict=create, null_ok=False)
    rest = {k: v for k, v in body.items() if k not in _FORBIDDEN_BODY_KEYS and k != "name"}
    _check_object(_FIELDS, (), rest, "config_json", errs, strict=create, null_ok=not create)
    for key, value in rest.items():
        if isinstance(value, list) and not value:
            errs.append(
                f"config_json.{key}: an empty list is not accepted by the API; "
                "use null to remove the member type"
            )
        elif isinstance(value, list) and len(value) > 1:
            errs.append(
                f"config_json.{key}: a group takes at most one profile per member type "
                f"(SCM rejects more, API_I00013); got {len(value)}"
            )
        elif isinstance(value, list) and len(set(map(str, value))) != len(value):
            errs.append(f"config_json.{key}: a profile is listed more than once")
    return body, errs


def _api_scope(scope: dict[str, str]) -> dict[str, str]:
    """The container as the API takes it: only a folder is aliased ("Shared" -> "Prisma Access")."""
    return {k: (api_folder(v) if k == "folder" else v) for k, v in scope.items()}


def check_members(
    client: Any, scope: dict[str, str], members: dict[str, list[str]]
) -> tuple[list[str], list[str]]:
    """(errors, warnings) for the profiles *members* names, per member type.

    Each type is listed once from the group's container (inherited and
    predefined profiles included).  Not found after a good lookup is an
    error; anything that cannot be checked is a warning.
    """
    errors: list[str] = []
    warnings: list[str] = []
    lookup = _api_scope(scope)
    inherited_blind = "folder" not in lookup
    for field in MEMBER_FIELDS:
        names = members.get(field) or []
        if not names:
            continue
        kind = clone_preflight.KINDS[field]
        if not kind.sources:
            warnings.append(f"{field}: no list API for {kind.label}s, {names} not verified")
            continue
        url, _ = kind.sources[0]
        known, err = _paged_names(
            client, url, lookup, lambda r: [str(r["name"])] if r.get("name") else []
        )
        if err:
            warnings.append(f"{field}: could not list {kind.label}s ({err}); {names} not verified")
            continue
        for name in names:
            if name in known:
                continue
            if name in _PREDEFINED_HINT:
                warnings.append(
                    f"{field}: {name!r} is not in the {kind.label} list but is a predefined "
                    "name; assumed to exist"
                )
            else:
                where = next(iter(scope.values()), "")
                if inherited_blind:
                    warnings.append(
                        f"{field}: {kind.label} {name!r} not found in {where!r}, but a "
                        "snippet/device listing does not include inherited profiles, so it "
                        "may still exist; not verified"
                    )
                    continue
                errors.append(
                    f"{field}: {kind.label} {name!r} not found in {where!r} "
                    "(own, inherited or predefined)"
                )
    return errors, warnings


def _name_error(name: str) -> str:
    if not isinstance(name, str) or not name.strip():
        return "name is required"
    return ""


def _member_lists(delta: dict[str, Any]) -> dict[str, list[str]]:
    return {k: [str(n) for n in v] for k, v in delta.items() if k in MEMBER_FIELDS and v}


def _member_report(
    client: Any, scope: dict[str, str], delta: dict[str, Any], allow_unresolved: bool
) -> tuple[dict[str, Any], str]:
    """(validation block, refusal text or "")."""
    errors, warnings = check_members(client, scope, _member_lists(delta))
    if allow_unresolved and errors:
        warnings = [f"{e} (allowed by allow_unresolved_members)" for e in errors] + warnings
        errors = []
    validation: dict[str, Any] = {"ok": not errors, "warnings": warnings}
    if errors:
        validation["errors"] = errors
        return validation, (
            "Error: member profiles not found:\n  - " + "\n  - ".join(errors) + "\n"
            "Create them first, fix the names, or pass allow_unresolved_members=true."
        )
    return validation, ""


def _real_scope(current: dict[str, Any]) -> dict[str, str]:
    return {k: str(current[k]) for k in _SCOPE_KEYS if current.get(k)}


def _container_note(current: dict[str, Any], requested: dict[str, str]) -> dict[str, Any]:
    """The container really being edited, plus a loud note when it is not the requested one."""
    real = _real_scope(current)
    out: dict[str, Any] = {"container": real}
    if requested and _api_scope(requested) != real:
        out["container_warning"] = (
            f"the group {current.get('name')!r} lives in {real}, not the requested "
            f"{_api_scope(requested)}: it is inherited from that container, so this change "
            "edits the parent group and affects everything that inherits it"
        )
    return out


# ---------------------------------------------------------------------------
# Delete reference scan
# ---------------------------------------------------------------------------

_NOT_SCANNED = [
    "security rules in custom child folders, or in other snippets/devices, that inherit this group",
    "the default rulebase",
    "references outside SCM (Panorama or NGFW local config)",
]


def _rules_using(client: Any, name: str, scope: dict[str, str]) -> tuple[list[str], str]:
    """Security rules (pre and post) in *scope* whose profile_setting.group has *name*.

    A top-level folder also scans the common child folders.
    """
    found: list[str] = []
    for label, query in scan_scopes(scope):
        where = f" in {label}" if label else ""
        for position in ("pre", "post"):

            def extract(
                row: dict[str, Any], position: str = position, where: str = where
            ) -> list[str]:
                setting = row.get("profile_setting")
                value = setting.get("group") if isinstance(setting, dict) else None
                members = [value] if isinstance(value, str) else (value or [])
                hit = name in members and row.get("name")
                return [f"{row['name']} ({position}{where})"] if hit else []

            names, err = _paged_names(client, _RULES_URL, {**query, "position": position}, extract)
            if err:
                return [], f"security-rule lookup ({position}{where}) failed: {err}"
            found.extend(names)
    return sorted(found), ""


# ---------------------------------------------------------------------------
# Write paths
# ---------------------------------------------------------------------------


def _create(
    client: Any,
    tenant_id: str,
    scope: dict[str, str],
    name: str,
    config_json: str,
    dry_run: bool,
    ticket_ref: str,
    allow_unresolved: bool,
) -> str:
    if not scope:
        return "Error: create needs one of folder, snippet or device"
    body, errs = parse_config(config_json, create=True)
    if body.get("name") and name and body["name"] != name:
        errs.append("name argument and config_json name disagree")
    name = name or str(body.get("name") or "")
    if _name_error(name):
        errs.append(_name_error(name))
    if errs:
        return "Error: invalid profile group:\n  - " + "\n  - ".join(dict.fromkeys(errs))
    if _fetch(client, _SPEC, name, scope) is not None:
        return (
            f"Error: profile group {name!r} already exists in {next(iter(scope.values()))}; "
            "use action=update"
        )
    validation, refusal = _member_report(client, scope, body, allow_unresolved)
    if refusal:
        return refusal
    if not _member_lists(body):
        validation["warnings"].append("the group has no member profiles")
    request_body: dict[str, Any] = {**body, "name": name, **scope}
    if dry_run:
        return _fmt(
            {
                "action": "create",
                "dry_run": True,
                "ticket_ref": ticket_ref,
                "request": {"method": "POST", "path": _BASE, "body": request_body},
                "validation": validation,
                "exists": False,
                "hint": DRY_RUN_HINT,
            }
        )
    audit_write("scm_profile_group", ticket_ref, tenant_id, action="create", path=_BASE)
    result = client.post(_BASE, json=request_body)
    stored = _fetch(client, _SPEC, name, scope)
    out: dict[str, Any] = {
        "action": "create",
        "applied": True,
        "ticket_ref": ticket_ref,
        "result": result,
        "validation": validation,
        "verified": stored is not None and _covers(stored, body),
        "hint": COMMIT_HINT,
    }
    if not out["verified"]:
        out["warning"] = (
            "read-back does not match the request; the API may have altered or ignored it"
        )
    return _fmt(out)


def _update(
    client: Any,
    tenant_id: str,
    current: dict[str, Any],
    config_json: str,
    dry_run: bool,
    ticket_ref: str,
    allow_unresolved: bool,
    requested: dict[str, str] | None = None,
) -> str:
    delta, errs = parse_config(config_json, create=False)
    if not errs and "name" in delta and delta["name"] != current.get("name"):
        errs.append("renaming is not supported: omit name from config_json")
    if not errs and not [k for k in delta if k != "name"]:
        errs.append("config_json has nothing to change")
    if errs:
        return "Error: invalid profile group update:\n  - " + "\n  - ".join(dict.fromkeys(errs))
    delta = {k: v for k, v in delta.items() if k != "name"}
    scope = _real_scope(current)
    where = _container_note(current, requested or {})
    validation, refusal = _member_report(client, scope, delta, allow_unresolved)
    if refusal:
        return refusal
    merged = _merge(current, delta, _FIELDS)
    if not _member_lists(merged):
        validation["warnings"].append("the group would have no member profiles")
    path = f"{_BASE}/{current['id']}"
    body = scm_rest.put_payload(_SDK_ATTR, merged)
    diff = _diff(current, merged)
    if dry_run:
        return _fmt(
            {
                "action": "update",
                "dry_run": True,
                "ticket_ref": ticket_ref,
                "request": {"method": "PUT", "path": path, "body": body},
                **where,
                "diff": diff,
                "validation": validation,
                "hint": DRY_RUN_HINT,
            }
        )
    audit_write("scm_profile_group", ticket_ref, tenant_id, action="update", path=path)
    result = client.put(path, json=body)
    # A PUT can answer 200 and change nothing: read it back and compare.
    stored = _fetch_by_id(client, _SPEC, str(current["id"]))
    verified = stored is not None and _covers(stored, delta)
    out: dict[str, Any] = {
        "action": "update",
        "applied": True,
        "ticket_ref": ticket_ref,
        "result": result,
        **where,
        "diff": diff,
        "validation": validation,
        "verified": verified,
        "hint": COMMIT_HINT,
    }
    if not verified:
        out["warning"] = "read-back does not match the update; the API may have ignored it"
    return _fmt(out)


def _delete(
    client: Any,
    tenant_id: str,
    current: dict[str, Any],
    dry_run: bool,
    ticket_ref: str,
    acknowledge_unscanned_scope: bool = False,
    requested: dict[str, str] | None = None,
) -> str:
    scope = _real_scope(current)
    name = str(current.get("name"))
    refs, lookup_err = _rules_using(client, name, scope)
    container = next(iter(scope.values()), "")
    check: dict[str, Any] = {
        "scanned": (
            f"security rules, pre and post rulebases, in {next(iter(scope), 'folder')} "
            f"{container!r}"
            + (" and Mobile Users, Remote Networks" if scope.get("folder") in INHERITED else "")
            + " (field profile_setting.group)"
        ),
        "not_scanned": _NOT_SCANNED,
        "referenced_by": refs,
        **_container_note(current, requested or {}),
    }
    if lookup_err:
        check["warning"] = lookup_err
    notice = unscanned_scope_notice(scope)
    refusal = scope_refusal(scope, acknowledge_unscanned_scope)
    if notice:
        check["unscanned_scope_warning"] = notice
    if refusal:
        check["would_refuse"] = refusal
    if refs:
        return (
            f"Error: profile group {name!r} is used by security rule(s) {refs}; point them at "
            f"another group first. Scanned: {check['scanned']}. "
            f"Not scanned: {'; '.join(_NOT_SCANNED)}."
        )
    if lookup_err and not dry_run:
        return (
            f"Error: cannot confirm {name!r} is unused ({lookup_err}); delete refused. "
            f"Scanned: {check['scanned']}. Dry run still works."
        )
    if refusal and not dry_run:
        return f"Error: delete refused: {refusal}. Scanned: {check['scanned']}"
    path = f"{_BASE}/{current['id']}"
    if dry_run:
        return _fmt(
            {
                "action": "delete",
                "dry_run": True,
                "ticket_ref": ticket_ref,
                "request": {"method": "DELETE", "path": path},
                "current": current,
                **check,
                "hint": DRY_RUN_HINT,
            }
        )
    audit_write("scm_profile_group", ticket_ref, tenant_id, action="delete", path=path)
    result = client.delete(path)
    return _fmt(
        {
            "action": "delete",
            "applied": True,
            "ticket_ref": ticket_ref,
            "result": result,
            **check,
            "hint": COMMIT_HINT,
        }
    )


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_profile_group_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register the security profile group tool."""
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_profile_group(
        client: Any,
        tenant_id: str,
        action: str = "list",
        folder: str = "",
        snippet: str = "",
        device: str = "",
        name: str = "",
        profile_id: str = "",
        config_json: str = "",
        dry_run: bool = True,
        ticket_ref: str = "",
        allow_unresolved_members: bool = False,
        acknowledge_unscanned_scope: bool = False,
        limit: int = 200,
    ) -> str:
        """List and manage security profile groups (``profile_setting.group`` targets).

        Actions:
          * ``list`` - groups in a folder/snippet/device (optional ``name``
            substring filter); ``get`` returns the full body.
          * ``get`` - one group by ``profile_id``, or ``name`` + container.
          * ``create`` - new group from ``config_json``.
          * ``update`` - merge ``config_json`` into the group.  Each member
            type given replaces that type's whole list; types not given are
            kept; a null value removes a type.
          * ``delete`` - refused while a security rule (pre and post) in the
            same container uses the group (a top-level folder also scans
            Mobile Users and Remote Networks), or when that lookup fails.  A
            group in a top-level folder or snippet needs
            ``acknowledge_unscanned_scope`` for a real delete.  The response
            lists what was and was not scanned.

        ``config_json`` is an API-shaped JSON object whose keys are member
        types, each a list of profile names: spyware, vulnerability,
        virus_and_wildfire_analysis, url_filtering, file_blocking,
        dns_security, data_filtering, saas_security, ai_security.  Do not put
        id, folder, snippet or device in it; ``name`` may be given there or as
        the ``name`` argument.  Unknown keys and wrong types are reported
        together.

        On create and update every named profile is looked up in the group's
        container (inherited and predefined profiles included).  A name that
        does not exist is an error, unless ``allow_unresolved_members`` is
        true; a name that cannot be checked (SaaS/AI security have no list
        API, a failed or forbidden lookup) is a warning.

        **Write safety (SSR pattern):** ``dry_run=True`` by default; a dry run
        reads only and returns the planned request.  ``ticket_ref`` is
        mandatory for every write action (dry runs included), is logged, and
        is never sent to SCM.  Writes are read back (``verified``).  No commit
        is performed: run scm_commit.

        Args:
            action: list (default), get, create, update or delete.
            folder: Folder container (pass only one of folder, snippet, device).
            snippet: Snippet container.
            device: Device container.
            name: Group name (create/update/delete/get target; list filter).
            profile_id: Group UUID (get/update/delete).
            config_json: JSON object with the member lists (create, update).
            dry_run: If True (default), preview a write without applying it.
            ticket_ref: Mandatory change-ticket reference for writes.
            allow_unresolved_members: Treat member profiles that are not found as warnings.
            acknowledge_unscanned_scope: delete only.  A group in a top-level folder
                (All, Shared, Prisma Access, Global) or a snippet is inherited by
                containers that cannot be enumerated; set True to delete it anyway.
            limit: Maximum rows returned by list.
            tenant_id: SCM tenant ID.
        """
        if action not in _ACTIONS:
            return f"Error: unknown action {action!r} - use one of: {', '.join(_ACTIONS)}"
        scope, err = _scope(folder, snippet, device)
        if err:
            return f"Error: {err}"
        scope = _api_scope(scope)

        if action == "list":
            if not scope:
                return "Error: list needs one of folder, snippet or device"
            rows = _list_all(client, _SPEC, scope)
            if name:
                rows = [r for r in rows if name.lower() in str(r.get("name", "")).lower()]
            shown = [_summary(r) for r in rows[: max(0, limit)]]
            return _fmt({"scope": scope, "total": len(rows), "items": shown})
        if action == "get":
            if profile_id:
                item = _fetch_by_id(client, _SPEC, profile_id.strip())
            elif name and scope:
                item = _fetch(client, _SPEC, name, scope)
            else:
                return "Error: get needs profile_id, or name with one of folder/snippet/device"
            if item is None:
                return "Error: profile group not found"
            return _fmt({"item": item})

        err = ticket_ref_error(ticket_ref)
        if err:
            return f"Error: {err}"
        ticket_ref = normalize_ticket_ref(ticket_ref)

        if action == "create":
            return _create(
                client,
                tenant_id,
                scope,
                name,
                config_json,
                dry_run,
                ticket_ref,
                allow_unresolved_members,
            )

        if profile_id.strip():
            current = _fetch_by_id(client, _SPEC, profile_id.strip())
        elif name and scope:
            current = _fetch(client, _SPEC, name, scope)
        else:
            return f"Error: {action} needs profile_id, or name with one of folder/snippet/device"
        if current is None:
            return "Error: profile group not found"
        if action == "update":
            return _update(
                client,
                tenant_id,
                current,
                config_json,
                dry_run,
                ticket_ref,
                allow_unresolved_members,
                scope,
            )
        return _delete(
            client, tenant_id, current, dry_run, ticket_ref, acknowledge_unscanned_scope, scope
        )
