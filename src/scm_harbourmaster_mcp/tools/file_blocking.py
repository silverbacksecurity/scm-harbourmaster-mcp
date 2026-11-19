"""MCP tools for file-blocking profiles and the applications they can match.

``scm_file_blocking_apps`` answers which applications a file-blocking rule may
name.  The write API accepts only applications whose ``file_type_ident`` flag
is true (live-proven: 1089 accepted == 1089 flagged) and reports just the
first bad keyword per request, so the tool derives the eligible set from the
tenant's application catalogue and lets callers pre-check a whole list.

``scm_file_blocking_profile`` lists, reads and (dry-run first) writes
file-blocking profiles (``config/security/v1/file-blocking-profiles``).  It
pre-validates every rule against the catalogue, reporting all offenders at
once.

**Write safety (SSR pattern):** ``dry_run=True`` by default, ``ticket_ref``
mandatory for writes (dry runs included), logged and never sent in a body.
Commit is a separate ``scm_commit`` step.
"""

from __future__ import annotations

import difflib
import json
import re
import threading
import time
from dataclasses import dataclass, field
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

logger = get_logger(__name__)

_HOST = "https://api.sase.paloaltonetworks.com"
_APPS_URL = f"{_HOST}/config/objects/v1/applications"
_GROUPS_URL = f"{_HOST}/sse/config/v1/profile-groups"
_BASE = "/config/security/v1/file-blocking-profiles"
_SDK_ATTR = "file_blocking_profile"
_PAGE = 200

CACHE_TTL = 6 * 3600.0
# 12 x 1000-row pages cover the ~11,200-row catalogue in one concurrent wave
# (~40 s measured, against 61-68 s with a serial first page).
_PREFETCH_PAGES = 12
# Many MCP clients give up on a tool call after 60 s.  Callers wait this long,
# then report "still loading" while the fetch carries on in a background thread.
WAIT_BUDGET = 45.0
WARMING_MSG = (
    "the applications catalogue is still loading (the first fetch for a tenant "
    "takes about 40-70 s); retry in a minute"
)
CHECK_MAX = 200
LIMIT_MAX = 500

CONTENT_NOTE = (
    "Eligibility is derived from the tenant's current application content "
    "(file_type_ident flag), validated live 2026-11-19 against file-blocking "
    "profile writes (1089 accepted == 1089 flagged). The SCM UI may list more "
    "applications; the write API is the authority. Content updates change the "
    "set: use refresh=True after a content release."
)

_ACTIONS_READ = ("list", "get")
_ACTIONS_WRITE = ("create", "update", "delete")
_ACTIONS = _ACTIONS_READ + _ACTIONS_WRITE
_RULE_ACTIONS = ("alert", "block", "continue")
_DIRECTIONS = ("download", "upload", "both")
_RULE_KEYS = frozenset({"name", "action", "application", "direction", "file_type"})
_NAME_RE = re.compile(r"^[A-Za-z0-9 ._-]{1,31}$")
_SCOPE_KEYS = ("folder", "snippet", "device")


# ---------------------------------------------------------------------------
# Application catalogue
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AppInfo:
    """One application, merged across the duplicate catalogue rows."""

    eligible: bool
    transfer_only: bool
    category: str
    subcategory: str
    risk: Any


@dataclass
class Catalogue:
    """Slim, merged view of the applications catalogue."""

    apps: dict[str, AppInfo]
    containers: dict[str, list[str]]  # container name -> children (known apps)
    fetched_at: float = field(default_factory=time.time)
    cached: bool = False

    @property
    def eligible_names(self) -> list[str]:
        return sorted(n for n, a in self.apps.items() if a.eligible)

    def totals(self) -> dict[str, int]:
        return {
            "unique_apps": len(self.apps),
            "eligible": sum(1 for a in self.apps.values() if a.eligible),
            "transfer_only": sum(1 for a in self.apps.values() if a.transfer_only),
            "containers": len(self.containers),
        }


def merge_rows(rows: list[dict[str, Any]]) -> Catalogue:
    """Merge catalogue rows by name (every app comes back twice, ids null).

    Per field the first non-null/truthy value across an app's rows wins, which
    matters because ``file_type_ident`` is set on only one of the two rows.
    """
    merged: dict[str, dict[str, Any]] = {}
    containers: dict[str, set[str]] = {}
    for row in rows:
        name = row.get("name")
        if not isinstance(name, str) or not name:
            continue
        slot = merged.setdefault(name, {})
        for key in (
            "file_type_ident",
            "able_to_transfer_file",
            "category",
            "subcategory",
            "risk",
        ):
            if not slot.get(key) and row.get(key):
                slot[key] = row[key]
        parent = row.get("container")
        if isinstance(parent, str) and parent:
            containers.setdefault(parent, set()).add(name)
    apps = {
        n: AppInfo(
            eligible=s.get("file_type_ident") is True,
            transfer_only=s.get("able_to_transfer_file") is True
            and s.get("file_type_ident") is not True,
            category=str(s.get("category") or ""),
            subcategory=str(s.get("subcategory") or ""),
            risk=s.get("risk"),
        )
        for n, s in merged.items()
    }
    # A container is a name that only appears as another app's `container`.
    boxes = {c: sorted(kids) for c, kids in containers.items() if c not in apps}
    return Catalogue(apps=apps, containers=boxes)


def _fetch_catalogue(client: Any) -> tuple[list[dict[str, Any]], str]:
    """Every row of the applications catalogue, or ([], error).

    A run takes 60-90 s and tokens expire mid-run, so the token is refreshed
    before each attempt and the fetch is retried once after a 401.
    """
    err = ""
    for _ in range(2):
        scm_rest.refresh_token(client)
        session = scm_rest.bearer_session(client)
        rows, err = clone_preflight.list_rows(
            session, _APPS_URL, "All", prefetch_pages=_PREFETCH_PAGES
        )
        if not err:
            return rows, ""
        if "401" not in err:
            break
    return [], err


_CACHE: dict[str, tuple[float, Catalogue]] = {}
_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()


def _clock() -> float:
    return time.monotonic()


def _lock_for(tenant: str) -> threading.Lock:
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(tenant, threading.Lock())


def _load_catalogue(client: Any, tenant_id: str, refresh: bool) -> tuple[Catalogue, str]:
    key = tenant_id or "default"

    def _hit() -> Catalogue | None:
        entry = _CACHE.get(key)
        if entry and not refresh and _clock() - entry[0] < CACHE_TTL:
            cat = entry[1]
            return Catalogue(cat.apps, cat.containers, cat.fetched_at, cached=True)
        return None

    hit = _hit()
    if hit:
        return hit, ""
    with _lock_for(key):
        hit = _hit() if not refresh else None
        if hit:
            return hit, ""
        rows, err = _fetch_catalogue(client)
        if err:
            return Catalogue({}, {}), err
        cat = merge_rows(rows)
        if not cat.apps:
            return Catalogue({}, {}), "applications catalogue came back empty"
        _CACHE[key] = (_clock(), cat)
        return cat, ""


@dataclass
class _Load:
    done: threading.Event
    result: tuple[Catalogue, str] | None = None


_INFLIGHT: dict[str, _Load] = {}


def get_catalogue(
    client: Any, tenant_id: str, refresh: bool = False, wait: float | None = None
) -> tuple[Catalogue, str]:
    """The tenant's merged catalogue (cached 6 h), or (empty, error).

    A failed or partial fetch is never cached: a false "not eligible" verdict
    is the dangerous failure.  With ``wait`` set the load runs in a background
    thread and the call returns ``WARMING_MSG`` as the error if it is not done
    within ``wait`` seconds; the thread keeps going and fills the cache, so the
    next call is a hit.  Without ``wait`` the call blocks until the load ends.
    """
    key = tenant_id or "default"
    if wait is None:
        return _load_catalogue(client, tenant_id, refresh)
    if not refresh:
        entry = _CACHE.get(key)
        if entry and _clock() - entry[0] < CACHE_TTL:
            cat = entry[1]
            return Catalogue(cat.apps, cat.containers, cat.fetched_at, cached=True), ""
    with _LOCKS_GUARD:
        load = _INFLIGHT.get(key)
        if load is None or load.done.is_set():
            load = _Load(threading.Event())
            _INFLIGHT[key] = load

            def _run(load: _Load = load) -> None:
                try:
                    load.result = _load_catalogue(client, tenant_id, refresh)
                except Exception as exc:  # never leave waiters hanging
                    load.result = (Catalogue({}, {}), str(exc)[:200])
                finally:
                    load.done.set()

            threading.Thread(target=_run, daemon=True).start()
    if load.done.wait(wait) and load.result is not None:
        return load.result
    return Catalogue({}, {}), WARMING_MSG


def classify(name: str, cat: Catalogue) -> dict[str, Any]:
    """Verdict for one application name."""
    if name == "any":
        return {"name": name, "verdict": "eligible", "note": "'any' matches every application"}
    info = cat.apps.get(name)
    if info is not None:
        if info.eligible:
            return {
                "name": name,
                "verdict": "eligible",
                "category": info.category,
                "subcategory": info.subcategory,
            }
        if info.transfer_only:
            return {
                "name": name,
                "verdict": "not_eligible_transfer_only",
                "note": "able to transfer files but not file-type identifiable",
            }
        return {"name": name, "verdict": "not_eligible"}
    if name in cat.containers:
        kids = [k for k in cat.containers[name] if cat.apps.get(k) and cat.apps[k].eligible]
        return {
            "name": name,
            "verdict": "container",
            "note": "container application, never accepted; name its children",
            "eligible_children": kids[:25],
        }
    close = difflib.get_close_matches(name, list(cat.apps), n=5, cutoff=0.6)
    return {"name": name, "verdict": "unknown", "close_matches": close}


# ---------------------------------------------------------------------------
# Rule parsing / validation
# ---------------------------------------------------------------------------


def _as_list(value: Any) -> list[str] | None:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return list(value)
    return None


def parse_rules(rules_json: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Parse and normalise ``rules_json`` into API-shaped rules plus errors."""
    try:
        raw = json.loads(rules_json)
    except (json.JSONDecodeError, TypeError) as exc:
        return [], [f"rules_json is not valid JSON: {exc}"]
    if not isinstance(raw, list) or not raw:
        return [], ["rules_json must be a non-empty JSON list of rule objects"]
    rules: list[dict[str, Any]] = []
    errors: list[str] = []
    seen: set[str] = set()
    for i, item in enumerate(raw, 1):
        if not isinstance(item, dict):
            errors.append(f"rule {i}: must be an object")
            continue
        label = f"rule {i} ({item.get('name')!r})"
        unknown = sorted(set(item) - _RULE_KEYS)
        if unknown:
            errors.append(f"{label}: unknown keys {unknown}; allowed {sorted(_RULE_KEYS)}")
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            errors.append(f"{label}: name is required")
        elif len(name) > 31:
            errors.append(f"{label}: name longer than 31 characters")
        elif name in seen:
            errors.append(f"{label}: duplicate rule name")
        else:
            seen.add(name)
        action = item.get("action", "alert")
        if action not in _RULE_ACTIONS:
            errors.append(f"{label}: action {action!r} not one of {list(_RULE_ACTIONS)}")
        direction = item.get("direction", "both")
        if direction not in _DIRECTIONS:
            errors.append(f"{label}: direction {direction!r} not one of {list(_DIRECTIONS)}")
        apps = _as_list(item.get("application", ["any"]))
        types = _as_list(item.get("file_type", ["any"]))
        if not apps:
            errors.append(f"{label}: application must be a non-empty list of names")
        elif "any" in apps and len(apps) > 1:
            errors.append(f"{label}: 'any' cannot be mixed with application names")
        if not types:
            errors.append(f"{label}: file_type must be a non-empty list")
        elif "any" in types and len(types) > 1:
            errors.append(f"{label}: 'any' cannot be mixed with file types")
        rules.append(
            {
                "name": name,
                "action": action,
                "application": apps or [],
                "direction": direction,
                "file_type": types or [],
            }
        )
    return rules, errors


def validate_apps(rules: list[dict[str, Any]], cat: Catalogue) -> list[dict[str, Any]]:
    """Every application that cannot be used, across all rules (not just the first)."""
    issues: list[dict[str, Any]] = []
    for rule in rules:
        for app in rule.get("application") or []:
            verdict = classify(app, cat)
            if verdict["verdict"] == "eligible":
                continue
            issue: dict[str, Any] = {
                "rule": rule.get("name"),
                "application": app,
                "problem": {
                    "not_eligible_transfer_only": "transfer_only",
                    "not_eligible": "not_eligible",
                }.get(verdict["verdict"], verdict["verdict"]),
            }
            if verdict["verdict"] == "unknown":
                issue["did_you_mean"] = difflib.get_close_matches(
                    app, cat.eligible_names, n=3, cutoff=0.6
                )
            elif verdict["verdict"] == "container":
                issue["eligible_children"] = verdict.get("eligible_children", [])
            issues.append(issue)
    return issues


def _validate(
    client: Any, tenant_id: str, rules: list[dict[str, Any]], skip_app_check: bool
) -> tuple[dict[str, Any], str]:
    """(validation block, error).  The error is set when apps are rejected."""
    if skip_app_check:
        return {"ok": True, "app_check": "skipped (skip_app_check=True)", "issues": []}, ""
    cat, err = get_catalogue(client, tenant_id, wait=WAIT_BUDGET)
    if err:
        # Degrade to a warning: the API still checks on a real write.
        return {"ok": True, "app_check": f"skipped ({err})", "issues": []}, ""
    issues = validate_apps(rules, cat)
    checked = sum(len(r.get("application") or []) for r in rules)
    block = {"ok": not issues, "apps_checked": checked, "issues": issues}
    if issues:
        lines = []
        for i in issues:
            hint = ""
            if i.get("did_you_mean"):
                hint = f" (did you mean {', '.join(i['did_you_mean'])}?)"
            elif i.get("eligible_children"):
                hint = f" (eligible children: {', '.join(i['eligible_children'][:5])})"
            lines.append(f"  - rule {i['rule']!r}: {i['application']!r} is {i['problem']}{hint}")
        return block, (
            f"{len(issues)} application(s) cannot be used in a file-blocking rule:\n"
            + "\n".join(lines)
            + "\nFix them, or pass skip_app_check=True to let the API decide."
        )
    return block, ""


# ---------------------------------------------------------------------------
# REST helpers
# ---------------------------------------------------------------------------


def _scope(folder: str, snippet: str, device: str) -> tuple[dict[str, str], str]:
    given = {
        k: v.strip() for k, v in (("folder", folder), ("snippet", snippet), ("device", device))
    }
    given = {k: v for k, v in given.items() if v}
    if len(given) > 1:
        return {}, "pass only one of folder, snippet or device"
    return given, ""


def _items(body: Any) -> list[dict[str, Any]]:
    if isinstance(body, dict) and isinstance(body.get("data"), list):
        items = body["data"]
    elif isinstance(body, list):
        items = body
    else:
        items = [body]
    return [i for i in items if isinstance(i, dict)]


def _fetch(client: Any, name: str, scope: dict[str, str]) -> dict[str, Any] | None:
    """The profile called *name* in *scope* as the raw API dict, or None."""
    try:
        body = client.get(_BASE, params={"name": name, **scope})
    except Exception as exc:
        if scm_rest.exc_status(exc) == 404 or type(exc).__name__ == "ObjectNotPresentError":
            return None
        raise
    for item in _items(body):
        if item.get("id") and item.get("name") == name:
            return item
    return None


def _fetch_by_id(client: Any, profile_id: str) -> dict[str, Any] | None:
    try:
        body = client.get(f"{_BASE}/{profile_id}")
    except Exception as exc:
        if scm_rest.exc_status(exc) == 404 or type(exc).__name__ == "ObjectNotPresentError":
            return None
        raise
    items = _items(body)
    return items[0] if items and items[0].get("id") else None


def _list_all(client: Any, scope: dict[str, str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    while True:
        body = client.get(_BASE, params={**scope, "limit": str(_PAGE), "offset": str(len(rows))})
        if isinstance(body, list):
            return [r for r in body if isinstance(r, dict)]
        page = [r for r in (body or {}).get("data", []) if isinstance(r, dict)]
        rows.extend(page)
        total = (body or {}).get("total")
        if len(page) < _PAGE or (isinstance(total, int) and len(rows) >= total):
            return rows


def _referencing_groups(client: Any, name: str, scope: dict[str, str]) -> tuple[list[str], str]:
    """Profile groups in the same container whose file_blocking list names *name*."""
    try:
        scm_rest.refresh_token(client)
        session = scm_rest.bearer_session(client)
        names: list[str] = []
        offset = 0
        while True:
            resp = session.get(
                _GROUPS_URL,
                params={**scope, "limit": _PAGE, "offset": offset},
                timeout=clone_preflight._TIMEOUT,
            )
            if resp.status_code != 200:
                return [], f"profile-group lookup failed: HTTP {resp.status_code}"
            body = resp.json()
            page = [r for r in _items(body) if r.get("name")]
            for row in page:
                fb = row.get("file_blocking")
                fb_list = [fb] if isinstance(fb, str) else (fb or [])
                if name in fb_list:
                    names.append(str(row["name"]))
            if len(page) < _PAGE:
                return sorted(set(names)), ""
            offset += _PAGE
    except Exception as exc:
        return [], f"profile-group lookup failed: {str(exc)[:200]}"


def _rule_sig(rule: dict[str, Any]) -> tuple[Any, ...]:
    return (
        rule.get("action"),
        tuple(sorted(rule.get("application") or [])),
        rule.get("direction"),
        tuple(sorted(rule.get("file_type") or [])),
    )


def _rules_by_name(rules: list[dict[str, Any]]) -> dict[str, tuple[Any, ...]]:
    return {str(r.get("name")): _rule_sig(r) for r in rules}


def _diff(before: list[dict[str, Any]], after: list[dict[str, Any]]) -> dict[str, list[str]]:
    old, new = _rules_by_name(before), _rules_by_name(after)
    return {
        "added": sorted(set(new) - set(old)),
        "removed": sorted(set(old) - set(new)),
        "changed": sorted(n for n in set(old) & set(new) if old[n] != new[n]),
    }


COMMIT_HINT = "Not committed: run scm_commit to push the change."


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_file_blocking_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register the file-blocking application and profile tools."""
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_file_blocking_apps(
        client: Any,
        tenant_id: str,
        check: list[str] | None = None,
        name_contains: str = "",
        category: str = "",
        subcategory: str = "",
        limit: int = 100,
        offset: int = 0,
        refresh: bool = False,
        include_all: bool = False,
    ) -> str:
        """Which applications can a file-blocking rule name?

        The write API accepts only applications whose ``file_type_ident`` flag
        is true; transfer-only apps and container apps are rejected, and the API
        reports just the first bad name per request.  Use ``check`` to test a
        list of names up front.  First call per tenant fetches the whole
        applications catalogue (~60-90 s, 11k rows), then it is cached for 6 h.

        With ``check``: a verdict per name (eligible, not_eligible_transfer_only,
        container, not_eligible, unknown with close matches).  Without it: a
        paged list of eligible apps filtered by name/category/subcategory
        (``include_all=True`` also lists the non-eligible ones).

        Args:
            check: Exact application names to test (max 200).
            name_contains: Case-insensitive substring filter on the name.
            category: Exact category filter (case-insensitive).
            subcategory: Exact subcategory filter (case-insensitive).
            limit: Page size, 1-500 (default 100).
            offset: Page offset.
            refresh: Bypass the cache (use after a content release).
            include_all: Also list non-eligible apps, with an eligible field.
            tenant_id: SCM tenant ID.
        """
        if check is not None and len(check) > CHECK_MAX:
            return f"Error: check accepts at most {CHECK_MAX} names (got {len(check)})"
        cat, err = get_catalogue(client, tenant_id, refresh=refresh, wait=WAIT_BUDGET)
        if err == WARMING_MSG:
            return f"Catalogue warming: {err}."
        if err:
            return f"Error: could not read the applications catalogue: {err}"
        out: dict[str, Any] = {
            "tenant": tenant_id or "default",
            "folder": "All",
            "content_note": CONTENT_NOTE,
            "cached": cat.cached,
            "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(cat.fetched_at)),
            "totals": cat.totals(),
        }
        if check is not None:
            out["results"] = [classify(n, cat) for n in check]
            return _fmt(out)

        needle, cat_f, sub_f = name_contains.lower(), category.lower(), subcategory.lower()
        matches = []
        for name in sorted(cat.apps):
            info = cat.apps[name]
            if not include_all and not info.eligible:
                continue
            if needle and needle not in name.lower():
                continue
            if cat_f and info.category.lower() != cat_f:
                continue
            if sub_f and info.subcategory.lower() != sub_f:
                continue
            row: dict[str, Any] = {
                "name": name,
                "category": info.category,
                "subcategory": info.subcategory,
                "risk": info.risk,
            }
            if include_all:
                row["eligible"] = info.eligible
                if not info.eligible:
                    row["reason"] = "transfer_only" if info.transfer_only else "not_flagged"
            matches.append(row)
        limit = max(1, min(int(limit), LIMIT_MAX))
        offset = max(0, int(offset))
        out.update(
            total_matches=len(matches),
            offset=offset,
            limit=limit,
            items=matches[offset : offset + limit],
        )
        return _fmt(out)

    @mcp.tool()
    @tool
    def scm_file_blocking_profile(
        client: Any,
        tenant_id: str,
        action: str = "list",
        folder: str = "",
        snippet: str = "",
        device: str = "",
        name: str = "",
        profile_id: str = "",
        description: str | None = None,
        rules_json: str = "",
        dry_run: bool = True,
        ticket_ref: str = "",
        skip_app_check: bool = False,
        limit: int = 200,
    ) -> str:
        """List and manage file-blocking security profiles.

        Actions:
          * ``list`` - profiles in a folder/snippet/device (optional ``name``
            substring filter).
          * ``get`` - one profile by ``profile_id``, or ``name`` + container.
          * ``create`` - new profile from ``rules_json``.
          * ``update`` - replace the profile's rules (``rules_json`` is the FULL
            new list; no partial patching) and/or ``description``.
          * ``delete`` - remove a profile; refused while a profile group in the
            same container references it.

        ``rules_json`` is a JSON list of ``{"name", "action", "application",
        "direction", "file_type"}``; defaults are action alert, application
        ["any"], direction both, file_type ["any"].  Applications are
        pre-validated against the tenant's catalogue (see
        scm_file_blocking_apps; first call per tenant can take up to a minute and then reports "still loading"; the check is skipped with a note) and ALL offenders
        are reported together.  ``skip_app_check=True`` bypasses that check and
        lets the API decide (it reports only the first bad name).  file_type is
        checked for syntax only.

        **Write safety (SSR pattern):** ``dry_run=True`` by default; a dry run
        reads only and returns the planned request.  ``ticket_ref`` is
        mandatory for every write action (dry runs included), is logged, and
        is never sent to SCM.  No commit is performed: run scm_commit.

        Args:
            action: list (default), get, create, update or delete.
            folder: Folder container (pass only one of folder, snippet, device).
            snippet: Snippet container.
            device: Device container.
            name: Profile name (create/update/delete/get target; list filter).
            profile_id: Profile UUID (get/update/delete).
            description: Profile description (create/update).
            rules_json: JSON list of rules (create; update replaces all rules).
            dry_run: If True (default), preview a write without applying it.
            ticket_ref: Mandatory change-ticket reference for writes.
            skip_app_check: Skip the application eligibility pre-check.
            limit: Maximum rows returned by list.
            tenant_id: SCM tenant ID.
        """
        if action not in _ACTIONS:
            return f"Error: unknown action {action!r} - use one of: {', '.join(_ACTIONS)}"
        scope, err = _scope(folder, snippet, device)
        if err:
            return f"Error: {err}"

        if action == "list":
            if not scope:
                return "Error: list needs one of folder, snippet or device"
            rows = _list_all(client, scope)
            if name:
                rows = [r for r in rows if name.lower() in str(r.get("name", "")).lower()]
            shown = rows[: max(0, limit)]
            return _fmt({"scope": scope, "total": len(rows), "items": shown})
        if action == "get":
            if profile_id:
                item = _fetch_by_id(client, profile_id.strip())
            elif name and scope:
                item = _fetch(client, name, scope)
            else:
                return "Error: get needs profile_id, or name with one of folder/snippet/device"
            if item is None:
                return "Error: file-blocking profile not found"
            return _fmt({"item": item})

        err = ticket_ref_error(ticket_ref)
        if err:
            return f"Error: {err}"
        ticket_ref = normalize_ticket_ref(ticket_ref)

        current: dict[str, Any] | None = None
        if action == "create":
            return _create(
                client,
                tenant_id,
                scope,
                name,
                description,
                rules_json,
                dry_run,
                ticket_ref,
                skip_app_check,
            )

        # update / delete need the existing profile
        if profile_id.strip():
            current = _fetch_by_id(client, profile_id.strip())
        elif name and scope:
            current = _fetch(client, name, scope)
        else:
            return f"Error: {action} needs profile_id, or name with one of folder/snippet/device"
        if current is None:
            return "Error: file-blocking profile not found"
        if action == "update":
            return _update(
                client,
                tenant_id,
                current,
                description,
                rules_json,
                dry_run,
                ticket_ref,
                skip_app_check,
            )
        return _delete(client, tenant_id, current, dry_run, ticket_ref)


def _create(
    client: Any,
    tenant_id: str,
    scope: dict[str, str],
    name: str,
    description: str | None,
    rules_json: str,
    dry_run: bool,
    ticket_ref: str,
    skip_app_check: bool,
) -> str:
    if not scope:
        return "Error: create needs one of folder, snippet or device"
    if not _NAME_RE.match(name or ""):
        return "Error: name must be 1-31 characters from A-Z a-z 0-9 space . _ -"
    rules, errors = parse_rules(rules_json)
    if errors:
        return "Error: invalid rules_json:\n  - " + "\n  - ".join(errors)
    validation, err = _validate(client, tenant_id, rules, skip_app_check)
    if err:
        return f"Error: {err}"
    if _fetch(client, name, scope) is not None:
        return f"Error: profile {name!r} already exists in {next(iter(scope.values()))}; use action=update"
    body: dict[str, Any] = {"name": name, **scope, "rules": rules}
    if description:
        body["description"] = description
    if dry_run:
        return _fmt(
            {
                "action": "create",
                "dry_run": True,
                "ticket_ref": ticket_ref,
                "request": {"method": "POST", "path": _BASE, "body": body},
                "validation": validation,
                "exists": False,
                "hint": DRY_RUN_HINT,
            }
        )
    audit_write("scm_file_blocking_profile", ticket_ref, tenant_id, action="create", path=_BASE)
    result = client.post(_BASE, json=body)
    return _fmt(
        {
            "action": "create",
            "applied": True,
            "ticket_ref": ticket_ref,
            "result": result,
            "validation": validation,
            "hint": COMMIT_HINT,
        }
    )


def _update(
    client: Any,
    tenant_id: str,
    current: dict[str, Any],
    description: str | None,
    rules_json: str,
    dry_run: bool,
    ticket_ref: str,
    skip_app_check: bool,
) -> str:
    if not rules_json and description is None:
        return "Error: update needs rules_json (the full new list) and/or description"
    before = [r for r in current.get("rules") or [] if isinstance(r, dict)]
    after = before
    validation: dict[str, Any] = {"ok": True, "issues": [], "app_check": "rules unchanged"}
    if rules_json:
        after, errors = parse_rules(rules_json)
        if errors:
            return "Error: invalid rules_json:\n  - " + "\n  - ".join(errors)
        validation, err = _validate(client, tenant_id, after, skip_app_check)
        if err:
            return f"Error: {err}"
    data = {**current, "rules": after}
    if description is not None:
        data["description"] = description
    path = f"{_BASE}/{current['id']}"
    body = scm_rest.put_payload(_SDK_ATTR, data)
    if dry_run:
        return _fmt(
            {
                "action": "update",
                "dry_run": True,
                "ticket_ref": ticket_ref,
                "request": {"method": "PUT", "path": path, "body": body},
                "rule_diff": _diff(before, after),
                "validation": validation,
                "hint": DRY_RUN_HINT,
            }
        )
    audit_write("scm_file_blocking_profile", ticket_ref, tenant_id, action="update", path=path)
    result = scm_rest.put_object(client, _SDK_ATTR, data)
    # A PUT can answer 200 and change nothing: read it back and compare.
    stored = _fetch_by_id(client, str(current["id"]))
    verified = False
    if stored is not None:
        verified = _rules_by_name(stored.get("rules") or []) == _rules_by_name(after)
        if description is not None:
            verified = verified and (stored.get("description") or "") == description
    out: dict[str, Any] = {
        "action": "update",
        "applied": True,
        "ticket_ref": ticket_ref,
        "result": result,
        "rule_diff": _diff(before, after),
        "validation": validation,
        "verified": verified,
        "hint": COMMIT_HINT,
    }
    if not verified:
        out["warning"] = "read-back does not match the update; the API may have ignored it"
    return _fmt(out)


def _delete(
    client: Any, tenant_id: str, current: dict[str, Any], dry_run: bool, ticket_ref: str
) -> str:
    scope = {k: str(current[k]) for k in _SCOPE_KEYS if current.get(k)}
    groups, lookup_err = _referencing_groups(client, str(current.get("name")), scope)
    check = {"reference_check": "same container only (profile groups)", "referenced_by": groups}
    if lookup_err:
        check["warning"] = lookup_err
    path = f"{_BASE}/{current['id']}"
    if groups:
        return (
            f"Error: profile {current.get('name')!r} is referenced by profile group(s) "
            f"{groups}; remove it from them first ({check['reference_check']})"
        )
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
    audit_write("scm_file_blocking_profile", ticket_ref, tenant_id, action="delete", path=path)
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
