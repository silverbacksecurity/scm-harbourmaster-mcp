"""One MCP tool for the core policy objects: ``scm_object``.

Lists, reads and (dry-run first) writes four object types through a per-kind
spec table, so a single tool (one slot in its domain's tool cap) covers them:

  * ``address_group`` - ``/config/objects/v1/address-groups`` (static or dynamic)
  * ``service`` - ``/config/objects/v1/services`` (TCP or UDP)
  * ``service_group`` - ``/config/objects/v1/service-groups``
  * ``tag`` - ``/config/objects/v1/tags``

Addresses keep their own tools (``scm_address_*``); EDLs, application groups
and application filters are not covered yet.

The engine is ``security_profile``'s (validate, merge, read back, delete guard),
parameterised by a ``Spec``.  What is specific here:

  * **Member checks.**  Static address group and service group members must
    exist in the group's scope (inherited and predefined objects included);
    nested groups may not form a cycle; dynamic filter tags are looked up and
    reported as warnings.
  * **Delete guard.**  A delete is refused while anything references the
    object.  The reference table is the clone preflight's
    (``clone_preflight.REFERENCE_FIELDS``), so the two cannot drift.  The
    response states what was scanned and what was not, and a lookup that
    fails refuses the delete.
  * **No rename.**  Rules reference objects by name, so ``update`` refuses a
    changed name.

**Write safety (SSR pattern):** ``dry_run=True`` by default, ``ticket_ref``
mandatory for every write action (dry runs included), logged and never sent in
a body.  Commit is a separate ``scm_commit`` step.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..audit import clone_preflight
from ..utils import scm_rest
from ..utils.formatting import format_result as _fmt
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool
from ..utils.write_safety import normalize_ticket_ref, ticket_ref_error
from ._crud_engine import Int, L, Node, Obj, S, X, _scope
from .security_profile import (
    _ACTIONS,
    _PAGE,
    Spec,
    _create,
    _delete,
    _fetch,
    _fetch_by_id,
    _list_all,
    _summary,
    _update,
)
from .threat_profile import api_folder

logger = get_logger(__name__)

_HOST = "https://api.sase.paloaltonetworks.com"
_OBJECTS = f"{_HOST}/config/objects/v1"
_SECURITY = f"{_HOST}/config/security/v1"
_NETWORK = f"{_HOST}/config/network/v1"

# ---------------------------------------------------------------------------
# Schemas (pan.dev objects spec, objects_R3.yaml)
# ---------------------------------------------------------------------------

_TAG_COLORS = (
    "Red", "Green", "Blue", "Yellow", "Copper", "Orange", "Purple", "Gray",
    "Light Green", "Cyan", "Light Gray", "Blue Gray", "Lime", "Black", "Gold",
    "Brown", "Olive", "Maroon", "Red-Orange", "Yellow-Orange", "Forest Green",
    "Turquoise Blue", "Azure Blue", "Cerulean Blue", "Midnight Blue",
    "Medium Blue", "Cobalt Blue", "Violet Blue", "Blue Violet", "Medium Violet",
    "Medium Rose", "Lavender", "Orchid", "Thistle", "Peach", "Salmon", "Magenta",
    "Red Violet", "Mahogany", "Burnt Sienna", "Chestnut",
)  # fmt: skip

_TAGS = L(S(max_len=127))
_DESCRIPTION = S(max_len=1023)
_MEMBER = S(max_len=63)

_ADDRESS_GROUP_SCHEMA: dict[str, Node] = {
    "name": S(max_len=63, pattern=r"^[ a-zA-Z\d._-]+$"),
    "description": _DESCRIPTION,
    "tag": _TAGS,
    "static": L(_MEMBER),
    "dynamic": Obj({"filter": S(max_len=2047)}, required=("filter",)),
}

_SERVICE_SCHEMA: dict[str, Node] = {
    "name": S(max_len=63, pattern=r"^[ a-zA-Z\d.\-_]+$"),
    "description": _DESCRIPTION,
    "tag": _TAGS,
    "protocol": X(
        {
            "tcp": Obj(
                {
                    "port": S(max_len=1023, pattern=r"\S"),
                    "source_port": S(max_len=1023, pattern=r"\S"),
                    "override": Obj(
                        {
                            "timeout": Int(1, 604800),
                            "halfclose_timeout": Int(1, 604800),
                            "timewait_timeout": Int(1, 600),
                        }
                    ),
                },
                required=("port",),
            ),
            "udp": Obj(
                {
                    "port": S(max_len=1023, pattern=r"\S"),
                    "source_port": S(max_len=1023, pattern=r"\S"),
                    "override": Obj({"timeout": Int(1, 604800)}),
                },
                required=("port",),
            ),
        }
    ),
}

_SERVICE_GROUP_SCHEMA: dict[str, Node] = {
    "name": S(max_len=63, pattern=r"^[ a-zA-Z\d.\-_]+$"),
    "members": L(_MEMBER),
    "tag": _TAGS,
}

_TAG_SCHEMA: dict[str, Node] = {
    "name": S(max_len=127),
    "color": S(enum=_TAG_COLORS),
    "comments": _DESCRIPTION,
}

# ---------------------------------------------------------------------------
# Lookups
# ---------------------------------------------------------------------------


def _query(scope: dict[str, str]) -> dict[str, str]:
    """The container as the API takes it (a folder is aliased, e.g. Shared)."""
    return {k: (api_folder(v) if k == "folder" else v) for k, v in scope.items()}


def _rows(client: Any, url: str, params: dict[str, Any]) -> tuple[list[dict[str, Any]], str]:
    """Every row of a paged list call, or ([], error)."""
    rows: list[dict[str, Any]] = []
    try:
        scm_rest.refresh_token(client)
        session = scm_rest.bearer_session(client)
        offset = 0
        while True:
            res = scm_rest.request(
                session,
                "GET",
                url,
                params={**params, "limit": _PAGE, "offset": offset},
                timeout=clone_preflight._TIMEOUT,
            )
            if res.status != 200:
                return [], f"HTTP {res.status}{(': ' + res.error) if res.error else ''}"
            page = [r for r in clone_preflight._page_rows(res.data) if isinstance(r, dict)]
            rows.extend(page)
            if len(page) < _PAGE:
                return rows, ""
            offset += _PAGE
    except Exception as exc:
        return [], str(exc)[:200]


def _names(client: Any, scope: dict[str, str], *paths: str) -> tuple[set[str], str]:
    """Names of every object under *paths* visible from *scope* (inherited included)."""
    found: set[str] = set()
    for path in paths:
        rows, err = _rows(client, f"{_HOST}{path}", _query(scope))
        if err:
            return set(), f"{path}: {err}"
        found.update(str(r["name"]) for r in rows if r.get("name"))
    return found, ""


def _members_of(body: dict[str, Any], kind: str) -> list[str]:
    field = "static" if kind == "address_group" else "members"
    return [str(m) for m in (body.get(field) or [])]


def _cycle(
    client: Any, scope: dict[str, str], kind: str, name: str, members: list[str]
) -> tuple[str, str]:
    """(cycle description, lookup error) for *name* with *members* among its peers."""
    path = "/config/objects/v1/" + (
        "address-groups" if kind == "address_group" else "service-groups"
    )
    rows, err = _rows(client, f"{_HOST}{path}", _query(scope))
    if err:
        return "", err
    graph = {str(r["name"]): _members_of(r, kind) for r in rows if r.get("name")}
    graph[name] = members
    stack: list[str] = []

    def visit(node: str) -> list[str] | None:
        if node in stack:
            return stack[stack.index(node) :] + [node]
        if node not in graph:
            return None
        stack.append(node)
        for child in graph[node]:
            found = visit(child)
            if found is not None:
                return found
        stack.pop()
        return None

    loop = visit(name)
    return (" -> ".join(loop), "") if loop else ("", "")


def _make_check(kind: str, allow_unresolved: bool) -> Any:
    """The (errors, warnings) check for *kind* on the body that would be stored."""

    def check(
        client: Any,
        scope: dict[str, str],
        body: dict[str, Any],
        current: dict[str, Any] | None,
    ) -> tuple[list[str], list[str]]:
        errors: list[str] = []
        warnings: list[str] = []
        name = str(body.get("name") or "")
        if kind == "address_group":
            kinds = [k for k in ("static", "dynamic") if body.get(k)]
            if len(kinds) != 1:
                errors.append("set exactly one of static or dynamic (with a value)")
                return errors, warnings
            paths = ("/config/objects/v1/addresses", "/config/objects/v1/address-groups")
        elif kind == "service_group":
            if not body.get("members"):
                errors.append("members must list at least one service or service group")
                return errors, warnings
            paths = ("/config/objects/v1/services", "/config/objects/v1/service-groups")
        else:
            return errors, warnings

        if kind == "address_group" and body.get("dynamic"):
            warnings.append("the dynamic filter's tag names are not checked against the tag list")
            return errors, warnings

        members = _members_of(body, kind)
        if len(set(members)) != len(members):
            errors.append("a member is listed more than once")
        known, err = _names(client, scope, *paths)
        if err:
            warnings.append(f"could not check that the members exist ({err})")
        else:
            missing = sorted({m for m in members if m not in known})
            if missing:
                msg = f"members not found in {next(iter(scope.values()))}: {missing}"
                if allow_unresolved:
                    warnings.append(f"{msg} (allowed by allow_unresolved_members)")
                else:
                    errors.append(
                        f"{msg}; create them first, fix the names or pass "
                        "allow_unresolved_members=true"
                    )
        if name in members:
            errors.append(f"{name!r} lists itself as a member")
        else:
            loop, lookup_err = _cycle(client, scope, kind, name, members)
            if loop:
                errors.append(f"nested groups form a cycle: {loop}")
            elif lookup_err:
                warnings.append(f"could not check for nested-group cycles ({lookup_err})")
        return errors, warnings

    return check


# ---------------------------------------------------------------------------
# Reference scan (delete guard), driven by the clone preflight's table
# ---------------------------------------------------------------------------

_RESOURCES: tuple[tuple[str, str, str | None, str], ...] = (
    # (REFERENCE_FIELDS key, list URL, position, label)
    ("address_groups", f"{_OBJECTS}/address-groups", None, "address group"),
    ("service_groups", f"{_OBJECTS}/service-groups", None, "service group"),
    ("addresses", f"{_OBJECTS}/addresses", None, "address"),
    ("services", f"{_OBJECTS}/services", None, "service"),
    ("security_rules_pre", f"{_SECURITY}/security-rules", "pre", "security rule (pre)"),
    ("security_rules_post", f"{_SECURITY}/security-rules", "post", "security rule (post)"),
    ("nat_rules_pre", f"{_NETWORK}/nat-rules", "pre", "NAT rule (pre)"),
    ("nat_rules_post", f"{_NETWORK}/nat-rules", "post", "NAT rule (post)"),
    ("decryption_rules", f"{_SECURITY}/decryption-rules", "pre", "decryption rule (pre)"),
    ("decryption_rules", f"{_SECURITY}/decryption-rules", "post", "decryption rule (post)"),
    ("app_override_rules", f"{_SECURITY}/app-override-rules", "pre", "app-override rule (pre)"),
    ("app_override_rules", f"{_SECURITY}/app-override-rules", "post", "app-override rule (post)"),
)

# Object kind -> the reference kind in REFERENCE_FIELDS that names it
_REFERENCE_KIND = {
    "address_group": "address",
    "service": "service",
    "service_group": "service",
    "tag": "tag",
}


def _object_scan(kind: str) -> Any:
    ref_kind = _REFERENCE_KIND[kind]

    def scan(client: Any, name: str, scope: dict[str, str]) -> tuple[list[str], str]:
        found: list[str] = []
        for key, url, position, label in _RESOURCES:
            refs = [r for r in clone_preflight.REFERENCE_FIELDS.get(key, ()) if r.kind == ref_kind]
            if not refs:
                continue
            params = {**scope, **({"position": position} if position else {})}
            rows, err = _rows(client, url, params)
            if err:
                return sorted(found), f"{label} lookup failed: {err}"
            for row in rows:
                if not row.get("name") or (row["name"] == name and key.endswith("groups")):
                    continue
                if any(name in clone_preflight._ref_values(row, ref) for ref in refs):
                    found.append(f"{label} {row['name']}")
        return sorted(set(found)), ""

    return scan


_NOT_SCANNED = (
    "other folders, snippets and devices that inherit the object, the default "
    "rulebase, PBF/QoS/authentication rules, log-forwarding match lists, auto-tag "
    "actions, application filters, and anything outside SCM"
)


def _ref_scope(what: str) -> str:
    return (
        f"{what} in the same container (plus Mobile Users and Remote Networks for a "
        f"top-level folder); not scanned: {_NOT_SCANNED}"
    )


SPECS: dict[str, Spec] = {
    "address_group": Spec(
        kind="address_group",
        label="address group",
        path="/config/objects/v1/address-groups",
        sdk_attr="address_group",
        schema=_ADDRESS_GROUP_SCHEMA,
        required=(),
        readonly=frozenset(),
        ref_scan=_object_scan("address_group"),
        ref_scope=_ref_scope(
            "address groups, security, NAT, decryption and app-override rules (pre and post)"
        ),
        name_max=63,
        tool="scm_object",
        noun="object",
    ),
    "service": Spec(
        kind="service",
        label="service",
        path="/config/objects/v1/services",
        sdk_attr="service",
        schema=_SERVICE_SCHEMA,
        required=("protocol",),
        readonly=frozenset(),
        ref_scan=_object_scan("service"),
        ref_scope=_ref_scope("service groups, security, NAT and decryption rules (pre and post)"),
        name_max=63,
        tool="scm_object",
        noun="object",
    ),
    "service_group": Spec(
        kind="service_group",
        label="service group",
        path="/config/objects/v1/service-groups",
        sdk_attr="service_group",
        schema=_SERVICE_GROUP_SCHEMA,
        required=("members",),
        readonly=frozenset(),
        ref_scan=_object_scan("service_group"),
        ref_scope=_ref_scope("service groups, security, NAT and decryption rules (pre and post)"),
        name_max=63,
        tool="scm_object",
        noun="object",
    ),
    "tag": Spec(
        kind="tag",
        label="tag",
        path="/config/objects/v1/tags",
        sdk_attr="tag",
        schema=_TAG_SCHEMA,
        required=(),
        readonly=frozenset(),
        ref_scan=_object_scan("tag"),
        ref_scope=_ref_scope(
            "addresses, address groups, services, service groups, security, NAT, "
            "decryption and app-override rules (pre and post), and dynamic group filters"
        ),
        name_max=127,
        tool="scm_object",
        noun="object",
    ),
}
KINDS = tuple(SPECS)


def resolve_kind(kind: str) -> Spec | None:
    return SPECS.get((kind or "").strip().lower())


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_object_crud_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register the generic object CRUD tool."""
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_object(
        client: Any,
        tenant_id: str,
        kind: str,
        action: str = "list",
        folder: str = "",
        snippet: str = "",
        device: str = "",
        name: str = "",
        object_id: str = "",
        config_json: str = "",
        dry_run: bool = True,
        ticket_ref: str = "",
        allow_unresolved_members: bool = False,
        acknowledge_unscanned_scope: bool = False,
        limit: int = 200,
    ) -> str:
        """List and manage address groups, services, service groups and tags.

        Kinds: ``address_group``, ``service``, ``service_group``, ``tag``.
        Addresses have ``scm_address_*``; EDLs and application groups/filters
        are not covered here yet.

        Actions:
          * ``list`` - objects in a folder/snippet/device (optional ``name``
            substring filter); ``get`` returns the full body.
          * ``get`` - one object by ``object_id``, or ``name`` + container.
          * ``create`` - new object from ``config_json``.
          * ``update`` - merge ``config_json`` into the object.  Objects merge
            key by key; lists and one-of objects (a service's ``protocol``)
            replace; a null value removes a key.  Renaming is refused: rules
            reference objects by name.
          * ``delete`` - refused while another object or rule references it
            (the response lists what was and was not scanned), or when that
            lookup fails.  A top-level folder or snippet needs
            ``acknowledge_unscanned_scope``.

        ``config_json`` is an API-shaped JSON object; unknown keys, wrong types
        and bad enum values are all reported together.  Do not put id, folder,
        snippet or device in it; ``name`` may be given there or as the argument.
          * address_group: description, tag, and exactly one of ``static``
            (list of address or address group names) or ``dynamic``
            ``{"filter": "'tag1' and 'tag2'"}``.
          * service: description, tag, ``protocol`` set to exactly one of
            ``{"tcp": {"port", "source_port", "override": {timeout,
            halfclose_timeout, timewait_timeout}}}`` or ``{"udp": {...}}``
            (port is required, e.g. "80,443" or "1000-2000").
          * service_group: ``members`` (service or service group names), tag.
          * tag: ``color`` (one of SCM's 41 named colours) and ``comments``.

        Group members must exist in the group's scope (inherited and
        predefined objects count) and nested groups may not form a cycle.

        **Write safety (SSR pattern):** ``dry_run=True`` by default; a dry run
        reads only and returns the planned request.  ``ticket_ref`` is
        mandatory for every write action (dry runs included), is logged, and
        is never sent to SCM.  Writes are read back (``verified``).  No commit
        is performed: run scm_commit.

        Args:
            kind: address_group, service, service_group or tag.
            action: list (default), get, create, update or delete.
            folder: Folder container (pass only one of folder, snippet, device).
            snippet: Snippet container.
            device: Device container.
            name: Object name (create/update/delete/get target; list filter).
            object_id: Object UUID (get/update/delete).
            config_json: JSON object with the settings (create, update).
            dry_run: If True (default), preview a write without applying it.
            ticket_ref: Mandatory change-ticket reference for writes.
            allow_unresolved_members: Treat group members that are not found as warnings.
            acknowledge_unscanned_scope: delete only.  An object in a top-level folder
                (All, Shared, Prisma Access, Global) or a snippet is inherited by
                containers that cannot all be enumerated; set True to delete anyway.
            limit: Maximum rows returned by list.
            tenant_id: SCM tenant ID.
        """
        spec = resolve_kind(kind)
        if spec is None:
            return f"Error: unknown kind {kind!r} - use one of: {', '.join(KINDS)}"
        if action not in _ACTIONS:
            return f"Error: unknown action {action!r} - use one of: {', '.join(_ACTIONS)}"
        scope, err = _scope(folder, snippet, device)
        if err:
            return f"Error: {err}"

        if action == "list":
            if not scope:
                return "Error: list needs one of folder, snippet or device"
            rows = _list_all(client, spec, scope)
            if name:
                rows = [r for r in rows if name.lower() in str(r.get("name", "")).lower()]
            shown = [_summary(r) for r in rows[: max(0, limit)]]
            return _fmt({"kind": spec.kind, "scope": scope, "total": len(rows), "items": shown})
        if action == "get":
            if object_id:
                item = _fetch_by_id(client, spec, object_id.strip())
            elif name and scope:
                item = _fetch(client, spec, name, scope)
            else:
                return "Error: get needs object_id, or name with one of folder/snippet/device"
            if item is None:
                return f"Error: {spec.label} not found"
            return _fmt({"kind": spec.kind, "item": item})

        err = ticket_ref_error(ticket_ref)
        if err:
            return f"Error: {err}"
        ticket_ref = normalize_ticket_ref(ticket_ref)
        write_spec = dataclasses.replace(
            spec, check=_make_check(spec.kind, allow_unresolved_members)
        )

        if action == "create":
            return _create(
                client, tenant_id, write_spec, scope, name, config_json, dry_run, ticket_ref, True
            )

        if object_id.strip():
            current = _fetch_by_id(client, spec, object_id.strip())
        elif name and scope:
            current = _fetch(client, spec, name, scope)
        else:
            return f"Error: {action} needs object_id, or name with one of folder/snippet/device"
        if current is None:
            return f"Error: {spec.label} not found"
        if action == "update":
            return _update(
                client, tenant_id, write_spec, current, config_json, dry_run, ticket_ref, True
            )
        return _delete(
            client, tenant_id, spec, current, dry_run, ticket_ref, acknowledge_unscanned_scope
        )
