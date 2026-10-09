"""
Local SQLite search index over extracted SCM config — the Global Find replacement.

SCM's Global Search is a UI feature that live-queries a multi-tenant control
plane: it string-matches, it is slow, it is scoped to one tenant, and it cannot
answer "which rules reference anything inside 10.20.0.0/16". Every object it
searches is already available through the same API this server uses, so the fix
is to keep a local copy and query that instead.

``index_snapshot`` flattens an :class:`AuditSnapshot` into one row per config
object and writes it to SQLite; ``search`` queries across every indexed tenant
at once. One current index per (tenant, folder) — history already lives in
``backups/`` (scm_config_backup) and ``baselines/`` (scm_drift_baseline); this
is a lookup table, not an archive.

Two query paths:

  * **Text** — FTS5 with bm25 ranking over the flattened object, falling back
    to infix ``LIKE`` on the same blob when FTS5
    is unavailable in the host's SQLite build, or when a ranked search returns
    nothing (FTS5 tokenizes on non-alphanumerics, so a fragment inside a token
    like ``ayment`` has no ranked match but is still worth finding).
  * **IP** — real containment. Any address literal found anywhere in an object
    is stored as a start/end range, so searching an IP returns every object
    whose range covers it, not just objects that spell it the same way.

Pure functions only — no SCM client or MCP imports (same contract as
``drift_baseline``). Connections are opened per call rather than shared: MCP
tools run on multiple threads and a per-call connection needs no locking.
"""

from __future__ import annotations

import contextlib
import ipaddress
import re
import sqlite3
import time
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

from ..utils.paths import index_dir
from .models import AuditSnapshot

_DEFAULT_INDEX_DIR = index_dir()
_INDEX_FILENAME = "config_index.db"

# AuditSnapshot fields that are NOT searchable config objects. Everything else
# holding a list of dicts is indexed automatically, so config sections added to
# the model in future are picked up without touching this module.
#
#   telemetry  — runtime status that changes by the minute; stale the moment it
#                is written, and answering from a stale copy would be worse than
#                not answering (use the live tools: scm_insights_query, adem).
#   inventory  — device/licence state, not policy; already has dedicated tools.
#   sd-wan     — populated by extract_sdwan_snapshot, not extract_snapshot, so
#                these are empty here anyway; the sdwan_* tools own that estate.
#   identity   — per-user and per-device records. Excluded deliberately: an
#                estate-wide grep-able copy of who browses what is a privacy
#                liability, and no policy question needs it.
_NON_CONFIG_FIELDS: frozenset[str] = frozenset(
    {
        # telemetry / runtime status
        "insights_rn_status",
        "insights_sc_status",
        "insights_mu_status",
        "insights_rn_bandwidth",
        "insights_sc_bandwidth",
        "insights_tunnel_list",
        "insights_alerts",
        "adem_app_scores",
        "mt_monitor_alerts",
        "prisma_egress_ips",
        "ngfw_interface_ips",
        "app_accl_apps",
        "iot_alerts",
        "iot_vulnerabilities",
        "iot_policy_recommendations",
        # inventory, not policy
        "licenses",
        "pab_tenant_licenses",
        "managed_tenants",
        "sspm_catalog",
        # SD-WAN — different extractor, different tool family
        "sdwan_sites",
        "sdwan_elements",
        "sdwan_wan_interfaces",
        "sdwan_wan_networks",
        "sdwan_path_groups",
        "sdwan_policy_sets",
        "sdwan_priority_policy_sets",
        "sdwan_hub_clusters",
        "sdwan_spoke_clusters",
        "sdwan_bgp_peers",
        "sdwan_vpn_links",
        "sdwan_wan_ips",
        "sdwan_detected_public_ips",
        # per-user / per-device identity records
        "browser_users",
        "browser_devices",
        "browser_user_requests",
        "iot_devices",
        "iam_service_accounts",
        # not object data
        "extraction_errors",
    }
)

_LIST_FIELDS: frozenset[str] = frozenset(
    f.name for f in fields(AuditSnapshot) if f.type.startswith("list[dict")
)

INDEXABLE_FIELDS: frozenset[str] = _LIST_FIELDS - _NON_CONFIG_FIELDS

# Keys whose values carry no search signal — they are opaque identifiers that
# would only dilute bm25 ranking. `id` is still stored in its own column.
_SKIP_KEYS: frozenset[str] = frozenset({"id", "uuid", "tenant_id", "@uuid"})

# Per-object cap on the flattened text blob. Security rules with large member
# lists would otherwise dominate the FTS index; 4000 chars covers every real
# rule seen in practice while bounding worst-case index size.
_MAX_VALUE_CHARS = 4000

# Palo Alto ships the App-ID catalogue (~11k signatures on a current content
# release) into every tenant under this snippet. It is vendor reference data,
# byte-identical across tenants, and on a typical Prisma Access tenant it is
# ~98% of the objects and ~95% of the index size — indexing it by default would
# bury nine real security rules under ten thousand app descriptions and cost
# ~25 MB per tenant to do it. Excluded unless explicitly asked for.
_PREDEFINED_SNIPPET_PREFIX = "predefined"


def is_predefined(obj: dict[str, Any]) -> bool:
    """True for vendor content shipped into the tenant rather than configured in it."""
    return str(obj.get("snippet") or "").startswith(_PREDEFINED_SNIPPET_PREFIX)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS objects (
    id          INTEGER PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    folder      TEXT NOT NULL,
    obj_type    TEXT NOT NULL,
    name        TEXT NOT NULL,
    uuid        TEXT,
    scope       TEXT,
    description TEXT,
    tags        TEXT,
    summary     TEXT,
    predefined  INTEGER NOT NULL DEFAULT 0,
    value       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS objects_by_snapshot ON objects (tenant_id, folder);
CREATE INDEX IF NOT EXISTS objects_by_type ON objects (obj_type);
CREATE INDEX IF NOT EXISTS objects_by_name ON objects (name);

CREATE TABLE IF NOT EXISTS ip_ranges (
    object_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
    version   INTEGER NOT NULL,
    start_hex TEXT NOT NULL,
    end_hex   TEXT NOT NULL,
    cidr      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ip_ranges_by_start ON ip_ranges (version, start_hex);
CREATE INDEX IF NOT EXISTS ip_ranges_by_object ON ip_ranges (object_id);

CREATE TABLE IF NOT EXISTS index_meta (
    tenant_id    TEXT NOT NULL,
    folder       TEXT NOT NULL,
    tenant_label TEXT,
    indexed_at   REAL NOT NULL,
    object_count INTEGER NOT NULL,
    type_count   INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, folder)
);
"""

_FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS objects_fts
USING fts5(name, value, description, tags);
"""


@dataclass
class IndexStats:
    """Outcome of indexing one snapshot."""

    tenant_id: str
    folder: str
    object_count: int
    type_count: int
    ip_range_count: int
    predefined_skipped: int
    fts: bool
    db_path: str
    elapsed: float


@dataclass
class Hit:
    """One search result."""

    tenant_id: str
    tenant_label: str
    folder: str
    obj_type: str
    name: str
    scope: str
    summary: str
    matched_cidr: str = ""


# ── Storage ───────────────────────────────────────────────────────────────────


def index_path(index_dir: Path | None = None) -> Path:
    return (index_dir or _DEFAULT_INDEX_DIR) / _INDEX_FILENAME


def connect(index_dir: Path | None = None) -> sqlite3.Connection:
    """Open (creating if needed) the index database with its schema applied."""
    path = index_path(index_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(_SCHEMA)
    # No FTS5 in this SQLite build — searches fall back to infix LIKE.
    with contextlib.suppress(sqlite3.OperationalError):
        conn.executescript(_FTS_SCHEMA)
    conn.commit()
    return conn


def fts_available(conn: sqlite3.Connection) -> bool:
    """True when the FTS5 index table exists.

    Python's bundled SQLite normally has FTS5, but distro and container builds
    vary — an index that silently produced zero hits on such a host would be a
    very confusing failure, so both paths are supported. Probing for the table
    rather than trying to create one keeps every search read-only.
    """
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'objects_fts'"
    ).fetchone()
    return row is not None


# ── Flattening ────────────────────────────────────────────────────────────────


def _leaves(node: Any, out: list[str], depth: int = 0) -> None:
    """Collect scalar leaf values from an arbitrarily nested SDK dict."""
    if depth > 8:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _SKIP_KEYS:
                continue
            _leaves(value, out, depth + 1)
    elif isinstance(node, list | tuple):
        for item in node:
            _leaves(item, out, depth + 1)
    elif isinstance(node, str):
        if node:
            out.append(node)
    elif isinstance(node, bool):
        out.append("true" if node else "false")
    elif isinstance(node, int | float):
        out.append(str(node))


def flatten_values(obj: dict[str, Any]) -> str:
    """Every scalar in the object as one searchable blob, capped for size.

    Deliberately type-agnostic: a per-type field map would need updating every
    time the SDK grows a field, and recall matters more here than precision —
    an unexpected match is a nuisance, a missed rule is the bug this whole
    index exists to prevent.
    """
    out: list[str] = []
    _leaves(obj, out)
    blob = " ".join(out)
    return blob[:_MAX_VALUE_CHARS]


_IP_TOKEN = re.compile(r"[0-9A-Fa-f:.]+(?:/\d{1,3})?")


def _hexpair(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> tuple[str, str]:
    """Network bounds as fixed-width hex.

    Zero-padded hex sorts identically to the integer it encodes, so ``BETWEEN``
    on TEXT is a correct containment test — which keeps IPv6 (128-bit, well past
    SQLite's signed 64-bit INTEGER) on exactly the same code path as IPv4.
    """
    width = 8 if net.version == 4 else 32
    return (
        format(int(net.network_address), f"0{width}x"),
        format(int(net.broadcast_address), f"0{width}x"),
    )


def _as_network(text: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


def extract_ip_ranges(obj: dict[str, Any]) -> list[tuple[int, str, str, str]]:
    """(version, start_hex, end_hex, cidr) for every address literal in the object.

    Covers the forms SCM actually stores: ``ip_netmask`` (10.0.0.0/24), bare
    addresses, and ``ip_range`` (10.0.0.1-10.0.0.50). FQDN and wildcard
    addresses have no numeric range and are found by text search instead.
    """
    seen: set[tuple[int, str, str, str]] = set()
    values: list[str] = []
    _leaves(obj, values)
    for value in values:
        for token in _IP_TOKEN.findall(value):
            if not any(c in token for c in ".:"):
                continue
            net = _as_network(token)
            if net is not None:
                start, end = _hexpair(net)
                seen.add((net.version, start, end, str(net)))
        # ip_range form ("10.0.0.1-10.0.0.50"): the token regex stops at the
        # hyphen, so ranges are recovered by splitting the original value.
        if "-" in value:
            left, _, right = value.partition("-")
            lo, hi = _as_network(left.strip()), _as_network(right.strip())
            if lo is not None and hi is not None and lo.version == hi.version:
                start, _ = _hexpair(lo)
                _, end = _hexpair(hi)
                if start <= end:
                    seen.add((lo.version, start, end, f"{lo.network_address}-{hi.network_address}"))
    return sorted(seen)


def _first_str(obj: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = obj.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _joined(value: Any, limit: int = 6) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        items = [str(v) for v in value if v]
        head = ", ".join(items[:limit])
        return f"{head} (+{len(items) - limit} more)" if len(items) > limit else head
    return ""


def summarize(obj_type: str, obj: dict[str, Any]) -> str:
    """A one-line, human-readable gist of the object for result tables."""
    if obj_type == "addresses":
        return _first_str(obj, "ip_netmask", "ip_range", "ip_wildcard", "fqdn")
    if obj_type in ("address_groups", "service_groups", "application_groups"):
        static = obj.get("static") or obj.get("members")
        if isinstance(static, list):
            return f"{len(static)} member(s): {_joined(static, 4)}"
        dynamic = obj.get("dynamic")
        if isinstance(dynamic, dict):
            return f"dynamic: {dynamic.get('filter', '')}"
        return _joined(static)
    if obj_type == "services":
        proto = obj.get("protocol")
        if isinstance(proto, dict):
            for name in ("tcp", "udp"):
                spec = proto.get(name)
                if isinstance(spec, dict):
                    return f"{name}/{spec.get('port', '')}"
        return ""
    if obj_type.endswith("_rules") or obj_type.startswith("security_rules"):
        src = _joined(obj.get("source"), 3) or "any"
        dst = _joined(obj.get("destination"), 3) or "any"
        app = _joined(obj.get("application"), 3) or "any"
        action = obj.get("action") or obj.get("type") or ""
        state = "" if obj.get("disabled") is not True else " [disabled]"
        return f"{src} → {dst} | app: {app} | {action}{state}"
    if obj_type == "edls":
        return _first_str(obj, "url") or _joined(obj.get("type"))
    return _first_str(obj, "description", "url", "address", "hostname", "value")


def _tags_of(obj: dict[str, Any]) -> str:
    tag = obj.get("tag")
    if isinstance(tag, list):
        return " ".join(str(t) for t in tag if t)
    return str(tag) if tag else ""


def _name_of(obj: dict[str, Any]) -> str:
    return _first_str(obj, "name", "display_name", "title") or _first_str(obj, "id")


def _scope_of(obj: dict[str, Any]) -> str:
    return _first_str(obj, "folder", "snippet", "device")


# ── Indexing ──────────────────────────────────────────────────────────────────


def index_snapshot(
    snap: AuditSnapshot,
    index_dir: Path | None = None,
    tenant_label: str = "",
    include_predefined: bool = False,
) -> IndexStats:
    """Replace the stored index for this snapshot's (tenant, folder).

    The rebuild is a single transaction: a failure part-way leaves the previous
    index intact rather than a half-populated one, which matters because the
    caller is usually a scheduled sweep nobody is watching.

    ``include_predefined`` pulls in the shipped App-ID catalogue too — off by
    default, see :data:`_PREDEFINED_SNIPPET_PREFIX`.
    """
    started = time.monotonic()
    conn = connect(index_dir)
    use_fts = fts_available(conn)
    tenant_id = snap.tenant_id or "default"
    folder = snap.folder or ""

    rows = 0
    ranges = 0
    skipped = 0
    types: set[str] = set()
    try:
        with conn:
            stale = [
                r[0]
                for r in conn.execute(
                    "SELECT id FROM objects WHERE tenant_id = ? AND folder = ?",
                    (tenant_id, folder),
                )
            ]
            if stale:
                # `marks` is only "?,?,?…" — the row ids themselves stay bound
                # parameters, so the interpolation carries no caller data.
                marks = ",".join("?" * len(stale))
                conn.execute(
                    f"DELETE FROM ip_ranges WHERE object_id IN ({marks})",  # nosec B608
                    stale,
                )
                if use_fts:
                    conn.execute(
                        f"DELETE FROM objects_fts WHERE rowid IN ({marks})",  # nosec B608
                        stale,
                    )
                conn.execute(f"DELETE FROM objects WHERE id IN ({marks})", stale)  # nosec B608

            for field_name in sorted(INDEXABLE_FIELDS):
                items = getattr(snap, field_name, None)
                if not items:
                    continue
                for obj in items:
                    if not isinstance(obj, dict):
                        continue
                    name = _name_of(obj)
                    if not name:
                        continue
                    predefined = is_predefined(obj)
                    if predefined and not include_predefined:
                        skipped += 1
                        continue
                    value = flatten_values(obj)
                    description = _first_str(obj, "description")
                    tags = _tags_of(obj)
                    cur = conn.execute(
                        "INSERT INTO objects (tenant_id, folder, obj_type, name, uuid, scope, "
                        "description, tags, summary, predefined, value) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            tenant_id,
                            folder,
                            field_name,
                            name,
                            _first_str(obj, "id"),
                            _scope_of(obj),
                            description,
                            tags,
                            summarize(field_name, obj),
                            int(predefined),
                            value,
                        ),
                    )
                    object_id = int(cur.lastrowid or 0)
                    if use_fts:
                        conn.execute(
                            "INSERT INTO objects_fts (rowid, name, value, description, tags) "
                            "VALUES (?,?,?,?,?)",
                            (object_id, name, value, description, tags),
                        )
                    for version, start, end, cidr in extract_ip_ranges(obj):
                        conn.execute(
                            "INSERT INTO ip_ranges (object_id, version, start_hex, end_hex, cidr) "
                            "VALUES (?,?,?,?,?)",
                            (object_id, version, start, end, cidr),
                        )
                        ranges += 1
                    rows += 1
                    types.add(field_name)

            conn.execute(
                "INSERT INTO index_meta (tenant_id, folder, tenant_label, indexed_at, "
                "object_count, type_count) VALUES (?,?,?,?,?,?) "
                "ON CONFLICT(tenant_id, folder) DO UPDATE SET tenant_label=excluded.tenant_label, "
                "indexed_at=excluded.indexed_at, object_count=excluded.object_count, "
                "type_count=excluded.type_count",
                (tenant_id, folder, tenant_label, time.time(), rows, len(types)),
            )
    finally:
        conn.close()

    return IndexStats(
        tenant_id=tenant_id,
        folder=folder,
        object_count=rows,
        type_count=len(types),
        ip_range_count=ranges,
        predefined_skipped=skipped,
        fts=use_fts,
        db_path=str(index_path(index_dir)),
        elapsed=time.monotonic() - started,
    )


def index_status(index_dir: Path | None = None) -> list[dict[str, Any]]:
    """What is currently indexed, newest first. Empty list when no index exists."""
    path = index_path(index_dir)
    if not path.exists():
        return []
    conn = connect(index_dir)
    try:
        return [
            dict(r)
            for r in conn.execute(
                "SELECT tenant_id, folder, tenant_label, indexed_at, object_count, type_count "
                "FROM index_meta ORDER BY indexed_at DESC"
            )
        ]
    finally:
        conn.close()


# ── Search ────────────────────────────────────────────────────────────────────


def parse_ip_query(query: str) -> tuple[int, str, str] | None:
    """(version, start_hex, end_hex) when the query is an address or CIDR."""
    text = query.strip()
    if not any(c in text for c in ".:"):
        return None
    net = _as_network(text)
    if net is None:
        return None
    start, end = _hexpair(net)
    return net.version, start, end


def fts_expr(query: str) -> str:
    """Quote each term so arbitrary user input can never be FTS5 syntax.

    Terms become prefix phrases (``"payments"*``), which is what a search box
    is expected to do; the unicode61 tokenizer already splits ``srv-payments-db``
    so a mid-name word still matches its object.
    """
    terms = [t for t in re.split(r"\s+", query.strip()) if t]
    return " ".join('"{}"*'.format(t.replace('"', '""')) for t in terms)


def _filters(
    tenant_ids: list[str] | None,
    folder: str,
    obj_types: list[str] | None,
    include_predefined: bool,
) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if not include_predefined:
        clauses.append("o.predefined = 0")
    if tenant_ids:
        clauses.append("o.tenant_id IN ({})".format(",".join("?" * len(tenant_ids))))
        params.extend(tenant_ids)
    if folder:
        clauses.append("o.folder = ?")
        params.append(folder)
    if obj_types:
        clauses.append("o.obj_type IN ({})".format(",".join("?" * len(obj_types))))
        params.extend(obj_types)
    return (" AND " + " AND ".join(clauses) if clauses else ""), params


_SELECT = (
    "SELECT o.tenant_id, o.folder, o.obj_type, o.name, o.scope, o.summary, "
    "COALESCE(m.tenant_label, '') AS tenant_label"
)
_FROM = "FROM objects o LEFT JOIN index_meta m ON m.tenant_id = o.tenant_id AND m.folder = o.folder"


def search(
    query: str,
    index_dir: Path | None = None,
    tenant_ids: list[str] | None = None,
    folder: str = "",
    obj_types: list[str] | None = None,
    limit: int = 50,
    include_predefined: bool = False,
) -> tuple[list[Hit], str]:
    """Search the index. Returns (hits, mode) where mode names the path taken."""
    path = index_path(index_dir)
    if not path.exists():
        return [], "no-index"
    query = query.strip()
    if not query:
        return [], "empty"

    limit = max(1, min(limit, 500))
    where, params = _filters(tenant_ids, folder, obj_types, include_predefined)
    conn = connect(index_dir)
    try:
        ip_query = parse_ip_query(query)
        if ip_query is not None:
            version, start, end = ip_query
            # Overlap, not containment: searching a /16 should also surface the
            # /24s inside it, which is the question an engineer is really asking.
            rows = conn.execute(
                f"{_SELECT}, r.cidr AS matched_cidr {_FROM} "
                "JOIN ip_ranges r ON r.object_id = o.id "
                f"WHERE r.version = ? AND r.start_hex <= ? AND r.end_hex >= ?{where} "
                "ORDER BY (r.end_hex > r.start_hex), o.obj_type, o.name LIMIT ?",
                [version, end, start, *params, limit],
            ).fetchall()
            if rows:
                return [_hit(r) for r in rows], "ip"

        if fts_available(conn):
            try:
                rows = conn.execute(
                    f"{_SELECT}, '' AS matched_cidr {_FROM} "
                    "JOIN objects_fts f ON f.rowid = o.id "
                    f"WHERE objects_fts MATCH ?{where} ORDER BY rank LIMIT ?",
                    [fts_expr(query), *params, limit],
                ).fetchall()
            except sqlite3.OperationalError:
                rows = []
            if rows:
                return [_hit(r) for r in rows], "fts"

        like = f"%{query}%"
        rows = conn.execute(
            f"{_SELECT}, '' AS matched_cidr {_FROM} "
            "WHERE (o.name LIKE ? OR o.value LIKE ?)"
            f"{where} ORDER BY o.obj_type, o.name LIMIT ?",
            [like, like, *params, limit],
        ).fetchall()
        return [_hit(r) for r in rows], "like"
    finally:
        conn.close()


def _hit(row: sqlite3.Row) -> Hit:
    return Hit(
        tenant_id=row["tenant_id"],
        tenant_label=row["tenant_label"],
        folder=row["folder"],
        obj_type=row["obj_type"],
        name=row["name"],
        scope=row["scope"] or "",
        summary=row["summary"] or "",
        matched_cidr=row["matched_cidr"] or "",
    )
