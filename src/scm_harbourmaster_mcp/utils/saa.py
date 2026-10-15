"""Secure Agentless Access (SAA) — shared fetch, region gate and risk checks.

SAA publishes private RDP/SSH/VNC hosts and web apps to users through the
browser, with no agent. One fetcher feeds ``scm_saa_list`` and the AS-BUILT
extractor, so both agree on what "SAA is provisioned" means.

API (pan.dev ``openapi-specs/scm/config/secure_agentless_access``):
  Base:  https://api.strata.paloaltonetworks.com/secure-agentless-access/v1
  Auth:  the tenant's SCM OAuth bearer token; the TSG comes from the token.
  Lists: /applications, /application-groups, /application-profiles,
         /application-policies, /active-sessions — offset/limit paging
         (max limit 1000), response ``{"data": [...], "total": n, ...}``.
         An empty policy list omits ``total`` and ``offset``.

Live behaviour (2026-10-15, every lab tenant):
  * Every request is routed by the ``x-panw-region`` header. Without it, or
    with the wrong region, /applications and /application-groups answer 404
    ``SAA_12008``/``SAA_22008`` "tenant not found". Only lowercase values work.
  * /application-profiles, /application-policies and /active-sessions answer
    200 in ANY region, wrong or right, with the system read-only profile and
    empty lists. They prove nothing until a region is established.
  * A tenant's first call in its region can answer the groups list before the
    applications list (404 then 200 moments later), so either list answering
    200 establishes the region.
  So "provisioned in region R" = /applications or /application-groups → 200
  with ``x-panw-region: R``; "not provisioned" = both 404 in every region.

The region is probed here rather than through ``mssp_detect_region``: SAA
says "tenant not found" for a wrong region instead of an empty 200, so the
probe is unambiguous. The result is cached per tenant in this module only and
never fed to the shared resolver that steers Insights and Compliance.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import partial
from typing import Any

from ..audit.extractor import _exc_status
from ..config.region import KNOWN_REGIONS, normalise_region, resolve_region_with_source
from .airs import AirsSection, _parse_ts, cell

SAA_BASE = "https://api.strata.paloaltonetworks.com/secure-agentless-access/v1"
_TIMEOUT = (4, 15)
_PAGE_SIZE = 500
_MAX_PAGES = 20
_PROBE_WORKERS = 8

# Every x-panw-region value the SAA spec accepts, the codebase's known
# regions first so the common answers are probed in the first wave.
SAA_REGIONS: tuple[str, ...] = tuple(
    dict.fromkeys(
        (
            *KNOWN_REGIONS,
            "br",
            "ch",
            "es",
            "fr",
            "id",
            "il",
            "it",
            "kr",
            "pl",
            "qa",
            "sa",
            "tw",
            "za",
        )
    )
)

# (inventory attribute, path, extra query params). The two gate lists first.
_LISTS: tuple[tuple[str, str, dict[str, Any]], ...] = (
    ("applications", "/applications", {"expand": "app_groups"}),
    ("groups", "/application-groups", {"expand": "apps"}),
    ("profiles", "/application-profiles", {}),
    ("policies", "/application-policies", {}),
    ("sessions", "/active-sessions", {}),
)

# Stored-credential fields, dropped at any depth. Most are writeOnly in the
# spec, but the VNC sftp_* ones are not, so they may come back. The
# has_credentials flags are kept: they say a secret exists without holding it.
_SECRET_FIELDS = frozenset(
    {
        "password",
        "private_key",
        "passphrase",
        "sftp_password",
        "sftp_private_key",
        "sftp_passphrase",
    }
)

# Sessions are live state that names users: shown by scm_saa_list, never kept
# in snapshots, the config index or drift baselines.
LONG_SESSION_HOURS = 12

_region_cache: dict[str, str] = {}
_region_lock = threading.Lock()


@dataclass
class SaaInventory:
    """Everything the SAA API returned for one tenant."""

    region: str = ""
    # override / configured / detected / probed / cached
    region_source: str = ""
    applications: list[dict[str, Any]] = field(default_factory=list)
    groups: list[dict[str, Any]] = field(default_factory=list)
    profiles: list[dict[str, Any]] = field(default_factory=list)
    policies: list[dict[str, Any]] = field(default_factory=list)
    sessions: list[dict[str, Any]] = field(default_factory=list)
    sessions_fetched: bool = False
    # resource -> HTTP status for lists the API refused (401/403/404/424)
    refused: dict[str, int] = field(default_factory=dict)
    # resource -> error text (a list that failed part-way keeps what it got)
    errors: dict[str, str] = field(default_factory=dict)
    truncated: set[str] = field(default_factory=set)
    # HTTP statuses other than 404 seen while probing regions (401/403 = token
    # or role, 5xx = service) — these make "not provisioned" unprovable.
    probe_failures: dict[str, str] = field(default_factory=dict)

    @property
    def provisioned(self) -> bool:
        return bool(self.region)

    @property
    def forbidden(self) -> bool:
        """No region found, and the probe was refused with 403 (RBAC)."""
        return not self.region and any(v == "HTTP 403" for v in self.probe_failures.values())

    def complete(self, attr: str) -> bool:
        """True when *attr* was listed in full — safe to reason about absence."""
        return attr not in self.refused and attr not in self.errors and attr not in self.truncated

    @property
    def custom_profiles(self) -> list[dict[str, Any]]:
        """Profiles minus the system-defined read-only one every tenant has."""
        return [p for p in self.profiles if not p.get("is_read_only")]


@dataclass(frozen=True)
class SaaRisk:
    severity: str  # HIGH / MEDIUM / LOW
    area: str
    finding: str
    recommendation: str


_SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def _strip_secrets(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _strip_secrets(v) for k, v in value.items() if k not in _SECRET_FIELDS}
    if isinstance(value, list):
        return [_strip_secrets(v) for v in value]
    return value


def _get(
    session: Any,
    path: str,
    region: str,
    params: dict[str, Any] | None = None,
    timeout: tuple[float, float] = _TIMEOUT,
) -> tuple[int, Any]:
    """GET one path → (status, json). 4xx refusals come back as a status, not a raise."""
    try:
        resp = session.get(
            f"{SAA_BASE}{path}",
            params=params,
            headers={"x-panw-region": region},
            timeout=timeout,
        )
    except Exception as exc:
        status = _exc_status(exc)
        if status is not None and 400 <= status < 500:
            return status, None
        raise
    if 400 <= resp.status_code < 500:
        return resp.status_code, None
    resp.raise_for_status()
    return resp.status_code, resp.json()


def _items(data: Any) -> list[Any]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        found = data.get("data")
        if found is None:
            return []
        if not isinstance(found, list):
            # Raised so the caller records the list as incomplete, not empty.
            raise ValueError(f"unexpected 'data' shape: {type(found).__name__}")
        return found
    return []


# ── Region gate ──────────────────────────────────────────────────────────────


def _probe_region(session: Any, region: str, timeout: tuple[float, float]) -> tuple[bool, str]:
    """(answered, failure). Groups first: it answers before applications on first touch."""
    failure = ""
    for path in ("/application-groups", "/applications"):
        try:
            status, data = _get(session, path, region, {"limit": 1}, timeout)
        except Exception as exc:
            failure = str(exc)[:120]
            continue
        if data is not None:
            return True, ""
        if status != 404:
            failure = f"HTTP {status}"
    return False, failure


def find_region(
    session: Any,
    tenant_id: str,
    explicit: str = "",
    timeout: tuple[float, float] = _TIMEOUT,
) -> tuple[str, str, dict[str, str]]:
    """(region, source, probe failures) — region is "" when no region answered.

    Order: the *explicit* argument alone (no fallback, so a wrong override is
    reported rather than silently replaced); else the region cached by an
    earlier probe; else the tenant's configured or detected region; else
    every SAA region, concurrently.
    """
    failures: dict[str, str] = {}
    if explicit.strip():
        region = normalise_region(explicit)
        ok, failure = _probe_region(session, region, timeout)
        if failure:
            failures[region] = failure
        return (region, "override", failures) if ok else ("", "", failures)

    tried: set[str] = set()
    with _region_lock:
        cached = _region_cache.get(tenant_id, "") if tenant_id else ""
    preferred, source = resolve_region_with_source(tenant_id)
    for region, src in ((cached, "cached"), (preferred, source)):
        if not region or region in tried:
            continue
        tried.add(region)
        ok, failure = _probe_region(session, region, timeout)
        if ok:
            _remember(tenant_id, region)
            return region, src, failures
        if failure:
            failures[region] = failure

    rest = [r for r in SAA_REGIONS if r not in tried]
    with ThreadPoolExecutor(max_workers=_PROBE_WORKERS) as pool:
        results = list(pool.map(lambda r: _probe_region(session, r, timeout), rest))
    hits = [r for r, (ok, _) in zip(rest, results, strict=True) if ok]
    failures.update({r: f for r, (ok, f) in zip(rest, results, strict=True) if f and not ok})
    if hits:
        # More than one region answering has not been seen live; the first in
        # SAA_REGIONS order wins and the rest are reported by the caller.
        _remember(tenant_id, hits[0])
        if len(hits) > 1:
            failures.update({r: "also answered" for r in hits[1:]})
        return hits[0], "probed", failures
    _forget(tenant_id)
    return "", "", failures


def _remember(tenant_id: str, region: str) -> None:
    if tenant_id:
        with _region_lock:
            _region_cache[tenant_id] = region


def _forget(tenant_id: str) -> None:
    with _region_lock:
        _region_cache.pop(tenant_id, None)


def clear_region_cache() -> None:
    with _region_lock:
        _region_cache.clear()


# ── Fetch ────────────────────────────────────────────────────────────────────


def _fetch_list(
    inv: SaaInventory,
    session: Any,
    attr: str,
    path: str,
    extra: dict[str, Any],
    max_pages: int,
    timeout: tuple[float, float],
) -> None:
    """Fetch every page of one list into *inv* (offset/limit; stop on a short page)."""
    items: list[dict[str, Any]] = []
    offset = 0
    for page_no in range(1, max_pages + 1):
        try:
            status, page = _get(
                session,
                path,
                inv.region,
                {**extra, "offset": offset, "limit": _PAGE_SIZE},
                timeout,
            )
        except Exception as exc:
            inv.errors[attr] = f"page {page_no}: {exc}" if page_no > 1 else str(exc)
            break
        if page is None:
            if page_no == 1:
                inv.refused[attr] = status
            else:
                inv.errors[attr] = f"page {page_no}: HTTP {status}"
            break
        rows = _items(page)
        items.extend(_strip_secrets(r) for r in rows if isinstance(r, dict))
        total = page.get("total") if isinstance(page, dict) else None
        if len(rows) < _PAGE_SIZE or (isinstance(total, int) and len(items) >= total):
            break
        if page_no == max_pages:
            inv.truncated.add(attr)
        offset += len(rows)
    setattr(inv, attr, items)


def fetch_saa(
    session: Any,
    tenant_id: str = "",
    region: str = "",
    include_sessions: bool = True,
    max_pages: int = _MAX_PAGES,
    timeout: tuple[float, float] = _TIMEOUT,
) -> SaaInventory:
    """Pull the SAA inventory for the tenant behind *session*.

    The region is established first (see :func:`find_region`); with none,
    the lists are not fetched, because profiles, policies and sessions answer
    200 in any region and would look like an empty deployment.
    """
    inv = SaaInventory()
    inv.region, inv.region_source, inv.probe_failures = find_region(
        session, tenant_id, region, timeout
    )
    if not inv.region:
        return inv

    lists = _LISTS if include_sessions else tuple(s for s in _LISTS if s[0] != "sessions")
    with ThreadPoolExecutor(max_workers=len(lists)) as pool:
        futures = {
            spec[0]: pool.submit(partial(_fetch_list, inv, session, *spec, max_pages, timeout))
            for spec in lists
        }
        for name, fut in futures.items():
            try:
                fut.result()
            except Exception as exc:
                inv.errors.setdefault(name, str(exc))
    inv.sessions_fetched = include_sessions
    return inv


# ── Session disconnect ───────────────────────────────────────────────────────
#
# POST /active-sessions:disconnect     {"session_ids": [...]} (1–1000 ids)
#   207 → {"data": [{"session_id", "status"}]}, per session 202 = disconnected
#         by this request, 404 = not found or already gone
#   404 → none of the ids were active (an outcome, not an error)
# POST /active-sessions:disconnect-all (no body) → 202, asynchronous, no body
#
# Sessions answer 200 in any region, so a disconnect sent to the wrong region
# would "succeed" against nothing: callers establish the region with
# find_region first and refuse to write without one.

DISCONNECT_PATH = "/active-sessions:disconnect"
DISCONNECT_ALL_PATH = "/active-sessions:disconnect-all"
_DISCONNECT_CHUNK = 1000


@dataclass
class DisconnectOutcome:
    """What the API said about each session id sent to :disconnect."""

    disconnected: list[str] = field(default_factory=list)
    not_found: list[str] = field(default_factory=list)
    # session id -> per-session status other than 202/404
    other: dict[str, int] = field(default_factory=dict)
    # ids sent in a chunk the API accepted without per-session results
    unconfirmed: list[str] = field(default_factory=list)
    # ids never confirmed because their request failed (or was not sent)
    failed: list[str] = field(default_factory=list)
    error: str = ""


def _post(
    session: Any,
    path: str,
    region: str,
    body: dict[str, Any] | None,
    timeout: tuple[float, float] = _TIMEOUT,
) -> tuple[int, Any, str]:
    """POST one path → (status, json or None, error text). Never raises on HTTP status."""
    resp = session.post(
        f"{SAA_BASE}{path}",
        json=body,
        headers={"x-panw-region": region},
        timeout=timeout,
    )
    try:
        data = resp.json() if resp.content else None
    except ValueError:
        data = None
    text = "" if data is not None else (resp.text or "")[:300]
    return resp.status_code, data, text


def _error_text(status: int, data: Any, text: str) -> str:
    """One line for a refused or failed POST, with the API's own message when present."""
    detail = text
    if isinstance(data, dict):
        errs = data.get("_errors") or []
        msgs = [str(e.get("message") or e.get("code") or e) for e in errs if isinstance(e, dict)]
        detail = "; ".join(msgs) or detail
    if status in (401, 403):
        label = f"HTTP {status} — the service account's role lacks SAA session permissions (RBAC)"
    elif status >= 500:
        label = f"HTTP {status} — SAA service error"
    else:
        label = f"HTTP {status}"
    return f"{label}: {detail}" if detail else label


def list_active_sessions(
    session: Any,
    region: str,
    user_id: str = "",
    app_id: str = "",
    timeout: tuple[float, float] = _TIMEOUT,
) -> tuple[list[dict[str, Any]], str]:
    """(active sessions, problem) in an established region; problem is "" when listed in full."""
    inv = SaaInventory(region=region)
    extra = {k: v for k, v in (("user_id", user_id), ("app_id", app_id)) if v}
    _fetch_list(inv, session, "sessions", "/active-sessions", extra, _MAX_PAGES, timeout)
    # Filtered here too: a filter the API ignored must not widen the target set.
    inv.sessions = [
        s
        for s in inv.sessions
        if (not user_id or str(s.get("user_id", "")).lower() == user_id.lower())
        and (not app_id or str(s.get("app_id", "")) == app_id)
    ]
    if "sessions" in inv.refused:
        return inv.sessions, f"the session list was refused (HTTP {inv.refused['sessions']})"
    if "sessions" in inv.errors:
        return inv.sessions, f"the session list failed ({inv.errors['sessions']})"
    if "sessions" in inv.truncated:
        return inv.sessions, f"the session list stopped after {_MAX_PAGES} pages"
    return inv.sessions, ""


def disconnect_sessions(
    session: Any,
    region: str,
    session_ids: list[str],
    timeout: tuple[float, float] = _TIMEOUT,
    before_post: Any = None,
) -> DisconnectOutcome:
    """Send *session_ids* to :disconnect in chunks; stop at the first refused or failed chunk.

    *before_post*, when given, is called with each chunk just before it is
    sent (the audit-log hook).
    """
    out = DisconnectOutcome()
    chunks = [
        session_ids[i : i + _DISCONNECT_CHUNK]
        for i in range(0, len(session_ids), _DISCONNECT_CHUNK)
    ]
    for n, chunk in enumerate(chunks):
        if before_post is not None:
            before_post(chunk)
        try:
            status, data, text = _post(
                session, DISCONNECT_PATH, region, {"session_ids": chunk}, timeout
            )
        except Exception as exc:
            out.error = f"request failed: {exc}"
            out.failed += [i for c in chunks[n:] for i in c]
            break
        if status == 207 or (200 <= status < 300 and isinstance(data, dict) and "data" in data):
            seen: set[str] = set()
            for row in _dicts(data.get("data") if isinstance(data, dict) else None):
                sid = str(row.get("session_id") or "")
                code = row.get("status")
                seen.add(sid)
                if code == 202:
                    out.disconnected.append(sid)
                elif code == 404:
                    out.not_found.append(sid)
                else:
                    out.other[sid] = code if isinstance(code, int) else -1
            out.unconfirmed += [i for i in chunk if i not in seen]
        elif 200 <= status < 300:
            out.unconfirmed += chunk
        elif status == 404:
            out.not_found += chunk
        else:
            out.error = _error_text(status, data, text)
            out.failed += [i for c in chunks[n:] for i in c]
            break
    return out


def disconnect_all_sessions(
    session: Any, region: str, timeout: tuple[float, float] = _TIMEOUT
) -> tuple[bool, str]:
    """(accepted, error text) for :disconnect-all. Accepted means queued, not done."""
    status, data, text = _post(session, DISCONNECT_ALL_PATH, region, None, timeout)
    if 200 <= status < 300:
        return True, ""
    return False, _error_text(status, data, text)


# ── Risk assessment ──────────────────────────────────────────────────────────


def _dicts(value: Any) -> list[dict[str, Any]]:
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _strs(value: Any) -> list[str]:
    return [str(v) for v in value if v] if isinstance(value, list) else []


def _settings(item: dict[str, Any], key: str) -> dict[str, Any]:
    value = item.get(key)
    return value if isinstance(value, dict) else {}


def _policy_targets(policy: dict[str, Any]) -> tuple[list[str], list[str]]:
    return _strs(policy.get("app_ids")), _strs(policy.get("app_group_ids"))


def _principals(policy: dict[str, Any]) -> int:
    rules = _settings(policy, "rules")
    return sum(
        len(_dicts(a.get("users"))) + len(_strs(a.get("user_groups")))
        for a in _dicts(rules.get("actions"))
    )


_FILE_FLAGS = ("allow_file_upload", "allow_file_download")


_PROTOCOLS = ("rdp", "ssh", "vnc")


def _file_transfer(profile: dict[str, Any], protocols: set[str]) -> list[str]:
    """Of *protocols*, those whose settings allow file upload or download."""
    return [
        proto.upper()
        for proto in _PROTOCOLS
        if proto in protocols and any(_settings(profile, proto).get(f) for f in _FILE_FLAGS)
    ]


def _no_recording(profile: dict[str, Any], protocols: set[str]) -> list[str]:
    """Of *protocols*, those that report allow_session_recording and have it off.

    The flag is live-only (not in the spec), so absence is not a finding.
    """
    return [
        proto.upper()
        for proto in _PROTOCOLS
        if proto in protocols and _settings(profile, proto).get("allow_session_recording") is False
    ]


def _reached(inv: SaaInventory, policy: dict[str, Any]) -> set[str]:
    """App ids one policy reaches, directly or via its groups."""
    group_apps = {str(g.get("group_id")): set(_strs(g.get("app_ids"))) for g in _dicts(inv.groups)}
    apps, groups = _policy_targets(policy)
    reached = set(apps)
    for gid in groups:
        reached.update(group_apps.get(gid, set()))
    return reached


def covered_apps(inv: SaaInventory) -> set[str]:
    """App ids reachable through an enabled policy, directly or via a group."""
    covered: set[str] = set()
    for pol in _dicts(inv.policies):
        if pol.get("enabled") is not False:
            covered.update(_reached(inv, pol))
    return covered


def assess_saa(inv: SaaInventory, now: datetime | None = None) -> list[SaaRisk]:
    """Configuration risks worth reporting, most severe first."""
    now = now or datetime.now(UTC)
    risks: list[SaaRisk] = []
    add = risks.append
    if not inv.provisioned:
        return risks

    apps = {str(a.get("app_id")): a for a in _dicts(inv.applications)}
    groups = {str(g.get("group_id")): g for g in _dicts(inv.groups)}
    profiles = {str(p.get("profile_id")): p for p in _dicts(inv.profiles)}
    policies = _dicts(inv.policies)
    enabled = [p for p in policies if p.get("enabled") is not False]

    for pol in policies:
        name = pol.get("name", "—")
        if pol.get("enabled") is False:
            add(
                SaaRisk(
                    "LOW",
                    "Policy",
                    f"Policy `{name}` is disabled.",
                    "Delete it if it is no longer needed.",
                )
            )
            continue
        pid = str(pol.get("profile_id") or "")
        if inv.complete("profiles") and pid and pid not in profiles:
            add(
                SaaRisk(
                    "MEDIUM",
                    "Policy",
                    f"Policy `{name}` uses profile `{pid}`, which does not exist.",
                    "Point the policy at an existing application profile.",
                )
            )
        app_ids, group_ids = _policy_targets(pol)
        missing = [a for a in app_ids if inv.complete("applications") and a not in apps] + [
            g for g in group_ids if inv.complete("groups") and g not in groups
        ]
        if missing:
            add(
                SaaRisk(
                    "MEDIUM",
                    "Policy",
                    f"Policy `{name}` targets {len(missing)} application(s) or group(s) "
                    "that no longer exist.",
                    "Remove the stale targets or re-create the objects.",
                )
            )
        if not app_ids and not group_ids:
            add(
                SaaRisk(
                    "LOW",
                    "Policy",
                    f"Policy `{name}` targets no applications or groups.",
                    "Add targets or delete the policy.",
                )
            )
        if not _principals(pol):
            add(
                SaaRisk(
                    "LOW",
                    "Policy",
                    f"Policy `{name}` names no users or user groups.",
                    "Add the users or groups it should allow, or delete it.",
                )
            )

    # Profile checks only count the protocols of the apps that enabled
    # policies actually reach with that profile: an RDP-only policy must not
    # be flagged for its profile's SSH settings.
    in_use: dict[str, set[str]] = {}
    for pol in enabled:
        types = {str(apps[a].get("type") or "") for a in _reached(inv, pol) if a in apps}
        in_use.setdefault(str(pol.get("profile_id")), set()).update(types & set(_PROTOCOLS))
    for pid, protocols in sorted(in_use.items()):
        prof = profiles.get(pid)
        if prof is None or not protocols:
            continue
        pname = prof.get("name", "—")
        transfer = _file_transfer(prof, protocols)
        if transfer:
            add(
                SaaRisk(
                    "MEDIUM",
                    "Profile",
                    f"Profile `{pname}` allows file transfer over {', '.join(transfer)} "
                    "and is used by an enabled policy.",
                    "Disable file upload/download unless the users need it — it is a "
                    "direct data-exfiltration path from private hosts.",
                )
            )
        unrecorded = _no_recording(prof, protocols)
        if unrecorded:
            add(
                SaaRisk(
                    "LOW",
                    "Profile",
                    f"Profile `{pname}` does not record {', '.join(unrecorded)} sessions.",
                    "Enable session recording for privileged access to keep an audit trail.",
                )
            )

    if inv.complete("policies") and inv.complete("groups"):
        covered = covered_apps(inv)
        for aid, app in apps.items():
            if aid not in covered:
                add(
                    SaaRisk(
                        "LOW",
                        "Application",
                        f"Application `{app.get('name', '—')}` is not reachable through any "
                        "enabled policy.",
                        "Add it to a policy or delete it.",
                    )
                )

    for app in apps.values():
        name = app.get("name", "—")
        kind = str(app.get("type") or "")
        if kind == "rdp" and _settings(app, "rdp_settings").get("security_mode") == "tls":
            add(
                SaaRisk(
                    "LOW",
                    "Application",
                    f"RDP application `{name}` uses TLS security mode, not NLA.",
                    "Use NLA so the host authenticates the session before it starts.",
                )
            )
        if kind == "ssh" and not _settings(app, "ssh_settings").get("host_key"):
            add(
                SaaRisk(
                    "MEDIUM",
                    "Application",
                    f"SSH application `{name}` has no pinned host key.",
                    "Set the host key so a spoofed server cannot capture the session.",
                )
            )

    if inv.complete("policies"):
        targeted = {g for p in enabled for g in _policy_targets(p)[1]}
        for gid, grp in groups.items():
            if not _strs(grp.get("app_ids")):
                add(
                    SaaRisk(
                        "LOW",
                        "Group",
                        f"Application group `{grp.get('name', '—')}` is empty.",
                        "Add applications or delete the group.",
                    )
                )
            elif gid not in targeted:
                add(
                    SaaRisk(
                        "LOW",
                        "Group",
                        f"Application group `{grp.get('name', '—')}` is not used by any "
                        "enabled policy.",
                        "Reference it from a policy or delete it.",
                    )
                )

    long_running = [
        s
        for s in _dicts(inv.sessions)
        if (start := _parse_ts(s.get("start_time")))
        and (now - start).total_seconds() > LONG_SESSION_HOURS * 3600
    ]
    if long_running:
        add(
            SaaRisk(
                "LOW",
                "Sessions",
                f"{len(long_running)} active session(s) have run for over "
                f"{LONG_SESSION_HOURS} hours.",
                "Check they are still in use; disconnect idle ones in SCM.",
            )
        )

    risks.sort(key=lambda r: _SEVERITY_ORDER.get(r.severity, 9))
    return risks


def risk_headline(risks: list[SaaRisk]) -> str:
    """One line for the top of reports (the estate planner keeps ~1200 chars)."""
    if not risks:
        return "**SAA risks:** none found."
    counts = {sev: sum(1 for r in risks if r.severity == sev) for sev in ("HIGH", "MEDIUM", "LOW")}
    icon = "🔴" if counts["HIGH"] else "🟡" if counts["MEDIUM"] else "🟢"
    worst = risks[0]
    return (
        f"**SAA risks:** {icon} {counts['HIGH']} high · {counts['MEDIUM']} medium · "
        f"{counts['LOW']} low — worst: {worst.severity} {worst.finding}"
    )


def not_provisioned_text(inv: SaaInventory, explicit_region: str = "") -> str:
    """The one-paragraph answer when no region answered."""
    if inv.forbidden:
        return (
            "Secure Agentless Access: the API refused the probe with HTTP 403 — the "
            "service account's role lacks SAA permissions (RBAC), so whether SAA is "
            "provisioned cannot be determined."
        )
    failures = {r: f for r, f in inv.probe_failures.items() if f != "also answered"}
    if failures:
        detail = "; ".join(f"{r}: {f}" for r, f in sorted(failures.items()))
        return f"Error: the SAA region probe failed ({detail})."
    if explicit_region:
        return (
            f"Secure Agentless Access does not know this tenant in region "
            f'`{normalise_region(explicit_region)}` (HTTP 404 "tenant not found"). '
            "Omit `region` to probe every region."
        )
    return (
        "Secure Agentless Access is not provisioned for this tenant "
        f'("tenant not found" in all {len(SAA_REGIONS)} regions).'
    )


# ── Shared table rows (scm_saa_list and AS-BUILT) ────────────────────────────


def _flags(settings: dict[str, Any]) -> str:
    """Compact permission summary, e.g. 'copy ✓ · paste ✓ · upload ✗'."""
    labels = (
        ("allow_copy", "copy"),
        ("allow_paste", "paste"),
        ("allow_file_upload", "upload"),
        ("allow_file_download", "download"),
        ("allow_audio", "audio"),
        ("allow_session_recording", "record"),
        ("read_only", "read-only"),
    )
    parts = [f"{label} {'✓' if settings[k] else '✗'}" for k, label in labels if k in settings]
    return " · ".join(parts) or "—"


def _destinations(app: dict[str, Any]) -> str:
    out = []
    for d in _dicts(app.get("destinations")):
        host = d.get("host") or "?"
        out.append(f"{host}:{d['port']}" if d.get("port") else str(host))
    return ", ".join(out)


def _creds(app: dict[str, Any]) -> str:
    for key in ("rdp_settings", "ssh_settings", "vnc_settings"):
        has = _settings(_settings(app, key), "has_credentials")
        if has:
            return "stored" if any(has.values()) else "none"
    return "—"


def _names(ids: list[str], lookup: dict[str, str]) -> str:
    return ", ".join(lookup.get(i, i) for i in ids)


def saa_changes(inv: SaaInventory, limit: int = 20) -> list[dict[str, str]]:
    """Most recent create/update per application or group, newest first.

    Only applications and groups carry timestamps, and none carry an author.
    """
    rows: list[tuple[datetime, dict[str, str]]] = []
    for kind, items in (("Application", inv.applications), ("Application group", inv.groups)):
        for item in _dicts(items):
            created = _parse_ts(item.get("created_at"))
            updated = _parse_ts(item.get("updated_at"))
            when = updated or created
            if when is None:
                continue
            action = "updated" if updated and created and updated > created else "created"
            rows.append(
                (
                    when,
                    {
                        "when": when.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC"),
                        "kind": kind,
                        "name": str(item.get("name") or "—"),
                        "action": action,
                    },
                )
            )
    rows.sort(key=lambda r: r[0], reverse=True)
    return [r for _, r in rows[:limit]]


def saa_sections(
    inv: SaaInventory, risks: list[SaaRisk], include_sessions: bool = True
) -> list[AirsSection]:
    """Every SAA table, in report order. Sessions only when fetched and asked for."""

    def section(
        title: str, attr: str, items: list[Any], headers: list[str], row: Any, empty: str
    ) -> AirsSection:
        if attr in inv.refused:
            return AirsSection(
                title, headers, [], f"Refused by the API (HTTP {inv.refused[attr]})."
            )
        rows = [[cell(c) for c in row(i)] for i in _dicts(items)]
        notes = []
        if attr in inv.errors:
            notes.append(f"Incomplete — {inv.errors[attr]}")
        if attr in inv.truncated:
            notes.append("Truncated at the page limit.")
        title = f"{title} ({len(rows)}{'' if inv.complete(attr) else '+'})"
        if not rows and not notes:
            notes.append(empty)
        return AirsSection(title, headers, rows, " ".join(notes))

    app_names = {str(a.get("app_id")): str(a.get("name") or "—") for a in _dicts(inv.applications)}
    group_names = {str(g.get("group_id")): str(g.get("name") or "—") for g in _dicts(inv.groups)}
    profile_names = {
        str(p.get("profile_id")): str(p.get("name") or "—") for p in _dicts(inv.profiles)
    }
    policies_by_group: dict[str, int] = {}
    for pol in _dicts(inv.policies):
        for gid in _policy_targets(pol)[1]:
            policies_by_group[gid] = policies_by_group.get(gid, 0) + 1

    out = [
        section(
            "Applications",
            "applications",
            inv.applications,
            ["Name", "Type", "Destinations", "Groups", "Credentials", "Updated"],
            lambda a: [
                a.get("name"),
                a.get("type"),
                _destinations(a),
                _names(_strs(a.get("app_group_ids")), group_names),
                _creds(a),
                a.get("updated_at") or a.get("created_at"),
            ],
            "No applications published.",
        ),
        section(
            "Application Groups",
            "groups",
            inv.groups,
            ["Name", "Applications", "Policies", "Description"],
            lambda g: [
                g.get("name"),
                _names(_strs(g.get("app_ids")), app_names),
                policies_by_group.get(str(g.get("group_id")), 0),
                str(g.get("description") or "")[:80],
            ],
            "No application groups.",
        ),
        section(
            "Application Profiles",
            "profiles",
            inv.profiles,
            ["Name", "System", "RDP", "SSH", "VNC"],
            lambda p: [
                p.get("name"),
                "✓" if p.get("is_read_only") else "",
                _flags(_settings(p, "rdp")),
                _flags(_settings(p, "ssh")),
                _flags(_settings(p, "vnc")),
            ],
            "No application profiles.",
        ),
        section(
            "Access Policies",
            "policies",
            inv.policies,
            ["Name", "Enabled", "Profile", "Applications", "Groups", "Users/Groups"],
            lambda p: [
                p.get("name"),
                "✗" if p.get("enabled") is False else "✓",
                profile_names.get(str(p.get("profile_id")), p.get("profile_id")),
                _names(_policy_targets(p)[0], app_names),
                _names(_policy_targets(p)[1], group_names),
                _principals(p),
            ],
            "No access policies.",
        ),
    ]
    if include_sessions and inv.sessions_fetched:
        out.append(
            section(
                "Active Sessions",
                "sessions",
                inv.sessions,
                ["User", "Application", "Type", "Source IP", "Started", "Last Heartbeat"],
                lambda s: [
                    s.get("user_id"),
                    app_names.get(str(s.get("app_id")), s.get("app_id")),
                    s.get("app_type") or s.get("session_type"),
                    s.get("source_ip"),
                    s.get("start_time"),
                    s.get("last_heartbeat"),
                ],
                "No active sessions.",
            )
        )
    changes = saa_changes(inv)
    out.append(
        AirsSection(
            f"Recent Changes ({len(changes)})",
            ["When", "Object", "Name", "Action"],
            [[cell(c[k]) for k in ("when", "kind", "name", "action")] for c in changes],
            "" if changes else "No timestamps returned.",
        )
    )
    out.append(
        AirsSection(
            f"Risks ({len(risks)})",
            ["Severity", "Area", "Finding", "Recommendation"],
            [[r.severity, r.area, cell(r.finding), cell(r.recommendation)] for r in risks],
            "" if risks else "No SAA configuration risks found.",
        )
    )
    return out


def region_line(inv: SaaInventory) -> str:
    extra = [r for r, f in inv.probe_failures.items() if f == "also answered"]
    line = f"**Region:** `{inv.region}` ({inv.region_source})"
    if extra:
        line += f" — also answered in {', '.join(f'`{r}`' for r in extra)}"
    return line
