"""Prisma AIRS (AI Runtime Security) — shared fetch, change history and risk checks.

One fetcher feeds ``scm_airs_list``, the AS-BUILT extractor and the tenant
dashboard, so all three agree on what "AIRS is provisioned" means.

Management API (pan.dev ``openapi-specs/prisma-airs/management``):
  Base:  https://api.sase.paloaltonetworks.com/aisec
  Auth:  the tenant's SCM OAuth bearer token (``client.session``); the TSG is
         taken from the token, so no path carries it.
  Lists: /v1/mgmt/{customerapps,profiles,topics,apikeys} — offset/limit
         pagination, response ``{<list_key>: [...], "next_offset": n}``;
         /v1/mgmt/deploymentprofiles — unpaginated ``{"deployment_profiles": []}``.

Live behaviour (2026-10-14, every lab tenant, none with AIRS):
  * deploymentprofiles → 200 with an empty list;
  * every other mgmt list → 401 "Not Authorized" (an unrouted path gets 403
    "Access denied" instead, so the 401 is the gateway refusing an
    unprovisioned tenant, not a bad URL).
  So "not provisioned" = no deployment profiles AND the profiles list refused.

Deployment profiles are the AIRS licence allocation (auth code + expiry); an
NGFW running AIRS network intercept carries that auth code on an installed
licence, which is how devices are associated.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import partial
from typing import Any

from ..audit.extractor import _NOT_LICENSED_STATUSES, _exc_status

AIRS_BASE = "https://api.sase.paloaltonetworks.com/aisec"
_MGMT = f"{AIRS_BASE}/v1/mgmt"
_TIMEOUT = (4, 15)
_PAGE_SIZE = 100
_MAX_PAGES = 50

# 401 is the live answer for an unprovisioned tenant (see module docstring).
AIRS_REFUSED_STATUSES = _NOT_LICENSED_STATUSES

# (inventory attribute, path, response list key, extra query params)
# Profiles first: it is the provisioning gate in fetch_airs. `latest` returns
# only each profile's current revision (spec: "Get only the latest AI Sec
# Profiles") — without it old revisions would be listed and risk-checked.
_PAGED_LISTS: tuple[tuple[str, str, str, dict[str, Any]], ...] = (
    ("profiles", "/profiles", "ai_profiles", {"latest": "true"}),
    ("apps", "/customerapps", "customer_apps", {}),
    ("topics", "/topics", "custom_topics", {}),
    ("api_keys", "/apikeys", "api_keys", {}),
)

# Fields never kept: the spec's APIKeyObject carries the key value itself.
# Records flow into snapshots, the config search index and drift baselines.
_SECRET_FIELDS = frozenset({"api_key"})

KEY_EXPIRY_WARN_DAYS = 30
LICENCE_EXPIRY_WARN_DAYS = 90


@dataclass
class AirsInventory:
    """Everything the AIRS management API returned for one tenant."""

    provisioned: bool = False
    deployment_profiles: list[dict[str, Any]] = field(default_factory=list)
    apps: list[dict[str, Any]] = field(default_factory=list)
    profiles: list[dict[str, Any]] = field(default_factory=list)
    topics: list[dict[str, Any]] = field(default_factory=list)
    api_keys: list[dict[str, Any]] = field(default_factory=list)
    # resource -> HTTP status for lists the API refused (401/403/404/424)
    refused: dict[str, int] = field(default_factory=dict)
    # resource -> error text for anything else (a list that failed part-way
    # keeps the pages it got and is also listed here)
    errors: dict[str, str] = field(default_factory=dict)
    # lists cut short by max_pages
    truncated: set[str] = field(default_factory=set)

    @property
    def licensed(self) -> bool:
        return bool(self.deployment_profiles)

    @property
    def forbidden(self) -> bool:
        """Unprovisioned-looking, but the profile list was refused with 403 (RBAC)."""
        return not self.provisioned and self.refused.get("profiles") == 403

    def complete(self, attr: str) -> bool:
        """True when *attr* was listed in full — safe to reason about absence."""
        return attr not in self.refused and attr not in self.errors and attr not in self.truncated


@dataclass(frozen=True)
class AirsRisk:
    severity: str  # HIGH / MEDIUM / LOW
    area: str
    finding: str
    recommendation: str


_SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def _get(
    session: Any,
    path: str,
    params: dict[str, Any] | None = None,
    timeout: tuple[float, float] = _TIMEOUT,
) -> tuple[int, Any]:
    """GET one mgmt path → (status, json). Refusals come back as a status, not a raise."""
    try:
        resp = session.get(f"{_MGMT}{path}", params=params, timeout=timeout)
    except Exception as exc:
        status = _exc_status(exc)
        if status in AIRS_REFUSED_STATUSES:
            return status, None
        raise
    if resp.status_code in AIRS_REFUSED_STATUSES:
        return resp.status_code, None
    resp.raise_for_status()
    return resp.status_code, resp.json()


def _items(data: Any, list_key: str) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        found = data.get(list_key, data.get("data", data.get("items")))
        if found is None:
            return []
        if not isinstance(found, list):
            # Raised so the caller records the list as incomplete, not empty.
            raise ValueError(f"unexpected {list_key!r} shape: {type(found).__name__}")
        return found
    return []


def _next_offset(page: Any, offset: int, list_key: str) -> int | None:
    nxt = page.get("next_offset") if isinstance(page, dict) else None
    if not isinstance(nxt, int) or nxt <= offset or not _items(page, list_key):
        return None
    return nxt


def _fetch_list(
    inv: AirsInventory,
    session: Any,
    attr: str,
    path: str,
    list_key: str,
    extra: dict[str, Any],
    max_pages: int,
    timeout: tuple[float, float],
) -> None:
    """Fetch every page of one list into *inv*, following ``next_offset``.

    A refusal is recorded in ``inv.refused``; a failure keeps the pages
    already fetched and is recorded in ``inv.errors``; hitting *max_pages*
    marks the list truncated.
    """
    items: list[dict[str, Any]] = []
    offset = 0
    for page_no in range(1, max_pages + 1):
        try:
            status, page = _get(
                session, path, {**extra, "offset": offset, "limit": _PAGE_SIZE}, timeout
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
        items.extend(
            {k: v for k, v in item.items() if k not in _SECRET_FIELDS}
            for item in _items(page, list_key)
            if isinstance(item, dict)
        )
        nxt = _next_offset(page, offset, list_key)
        if len(_items(page, list_key)) < _PAGE_SIZE:
            break
        if nxt is None:
            # A full page with no usable next_offset: there may be more.
            inv.truncated.add(attr)
            break
        if page_no == max_pages:
            inv.truncated.add(attr)
        offset = nxt
    setattr(inv, attr, items)


def fetch_airs(
    session: Any, max_pages: int = _MAX_PAGES, timeout: tuple[float, float] = _TIMEOUT
) -> AirsInventory:
    """Pull the AIRS management inventory for the tenant behind *session*.

    Deployment profiles and the profile list are fetched first; when there
    are no deployment profiles and the profile list is refused, the tenant is
    unprovisioned (or, on 403, the service account lacks the AIRS role) and
    the remaining lists are skipped. Otherwise they are fetched concurrently.
    *max_pages* caps each paged list (the dashboard passes 1).
    """
    inv = AirsInventory()

    def deployment_profiles() -> None:
        status, data = _get(session, "/deploymentprofiles", timeout=timeout)
        if data is None and status in (401, 403):
            # Live, this answers 200 even on unprovisioned tenants, so an auth
            # refusal means the token itself is bad, not "no AIRS". Recording
            # it as an error keeps the gate from calling it unprovisioned.
            inv.errors["deployment_profiles"] = f"HTTP {status} (token or scope)"
        elif data is None:
            inv.refused["deployment_profiles"] = status  # 404/424: not licensed
        else:
            inv.deployment_profiles = _items(data, "deployment_profiles")

    def run(pool: ThreadPoolExecutor, jobs: dict[str, Any]) -> None:
        # Exceptions outside _get's own handling (odd response shapes) must
        # still mark the list incomplete rather than leave it looking empty.
        futures = {name: pool.submit(fn) for name, fn in jobs.items()}
        for name, fut in futures.items():
            try:
                fut.result()
            except Exception as exc:
                inv.errors.setdefault(name, str(exc))

    gate, *rest = _PAGED_LISTS
    with ThreadPoolExecutor(max_workers=len(_PAGED_LISTS)) as pool:
        # Both halves of the provisioning gate run at once.
        run(
            pool,
            {
                "deployment_profiles": deployment_profiles,
                gate[0]: partial(_fetch_list, inv, session, *gate, max_pages, timeout),
            },
        )
        if "profiles" in inv.refused and not inv.deployment_profiles:
            return inv  # unprovisioned, forbidden, or (with errors) unreadable
        run(
            pool,
            {
                spec[0]: partial(_fetch_list, inv, session, *spec, max_pages, timeout)
                for spec in rest
            },
        )

    # A list answered at all (even if a later page failed) means AIRS is there.
    answered = [
        attr
        for attr, *_ in _PAGED_LISTS
        if attr not in inv.refused and (attr not in inv.errors or getattr(inv, attr))
    ]
    inv.provisioned = bool(inv.deployment_profiles or answered)
    return inv


# ── Change attribution ───────────────────────────────────────────────────────


def _parse_ts(raw: Any) -> datetime | None:
    if not raw or not isinstance(raw, str):
        return None
    try:
        dt = datetime.fromisoformat(raw.strip().replace("Z", "+00:00").replace(" ", "T"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def airs_changes(inv: AirsInventory, limit: int = 20) -> list[dict[str, str]]:
    """Most recent create/update per object, newest first — who changed what, when."""
    sources = (
        ("AI security profile", inv.profiles, "profile_name"),
        ("Custom topic", inv.topics, "topic_name"),
        ("Customer app", inv.apps, "app_name"),
        ("API key", inv.api_keys, "api_key_name"),
    )
    rows: list[tuple[datetime | None, dict[str, str]]] = []
    for kind, items, name_key in sources:
        for item in items:
            updated = _parse_ts(item.get("last_modified_ts"))
            created = _parse_ts(item.get("created_ts") or item.get("creation_ts"))
            by_update = item.get("updated_by")
            if by_update and (updated or not created):
                when, who, action = updated, by_update, "updated"
            else:
                when, who, action = created or updated, item.get("created_by"), "created"
            if not who and not when:
                continue
            rows.append(
                (
                    when,
                    {
                        "when": when.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
                        if when
                        else "—",
                        "who": who or "—",
                        "kind": kind,
                        "name": str(item.get(name_key) or "—"),
                        "action": action,
                    },
                )
            )
    floor = datetime.min.replace(tzinfo=UTC)
    rows.sort(key=lambda r: r[0] or floor, reverse=True)
    return [r for _, r in rows[:limit]]


# ── Device association ───────────────────────────────────────────────────────

_AIRS_FEATURE_MARKERS = ("ai runtime", "airs", "ai security")


def _device_licences(device: dict[str, Any]) -> list[dict[str, Any]]:
    return device.get("installed_licenses") or device.get("installedLicenses") or []


def airs_devices(devices: list[dict[str, Any]], inv: AirsInventory) -> list[dict[str, Any]]:
    """NGFWs carrying an AIRS licence — matched by deployment-profile auth code
    or, failing that, by an AIRS-named licence feature."""
    dp_by_code = {
        dp["auth_code"]: dp.get("dp_name", "—")
        for dp in inv.deployment_profiles
        if dp.get("auth_code")
    }
    matched: list[dict[str, Any]] = []
    for dev in devices:
        for lic in _device_licences(dev):
            code = lic.get("authcode")
            feature = str(lic.get("feature") or "")
            if code in dp_by_code or any(m in feature.lower() for m in _AIRS_FEATURE_MARKERS):
                matched.append(
                    {
                        "name": dev.get("hostname") or dev.get("name") or "—",
                        "serial": dev.get("serial_number")
                        or dev.get("serial")
                        or dev.get("id")
                        or "—",
                        "model": dev.get("model") or "—",
                        "feature": feature or "—",
                        "deployment_profile": dp_by_code.get(code, "—"),
                        "expires": lic.get("expires") or "—",
                        "expired": str(lic.get("expired") or "").lower() == "yes",
                    }
                )
                break
    return matched


_DEVICES_URL = "https://api.sase.paloaltonetworks.com/config/setup/v1/devices"
_DEVICE_PAGE = 1000


def fetch_airs_devices(
    session: Any, inv: AirsInventory, quick: bool = False
) -> list[dict[str, Any]]:
    """Keep the AIRS-licensed firewalls from the tenant's SCM device list.

    Pages through every device by default; ``quick`` (the dashboard) reads one
    page with short timeouts so a slow device API cannot hold a thread long.
    """
    # Every page raises on refusal (403 RBAC) so callers can say the device
    # list is unknown rather than show an empty one.
    devices: list[dict[str, Any]] = []
    for _ in range(1 if quick else 25):
        resp = session.get(
            _DEVICES_URL,
            params={"limit": str(_DEVICE_PAGE), "offset": str(len(devices))},
            timeout=(3, 6) if quick else (5, 20),
        )
        resp.raise_for_status()
        body = resp.json()
        page = (body.get("data") if isinstance(body, dict) else body) or []
        devices.extend(page)
        total = body.get("total") if isinstance(body, dict) else None
        if len(page) < _DEVICE_PAGE or (isinstance(total, int) and len(devices) >= total):
            break
    return airs_devices(devices, inv)


# ── Risk assessment ──────────────────────────────────────────────────────────


def _dicts(value: Any) -> list[dict[str, Any]]:
    """Only the dict entries of an API list — one malformed entry must not
    abort the assessment (AS-BUILT calls this unguarded)."""
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _policy(profile: dict[str, Any]) -> dict[str, Any]:
    policy = profile.get("policy")
    return policy if isinstance(policy, dict) else {}


def _protections(profile: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for sp in _dicts(_policy(profile).get("ai-security-profiles")):
        cfg = sp.get("model-configuration")
        out.append(cfg if isinstance(cfg, dict) else {})
    return out


def _has_dlp(profile: dict[str, Any], configs: list[dict[str, Any]]) -> bool:
    """DLP may sit in model-configuration or at policy['dlp-data-profiles']."""
    return bool(_dicts(_policy(profile).get("dlp-data-profiles"))) or any(
        c.get("data-protection") for c in configs
    )


# Actions that let traffic through: "allow" and log-only "alert".
_PERMISSIVE = frozenset({"allow", "alert"})


def _days_until(raw: Any, now: datetime) -> int | None:
    dt = _parse_ts(raw)
    return None if dt is None else (dt - now).days


def assess_airs(
    inv: AirsInventory,
    devices: list[dict[str, Any]] | None = None,
    now: datetime | None = None,
) -> list[AirsRisk]:
    """Configuration risks worth reporting, most severe first.

    Checks are name-agnostic: any protection set to ``allow`` is reported
    rather than relying on specific detection names.
    """
    now = now or datetime.now(UTC)
    risks: list[AirsRisk] = []
    add = risks.append

    if not inv.provisioned:
        return risks

    for dp in inv.deployment_profiles:
        days = _days_until(dp.get("expiration_date"), now)
        name = dp.get("dp_name", "—")
        if days is not None and days < 0:
            add(
                AirsRisk(
                    "HIGH",
                    "Licence",
                    f"Deployment profile `{name}` expired {-days} days ago.",
                    "Renew the AIRS licence; inspection stops when it lapses.",
                )
            )
        elif days is not None and days <= LICENCE_EXPIRY_WARN_DAYS:
            add(
                AirsRisk(
                    "MEDIUM",
                    "Licence",
                    f"Deployment profile `{name}` expires in {days} days.",
                    "Start the AIRS renewal.",
                )
            )

    if inv.licensed and not inv.profiles and inv.complete("profiles"):
        add(
            AirsRisk(
                "MEDIUM",
                "Coverage",
                "AIRS is licensed but no AI security profiles exist.",
                "Create a security profile and bind it to each AI app or API key.",
            )
        )

    # Topics referenced by any profile, active or not (an inactive profile's
    # topic is still in use, so it must not be reported as deletable).
    referenced_topics = {
        t["topic_id"]
        for p in inv.profiles
        for c in _protections(p)
        for m in _dicts(c.get("model-protection"))
        for ta in _dicts(m.get("topic-list"))
        for t in _dicts(ta.get("topic"))
        if t.get("topic_id")
    }
    for p in inv.profiles:
        name = p.get("profile_name", "—")
        if p.get("active") is False:
            add(
                AirsRisk(
                    "LOW",
                    "Profile",
                    f"Profile `{name}` is inactive.",
                    "Delete it or reactivate it so it is not assumed to be protecting traffic.",
                )
            )
            continue  # protects nothing, so its protection gaps are noise
        configs = _protections(p)
        model_prot = [m for c in configs for m in _dicts(c.get("model-protection"))]
        agent_prot = [a for c in configs for a in _dicts(c.get("agent-protection"))]
        has_dlp = _has_dlp(p, configs)
        if not model_prot:
            # HIGH only when the profile protects nothing at all; a DLP-,
            # agent- or URL-only profile is a deliberate design: MEDIUM.
            other = agent_prot or has_dlp or any(c.get("app-protection") for c in configs)
            add(
                AirsRisk(
                    "MEDIUM" if other else "HIGH",
                    "Profile",
                    f"Profile `{name}` has no model protection configured"
                    + (" (it has other protections)." if other else " — it protects nothing."),
                    "Enable prompt-injection and related model-protection detections.",
                )
            )
        allowed = sorted(
            {
                str(m.get("name"))
                for m in model_prot + agent_prot
                if str(m.get("action", "")).lower() in _PERMISSIVE
            }
        )
        toxic_allowed = sorted(
            {
                str(t.get("category"))
                for m in model_prot
                for t in _dicts(m.get("toxic-category-list"))
                if str(t.get("action", "")).lower() in _PERMISSIVE
            }
        )
        if allowed:
            add(
                AirsRisk(
                    "MEDIUM",
                    "Profile",
                    f"Profile `{name}` detects but lets through (allow/alert): {', '.join(allowed)}.",
                    "Set these detections to block once false positives are understood.",
                )
            )
        if toxic_allowed:
            add(
                AirsRisk(
                    "LOW",
                    "Profile",
                    f"Profile `{name}` allows toxic categories: {', '.join(toxic_allowed)}.",
                    "Review whether these categories should block.",
                )
            )
        for c in configs:
            raw_latency = c.get("latency")
            latency: dict[str, Any] = raw_latency if isinstance(raw_latency, dict) else {}
            if str(latency.get("inline-timeout-action", "")).lower() == "allow":
                add(
                    AirsRisk(
                        "MEDIUM",
                        "Profile",
                        f"Profile `{name}` fails open: traffic is allowed when inline scanning times out.",
                        "Set inline-timeout-action to block for high-risk apps, or raise max-inline-latency.",
                    )
                )
                break
        if not has_dlp:
            add(
                AirsRisk(
                    "LOW",
                    "Profile",
                    f"Profile `{name}` has no data-protection (DLP) configured.",
                    "Attach a DLP data profile to catch sensitive data in prompts and responses.",
                )
            )

    for t in inv.topics:
        if (
            inv.profiles
            and inv.complete("profiles")
            and t.get("topic_id")
            and t["topic_id"] not in referenced_topics
        ):
            add(
                AirsRisk(
                    "LOW",
                    "Topic",
                    f"Custom topic `{t.get('topic_name', '—')}` is not used by any profile.",
                    "Reference it from a profile's topic guardrail or delete it.",
                )
            )

    for k in inv.api_keys:
        if k.get("revoked"):
            continue
        name = k.get("api_key_name", "—")
        days = _days_until(k.get("expiration"), now)
        if days is not None and days < 0:
            add(
                AirsRisk(
                    "LOW",
                    "API key",
                    f"API key `{name}` expired {-days} days ago but is not revoked.",
                    "Revoke or delete expired keys.",
                )
            )
        elif days is not None and days <= KEY_EXPIRY_WARN_DAYS:
            add(
                AirsRisk(
                    "MEDIUM",
                    "API key",
                    f"API key `{name}` expires in {days} days.",
                    "Regenerate it and update the app before it expires, or apps lose scanning.",
                )
            )
        if not k.get("rotation_time_interval"):
            add(
                AirsRisk(
                    "LOW",
                    "API key",
                    f"API key `{name}` has no rotation interval.",
                    "Set a rotation interval.",
                )
            )

    for a in inv.apps:
        if not a.get("api_keys_dp_info"):
            add(
                AirsRisk(
                    "LOW",
                    "App",
                    f"Customer app `{a.get('app_name', '—')}` has no API key.",
                    "Issue a key or remove the unused app.",
                )
            )

    for d in devices or []:
        if d.get("expired"):
            add(
                AirsRisk(
                    "HIGH",
                    "Device",
                    f"Firewall `{d['name']}` has an expired AIRS licence.",
                    "Renew the licence on the firewall.",
                )
            )

    risks.sort(key=lambda r: _SEVERITY_ORDER.get(r.severity, 9))
    return risks


def airs_dashboard_cell(inv: AirsInventory, risks: list[AirsRisk]) -> str:
    """Compact one-cell summary for the tenant dashboard ("+" = partial count,
    "—" = not provisioned, "⚠️ error" = the AIRS API could not be read)."""
    if inv.forbidden:
        return "⛔ RBAC"
    if not inv.provisioned:
        # "—" only when the API answered "not provisioned"; failures are not that.
        return "⚠️ error" if inv.errors else "—"

    def n(attr: str) -> str:
        return f"{len(getattr(inv, attr))}{'' if inv.complete(attr) else '+'}"

    high = sum(1 for r in risks if r.severity == "HIGH")
    cell = f"{n('profiles')}p/{n('apps')}a"
    if high:
        cell += f" 🔴{high}"
    elif risks:
        cell += f" 🟡{len(risks)}"
    return cell


def risk_headline(risks: list[AirsRisk]) -> str:
    """One line placed at the top of reports so truncated summaries (the
    estate planner keeps ~1200 chars) still carry the risk verdict; 🔴 is what
    the planner's attention-line scan picks up."""
    if not risks:
        return "**AIRS risks:** none found."
    counts = {sev: sum(1 for r in risks if r.severity == sev) for sev in ("HIGH", "MEDIUM", "LOW")}
    icon = "🔴" if counts["HIGH"] else "🟡" if counts["MEDIUM"] else "🟢"
    worst = risks[0]
    return (
        f"**AIRS risks:** {icon} {counts['HIGH']} high · {counts['MEDIUM']} medium · "
        f"{counts['LOW']} low — worst: {worst.severity} {worst.finding}"
    )


# ── Shared table rows (scm_airs_list and AS-BUILT §5.6) ──────────────────────


def cell(value: Any) -> str:
    """Markdown-table-safe text: API free text may contain '|' or newlines."""
    if value is None or str(value) in ("", "None", "[]", "{}"):
        return "—"
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


@dataclass
class AirsSection:
    title: str
    headers: list[str]
    rows: list[list[str]]
    note: str = ""  # replaces the table: refusal/error text, or the empty-list text


def _rotation(k: dict[str, Any]) -> str:
    if not k.get("rotation_time_interval"):
        return "—"
    return f"{k.get('rotation_time_interval')} {k.get('rotation_time_unit', '')}".strip()


def airs_sections(
    inv: AirsInventory,
    devices: list[dict[str, Any]] | None,
    risks: list[AirsRisk],
) -> list[AirsSection]:
    """Every AIRS table, in report order. ``devices=None`` omits the device table."""

    def section(
        title: str, attr: str, items: list[Any], headers: list[str], row: Any, empty: str
    ) -> AirsSection:
        if attr in inv.refused:
            return AirsSection(
                title, headers, [], f"Refused by the API (HTTP {inv.refused[attr]})."
            )
        rows = [[cell(c) for c in row(i)] for i in items]
        notes = []
        if attr in inv.errors:
            notes.append(f"Incomplete — {inv.errors[attr]}")
        if attr in inv.truncated:
            notes.append("Truncated at the page limit.")
        title = f"{title} ({len(items)}{'' if inv.complete(attr) else '+'})"
        if not rows and not notes:
            notes.append(empty)
        return AirsSection(title, headers, rows, " ".join(notes))

    out = [
        section(
            "Licence — Deployment Profiles",
            "deployment_profiles",
            inv.deployment_profiles,
            ["Profile Name", "Auth Code", "Status", "Expiration"],
            lambda d: [
                d.get("dp_name"),
                d.get("auth_code"),
                d.get("status"),
                d.get("expiration_date"),
            ],
            "No deployment profiles.",
        ),
        section(
            "Customer Applications",
            "apps",
            inv.apps,
            ["App Name", "Cloud Provider", "Environment", "AI Agent Framework", "API Keys"],
            lambda a: [
                a.get("app_name"),
                a.get("cloud_provider"),
                a.get("environment"),
                a.get("ai_agent_framework"),
                len(a.get("api_keys_dp_info") or []),
            ],
            "No customer applications registered.",
        ),
        section(
            "AI Security Profiles",
            "profiles",
            inv.profiles,
            ["Profile Name", "Profile ID", "Revision", "Active", "Last Changed By"],
            lambda p: [
                p.get("profile_name"),
                p.get("profile_id"),
                p.get("revision"),
                "✓" if p.get("active") else "✗",
                p.get("updated_by") or p.get("created_by"),
            ],
            "No AI security profiles defined.",
        ),
        section(
            "Custom Topics",
            "topics",
            inv.topics,
            ["Topic Name", "Revision", "Active", "Description"],
            lambda t: [
                t.get("topic_name"),
                t.get("revision"),
                "✓" if t.get("active") else "✗",
                str(t.get("description") or "")[:80],
            ],
            "No custom topics.",
        ),
        section(
            "API Keys",
            "api_keys",
            inv.api_keys,
            ["Key Name", "App", "Last 8", "Expires", "Rotation", "Revoked"],
            lambda k: [
                k.get("api_key_name"),
                k.get("cust_app"),
                k.get("api_key_last8"),
                k.get("expiration"),
                _rotation(k),
                "✓" if k.get("revoked") else "✗",
            ],
            "No API keys.",
        ),
    ]
    if devices is not None:
        out.append(
            AirsSection(
                f"Firewalls Licensed for AIRS ({len(devices)})",
                ["Device", "Serial", "Model", "Licence", "Deployment Profile", "Expires"],
                [
                    [
                        cell(d["name"]),
                        cell(d["serial"]),
                        cell(d["model"]),
                        cell(d["feature"]),
                        cell(d["deployment_profile"]),
                        cell(d["expires"]) + (" ❌" if d["expired"] else ""),
                    ]
                    for d in devices
                ],
                "" if devices else "No SCM-managed firewall carries an AIRS licence.",
            )
        )
    changes = airs_changes(inv)
    out.append(
        AirsSection(
            f"Recent Changes ({len(changes)})",
            ["When", "Who", "Object", "Name", "Action"],
            [[cell(c[k]) for k in ("when", "who", "kind", "name", "action")] for c in changes],
            "" if changes else "No change attribution returned.",
        )
    )
    out.append(
        AirsSection(
            f"Risks ({len(risks)})",
            ["Severity", "Area", "Finding", "Recommendation"],
            [[r.severity, r.area, cell(r.finding), cell(r.recommendation)] for r in risks],
            "" if risks else "No AIRS configuration risks found.",
        )
    )
    return out


def render_sections_markdown(sections: list[AirsSection], level: int = 3) -> list[str]:
    lines: list[str] = []
    for sec in sections:
        lines += [f"{'#' * level} {sec.title}", ""]
        if sec.rows:
            lines.append("| " + " | ".join(sec.headers) + " |")
            lines.append("|" + "---|" * len(sec.headers))
            lines.extend("| " + " | ".join(r) + " |" for r in sec.rows)
            lines.append("")  # a note right after the last row would parse as a row
        if sec.note:
            lines += [f"_{sec.note}_", ""]
        elif not sec.rows:
            lines.append("")
    return lines
