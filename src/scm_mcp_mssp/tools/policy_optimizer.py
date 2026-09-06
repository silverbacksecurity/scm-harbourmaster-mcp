"""
Policy Optimizer — read-only least-privilege rule recommendations.

New pan.dev API family (`policy-optimizer`), announced in the SCM API release
notes for 2026-08 and split into its own spec on 2026-08-18 when the
consolidated `posture.yaml` was broken up. Two endpoints: list security rules
that have optimization recommendations, and fetch one rule with its full set of
recommended replacement rules. Not present in pan-scm-sdk (0.15.1).

The recommendations are the API side of "App-ID cleanup": for a permissive rule
(``application: ["any"]``), the optimizer proposes a set of narrowed rules that
between them cover the applications actually observed in that rule's traffic.

API family: pan.dev `scm/config`
(posture-management/policy-optimizer/policy-optimizer.yaml), tag "Policy
Optimizer". Base URL is `api.strata.paloaltonetworks.com/posture` — a different
host than the usual `api.sase.paloaltonetworks.com`.

Note the manager sentinel differs from its sibling Config Cleanup API: this one
wants ``manager_hostname="cloud_managed"`` for Strata Cloud Manager, whereas
`config_cleanup` wants ``"SCM"``. Both specs are explicit about their own
spelling; don't unify them. Passing ``"SCM"`` here returns
``404 {"_errors":[{"message":"Manager not found"}]}`` (live-verified).

Two upstream quirks found while live-testing this module against three lab
tenants (2026-08-25):

* ``recommendation_count`` under-reports in the **list** response. A rule
  listed with ``recommendation_count: 0`` returned two recommendations from the
  by-ID endpoint. Never treat a 0 in the list as "no advice for this rule".
* ``name``, ``action`` and ``location`` come back as ``""`` rather than being
  omitted, in both responses, even when the rule plainly has a name — the
  recommendation names embed it (``optrule_<rule name>_0``). Hence `_field`,
  which renders an empty string as a visible placeholder.

Tenants with no SCM manager registered 404 with a completely empty body.
"""

from __future__ import annotations

import json
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..audit.extractor import _bearer_session_for
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool

logger = get_logger(__name__)

_MAX_CHARS = 15000
_BASE = "https://api.strata.paloaltonetworks.com/posture/policy-optimizer/v1"
_LIST_URL = f"{_BASE}/security-rules"

# Sentinel for the optional integer range filters. 0 is a meaningful value for
# every one of them (the spec sets `minimum: 0`), so absence can't be signalled
# with 0 the way it can for `offset`. Spelled as a literal `-1` in the tool
# signatures too — the docs generator prints default *expressions* verbatim, so
# a named constant would reach TOOL_REFERENCE.md as the unhelpful text "_UNSET".
_UNSET = -1


def _get_json(client: Any, url: str, params: dict[str, Any]) -> tuple[int, Any]:
    """GET a Policy Optimizer URL with a fresh bearer session; return (status, parsed-or-text)."""
    session = _bearer_session_for(client)
    resp = session.get(
        url, params={k: v for k, v in params.items() if v not in (None, "")}, timeout=(5, 30)
    )
    try:
        return resp.status_code, resp.json()
    except Exception:
        return resp.status_code, (resp.text or "")[:500]


def _int(value: Any) -> int:
    """Coerce a numeric-ish field to int; 0 on anything that isn't cleanly int-like.

    Same defensive reason as `config_cleanup._zero_hit_days`: a brand-new
    upstream API with no SDK-level schema validation gives no guarantee that
    `recommendation_count` / `overall_traffic` / `sessions` carry a consistent
    type across every rule in one response, and `sorted()` compares each pair
    of keys it touches — so a bare `.get(...) or 0` raises TypeError the moment
    two rules disagree.
    """
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def _field(value: Any, default: str = "—") -> str:
    """Render a scalar field, treating an empty string as absent.

    Live responses populate `name` / `action` / `location` with `""` rather
    than omitting them (observed on a real tenant), so a plain
    `.get(key, "?")` yields blank table cells instead of a visible placeholder.
    """
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _join(value: Any) -> str:
    """Render a spec-declared string array as a table cell.

    Guards the two shapes that break `str.join()`: a bare string (which would
    be iterated character-by-character) and a list holding non-string members.
    """
    if isinstance(value, list):
        return ", ".join(str(v) for v in value if v is not None) or "—"
    if isinstance(value, str):
        return value or "—"
    if value is None:
        return "—"
    return str(value)


def _human_bytes(value: Any) -> str:
    """Format a byte count compactly; '—' when the field is absent or unparsable."""
    if value is None:
        return "—"
    try:
        num = float(value)
    except (TypeError, ValueError):
        return str(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024.0:
            return f"{num:.0f} {unit}" if unit == "B" else f"{num:.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} PB"


def _error_detail(data: Any) -> str:
    """Flatten this API's `_errors` envelope into one readable line.

    Policy Optimizer returns `{"_errors": [{code, message, details[]}], "_request_id": ...}`
    rather than the plain body Config Cleanup returns, so the raw dict is not
    useful on its own in a chat transcript. Returns "" when there is nothing to
    say — some 404s come back with a completely empty body (observed on a real
    tenant), and callers append this to a sentence.
    """
    if data is None:
        return ""
    if not isinstance(data, dict):
        return str(data).strip()
    errors = data.get("_errors")
    if not isinstance(errors, list) or not errors:
        return str(data)
    parts: list[str] = []
    for err in errors:
        if not isinstance(err, dict):
            parts.append(str(err))
            continue
        chunk = " ".join(str(x) for x in (err.get("code"), err.get("message")) if x)
        details = err.get("details")
        if isinstance(details, list) and details:
            chunk += " — " + "; ".join(str(d) for d in details)
        elif isinstance(details, str) and details:
            chunk += f" — {details}"
        parts.append(chunk or str(err))
    request_id = data.get("_request_id")
    line = " | ".join(p for p in parts if p)
    return f"{line} (request_id: {request_id})" if request_id else line


def _render_failure(status: int, data: Any, title: str, url: str) -> str | None:
    """Return a rendered message for a non-200 status, or None when status is 200."""
    if status == 200:
        return None
    if status in (401, 403):
        return (
            f"# {title}\n\n⚠️ HTTP {status} — the service account lacks access to "
            f"`{url}`. Policy Optimizer is a new SCM API (2026-08); it may require a "
            f"licence/role entitlement not yet granted to this account."
        )
    detail = _error_detail(data)
    if status == 400:
        suffix = f": {detail}" if detail else "."
        return f"# {title}\n\nHTTP 400 — invalid request{suffix}"
    if status == 404:
        suffix = f": {detail}" if detail else "."
        return (
            f"# {title}\n\nHTTP 404 — manager not found, or no optimization data "
            f"available for it{suffix}\n\nCheck `manager_hostname` — Strata Cloud "
            f'Manager is `"cloud_managed"` here (the sibling `scm_zerohit_rules` '
            f'tool uses `"SCM"` instead, and the wrong one returns exactly this 404).'
        )
    if status >= 500:
        return f"# {title}\n\nHTTP {status} — upstream backend error (response body suppressed)."
    return f"# {title}\n\nHTTP {status} from `{url}`:\n\n{detail}"


def _raw_json_block(payload: Any) -> list[str]:
    body = json.dumps(payload, indent=2, default=str)
    if len(body) > _MAX_CHARS:
        body = body[:_MAX_CHARS] + "\n… (truncated)"
    return ["", "<details><summary>Raw JSON</summary>", "", "```json", body, "```", "</details>"]


def _render_list(status: int, data: Any) -> str:
    title = "Security Rules with Optimization Recommendations"
    failure = _render_failure(status, data, title, _LIST_URL)
    if failure is not None:
        return failure

    if not isinstance(data, dict):
        return (
            f"# {title}\n\nUnexpected response shape:\n\n"
            f"```json\n{json.dumps(data, indent=2, default=str)}\n```"
        )

    raw_rules = data.get("data")
    shape_warning = ""
    if raw_rules is None:
        rules: list[dict[str, Any]] = []
    elif isinstance(raw_rules, list):
        rules = [r for r in raw_rules if isinstance(r, dict)]
        if len(rules) != len(raw_rules):
            shape_warning = (
                "⚠️ Some entries in the response `data` array were not rule "
                "objects and were skipped."
            )
    else:
        rules = []
        shape_warning = "⚠️ Unexpected response shape — `data` was not a list; showing no rules."

    total = data.get("total", len(rules))
    lines = [f"# {title}", ""]
    lines.append(f"Rules returned by the optimizer: **{total}** (showing {len(rules)})")
    # `recommendation_count` is unreliable in the list response: a rule reported
    # here as 0 came back from the by-ID endpoint as 2 on a live tenant. Never
    # present a 0 as "this rule is clean" — point at the detail tool instead.
    with_recs = sum(1 for r in rules if _int(r.get("recommendation_count")) > 0)
    if rules and with_recs < len(rules):
        lines.append(
            f"⚠️ {len(rules) - with_recs} of these report "
            "`recommendation_count: 0`, but that field under-reports in the list "
            "response (a rule listed as 0 returned 2 recommendations from the "
            "by-ID endpoint). Confirm with `scm_policy_optimizer_rule` before "
            "concluding a rule has no advice."
        )
    if shape_warning:
        lines.append(shape_warning)
    lines.append("")

    if not rules:
        lines.append(
            "No rules with optimization recommendations found. This is also the "
            "expected result when the optimizer has not yet analysed this manager."
        )
        return "\n".join(lines)

    # Worst offender first: most recommendations, then heaviest traffic — a rule
    # with 12 suggested replacements is a bigger cleanup win than one with 1.
    rules_sorted = sorted(
        rules,
        key=lambda r: (_int(r.get("recommendation_count")), _int(r.get("overall_traffic"))),
        reverse=True,
    )
    lines += [
        "| Recs | Rule | Location | Action | Apps | Traffic | Sessions | Users | Rule ID |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rules_sorted:
        disabled = " _(disabled)_" if r.get("disabled") else ""
        lines.append(
            f"| {_field(r.get('recommendation_count'))} | {_field(r.get('name'))}{disabled} | "
            f"{_field(r.get('location'))} | {_field(r.get('action'))} | "
            f"{_join(r.get('application'))} | {_human_bytes(r.get('overall_traffic'))} | "
            f"{_field(r.get('sessions'))} | {_field(r.get('unique_users'))} | "
            f"`{_field(r.get('id'), '?')}` |"
        )
    lines += [
        "",
        "Use `scm_policy_optimizer_rule` with a Rule ID above to see the "
        "recommended replacement rules for that rule.",
    ]
    lines += _raw_json_block(rules_sorted)
    return "\n".join(lines)


def _render_detail(status: int, data: Any, rule_id: str) -> str:
    title = "Rule Optimization Recommendations"
    url = f"{_LIST_URL}/{rule_id}"
    failure = _render_failure(status, data, title, url)
    if failure is not None:
        return failure

    if not isinstance(data, dict):
        return (
            f"# {title}\n\nUnexpected response shape:\n\n"
            f"```json\n{json.dumps(data, indent=2, default=str)}\n```"
        )

    lines = [f"# {title}: {_field(data.get('name'), rule_id)}", ""]
    lines += [
        "## Original rule",
        "",
        f"- **ID:** `{_field(data.get('id'), rule_id)}`",
        f"- **Location:** {_field(data.get('location'))} "
        f"({_field(data.get('platform'))} / {_field(data.get('manager_hostname'))})",
        f"- **Action:** {_field(data.get('action'))}"
        + (" · **disabled**" if data.get("disabled") else ""),
        f"- **From → To:** {_join(data.get('from'))} → {_join(data.get('to'))}",
        f"- **Source → Destination:** {_join(data.get('source'))} → "
        f"{_join(data.get('destination'))}",
        f"- **Application:** {_join(data.get('application'))}",
        f"- **Service:** {_join(data.get('service'))}",
        f"- **Observed:** {_human_bytes(data.get('overall_traffic'))} traffic · "
        f"{_field(data.get('sessions'))} sessions · "
        f"{_field(data.get('unique_users'))} unique users",
        f"- **Last analysed:** {_field(data.get('last_analyzed_at'), 'unknown')}",
    ]
    if data.get("tag"):
        lines.append(f"- **Tags:** {_join(data.get('tag'))}")
    if data.get("description"):
        lines.append(f"- **Description:** {data.get('description')}")
    lines.append("")

    raw_recs = data.get("recommended_rules")
    shape_warning = ""
    if raw_recs is None:
        recs: list[dict[str, Any]] = []
    elif isinstance(raw_recs, list):
        recs = [r for r in raw_recs if isinstance(r, dict)]
        if len(recs) != len(raw_recs):
            shape_warning = (
                "⚠️ Some entries in `recommended_rules` were not rule objects and were skipped."
            )
    else:
        recs = []
        shape_warning = (
            "⚠️ Unexpected response shape — `recommended_rules` was not a list; "
            "showing no recommendations."
        )

    lines.append(f"## Recommended replacement rules ({len(recs)})")
    if shape_warning:
        lines += ["", shape_warning]
    lines.append("")

    if not recs:
        lines.append("No recommendations are currently available for this rule.")
        return "\n".join(lines)

    lines += [
        "| Status | Suggested name | Applications | Service | Traffic | Sessions | Users | New app |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for rec in sorted(recs, key=lambda r: _int(r.get("traffic")), reverse=True):
        lines.append(
            f"| {_field(rec.get('status'))} | {_field(rec.get('name'))} | "
            f"{_join(rec.get('application'))} | {_join(rec.get('service'))} | "
            f"{_human_bytes(rec.get('traffic'))} | {_field(rec.get('sessions'))} | "
            f"{_field(rec.get('unique_users'))} | "
            f"{'yes' if rec.get('is_new_application') else 'no'} |"
        )
    lines += [
        "",
        "Recommendations are read-only here — accepting or disabling them is not "
        "exposed by this API family, so apply the chosen rules through the normal "
        "security-rule tools.",
    ]
    lines += _raw_json_block(data)
    return "\n".join(lines)


def register_policy_optimizer_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register Policy Optimizer read-only tools."""
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_policy_optimizer_rules(
        client: Any,
        tenant_id: str,
        manager_hostname: str = "cloud_managed",
        location: str = "",
        min_traffic: int = -1,
        max_traffic: int = -1,
        min_sessions: int = -1,
        max_sessions: int = -1,
        limit: int = 200,
        offset: int = 0,
    ) -> str:
        """Security rules that have least-privilege optimization recommendations.

        New SCM Policy Optimizer API (2026-08). Lists overly permissive rules the
        optimizer has analysed, ranked by how many replacement rules it suggests
        (biggest cleanup win first). Read-only — use `scm_policy_optimizer_rule`
        to see the suggested replacements for one rule.

        The `recommendation_count` in this response under-reports (live-verified:
        a rule listed as 0 returned 2 from the by-ID endpoint), so do not report a
        rule as having no recommendations on the strength of this list alone.

        Args:
            tenant_id: SCM tenant ID (MSSP mode).
            manager_hostname: "cloud_managed" for Strata Cloud Manager (default), or a
                Panorama hostname for Panorama-managed rules. Note this differs from
                the sibling `scm_zerohit_rules` tool, which uses "SCM".
            location: Filter by folder (cloud_managed) or device group/template (Panorama).
            min_traffic: Only rules with at least this many bytes over the lookback
                period. Omit for no lower bound (0 is a valid bound, not "unset").
            max_traffic: Only rules with at most this many bytes over the lookback period.
            min_sessions: Only rules with at least this many sessions.
            max_sessions: Only rules with at most this many sessions.
            limit: Max rules to return (default 200).
            offset: Pagination offset.

        Returns:
            Markdown table of rules ranked by recommendation count, or an actionable
            message on 4xx/5xx.
        """
        params: dict[str, Any] = {
            "manager_hostname": manager_hostname,
            "location": location,
            "limit": limit,
            "offset": offset,
        }
        # The spec names these with literal brackets; they are only meaningful
        # when the caller actually set one, since 0 is a valid bound.
        for name, value in (
            ("overall_traffic[ge]", min_traffic),
            ("overall_traffic[le]", max_traffic),
            ("sessions[ge]", min_sessions),
            ("sessions[le]", max_sessions),
        ):
            if value != _UNSET:
                params[name] = value

        status, data = _get_json(client, _LIST_URL, params)
        logger.info("policy_optimizer_rules", tenant_id=tenant_id, status=status)
        return _render_list(status, data)

    @mcp.tool()
    @tool
    def scm_policy_optimizer_rule(
        client: Any,
        tenant_id: str,
        rule_id: str,
        manager_hostname: str = "cloud_managed",
    ) -> str:
        """Recommended least-privilege replacement rules for one security rule.

        New SCM Policy Optimizer API (2026-08). Returns the original rule plus the
        narrowed, application-specific rules the optimizer suggests in its place —
        together they cover the applications actually seen in that rule's traffic.
        Read-only; accepting a recommendation is not exposed by this API.

        Args:
            tenant_id: SCM tenant ID (MSSP mode).
            rule_id: UUID of the security rule (the Rule ID column from
                `scm_policy_optimizer_rules`).
            manager_hostname: "cloud_managed" for Strata Cloud Manager (default), or the
                Panorama hostname that owns this rule.

        Returns:
            Markdown summary of the original rule and its recommended replacements,
            or an actionable message on 4xx/5xx.
        """
        if not rule_id:
            return "# Rule Optimization Recommendations\n\n⚠️ `rule_id` is required."

        status, data = _get_json(
            client,
            f"{_LIST_URL}/{rule_id}",
            {"manager_hostname": manager_hostname},
        )
        logger.info("policy_optimizer_rule", tenant_id=tenant_id, status=status)
        return _render_detail(status, data, rule_id)
