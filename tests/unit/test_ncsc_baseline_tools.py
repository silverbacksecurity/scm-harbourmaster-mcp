"""Tests for the NCSC / NIST baseline write-path and gap tools (no network)."""

from __future__ import annotations

import functools
import inspect
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.audit import nist_templates as nist
from scm_harbourmaster_mcp.audit.ncsc_templates import (
    ANTI_SPYWARE_NAME,
    LOG_FORWARDING_NAME,
    URL_ACCESS_NAME,
    VULN_PROTECTION_NAME,
    WILDFIRE_NAME,
)
from scm_harbourmaster_mcp.tools.ncsc_baseline import register_ncsc_tools

TENANT = "1234567890"


def _tools(client: Any) -> dict[str, Any]:
    mcp = FastMCP("test")
    register_ncsc_tools(mcp, lambda tenant_id="": client)
    return {
        name: functools.partial(t.fn, ticket_ref="CHG-TEST")
        for name, t in mcp._tool_manager._tools.items()
        if "ticket_ref" in inspect.signature(t.fn).parameters
    } | {
        name: t.fn
        for name, t in mcp._tool_manager._tools.items()
        if "ticket_ref" not in inspect.signature(t.fn).parameters
    }


def _named(name: str, **extra: Any) -> SimpleNamespace:
    return SimpleNamespace(name=name, **extra)


# ── scm_apply_ncsc_baseline ────────────────────────────────────────────────


class TestApplyBaseline:
    def test_dry_run_writes_nothing(self) -> None:
        client = MagicMock()
        out = _tools(client)["scm_apply_ncsc_baseline"](tenant_id=TENANT, folder="Branch")
        assert "DRY-RUN" in out
        assert "Created: 7 | Skipped: 0 | Failed: 0" in out
        assert "No changes written" in out
        client.anti_spyware_profile.create.assert_not_called()
        client.security_rule.create.assert_not_called()

    def test_apply_creates_every_object(self) -> None:
        client = MagicMock()
        client.anti_spyware_profile.create.return_value = SimpleNamespace(id="abc")
        out = _tools(client)["scm_apply_ncsc_baseline"](
            tenant_id=TENANT, folder="Branch", dry_run=False, syslog_profile="siem"
        )
        assert "Created: 7 | Skipped: 0 | Failed: 0" in out
        assert "(id=abc)" in out
        assert "NCSC baseline applied" in out
        payload = client.security_rule.create.call_args.args[0]
        assert payload["folder"] == "Branch"

    def test_apply_classifies_existing_failed_and_missing_attrs(self) -> None:
        client = MagicMock(spec=["anti_spyware_profile", "vulnerability_protection_profile", "tag"])
        client.anti_spyware_profile = MagicMock()
        client.anti_spyware_profile.create.side_effect = RuntimeError("Object already exists")
        client.vulnerability_protection_profile = MagicMock()
        client.vulnerability_protection_profile.create.side_effect = RuntimeError("HTTP 500")
        client.tag = MagicMock()
        out = _tools(client)["scm_apply_ncsc_baseline"](
            tenant_id=TENANT, folder="Branch", dry_run=False
        )
        assert f"[SKIP] {ANTI_SPYWARE_NAME} already exists" in out
        assert f"[FAIL] {VULN_PROTECTION_NAME}: HTTP 500" in out
        assert "SDK attr 'security_rule' not available" in out
        assert "Created: 1 | Skipped: 5 | Failed: 1" in out
        assert "1 object(s) failed" in out


# ── snippets ───────────────────────────────────────────────────────────────


class TestSnippets:
    def test_ncsc_snippet_dry_run(self) -> None:
        client = MagicMock()
        out = _tools(client)["scm_create_ncsc_snippet"](tenant_id=TENANT)
        assert "would create snippet 'NCSC-Compliance'" in out
        assert "Security rules (deny-all etc.) cannot be stored in a snippet" in out
        client.snippet.create.assert_not_called()

    def test_ncsc_snippet_apply_success(self) -> None:
        client = MagicMock()
        client.snippet.create.return_value = SimpleNamespace(id="snip-1")
        out = _tools(client)["scm_create_ncsc_snippet"](
            tenant_id=TENANT, snippet_name="Baseline", dry_run=False
        )
        assert "Created snippet 'Baseline' (id=snip-1)" in out
        assert "NCSC snippet 'Baseline' created" in out
        assert client.snippet.create.call_args.args[0]["enable_prefix"] is False

    def test_ncsc_snippet_existing_container_continues(self) -> None:
        client = MagicMock()
        client.snippet.create.side_effect = RuntimeError("duplicate name")
        client.tag.create.side_effect = RuntimeError("boom")
        out = _tools(client)["scm_create_ncsc_snippet"](tenant_id=TENANT, dry_run=False)
        assert "already exists — continuing" in out
        assert "Failed: 1" in out and "1 object(s) failed" in out

    def test_ncsc_snippet_container_failure_aborts(self) -> None:
        client = MagicMock()
        client.snippet.create.side_effect = RuntimeError("403 forbidden")
        out = _tools(client)["scm_create_ncsc_snippet"](tenant_id=TENANT, dry_run=False)
        assert "Could not create snippet: 403 forbidden" in out
        assert "Aborting" in out
        client.tag.create.assert_not_called()

    def test_nist_snippet_dry_run_and_apply(self) -> None:
        client = MagicMock()
        tools = _tools(client)
        dry = tools["scm_create_nist_snippet"](tenant_id=TENANT)
        assert "NIST Snippet — DRY-RUN" in dry and "No changes written" in dry

        applied = tools["scm_create_nist_snippet"](tenant_id=TENANT, dry_run=False)
        assert "NIST snippet 'NIST-Compliance' created" in applied
        client.tag.create.assert_called_once()

    def test_nist_snippet_abort_and_partial_failure(self) -> None:
        client = MagicMock()
        client.snippet.create.side_effect = RuntimeError("nope")
        out = _tools(client)["scm_create_nist_snippet"](tenant_id=TENANT, dry_run=False)
        assert "Aborting" in out

        client = MagicMock(spec=["snippet", "tag"])
        client.snippet = MagicMock()
        client.snippet.create.side_effect = RuntimeError("already exists")
        client.tag = MagicMock()
        client.tag.create.side_effect = RuntimeError("already exists")
        out = _tools(client)["scm_create_nist_snippet"](tenant_id=TENANT, dry_run=False)
        assert "not available" in out
        assert f"[SKIP] {nist.TAG_NAME} already exists" in out
        assert "Failed: 0" in out


# ── scm_attach_ncsc_profiles ───────────────────────────────────────────────


def _sdk_rule(name: str, **overrides: Any) -> MagicMock:
    fields: dict[str, Any] = {
        "id": f"id-{name}",
        "name": name,
        "action": "allow",
        "folder": "Branch",
        "profile_setting": None,
        "log_setting": None,
        "log_end": False,
        "description": "x",
        "rulebase": "pre",
        "tag": None,
    }
    fields.update(overrides)
    rule = MagicMock()
    for k, v in fields.items():
        setattr(rule, k, v)
    rule.model_dump.return_value = dict(fields)
    return rule


def _json_resp(status: int, data: Any = None, text: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = data if data is not None else {}
    resp.text = text
    return resp


class TestAttachProfiles:
    def _client(self, rules_pre: list[Any], rules_post: list[Any] | None = None) -> MagicMock:
        client = MagicMock()
        by_pos = {"pre": rules_pre, "post": rules_post or []}
        client.security_rule.list.side_effect = lambda folder, rulebase: by_pos[rulebase]
        return client

    def test_dry_run_reports_planned_changes_and_skips(self) -> None:
        rules = [
            _sdk_rule("needs-both"),
            _sdk_rule("predefined", folder="All"),
            _sdk_rule("done", profile_setting={"group": ["x"]}, log_setting="lfp"),
            _sdk_rule("deny", action="deny"),
        ]
        # a rule appearing in both rulebases is only processed once
        client = self._client(rules, [rules[0]])
        out = _tools(client)["scm_attach_ncsc_profiles"](tenant_id=TENANT, folder="Branch")
        assert "would set: profile_setting→NCSC-Baseline, log_setting" in out
        assert "'predefined' — folder=All" in out
        assert "'done' — already has profile group" in out
        assert "deny" not in out.split("### Step 2")[1].split("### Summary")[0]
        assert "Updated: 1 | Skipped: 2 | Failed: 0" in out
        client.session.post.assert_not_called()

    def test_apply_creates_group_and_updates_rules(self) -> None:
        rule = _sdk_rule("needs-both")
        broken = _sdk_rule("broken")
        client = self._client([rule, broken])
        client.session.get.return_value = _json_resp(200, {"data": []})
        client.session.post.return_value = _json_resp(201, {"id": "pg-1"})
        client.security_rule.update.side_effect = [None, RuntimeError("validation failed")]

        with patch(
            "scm.models.security.security_rules.SecurityRuleUpdateModel",
            side_effect=lambda **kw: kw,
        ):
            out = _tools(client)["scm_attach_ncsc_profiles"](
                tenant_id=TENANT, folder="Branch", dry_run=False
            )

        assert "Created profile group 'NCSC-Baseline' (id=pg-1)" in out
        posted = client.session.post.call_args.kwargs["json"]
        assert posted["spyware"] == [ANTI_SPYWARE_NAME]
        assert posted["url_filtering"] == [URL_ACCESS_NAME]
        assert posted["virus_and_wildfire_analysis"] == [WILDFIRE_NAME]

        sent, kwargs = client.security_rule.update.call_args_list[0]
        payload = sent[0]
        assert payload["profile_setting"] == {"group": ["NCSC-Baseline"]}
        assert payload["log_setting"] == LOG_FORWARDING_NAME
        assert payload["log_end"] is True
        # read-only / None fields are stripped before the PUT
        assert "rulebase" not in payload and "description" not in payload
        assert "tag" not in payload
        assert kwargs == {"rulebase": "pre"}

        assert "[FAIL] 'broken': validation failed" in out
        assert "Updated: 1 | Skipped: 0 | Failed: 1" in out

    def test_apply_existing_group_is_reused(self) -> None:
        client = self._client([])
        client.session.get.return_value = _json_resp(
            200, {"data": [{"name": "NCSC-Baseline", "id": "pg-9"}]}
        )
        out = _tools(client)["scm_attach_ncsc_profiles"](
            tenant_id=TENANT, folder="Branch", dry_run=False
        )
        assert "already exists (id=pg-9)" in out
        assert "**Done.**" in out
        client.session.post.assert_not_called()

    def test_apply_group_400_already_exists_is_ok(self) -> None:
        client = self._client([])
        client.session.get.return_value = _json_resp(200, {"data": []})
        client.session.post.return_value = _json_resp(400, text="Object Already Exists")
        out = _tools(client)["scm_attach_ncsc_profiles"](
            tenant_id=TENANT, folder="Branch", dry_run=False
        )
        assert "Profile group 'NCSC-Baseline' already exists" in out

    def test_apply_group_failure_stops_before_rules(self) -> None:
        client = self._client([_sdk_rule("r")])
        client.session.get.return_value = _json_resp(200, {"data": []})
        client.session.post.return_value = _json_resp(500, text="internal error")
        out = _tools(client)["scm_attach_ncsc_profiles"](
            tenant_id=TENANT, folder="Branch", dry_run=False
        )
        assert "Could not create profile group: internal error" in out
        assert "profile group creation failed" in out
        client.security_rule.list.assert_not_called()

        client.session.get.side_effect = RuntimeError("conn reset")
        out = _tools(client)["scm_attach_ncsc_profiles"](
            tenant_id=TENANT, folder="Branch", dry_run=False
        )
        assert "Profile group error: conn reset" in out

    def test_rule_list_failure_is_reported(self) -> None:
        client = MagicMock()
        client.security_rule.list.side_effect = RuntimeError("list broke")
        out = _tools(client)["scm_attach_ncsc_profiles"](tenant_id=TENANT, folder="Branch")
        assert "Could not list rules: list broke" in out


# ── gap reports ────────────────────────────────────────────────────────────


class _Obj:
    """Minimal stand-in for an SDK response model (attributes + model_dump)."""

    def __init__(self, **fields: Any) -> None:
        self.__dict__.update(fields)
        self._fields = fields

    def model_dump(self) -> dict[str, Any]:
        return dict(self._fields)


def _gap_client(
    rules: list[dict[str, Any]],
    anti_spyware: list[dict[str, Any]],
    log_profiles: list[dict[str, Any]],
    present: set[str],
) -> MagicMock:
    client = MagicMock()
    client.security_rule.list.return_value = [_Obj(id=f"id-{r['name']}", **r) for r in rules]
    client.anti_spyware_profile.list.return_value = anti_spyware
    client.log_forwarding_profile.list.return_value = log_profiles
    objs = [_named(n) for n in present]
    client.vulnerability_protection_profile.list.return_value = objs
    client.wildfire_antivirus_profile.list.return_value = objs
    client.url_access_profile.list.return_value = objs
    return client


FULL_LOG = {
    "name": LOG_FORWARDING_NAME,
    "match_list": [{"log_type": t} for t in ("traffic", "threat", "wildfire", "url")],
}


class TestGapReports:
    def test_ncsc_gap_clean_folder(self) -> None:
        client = _gap_client(
            rules=[
                {
                    "name": "web",
                    "action": "allow",
                    "log_end": True,
                    "profile_setting": {"group": ["g"]},
                },
                {"name": "deny-all", "action": "deny", "source": ["any"]},
            ],
            anti_spyware=[
                {
                    "name": ANTI_SPYWARE_NAME,
                    "cloud_inline_analysis": True,
                    "mica_engine_spyware_enabled": [{"name": "x"}],
                }
            ],
            log_profiles=[FULL_LOG],
            present={VULN_PROTECTION_NAME, WILDFIRE_NAME, URL_ACCESS_NAME},
        )
        out = _tools(client)["scm_ncsc_gap"](tenant_id=TENANT, folder="Branch")
        assert "All checks passed" in out

    def test_ncsc_gap_groups_findings_by_severity(self) -> None:
        client = _gap_client(
            rules=[{"name": "naked", "action": "allow"}],
            anti_spyware=[{"name": "weak-as"}],
            log_profiles=[],
            present=set(),
        )
        # identical ids across pre/post are de-duplicated when position=both
        out = _tools(client)["scm_ncsc_gap"](tenant_id=TENANT, folder="Branch", position="both")
        assert client.security_rule.list.call_count == 2
        assert out.count("Rule 'naked' has no security profile group") == 1
        assert "🔴 Critical" in out and "🟠 High" in out and "🟡 Medium" in out
        assert "🔵 Info" in out
        assert f"Baseline object '{WILDFIRE_NAME}' not found" in out
        assert "`naked`" in out

    def test_ncsc_gap_surfaces_fetch_warnings(self) -> None:
        client = MagicMock()
        for attr in (
            "security_rule",
            "anti_spyware_profile",
            "log_forwarding_profile",
            "vulnerability_protection_profile",
            "wildfire_antivirus_profile",
            "url_access_profile",
        ):
            getattr(client, attr).list.side_effect = RuntimeError(f"{attr} 403")
        out = _tools(client)["scm_ncsc_gap"](tenant_id=TENANT, folder="Branch")
        assert "### Warnings" in out
        assert "Could not fetch security rules: security_rule 403" in out
        assert "Could not check url_access_profile" in out
        assert "All checks passed" in out

    def test_nist_gap_remaps_controls(self) -> None:
        client = _gap_client(
            rules=[{"name": "naked", "action": "allow"}],
            anti_spyware=[{"name": "weak-as"}],
            log_profiles=[{"name": "partial", "match_list": [{"log_type": "traffic"}]}],
            present=set(),
        )
        client.log_forwarding_profile.list.return_value = [
            {"name": "partial", "match_list": [{"log_type": "traffic"}]}
        ]
        out = _tools(client)["scm_nist_gap"](tenant_id=TENANT, folder="Branch", position="post")
        assert "NIST Compliance Gap Report" in out
        assert "SP 800-53 SI-3" in out
        assert f"NIST baseline object '{nist.WILDFIRE_NAME}' not found" in out
        assert "missing log types: threat, url, wildfire" in out
        client.security_rule.list.assert_called_once_with(folder="Branch", rulebase="post")

    def test_nist_gap_clean_and_warnings(self) -> None:
        names = {
            nist.ANTI_SPYWARE_NAME,
            nist.VULN_PROTECTION_NAME,
            nist.WILDFIRE_NAME,
            nist.URL_ACCESS_NAME,
            nist.LOG_FORWARDING_NAME,
        }
        client = MagicMock()
        client.security_rule.list.side_effect = RuntimeError("rules down")
        client.anti_spyware_profile.list.return_value = [_named(n) for n in names]
        client.log_forwarding_profile.list.side_effect = RuntimeError("lfp down")
        for attr in (
            "vulnerability_protection_profile",
            "wildfire_antivirus_profile",
            "url_access_profile",
        ):
            getattr(client, attr).list.return_value = [_named(n) for n in names]
        # anti-spyware objects are SimpleNamespace (no model_dump / .get) so the
        # structural check raises and is reported as a warning
        out = _tools(client)["scm_nist_gap"](tenant_id=TENANT, folder="Branch")
        assert "Could not fetch security rules: rules down" in out
        assert "Could not fetch log forwarding profiles: lfp down" in out
        assert "Could not fetch anti-spyware profiles" in out
        assert "All checks passed — no NIST gaps" in out


# ── SDK validation errors fall back to raw REST ─────────────────────────────

# pan-scm-sdk's log forwarding response model forbids extra fields, so a
# match-list entry carrying an auto-tag ``actions`` block makes list() raise.
_LFP_VALIDATION_ERROR = ValueError(
    "1 validation error for LogForwardingProfileResponseModel\n"
    "match_list.4.actions\n  Extra inputs are not permitted [type=extra_forbidden]"
)

AUTO_TAG_LOG = {
    "name": nist.LOG_FORWARDING_NAME,
    "match_list": [{"log_type": t} for t in ("traffic", "threat", "wildfire", "url")]
    + [{"log_type": "threat", "actions": [{"name": "tag-src"}]}],
}


def _rest_fallback_client(present: set[str]) -> MagicMock:
    client = _gap_client(
        rules=[{"name": "naked", "action": "allow"}],
        anti_spyware=[],
        log_profiles=[],
        present=present,
    )
    client.log_forwarding_profile.list.side_effect = _LFP_VALIDATION_ERROR
    client.log_forwarding_profile.ENDPOINT = "/config/objects/v1/log-forwarding-profiles"
    resp = MagicMock(status_code=200)
    resp.json.return_value = {"data": [AUTO_TAG_LOG]}
    client.session.get.return_value = resp
    return client


class TestLogForwardingRestFallback:
    def test_nist_gap_reads_log_profiles_over_rest(self) -> None:
        client = _rest_fallback_client(present=set())

        out = _tools(client)["scm_nist_gap"](tenant_id=TENANT, folder="Branch")

        assert "Could not fetch log forwarding profiles" not in out
        assert "Could not check log_forwarding_profile" not in out
        assert "missing log types" not in out
        # The dict from REST satisfies the baseline-object existence check too.
        assert f"NIST baseline object '{nist.LOG_FORWARDING_NAME}' not found" not in out
        url = client.session.get.call_args.args[0]
        assert url.endswith("/config/objects/v1/log-forwarding-profiles")

    def test_ncsc_gap_reads_log_profiles_over_rest(self) -> None:
        client = _rest_fallback_client(present=set())
        client.session.get.return_value.json.return_value = {
            "data": [{"name": "partial", "match_list": [{"log_type": "traffic"}]}]
        }

        out = _tools(client)["scm_ncsc_gap"](tenant_id=TENANT, folder="Branch")

        assert "Could not fetch log forwarding profiles" not in out
        assert "Log profile 'partial' missing log types: threat, url, wildfire" in out

    def test_ai_advisor_checks_read_log_profiles_over_rest(self) -> None:
        from scm_harbourmaster_mcp.tools.ai_advisor import _run_ncsc_checks, _run_nist_checks

        client = _rest_fallback_client(present=set())

        for run in (_run_ncsc_checks, _run_nist_checks):
            gaps, warnings = run(client, "Branch", "pre")
            assert not [w for w in warnings if "log forwarding" in w or "log_forwarding" in w]
            assert not [g for g in gaps if "missing log types" in g.finding]
