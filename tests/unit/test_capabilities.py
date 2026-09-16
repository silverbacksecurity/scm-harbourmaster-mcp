"""Unit tests for the per-tenant capability probe (utils/capabilities.py).

Covers: status classification (available / forbidden / unprovisioned /
error), the read-only guard, per-tenant cache + TTL + refresh,
has_capability / capability_skip_reason, the mssp_tenant_capabilities tool's
markdown table, and the report integrations (MSR gather, AS-BUILT job,
tenant dashboard) skipping forbidden sections up front.
"""

from __future__ import annotations

import contextlib
import time
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.utils import capabilities as caps
from scm_harbourmaster_mcp.utils.family_probe import probe_endpoint

TID = "1234567890"


class FakeResp:
    def __init__(self, status_code: int, text: str = "") -> None:
        self.status_code = status_code
        self.text = text
        self.closed = False

    def close(self) -> None:
        self.closed = True


class FakeSession:
    """Routes requests by URL substring; records every call."""

    def __init__(self, routes: dict[str, int | Exception], default: int = 200) -> None:
        self.routes = routes
        self.default = default
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.headers: dict[str, str] = {}

    def _answer(self, method: str, url: str, kwargs: dict[str, Any]) -> FakeResp:
        self.calls.append((method, url, kwargs))
        for marker, outcome in self.routes.items():
            if marker in url:
                if isinstance(outcome, Exception):
                    raise outcome
                return FakeResp(outcome, text=f"body {outcome}")
        return FakeResp(self.default)

    def get(self, url: str, **kwargs: Any) -> FakeResp:
        return self._answer("GET", url, kwargs)

    def request(self, method: str, url: str, **kwargs: Any) -> FakeResp:
        return self._answer(method, url, kwargs)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch) -> Any:
    caps.clear_capability_cache()
    monkeypatch.setattr(caps, "_tenant_configs", lambda: {})
    yield
    caps.clear_capability_cache()


def _probe(
    routes: dict[str, int | Exception],
    *,
    refresh: bool = False,
    sdwan: Any = None,
) -> tuple[dict[str, caps.CapabilityResult], FakeSession, FakeSession]:
    scm = FakeSession(routes)
    sd = FakeSession(routes)
    factory = sdwan or (lambda _tid: (sd, "https://sdwan.example"))
    with patch.object(caps, "_bearer_session", return_value=scm):
        results, _, _ = caps.probe_tenant_capabilities(
            MagicMock(), TID, refresh=refresh, sdwan_session_factory=factory
        )
    return results, scm, sd


# ── Classification ───────────────────────────────────────────────────────────


class TestClassification:
    def test_every_family_classified(self) -> None:
        results, scm, sd = _probe(
            {
                "infrastructure/allocated-ips": 403,
                "tunnel_list": 403,
                "email.dlp": 400,
                "api.dlp.paloaltonetworks.com": 424,
                "sspm/api/v1/apps": 500,
                "tenancy/v1/tenants": 404,
                "iam/v1/roles": 401,
                "subscription/v1/licenses": 503,
                "auditlog": 403,
            }
        )
        assert set(results) == set(caps.known_families())
        s = {f: r.status for f, r in results.items()}
        assert s["allocated_ips"] == caps.FORBIDDEN
        assert s["insights"] == caps.FORBIDDEN
        assert s["sdwan_auditlog"] == caps.FORBIDDEN
        assert s["email_dlp"] == caps.UNPROVISIONED  # Email DLP 400 = unprovisioned
        assert s["enterprise_dlp"] == caps.UNPROVISIONED
        assert s["sspm"] == caps.UNPROVISIONED  # SSPM 500 = unlicensed
        assert s["tenancy"] == caps.UNPROVISIONED
        assert s["iam"] == caps.ERROR  # 401 is inconclusive, not RBAC
        assert s["licensing"] == caps.ERROR
        assert s["config_jobs"] == caps.AVAILABLE
        assert s["sdwan"] == caps.AVAILABLE
        # SD-WAN probes go through the SD-WAN session, not the SCM one
        assert all("sdwan.example" in c[1] for c in sd.calls)
        assert not any("sdwan.example" in c[1] for c in scm.calls)

    def test_400_is_not_unprovisioned_outside_listed_families(self) -> None:
        results, _, _ = _probe({"agent/score": 400, "compliance-frameworks": 400})
        assert results["adem"].status == caps.ERROR
        assert results["compliance"].status == caps.ERROR

    def test_transport_error(self) -> None:
        results, _, _ = _probe({"sse/config/v1/jobs": ConnectionError("dns fail")})
        r = results["config_jobs"]
        assert r.status == caps.ERROR
        assert r.http_status == -1
        assert "dns fail" in r.detail

    def test_sdwan_client_failure_marks_sdwan_families_error(self) -> None:
        def boom(_tid: str) -> Any:
            raise RuntimeError("login failed")

        results, _, _ = _probe({}, sdwan=boom)
        assert results["sdwan"].status == caps.ERROR
        assert "login failed" in results["sdwan"].detail
        assert results["config_jobs"].status == caps.AVAILABLE

    def test_classify_status_boundaries(self) -> None:
        spec = caps.CapabilitySpec("x", "x", "https://h/x")
        assert caps.classify_status(204, spec) == caps.AVAILABLE
        assert caps.classify_status(403, spec) == caps.FORBIDDEN
        assert caps.classify_status(424, spec) == caps.UNPROVISIONED
        assert caps.classify_status(500, spec) == caps.ERROR


class TestReadOnly:
    def test_all_specs_are_read_only(self) -> None:
        for spec in caps.capability_specs(TID):
            caps.assert_read_only(spec)
            if spec.method != "GET":
                assert spec.method == "POST"

    def test_guard_rejects_writes(self) -> None:
        for method, url in [
            ("POST", "https://h/sse/config/v1/addresses"),
            ("PUT", "https://h/insights/v3.0/resource/query/x"),
            ("DELETE", "https://h/iam/v1/roles"),
        ]:
            with pytest.raises(ValueError):
                caps.assert_read_only(caps.CapabilitySpec("x", "x", url, method=method))

    def test_only_get_and_query_post_sent(self) -> None:
        _, scm, sd = _probe({})
        for method, url, _ in scm.calls + sd.calls:
            assert method == "GET" or (
                method == "POST" and ("/resource/query/" in url or "/incidents/v1/search" in url)
            )

    def test_probe_endpoint_streams_and_closes(self) -> None:
        resp = FakeResp(403, text="denied")
        session = MagicMock()
        session.get.return_value = resp
        code, detail = probe_endpoint(session, "https://h/x")
        assert (code, detail) == (403, "denied")
        assert session.get.call_args.kwargs["stream"] is True
        assert resp.closed

    def test_catalogued_get_probes_exist_in_endpoint_catalog(self) -> None:
        from scm_harbourmaster_mcp.resources.endpoint_catalog import load_catalog

        documented: set[str] = set()
        for fam in load_catalog()["specs"].values():
            for meta in fam["files"].values():
                for path, methods in meta["paths"].items():
                    if "get" in methods:
                        documented.add(path)
        for fam_name in ("iam", "enterprise_dlp", "email_dlp", "adem", "sdwan", "sdwan_auditlog"):
            spec = next(s for s in caps.capability_specs(TID) if s.family == fam_name)
            path = "/" + spec.url.split("://", 1)[-1].split("/", 1)[-1]
            path = spec.url if spec.transport == "sdwan" else path
            assert path in documented, f"{fam_name}: {path} not in endpoint catalog"


# ── Cache ────────────────────────────────────────────────────────────────────


class TestCache:
    def test_cached_until_refresh(self) -> None:
        _probe({"allocated-ips": 403})
        scm = FakeSession({})
        with patch.object(caps, "_bearer_session", return_value=scm):
            results, _, from_cache = caps.probe_tenant_capabilities(
                MagicMock(), TID, sdwan_session_factory=lambda t: (scm, "https://s")
            )
        assert from_cache and not scm.calls
        assert results["allocated_ips"].status == caps.FORBIDDEN

        results, _, _ = _probe({}, refresh=True)
        assert results["allocated_ips"].status == caps.AVAILABLE
        assert caps.has_capability(TID, "allocated_ips") is True

    def test_ttl_expiry(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _probe({"allocated-ips": 403})
        assert caps.has_capability(TID, "allocated_ips") is False
        real = time.time
        monkeypatch.setattr(caps.time, "time", lambda: real() + caps.CAPABILITY_TTL_SECONDS + 1)
        assert caps.has_capability(TID, "allocated_ips") is None
        assert caps.get_cached_capabilities(TID) is None

    def test_has_capability_values(self) -> None:
        assert caps.has_capability(TID, "insights") is None  # not probed
        _probe({"tunnel_list": 403, "email.dlp": 400, "iam/v1/roles": 500})
        assert caps.has_capability(TID, "insights") is False
        assert caps.has_capability(TID, "email_dlp") is False
        assert caps.has_capability(TID, "iam") is None  # error = unknown
        assert caps.has_capability(TID, "config_jobs") is True
        assert caps.has_capability(TID, "no_such_family") is None
        assert caps.has_capability("9999999999", "insights") is None  # other tenant

    def test_skip_reason(self) -> None:
        assert caps.capability_skip_reason(TID, "insights") is None
        _probe({"tunnel_list": 403, "iam/v1/roles": 500})
        reason = caps.capability_skip_reason(TID, "insights")
        assert reason is not None and "forbidden" in reason and "HTTP 403" in reason
        assert caps.capability_skip_reason(TID, "iam") is None  # error never skips
        assert caps.capability_skip_reason(TID, "config_jobs") is None

    def test_label_resolves_to_tsg(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _probe({"tunnel_list": 403})
        monkeypatch.setattr(
            caps,
            "_tenant_configs",
            lambda: {"lab": SimpleNamespace(tenant_id=TID, label="Lab Tenant")},
        )
        assert caps.has_capability("lab", "insights") is False
        assert caps.has_capability("Lab Tenant", "insights") is False


# ── Tool ─────────────────────────────────────────────────────────────────────


class TestTool:
    def test_markdown_table(self) -> None:
        from scm_harbourmaster_mcp.tools.capabilities import register_capability_tools

        mcp = FastMCP("test")
        register_capability_tools(mcp, lambda tid="": MagicMock())
        fn = mcp._tool_manager.get_tool("mssp_tenant_capabilities").fn
        scm = FakeSession({"allocated-ips": 403})
        with (
            patch.object(caps, "_bearer_session", return_value=scm),
            patch.object(caps, "_default_sdwan_session_factory", return_value=(scm, "https://s")),
        ):
            out = fn(tenant_id=TID)
            again = fn(tenant_id=TID)
        assert f"# API Capabilities — Tenant `{TID}`" in out
        assert "| Status | Family |" in out
        assert "⛔ forbidden | `allocated_ips`" in out
        assert "live probe" in out and "cached" in again
        assert "1 forbidden" in out


# ── Report integrations ──────────────────────────────────────────────────────


class TestMsrSkip:
    def test_forbidden_sections_skipped_up_front(self) -> None:
        from scm_harbourmaster_mcp.tools.msr import gather_msr_data

        _probe({"tunnel_list": 403, "incidents/v1/search": 403, "email.dlp": 400})
        client = MagicMock()
        client.list_jobs.return_value = MagicMock(data=[])
        with contextlib.ExitStack() as stack:
            ins = stack.enter_context(patch("scm_harbourmaster_mcp.tools.msr.extract_insights"))
            inc = stack.enter_context(
                patch("scm_harbourmaster_mcp.tools.msr._incidents_for_tenant")
            )
            for p in [
                patch(
                    "scm_harbourmaster_mcp.tools.msr._resolve_tenant_meta",
                    return_value=("T", TID, "uk"),
                ),
                patch("scm_harbourmaster_mcp.tools.msr.fetch_licenses", return_value=[]),
                patch("scm_harbourmaster_mcp.tools.msr._compliance_get", return_value=[]),
                patch("scm_harbourmaster_mcp.tools.msr._get_ssr_config", return_value={}),
                patch("scm_harbourmaster_mcp.tools.msr.extract_adem", side_effect=lambda c, s: s),
                patch(
                    "scm_harbourmaster_mcp.tools.msr._bearer_session_for",
                    side_effect=RuntimeError("no mt"),
                ),
            ]:
                stack.enter_context(p)
            data = gather_msr_data(client, tenant_id=TID, month="2026-06")

        ins.assert_not_called()
        inc.assert_not_called()
        for key in ("incidents", "bandwidth", "bandwidth_month", "mobile_users"):
            assert "capability probe" in data.errors[key]
        assert "jobs" not in data.errors  # available → still gathered
        client.list_jobs.assert_called_once()

    def test_no_cache_keeps_existing_behaviour(self) -> None:
        from scm_harbourmaster_mcp.tools.msr import gather_msr_data

        client = MagicMock()
        client.list_jobs.return_value = MagicMock(data=[])
        with contextlib.ExitStack() as stack:
            inc = stack.enter_context(
                patch(
                    "scm_harbourmaster_mcp.tools.msr._incidents_for_tenant",
                    return_value=[],
                )
            )
            bearer = stack.enter_context(patch.object(caps, "_bearer_session"))
            for p in [
                patch(
                    "scm_harbourmaster_mcp.tools.msr._resolve_tenant_meta",
                    return_value=("T", TID, "uk"),
                ),
                patch("scm_harbourmaster_mcp.tools.msr.fetch_licenses", return_value=[]),
                patch("scm_harbourmaster_mcp.tools.msr._compliance_get", return_value=[]),
                patch("scm_harbourmaster_mcp.tools.msr._get_ssr_config", return_value={}),
                patch("scm_harbourmaster_mcp.tools.msr.extract_adem", side_effect=lambda c, s: s),
                patch(
                    "scm_harbourmaster_mcp.tools.msr._bearer_session_for",
                    side_effect=RuntimeError("no mt"),
                ),
            ]:
                stack.enter_context(p)
            data = gather_msr_data(client, tenant_id=TID, month="2026-06", include_insights=False)
        inc.assert_called_once()
        bearer.assert_not_called()  # reports never trigger a probe
        assert data.errors["bandwidth"] == "skipped (include_insights=False)"


class TestAsBuiltSkip:
    def _run_job(self, monkeypatch: pytest.MonkeyPatch) -> tuple[dict[str, Any], dict[str, Any]]:
        from scm_harbourmaster_mcp.audit.models import AuditSnapshot
        from scm_harbourmaster_mcp.tools import audit as audit_tools

        calls: dict[str, Any] = {}
        for name in dir(audit_tools):
            if name.startswith("extract_") and name != "extract_snapshot":
                mock = MagicMock(name=name)
                calls[name] = mock
                monkeypatch.setattr(audit_tools, name, mock)
        snap = AuditSnapshot(folder="Prisma Access", tenant_id=TID)
        monkeypatch.setattr(audit_tools, "extract_snapshot", lambda *a, **k: snap)
        monkeypatch.setattr(audit_tools, "get_tenant_meta", lambda tid: None)
        builder = MagicMock()
        builder.return_value.to_markdown.return_value = "# report"
        monkeypatch.setattr(audit_tools, "AsBuiltReportBuilder", builder)

        client = MagicMock()
        client.list_jobs.return_value = MagicMock(data=[])
        mcp = FastMCP("test")
        audit_tools.register_audit_tools(mcp, lambda tid="": client)
        fn = mcp._tool_manager.get_tool("scm_asbuilt_report").fn
        out = fn(
            tenant_id=TID,
            include_insights=True,
            include_adem=True,
            include_extended=True,
        )
        job_id = next(k for k, v in audit_tools._ASBUILT_JOBS.items() if k in out)
        deadline = time.time() + 10
        while audit_tools._ASBUILT_JOBS[job_id]["status"] == "running":
            assert time.time() < deadline, "asbuilt job did not finish"
            time.sleep(0.01)
        job = audit_tools._ASBUILT_JOBS[job_id]
        assert job["status"] == "done", job["error"]
        calls["_client"] = client
        calls["_snap"] = snap
        return calls, job

    def test_forbidden_families_skipped_with_disclosure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _probe(
            {
                "allocated-ips": 403,
                "tunnel_list": 403,
                "api.dlp.paloaltonetworks.com": 424,
                "iam/v1/roles": 403,
                "sse/config/v1/jobs": 403,
            }
        )
        calls, _ = self._run_job(monkeypatch)
        snap = calls["_snap"]
        for skipped in (
            "extract_allocated_ips",
            "extract_insights",
            "extract_enterprise_dlp",
            "extract_iam_roles",
            "extract_iam_access_policies",
        ):
            calls[skipped].assert_not_called()
        calls["_client"].list_jobs.assert_not_called()
        for ran in ("extract_licenses", "extract_adem", "extract_sspm", "extract_casb_dlp"):
            calls[ran].assert_called_once()
        joined = "\n".join(snap.extraction_errors)
        for fam in ("allocated_ips", "insights", "enterprise_dlp", "iam", "config_jobs"):
            assert f"{fam}: skipped — capability probe" in joined
        assert any("capability probe" in e for e in snap.insights_errors)

    def test_no_cache_runs_everything(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls, _ = self._run_job(monkeypatch)
        for ran in ("extract_allocated_ips", "extract_insights", "extract_iam_roles"):
            calls[ran].assert_called_once()
        calls["_client"].list_jobs.assert_called_once()
        assert not any("capability probe" in e for e in calls["_snap"].extraction_errors)


class TestDashboard:
    def test_capability_column(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scm_harbourmaster_mcp.tools import mssp as mssp_tools

        other = "9876543210"
        monkeypatch.setattr(mssp_tools, "list_loaded_tenants", lambda: [TID, other])
        monkeypatch.setattr(mssp_tools, "get_tenant_meta", lambda tid: None)
        _probe({"allocated-ips": 403, "email.dlp": 400})

        mcp = FastMCP("test")
        mssp_tools.register_mssp_tools(mcp, lambda tid="": MagicMock(), lambda: None)
        out = mcp._tool_manager.get_tool("mssp_tenant_dashboard").fn()
        total = len(caps.known_families())
        assert "API Capabilities" in out
        assert f"{total - 2}/{total} available · 2 restricted" in out
        assert f"| `{other}` | — | — | — | — | not probed |" in out
        assert "`allocated_ips` (forbidden)" in out
        assert "`email_dlp` (unprovisioned)" in out


class TestInsightsRegionFor:
    def test_maps_the_tenant_insights_region(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = SimpleNamespace(tenant_id="1234567890", insights_region="us")
        monkeypatch.setattr(caps, "_tenant_configs", lambda: {"acme": cfg})
        assert caps._insights_region_for("1234567890") == "americas"

    def test_unknown_tenant_falls_back_to_europe(self) -> None:
        assert caps._insights_region_for("999") == "europe"
