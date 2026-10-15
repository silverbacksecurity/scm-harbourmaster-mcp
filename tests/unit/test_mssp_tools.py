"""Tests for the MSSP estate, CASB/DLP/ZTNA/browser and NGFW/AIRS tools (no network)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from mcp.server.fastmcp import FastMCP

import scm_harbourmaster_mcp.auth.oauth as oauth_mod
import scm_harbourmaster_mcp.tools.mssp as mssp
from scm_harbourmaster_mcp.config.settings import TenantConfig

TENANT = "1234567890"


def _resp(status: int, data: Any = None, text: str = "") -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.json.return_value = data
    r.text = text
    if status >= 400:
        r.raise_for_status.side_effect = RuntimeError(f"HTTP {status}")
    return r


def _all_tools(client: Any, settings: Any = None) -> dict[str, Any]:
    mcp = FastMCP("test")
    mssp.register_mssp_tools(
        mcp, lambda tenant_id="": client, lambda: settings or SimpleNamespace(mssp_name="Acme")
    )
    mssp.register_casb_dlp_tools(mcp, lambda tenant_id="": client)
    mssp.register_ngfw_airs_tools(mcp, lambda tenant_id="": client)
    return {name: t.fn for name, t in mcp._tool_manager._tools.items()}


@pytest.fixture(autouse=True)
def _clean_oauth_cache() -> Any:
    oauth_mod._clients.clear()
    oauth_mod._tenant_configs.clear()
    yield
    oauth_mod._clients.clear()
    oauth_mod._tenant_configs.clear()


# ── mssp_tenant_dashboard ──────────────────────────────────────────────────


class TestTenantDashboard:
    def test_no_tenants(self) -> None:
        out = _all_tools(MagicMock())["mssp_tenant_dashboard"]()
        assert "No tenants currently loaded" in out

    def test_lists_loaded_tenants_with_metadata(self) -> None:
        oauth_mod._clients[TENANT] = MagicMock()
        oauth_mod._tenant_configs[TENANT] = TenantConfig(
            tenant_id=TENANT,
            client_id="svc@iam",
            client_secret="s",
            label="Example Customer",
            default_folder="ngfw-shared",
            service_term_years=3,
            account_ref="ACC-1",
        )
        oauth_mod._clients["1234567891"] = MagicMock()  # no metadata cached
        out = _all_tools(MagicMock())["mssp_tenant_dashboard"]()
        assert "**Loaded tenants:** 2" in out
        assert f"| `{TENANT}` | Example Customer | ngfw-shared | 3yr | ACC-1 |" in out
        assert "| `1234567891` | — | — | — | — |" in out


# ── scm_license_info ───────────────────────────────────────────────────────


def _iso(days: int) -> str:
    return (datetime.now(UTC) + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")


class TestLicenseInfo:
    def test_status_classification_and_sort(self) -> None:
        bundles = [
            {
                "claim_by": "ops@example.com",
                "licenses": [
                    {
                        "app_id": "prisma_access",
                        "license_type": "PA-ACTIVE",
                        "license_expiration": _iso(400),
                        "purchased_size": 100,
                        "remaining_size": 40,
                    },
                    {
                        "app_id": "prisma_access",
                        "license_type": "PA-SOON",
                        "license_expiration": _iso(30),
                        "purchased_size": 10,
                        "remaining_size": None,
                    },
                    {
                        "app_id": "sdwan",
                        "license_type": "SDWAN-OLD",
                        "license_expiration": _iso(-5),
                        "purchased_size": 5,
                    },
                    {"app_id": "x", "license_type": "BAD-DATE", "license_expiration": "soon"},
                ],
            }
        ]
        with patch.object(oauth_mod, "fetch_licenses", return_value=bundles):
            out = _all_tools(MagicMock())["scm_license_info"](tenant_id=TENANT)
        assert f"Tenant `{TENANT}`" in out
        assert "1 bundle(s) · 4 licence line(s)" in out
        rows = [line for line in out.splitlines() if line.startswith("| ") and "`" in line]
        assert rows[0].startswith("| ❌ Expired")  # expired sorts first
        assert "| ✅ Active | prisma_access | `PA-ACTIVE` | 100 | 60 |" in out
        assert "⚠️ Expiring" in out and "| 10 | 10 |" in out
        assert "❓ Unknown" in out and "| soon |" in out

    def test_remaining_above_purchased_is_na(self) -> None:
        bundles = [
            {
                "claim_by": "ops@example.com",
                "licenses": [
                    {
                        "app_id": "aperture",
                        "license_type": "EVAL-POOLED",
                        "license_expiration": _iso(100),
                        "purchased_size": 100,
                        "remaining_size": 2800,
                    }
                ],
            }
        ]
        with patch.object(oauth_mod, "fetch_licenses", return_value=bundles):
            out = _all_tools(MagicMock())["scm_license_info"](tenant_id=TENANT)
        assert "| 100 | n/a |" in out
        assert "-2700" not in out

    def test_empty_and_error(self) -> None:
        with patch.object(oauth_mod, "fetch_licenses", return_value=[]):
            assert "No licences found" in _all_tools(MagicMock())["scm_license_info"]()
        with patch.object(oauth_mod, "fetch_licenses", side_effect=RuntimeError("401")):
            assert "Error fetching licences: 401" in _all_tools(MagicMock())["scm_license_info"]()


# ── scm_mobile_user_stats ──────────────────────────────────────────────────


class TestMobileUserStats:
    def test_happy_path(self) -> None:
        client = MagicMock()
        client.session.post.side_effect = [
            _resp(200, {"data": [{"user_count": 42}]}),
            _resp(200, {"data": [{"user_count": 41}]}),
        ]
        bw = MagicMock()
        bw.model_dump.return_value = {
            "name": "europe-west",
            "allocated_bandwidth": 200,
            "spn_name_list": ["spn-a", "spn-b"],
        }
        client.bandwidth_allocation.list.return_value = [bw]
        bundles = [
            {
                "claim_by": "ops",
                "licenses": [
                    {
                        "app_id": "prisma_access_edition",
                        "license_type": "PA-MU-ENT",
                        "license_expiration": _iso(100),
                        "purchased_size": 500,
                        "remaining_size": 100,
                    },
                    {
                        "app_id": "prisma_access_edition",
                        "license_type": "PA-MU-OLD",
                        "license_expiration": _iso(-1),
                        "purchased_size": 1,
                    },
                    {"app_id": "other", "license_type": "PA-MU-X"},
                ],
            }
        ]
        with patch.object(oauth_mod, "fetch_licenses", return_value=bundles):
            out = _all_tools(client)["scm_mobile_user_stats"](tenant_id=TENANT, region="uk")

        assert "Connected users: **42**" in out
        assert "Connected users: **41**" in out
        headers = client.session.post.call_args.kwargs["headers"]
        assert headers["X-PANW-Region"] == "uk" and headers["Prisma-Tenant"] == TENANT
        assert "| `PA-MU-ENT` | 500 | 400 | ops |" in out
        assert "PA-MU-OLD" not in out and "PA-MU-X" not in out
        assert "| europe-west | 200 | spn-a, spn-b |" in out
        client.oauth_client.refresh_token.assert_called()

    def test_errors_are_reported_inline(self) -> None:
        client = MagicMock()
        client.oauth_client.refresh_token.side_effect = [RuntimeError("no"), None, None]
        client.oauth_client.is_expired = True
        client.session.post.side_effect = [
            _resp(403, text="forbidden"),
            RuntimeError("Token expired at 12:00"),
            _resp(200, {"data": []}),
        ]
        client.bandwidth_allocation.list.side_effect = RuntimeError("bw down")
        with patch.object(oauth_mod, "fetch_licenses", side_effect=RuntimeError("lic down")):
            out = _all_tools(client)["scm_mobile_user_stats"](tenant_id=TENANT)
        assert "v2.0 connected_user_count → HTTP 403: forbidden" in out
        # v3.0: token-expired exception triggers one refresh + retry
        assert "Connected users: **{'data': []}**" in out
        assert "License fetch error: lic down" in out
        assert "Bandwidth fetch error: bw down" in out

    def test_no_licences_or_bandwidth(self) -> None:
        client = MagicMock()
        client.oauth_client = None
        client.session.post.side_effect = RuntimeError("connection refused")
        client.bandwidth_allocation.list.return_value = []
        with patch.object(oauth_mod, "fetch_licenses", return_value=[]):
            out = _all_tools(client)["scm_mobile_user_stats"](tenant_id="")
        assert "HTTP 0: connection refused" in out
        assert "No active PAE-MU licenses found" in out
        assert "No bandwidth allocations found" in out


# ── scm_discover_tenants ───────────────────────────────────────────────────


class TestDiscoverTenants:
    def _run(self, responses: list[Any], token: str | None = "tok") -> str:
        client = MagicMock()
        client.oauth_client.is_expired = True
        client.session.token = {"access_token": token} if token else None
        sess = MagicMock()
        sess.headers = {}
        sess.get.side_effect = responses
        with patch("requests.Session", return_value=sess):
            out = _all_tools(client)["scm_discover_tenants"](tenant_id=TENANT)
        if token:
            assert sess.headers["Authorization"] == f"Bearer {token}"
        return out

    def test_full_discovery(self) -> None:
        out = self._run(
            [
                _resp(
                    200,
                    {
                        "items": [
                            {"id": "2", "display_name": "Zeta", "status": "active"},
                            {"tsg_id": "1", "name": "Alpha", "type": "child"},
                        ]
                    },
                ),
                _resp(200, {"items": [{"principal": "admin@example.com", "role": "superuser"}]}),
                _resp(
                    200,
                    {
                        "items": [
                            {
                                "name": "automation",
                                "client_id": "svc@iam",
                                "created_at": "2026-01-02T03:04:05Z",
                            }
                        ]
                    },
                ),
            ]
        )
        assert out.startswith("# Acme — Managed Tenant & Admin Discovery")
        assert "| `2` | Zeta | active | — |" in out
        assert "| `1` | Alpha | — | child |" in out
        assert "_Total: 2 managed tenant(s)_" in out
        assert "| admin@example.com | User | superuser | All |" in out
        assert "| automation | `svc@iam` | — | 2026-01-02 |" in out

    def test_denied_empty_and_errors(self) -> None:
        out = self._run(
            [_resp(403), _resp(500), RuntimeError("dns failure")],
            token=None,
        )
        assert "Access denied (HTTP 403)" in out
        assert "IAM access-policies API returned HTTP 500" in out
        assert "IAM service-accounts error: dns failure" in out

        out = self._run(
            [_resp(200, {"items": []}), _resp(200, {"items": []}), _resp(401)],
        )
        assert "No sub-tenants returned" in out
        assert "No access policies found" in out
        assert "Access denied (HTTP 401) — IAM read permission required" in out

        out = self._run(
            [RuntimeError("tenancy down"), _resp(401), _resp(200, {"items": []})],
        )
        assert "Tenancy API error: tenancy down" in out
        assert "No service accounts found" in out

        out = self._run([_resp(502), _resp(200, {}), _resp(503)])
        assert "Tenancy API returned HTTP 502" in out
        assert "IAM service-accounts API returned HTTP 503" in out


# ── module helpers ─────────────────────────────────────────────────────────


class TestRestHelpers:
    def test_bearer_session_uses_sdk_token(self) -> None:
        client = MagicMock()
        client.oauth_client.is_expired = True
        client.session.token = {"access_token": "abc"}
        sess = mssp._bearer_session(client)
        client.oauth_client.refresh_token.assert_called_once()
        assert sess.headers["Authorization"] == "Bearer abc"

    def test_bearer_session_without_token(self) -> None:
        client = SimpleNamespace(oauth_client=None, session=SimpleNamespace(token=None))
        assert "Authorization" not in mssp._bearer_session(client).headers

    @pytest.mark.parametrize("status", [401, 403, 404, 424])
    def test_rest_get_not_licensed_is_empty(self, status: int) -> None:
        session = MagicMock()
        session.get.return_value = _resp(status)
        assert mssp._rest_get(session, "https://x") == []

    def test_rest_get_shapes_and_errors(self) -> None:
        session = MagicMock()
        session.get.return_value = _resp(200, [{"a": 1}])
        assert mssp._rest_get(session, "u") == [{"a": 1}]
        session.get.return_value = _resp(200, {"items": [{"b": 2}]})
        assert mssp._rest_get(session, "u") == [{"b": 2}]
        session.get.return_value = _resp(200, {"data": [{"c": 3}]})
        assert mssp._rest_get(session, "u") == [{"c": 3}]

        session.get.return_value = _resp(500)
        with pytest.raises(RuntimeError):
            mssp._rest_get(session, "u")

        exc = RuntimeError("boom")
        exc.response = SimpleNamespace(status_code=424)  # type: ignore[attr-defined]
        session.get.side_effect = exc
        assert mssp._rest_get(session, "u") == []
        session.get.side_effect = RuntimeError("other")
        with pytest.raises(RuntimeError):
            mssp._rest_get(session, "u")


# ── CASB / DLP / ZTNA / Browser ────────────────────────────────────────────


@pytest.fixture
def rest_session() -> Any:
    sess = MagicMock()
    with patch.object(mssp, "_bearer_session", return_value=sess):
        yield sess


class TestCasbDlp:
    def test_dlp_list(self, rest_session: MagicMock) -> None:
        rest_session.get.side_effect = [
            _resp(
                200,
                {"data": [{"name": "pci", "data_capture": {"rules": [{"name": "ccn"}]}}]},
            ),
            _resp(200, {"data": [{"name": "ssn", "pattern_type": {"regex": {}}}]}),
        ]
        out = _all_tools(MagicMock())["scm_dlp_list"](tenant_id=TENANT, folder="Shared")
        assert "## Data Filtering Profiles (1)" in out
        assert "| pci | — | ccn |" in out
        assert "| ssn | regex | — |" in out
        assert rest_session.get.call_args.kwargs["params"] == {"folder": "Shared", "limit": 1000}

    def test_dlp_and_casb_empty(self, rest_session: MagicMock) -> None:
        rest_session.get.return_value = _resp(404)
        tools = _all_tools(MagicMock())
        out = tools["scm_dlp_list"](tenant_id=TENANT)
        assert "No data filtering profiles found" in out and "No data objects found" in out
        assert "No SaaS tenant restrictions found" in tools["scm_casb_list"](tenant_id=TENANT)

    def test_casb_list(self, rest_session: MagicMock) -> None:
        rest_session.get.return_value = _resp(
            200,
            [{"name": "m365", "applications": [f"app{i}" for i in range(7)], "action": "block"}],
        )
        out = _all_tools(MagicMock())["scm_casb_list"](tenant_id=TENANT)
        assert "| m365 | — | app0, app1, app2, app3, app4 | block |" in out

    def test_ztna_not_enabled(self, rest_session: MagicMock) -> None:
        rest_session.get.return_value = _resp(424)
        out = _all_tools(MagicMock())["scm_ztna_connector_list"](tenant_id=TENANT)
        assert "ZTNA Connector is not enabled" in out

    def test_ztna_lists(self, rest_session: MagicMock) -> None:
        rest_session.get.side_effect = [
            _resp(200, {}),
            _resp(200, {"items": [{"name": "c1", "status": "up", "version": "2.0"}]}),
            _resp(200, {"items": [{"name": "g1", "region": "eu", "connector_ids": ["a", "b"]}]}),
        ]
        out = _all_tools(MagicMock())["scm_ztna_connector_list"](tenant_id=TENANT)
        assert "| g1 | eu | 2 | — |" in out
        assert "| c1 | up | 2.0 | — | — |" in out

        rest_session.get.side_effect = [_resp(200, {}), _resp(200, []), _resp(200, [])]
        out = _all_tools(MagicMock())["scm_ztna_connector_list"](tenant_id=TENANT)
        assert "No connector groups found" in out and "No connectors found" in out

    def test_browser_not_licensed(self, rest_session: MagicMock) -> None:
        rest_session.get.return_value = _resp(403)
        out = _all_tools(MagicMock())["scm_browser_list"](tenant_id=TENANT)
        assert "No Prisma Browser configuration found" in out

    def test_browser_lists(self, rest_session: MagicMock) -> None:
        responses = {
            "device-groups": [{"name": "laptops", "devices": [1, 2, 3]}],
            "user-groups": [],
            "application-groups": [{"name": "saas", "members": [1]}],
            "users": [{"id": 1}, {"id": 2}],
            "devices": [{"id": 1}],
            "applications": [{"name": "Workday", "type": "web", "category": "hr"}],
            "applications/plugins": [{"name": "pw-mgr", "version": "1.2", "enabled": True}],
            "user-requests": [{"id": 9}],
        }

        def _get(url: str, params: Any = None, timeout: Any = None) -> MagicMock:
            key = url.split("/seb-api/v1/")[1]
            return _resp(200, {"data": responses[key]})

        rest_session.get.side_effect = _get
        out = _all_tools(MagicMock())["scm_browser_list"](tenant_id=TENANT)
        assert "**Enrolled users:** 2" in out
        assert "**Pending user requests:** 1" in out
        assert "| laptops | — | 3 |" in out
        assert "_No user groups configured._" in out
        assert "| Workday | web | hr |" in out
        assert "| pw-mgr | 1.2 | True |" in out

        responses.update({"applications": [], "applications/plugins": [], "user-requests": []})
        out = _all_tools(MagicMock())["scm_browser_list"](tenant_id=TENANT)
        assert "_No applications configured._" in out and "_No plugins configured._" in out
        assert "Pending user requests" not in out


# ── Secure Agentless Access ────────────────────────────────────────────────


class TestSaa:
    @pytest.fixture(autouse=True)
    def _isolated(self):  # type: ignore[no-untyped-def]
        from scm_harbourmaster_mcp.utils import saa

        saa.clear_region_cache()
        with (
            patch.object(mssp, "_bearer_session", side_effect=lambda c: c.session),
            patch.object(saa, "resolve_region_with_source", return_value=("", "none")),
        ):
            yield
        saa.clear_region_cache()

    @staticmethod
    def _router(region: str, routes: dict[str, Any]) -> Any:
        """Answer *routes* only for *region*; everything else 404 "tenant not found"."""

        def get(url: str, params: Any = None, headers: Any = None, timeout: Any = None) -> Any:
            if (headers or {}).get("x-panw-region") == region:
                for suffix, resp in routes.items():
                    if url.endswith(suffix):
                        return resp
            return _resp(404, {"_errors": [{"code": "SAA_12008"}]})

        return get

    def test_not_provisioned(self) -> None:
        client = MagicMock()
        client.session.get.side_effect = self._router("uk", {})
        out = _all_tools(client)["scm_saa_list"](tenant_id=TENANT)
        assert out.startswith("Secure Agentless Access is not provisioned")

    def test_full_report(self) -> None:
        client = MagicMock()
        client.session.get.side_effect = self._router(
            "europe",
            {
                "/applications": _resp(
                    200,
                    {
                        "data": [
                            {
                                "app_id": "a1",
                                "name": "ssh-bastion",
                                "type": "ssh",
                                "ssh_settings": {"private_key": "SECRET", "host_key": ""},
                            }
                        ]
                    },
                ),
                "/application-groups": _resp(200, {"data": []}),
                "/application-profiles": _resp(200, {"data": []}),
                "/application-policies": _resp(200, {"data": []}),
                "/active-sessions": _resp(
                    200, {"data": [{"user_id": "user@example.com", "app_id": "a1"}]}
                ),
            },
        )
        out = _all_tools(client)["scm_saa_list"](tenant_id=TENANT)
        assert out.startswith("## Secure Agentless Access")
        assert "**Region:** `europe` (probed)" in out
        assert "| ssh-bastion | ssh |" in out
        assert "SSH application `ssh-bastion` has no pinned host key." in out
        assert "| user@example.com | ssh-bastion |" in out
        assert "SECRET" not in out
        no_sessions = _all_tools(client)["scm_saa_list"](tenant_id=TENANT, include_sessions=False)
        assert "Active Sessions" not in no_sessions
        assert "**Region:** `europe` (cached)" in no_sessions

    def test_error_is_reported(self) -> None:
        client = MagicMock()
        client.session.get.side_effect = RuntimeError("connection reset")
        out = _all_tools(client)["scm_saa_list"](tenant_id=TENANT, region="uk")
        assert out.startswith("Error:") and "connection reset" in out


# ── NGFW / AIRS ────────────────────────────────────────────────────────────


class TestNgfwAirs:
    @pytest.fixture(autouse=True)
    def _sdk_session_as_bearer(self):  # type: ignore[no-untyped-def]
        # scm_airs_list builds a bearer session; route it back to the mock.
        with patch.object(mssp, "_bearer_session", side_effect=lambda c: c.session):
            yield

    def test_ngfw_device_list(self) -> None:
        client = MagicMock()
        dev = MagicMock()
        dev.model_dump.return_value = {
            "name": "fw-1",
            "serial_number": "0001",
            "model": "PA-440",
            "sw_version": "11.1.4",
            "is_connected": True,
        }
        client.device.list.return_value = [dev, {"name": "fw-2"}]
        out = _all_tools(client)["scm_ngfw_device_list"](tenant_id=TENANT)
        assert "ngfw-shared (2 devices)" in out
        assert "| fw-1 | 0001 | PA-440 | 11.1.4 | — | ✓ | — |" in out
        assert "| fw-2 | — | — | — | — | ✗ | — |" in out

    def test_ngfw_device_list_empty_and_error(self) -> None:
        client = MagicMock()
        client.device.list.return_value = []
        assert "No NGFW devices found in folder: lab" in _all_tools(client)["scm_ngfw_device_list"](
            folder="lab"
        )
        client.device.list.side_effect = RuntimeError("503")
        assert _all_tools(client)["scm_ngfw_device_list"]().startswith("Error: [RuntimeError] 503")

    @staticmethod
    def _airs_router(routes: dict[str, Any]) -> Any:
        """session.get side effect keyed on the URL suffix; unknown paths 401."""

        def get(url: str, params: Any = None, timeout: Any = None) -> Any:
            for suffix, resp in routes.items():
                if url.endswith(suffix):
                    return resp
            return _resp(401)

        return get

    def test_airs_not_provisioned(self) -> None:
        client = MagicMock()
        client.session.get.side_effect = self._airs_router(
            {"/deploymentprofiles": _resp(200, {"deployment_profiles": [], "status": ""})}
        )
        out = _all_tools(client)["scm_airs_list"](tenant_id=TENANT)
        assert "Prisma AIRS is not provisioned" in out
        # Gate: deployment profiles + profiles only, no further list calls.
        assert client.session.get.call_count == 2
        assert all("/tsg/" not in c.args[0] for c in client.session.get.call_args_list)

    def test_airs_full_report(self) -> None:
        client = MagicMock()
        client.session.get.side_effect = self._airs_router(
            {
                "/deploymentprofiles": _resp(
                    200,
                    {
                        "deployment_profiles": [
                            {"dp_name": "dp1", "auth_code": "AC1", "expiration_date": "2020-01-01"}
                        ]
                    },
                ),
                "/profiles": _resp(
                    200,
                    {
                        "ai_profiles": [
                            {
                                "profile_name": "strict",
                                "profile_id": "p1",
                                "active": True,
                                "updated_by": "admin@example.com",
                                "last_modified_ts": "2026-10-01T10:00:00Z",
                                "policy": {"ai-security-profiles": []},
                            }
                        ]
                    },
                ),
                "/customerapps": _resp(200, {"customer_apps": [{"app_name": "chatbot"}]}),
                "/topics": _resp(200, {"custom_topics": []}),
                "/apikeys": _resp(403),
                "/devices": _resp(
                    200,
                    {
                        "data": [
                            {
                                "hostname": "fw-1",
                                "serial_number": "001",
                                "installedLicenses": [{"feature": "X", "authcode": "AC1"}],
                            }
                        ]
                    },
                ),
            }
        )
        out = _all_tools(client)["scm_airs_list"](tenant_id=TENANT)
        assert "| dp1 | AC1 | — | 2020-01-01 |" in out
        assert "| strict | p1 | — | ✓ | admin@example.com |" in out
        assert "| chatbot | — | — | — | 0 |" in out
        assert "### API Keys\n\n_Refused by the API (HTTP 403)._" in out
        assert "| fw-1 | 001 | — | X | dp1 | — |" in out
        assert (
            "| 2026-10-01 10:00 UTC | admin@example.com | AI security profile | strict | updated |"
            in out
        )
        assert "HIGH | Licence | Deployment profile `dp1` expired" in out
        assert "no model protection" in out
        assert out.index("**AIRS risks:** 🔴") < out.index("### Licence")  # headline on top

    def test_airs_errors(self) -> None:
        client = SimpleNamespace(session=None)
        assert "client has no .session attribute" in _all_tools(client)["scm_airs_list"](
            tenant_id=TENANT
        )

        client2 = MagicMock()
        client2.session.get.return_value = _resp(500)
        assert _all_tools(client2)["scm_airs_list"](tenant_id=TENANT).startswith("Error:")

        exc = RuntimeError("gone")
        exc.response = SimpleNamespace(status_code=404)  # type: ignore[attr-defined]
        client3 = MagicMock()
        client3.session.get.side_effect = exc
        # 404 everywhere (deploymentprofiles included) = not licensed.
        assert "not provisioned" in _all_tools(client3)["scm_airs_list"](tenant_id=TENANT)

        client4 = MagicMock()
        client4.session.get.side_effect = RuntimeError("timeout")
        assert "timeout" in _all_tools(client4)["scm_airs_list"](tenant_id=TENANT)
