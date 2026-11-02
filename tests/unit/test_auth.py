"""Unit tests for auth/oauth module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from scm_harbourmaster_mcp.auth.oauth import evict_tenant, list_loaded_tenants
from scm_harbourmaster_mcp.config.settings import TenantConfig
from scm_harbourmaster_mcp.utils.errors import TenantNotFoundError


@pytest.fixture(autouse=True)
def clear_client_cache() -> None:
    """Ensure the global client cache is clean before each test."""
    import scm_harbourmaster_mcp.auth.oauth as oauth_module

    oauth_module._clients.clear()
    oauth_module._auth_failures.clear()
    yield
    oauth_module._clients.clear()
    oauth_module._auth_failures.clear()


class TestClientCaching:
    def test_get_scm_client_creates_and_caches(self) -> None:
        from scm_harbourmaster_mcp.auth.oauth import get_scm_client

        tc = TenantConfig(
            tenant_id="t-cache-test",
            client_id="svc@iam",
            client_secret="secret",
        )
        mock_scm = MagicMock()
        with patch("scm_harbourmaster_mcp.auth.oauth.Scm", return_value=mock_scm):
            c1 = get_scm_client(tc)
            c2 = get_scm_client(tc)
        assert c1 is c2, "second call should return cached client"

    def test_evict_removes_tenant(self) -> None:
        import scm_harbourmaster_mcp.auth.oauth as oauth_module

        oauth_module._clients["t-evict"] = MagicMock()
        assert evict_tenant("t-evict") is True
        assert "t-evict" not in oauth_module._clients

    def test_evict_nonexistent_returns_false(self) -> None:
        assert evict_tenant("nonexistent-tenant") is False

    def test_list_loaded_tenants(self) -> None:
        import scm_harbourmaster_mcp.auth.oauth as oauth_module

        oauth_module._clients["t-a"] = MagicMock()
        oauth_module._clients["t-b"] = MagicMock()
        result = list_loaded_tenants()
        assert "t-a" in result
        assert "t-b" in result

    def test_get_client_for_unknown_tenant_raises(self) -> None:
        from scm_harbourmaster_mcp.auth.oauth import get_client_for_tenant

        with pytest.raises(TenantNotFoundError):
            get_client_for_tenant("does-not-exist")


class TestAuthFailureMessages:
    """pan-scm-sdk's APIError.__str__ is blank when only `message` is set."""

    def _failing_config(self) -> TenantConfig:
        return TenantConfig(tenant_id="1234567890", client_id="svc@iam", client_secret="secret")

    def test_failure_reason_not_blank(self) -> None:
        from scm.exceptions import APIError

        from scm_harbourmaster_mcp.auth.oauth import get_scm_client
        from scm_harbourmaster_mcp.utils.errors import AuthenticationError

        err = APIError("Failed to create session: (invalid_client) Client authentication failed")
        assert str(err) == ""
        with (
            patch("scm_harbourmaster_mcp.auth.oauth.Scm", side_effect=err),
            pytest.raises(AuthenticationError, match="invalid_client"),
        ):
            get_scm_client(self._failing_config())

    def test_lookup_reports_stored_failure(self) -> None:
        from scm.exceptions import APIError

        from scm_harbourmaster_mcp.auth.oauth import get_client_for_tenant, get_scm_client
        from scm_harbourmaster_mcp.utils.errors import AuthenticationError

        err = APIError("Failed to create session: (invalid_client) Client authentication failed")
        with (
            patch("scm_harbourmaster_mcp.auth.oauth.Scm", side_effect=err),
            pytest.raises(AuthenticationError),
        ):
            get_scm_client(self._failing_config())
        with pytest.raises(AuthenticationError, match="invalid_client"):
            get_client_for_tenant("1234567890")

    def test_success_clears_stored_failure(self) -> None:
        import scm_harbourmaster_mcp.auth.oauth as oauth_module
        from scm_harbourmaster_mcp.auth.oauth import get_client_for_tenant, get_scm_client

        oauth_module._auth_failures["1234567890"] = "stale"
        with patch("scm_harbourmaster_mcp.auth.oauth.Scm", return_value=MagicMock()):
            client = get_scm_client(self._failing_config())
        assert get_client_for_tenant("1234567890") is client
        assert "1234567890" not in oauth_module._auth_failures
