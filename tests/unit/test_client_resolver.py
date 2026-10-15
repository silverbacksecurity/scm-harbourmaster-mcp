"""The server's tenant → client resolver (server._build_client_resolver)."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from scm_harbourmaster_mcp import server
from scm_harbourmaster_mcp.utils.errors import TenantNotFoundError, handle_scm_exception


def _settings(mssp: bool, tenant_id: str = "") -> SimpleNamespace:
    return SimpleNamespace(
        mssp_mode=mssp,
        scm_tenant_id=tenant_id,
        default_tenant=lambda: SimpleNamespace(tenant_id=tenant_id),
    )


@pytest.mark.parametrize("mssp", [True, False])
def test_no_tenant_and_no_default_names_the_valid_tenants(mssp: bool) -> None:
    resolve = server._build_client_resolver(_settings(mssp))
    with (
        patch("scm_harbourmaster_mcp.auth.oauth._known_tenants", return_value={}),
        pytest.raises(TenantNotFoundError) as err,
    ):
        resolve("")
    assert "No tenant_id given" in str(err.value) and "Valid tenants" in str(err.value)
    # Tools render it as a readable error, not a pydantic TenantConfig failure
    assert handle_scm_exception(err.value).startswith("[TenantNotFoundError] No tenant_id given")


def test_default_tenant_still_used_when_configured() -> None:
    resolve = server._build_client_resolver(_settings(True, tenant_id="1234567890"))
    with patch.object(server, "get_scm_client", side_effect=lambda cfg: f"client-{cfg.tenant_id}"):
        assert resolve("") == "client-1234567890"


def test_named_tenant_in_mssp_mode_uses_the_tenant_cache() -> None:
    resolve = server._build_client_resolver(_settings(True))
    with patch("scm_harbourmaster_mcp.auth.oauth.get_client_for_tenant", return_value="c") as get:
        assert resolve("acme") == "c"
    get.assert_called_once_with("acme")
