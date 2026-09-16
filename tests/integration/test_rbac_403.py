"""403 RBAC responses must degrade to a per-tenant note, never abort a report.

MSSP service accounts are often scoped (view-only admin and similar), so one
tenant answering 403 on an endpoint is routine. A cross-tenant dashboard must
still render every other tenant, and a single-tenant report must explain the
denial rather than return a raw HTTP error.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
import responses

from scm_harbourmaster_mcp.config.settings import TenantConfig
from scm_harbourmaster_mcp.tools import posture as posture_mod
from scm_harbourmaster_mcp.tools.posture import register_posture_tools

from .conftest import FAKE_TSG_ID, make_scm_client

pytestmark = pytest.mark.integration

_TOKENS = {"Tenant Permitted": "token-permitted", "Tenant View-Only": "token-view-only"}


def _tenant(label: str) -> TenantConfig:
    return TenantConfig(
        tenant_id=FAKE_TSG_ID, client_id="placeholder-client", client_secret="x", label=label
    )


@pytest.fixture
def two_tenants(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two configured tenants whose clients authenticate with distinct fake tokens."""
    monkeypatch.setattr(
        posture_mod,
        "_load_tenant_configs",
        lambda: {
            "permitted": _tenant("Tenant Permitted"),
            "view-only": _tenant("Tenant View-Only"),
        },
    )
    monkeypatch.setattr(
        posture_mod, "get_scm_client", lambda tc: make_scm_client(_TOKENS[tc.label])
    )


def test_cross_tenant_incident_summary_survives_one_403(
    cassette: Callable[[str], Any],
    http: responses.RequestsMock,
    two_tenants: None,
    invoke_tool: Callable[..., str],
) -> None:
    cassette("rbac_403")
    out = invoke_tool(register_posture_tools, "scm_incident_summary", None, all_tenants=True)

    assert not out.startswith("Error"), out
    rows = {
        label: line
        for line in out.splitlines()
        for label in _TOKENS
        if line.startswith(f"| {label} |")
    }
    assert set(rows) == {"Tenant Permitted", "Tenant View-Only"}
    # The permitted tenant is fully rendered: 1 critical, 1 high, 1 low.
    assert "| **1** | **1** | 0 | 1 | 3 | Example critical incident |" in rows["Tenant Permitted"]
    # The denied tenant becomes an error row that names the cause.
    assert "403" in rows["Tenant View-Only"]
    assert "Error" in rows["Tenant View-Only"]
    assert len(http.calls) == 2


def test_posture_report_403_returns_explanation(
    cassette: Callable[[str], Any],
    invoke_tool: Callable[..., str],
) -> None:
    cassette("rbac_403")
    client = make_scm_client("token-view-only")
    out = invoke_tool(register_posture_tools, "scm_posture_report", client, tenant_id=FAKE_TSG_ID)

    assert not out.startswith("Error"), out
    assert "Access denied: insufficient role" in out
    assert "Posture Management" in out
