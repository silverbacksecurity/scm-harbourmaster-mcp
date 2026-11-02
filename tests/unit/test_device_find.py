"""Unit tests for scm_device_find (cross-tenant device search by serial/name)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.config.settings import TenantConfig
from scm_harbourmaster_mcp.tools.setup import register_setup_tools

_MOD = "scm_harbourmaster_mcp.tools.setup"


def _tool(get_client: Any = None) -> Any:
    mcp = FastMCP("test-device-find")
    register_setup_tools(mcp, get_client or (lambda tenant_id="": MagicMock()))
    return mcp._tool_manager.get_tool("scm_device_find").fn  # noqa: SLF001


def _device(serial: str, name: str, **extra: Any) -> SimpleNamespace:
    fields = {
        "serial_number": serial,
        "id": serial,
        "name": name,
        "display_name": None,
        "hostname": None,
        "model": "PA-440",
        "folder": "ngfw-shared",
        "is_connected": True,
        "software_version": "12.2.0",
    }
    fields.update(extra)
    return SimpleNamespace(**fields)


def _tenant(key: str, tsg: str) -> TenantConfig:
    return TenantConfig(tenant_id=tsg, client_id=f"{key}@iam", client_secret="secret", label=key)


def _client(*devices: Any) -> MagicMock:
    client = MagicMock()
    client.device.list.return_value = list(devices)
    return client


class TestDeviceFind:
    def test_finds_serial_in_one_of_several_tenants(self) -> None:
        tenants = {"lab-a": _tenant("lab-a", "1000000001"), "lab-b": _tenant("lab-b", "1000000002")}
        clients = {
            "1000000001": _client(_device("011111111111", "fw-other")),
            "1000000002": _client(_device("012345678901", "branch-fw")),
        }
        with (
            patch(f"{_MOD}.load_all_tenant_configs", return_value=tenants),
            patch(f"{_MOD}.get_scm_client", side_effect=lambda tc: clients[tc.tenant_id]),
        ):
            out = _tool()(query="012345678901")
        assert "1 match(es)** across 2 tenant(s)" in out
        assert "lab-b (1000000002)" in out
        assert "branch-fw" in out
        assert "fw-other" not in out

    def test_matches_name_case_insensitively(self) -> None:
        tenants = {"lab-a": _tenant("lab-a", "1000000001")}
        client = _client(_device("011111111111", "Branch-FW-01", folder="Branches"))
        with (
            patch(f"{_MOD}.load_all_tenant_configs", return_value=tenants),
            patch(f"{_MOD}.get_scm_client", return_value=client),
        ):
            out = _tool()(query="branch-fw")
        assert "Branch-FW-01" in out
        assert "Branches" in out

    def test_no_match_gives_onboarding_hint(self) -> None:
        tenants = {"lab-a": _tenant("lab-a", "1000000001")}
        with (
            patch(f"{_MOD}.load_all_tenant_configs", return_value=tenants),
            patch(f"{_MOD}.get_scm_client", return_value=_client()),
        ):
            out = _tool()(query="012345678901")
        assert "No device matching" in out
        assert "device association" in out

    def test_failed_tenants_listed_not_fatal(self) -> None:
        tenants = {
            "good": _tenant("good", "1000000001"),
            "no-auth": _tenant("no-auth", "1000000002"),
            "no-config": _tenant("no-config", "1000000003"),
        }
        broken = MagicMock()
        broken.device.list.side_effect = RuntimeError("Tenant Id not found")

        def client_for(tc: TenantConfig) -> Any:
            if tc.tenant_id == "1000000002":
                raise RuntimeError("invalid_client")
            if tc.tenant_id == "1000000003":
                return broken
            return _client(_device("012345678901", "fw"))

        with (
            patch(f"{_MOD}.load_all_tenant_configs", return_value=tenants),
            patch(f"{_MOD}.get_scm_client", side_effect=client_for),
        ):
            out = _tool()(query="012345678901")
        assert "1 match(es)** across 1 tenant(s)" in out
        assert "Not searched (2)" in out
        assert "invalid_client" in out
        assert "Tenant Id not found" in out

    def test_single_tenant_mode_uses_get_client(self) -> None:
        client = _client(_device("012345678901", "fw"))
        out = _tool(lambda tenant_id="": client)(
            query="012345678901", tenant_id="1000000001", all_tenants=False
        )
        assert "1 match(es)" in out

    def test_rejects_short_query(self) -> None:
        assert _tool()(query="02").startswith("Error:")
