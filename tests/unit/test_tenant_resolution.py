"""Unit tests for centralised tenant identifier resolution.

Every tool accepts the numeric TSG ID, the settings.toml ``[tenants.<key>]``
section name or the tenant ``label`` (case-insensitive, whitespace-tolerant).
Dummy tenants only.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

import scm_harbourmaster_mcp.auth.oauth as oauth
from scm_harbourmaster_mcp.config.settings import TenantConfig
from scm_harbourmaster_mcp.utils.errors import TenantNotFoundError
from scm_harbourmaster_mcp.utils.tool_decorator import (
    install_tenant_resolution,
    resolve_tenant_kwarg,
    scm_tool,
)

ACME = "1234567890"
GLOBEX = "1111111111"
INITECH = "2222222222"


def _tc(tsg: str, label: str) -> TenantConfig:
    return TenantConfig(tenant_id=tsg, client_id="svc@iam", client_secret="x", label=label)


@pytest.fixture(autouse=True)
def tenants(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, TenantConfig]]:
    """Two loaded tenants plus one configured-but-not-loaded tenant."""
    monkeypatch.setattr(oauth, "_clients", {ACME: MagicMock(name="acme"), GLOBEX: MagicMock()})
    monkeypatch.setattr(
        oauth,
        "_tenant_configs",
        {ACME: _tc(ACME, "Acme Corp"), GLOBEX: _tc(GLOBEX, "Globex")},
    )
    monkeypatch.setattr(oauth, "_tenant_keys", {})
    oauth.register_tenant_key("acme", ACME)
    oauth.register_tenant_key("globex-lab", GLOBEX)
    configured = {
        "acme": _tc(ACME, "Acme Corp"),
        "globex-lab": _tc(GLOBEX, "Globex"),
        "initech": _tc(INITECH, "Initech"),
    }
    monkeypatch.setattr(
        "scm_harbourmaster_mcp.config.settings.load_all_tenant_configs", lambda: configured
    )
    yield configured


class TestResolveTenantId:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (ACME, ACME),
            (f"  {ACME} ", ACME),
            ("acme", ACME),
            ("ACME", ACME),
            ("Acme Corp", ACME),
            ("  acme   CORP ", ACME),
            ("globex-lab", GLOBEX),
            ("globex", GLOBEX),
            ("", ""),
            ("   ", ""),
        ],
    )
    def test_accepts_every_form(self, value: str, expected: str) -> None:
        assert oauth.resolve_tenant_id(value) == expected

    def test_configured_but_not_loaded_resolves_from_settings(self) -> None:
        assert oauth.resolve_tenant_id("initech") == INITECH
        assert oauth.resolve_tenant_id("INITECH") == INITECH

    def test_section_key_beats_another_tenants_label(
        self, tenants: dict[str, TenantConfig]
    ) -> None:
        oauth._tenant_configs[GLOBEX] = _tc(GLOBEX, "acme")
        assert oauth.resolve_tenant_id("acme") == ACME

    def test_ambiguous_label_lists_candidates(self) -> None:
        oauth._tenant_configs[GLOBEX] = _tc(GLOBEX, "Acme Corp")
        with pytest.raises(TenantNotFoundError) as exc_info:
            oauth.resolve_tenant_id("acme corp")
        msg = str(exc_info.value)
        assert "ambiguous" in msg
        assert ACME in msg and GLOBEX in msg

    def test_unknown_passes_through_when_not_strict(self) -> None:
        assert oauth.resolve_tenant_id("nope") == "nope"

    def test_unknown_strict_lists_valid_tenants(self) -> None:
        with pytest.raises(TenantNotFoundError) as exc_info:
            oauth.resolve_tenant_id("nope", strict=True)
        msg = str(exc_info.value)
        assert "acme / Acme Corp" in msg and "initech" in msg and INITECH in msg

    def test_unknown_numeric_passes_through_even_when_strict(self) -> None:
        assert oauth.resolve_tenant_id("9999999999", strict=True) == "9999999999"


class TestClientLookup:
    def test_get_client_for_tenant_by_label(self) -> None:
        assert oauth.get_client_for_tenant("acme corp") is oauth._clients[ACME]
        assert oauth.get_client_for_tenant("Globex-Lab") is oauth._clients[GLOBEX]

    def test_get_client_for_unknown_lists_labels(self) -> None:
        with pytest.raises(TenantNotFoundError, match="Valid tenants:.*acme"):
            oauth.get_client_for_tenant("umbrella")

    def test_get_client_for_configured_but_unloaded_tenant(self) -> None:
        with pytest.raises(TenantNotFoundError, match="not yet loaded"):
            oauth.get_client_for_tenant("initech")

    def test_get_tenant_meta_by_key_and_ambiguous_is_none(self) -> None:
        meta = oauth.get_tenant_meta("ACME")
        assert meta is not None and meta.tenant_id == ACME
        oauth._tenant_configs[GLOBEX] = _tc(GLOBEX, "Acme Corp")
        assert oauth.get_tenant_meta("acme corp") is None

    def test_find_tenant_config_falls_back_to_settings(self) -> None:
        cfg = oauth.find_tenant_config("Initech")
        assert cfg is not None and cfg.tenant_id == INITECH
        assert oauth.find_tenant_config("") is None


class TestToolDecorators:
    def test_scm_tool_hands_canonical_tsg_to_body(self) -> None:
        seen: list[str] = []
        mcp = FastMCP("t")
        tool = scm_tool(lambda tid: seen.append(tid) or "client")

        @mcp.tool()
        @tool
        def scm_x(client: Any, tenant_id: str) -> str:
            return tenant_id

        fn = mcp._tool_manager.get_tool("scm_x").fn
        assert fn(tenant_id=" Acme Corp ") == ACME
        assert seen == [ACME]

    def test_scm_tool_ambiguous_returns_error_string(self) -> None:
        oauth._tenant_configs[GLOBEX] = _tc(GLOBEX, "Acme Corp")
        mcp = FastMCP("t")

        @mcp.tool()
        @scm_tool(lambda tid: "client")
        def scm_y(client: Any) -> str:
            return "ran"

        out = mcp._tool_manager.get_tool("scm_y").fn(tenant_id="acme corp")
        assert out.startswith("Error:") and "ambiguous" in out

    def test_install_tenant_resolution_wraps_raw_tools(self) -> None:
        mcp = FastMCP("t")

        @mcp.tool()
        def raw_tool(tenant_id: str = "", folder: str = "Shared") -> str:
            return f"{tenant_id}|{folder}"

        @mcp.tool()
        async def raw_async(tenant_id: str = "") -> str:
            return tenant_id

        @mcp.tool()
        def no_tenant(folder: str = "") -> str:
            return folder

        before_no_tenant = mcp._tool_manager.get_tool("no_tenant").fn
        assert install_tenant_resolution(mcp) == 2
        assert install_tenant_resolution(mcp) == 0  # idempotent
        assert mcp._tool_manager.get_tool("no_tenant").fn is before_no_tenant
        assert mcp._tool_manager.get_tool("raw_tool").fn(tenant_id="globex", folder="F") == (
            f"{GLOBEX}|F"
        )

    @pytest.mark.anyio
    async def test_install_preserves_async_and_schema(self) -> None:
        mcp = FastMCP("t")

        @mcp.tool()
        async def raw_async(tenant_id: str = "") -> str:
            return tenant_id

        install_tenant_resolution(mcp)
        tool = mcp._tool_manager.get_tool("raw_async")
        assert "tenant_id" in tool.parameters["properties"]
        result = await tool.run({"tenant_id": "INITECH"})
        assert result == INITECH

    def test_resolve_tenant_kwarg_error_string_on_ambiguity(self) -> None:
        oauth._tenant_configs[GLOBEX] = _tc(GLOBEX, "Acme Corp")

        def raw(tenant_id: str = "") -> str:
            return "ran"

        out = resolve_tenant_kwarg(raw)(tenant_id="acme corp")
        assert out.startswith("Error:") and "ambiguous" in out


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
