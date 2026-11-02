"""Unit tests for the ADNSR / NGFW Operations tools' token handling."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.tools.adnsr import register_adnsr_tools


def _tool(name: str, client: Any) -> Any:
    mcp = FastMCP("test-adnsr")
    register_adnsr_tools(mcp, lambda tenant_id="": client)
    return mcp._tool_manager.get_tool(name).fn  # noqa: SLF001


def _client() -> MagicMock:
    client = MagicMock()
    client.session.get.return_value = MagicMock(
        status_code=200, json=MagicMock(return_value={"data": []})
    )
    return client


class TestTokenRefresh:
    """Direct session calls bypass the SDK's own refresh, so a long-lived
    server hit TokenExpiredError on these tools until something else refreshed."""

    def test_list_refreshes_before_request(self) -> None:
        client = _client()
        order: list[str] = []
        client.oauth_client.refresh_token.side_effect = lambda: order.append("refresh")
        client.session.get.side_effect = lambda *a, **k: (
            order.append("get"),
            client.session.get.return_value,
        )[1]
        _tool("scm_adnsr_list", client)(resource="profiles")
        assert order == ["refresh", "get"]

    def test_profile_create_refreshes(self) -> None:
        client = _client()
        client.session.post.return_value = MagicMock(
            status_code=201, json=MagicMock(return_value={"id": "p-1"})
        )
        _tool("scm_adnsr_profile_create", client)(
            name="dns-prof", dry_run=False, ticket_ref="CHG-1"
        )
        client.oauth_client.refresh_token.assert_called()

    def test_ngfw_local_config_list_refreshes(self) -> None:
        client = _client()
        _tool("scm_ngfw_local_config_list", client)(serial="0123456789")
        client.oauth_client.refresh_token.assert_called()

    def test_refresh_failure_does_not_block_request(self) -> None:
        client = _client()
        client.oauth_client.refresh_token.side_effect = RuntimeError("auth down")
        _tool("scm_adnsr_list", client)(resource="profiles")
        client.session.get.assert_called_once()
