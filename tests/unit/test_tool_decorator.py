"""Unit tests for the shared `@scm_tool` decorator (tenant resolution +
exception normalization) used by MCP tool modules — see retrospective item
#1 (utils/tool_decorator.py)."""

from __future__ import annotations

from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.utils.tool_decorator import scm_tool


def _register(mcp: FastMCP, get_client: Any) -> None:
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_thing_get(client: Any, name: str, limit: int = 10) -> str:
        """Fetch a thing.

        Args:
            name: Thing name.
            tenant_id: SCM tenant ID.
            limit: Maximum results.
        """
        return f"client={client!r} name={name} limit={limit}"

    @mcp.tool()
    @tool
    def scm_thing_break(client: Any) -> str:
        """Always raises."""
        raise ValueError("nope")

    @mcp.tool()
    @tool
    def scm_thing_report(client: Any, tenant_id: str, folder: str = "Shared") -> str:
        """Report needing the resolved tenant_id for display, not just client."""
        return f"tenant={tenant_id or 'default'} folder={folder} client={client!r}"


def _mcp_with_tools(get_client: Any) -> FastMCP:
    mcp = FastMCP("test")
    _register(mcp, get_client)
    return mcp


def test_client_is_hidden_from_the_exposed_schema() -> None:
    mcp = _mcp_with_tools(lambda tenant_id="": "fake-client")
    props = mcp._tool_manager.get_tool("scm_thing_get").parameters["properties"]
    assert "client" not in props
    assert "tenant_id" in props
    assert props["tenant_id"]["default"] == ""
    assert "name" in props and "limit" in props


def test_required_and_optional_params_preserved() -> None:
    mcp = _mcp_with_tools(lambda tenant_id="": "fake-client")
    schema = mcp._tool_manager.get_tool("scm_thing_get").parameters
    assert schema["required"] == ["name"]
    assert schema["properties"]["limit"]["default"] == 10


def test_tenant_id_is_resolved_into_client() -> None:
    seen: list[str] = []

    def get_client(tenant_id: str = "") -> str:
        seen.append(tenant_id)
        return f"client-for-{tenant_id or 'default'}"

    mcp = _mcp_with_tools(get_client)
    out = mcp._tool_manager.get_tool("scm_thing_get").fn(tenant_id="acme", name="x")
    assert seen == ["acme"]
    assert "client-for-acme" in out
    assert "name=x" in out
    assert "limit=10" in out  # default applied


def test_tenant_id_defaults_to_empty_string_when_omitted() -> None:
    seen: list[str] = []

    def get_client(tenant_id: str = "") -> str:
        seen.append(tenant_id)
        return "client"

    mcp = _mcp_with_tools(get_client)
    mcp._tool_manager.get_tool("scm_thing_get").fn(name="x")
    assert seen == [""]


def test_exceptions_are_normalized_not_raised() -> None:
    mcp = _mcp_with_tools(lambda tenant_id="": "fake-client")
    out = mcp._tool_manager.get_tool("scm_thing_break").fn(tenant_id="acme")
    assert out == "Error: [ValueError] nope"


def test_get_client_failure_is_also_normalized() -> None:
    def broken_get_client(tenant_id: str = "") -> Any:
        raise RuntimeError("tenant not found")

    mcp = _mcp_with_tools(broken_get_client)
    out = mcp._tool_manager.get_tool("scm_thing_get").fn(tenant_id="acme", name="x")
    assert out == "Error: [RuntimeError] tenant not found"


def test_optional_tenant_id_passthrough() -> None:
    mcp = _mcp_with_tools(lambda tenant_id="": "fake-client")
    tool_obj = mcp._tool_manager.get_tool("scm_thing_report")

    # Still exposes exactly one tenant_id param — not duplicated in the schema.
    props = tool_obj.parameters["properties"]
    assert "tenant_id" in props
    assert props["tenant_id"]["default"] == ""
    assert "client" not in props

    out = tool_obj.fn(tenant_id="acme", folder="X")
    assert out == "tenant=acme folder=X client='fake-client'"

    out_default = tool_obj.fn(folder="X")
    assert out_default == "tenant=default folder=X client='fake-client'"


def test_missing_required_argument_degrades_instead_of_raising() -> None:
    """A tool must always return a string, never propagate a raw TypeError.

    Argument binding happens inside the decorator's try/except for this
    reason — found by live tenant testing, where a missing required arg
    escaped as an unhandled TypeError instead of an "Error: ..." string.
    """
    mcp = _mcp_with_tools(lambda tenant_id="": "fake-client")
    out = mcp._tool_manager.get_tool("scm_thing_get").fn(tenant_id="acme")  # no `name`
    assert isinstance(out, str)
    assert out.startswith("Error: [TypeError]")
    assert "name" in out


def test_unexpected_argument_degrades_instead_of_raising() -> None:
    mcp = _mcp_with_tools(lambda tenant_id="": "fake-client")
    out = mcp._tool_manager.get_tool("scm_thing_get").fn(tenant_id="acme", name="x", bogus_param=1)
    assert isinstance(out, str)
    assert out.startswith("Error: [TypeError]")


def test_decorator_requires_client_as_first_parameter() -> None:
    tool = scm_tool(lambda tenant_id="": None)

    with pytest.raises(TypeError, match="must take `client` as its first parameter"):

        @tool
        def scm_bad_tool(name: str) -> str:  # missing `client` first param
            return name
