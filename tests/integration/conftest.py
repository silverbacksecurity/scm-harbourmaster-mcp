"""Fixtures for the offline recorded-response integration suite.

These tests drive registered FastMCP tools end-to-end through the real
``requests`` stack with the HTTP layer replaced by cassettes (see
``_cassette.py``). They need no credentials and make no network calls, so
they run in the default ``uv run pytest``; select or skip them with
``-m integration`` / ``-m "not integration"``.

Every identifier in a cassette is a placeholder: the TSG ID is always
``1234567890``, hosts are the public SCM API hosts, and any address is from
the RFC 5737 documentation ranges.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

import pytest
import responses
from mcp.server.fastmcp import FastMCP

from ._cassette import register_cassette

FAKE_TSG_ID = "1234567890"
FAKE_TOKEN = "integration-test-token"  # noqa: S105 - placeholder, not a credential


def make_scm_client(token: str = FAKE_TOKEN) -> Any:
    """A real pan-scm-sdk ``Scm`` client that never authenticates.

    Bearer-token mode builds a plain ``requests.Session`` with no token fetch.
    ``session.token`` is set to mirror the OAuth2Session the server uses in
    production, which the raw-REST helpers read to build their own sessions.
    """
    from scm.client import Scm

    client = Scm(access_token=token)
    client.session.token = {"access_token": token}  # type: ignore[attr-defined]
    return client


@pytest.fixture
def http() -> Iterator[responses.RequestsMock]:
    """Intercept all ``requests`` traffic; unmatched requests raise."""
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        yield rsps


@pytest.fixture
def cassette(http: responses.RequestsMock) -> Callable[[str], dict[str, Any]]:
    """Load and register a cassette by name: ``cassette("tls_profiles_sse_base")``."""
    return lambda name: register_cassette(http, name)


@pytest.fixture
def scm_client() -> Any:
    return make_scm_client()


@pytest.fixture
def invoke_tool() -> Callable[..., str]:
    """Register a tool module on a throwaway FastMCP and call one tool by name.

    ``invoke_tool(register_ops_tools, "scm_cert_scan", client, folder="Shared")``
    goes through the same ``mcp._tool_manager`` entry FastMCP dispatches to,
    so the ``@scm_tool`` wrapper (tenant resolution + error normalisation) runs.
    """

    def _invoke(register: Callable[..., None], name: str, client: Any, /, **kwargs: Any) -> str:
        mcp = FastMCP("integration")
        register(mcp, lambda _tenant_id="": client)
        tool = mcp._tool_manager.get_tool(name)
        assert tool is not None, f"tool {name} is not registered"
        result: str = tool.fn(**kwargs)
        return result

    return _invoke


@pytest.fixture(autouse=True)
def _reset_compliance_region_cache() -> Iterator[None]:
    """The compliance region is cached per process — isolate scenarios."""
    from scm_harbourmaster_mcp.tools.compliance import _reset_region_cache

    _reset_region_cache()
    yield
    _reset_region_cache()
