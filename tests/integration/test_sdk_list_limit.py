"""pan-scm-sdk ``.list()`` silently swallows unknown kwargs such as ``limit=``.

Every resource ``list()`` takes ``**filters``, so ``limit=2`` raises nothing
and never reaches the wire — the SDK pages with its own max_limit and returns
everything. Tools must fetch and then slice. The first test pins the SDK
behaviour itself so an SDK upgrade that changes it is noticed.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest
import responses

from scm_harbourmaster_mcp.tools.objects import register_object_tools

from .conftest import FAKE_TSG_ID

pytestmark = pytest.mark.integration


def test_sdk_list_ignores_limit_kwarg(
    cassette: Callable[[str], Any], http: responses.RequestsMock, scm_client: Any
) -> None:
    cassette("sdk_address_list")
    results = scm_client.address.list(folder="Shared", limit=2)

    assert len(results) == 5, "SDK now honours limit= — revisit the slicing in the tools"
    sent = http.calls[0].request.params
    assert sent["limit"] != "2"  # the SDK's own page size went out instead


@pytest.mark.parametrize(("limit", "expected"), [(2, 2), (200, 5), (0, 0)])
def test_address_list_tool_slices_client_side(
    cassette: Callable[[str], Any],
    http: responses.RequestsMock,
    scm_client: Any,
    invoke_tool: Callable[..., str],
    limit: int,
    expected: int,
) -> None:
    cassette("sdk_address_list")
    out = invoke_tool(
        register_object_tools,
        "scm_address_list",
        scm_client,
        tenant_id=FAKE_TSG_ID,
        folder="Shared",
        limit=limit,
    )

    assert not out.startswith("Error"), out
    rows = json.loads(out)
    assert len(rows) == expected
    assert [r["name"] for r in rows] == [f"example-host-{n}" for n in range(1, expected + 1)]
    assert len(http.calls) == 1
