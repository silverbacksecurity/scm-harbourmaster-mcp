"""Email DLP: a 400 "Can't find tenant name with tsgId=..." means not onboarded.

It is a provisioning gate like 401/403/404, so the tool reports an empty,
explained result. A genuinely malformed request is still a 400 and must keep
surfacing as an error, with the API's body intact.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest
import responses

from scm_harbourmaster_mcp.tools.email_dlp import register_email_dlp_tools

from .conftest import FAKE_TOKEN, FAKE_TSG_ID

pytestmark = pytest.mark.integration


def _list(invoke_tool: Callable[..., str], client: Any, **kwargs: Any) -> dict[str, Any]:
    out = invoke_tool(
        register_email_dlp_tools,
        "scm_email_dlp_incidents",
        client,
        tenant_id=FAKE_TSG_ID,
        **kwargs,
    )
    parsed: dict[str, Any] = json.loads(out)
    return parsed


def test_unprovisioned_tenant_is_reported_gracefully(
    cassette: Callable[[str], Any],
    http: responses.RequestsMock,
    scm_client: Any,
    invoke_tool: Callable[..., str],
) -> None:
    cassette("email_dlp_unprovisioned")
    out = _list(invoke_tool, scm_client)

    assert "error" not in out, out
    assert out["incidents"] == []
    assert out["total"] == 0
    assert "not onboarded" in out["hint"]
    # The bearer token from the SDK session reached the Email DLP host.
    assert http.calls[0].request.headers["Authorization"] == f"Bearer {FAKE_TOKEN}"


def test_real_bad_request_still_surfaces_with_body(
    cassette: Callable[[str], Any],
    scm_client: Any,
    invoke_tool: Callable[..., str],
) -> None:
    cassette("email_dlp_bad_request")
    out = _list(invoke_tool, scm_client, status="bogus")

    assert out["error"] == "email_dlp_api_error"
    assert out["status_code"] == 400
    assert "Invalid parameter status" in out["detail"]
