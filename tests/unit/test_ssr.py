"""Tests for SSR — Simple Service Requests (scm_ssr_execute).

Covers:
  - All four operations in dry-run mode
  - Idempotency (already_present / already_absent)
  - Validation (missing ticket_ref, invalid operation, bad target)
  - Missing SSR config
  - Execute path with mocked SDK
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

from scm_harbourmaster_mcp.tools.ssr import _validate_target, register_ssr_tools

# ---------------------------------------------------------------------------
# Canned SDK response data
# ---------------------------------------------------------------------------

_URL_CATEGORY = {
    "id": "abcd1234-abcd-1234-abcd-123456789abc",
    "name": "SSR-Allow-List",
    "list": ["example.com", "test.org"],
    "description": "SSR managed",
    "type": "URL List",
    "folder": "Shared",
}

_ANTI_SPYWARE_PROFILE = {
    "id": "efgh5678-efgh-5678-efgh-567890abcdef",
    "name": "SSR-AntiSpyware",
    "description": "SSR managed",
    "threat_exception": [
        {"name": "12345", "action": {"allow": {}}, "packet_capture": "disable"},
    ],
    "folder": "Shared",
}

_VULN_PROFILE = {
    "id": "ijkl9012-ijkl-9012-ijkl-901234ghijkl",
    "name": "SSR-VulnProtection",
    "description": "SSR managed",
    "threat_exception": [],
    "folder": "Shared",
}

_DECRYPT_RULE = {
    "id": "mnop3456-mnop-3456-mnop-345678mnopqr",
    "name": "SSR-Decrypt-Exclude",
    "description": "SSR managed",
    "category": ["Business-Apps"],
    "action": "no_decrypt",
    "folder": "Shared",
}


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------


class MockSDKResource:
    """Simulates a pan-scm-sdk resource (e.g. client.url_category)."""

    def __init__(self, fetch_data: dict[str, Any], resource_name: str = "") -> None:
        self._fetch_data = fetch_data
        self._resource_name = resource_name or "mock_resource"
        self._update_calls: list[dict[str, Any]] = []

    def fetch(self, name: str = "", folder: str = "") -> MagicMock:  # noqa: ARG002
        obj = MagicMock()
        obj.model_dump.return_value = dict(self._fetch_data)
        return obj

    def update(self, data: dict[str, Any]) -> None:
        self._update_calls.append(data)


def _make_mock_client(
    url_cat_data: dict[str, Any] | None = None,
    asp_data: dict[str, Any] | None = None,
    vp_data: dict[str, Any] | None = None,
    decrypt_data: dict[str, Any] | None = None,
    ssr_objects: dict[str, str] | None = None,
    default_folder: str = "Shared",
) -> Any:
    """Build a mock SCM client with SSR-managed objects."""
    client = MagicMock()
    client.url_category = MockSDKResource(url_cat_data or _URL_CATEGORY, "url_category")
    client.anti_spyware_profile = MockSDKResource(asp_data or _ANTI_SPYWARE_PROFILE, "asp")
    client.vulnerability_protection_profile = MockSDKResource(vp_data or _VULN_PROFILE, "vp")
    client.decryption_rule = MockSDKResource(decrypt_data or _DECRYPT_RULE, "decrypt")

    # Inject SSR config
    client._ssr_objects = ssr_objects or {
        "url_allow_list": "SSR-Allow-List",
        "url_block_list": "SSR-Block-List",
        "anti_spyware_profile": "SSR-AntiSpyware",
        "vulnerability_protection_profile": "SSR-VulnProtection",
        "ssl_decrypt_exclude_rule": "SSR-Decrypt-Exclude",
    }
    client._default_folder = default_folder

    return client


def _get_client_fn(mock_client: Any, monkeypatch: Any) -> Any:
    """Return a `get_client` callable that returns *mock_client* and patch config."""

    def get_client(_tenant_id: str = "") -> Any:
        return mock_client

    # Patch config loading
    monkeypatch.setattr(
        "scm_harbourmaster_mcp.tools.ssr._get_ssr_config",
        lambda _tid: mock_client._ssr_objects,
    )
    monkeypatch.setattr(
        "scm_harbourmaster_mcp.tools.ssr._resolve_default_folder",
        lambda _tid: mock_client._default_folder,
    )
    return get_client


def _invoke(
    monkeypatch: Any,
    mock_client: Any,
    **kwargs: Any,
) -> dict[str, Any]:
    """Invoke scm_ssr_execute and parse the JSON result."""
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("test-ssr")
    get_client = _get_client_fn(mock_client, monkeypatch)
    register_ssr_tools(mcp, get_client)
    tool = mcp._tool_manager.get_tool("scm_ssr_execute")
    result = tool.fn(**kwargs)
    return json.loads(result)


# ---------------------------------------------------------------------------
# Tests — validation
# ---------------------------------------------------------------------------


def test_missing_ticket_ref_errors(monkeypatch: Any) -> None:
    client = _make_mock_client()
    result = _invoke(
        monkeypatch, client, operation="url-allow-list", target="example.com", ticket_ref=""
    )
    assert result["status"] == "error"
    assert "ticket_ref" in result["error"].lower()


def test_invalid_operation_errors(monkeypatch: Any) -> None:
    client = _make_mock_client()
    result = _invoke(monkeypatch, client, operation="bogus", target="x", ticket_ref="INC-1")
    assert result["status"] == "error"
    assert "bogus" in result["error"]


def test_invalid_action_errors(monkeypatch: Any) -> None:
    client = _make_mock_client()
    result = _invoke(
        monkeypatch,
        client,
        operation="url-allow-list",
        target="x",
        ticket_ref="INC-1",
        action="toggle",
    )
    assert result["status"] == "error"
    assert "toggle" in result["error"]


def test_bad_url_target_errors(monkeypatch: Any) -> None:
    client = _make_mock_client()
    result = _invoke(
        monkeypatch, client, operation="url-allow-list", target="*", ticket_ref="INC-1"
    )
    assert result["status"] == "error"
    assert "wildcard" in result["error"].lower()


def test_bad_threat_id_errors(monkeypatch: Any) -> None:
    client = _make_mock_client()
    result = _invoke(
        monkeypatch, client, operation="threat-exception", target="abc", ticket_ref="INC-1"
    )
    assert result["status"] == "error"
    assert "threat" in result["error"].lower()


def test_missing_ssr_config_errors() -> None:
    """When ssr_objects is empty, the tool should error.

    Uses the _invoke helper directly with an empty ssr_objects config —
    the monkeypatch inside _invoke wires _get_ssr_config to return the
    empty dict from the mock client.
    """
    client = _make_mock_client(ssr_objects={})
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("test-ssr-empty")

    # Don't use _invoke — manually set up with empty config and NO _get_ssr_config override
    def get_client(_tid: str = "") -> Any:
        return client

    # Patch load_all_tenant_configs to return empty so _get_ssr_config returns {}
    import scm_harbourmaster_mcp.tools.ssr as ssr_mod

    original = ssr_mod.load_all_tenant_configs
    ssr_mod.load_all_tenant_configs = lambda: {}  # type: ignore[assignment]

    try:
        register_ssr_tools(mcp, get_client)
        tool = mcp._tool_manager.get_tool("scm_ssr_execute")
        result = json.loads(
            tool.fn(operation="url-allow-list", target="example.com", ticket_ref="INC-1")
        )
    finally:
        ssr_mod.load_all_tenant_configs = original  # type: ignore[assignment]

    assert result["status"] == "error"
    assert "ssr_objects" in result["error"].lower()


# ---------------------------------------------------------------------------
# Tests — URL allow-list (dry-run)
# ---------------------------------------------------------------------------


def test_url_allow_add_dry_run(monkeypatch: Any) -> None:
    client = _make_mock_client()
    result = _invoke(
        monkeypatch, client, operation="url-allow-list", target="newsite.com", ticket_ref="INC-42"
    )
    assert result["status"] == "planned"
    assert result["dry_run"] is True
    assert result["commit_required"] is True
    assert "newsite.com" in json.dumps(result["after"])
    assert "newsite.com" not in json.dumps(result["before"]["list"])


def test_url_allow_add_idempotent(monkeypatch: Any) -> None:
    """Re-adding an existing URL returns already_present."""
    client = _make_mock_client()
    result = _invoke(
        monkeypatch, client, operation="url-allow-list", target="example.com", ticket_ref="INC-42"
    )
    assert result["already_present"] is True
    assert result["before"] == result["after"]


def test_url_allow_remove_idempotent(monkeypatch: Any) -> None:
    """Removing a non-existent URL returns already_absent."""
    client = _make_mock_client()
    result = _invoke(
        monkeypatch,
        client,
        operation="url-allow-list",
        target="nonexistent.com",
        ticket_ref="INC-42",
        action="remove",
    )
    assert result["already_absent"] is True


def test_url_block_list_add(monkeypatch: Any) -> None:
    client = _make_mock_client()
    result = _invoke(
        monkeypatch, client, operation="url-block-list", target="badsite.net", ticket_ref="INC-7"
    )
    assert result["status"] == "planned"
    assert "badsite.net" in json.dumps(result["after"])


# ---------------------------------------------------------------------------
# Tests — threat exception (dry-run)
# ---------------------------------------------------------------------------


def test_threat_add_dry_run(monkeypatch: Any) -> None:
    client = _make_mock_client()
    result = _invoke(
        monkeypatch, client, operation="threat-exception", target="67890", ticket_ref="INC-99"
    )
    assert result["status"] == "planned"
    assert "profiles" in result
    assert "SSR-AntiSpyware" in result["profiles"]


def test_threat_add_idempotent(monkeypatch: Any) -> None:
    """Re-adding an existing threat exception is per-profile idempotent.

    The anti-spyware profile already has threat 12345 in its threat_exception list;
    the vulnerability profile has an empty list.  ``already_present`` is ``all()``
    across profiles, so it is only True when BOTH profiles already have it.
    """
    client = _make_mock_client()
    result = _invoke(
        monkeypatch, client, operation="threat-exception", target="12345", ticket_ref="INC-99"
    )
    # Per-profile check: anti-spyware already has it
    asp_result = result["profiles"]["SSR-AntiSpyware"]
    assert asp_result["already_present"] is True
    # Overall flag is all() — vuln profile doesn't have it, so it's False
    assert result["already_present"] is False


def test_threat_remove(monkeypatch: Any) -> None:
    client = _make_mock_client()
    result = _invoke(
        monkeypatch,
        client,
        operation="threat-exception",
        target="12345",
        ticket_ref="INC-99",
        action="remove",
    )
    assert result["status"] == "planned"


# ---------------------------------------------------------------------------
# Tests — SSL decrypt exclude (dry-run)
# ---------------------------------------------------------------------------


def test_ssl_decrypt_add_dry_run(monkeypatch: Any) -> None:
    client = _make_mock_client()
    result = _invoke(
        monkeypatch,
        client,
        operation="ssl-decrypt-exclude",
        target="Streaming-Media",
        ticket_ref="INC-3",
    )
    assert result["status"] == "planned"
    assert result["commit_required"] is True
    assert "Streaming-Media" in json.dumps(result["after"])


def test_ssl_decrypt_add_idempotent(monkeypatch: Any) -> None:
    client = _make_mock_client()
    result = _invoke(
        monkeypatch,
        client,
        operation="ssl-decrypt-exclude",
        target="Business-Apps",
        ticket_ref="INC-3",
    )
    assert result["already_present"] is True


# ---------------------------------------------------------------------------
# Tests — execute path
# ---------------------------------------------------------------------------


def test_url_allow_execute(monkeypatch: Any) -> None:
    client = _make_mock_client()
    result = _invoke(
        monkeypatch,
        client,
        operation="url-allow-list",
        target="newsite.com",
        ticket_ref="INC-42",
        dry_run=False,
    )
    assert result["status"] == "applied"
    assert result["commit_required"] is True
    # Verify update was called
    assert len(client.url_category._update_calls) == 1


def test_threat_exception_missing_profile_config(monkeypatch: Any) -> None:
    """If neither anti_spyware_profile nor vulnerability_protection_profile is in ssr_objects, error."""
    client = _make_mock_client(ssr_objects={"url_allow_list": "SSR-Allow-List"})
    result = _invoke(
        monkeypatch, client, operation="threat-exception", target="12345", ticket_ref="INC-1"
    )
    assert result["status"] == "error"


# ---------------------------------------------------------------------------
# Tests — _validate_target unit
# ---------------------------------------------------------------------------


def test_validate_url_fqdn() -> None:
    assert _validate_target("url-allow-list", "example.com") is None
    assert _validate_target("url-allow-list", "sub.example.co.uk") is None
    assert _validate_target("url-allow-list", "https://example.com/path") is None
    assert _validate_target("url-allow-list", "*.example.com") is None


def test_validate_url_ip() -> None:
    assert _validate_target("url-allow-list", "10.0.0.1") is None
    assert _validate_target("url-allow-list", "10.0.0.0/24") is None


def test_validate_url_rejects_overbroad() -> None:
    assert _validate_target("url-allow-list", "*") is not None
    assert _validate_target("url-allow-list", "*.*") is not None
    assert _validate_target("url-allow-list", "*.*.*.*") is not None


def test_validate_threat_id() -> None:
    assert _validate_target("threat-exception", "12345") is None
    assert _validate_target("threat-exception", "12345678") is None
    assert _validate_target("threat-exception", "abc") is not None
    assert _validate_target("threat-exception", "12") is not None


# ---------------------------------------------------------------------------
# Tests — review fixes (2026-07-15): status contract + no cross-tenant bleed
# ---------------------------------------------------------------------------


class _ExplodingResource:
    def fetch(self, name: str = "", folder: str = "") -> Any:  # noqa: ARG002
        raise RuntimeError("boom: profile fetch failed")


def test_threat_exception_all_profiles_failing_reports_error_status(monkeypatch: Any) -> None:
    """If every configured profile errors, status must NOT read applied."""
    client = _make_mock_client()
    client.anti_spyware_profile = _ExplodingResource()
    client.vulnerability_protection_profile = _ExplodingResource()
    result = _invoke(
        monkeypatch,
        client,
        operation="threat-exception",
        target="12345",
        ticket_ref="INC-1",
        dry_run=False,
    )
    assert result["status"] == "error"
    assert result["errors"]
    assert result["commit_required"] is False


def test_threat_exception_noop_does_not_require_commit(monkeypatch: Any) -> None:
    """already_present on every profile means nothing changed — no commit needed."""
    existing = {"name": "12345", "action": {"allow": {}}}
    client = _make_mock_client(
        asp_data={"name": "SSR-AntiSpyware", "threat_exception": [dict(existing)]},
        vp_data={"name": "SSR-VulnProtection", "threat_exception": [dict(existing)]},
    )
    result = _invoke(
        monkeypatch,
        client,
        operation="threat-exception",
        target="12345",
        ticket_ref="INC-1",
        dry_run=False,
    )
    assert result["already_present"] is True
    assert result["commit_required"] is False


def test_threat_exception_change_requires_commit_even_in_dry_run(monkeypatch: Any) -> None:
    client = _make_mock_client()
    result = _invoke(
        monkeypatch,
        client,
        operation="threat-exception",
        target="99999",
        ticket_ref="INC-1",
        dry_run=True,
    )
    assert result["status"] == "planned"
    assert result["commit_required"] is True


def test_unmatched_tenant_id_gets_no_other_tenants_ssr_config() -> None:
    """Explicit tenant_id with no config match must return {} — never another
    tenant's allowlist (cross-tenant bleed)."""
    from unittest.mock import patch

    from scm_harbourmaster_mcp.tools.ssr import _get_ssr_config, _resolve_default_folder

    fake_tc = MagicMock()
    fake_tc.tenant_id = "111"
    fake_tc.ssr_objects = {"url_allow_list": "Other-Tenant-List"}
    fake_tc.default_folder = "Other-Folder"
    with patch(
        "scm_harbourmaster_mcp.tools.ssr.load_all_tenant_configs", return_value={"other": fake_tc}
    ):
        assert _get_ssr_config("999") == {}
        assert _resolve_default_folder("999") == ""
        # empty tenant_id keeps the single-tenant fallback
        assert _get_ssr_config("") == {"url_allow_list": "Other-Tenant-List"}
        assert _resolve_default_folder("") == "Other-Folder"
