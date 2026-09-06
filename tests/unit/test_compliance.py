"""Tests for Compliance Center tools (scm_compliance_center, scm_compliance_framework).

Covers:
  - Action dispatch (valid/invalid)
  - Markdown rendering for each read action
  - 403 graceful degradation
  - Missing required parameters
  - Empty response handling
  - Write-side CRUD operations
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

from scm_harbourmaster_mcp.tools.compliance import register_compliance_tools

# ---------------------------------------------------------------------------
# Canned response data (shapes from the API spec examples)
# ---------------------------------------------------------------------------

_FRAMEWORKS_LIST: list[dict[str, Any]] = [
    {
        "id": "PCF-7f1ae852-f5a4-40ed-911a-88d54ebf8876",
        "name": "CSCV8",
        "description": "Center for Internet Security Controls Version 8",
        "source_url": "https://www.cisecurity.org/controls/cis-controls-list",
        "source": "CIS",
        "category": "PCF",
        "status": "released",
    },
    {
        "id": "CCF-8b2cf963-g6b5-51fe-a22b-99e65fcg9987",
        "name": "Custom Security Framework",
        "description": "Organization-specific security controls",
        "source_url": "https://internal.example.com/security-framework",
        "source": "Internal",
        "category": "CCF",
        "status": "draft",
    },
]

_SUMMARIES: dict[str, Any] = {
    "data": [
        {
            "id": "PCF-7f1ae852-f5a4-40ed-911a-88d54ebf8876",
            "category": "PCF",
            "create_time": 1758913230056,
            "benchmark": True,
            "revision_summary": [
                {
                    "name": "NIST CSF 2.0",
                    "source_url": "https://example.com",
                    "source": "NIST",
                    "update_time": 1764789586408,
                    "revision_id": "in_release",
                    "revision_number": "Updated logo",
                    "description": "NIST CSF 2.0 compliance",
                    "state": "released",
                    "overall_score": 82,
                    "industry_score": 80,
                }
            ],
        }
    ]
}

_SCORES: dict[str, Any] = {
    "products": {
        "all": {
            "name": "all",
            "data_available": True,
            "compliance": {"overall_score": 83, "industry_score": 87},
        },
        "ngfw": {
            "name": "ngfw",
            "data_available": True,
            "compliance": {"overall_score": 83, "industry_score": 87},
            "categories": [
                {
                    "name": "network",
                    "compliance": {"overall_score": 62, "industry_score": 87},
                },
            ],
        },
        "sase": {
            "name": "sase",
            "data_available": False,
            "compliance": {"overall_score": -1, "industry_score": -1},
            "categories": [
                {
                    "name": "network",
                    "compliance": {"overall_score": -1, "industry_score": -1},
                },
            ],
        },
    },
    "category": "PCF",
}

_TIMELINE: dict[str, Any] = {
    "timeline_30_days": [
        {"ts": 1774051200000000, "compliance_score": 83, "data_available": True},
        {"ts": 1773964800000000, "compliance_score": 83, "data_available": True},
        {"ts": 1772496000000000, "compliance_score": 82, "data_available": True},
    ],
    "timeline_1_year": [],
}

_CONTROLS: dict[str, Any] = {
    "compliance_framework_metadata": {
        "id": "PCF-fake",
        "name": "NIST 800-53 r5",
        "assessment_date": "2026-03-21",
    },
    "compliance_framework_control_groups": [
        {
            "control_name": "AC-1 : Policy and Procedures",
            "data_available": True,
            "all": {
                "most_severe": {"category": 1, "category_name": "Informational", "count": 0},
                "failed": 0,
                "passed": 22,
                "overall_score": 100.0,
            },
        },
        {
            "control_name": "AC-2 : Account Management",
            "data_available": True,
            "all": {
                "most_severe": {"category": 5, "category_name": "Critical", "count": 6},
                "failed": 9,
                "passed": 40,
                "overall_score": 81.0,
            },
        },
    ],
}

_ASSESSED: dict[str, Any] = {
    "configurations_assessed": {
        "checks": 87,
        "assessments": 270,
        "total_exceptions": 29,
        "expiring_exceptions": 0,
    }
}

_BENCHMARK_MONITORING: dict[str, Any] = {
    "device_serial": ["SN001", "SN002"],
    "bpc_id": ["100", "102"],
    "severity": ["Critical", "Warning", "Informational"],
    "bpc_status": ["pass", "fail", "exception"],
    "bpc_stats": {
        "controls": {
            "compliance_rate": 57,
            "data_available": True,
            "failed_assessments": 248,
            "severity": {
                "critical": 65,
                "warning": 84,
                "informational": 99,
                "pass": 333,
            },
        },
        "exceptions": {
            "total_exceptions": 76,
            "expiring_exceptions": 0,
            "severity": {"critical": 52, "warning": 10, "informational": 14},
        },
    },
}

# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------


class MockResponse:
    """A mock requests.Response with status_code, .json(), .raise_for_status()."""

    def __init__(
        self, data: Any, status_code: int = 200, content_type: str = "application/json"
    ) -> None:
        self._data = data
        self.status_code = status_code
        self._content_type = content_type

    def json(self) -> Any:
        return self._data

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise OSError(f"HTTP {self.status_code}")

    @property
    def headers(self) -> dict[str, str]:
        return {"Content-Type": self._content_type}


def _make_mock_client(
    monkeypatch: Any,
    get_data: Any = None,
    post_data: Any = None,
    put_data: Any = None,
    delete_status: int = 204,
    get_status: int = 200,
    post_status: int = 200,
    put_status: int = 200,
) -> MagicMock:
    """Build a mock client whose .session handles GET/POST/PUT/DELETE.

    Returns the mock client so the caller can assert on session calls if needed.
    """
    mock_session = MagicMock()
    mock_session.get.return_value = MockResponse(get_data or {}, get_status)
    mock_session.post.return_value = MockResponse(post_data or {}, post_status)
    mock_session.put.return_value = MockResponse(put_data or {}, put_status)
    mock_session.delete.return_value = MockResponse(None, delete_status)

    mock_client = MagicMock()
    mock_client.session = mock_session
    mock_client.oauth_client = None  # skip token refresh in _bearer_session

    return mock_client


def _resolve_get_client(mock_client: MagicMock) -> Any:
    """Return a callable that always returns *mock_client* (ignoring tenant_id)."""

    def get_client(_tenant_id: str = "") -> Any:  # noqa: ARG001
        return mock_client

    return get_client


def _invoke_tool(
    monkeypatch: Any,
    tool_name: str,
    **kwargs: Any,
) -> str:
    """Register tools onto a throwaway FastMCP and invoke *tool_name*.

    Returns the tool's string output.
    """
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("test-compliance")
    mock_client = _make_mock_client(monkeypatch)
    get_client = _resolve_get_client(mock_client)
    register_compliance_tools(mcp, get_client)

    tool = mcp._tool_manager.get_tool(tool_name)
    return tool.fn(**kwargs)


# ---------------------------------------------------------------------------
# Tests — read-side (scm_compliance_center)
# ---------------------------------------------------------------------------


def test_list_frameworks_renders_table(monkeypatch: Any) -> None:
    mock_client = _make_mock_client(monkeypatch, get_data={"data": _FRAMEWORKS_LIST})
    get_client = _resolve_get_client(mock_client)
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("test-list")
    register_compliance_tools(mcp, get_client)
    tool = mcp._tool_manager.get_tool("scm_compliance_center")
    result = tool.fn(action="list-frameworks")

    assert "CSCV8" in result
    assert "PCF-7f1ae852" in result
    assert "Custom Security Framework" in result
    assert "released" in result
    assert "draft" in result


def test_summaries_renders_scores(monkeypatch: Any) -> None:
    mock_client = _make_mock_client(monkeypatch, get_data=_SUMMARIES)
    get_client = _resolve_get_client(mock_client)
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("test-summaries")
    register_compliance_tools(mcp, get_client)
    tool = mcp._tool_manager.get_tool("scm_compliance_center")
    result = tool.fn(action="summaries")

    assert "NIST CSF 2.0" in result
    assert "82" in result
    assert "released" in result


def test_scores_requires_framework_id(monkeypatch: Any) -> None:
    mock_client = _make_mock_client(monkeypatch, get_data={})
    get_client = _resolve_get_client(mock_client)
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("test-scores")
    register_compliance_tools(mcp, get_client)
    tool = mcp._tool_manager.get_tool("scm_compliance_center")
    result = tool.fn(action="scores")

    assert "Error" in result
    assert "framework_id" in result


def test_scores_renders_scoreboard(monkeypatch: Any) -> None:
    mock_client = _make_mock_client(monkeypatch, get_data=_SCORES)
    get_client = _resolve_get_client(mock_client)
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("test-scores2")
    register_compliance_tools(mcp, get_client)
    tool = mcp._tool_manager.get_tool("scm_compliance_center")
    result = tool.fn(action="scores", framework_id="PCF-fake")

    assert "Scoreboard" in result
    assert "83" in result
    assert "87" in result


def test_timeline_renders_trend(monkeypatch: Any) -> None:
    mock_client = _make_mock_client(monkeypatch, get_data=_TIMELINE)
    get_client = _resolve_get_client(mock_client)
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("test-timeline")
    register_compliance_tools(mcp, get_client)
    tool = mcp._tool_manager.get_tool("scm_compliance_center")
    result = tool.fn(action="timeline", framework_id="PCF-fake")

    assert "30-Day Trend" in result
    assert "83" in result
    assert "82" in result


def test_controls_renders_per_control_detail(monkeypatch: Any) -> None:
    mock_client = _make_mock_client(monkeypatch, get_data=_CONTROLS)
    get_client = _resolve_get_client(mock_client)
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("test-controls")
    register_compliance_tools(mcp, get_client)
    tool = mcp._tool_manager.get_tool("scm_compliance_center")
    result = tool.fn(action="controls", framework_id="PCF-fake")

    assert "AC-1 : Policy and Procedures" in result
    assert "AC-2 : Account Management" in result
    assert "Critical" in result
    assert "Informational" in result
    assert "100" in result  # score
    assert "NIST 800-53" in result


def test_assessed_renders_counts(monkeypatch: Any) -> None:
    mock_client = _make_mock_client(monkeypatch, get_data=_ASSESSED)
    get_client = _resolve_get_client(mock_client)
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("test-assessed")
    register_compliance_tools(mcp, get_client)
    tool = mcp._tool_manager.get_tool("scm_compliance_center")
    result = tool.fn(action="assessed", framework_id="PCF-fake")

    assert "87" in result
    assert "270" in result
    assert "29" in result


def test_framework_detail_returns_json(monkeypatch: Any) -> None:
    detail: dict[str, Any] = {
        "id": "PCF-fake",
        "name": "Test Framework",
        "hierarchy_data": {"children": []},
    }
    mock_client = _make_mock_client(monkeypatch, get_data=detail)
    get_client = _resolve_get_client(mock_client)
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("test-detail")
    register_compliance_tools(mcp, get_client)
    tool = mcp._tool_manager.get_tool("scm_compliance_center")
    result = tool.fn(action="framework-detail", framework_id="PCF-fake")

    assert "```json" in result
    assert "Test Framework" in result


def test_benchmark_monitoring_renders(monkeypatch: Any) -> None:
    mock_client = _make_mock_client(monkeypatch, post_data=_BENCHMARK_MONITORING)
    get_client = _resolve_get_client(mock_client)
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("test-benchmark")
    register_compliance_tools(mcp, get_client)
    tool = mcp._tool_manager.get_tool("scm_compliance_center")
    result = tool.fn(action="benchmark-monitoring")

    assert "Benchmark Monitoring" in result
    assert "Severity Breakdown" in result
    assert "Critical" in result
    assert "65" in result


# ---------------------------------------------------------------------------
# Tests — error handling
# ---------------------------------------------------------------------------


def test_403_returns_licence_hint(monkeypatch: Any) -> None:
    err_body = {"_errors": [{"code": "API_CF_E00003", "message": "Access denied"}]}
    mock_client = _make_mock_client(monkeypatch, get_data=err_body, get_status=403)
    get_client = _resolve_get_client(mock_client)
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("test-403")
    register_compliance_tools(mcp, get_client)
    tool = mcp._tool_manager.get_tool("scm_compliance_center")
    result = tool.fn(action="list-frameworks")

    assert "Compliance Center API" in result
    assert "Access denied" in result
    assert "add-on licence" in result.lower()


def test_403_with_flat_message(monkeypatch: Any) -> None:
    """403 response body uses {"msg": "..."} instead of _errors array."""
    err_body: dict[str, Any] = {"msg": "Forbidden — not entitled"}
    mock_client = _make_mock_client(monkeypatch, get_data=err_body, get_status=403)
    get_client = _resolve_get_client(mock_client)
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("test-403-flat")
    register_compliance_tools(mcp, get_client)
    tool = mcp._tool_manager.get_tool("scm_compliance_center")
    result = tool.fn(action="list-frameworks")

    assert "Compliance Center API" in result
    assert "not entitled" in result


def test_invalid_action(monkeypatch: Any) -> None:
    mock_client = _make_mock_client(monkeypatch)
    get_client = _resolve_get_client(mock_client)
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("test-invalid")
    register_compliance_tools(mcp, get_client)
    tool = mcp._tool_manager.get_tool("scm_compliance_center")
    result = tool.fn(action="bogus-action")

    assert "Error" in result
    assert "unknown action" in result.lower()
    assert "bogus-action" in result


def test_empty_frameworks(monkeypatch: Any) -> None:
    mock_client = _make_mock_client(monkeypatch, get_data={"data": []})
    get_client = _resolve_get_client(mock_client)
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("test-empty")
    register_compliance_tools(mcp, get_client)
    tool = mcp._tool_manager.get_tool("scm_compliance_center")
    result = tool.fn(action="list-frameworks")

    assert "No compliance frameworks found" in result


# ---------------------------------------------------------------------------
# Tests — write-side (scm_compliance_framework)
# ---------------------------------------------------------------------------


def test_create_framework(monkeypatch: Any) -> None:
    created: dict[str, Any] = {
        "id": "CCF-new123",
        "name": "My Framework",
        "category": "CCF",
        "status": "draft",
    }
    mock_client = _make_mock_client(monkeypatch, post_data=created, post_status=201)
    get_client = _resolve_get_client(mock_client)
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("test-create")
    register_compliance_tools(mcp, get_client)
    tool = mcp._tool_manager.get_tool("scm_compliance_framework")
    result = tool.fn(
        action="create",
        payload_json=json.dumps({"name": "My Framework", "category": "CCF"}),
    )

    assert "Framework Created" in result
    assert "CCF-new123" in result
    assert "My Framework" in result


def test_create_missing_payload(monkeypatch: Any) -> None:
    mock_client = _make_mock_client(monkeypatch)
    get_client = _resolve_get_client(mock_client)
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("test-create-empty")
    register_compliance_tools(mcp, get_client)
    tool = mcp._tool_manager.get_tool("scm_compliance_framework")
    result = tool.fn(action="create")

    assert "Error" in result
    assert "payload_json" in result


def test_delete_framework(monkeypatch: Any) -> None:
    mock_client = _make_mock_client(monkeypatch, delete_status=204)
    get_client = _resolve_get_client(mock_client)
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("test-delete")
    register_compliance_tools(mcp, get_client)
    tool = mcp._tool_manager.get_tool("scm_compliance_framework")
    result = tool.fn(action="delete", framework_id="PCF-fake")

    assert "Framework Deleted" in result
    assert "PCF-fake" in result
    assert "successfully" in result.lower()


def test_benchmark_framework(monkeypatch: Any) -> None:
    mock_client = _make_mock_client(monkeypatch, post_data={"status": "success"})
    get_client = _resolve_get_client(mock_client)
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("test-benchmark")
    register_compliance_tools(mcp, get_client)
    tool = mcp._tool_manager.get_tool("scm_compliance_framework")
    result = tool.fn(action="benchmark", framework_id="PCF-fake")

    assert "Framework Benchmarked" in result
    assert "PCF-fake" in result


def test_invalid_write_action(monkeypatch: Any) -> None:
    mock_client = _make_mock_client(monkeypatch)
    get_client = _resolve_get_client(mock_client)
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("test-invalid-write")
    register_compliance_tools(mcp, get_client)
    tool = mcp._tool_manager.get_tool("scm_compliance_framework")
    result = tool.fn(action="list-frameworks")  # write tool, read action

    assert "Error" in result
    assert "unknown action" in result.lower()
