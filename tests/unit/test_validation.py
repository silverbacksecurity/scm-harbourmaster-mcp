"""Unit tests for the OpenAPI pre-request validation layer."""

from __future__ import annotations

import pytest

from src.scm_harbourmaster_mcp.utils import validation

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


_FAKE_INDEX = {
    "GET /v1/things": {
        "parameters": [
            {"name": "limit", "required": False, "schema": {"type": "integer"}},
            {"name": "kind", "required": True, "schema": {"type": "string", "enum": ["a", "b"]}},
        ]
    },
    "POST /v1/things/query": {
        "requestBody": {
            "type": "object",
            "required": ["filter"],
            "properties": {
                "filter": {"type": "object"},
                "limit": {"type": "integer"},
            },
        }
    },
}


@pytest.fixture
def fake_index(monkeypatch):
    monkeypatch.setattr(validation, "_schema_index", dict(_FAKE_INDEX))
    return _FAKE_INDEX


# ---------------------------------------------------------------------------
# validate_params
# ---------------------------------------------------------------------------


class TestValidateParams:
    def test_unknown_endpoint_is_noop(self, fake_index) -> None:
        assert validation.validate_params("GET /nope", {"x": 1}) == []

    def test_missing_required(self, fake_index) -> None:
        errors = validation.validate_params("GET /v1/things", {"limit": 5})
        assert any("kind" in e for e in errors)

    def test_valid_params(self, fake_index) -> None:
        assert validation.validate_params("GET /v1/things", {"kind": "a", "limit": 5}) == []

    def test_integer_coercible_string_ok(self, fake_index) -> None:
        assert validation.validate_params("GET /v1/things", {"kind": "a", "limit": "5"}) == []

    def test_integer_bad_string(self, fake_index) -> None:
        errors = validation.validate_params("GET /v1/things", {"kind": "a", "limit": "many"})
        assert any("integer" in e for e in errors)

    def test_enum_violation(self, fake_index) -> None:
        errors = validation.validate_params("GET /v1/things", {"kind": "z"})
        assert any("allowed values" in e for e in errors)


# ---------------------------------------------------------------------------
# validate_body
# ---------------------------------------------------------------------------


class TestValidateBody:
    def test_unknown_endpoint_is_noop(self, fake_index) -> None:
        assert validation.validate_body("POST /nope", {}) == []

    def test_valid_body(self, fake_index) -> None:
        assert validation.validate_body("POST /v1/things/query", {"filter": {}}) == []

    def test_reports_all_errors(self, fake_index) -> None:
        # Missing required "filter" AND wrong type for "limit" — both reported.
        errors = validation.validate_body("POST /v1/things/query", {"limit": "ten"})
        assert len(errors) == 2

    def test_jsonschema_missing_degrades_to_noop(self, fake_index, monkeypatch) -> None:
        monkeypatch.setattr(validation, "jsonschema", None)
        assert validation.validate_body("POST /v1/things/query", {"limit": "ten"}) == []


# ---------------------------------------------------------------------------
# Index loading
# ---------------------------------------------------------------------------


class TestIndexLoading:
    def test_absent_file_is_noop(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setattr(validation, "_schema_index", None)
        monkeypatch.setattr(validation, "_SCHEMA_PATH", tmp_path / "missing.json")
        assert validation.validate_params("GET /v1/things", {}) == []
        assert validation.validate_body("POST /v1/things/query", {}) == []
        assert validation.has_schema("GET /v1/things") is False

    def test_schema_coverage_reports(self, fake_index) -> None:
        cov = validation.schema_coverage()
        assert cov["total_endpoints"] == 2
