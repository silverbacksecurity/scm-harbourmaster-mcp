"""Tests for the shared direct-REST helpers in utils/scm_rest.py."""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from scm_harbourmaster_mcp.utils import scm_rest


def _resp(status: int, data: Any = None, text: str = "", bad_json: bool = False) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    if bad_json:
        r.json.side_effect = ValueError("not json")
    else:
        r.json.return_value = data
    r.text = text
    if status >= 400:
        r.raise_for_status.side_effect = RuntimeError(f"HTTP {status}")
    return r


class TestRefreshToken:
    def test_no_oauth_client_is_noop(self) -> None:
        scm_rest.refresh_token(SimpleNamespace(oauth_client=None))

    def test_refreshes_unconditionally(self) -> None:
        oauth = MagicMock(is_expired=False, token_expires_soon=False)
        scm_rest.refresh_token(SimpleNamespace(oauth_client=oauth))
        oauth.refresh_token.assert_called_once()

    def test_retries_when_first_refresh_fails_and_token_expired(self) -> None:
        oauth = MagicMock(is_expired=True)
        oauth.refresh_token.side_effect = [RuntimeError("boom"), None]
        scm_rest.refresh_token(SimpleNamespace(oauth_client=oauth))
        assert oauth.refresh_token.call_count == 2

    def test_swallows_repeated_failure(self) -> None:
        oauth = MagicMock(is_expired=True)
        oauth.refresh_token.side_effect = RuntimeError("boom")
        scm_rest.refresh_token(SimpleNamespace(oauth_client=oauth))


class TestBearerSession:
    def test_sets_bearer_header(self) -> None:
        client = SimpleNamespace(
            oauth_client=MagicMock(is_expired=False),
            session=SimpleNamespace(token={"access_token": "abc"}),
        )
        sess = scm_rest.bearer_session(client)
        assert sess.headers["Authorization"] == "Bearer abc"
        client.oauth_client.refresh_token.assert_not_called()

    def test_refreshes_only_when_expired(self) -> None:
        client = SimpleNamespace(
            oauth_client=MagicMock(is_expired=True),
            session=SimpleNamespace(token={"access_token": "abc"}),
        )
        scm_rest.bearer_session(client)
        client.oauth_client.refresh_token.assert_called_once()

    def test_no_token_no_header(self) -> None:
        client = SimpleNamespace(oauth_client=None, session=SimpleNamespace(token=None))
        assert "Authorization" not in scm_rest.bearer_session(client).headers


class TestRequest:
    def test_json_body(self) -> None:
        session = MagicMock()
        session.get.return_value = _resp(200, {"a": 1})
        res = scm_rest.request(session, "get", "u")
        assert (res.status, res.data, res.ok, res.not_licensed) == (200, {"a": 1}, True, False)
        session.get.assert_called_once_with("u", timeout=scm_rest.DEFAULT_TIMEOUT)

    def test_passes_only_set_kwargs(self) -> None:
        session = MagicMock()
        session.post.return_value = _resp(201, {})
        scm_rest.request(session, "POST", "u", params={"p": 1}, json={"j": 2}, timeout=(1, 2))
        session.post.assert_called_once_with("u", timeout=(1, 2), params={"p": 1}, json={"j": 2})

    def test_region_header_is_lowercased_and_merged(self) -> None:
        session = MagicMock()
        session.get.return_value = _resp(200, [])
        scm_rest.request(session, "GET", "u", headers={"X-Other": "1"}, region=" UK ")
        assert session.get.call_args.kwargs["headers"] == {"X-Other": "1", "x-panw-region": "uk"}

    def test_no_region_sends_no_headers(self) -> None:
        session = MagicMock()
        session.get.return_value = _resp(200, [])
        scm_rest.request(session, "GET", "u")
        assert "headers" not in session.get.call_args.kwargs

    def test_non_json_body_keeps_text(self) -> None:
        session = MagicMock()
        session.get.return_value = _resp(502, text="x" * 900, bad_json=True)
        res = scm_rest.request(session, "GET", "u")
        assert res.status == 502 and res.data is None and len(res.text) == 500

    def test_transport_error(self) -> None:
        session = MagicMock()
        session.get.side_effect = RuntimeError("down")
        res = scm_rest.request(session, "GET", "u")
        assert (res.status, res.error) == (-1, "down")

    def test_unknown_method(self) -> None:
        res = scm_rest.request(MagicMock(), "TRACE", "u")
        assert res.status == -1 and "Unknown method" in res.error

    @pytest.mark.parametrize("status", sorted(scm_rest.NOT_LICENSED))
    def test_not_licensed_flag(self, status: int) -> None:
        session = MagicMock()
        session.get.return_value = _resp(status, {})
        assert scm_rest.request(session, "GET", "u").not_licensed


class TestCall:
    def test_success(self) -> None:
        session = MagicMock()
        session.put.return_value = _resp(200, {"id": "1"})
        assert scm_rest.call(session, "PUT", "u", json_body={"a": 1}) == (200, {"id": "1"}, "")

    @pytest.mark.parametrize("status", [401, 403, 404, 424])
    def test_not_licensed(self, status: int) -> None:
        session = MagicMock()
        session.get.return_value = _resp(status, {"error": "x"})
        assert scm_rest.call(session, "GET", "u") == (status, None, "")

    def test_non_json_returns_text_as_error(self) -> None:
        session = MagicMock()
        session.delete.return_value = _resp(204, text="", bad_json=True)
        assert scm_rest.call(session, "DELETE", "u") == (204, None, "")
        session.get.return_value = _resp(500, text="oops", bad_json=True)
        assert scm_rest.call(session, "GET", "u") == (500, None, "oops")

    def test_transport_and_unknown_method(self) -> None:
        session = MagicMock()
        session.get.side_effect = RuntimeError("down")
        assert scm_rest.call(session, "GET", "u") == (-1, None, "down")
        assert scm_rest.call(session, "NOPE", "u") == (-1, None, "Unknown method: NOPE")


class TestGetList:
    def test_shapes(self) -> None:
        session = MagicMock()
        session.get.return_value = _resp(200, [{"a": 1}])
        assert scm_rest.get_list(session, "u") == [{"a": 1}]
        session.get.return_value = _resp(200, {"items": [{"b": 2}]})
        assert scm_rest.get_list(session, "u") == [{"b": 2}]
        session.get.return_value = _resp(200, {"data": [{"c": 3}], "items": [{"d": 4}]})
        assert scm_rest.get_list(session, "u") == [{"c": 3}]
        session.get.return_value = _resp(200, {"other": 1})
        assert scm_rest.get_list(session, "u") == []

    def test_custom_keys(self) -> None:
        session = MagicMock()
        session.get.return_value = _resp(200, {"patterns": [{"p": 1}]})
        assert scm_rest.get_list(session, "u", keys=("data", "patterns")) == [{"p": 1}]

    @pytest.mark.parametrize("status", [401, 403, 404, 424])
    def test_not_licensed_is_empty(self, status: int) -> None:
        session = MagicMock()
        session.get.return_value = _resp(status)
        assert scm_rest.get_list(session, "u") == []

    def test_errors_raise(self) -> None:
        session = MagicMock()
        session.get.return_value = _resp(500)
        with pytest.raises(RuntimeError):
            scm_rest.get_list(session, "u")

        exc = RuntimeError("boom")
        exc.response = SimpleNamespace(status_code=424)  # type: ignore[attr-defined]
        session.get.side_effect = exc
        assert scm_rest.get_list(session, "u") == []
        session.get.side_effect = RuntimeError("other")
        with pytest.raises(RuntimeError):
            scm_rest.get_list(session, "u")


class TestPutObject:
    def test_payload_keeps_container_strips_none_and_renames(self) -> None:
        oid = uuid.uuid4()
        data = {
            "id": oid,
            "folder": "f",
            "snippet": None,
            "name": "p",
            "description": None,
            "continue_": ["gambling"],
            "credential_enforcement": {"continue_": ["x"], "mode": None, "ref": oid},
        }
        assert scm_rest.put_payload("url_access_profile", data) == {
            "folder": "f",
            "name": "p",
            "continue": ["gambling"],
            "credential_enforcement": {"continue": ["x"], "ref": str(oid)},
        }

    def test_payload_without_aliases_is_unrenamed(self) -> None:
        assert scm_rest.put_payload("url_category", {"id": "1", "list": ["a"]}) == {"list": ["a"]}

    def test_put_object_calls_client_put(self) -> None:
        client = MagicMock()
        client.hip_object.ENDPOINT = "/config/objects/v1/hip-objects"
        scm_rest.put_object(client, "hip_object", {"id": "abc", "name": "h", "is_": "yes"})
        client.put.assert_called_once_with(
            "/config/objects/v1/hip-objects/abc", json={"name": "h", "is": "yes"}
        )

    def test_put_object_passes_params(self) -> None:
        client = MagicMock()
        client.decryption_rule.ENDPOINT = "/e"
        scm_rest.put_object(client, "decryption_rule", {"id": "1"}, params={"position": "pre"})
        assert client.put.call_args.kwargs["params"] == {"position": "pre"}

    def test_put_object_needs_id_and_endpoint(self) -> None:
        client = MagicMock()
        client.thing.ENDPOINT = "/e"
        with pytest.raises(ValueError, match="no id"):
            scm_rest.put_object(client, "thing", {"name": "x"})
        client.other.ENDPOINT = None
        with pytest.raises(ValueError, match="no REST endpoint"):
            scm_rest.put_object(client, "other", {"id": "1"})

    def test_sdk_endpoints_exist_for_ssr_resources(self) -> None:
        from scm.config.security import (
            AntiSpywareProfile,
            DecryptionRule,
            URLCategories,
            VulnerabilityProtectionProfile,
        )

        for cls in (
            AntiSpywareProfile,
            DecryptionRule,
            URLCategories,
            VulnerabilityProtectionProfile,
        ):
            assert cls.ENDPOINT.startswith("/config/security/v1/")

    def test_vulnerability_vendor_id_is_not_renamed(self) -> None:
        # The API field is vendor_id; SCM rejects the SDK's "vendor-id" alias.
        data = {"id": "1", "folder": "f", "rules": [{"name": "r", "vendor_id": ["any"]}]}
        assert scm_rest.put_payload("vulnerability_protection_profile", data) == {
            "folder": "f",
            "rules": [{"name": "r", "vendor_id": ["any"]}],
        }
        assert "vulnerability_protection_profile" not in scm_rest.SDK_DROPPED_ALIASES


class TestGetObject:
    def _client(self, body: Any) -> MagicMock:
        client = MagicMock()
        client.url_category.ENDPOINT = "/e"
        client.get.return_value = body
        return client

    def test_bare_object(self) -> None:
        client = self._client({"id": "1", "name": "n"})
        assert scm_rest.get_object(client, "url_category", "n", "f") == {"id": "1", "name": "n"}
        client.get.assert_called_once_with("/e", params={"name": "n", "folder": "f"})

    def test_data_wrapper_and_extra_params(self) -> None:
        client = self._client({"data": [{"id": "1"}]})
        got = scm_rest.get_object(client, "url_category", "n", "f", params={"position": "pre"})
        assert got == {"id": "1"}
        assert client.get.call_args.kwargs["params"]["position"] == "pre"

    @pytest.mark.parametrize("body", [{"data": []}, [], {"name": "no-id"}])
    def test_not_found(self, body: Any) -> None:
        with pytest.raises(scm_rest.ObjectNotFoundError, match="not found"):
            scm_rest.get_object(self._client(body), "url_category", "n", "f")
