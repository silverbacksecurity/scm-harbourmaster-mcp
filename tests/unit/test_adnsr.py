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


class TestCustomFqdn:
    def _fn(self, client: Any) -> Any:
        return _tool("scm_adnsr_custom_fqdn", client)

    def test_requires_ticket_ref(self) -> None:
        out = self._fn(_client())(name="blocklist", fqdns="a.example.com")
        assert out.startswith("Error")

    def test_create_dry_run_sends_nothing(self) -> None:
        client = _client()
        out = self._fn(client)(
            name="blocklist",
            fqdns="B.example.com\na.example.com\na.example.com",
            ticket_ref="CHG-1",
        )
        assert "DRY-RUN" in out
        assert '"fqdn_count": 2' in out
        client.session.post.assert_not_called()

    def test_create_validation(self) -> None:
        fn = self._fn(_client())
        assert "name is required" in fn(fqdns="a.example.com", ticket_ref="CHG-1")
        assert "at least one FQDN" in fn(name="blocklist", ticket_ref="CHG-1")
        assert "4-128" in fn(name="ab", fqdns="a.example.com", ticket_ref="CHG-1")

    def test_update_and_delete_need_id(self) -> None:
        fn = self._fn(_client())
        assert "custom_fqdn_id is required" in fn(action="delete", ticket_ref="CHG-1")
        assert "custom_fqdn_id is required" in fn(
            action="update", fqdns="a.example.com", ticket_ref="CHG-1"
        )

    def test_create_posts_multipart(self) -> None:
        client = _client()
        client.session.post.return_value = MagicMock(
            status_code=201,
            json=MagicMock(return_value={"data": {"id": "f-1", "name": "blocklist"}}),
        )
        out = self._fn(client)(
            name="blocklist", fqdns="a.example.com", dry_run=False, ticket_ref="CHG-1"
        )
        assert "created" in out
        assert "`f-1`" in out
        kwargs = client.session.post.call_args.kwargs
        assert kwargs["files"]["fqdns"][1] == "a.example.com\n"
        assert kwargs["headers"] == {"Content-Type": None}
        assert kwargs["data"] == {"name": "blocklist"}

    def test_delete_live(self) -> None:
        client = _client()
        client.session.get.return_value = MagicMock(
            status_code=200, json=MagicMock(return_value={"item": {"id": "f-1"}})
        )
        client.session.delete.return_value = MagicMock(status_code=204)
        out = self._fn(client)(
            action="delete", custom_fqdn_id="f-1", dry_run=False, ticket_ref="CHG-1"
        )
        assert "deleted" in out
        assert client.session.delete.call_args.args[0].endswith("/custom-fqdns/f-1")

    def test_http_error_surfaced(self) -> None:
        client = _client()
        client.session.post.return_value = MagicMock(status_code=400, text="bad body")
        out = self._fn(client)(
            name="blocklist", fqdns="a.example.com", dry_run=False, ticket_ref="CHG-1"
        )
        assert out.startswith("Error 400")

    def _existing(self, client: Any) -> None:
        client.session.get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(
                return_value={
                    "item": {
                        "id": "f-1",
                        "name": "blocklist",
                        "description": "keep me",
                        "total_fqdns": 500,
                    }
                }
            ),
        )

    def test_update_keeps_name_and_description(self) -> None:
        client = _client()
        self._existing(client)
        client.session.put.return_value = MagicMock(
            status_code=200, json=MagicMock(return_value={"data": {"id": "f-1"}})
        )
        out = self._fn(client)(
            action="update",
            custom_fqdn_id="f-1",
            fqdns="a.example.com",
            dry_run=False,
            ticket_ref="CHG-1",
        )
        assert "updated" in out
        call = client.session.put.call_args
        assert call.args[0].endswith("/custom-fqdns/f-1")
        assert call.kwargs["data"] == {"name": "blocklist", "description": "keep me"}

    def test_update_dry_run_warns_of_replacement(self) -> None:
        client = _client()
        self._existing(client)
        out = self._fn(client)(
            action="update", custom_fqdn_id="f-1", fqdns="a.example.com", ticket_ref="CHG-1"
        )
        assert "replaces the whole list" in out
        assert "500 FQDN(s) now" in out
        client.session.put.assert_not_called()

    def test_unsafe_id_rejected_before_any_request(self) -> None:
        client = _client()
        for bad in ("../profiles/p-1", "f-1?fqdn-limit=1", "a/b"):
            out = self._fn(client)(
                action="delete", custom_fqdn_id=bad, dry_run=False, ticket_ref="CHG-1"
            )
            assert out.startswith("Error: custom_fqdn_id may only contain")
        client.session.get.assert_not_called()
        client.session.delete.assert_not_called()

    def test_delete_refused_when_read_is_not_that_list(self) -> None:
        client = _client()
        client.session.get.return_value = MagicMock(
            status_code=200, json=MagicMock(return_value={"item": {"id": "other"}})
        )
        out = self._fn(client)(
            action="delete", custom_fqdn_id="f-1", dry_run=False, ticket_ref="CHG-1"
        )
        assert out.startswith("Error")
        client.session.delete.assert_not_called()

    def test_audit_only_on_real_write(self, monkeypatch: Any) -> None:
        calls: list[str] = []
        monkeypatch.setattr(
            "scm_harbourmaster_mcp.tools.adnsr.audit_write", lambda *a, **k: calls.append(a[0])
        )
        client = _client()
        client.session.post.side_effect = lambda *a, **k: (
            calls.append("post"),
            MagicMock(status_code=201, json=MagicMock(return_value={"data": {"id": "f-1"}})),
        )[1]
        fn = self._fn(client)
        fn(name="blocklist", fqdns="a.example.com", ticket_ref="CHG-1")
        assert calls == []
        fn(name="blocklist", fqdns="a.example.com", dry_run=False, ticket_ref="CHG-1")
        assert calls == ["scm_adnsr_custom_fqdn", "post"]


class TestProfileOverride:
    PROFILE = {
        "id": "p-1",
        "name": "dns-prof",
        "read_only": False,
        "created_at": "2026-01-01T00:00:00Z",
        "last_updated_at": "2026-01-02T00:00:00Z",
        "description": "keep me",
        "safesearch_enabled": True,
        "category_overrides": [{"category_id": "7", "action": "block"}],
        "edl_overrides": [{"id": "e-1", "name": "edl", "action": "alert"}],
        "custom_fqdn_overrides": [{"id": "f-9", "name": "other", "action": "allow"}],
    }

    def _fn(self, client: Any) -> Any:
        return _tool("scm_adnsr_profile_override", client)

    def _client(self, profile: Any = None, fqdn: Any = None) -> MagicMock:
        profile = self.PROFILE if profile is None else profile
        fqdn = {"id": "f-1", "name": "blocklist"} if fqdn is None else fqdn
        client = _client()

        def get(url: str, **_: Any) -> MagicMock:
            if "/profiles/p-1" in url:
                return MagicMock(status_code=200, json=MagicMock(return_value={"item": profile}))
            if "/custom-fqdns/f-1" in url:
                return MagicMock(status_code=200, json=MagicMock(return_value={"item": fqdn}))
            return MagicMock(status_code=404, json=MagicMock(return_value={"data": []}))

        client.session.get.side_effect = get
        client.session.put.return_value = MagicMock(status_code=200)
        return client

    def test_requires_ticket_ref(self) -> None:
        out = self._fn(self._client())(profile="p-1", custom_fqdn="f-1")
        assert out.startswith("Error")

    def test_dry_run_sends_no_write(self) -> None:
        client = self._client()
        out = self._fn(client)(profile="p-1", custom_fqdn="f-1", ticket_ref="CHG-1")
        assert "DRY-RUN" in out
        assert "before" in out and "after" in out
        client.session.put.assert_not_called()

    def test_attach_preserves_other_fields(self) -> None:
        client = self._client()
        out = self._fn(client)(
            profile="p-1", custom_fqdn="f-1", action="sinkhole", dry_run=False, ticket_ref="CHG-1"
        )
        assert "attached" in out
        body = client.session.put.call_args.kwargs["json"]
        assert client.session.put.call_args.args[0].endswith("/profiles/p-1")
        assert body["name"] == "dns-prof"
        assert body["description"] == "keep me"
        assert body["safesearch_enabled"] is True
        assert body["category_overrides"] == [{"category_id": "7", "action": "block"}]
        assert body["edl_overrides"] == [{"id": "e-1", "action": "alert"}]
        assert body["custom_fqdn_overrides"] == [
            {"id": "f-9", "action": "allow"},
            {"id": "f-1", "action": "sinkhole"},
        ]
        for read_only in ("id", "created_at", "last_updated_at", "read_only"):
            assert read_only not in body
        assert "ticket_ref" not in str(body)

    def test_update_existing_override(self) -> None:
        profile = {**self.PROFILE, "custom_fqdn_overrides": [{"id": "f-1", "action": "allow"}]}
        client = self._client(profile=profile)
        self._fn(client)(
            profile="p-1", custom_fqdn="f-1", action="block", dry_run=False, ticket_ref="CHG-1"
        )
        body = client.session.put.call_args.kwargs["json"]
        assert body["custom_fqdn_overrides"] == [{"id": "f-1", "action": "block"}]

    def test_detach(self) -> None:
        profile = {
            **self.PROFILE,
            "custom_fqdn_overrides": [
                {"id": "f-1", "name": "blocklist", "action": "block"},
                {"id": "f-9", "action": "allow"},
            ],
        }
        client = self._client(profile=profile)
        out = self._fn(client)(
            profile="p-1", custom_fqdn="f-1", operation="detach", dry_run=False, ticket_ref="CHG-1"
        )
        assert "detached" in out
        body = client.session.put.call_args.kwargs["json"]
        assert body["custom_fqdn_overrides"] == [{"id": "f-9", "action": "allow"}]

    def test_detach_when_not_attached_is_noop(self) -> None:
        client = self._client()
        out = self._fn(client)(
            profile="p-1", custom_fqdn="f-1", operation="detach", dry_run=False, ticket_ref="CHG-1"
        )
        assert "Nothing to do" in out
        client.session.put.assert_not_called()

    def test_unknown_profile_and_list(self) -> None:
        client = self._client()
        out = self._fn(client)(profile="nope", custom_fqdn="f-1", ticket_ref="CHG-1")
        assert out.startswith("Error: profile `nope`")
        out = self._fn(client)(profile="p-1", custom_fqdn="nope", ticket_ref="CHG-1")
        assert out.startswith("Error: custom FQDN list `nope`")
        client.session.put.assert_not_called()

    def test_resolves_by_name(self) -> None:
        client = self._client()
        base_get = client.session.get.side_effect

        def get(url: str, **kw: Any) -> MagicMock:
            if url.endswith("/profiles"):
                return MagicMock(
                    status_code=200,
                    json=MagicMock(return_value={"data": [{"id": "p-1", "name": "dns-prof"}]}),
                )
            return base_get(url, **kw)

        client.session.get.side_effect = get
        self._fn(client)(profile="dns-prof", custom_fqdn="f-1", dry_run=False, ticket_ref="CHG-1")
        assert client.session.put.call_args.args[0].endswith("/profiles/p-1")

    def test_invalid_action(self) -> None:
        out = self._fn(self._client())(
            profile="p-1", custom_fqdn="f-1", action="drop", ticket_ref="CHG-1"
        )
        assert out.startswith("Error: action")

    def test_http_error_surfaced(self) -> None:
        client = self._client()
        client.session.put.return_value = MagicMock(status_code=400, text="bad body")
        out = self._fn(client)(profile="p-1", custom_fqdn="f-1", dry_run=False, ticket_ref="CHG-1")
        assert out.startswith("Error 400")

    def _listing_client(self, rows: list[dict[str, Any]]) -> MagicMock:
        client = self._client()
        inner = client.session.get.side_effect

        def get(url: str, **kw: Any) -> MagicMock:
            if url.endswith("/profiles"):
                return MagicMock(status_code=200, json=MagicMock(return_value={"data": rows}))
            if url.endswith("/profiles/categories"):
                return MagicMock(status_code=200, json=MagicMock(return_value={"data": [{}]}))
            return inner(url, **kw)

        client.session.get.side_effect = get
        return client

    def test_duplicate_names_refused(self) -> None:
        client = self._listing_client([{"id": "p-1", "name": "dup"}, {"id": "p-2", "name": "dup"}])
        out = self._fn(client)(profile="dup", custom_fqdn="f-1", dry_run=False, ticket_ref="CHG-1")
        assert "ambiguous" in out and "p-1" in out and "p-2" in out
        client.session.put.assert_not_called()

    def test_name_not_found(self) -> None:
        client = self._listing_client([{"id": "p-1", "name": "dns-prof"}])
        out = self._fn(client)(profile="nope", custom_fqdn="f-1", ticket_ref="CHG-1")
        assert "not found (no matching ID or name)" in out

    def test_sub_resource_path_is_not_a_profile(self) -> None:
        client = self._listing_client([])
        out = self._fn(client)(
            profile="categories", custom_fqdn="f-1", dry_run=False, ticket_ref="CHG-1"
        )
        assert out.startswith("Error: profile `categories` not found")
        client.session.put.assert_not_called()

    def test_traversal_ref_never_reaches_a_url(self) -> None:
        client = self._listing_client([])
        self._fn(client)(
            profile="../custom-fqdns/f-1", custom_fqdn="f-1", dry_run=False, ticket_ref="CHG-1"
        )
        assert all(".." not in c.args[0] for c in client.session.get.call_args_list)
        client.session.put.assert_not_called()

    def test_action_change_drops_sinkhole_fields_and_keeps_order(self) -> None:
        profile = {
            **self.PROFILE,
            "custom_fqdn_overrides": [
                {
                    "id": "f-1",
                    "action": "sinkhole",
                    "is_custom_sinkhole": True,
                    "custom_sinkhole_id": "s-1",
                },
                {"id": "f-9", "action": "allow"},
            ],
        }
        client = self._client(profile=profile)
        self._fn(client)(
            profile="p-1", custom_fqdn="f-1", action="block", dry_run=False, ticket_ref="CHG-1"
        )
        assert client.session.put.call_args.kwargs["json"]["custom_fqdn_overrides"] == [
            {"id": "f-1", "action": "block"},
            {"id": "f-9", "action": "allow"},
        ]

    def test_already_attached_is_a_no_op(self) -> None:
        profile = {**self.PROFILE, "custom_fqdn_overrides": [{"id": "f-1", "action": "block"}]}
        client = self._client(profile=profile)
        out = self._fn(client)(
            profile="p-1", custom_fqdn="f-1", action="block", dry_run=False, ticket_ref="CHG-1"
        )
        assert out.startswith("Nothing to do")
        client.session.put.assert_not_called()

    def test_read_only_profile_refused(self) -> None:
        client = self._client(profile={**self.PROFILE, "read_only": True})
        out = self._fn(client)(profile="p-1", custom_fqdn="f-1", dry_run=False, ticket_ref="CHG-1")
        assert "read-only" in out
        client.session.put.assert_not_called()
