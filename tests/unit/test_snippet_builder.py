"""Tests for the shared build_and_create_snippet() helper (no network)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

from scm_harbourmaster_mcp.audit.snippet_blocks import SnippetSpec
from scm_harbourmaster_mcp.tools.snippet_builder import build_and_create_snippet

TENANT = "1234567890"
SETUP = "https://api.sase.paloaltonetworks.com/config/setup/v1"


def _spec(name: str = "Demo-Snippet") -> SnippetSpec:
    return SnippetSpec(
        label="Demo",
        snippet=name,
        sections=(
            (
                "Security Profiles",
                (
                    ("anti_spyware_profile", {"name": "Demo-AS", "snippet": name}),
                    ("url_access_profile", {"name": "Demo-URL", "snippet": name}),
                ),
            ),
            ("Tag", (("tag", {"name": "Demo-Tag", "snippet": name}),)),
        ),
        log_event="demo_snippet_create_failed",
        dry_run_note="Rules live in folders.",
        next_steps=("Do the next thing",),
    )


def _run(client: Any, **kwargs: Any) -> str:
    kwargs.setdefault("ticket_ref", "CHG-TEST")
    return build_and_create_snippet(
        client,
        kwargs.pop("spec", _spec()),
        tool_name="scm_create_demo_snippet",
        tenant_id=TENANT,
        description="demo",
        **kwargs,
    )


def _resp(status: int, data: Any = None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.ok = status < 400
    resp.content = b"x"
    resp.text = "" if resp.ok else "server says no"
    resp.json.return_value = data if data is not None else {}
    return resp


def _session(folder_name: str, snippets: list[str], put_status: int = 200) -> MagicMock:
    """Session stub for GET folders → GET folder by id → PUT folder."""
    folder = {"id": "f-1", "name": folder_name, "parent": "All", "snippets": snippets}

    def _get(url: str, **_: Any) -> MagicMock:
        if url == f"{SETUP}/folders":
            return _resp(200, {"data": [{"name": "Other", "id": "f-0"}, dict(folder)]})
        assert url == f"{SETUP}/folders/f-1"
        return _resp(200, dict(folder))

    session = MagicMock()
    session.get.side_effect = _get
    session.put.return_value = _resp(put_status)
    return session


class TestSafety:
    def test_ticket_ref_is_mandatory(self) -> None:
        client = MagicMock()
        out = _run(client, ticket_ref="  ", dry_run=False)
        assert "ticket_ref is mandatory" in out
        client.snippet.create.assert_not_called()

    def test_dry_run_makes_no_calls(self) -> None:
        client = MagicMock()
        out = _run(client, associate_folder="Branch")
        assert "## Demo Snippet — DRY-RUN: 'Demo-Snippet'" in out
        assert "[DRY-RUN] would create snippet 'Demo-Snippet'" in out
        assert "### Step 2: Security Profiles" in out and "### Step 3: Tag" in out
        assert "### Step 4: Folder Association" in out
        assert "would associate snippet 'Demo-Snippet' with folder 'Branch'" in out
        assert "Created: 3 | Skipped: 0 | Failed: 0" in out
        assert out.endswith("Note: Rules live in folders.")
        assert client.mock_calls == []


class TestApply:
    def test_creates_container_then_objects_in_order(self) -> None:
        client = MagicMock()
        client.snippet.create.return_value = SimpleNamespace(id="s-1")
        client.tag.create.return_value = SimpleNamespace(id="t-1")
        out = _run(client, dry_run=False)
        assert client.snippet.create.call_args.args[0] == {
            "name": "Demo-Snippet",
            "description": "demo",
            "enable_prefix": False,
        }
        assert client.anti_spyware_profile.create.call_args.args[0]["name"] == "Demo-AS"
        assert "[OK] Created Demo-Tag (id=t-1)" in out
        assert "**Demo snippet 'Demo-Snippet' created.**" in out
        assert "  1. Assign this snippet to tenants/folders via the SCM portal or API" in out
        assert "  2. Do the next thing" in out
        assert "Folder Association" not in out
        client.session.put.assert_not_called()

    def test_existing_container_failures_and_missing_attrs(self) -> None:
        client = MagicMock(spec=["snippet", "url_access_profile", "tag"])
        client.snippet = MagicMock()
        client.snippet.create.side_effect = RuntimeError("Name duplicate")
        client.url_access_profile = MagicMock()
        client.url_access_profile.create.side_effect = RuntimeError("Object already exists")
        client.tag = MagicMock()
        client.tag.create.side_effect = RuntimeError("HTTP 400 bad colour")
        out = _run(client, dry_run=False)
        assert "Snippet 'Demo-Snippet' already exists — continuing" in out
        assert "[SKIP] Demo-AS — SDK attr 'anti_spyware_profile' not available" in out
        assert "[SKIP] Demo-URL already exists" in out
        assert "[FAIL] Demo-Tag: HTTP 400 bad colour" in out
        assert "Created: 0 | Skipped: 2 | Failed: 1" in out
        assert "1 object(s) failed" in out

    def test_container_failure_aborts(self) -> None:
        client = MagicMock()
        client.snippet.create.side_effect = RuntimeError("403 forbidden")
        out = _run(client, dry_run=False, associate_folder="Branch")
        assert "Could not create snippet: 403 forbidden" in out
        assert out.endswith("Aborting — snippet container is required.")
        client.anti_spyware_profile.create.assert_not_called()
        client.session.get.assert_not_called()


class TestFolderAssociation:
    def test_associates_with_full_folder_body(self) -> None:
        client = MagicMock()
        client.session = _session("Branch", ["Existing"])
        out = _run(client, dry_run=False, associate_folder="Branch")
        url = client.session.put.call_args.args[0]
        body = client.session.put.call_args.kwargs["json"]
        assert url == f"{SETUP}/folders/f-1"
        assert body == {"name": "Branch", "parent": "All", "snippets": ["Existing", "Demo-Snippet"]}
        assert "[OK] Associated snippet 'Demo-Snippet' with folder 'Branch'" in out
        assert "1. Push folder 'Branch' to activate" in out
        assert "Assign this snippet" not in out

    def test_shared_maps_to_prisma_access(self) -> None:
        client = MagicMock()
        client.session = _session("Prisma Access", [])
        out = _run(client, dry_run=False, associate_folder="Shared")
        assert client.session.put.call_args.kwargs["json"]["snippets"] == ["Demo-Snippet"]
        assert "with folder 'Shared'" in out

    def test_already_associated_skips_put(self) -> None:
        client = MagicMock()
        client.session = _session("Branch", ["Demo-Snippet"])
        out = _run(client, dry_run=False, associate_folder="Branch")
        client.session.put.assert_not_called()
        assert "already associated with folder 'Branch'" in out

    def test_failure_is_reported_not_raised(self) -> None:
        client = MagicMock()
        client.session = _session("Branch", [], put_status=500)
        out = _run(client, dry_run=False, associate_folder="Branch")
        assert "[FAIL] Could not associate with 'Branch': HTTP 500" in out
        assert "1. Associate this snippet with folder 'Branch' via the SCM portal" in out

        client.session = _session("Branch", [])
        out = _run(client, dry_run=False, associate_folder="Nowhere")
        assert "target folder `Nowhere` not found" in out

    def test_skipped_when_an_object_failed(self) -> None:
        client = MagicMock()
        client.tag.create.side_effect = RuntimeError("boom")
        out = _run(client, dry_run=False, associate_folder="Branch")
        assert "[SKIP] Not associating with 'Branch' — 1 object(s) failed" in out
        client.session.get.assert_not_called()
        client.session.put.assert_not_called()
