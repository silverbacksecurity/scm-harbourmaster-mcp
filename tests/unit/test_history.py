"""Unit tests for the CLI action history log (history.py)."""

from __future__ import annotations

from pathlib import Path

import pytest

from scm_harbourmaster_mcp import history


@pytest.fixture(autouse=True)
def _isolated_history(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "logs" / "cli_history.jsonl"
    monkeypatch.setattr(history, "HISTORY_PATH", path)
    return path


class TestLogAndReadHistory:
    def test_round_trip(self) -> None:
        history.log_action("backup", "tsg-1", "Acme", "ok", detail="", source="menu")
        entries = history.read_history()
        assert len(entries) == 1
        assert entries[0]["action"] == "backup"
        assert entries[0]["tenant_id"] == "tsg-1"
        assert entries[0]["tenant_label"] == "Acme"
        assert entries[0]["status"] == "ok"
        assert entries[0]["source"] == "menu"
        assert "ts" in entries[0]

    def test_read_returns_newest_first(self) -> None:
        history.log_action("backup", "tsg-1", "Acme", "ok")
        history.log_action("bpa", "tsg-1", "Acme", "ok")
        history.log_action("ncsc", "tsg-1", "Acme", "ok")
        entries = history.read_history()
        assert [e["action"] for e in entries] == ["ncsc", "bpa", "backup"]

    def test_read_respects_limit(self) -> None:
        for i in range(5):
            history.log_action(f"action-{i}", None, None, "ok")
        entries = history.read_history(limit=2)
        assert len(entries) == 2
        assert entries[0]["action"] == "action-4"
        assert entries[1]["action"] == "action-3"

    def test_read_missing_file_returns_empty(self) -> None:
        assert history.read_history() == []

    def test_log_action_never_raises_on_write_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Point HISTORY_PATH at a location whose parent can't be created
        # (a file, not a directory) — log_action must swallow the error.
        blocker = tmp_path / "not-a-dir"
        blocker.write_text("x")
        monkeypatch.setattr(history, "HISTORY_PATH", blocker / "sub" / "cli_history.jsonl")
        history.log_action("backup", "tsg-1", "Acme", "ok")  # must not raise

    def test_read_skips_malformed_lines(self, tmp_path: Path) -> None:
        history.HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
        history.HISTORY_PATH.write_text('{"action": "good", "status": "ok"}\nnot json\n')
        entries = history.read_history()
        assert len(entries) == 1
        assert entries[0]["action"] == "good"


class _FakeTenant:
    def __init__(self, tenant_id: str, label: str) -> None:
        self.tenant_id = tenant_id
        self.label = label


class TestAudited:
    def test_logs_ok_on_success_with_tenant_arg(self) -> None:
        @history.audited("backup")
        def op(tenant: _FakeTenant) -> str:
            return "done"

        result = op(_FakeTenant("tsg-1", "Acme"))
        assert result == "done"

        entries = history.read_history()
        assert len(entries) == 1
        assert entries[0] == {
            "ts": entries[0]["ts"],
            "action": "backup",
            "tenant_id": "tsg-1",
            "tenant_label": "Acme",
            "status": "ok",
            "detail": "",
            "source": "menu",
        }

    def test_logs_error_and_reraises_on_exception(self) -> None:
        @history.audited("bpa")
        def op(tenant: _FakeTenant) -> None:
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError, match="boom"):
            op(_FakeTenant("tsg-2", "Contoso"))

        entries = history.read_history()
        assert len(entries) == 1
        assert entries[0]["status"] == "error"
        assert "boom" in entries[0]["detail"]
        assert entries[0]["tenant_id"] == "tsg-2"

    def test_logs_no_tenant_for_zero_arg_functions(self) -> None:
        @history.audited("restart_server")
        def op() -> None:
            return None

        op()
        entries = history.read_history()
        assert entries[0]["tenant_id"] is None
        assert entries[0]["tenant_label"] is None
