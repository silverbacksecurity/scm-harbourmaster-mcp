"""Unit tests for the non-interactive scm-mcp-cli subcommands (cli_commands.py)."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import SecretStr

from scm_harbourmaster_mcp import cli, cli_commands, cli_ops, history
from scm_harbourmaster_mcp.config.settings import TenantConfig


def _tenant(key: str, label: str) -> TenantConfig:
    return TenantConfig(
        tenant_id=f"tsg-{key}",
        client_id="svc@iam.panserviceaccount.com",
        client_secret=SecretStr("s3cr3t"),
        default_folder="Shared",
        label=label,
        tier="gold",
    )


@pytest.fixture(autouse=True)
def _isolated_history(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "logs" / "cli_history.jsonl"
    monkeypatch.setattr(history, "HISTORY_PATH", path)
    return path


@pytest.fixture
def one_tenant(monkeypatch: pytest.MonkeyPatch) -> dict[str, TenantConfig]:
    tenants = {"acme": _tenant("acme", "Acme Corp")}
    monkeypatch.setattr(cli, "_load_all_tenants", lambda: tenants)
    return tenants


@pytest.fixture
def two_tenants(monkeypatch: pytest.MonkeyPatch) -> dict[str, TenantConfig]:
    tenants = {"acme": _tenant("acme", "Acme Corp"), "contoso": _tenant("contoso", "Contoso Ltd")}
    monkeypatch.setattr(cli, "_load_all_tenants", lambda: tenants)
    return tenants


class TestBuildParser:
    def test_requires_tenant_or_all_tenants(self) -> None:
        parser = cli_commands.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["backup"])

    def test_rejects_both_tenant_and_all_tenants(self) -> None:
        parser = cli_commands.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["backup", "--tenant", "acme", "--all-tenants"])

    def test_accepts_tenant(self) -> None:
        parser = cli_commands.build_parser()
        args = parser.parse_args(["backup", "--tenant", "acme"])
        assert args.tenant == "acme"
        assert args.all_tenants is False
        assert args.quiet is False

    def test_ncsc_framework_default_and_choices(self) -> None:
        parser = cli_commands.build_parser()
        args = parser.parse_args(["ncsc", "--tenant", "acme"])
        assert args.framework == "all"
        with pytest.raises(SystemExit):
            parser.parse_args(["ncsc", "--tenant", "acme", "--framework", "bogus"])

    def test_list_tenants_and_history_need_no_tenant_arg(self) -> None:
        parser = cli_commands.build_parser()
        assert parser.parse_args(["list-tenants"]).command == "list-tenants"
        assert parser.parse_args(["history"]).command == "history"


class TestDispatchBackup:
    def test_success_prints_result_and_logs_history(
        self,
        one_tenant: dict[str, TenantConfig],
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        fake_result = cli_ops.BackupResult(
            path=Path("backups/fake.json"),
            size_kb=1,
            prisma_counts={},
            sdwan_counts=None,
            sdwan_error=None,
            extraction_errors=[],
        )
        monkeypatch.setattr(cli_ops, "run_backup", lambda tenant, on_progress=None: fake_result)

        parser = cli_commands.build_parser()
        args = parser.parse_args(["backup", "--tenant", "acme", "--quiet"])
        exit_code = cli_commands.dispatch(args)

        assert exit_code == 0
        out = capsys.readouterr().out
        assert "[acme] backup: OK -> backups/fake.json" in out

        entries = history.read_history()
        assert len(entries) == 1
        assert entries[0] == {
            "ts": entries[0]["ts"],
            "action": "backup",
            "tenant_id": "tsg-acme",
            "tenant_label": "Acme Corp",
            "status": "ok",
            "detail": "",
            "source": "cli",
        }

    def test_failure_returns_nonzero_and_logs_error(
        self,
        one_tenant: dict[str, TenantConfig],
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        def _boom(tenant: TenantConfig, on_progress: object = None) -> None:
            raise RuntimeError("auth failed")

        monkeypatch.setattr(cli_ops, "run_backup", _boom)

        parser = cli_commands.build_parser()
        args = parser.parse_args(["backup", "--tenant", "acme", "--quiet"])
        exit_code = cli_commands.dispatch(args)

        assert exit_code == 1
        err = capsys.readouterr().err
        assert "[acme] backup: FAILED" in err
        assert "auth failed" in err

        entries = history.read_history()
        assert entries[0]["status"] == "error"
        assert "auth failed" in entries[0]["detail"]

    def test_unknown_tenant_key_fails_without_calling_run_backup(
        self,
        one_tenant: dict[str, TenantConfig],
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        called = False

        def _should_not_run(tenant: TenantConfig, on_progress: object = None) -> None:
            nonlocal called
            called = True

        monkeypatch.setattr(cli_ops, "run_backup", _should_not_run)

        parser = cli_commands.build_parser()
        args = parser.parse_args(["backup", "--tenant", "does-not-exist", "--quiet"])
        exit_code = cli_commands.dispatch(args)

        assert exit_code == 1
        assert not called
        assert "Unknown tenant key" in capsys.readouterr().err

    def test_all_tenants_continues_past_a_failure(
        self,
        two_tenants: dict[str, TenantConfig],
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        fake_result = cli_ops.BackupResult(
            path=Path("backups/ok.json"),
            size_kb=1,
            prisma_counts={},
            sdwan_counts=None,
            sdwan_error=None,
            extraction_errors=[],
        )

        def _maybe_boom(tenant: TenantConfig, on_progress: object = None) -> cli_ops.BackupResult:
            if tenant.label == "Contoso Ltd":
                raise RuntimeError("boom")
            return fake_result

        monkeypatch.setattr(cli_ops, "run_backup", _maybe_boom)

        parser = cli_commands.build_parser()
        args = parser.parse_args(["backup", "--all-tenants", "--quiet"])
        exit_code = cli_commands.dispatch(args)

        assert exit_code == 1  # at least one tenant failed
        captured = capsys.readouterr()
        assert "[acme] backup: OK" in captured.out
        assert "[contoso] backup: FAILED" in captured.err
        assert len(history.read_history()) == 2


class TestDispatchOtherCommands:
    def test_list_tenants(
        self, two_tenants: dict[str, TenantConfig], capsys: pytest.CaptureFixture[str]
    ) -> None:
        parser = cli_commands.build_parser()
        args = parser.parse_args(["list-tenants"])
        exit_code = cli_commands.dispatch(args)
        assert exit_code == 0
        out = capsys.readouterr().out
        assert "acme" in out
        assert "contoso" in out

    def test_history_empty(self, capsys: pytest.CaptureFixture[str]) -> None:
        parser = cli_commands.build_parser()
        args = parser.parse_args(["history"])
        exit_code = cli_commands.dispatch(args)
        assert exit_code == 0
        assert "No history yet." in capsys.readouterr().out

    def test_history_shows_entries(self, capsys: pytest.CaptureFixture[str]) -> None:
        history.log_action("backup", "tsg-1", "Acme", "ok", source="cli")
        parser = cli_commands.build_parser()
        args = parser.parse_args(["history", "--limit", "5"])
        exit_code = cli_commands.dispatch(args)
        assert exit_code == 0
        out = capsys.readouterr().out
        assert "backup" in out
        assert "Acme" in out

    def test_ncsc_passes_framework_through(
        self, one_tenant: dict[str, TenantConfig], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: dict[str, str] = {}

        def _fake_run_ncsc(
            tenant: TenantConfig, framework: str, on_progress: object = None
        ) -> object:
            seen["framework"] = framework
            return cli_ops.NcscResult(
                path=Path("backups/ncsc.json"),
                framework=framework,
                folder="Shared",
                controls=[],
                total=0,
                compliant=0,
                non_compliant=0,
                not_assessed=0,
            )

        monkeypatch.setattr(cli_ops, "run_ncsc", _fake_run_ncsc)

        parser = cli_commands.build_parser()
        args = parser.parse_args(["ncsc", "--tenant", "acme", "--framework", "caf", "--quiet"])
        exit_code = cli_commands.dispatch(args)

        assert exit_code == 0
        assert seen["framework"] == "caf"
