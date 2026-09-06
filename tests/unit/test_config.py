"""Unit tests for config/settings module."""

from __future__ import annotations

import os

import pytest

from scm_harbourmaster_mcp.config.settings import Settings, TenantConfig


class TestTenantConfig:
    def test_valid_config(self) -> None:
        tc = TenantConfig(
            tenant_id="tsg-123",
            client_id="svc@iam.panserviceaccount.com",
            client_secret="s3cr3t",
            default_folder="Acme",
        )
        assert tc.tenant_id == "tsg-123"
        assert tc.default_folder == "Acme"

    def test_empty_tenant_id_raises(self) -> None:
        with pytest.raises(ValueError):
            TenantConfig(
                tenant_id="   ",
                client_id="svc@iam.panserviceaccount.com",
                client_secret="s3cr3t",
            )

    def test_secret_not_leaked_in_repr(self) -> None:
        tc = TenantConfig(
            tenant_id="t1",
            client_id="svc@iam.panserviceaccount.com",
            client_secret="super-secret",
        )
        assert "super-secret" not in repr(tc)


class TestSettings:
    def test_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for k in list(os.environ.keys()):
            if k.startswith("SCM_MCP_"):
                monkeypatch.delenv(k, raising=False)
        # Settings should instantiate with defaults without error
        s = Settings()
        assert s.log_level == "INFO"
        assert s.mssp_mode is False

    def test_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SCM_MCP_LOG_LEVEL", "DEBUG")
        monkeypatch.setenv("SCM_MCP_MSSP_MODE", "true")
        s = Settings()
        assert s.log_level == "DEBUG"
        assert s.mssp_mode is True
