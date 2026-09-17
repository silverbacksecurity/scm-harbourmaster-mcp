"""Write-safety (SSR pattern) tests for the legacy SCM write tools.

Every tool that mutates SCM must:
  * default to ``dry_run=True`` and make no mutating call in a dry run,
  * reject a call without ``ticket_ref`` before touching the API,
  * execute for real only with ``dry_run=False`` + ``ticket_ref``, and
  * never put ``ticket_ref`` into the request body sent to SCM.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.tools import audit as audit_tools
from scm_harbourmaster_mcp.tools.adnsr import register_adnsr_tools
from scm_harbourmaster_mcp.tools.deployment import register_deployment_tools
from scm_harbourmaster_mcp.tools.dlp import register_dlp_tools
from scm_harbourmaster_mcp.tools.ncsc_baseline import register_ncsc_tools
from scm_harbourmaster_mcp.tools.objects import register_object_tools
from scm_harbourmaster_mcp.tools.ops import register_ops_tools
from scm_harbourmaster_mcp.tools.security import register_security_tools
from scm_harbourmaster_mcp.utils.write_safety import (
    TICKET_REF_REQUIRED,
    normalize_ticket_ref,
    ticket_ref_error,
)

TENANT = "1234567890"
TICKET = "CHG-4242"


def _tool(register: Any, name: str, client: Any) -> Any:
    mcp = FastMCP("test-write-safety")
    register(mcp, lambda tenant_id="": client)
    return mcp._tool_manager.get_tool(name).fn  # noqa: SLF001


def _model(**fields: Any) -> MagicMock:
    obj = MagicMock()
    for k, v in fields.items():
        setattr(obj, k, v)
    obj.model_dump.return_value = dict(fields)
    return obj


# ── helper ────────────────────────────────────────────────────────────────


def test_ticket_ref_helpers() -> None:
    assert ticket_ref_error("") == TICKET_REF_REQUIRED
    assert ticket_ref_error("   ") == TICKET_REF_REQUIRED
    assert ticket_ref_error(None) == TICKET_REF_REQUIRED
    assert ticket_ref_error(TICKET) == ""
    assert normalize_ticket_ref(f"  {TICKET} ") == TICKET


# ── addresses ─────────────────────────────────────────────────────────────


class TestAddressCreate:
    def _client(self) -> MagicMock:
        client = MagicMock()
        client.address.fetch.side_effect = Exception("not found")
        client.address.create.return_value = _model(id="a-1", name="web1")
        return client

    def test_dry_run_is_default(self) -> None:
        client = self._client()
        fn = _tool(register_object_tools, "scm_address_create", client)
        out = json.loads(
            fn(
                tenant_id=TENANT,
                name="web1",
                folder="Shared",
                ip_netmask="10.0.0.1/32",
                ticket_ref=TICKET,
            )
        )
        assert out["dry_run"] is True
        assert out["ticket_ref"] == TICKET
        assert out["planned_payload"]["ip_netmask"] == "10.0.0.1/32"
        assert out["existing_object"] is None
        client.address.create.assert_not_called()

    def test_missing_ticket_ref_rejected(self) -> None:
        client = self._client()
        fn = _tool(register_object_tools, "scm_address_create", client)
        out = fn(name="web1", folder="Shared", ip_netmask="10.0.0.1/32", dry_run=False)
        assert "ticket_ref is mandatory" in out
        client.address.create.assert_not_called()
        client.address.fetch.assert_not_called()

    def test_real_execution(self) -> None:
        client = self._client()
        fn = _tool(register_object_tools, "scm_address_create", client)
        out = json.loads(
            fn(
                name="web1",
                folder="Shared",
                ip_netmask="10.0.0.1/32",
                dry_run=False,
                ticket_ref=TICKET,
            )
        )
        assert out["applied"] is True
        assert out["result"]["id"] == "a-1"
        payload = client.address.create.call_args.args[0]
        assert "ticket_ref" not in payload
        assert TICKET not in json.dumps(payload)


class TestAddressDelete:
    def _client(self) -> MagicMock:
        client = MagicMock()
        client.address.fetch.return_value = _model(id="a-1", name="web1", folder="Shared")
        return client

    def test_dry_run_is_default_and_shows_target(self) -> None:
        client = self._client()
        fn = _tool(register_object_tools, "scm_address_delete", client)
        out = json.loads(fn(name="web1", folder="Shared", ticket_ref=TICKET))
        assert out["dry_run"] is True
        assert out["current_state"]["id"] == "a-1"
        client.address.delete.assert_not_called()

    def test_missing_ticket_ref_rejected(self) -> None:
        client = self._client()
        fn = _tool(register_object_tools, "scm_address_delete", client)
        out = fn(name="web1", folder="Shared", dry_run=False)
        assert "ticket_ref is mandatory" in out
        client.address.delete.assert_not_called()

    def test_real_execution(self) -> None:
        client = self._client()
        fn = _tool(register_object_tools, "scm_address_delete", client)
        out = fn(name="web1", folder="Shared", dry_run=False, ticket_ref=TICKET)
        client.address.delete.assert_called_once_with("a-1")
        assert "Deleted address 'web1'" in out
        assert TICKET in out


# ── security rules ────────────────────────────────────────────────────────


class TestSecurityRuleCreate:
    _args: dict[str, Any] = {
        "name": "allow-web",
        "folder": "Shared",
        "action": "allow",
        "source_zones": ["trust"],
        "destination_zones": ["untrust"],
    }

    def test_dry_run_is_default(self) -> None:
        client = MagicMock()
        client.security_rule.fetch.return_value = _model(id="r-1", name="allow-web")
        fn = _tool(register_security_tools, "scm_security_rule_create", client)
        out = json.loads(fn(**self._args, ticket_ref=TICKET))
        assert out["dry_run"] is True
        assert out["planned_payload"]["from"] == ["trust"]
        assert out["existing_rule"]["id"] == "r-1"  # name collision surfaced
        client.security_rule.create.assert_not_called()

    def test_missing_ticket_ref_rejected(self) -> None:
        client = MagicMock()
        fn = _tool(register_security_tools, "scm_security_rule_create", client)
        out = fn(**self._args, dry_run=False)
        assert "ticket_ref is mandatory" in out
        client.security_rule.create.assert_not_called()

    def test_real_execution(self) -> None:
        client = MagicMock()
        client.security_rule.create.return_value = _model(id="r-2", name="allow-web")
        fn = _tool(register_security_tools, "scm_security_rule_create", client)
        out = json.loads(fn(**self._args, dry_run=False, ticket_ref=TICKET))
        assert out["applied"] is True
        payload = client.security_rule.create.call_args.args[0]
        assert TICKET not in json.dumps(payload)


class TestSecurityRuleDelete:
    def _client(self) -> MagicMock:
        client = MagicMock()
        client.security_rule.fetch.return_value = _model(id="r-1", name="allow-web")
        return client

    def test_dry_run_is_default(self) -> None:
        client = self._client()
        fn = _tool(register_security_tools, "scm_security_rule_delete", client)
        out = json.loads(fn(name="allow-web", folder="Shared", ticket_ref=TICKET))
        assert out["dry_run"] is True
        assert out["current_state"]["name"] == "allow-web"
        client.security_rule.delete.assert_not_called()

    def test_missing_ticket_ref_rejected(self) -> None:
        client = self._client()
        fn = _tool(register_security_tools, "scm_security_rule_delete", client)
        assert "ticket_ref is mandatory" in fn(name="allow-web", folder="Shared", dry_run=False)
        client.security_rule.delete.assert_not_called()

    def test_real_execution(self) -> None:
        client = self._client()
        fn = _tool(register_security_tools, "scm_security_rule_delete", client)
        fn(name="allow-web", folder="Shared", dry_run=False, ticket_ref=TICKET)
        client.security_rule.delete.assert_called_once_with("r-1")


# ── commit / push / rollback ──────────────────────────────────────────────


def _deploy_client() -> MagicMock:
    client = MagicMock()
    client.get.return_value = {
        "data": [{"device": "Remote Networks", "version": 41}, {"device": "Other", "version": 7}]
    }
    client.commit.return_value = SimpleNamespace(job_id="job-9", status="OK")
    return client


class TestCommit:
    def test_dry_run_is_default(self) -> None:
        client = _deploy_client()
        fn = _tool(register_deployment_tools, "scm_commit", client)
        out = json.loads(fn(folders=["Remote Networks"], ticket_ref=TICKET))
        assert out["dry_run"] is True
        assert out["running_versions"] == {"Remote Networks": 41}
        client.commit.assert_not_called()

    def test_missing_ticket_ref_rejected(self) -> None:
        client = _deploy_client()
        fn = _tool(register_deployment_tools, "scm_commit", client)
        assert "ticket_ref is mandatory" in fn(folders=["Remote Networks"], dry_run=False)
        client.commit.assert_not_called()

    def test_real_execution_keeps_ticket_out_of_description(self) -> None:
        client = _deploy_client()
        fn = _tool(register_deployment_tools, "scm_commit", client)
        fn(
            folders=["Remote Networks"],
            description="Weekly change",
            dry_run=False,
            ticket_ref=TICKET,
        )
        client.commit.assert_called_once()
        kwargs = client.commit.call_args.kwargs
        assert kwargs["folders"] == ["Remote Networks"]
        assert kwargs["description"] == "Weekly change"


class TestConfigPushTrack:
    def test_dry_run_is_default(self) -> None:
        client = _deploy_client()
        fn = _tool(register_deployment_tools, "scm_config_push_track", client)
        out = json.loads(fn(folders=["Remote Networks"], ticket_ref=TICKET))
        assert out["dry_run"] is True
        client.commit.assert_not_called()

    def test_missing_ticket_ref_rejected(self) -> None:
        client = _deploy_client()
        fn = _tool(register_deployment_tools, "scm_config_push_track", client)
        assert "ticket_ref is mandatory" in fn(folders=["Remote Networks"], dry_run=False)
        client.commit.assert_not_called()

    def test_real_execution(self) -> None:
        client = _deploy_client()
        job = SimpleNamespace(
            result_str="OK",
            status_str="FIN",
            percent=100,
            details="",
            summary="",
            start_ts=None,
            end_ts=None,
        )
        client.wait_for_job.return_value = SimpleNamespace(data=[job])
        fn = _tool(register_deployment_tools, "scm_config_push_track", client)
        out = fn(folders=["Remote Networks"], dry_run=False, ticket_ref=TICKET)
        client.commit.assert_called_once()
        assert "Config Push — OK" in out


class TestConfigRollback:
    def _client(self) -> MagicMock:
        client = MagicMock()
        client.get.return_value = {"version": 40, "description": "known good", "admin": "ops"}
        client.commit.return_value = SimpleNamespace(job_id="job-10")
        return client

    def test_dry_run_is_default(self) -> None:
        client = self._client()
        fn = _tool(register_deployment_tools, "scm_config_rollback", client)
        out = fn(version=40, commit_immediately=True, ticket_ref=TICKET)
        assert "DRY-RUN" in out
        assert "known good" in out
        client.post.assert_not_called()
        client.commit.assert_not_called()

    def test_missing_ticket_ref_rejected(self) -> None:
        client = self._client()
        fn = _tool(register_deployment_tools, "scm_config_rollback", client)
        assert "ticket_ref is mandatory" in fn(version=40, dry_run=False)
        client.post.assert_not_called()
        client.get.assert_not_called()

    def test_real_execution(self) -> None:
        client = self._client()
        fn = _tool(register_deployment_tools, "scm_config_rollback", client)
        out = fn(version=40, dry_run=False, ticket_ref=TICKET)
        client.post.assert_called_once()
        assert client.post.call_args.args[0].endswith("/40:load")
        client.commit.assert_not_called()
        assert "Loaded to Candidate" in out


# ── certificates / TLS / ADNSR ────────────────────────────────────────────


@pytest.fixture(scope="module")
def pem() -> str:
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-inspect-ca")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


class TestCertImport:
    def test_dry_run_is_default(self, pem: str) -> None:
        client = MagicMock()
        fn = _tool(register_ops_tools, "scm_cert_import", client)
        out = fn(name="Inspect-CA", pem=pem, is_ca=True, ticket_ref=TICKET)
        assert "DRY-RUN" in out
        assert "test-inspect-ca" in out
        assert "BEGIN CERTIFICATE" not in out
        client.post.assert_not_called()

    def test_missing_ticket_ref_rejected(self, pem: str) -> None:
        client = MagicMock()
        fn = _tool(register_ops_tools, "scm_cert_import", client)
        assert "ticket_ref is mandatory" in fn(name="Inspect-CA", pem=pem, dry_run=False)
        client.post.assert_not_called()

    def test_real_execution(self, pem: str) -> None:
        client = MagicMock()
        client.post.return_value = {"id": "c-1"}
        fn = _tool(register_ops_tools, "scm_cert_import", client)
        fn(name="Inspect-CA", pem=pem, dry_run=False, ticket_ref=TICKET)
        client.post.assert_called_once()
        assert client.post.call_args.args[0] == "/sse/config/v1/certificates:import"
        assert TICKET not in json.dumps(client.post.call_args.kwargs["json"])


class TestTlsProfileCreate:
    def test_list_needs_no_ticket(self) -> None:
        client = MagicMock()
        client.get.return_value = {"data": []}
        fn = _tool(register_ops_tools, "scm_tls_profile_manager", client)
        assert "No TLS service profiles" in fn(action="list")

    def test_dry_run_is_default(self) -> None:
        client = MagicMock()
        fn = _tool(register_ops_tools, "scm_tls_profile_manager", client)
        out = fn(action="create", name="tls-strict", ticket_ref=TICKET)
        assert "DRY-RUN" in out
        assert "tls-strict" in out
        client.post.assert_not_called()

    def test_missing_ticket_ref_rejected(self) -> None:
        client = MagicMock()
        fn = _tool(register_ops_tools, "scm_tls_profile_manager", client)
        assert "ticket_ref is mandatory" in fn(action="create", name="tls-strict", dry_run=False)
        client.post.assert_not_called()

    def test_real_execution(self) -> None:
        client = MagicMock()
        client.post.return_value = {"id": "t-1"}
        fn = _tool(register_ops_tools, "scm_tls_profile_manager", client)
        out = fn(action="create", name="tls-strict", dry_run=False, ticket_ref=TICKET)
        client.post.assert_called_once()
        assert "created" in out


class TestAdnsrProfileCreate:
    def test_dry_run_is_default(self) -> None:
        client = MagicMock()
        fn = _tool(register_adnsr_tools, "scm_adnsr_profile_create", client)
        out = fn(name="dns-prof", ticket_ref=TICKET)
        assert "DRY-RUN" in out
        client.session.post.assert_not_called()

    def test_missing_ticket_ref_rejected(self) -> None:
        client = MagicMock()
        fn = _tool(register_adnsr_tools, "scm_adnsr_profile_create", client)
        assert "ticket_ref is mandatory" in fn(name="dns-prof", dry_run=False)
        client.session.post.assert_not_called()

    def test_real_execution(self) -> None:
        client = MagicMock()
        client.session.post.return_value = MagicMock(
            status_code=201, json=MagicMock(return_value={"id": "p-1"})
        )
        fn = _tool(register_adnsr_tools, "scm_adnsr_profile_create", client)
        out = fn(name="dns-prof", dry_run=False, ticket_ref=TICKET)
        assert "created" in out
        body = client.session.post.call_args.kwargs["json"]
        assert "ticket_ref" not in body


# ── tools that already had dry_run: ticket_ref now mandatory ──────────────


class TestExistingDryRunTools:
    def test_dlp_restore_requires_ticket_ref(self) -> None:
        client = MagicMock()
        fn = _tool(register_dlp_tools, "dlp_restore", client)
        backup = json.dumps({"backup_version": "1.0", "scm_dlp": {"data_objects": [{"name": "o"}]}})
        assert "ticket_ref is mandatory" in fn(backup_json=backup, target_folder="All")
        out = fn(backup_json=backup, target_folder="All", ticket_ref=TICKET)
        assert "DRY-RUN" in out
        assert TICKET in out
        client.session.post.assert_not_called()

    @pytest.mark.parametrize(
        ("tool_name", "kwargs"),
        [
            ("scm_apply_ncsc_baseline", {"folder": "Shared"}),
            ("scm_create_ncsc_snippet", {}),
            ("scm_create_nist_snippet", {}),
        ],
    )
    def test_ncsc_tools_require_ticket_ref(self, tool_name: str, kwargs: dict[str, Any]) -> None:
        client = MagicMock()
        fn = _tool(register_ncsc_tools, tool_name, client)
        assert "ticket_ref is mandatory" in fn(**kwargs, dry_run=False)
        client.snippet.create.assert_not_called()
        out = fn(**kwargs, ticket_ref=TICKET)
        assert "DRY-RUN" in out
        client.snippet.create.assert_not_called()

    def test_attach_ncsc_profiles_requires_ticket_ref(self) -> None:
        client = MagicMock()
        fn = _tool(register_ncsc_tools, "scm_attach_ncsc_profiles", client)
        assert "ticket_ref is mandatory" in fn(folder="Shared", dry_run=False)
        client.session.post.assert_not_called()
        client.security_rule.update.assert_not_called()

    def test_config_clone_requires_ticket_ref(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[dict[str, Any]] = []

        def fake_clone(client: Any, **kwargs: Any) -> Any:
            calls.append(kwargs)
            return SimpleNamespace(to_markdown=lambda: "# clone report", target_tenant_id="")

        monkeypatch.setattr(audit_tools, "clone_config", fake_clone)
        mcp = FastMCP("test-clone")
        audit_tools.register_audit_tools(mcp, lambda tenant_id="": MagicMock())
        fn = mcp._tool_manager.get_tool("scm_config_clone").fn  # noqa: SLF001

        out = fn(source_backup_file="backup.json", target_folder="Lab", dry_run=False)
        assert "ticket_ref is mandatory" in out
        assert calls == []

        assert fn(source_backup_file="backup.json", target_folder="Lab", ticket_ref=TICKET) == (
            "# clone report"
        )
        assert calls[0]["dry_run"] is True
        assert "ticket_ref" not in calls[0]
