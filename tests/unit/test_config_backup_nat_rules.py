"""Both config-backup writers must persist NAT rules per rulebase (no network).

The extractor splits NAT rules into nat_rules_pre / nat_rules_post; the flat
``nat_rules`` field it leaves empty, so a backup that only wrote the flat key
carried no NAT rules at all.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP
from pydantic import SecretStr

from scm_harbourmaster_mcp import cli_ops
from scm_harbourmaster_mcp.audit import extractor as extractor_mod
from scm_harbourmaster_mcp.audit.models import AuditSnapshot
from scm_harbourmaster_mcp.config.settings import TenantConfig
from scm_harbourmaster_mcp.tools import audit as audit_mod

PRE = [{"name": "nat-pre", "folder": "All", "_position": "pre"}]
POST = [{"name": "nat-post", "folder": "All", "_position": "post"}]


def _snapshot() -> AuditSnapshot:
    snap = AuditSnapshot(tenant_id="1234567890", folder="All")
    snap.nat_rules_pre = list(PRE)
    snap.nat_rules_post = list(POST)
    return snap


@pytest.fixture
def in_tmp_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_mcp_backup_tool_writes_split_nat_keys(in_tmp_cwd, monkeypatch):
    monkeypatch.setattr(audit_mod, "extract_snapshot", lambda *a, **k: _snapshot())
    mcp = FastMCP("test")
    audit_mod.register_audit_tools(mcp, lambda tenant_id="": object())

    out = mcp._tool_manager.get_tool("scm_config_backup").fn(tenant_id="1234567890", folder="All")

    path = Path(out.split("Backup written to: ")[1].splitlines()[0])
    resources = json.loads(path.read_text())["resources"]
    assert resources["nat_rules_pre"] == PRE
    assert resources["nat_rules_post"] == POST
    assert resources["nat_rules"] == []


def test_cli_backup_writes_split_nat_keys(in_tmp_cwd, monkeypatch):
    def _fail_sdwan(_tenant: Any) -> Any:
        raise RuntimeError("no SD-WAN in this test")

    monkeypatch.setattr(extractor_mod, "extract_snapshot", lambda *a, **k: _snapshot())
    monkeypatch.setattr("scm_harbourmaster_mcp.auth.oauth.get_scm_client", lambda _t: object())
    monkeypatch.setattr("scm_harbourmaster_mcp.auth.sdwan.get_sdwan_client", _fail_sdwan)

    tenant = TenantConfig(
        tenant_id="1234567890",
        client_id="svc@iam.panserviceaccount.com",
        client_secret=SecretStr("s3cr3t"),
        default_folder="All",
        label="Acme Corp",
    )
    result = cli_ops.run_backup(tenant)

    resources = json.loads(result.path.read_text())["resources"]
    assert resources["nat_rules_pre"] == PRE
    assert resources["nat_rules_post"] == POST
    assert resources["nat_rules"] == []


def test_cloned_backup_replays_split_nat_keys(in_tmp_cwd, monkeypatch):
    """The keys the writers emit are the ones the cloner pushes."""
    from scm_harbourmaster_mcp.audit import cloner

    monkeypatch.setattr(audit_mod, "extract_snapshot", lambda *a, **k: _snapshot())
    mcp = FastMCP("test")
    audit_mod.register_audit_tools(mcp, lambda tenant_id="": object())
    out = mcp._tool_manager.get_tool("scm_config_backup").fn(tenant_id="1234567890", folder="All")
    path = out.split("Backup written to: ")[1].splitlines()[0]

    calls: list[tuple[dict[str, Any], dict[str, Any]]] = []

    class Resource:
        def create(self, data, **kwargs):
            calls.append((data, kwargs))
            return data

    class Client:
        def __getattr__(self, name):
            return Resource()

    cloner.clone_config(Client(), path, "dst", dry_run=False)

    assert [(d["name"], k) for d, k in calls] == [
        ("nat-pre", {"position": "pre"}),
        ("nat-post", {"position": "post"}),
    ]


def test_backup_writers_persist_gp_and_infra_resources(in_tmp_cwd, monkeypatch):
    """The extended writers carry GP settings and network infrastructure keys."""
    snap = _snapshot()
    snap.mobile_agent_auth_settings = [{"name": "auths-1", "folder": "Mobile Users"}]
    snap.mobile_agent_tunnel_profiles = [{"name": "tp-1", "folder": "Mobile Users"}]
    snap.mobile_agent_infrastructure = [{"name": "infra-1", "folder": "Mobile Users"}]
    snap.mobile_agent_global_settings = {"totp_tunnel_profile": "tp-1"}
    snap.forwarding_profiles = [{"name": "fp-1", "folder": "Mobile Users"}]
    snap.authentication_profiles = [{"name": "authp-1", "folder": "All"}]
    snap.internal_dns_servers = [{"name": "dns-1", "folder": "Remote Networks"}]
    snap.network_locations = [{"name": "loc-1"}]
    snap.bgp_routing_config = {"backbone_routing": "no-export"}
    snap.qos_profiles = [{"name": "qos-1", "folder": "Remote Networks"}]
    snap.ike_crypto_profiles = [{"name": "ike-1", "folder": "Remote Networks"}]

    monkeypatch.setattr(audit_mod, "extract_snapshot", lambda *a, **k: snap)
    mcp = FastMCP("test")
    audit_mod.register_audit_tools(mcp, lambda tenant_id="": object())
    out = mcp._tool_manager.get_tool("scm_config_backup").fn(tenant_id="1234567890", folder="All")
    path = out.split("Backup written to: ")[1].splitlines()[0]
    resources = json.loads(Path(path).read_text())["resources"]

    assert resources["mobile_agent_auth_settings"] == [
        {"name": "auths-1", "folder": "Mobile Users"}
    ]
    assert resources["mobile_agent_tunnel_profiles"] == [{"name": "tp-1", "folder": "Mobile Users"}]
    assert resources["mobile_agent_infrastructure"] == [
        {"name": "infra-1", "folder": "Mobile Users"}
    ]
    assert resources["mobile_agent_global_settings"] == {"totp_tunnel_profile": "tp-1"}
    assert resources["forwarding_profiles"] == [{"name": "fp-1", "folder": "Mobile Users"}]
    assert resources["authentication_profiles"] == [{"name": "authp-1", "folder": "All"}]
    assert resources["internal_dns_servers"] == [{"name": "dns-1", "folder": "Remote Networks"}]
    assert resources["network_locations"] == [{"name": "loc-1"}]
    assert resources["bgp_routing_config"] == {"backbone_routing": "no-export"}
    assert resources["qos_profiles"] == [{"name": "qos-1", "folder": "Remote Networks"}]
    assert resources["ike_crypto_profiles"] == [{"name": "ike-1", "folder": "Remote Networks"}]
