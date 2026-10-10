"""Tests for the /v1 REST tool gateway (scm_harbourmaster_mcp.gateway).

Runs against the live tool registry (every tool registered on a throwaway
FastMCP, no credentials) with a stub executor, so it covers the real
schemas, manifest classifications and toolsets without touching a tenant.

Fail-closed rules proved here:
  - gateway keys work on /v1 only; the legacy API key doesn't work on /v1
  - NEVER_REST tools are hidden even from a write key with writes enabled
  - write tools need both SCM_MCP_HTTP_REST_WRITE and access = "write"
  - a tenant-limited key can't reach cross-tenant tools, other tenants (by
    TSG ID, label or omission), file-path parameters or widening flags
  - GET /v1/tools and POST .../call agree for every key
  - every tenant-like and path-like parameter in the registry is classified
"""

from __future__ import annotations

import asyncio
import json
import re
from types import SimpleNamespace
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.testclient import TestClient

import scm_harbourmaster_mcp.auth.oauth as oauth
import scm_harbourmaster_mcp.server_http as server_http
from scm_harbourmaster_mcp import server
from scm_harbourmaster_mcp.gateway import keys as gw_keys
from scm_harbourmaster_mcp.gateway import policy, schemas
from scm_harbourmaster_mcp.gateway.app import gateway_routes
from scm_harbourmaster_mcp.tools.reload import register_reload_tool

TENANT_A = "1234567890"
TENANT_B = "2345678901"
LABELS = {"customer-a": TENANT_A, "customer-b": TENANT_B}

RAW_READ_A = "hmg_read-key-for-tenant-a"
RAW_READ_ALL = "hmg_read-key-for-all-tenants"
RAW_WRITE_A = "hmg_write-key-for-tenant-a"
RAW_TWO = "hmg_read-key-for-two-tenants"


def _key(key_id: str, raw: str, **overrides: Any) -> gw_keys.GatewayKey:
    entry = {
        "key_sha256": gw_keys.hash_key(raw),
        "access": "read",
        "tenants": [TENANT_A],
        "toolsets": ["sdwan", "objects", "core", "audit"],
        "rate_per_minute": 100_000,  # the agreement test makes ~700 calls
        **overrides,
    }
    return gw_keys.parse_key(key_id, entry)


KEYS = {
    "read-a": _key("read-a", RAW_READ_A),
    "read-all": _key("read-all", RAW_READ_ALL, tenants=["*"], toolsets=["all"]),
    "write-a": _key("write-a", RAW_WRITE_A, access="write", toolsets=["all"]),
    "two": _key("two", RAW_TWO, tenants=[TENANT_A, TENANT_B]),
}


@pytest.fixture(scope="module")
def registry_mcp() -> FastMCP:
    mcp = FastMCP(name="registry")
    server.register_all_tools(mcp, lambda *a, **k: None, lambda: None)
    register_reload_tool(mcp, reregister=lambda: None)
    return mcp


@pytest.fixture(scope="module")
def registry_tools(registry_mcp) -> list[Any]:
    return asyncio.run(registry_mcp.list_tools())


@pytest.fixture(scope="module")
def toolset_map(registry_mcp) -> dict[str, frozenset[str]]:
    return policy.tools_by_toolset(registry_mcp)


class StubMCP:
    """Real tool list and registry, recorded calls, canned output."""

    def __init__(self, registry: FastMCP, tools: list[Any], output: str = "ok") -> None:
        self._tool_manager = registry._tool_manager
        self._tools = tools
        self.output = output
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.settings = SimpleNamespace(transport_security=None, stateless_http=False)

    async def list_tools(self) -> list[Any]:
        return self._tools

    async def call_tool(self, name: str, args: dict[str, Any]) -> list[Any]:
        self.calls.append((name, args))
        return [SimpleNamespace(text=self.output)]

    def sse_app(self) -> Starlette:
        return Starlette()

    def streamable_http_app(self) -> Starlette:
        return Starlette()


def _fake_resolve(value: str, *, strict: bool = False) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if raw in LABELS:
        return LABELS[raw]
    if raw.isdigit():
        return raw
    raise oauth.TenantNotFoundError(raw)


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setattr(oauth, "resolve_tenant_id", _fake_resolve)
    monkeypatch.setattr(oauth, "get_tenant_meta", lambda tid: None)
    monkeypatch.setattr(oauth, "list_loaded_tenants", lambda: [TENANT_A, TENANT_B])
    monkeypatch.setattr(policy, "_default_tenant", lambda: "")
    monkeypatch.setenv("SCM_MCP_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("SCM_MCP_HTTP_REST_WRITE", raising=False)
    monkeypatch.delenv("SCM_MCP_GATEWAY_MAX_CHARS", raising=False)


@pytest.fixture
def stub(registry_mcp, registry_tools) -> StubMCP:
    return StubMCP(registry_mcp, registry_tools)


@pytest.fixture
def client(stub) -> TestClient:
    return TestClient(Starlette(routes=gateway_routes(stub, KEYS)))


def _h(raw: str) -> dict[str, str]:
    return {"X-API-Key": raw}


def _visible(client: TestClient, raw: str, **params: str) -> set[str]:
    resp = client.get("/v1/tools", params={"format": "mcp", **params}, headers=_h(raw))
    assert resp.status_code == 200, resp.text
    return {t["name"] for t in resp.json()["tools"]}


def _call(client: TestClient, raw: str, tool: str, **arguments: Any):
    return client.post(f"/v1/tools/{tool}/call", json={"arguments": arguments}, headers=_h(raw))


def _audit(tmp_path) -> list[dict[str, Any]]:
    path = tmp_path / "logs" / "gateway_audit.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


# ─── Keys ────────────────────────────────────────────────────────────────────


class TestKeys:
    def test_authenticate_matches_by_hash(self) -> None:
        assert gw_keys.authenticate(RAW_READ_A, KEYS).key_id == "read-a"
        assert gw_keys.authenticate("hmg_wrong", KEYS) is None
        assert gw_keys.authenticate("", KEYS) is None

    @pytest.mark.parametrize(
        "override, message",
        [
            ({"key_sha256": "abc"}, "SHA-256"),
            ({"access": "admin"}, "access"),
            ({"tenants": []}, "tenants is required"),
            ({"toolsets": []}, "toolsets is required"),
            ({"toolsets": ["nope"]}, "nope"),
            ({"rate_per_minute": 0}, "at least 1"),
        ],
    )
    def test_bad_entries_are_rejected(self, override, message) -> None:
        entry = {
            "key_sha256": gw_keys.hash_key("x"),
            "tenants": ["*"],
            "toolsets": ["core"],
            **override,
        }
        with pytest.raises(gw_keys.KeyConfigError, match=message):
            gw_keys.parse_key("k", entry)

    def test_load_skips_bad_entries(self) -> None:
        raw = {
            "good": {"key_sha256": gw_keys.hash_key("x"), "tenants": ["*"], "toolsets": ["core"]},
            "bad": {"key_sha256": "nope"},
        }
        assert set(gw_keys.load_keys(raw)) == {"good"}

    def test_mint_prints_a_loadable_entry(self, capsys) -> None:
        assert gw_keys.main(["new", "--id", "k1", "--tenants", TENANT_A, "--toolsets", "noc"]) == 0
        out = capsys.readouterr()
        raw_key = re.search(r"(hmg_\S+)", out.err).group(1)
        entry = dict(re.findall(r"^(\w+) = (.+)$", out.out, re.M))
        assert json.loads(entry["key_sha256"]) == gw_keys.hash_key(raw_key)


# ─── Registry classification ─────────────────────────────────────────────────

# Parameters that look path- or tenant-like but are neither. A new match
# fails test_every_* below until it is classified here or in policy.py.
NOT_PATHS = {
    "backup_json",  # dlp_restore: the backup's JSON content, not a path
    "certificate_file_b64",  # file content, base64
    "cert_profile",
    "destination_addresses",
    "destination_zones",
    "max_paths",
    "profile_group_name",
    "profile_id",
    "profile_setting",
    "profile_type",
    "skip_already_profiled",
    "syslog_profile",
    "timeout",
    "update_baseline",
}
_PATHISH = re.compile(
    r"path|file|dir|save|out(put)?_?(to|file|path)?$|^dest|backup|baseline|snapshot", re.I
)


class TestRegistryClassification:
    def test_every_path_like_parameter_is_classified(self, registry_tools) -> None:
        found = {
            p
            for t in registry_tools
            for p in (t.inputSchema or {}).get("properties", {})
            if _PATHISH.search(p)
        }
        unclassified = found - policy.PATH_PARAMS - NOT_PATHS
        assert not unclassified, f"classify in policy.PATH_PARAMS or NOT_PATHS: {unclassified}"
        assert found >= policy.PATH_PARAMS, "stale entries in policy.PATH_PARAMS"

    def test_every_tenant_like_parameter_is_handled(self, registry_tools) -> None:
        for t in registry_tools:
            assert not policy._unhandled_tenant_params(t.inputSchema or {}), t.name

    def test_no_nested_tenant_or_path_parameters(self, registry_tools) -> None:
        # check_call only inspects top-level arguments; fail if that stops being enough.
        def nested_names(node: Any, depth: int) -> set[str]:
            found: set[str] = set()
            if isinstance(node, dict):
                props = node.get("properties")
                if isinstance(props, dict):
                    if depth > 0:
                        found |= set(props)
                    for prop in props.values():
                        found |= nested_names(prop, depth + 1)
                for k in ("items", "anyOf", "allOf", "oneOf", "additionalProperties"):
                    v = node.get(k)
                    for sub in v if isinstance(v, list) else [v]:
                        found |= nested_names(sub, depth + (k != "anyOf"))
            return found

        for t in registry_tools:
            nested = nested_names(schemas.inline_refs(t.inputSchema or {}), 0)
            risky = {n for n in nested if _PATHISH.search(n) or re.search("tenant|tsg", n, re.I)}
            assert not risky - NOT_PATHS, (t.name, risky)

    def test_never_rest_tools_exist(self, registry_tools) -> None:
        names = {t.name for t in registry_tools}
        assert names >= policy.NEVER_REST

    def test_every_tool_belongs_to_a_toolset_or_is_never_rest(
        self, registry_tools, toolset_map
    ) -> None:
        in_toolsets = set().union(*toolset_map.values())
        stray = {t.name for t in registry_tools} - in_toolsets - policy.NEVER_REST
        assert not stray


# ─── Visibility ──────────────────────────────────────────────────────────────


class TestVisibility:
    def test_never_rest_hidden_even_with_writes_enabled(self, client, monkeypatch) -> None:
        monkeypatch.setenv("SCM_MCP_HTTP_REST_WRITE", "1")
        assert not (_visible(client, RAW_WRITE_A) & policy.NEVER_REST)
        assert not (_visible(client, RAW_READ_ALL) & policy.NEVER_REST)

    def test_writes_hidden_by_default(self, client) -> None:
        assert "scm_address_create" not in _visible(client, RAW_WRITE_A)

    def test_writes_need_the_env_flag_and_write_access(self, client, monkeypatch) -> None:
        monkeypatch.setenv("SCM_MCP_HTTP_REST_WRITE", "1")
        assert "scm_address_create" in _visible(client, RAW_WRITE_A)
        assert "scm_address_create" not in _visible(client, RAW_READ_A)

    def test_cross_tenant_tools_hidden_from_limited_keys(self, client) -> None:
        limited = _visible(client, RAW_READ_A)
        assert "mssp_list_tenants" not in limited
        assert "scm_drift_check" not in _visible(client, RAW_TWO)
        assert "mssp_list_tenants" in _visible(client, RAW_READ_ALL)

    def test_limited_keys_only_see_tools_that_take_tenant_id(self, client, stub) -> None:
        schemas_by_name = {t.name: t.inputSchema or {} for t in stub._tools}
        for raw in (RAW_READ_A, RAW_TWO):
            for name in _visible(client, raw):
                assert "tenant_id" in schemas_by_name[name].get("properties", {}), name

    @pytest.mark.parametrize(
        "tool",
        # no tenant selector: default tenant, or a shared job table read by ID
        ["scm_ai_compliance_advisor", "scm_asbuilt_result", "scm_asbuilt_verify"],
    )
    def test_selectorless_tools_hidden_from_limited_keys(self, stub, tool) -> None:
        both = {
            "lim": _key("lim", "hmg_lim", toolsets=["all"]),
            "all": _key("all", "hmg_all", tenants=["*"], toolsets=["all"]),
        }
        c = TestClient(Starlette(routes=gateway_routes(stub, both)))
        assert tool not in _visible(c, "hmg_lim")
        assert tool in _visible(c, "hmg_all")

    def test_unmapped_tool_is_invisible(self, stub) -> None:
        # A tool whose registrar isn't in TOOLSETS belongs to no toolset.
        extra = FastMCP(name="extra")

        @extra.tool()
        def scm_folder_list(tenant_id: str = "") -> str:
            return "rogue"

        everything = {"all": _key("all", "hmg_all", tenants=["*"], toolsets=["all"])}
        rogue = StubMCP(extra, asyncio.run(extra.list_tools()))
        c = TestClient(Starlette(routes=gateway_routes(rogue, everything)))
        assert _visible(c, "hmg_all") == set()

    def test_toolsets_limit_visibility(self, client) -> None:
        tools = _visible(client, RAW_READ_A)
        assert "sdwan_list_sites" in tools
        assert "scm_msr_report" not in tools  # mssp toolset, not on this key

    def test_toolset_query_narrows_and_cannot_widen(self, client, toolset_map) -> None:
        core = toolset_map["core"]  # always included, as everywhere
        narrowed = _visible(client, RAW_READ_A, toolset="sdwan")
        assert any(n.startswith("sdwan_") for n in narrowed)
        assert all(n.startswith("sdwan_") or n in core for n in narrowed)
        assert _visible(client, RAW_READ_A, toolset="mssp") <= core

    def test_unknown_toolset_is_400(self, client) -> None:
        resp = client.get("/v1/tools", params={"toolset": "nope"}, headers=_h(RAW_READ_A))
        assert resp.status_code == 400

    def test_list_and_call_agree(self, client, stub, monkeypatch) -> None:
        monkeypatch.setenv("SCM_MCP_HTTP_REST_WRITE", "1")
        for raw in (RAW_READ_A, RAW_READ_ALL, RAW_WRITE_A, RAW_TWO):
            visible = _visible(client, raw)
            for tool in stub._tools:
                resp = _call(client, raw, tool.name, tenant_id=TENANT_A)
                if tool.name in visible:
                    assert resp.status_code != 404, (raw, tool.name, resp.text)
                else:
                    assert resp.status_code == 404, (raw, tool.name, resp.text)


# ─── Calls ───────────────────────────────────────────────────────────────────


class TestCalls:
    def test_call_runs_with_canonical_tenant(self, client, stub) -> None:
        resp = _call(client, RAW_READ_A, "sdwan_list_sites", tenant_id="customer-a")
        assert resp.status_code == 200
        assert resp.json() == {
            "tool": "sdwan_list_sites",
            "content": "ok",
            "truncated": False,
            "total_chars": 2,
        }
        assert stub.calls == [("sdwan_list_sites", {"tenant_id": TENANT_A})]

    def test_single_tenant_key_fills_tenant_id(self, client, stub) -> None:
        assert _call(client, RAW_READ_A, "sdwan_list_sites").status_code == 200
        assert stub.calls[-1][1]["tenant_id"] == TENANT_A

    def test_multi_tenant_key_must_name_the_tenant(self, client, stub) -> None:
        resp = _call(client, RAW_TWO, "sdwan_list_sites")
        assert resp.status_code == 400
        assert not stub.calls

    @pytest.mark.parametrize("tenant", [TENANT_B, "customer-b", "no-such-customer"])
    def test_other_tenants_refused(self, client, stub, tenant) -> None:
        resp = _call(client, RAW_READ_A, "sdwan_list_sites", tenant_id=tenant)
        assert resp.status_code == 403
        assert not stub.calls

    def test_path_parameters_refused(self, client, stub) -> None:
        resp = _call(client, RAW_READ_A, "scm_audit_report", tenant_id=TENANT_A, save_to="/data/x")
        assert resp.status_code == 403
        assert "file-path" in resp.json()["error"]
        resp = _call(client, RAW_READ_ALL, "scm_audit_report", save_to="/etc/passwd")
        assert resp.status_code == 403
        assert not stub.calls

    def test_widening_flag_refused_for_limited_key(self, client, stub) -> None:
        # scm_config_index takes all_tenants and is visible to a tenant-scoped key
        resp = _call(client, RAW_READ_A, "scm_config_index", tenant_id=TENANT_A, all_tenants=True)
        assert resp.status_code in (403, 404)
        assert not stub.calls

    @pytest.mark.parametrize("flag", sorted(policy.CROSS_TENANT_PARAMS))
    def test_widening_flags_refused_by_check_call(self, flag) -> None:
        schema = {"properties": {"tenant_id": {}, flag: {}}}
        with pytest.raises(policy.GatewayDenied) as exc:
            policy.check_call(KEYS["read-a"], schema, {"tenant_id": TENANT_A, flag: True})
        assert exc.value.status == 403
        args, tenants = policy.check_call(KEYS["read-all"], schema, {flag: True})
        assert args[flag] is True and tenants == []

    def test_target_tenant_checked_like_tenant_id(self) -> None:
        schema = {"properties": {"tenant_id": {}, "target_tenant_id": {}}}
        with pytest.raises(policy.GatewayDenied):
            policy.check_call(
                KEYS["read-a"], schema, {"tenant_id": TENANT_A, "target_tenant_id": TENANT_B}
            )
        args, tenants = policy.check_call(
            KEYS["two"], schema, {"tenant_id": "customer-a", "target_tenant_id": "customer-b"}
        )
        assert (args["tenant_id"], args["target_tenant_id"]) == (TENANT_A, TENANT_B)
        assert sorted(tenants) == [TENANT_A, TENANT_B]

    def test_unknown_argument_is_400(self, client, stub) -> None:
        resp = _call(client, RAW_READ_A, "sdwan_list_sites", tenant_id=TENANT_A, sneaky="1")
        assert resp.status_code == 400
        assert not stub.calls

    def test_not_permitted_looks_like_not_found(self, client) -> None:
        hidden = _call(client, RAW_READ_A, "scm_commit", tenant_id=TENANT_A)
        missing = _call(client, RAW_READ_A, "no_such_tool")
        assert hidden.status_code == missing.status_code == 404
        assert hidden.json() == missing.json()

    def test_planner_run_refused_with_full_write_access(self, client, stub, monkeypatch) -> None:
        monkeypatch.setenv("SCM_MCP_HTTP_REST_WRITE", "1")
        resp = _call(client, RAW_WRITE_A, "scm_planner_run", tenant_id=TENANT_A)
        assert resp.status_code == 404
        assert not stub.calls

    def test_write_runs_only_with_flag_and_access(self, client, stub, monkeypatch) -> None:
        args = {"tenant_id": TENANT_A, "name": "example", "ip_netmask": "192.0.2.1/32"}
        assert _call(client, RAW_WRITE_A, "scm_address_create", **args).status_code == 404
        monkeypatch.setenv("SCM_MCP_HTTP_REST_WRITE", "1")
        assert _call(client, RAW_READ_A, "scm_address_create", **args).status_code == 404
        assert _call(client, RAW_WRITE_A, "scm_address_create", **args).status_code == 200
        assert [c[0] for c in stub.calls] == ["scm_address_create"]

    def test_output_is_capped(self, client, stub, monkeypatch) -> None:
        monkeypatch.setenv("SCM_MCP_GATEWAY_MAX_CHARS", "1000")
        stub.output = "x" * 5000
        body = _call(client, RAW_READ_A, "sdwan_list_sites").json()
        assert body["truncated"] is True and len(body["content"]) == 1000
        assert body["total_chars"] == 5000
        small = client.post(
            "/v1/tools/sdwan_list_sites/call",
            json={"arguments": {}, "max_chars": 10},
            headers=_h(RAW_READ_A),
        ).json()
        assert len(small["content"]) == 10

    def test_rate_limit(self, stub) -> None:
        slow = {"slow": _key("slow", "hmg_slow", rate_per_minute=2)}
        c = TestClient(Starlette(routes=gateway_routes(stub, slow)))
        codes = [_call(c, "hmg_slow", "sdwan_list_sites").status_code for _ in range(3)]
        assert codes == [200, 200, 429]

    def test_llm_provider_policy(self, client, stub, monkeypatch) -> None:
        monkeypatch.setattr(
            oauth,
            "get_tenant_meta",
            lambda tid: SimpleNamespace(allowed_llm_providers=["claude"]),
        )
        resp = _call(client, RAW_READ_A, "sdwan_list_sites")
        assert resp.status_code == 403 and "LLM provider" in resp.json()["error"]
        claude = {"c": _key("c", "hmg_claude", llm_provider="claude")}
        c = TestClient(Starlette(routes=gateway_routes(stub, claude)))
        assert _call(c, "hmg_claude", "sdwan_list_sites").status_code == 200

    @pytest.fixture
    def b_allows_claude_only(self, stub, monkeypatch) -> TestClient:
        policies = {TENANT_B: ["claude"]}
        monkeypatch.setattr(
            oauth,
            "get_tenant_meta",
            lambda tid: SimpleNamespace(allowed_llm_providers=policies.get(tid)),
        )
        deepseek = {
            "ds": _key("ds", "hmg_ds", tenants=["*"], toolsets=["all"], llm_provider="deepseek")
        }
        return TestClient(Starlette(routes=gateway_routes(stub, deepseek)))

    def test_provider_policy_allows_unrestricted_tenant(self, b_allows_claude_only) -> None:
        resp = _call(b_allows_claude_only, "hmg_ds", "sdwan_list_sites", tenant_id=TENANT_A)
        assert resp.status_code == 200

    def test_provider_policy_refuses_named_tenant(self, b_allows_claude_only) -> None:
        resp = _call(b_allows_claude_only, "hmg_ds", "sdwan_list_sites", tenant_id="customer-b")
        assert resp.status_code == 403

    def test_provider_policy_covers_cross_tenant_tools(self, b_allows_claude_only, stub) -> None:
        resp = _call(b_allows_claude_only, "hmg_ds", "mssp_list_tenants")
        assert resp.status_code == 403
        assert not stub.calls

    def test_provider_policy_covers_widening_flags(self, b_allows_claude_only, stub) -> None:
        resp = _call(b_allows_claude_only, "hmg_ds", "scm_incident_summary", all_tenants=True)
        assert resp.status_code == 403
        assert not stub.calls

    def test_provider_policy_covers_the_default_tenant(
        self, b_allows_claude_only, stub, monkeypatch
    ) -> None:
        monkeypatch.setattr(policy, "_default_tenant", lambda: TENANT_B)
        resp = _call(b_allows_claude_only, "hmg_ds", "sdwan_list_sites")
        assert resp.status_code == 403
        assert not stub.calls

    def test_audit_log_records_calls_without_arguments(self, client, tmp_path) -> None:
        _call(client, RAW_READ_A, "sdwan_list_sites", tenant_id=TENANT_A, site_id="secret-site")
        _call(client, RAW_READ_A, "sdwan_list_sites", tenant_id=TENANT_B)
        lines = _audit(tmp_path)
        assert [ln["outcome"] for ln in lines] == ["started", "ok", "denied"]
        assert all(ln["key_id"] == "read-a" for ln in lines)
        assert "secret-site" not in json.dumps(lines)
        assert lines[1]["tenants"] == [TENANT_A]


# ─── Auth boundaries ─────────────────────────────────────────────────────────


class TestAuthBoundaries:
    def test_no_key_is_401(self, client) -> None:
        assert client.get("/v1/tools").status_code == 401
        assert client.post("/v1/tools/x/call", json={"arguments": {}}).status_code == 401

    def test_query_parameter_key_not_accepted(self, client) -> None:
        assert client.get("/v1/tools", params={"api_key": RAW_READ_A}).status_code == 401

    def test_bearer_header_accepted(self, client) -> None:
        resp = client.get("/v1/tools", headers={"Authorization": f"Bearer {RAW_READ_A}"})
        assert resp.status_code == 200

    @pytest.fixture
    def full_app(self, stub, monkeypatch) -> TestClient:
        monkeypatch.setattr(server_http, "create_server", lambda: stub)
        monkeypatch.setattr(server_http, "_AUTH_MODE", "apikey")
        monkeypatch.setattr(server_http, "_API_KEY", "legacy-key")
        monkeypatch.setattr(gw_keys, "load_keys", lambda raw=None: KEYS)
        monkeypatch.setattr("scm_harbourmaster_mcp.gateway.app.load_keys", lambda: KEYS)
        return TestClient(server_http.create_http_app())

    def test_legacy_key_not_valid_on_v1(self, full_app) -> None:
        assert full_app.get("/v1/tools", headers=_h("legacy-key")).status_code == 401
        assert full_app.get("/v1/tools", headers=_h(RAW_READ_A)).status_code == 200

    @pytest.mark.parametrize("path", ["/mcp", "/sse", "/messages/", "/dashboard", "/webhook/ir"])
    def test_gateway_key_not_valid_outside_v1(self, full_app, path) -> None:
        resp = full_app.post(path, json={}, headers=_h(RAW_READ_ALL))
        assert resp.status_code == 401


# ─── Schema formats ──────────────────────────────────────────────────────────


def _keywords(node: Any) -> set[str]:
    """Every schema keyword used anywhere (property names excluded)."""
    found: set[str] = set()
    if isinstance(node, dict):
        for k, v in node.items():
            found.add(k)
            if k == "properties" and isinstance(v, dict):
                for prop in v.values():
                    found |= _keywords(prop)
            elif isinstance(v, dict | list):
                found |= _keywords(v)
    elif isinstance(node, list):
        for v in node:
            found |= _keywords(v)
    return found


class TestSchemas:
    def test_gemini_output_stays_inside_its_allowlist(self, registry_tools) -> None:
        for t in registry_tools:
            used = _keywords(schemas.gemini_parameters(t.inputSchema))
            assert used <= schemas.GEMINI_KEYWORDS, (t.name, used - schemas.GEMINI_KEYWORDS)

    def test_openai_output_stays_inside_its_allowlist(self, registry_tools) -> None:
        for t in registry_tools:
            used = _keywords(schemas.openai_parameters(t.inputSchema))
            assert used <= schemas.OPENAI_KEYWORDS, (t.name, used - schemas.OPENAI_KEYWORDS)

    def test_swagger2_has_no_anyof_or_refs(self, registry_tools) -> None:
        for t in registry_tools:
            used = _keywords(schemas.swagger2_schema(t.inputSchema))
            assert used <= schemas.SWAGGER2_KEYWORDS, (t.name, used - schemas.SWAGGER2_KEYWORDS)

    def test_swagger2_drops_null_defaults(self) -> None:
        schema = {
            "type": "object",
            "properties": {"x": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": None}},
        }
        assert schemas.swagger2_schema(schema)["properties"]["x"] == {
            "type": "string",
            "x-nullable": True,
        }

    def test_refs_are_inlined(self) -> None:
        schema = {
            "type": "object",
            "properties": {"item": {"$ref": "#/$defs/Item"}},
            "$defs": {"Item": {"type": "object", "properties": {"n": {"type": "integer"}}}},
        }
        out = schemas.inline_refs(schema)
        assert out["properties"]["item"]["properties"]["n"] == {"type": "integer"}
        assert "$defs" not in out

    def test_optional_becomes_nullable_for_gemini(self) -> None:
        schema = {
            "type": "object",
            "properties": {"x": {"anyOf": [{"type": "string"}, {"type": "null"}], "title": "X"}},
        }
        assert schemas.gemini_parameters(schema)["properties"]["x"] == {
            "type": "string",
            "nullable": True,
        }

    def test_formats_and_openapi_list_the_same_tools(self, client) -> None:
        names = _visible(client, RAW_READ_A)
        openai = client.get("/v1/tools", headers=_h(RAW_READ_A)).json()["tools"]
        gemini = client.get("/v1/tools", params={"format": "gemini"}, headers=_h(RAW_READ_A))
        decls = gemini.json()["tools"][0]["function_declarations"]
        v3 = client.get("/v1/openapi.json", headers=_h(RAW_READ_A)).json()
        v2 = client.get("/v1/openapi.json", params={"version": "2"}, headers=_h(RAW_READ_A)).json()
        assert {t["function"]["name"] for t in openai} == names
        assert {d["name"] for d in decls} == names
        assert {op["post"]["operationId"] for op in v3["paths"].values()} == names
        assert {op["post"]["operationId"] for op in v2["paths"].values()} == names
        assert v3["openapi"] == "3.0.3" and v2["swagger"] == "2.0"

    @pytest.mark.parametrize("version", ["3", "2"])
    def test_max_description_caps_every_description(self, client, version) -> None:
        params = {"version": version, "max_description": "300"}
        full = client.get("/v1/openapi.json", params={"version": version}, headers=_h(RAW_READ_A))
        capped = client.get("/v1/openapi.json", params=params, headers=_h(RAW_READ_A))
        assert capped.status_code == 200

        def descriptions(node: Any) -> list[str]:
            if isinstance(node, dict):
                own = [v for k, v in node.items() if k == "description" and isinstance(v, str)]
                return own + [d for v in node.values() for d in descriptions(v)]
            if isinstance(node, list):
                return [d for v in node for d in descriptions(v)]
            return []

        before, after = descriptions(full.json()), descriptions(capped.json())
        assert max(map(len, before)) > 300  # the cap has something to do
        assert len(after) == len(before) and max(map(len, after)) <= 300
        assert any(d.endswith("…") for d in after)
        assert capped.json()["paths"].keys() == full.json()["paths"].keys()

    @pytest.mark.parametrize("bad", ["10", "abc", "-1"])
    def test_max_description_rejects_bad_values(self, client, bad) -> None:
        resp = client.get(
            "/v1/openapi.json", params={"max_description": bad}, headers=_h(RAW_READ_A)
        )
        assert resp.status_code == 400
