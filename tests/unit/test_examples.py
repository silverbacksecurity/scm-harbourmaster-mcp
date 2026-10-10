"""The examples/ agents drive the real /v1 gateway correctly (no network, no LLM).

A scripted fake model asks for tool calls; the agent loop runs them through
the gateway routes (stub executor, real registry and key policy) and feeds
the results back. Covers the tool format each agent requests, the call
envelope, and that errors reach the model as data rather than crashing.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.testclient import TestClient

import scm_harbourmaster_mcp.auth.oauth as oauth
from scm_harbourmaster_mcp import server
from scm_harbourmaster_mcp.gateway import keys as gw_keys
from scm_harbourmaster_mcp.gateway import policy
from scm_harbourmaster_mcp.gateway.app import gateway_routes

EXAMPLES = Path(__file__).resolve().parents[2] / "examples"
RAW_KEY = "hmg_examples-test-key"
TOOL = "mssp_list_tenants"  # in the noc profile, takes no tenant


def _load(name: str):
    sys.path.insert(0, str(EXAMPLES))
    try:
        spec = importlib.util.spec_from_file_location(name, EXAMPLES / f"{name}.py")
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        sys.path.remove(str(EXAMPLES))


agent = _load("openai_compatible_agent")


class _Stub:
    def __init__(self, registry: FastMCP) -> None:
        self._tool_manager = registry._tool_manager
        self._tools = asyncio.run(registry.list_tools())
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def list_tools(self) -> list[Any]:
        return self._tools

    async def call_tool(self, name: str, args: dict[str, Any]) -> list[Any]:
        self.calls.append((name, args))
        return [SimpleNamespace(text="tenant-a, tenant-b")]


@pytest.fixture(scope="module")
def registry() -> FastMCP:
    mcp = FastMCP(name="registry")
    server.register_all_tools(mcp, lambda *a, **k: None, lambda: None)
    return mcp


@pytest.fixture
def stub(registry, monkeypatch, tmp_path) -> _Stub:
    monkeypatch.setattr(oauth, "list_loaded_tenants", lambda: [])
    monkeypatch.setattr(oauth, "get_tenant_meta", lambda tid: None)
    monkeypatch.setattr(policy, "_default_tenant", lambda: "")
    monkeypatch.setenv("SCM_MCP_DATA_DIR", str(tmp_path))
    return _Stub(registry)


@pytest.fixture
def gateway(stub):
    key = gw_keys.parse_key(
        "examples",
        {
            "key_sha256": gw_keys.hash_key(RAW_KEY),
            "access": "read",
            "tenants": ["*"],
            "toolsets": ["noc"],
            "llm_provider": "deepseek",
        },
    )
    client = TestClient(Starlette(routes=gateway_routes(stub, {"examples": key})))

    class _TestGateway(agent.Gateway):
        def _send(self, method, path, body):
            resp = client.request(method, path, content=body, headers={"X-API-Key": self.key})
            return resp.status_code, resp.content

    return _TestGateway("http://testserver", RAW_KEY, toolset="noc")


def _tool_call(call_id: str, name: str, arguments: str) -> Any:
    return SimpleNamespace(id=call_id, function=SimpleNamespace(name=name, arguments=arguments))


class FakeOpenAI:
    """Replies with each scripted message in turn and records what it was sent."""

    def __init__(self, script: list[Any]) -> None:
        self.script = list(script)
        self.requests: list[dict[str, Any]] = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs: Any) -> Any:
        self.requests.append(json.loads(json.dumps(kwargs)))
        return SimpleNamespace(choices=[SimpleNamespace(message=self.script.pop(0))])


def test_openai_agent_runs_a_tool_and_answers(gateway, stub):
    llm = FakeOpenAI(
        [
            SimpleNamespace(content=None, tool_calls=[_tool_call("c1", TOOL, "{}")]),
            SimpleNamespace(content="Two tenants.", tool_calls=None),
        ]
    )
    assert agent.run_agent(llm, "m", gateway, "list tenants") == "Two tenants."
    assert stub.calls == [(TOOL, {})]

    first, second = llm.requests
    names = {t["function"]["name"] for t in first["tools"]}
    assert TOOL in names and len(names) <= 40  # narrowed to the noc profile
    tool_msg = second["messages"][-1]
    assert tool_msg["role"] == "tool" and tool_msg["tool_call_id"] == "c1"
    assert json.loads(tool_msg["content"])["content"] == "tenant-a, tenant-b"


def test_openai_agent_returns_errors_to_the_model(gateway, stub):
    llm = FakeOpenAI(
        [
            SimpleNamespace(
                content="",
                tool_calls=[
                    _tool_call("c1", "scm_commit", "{}"),  # never exposed over REST
                    _tool_call("c2", TOOL, "{not json"),
                ],
            ),
            SimpleNamespace(content="Could not.", tool_calls=None),
        ]
    )
    assert agent.run_agent(llm, "m", gateway, "commit") == "Could not."
    assert stub.calls == []
    results = [json.loads(m["content"]) for m in llm.requests[1]["messages"][-2:]]
    assert results[0] == {"error": "tool not found", "status": 404}
    assert "not valid JSON" in results[1]["error"]


def test_openai_agent_stops_after_max_turns(gateway):
    loop = SimpleNamespace(content="", tool_calls=[_tool_call("c", TOOL, "{}")])
    llm = FakeOpenAI([loop, loop])
    assert "Stopped after 2" in agent.run_agent(llm, "m", gateway, "x", max_turns=2)


def test_bad_gateway_key_fails_before_the_model_is_called(gateway):
    gateway.key = "hmg_wrong"
    with pytest.raises(RuntimeError, match="HTTP 401"):
        agent.run_agent(FakeOpenAI([]), "m", gateway, "x")


def test_gemini_agent_loop(gateway, stub):
    types = pytest.importorskip("google.genai.types")
    gemini = _load("gemini_agent")
    replies = [
        SimpleNamespace(
            function_calls=[types.FunctionCall(name=TOOL, args={})],
            candidates=[
                SimpleNamespace(
                    content=types.Content(
                        role="model",
                        parts=[types.Part(function_call=types.FunctionCall(name=TOOL, args={}))],
                    )
                )
            ],
            text=None,
        ),
        SimpleNamespace(function_calls=None, text="Two tenants."),
    ]
    seen: list[Any] = []

    def generate_content(model, contents, config):
        seen.append((list(contents), config))
        return replies.pop(0)

    client = SimpleNamespace(models=SimpleNamespace(generate_content=generate_content))
    assert gemini.run_agent(client, "m", gateway, "list tenants") == "Two tenants."
    assert stub.calls == [(TOOL, {})]
    config = seen[0][1]
    assert config.automatic_function_calling.disable is True
    names = {d.name for t in config.tools for d in t.function_declarations}
    assert TOOL in names
    response_part = seen[1][0][-1].parts[0]
    assert response_part.function_response.response["content"] == "tenant-a, tenant-b"
