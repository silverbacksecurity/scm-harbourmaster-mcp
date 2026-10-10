#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["openai>=1.40"]
# ///
"""A tool-calling agent over the /v1 REST gateway, for any OpenAI-compatible API.

The model sees the tools a gateway key allows (narrowed by --toolset), calls
them through ``POST /v1/tools/{name}/call``, and answers from the results.
The same code runs against OpenAI, DeepSeek, Qwen (DashScope) and Moonshot
Kimi, because all four speak the Chat Completions tool-calling format:

    export SCM_GATEWAY_URL=https://scm-mcp.example.net
    export SCM_GATEWAY_KEY=hmg_...            # minted for this provider, see below
    export DEEPSEEK_API_KEY=...
    uv run examples/openai_compatible_agent.py --provider deepseek \\
        --model deepseek-chat "Which tenants have licences expiring in 90 days?"

Mint the gateway key with ``llm_provider`` set to the same provider, so a
tenant whose ``allowed_llm_providers`` excludes it is refused. The command
prints the key once and the entry to paste into ``.secrets.toml``:

    python -m scm_harbourmaster_mcp.gateway.keys new --id noc-deepseek \
        --tenants '*' --toolsets noc --llm-provider deepseek

Model names change often, so --model has no default: use one from the
provider's current model list that supports tool calling.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any

# provider -> (base_url, env var holding its API key)
PROVIDERS: dict[str, tuple[str, str]] = {
    "openai": ("https://api.openai.com/v1", "OPENAI_API_KEY"),
    "deepseek": ("https://api.deepseek.com", "DEEPSEEK_API_KEY"),
    "qwen": ("https://dashscope-intl.aliyuncs.com/compatible-mode/v1", "DASHSCOPE_API_KEY"),
    "kimi": ("https://api.moonshot.ai/v1", "MOONSHOT_API_KEY"),
}

SYSTEM = (
    "You are an MSSP operations assistant for Palo Alto Networks Strata Cloud "
    "Manager. Use the tools to answer; never guess tenant data. Tenant IDs are "
    "numeric TSG IDs: list tenants first if you don't know one. If a result says "
    "it was truncated, say so rather than presenting it as complete."
)


class Gateway:
    """Minimal client for the /v1 gateway (stdlib only)."""

    def __init__(self, base_url: str, key: str, toolset: str = "", timeout: float = 300):
        self.base_url = base_url.rstrip("/")
        self.key = key
        self.toolset = toolset
        self.timeout = timeout

    def _send(self, method: str, path: str, body: bytes | None) -> tuple[int, bytes]:
        req = urllib.request.Request(
            self.base_url + path,
            data=body,
            method=method,
            headers={"X-API-Key": self.key, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def _json(self, method: str, path: str, payload: Any = None) -> tuple[int, Any]:
        body = None if payload is None else json.dumps(payload).encode()
        status, raw = self._send(method, path, body)
        try:
            return status, json.loads(raw or b"{}")
        except ValueError:
            return status, {"error": raw.decode(errors="replace")[:500]}

    def tools(self, fmt: str) -> list[dict[str, Any]]:
        query = f"?format={fmt}" + (f"&toolset={self.toolset}" if self.toolset else "")
        status, data = self._json("GET", "/v1/tools" + query)
        if status != 200:
            raise RuntimeError(f"GET /v1/tools: HTTP {status}: {data.get('error', data)}")
        return list(data["tools"])

    def call(self, name: str, arguments: dict[str, Any], max_chars: int = 20_000) -> dict[str, Any]:
        """Call a tool. Errors come back as data, so the model can see and react."""
        status, data = self._json(
            "POST", f"/v1/tools/{name}/call", {"arguments": arguments, "max_chars": max_chars}
        )
        if status != 200:
            return {"error": data.get("error", data), "status": status}
        return dict(data)


def run_agent(
    llm: Any, model: str, gateway: Gateway, prompt: str, max_turns: int = 8, log: Any = None
) -> str:
    """Chat Completions tool loop. *llm* is an ``openai.OpenAI`` client (or a fake)."""
    tools = gateway.tools("openai")
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": prompt},
    ]
    for _ in range(max_turns):
        msg = llm.chat.completions.create(model=model, messages=messages, tools=tools)
        msg = msg.choices[0].message
        if not msg.tool_calls:
            return msg.content or ""
        messages.append(
            {
                "role": "assistant",
                "content": msg.content or "",
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                    }
                    for tc in msg.tool_calls
                ],
            }
        )
        for tc in msg.tool_calls:
            try:
                args = json.loads(tc.function.arguments or "{}")
                result = gateway.call(tc.function.name, args)
            except ValueError as exc:
                result = {"error": f"arguments were not valid JSON: {exc}"}
            if log:
                log(f"→ {tc.function.name}: {'error' if 'error' in result else 'ok'}")
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": json.dumps(result)})
    return f"Stopped after {max_turns} tool rounds without a final answer."


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("prompt")
    parser.add_argument("--provider", choices=sorted(PROVIDERS), default="openai")
    parser.add_argument("--model", required=True, help="a tool-calling model of that provider")
    parser.add_argument("--base-url", help="override the provider's API base URL")
    parser.add_argument("--toolset", default="noc", help="narrow the key's tools (default noc)")
    parser.add_argument("--max-turns", type=int, default=8)
    args = parser.parse_args(argv)

    base_url, key_env = PROVIDERS[args.provider]
    gateway_url, gateway_key = os.getenv("SCM_GATEWAY_URL"), os.getenv("SCM_GATEWAY_KEY")
    if not (gateway_url and gateway_key and os.getenv(key_env)):
        sys.exit(f"Set SCM_GATEWAY_URL, SCM_GATEWAY_KEY and {key_env}.")

    from openai import OpenAI

    llm = OpenAI(base_url=args.base_url or base_url, api_key=os.environ[key_env])
    gateway = Gateway(gateway_url, gateway_key, args.toolset)
    log = lambda line: print(line, file=sys.stderr)  # noqa: E731
    print(run_agent(llm, args.model, gateway, args.prompt, args.max_turns, log))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
