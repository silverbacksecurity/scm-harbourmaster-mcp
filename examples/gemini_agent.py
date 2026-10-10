#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["google-genai>=1.0"]
# ///
"""A Gemini function-calling agent over the /v1 REST gateway.

Fetches the key's tools in Gemini format (``GET /v1/tools?format=gemini``),
runs google-genai's manual function-calling loop, and executes each call
through ``POST /v1/tools/{name}/call``:

    export SCM_GATEWAY_URL=https://scm-mcp.example.net
    export SCM_GATEWAY_KEY=hmg_...           # minted with llm_provider = "gemini"
    export GEMINI_API_KEY=...                # or Vertex AI env, see google-genai docs
    uv run examples/gemini_agent.py --model gemini-2.5-flash \\
        "Summarise open incidents for tenant 1234567890"

Automatic function calling is off on purpose: every tool call goes through
the gateway, where the key's scope, rate limit and audit log apply.
Model names change often, so --model has no default.

This file reuses the gateway client from openai_compatible_agent.py when the
two sit side by side; copy that class across if you take this file alone.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from openai_compatible_agent import SYSTEM, Gateway  # noqa: E402


def run_agent(
    client: Any, model: str, gateway: Gateway, prompt: str, max_turns: int = 8, log: Any = None
) -> str:
    """Manual function-calling loop. *client* is a ``google.genai.Client``."""
    from google.genai import types

    tools = [types.Tool.model_validate(t) for t in gateway.tools("gemini")]
    config = types.GenerateContentConfig(
        system_instruction=SYSTEM,
        tools=tools,
        automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
    )
    contents: list[Any] = [types.Content(role="user", parts=[types.Part.from_text(text=prompt)])]
    for _ in range(max_turns):
        resp = client.models.generate_content(model=model, contents=contents, config=config)
        calls = resp.function_calls or []
        if not calls:
            return resp.text or ""
        contents.append(resp.candidates[0].content)
        parts = []
        for call in calls:
            result = gateway.call(call.name or "", dict(call.args or {}))
            if log:
                log(f"→ {call.name}: {'error' if 'error' in result else 'ok'}")
            parts.append(types.Part.from_function_response(name=call.name or "", response=result))
        contents.append(types.Content(role="user", parts=parts))
    return f"Stopped after {max_turns} tool rounds without a final answer."


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("prompt")
    parser.add_argument("--model", required=True, help="a Gemini model with function calling")
    parser.add_argument("--toolset", default="noc", help="narrow the key's tools (default noc)")
    parser.add_argument("--max-turns", type=int, default=8)
    args = parser.parse_args(argv)

    gateway_url, gateway_key = os.getenv("SCM_GATEWAY_URL"), os.getenv("SCM_GATEWAY_KEY")
    if not (gateway_url and gateway_key):
        sys.exit("Set SCM_GATEWAY_URL and SCM_GATEWAY_KEY (and GEMINI_API_KEY).")

    from google import genai

    client = genai.Client()
    gateway = Gateway(gateway_url, gateway_key, args.toolset)
    log = lambda line: print(line, file=sys.stderr)  # noqa: E731
    print(run_agent(client, args.model, gateway, args.prompt, args.max_turns, log))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
