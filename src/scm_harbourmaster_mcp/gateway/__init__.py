"""REST tool gateway (``/v1``) for LLM platforms that call tools by function calling.

DeepSeek, Qwen, Kimi, the OpenAI and Gemini APIs, Microsoft 365 Copilot and
ChatGPT custom GPTs don't speak MCP. They take function schemas and expect the
caller to run each call. ``/v1`` serves the schemas in their formats and runs
the calls in-process, behind per-key scopes:

* ``keys``    — gateway API keys (hashed, in ``.secrets.toml``) and their scopes
* ``policy``  — which tools a key may see and call, and per-call argument checks
* ``schemas`` — MCP input schemas → OpenAI / Gemini / OpenAPI 3 / Swagger 2.0
* ``audit``   — JSONL record of every call
* ``app``     — the Starlette routes mounted by ``server_http``
"""
