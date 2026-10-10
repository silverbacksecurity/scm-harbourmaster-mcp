# Examples

Ways to use scm-harbourmaster-mcp from LLM platforms other than Claude, and
from Claude too. Every example uses a toolset profile (`noc` by default) and
placeholder hosts and tenants.

| You have | Use | Path |
|---|---|---|
| An MCP client (Claude, Gemini CLI, Qwen Code, Kimi, Antigravity) | [`mcp-clients/`](mcp-clients/) | `/mcp` or stdio |
| Microsoft Copilot Studio / Power Automate | [`../deploy/copilot-studio/`](../deploy/copilot-studio/) | `/mcp` or `/v1` |
| An OpenAI-compatible API: OpenAI, DeepSeek, Qwen (DashScope), Moonshot Kimi | [`openai_compatible_agent.py`](openai_compatible_agent.py) | `/v1` |
| The Gemini API or Vertex AI | [`gemini_agent.py`](gemini_agent.py) | `/v1` |
| ChatGPT | [`mcp-clients/README.md#clients`](mcp-clients/README.md#clients) | `/v1` via a GPT Action, until OAuth (Phase C2) |

## The REST gateway agents

The two agent scripts call the server's `/v1` gateway. The model never
touches the server directly. It asks for tool calls, and the script runs
each one through the gateway with a **scoped gateway key**, which fixes the
tenants, toolsets, access level and rate limit, and is audited per call.
That is the way to give a third-party model access to some customers but not
others.

1. Run `scm-mcp-http` (see `deploy/docker-compose.yml`).
2. Mint a key for the provider and add the printed entry to `.secrets.toml`:
   ```bash
   python -m scm_harbourmaster_mcp.gateway.keys new --id noc-deepseek \
       --tenants 1234567890,2345678901 --toolsets noc --llm-provider deepseek
   ```
   Restart the server so it loads the key.
3. Run an agent. The scripts carry their dependencies inline, so `uv run`
   needs no install:
   ```bash
   export SCM_GATEWAY_URL=https://scm-mcp.example.net SCM_GATEWAY_KEY=hmg_...
   export DEEPSEEK_API_KEY=...
   uv run examples/openai_compatible_agent.py --provider deepseek --model deepseek-chat \
       "Which tenants have licences expiring in the next 90 days?"

   export GEMINI_API_KEY=...
   uv run examples/gemini_agent.py --model gemini-2.5-flash "Summarise open incidents"
   ```

`--model` has no default because model names change. Pick a current model
of that provider that supports tool calling. The gateway is read-only unless
the server sets `SCM_MCP_HTTP_REST_WRITE=1` *and* the key has
`access = "write"`. Even then, pushes, commits and rollbacks are never
exposed over REST.

If a tenant sets `allowed_llm_providers`, a key whose `llm_provider` isn't in
that list is refused for that tenant. Set `llm_provider` truthfully on every
key.
