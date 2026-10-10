# MCP client configuration

Snippets for connecting MCP clients to scm-harbourmaster-mcp. Host names
(`scm-mcp.example.net`) and paths are placeholders.

There are two ways in:

- **Local (stdio).** The client starts the server itself, as in
  `claude-desktop.json`. The toolset profile goes on the command line
  (`--toolsets noc --read-only`).
- **Remote (Streamable HTTP at `/mcp`).** The client connects to a running
  `scm-mcp-http`, as in every other file here. It authenticates with
  `X-API-Key: <SCM_MCP_HTTP_API_KEY>`. This server does not accept the key as
  a Bearer token on `/mcp`. A server in Entra mode takes OAuth sign-in
  instead (or as well); see [`../../docs/entra-oauth.md`](../../docs/entra-oauth.md).

## Scope the remote server, not just the client

`SCM_MCP_HTTP_API_KEY` is one shared key with no per-client scoping. Unlike a
`/v1` gateway key, it reaches every tenant and every tool the server
registers. Scope `/mcp` on the **server** instead. Run one instance per
audience, each with a toolset profile and read-only mode. For example, in
`deploy/.env`:

```bash
SCM_MCP_ENABLED_TOOLSETS=noc   # or grc, config, sdwan; profiles are in toolsets.py
SCM_MCP_READ_ONLY=true
SCM_MCP_HTTP_ALLOWED_HOSTS=scm-mcp.example.net
```

Read-only, each profile is 33–36 tools, which is well inside every client's
limit. The full server is about 143 tools, which strains most clients'
context and Copilot Studio's tool ceiling. Use profiles.

For per-client, per-tenant scoping today, use the REST gateway (`/v1`) with
a scoped key; see [`../README.md`](../README.md). OAuth for `/mcp` with
Entra ID adds per-user sign-in, but not per-user tenant limits yet.

## Clients

| Client | File | Where it goes |
|---|---|---|
| Claude Desktop | `claude-desktop.json` | `claude_desktop_config.json` |
| Claude Code | see below | `claude mcp add` |
| Gemini CLI | `gemini-cli.settings.json` | `~/.gemini/settings.json` or `.gemini/settings.json` |
| Qwen Code | `qwen-code.settings.json` | `~/.qwen/settings.json` or `.qwen/settings.json` |
| Antigravity | `antigravity.mcp_config.json` | `~/.gemini/config/mcp_config.json` (MCP Servers → *View raw config*) |
| Kimi Code CLI | `kimi-code.mcp.json` | `~/.kimi-code/mcp.json` or `.kimi-code/mcp.json` |
| OpenAI Responses API | `openai-responses-mcp-tool.json` | request body |
| ChatGPT | see below | — |
| Microsoft Copilot Studio | [`../../deploy/copilot-studio/`](../../deploy/copilot-studio/) | — |

Per-client notes:

- **Claude Desktop** runs the server from a source checkout, so `uv
  --directory` must point at the repo, where `settings.toml` and
  `.secrets.toml` live. For the container image, see the `docker run -i`
  snippet in the main README's Docker section.
- **Claude Code:**
  ```bash
  # local
  claude mcp add scm-harbourmaster -- \
    uv --directory /path/to/scm-harbourmaster-mcp run scm-mcp --toolsets noc --read-only
  # remote
  claude mcp add --transport http scm-harbourmaster https://scm-mcp.example.net/mcp \
    --header "X-API-Key: $SCM_MCP_HTTP_API_KEY"
  ```
- **Gemini CLI and Qwen Code** use `httpUrl` for Streamable HTTP; `url` means
  SSE there. Gemini CLI expands `$SCM_MCP_HTTP_API_KEY` from the environment.
  Qwen Code is a Gemini CLI fork; if your version doesn't expand variables,
  paste the key in. Both clients can also narrow tools on their side with
  `includeTools` / `excludeTools`. The CLI equivalent is
  `gemini mcp add --transport http --header "X-API-Key: …" scm-harbourmaster https://scm-mcp.example.net/mcp`,
  and the same with `qwen`.
- **Antigravity** takes only `serverUrl` for remote servers; `url` and
  `httpUrl` are rejected. Older builds read `~/.gemini/antigravity/mcp_config.json`;
  *View raw config* opens whichever file yours uses.
- **Kimi Code CLI** treats a `url` with no `transport` as Streamable HTTP. Its
  `bearerTokenEnvVar` option sends `Authorization: Bearer`, which `/mcp` doesn't
  accept, so use `headers`.
- **OpenAI Responses API.** OpenAI's servers call `/mcp`, so it must be
  reachable from the internet over TLS. Send the `headers` on every request,
  because OpenAI doesn't store them. Keep `require_approval: "always"` unless
  the server is read-only. Prefer the gateway example
  (`../openai_compatible_agent.py`) when the server shouldn't be public:
  that agent runs on your side, so `/v1` only has to be reachable from it.
- **ChatGPT** (developer-mode connectors / apps): ChatGPT supports only
  OAuth, no authentication, or mixed authentication for MCP servers. It can't
  send `X-API-Key`. Never expose `/mcp` with `SCM_MCP_HTTP_AUTH_MODE=none` to
  make it fit. Run the server in Entra mode and add it as a connector with a
  user-defined OAuth client; the steps are in
  [`../../docs/entra-oauth.md`](../../docs/entra-oauth.md). This hasn't been
  tried against a real ChatGPT connector yet.

  Without Entra, a **custom GPT Action** can call the REST gateway with
  API-key auth:
  1. Download the schema with your key:
     ```bash
     curl -H "X-API-Key: $KEY" \
       "https://scm-mcp.example.net/v1/openapi.json?toolset=mssp&max_description=300"
     ```
     The schema URL itself needs a key, so "Import from URL" can't fetch it.
     Check that `servers[0].url` is `https://` and your public host (see
     `FORWARDED_ALLOW_IPS` in `deploy/docker-compose.yml`).
  2. Paste the schema into the Action.
  3. Set authentication to *API Key → Custom header* `X-API-Key`.

  GPT Actions have limits the profiles don't fit.
  - **Operations.** A GPT is reported to allow about 30. `noc` is 34 over
    REST, so pick one toolset instead: `mssp` is 13 and `ops` is 17.
  - **Descriptions.** OpenAI caps endpoint descriptions at 300 characters.
    `max_description=300` trims them, because tool docstrings run to
    thousands.
  - **Timeouts.** A call times out after 45 seconds, so long-running
    reports (AS-BUILT, MSR, BPA) won't finish through an Action.
