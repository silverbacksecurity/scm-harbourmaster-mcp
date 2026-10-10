# Microsoft Copilot Studio

Copilot Studio can connect to scm-harbourmaster-mcp in two ways.

- **As an MCP server (`/mcp`)** for a Copilot Studio agent. The agent sees
  the server's tools and picks among them with generative orchestration,
  which must be turned on.
- **As a REST connector (`/v1`)**, where each tool is a connector action, for
  Power Automate flows or agents that need per-key tenant scoping.

Copilot Studio supports only Streamable HTTP for MCP. It dropped SSE in August
2025, so use `/mcp`, not `/sse`.

## Before you start

- Run `scm-mcp-http` behind TLS on a public name, with
  `SCM_MCP_HTTP_ALLOWED_HOSTS` set to that name. `deploy/docker-compose.yml`
  plus a reverse proxy is enough.
- Give the server a toolset profile and read-only mode:
  `SCM_MCP_ENABLED_TOOLSETS=noc` and `SCM_MCP_READ_ONLY=true`. Read-only,
  each profile is 33–36 tools. The full server (~143) is over Copilot
  Studio's tool ceiling, and the orchestrator chooses worse from a long list.
- `/mcp` uses the single shared `SCM_MCP_HTTP_API_KEY`, which reaches every
  tenant the server has loaded. To limit an agent to particular customers,
  either run a separate instance whose `settings.toml` holds only those
  tenants, or use the REST connector with a tenant-scoped gateway key.

## Option 1: MCP onboarding wizard (recommended)

1. In your agent, open **Tools → Add a tool → New tool → Model Context Protocol**.
2. Enter:
   - **Server URL:** `https://scm-mcp.example.net/mcp`
   - **Server name and description:** the orchestrator reads the description
     to decide when to call this server, so say what it covers, e.g.
     "Strata Cloud Manager NOC tools: tenants, incidents, licences, service
     health."
3. Set authentication to **API key**, type **Header**, header name `X-API-Key`.
   If the server runs in Entra mode, choose **OAuth 2.0** instead; see
   [`../../docs/entra-oauth.md`](../../docs/entra-oauth.md).
4. Select **Create**, then create a connection and paste the key. Select
   **Add to agent**.

## Option 2: custom connector from these files

`apiDefinition.swagger.json` and `apiProperties.json` define the same MCP
connector. Use them when you want it in source control, in a solution, or
deployed with the Power Platform CLI.

1. Replace `host` (`scm-mcp.example.net`) in `apiDefinition.swagger.json`,
   and `publisher` / `stackOwner` in `apiProperties.json`.
2. Import the connector:
   - **In the portal:** Power Apps → **Custom connectors → New custom
     connector → Import an OpenAPI file**, and select
     `apiDefinition.swagger.json`. In the **Security** step, set API key,
     parameter `X-API-Key`, location Header.
   - **With the CLI:**
     ```bash
     paconn validate --api-def apiDefinition.swagger.json
     paconn create --api-def apiDefinition.swagger.json --api-prop apiProperties.json
     ```
3. In the agent: **Tools → Add a tool**, then search for the connector and
   add it.

The `/mcp` operation carries `x-ms-agentic-protocol: mcp-streamable-1.0`. That
is what makes Copilot Studio treat the connector as an MCP server rather than
a single REST action.

## Option 3: REST connector over the gateway (`/v1`)

Use this one for Power Automate, or when an agent must be limited to certain
tenants. The gateway generates a Swagger 2.0 document from the tools a
gateway key can use:

```bash
curl -H "X-API-Key: $GATEWAY_KEY" \
  "https://scm-mcp.example.net/v1/openapi.json?version=2&toolset=noc" \
  > scm-gateway.swagger.json
```

Check that `schemes` is `["https"]` and `host` is your public name before
importing. If it says `http`, the proxy isn't trusted: set
`FORWARDED_ALLOW_IPS` to its address (see `deploy/docker-compose.yml`). Add
`&max_description=300` if the importer complains about description length.

Import `scm-gateway.swagger.json` as a custom connector, with API key auth in
header `X-API-Key`. Each tool becomes an action whose input is
`{"arguments": {...}}`. Mint the key with `llm_provider = "copilot"` (or
whatever value the tenants' `allowed_llm_providers` use for Microsoft), and
with only the tenants and toolsets the agent needs. Regenerate the document
when the server's tools change.

## Data policy

Copilot Studio reaches MCP servers through Power Platform connectors, so a
data policy that covers connectors covers this connector too. Classify it in
the Power Platform admin center before people build on it.
