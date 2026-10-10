# OAuth for `/mcp` with Microsoft Entra ID

With `SCM_MCP_HTTP_AUTH_MODE=entra`, `/mcp` (and `/sse`, `/webhook/*`) accept
Entra ID access tokens instead of the shared API key. Each user signs in with
their own Entra account, so this is the way to connect clients that only do
OAuth, such as ChatGPT connectors. The server logs each new session's
caller (`entra_auth_ok`, with the user's object ID and name).

The server is a **resource server** only. Clients sign in with Entra
directly, and the server never sees a password, an authorization code or a
refresh token. It publishes discovery metadata and checks the tokens:

- signature, against Entra's published keys for your tenant;
- issuer (v1 or v2 format) and `tid`, which must be your tenant;
- audience, which must be the API app's client ID or App ID URI;
- the `access` scope (or an app role you name, for app-only tokens).

What it doesn't do yet: map users or Entra groups to particular customer
tenants. Every signed-in user with the scope reaches every tenant the
server has loaded, as with the API key. Limit who can get the scope (step 1)
and scope the server with a toolset profile and read-only mode. `/v1`
gateway keys are unchanged and still the way to give a client only some
tenants. Entra tokens are not accepted on `/v1`.

## 1. Register the API in Entra

In the Entra admin center, under **App registrations → New registration**,
create the API app (for example "SCM Harbourmaster MCP API").

1. **Expose an API → Application ID URI.** Set it to the server's public
   `/mcp` URL, exactly, for example `https://scm-mcp.example.net/mcp`, with
   no trailing slash.
   - MCP clients send this URL to Entra as the `resource`, and Entra refuses
     the sign-in (AADSTS9010010) unless it matches the App ID URI byte for
     byte. The default `api://<client-id>` therefore doesn't work with most
     MCP clients.
   - An `https://` App ID URI must be on a domain verified in your tenant. A
     host such as `*.azurewebsites.net` can't be used; put the server on a
     custom domain you've verified.
   - *Verify live:* that Entra accepts the `/mcp` path in your App ID URI. If
     it doesn't, serve the MCP endpoint at the domain root behind your proxy
     and use the bare origin for both.
2. **Expose an API → Add a scope.** Name it `access`, admins and users can
   consent, and give it a display name like "Use SCM Harbourmaster tools".
   The full scope is then `https://scm-mcp.example.net/mcp/access`.
3. **Manifest:** set `"requestedAccessTokenVersion": 2` (shown as
   `accessTokenAcceptedVersion` in the older manifest view). The server
   accepts v1 tokens too, but v2 is the cleaner choice.
4. **Enterprise applications →** the same app **→ Properties:** set
   **Assignment required** to **Yes**, then add the users or groups allowed
   to use the server under **Users and groups**. Otherwise anyone in the
   tenant can sign in.
5. Note the **Directory (tenant) ID** and the **Application (client) ID**.

### App-only callers (optional)

For a service calling with the client credentials flow, add an app role
under **App roles** (allowed member type *Applications*, value for example
`MCP.Access`), grant it to the calling app, and set
`SCM_MCP_HTTP_ENTRA_APP_ROLE=MCP.Access`. App-only tokens are refused
unless this is set.

## 2. Register each client

Entra has no dynamic client registration, so an MCP client can't register
itself. Register a **separate** app for each client (Entra refuses a token
an app requests for itself, AADSTS90009):

1. **New registration**, e.g. "SCM Harbourmaster – ChatGPT".
2. **API permissions → Add a permission → My APIs →** the API app → the
   `access` scope. Grant admin consent if users can't consent themselves.
3. **Authentication → Add a platform** with the client's redirect URI. Take
   the URI from the client's own setup screen rather than guessing it:
   - **Desktop and CLI clients** (Claude Code, Gemini CLI, VS Code) listen on
     localhost. Use **Mobile and desktop applications**, and turn on
     **Allow public client flows**.
   - **Hosted clients** (ChatGPT, Claude.ai) redirect to their own servers.
     *Verify live* which platform works: Web (with a client secret) or
     Single-page application. Entra checks the platform as well as the URI.
4. Give the client its application (client) ID, and the secret if you made
   one.

## 3. Configure the server

```bash
SCM_MCP_HTTP_AUTH_MODE=entra                       # or apikey,entra during a move
SCM_MCP_HTTP_ENTRA_TENANT=<directory-tenant-id>
SCM_MCP_HTTP_ENTRA_AUDIENCE=<api-app-client-id>
SCM_MCP_HTTP_RESOURCE_URL=https://scm-mcp.example.net/mcp
SCM_MCP_HTTP_ALLOWED_HOSTS=scm-mcp.example.net
SCM_MCP_ENABLED_TOOLSETS=noc
SCM_MCP_READ_ONLY=true
```

| Variable | Default | Purpose |
|---|---|---|
| `SCM_MCP_HTTP_RESOURCE_URL` | — | The public `/mcp` URL. Publishes the metadata and the `WWW-Authenticate` challenge. Must be `https://` (or `http://localhost`), with no trailing slash |
| `SCM_MCP_HTTP_ENTRA_APP_ID_URI` | the resource URL | Only if the API's App ID URI differs from the resource URL |
| `SCM_MCP_HTTP_ENTRA_SCOPE` | `access` | Scope name from step 1.2 |
| `SCM_MCP_HTTP_ENTRA_APP_ROLE` | — | App role that app-only tokens must carry |
| `SCM_MCP_HTTP_OAUTH_AS_METADATA` | off | See below |

The server refuses to start if the tenant, audience or resource URL is
missing or malformed.

**`apikey,entra`** accepts either credential. A request that sends
`X-API-Key` is judged on the key alone; anything else needs a token. Use it
to move clients across one at a time, then drop `apikey`.

### What the server publishes

- `GET /.well-known/oauth-protected-resource/mcp` (and the same without
  `/mcp`): RFC 9728 metadata naming the resource, the authorization server
  and the scope. No auth.
- A 401 without a valid token carries
  `WWW-Authenticate: Bearer resource_metadata="…", scope="…"`, which is how
  MCP clients find the metadata. A token without the scope gets 403 with
  `error="insufficient_scope"`.

### `SCM_MCP_HTTP_OAUTH_AS_METADATA`

Entra's discovery document doesn't list `code_challenge_methods_supported`,
although Entra supports PKCE with S256. The MCP specification tells clients
to refuse an authorization server that doesn't advertise it, so a strict
client may stop there.

With this set to `1`, the server publishes its own
`/.well-known/oauth-authorization-server`. It points at Entra's authorize,
token and key endpoints for your tenant, and adds S256. The protected
resource metadata then lists this server as the authorization server. Sign-in
and token requests still go straight to Entra; nothing is proxied.

Leave it off unless a client fails discovery. It is a workaround: the
`issuer` it publishes is this server, not Entra, which is only valid because
clients treat access tokens as opaque.

## 4. Connect clients

- **ChatGPT** (developer mode → connectors / apps): add the server URL
  `https://scm-mcp.example.net/mcp`, choose OAuth, and under the advanced
  OAuth settings choose a user-defined OAuth client. Enter the client app's
  ID (and secret, if it has one) and the scope. ChatGPT shows the redirect
  URI to register in step 2.3. *Verify live:* this has not been tried
  against a real ChatGPT connector yet.
- **Claude Code:**
  ```bash
  claude mcp add --transport http --client-id <client-app-id> --callback-port 8765 \
    scm-harbourmaster https://scm-mcp.example.net/mcp
  ```
  Register `http://localhost:8765/callback` for that client, then sign in
  from `/mcp` inside Claude Code. Some Claude
  Code versions append a trailing slash to `resource` or can't override it
  (anthropics/claude-code#52871, #73460); those are client-side.
- **Copilot Studio:** in the MCP wizard, choose OAuth 2.0 → manual, with
  Entra's authorize and token URLs for your tenant, the client app's ID and
  secret, and the full scope. Copilot Studio shows the redirect URI to
  register.

Keep clients that can only send a static header (Kimi, Antigravity, the
Phase D snippets) on an `apikey` instance, or run `apikey,entra`.

## Troubleshooting

| Symptom | Cause |
|---|---|
| AADSTS9010010 at sign-in | The client's `resource` doesn't match the App ID URI byte for byte. Check the trailing slash and the path |
| AADSTS90009 | The client and the API use the same app registration. Register a separate client app |
| AADSTS50011 | The redirect URI isn't registered exactly as the client sends it |
| AADSTS9002326 / 9002327 | The redirect URI is under the wrong platform (Web, SPA, or Mobile and desktop) |
| 401 `invalid_token`, "not valid for this server" | Wrong audience or issuer. The server log (`entra_token_invalid`) says which |
| 401 "token is from another tenant" | The user signed in to a different tenant. Use the tenant-specific authorize URL, not `common` |
| 403 `insufficient_scope` | The token was requested without the `access` scope, or the user hasn't consented |
| Client stops after fetching the metadata | Try `SCM_MCP_HTTP_OAUTH_AS_METADATA=1` |
| 403 for a Power Automate or other service caller | Its token is app-only and has no `scp`. Set `SCM_MCP_HTTP_ENTRA_APP_ROLE` (see *App-only callers*) |
| 401 "not valid for this server" right after Entra rotates keys | The server refetches Entra's keys at most once every 5 minutes for an unknown key ID. It clears up by itself |
