"""
HTTP transport server for Copilot Studio and other remote MCP clients.

Wraps the same FastMCP instance as the stdio server and serves it over both
MCP HTTP transports, behind the same auth:

  /mcp  Streamable HTTP, the current MCP transport. Use this for Copilot
        Studio, ChatGPT connectors, Gemini CLI/ADK, Antigravity, Qwen Code,
        Kimi CLI and Claude.
  /sse  The older HTTP+SSE transport (with /messages/). Kept for clients
        that haven't moved yet.

Runs locally or in Azure Container Apps / App Service style deployments.

/v1 is the REST tool gateway (scm_harbourmaster_mcp.gateway) for platforms
that call tools by function calling rather than MCP: DeepSeek, Qwen, Kimi,
the OpenAI and Gemini APIs, Microsoft 365 Copilot and custom GPTs. It
authenticates with its own scoped keys (``[gateway_keys.*]``), not with the
settings below.

Auth modes (SCM_MCP_HTTP_AUTH_MODE):
  apikey        — X-API-Key header or ?api_key= query param (default)
  entra         — Entra ID Bearer access token (OAuth 2.1 resource server;
                  see auth/entra_resource.py for its env vars)
  apikey,entra  — either credential, for moving clients over one at a time
  none          — No auth (dev/localhost only — never expose publicly)

Env vars:
  SCM_MCP_HTTP_HOST           Bind address (default 0.0.0.0 for containers)
  SCM_MCP_HTTP_PORT           TCP port (default 8080)
  SCM_MCP_HTTP_API_KEY        Required for apikey mode
  SCM_MCP_HTTP_AUTH_MODE      apikey | entra | none  (default: apikey)
  SCM_MCP_HTTP_ENTRA_TENANT   Entra tenant ID (entra mode)
  SCM_MCP_HTTP_ENTRA_AUDIENCE Client ID of the API app registration
  SCM_MCP_HTTP_RESOURCE_URL   Public URL of /mcp; publishes OAuth metadata
  SCM_MCP_HTTP_ALLOWED_ORIGINS CORS origins, comma-separated (default: *)
  SCM_MCP_HTTP_ALLOWED_HOSTS  Public hostnames clients use, comma-separated
                              (e.g. mcp.example.com). Enables Host/Origin
                              checks for them. Unset on a non-loopback bind,
                              those checks are off (auth still applies);
                              unset on a loopback bind, only localhost is
                              accepted.
  SCM_MCP_HTTP_STATELESS      "1"/"true" serves /mcp without sessions, for
                              several replicas behind a load balancer
                              (default: off)
  SCM_MCP_HTTP_REST_WRITE     "1"/"true" lets /v1 keys with access="write"
                              call write tools (default: off — /v1 is
                              read-only)
  SCM_MCP_GATEWAY_MAX_CHARS   Cap on a /v1 tool result (default 60000)
  SCM_MCP_HTTP_SSR_WEBHOOK    "1"/"true" enables POST /webhook/ssr (default: off)
"""

from __future__ import annotations

import contextlib
import hmac
import json
import os
from collections.abc import AsyncIterator, Awaitable, Callable

import uvicorn
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route

from .auth.entra_resource import (
    ASM_PATH,
    PRM_PATH,
    EntraResourceConfig,
    EntraTokenValidator,
    principal,
)
from .gateway.app import gateway_routes
from .server import create_server
from .utils.logging import get_logger

logger = get_logger(__name__)

# ─── Configuration ────────────────────────────────────────────────────────────

# Default 0.0.0.0 so the server is reachable inside a container; override with
# SCM_MCP_HTTP_HOST=127.0.0.1 for local-only binding.
_HOST = os.getenv("SCM_MCP_HTTP_HOST", "0.0.0.0")  # nosec B104
_PORT = int(os.getenv("SCM_MCP_HTTP_PORT", "8080"))
_AUTH_MODE = os.getenv("SCM_MCP_HTTP_AUTH_MODE", "apikey").lower()
_API_KEY = os.getenv("SCM_MCP_HTTP_API_KEY", "")
_ALLOWED_ORIGINS = [
    o.strip() for o in os.getenv("SCM_MCP_HTTP_ALLOWED_ORIGINS", "*").split(",") if o.strip()
]
# /webhook/ssr is a WRITE endpoint (unlike /webhook/ir, which is read-only by
# construction) — operators must opt in explicitly.
_SSR_WEBHOOK_ENABLED = os.getenv("SCM_MCP_HTTP_SSR_WEBHOOK", "").lower() in ("1", "true", "yes")

_ALLOWED_HOSTS = [
    h.strip() for h in os.getenv("SCM_MCP_HTTP_ALLOWED_HOSTS", "").split(",") if h.strip()
]
_STATELESS = os.getenv("SCM_MCP_HTTP_STATELESS", "").lower() in ("1", "true", "yes")

_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
_LOCAL_HOST_PATTERNS = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
_LOCAL_ORIGIN_PATTERNS = ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"]

# Entra ID resource-server mode (Phase C2), see auth/entra_resource.py
_ENTRA = EntraResourceConfig.from_env()
_VALIDATOR: EntraTokenValidator | None = None

# Always public: health checks and the OAuth discovery documents.
_PUBLIC_PREFIXES = (PRM_PATH, ASM_PATH)


def _auth_modes() -> set[str]:
    """SCM_MCP_HTTP_AUTH_MODE as a set: "apikey", "entra", "apikey,entra" or "none"."""
    return {m.strip() for m in _AUTH_MODE.split(",") if m.strip()}


def _validator() -> EntraTokenValidator:
    global _VALIDATOR
    if _VALIDATOR is None or _VALIDATOR.config is not _ENTRA:
        _VALIDATOR = EntraTokenValidator(_ENTRA)
    return _VALIDATOR


def _unauthorized(
    error: str, *, challenge: bool, oauth_error: str = "", detail: str = ""
) -> Response:
    headers = {"WWW-Authenticate": _ENTRA.challenge(oauth_error, detail)} if challenge else None
    return JSONResponse({"error": error}, status_code=401, headers=headers)


# ─── Auth middleware ──────────────────────────────────────────────────────────


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Validate inbound requests before passing them to the MCP handlers.

    SCM_MCP_HTTP_AUTH_MODE is one mode or a comma-separated pair:
      - apikey: X-API-Key header or ?api_key= query param
      - entra:  Authorization: Bearer <Entra ID access token>
      - apikey,entra: either; a request carrying an API key is judged on it
      - none:   Always allow (dev only)
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        path = request.url.path
        # Health checks and OAuth discovery are public. CORS preflights carry
        # no credentials by design; CORSMiddleware answers them itself, but
        # only when Origin is present (without it the request would reach
        # the route), so a preflight must have both headers.
        preflight = (
            request.method == "OPTIONS"
            and "origin" in request.headers
            and "access-control-request-method" in request.headers
        )
        if path in ("/health", "/healthz") or path.startswith(_PUBLIC_PREFIXES) or preflight:
            return await call_next(request)

        # /v1 authenticates with its own scoped gateway keys (gateway.app),
        # and only there: neither credential below is accepted on /v1, and a
        # gateway key matches neither of them on any other route.
        if path == "/v1" or path.startswith("/v1/"):
            return await call_next(request)

        modes = _auth_modes()
        if "none" in modes:
            return await call_next(request)
        unknown = modes - {"apikey", "entra"}
        if unknown or not modes:
            return JSONResponse({"error": f"Unknown auth mode: {_AUTH_MODE}"}, status_code=500)
        entra = "entra" in modes

        provided = request.headers.get("X-API-Key") or request.query_params.get("api_key")
        if "apikey" in modes and (provided or not entra):
            if not _API_KEY:
                logger.error("apikey_auth_no_key_configured")
                return JSONResponse(
                    {"error": "Server misconfigured — SCM_MCP_HTTP_API_KEY not set"},
                    status_code=500,
                )
            if not hmac.compare_digest((provided or "").encode(), _API_KEY.encode()):
                logger.warning("apikey_auth_failed", path=path)
                return _unauthorized("Unauthorized — invalid or missing X-API-Key", challenge=entra)
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return _unauthorized("Unauthorized — Bearer token required", challenge=True)
        check = await run_in_threadpool(_validator().validate, auth_header[len("Bearer ") :])
        if check.error == "insufficient_scope":
            return JSONResponse(
                {"error": f"Forbidden — {check.description}"},
                status_code=403,
                headers={"WWW-Authenticate": _ENTRA.challenge(check.error, check.description)},
            )
        if not check.ok:
            return _unauthorized(
                f"Unauthorized — {check.description}",
                challenge=True,
                oauth_error=check.error,
                detail=check.description,
            )
        request.state.principal = principal(check.claims)
        # Info once per MCP session (its first request has no session ID),
        # debug for every message after that.
        log = logger.debug if request.headers.get("mcp-session-id") else logger.info
        log("entra_auth_ok", path=path, **request.state.principal)
        return await call_next(request)


# ─── SSR webhook ─────────────────────────────────────────────────────────────


def _coerce_bool(value: object, default: bool) -> bool:
    """Lenient bool coercion — Power Automate form outputs arrive as strings.

    Only an explicit truthy/falsy string flips the value; anything
    unrecognized keeps the default, so a malformed dry_run can never
    silently switch a request into execute mode.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("1", "true", "yes"):
            return True
        if v in ("0", "false", "no"):
            return False
    return default


async def process_ssr_webhook(mcp: object, payload: object) -> tuple[dict[str, object], int]:
    """Validate an SSR intake payload and run it through ``scm_ssr_execute``.

    Returns ``(body, http_status)``. Separated from the route handler so the
    logic is testable with a stub MCP instance (same pattern as start_ir_run).

    Statuses:
      400 — malformed request (missing/invalid fields; nothing was attempted)
      422 — the SSR tool rejected or failed the request (body carries detail)
      200 — planned (dry-run) or applied
    """
    if not isinstance(payload, dict):
        return {"error": "body must be a JSON object"}, 400

    missing = [
        f for f in ("operation", "target", "ticket_ref") if not str(payload.get(f) or "").strip()
    ]
    if missing:
        return {"error": f"missing required field(s): {', '.join(missing)}"}, 400

    params = {
        "operation": str(payload["operation"]).strip(),
        "target": str(payload["target"]).strip(),
        "ticket_ref": str(payload["ticket_ref"]).strip(),
        "tenant_id": str(payload.get("tenant_id") or "").strip(),
        "folder": str(payload.get("folder") or "").strip(),
        "action": str(payload.get("action") or "add").strip().lower(),
        # Dry-run wins on ambiguity — an execute must say dry_run=false explicitly.
        "dry_run": _coerce_bool(payload.get("dry_run"), default=True),
    }
    requested_by = str(payload.get("requested_by") or "").strip()

    result = await mcp.call_tool("scm_ssr_execute", params)  # type: ignore[attr-defined]
    blocks = result[0] if isinstance(result, tuple) else result
    text = "\n".join(getattr(b, "text", str(b)) for b in blocks)
    try:
        body: dict[str, object] = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        body = {"status": "error", "error": f"unparseable tool response: {text[:500]}"}

    if requested_by:
        body["requested_by"] = requested_by

    status_code = 200 if body.get("status") in ("planned", "applied") else 422
    logger.info(
        "ssr_webhook_processed",
        operation=params["operation"],
        action=params["action"],
        target=params["target"],
        tenant_id=params["tenant_id"],
        ticket_ref=params["ticket_ref"],
        dry_run=params["dry_run"],
        requested_by=requested_by,
        status=body.get("status"),
        http_status=status_code,
    )
    return body, status_code


# ─── Transport security ──────────────────────────────────────────────────────


def _transport_security() -> TransportSecuritySettings | None:
    """Host/Origin (DNS-rebinding) checks for the MCP endpoints.

    FastMCP turns these on for localhost only, because it assumes a loopback
    bind. Behind a real hostname every request then fails with 421 Invalid
    Host header, so a remote client could never connect.

    - Hostnames listed in SCM_MCP_HTTP_ALLOWED_HOSTS (plus localhost, for
      health checks and port-forwards) → checks on for those names.
    - No list, loopback bind → keep FastMCP's localhost-only default.
    - No list, any other bind → checks off. DNS rebinding targets
      unauthenticated local servers; here AuthMiddleware still guards every
      route.
    """
    if _ALLOWED_HOSTS:
        hosts = [*_ALLOWED_HOSTS, *_LOCAL_HOST_PATTERNS]
        origins = [
            *(f"https://{h}" for h in _ALLOWED_HOSTS),
            *(o for o in _ALLOWED_ORIGINS if o != "*"),
            *_LOCAL_ORIGIN_PATTERNS,
        ]
        return TransportSecuritySettings(
            enable_dns_rebinding_protection=True, allowed_hosts=hosts, allowed_origins=origins
        )
    if _HOST in _LOOPBACK_HOSTS:
        return None
    logger.warning(
        "dns_rebinding_protection_off",
        reason="SCM_MCP_HTTP_ALLOWED_HOSTS unset on a non-loopback bind",
        hint="set it to the hostname(s) clients use to turn Host/Origin checks on",
    )
    return TransportSecuritySettings(enable_dns_rebinding_protection=False)


# ─── App factory ─────────────────────────────────────────────────────────────


def create_http_app() -> Starlette:
    """Build the Starlette ASGI app: auth + CORS + MCP (/mcp and /sse) + /health."""
    mcp = create_server()
    security = _transport_security()
    if security is not None:
        mcp.settings.transport_security = security
    mcp.settings.stateless_http = _STATELESS
    # streamable_http_app() creates the session manager, so it comes first;
    # only its /mcp route is mounted here, and the session manager runs in
    # this app's lifespan.
    streamable = mcp.streamable_http_app()
    sse = mcp.sse_app()

    @contextlib.asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        async with mcp.session_manager.run():
            yield

    async def health(_: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "server": "scm-harbourmaster-mcp"})

    async def ir_webhook(request: Request) -> JSONResponse:
        """Planner Phase 3c: alert bridge → IR triage through the Planner loop.

        POST {"alert": {...}, "tenant_id": "...", "folder": "..."} — goes
        through the same AuthMiddleware as every other route. The triage
        template is read-only by construction (no approver is wired), so a
        forged alert cannot make this endpoint execute a write tool.
        """
        from .planner.backend import InProcessBackend
        from .planner.ir import start_ir_run
        from .planner.store import PlanStore

        try:
            payload = await request.json()
        except Exception:
            return JSONResponse({"error": "body must be JSON"}, status_code=400)
        alert = payload.get("alert")
        if not isinstance(alert, dict):
            return JSONResponse({"error": "`alert` must be a JSON object"}, status_code=400)

        plan_id, incident_class = start_ir_run(
            InProcessBackend(mcp),
            PlanStore(),
            alert,
            tenant_id=str(payload.get("tenant_id", "")),
            folder=str(payload.get("folder", "Prisma Access")),
        )
        logger.info("ir_webhook_accepted", plan_id=plan_id, incident_class=incident_class)
        return JSONResponse(
            {"plan_id": plan_id, "incident_class": incident_class, "status": "accepted"},
            status_code=202,
        )

    async def ssr_webhook(request: Request) -> JSONResponse:
        """SSR intake bridge: form/flow front-ends → scm_ssr_execute.

        POST {"operation": ..., "target": ..., "ticket_ref": ..., "action": ...,
        "tenant_id": ..., "dry_run": ...} — the two-phase contract is the
        caller's: submit with dry_run=true (default) to get a before/after
        diff for the approval step, then re-POST with dry_run=false after
        sign-off. Commit remains a separate scm_commit step; this endpoint
        never commits. Unlike /webhook/ir this endpoint can WRITE (to
        ssr_objects-allowlisted objects only), so it is gated behind
        SCM_MCP_HTTP_SSR_WEBHOOK=1 on top of the usual AuthMiddleware.
        """
        if not _SSR_WEBHOOK_ENABLED:
            return JSONResponse(
                {"error": "SSR webhook disabled — set SCM_MCP_HTTP_SSR_WEBHOOK=1 to enable"},
                status_code=403,
            )
        try:
            payload = await request.json()
        except Exception:
            return JSONResponse({"error": "body must be JSON"}, status_code=400)
        body, status_code = await process_ssr_webhook(mcp, payload)
        return JSONResponse(body, status_code=status_code)

    async def protected_resource(_: Request) -> JSONResponse:
        return JSONResponse(_ENTRA.protected_resource_metadata())

    async def authorization_server(_: Request) -> JSONResponse:
        return JSONResponse(_ENTRA.authorization_server_metadata())

    # OAuth discovery, only when Entra is on and the public URL is known.
    oauth_routes: list[Route] = []
    if "entra" in _auth_modes() and _ENTRA.resource_url:
        oauth_routes = [Route(p, protected_resource) for p in _ENTRA.metadata_paths()]
        if _ENTRA.as_metadata:
            oauth_routes.append(Route(ASM_PATH, authorization_server))

    app = Starlette(
        routes=[
            Route("/health", health),
            Route("/healthz", health),
            *oauth_routes,
            Route("/webhook/ir", ir_webhook, methods=["POST"]),
            Route("/webhook/ssr", ssr_webhook, methods=["POST"]),
            *gateway_routes(mcp),
            *streamable.routes,
            Mount("/", app=sse),
        ],
        lifespan=lifespan,
    )

    # CORS — required for browser-based Copilot Studio flows
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_ALLOWED_ORIGINS,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "X-API-Key",
            "Content-Type",
            "Mcp-Session-Id",
            "Mcp-Protocol-Version",
            "Last-Event-ID",
        ],
        expose_headers=["Mcp-Session-Id", "WWW-Authenticate"],
    )

    # Auth — outermost middleware so it runs first
    app.add_middleware(AuthMiddleware)

    return app


def _rest_write_enabled() -> bool:
    from .gateway.policy import rest_writes_enabled

    return rest_writes_enabled()


def main() -> None:
    modes = _auth_modes()
    if not modes or modes - {"apikey", "entra", "none"} or ("none" in modes and len(modes) > 1):
        raise SystemExit(
            f"ERROR: SCM_MCP_HTTP_AUTH_MODE={_AUTH_MODE!r} — use apikey, entra, "
            "apikey,entra or none."
        )
    if "apikey" in modes and not _API_KEY:
        raise SystemExit(
            "ERROR: SCM_MCP_HTTP_API_KEY must be set when SCM_MCP_HTTP_AUTH_MODE includes apikey.\n"
            'Generate one with:  python -c "import secrets; print(secrets.token_urlsafe(32))"\n'
            "Then set:           export SCM_MCP_HTTP_API_KEY=<value>"
        )
    if "entra" in modes:
        problems = _ENTRA.problems()
        if problems:
            raise SystemExit("ERROR: " + "\n       ".join(problems))
        if not _ENTRA.resource_url:
            logger.warning(
                "oauth_metadata_off",
                reason="SCM_MCP_HTTP_RESOURCE_URL unset",
                hint="MCP clients can't discover Entra without it; set it to the public /mcp URL",
            )

    logger.info(
        "http_server_starting",
        host=_HOST,
        port=_PORT,
        auth_mode=_AUTH_MODE,
        resource_url=_ENTRA.resource_url if "entra" in modes else "",
        origins=_ALLOWED_ORIGINS,
        allowed_hosts=_ALLOWED_HOSTS,
        stateless=_STATELESS,
        endpoints=["/mcp", "/sse", "/v1"],
        rest_write=_rest_write_enabled(),
    )

    app = create_http_app()
    uvicorn.run(app, host=_HOST, port=_PORT, log_level="warning")
