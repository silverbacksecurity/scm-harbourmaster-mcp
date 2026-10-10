"""``/v1`` routes: tool schemas, tool calls and OpenAPI documents, per gateway key.

    GET  /v1/tools?format=openai|gemini|mcp&toolset=a,b
    POST /v1/tools/{name}/call      {"arguments": {...}, "max_chars": 20000}
    GET  /v1/openapi.json[?version=2]&toolset=a,b[&max_description=300]

Authenticate with ``X-API-Key: <key>`` or ``Authorization: Bearer <key>``.
Never as a query parameter: URLs end up in proxy and browser logs. A tool
the key may not use answers exactly like a tool that doesn't exist (404),
so a key can't map what it is missing.
"""

from __future__ import annotations

import os
import time
from collections import deque
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from ..toolsets import UnknownToolsetError, resolve_toolsets
from ..utils.logging import get_logger
from ..utils.tool_annotations import tool_access
from . import audit
from .keys import GatewayKey, authenticate, load_keys
from .policy import GatewayDenied, allowed_tools, check_call, tools_by_toolset
from .schemas import (
    cap_descriptions,
    openapi3_document,
    swagger2_document,
    to_gemini,
    to_mcp,
    to_openai,
)

logger = get_logger(__name__)

DEFAULT_MAX_CHARS = 60_000
_NOT_FOUND = {"error": "tool not found"}


def _max_chars() -> int:
    try:
        return max(1_000, int(os.getenv("SCM_MCP_GATEWAY_MAX_CHARS", DEFAULT_MAX_CHARS)))
    except ValueError:
        return DEFAULT_MAX_CHARS


class _RateLimiter:
    """Sliding one-minute window per key. In-process: per replica."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = {}

    def allow(self, key: GatewayKey) -> bool:
        now = time.monotonic()
        hits = self._hits.setdefault(key.key_id, deque())
        while hits and now - hits[0] > 60:
            hits.popleft()
        if len(hits) >= key.rate_per_minute:
            return False
        hits.append(now)
        return True


def _scope(name: str) -> str:
    from ..planner.manifest import load_manifest

    return str(load_manifest().policy(name).scope)


def _text(result: Any) -> str:
    blocks = result[0] if isinstance(result, tuple) else result
    return "\n".join(getattr(b, "text", str(b)) for b in blocks or [])


def gateway_routes(mcp: Any, keys: dict[str, GatewayKey] | None = None) -> list[Route]:
    """Build the ``/v1`` routes over *mcp*. Keys load from settings when not given."""
    key_table = load_keys() if keys is None else keys
    limiter = _RateLimiter()
    logger.info("gateway_keys_loaded", count=len(key_table), key_ids=sorted(key_table))

    def _key_for(request: Request) -> GatewayKey | None:
        provided = request.headers.get("x-api-key")
        if not provided:
            auth = request.headers.get("authorization", "")
            if auth.lower().startswith("bearer "):
                provided = auth[7:]
        return authenticate(provided, key_table)

    async def _visible(key: GatewayKey, request: Request) -> dict[str, Any]:
        tools = allowed_tools(key, await mcp.list_tools(), tools_by_toolset(mcp))
        requested = request.query_params.get("toolset", "")
        if requested:
            try:
                wanted = set(resolve_toolsets(requested))
            except UnknownToolsetError as exc:
                raise GatewayDenied(400, str(exc)) from exc
            # Narrow only: a toolset outside the key's own adds nothing.
            toolset_map = tools_by_toolset(mcp)
            names = set().union(
                *(toolset_map.get(ts, frozenset()) for ts in wanted & set(key.toolsets))
            )
            tools = {n: t for n, t in tools.items() if n in names}
        return tools

    def _deny(exc: GatewayDenied) -> JSONResponse:
        return JSONResponse({"error": exc.message}, status_code=exc.status)

    def _unauthorized() -> JSONResponse:
        return JSONResponse(
            {"error": "Unauthorized — send a gateway key as X-API-Key or Bearer token"},
            status_code=401,
        )

    async def list_tools(request: Request) -> JSONResponse:
        key = _key_for(request)
        if key is None:
            return _unauthorized()
        fmt = request.query_params.get("format", "openai").lower()
        try:
            tools = list((await _visible(key, request)).values())
        except GatewayDenied as exc:
            return _deny(exc)
        if fmt == "openai":
            return JSONResponse({"tools": to_openai(tools)})
        if fmt == "gemini":
            return JSONResponse({"tools": [to_gemini(tools)]})
        if fmt == "mcp":
            return JSONResponse({"tools": to_mcp(tools)})
        return JSONResponse({"error": "format must be openai, gemini or mcp"}, status_code=400)

    async def call_tool(request: Request) -> JSONResponse:
        key = _key_for(request)
        if key is None:
            return _unauthorized()
        name = request.path_params["name"]
        if not limiter.allow(key):
            audit.record(key_id=key.key_id, tool=name, outcome="rate_limited")
            return JSONResponse(
                {"error": f"rate limit: {key.rate_per_minute} calls per minute"},
                status_code=429,
                headers={"Retry-After": "60"},
            )
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "body must be JSON"}, status_code=400)
        if not isinstance(body, dict) or not isinstance(body.get("arguments", {}), dict):
            return JSONResponse({"error": 'body must be {"arguments": {...}}'}, status_code=400)

        tool = allowed_tools(key, await mcp.list_tools(), tools_by_toolset(mcp)).get(name)
        if tool is None:
            audit.record(key_id=key.key_id, tool=name, outcome="not_found")
            return JSONResponse(_NOT_FOUND, status_code=404)

        arguments = body.get("arguments") or {}
        digest = audit.args_digest(arguments)
        try:
            args, tenants = check_call(key, tool.inputSchema or {}, arguments, _scope(name))
        except GatewayDenied as exc:
            audit.record(
                key_id=key.key_id,
                tool=name,
                args_sha256=digest,
                outcome="denied",
                status=exc.status,
                reason=exc.message,
            )
            return _deny(exc)

        is_write = tool_access(name) == "write"
        started = audit.record(
            key_id=key.key_id,
            tool=name,
            tenants=tenants,
            args_sha256=digest,
            llm_provider=key.llm_provider,
            write=is_write,
            outcome="started",
        )
        if is_write and not started:
            return JSONResponse({"error": "audit log unavailable; write refused"}, status_code=503)

        t0 = time.perf_counter()
        try:
            text = _text(await mcp.call_tool(name, args))
        except Exception as exc:  # ToolError (bad arguments) and tool crashes
            audit.record(
                key_id=key.key_id,
                tool=name,
                tenants=tenants,
                args_sha256=digest,
                outcome="error",
                error=type(exc).__name__,
                duration_s=round(time.perf_counter() - t0, 3),
            )
            return JSONResponse({"error": str(exc) or type(exc).__name__}, status_code=422)

        limit = _max_chars()
        try:
            requested_max = int(body.get("max_chars") or limit)
        except (TypeError, ValueError):
            requested_max = limit
        cap = max(1, min(limit, requested_max))
        audit.record(
            key_id=key.key_id,
            tool=name,
            tenants=tenants,
            args_sha256=digest,
            outcome="ok",
            chars=len(text),
            duration_s=round(time.perf_counter() - t0, 3),
        )
        return JSONResponse(
            {
                "tool": name,
                "content": text[:cap],
                "truncated": len(text) > cap,
                "total_chars": len(text),
            }
        )

    async def openapi(request: Request) -> JSONResponse:
        key = _key_for(request)
        if key is None:
            return _unauthorized()
        try:
            tools = list((await _visible(key, request)).values())
        except GatewayDenied as exc:
            return _deny(exc)
        cap_raw = request.query_params.get("max_description", "")
        try:
            cap = int(cap_raw) if cap_raw else 0
        except ValueError:
            cap = -1
        if cap_raw and cap < 50:
            return JSONResponse(
                {"error": "max_description must be an integer >= 50"}, status_code=400
            )
        title = "scm-harbourmaster-mcp tools"
        if request.query_params.get("version") == "2":
            doc = swagger2_document(tools, request.url.netloc, request.url.scheme, title)
        else:
            doc = openapi3_document(tools, f"{request.url.scheme}://{request.url.netloc}", title)
        return JSONResponse(cap_descriptions(doc, cap) if cap else doc)

    return [
        Route("/v1/tools", list_tools, methods=["GET"]),
        Route("/v1/tools/{name}/call", call_tool, methods=["POST"]),
        Route("/v1/openapi.json", openapi, methods=["GET"]),
    ]
