"""Turn MCP tool input schemas into what each LLM platform accepts.

FastMCP emits JSON Schema with ``$defs``/``$ref``, ``title`` on every
property and ``anyOf: [T, null]`` for optional values. Function-calling APIs
accept narrower dialects, so every converter inlines references first and
then keeps an explicit allowlist of keywords. A keyword not on the list
never reaches the output.
"""

from __future__ import annotations

import copy
from collections.abc import Iterable, Mapping
from typing import Any

# JSON Schema keywords kept for OpenAI-style function parameters (DeepSeek,
# Qwen, Kimi, OpenAI, Ollama, vLLM, Groq).
OPENAI_KEYWORDS: frozenset[str] = frozenset(
    {
        "type",
        "description",
        "enum",
        "properties",
        "required",
        "items",
        "anyOf",
        "default",
        "minimum",
        "maximum",
        "minItems",
        "maxItems",
        "format",
        "additionalProperties",
    }
)

# Gemini FunctionDeclaration parameters: an OpenAPI 3.0 subset. Optional
# values become ``nullable`` rather than ``anyOf`` with null.
GEMINI_KEYWORDS: frozenset[str] = frozenset(
    {"type", "format", "description", "nullable", "enum", "properties", "required", "items"}
)

# OpenAPI 3.0 schema objects (ChatGPT custom GPT Actions).
OPENAPI3_KEYWORDS: frozenset[str] = frozenset(
    {
        "type",
        "format",
        "description",
        "nullable",
        "enum",
        "properties",
        "required",
        "items",
        "default",
        "minimum",
        "maximum",
        "minItems",
        "maxItems",
        "additionalProperties",
    }
)

# Swagger 2.0 schema objects (Power Platform custom connectors).
SWAGGER2_KEYWORDS: frozenset[str] = frozenset(
    {
        "type",
        "format",
        "description",
        "x-nullable",
        "enum",
        "properties",
        "required",
        "items",
        "default",
        "minimum",
        "maximum",
        "minItems",
        "maxItems",
        "additionalProperties",
    }
)


def inline_refs(schema: Mapping[str, Any]) -> dict[str, Any]:
    """Replace every local ``$ref`` with its ``$defs`` target and drop ``$defs``."""
    root = copy.deepcopy(dict(schema))
    defs = root.pop("$defs", None) or root.pop("definitions", None) or {}

    def walk(node: Any, seen: tuple[str, ...]) -> Any:
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str) and ref.rsplit("/", 1)[-1] in defs:
                name = ref.rsplit("/", 1)[-1]
                if name in seen:  # recursive model: stop at a plain object
                    return {"type": "object"}
                target = walk(defs[name], (*seen, name))
                extra = {k: walk(v, seen) for k, v in node.items() if k != "$ref"}
                return {**target, **extra}
            return {k: walk(v, seen) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(v, seen) for v in node]
        return node

    return walk(root, ())


def _collapse_nullable(node: dict[str, Any], marker: str | None) -> dict[str, Any]:
    """``anyOf: [T, {type: null}]`` → ``T`` (+ ``marker: true`` when given)."""
    options = node.get("anyOf")
    if not isinstance(options, list):
        return node
    non_null = [o for o in options if not (isinstance(o, dict) and o.get("type") == "null")]
    if not non_null:
        return {k: v for k, v in node.items() if k != "anyOf"}
    first = non_null[0] if isinstance(non_null[0], dict) else {}
    merged = {**first, **{k: v for k, v in node.items() if k != "anyOf"}}
    if marker and len(non_null) < len(options):
        merged[marker] = True
    return merged


def _filter(
    node: Any, keywords: frozenset[str], nullable_marker: str | None, keep_anyof: bool
) -> Any:
    if isinstance(node, list):
        return [_filter(v, keywords, nullable_marker, keep_anyof) for v in node]
    if not isinstance(node, dict):
        return node
    if not keep_anyof:
        node = _collapse_nullable(node, nullable_marker)
    out: dict[str, Any] = {}
    for key, value in node.items():
        if key not in keywords:
            continue
        if key == "default" and value is None and nullable_marker == "x-nullable":
            continue  # Swagger 2.0 has no null type, so a null default is invalid
        if key == "properties" and isinstance(value, dict):
            out[key] = {
                name: _filter(prop, keywords, nullable_marker, keep_anyof)
                for name, prop in value.items()
            }
        elif key in ("items", "anyOf", "additionalProperties") and isinstance(value, dict | list):
            out[key] = _filter(value, keywords, nullable_marker, keep_anyof)
        else:
            out[key] = value
    if "required" in out and isinstance(out.get("properties"), dict):
        out["required"] = [r for r in out["required"] if r in out["properties"]]
        if not out["required"]:
            del out["required"]
    return out


def _params(schema: Mapping[str, Any] | None) -> dict[str, Any]:
    base = dict(schema or {"type": "object", "properties": {}})
    base.setdefault("type", "object")
    base.setdefault("properties", {})
    return inline_refs(base)


def openai_parameters(schema: Mapping[str, Any] | None) -> dict[str, Any]:
    return _filter(_params(schema), OPENAI_KEYWORDS, None, keep_anyof=True)


def gemini_parameters(schema: Mapping[str, Any] | None) -> dict[str, Any]:
    return _filter(_params(schema), GEMINI_KEYWORDS, "nullable", keep_anyof=False)


def openapi3_schema(schema: Mapping[str, Any] | None) -> dict[str, Any]:
    return _filter(_params(schema), OPENAPI3_KEYWORDS, "nullable", keep_anyof=False)


def swagger2_schema(schema: Mapping[str, Any] | None) -> dict[str, Any]:
    return _filter(_params(schema), SWAGGER2_KEYWORDS, "x-nullable", keep_anyof=False)


# ─── Tool list formats ───────────────────────────────────────────────────────


def to_openai(tools: Iterable[Any]) -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description or "",
                "parameters": openai_parameters(t.inputSchema),
            },
        }
        for t in tools
    ]


def to_gemini(tools: Iterable[Any]) -> dict[str, Any]:
    return {
        "function_declarations": [
            {
                "name": t.name,
                "description": t.description or "",
                "parameters": gemini_parameters(t.inputSchema),
            }
            for t in tools
        ]
    }


def to_mcp(tools: Iterable[Any]) -> list[dict[str, Any]]:
    return [
        {"name": t.name, "description": t.description or "", "inputSchema": t.inputSchema}
        for t in tools
    ]


# ─── OpenAPI documents ───────────────────────────────────────────────────────

_CALL_RESULT = {
    "type": "object",
    "properties": {
        "tool": {"type": "string"},
        "content": {"type": "string", "description": "The tool's output"},
        "truncated": {"type": "boolean"},
        "total_chars": {"type": "integer"},
    },
}
_ERROR = {"type": "object", "properties": {"error": {"type": "string"}}}
_SUMMARY_MAX = 300  # OpenAPI operation summaries; GPT Actions truncate long ones


def _summary(description: str) -> str:
    first = (description or "").strip().split("\n\n", 1)[0].replace("\n", " ").strip()
    return first[:_SUMMARY_MAX]


def openapi3_document(tools: Iterable[Any], server_url: str, title: str) -> dict[str, Any]:
    paths: dict[str, Any] = {}
    for t in tools:
        paths[f"/v1/tools/{t.name}/call"] = {
            "post": {
                "operationId": t.name,
                "summary": _summary(t.description or ""),
                "description": t.description or "",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {"arguments": openapi3_schema(t.inputSchema)},
                                "required": ["arguments"],
                            }
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Tool output",
                        "content": {"application/json": {"schema": _CALL_RESULT}},
                    },
                    "default": {
                        "description": "Refused or failed",
                        "content": {"application/json": {"schema": _ERROR}},
                    },
                },
            }
        }
    return {
        "openapi": "3.0.3",
        "info": {"title": title, "version": "1"},
        "servers": [{"url": server_url}],
        "paths": paths,
        "components": {
            "securitySchemes": {"apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"}}
        },
        "security": [{"apiKey": []}],
    }


def swagger2_document(tools: Iterable[Any], host: str, scheme: str, title: str) -> dict[str, Any]:
    paths: dict[str, Any] = {}
    for t in tools:
        paths[f"/v1/tools/{t.name}/call"] = {
            "post": {
                "operationId": t.name,
                "summary": _summary(t.description or "")[:80],
                "description": t.description or "",
                "consumes": ["application/json"],
                "produces": ["application/json"],
                "parameters": [
                    {
                        "name": "body",
                        "in": "body",
                        "required": True,
                        "schema": {
                            "type": "object",
                            "properties": {"arguments": swagger2_schema(t.inputSchema)},
                            "required": ["arguments"],
                        },
                    }
                ],
                "responses": {
                    "200": {"description": "Tool output", "schema": _CALL_RESULT},
                    "default": {"description": "Refused or failed", "schema": _ERROR},
                },
            }
        }
    return {
        "swagger": "2.0",
        "info": {"title": title, "version": "1"},
        "host": host,
        "schemes": [scheme],
        "paths": paths,
        "securityDefinitions": {"apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"}},
        "security": [{"apiKey": []}],
    }
