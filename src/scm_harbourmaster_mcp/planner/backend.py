"""
Planner Phase 2 — tool backends.

The loop talks to tools through the ToolBackend protocol (executor.py).
InProcessBackend executes against a live FastMCP instance in the same
process — the natural backend for the scheduled-ops MVP, where the Planner
runs inside (or alongside) the server. A Streamable-HTTP MCP client backend
can implement the same protocol later for remote execution (Copilot Studio
transport) without touching the loop.
"""

from __future__ import annotations

import asyncio
from typing import Any


class InProcessBackend:
    """Execute tools on a FastMCP instance in this process.

    Uses asyncio.run per call — callers must not already be inside a
    running event loop (true for CLI and cron entrypoints).
    """

    def __init__(self, mcp: Any) -> None:
        self.mcp = mcp

    def call(self, tool_name: str, params: dict[str, Any]) -> str:
        result = asyncio.run(self.mcp.call_tool(tool_name, params))
        blocks = result[0] if isinstance(result, tuple) else result
        return "\n".join(getattr(b, "text", str(b)) for b in blocks)
