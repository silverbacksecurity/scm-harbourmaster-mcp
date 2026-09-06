"""Shared response formatting for MCP tools."""

from __future__ import annotations

import json
from typing import Any


def format_result(data: Any) -> str:
    """Serialise a Pydantic model, list of models, or plain dict to JSON."""
    if hasattr(data, "model_dump"):
        return json.dumps(data.model_dump(), indent=2, default=str)
    if isinstance(data, list):
        return json.dumps(
            [d.model_dump() if hasattr(d, "model_dump") else d for d in data],
            indent=2,
            default=str,
        )
    return json.dumps(data, indent=2, default=str)
