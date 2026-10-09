"""Messages and reload behaviour in the container image (no network).

In the image the code lives in a root-owned venv, so scm_reload can't pick up
anything and the operator needs "pull a new image", not "uv run". The dev
compose file bind-mounts src/ and sets SCM_MCP_CONTAINER=dev, where reload
works as usual.
"""

from __future__ import annotations

import importlib

import pytest
from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.tools import reload as reload_mod
from scm_harbourmaster_mcp.utils import runtime


def _tool(name: str):
    mcp = FastMCP("test")
    reload_mod.register_reload_tool(mcp)
    return mcp._tool_manager.get_tool(name).fn


@pytest.mark.parametrize(
    ("value", "mode"), [(None, None), ("", None), ("image", "image"), ("Dev", "dev")]
)
def test_container_mode(monkeypatch, value, mode):
    if value is None:
        monkeypatch.delenv("SCM_MCP_CONTAINER", raising=False)
    else:
        monkeypatch.setenv("SCM_MCP_CONTAINER", value)
    assert runtime.container_mode() == mode
    assert runtime.in_image() is (mode == "image")


def test_reload_in_image_points_at_a_new_image(monkeypatch):
    monkeypatch.setenv("SCM_MCP_CONTAINER", "image")
    calls: list[str] = []
    monkeypatch.setattr(importlib, "reload", lambda m: calls.append(m.__name__))
    out = _tool("scm_reload")()
    assert calls == []
    assert "docker compose pull" in out


def test_reload_in_dev_container_still_reloads(monkeypatch):
    monkeypatch.setenv("SCM_MCP_CONTAINER", "dev")
    calls: list[str] = []
    monkeypatch.setattr(importlib, "reload", lambda m: calls.append(m.__name__) or m)
    out = _tool("scm_reload")(modules=["paths"])
    assert calls == ["scm_harbourmaster_mcp.utils.paths"]
    assert "Reloaded 1 module" in out


@pytest.mark.parametrize("mode", ["image", None])
def test_restart_message(monkeypatch, mode):
    if mode:
        monkeypatch.setenv("SCM_MCP_CONTAINER", mode)
    else:
        monkeypatch.delenv("SCM_MCP_CONTAINER", raising=False)

    class _NoThread:
        def __init__(self, *a, **k):
            pass

        def start(self):
            pass

    monkeypatch.setattr("threading.Thread", _NoThread)
    out = _tool("scm_restart")()
    if mode:
        assert "restart policy" in out and "uv run" not in out
    else:
        assert "uv run scm-mcp" in out
