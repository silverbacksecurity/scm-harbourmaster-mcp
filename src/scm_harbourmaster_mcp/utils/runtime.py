"""How the server was installed, for messages that tell the operator what to run.

The container image sets ``SCM_MCP_CONTAINER=image``: the code is baked into a
root-owned venv, so editing it in place or ``uv sync`` can't change anything,
and the fix is a new image. ``deploy/compose.dev.yml`` sets it to ``dev``,
bind-mounting ``src/`` over the installed package, so hot reload works again.
Unset means a source checkout or a pip/uv install.
"""

from __future__ import annotations

import os

IMAGE_UPDATE_HINT = (
    "This server runs from a container image, so its code can only change with a "
    "new image: `docker compose pull && docker compose up -d` (or `docker pull` and "
    "re-run the container). For live code edits use deploy/compose.dev.yml."
)


def container_mode() -> str | None:
    """``"image"``, ``"dev"`` or ``None`` (not in the container image)."""
    mode = (os.getenv("SCM_MCP_CONTAINER") or "").strip().lower()
    return mode or None


def in_image() -> bool:
    """True when running from the image with no source mounted over it."""
    return container_mode() == "image"
