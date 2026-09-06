"""Structured logging setup via structlog."""

from __future__ import annotations

import logging
import sys
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

import structlog


def configure_logging(level: str = "INFO", json_logs: bool = True) -> None:
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    if json_logs:
        renderer: structlog.types.Processor = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processor=renderer,
        foreign_pre_chain=shared_processors,
    )

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Silence noisy third-party loggers
    for noisy in (
        "httpx",
        "httpcore",
        "urllib3",
        "requests",
        "anyio",
        "asyncio",
        "websockets",
        "mcp.server",
        "mcp.client",
    ):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _defuse_pan_scm_sdk_stdout_logging()


def _defuse_pan_scm_sdk_stdout_logging() -> None:
    """pan-scm-sdk attaches raw ``StreamHandler(sys.stdout)`` handlers to its
    loggers in two places: ``scm.utils.logging.setup_logger`` (used by
    ``scm.auth`` and every ``scm.config.*`` submodule at import time) and
    inline in ``Scm.__init__`` for the bare ``"scm"`` logger, guarded by
    ``if not self.logger.handlers`` (attached lazily, on first tenant client
    construction). Over stdio transport, any error-level SDK log (e.g. a
    failed token fetch) writes non-JSON text straight into the MCP
    JSON-RPC stream and corrupts it for the client.

    Three-part fix: strip handlers already attached by eagerly-imported
    submodules (``scm.auth`` via ``scm.client``); patch the factory so
    submodules imported later (``scm.config.*``) propagate into our
    stderr-bound root handler instead; and pre-seed the bare ``"scm"``
    logger with a handler now so ``Scm.__init__``'s guard sees it as
    already configured and skips attaching its own stdout handler when
    tenant clients are constructed later.
    """
    for name, existing in list(logging.root.manager.loggerDict.items()):
        if (name == "scm" or name.startswith("scm.")) and isinstance(existing, logging.Logger):
            for h in list(existing.handlers):
                if isinstance(h, logging.StreamHandler) and h.stream is sys.stdout:
                    existing.removeHandler(h)

    scm_root_logger = logging.getLogger("scm")
    if not scm_root_logger.handlers:
        scm_root_logger.addHandler(logging.NullHandler())

    try:
        import scm.utils.logging as scm_logging
    except ImportError:
        return

    def _propagating_setup_logger(name: str, log_level: int = logging.ERROR) -> logging.Logger:
        propagating_logger = logging.getLogger(name)
        propagating_logger.setLevel(log_level)
        return propagating_logger

    scm_logging.setup_logger = _propagating_setup_logger


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)  # type: ignore[no-any-return]


@contextmanager
def bind_tool_context(**fields: Any) -> Generator[None, None, None]:
    """Bind key/value pairs to structlog context for the duration of a tool call.

    Usage::

        with bind_tool_context(tool="scm_commit", tenant_id=tenant_id, folder=folder):
            ...

    All log events emitted inside the block automatically carry the bound fields.
    """
    structlog.contextvars.bind_contextvars(**fields)
    try:
        yield
    finally:
        structlog.contextvars.unbind_contextvars(*fields.keys())
