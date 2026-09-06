"""Error handling and SCM exception mapping."""

from __future__ import annotations

from typing import Any

import structlog

_logger = structlog.get_logger(__name__)

# SDK exceptions that represent expected / user-recoverable conditions.
# These are logged at WARNING rather than ERROR to keep alert noise low.
_EXPECTED_EXCEPTION_NAMES = frozenset(
    {
        "ObjectNotPresentError",
        "InvalidObjectError",
        "NotFoundError",
        "NameNotUniqueError",
        "MissingQueryParameterError",
        "HTTPStatusError",
        "AuthenticationError",
        "EmptyFieldError",
        "ReferenceNotZeroError",
    }
)


class ScmMcpError(Exception):
    """Base error for this MCP server."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.details = details or {}


class TenantNotFoundError(ScmMcpError):
    """Requested tenant is not configured."""


class AuthenticationError(ScmMcpError):
    """OAuth2 token acquisition failed."""


class ResourceNotFoundError(ScmMcpError):
    """SCM resource does not exist."""


class ValidationError(ScmMcpError):
    """Input failed Pydantic or SCM validation."""


def handle_scm_exception(exc: Exception, **log_context: Any) -> str:
    """Convert an SDK exception into a user-friendly error string and log it.

    Expected SDK errors (not-found, validation, auth) are logged at WARNING.
    Unexpected errors are logged at ERROR with a full stack trace.
    """
    name = type(exc).__name__
    # pan-scm-sdk's APIError.__str__ only renders `details`/`http_status_code`/
    # `error_code` — when all three are unset (e.g. a bare 404 with no response
    # body) it returns "" even though the real text lives in exc.message.
    # Fall back to that attribute so callers never see a blank error string.
    msg = str(exc) or str(getattr(exc, "message", "") or "") or "(no error detail available)"
    formatted = f"[{name}] {msg}"

    if name in _EXPECTED_EXCEPTION_NAMES:
        _logger.warning("scm_api_error", exc_type=name, error=msg, **log_context)
    else:
        _logger.error(
            "scm_unexpected_error",
            exc_type=name,
            error=msg,
            exc_info=True,
            **log_context,
        )

    return formatted
