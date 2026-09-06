"""Shared MCP tool decorator: tenant resolution + exception normalization.

Every ``@mcp.tool()`` function used to repeat the same shape: resolve
``tenant_id`` -> ``client``, wrap the body in ``try/except``, and format any
SDK exception through :func:`~scm_mcp_mssp.utils.errors.handle_scm_exception`.
That boilerplate had drifted — several tool modules invented their own
error-return shapes instead of sharing this one, which is exactly how an
uncaught ``HTTPError`` from ``scm_email_dlp_incidents`` reached a caller
ungracefully before being fixed as a one-off (commit 8ff77b1).

Usage: write the business logic taking ``client`` as its first parameter
instead of ``tenant_id``; ``@scm_tool(get_client)`` presents
``tenant_id: str = ""`` to FastMCP in its place (via an explicit
``__signature__``) and resolves/injects the real client at call time::

    def register_foo_tools(mcp: FastMCP, get_client: Any) -> None:
        tool = scm_tool(get_client)

        @mcp.tool()
        @tool
        def scm_foo_list(client: Any, folder: str, limit: int = 200) -> str:
            '''List foos in a folder.

            Args:
                folder: SCM folder.
                tenant_id: SCM tenant ID.
                limit: Maximum results.
            '''
            results = client.foo.list(folder=folder)[: max(0, limit)]
            return _fmt(results)

If the function body also needs the resolved ``tenant_id`` itself (for
display text or log context — a real, recurring need, not boilerplate),
declare it as an explicit second parameter right after ``client``::

    def scm_foo_report(client: Any, tenant_id: str, folder: str) -> str:
        '''...'''
        return f"# Report for tenant {tenant_id or 'default'}\\n..."

The decorator still exposes a single ``tenant_id`` parameter to FastMCP
either way — this only changes whether the resolved value is also handed to
the function body.

``client`` is intentionally typed ``Any`` rather than the SDK's ``Scm``
class: the decorator resolves the function's signature with
``eval_str=True`` at decoration time (module import time), and ``Scm`` is
conventionally only imported under ``TYPE_CHECKING`` elsewhere in this
codebase, which would make that annotation unresolvable at runtime.

FastMCP always calls registered tool functions with keyword arguments built
from the schema derived from ``__signature__`` (see
``FuncMetadata.call_fn_with_arg_validation``), and existing unit tests invoke
``mcp._tool_manager.get_tool(name).fn(tenant_id=...)`` the same way — so a
keyword-only wrapper is sufficient; no positional-arg handling is needed.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from typing import Any, TypeVar

from .errors import handle_scm_exception

F = TypeVar("F", bound=Callable[..., str])


def scm_tool(get_client: Callable[[str], Any]) -> Callable[[F], F]:
    """Return a decorator bound to one ``register_*_tools(mcp, get_client)`` call.

    The decorated function must take ``client`` as its first parameter. The
    decorator presents ``tenant_id: str = ""`` to FastMCP in its place,
    resolves the real client via ``get_client(tenant_id)``, and normalizes
    any exception raised by the function body through
    :func:`handle_scm_exception`.
    """

    def decorate(func: F) -> F:
        sig = inspect.signature(func, eval_str=True)
        params = list(sig.parameters.values())
        if not params or params[0].name != "client":
            raise TypeError(
                f"{func.__qualname__} must take `client` as its first parameter to use @scm_tool"
            )
        wants_tenant_id = len(params) > 1 and params[1].name == "tenant_id"
        rest = params[2:] if wants_tenant_id else params[1:]

        # FastMCP only ever calls tools by keyword (see module docstring), so
        # every exposed parameter is made KEYWORD_ONLY here — that sidesteps
        # Signature's "required argument after one with a default" ordering
        # rule, which would otherwise reject `tenant_id`'s default sitting
        # ahead of a required parameter like `folder`.
        tenant_param = inspect.Parameter(
            "tenant_id",
            inspect.Parameter.KEYWORD_ONLY,
            default="",
            annotation=str,
        )
        rest_params = [p.replace(kind=inspect.Parameter.KEYWORD_ONLY) for p in rest]
        new_sig = sig.replace(parameters=[tenant_param, *rest_params])

        @functools.wraps(func)
        def wrapper(**kwargs: Any) -> str:
            bound = new_sig.bind(**kwargs)
            bound.apply_defaults()
            call_kwargs = dict(bound.arguments)
            tenant_id = call_kwargs.pop("tenant_id", "")
            try:
                client = get_client(tenant_id)
                if wants_tenant_id:
                    return func(client, tenant_id, **call_kwargs)
                return func(client, **call_kwargs)
            except Exception as exc:
                return (
                    f"Error: {handle_scm_exception(exc, tool=func.__name__, tenant_id=tenant_id)}"
                )

        wrapper.__signature__ = new_sig  # type: ignore[attr-defined]
        return wrapper  # type: ignore[return-value]

    return decorate
