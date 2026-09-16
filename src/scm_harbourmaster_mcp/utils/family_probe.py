"""Family probe helper — discover which API families a tenant can access.

Used before scaffolding tools for newly-catalogued families.  Probes each
family's base URL with the tenant's bearer token and reports the HTTP status
code so we know whether the tenant is entitled, blocked by RBAC, or the API
simply doesn't exist at that URL.

Usage:
    from scm_harbourmaster_mcp.utils.family_probe import probe_family
    results = probe_family(base_url, client, paths=["/v1/some/endpoint"])
    # results = {"/v1/some/endpoint": 200, ...}
"""

from __future__ import annotations

import contextlib
from typing import Any


def _bearer_session(client: Any) -> Any:
    """Return a plain ``requests.Session`` with a fresh Bearer token.

    Extracts the token from the SDK client's OAuth session (refreshing first if
    expired) and builds a standard requests.Session — the same pattern used by
    ``extractor._bearer_session_for`` and ``compliance._bearer_session``.
    """
    import requests as _requests

    oauth = getattr(client, "oauth_client", None)
    if oauth is not None:
        with contextlib.suppress(Exception):
            if getattr(oauth, "is_expired", False):
                oauth.refresh_token()

    token = None
    sdk_session = getattr(client, "session", None)
    if sdk_session is not None:
        raw = getattr(sdk_session, "token", None)
        if raw:
            token = raw.get("access_token")

    sess = _requests.Session()
    if token:
        sess.headers["Authorization"] = f"Bearer {token}"
    return sess


def probe_family(
    base_url: str,
    client: Any,
    paths: list[str],
    timeout: tuple[float, float] = (4.0, 10.0),
) -> dict[str, int]:
    """Probe a family's endpoints with the tenant's bearer token.

    Args:
        base_url:  The API base URL (e.g. ``https://api.sase.paloaltonetworks.com``).
        client:    An authenticated SCM SDK client (from ``get_client(tenant_id)``).
        paths:     Relative paths to probe (e.g. ``["/v1/remote-networks"]``).
        timeout:   ``(connect, read)`` timeout in seconds.

    Returns:
        Dict mapping each **path** to its HTTP status code, or ``-1`` if the
        request failed at the transport level (DNS, connection refused, TLS error).
    """
    session = _bearer_session(client)
    results: dict[str, int] = {}

    for path in paths:
        url = f"{base_url.rstrip('/')}{path}"
        results[path], _ = probe_endpoint(session, url, timeout=timeout)

    return results


def probe_endpoint(
    session: Any,
    url: str,
    *,
    method: str = "GET",
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    json_body: Any = None,
    timeout: tuple[float, float] = (4.0, 10.0),
) -> tuple[int, str]:
    """Send one probe request and return ``(status_code, detail)``.

    The response is streamed and only a short error snippet is ever read, so a
    probe against a large collection costs the status line, not the payload.
    ``status_code`` is ``-1`` on a transport failure, with the exception text
    as ``detail``. Callers are responsible for only passing read-only requests.
    """
    try:
        kwargs: dict[str, Any] = {"params": params, "headers": headers, "timeout": timeout}
        if method.upper() == "GET":
            resp = session.get(url, stream=True, **kwargs)
        else:
            resp = session.request(method.upper(), url, json=json_body, stream=True, **kwargs)
    except Exception as exc:
        return -1, str(exc)[:300]

    detail = ""
    try:
        if resp.status_code >= 400:
            detail = str(getattr(resp, "text", "") or "")[:300]
    except Exception:
        detail = ""
    finally:
        with contextlib.suppress(Exception):
            resp.close()
    return int(resp.status_code), detail


def probe_summary(results: dict[str, int]) -> str:
    """Render probe results as a human-readable summary string.

    Args:
        results:  The dict returned by :func:`probe_family`.

    Returns:
        A multi-line summary suitable for logging or display.
    """
    lines = ["Family probe results:"]
    for path, code in sorted(results.items()):
        if code == 200:
            label = "OK"
        elif code == 401:
            label = "UNAUTHORIZED — bad or missing credentials"
        elif code == 403:
            label = "FORBIDDEN — RBAC role missing this permission"
        elif code == 404:
            label = "NOT FOUND — endpoint may not exist at this base URL"
        elif code == -1:
            label = "TRANSPORT ERROR — DNS, connection refused, or TLS failure"
        else:
            label = f"HTTP {code}"
        lines.append(f"  {path:50s} → {label}")
    return "\n".join(lines)
