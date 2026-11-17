"""Shared plumbing for direct SCM REST calls that pan-scm-sdk does not cover.

pan-scm-sdk 0.15.1 is the latest release and leaves gaps (Compliance
Frameworks, ADNSR, snippet association, URL ``continue`` and others). Tools
call those endpoints directly. This module holds the pieces they all need,
which used to be copied into each tool module:

- the API host and base-path constants
- the "not licensed / not provisioned" status set
- OAuth token refresh and a plain bearer-token ``requests.Session``
- a single request primitive returning a :class:`RestResult`
- helpers for the two common response contracts (list-or-raise and
  ``(status, data, error)``)

Tool modules keep thin local wrappers (``_bearer_session``, ``_rest_get``,
``_rest_call``) so their return contracts and test monkeypatch points stay
unchanged.

Region header: pass ``region`` only when the API needs it. It is sent
lowercased because some APIs (Compliance Frameworks, SAA) silently select a
data region from it and only accept lowercase values. Omitting it on those
APIs gives an empty-looking 200, so there is deliberately no default.
"""

from __future__ import annotations

import contextlib
import json as _json
from dataclasses import dataclass
from typing import Any

SASE_HOST = "https://api.sase.paloaltonetworks.com"
STRATA_HOST = "https://api.strata.paloaltonetworks.com"

CONFIG_V1 = f"{SASE_HOST}/config/v1"
SSE_CONFIG_V1 = f"{SASE_HOST}/sse/config/v1"

# Statuses the SCM APIs return when a feature is unlicensed, unprovisioned or
# outside the service account's RBAC scope. Callers treat them as "no data".
# Note: 401 is in this set for historical reasons and can mask a real auth
# failure.
NOT_LICENSED: frozenset[int] = frozenset({401, 403, 404, 424})

DEFAULT_TIMEOUT: tuple[int, int] = (10, 30)


def exc_status(exc: BaseException) -> int | None:
    """Return the HTTP status attached to a requests-style exception, if any."""
    resp = getattr(exc, "response", None)
    return getattr(resp, "status_code", None)


def refresh_token(client: Any) -> None:
    """Refresh the OAuth token unconditionally before direct-session calls.

    ``is_expired``/``token_expires_soon`` can miss stale tokens, so a
    refresh is always attempted first, with the expiry checks as a fallback.
    Failures are swallowed: the request itself will surface any auth error.
    """
    oauth = getattr(client, "oauth_client", None)
    if oauth is None:
        return
    try:
        oauth.refresh_token()
    except Exception:
        try:
            if oauth.is_expired or oauth.token_expires_soon:
                oauth.refresh_token()
        except Exception:  # noqa: S110 - best-effort; the request surfaces auth errors
            pass


def bearer_session(client: Any) -> Any:
    """Return a plain ``requests.Session`` carrying the client's bearer token.

    ``client.session`` is a requests_oauthlib ``OAuth2Session``. It raises
    ``TokenExpiredError`` for direct calls outside the SDK wrappers, and its
    retry adapter hides 5xx responses. A plain session avoids both.

    The token is refreshed only when the SDK reports it expired.
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


@dataclass(frozen=True)
class RestResult:
    """Outcome of :func:`request`.

    ``status`` is -1 for a transport failure (``error`` holds the reason).
    ``data`` is the parsed JSON body, or None when the body is not JSON.
    ``text`` is the first 500 characters of a non-JSON body.
    """

    status: int
    data: Any = None
    text: str = ""
    error: str = ""

    @property
    def not_licensed(self) -> bool:
        return self.status in NOT_LICENSED

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


def _region_headers(headers: dict[str, str] | None, region: str | None) -> dict[str, str] | None:
    if not region:
        return headers
    merged = dict(headers or {})
    merged["x-panw-region"] = region.strip().lower()
    return merged


def request(
    session: Any,
    method: str,
    url: str,
    *,
    params: dict[str, Any] | None = None,
    json: Any = None,
    headers: dict[str, str] | None = None,
    region: str | None = None,
    timeout: tuple[int, int] = DEFAULT_TIMEOUT,
) -> RestResult:
    """Make one REST call and never raise.

    Only the keyword arguments that are set are passed to the session, so
    mock sessions in tests see the same call shape as before.
    """
    kwargs: dict[str, Any] = {"timeout": timeout}
    if params is not None:
        kwargs["params"] = params
    if json is not None:
        kwargs["json"] = json
    hdrs = _region_headers(headers, region)
    if hdrs:
        kwargs["headers"] = hdrs

    method = method.upper()
    fn = {
        "GET": getattr(session, "get", None),
        "POST": getattr(session, "post", None),
        "PUT": getattr(session, "put", None),
        "PATCH": getattr(session, "patch", None),
        "DELETE": getattr(session, "delete", None),
    }.get(method)
    if fn is None:
        return RestResult(-1, error=f"Unknown method: {method}")

    try:
        resp = fn(url, **kwargs)
    except Exception as exc:
        return RestResult(-1, error=str(exc))

    try:
        return RestResult(resp.status_code, data=resp.json())
    except Exception:
        return RestResult(resp.status_code, text=(getattr(resp, "text", "") or "")[:500])


def call(
    session: Any,
    method: str,
    url: str,
    json_body: dict | None = None,
    params: dict | None = None,
    timeout: tuple = DEFAULT_TIMEOUT,
) -> tuple[int, dict | list | None, str]:
    """``(status, data_or_None, error)`` contract used by write-capable tools.

    Not-licensed statuses return ``(status, None, "")``. A transport failure
    returns ``(-1, None, reason)``. A non-JSON body returns its text as the
    error.
    """
    res = request(session, method, url, params=params, json=json_body, timeout=timeout)
    if res.status == -1:
        return -1, None, res.error
    if res.not_licensed:
        return res.status, None, ""
    if res.data is None:
        return res.status, None, res.text
    return res.status, res.data, ""


def get_list(
    session: Any,
    url: str,
    params: dict | None = None,
    *,
    keys: tuple[str, ...] = ("data", "items"),
    timeout: tuple = (5, 15),
) -> list[dict]:
    """GET a collection, returning ``[]`` when unlicensed and raising otherwise.

    The list is taken from a bare JSON array or from the first of ``keys``
    present in an object body. Transport exceptions carrying a not-licensed
    status also return ``[]``; any other failure raises.
    """
    try:
        resp = session.get(url, params=params, timeout=timeout)
    except Exception as exc:
        if exc_status(exc) in NOT_LICENSED:
            return []
        raise
    if resp.status_code in NOT_LICENSED:
        return []
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, list):
        return data
    for key in keys:
        if key in data:
            return data[key]
    return []


# ---------------------------------------------------------------------------
# Object writes with the API's field names
# ---------------------------------------------------------------------------

# pan-scm-sdk (0.15.1) create()/update() serialise these resources without
# by_alias, so the aliased fields never reach SCM and are dropped without an
# error: a URL profile's "continue" action and a HIP object's "is" criteria.
# Writes to them must go over REST.
#
# Vulnerability profiles are deliberately absent. The SDK model aliases a
# rule's vendor filter to "vendor-id", but the API's JSON field is
# ``vendor_id``: sending "vendor-id" is rejected with "missing 'vendor-id'"
# (live-proven 2026-11-13), so the SDK's un-aliased dump is the correct one.
SDK_DROPPED_ALIASES: dict[str, dict[str, str]] = {
    "url_access_profile": {"continue_": "continue"},
    "hip_object": {"is_": "is"},
}

# Every python-name -> API-name rename needed when a ``model_dump()`` dict is
# sent as a request body, including resources the SDK itself writes correctly.
FIELD_ALIASES: dict[str, dict[str, str]] = {
    **SDK_DROPPED_ALIASES,
    "decryption_rule": {"from_": "from", "to_": "to"},
    "security_rule": {"from_": "from", "to_": "to"},
}

# The id travels in the URL. The container (folder/snippet/device) stays in
# the body: a vulnerability-profile PUT without it returns 200 and changes
# nothing (live-proven 2026-11-13), and the other types accept it.
_PUT_EXCLUDED = frozenset({"id"})


def rename_keys(value: Any, renames: dict[str, str]) -> Any:
    """Rename dict keys at every depth of a nested structure."""
    if isinstance(value, dict):
        return {renames.get(k, k): rename_keys(v, renames) for k, v in value.items()}
    if isinstance(value, list):
        return [rename_keys(v, renames) for v in value]
    return value


def _drop_none(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _drop_none(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_drop_none(v) for v in value]
    return value


def put_payload(sdk_attr: str, data: dict[str, Any]) -> dict[str, Any]:
    """Turn a ``model_dump()`` dict into a PUT body for ``sdk_attr``.

    Drops the id and None values, keeps the container, renames SDK field
    names to the API's, and converts UUIDs and enums to JSON-safe values.
    """
    body = {k: v for k, v in data.items() if k not in _PUT_EXCLUDED}
    body = rename_keys(_drop_none(body), FIELD_ALIASES.get(sdk_attr, {}))
    return _json.loads(_json.dumps(body, default=str))


def _endpoint(client: Any, sdk_attr: str) -> str:
    endpoint = getattr(getattr(client, sdk_attr, None), "ENDPOINT", None)
    if not endpoint:
        raise ValueError(f"no REST endpoint known for {sdk_attr!r}")
    return str(endpoint)


class ObjectNotFoundError(LookupError):
    """A named config object does not exist in the folder (an expected condition)."""


def get_object(
    client: Any,
    sdk_attr: str,
    name: str,
    folder: str,
    *,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Fetch one config object by name as the raw API dict.

    The SDK's ``fetch()`` validates the response against its models, which
    reject some valid objects (a profile whose threat exception carries an
    ``action`` cannot be read back). The raw dict uses the API's field names,
    so it can be edited and passed straight to :func:`put_object`.
    """
    body = client.get(
        _endpoint(client, sdk_attr), params={"name": name, "folder": folder, **(params or {})}
    )
    # A name lookup returns the bare object; a filtered list wraps it in "data".
    if isinstance(body, dict) and isinstance(body.get("data"), list):
        items = body["data"]
    else:
        items = body if isinstance(body, list) else [body]
    if not items or not isinstance(items[0], dict) or not items[0].get("id"):
        raise ObjectNotFoundError(f"{sdk_attr} {name!r} not found in folder {folder!r}")
    return dict(items[0])


def put_object(
    client: Any,
    sdk_attr: str,
    data: dict[str, Any],
    *,
    params: dict[str, Any] | None = None,
) -> Any:
    """Update one config object from a plain dict, through the SDK client.

    The SDK's own ``update()`` needs a pydantic model (a dict raises
    AttributeError) and drops aliased fields for some resources. This sends
    the dict with ``client.put``, which keeps the SDK's token refresh and
    error mapping. ``data`` must include the object's ``id``.
    """
    endpoint = _endpoint(client, sdk_attr)
    object_id = data.get("id")
    if not object_id:
        raise ValueError(f"cannot update {sdk_attr}: object has no id")
    kwargs: dict[str, Any] = {"json": put_payload(sdk_attr, data)}
    if params:
        kwargs["params"] = params
    return client.put(f"{endpoint}/{object_id}", **kwargs)
