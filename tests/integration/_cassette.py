"""Cassette loader for the offline integration suite.

A *cassette* is a JSON file in ``tests/integration/cassettes/`` holding the
HTTP interactions one scenario needs. Each interaction is registered on a
``responses.RequestsMock``, so the real ``requests`` stack — pan-scm-sdk's
``Scm`` client and every raw-REST helper in the tools — runs unmodified up to
the adapter, and nothing leaves the process: an unmatched request raises
``ConnectionError`` instead of reaching the network.

Cassette format::

    {
      "description": "what real-world behaviour this reproduces",
      "interactions": [
        {
          "name": "short label, shown in match failures",
          "request": {
            "method": "GET",
            "url": "https://api.strata.paloaltonetworks.com/sse/config/v1/...",
            "query":   {"folder": "Shared"},        # optional, subset match
            "headers": {"X-PANW-Region": "uk",       # optional, exact value
                        "Prisma-Tenant": null},      #   null = must be ABSENT
            "json_body_has":   ["filter"],           # optional, top-level keys
            "json_body_lacks": ["filter"]            # optional, top-level keys
          },
          "response": {
            "status": 200,
            "json": {...},                           # or "body": "raw text"
            "headers": {"Content-Type": "application/json"}
          }
        }
      ]
    }

Matching rules: the URL is compared without its query string; every
constraint present must hold. Interactions for the same URL should be made
mutually exclusive with ``headers``/``query``/``json_body_*`` so the result
never depends on registration order.

Fixtures are hand-authored and sanitized. To turn a real capture into a
cassette, run it through ``tests/integration/scrubber.py`` first — see that
module's docstring.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import responses

CASSETTE_DIR = Path(__file__).parent / "cassettes"


def load_cassette(name: str) -> dict[str, Any]:
    """Read ``cassettes/<name>.json`` and return the parsed document."""
    path = CASSETTE_DIR / f"{name.removesuffix('.json')}.json"
    with path.open(encoding="utf-8") as fh:
        doc: dict[str, Any] = json.load(fh)
    if not isinstance(doc.get("interactions"), list):
        raise ValueError(f"cassette {path.name} has no 'interactions' list")
    return doc


def _request_json(request: Any) -> Any:
    body = request.body
    if body is None:
        return None
    if isinstance(body, bytes):
        body = body.decode("utf-8")
    try:
        return json.loads(body)
    except (TypeError, ValueError):
        return None


def _headers_matcher(expected: dict[str, str | None]) -> Any:
    def match(request: Any) -> tuple[bool, str]:
        for key, want in expected.items():
            got = request.headers.get(key)
            if want is None and got is not None:
                return False, f"header {key!r} should be absent, got {got!r}"
            if want is not None and got != want:
                return False, f"header {key!r} is {got!r}, want {want!r}"
        return True, ""

    return match


def _body_keys_matcher(has: list[str], lacks: list[str]) -> Any:
    def match(request: Any) -> tuple[bool, str]:
        body = _request_json(request)
        keys = set(body) if isinstance(body, dict) else set()
        missing = [k for k in has if k not in keys]
        if missing:
            return False, f"JSON body lacks required keys {missing}"
        present = [k for k in lacks if k in keys]
        if present:
            return False, f"JSON body carries forbidden keys {present}"
        return True, ""

    return match


def register_cassette(rsps: responses.RequestsMock, name: str) -> dict[str, Any]:
    """Register every interaction in cassette *name* on *rsps*; return the doc."""
    doc = load_cassette(name)
    for item in doc["interactions"]:
        req = item["request"]
        res = item["response"]
        matchers: list[Any] = []
        if req.get("query"):
            matchers.append(
                responses.matchers.query_param_matcher(
                    {k: str(v) for k, v in req["query"].items()}, strict_match=False
                )
            )
        if req.get("headers"):
            matchers.append(_headers_matcher(req["headers"]))
        if req.get("json_body_has") or req.get("json_body_lacks"):
            matchers.append(
                _body_keys_matcher(req.get("json_body_has", []), req.get("json_body_lacks", []))
            )

        kwargs: dict[str, Any] = {
            "method": req["method"].upper(),
            "url": req["url"],
            "status": res.get("status", 200),
            "headers": res.get("headers") or {},
            "match": matchers,
        }
        if "json" in res:
            kwargs["json"] = res["json"]
        else:
            kwargs["body"] = res.get("body", "")
        rsps.add(**kwargs)
    return doc


def request_json(call: Any) -> Any:
    """Parsed JSON body of a recorded ``responses`` call (or None)."""
    return _request_json(call.request)
