"""Sanitize real SCM API captures before they become cassettes.

The cassettes shipped in ``cassettes/`` are hand-authored. When a new quirk is
easier to reproduce from a real response, capture it, scrub it with this
module, **read the result**, and only then commit it. This repository is
mirrored publicly and a pre-commit leak guard blocks tenant identifiers, so a
cassette must never carry a real credential, TSG ID, tenant/customer name,
email address or IP address.

Recording a real interaction
----------------------------
Attach :func:`capture_hook` to the session the tool uses, run the tool once
against a lab tenant, then write the scrubbed cassette::

    from tests.integration.scrubber import Scrubber, capture_hook

    captured: list[dict] = []
    client.session.hooks["response"].append(capture_hook(captured))
    ...  # invoke the tool
    doc = {"description": "what this reproduces", "interactions": captured}
    Scrubber(tenant_names=["Acme Retail"], known_ids=["<real tsg>"]).write(
        doc, "tests/integration/cassettes/my_quirk.json"
    )

or scrub a hand-edited capture from the command line::

    uv run python -m tests.integration.scrubber raw.json \\
        tests/integration/cassettes/my_quirk.json \\
        --tenant-name "Acme Retail" --known-id <real tsg>

Raw captures belong in the session scratchpad, never inside the repository.

What is scrubbed
----------------
* Credential headers (``Authorization``, ``Cookie``, ``Set-Cookie``,
  ``X-Auth-Token``, ``X-Api-Key``, ``Proxy-Authorization``) are dropped —
  except a placeholder ``Bearer token-<label>`` that a cassette uses on
  purpose to match one fake tenant's requests.
* Credential-like JSON keys (``access_token``, ``client_secret``,
  ``password`` ...) are replaced with ``"REDACTED"``.
* TSG / tenant IDs become ``1234567890`` — values under ID-named keys
  (``tsg_id``, ``tenant_id``, ``Prisma-Tenant`` ...), ``tsgId=<n>``-style text,
  and every ``known_ids`` value wherever it appears. Bare 10-digit numbers are
  *not* rewritten blindly, because epoch-second timestamps look the same.
* Tenant / customer names become ``Example Tenant`` — every ``tenant_names``
  value (case-insensitive) and values under name keys such as ``tenant_name``,
  ``tsg_name``, ``customer_name``.
* Email addresses become ``user@example.com``.
* IPv4 / IPv6 addresses are mapped consistently onto the RFC 5737 / RFC 3849
  documentation ranges (the same real address always maps to the same
  placeholder, so topology relationships survive). Addresses already in a
  documentation range are left alone.

Heuristics are conservative, not perfect: a four-part software version can
look like an IPv4 address, and free-text fields may name a customer in a way
no rule anticipates. Review every scrubbed cassette by eye.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

PLACEHOLDER_TSG_ID = "1234567890"
PLACEHOLDER_TENANT = "Example Tenant"
PLACEHOLDER_EMAIL = "user@example.com"
REDACTED = "REDACTED"

_DROP_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-auth-token",
        "x-api-key",
    }
)
# Fake bearer values that cassettes use to tell tenants apart in request
# matchers. They are placeholders already, so they survive scrubbing.
_PLACEHOLDER_AUTH_RE = re.compile(r"^Bearer token-[a-z0-9-]+$")
_SECRET_KEYS = frozenset(
    {
        "access_token",
        "refresh_token",
        "id_token",
        "client_secret",
        "clientsecret",
        "password",
        "secret",
        "api_key",
        "apikey",
        "private_key",
        "psk",
        "pre_shared_key",
    }
)
_ID_KEYS = frozenset(
    {"tsg_id", "tsgid", "tenant_id", "tenantid", "prisma-tenant", "prisma_tenant", "tsg"}
)
_NAME_KEYS = frozenset(
    {"tenant_name", "tenantname", "tsg_name", "tsgname", "customer_name", "company_name"}
)

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_ID_TEXT_RE = re.compile(r"(?i)\b(tsg[_-]?id|tenant[_-]?id|prisma-tenant)(\W{1,4})(\d{6,})")
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
# IPv6 only when unambiguous ("::" compression or all eight groups), so clock
# times like 12:30:45 and MAC addresses are not mistaken for addresses.
_IPV6_RE = re.compile(
    r"(?i)(?<![0-9a-f:])(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}"
    r"|(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{0,4}::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{0,4})(?![0-9a-f:])"
)

_DOC_V4 = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
_DOC_V6 = ipaddress.ip_network("2001:db8::/32")


class Scrubber:
    """Stateful scrubber: one instance keeps address mappings consistent."""

    def __init__(self, tenant_names: Iterable[str] = (), known_ids: Iterable[str] = ()) -> None:
        self.tenant_names = sorted({n for n in tenant_names if n}, key=len, reverse=True)
        self.known_ids = sorted({i for i in known_ids if i}, key=len, reverse=True)
        self._v4: dict[str, str] = {}
        self._v6: dict[str, str] = {}

    # -- strings ---------------------------------------------------------

    def _map_v4(self, match: re.Match[str]) -> str:
        raw = match.group(0)
        try:
            addr = ipaddress.IPv4Address(raw)
        except ValueError:
            return raw  # e.g. 999.1.2.3 — not an address
        if any(addr in net for net in _DOC_V4):
            return raw
        if raw not in self._v4:
            n = len(self._v4)
            net = _DOC_V4[(n // 254) % len(_DOC_V4)]
            self._v4[raw] = str(net.network_address + (n % 254) + 1)
        return self._v4[raw]

    def _map_v6(self, match: re.Match[str]) -> str:
        raw = match.group(0)
        if raw == "::":  # e.g. "Class::method" — no address digits at all
            return raw
        try:
            addr = ipaddress.IPv6Address(raw)
        except ValueError:
            return raw
        if addr in _DOC_V6:
            return raw
        if raw not in self._v6:
            self._v6[raw] = str(_DOC_V6.network_address + len(self._v6) + 1)
        return self._v6[raw]

    def scrub_text(self, text: str) -> str:
        for real_id in self.known_ids:
            text = text.replace(real_id, PLACEHOLDER_TSG_ID)
        for name in self.tenant_names:
            text = re.sub(re.escape(name), PLACEHOLDER_TENANT, text, flags=re.IGNORECASE)
        text = _ID_TEXT_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{PLACEHOLDER_TSG_ID}", text)
        text = _EMAIL_RE.sub(PLACEHOLDER_EMAIL, text)
        text = _IPV6_RE.sub(self._map_v6, text)
        return _IPV4_RE.sub(self._map_v4, text)

    # -- structures ------------------------------------------------------

    def scrub_value(self, value: Any, key: str = "") -> Any:
        k = key.lower()
        if isinstance(value, dict):
            return {kk: self.scrub_value(vv, str(kk)) for kk, vv in value.items()}
        if isinstance(value, list):
            return [self.scrub_value(v, key) for v in value]
        if value is None or isinstance(value, bool):
            return value
        if k in _SECRET_KEYS:
            return REDACTED
        if k in _ID_KEYS:
            return PLACEHOLDER_TSG_ID if isinstance(value, str) else int(PLACEHOLDER_TSG_ID)
        if k in _NAME_KEYS and isinstance(value, str):
            return PLACEHOLDER_TENANT
        if isinstance(value, str):
            return self.scrub_text(value)
        return value

    def scrub_headers(self, headers: dict[str, Any] | None) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for name, value in (headers or {}).items():
            if name.lower() in _DROP_HEADERS and not _PLACEHOLDER_AUTH_RE.match(str(value)):
                continue
            out[name] = self.scrub_value(value, name)
        return out

    def scrub_cassette(self, doc: dict[str, Any]) -> dict[str, Any]:
        """Return a scrubbed copy of a cassette document (input is not mutated)."""
        clean = json.loads(json.dumps(doc))
        for item in clean.get("interactions", []):
            for side in ("request", "response"):
                part = item.get(side) or {}
                if "headers" in part:
                    part["headers"] = self.scrub_headers(part["headers"])
                for field in [f for f in part if f != "headers"]:
                    part[field] = self.scrub_value(part[field], field)
        clean["description"] = self.scrub_value(clean.get("description", ""))
        return clean

    def write(self, doc: dict[str, Any], path: str | Path) -> None:
        Path(path).write_text(
            json.dumps(self.scrub_cassette(doc), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )


def capture_hook(sink: list[dict[str, Any]]) -> Callable[..., Any]:
    """A ``requests`` response hook that appends each exchange in cassette form.

    The capture is raw — it includes the Authorization header and real
    identifiers. Scrub it before it is written anywhere inside the repository.
    """

    def hook(resp: Any, *_args: Any, **_kwargs: Any) -> Any:
        req = resp.request
        url, _, _query = (req.url or "").partition("?")
        body: Any = req.body
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")
        entry: dict[str, Any] = {
            "name": f"{req.method} {url}",
            "request": {"method": req.method, "url": url, "headers": dict(req.headers)},
            "response": {
                "status": resp.status_code,
                "headers": {"Content-Type": resp.headers.get("Content-Type", "")},
            },
        }
        if body:
            entry["request"]["body"] = body
        try:
            entry["response"]["json"] = resp.json()
        except ValueError:
            entry["response"]["body"] = resp.text
        sink.append(entry)
        return resp

    return hook


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source", help="raw cassette JSON (keep it outside the repo)")
    parser.add_argument("dest", help="scrubbed cassette to write")
    parser.add_argument("--tenant-name", action="append", default=[], help="name to replace")
    parser.add_argument("--known-id", action="append", default=[], help="TSG ID to replace")
    args = parser.parse_args(argv)
    doc = json.loads(Path(args.source).read_text(encoding="utf-8"))
    Scrubber(args.tenant_name, args.known_id).write(doc, args.dest)
    print(f"wrote {args.dest} — review it before committing")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
