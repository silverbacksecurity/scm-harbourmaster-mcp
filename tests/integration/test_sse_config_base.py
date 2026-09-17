"""Certificates and TLS service profiles live under /sse/config/v1, not /config/v1.

A /config/v1 call 404s on every folder. Because the tools treated the 404 as
"nothing there", scm_cert_scan / scm_cert_lifecycle / scm_tls_profile_manager
reported no certificates or profiles on tenants that had plenty. The cassette
answers both bases the way the live API does, so a regression to the wrong
base shows up as an error or an empty report here.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

import pytest
import requests
import responses

from scm_harbourmaster_mcp.tools.ops import register_ops_tools

pytestmark = pytest.mark.integration


def _example_pem() -> str:
    """A real self-signed certificate — scm_cert_import parses the PEM."""
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example-import")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _paths(http: responses.RequestsMock) -> list[str]:
    return [urlsplit(c.request.url or "").path for c in http.calls]


def _assert_only_sse_base(http: responses.RequestsMock) -> None:
    paths = _paths(http)
    assert paths, "the tool made no HTTP calls"
    wrong = [p for p in paths if p.startswith("/config/v1/")]
    assert not wrong, f"tool hit the /config/v1 base, which 404s live: {wrong}"


def test_cassette_reproduces_the_wrong_base_404(
    cassette: Callable[[str], Any], http: responses.RequestsMock
) -> None:
    cassette("sse_config_base")
    wrong = requests.get(
        "https://api.strata.paloaltonetworks.com/config/v1/tls-service-profiles",
        params={"folder": "Shared"},
        timeout=5,
    )
    right = requests.get(
        "https://api.strata.paloaltonetworks.com/sse/config/v1/tls-service-profiles",
        params={"folder": "Shared"},
        timeout=5,
    )
    assert (wrong.status_code, right.status_code) == (404, 200)


def test_tls_profile_list_uses_sse_base(
    cassette: Callable[[str], Any],
    http: responses.RequestsMock,
    scm_client: Any,
    invoke_tool: Callable[..., str],
) -> None:
    cassette("sse_config_base")
    out = invoke_tool(
        register_ops_tools, "scm_tls_profile_manager", scm_client, action="list", folder="Shared"
    )

    assert not out.startswith("Error"), out
    assert "Total: 2" in out
    assert "`tls-modern`" in out and "`tls-legacy`" in out
    _assert_only_sse_base(http)


def test_tls_profile_create_uses_sse_base(
    cassette: Callable[[str], Any],
    http: responses.RequestsMock,
    scm_client: Any,
    invoke_tool: Callable[..., str],
) -> None:
    cassette("sse_config_base")
    out = invoke_tool(
        register_ops_tools,
        "scm_tls_profile_manager",
        scm_client,
        action="create",
        name="tls-baseline",
        dry_run=False,
        ticket_ref="CHG-TEST",
    )

    assert "created in folder `Shared`" in out, out
    assert http.calls[0].request.method == "POST"
    _assert_only_sse_base(http)


def test_cert_import_uses_sse_base(
    cassette: Callable[[str], Any],
    http: responses.RequestsMock,
    scm_client: Any,
    invoke_tool: Callable[..., str],
) -> None:
    cassette("sse_config_base")
    out = invoke_tool(
        register_ops_tools,
        "scm_cert_import",
        scm_client,
        name="example-import",
        pem=_example_pem(),
        dry_run=False,
        ticket_ref="CHG-TEST",
    )

    assert "imported into folder" in out, out
    _assert_only_sse_base(http)


def test_cert_scan_finds_certificates_on_sse_base(
    cassette: Callable[[str], Any],
    http: responses.RequestsMock,
    scm_client: Any,
    invoke_tool: Callable[..., str],
) -> None:
    cassette("sse_config_base")
    out = invoke_tool(register_ops_tools, "scm_cert_scan", scm_client, folder="Shared")

    assert "No certificate objects found" not in out, out
    assert "**Certificates scanned:** 1" in out
    assert "`example-forward-proxy-ca`" in out
    _assert_only_sse_base(http)
    scanned = {
        c.request.params.get("folder") for c in http.calls if "certificates" in c.request.url
    }
    assert scanned == {"Shared", "Remote Networks", "Mobile Users", "Service Connections"}
