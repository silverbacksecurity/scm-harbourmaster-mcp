"""scm_cert_import against the certificate import API (no network).

The tool used to POST a PEM to /sse/config/v1/certificates — the certificate
*generate* endpoint, whose schema has no certificate field — and could not
carry a private key, so a forward-trust CA could never be imported.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.tools.ops import register_ops_tools

TICKET = "CHG-CERT-1"
PASSPHRASE = "example-passphrase"
IMPORT_PATH = "/sse/config/v1/certificates:import"


def _cert(common_name: str, *, ca: bool, issuer: Any = None, issuer_key: Any = None):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject if issuer else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(issuer_key or key, hashes.SHA256())
    )
    return cert, key


@pytest.fixture(scope="module")
def chain() -> dict[str, Any]:
    root, root_key = _cert("example-root-ca", ca=True)
    inter, inter_key = _cert("example-intermediate", ca=True, issuer=root, issuer_key=root_key)
    pem = lambda c: c.public_bytes(serialization.Encoding.PEM).decode()  # noqa: E731
    key_pem = inter_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    p12 = pkcs12.serialize_key_and_certificates(
        b"example-intermediate",
        inter_key,
        inter,
        [root],
        serialization.BestAvailableEncryption(PASSPHRASE.encode()),
    )
    return {
        "chain_pem": pem(inter) + pem(root),
        "key_pem": key_pem,
        "p12_b64": base64.b64encode(p12).decode(),
    }


def _tool(client: Any) -> Any:
    mcp = FastMCP("test-cert-import")
    register_ops_tools(mcp, lambda tenant_id="": client)
    return mcp._tool_manager.get_tool("scm_cert_import").fn  # noqa: SLF001


def _post_payload(client: MagicMock) -> dict[str, Any]:
    client.post.assert_called_once()
    assert client.post.call_args.args[0] == IMPORT_PATH
    return client.post.call_args.kwargs["json"]


def test_pem_chain_with_key_uses_import_endpoint(chain: dict[str, Any]) -> None:
    client = MagicMock()
    client.post.return_value = {"id": "c-1", "name": "fwd-trust"}
    out = _tool(client)(
        name="fwd-trust",
        pem=chain["chain_pem"],
        private_key_pem=chain["key_pem"],
        dry_run=False,
        ticket_ref=TICKET,
    )

    body = _post_payload(client)
    assert body["format"] == "pem"
    assert base64.b64decode(body["certificate_file"]).decode() == chain["chain_pem"].strip()
    assert "certificate" not in body and "ca" not in body
    # SCM 400s (API_I00035) on a key without a passphrase, so the unencrypted
    # key goes out encrypted under a generated one — the same key underneath.
    _assert_key_matches(body, chain["key_pem"])
    assert "with its private key" in out
    assert "PRIVATE KEY" not in out and body["key_file"] not in out
    assert body["passphrase"] not in out
    assert len(body["passphrase"]) <= 31


def _assert_key_matches(body: dict[str, Any], key_pem: str) -> None:
    sent = base64.b64decode(body["key_file"])
    assert b"ENCRYPTED PRIVATE KEY" in sent
    loaded = serialization.load_pem_private_key(sent, password=body["passphrase"].encode())
    original = serialization.load_pem_private_key(key_pem.encode(), password=None)
    assert loaded.private_numbers() == original.private_numbers()  # type: ignore[union-attr]


def test_unencrypted_key_uses_caller_passphrase(chain: dict[str, Any]) -> None:
    client = MagicMock()
    client.post.return_value = {"id": "c-3"}
    _tool(client)(
        name="fwd-trust",
        pem=chain["chain_pem"],
        private_key_pem=chain["key_pem"],
        passphrase=PASSPHRASE,
        dry_run=False,
        ticket_ref=TICKET,
    )
    body = _post_payload(client)
    assert body["passphrase"] == PASSPHRASE
    _assert_key_matches(body, chain["key_pem"])


def test_encrypted_key_is_sent_unchanged_with_its_passphrase() -> None:
    root, root_key = _cert("enc-key-ok", ca=True)
    encrypted = root_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"right"),
    ).decode()
    client = MagicMock()
    client.post.return_value = {"id": "c-4"}
    _tool(client)(
        name="c",
        pem=root.public_bytes(serialization.Encoding.PEM).decode(),
        private_key_pem=encrypted,
        passphrase="right",
        dry_run=False,
        ticket_ref=TICKET,
    )
    body = _post_payload(client)
    assert base64.b64decode(body["key_file"]).decode() == encrypted.strip()
    assert body["passphrase"] == "right"


def test_encrypted_key_without_passphrase_rejected() -> None:
    root, root_key = _cert("enc-key-nopass", ca=True)
    encrypted = root_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"right"),
    ).decode()
    client = MagicMock()
    out = _tool(client)(
        name="c",
        pem=root.public_bytes(serialization.Encoding.PEM).decode(),
        private_key_pem=encrypted,
        dry_run=False,
        ticket_ref=TICKET,
    )
    assert "encrypted — pass its passphrase" in out
    client.post.assert_not_called()


def test_pkcs12_sends_file_and_passphrase_but_never_echoes_them(chain: dict[str, Any]) -> None:
    client = MagicMock()
    client.post.return_value = {"id": "c-2", "passphrase": PASSPHRASE, "key_file": "x"}
    out = _tool(client)(
        name="fwd-trust",
        certificate_file_b64=chain["p12_b64"],
        format="pkcs12",
        passphrase=PASSPHRASE,
        dry_run=False,
        ticket_ref=TICKET,
    )

    body = _post_payload(client)
    assert body == {
        "name": "fwd-trust",
        "folder": "Shared",
        "certificate_file": chain["p12_b64"],
        "format": "pkcs12",
        "passphrase": PASSPHRASE,
    }
    assert PASSPHRASE not in out and chain["p12_b64"] not in out
    assert TICKET not in json.dumps(body)


def test_dry_run_describes_chain_without_secrets(chain: dict[str, Any]) -> None:
    client = MagicMock()
    out = _tool(client)(
        name="fwd-trust",
        certificate_file_b64=chain["p12_b64"],
        format="pkcs12",
        passphrase=PASSPHRASE,
        ticket_ref=TICKET,
    )

    client.post.assert_not_called()
    assert "DRY-RUN" in out and IMPORT_PATH in out
    assert "| Private key | included |" in out
    assert "example-intermediate" in out and "example-root-ca" in out
    assert "| Cert 1 CA | yes |" in out
    assert PASSPHRASE not in out and chain["p12_b64"] not in out


def test_api_error_is_redacted(chain: dict[str, Any]) -> None:
    client = MagicMock()
    client.post.side_effect = RuntimeError(f"400 bad request echoing {PASSPHRASE}")
    out = _tool(client)(
        name="fwd-trust",
        certificate_file_b64=chain["p12_b64"],
        format="pkcs12",
        passphrase=PASSPHRASE,
        dry_run=False,
        ticket_ref=TICKET,
    )
    assert out.startswith("Error: certificate import failed")
    assert PASSPHRASE not in out and "<passphrase redacted>" in out


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({}, "exactly one of pem or certificate_file_b64"),
        ({"pem": "x", "certificate_file_b64": "eA=="}, "exactly one of"),
        ({"pem": "not a cert"}, "could not be parsed as one or more PEM"),
        ({"certificate_file_b64": "eA==", "format": "pkcs12"}, "requires passphrase"),
        (
            {"certificate_file_b64": "eA==", "format": "pkcs12", "passphrase": "x" * 32},
            "at most 31 characters",
        ),
        (
            {"certificate_file_b64": "eA==", "format": "pkcs12", "passphrase": "wrong"},
            "could not be opened",
        ),
        ({"certificate_file_b64": "***", "format": "der"}, "not valid base64"),
        ({"pem": "x", "format": "p7b"}, "format must be one of"),
    ],
)
def test_invalid_inputs_rejected_before_any_call(kwargs: dict[str, Any], message: str) -> None:
    client = MagicMock()
    out = _tool(client)(name="c", dry_run=False, ticket_ref=TICKET, **kwargs)
    assert out.startswith("Error:") and message in out
    client.post.assert_not_called()


def test_wrong_key_passphrase_rejected(chain: dict[str, Any]) -> None:
    root, root_key = _cert("enc-key-ca", ca=True)
    encrypted = root_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"right"),
    ).decode()
    client = MagicMock()
    out = _tool(client)(
        name="c",
        pem=root.public_bytes(serialization.Encoding.PEM).decode(),
        private_key_pem=encrypted,
        passphrase="wrong",
        dry_run=False,
        ticket_ref=TICKET,
    )
    assert "private_key_pem could not be loaded" in out
    assert "PRIVATE KEY" not in out
    client.post.assert_not_called()
