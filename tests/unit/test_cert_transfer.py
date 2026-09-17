"""scm_cert_export / scm_cert_copy against a fake certificate API (no network)."""

from __future__ import annotations

import base64
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.tools.cert_transfer import register_cert_transfer_tools

TICKET = "CHG-CERT-COPY"
SRC, DST = "1000000001", "1000000002"
CERT_PEM = "-----BEGIN CERTIFICATE-----\nMIIBexample\n-----END CERTIFICATE-----"
# Assembled at runtime so secret scanners don't flag a fake key as a real one.
_KEY_LABEL = "ENCRYPTED " + "PRIVATE KEY"
KEY_PEM = f"-----BEGIN {_KEY_LABEL}-----\nMIIEexample\n-----END {_KEY_LABEL}-----"


def _resp(status: int, body: Any) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.json.return_value = body
    return r


class FakeTenant:
    """A tenant's certificate store behind client.session."""

    def __init__(self, certs: list[dict[str, Any]], keys: set[str] = frozenset()) -> None:  # type: ignore[assignment]
        self.certs = certs
        self.keys = keys
        self.imports: list[dict[str, Any]] = []
        self.import_status = 201
        self.client = MagicMock()
        self.client.session.get.side_effect = self._get
        self.client.session.post.side_effect = self._post

    def _get(self, url: str, params: dict[str, Any], timeout: Any) -> MagicMock:
        return _resp(200, {"data": [c for c in self.certs if c["folder"] == params["folder"]]})

    def _post(self, url: str, json: dict[str, Any], timeout: Any) -> MagicMock:
        if url.endswith(":import"):
            self.imports.append(json)
            if self.import_status != 201:
                return _resp(
                    400,
                    {
                        "_errors": [
                            {"details": {"message": f"bad passphrase {json.get('passphrase')}"}}
                        ]
                    },
                )
            return _resp(201, {"id": "new"})
        cert_id = url.rsplit("/", 1)[1].split(":")[0]
        assert json["format"] == "pem" and 0 < len(json["passphrase"]) <= 31
        body = CERT_PEM + ("\n" + KEY_PEM if cert_id in self.keys else "")
        return _resp(200, {"certificate": body})


def _cert(
    cid: str, name: str, folder: str = "Shared", ca: bool = True, root: bool = True
) -> dict[str, Any]:
    return {
        "id": cid,
        "name": name,
        "folder": folder,
        "ca": ca,
        "subject": f"/CN={name}",
        "issuer": f"/CN={name}" if root else "/CN=Some Root",
        "common_name": name,
        "not_valid_after": "Oct 16 23:59:59 2039 GMT",
    }


@pytest.fixture
def tenants() -> dict[str, FakeTenant]:
    src = FakeTenant(
        [
            _cert("1", "Customer-Leaf", ca=False, root=False),
            _cert("2", "Customer-Root"),
            _cert("3", "Customer-Intermediate", root=False),
            _cert("4", "Forward-Trust-CA"),  # system cert
            _cert("5", "Already-There"),
            _cert("6", "GlobalSign-Root-CA", folder="default"),
        ],
        keys={"1"},
    )
    dst = FakeTenant([_cert("9", "Already-There", folder="All")])
    return {SRC: src, DST: dst}


def _tools(tenants: dict[str, FakeTenant]) -> FastMCP:
    mcp = FastMCP("test-cert-transfer")
    register_cert_transfer_tools(mcp, lambda tenant_id="": tenants[tenant_id].client)
    return mcp


def _fn(mcp: FastMCP, name: str) -> Any:
    return mcp._tool_manager.get_tool(name).fn  # noqa: SLF001


def test_export_reports_key_availability_but_never_the_key(tenants: dict[str, FakeTenant]) -> None:
    out = _fn(_tools(tenants), "scm_cert_export")(tenant_id=SRC)
    assert "**Certificates:** 6" in out and "**With exportable private key:** 1" in out
    assert "PRIVATE KEY" not in out and "MIIEexample" not in out
    assert "MIIBexample" in out  # public PEM is included
    leaf = next(line for line in out.splitlines() if "`Customer-Leaf`" in line)
    assert leaf.rstrip(" |").endswith("| yes | —")


def test_export_unknown_name_errors(tenants: dict[str, FakeTenant]) -> None:
    out = _fn(_tools(tenants), "scm_cert_export")(tenant_id=SRC, names=["Nope"])
    assert out.startswith("Error:") and "Nope" in out


def test_copy_requires_ticket_ref_and_distinct_target(tenants: dict[str, FakeTenant]) -> None:
    copy = _fn(_tools(tenants), "scm_cert_copy")
    assert "ticket_ref is mandatory" in copy(tenant_id=SRC, target_tenant_id=DST)
    assert "same" in copy(tenant_id=SRC, target_tenant_id=SRC, ticket_ref=TICKET)


def test_copy_dry_run_imports_nothing(tenants: dict[str, FakeTenant]) -> None:
    out = _fn(_tools(tenants), "scm_cert_copy")(
        tenant_id=SRC, target_tenant_id=DST, ticket_ref=TICKET
    )
    assert "DRY-RUN" in out
    assert "**Would import:** 3" in out and "**Skipped:** 1" in out
    assert "2 Prisma Access system certificate(s) excluded" in out
    assert tenants[DST].imports == []


def test_copy_imports_in_signer_order_with_key_and_skips_clashes(
    tenants: dict[str, FakeTenant],
) -> None:
    out = _fn(_tools(tenants), "scm_cert_copy")(
        tenant_id=SRC, target_tenant_id=DST, ticket_ref=TICKET, dry_run=False
    )
    imports = tenants[DST].imports
    assert [i["name"] for i in imports] == [
        "Customer-Root",
        "Customer-Intermediate",
        "Customer-Leaf",
    ]
    assert all(i["folder"] == "Shared" and i["format"] == "pem" for i in imports)
    root, _, leaf = imports
    assert "key_file" not in root and "passphrase" not in root
    assert base64.b64decode(leaf["key_file"]).decode().strip() == KEY_PEM
    assert 0 < len(leaf["passphrase"]) <= 31
    assert "**Imported:** 3" in out and "name exists in target (All)" in out
    assert "scm_commit(folders=['Shared']" in out
    assert "PRIVATE KEY" not in out and leaf["passphrase"] not in out


def test_copy_can_hold_back_keys_and_retarget_folder(tenants: dict[str, FakeTenant]) -> None:
    _fn(_tools(tenants), "scm_cert_copy")(
        tenant_id=SRC,
        target_tenant_id=DST,
        names=["Customer-Leaf"],
        include_keys=False,
        target_folder="Mobile Users",
        ticket_ref=TICKET,
        dry_run=False,
    )
    (only,) = tenants[DST].imports
    assert only["folder"] == "Mobile Users" and "key_file" not in only


def test_named_system_cert_is_copied(tenants: dict[str, FakeTenant]) -> None:
    _fn(_tools(tenants), "scm_cert_copy")(
        tenant_id=SRC,
        target_tenant_id=DST,
        names=["Forward-Trust-CA"],
        ticket_ref=TICKET,
        dry_run=False,
    )
    assert [i["name"] for i in tenants[DST].imports] == ["Forward-Trust-CA"]


def test_import_error_redacts_passphrase(tenants: dict[str, FakeTenant]) -> None:
    tenants[DST].import_status = 400
    out = _fn(_tools(tenants), "scm_cert_copy")(
        tenant_id=SRC,
        target_tenant_id=DST,
        names=["Customer-Leaf"],
        ticket_ref=TICKET,
        dry_run=False,
    )
    (sent,) = tenants[DST].imports
    assert "**Failed:** 1" in out
    assert sent["passphrase"] not in out and "<passphrase redacted>" in out


def test_self_signed_leaf_is_skipped_not_attempted(tenants: dict[str, FakeTenant]) -> None:
    tenants[SRC].certs.append(_cert("7", "crt.saml_IDP_example", folder="Mobile Users", ca=False))
    out = _fn(_tools(tenants), "scm_cert_copy")(
        tenant_id=SRC,
        target_tenant_id=DST,
        names=["crt.saml_IDP_example"],
        ticket_ref=TICKET,
        dry_run=False,
    )
    assert tenants[DST].imports == []
    assert "SCM refuses self-signed non-CA certs" in out
