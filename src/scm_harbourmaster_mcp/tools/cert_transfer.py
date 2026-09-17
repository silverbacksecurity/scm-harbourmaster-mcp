"""Certificate export and tenant-to-tenant copy.

``scm_cert_export`` lists a tenant's certificates with their public PEM and
whether SCM holds (and will release) a private key for each. It never returns
key material: tool output goes straight into an LLM transcript.

``scm_cert_copy`` moves certificates between tenants — export from the source
and import into the target in one process, so an exported private key only
ever exists in memory, encrypted under a one-time passphrase.

Behaviour of the export API (``POST /sse/config/v1/certificates/{id}:export``),
verified live:

* ``format: pem`` with a ``passphrase`` returns the certificate and, when SCM
  holds an exportable key, that key encrypted under the passphrase. Without a
  passphrase a cert that has a key is refused ("Passphrase is needed to
  include key in the exported file"), so the passphrase is always sent.
* Prisma Access's own per-tenant CAs (Forward-Trust, Root CA, ...) export
  without keys; only a few generated leaf certs (auth cookie, SAML signing)
  release theirs.

Import quirks (see also ``tools/ops.py``): a key needs a passphrase of at
most 31 characters, and a self-signed certificate that is not a CA — e.g. a
SAML IdP cert created from IdP metadata — is refused ("Certificate must have
a signer or be a CA certificate").
"""

from __future__ import annotations

import base64
import re
import secrets
from dataclasses import dataclass
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..auth.oauth import resolve_tenant_id
from ..utils.errors import handle_scm_exception
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool
from ..utils.write_safety import (
    DRY_RUN_HINT,
    audit_write,
    normalize_ticket_ref,
    ticket_ref_error,
)
from .ops import _SCM_BASE

logger = get_logger(__name__)

# Every folder a certificate object has been seen in. `default` and
# `optional-default` hold predefined certificates.
_CERT_FOLDERS = (
    "All",
    "Shared",
    "Mobile Users",
    "Remote Networks",
    "Service Connections",
    "default",
    "optional-default",
)

# Certificates Prisma Access creates for every tenant. Each tenant has its
# own, so copying them overrides the target's working set (decryption, GP
# authentication cookies, SAML signing). Excluded from scm_cert_copy unless
# named explicitly or include_system=True.
SYSTEM_CERT_NAMES = frozenset(
    {
        "Root CA",
        "Forward-Trust-CA",
        "Forward-Trust-CA-ECDSA",
        "Forward-UnTrust-CA",
        "Forward-UnTrust-CA-ECDSA",
        "Authentication Cookie CA",
        "Authentication Cookie Cert",
        "Global Authentication Cookie CA",
        "Global Authentication Cookie Cert",
        "SAML-Signing-Cert",
        "GP_Log_Certificate",
        "PaloAlto-Root-CA",
        "GlobalSign-Root-CA",
    }
)
_SYSTEM_FOLDERS = frozenset({"default", "optional-default"})

_CERT_BLOCK = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)
_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S
)
_TIMEOUT = (5, 30)


def is_system_cert(cert: dict[str, Any]) -> bool:
    return cert.get("name") in SYSTEM_CERT_NAMES or cert.get("folder") in _SYSTEM_FOLDERS


def _session(client: Any) -> Any:
    session = getattr(client, "session", None)
    if session is None:
        raise RuntimeError("no HTTP session available on the SCM client")
    return session


def _error_text(resp: Any) -> str:
    try:
        errors = resp.json().get("_errors") or []
        details = errors[0].get("details") if errors else None
        if isinstance(details, dict) and details.get("message"):
            return str(details["message"]).strip()
        if errors:
            return str(errors[0].get("message", "")).strip()
    except Exception:  # noqa: S110 — fall back to the status code
        pass
    return f"HTTP {resp.status_code}"


def list_certs(client: Any) -> list[dict[str, Any]]:
    """Every certificate object in the tenant, de-duplicated by id."""
    session = _session(client)
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for folder in _CERT_FOLDERS:
        resp = session.get(
            f"{_SCM_BASE}/certificates", params={"folder": folder, "limit": 500}, timeout=_TIMEOUT
        )
        if resp.status_code != 200:
            continue
        body = resp.json()
        for cert in body if isinstance(body, list) else body.get("data", []):
            cid = str(cert.get("id", ""))
            if cid and cid not in seen:
                seen.add(cid)
                out.append(cert)
    return out


@dataclass
class ExportedCert:
    """One certificate as exported. ``key_pem`` is encrypted under ``passphrase``."""

    cert_pem: str
    key_pem: str = ""
    passphrase: str = ""
    error: str = ""

    @property
    def has_key(self) -> bool:
        return bool(self.key_pem)


def export_cert(client: Any, cert_id: str) -> ExportedCert:
    """Export one certificate, with its key (encrypted) when SCM releases it."""
    passphrase = secrets.token_urlsafe(18)  # 24 chars — SCM caps passphrases at 31
    resp = _session(client).post(
        f"{_SCM_BASE}/certificates/{cert_id}:export",
        json={"format": "pem", "passphrase": passphrase},
        timeout=_TIMEOUT,
    )
    if resp.status_code not in (200, 201):
        return ExportedCert("", error=_error_text(resp))
    text = str((resp.json() or {}).get("certificate", ""))
    if "-----BEGIN" not in text:
        try:
            text = base64.b64decode(text).decode()
        except Exception:
            return ExportedCert("", error="export returned an unrecognised body")
    certs = _CERT_BLOCK.findall(text)
    if not certs:
        return ExportedCert("", error="export contained no certificate")
    key = _KEY_BLOCK.search(text)
    return ExportedCert(
        "\n".join(certs) + "\n",
        key_pem=key.group(0) + "\n" if key else "",
        passphrase=passphrase if key else "",
    )


def refused_by_import(cert: dict[str, Any]) -> bool:
    """A self-signed non-CA cert — SCM's import API refuses these (verified live)."""
    return (
        not cert.get("ca")
        and bool(cert.get("subject"))
        and cert.get("subject") == cert.get("issuer")
    )


def _import_order(cert: dict[str, Any]) -> tuple[int, str]:
    """Roots first, then other CAs, then leaves — so each signer exists first."""
    if cert.get("ca") and cert.get("subject") == cert.get("issuer"):
        rank = 0
    elif cert.get("ca"):
        rank = 1
    else:
        rank = 2
    return rank, str(cert.get("name", ""))


def _cell(value: Any) -> str:
    return str(value if value not in (None, "") else "—").replace("|", "\\|")


def register_cert_transfer_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register scm_cert_export and scm_cert_copy."""
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_cert_export(
        client: Any,
        tenant_id: str,
        names: list[str] | None = None,
        include_pem: bool = True,
    ) -> str:
        """Export a tenant's certificates: public PEM plus whether a private key is exportable.

        Read-only. Lists every certificate object (all folders), exports each
        through the certificate export API and reports its folder, CA flag,
        subject, issuer, expiry, whether it is a Prisma Access system cert, and
        whether SCM released a private key. Private keys are NEVER returned —
        use scm_cert_copy to move a certificate with its key to another tenant.

        Args:
            tenant_id: SCM tenant ID to export from.
            names: Only these certificate names (default: all).
            include_pem: Append each public certificate PEM (default True).
        """
        certs = list_certs(client)
        if names:
            wanted = set(names)
            missing = sorted(wanted - {c.get("name") for c in certs})
            if missing:
                return f"Error: no certificate named {', '.join(missing)} in this tenant"
            certs = [c for c in certs if c.get("name") in wanted]
        certs.sort(key=lambda c: (str(c.get("folder", "")), str(c.get("name", ""))))

        rows = []
        pems: list[tuple[str, str]] = []
        with_key = 0
        for cert in certs:
            exported = export_cert(client, str(cert["id"]))
            with_key += exported.has_key
            key = "error" if exported.error else ("yes" if exported.has_key else "no")
            rows.append(
                f"| `{_cell(cert.get('name'))}` | {_cell(cert.get('folder'))} "
                f"| {'yes' if cert.get('ca') else 'no'} | {_cell(cert.get('common_name'))} "
                f"| {_cell(cert.get('issuer'))} | {_cell(cert.get('not_valid_after'))} "
                f"| {'yes' if is_system_cert(cert) else 'no'} | {key} "
                f"| {_cell(exported.error)} |"
            )
            if include_pem and exported.cert_pem:
                pems.append((str(cert.get("name")), exported.cert_pem))

        lines = [
            f"## Certificate Export — tenant `{tenant_id or 'default'}`",
            "",
            f"**Certificates:** {len(certs)}  |  **With exportable private key:** {with_key}",
            "",
            "| Certificate | Folder | CA | Common Name | Issuer | Expires | System | Private key | Error |",
            "|---|---|---|---|---|---|---|---|---|",
            *rows,
            "",
            "_Private keys are never shown. System = created by Prisma Access for every "
            "tenant; each tenant has its own._",
        ]
        for name, pem in pems:
            lines += ["", f"### `{name}`", "```", pem.strip(), "```"]
        return "\n".join(lines)

    # Not @scm_tool: it needs clients for two tenants, like scm_config_clone.
    @mcp.tool()
    def scm_cert_copy(
        tenant_id: str,
        target_tenant_id: str,
        names: list[str] | None = None,
        include_system: bool = False,
        include_keys: bool = True,
        target_folder: str = "",
        dry_run: bool = True,
        ticket_ref: str = "",
    ) -> str:
        """Copy certificates (with private keys where exportable) from one tenant to another.

        Exports each certificate from the source tenant and imports it into the
        target in the same process — an exported key only exists in memory,
        encrypted under a one-time passphrase, and is never logged or shown.

        Never overwrites: a certificate whose name already exists anywhere in
        the target is skipped. Prisma Access system certs (Root CA,
        Forward-Trust/UnTrust CAs, authentication cookie and SAML signing
        certs, predefined roots) are excluded unless named in ``names`` or
        ``include_system=True`` — every tenant has its own, and a copy in a
        child folder overrides the target's working set. Imports run roots
        first, then intermediate CAs, then leaves. Nothing is committed: run
        scm_commit on the target afterwards.

        Known refusals: SCM rejects a self-signed non-CA certificate (e.g. a
        SAML IdP cert from IdP metadata — re-import that metadata instead), and
        most Prisma Access CAs export without their private key.

        Args:
            tenant_id: Source tenant ID.
            target_tenant_id: Destination tenant ID.
            names: Certificate names to copy (default: all non-system certs).
            include_system: Also copy Prisma Access system certs when ``names`` is empty.
            include_keys: Import private keys that the source releases (default True).
            target_folder: Import every cert into this folder (default: each
                cert's source folder).
            dry_run: If True (default), export and check for clashes without importing.
            ticket_ref: Mandatory change-ticket reference (never sent to SCM).

        **Write safety (SSR pattern):** ``dry_run=True`` by default;
        ``ticket_ref`` is mandatory.
        """
        err = ticket_ref_error(ticket_ref)
        if err:
            return f"Error: {err}"
        ticket_ref = normalize_ticket_ref(ticket_ref)
        if not target_tenant_id:
            return "Error: target_tenant_id is required"
        try:
            target_tenant_id = resolve_tenant_id(str(target_tenant_id))
            if str(target_tenant_id) == str(tenant_id):
                return "Error: source and target tenant are the same"
            client = get_client(tenant_id)
            target = get_client(target_tenant_id)
            return _copy(
                client,
                target,
                str(tenant_id),
                str(target_tenant_id),
                names=names,
                include_system=include_system,
                include_keys=include_keys,
                target_folder=target_folder,
                dry_run=dry_run,
                ticket_ref=ticket_ref,
            )
        except Exception as exc:
            return f"Error: {handle_scm_exception(exc, tool='scm_cert_copy', tenant_id=tenant_id)}"


def _copy(
    client: Any,
    target: Any,
    tenant_id: str,
    target_tenant_id: str,
    *,
    names: list[str] | None,
    include_system: bool,
    include_keys: bool,
    target_folder: str,
    dry_run: bool,
    ticket_ref: str,
) -> str:
    """Body of scm_cert_copy, with both tenants' clients already resolved."""
    source_certs = list_certs(client)
    if names:
        wanted = set(names)
        missing = sorted(wanted - {c.get("name") for c in source_certs})
        if missing:
            return f"Error: no certificate named {', '.join(missing)} in the source tenant"
        selected = [c for c in source_certs if c.get("name") in wanted]
    else:
        selected = [c for c in source_certs if include_system or not is_system_cert(c)]
    selected.sort(key=_import_order)

    target_names: dict[str, list[str]] = {}
    for cert in list_certs(target):
        target_names.setdefault(str(cert.get("name")), []).append(str(cert.get("folder")))

    rows: list[str] = []
    imported_folders: set[str] = set()
    counts = {"imported": 0, "would import": 0, "skipped": 0, "failed": 0}
    for cert in selected:
        name = str(cert.get("name"))
        folder = target_folder or str(cert.get("folder") or "Shared")
        exported = export_cert(client, str(cert["id"]))
        send_key = include_keys and exported.has_key
        key_note = "yes" if send_key else ("held back" if exported.has_key else "no")

        if name in target_names:
            status = f"skipped — name exists in target ({', '.join(target_names[name])})"
            counts["skipped"] += 1
        elif refused_by_import(cert):
            status = (
                "skipped — SCM refuses self-signed non-CA certs (for a SAML IdP cert, "
                "import the IdP metadata into a SAML profile instead)"
            )
            counts["skipped"] += 1
        elif exported.error:
            status = f"failed — export: {exported.error}"
            counts["failed"] += 1
        elif dry_run:
            status = "would import"
            counts["would import"] += 1
        else:
            payload: dict[str, Any] = {
                "name": name,
                "folder": folder,
                "format": "pem",
                "certificate_file": base64.b64encode(exported.cert_pem.encode()).decode(),
            }
            if send_key:
                payload["key_file"] = base64.b64encode(exported.key_pem.encode()).decode()
                payload["passphrase"] = exported.passphrase
            audit_write(
                "scm_cert_copy",
                ticket_ref,
                str(target_tenant_id),
                source_tenant_id=str(tenant_id),
                name=name,
                folder=folder,
                private_key=send_key,
            )
            resp = _session(target).post(
                f"{_SCM_BASE}/certificates:import",
                json=payload,
                timeout=_TIMEOUT,
            )
            if resp.status_code in (200, 201):
                status = "imported"
                counts["imported"] += 1
                imported_folders.add(folder)
                target_names[name] = [folder]
            else:
                reason = _error_text(resp)
                if exported.passphrase:
                    reason = reason.replace(exported.passphrase, "<passphrase redacted>")
                status = f"failed — {reason}"
                counts["failed"] += 1
        rows.append(
            f"| `{_cell(name)}` | {_cell(folder)} | {'yes' if cert.get('ca') else 'no'} "
            f"| {key_note} | {_cell(status)} |"
        )

    excluded = len(source_certs) - len(selected)
    logger.info(
        "cert_copy",
        source_tenant_id=str(tenant_id),
        target_tenant_id=str(target_tenant_id),
        dry_run=dry_run,
        ticket_ref=ticket_ref,
        **{k.replace(" ", "_"): v for k, v in counts.items()},
    )
    lines = [
        f"## Certificate Copy{' — DRY-RUN' if dry_run else ''}",
        "",
        f"**Source:** `{tenant_id}` → **Target:** `{target_tenant_id}`  |  "
        f"**Ticket ref:** {ticket_ref}",
        "",
        "  |  ".join(f"**{k.capitalize()}:** {v}" for k, v in counts.items() if v)
        or "Nothing selected.",
    ]
    if excluded and not names:
        lines.append(
            f"_{excluded} Prisma Access system certificate(s) excluded — pass "
            "`include_system=True` or name them to copy._"
        )
    if rows:
        lines += [
            "",
            "| Certificate | Target folder | CA | Private key | Result |",
            "|---|---|---|---|---|",
            *rows,
        ]
    lines.append("")
    if dry_run:
        lines.append(DRY_RUN_HINT)
    elif counts["imported"]:
        lines.append(
            f"Nothing is committed yet — run `scm_commit(folders={sorted(imported_folders)}, "
            f"tenant_id='{target_tenant_id}', ticket_ref=..., dry_run=False)` on the target."
        )
    return "\n".join(lines)
