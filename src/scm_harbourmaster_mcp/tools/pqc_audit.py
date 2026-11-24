"""Read-only post-quantum VPN audit: ``scm_pqc_audit``.

Walks IKE gateways, IKE/IPsec crypto profiles and IPsec tunnels in one
container and reports how each tunnel is protected against a quantum-capable
attacker:

  * **PPK** (RFC 8784) - ``pq_ppk`` on the IKE gateway: ``enabled`` and
    ``negotiation_mode`` (``preferred`` falls back to classical, ``mandatory``
    does not).
  * **ML-KEM** (RFC 9370) - the ``ake`` object on the IKE and IPsec crypto
    profiles (``ml-kem-512/768/1024``), and ``pq_kem`` on the gateway.

pan-scm-sdk 0.15.1 does not model these fields (it drops unknown keys), so the
audit reads the raw REST bodies.  It never writes.  Field names come from the
pan.dev network spec and have not been seen on a live tenant: a gateway with
no ``pq_*`` block is reported as having none, which is also what a tenant on a
PAN-OS release without PQ support returns.
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from ..utils.formatting import format_result as _fmt
from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool

logger = get_logger(__name__)

_NETWORK = "/config/network/v1"
_PAGE = 200
_AKE_ROUNDS = tuple(f"ake_{n}" for n in range(1, 8))


def _rows(client: Any, path: str, scope: dict[str, str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    while True:
        body = client.get(
            f"{_NETWORK}/{path}", params={**scope, "limit": str(_PAGE), "offset": str(len(rows))}
        )
        if isinstance(body, list):
            return [r for r in body if isinstance(r, dict)]
        page = [r for r in (body or {}).get("data", []) if isinstance(r, dict)]
        rows.extend(page)
        total = (body or {}).get("total")
        if len(page) < _PAGE or (isinstance(total, int) and len(rows) >= total):
            return rows


def _obj(value: Any) -> dict[str, Any]:
    """``value`` if it is a dict, else an empty dict (a missing or odd block)."""
    return value if isinstance(value, dict) else {}


def _algos(value: Any) -> list[str]:
    """Flatten an ``ake_N`` value (a string, or a list of strings) to names."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


def ake_summary(profile: dict[str, Any] | None) -> dict[str, Any]:
    """ML-KEM state of a crypto profile's ``ake`` object."""
    ake = (profile or {}).get("ake")
    if not isinstance(ake, dict):
        return {"configured": False, "ml_kem": [], "rounds": 0}
    found: list[str] = []
    rounds = 0
    for key in _AKE_ROUNDS:
        names = _algos(ake.get(key))
        if names:
            rounds += 1
        found.extend(n for n in names if n.startswith("ml-kem"))
    # The IKE profile carries an ``enabled`` flag; the IPsec one does not.
    enabled = ake.get("enabled", True)
    return {
        "configured": True,
        "enabled": bool(enabled),
        "rounds": rounds,
        "ml_kem": sorted(set(found)),
    }


def _ppk_summary(gw: dict[str, Any]) -> dict[str, Any]:
    ppk = gw.get("pq_ppk")
    if not isinstance(ppk, dict) or not ppk.get("enabled"):
        return {"mode": "off"}
    keys = [k for k in ppk.get("keys") or [] if isinstance(k, dict)]
    return {
        "mode": ppk.get("negotiation_mode") or "preferred",
        "keys": len(keys),
        "active_keys": sum(1 for k in keys if k.get("enabled", True)),
    }


def _gateway_version(gw: dict[str, Any]) -> str:
    proto = _obj(gw.get("protocol"))
    if proto.get("version"):
        return str(proto["version"])
    # The API omits ``version`` when it is the default: both blocks present
    # means IKEv2 preferred, with IKEv1 as the fallback.
    v1, v2 = bool(proto.get("ikev1")), bool(proto.get("ikev2"))
    if v1 and v2:
        return "ikev2-preferred"
    return "ikev2" if v2 else ("ikev1" if v1 else "unknown")


def _gateway_ike_profile(gw: dict[str, Any]) -> str:
    proto = _obj(gw.get("protocol"))
    v2 = _obj(proto.get("ikev2"))
    return str(v2.get("ike_crypto_profile") or "")


def _fragmentation(gw: dict[str, Any]) -> bool | None:
    common = _obj(gw.get("protocol_common"))
    frag = _obj(common.get("fragmentation"))
    return frag.get("enable") if "enable" in frag else None


def assess_gateway(gw: dict[str, Any], ike_profiles: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Classify one IKE gateway.

    ``protected``: ML-KEM negotiated (hybrid) or a mandatory PPK.
    ``fallback``: a PQ mechanism is configured but a classical-only peer can
    still connect (PPK ``preferred``, or ML-KEM with vulnerable ciphers not
    blocked).  ``vulnerable``: no PQ mechanism.  ``unsupported``: IKEv1 only.
    """
    version = _gateway_version(gw)
    ppk = _ppk_summary(gw)
    kem_block = _obj(gw.get("pq_kem"))
    profile_name = _gateway_ike_profile(gw)
    ake = ake_summary(ike_profiles.get(profile_name))
    kem_on = bool(ake.get("enabled") and ake["ml_kem"]) or bool(kem_block.get("enable"))
    blocks_classical = bool(kem_block.get("block_vulnerable_cipher"))

    notes: list[str] = []
    if version == "ikev1":
        status = "unsupported"
        notes.append("IKEv1 cannot negotiate PPK or ML-KEM")
    elif ppk["mode"] == "mandatory" or (kem_on and blocks_classical):
        status = "protected"
    elif ppk["mode"] != "off" or kem_on:
        status = "fallback"
        if ppk["mode"] == "preferred":
            notes.append("PPK is preferred, so a peer without a PPK negotiates classical keys")
        if kem_on and not blocks_classical:
            notes.append("ML-KEM is on but vulnerable ciphers are not blocked")
    else:
        status = "vulnerable"
    if version == "ikev2-preferred" and status in ("protected", "fallback"):
        notes.append("version is ikev2-preferred: a peer can fall back to IKEv1")
    if kem_on and _fragmentation(gw) is False:
        notes.append("ML-KEM needs IKEv2 fragmentation, which is disabled")
    if ppk["mode"] != "off" and not ppk.get("active_keys"):
        notes.append("PPK is enabled but no key is active")
    if profile_name and profile_name not in ike_profiles:
        notes.append(
            f"IKE crypto profile {profile_name!r} is not in this scope's profile list "
            "(device-level, auto-generated or in another container), so its ML-KEM state is unknown"
        )
    return {
        "gateway": gw.get("name"),
        "ike_version": version,
        "ike_crypto_profile": profile_name or None,
        "ppk": ppk,
        "ml_kem": {
            "profile_ake": ake,
            "gateway_pq_kem": bool(kem_block.get("enable")),
            "blocks_classical": blocks_classical,
        },
        "status": status,
        "notes": notes,
    }


def audit(client: Any, scope: dict[str, str]) -> dict[str, Any]:
    """Build the audit for one container; raises on a REST failure."""
    gateways = _rows(client, "ike-gateways", scope)
    ike_profiles = {
        r["name"]: r for r in _rows(client, "ike-crypto-profiles", scope) if r.get("name")
    }
    ipsec_profiles = {
        r["name"]: r for r in _rows(client, "ipsec-crypto-profiles", scope) if r.get("name")
    }
    tunnels = _rows(client, "ipsec-tunnels", scope)

    by_gw = {g["gateway"]: g for g in (assess_gateway(gw, ike_profiles) for gw in gateways)}
    rows: list[dict[str, Any]] = []
    for t in tunnels:
        auto = _obj(t.get("auto_key"))
        refs = [r.get("name") if isinstance(r, dict) else r for r in auto.get("ike_gateway") or []]
        gw_name = next((r for r in refs if r), None)
        gw_view = by_gw.get(str(gw_name)) if gw_name else None
        ipsec_name = auto.get("ipsec_crypto_profile")
        ake = ake_summary(ipsec_profiles.get(str(ipsec_name)))
        child_pq = bool(ake["configured"] and ake["ml_kem"])
        status = gw_view["status"] if gw_view else "unknown"
        notes = (
            list(gw_view["notes"]) if gw_view else [f"IKE gateway {gw_name!r} not found in scope"]
        )
        if (
            gw_view
            and status == "protected"
            and not child_pq
            and gw_view["ppk"]["mode"] != "mandatory"
        ):
            notes.append("child SA rekeys use no ML-KEM (IPsec profile has no ake)")
        rows.append(
            {
                "tunnel": t.get("name"),
                "ike_gateway": gw_name,
                "ipsec_crypto_profile": ipsec_name,
                "ipsec_ml_kem": ake["ml_kem"],
                "status": status,
                "notes": notes,
            }
        )
    counts: dict[str, int] = {}
    for g in by_gw.values():
        counts[g["status"]] = counts.get(g["status"], 0) + 1
    tunnel_counts: dict[str, int] = {}
    for r in rows:
        tunnel_counts[r["status"]] = tunnel_counts.get(r["status"], 0) + 1
    in_use = {r["ike_gateway"] for r in rows}
    return {
        "scope": scope,
        "gateways_by_status": counts,
        "tunnels_by_status": tunnel_counts,
        "gateways": list(by_gw.values()),
        "tunnels": rows,
        "unused_gateways": sorted(n for n in by_gw if n not in in_use),
        "crypto_profiles": {
            "ike_with_ml_kem": sorted(
                n for n, p in ike_profiles.items() if ake_summary(p)["ml_kem"]
            ),
            "ipsec_with_ml_kem": sorted(
                n for n, p in ipsec_profiles.items() if ake_summary(p)["ml_kem"]
            ),
            "ike_total": len(ike_profiles),
            "ipsec_total": len(ipsec_profiles),
        },
        "caveats": [
            "Read from the SCM config API. Candidate/running state on the device is not checked.",
            "Field names (pq_ppk, pq_kem, ake) follow the pan.dev spec and are unverified on a live tenant.",
            "TLS decryption has no PQC settings in the API, so inspection is not covered.",
        ],
    }


def register_pqc_audit_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register the post-quantum VPN audit tool."""
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_pqc_audit(
        client: Any,
        tenant_id: str,
        folder: str = "",
        snippet: str = "",
        device: str = "",
    ) -> str:
        """Audit IPsec VPN post-quantum protection (read-only).

        Reports, per IKE gateway and per tunnel, whether RFC 8784 PPK and
        RFC 9370 ML-KEM are configured, and classifies each as ``protected``
        (ML-KEM with classical ciphers blocked, or a mandatory PPK),
        ``fallback`` (configured but a classical peer can still connect),
        ``vulnerable`` (nothing configured) or ``unsupported`` (IKEv1).
        Also lists crypto profiles that carry ML-KEM and gateways no tunnel
        uses.  Give exactly one of ``folder``, ``snippet`` or ``device``.

        Args:
            tenant_id: SCM tenant ID.
            folder: SCM folder.
            snippet: Snippet name.
            device: Device serial.
        """
        scopes = {
            k: v for k, v in (("folder", folder), ("snippet", snippet), ("device", device)) if v
        }
        if len(scopes) != 1:
            return _fmt({"error": "give exactly one of folder, snippet or device"})
        return _fmt(audit(client, scopes))
