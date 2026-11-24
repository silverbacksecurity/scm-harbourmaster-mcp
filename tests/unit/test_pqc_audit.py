"""scm_pqc_audit: gateway/tunnel classification over mocked REST."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

from mcp.server.fastmcp import FastMCP

from scm_harbourmaster_mcp.tools import pqc_audit as pa

NET = "/config/network/v1"


def _gw(name: str, **over: Any) -> dict[str, Any]:
    return {
        "name": name,
        "protocol": {"version": "ikev2", "ikev2": {"ike_crypto_profile": "ike-pq"}},
        **over,
    }


def _client(data: dict[str, list[dict[str, Any]]]) -> Any:
    client = MagicMock()

    def _get(path: str, params: dict[str, Any] | None = None) -> Any:
        rows = data.get(path.removeprefix(f"{NET}/"), [])
        return {"data": rows, "total": len(rows)}

    client.get.side_effect = _get
    return client


def _tool(client: Any) -> Any:
    mcp = FastMCP("test")
    pa.register_pqc_audit_tools(mcp, lambda tenant_id="": client)
    return mcp._tool_manager.get_tool("scm_pqc_audit").fn


PROFILES = [
    {"name": "ike-pq", "ake": {"enabled": True, "ake_1": ["ml-kem-768", "group20"]}},
    {"name": "ike-classic", "dh_group": ["group14"]},
]
IPSEC = [{"name": "ipsec-pq", "ake": {"ake_1": "ml-kem-768"}}, {"name": "ipsec-classic"}]


def test_status_classes() -> None:
    profiles = {p["name"]: p for p in PROFILES}
    kem_blocked = _gw("a", pq_kem={"enable": True, "block_vulnerable_cipher": True})
    assert pa.assess_gateway(kem_blocked, profiles)["status"] == "protected"
    ppk_must = _gw(
        "b", pq_ppk={"enabled": True, "negotiation_mode": "mandatory", "keys": [{"name": "k"}]}
    )
    assert pa.assess_gateway(ppk_must, profiles)["status"] == "protected"
    ppk_pref = _gw(
        "c", pq_ppk={"enabled": True, "negotiation_mode": "preferred", "keys": [{"name": "k"}]}
    )
    assert pa.assess_gateway(ppk_pref, profiles)["status"] == "fallback"
    # ML-KEM only via the profile, classical ciphers not blocked.
    assert pa.assess_gateway(_gw("d"), profiles)["status"] == "fallback"
    classic = _gw(
        "e", protocol={"version": "ikev2", "ikev2": {"ike_crypto_profile": "ike-classic"}}
    )
    assert pa.assess_gateway(classic, profiles)["status"] == "vulnerable"
    v1 = _gw("f", protocol={"version": "ikev1", "ikev1": {}})
    assert pa.assess_gateway(v1, profiles)["status"] == "unsupported"


def test_notes() -> None:
    profiles = {p["name"]: p for p in PROFILES}
    gw = _gw(
        "g",
        pq_ppk={
            "enabled": True,
            "negotiation_mode": "mandatory",
            "keys": [{"name": "k", "enabled": False}],
        },
        protocol_common={"fragmentation": {"enable": False}},
        protocol={"version": "ikev2-preferred", "ikev2": {"ike_crypto_profile": "missing"}},
    )
    notes = " | ".join(pa.assess_gateway(gw, profiles)["notes"])
    assert "no key is active" in notes
    assert "ikev2-preferred" in notes
    assert "'missing' is not in this scope" in notes


def test_ake_summary_shapes() -> None:
    assert pa.ake_summary(None)["configured"] is False
    assert pa.ake_summary({"ake": {"enabled": False, "ake_1": ["ml-kem-512"]}})["enabled"] is False
    assert pa.ake_summary({"ake": {"ake_2": "ml-kem-1024"}})["ml_kem"] == ["ml-kem-1024"]


def test_tool_end_to_end() -> None:
    client = _client(
        {
            "ike-gateways": [
                _gw("gw-pq", pq_kem={"enable": True, "block_vulnerable_cipher": True}),
                _gw(
                    "gw-old",
                    protocol={"version": "ikev2", "ikev2": {"ike_crypto_profile": "ike-classic"}},
                ),
                _gw("gw-spare"),
            ],
            "ike-crypto-profiles": PROFILES,
            "ipsec-crypto-profiles": IPSEC,
            "ipsec-tunnels": [
                {
                    "name": "t1",
                    "auto_key": {
                        "ike_gateway": [{"name": "gw-pq"}],
                        "ipsec_crypto_profile": "ipsec-classic",
                    },
                },
                {
                    "name": "t2",
                    "auto_key": {
                        "ike_gateway": [{"name": "gw-old"}],
                        "ipsec_crypto_profile": "ipsec-pq",
                    },
                },
                {"name": "t3", "auto_key": {"ike_gateway": [{"name": "nope"}]}},
            ],
        }
    )
    out = json.loads(_tool(client)(tenant_id="1", folder="fw"))
    assert out["tunnels_by_status"] == {"protected": 1, "vulnerable": 1, "unknown": 1}
    assert out["unused_gateways"] == ["gw-spare"]
    assert out["crypto_profiles"]["ike_with_ml_kem"] == ["ike-pq"]
    t1 = next(t for t in out["tunnels"] if t["tunnel"] == "t1")
    assert any("child SA" in n for n in t1["notes"])
    assert all(c.kwargs["params"]["folder"] == "fw" for c in client.get.call_args_list)


def test_scope_validation() -> None:
    fn = _tool(_client({}))
    assert "exactly one" in fn(tenant_id="1")
    assert "exactly one" in fn(tenant_id="1", folder="a", snippet="b")


def test_missing_version_key_means_ikev2_preferred() -> None:
    profiles = {p["name"]: p for p in PROFILES}
    both = _gw("h", protocol={"ikev1": {"dpd": {}}, "ikev2": {"ike_crypto_profile": "ike-pq"}})
    assert pa.assess_gateway(both, profiles)["ike_version"] == "ikev2-preferred"
    only_v1 = _gw("i", protocol={"ikev1": {"dpd": {}}})
    assert pa.assess_gateway(only_v1, profiles)["status"] == "unsupported"
