"""Tests for the Entra ID resource-server mode on /mcp (Phase C2).

Tokens are signed locally with a throwaway RSA key and the JWKS lookup is
stubbed, so nothing here talks to Entra. All IDs are placeholders.
"""

from __future__ import annotations

import time
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp.server.fastmcp import FastMCP
from starlette.testclient import TestClient

import scm_harbourmaster_mcp.server_http as server_http
from scm_harbourmaster_mcp.auth import entra_resource
from scm_harbourmaster_mcp.auth.entra_resource import EntraResourceConfig, EntraTokenValidator

TENANT = "00000000-0000-0000-0000-00000000aaaa"
OTHER_TENANT = "00000000-0000-0000-0000-00000000bbbb"
CLIENT_ID = "00000000-0000-0000-0000-00000000cccc"
RESOURCE = "https://scm-mcp.example.net/mcp"
PRM_URL = "https://scm-mcp.example.net/.well-known/oauth-protected-resource/mcp"
SCOPE = f"{RESOURCE}/access"
API_KEY = "legacy-key"

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
WRONG_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)

CONFIG = EntraResourceConfig(
    tenant=TENANT, audience=CLIENT_ID, resource_url=RESOURCE, app_id_uri=RESOURCE
)

MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "pytest", "version": "0"},
    },
}


def token(key=KEY, kid="test", **overrides) -> str:
    now = int(time.time())
    claims = {
        "iss": f"https://login.microsoftonline.com/{TENANT}/v2.0",
        "aud": CLIENT_ID,
        "tid": TENANT,
        "oid": "00000000-0000-0000-0000-0000000000d1",
        "preferred_username": "user@example.net",
        "scp": "access",
        "iat": now,
        "exp": now + 600,
    }
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})


class FakeJWKS:
    """Stands in for PyJWKClient: one key, "test", and a fetch counter."""

    def __init__(self) -> None:
        self.refreshes = 0

    def get_signing_keys(self, refresh: bool = False):
        self.refreshes += refresh
        return [SimpleNamespace(key_id="test", key=KEY.public_key())]

    @staticmethod
    def match_kid(keys, kid):
        return next((k for k in keys if k.key_id == kid), None)


@pytest.fixture(autouse=True)
def stub_jwks(monkeypatch: pytest.MonkeyPatch) -> FakeJWKS:
    fake = FakeJWKS()
    monkeypatch.setattr(EntraTokenValidator, "_jwks_client", lambda self: fake)
    return fake


# ─── Validator ───────────────────────────────────────────────────────────────


class TestValidator:
    def check(self, tok: str, config: EntraResourceConfig = CONFIG):
        return EntraTokenValidator(config).validate(tok)

    def test_v2_token_with_client_id_audience(self) -> None:
        result = self.check(token())
        assert result.ok and result.claims["oid"].endswith("d1")

    def test_v1_token_with_app_id_uri_audience(self) -> None:
        result = self.check(token(iss=f"https://sts.windows.net/{TENANT}/", aud=RESOURCE))
        assert result.ok

    def test_default_api_uri_audience(self) -> None:
        assert self.check(token(aud=f"api://{CLIENT_ID}")).ok

    @pytest.mark.parametrize(
        "overrides",
        [
            {"aud": "00000000-0000-0000-0000-00000000ffff"},
            {"iss": f"https://login.microsoftonline.com/{OTHER_TENANT}/v2.0"},
            {"exp": int(time.time()) - 60},
            {"exp": None},
        ],
        ids=["wrong-aud", "wrong-iss", "expired", "no-exp"],
    )
    def test_rejected_claims(self, overrides) -> None:
        result = self.check(token(**overrides))
        assert not result.ok and result.error == "invalid_token"

    def test_wrong_tenant_claim(self) -> None:
        result = self.check(token(tid=OTHER_TENANT))
        assert result.error == "invalid_token" and "tenant" in result.description

    def test_bad_signature(self) -> None:
        assert self.check(token(key=WRONG_KEY)).error == "invalid_token"

    def test_hs256_is_refused(self) -> None:
        forged = jwt.encode(
            {"aud": CLIENT_ID}, "secret-long-enough-for-hmac-key", algorithm="HS256"
        )
        assert self.check(forged).error == "invalid_token"

    def test_missing_scope_is_insufficient(self) -> None:
        result = self.check(token(scp="User.Read"))
        assert result.error == "insufficient_scope"

    def test_app_role_only_when_configured(self) -> None:
        app_only = token(scp=None, roles=["MCP.Access"])
        assert self.check(app_only).error == "insufficient_scope"
        with_role = EntraResourceConfig(**{**CONFIG.__dict__, "app_role": "MCP.Access"})
        assert self.check(app_only, with_role).ok

    def test_unknown_kid_refetches_once_per_cooldown(self, stub_jwks) -> None:
        validator = EntraTokenValidator(CONFIG)
        for _ in range(5):
            assert validator.validate(token(kid="rotated")).error == "invalid_token"
        assert stub_jwks.refreshes == 1
        assert validator.validate(token()).ok

    def test_unconfigured_validator_refuses(self) -> None:
        assert not self.check(token(), EntraResourceConfig()).ok


# ─── Config and metadata ─────────────────────────────────────────────────────


class TestConfig:
    def test_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SCM_MCP_HTTP_ENTRA_TENANT", TENANT)
        monkeypatch.setenv("SCM_MCP_HTTP_ENTRA_AUDIENCE", CLIENT_ID)
        monkeypatch.setenv("SCM_MCP_HTTP_RESOURCE_URL", RESOURCE)
        cfg = EntraResourceConfig.from_env()
        assert cfg.app_id_uri == RESOURCE and cfg.scope == "access" and not cfg.as_metadata
        assert cfg.full_scope == SCOPE and cfg.problems() == []

    def test_full_scope_without_resource_url(self) -> None:
        cfg = EntraResourceConfig(tenant=TENANT, audience=CLIENT_ID)
        assert cfg.full_scope == f"api://{CLIENT_ID}/access"

    @pytest.mark.parametrize(
        "url",
        [RESOURCE + "/", "http://scm-mcp.example.net/mcp", RESOURCE + "?x=1"],
    )
    def test_bad_resource_urls(self, url) -> None:
        cfg = EntraResourceConfig(tenant=TENANT, audience=CLIENT_ID, resource_url=url)
        assert cfg.problems()

    def test_http_allowed_for_localhost(self) -> None:
        cfg = EntraResourceConfig(
            tenant=TENANT, audience=CLIENT_ID, resource_url="http://localhost:8080/mcp"
        )
        assert cfg.problems() == []

    def test_as_metadata_needs_resource_url(self) -> None:
        cfg = EntraResourceConfig(tenant=TENANT, audience=CLIENT_ID, as_metadata=True)
        assert cfg.problems()

    def test_challenge_strings(self) -> None:
        assert CONFIG.challenge() == f'Bearer resource_metadata="{PRM_URL}", scope="{SCOPE}"'
        assert CONFIG.challenge("insufficient_scope", 'no "access"') == (
            'Bearer error="insufficient_scope", error_description="no \'access\'", '
            f'resource_metadata="{PRM_URL}", scope="{SCOPE}"'
        )

    def test_metadata_points_at_entra_by_default(self) -> None:
        prm = CONFIG.protected_resource_metadata()
        assert prm["resource"] == RESOURCE
        assert prm["authorization_servers"] == [f"https://login.microsoftonline.com/{TENANT}/v2.0"]
        assert prm["scopes_supported"] == [SCOPE]

    def test_as_metadata_issuer_matches_prm(self) -> None:
        cfg = EntraResourceConfig(**{**CONFIG.__dict__, "as_metadata": True})
        asm = cfg.authorization_server_metadata()
        assert cfg.protected_resource_metadata()["authorization_servers"] == [asm["issuer"]]
        assert asm["issuer"] == "https://scm-mcp.example.net"
        assert asm["code_challenge_methods_supported"] == ["S256"]
        assert asm["authorization_endpoint"].startswith(
            f"https://login.microsoftonline.com/{TENANT}/"
        )
        assert "registration_endpoint" not in asm


# ─── HTTP app ────────────────────────────────────────────────────────────────


def _tiny_server() -> FastMCP:
    mcp = FastMCP(name="test-server")

    @mcp.tool()
    def ping() -> str:
        """Reply with pong."""
        return "pong"

    return mcp


def _app(monkeypatch: pytest.MonkeyPatch, mode: str, config: EntraResourceConfig = CONFIG):
    monkeypatch.setattr(server_http, "create_server", _tiny_server)
    monkeypatch.setattr(server_http, "_AUTH_MODE", mode)
    monkeypatch.setattr(server_http, "_API_KEY", API_KEY)
    monkeypatch.setattr(server_http, "_ENTRA", config)
    monkeypatch.setattr(server_http, "_HOST", "0.0.0.0")
    monkeypatch.setattr(server_http, "_ALLOWED_HOSTS", [])
    monkeypatch.setattr(server_http, "_STATELESS", False)
    return TestClient(server_http.create_http_app())


def _bearer(tok: str) -> dict[str, str]:
    return {**MCP_HEADERS, "Authorization": f"Bearer {tok}"}


class TestHttpApp:
    def test_metadata_is_public_at_both_paths(self, monkeypatch) -> None:
        with _app(monkeypatch, "entra") as client:
            for path in (
                "/.well-known/oauth-protected-resource/mcp",
                "/.well-known/oauth-protected-resource",
            ):
                resp = client.get(path)
                assert resp.status_code == 200, path
                assert resp.json()["resource"] == RESOURCE
            # AS metadata is off by default.
            assert client.get("/.well-known/oauth-authorization-server").status_code == 404

    def test_as_metadata_route_when_enabled(self, monkeypatch) -> None:
        cfg = EntraResourceConfig(**{**CONFIG.__dict__, "as_metadata": True})
        with _app(monkeypatch, "entra", cfg) as client:
            asm = client.get("/.well-known/oauth-authorization-server").json()
            prm = client.get("/.well-known/oauth-protected-resource/mcp").json()
            assert prm["authorization_servers"] == [asm["issuer"]]

    def test_no_metadata_in_apikey_mode(self, monkeypatch) -> None:
        with _app(monkeypatch, "apikey") as client:
            assert client.get("/.well-known/oauth-protected-resource/mcp").status_code == 404

    def test_missing_token_gets_challenge(self, monkeypatch) -> None:
        with _app(monkeypatch, "entra") as client:
            resp = client.post("/mcp", json=INITIALIZE, headers=MCP_HEADERS)
            assert resp.status_code == 401
            assert (
                resp.headers["www-authenticate"]
                == f'Bearer resource_metadata="{PRM_URL}", scope="{SCOPE}"'
            )

    def test_valid_token_initializes(self, monkeypatch) -> None:
        with _app(monkeypatch, "entra") as client:
            resp = client.post("/mcp", json=INITIALIZE, headers=_bearer(token()))
            assert resp.status_code == 200

    def test_invalid_token_401(self, monkeypatch) -> None:
        with _app(monkeypatch, "entra") as client:
            resp = client.post("/mcp", json=INITIALIZE, headers=_bearer(token(key=WRONG_KEY)))
            assert resp.status_code == 401
            assert 'error="invalid_token"' in resp.headers["www-authenticate"]

    def test_missing_scope_403(self, monkeypatch) -> None:
        with _app(monkeypatch, "entra") as client:
            resp = client.post("/mcp", json=INITIALIZE, headers=_bearer(token(scp="User.Read")))
            assert resp.status_code == 403
            assert 'error="insufficient_scope"' in resp.headers["www-authenticate"]

    def test_api_key_refused_in_entra_only_mode(self, monkeypatch) -> None:
        with _app(monkeypatch, "entra") as client:
            resp = client.post(
                "/mcp", json=INITIALIZE, headers={**MCP_HEADERS, "X-API-Key": API_KEY}
            )
            assert resp.status_code == 401

    def test_dual_mode_accepts_either(self, monkeypatch) -> None:
        with _app(monkeypatch, "apikey,entra") as client:
            by_key = client.post(
                "/mcp", json=INITIALIZE, headers={**MCP_HEADERS, "X-API-Key": API_KEY}
            )
            assert by_key.status_code == 200
            assert client.post("/mcp", json=INITIALIZE, headers=_bearer(token())).status_code == 200
            bad_key = client.post(
                "/mcp", json=INITIALIZE, headers={**MCP_HEADERS, "X-API-Key": "nope"}
            )
            assert bad_key.status_code == 401 and "www-authenticate" in bad_key.headers
            neither = client.post("/mcp", json=INITIALIZE, headers=MCP_HEADERS)
            assert (
                neither.status_code == 401
                and "resource_metadata" in neither.headers["www-authenticate"]
            )

    def test_apikey_mode_sends_no_challenge(self, monkeypatch) -> None:
        with _app(monkeypatch, "apikey") as client:
            resp = client.post("/mcp", json=INITIALIZE, headers=MCP_HEADERS)
            assert resp.status_code == 401 and "www-authenticate" not in resp.headers

    def test_entra_token_not_valid_on_v1(self, monkeypatch) -> None:
        monkeypatch.setattr("scm_harbourmaster_mcp.gateway.app.load_keys", lambda: {})
        with _app(monkeypatch, "apikey,entra") as client:
            assert (
                client.get("/v1/tools", headers={"Authorization": f"Bearer {token()}"}).status_code
                == 401
            )

    def test_cors_preflight_needs_no_credentials(self, monkeypatch) -> None:
        with _app(monkeypatch, "entra") as client:
            resp = client.options(
                "/mcp",
                headers={
                    "Origin": "https://app.example.net",
                    "Access-Control-Request-Method": "POST",
                },
            )
            assert resp.status_code == 200

    def test_options_without_origin_is_not_a_preflight(self, monkeypatch) -> None:
        with _app(monkeypatch, "entra") as client:
            for path in ("/mcp", "/messages/?session_id=" + "0" * 32):
                resp = client.options(path, headers={"Access-Control-Request-Method": "POST"})
                assert resp.status_code == 401, path

    def test_unknown_mode_is_500(self, monkeypatch) -> None:
        with _app(monkeypatch, "entra,bogus") as client:
            assert client.post("/mcp", json=INITIALIZE, headers=MCP_HEADERS).status_code == 500


class TestMain:
    @pytest.mark.parametrize("mode", ["bogus", "none,entra", ""])
    def test_bad_modes_refused(self, monkeypatch, mode) -> None:
        monkeypatch.setattr(server_http, "_AUTH_MODE", mode)
        with pytest.raises(SystemExit):
            server_http.main()

    def test_entra_problems_stop_startup(self, monkeypatch) -> None:
        monkeypatch.setattr(server_http, "_AUTH_MODE", "entra")
        bad = EntraResourceConfig(tenant=TENANT, audience=CLIENT_ID, resource_url=RESOURCE + "/")
        monkeypatch.setattr(server_http, "_ENTRA", bad)
        with pytest.raises(SystemExit, match="trailing slash"):
            server_http.main()


def test_principal_prefers_upn() -> None:
    assert entra_resource.principal({"oid": "x", "upn": "a@example.net", "azp": "c"}) == {
        "oid": "x",
        "upn": "a@example.net",
        "app_id": "c",
    }
