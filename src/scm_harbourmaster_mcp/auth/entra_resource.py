"""OAuth 2.1 resource-server mode for ``/mcp``, with Microsoft Entra ID as the
authorization server (Phase C2).

The server never handles authorization codes or refresh tokens. Clients sign
users in with Entra directly; this module only

- publishes RFC 9728 protected resource metadata, so an MCP client can find
  Entra and the scope to ask for;
- optionally publishes RFC 8414 authorization server metadata that points at
  Entra's endpoints and adds ``code_challenge_methods_supported``, which
  Entra's own discovery document leaves out and which MCP clients are told
  to require (``SCM_MCP_HTTP_OAUTH_AS_METADATA``);
- validates Entra access tokens (signature via JWKS, issuer, audience,
  tenant, scope or app role) and builds the ``WWW-Authenticate`` challenges.

Env vars (all read by :meth:`EntraResourceConfig.from_env`):

  SCM_MCP_HTTP_ENTRA_TENANT      Entra tenant ID (GUID)
  SCM_MCP_HTTP_ENTRA_AUDIENCE    Application (client) ID of the API app
                                 registration
  SCM_MCP_HTTP_RESOURCE_URL      Public URL of /mcp, exactly as clients use it
                                 (e.g. https://scm-mcp.example.net/mcp). Turns
                                 on the metadata and the WWW-Authenticate
                                 challenge. No trailing slash.
  SCM_MCP_HTTP_ENTRA_APP_ID_URI  The API app's Application ID URI (default:
                                 the resource URL, which is what MCP clients
                                 send Entra as ``resource``)
  SCM_MCP_HTTP_ENTRA_SCOPE       Delegated scope the API app exposes
                                 (default: access)
  SCM_MCP_HTTP_ENTRA_APP_ROLE    App role accepted for app-only tokens
                                 (default: none, so app-only tokens are refused)
  SCM_MCP_HTTP_OAUTH_AS_METADATA "1"/"true" serves the authorization server
                                 metadata on this host and lists this host,
                                 not Entra, as the authorization server
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import jwt

from ..utils.logging import get_logger

logger = get_logger(__name__)

ENTRA_HOST = "https://login.microsoftonline.com"
# Least time between key-set refetches forced by an unknown key ID, so junk
# tokens can't make every request a round trip to Entra.
JWKS_REFRESH_COOLDOWN = 300.0
PRM_PATH = "/.well-known/oauth-protected-resource"
ASM_PATH = "/.well-known/oauth-authorization-server"


def _truthy(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes")


@dataclass(frozen=True)
class TokenCheck:
    """Outcome of validating a Bearer token."""

    ok: bool
    error: str = ""  # "invalid_token" | "insufficient_scope" when not ok
    description: str = ""
    claims: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EntraResourceConfig:
    tenant: str = ""
    audience: str = ""
    resource_url: str = ""
    app_id_uri: str = ""
    scope: str = "access"
    app_role: str = ""
    as_metadata: bool = False

    @classmethod
    def from_env(cls) -> EntraResourceConfig:
        resource_url = os.getenv("SCM_MCP_HTTP_RESOURCE_URL", "").strip()
        return cls(
            tenant=os.getenv("SCM_MCP_HTTP_ENTRA_TENANT", "").strip(),
            audience=os.getenv("SCM_MCP_HTTP_ENTRA_AUDIENCE", "").strip(),
            resource_url=resource_url,
            app_id_uri=os.getenv("SCM_MCP_HTTP_ENTRA_APP_ID_URI", "").strip() or resource_url,
            scope=os.getenv("SCM_MCP_HTTP_ENTRA_SCOPE", "").strip() or "access",
            app_role=os.getenv("SCM_MCP_HTTP_ENTRA_APP_ROLE", "").strip(),
            as_metadata=_truthy(os.getenv("SCM_MCP_HTTP_OAUTH_AS_METADATA", "")),
        )

    # ── Derived values ───────────────────────────────────────────────────────

    @property
    def issuer_v2(self) -> str:
        return f"{ENTRA_HOST}/{self.tenant}/v2.0"

    @property
    def issuer_v1(self) -> str:
        return f"https://sts.windows.net/{self.tenant}/"

    @property
    def jwks_uri(self) -> str:
        return f"{ENTRA_HOST}/{self.tenant}/discovery/v2.0/keys"

    @property
    def full_scope(self) -> str:
        """The scope a client requests from Entra, e.g. ``<App ID URI>/access``."""
        base = self.app_id_uri or (f"api://{self.audience}" if self.audience else "")
        return f"{base}/{self.scope}" if base else self.scope

    @property
    def origin(self) -> str:
        parts = urlsplit(self.resource_url)
        return f"{parts.scheme}://{parts.netloc}"

    @property
    def authorization_server(self) -> str:
        """The issuer listed in the protected resource metadata."""
        return self.origin if self.as_metadata else self.issuer_v2

    @property
    def metadata_url(self) -> str:
        """Where the protected resource metadata lives (RFC 9728 path form)."""
        path = urlsplit(self.resource_url).path
        return f"{self.origin}{PRM_PATH}{path if path != '/' else ''}"

    def metadata_paths(self) -> list[str]:
        """Local paths to serve the protected resource metadata on."""
        path = urlsplit(self.resource_url).path.rstrip("/")
        return [PRM_PATH + path, PRM_PATH] if path else [PRM_PATH]

    def problems(self) -> list[str]:
        """Configuration errors that should stop the server starting."""
        out = []
        if not self.tenant or not self.audience:
            out.append("SCM_MCP_HTTP_ENTRA_TENANT and SCM_MCP_HTTP_ENTRA_AUDIENCE must be set")
        if self.resource_url:
            parts = urlsplit(self.resource_url)
            local = parts.hostname in ("localhost", "127.0.0.1", "::1")
            if parts.scheme != "https" and not (parts.scheme == "http" and local):
                out.append("SCM_MCP_HTTP_RESOURCE_URL must be https:// (http only for localhost)")
            if self.resource_url.endswith("/") or parts.query or parts.fragment:
                out.append(
                    "SCM_MCP_HTTP_RESOURCE_URL must have no trailing slash, query or "
                    "fragment: Entra compares it byte for byte with the App ID URI"
                )
        elif self.as_metadata:
            out.append("SCM_MCP_HTTP_OAUTH_AS_METADATA needs SCM_MCP_HTTP_RESOURCE_URL")
        return out

    # ── Metadata documents ───────────────────────────────────────────────────

    def protected_resource_metadata(self) -> dict[str, Any]:
        return {
            "resource": self.resource_url,
            "authorization_servers": [self.authorization_server],
            "scopes_supported": [self.full_scope],
            "bearer_methods_supported": ["header"],
            "resource_name": "scm-harbourmaster-mcp",
        }

    def authorization_server_metadata(self) -> dict[str, Any]:
        """Entra's endpoints under this host's issuer, with PKCE advertised.

        Built from the tenant ID, not fetched, so it can't fail at request
        time. There is deliberately no ``registration_endpoint``: Entra has
        no dynamic client registration, so clients use a pre-registered ID.
        """
        base = f"{ENTRA_HOST}/{self.tenant}/oauth2/v2.0"
        return {
            "issuer": self.origin,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "jwks_uri": self.jwks_uri,
            "response_types_supported": ["code"],
            "response_modes_supported": ["query", "fragment", "form_post"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": [
                "none",
                "client_secret_post",
                "client_secret_basic",
            ],
            "scopes_supported": [self.full_scope, "offline_access"],
        }

    # ── Challenges ───────────────────────────────────────────────────────────

    def challenge(self, error: str = "", description: str = "") -> str:
        """``WWW-Authenticate`` value for a 401 or 403 (RFC 6750, RFC 9728)."""
        params = []
        if error:
            params.append(f'error="{error}"')
        if description:
            params.append(f'error_description="{description.replace(chr(34), chr(39))}"')
        if self.resource_url:
            params.append(f'resource_metadata="{self.metadata_url}"')
        params.append(f'scope="{self.full_scope}"')
        return "Bearer " + ", ".join(params)


class EntraTokenValidator:
    """Validates Entra access tokens for one API app registration."""

    def __init__(self, config: EntraResourceConfig) -> None:
        self.config = config
        self._jwks: jwt.PyJWKClient | None = None
        self._lock = threading.Lock()
        self._last_refresh = float("-inf")

    def _jwks_client(self) -> jwt.PyJWKClient:
        if self._jwks is None:
            self._jwks = jwt.PyJWKClient(self.config.jwks_uri)
        return self._jwks

    def _signing_key(self, token: str) -> Any:
        """The key for the token's ``kid``, refetching at most once per cooldown."""
        kid = jwt.get_unverified_header(token).get("kid")
        if not kid:
            raise jwt.InvalidTokenError("token has no kid")
        client = self._jwks_client()
        key = client.match_kid(client.get_signing_keys(), kid)
        if key is None:
            with self._lock:
                now = time.monotonic()
                if now - self._last_refresh < JWKS_REFRESH_COOLDOWN:
                    raise jwt.InvalidTokenError("unknown kid")
                self._last_refresh = now
            key = client.match_kid(client.get_signing_keys(refresh=True), kid)
        if key is None:
            raise jwt.InvalidTokenError("unknown kid")
        return key

    def _audiences(self) -> list[str]:
        cfg = self.config
        # v2 tokens carry the client ID; v1 tokens carry the App ID URI.
        return [
            a for a in dict.fromkeys([cfg.audience, cfg.app_id_uri, f"api://{cfg.audience}"]) if a
        ]

    def validate(self, token: str) -> TokenCheck:
        """Check a token. Blocking on a JWKS fetch: call from a thread."""
        cfg = self.config
        if not cfg.tenant or not cfg.audience:
            logger.warning("entra_auth_misconfigured")
            return TokenCheck(False, "invalid_token", "server is not configured for Entra")
        try:
            signing_key = self._signing_key(token)
            claims: dict[str, Any] = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self._audiences(),
                issuer=[cfg.issuer_v2, cfg.issuer_v1],
                options={"require": ["exp", "iss", "aud"]},
            )
        except jwt.ExpiredSignatureError:
            return TokenCheck(False, "invalid_token", "token expired")
        except (jwt.InvalidTokenError, jwt.PyJWKClientError) as exc:
            logger.warning("entra_token_invalid", error=str(exc))
            return TokenCheck(False, "invalid_token", "token is not valid for this server")

        if claims.get("tid") != cfg.tenant:
            return TokenCheck(False, "invalid_token", "token is from another tenant")
        scopes = str(claims.get("scp", "")).split()
        roles = claims.get("roles") or []
        if cfg.scope in scopes or (cfg.app_role and cfg.app_role in roles):
            return TokenCheck(True, claims=claims)
        return TokenCheck(False, "insufficient_scope", f"token lacks the {cfg.scope} scope")


def principal(claims: dict[str, Any]) -> dict[str, str]:
    """The caller's identity, for logs and request state."""
    return {
        "oid": str(claims.get("oid", "")),
        "upn": str(claims.get("upn") or claims.get("preferred_username") or ""),
        "app_id": str(claims.get("azp") or claims.get("appid") or ""),
    }
