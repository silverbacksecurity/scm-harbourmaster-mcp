"""
Palo Alto Networks Customer Support Portal (CSP) — Software NGFW flexible
licensing API (the `fwflex-service` OAuth scope, `/tms/v1/*`).

This is NOT a general CSP asset/case-management surface — CSP's Account
Management → OAuth API Management page only exposes the `fwflex-service`
scope, which covers credit-pool based (usage) licensing for Software NGFW /
VM-Series deployments: credit pools, deployment profiles (auth codes), and
the firewall serials registered against an auth code.

Auth: OAuth2 client_credentials against ONE global CSP account credential
(unlike SCM's per-managed-tenant OAuth) — SCM_MCP_CSP_CLIENT_ID /
SCM_MCP_CSP_CLIENT_SECRET. Token endpoint:
https://identity.paloaltonetworks.com/as/token.oauth2 (scope=fwflex-service).
The resulting token is sent as a bare `token:` header on
api.paloaltonetworks.com calls — NOT `Authorization: Bearer`.

Ref: https://docs.paloaltonetworks.com/vm-series/vm-series-deployment/
license-the-vm-series-firewall/software-ngfw/software-ngfw-licensing-api

Read-only for now — create/update/delete of deployment profiles and
firewall deactivation are real licensing-affecting writes and are
deliberately not wired up here.
"""

from __future__ import annotations

import json as _json
import time
from typing import Any

import requests as _requests
from mcp.server.fastmcp import FastMCP

from ..config.settings import get_settings
from ..utils.logging import get_logger

logger = get_logger(__name__)

_TOKEN_URL = "https://identity.paloaltonetworks.com/as/token.oauth2"
_API_BASE = "https://api.paloaltonetworks.com/tms/v1"
_SCOPE = "fwflex-service"
_MAX_CHARS = 15000

_VIEWS = (
    "credit_pools",
    "credit_pool",
    "deployment_profiles",
    "deployment_profile",
    "firewall_serial_numbers",
)

# Single global CSP credential → one cached token serves every call.
_token_cache: dict[str, Any] = {}


def _get_token() -> str | None:
    settings = get_settings()
    client_id = settings.csp_client_id
    client_secret = settings.csp_client_secret.get_secret_value()
    if not client_id or not client_secret:
        return None

    cached = _token_cache.get("token")
    expiry = _token_cache.get("expiry", 0.0)
    if cached and time.time() < expiry:
        return cached

    resp = _requests.post(
        _TOKEN_URL,
        data={
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": _SCOPE,
            "grant_type": "client_credentials",
        },
        timeout=(5, 15),
    )
    resp.raise_for_status()
    body = resp.json()
    token = body.get("access_token")
    if not token:
        return None
    ttl = int(body.get("expires_in") or 3600)
    _token_cache["token"] = token
    _token_cache["expiry"] = time.time() + max(ttl - 60, 30)
    return token


def _render(title: str, url: str, status: int, body: Any) -> str:
    if status == 401:
        return (
            f"# {title}\n\n⚠️ HTTP 401 — the CSP token was rejected. Verify "
            f"SCM_MCP_CSP_CLIENT_ID/SECRET are current (CSP shows the secret "
            f"only once, at creation) and still carry the fwflex-service scope."
        )
    if status in (403, 404):
        return f"# {title}\n\nHTTP {status} — not found, or not entitled on this CSP account."
    if status >= 500:
        return f"# {title}\n\nHTTP {status} — PAN backend error from `{url}` (transient; retry)."
    if status != 200:
        return f"# {title}\n\nHTTP {status} from `{url}`:\n\n{body}"
    text = _json.dumps(body, indent=2, default=str) if not isinstance(body, str) else body
    if len(text) > _MAX_CHARS:
        text = text[:_MAX_CHARS] + "\n… (truncated)"
    return f"# {title}\n\n```json\n{text}\n```"


def register_csp_licensing_tools(mcp: FastMCP) -> None:
    """Register the CSP Software NGFW flexible-licensing query tool."""

    @mcp.tool()
    def scm_csp_licensing_query(
        view: str,
        credit_pool_id: str = "",
        auth_code: str = "",
    ) -> str:
        """Query the CSP Software NGFW flexible-licensing API (fwflex-service scope).

        Credit-pool based (usage) licensing data for Software NGFW / VM-Series
        deployments — NOT a general CSP asset or case-management API (CSP's
        OAuth API Management page only exposes the fwflex-service scope).
        Read-only.

        Views:
            credit_pools — all credit pools on the CSP account.
            credit_pool — one credit pool (requires credit_pool_id).
            deployment_profiles — deployment profiles (auth codes) in a
                credit pool (requires credit_pool_id).
            deployment_profile — one deployment profile (requires auth_code).
            firewall_serial_numbers — firewall serials registered against an
                auth code (requires auth_code).

        Args:
            view: One of the views listed above.
            credit_pool_id: Credit pool ID — required for credit_pool and
                deployment_profiles.
            auth_code: Deployment profile auth code — required for
                deployment_profile and firewall_serial_numbers.

        Returns:
            Markdown with the JSON payload, or an actionable message on
            missing credentials/params or a 4xx/5xx.
        """
        if view not in _VIEWS:
            return f"Unknown view {view!r}. Valid views: {', '.join(_VIEWS)}"
        if view in ("credit_pool", "deployment_profiles") and not credit_pool_id:
            return f"view={view!r} requires credit_pool_id."
        if view in ("deployment_profile", "firewall_serial_numbers") and not auth_code:
            return f"view={view!r} requires auth_code."

        try:
            token = _get_token()
        except Exception as exc:
            logger.warning("csp_token_error", error=str(exc))
            return f"Error obtaining CSP token: {exc}"
        if not token:
            return (
                "No CSP credentials configured. Set SCM_MCP_CSP_CLIENT_ID and "
                "SCM_MCP_CSP_CLIENT_SECRET (CSP → Account Management → OAuth "
                "API Management → fwflex-service scope)."
            )

        params: dict[str, str] = {}
        if view == "credit_pools":
            url = f"{_API_BASE}/creditPool"
        elif view == "credit_pool":
            url = f"{_API_BASE}/creditPool/{credit_pool_id}"
        elif view == "deployment_profiles":
            url = f"{_API_BASE}/creditPool/{credit_pool_id}/deploymentProfile"
        elif view == "deployment_profile":
            url = f"{_API_BASE}/deploymentProfile/{auth_code}"
        else:  # firewall_serial_numbers
            url = f"{_API_BASE}/firewallserialnumbers"
            params["auth_code"] = auth_code

        try:
            resp = _requests.get(url, headers={"token": token}, params=params, timeout=(5, 30))
            try:
                body = resp.json()
            except Exception:
                body = (resp.text or "")[:500]
        except Exception as exc:
            logger.warning("csp_query_error", view=view, error=str(exc))
            return f"Error: {exc}"

        logger.info("csp_licensing_query", view=view, status=resp.status_code)
        return _render(f"CSP Licensing — {view}", url, resp.status_code, body)
