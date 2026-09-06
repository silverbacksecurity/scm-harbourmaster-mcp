"""OAuth2 authentication for SCM API."""

from .oauth import TenantCredentials, get_scm_client

__all__ = ["TenantCredentials", "get_scm_client"]
