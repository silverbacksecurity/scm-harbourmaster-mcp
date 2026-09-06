"""
Planner Agent Phase 1 — tool manifest loader and safety rails.

The manifest (resources/tools_manifest.yaml) classifies every registered MCP
tool: access (read/write), Expert-Agent domain, tenant scope, idempotency,
and retry policy, plus known failure modes with fallbacks.

Safety rail (v1, non-negotiable): every ``access: write`` tool requires
explicit human approval before execution, regardless of trigger type.
``requires_approval()`` derives its answer from the manifest alone — it takes
no override parameter, reads no config flag, and raises on tools the
manifest doesn't know, so the execution layer cannot run an unclassified
tool by accident.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources as importlib_resources

import yaml

VALID_ACCESS = frozenset({"read", "write"})
VALID_DOMAINS = frozenset(
    {
        "deployment",
        "threat_coverage",
        "operational_health",
        "posture_compliance",
        "config_change",
        "licensing",
        "sdwan",
        "certificates",
        "identity",
        "pab",
        "dlp",
    }
)
VALID_SCOPES = frozenset({"tenant", "cross_tenant"})
VALID_RETRY_POLICIES = frozenset({"retry", "fallback", "fail_fast"})


class UnknownToolError(KeyError):
    """Raised for tools the manifest does not classify — never execute these."""


class ManifestError(ValueError):
    """Raised when the manifest file itself is malformed."""


@dataclass(frozen=True)
class ToolPolicy:
    name: str
    access: str
    domain: str
    scope: str
    idempotent: bool
    retry_policy: str
    known_failure_modes: str = ""

    def __post_init__(self) -> None:
        if self.access not in VALID_ACCESS:
            raise ManifestError(f"{self.name}: invalid access {self.access!r}")
        if self.domain not in VALID_DOMAINS:
            raise ManifestError(f"{self.name}: invalid domain {self.domain!r}")
        if self.scope not in VALID_SCOPES:
            raise ManifestError(f"{self.name}: invalid scope {self.scope!r}")
        if self.retry_policy not in VALID_RETRY_POLICIES:
            raise ManifestError(f"{self.name}: invalid retry_policy {self.retry_policy!r}")


@dataclass(frozen=True)
class Manifest:
    policies: dict[str, ToolPolicy] = field(default_factory=dict)

    def policy(self, tool_name: str) -> ToolPolicy:
        try:
            return self.policies[tool_name]
        except KeyError:
            raise UnknownToolError(
                f"Tool {tool_name!r} has no manifest entry — the Planner must not "
                "execute unclassified tools. Add it to tools_manifest.yaml."
            ) from None

    def requires_approval(self, tool_name: str) -> bool:
        """True when the tool must be gated on explicit human approval.

        v1 hard rule: every write tool, always. There is deliberately no
        parameter, environment variable, or config flag that changes this
        answer; unknown tools raise rather than default to unattended
        execution.
        """
        return self.policy(tool_name).access == "write"

    def domain_tools(self, domain: str) -> list[str]:
        """Tools in one Expert-Agent domain — the per-sub-plan context load."""
        if domain not in VALID_DOMAINS:
            raise ManifestError(f"Unknown domain {domain!r}")
        return sorted(n for n, p in self.policies.items() if p.domain == domain)

    def write_tools(self) -> list[str]:
        return sorted(n for n, p in self.policies.items() if p.access == "write")

    def cross_tenant_tools(self) -> list[str]:
        return sorted(n for n, p in self.policies.items() if p.scope == "cross_tenant")

    def coverage_gaps(self, registered_tools: set[str]) -> tuple[set[str], set[str]]:
        """(unclassified, stale) vs a live tool registry — both must be empty."""
        known = set(self.policies)
        return registered_tools - known, known - registered_tools


@lru_cache(maxsize=1)
def load_manifest() -> Manifest:
    """Load and validate the bundled manifest (cached for the process)."""
    ref = importlib_resources.files("scm_harbourmaster_mcp.resources") / "tools_manifest.yaml"
    raw = yaml.safe_load(ref.read_text())
    if not isinstance(raw, dict) or not raw:
        raise ManifestError("tools_manifest.yaml is empty or not a mapping")

    policies: dict[str, ToolPolicy] = {}
    for name, entry in raw.items():
        if not isinstance(entry, dict):
            raise ManifestError(f"{name}: entry must be a mapping")
        policies[name] = ToolPolicy(
            name=name,
            access=str(entry.get("access", "")),
            domain=str(entry.get("domain", "")),
            scope=str(entry.get("scope", "")),
            idempotent=bool(entry.get("idempotent", False)),
            retry_policy=str(entry.get("retry_policy", "")),
            known_failure_modes=str(entry.get("known_failure_modes", "") or ""),
        )
    return Manifest(policies=policies)
