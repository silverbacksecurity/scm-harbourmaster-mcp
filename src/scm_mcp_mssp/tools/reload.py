"""
Hot-reload tool for the scm-mcp-mssp server.

Reloads all scm_mcp_mssp submodules in-process without restarting the MCP
server. After reloading it (1) patches stale `from X import Y` bindings in all
other loaded scm_mcp_mssp modules, and (2) re-runs tool registration so tool
closures themselves are refreshed.

Why both steps are needed
-------------------------
FastMCP registers each tool as a closure captured at startup.  Reloading the
defining module rebuilds the module dict but does NOT replace the closure the
tool manager already holds — so a change to a *tool's own body* would be
invisible with reloading alone.  Patching cross-module `from X import Y`
bindings only fixes helper functions called *by name*.  To pick up tool-body
edits we re-run the registration callback (`register_all_tools`), which
re-decorates every tool; FastMCP's ``add_tool`` overwrites by name, so the
manager ends up holding the freshly-defined closures.
"""

from __future__ import annotations

import importlib
import sys
from collections.abc import Callable

from mcp.server.fastmcp import FastMCP

from ..utils.logging import get_logger

logger = get_logger(__name__)

# Explicit reload order: leaf modules first so that when an importer is
# reloaded its `from X import Y` statements pull in already-fresh modules.
_RELOAD_ORDER = [
    # Utilities (no intra-package deps)
    "scm_mcp_mssp.utils.logging",
    "scm_mcp_mssp.utils.errors",
    "scm_mcp_mssp.utils.ipenrich",
    # NOTE: config.settings is intentionally excluded.  Reloading it creates a
    # new TenantConfig class object; existing cached instances (auth.oauth._tenant_configs)
    # are then instances of the OLD class and fail isinstance() checks in auth modules.
    # Auth modules
    "scm_mcp_mssp.auth.sdwan",
    # Audit — leaves first
    "scm_mcp_mssp.audit.models",
    "scm_mcp_mssp.audit.pan_references",
    "scm_mcp_mssp.audit.sdwan_topo",
    "scm_mcp_mssp.audit.insights_extractor",
    "scm_mcp_mssp.audit.asbuilt_report",
    "scm_mcp_mssp.audit.bpa_checks",
    "scm_mcp_mssp.audit.ncsc_controls",
    "scm_mcp_mssp.audit.report",
    "scm_mcp_mssp.audit.extractor",
    "scm_mcp_mssp.audit.cloner",
    # Tools — after all audit modules are fresh
    "scm_mcp_mssp.tools.objects",
    "scm_mcp_mssp.tools.security",
    "scm_mcp_mssp.tools.network",
    "scm_mcp_mssp.tools.deployment",
    "scm_mcp_mssp.tools.dlp",
    "scm_mcp_mssp.tools.dns_security",
    "scm_mcp_mssp.tools.email_dlp",
    "scm_mcp_mssp.tools.posture",
    "scm_mcp_mssp.tools.compliance",
    "scm_mcp_mssp.tools.config_cleanup",
    "scm_mcp_mssp.tools.policy_optimizer",
    "scm_mcp_mssp.tools.config_orch",
    "scm_mcp_mssp.tools.site_management",
    "scm_mcp_mssp.tools.cdl_logforwarding",
    "scm_mcp_mssp.tools.insights",
    "scm_mcp_mssp.tools.ssr",
    "scm_mcp_mssp.tools.adnsr",
    "scm_mcp_mssp.tools.aiops",
    "scm_mcp_mssp.tools.audit",
    "scm_mcp_mssp.tools.ops",
    "scm_mcp_mssp.tools.mssp",
    "scm_mcp_mssp.tools.mt_interconnect",
    "scm_mcp_mssp.tools.pab",
    "scm_mcp_mssp.tools.mt_monitor",
    "scm_mcp_mssp.tools.pab_msp",
    "scm_mcp_mssp.tools.service_status",
    "scm_mcp_mssp.tools.sdwan",
    "scm_mcp_mssp.tools.setup",
    "scm_mcp_mssp.tools.ncsc_baseline",
    "scm_mcp_mssp.tools.ai_advisor",
    "scm_mcp_mssp.tools.msr",
]


def _patch_cross_module_refs(pkg: str = "scm_mcp_mssp") -> list[str]:
    """
    After reloading, walk every loaded scm_mcp_mssp module and update any
    attribute whose ``__module__`` points to another scm_mcp_mssp module.
    This refreshes stale `from X import Y` bindings so existing closures
    see the new implementations.

    Returns a list of ``"module.attr"`` strings that were updated.
    """
    patched: list[str] = []

    for mod_name, mod in list(sys.modules.items()):
        if not mod_name.startswith(pkg) or mod is None:
            continue
        mod_dict = getattr(mod, "__dict__", {})
        for attr_name, attr_val in list(mod_dict.items()):
            if attr_name.startswith("_"):
                continue
            src_mod_name = getattr(attr_val, "__module__", None)
            if not src_mod_name or not src_mod_name.startswith(pkg):
                continue
            if src_mod_name == mod_name:
                continue  # defined in this module — nothing to patch

            src_mod = sys.modules.get(src_mod_name)
            if src_mod is None:
                continue

            # Look up the canonical name in the source module.
            # Use __qualname__ for classes/functions to handle nested definitions.
            canonical = getattr(attr_val, "__name__", None) or attr_name
            new_val = getattr(src_mod, canonical, None) or getattr(src_mod, attr_name, None)
            if new_val is None or new_val is attr_val:
                continue

            try:
                setattr(mod, attr_name, new_val)
                patched.append(f"{mod_name.split('.')[-1]}.{attr_name}")
            except Exception:
                pass

    return patched


def register_reload_tool(mcp: FastMCP, reregister: Callable[[], None] | None = None) -> None:
    """Register the scm_reload hot-reload tool with the MCP server.

    Args:
        mcp: The FastMCP server.
        reregister: Optional callback that re-runs tool registration (e.g.
            ``lambda: register_all_tools(mcp, get_client, get_settings)``).
            Called after modules are reloaded so tool-body edits take effect.
    """

    @mcp.tool()
    def scm_reload(modules: list[str] | None = None) -> str:
        """Hot-reload scm_mcp_mssp source modules without restarting the MCP server.

        Reloads all scm_mcp_mssp submodules in dependency order, patches
        cross-module references, then re-registers all tools so edits to a
        tool's own body take effect immediately.

        Args:
            modules: Optional list of short module names to reload (e.g.
                     ["asbuilt_report", "extractor"]).  If omitted, all modules
                     in the standard reload list are refreshed.

        Returns:
            Summary of reloaded modules, patched references, and any errors.
        """
        target_names: list[str]
        if modules:
            # Map short names → full dotted names
            short_map = {n.split(".")[-1]: n for n in _RELOAD_ORDER}
            target_names = [short_map.get(m, m) for m in modules]
        else:
            target_names = list(_RELOAD_ORDER)

        reloaded: list[str] = []
        skipped: list[str] = []
        errors: list[str] = []

        for full_name in target_names:
            mod = sys.modules.get(full_name)
            if mod is None:
                skipped.append(full_name.split(".")[-1])
                continue
            try:
                importlib.reload(mod)
                reloaded.append(full_name.split(".")[-1])
                logger.info("module_reloaded", module=full_name)
            except Exception as exc:
                errors.append(f"{full_name.split('.')[-1]}: {exc}")
                logger.warning("module_reload_failed", module=full_name, error=str(exc))

        patched = _patch_cross_module_refs()

        # Re-run tool registration so tool-body edits replace the closures the
        # FastMCP tool manager holds. add_tool() refuses to overwrite an existing
        # name (it returns the existing tool), so first drop the tools that
        # register_all_tools owns — everything except the reload tools — then
        # re-add them. Roll the registry back if re-registration fails.
        reregistered = False
        tm = getattr(mcp, "_tool_manager", None)
        if reregister is not None and tm is not None:
            keep = {"scm_reload", "scm_restart"}
            saved = dict(tm._tools)
            try:
                for tname in list(tm._tools):
                    if tname not in keep:
                        tm.remove_tool(tname)
                reregister()
                reregistered = True
            except Exception as exc:
                tm._tools = saved  # restore registry if re-registration failed
                errors.append(f"re-register: {exc}")

        lines = [f"✅ Reloaded {len(reloaded)} module(s): {', '.join(reloaded)}"]
        if skipped:
            lines.append(f"⏭️  Skipped (not loaded): {', '.join(skipped)}")
        if patched:
            lines.append(f"🔗 Patched {len(patched)} cross-module reference(s)")
        if reregistered:
            count = len(tm._tools) if tm is not None else 0
            lines.append(f"♻️  Re-registered {count} tool(s) — tool-body edits are live")
        if errors:
            lines.append(f"❌ Errors ({len(errors)}):")
            for e in errors:
                lines.append(f"   • {e}")
        else:
            lines.append("No errors — changes are live.")

        return "\n".join(lines)

    @mcp.tool()
    def scm_restart(delay_seconds: int = 3) -> str:
        """Restart the MCP server process.

        Schedules a clean exit after returning this response.  Claude Desktop
        and most MCP supervisors detect the exit and automatically reconnect /
        restart the server.  Use this when a hot-reload (`scm_reload`) is not
        enough — e.g. after adding a new dependency, changing `server.py`,
        editing config files, or installing an SDK update.

        For the HTTP transport (`scm-mcp-http`) the process must be managed by
        a supervisor (systemd, Docker restart policy) for automatic restart to
        occur; otherwise it simply exits and must be restarted manually.

        Args:
            delay_seconds: Seconds to wait before sending SIGTERM (default 3,
                           minimum 1).  The delay lets this response be
                           delivered before the process terminates.

        Returns:
            Confirmation that restart has been scheduled.
        """
        import os
        import signal
        import threading

        delay = max(1, delay_seconds)

        def _delayed_exit() -> None:
            import time

            time.sleep(delay)
            os.kill(os.getpid(), signal.SIGTERM)

        t = threading.Thread(target=_delayed_exit, daemon=True, name="scm-restart")
        t.start()
        logger.info("scm_restart_scheduled", delay_seconds=delay, pid=os.getpid())
        return (
            f"🔄 MCP server restart scheduled in {delay}s (PID {os.getpid()}).\n"
            "Claude Desktop will reconnect automatically.\n\n"
            "If the server does not restart, run:\n"
            "```\nuv run scm-mcp\n```"
        )
