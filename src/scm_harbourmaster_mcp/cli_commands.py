"""
Non-interactive subcommands for scm-mcp-cli — e.g. `scm-mcp-cli backup --tenant X`,
for cron/CI use. Parses arguments, resolves tenant(s), and calls the same
cli_ops.run_* functions the interactive menu uses; only argument parsing and
plain-text output live here.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from typing import Any

from .cli_ops import NCSC_FRAMEWORK_LABELS
from .config.settings import TenantConfig
from .history import log_action, read_history


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scm-mcp-cli",
        description="scm-harbourmaster-mcp CLI. Omit all arguments to launch the interactive menu.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # Shared --tenant/--all-tenants/--quiet flags for the report-generating
    # subcommands, as a parent parser so they can appear after the subcommand
    # name (`backup --tenant x --quiet`), not just before it.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--quiet", action="store_true", help="Suppress progress lines; print only the final result."
    )
    tenant_group = common.add_mutually_exclusive_group(required=True)
    tenant_group.add_argument("--tenant", metavar="KEY", help="Tenant key from settings.toml")
    tenant_group.add_argument(
        "--all-tenants", action="store_true", help="Run against every configured tenant"
    )

    sub.add_parser(
        "backup", parents=[common], help="Snapshot Prisma Access + SD-WAN config to backups/*.json"
    )

    sub.add_parser("bpa", parents=[common], help="Run PAN Best Practice Analysis checks")

    p_ncsc = sub.add_parser(
        "ncsc",
        parents=[common],
        help="Run NCSC compliance mapping (CAF / Cyber Essentials / 10 Steps)",
    )
    p_ncsc.add_argument("--framework", choices=sorted(NCSC_FRAMEWORK_LABELS), default="all")

    p_asbuilt = sub.add_parser("asbuilt", parents=[common], help="Generate an AS-BUILT report")
    p_asbuilt.add_argument("--format", choices=["markdown", "docx"], default="markdown")
    p_asbuilt.add_argument("--customer-name", default=None, help="Defaults to the tenant label")
    p_asbuilt.add_argument("--mssp-name", default="MSSP")
    p_asbuilt.add_argument("--doc-version", default="1.0")

    p_audit = sub.add_parser(
        "audit-report", parents=[common], help="Generate a combined security audit report"
    )
    p_audit.add_argument("--format", choices=["markdown", "json"], default="markdown")

    sub.add_parser("list-tenants", help="List configured tenants")

    p_history = sub.add_parser("history", help="Show recent CLI action history")
    p_history.add_argument("--limit", type=int, default=20)

    return parser


def _resolve_tenants(args: argparse.Namespace) -> dict[str, TenantConfig]:
    from .cli import _load_all_tenants

    tenants = _load_all_tenants()
    if not tenants:
        print("No tenants configured. Check settings.toml and .secrets.toml.", file=sys.stderr)
        return {}
    if getattr(args, "all_tenants", False):
        return tenants
    key = args.tenant
    if key not in tenants:
        print(
            f"Unknown tenant key: {key!r}. Run 'scm-mcp-cli list-tenants' to see configured keys.",
            file=sys.stderr,
        )
        return {}
    return {key: tenants[key]}


def _run_for_each(
    args: argparse.Namespace,
    action: str,
    fn: Callable[[TenantConfig, Callable[[str], None] | None], Any],
) -> int:
    """Run `fn(tenant, on_progress)` for each resolved tenant, printing one
    result line per tenant and logging to history. Returns the process exit
    code: 0 if every tenant succeeded, 1 if any failed."""
    tenants = _resolve_tenants(args)
    if not tenants:
        return 1

    failed = 0
    for key, tenant in sorted(tenants.items()):
        on_progress = None if args.quiet else (lambda m, key=key: print(f"[{key}] {m}"))
        try:
            path = fn(tenant, on_progress)
        except Exception as exc:
            failed += 1
            print(f"[{key}] {action}: FAILED — {exc}", file=sys.stderr)
            log_action(
                action, tenant.tenant_id, tenant.label, "error", detail=str(exc)[:200], source="cli"
            )
            continue
        print(f"[{key}] {action}: OK -> {path}")
        log_action(action, tenant.tenant_id, tenant.label, "ok", source="cli")

    return 1 if failed else 0


def dispatch(args: argparse.Namespace) -> int:
    from . import cli_ops
    from .cli import _load_all_tenants

    if args.command == "list-tenants":
        tenants = _load_all_tenants()
        for key, tc in sorted(tenants.items()):
            print(f"{key}\t{tc.tenant_id}\t{(tc.tier or '').upper()}\t{tc.label}")
        return 0

    if args.command == "history":
        entries = read_history(args.limit)
        if not entries:
            print("No history yet.")
            return 0
        for e in entries:
            print(
                f"{e.get('ts', '')}\t{e.get('source', '')}\t{e.get('tenant_label') or '-'}\t"
                f"{e.get('action', '')}\t{e.get('status', '')}\t{e.get('detail', '')}"
            )
        return 0

    if args.command == "backup":
        return _run_for_each(args, "backup", lambda t, p: cli_ops.run_backup(t, on_progress=p).path)

    if args.command == "bpa":
        return _run_for_each(args, "bpa", lambda t, p: cli_ops.run_bpa(t, on_progress=p).path)

    if args.command == "ncsc":
        return _run_for_each(
            args, "ncsc", lambda t, p: cli_ops.run_ncsc(t, args.framework, on_progress=p).path
        )

    if args.command == "asbuilt":
        return _run_for_each(
            args,
            "asbuilt_report",
            lambda t, p: (
                cli_ops.run_asbuilt(
                    t,
                    output_format=args.format,
                    customer_name=args.customer_name,
                    mssp_name=args.mssp_name,
                    doc_version=args.doc_version,
                    on_progress=p,
                ).path
            ),
        )

    if args.command == "audit-report":
        return _run_for_each(
            args,
            "audit_report",
            lambda t, p: cli_ops.run_audit_report(t, args.format, on_progress=p).path,
        )

    print(f"Unknown command: {args.command}", file=sys.stderr)
    return 1
