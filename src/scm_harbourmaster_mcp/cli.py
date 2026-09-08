"""
scm-harbourmaster-mcp interactive CLI — MSSP operator menu.

Launch with:  uv run scm-mcp-cli
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from pathlib import Path
from typing import Any, TypeGuard

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from .config.settings import TenantConfig, load_all_tenant_configs
from .history import audited, log_action, read_history

console = Console()

# PAN flame — stylised orange swoosh matching the Palo Alto Networks brand mark
PAN_FLAME = """\
          ░░░
        ░▒▒▒▒▒░
       ░▒███████▒░
      ░▒█████████▒░
      ░▒█████████▒░
       ░▒███████▒░
        ░░▒▒▒▒▒░░
          ░▒█▒░
         ░▒███▒░
        ░▒█████▒░
       ░▒███████▒░
      ░▒█████████▒░
      ░▒█████████▒░
       ░▒███████▒░
        ░░▒▒▒▒▒░░
          ░░░\
"""

PAN_WORDMARK = """\
 ██████╗  █████╗ ██╗      ██████╗
 ██╔══██╗██╔══██╗██║     ██╔═══██╗
 ██████╔╝███████║██║     ██║   ██║
 ██╔═══╝ ██╔══██║██║     ██║   ██║
 ██║     ██║  ██║███████╗╚██████╔╝
 ╚═╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝

  █████╗ ██╗  ████████╗ ██████╗
 ██╔══██╗██║  ╚══██╔══╝██╔═══██╗
 ███████║██║     ██║   ██║   ██║
 ██╔══██║██║     ██║   ██║   ██║
 ██║  ██║███████╗██║   ╚██████╔╝
 ╚═╝  ╚═╝╚══════╝╚═╝    ╚═════╝

  N  E  T  W  O  R  K  S\
"""

BANNER = r"""
 ██████╗ ██████╗███╗   ███╗      ███╗   ███╗ ██████╗██████╗
██╔════╝██╔════╝████╗ ████║      ████╗ ████║██╔════╝██╔══██╗
╚█████╗ ██║     ██╔████╔██║█████╗██╔████╔██║██║     ██████╔╝
 ╚═══██╗██║     ██║╚██╔╝██║╚════╝██║╚██╔╝██║██║     ██╔═══╝
██████╔╝╚██████╗██║ ╚═╝ ██║      ██║ ╚═╝ ██║╚██████╗██║
╚═════╝  ╚═════╝╚═╝     ╚═╝      ╚═╝     ╚═╝ ╚═════╝╚═╝
"""

try:
    VERSION = "v" + _pkg_version("scm-harbourmaster-mcp")
except PackageNotFoundError:
    VERSION = "dev"
SUBTITLE = "Strata Cloud Manager · MSSP Edition"


# ── tenant loader ────────────────────────────────────────────────────────────


def _load_all_tenants() -> dict[str, TenantConfig]:
    """Load and merge settings.toml + .secrets.toml, return keyed TenantConfigs."""
    try:
        return load_all_tenant_configs()
    except Exception as exc:
        console.print(f"[red]Failed to load tenants: {exc}[/red]")
        return {}


# ── display helpers ──────────────────────────────────────────────────────────


def _clear() -> None:
    console.clear()


def _print_banner(active_tenant: TenantConfig | None = None) -> None:
    _clear()
    flame_text = Text(PAN_FLAME, style="#FF6823")
    wordmark_text = Text(PAN_WORDMARK, style="bold #FF6823")
    console.print(Align.center(Columns([flame_text, wordmark_text], equal=False, expand=False)))
    console.print()
    console.print(Align.center(Text(BANNER, style="bold cyan")))
    console.print(Align.center(Text(f"{SUBTITLE}  {VERSION}", style="dim cyan")))
    console.print()

    if active_tenant:
        info = (
            f"[bold]Tenant:[/bold] {active_tenant.label}  "
            f"[dim]│[/dim]  [bold]TSG:[/bold] {active_tenant.tenant_id}  "
            f"[dim]│[/dim]  [bold]Folder:[/bold] {active_tenant.default_folder}"
        )
        console.print(Panel(info, box=box.ROUNDED, border_style="cyan"), justify="center")
    else:
        console.print(
            Panel(
                "[yellow]No tenant selected — choose option S to select[/yellow]",
                box=box.ROUNDED,
                border_style="yellow",
            ),
            justify="center",
        )
    console.print()


def _menu_table(rows: list[tuple[str, str, str]]) -> Table:
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2), expand=False)
    t.add_column(style="bold cyan", no_wrap=True, width=5)
    t.add_column(style="bold white", no_wrap=True, width=26)
    t.add_column(style="dim")
    for key, label, desc in rows:
        t.add_row(f"[{key}]", label, desc)
    return t


def _section(title: str) -> None:
    console.print(f"  [bold dim]── {title} {'─' * max(0, 44 - len(title))}[/bold dim]")


# ── generic CLI helpers ─────────────────────────────────────────────────────


def _get_cli_client(tenant: TenantConfig) -> Any | None:
    """Connect to SCM and return an authenticated client, or None on failure."""
    from .auth.oauth import get_scm_client

    console.print(f"\n[cyan]Connecting to [bold]{tenant.label}[/bold]...[/cyan]")
    try:
        return get_scm_client(tenant)
    except Exception as exc:
        console.print(f"[red]Auth failed: {exc}[/red]")
        Prompt.ask("\nPress Enter to continue")
        return None


def _list_and_display(
    client: Any,
    resource: str,
    folder: str,
    title: str,
    columns: list[str] | None = None,
    **kwargs: Any,
) -> list[Any]:
    """Generic list + Rich table display for any SDK resource."""
    with console.status(f"[cyan]Fetching {title.lower()} from [bold]{folder}[/bold]...[/cyan]"):
        try:
            obj = getattr(client, resource)
            try:
                results = list(obj.list(folder=folder, limit=200, **kwargs))
            except TypeError:
                # Some SDK resources (e.g. IKEGateway) don't accept a `limit` kwarg.
                results = list(obj.list(folder=folder, **kwargs))
        except Exception as exc:
            console.print(f"[red]Error fetching {title}: {exc}[/red]")
            return []

    if not results:
        console.print(f"\n[yellow]No {title.lower()} found in folder '{folder}'.[/yellow]")
        return []

    t = Table(title=title, box=box.SIMPLE_HEAD, expand=True)
    if columns:
        for col in columns:
            t.add_column(col.replace("_", " ").title(), style="cyan" if col == "name" else "")
    else:
        t.add_column("Name", style="cyan")

    for item in results:
        row: list[str] = []
        if columns:
            for col in columns:
                val = getattr(item, col, None)
                row.append(str(val) if val is not None else "—")
        else:
            row.append(str(getattr(item, "name", item)))
        t.add_row(*row)

    console.print(t)
    console.print(f"[dim]{len(results)} item(s)[/dim]")
    return results


def _save_json(data: Any, prefix: str, tenant_id: str) -> Path | None:
    """Save data as timestamped JSON in backups/. Returns path or None."""
    try:
        backup_dir = Path("backups")
        backup_dir.mkdir(exist_ok=True)
        ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        out = backup_dir / f"{prefix}_{tenant_id}_{ts}.json"
        if data and hasattr(data[0], "model_dump"):
            payload = [d.model_dump() for d in data]
        else:
            payload = data
        out.write_text(json.dumps(payload, indent=2, default=str))
        return out
    except Exception as exc:
        console.print(f"[yellow]⚠ Could not save JSON: {exc}[/yellow]")
        return None


def _pause() -> None:
    """Wait for the user to press Enter."""
    Prompt.ask("\nPress Enter to continue")


def _exc_str(exc: Exception) -> str:
    """str(exc), falling back for pan-scm-sdk APIErrors whose __str__ omits
    .message when raised without an error_code/http_status_code/details
    (e.g. HTTP errors with an empty response body)."""
    return str(exc) or getattr(exc, "message", "") or repr(exc)


# ── main menu ──────────────────────────────────────────────────────────────

_status_light_cache: dict[str, Any] = {"ts": 0.0, "line": ""}


def _scm_status_light() -> str:
    """Traffic-light PAN cloud status line for the main menu.

    Public statuspage feed, no tenant credentials; cached 5 minutes so menu
    redraws don't refetch, and failures degrade to a grey light rather than
    slowing or breaking the menu.
    """
    import time

    if time.time() - _status_light_cache["ts"] < 300:
        return _status_light_cache["line"]
    try:
        from .tools.service_status import _INDICATOR_EMOJI, _fetch, _is_sase_relevant, _text_of

        status = _fetch("status.json", timeout=(2, 5)).get("status", {})
        indicator = status.get("indicator") or "none"
        emoji = "🟢" if indicator == "none" else _INDICATOR_EMOJI.get(indicator, "🟡")
        line = f"{emoji} PAN cloud: {status.get('description', 'Operational')}"
        if indicator != "none":
            incidents = [
                i
                for i in _fetch("incidents/unresolved.json", timeout=(2, 5)).get("incidents", [])
                if _is_sase_relevant(_text_of(i))
            ]
            if incidents:
                line += (
                    f"  │  {len(incidents)} SASE incident(s) — see MSSP Ops → PAN Service Status"
                )
    except Exception:
        line = "⚪ PAN cloud: status unavailable"
    _status_light_cache.update(ts=time.time(), line=line)
    return line


def _print_main_menu(tenant: TenantConfig | None) -> None:
    _print_banner(tenant)
    console.print(Align.center(Text(_scm_status_light(), style="dim")))
    console.print()
    _section("CONFIG & INVENTORY")
    console.print(
        _menu_table(
            [
                ("1", "Browse Inventory", "Addresses, zones, rules, tunnels, devices, folders..."),
            ]
        )
    )
    console.print()
    _section("AUDIT & COMPLIANCE")
    console.print(
        _menu_table(
            [
                (
                    "2",
                    "Audit & Compliance",
                    "Backup, BPA, NCSC, NIST, DSPT, ISO, AS-BUILT, AI advisor...",
                ),
            ]
        )
    )
    console.print()
    _section("OPERATIONS")
    console.print(
        _menu_table(
            [
                ("3", "SD-WAN", "Sites, elements, WAN networks, topology diagrams..."),
                ("4", "SSE, DLP & CASB", "DLP profiles, CASB, ZTNA connectors, Browser, AIRS..."),
                ("5", "MSSP Operations", "Dashboards, licences, certs, GP sessions, SPN..."),
                (
                    "6",
                    "Posture & Incidents",
                    "Posture, SSPM, compliance scores, incidents, TLS certs",
                ),
                ("7", "NCSC / NIST Remediation", "Baselines, snippets, gap analysis, AI advisor"),
                ("8", "Config Lifecycle", "Diff, clone, push, rollback, commit, AIOps BPA, ADNSR"),
            ]
        )
    )
    console.print()
    _section("MANAGEMENT")
    console.print(
        _menu_table(
            [
                ("L", "List Tenants", "Show all configured tenants and status"),
                ("S", "Select Tenant", "Switch active tenant"),
                ("A", "Add Tenant", "Add a new tenant to settings.toml / .secrets.toml"),
                ("U", "Check for Updates", "pan-scm-sdk, prisma-sase, MCP — PyPI + pan.dev"),
                ("R", "Restart MCP Server", "Send SIGTERM and restart scm-mcp / scm-mcp-http"),
                ("H", "History", "Recent backups, reports, tenant changes — audit trail"),
                ("0", "Exit", ""),
            ]
        )
    )
    console.print()


# ── operation handlers ───────────────────────────────────────────────────────


def _require_tenant(tenant: TenantConfig | None) -> TypeGuard[TenantConfig]:
    if tenant is None:
        console.print("\n[red]No tenant selected. Choose option S first.[/red]")
        Prompt.ask("\nPress Enter to continue")
        return False
    return True


@audited("backup")
def _op_backup(tenant: TenantConfig) -> None:
    from .cli_ops import run_backup

    console.print(f"\n[cyan]Connecting to [bold]{tenant.label}[/bold]...[/cyan]")
    try:
        result = run_backup(tenant, on_progress=lambda m: console.print(f"  {m}"))
    except Exception as exc:
        console.print(f"[red]Error: {_exc_str(exc)}[/red]")
        Prompt.ask("\nPress Enter to continue")
        return

    console.print(
        f"\n  [bold green]Backup written:[/bold green] {result.path}  ({result.size_kb} KB)"
    )
    if result.extraction_errors:
        console.print(f"  [yellow]Warnings ({len(result.extraction_errors)}):[/yellow]")
        for e in result.extraction_errors[:5]:
            console.print(f"    [dim]{e[:120]}[/dim]")
    Prompt.ask("\nPress Enter to continue")


def _op_add_tenant() -> tuple[str, TenantConfig] | None:
    """Interactively add a new tenant, writing to settings.toml and .secrets.toml."""
    import re
    import tomllib
    from pathlib import Path

    from rich.prompt import Confirm

    console.print()
    settings_path = Path("settings.toml")
    secrets_path = Path(".secrets.toml")

    # Read existing keys to prevent duplicates
    existing_keys: set[str] = set()
    if settings_path.exists():
        with open(settings_path, "rb") as _f:
            existing_keys = set(tomllib.load(_f).get("tenants", {}).keys())

    # ── Prompts ───────────────────────────────────────────────────────────────
    label = Prompt.ask("Customer label (display name)").strip()
    if not label:
        console.print("[yellow]Cancelled.[/yellow]")
        return None

    suggested_key = re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")

    while True:
        key = Prompt.ask("Tenant key (TOML section name)", default=suggested_key).strip()
        if not key:
            console.print("[yellow]Cancelled.[/yellow]")
            return None
        if not re.match(r"^[a-z0-9][a-z0-9-]*$", key):
            console.print("[red]Key must be lowercase alphanumeric with hyphens.[/red]")
            continue
        if key in existing_keys:
            console.print(f"[red]Key [bold]{key}[/bold] already exists in settings.toml.[/red]")
            continue
        break

    tenant_id = Prompt.ask("Tenant / TSG ID (numeric)").strip()
    if not tenant_id.isdigit():
        console.print("[red]Tenant ID must be numeric.[/red]")
        Prompt.ask("\nPress Enter to continue")
        return None

    client_id = Prompt.ask("Client ID (OAuth2 service account)").strip()
    if not client_id:
        console.print("[yellow]Cancelled.[/yellow]")
        return None

    client_secret = Prompt.ask("Client Secret", password=True).strip()
    if not client_secret:
        console.print("[yellow]Cancelled.[/yellow]")
        return None

    default_folder = Prompt.ask("Default folder", default="Shared").strip() or "Shared"
    term_raw = Prompt.ask("Service term (years)", choices=["1", "2", "3"], default="1")
    service_term_years = int(term_raw)
    account_ref = Prompt.ask("Account / CRM reference (optional)", default="").strip()

    # ── Preview ───────────────────────────────────────────────────────────────
    console.print()
    t = Table(box=box.ROUNDED, border_style="cyan", show_header=False)
    t.add_column("Field", style="dim")
    t.add_column("Value")
    t.add_row("Key", f"[cyan]{key}[/cyan]")
    t.add_row("Label", label)
    t.add_row("Tenant ID", tenant_id)
    t.add_row("Client ID", client_id)
    t.add_row("Client Secret", "[dim]●●●●●●●●●●●●[/dim]")
    t.add_row("Default Folder", default_folder)
    t.add_row("Service Term", f"{service_term_years} year(s)")
    if account_ref:
        t.add_row("Account Ref", account_ref)
    console.print(t)

    if not Confirm.ask("\nSave this tenant?", default=True):
        console.print("[yellow]Cancelled.[/yellow]")
        return None

    # ── Write settings.toml ───────────────────────────────────────────────────
    settings_block = f"\n[tenants.{key}]\n"
    settings_block += f'tenant_id          = "{tenant_id}"\n'
    settings_block += f'client_id          = "{client_id}"\n'
    settings_block += f'default_folder     = "{default_folder}"\n'
    settings_block += f'label              = "{label}"\n'
    settings_block += f"service_term_years = {service_term_years}\n"
    if account_ref:
        settings_block += f'account_ref        = "{account_ref}"\n'

    existing_text = settings_path.read_text() if settings_path.exists() else ""
    if existing_text and not existing_text.endswith("\n"):
        settings_block = "\n" + settings_block
    settings_path.write_text(existing_text + settings_block)

    # ── Write .secrets.toml ───────────────────────────────────────────────────
    secrets_block = f"\n[tenants.{key}]\n"
    secrets_block += f'client_secret = "{client_secret}"\n'

    existing_sec = secrets_path.read_text() if secrets_path.exists() else ""
    if existing_sec and not existing_sec.endswith("\n"):
        secrets_block = "\n" + secrets_block
    secrets_path.write_text(existing_sec + secrets_block)

    console.print(
        f"\n[bold green]✅ Tenant [cyan]{label}[/cyan] written to "
        f"settings.toml and .secrets.toml[/bold green]"
    )

    # ── Optional connection test ──────────────────────────────────────────────
    from pydantic import SecretStr as _SecretStr

    from .auth.oauth import get_scm_client
    from .config.settings import TenantConfig as _TC

    if Confirm.ask("Test connection now?", default=True):
        try:
            tc = _TC(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=_SecretStr(client_secret),
                default_folder=default_folder,
                label=label,
                service_term_years=service_term_years,
                account_ref=account_ref,
            )
            with console.status(f"[cyan]Connecting to {label}...[/cyan]"):
                get_scm_client(tc)
            console.print("[bold green]✅ Connection successful![/bold green]")
        except Exception as exc:
            console.print(f"[yellow]⚠️  Connection test failed: {exc}[/yellow]")
            console.print("[dim]Credentials were saved — verify and retry.[/dim]")
            Prompt.ask("\nPress Enter to continue")
            return None

    from .config.settings import TenantConfig as TC  # noqa: F811

    new_tc = TC(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=_SecretStr(client_secret),
        default_folder=default_folder,
        label=label,
        service_term_years=service_term_years,
        account_ref=account_ref,
    )
    Prompt.ask("\nPress Enter to continue")
    return key, new_tc


def _op_list_tenants(tenants: dict[str, TenantConfig]) -> None:
    console.print()
    t = Table(title="Configured Tenants", box=box.ROUNDED, border_style="cyan")
    t.add_column("#", style="dim", width=3)
    t.add_column("Key", style="cyan")
    t.add_column("Tenant ID", style="white")
    t.add_column("Folder", style="white")
    t.add_column("Label", style="white")

    for i, (k, tc) in enumerate(sorted(tenants.items()), 1):
        t.add_row(
            str(i),
            k,
            tc.tenant_id,
            tc.default_folder or "—",
            tc.label,
        )
    console.print(t)
    Prompt.ask("\nPress Enter to continue")


def _op_select_tenant(tenants: dict[str, TenantConfig]) -> TenantConfig | None:
    console.print()
    keys = sorted(tenants.keys())
    for i, k in enumerate(keys, 1):
        tc = tenants[k]
        console.print(
            f"  [cyan][{i}][/cyan]  {tc.label}  "
            f"[dim]│[/dim]  {tc.default_folder or '—'}  "
            f"[dim]{tc.tenant_id}[/dim]"
        )
    console.print()
    raw = Prompt.ask("Select tenant number (or Enter to cancel)", default="")
    if not raw.strip():
        return None
    try:
        idx = int(raw.strip()) - 1
        if 0 <= idx < len(keys):
            chosen = tenants[keys[idx]]
            console.print(f"\n[green]✓ Selected: {chosen.label}[/green]")
            return chosen
    except ValueError:
        pass
    console.print("[red]Invalid selection.[/red]")
    return None


@audited("bpa")
def _op_bpa(tenant: TenantConfig) -> None:
    from .audit.models import Status
    from .cli_ops import run_bpa

    console.print(f"\n[cyan]Connecting to [bold]{tenant.label}[/bold]...[/cyan]")
    try:
        with console.status("[cyan]Running BPA checks...[/cyan]"):
            result = run_bpa(tenant)
    except Exception as exc:
        console.print(f"[red]Error: {_exc_str(exc)}[/red]")
        Prompt.ask("\nPress Enter to continue")
        return

    findings = result.findings
    counts = result.counts

    # Summary panel
    summary = (
        f"[bold]Total:[/bold] {len(findings)}  "
        f"[green]Pass: {counts.get('pass', 0)}[/green]  "
        f"[red]Fail: {counts.get('fail', 0)}[/red]  "
        f"[yellow]Warn: {counts.get('warn', 0)}[/yellow]  "
        f"[dim]Skip: {counts.get('skip', 0)}[/dim]"
    )
    console.print(Panel(summary, title="BPA Summary", box=box.ROUNDED, border_style="cyan"))
    console.print()

    # Findings table — failed + warned first
    failed = [f for f in findings if f.status in (Status.FAIL, Status.WARN)]
    if failed:
        t = Table(box=box.SIMPLE_HEAD, border_style="dim", show_lines=False)
        t.add_column("ID", style="dim", width=12)
        t.add_column("Sev", width=9)
        t.add_column("Status", width=6)
        t.add_column("Title", style="white")
        t.add_column("Affected", style="dim")

        sev_colours = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "green"}
        status_styles = {"fail": "[red]FAIL[/red]", "warn": "[yellow]WARN[/yellow]"}

        for f in sorted(
            failed, key=lambda x: ("critical", "high", "medium", "low").index(x.severity.value)
        ):
            colour = sev_colours.get(f.severity.value, "white")
            affected = ", ".join(f.affected_objects[:3])
            if len(f.affected_objects) > 3:
                affected += f" +{len(f.affected_objects) - 3}"
            t.add_row(
                f.check_id,
                f"[{colour}]{f.severity.value.upper()}[/{colour}]",
                status_styles.get(f.status.value, f.status.value.upper()),
                f.title,
                affected,
            )
        console.print(t)
    else:
        console.print("[green]  ✓ No failed or warned checks.[/green]")

    console.print(f"\n  [bold green]Report saved:[/bold green] {result.path}")
    Prompt.ask("\nPress Enter to continue")


@audited("ncsc")
def _op_ncsc(tenant: TenantConfig) -> None:
    from .cli_ops import NCSC_FRAMEWORK_LABELS, run_ncsc

    # Framework picker
    console.print()
    console.print(
        _menu_table(
            [
                ("1", "All frameworks", "CAF v4.0 + Cyber Essentials + 10 Steps + NSF"),
                ("2", "CAF v4.0", "NCSC Cyber Assessment Framework (August 2025)"),
                ("3", "Cyber Essentials", "CE v3.2 firewall controls"),
                ("4", "10 Steps", "NCSC 10 Steps to Cyber Security"),
            ]
        )
    )
    fw_choice = Prompt.ask("Framework", default="1").strip()
    fw_map = {"1": "all", "2": "caf", "3": "ce", "4": "10steps"}
    framework = fw_map.get(fw_choice, "all")
    fw_label = NCSC_FRAMEWORK_LABELS[framework]

    console.print(f"\n[cyan]Connecting to [bold]{tenant.label}[/bold]...[/cyan]")
    try:
        with console.status("[cyan]Running BPA + NCSC mapping...[/cyan]"):
            result = run_ncsc(tenant, framework)
    except Exception as exc:
        console.print(f"[red]Error: {_exc_str(exc)}[/red]")
        Prompt.ask("\nPress Enter to continue")
        return

    controls_output = result.controls
    compliant = result.compliant
    non_compliant = result.non_compliant
    not_assessed = result.not_assessed
    total = result.total

    summary = (
        f"[bold]{fw_label}[/bold]  ·  [bold]Total:[/bold] {total}  "
        f"[green]Compliant: {compliant}[/green]  "
        f"[red]Non-compliant: {non_compliant}[/red]  "
        f"[dim]Not assessed: {not_assessed}[/dim]"
    )
    console.print(
        Panel(summary, title="NCSC Compliance Summary", box=box.ROUNDED, border_style="cyan")
    )
    console.print()

    # Controls table — non-compliant first, then compliant, then not-assessed
    t = Table(box=box.SIMPLE_HEAD, border_style="dim", show_lines=False)
    t.add_column("Control", style="dim", width=12)
    t.add_column("Source", width=14)
    t.add_column("Status", width=14)
    t.add_column("Title", style="white")

    status_order = {"non-compliant": 0, "compliant": 1, "not-assessed": 2}
    status_styles = {
        "compliant": "[green]COMPLIANT[/green]",
        "non-compliant": "[red]NON-COMPLIANT[/red]",
        "not-assessed": "[dim]NOT ASSESSED[/dim]",
    }
    source_colours = {"CAF v4.0": "cyan", "CE v3.2": "blue", "10 Steps": "magenta", "NSF": "yellow"}

    for c in sorted(controls_output, key=lambda x: status_order.get(x["compliance_status"], 9)):
        sc = source_colours.get(c["source"], "white")
        t.add_row(
            c["control_id"],
            f"[{sc}]{c['source']}[/{sc}]",
            status_styles.get(c["compliance_status"], c["compliance_status"]),
            c["title"],
        )
    console.print(t)

    console.print(f"\n  [bold green]Report saved:[/bold green] {result.path}")
    Prompt.ask("\nPress Enter to continue")


@audited("asbuilt_report")
def _op_asbuilt_report(tenant: TenantConfig) -> None:
    from .cli_ops import run_asbuilt

    # ── config state ─────────────────────────────────────────────────────────
    inc_prisma = True
    inc_sdwan = True
    inc_ngfw = True
    output_format = "markdown"
    customer_name = tenant.label
    mssp_name = "MSSP"
    doc_version = "1.0"

    def _asbuilt_submenu() -> bool:
        """Draw the AS-BUILT config submenu. Returns True to generate, False to go back."""
        _print_banner(tenant)
        console.rule("[cyan]AS-BUILT Report — Configuration[/cyan]")
        console.print()

        tick = "[green]✓[/green]"
        cross = "[dim]✗[/dim]"
        fmt_label = "DOCX" if output_format == "docx" else "Markdown"

        _section("INCLUDE")
        console.print(
            _menu_table(
                [
                    (
                        "1",
                        "Prisma Access",
                        f"{tick if inc_prisma else cross}  Remote Networks · Service Connections · Mobile Users",
                    ),
                    (
                        "2",
                        "SD-WAN",
                        f"{tick if inc_sdwan else cross}  ION sites · WAN networks · path groups (live)",
                    ),
                    (
                        "3",
                        "NGFWs",
                        f"{tick if inc_ngfw else cross}  On-prem / cloud-managed firewalls (ngfw-shared)",
                    ),
                ]
            )
        )
        console.print()
        _section("DOCUMENT")
        console.print(
            _menu_table(
                [
                    ("4", "Output format", f"[cyan]{fmt_label}[/cyan]"),
                    ("5", "Customer name", f"[cyan]{customer_name}[/cyan]"),
                    ("6", "MSSP name", f"[cyan]{mssp_name}[/cyan]"),
                    ("7", "Doc version", f"[cyan]{doc_version}[/cyan]"),
                ]
            )
        )
        console.print()
        console.print(
            _menu_table(
                [
                    ("G", "Generate Report", ""),
                    ("0", "Back", ""),
                ]
            )
        )
        console.print()
        return True

    while True:
        _asbuilt_submenu()
        choice = Prompt.ask("[bold cyan]>[/bold cyan]", default="").strip().upper()

        if choice == "0":
            return
        elif choice == "1":
            inc_prisma = not inc_prisma
        elif choice == "2":
            inc_sdwan = not inc_sdwan
        elif choice == "3":
            inc_ngfw = not inc_ngfw
        elif choice == "4":
            output_format = "docx" if output_format == "markdown" else "markdown"
        elif choice == "5":
            customer_name = Prompt.ask("Customer name", default=customer_name)
        elif choice == "6":
            mssp_name = Prompt.ask("MSSP name", default=mssp_name)
        elif choice == "7":
            doc_version = Prompt.ask("Doc version", default=doc_version)
        elif choice == "G":
            break

    console.print(f"\n[cyan]Connecting to [bold]{tenant.label}[/bold]...[/cyan]")
    try:
        with console.status("[cyan]Working...[/cyan]"):
            result = run_asbuilt(
                tenant,
                inc_prisma=inc_prisma,
                inc_sdwan=inc_sdwan,
                inc_ngfw=inc_ngfw,
                output_format=output_format,
                customer_name=customer_name,
                mssp_name=mssp_name,
                doc_version=doc_version,
                on_progress=lambda m: console.print(f"  {m}"),
            )
    except Exception as exc:
        console.print(f"[red]Error: {_exc_str(exc)}[/red]")
        Prompt.ask("\nPress Enter to continue")
        return

    if result.output_format == "docx":
        console.print(f"\n  [bold green]DOCX saved:[/bold green] {result.path}")
    else:
        console.print(
            f"\n  [bold green]Markdown saved:[/bold green] {result.path}  ({result.size_kb} KB)"
        )
    if result.docx_error:
        console.print(f"  [yellow]DOCX conversion failed:[/yellow] {result.docx_error}")
    if result.extraction_errors:
        console.print(f"  [yellow]Warnings ({len(result.extraction_errors)}):[/yellow]")
        for e in result.extraction_errors[:3]:
            console.print(f"    [dim]{e[:120]}[/dim]")

    Prompt.ask("\nPress Enter to continue")


@audited("sdwan_topology")
def _op_sdwan_topology(tenant: TenantConfig) -> None:
    from .audit.sdwan_topo import build_topology, topology_to_mermaid
    from .auth.sdwan import get_sdwan_client, safe_items

    # submenu toggles
    inc_diagram = True
    inc_summary = True
    output_format = "markdown"

    def _topo_submenu() -> None:
        _print_banner(tenant)
        console.rule("[cyan]SD-WAN Topology[/cyan]")
        console.print()
        tick = "[green]✓[/green]"
        cross = "[dim]✗[/dim]"
        _section("GENERATE")
        console.print(
            _menu_table(
                [
                    (
                        "1",
                        "VPN Topology Diagram",
                        f"{tick if inc_diagram else cross}  Mermaid graph of VPN overlay (hub/spoke/branch)",
                    ),
                    (
                        "2",
                        "Site & Element Summary",
                        f"{tick if inc_summary else cross}  ION inventory, WAN networks, clusters, policies",
                    ),
                ]
            )
        )
        console.print()
        _section("OUTPUT")
        console.print(
            _menu_table(
                [
                    (
                        "3",
                        "Format",
                        f"[cyan]{'Markdown' if output_format == 'markdown' else 'JSON'}[/cyan]",
                    ),
                ]
            )
        )
        console.print()
        console.print(
            _menu_table(
                [
                    ("G", "Generate", ""),
                    ("0", "Back", ""),
                ]
            )
        )
        console.print()

    while True:
        _topo_submenu()
        choice = Prompt.ask("[bold cyan]>[/bold cyan]", default="").strip().upper()
        if choice == "0":
            return
        elif choice == "1":
            inc_diagram = not inc_diagram
        elif choice == "2":
            inc_summary = not inc_summary
        elif choice == "3":
            output_format = "json" if output_format == "markdown" else "markdown"
        elif choice == "G":
            break

    if not inc_diagram and not inc_summary:
        console.print("[yellow]Nothing selected — enable at least one option.[/yellow]")
        Prompt.ask("\nPress Enter to continue")
        return

    console.print(f"\n[cyan]Connecting SD-WAN for [bold]{tenant.label}[/bold]...[/cyan]")
    try:
        sdk = get_sdwan_client(tenant)
    except Exception as exc:
        console.print(f"[red]SD-WAN auth failed: {exc}[/red]")
        Prompt.ask("\nPress Enter to continue")
        return

    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")

    # ── Topology diagram ──────────────────────────────────────────────────────
    if inc_diagram:
        with console.status("[cyan]Fetching sites and WAN interfaces...[/cyan]"):
            sites = safe_items(sdk.get.sites())
            wan_networks = safe_items(sdk.get.wannetworks())
            wan_ifaces: list[Any] = []
            for site in sites:
                sid = site.get("id")
                if sid:
                    wan_ifaces.extend(safe_items(sdk.get.waninterfaces(site_id=sid)))

        with console.status("[cyan]Building VPN topology...[/cyan]"):
            connections = build_topology(sdk, sites, wan_ifaces, wan_networks)
            diagram = topology_to_mermaid(connections, sites, wan_networks)

        console.print(
            f"  [green]✓[/green] Topology: {len(connections)} VPN connections across {len(sites)} sites"
        )

        diag_out = reports_dir / f"sdwan_topology_{tenant.tenant_id}_{ts}.md"
        diag_out.write_text(
            f"# SD-WAN VPN Topology — {tenant.label}\n\n```mermaid\n{diagram}\n```\n\n"
            f"**{len(connections)} VPN connections** across {len(sites)} sites.\n"
        )
        console.print(f"  [bold green]Diagram saved:[/bold green] {diag_out}")

    # ── Site & element summary ────────────────────────────────────────────────
    if inc_summary:
        with console.status("[cyan]Fetching SD-WAN inventory...[/cyan]"):
            if not inc_diagram:
                sites = safe_items(sdk.get.sites())
                wan_networks = safe_items(sdk.get.wannetworks())
            elements = safe_items(sdk.get.elements())
            hubs: list[Any] = []
            spokes: list[Any] = []
            for _s in sites:
                _sid = _s.get("id")
                if _sid:
                    hubs.extend(safe_items(sdk.get.hubclusters(_sid)))
                    spokes.extend(safe_items(sdk.get.spokeclusters(_sid)))
            net_policies = safe_items(sdk.get.networkpolicysets())
            pri_policies = safe_items(sdk.get.prioritypolicysets())

        console.print(
            f"  [green]✓[/green] Inventory: {len(sites)} sites, {len(elements)} elements, "
            f"{len(wan_networks)} WAN networks, {len(hubs)} hub clusters"
        )

        # Sites table
        console.print()
        t = Table(title="SD-WAN Sites", box=box.SIMPLE_HEAD, border_style="dim")
        t.add_column("Site", style="white")
        t.add_column("Role", style="cyan", width=10)
        t.add_column("Location", style="dim")
        t.add_column("Elements", justify="right")

        elem_by_site: dict[str, int] = {}
        for e in elements:
            sid = e.get("site_id", "")
            elem_by_site[sid] = elem_by_site.get(sid, 0) + 1

        for s in sorted(sites, key=lambda x: x.get("name", "")):
            role = (s.get("element_cluster_role") or "").replace("_", " ").title()
            city = (s.get("address") or {}).get("city", "") or ""
            country = (s.get("address") or {}).get("country", "") or ""
            location = f"{city}, {country}".strip(", ") or "—"
            t.add_row(s.get("name", "—"), role, location, str(elem_by_site.get(s.get("id", ""), 0)))
        console.print(t)

        if output_format == "json":
            import json as _json

            summary_data = {
                "tenant_id": tenant.tenant_id,
                "label": tenant.label,
                "timestamp": ts,
                "summary": {
                    "sites": len(sites),
                    "elements": len(elements),
                    "wan_networks": len(wan_networks),
                    "hub_clusters": len(hubs),
                    "spoke_clusters": len(spokes),
                    "network_policies": len(net_policies),
                    "priority_policies": len(pri_policies),
                },
                "sites": [
                    {
                        "id": s.get("id"),
                        "name": s.get("name"),
                        "role": s.get("element_cluster_role"),
                        "address": s.get("address", {}),
                    }
                    for s in sites
                ],
                "wan_networks": [
                    {"id": n.get("id"), "name": n.get("name"), "type": n.get("type")}
                    for n in wan_networks
                ],
            }
            sum_out = reports_dir / f"sdwan_summary_{tenant.tenant_id}_{ts}.json"
            sum_out.write_text(_json.dumps(summary_data, indent=2))
        else:
            lines = [
                f"# SD-WAN Summary — {tenant.label}\n",
                f"**Sites:** {len(sites)}  |  **Elements:** {len(elements)}  |  "
                f"**WAN Networks:** {len(wan_networks)}  |  **Hub Clusters:** {len(hubs)}\n",
                "\n## Sites\n",
                "| Site | Role | Location | Elements |",
                "|---|---|---|---|",
            ]
            for s in sorted(sites, key=lambda x: x.get("name", "")):
                role = (s.get("element_cluster_role") or "").replace("_", " ").title()
                city = (s.get("address") or {}).get("city", "") or ""
                country = (s.get("address") or {}).get("country", "") or ""
                location = f"{city}, {country}".strip(", ") or "—"
                lines.append(
                    f"| {s.get('name', '—')} | {role} | {location} | {elem_by_site.get(s.get('id', ''), 0)} |"
                )
            sum_out = reports_dir / f"sdwan_summary_{tenant.tenant_id}_{ts}.md"
            sum_out.write_text("\n".join(lines) + "\n")

        console.print(f"  [bold green]Summary saved:[/bold green] {sum_out}")

    Prompt.ask("\nPress Enter to continue")


@audited("audit_report")
def _op_audit_report(tenant: TenantConfig) -> None:
    from .cli_ops import run_audit_report

    # Format picker
    console.print()
    console.print(
        _menu_table(
            [
                ("1", "Markdown", "Human-readable .md report"),
                ("2", "JSON", "Machine-readable structured output"),
            ]
        )
    )
    fmt_choice = Prompt.ask("Format", default="1").strip()
    output_format = "json" if fmt_choice == "2" else "markdown"

    console.print(f"\n[cyan]Connecting to [bold]{tenant.label}[/bold]...[/cyan]")
    try:
        with console.status("[cyan]Building report...[/cyan]"):
            result = run_audit_report(tenant, output_format)
    except Exception as exc:
        console.print(f"[red]Error: {_exc_str(exc)}[/red]")
        Prompt.ask("\nPress Enter to continue")
        return

    counts = result.counts
    summary = (
        f"[bold]Checks:[/bold] {sum(counts.values())}  "
        f"[green]Pass: {counts.get('pass', 0)}[/green]  "
        f"[red]Fail: {counts.get('fail', 0)}[/red]  "
        f"[yellow]Warn: {counts.get('warn', 0)}[/yellow]"
    )
    console.print(Panel(summary, title="Audit Summary", box=box.ROUNDED, border_style="cyan"))

    console.print(
        f"\n  [bold green]Report saved:[/bold green] {result.path}  ({result.size_kb} KB)"
    )
    Prompt.ask("\nPress Enter to continue")


@audited("config_diff")
def _op_config_diff(tenant: TenantConfig) -> None:
    backup_dir = Path("backups")
    backups = sorted(backup_dir.glob(f"scm_backup_{tenant.tenant_id}_*.json"), reverse=True)

    if len(backups) < 2:
        console.print(
            f"\n[yellow]Need at least 2 backups for this tenant — found {len(backups)}.[/yellow]"
        )
        console.print("[dim]Run option [1] Backup Config to create snapshots first.[/dim]")
        Prompt.ask("\nPress Enter to continue")
        return

    console.print()
    t = Table(title="Available Backups", box=box.SIMPLE_HEAD, border_style="dim")
    t.add_column("#", style="dim", width=4)
    t.add_column("File", style="cyan")
    t.add_column("Timestamp", style="white")
    t.add_column("Size", justify="right", style="dim")
    for i, f in enumerate(backups, 1):
        ts_part = f.stem.split("_")[-1]
        size_kb = f.stat().st_size // 1024
        t.add_row(str(i), f.name, ts_part, f"{size_kb} KB")
    console.print(t)
    console.print()

    raw_a = Prompt.ask("Baseline (older) — enter #", default="2")
    raw_b = Prompt.ask("Comparison (newer) — enter #", default="1")

    try:
        file_a = backups[int(raw_a) - 1]
        file_b = backups[int(raw_b) - 1]
    except (ValueError, IndexError):
        console.print("[red]Invalid selection.[/red]")
        Prompt.ask("\nPress Enter to continue")
        return

    with console.status("[cyan]Loading backups...[/cyan]"):
        data_a = json.loads(file_a.read_text())
        data_b = json.loads(file_b.read_text())

    def _extract_resources(data: dict[str, Any]) -> dict[str, list[Any]]:
        """Support both new ('resources') and old ('data') backup formats."""
        if "resources" in data:
            return {k: v for k, v in data["resources"].items() if isinstance(v, list)}
        legacy = data.get("data", {})
        return {k: v for k, v in legacy.items() if isinstance(v, list)}

    with console.status("[cyan]Computing diff...[/cyan]"):
        res_a: dict[str, dict[str, Any]] = {}
        res_b: dict[str, dict[str, Any]] = {}
        for rtype, items in _extract_resources(data_a).items():
            res_a[rtype] = {i.get("name", i.get("id", str(idx))): i for idx, i in enumerate(items)}
        for rtype, items in _extract_resources(data_b).items():
            res_b[rtype] = {i.get("name", i.get("id", str(idx))): i for idx, i in enumerate(items)}

        changes: dict[str, dict[str, list[str]]] = {}
        total_added = total_removed = total_changed = 0
        for rtype in sorted(set(res_a) | set(res_b)):
            a_names = set(res_a.get(rtype, {}).keys())
            b_names = set(res_b.get(rtype, {}).keys())
            added = sorted(b_names - a_names)
            removed = sorted(a_names - b_names)
            modified = sorted(n for n in a_names & b_names if res_a[rtype][n] != res_b[rtype][n])
            if added or removed or modified:
                changes[rtype] = {"added": added, "removed": removed, "modified": modified}
                total_added += len(added)
                total_removed += len(removed)
                total_changed += len(modified)

    # Summary panel
    summary = (
        f"[bold]Baseline:[/bold] {file_a.name}  [dim]→[/dim]  [bold]Compare:[/bold] {file_b.name}\n"
        f"[green]+{total_added} added[/green]   "
        f"[red]-{total_removed} removed[/red]   "
        f"[yellow]~{total_changed} modified[/yellow]   "
        f"[dim]{len(changes)} resource type(s) changed[/dim]"
    )
    console.print(Panel(summary, title="Config Diff", box=box.ROUNDED, border_style="cyan"))
    console.print()

    if not changes:
        console.print("[green]  ✓ No differences found — configs are identical.[/green]")
    else:
        status_colours = {"added": "green", "removed": "red", "modified": "yellow"}
        for rtype, buckets in changes.items():
            console.print(f"  [bold]{rtype}[/bold]")
            for bucket, names in buckets.items():
                if names:
                    colour = status_colours[bucket]
                    prefix = {"added": "+", "removed": "-", "modified": "~"}[bucket]
                    for name in names:
                        console.print(f"    [{colour}]{prefix}[/{colour}] {name}")

    # Save diff report
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out = reports_dir / f"diff_{tenant.tenant_id}_{ts}.json"
    out.write_text(
        json.dumps(
            {
                "tenant_id": tenant.tenant_id,
                "label": tenant.label,
                "timestamp": ts,
                "baseline": str(file_a),
                "comparison": str(file_b),
                "summary": {
                    "added": total_added,
                    "removed": total_removed,
                    "modified": total_changed,
                    "types_changed": len(changes),
                },
                "changes": changes,
            },
            indent=2,
        )
    )
    console.print(f"\n  [bold green]Diff saved:[/bold green] {out}")
    Prompt.ask("\nPress Enter to continue")


def _op_check_updates() -> None:
    """Check PyPI and GitHub for SDK / pan.dev API updates."""
    import json as _json
    import urllib.request
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _v

    PACKAGES = [
        ("pan-scm-sdk", "pan-scm-sdk"),
        ("prisma-sase", "prisma-sase"),
        ("mcp", "mcp"),
        ("scm-harbourmaster-mcp", "scm-harbourmaster-mcp"),
    ]
    UA = "scm-harbourmaster-mcp/updatecheck"

    def _pypi(pkg: str) -> str | None:
        try:
            req = urllib.request.Request(
                f"https://pypi.org/pypi/{pkg}/json",
                headers={"User-Agent": UA, "Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=8) as r:  # noqa: S310  # nosec B310: fixed https URL
                return _json.loads(r.read())["info"]["version"]
        except Exception:
            return None

    def _inst(pkg: str) -> str:
        try:
            return _v(pkg)
        except PackageNotFoundError:
            return "—"

    def _semver(v: str) -> tuple[int, ...]:
        try:
            return tuple(int(x) for x in v.split(".")[:3])
        except Exception:
            return (0, 0, 0)

    def _gh_json(url: str) -> Any:
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": UA, "Accept": "application/vnd.github.v3+json"},
            )
            with urllib.request.urlopen(req, timeout=8) as r:  # noqa: S310  # nosec B310: fixed https URL
                return _json.loads(r.read())
        except Exception:
            return None

    console.print()

    # Package version table
    with console.status("[cyan]Checking PyPI versions...[/cyan]"):
        rows = []
        any_update = False
        for dist, _ in PACKAGES:
            inst = _inst(dist)
            latest = _pypi(dist) or "?"
            if latest == "?" or inst == "—":
                flag = "⚪"
                style = "dim"
            elif _semver(latest) > _semver(inst):
                flag = "🟡 UPDATE"
                style = "yellow"
                any_update = True
            else:
                flag = "🟢 OK"
                style = "green"
            rows.append((dist, inst, latest, flag, style))

    t = Table(title="Package Versions", box=box.ROUNDED, border_style="cyan")
    t.add_column("Package", style="white")
    t.add_column("Installed", style="cyan", justify="right")
    t.add_column("Latest (PyPI)", style="white", justify="right")
    t.add_column("Status", justify="center")
    for dist, inst, latest, flag, style in rows:
        t.add_row(dist, inst, latest, f"[{style}]{flag}[/{style}]")
    console.print(t)

    if any_update:
        console.print(
            "\n[yellow]Updates available — run [bold]uv sync[/bold] then "
            "[bold]uv run scm-mcp[/bold] to apply.[/yellow]"
        )

    # pan-scm-sdk GitHub release notes
    console.print()
    with console.status("[cyan]Fetching pan-scm-sdk release notes...[/cyan]"):
        release = _gh_json("https://api.github.com/repos/cdot65/pan-scm-sdk/releases/latest")

    if release:
        tag = release.get("tag_name", "?")
        pub = (release.get("published_at") or "")[:10]
        body = (release.get("body") or "").strip()
        console.print(
            Panel(
                f"[bold cyan]{tag}[/bold cyan]  [dim]{pub}[/dim]\n\n"
                + (body[:800] + ("\n[dim]...[/dim]" if len(body) > 800 else "")),
                title="pan-scm-sdk Latest Release",
                box=box.ROUNDED,
                border_style="cyan",
            )
        )
    else:
        console.print("[dim]pan-scm-sdk release info unavailable (GitHub rate-limited?).[/dim]")

    # pan.dev recent SCM API changes
    console.print()
    with console.status("[cyan]Fetching pan.dev SCM API changes...[/cyan]"):
        commits = _gh_json(
            "https://api.github.com/repos/PaloAltoNetworks/pan.dev"
            "/commits?path=openapi-specs/scm&per_page=8"
        )

    if commits and isinstance(commits, list):
        ct = Table(title="Recent pan.dev SCM API Changes", box=box.SIMPLE_HEAD, border_style="dim")
        ct.add_column("Date", style="dim", width=11)
        ct.add_column("Author", style="cyan", width=22)
        ct.add_column("Message", style="white")
        for c in commits:
            cmeta = c.get("commit", {})
            date = (cmeta.get("author", {}).get("date") or "")[:10]
            author = (cmeta.get("author", {}).get("name") or "?")[:20]
            msg = (cmeta.get("message") or "").split("\n")[0][:80]
            ct.add_row(date, author, msg)
        console.print(ct)
    else:
        console.print("[dim]pan.dev commit history unavailable.[/dim]")

    Prompt.ask("\nPress Enter to continue")


@audited("restart_server")
def _op_restart_server() -> None:
    """Find and restart the running scm-mcp or scm-mcp-http process."""
    import os
    import signal
    import subprocess

    from rich.prompt import Confirm

    console.print()

    def _find_pids(name: str) -> list[int]:
        try:
            r = subprocess.run(
                ["pgrep", "-f", name],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return [int(p) for p in r.stdout.strip().split() if p.strip().isdigit()]
        except Exception:
            return []

    own_pid = os.getpid()
    stdio_pids = [p for p in _find_pids("scm-mcp") if p != own_pid]
    # Remove http pids from stdio list to avoid double-counting
    http_pids = [p for p in _find_pids("scm-mcp-http") if p != own_pid]
    # scm-mcp-http processes also match "scm-mcp" so deduplicate
    stdio_only = [p for p in stdio_pids if p not in http_pids]

    all_pids = sorted(set(stdio_only + http_pids))

    if not all_pids:
        console.print("[yellow]No running scm-mcp or scm-mcp-http process found.[/yellow]")
        console.print()
        if Confirm.ask("Start scm-mcp (stdio) in the background?", default=False):
            try:
                proc = subprocess.Popen(
                    ["uv", "run", "scm-mcp"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                console.print(f"[green]✓ Started scm-mcp (PID {proc.pid})[/green]")
            except Exception as exc:
                console.print(f"[red]Failed to start: {exc}[/red]")
        Prompt.ask("\nPress Enter to continue")
        return

    # Show what we found
    pt = Table(box=box.SIMPLE_HEAD, show_header=False, padding=(0, 2))
    pt.add_column(style="dim", width=8)
    pt.add_column(style="cyan")
    for pid in all_pids:
        kind = "http" if pid in http_pids else "stdio"
        pt.add_row(str(pid), f"scm-mcp-{kind}")
    console.print(Panel(pt, title=f"{len(all_pids)} running process(es)", box=box.ROUNDED))
    console.print()

    if not Confirm.ask("Send SIGTERM to all and restart?", default=True):
        Prompt.ask("\nPress Enter to continue")
        return

    # Terminate
    killed = []
    for pid in all_pids:
        try:
            os.kill(pid, signal.SIGTERM)
            killed.append(pid)
        except ProcessLookupError:
            pass
        except Exception as exc:
            console.print(f"[yellow]Could not signal PID {pid}: {exc}[/yellow]")

    if killed:
        console.print(
            f"[green]✓ Sent SIGTERM to PID(s): {', '.join(str(p) for p in killed)}[/green]"
        )

    # Brief wait then restart stdio server
    import time as _time

    _time.sleep(1)

    # Restart the appropriate server type
    restart_http = bool(http_pids)
    cmd = ["uv", "run", "scm-mcp-http" if restart_http else "scm-mcp"]
    label = "scm-mcp-http" if restart_http else "scm-mcp"

    if Confirm.ask(f"Start [bold]{label}[/bold] in the background?", default=True):
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            console.print(f"[bold green]✓ Restarted {label} (PID {proc.pid})[/bold green]")
            console.print(
                "[dim]Claude Desktop will reconnect automatically within ~10 seconds.[/dim]"
            )
        except Exception as exc:
            console.print(f"[red]Failed to restart: {exc}[/red]")
            console.print(f"[dim]Run manually: {' '.join(cmd)}[/dim]")

    Prompt.ask("\nPress Enter to continue")


def _op_history() -> None:
    """Render the CLI action history — backups, reports, tenant changes."""
    console.print()
    entries = read_history(50)
    if not entries:
        console.print("[yellow]No history yet.[/yellow]")
        Prompt.ask("\nPress Enter to continue")
        return

    t = Table(box=box.SIMPLE_HEAD, border_style="dim", show_lines=False)
    t.add_column("Time (UTC)", style="dim", width=20)
    t.add_column("Source", width=6)
    t.add_column("Tenant", style="white")
    t.add_column("Action", style="cyan")
    t.add_column("Status", width=8)
    t.add_column("Detail", style="dim")

    status_styles = {"ok": "[green]OK[/green]", "error": "[red]ERROR[/red]"}
    for e in entries:
        ts = str(e.get("ts", ""))[:19].replace("T", " ")
        t.add_row(
            ts,
            str(e.get("source", "")),
            str(e.get("tenant_label") or "—"),
            str(e.get("action", "")),
            status_styles.get(e.get("status", ""), str(e.get("status", ""))),
            str(e.get("detail", ""))[:60],
        )
    console.print(t)
    console.print(f"[dim]{len(entries)} entr{'y' if len(entries) == 1 else 'ies'}[/dim]")
    Prompt.ask("\nPress Enter to continue")


@audited("dspt")
def _op_dspt(tenant: TenantConfig) -> None:
    import json as _json

    from .audit.bpa_checks import run_all_checks
    from .audit.dspt_controls import BPA_TO_DSPT, DSPT_ASSERTIONS
    from .audit.extractor import extract_snapshot
    from .auth.oauth import get_scm_client

    # Standard filter picker
    console.print()
    console.print(
        _menu_table(
            [
                ("1", "All standards", "Standards 7, 8, 9 and 10"),
                ("2", "Standard 9 only", "IT Protection — firewall, malware, auth, logging"),
                ("3", "Standards 7 & 8", "Continuity Planning + Unsupported Systems"),
                ("4", "Standard 10", "Accountable Suppliers (MSSP DPAs)"),
            ]
        )
    )
    std_choice = Prompt.ask("Standard filter", default="1").strip()
    std_map = {"1": "all", "2": "9", "3": "7", "4": "10"}
    std_filter = std_map.get(std_choice, "all")
    std_label = {
        "all": "All Standards (7–10)",
        "9": "Standard 9: IT Protection",
        "7": "Standards 7 & 8",
        "10": "Standard 10",
    }.get(std_filter, "All Standards")

    console.print(f"\n[cyan]Connecting to [bold]{tenant.label}[/bold]...[/cyan]")
    try:
        client = get_scm_client(tenant)
    except Exception as exc:
        console.print(f"[red]Auth failed: {exc}[/red]")
        Prompt.ask("\nPress Enter to continue")
        return

    folder = tenant.default_folder or "All"
    with console.status(f"[cyan]Extracting config from [bold]{folder}[/bold]...[/cyan]"):
        snap = extract_snapshot(client, folder, tenant.tenant_id)

    with console.status("[cyan]Running BPA + DSPT mapping...[/cyan]"):
        findings = run_all_checks(snap)

        assertion_findings: dict[str, list[dict[str, Any]]] = {k: [] for k in DSPT_ASSERTIONS}
        for f in findings:
            for aid in BPA_TO_DSPT.get(f.check_id, []):
                if aid in assertion_findings:
                    assertion_findings[aid].append(f.to_dict())

        assessed: list[dict[str, Any]] = []
        for aid, assertion in DSPT_ASSERTIONS.items():
            if (
                std_filter != "all"
                and str(assertion.standard_number) != std_filter
                and not (std_filter == "7" and assertion.standard_number == 8)
            ):
                continue
            related = assertion_findings[aid]
            has_fail = any(f["status"] in ("fail", "warn") for f in related)
            has_pass = any(f["status"] == "pass" for f in related)
            compliance = (
                "non-compliant" if has_fail else ("compliant" if has_pass else "not-assessed")
            )
            assessed.append(
                {
                    "assertion_id": aid,
                    "assertion_ref": assertion.assertion_ref,
                    "title": assertion.title,
                    "standard": assertion.standard,
                    "standard_number": assertion.standard_number,
                    "dspt_level": assertion.dspt_level,
                    "compliance_status": compliance,
                }
            )

    compliant = sum(1 for a in assessed if a["compliance_status"] == "compliant")
    non_compliant = sum(1 for a in assessed if a["compliance_status"] == "non-compliant")
    not_assessed = sum(1 for a in assessed if a["compliance_status"] == "not-assessed")
    total = len(assessed)

    if non_compliant == 0 and compliant > 0:
        level = "[bold green]Meeting Standards[/bold green]"
    elif non_compliant <= 2:
        level = "[bold yellow]Approaching Standards[/bold yellow]"
    else:
        level = "[bold red]Not Meeting Standards[/bold red]"

    summary = (
        f"[bold]{std_label}[/bold]  ·  [bold]Total:[/bold] {total}  "
        f"[green]Compliant: {compliant}[/green]  "
        f"[red]Non-compliant: {non_compliant}[/red]  "
        f"[dim]Not assessed: {not_assessed}[/dim]\n"
        f"Overall DSPT level: {level}"
    )
    console.print(
        Panel(summary, title="NHS DSPT 2024-25 Assessment", box=box.ROUNDED, border_style="cyan")
    )
    console.print()

    t = Table(box=box.SIMPLE_HEAD, border_style="dim", show_lines=False)
    t.add_column("Assertion", style="dim", width=13)
    t.add_column("Std", width=5)
    t.add_column("Status", width=15)
    t.add_column("Level", width=12)
    t.add_column("Title", style="white")

    status_styles = {
        "compliant": "[green]COMPLIANT[/green]",
        "non-compliant": "[red]NON-COMPLIANT[/red]",
        "not-assessed": "[dim]NOT ASSESSED[/dim]",
    }
    level_styles = {
        "meeting": "[green]Meeting[/green]",
        "exceeding": "[cyan]Exceeding[/cyan]",
        "approaching": "[yellow]Approaching[/yellow]",
    }
    status_order = {"non-compliant": 0, "compliant": 1, "not-assessed": 2}

    for a in sorted(
        assessed,
        key=lambda x: (x["standard_number"], status_order.get(str(x["compliance_status"]), 9)),
    ):
        t.add_row(
            str(a["assertion_ref"]),
            str(a["standard_number"]),
            status_styles.get(str(a["compliance_status"]), str(a["compliance_status"])),
            level_styles.get(str(a["dspt_level"]), str(a["dspt_level"])),
            str(a["title"]),
        )
    console.print(t)

    backup_dir = Path("backups")
    backup_dir.mkdir(exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out = backup_dir / f"dspt_{tenant.tenant_id}_{ts}.json"
    out.write_text(
        _json.dumps(
            {
                "tenant_id": tenant.tenant_id,
                "label": tenant.label,
                "folder": folder,
                "standard_filter": std_filter,
                "timestamp": ts,
                "summary": {
                    "total": total,
                    "compliant": compliant,
                    "non_compliant": non_compliant,
                    "not_assessed": not_assessed,
                },
                "assertions": assessed,
            },
            indent=2,
        )
    )
    console.print(f"\n  [bold green]Report saved:[/bold green] {out}")
    Prompt.ask("\nPress Enter to continue")


@audited("aiops_bpa")
def _op_aiops_bpa(tenant: TenantConfig) -> None:
    import time

    import requests as _requests

    from .auth.oauth import get_scm_client

    _AIOPS_BPA_BASE = "https://api.stratacloud.paloaltonetworks.com/aiops/bpa/v1"

    console.print(
        Panel(
            "Submits a PAN-OS device running config XML to the AIOps BPA API.\n"
            "[dim]The API validates requester_email against PANW CSP — use a registered human email.[/dim]",
            title="AIOps BPA Assessment",
            box=box.ROUNDED,
            border_style="cyan",
        )
    )

    xml_path = Prompt.ask("\nPath to PAN-OS config XML file").strip()
    if not xml_path:
        console.print("[red]No file path provided.[/red]")
        Prompt.ask("\nPress Enter to continue")
        return

    xml_file = Path(xml_path)
    if not xml_file.exists():
        console.print(f"[red]File not found: {xml_file}[/red]")
        Prompt.ask("\nPress Enter to continue")
        return

    requester_email = Prompt.ask("Requester email (registered PANW CSP account)").strip()
    if not requester_email or "@" not in requester_email:
        console.print("[red]Valid requester email is required.[/red]")
        Prompt.ask("\nPress Enter to continue")
        return

    requester_name = Prompt.ask("Requester name", default=requester_email.split("@")[0]).strip()
    device_serial = Prompt.ask("Device serial", default="UNKNOWN").strip()
    device_family = Prompt.ask("Device family", default="PA-VM").strip()
    device_model = Prompt.ask("Device model", default="PA-VM").strip()
    device_version = Prompt.ask("PAN-OS version", default="10.2.0").strip()

    xml_bytes = xml_file.read_bytes()

    console.print(f"\n[cyan]Connecting to [bold]{tenant.label}[/bold]...[/cyan]")
    try:
        client = get_scm_client(tenant)
        session = getattr(client, "session", None)
        if not session:
            console.print("[red]No HTTP session on SCM client.[/red]")
            Prompt.ask("\nPress Enter to continue")
            return
    except Exception as exc:
        console.print(f"[red]Auth failed: {exc}[/red]")
        Prompt.ask("\nPress Enter to continue")
        return

    request_body = {
        "serial": device_serial,
        "family": device_family,
        "model": device_model,
        "version": device_version,
        "requesterName": requester_name,
        "requesterEmail": requester_email,
    }

    try:
        with console.status("[cyan]Initiating BPA job...[/cyan]"):
            init_resp = session.post(
                f"{_AIOPS_BPA_BASE}/requests", json=request_body, timeout=(10, 30)
            )
            if init_resp.status_code == 400:
                body = init_resp.json() if init_resp.content else {}
                msg = body.get("message", body.get("description", str(body)))
                console.print(f"[red]BPA API rejected request: {msg}[/red]")
                console.print(
                    "[dim]Hint: requester_email must be a registered PANW CSP/AIOps portal user.[/dim]"
                )
                Prompt.ask("\nPress Enter to continue")
                return
            init_resp.raise_for_status()

        init_data = init_resp.json()
        job_id = init_data.get("id") or init_data.get("job_id")
        upload_url = init_data.get("upload-url") or init_data.get("upload_url")

        if not job_id or not upload_url:
            console.print(f"[red]Missing job ID or upload URL: {init_data}[/red]")
            Prompt.ask("\nPress Enter to continue")
            return

        with console.status(f"[cyan]Uploading config XML ({len(xml_bytes):,} bytes)...[/cyan]"):
            up_resp = _requests.put(
                upload_url,
                data=xml_bytes,
                headers={"Content-Type": "text/xml"},
                timeout=(10, 60),
            )
            up_resp.raise_for_status()

        with console.status("[cyan]Waiting for BPA analysis (up to 120s)...[/cyan]"):
            _DONE = {"COMPLETED_WITH_SUCCESS", "COMPLETED_WITH_ERROR", "FAILED", "ERROR"}
            status = "PENDING"
            for _ in range(12):
                time.sleep(10)
                job_resp = session.get(f"{_AIOPS_BPA_BASE}/jobs/{job_id}", timeout=(10, 30))
                job_resp.raise_for_status()
                job_data = job_resp.json()
                status = (
                    job_data.get("status")
                    or job_data.get("state")
                    or job_data.get("job_status")
                    or "UNKNOWN"
                )
                if status in _DONE:
                    break

        if status not in _DONE:
            console.print(
                f"[yellow]Job still {status} after 120s. Check back with job ID: {job_id}[/yellow]"
            )
            Prompt.ask("\nPress Enter to continue")
            return

        if status != "COMPLETED_WITH_SUCCESS":
            console.print(f"[red]Job {status}. The config XML may be invalid.[/red]")
            Prompt.ask("\nPress Enter to continue")
            return

        with console.status("[cyan]Fetching report...[/cyan]"):
            rep_resp = session.get(f"{_AIOPS_BPA_BASE}/reports/{job_id}", timeout=(10, 30))
            rep_resp.raise_for_status()
            rep_data = rep_resp.json()
            dl_url = rep_data.get("download-url") or rep_data.get("download_url")
            if not dl_url:
                console.print(f"[red]No download URL in report response: {rep_data}[/red]")
                Prompt.ask("\nPress Enter to continue")
                return
            dl_resp = _requests.get(dl_url, timeout=(10, 60))
            dl_resp.raise_for_status()
            report = dl_resp.json()

        # Display summary
        score = report.get("score") or report.get("overall_score") or report.get("summary", {})
        overall = (
            score.get("overall") or score.get("score") or score.get("total_score")
            if isinstance(score, dict)
            else score
        ) or "—"
        console.print(
            Panel(
                f"[bold]Overall Score:[/bold] {overall}  |  [bold]Job:[/bold] {job_id}\n"
                f"[dim]Device: {device_serial} ({device_model} PAN-OS {device_version})[/dim]",
                title="AIOps BPA Result",
                box=box.ROUNDED,
                border_style="green",
            )
        )

        # Save report
        backup_dir = Path("backups")
        backup_dir.mkdir(exist_ok=True)
        ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        out = backup_dir / f"aiops_bpa_{device_serial}_{ts}.json"
        out.write_text(json.dumps(report, indent=2, default=str))
        console.print(f"\n  [bold green]Full report saved:[/bold green] {out}")

    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")

    Prompt.ask("\nPress Enter to continue")


@audited("incidents")
def _op_incidents(tenant: TenantConfig) -> None:
    from .auth.oauth import get_scm_client

    _INC_URL = "https://api.strata.paloaltonetworks.com/incidents/v1/search"
    _SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    _SEV_STYLE = {
        "critical": "[bold red]CRITICAL[/bold red]",
        "high": "[red]HIGH[/red]",
        "medium": "[yellow]MEDIUM[/yellow]",
        "low": "[green]LOW[/green]",
    }

    console.print(f"\n[cyan]Connecting to [bold]{tenant.label}[/bold]...[/cyan]")
    try:
        client = get_scm_client(tenant)
        session = getattr(client, "session", None)
        if not session:
            console.print("[red]No HTTP session on SCM client.[/red]")
            Prompt.ask("\nPress Enter to continue")
            return
    except Exception as exc:
        console.print(f"[red]Auth failed: {exc}[/red]")
        Prompt.ask("\nPress Enter to continue")
        return

    try:
        with console.status("[cyan]Fetching incidents...[/cyan]"):
            resp = session.post(_INC_URL, json={}, timeout=(10, 30))
            resp.raise_for_status()
            incidents: list[dict[str, Any]] = resp.json().get("data") or []
    except Exception as exc:
        console.print(f"[red]Error fetching incidents: {exc}[/red]")
        Prompt.ask("\nPress Enter to continue")
        return

    counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for inc in incidents:
        sev = str(inc.get("severity") or "").title()
        if sev in counts:
            counts[sev] += 1

    summary = (
        f"[bold]{tenant.label}[/bold]  ·  "
        f"[bold]Total:[/bold] {len(incidents)}  "
        f"[bold red]Crit: {counts['Critical']}[/bold red]  "
        f"[red]High: {counts['High']}[/red]  "
        f"[yellow]Med: {counts['Medium']}[/yellow]  "
        f"[green]Low: {counts['Low']}[/green]"
    )
    console.print(Panel(summary, title="SCM Incidents", box=box.ROUNDED, border_style="cyan"))
    console.print()

    if not incidents:
        console.print("[green]  ✓ No incidents found. ✅[/green]")
    else:
        t = Table(box=box.SIMPLE_HEAD, border_style="dim", show_lines=False)
        t.add_column("Severity", width=10)
        t.add_column("Raised", width=17)
        t.add_column("Status", width=14)
        t.add_column("Title", style="white")
        t.add_column("Product", style="dim", width=16)

        sorted_incs = sorted(
            incidents,
            key=lambda x: (
                _SEV_ORDER.get(str(x.get("severity") or "").title(), 99),
                str(x.get("raised_time") or ""),
            ),
        )
        for inc in sorted_incs[:50]:
            sev = str(inc.get("severity") or "—").lower()
            raised = str(inc.get("raised_time") or "—")[:16].replace("T", " ")
            status = str(inc.get("status") or "—")
            title = str(inc.get("title") or "—")[:55]
            product = str(inc.get("product") or "—")[:16]
            t.add_row(
                _SEV_STYLE.get(sev, sev.upper()),
                raised,
                status,
                title,
                product,
            )
        console.print(t)
        if len(incidents) > 50:
            console.print(
                f"[dim]  ... {len(incidents) - 50} more. Use scm_incident_search MCP tool for full results.[/dim]"
            )

    Prompt.ask("\nPress Enter to continue")


def _op_not_implemented(name: str) -> None:
    console.print(f"\n[yellow]{name} is available via the MCP server tools.[/yellow]")
    console.print("[dim]Start the server with: uv run scm-mcp[/dim]")
    Prompt.ask("\nPress Enter to continue")


# ── main loop ────────────────────────────────────────────────────────────────


def main() -> None:
    if sys.argv[1:]:
        from .cli_commands import build_parser, dispatch

        args = build_parser().parse_args()
        sys.exit(dispatch(args))

    from .cli_menus import (
        _menu_audit_compliance,
        _menu_config_inventory,
        _menu_config_lifecycle,
        _menu_mssp_ops,
        _menu_posture_noc,
        _menu_remediation,
        _menu_sdwan,
        _menu_sse_dlp,
    )

    tenants = _load_all_tenants()
    active: TenantConfig | None = None

    if not tenants:
        console.print("[red]No tenants configured. Check settings.toml and .secrets.toml.[/red]")
        sys.exit(1)

    while True:
        _print_main_menu(active)
        choice = Prompt.ask("[bold cyan]>[/bold cyan]", default="").strip()

        if choice == "0":
            console.print("\n[cyan]Goodbye.[/cyan]\n")
            break

        elif choice == "1":
            if _require_tenant(active):
                _menu_config_inventory(
                    active,
                    console,
                    _print_banner,
                    _menu_table,
                    _section,
                    _get_cli_client,
                    _list_and_display,
                    _save_json,
                    _pause,
                )

        elif choice == "2":
            if _require_tenant(active):
                _menu_audit_compliance(
                    active,
                    console,
                    _print_banner,
                    _menu_table,
                    _section,
                    _op_backup,
                    _op_config_diff,
                    _op_bpa,
                    _op_ncsc,
                    _op_dspt,
                    _op_audit_report,
                    _op_asbuilt_report,
                    _pause,
                )

        elif choice == "3":
            if _require_tenant(active):
                _menu_sdwan(
                    active,
                    console,
                    _print_banner,
                    _menu_table,
                    _section,
                    _op_sdwan_topology,
                    _pause,
                )

        elif choice == "4":
            if _require_tenant(active):
                _menu_sse_dlp(active, console, _print_banner, _menu_table, _section, _pause)

        elif choice == "5":
            if _require_tenant(active):
                _menu_mssp_ops(active, console, _print_banner, _menu_table, _section, _pause)

        elif choice == "6":
            if _require_tenant(active):
                _menu_posture_noc(
                    active,
                    console,
                    _print_banner,
                    _menu_table,
                    _section,
                    _op_incidents,
                    _pause,
                )

        elif choice == "7":
            if _require_tenant(active):
                _menu_remediation(active, console, _print_banner, _menu_table, _section, _pause)

        elif choice == "8":
            if _require_tenant(active):
                _menu_config_lifecycle(
                    active,
                    console,
                    _print_banner,
                    _menu_table,
                    _section,
                    _op_config_diff,
                    _op_aiops_bpa,
                    _pause,
                )

        elif choice in ("l", "L"):
            _print_banner(active)
            console.rule("[cyan]Tenants[/cyan]")
            _op_list_tenants(tenants)

        elif choice in ("s", "S"):
            _print_banner(active)
            console.rule("[cyan]Select Tenant[/cyan]")
            selected = _op_select_tenant(tenants)
            if selected:
                active = selected
                log_action("select_tenant", selected.tenant_id, selected.label, "ok")
                console.print(f"\n[bold green]Active tenant set to: {active.label}[/bold green]")
                Prompt.ask("\nPress Enter to continue")
            else:
                log_action("select_tenant", None, None, "ok", detail="cancelled")

        elif choice in ("a", "A"):
            _print_banner(active)
            console.rule("[cyan]Add Tenant[/cyan]")
            result = _op_add_tenant()
            if result is not None:
                new_key, new_tc = result
                tenants[new_key] = new_tc
                active = new_tc
                log_action("add_tenant", new_tc.tenant_id, new_tc.label, "ok")
                console.print(f"[bold green]Active tenant switched to: {new_tc.label}[/bold green]")

        elif choice in ("u", "U"):
            _print_banner(active)
            console.rule("[cyan]SDK & API Update Check[/cyan]")
            _op_check_updates()

        elif choice in ("r", "R"):
            _print_banner(active)
            console.rule("[cyan]Restart MCP Server[/cyan]")
            _op_restart_server()

        elif choice in ("h", "H"):
            _print_banner(active)
            console.rule("[cyan]CLI History[/cyan]")
            _op_history()

        else:
            console.print("[red]Invalid option.[/red]")
            Prompt.ask("\nPress Enter to continue")


if __name__ == "__main__":
    main()
