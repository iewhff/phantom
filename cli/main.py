"""
CLI entry point for AI Pentest Framework.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from core.config_manager import Settings, get_settings, validate_and_report
from core.orchestrator import PentestOrchestrator, ScanOptions
from core.auth_manager import AuthManager
from utils.logger import setup_logging, get_logger
from utils.validators import validate_target, ValidationError
from utils.http_client import load_bug_bounty_preset

# Alias for compatibility
load_settings = get_settings

console = Console()
logger = get_logger(__name__)


def async_command(f):
    """Decorator to run async commands."""
    from functools import wraps
    
    @wraps(f)
    def wrapper(*args: Any, **kwargs: Any):
        return asyncio.run(f(*args, **kwargs))
    
    return wrapper


@click.group()
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True),
    help="Path to configuration file",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose output",
)
@click.option(
    "--debug",
    is_flag=True,
    help="Enable debug logging",
)
@click.pass_context
def cli(ctx: click.Context, config: str | None, verbose: bool, debug: bool) -> None:
    """
    AI-Enhanced Penetration Testing Framework
    
    Automated security assessment with AI-powered analysis.
    """
    ctx.ensure_object(dict)
    
    # Setup logging
    log_level = "DEBUG" if debug else "INFO" if verbose else "WARNING"
    setup_logging(level=log_level)
    
    # Load configuration
    config_path = config or "config/settings.yaml"
    try:
        ctx.obj["settings"] = load_settings(config_path)
    except Exception as e:
        console.print(f"[red]Failed to load config: {e}[/red]")
        sys.exit(1)

    # Validate configuration at startup
    settings = ctx.obj["settings"]
    if not validate_and_report(settings, console):
        console.print("[red]Configuration validation failed. Fix errors before proceeding.[/red]")
        sys.exit(1)

    ctx.obj["verbose"] = verbose


@cli.command()
@click.argument("target")
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output directory for reports",
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["pdf", "html", "json", "markdown"]),
    default="pdf",
    help="Report format",
)
@click.option(
    "--scope",
    "-s",
    multiple=True,
    help="Additional targets in scope",
)
@click.option(
    "--subdomains",
    is_flag=True,
    default=False,
    help="Enable subdomain enumeration (default: OFF, requires explicit --subdomains)",
)
@click.option(
    "--no-port-scan",
    is_flag=True,
    help="Skip port scanning",
)
@click.option(
    "--no-ai",
    is_flag=True,
    help="Skip AI analysis",
)
@click.option(
    "--nuclei-templates",
    type=click.Path(exists=True),
    help="Custom Nuclei templates directory",
)
@click.option(
    "--resume",
    type=str,
    help="Resume previous scan by ID",
)
@click.option(
    "--safe-mode",
    type=click.Choice(["passive", "safe", "cautious", "standard", "aggressive"]),
    default="safe",
    help="Safety level (passive=read-only, safe=non-destructive, standard=normal)",
)
@click.option(
    "--bug-bounty-preset",
    "-b",
    type=str,
    help="Load bug bounty preset (e.g., 'twilio') for required headers",
)
@click.option(
    "--skip-auth-check",
    is_flag=True,
    help="Skip authorization check (use with caution)",
)
@click.pass_context
@async_command
async def scan(
    ctx: click.Context,
    target: str,
    output: str | None,
    format: str,
    scope: tuple[str, ...],
    subdomains: bool,
    no_port_scan: bool,
    no_ai: bool,
    nuclei_templates: str | None,
    resume: str | None,
    safe_mode: str,
    bug_bounty_preset: str | None,
    skip_auth_check: bool,
) -> None:
    """
    Run a security scan against TARGET.
    
    TARGET can be a domain, URL, IP address, or CIDR range.
    
    Examples:
    
        pentest scan example.com
        
        pentest scan https://example.com -f html
        
        pentest scan 192.168.1.0/24 --safe-mode passive
    """
    settings: Settings = ctx.obj["settings"]

    # Validate target
    try:
        target = validate_target(target)
    except ValidationError as e:
        console.print(f"[red]Invalid target: {e}[/red]")
        sys.exit(1)

    # =================================================================
    # AUTHORIZATION CHECK - Critical for legal compliance
    # =================================================================
    if not skip_auth_check:
        auth_manager = AuthManager(settings)
        if not auth_manager.is_authorized(target):
            console.print(Panel(
                f"[red bold]⚠️  TARGET NOT AUTHORIZED[/red bold]\n\n"
                f"Target: {target}\n\n"
                f"You must authorize the target before scanning.\n"
                f"This confirms you have permission to test.\n\n"
                f"[yellow]To authorize:[/yellow]\n"
                f"  pentest authorize -t {target}\n\n"
                f"[dim]Or use --skip-auth-check if you know what you're doing[/dim]",
                title="Authorization Required",
                border_style="red",
            ))
            sys.exit(1)
        console.print(f"[green]✓[/green] Target authorized: {target}")
    else:
        console.print(f"[yellow]⚠[/yellow] Authorization check skipped")

    # =================================================================
    # BUG BOUNTY PRESET LOADING
    # =================================================================
    if bug_bounty_preset:
        if load_bug_bounty_preset(bug_bounty_preset):
            console.print(f"[green]✓[/green] Bug bounty preset loaded: {bug_bounty_preset}")
        else:
            console.print(f"[red]Failed to load bug bounty preset: {bug_bounty_preset}[/red]")
            console.print("[yellow]Continuing without preset headers...[/yellow]")

    # =================================================================
    # LEGAL DISCLAIMER FOR BUG BOUNTY MODE
    # =================================================================
    bug_bounty_config = getattr(settings, 'bug_bounty', None)
    if bug_bounty_config and getattr(bug_bounty_config, 'enabled', False):
        disclaimer = getattr(bug_bounty_config, 'disclaimer', None)
        if disclaimer and getattr(disclaimer, 'show_before_scan', False):
            console.print(Panel(
                "[yellow bold]⚠️  BUG BOUNTY MODE ACTIVE[/yellow bold]\n\n"
                "WARNING: This tool is for AUTHORIZED security testing only.\n"
                "• You MUST have written permission to test the target\n"
                "• You MUST respect the program's scope and rules\n"
                "• You are LEGALLY responsible for your actions\n"
                "• Unauthorized access is a CRIME\n\n"
                "[dim]By continuing, you confirm you have authorization.[/dim]",
                title="Legal Disclaimer",
                border_style="yellow",
            ))
            if getattr(disclaimer, 'require_acceptance', False):
                if not click.confirm("Do you accept these terms?", default=False):
                    console.print("[red]Scan aborted - terms not accepted[/red]")
                    sys.exit(1)

    # Print banner
    _print_banner()
    
    safe_mode_display = {
        "passive": "🔒 PASSIVE (read-only)",
        "safe": "🛡️ SAFE (non-destructive)",
        "cautious": "⚠️ CAUTIOUS (limited)",
        "standard": "🔧 STANDARD",
        "aggressive": "⚡ AGGRESSIVE",
    }
    
    console.print(Panel(
        f"[bold cyan]Target:[/bold cyan] {target}\n"
        f"[bold cyan]Format:[/bold cyan] {format}\n"
        f"[bold cyan]AI Analysis:[/bold cyan] {'Disabled' if no_ai else 'Enabled'}\n"
        f"[bold cyan]Safe Mode:[/bold cyan] {safe_mode_display.get(safe_mode, safe_mode)}",
        title="Scan Configuration",
        border_style="blue",
    ))
    
    # Build options
    options = ScanOptions(
        enum_subdomains=subdomains,
        skip_ai=no_ai,
        report_formats=[format],
        aggressive=(safe_mode == "aggressive"),
    )
    
    # Override output directory if specified
    if output:
        settings.reporting.output_dir = output
    
    # Initialize orchestrator
    orchestrator = PentestOrchestrator(settings)
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Running scan...", total=None)
            
            # Run scan
            scan_id = await orchestrator.run_full_scan(target, options)
            
            progress.update(task, completed=True)
        
        console.print()
        console.print(Panel(
            f"[green]Scan completed successfully![/green]\n\n"
            f"Scan ID: {scan_id}",
            title="Success",
            border_style="green",
        ))
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        logger.exception("Scan failed")
        console.print(f"[red]Scan failed: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.argument("scan_id")
@click.pass_context
@async_command
async def status(ctx: click.Context, scan_id: str) -> None:
    """
    Check status of a scan.
    
    SCAN_ID is the unique identifier of the scan.
    """
    from core.state_manager import StateManager
    
    settings: Settings = ctx.obj["settings"]
    state_manager = StateManager(settings)
    
    status_data = await state_manager.get_status(scan_id)
    
    if not status_data:
        console.print(f"[red]Scan not found: {scan_id}[/red]")
        sys.exit(1)
    
    table = Table(title=f"Scan Status: {scan_id}")
    table.add_column("Property", style="cyan")
    table.add_column("Value")
    
    table.add_row("Target", status_data.get("target", "N/A"))
    table.add_row("Status", _format_status(status_data.get("status", "unknown")))
    table.add_row("Phase", status_data.get("current_phase", "N/A"))
    table.add_row("Progress", f"{status_data.get('progress', 0)}%")
    table.add_row("Findings", str(status_data.get("findings_count", 0)))
    table.add_row("Started", status_data.get("started_at", "N/A"))
    
    if status_data.get("completed_at"):
        table.add_row("Completed", status_data["completed_at"])
    
    console.print(table)


@cli.command(name="list-scans")
@click.option(
    "--limit",
    "-n",
    type=int,
    default=10,
    help="Number of scans to show",
)
@click.option(
    "--status",
    type=click.Choice(["all", "running", "completed", "failed"]),
    default="all",
    help="Filter by status",
)
@click.pass_context
@async_command
async def list_scans(ctx: click.Context, limit: int, status: str) -> None:
    """
    List recent scans.
    """
    from core.state_manager import StateManager
    
    settings: Settings = ctx.obj["settings"]
    state_manager = StateManager(settings)
    
    scans = await state_manager.list_scans(limit=limit, status_filter=status)
    
    if not scans:
        console.print("[yellow]No scans found[/yellow]")
        return
    
    table = Table(title="Recent Scans")
    table.add_column("ID", style="cyan")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Findings")
    table.add_column("Date")
    
    for scan in scans:
        table.add_row(
            scan["id"][:8],
            scan.get("target", "N/A")[:30],
            _format_status(scan.get("status", "unknown")),
            str(scan.get("findings_count", 0)),
            scan.get("started_at", "N/A")[:19],
        )
    
    console.print(table)


@cli.command()
@click.pass_context
def config(ctx: click.Context) -> None:
    """
    Show current configuration.
    """
    settings: Settings = ctx.obj["settings"]
    
    table = Table(title="Current Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value")
    
    table.add_row("AI Model", settings.ai.model_name)
    table.add_row("AI Provider", settings.ai.provider)
    table.add_row("Rate Limit", f"{settings.rate_limit.requests_per_second} req/s")
    table.add_row("Request Timeout", f"{settings.timeouts.request_timeout if hasattr(settings, 'timeouts') else 30}s")
    table.add_row("Report Format", settings.reporting.default_format)
    table.add_row("Log Level", settings.logging.level)
    
    console.print(table)


@cli.command()
@click.option(
    "--target",
    "-t",
    required=True,
    help="Target to authorize",
)
@click.option(
    "--scope",
    "-s",
    multiple=True,
    help="Additional scope items",
)
@click.pass_context
def authorize(ctx: click.Context, target: str, scope: tuple[str, ...]) -> None:
    """
    Add target to authorized list.
    
    This confirms you have permission to test the target.
    """
    from core.auth_manager import AuthManager
    
    settings: Settings = ctx.obj["settings"]
    auth_manager = AuthManager(settings)
    
    # Validate target
    try:
        target = validate_target(target)
    except ValidationError as e:
        console.print(f"[red]Invalid target: {e}[/red]")
        sys.exit(1)
    
    # Add authorization
    auth_manager.add_target(target, notes=f"Scope: {', '.join(scope)}" if scope else "")
    
    console.print(f"[green]✅ Authorized: {target}[/green]")
    if scope:
        console.print(f"Scope: {', '.join(scope)}")


@cli.command()
@click.pass_context
@async_command
async def check_tools(ctx: click.Context) -> None:
    """
    Check if required external tools are installed.
    """
    import shutil
    
    tools = {
        "nuclei": "Nuclei vulnerability scanner",
        "nmap": "Network mapper",
        "subfinder": "Subdomain discovery",
        "httpx": "HTTP toolkit",
        "amass": "Attack surface mapping",
    }
    
    table = Table(title="External Tools")
    table.add_column("Tool", style="cyan")
    table.add_column("Description")
    table.add_column("Status")
    
    for tool, description in tools.items():
        found = shutil.which(tool) is not None
        status = "[green]✓ Installed[/green]" if found else "[red]✗ Not found[/red]"
        table.add_row(tool, description, status)
    
    console.print(table)


@cli.command()
def version() -> None:
    """
    Show version information.
    """
    console.print(Panel(
        "[bold]AI-Enhanced Pentesting Framework[/bold]\n"
        "Version: 2.0.0\n"
        "Python: " + sys.version.split()[0],
        title="Version",
        border_style="blue",
    ))


def _print_banner() -> None:
    """Print ASCII banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║     █████╗ ██╗    ██████╗ ███████╗███╗   ██╗████████╗     ║
    ║    ██╔══██╗██║    ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝     ║
    ║    ███████║██║    ██████╔╝█████╗  ██╔██╗ ██║   ██║        ║
    ║    ██╔══██║██║    ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║        ║
    ║    ██║  ██║██║    ██║     ███████╗██║ ╚████║   ██║        ║
    ║    ╚═╝  ╚═╝╚═╝    ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝        ║
    ║                                                           ║
    ║           AI-Enhanced Penetration Testing                 ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="cyan")


def _format_status(status: str) -> str:
    """Format status with color."""
    colors = {
        "running": "[yellow]Running[/yellow]",
        "completed": "[green]Completed[/green]",
        "failed": "[red]Failed[/red]",
        "paused": "[blue]Paused[/blue]",
    }
    return colors.get(status.lower(), status)


def main() -> None:
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
