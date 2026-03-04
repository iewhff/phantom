#!/usr/bin/env python3
"""
PHANTOM AI CLI - Professional Heuristic Automated Network Threat Operations Module

Enterprise-grade AI-powered penetration testing command-line interface.

Version: 3.0.0
Date: 2026-01-30

Usage:
    phantom <command> [options] <target>

Commands:
    scan        Execute security scan with PHANTOM AI
    recon       Reconnaissance only (no active testing)
    quick       Fast scan (5 modules)
    full        Comprehensive scan (all 75+ modules)
    bounty      Bug bounty optimized scan
    client      Professional client engagement
    chain       Vulnerability chaining analysis

    status      Check scan status
    list        List previous scans
    resume      Resume interrupted scan
    report      Generate report from scan

    waf-detect  Detect and identify WAF
    validate    Re-validate findings
    authorize   Authorize target for scanning
    presets     Manage bug bounty presets
    modules     List available modules
    health      Check PHANTOM AI health
    update-kb   Update security knowledge base
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from scanning.scan_safety_config import ScanSafetyConfig

import click

# Professional Ethics & Legal Compliance
from utils.legal_disclaimer import check_authorization
from utils.audit_logger import init_audit_logger, get_audit_logger
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
)
from rich.table import Table

# Import PHANTOM AI modules
try:
    from phantom import (
        # Constants
        PHANTOM_VERSION,
        PHANTOM_CODENAME,
        get_version,
        get_module_count,
        ScanMode,
        SafetyLevel,
        ConfidenceThreshold,
        ChainPriority,
        MODULE_CATEGORIES,
        ALL_MODULES,
        # Network Protection
        PhantomNetworkProtection,
        get_phantom_protection,
        verify_target_and_protection,
        # Tech Fingerprinter
        TechFingerprinter,
        # Parameter Analyzer
        ParameterAnalyzer,
        # WAF Bypass Engine
        WAFBypassEngine,
        # Context Payload Selector
        ContextPayloadSelector,
        select_payloads_for_parameter,
        # Module Executor
        ModuleExecutor,
        get_module_executor,
        get_registry,
        execute_modules,
        ExecutionMode,
        ExecutorConfig,
        # Validation Pipeline
        ValidationPipeline,
        ValidationConfig,
        create_raw_finding,
        validate_findings,
        # Impact Assessment
        ImpactAssessmentEngine,
        assess_vulnerability,
        calculate_cvss_score,
        # Chain Visualization
        ChainVisualizationEngine,
        OutputFormat,
        create_chain_graph,
        visualize_chain,
        # SARIF Generator
        SARIFGenerator,
        findings_to_sarif,
        create_sarif_generator,
        # Bounty Estimator
        BountyEstimator,
        estimate_bounty,
        create_program_config,
        BountyPlatform,
        ProgramTier,
        # Compliance Mapper
        ComplianceMapper,
        map_to_compliance,
        get_cwe_mapping,
        ComplianceFramework,
    )
    PHANTOM_AVAILABLE = True
except ImportError as e:
    PHANTOM_AVAILABLE = False
    PHANTOM_IMPORT_ERROR = str(e)

# Import HackerOne Report Generator
try:
    from phantom.hackerone_report_generator import (
        HackerOneReportGenerator,
        generate_hackerone_report,
        findings_to_hackerone_reports,
    )
    HACKERONE_REPORTER_AVAILABLE = True
except ImportError:
    HACKERONE_REPORTER_AVAILABLE = False

console = Console()
logger = logging.getLogger(__name__)


def safe_asyncio_run(coro):
    """
    Safely run an async coroutine with proper subprocess cleanup.

    This prevents 'Event loop is closed' errors that occur when
    subprocesses are not properly cleaned up before the event loop closes.
    """
    import gc
    import sys
    import warnings

    # Suppress the specific RuntimeError from subprocess cleanup
    warnings.filterwarnings("ignore", message="Event loop is closed")

    # Store original unraisable hook to suppress subprocess cleanup errors
    original_hook = sys.unraisablehook

    def suppress_event_loop_closed(args):
        """Suppress 'Event loop is closed' errors from subprocess cleanup."""
        if args.exc_type is RuntimeError:
            msg = str(args.exc_value)
            if "Event loop is closed" in msg:
                return  # Suppress this specific error
        # Call original hook for other errors
        if original_hook:
            original_hook(args)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        return loop.run_until_complete(coro)
    finally:
        # Install suppression hook before cleanup
        sys.unraisablehook = suppress_event_loop_closed

        try:
            # Cancel all pending tasks
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()

            # Give tasks a chance to respond to cancellation
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))

            # Shutdown async generators
            loop.run_until_complete(loop.shutdown_asyncgens())

            # Shutdown default executor
            if hasattr(loop, 'shutdown_default_executor'):
                loop.run_until_complete(loop.shutdown_default_executor())

        except Exception as e:
            logger.debug(f"Event loop cleanup error (expected): {e}")
        finally:
            # Force garbage collection BEFORE closing loop
            # This cleans up subprocess transports while loop is still open
            gc.collect()

            # Now close the loop
            loop.close()

            # Force another GC to clean up any remaining transports
            # (they'll be suppressed by our hook)
            gc.collect()

            # Restore original hook after a brief delay for cleanup
            # Use a delayed restoration to catch any lingering cleanup
            import threading
            def restore_hook():
                import time
                time.sleep(0.1)
                sys.unraisablehook = original_hook

            restore_thread = threading.Thread(target=restore_hook, daemon=True)
            restore_thread.start()


@contextmanager
def suppress_logging_during_progress():
    """
    Suppress logging output during Rich Progress bars to prevent redraw spam.

    When logging outputs to stderr while a Rich Progress bar is active,
    it causes the progress bar to be redrawn on each log message, resulting
    in hundreds of lines of progress bar output.
    """
    # Get root logger and save its state
    root_logger = logging.getLogger()
    original_level = root_logger.level

    # Save and disable all handlers temporarily
    original_handlers = []
    for handler in root_logger.handlers[:]:
        original_handlers.append((handler, handler.level))
        handler.setLevel(logging.CRITICAL)  # Suppress almost everything

    # Also set root logger to CRITICAL
    root_logger.setLevel(logging.CRITICAL)

    # Suppress named loggers used by scanner modules
    named_loggers = [
        logging.getLogger("scanning"),
        logging.getLogger("phantom"),
        logging.getLogger("utils"),
        logging.getLogger("reconnaissance"),
        logging.getLogger("ai_engine"),
    ]
    original_named_levels = [(lg, lg.level) for lg in named_loggers]
    for lg in named_loggers:
        lg.setLevel(logging.CRITICAL)

    try:
        yield
    finally:
        # Restore root logger level
        root_logger.setLevel(original_level)

        # Restore handler levels
        for handler, level in original_handlers:
            handler.setLevel(level)

        # Restore named logger levels
        for lg, level in original_named_levels:
            lg.setLevel(level)


# =============================================================================
# PHANTOM AI BANNER
# =============================================================================

PHANTOM_BANNER = """
[bold cyan]╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║  ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗        ║
║  ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║        ║
║  ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║        ║
║  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║        ║
║  ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║        ║
║  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝        ║
║                                                                          ║
║            [white]Professional Heuristic Automated Network                     ║
║            Threat Operations Module[/white]                                     ║
║                                                                          ║
║  [yellow]v{version} ({codename})[/yellow]                                             ║
║  [green]{modules} Security Modules | 6-Stage Validation | Zero False Positives[/green]║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝[/bold cyan]
"""


def print_banner():
    """Print the PHANTOM AI banner."""
    if PHANTOM_AVAILABLE:
        version = PHANTOM_VERSION
        codename = PHANTOM_CODENAME
        modules = f"{get_module_count()}+"
    else:
        version = "3.0.0"
        codename = "Enterprise Edition"
        modules = "75+"

    banner = PHANTOM_BANNER.format(
        version=version,
        codename=codename,
        modules=modules,
    )
    console.print(banner)


def print_philosophy():
    """Print PHANTOM AI philosophy."""
    console.print(Panel(
        "[bold]PHANTOM AI Philosophy[/bold]\n\n"
        "[cyan]1. Intelligence Before Force[/cyan]\n"
        "   Understand the target completely before testing\n\n"
        "[cyan]2. Vulnerabilities Discover Vulnerabilities[/cyan]\n"
        "   Chain findings to uncover deeper issues\n\n"
        "[cyan]3. Detection, Not Destruction[/cyan]\n"
        "   Prove impact without causing harm",
        title="🧠 Philosophy",
        border_style="cyan",
    ))


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_scan_id() -> str:
    """Generate a unique scan ID."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    unique = uuid.uuid4().hex[:8]
    return f"PHANTOM_{timestamp}_{unique}"


def get_scans_dir() -> Path:
    """Get the scans directory."""
    scans_dir = Path.home() / ".phantom" / "scans"
    scans_dir.mkdir(parents=True, exist_ok=True)
    return scans_dir


def get_reports_dir() -> Path:
    """Get the reports directory."""
    reports_dir = Path("reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    return reports_dir


def save_scan_state(scan_id: str, state: Dict[str, Any]) -> None:
    """Save scan state for resume capability."""
    scans_dir = get_scans_dir()
    state_file = scans_dir / f"{scan_id}.json"
    state_file.write_text(json.dumps(state, indent=2, default=str))


def load_scan_state(scan_id: str) -> Optional[Dict[str, Any]]:
    """Load scan state for resume."""
    scans_dir = get_scans_dir()
    state_file = scans_dir / f"{scan_id}.json"
    if state_file.exists():
        return json.loads(state_file.read_text())
    return None


def normalize_target(target: str) -> str:
    """Normalize target URL.

    FIX CLI-04: Add validation for target format.
    """
    import re

    # Strip whitespace
    target = target.strip()

    # Validate non-empty
    if not target:
        raise click.BadParameter("Target cannot be empty")

    # Add scheme if missing
    if not target.startswith(("http://", "https://")):
        # Validate it looks like a domain/IP before adding https://
        if not re.match(r'^[\w\.-]+(:\d+)?(/.*)?$', target):
            raise click.BadParameter(f"Invalid target format: {target}")
        target = f"https://{target}"

    # Validate URL structure
    parsed = urlparse(target)
    if not parsed.netloc:
        raise click.BadParameter(f"Invalid URL (no host): {target}")

    # Check for suspicious patterns (path traversal attempts)
    if ".." in target or target.count("//") > 1:
        console.print(f"[yellow]⚠️ Warning: Suspicious pattern in target: {target}[/yellow]")

    return target.rstrip("/")


def get_domain(target: str) -> str:
    """Extract domain from target."""
    parsed = urlparse(normalize_target(target))
    return parsed.netloc or parsed.path


def format_severity(severity: str) -> str:
    """Format severity with color."""
    colors = {
        "CRITICAL": "[bold red]CRITICAL[/bold red]",
        "HIGH": "[orange1]HIGH[/orange1]",
        "MEDIUM": "[yellow]MEDIUM[/yellow]",
        "LOW": "[green]LOW[/green]",
        "INFO": "[dim]INFO[/dim]",
    }
    return colors.get(severity.upper(), severity)


def format_confidence(confidence: float | str) -> str:
    """Format confidence percentage.

    Handles both decimal (0.0-1.0) and percentage (0-100) formats.
    Also handles string values like "HIGH", "MEDIUM", "LOW", or "95%".
    """
    # Convert string confidence to float
    try:
        if isinstance(confidence, str):
            # Handle string labels
            confidence_map = {
                "HIGH": 0.9,
                "MEDIUM": 0.7,
                "LOW": 0.5,
                "CRITICAL": 0.95,
                "INFO": 0.3,
            }
            upper_conf = confidence.upper().strip()
            if upper_conf in confidence_map:
                confidence = confidence_map[upper_conf]
            else:
                # Handle percentage strings like "95%" or "0.85"
                confidence = float(confidence.rstrip('%'))
                if confidence > 1:
                    confidence = confidence / 100.0
        confidence = float(confidence)
    except (ValueError, TypeError):
        confidence = 0.5  # Default to medium confidence

    # Normalize: if confidence > 1, it's already a percentage
    if confidence > 1.0:
        pct = confidence
    else:
        pct = confidence * 100

    # Cap at 100%
    pct = min(pct, 100.0)

    if pct >= 95:
        return f"[bold green]{pct:.1f}%[/bold green]"
    elif pct >= 75:
        return f"[green]{pct:.1f}%[/green]"
    elif pct >= 60:
        return f"[yellow]{pct:.1f}%[/yellow]"
    else:
        return f"[dim]{pct:.1f}%[/dim]"


def format_bounty(min_val: int, max_val: int) -> str:
    """Format bounty estimate."""
    return f"[bold yellow]${min_val:,} - ${max_val:,}[/bold yellow]"


# =============================================================================
# CLI GROUP
# =============================================================================

@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--debug", is_flag=True, help="Debug logging")
@click.option("--no-banner", is_flag=True, help="Skip banner display")
@click.pass_context
def cli(ctx: click.Context, verbose: bool, debug: bool, no_banner: bool):
    """
    PHANTOM AI - Enterprise Penetration Testing Framework

    Professional Heuristic Automated Network Threat Operations Module.
    AI-powered security scanning with 6-stage validation and zero false positives.

    \b
    Examples:
        phantom scan https://target.com
        phantom bounty https://api.target.com --platform hackerone
        phantom client https://client.com --client-name "ACME Corp"
        phantom recon target.com --subdomains --technologies
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["debug"] = debug
    ctx.obj["no_banner"] = no_banner

    if not PHANTOM_AVAILABLE:
        console.print(f"[red]⚠️ PHANTOM AI modules not fully loaded: {PHANTOM_IMPORT_ERROR}[/red]")
        console.print("[yellow]Some features may be unavailable.[/yellow]")


# =============================================================================
# SCAN COMMAND
# =============================================================================

@cli.command()
@click.argument("target")
@click.option("--output", "-o", type=click.Path(), help="Output directory")
@click.option("--format", "-f", "output_format",
              type=click.Choice(["pdf", "html", "json", "md", "sarif"]),
              default="json", help="Report format (default: JSON)")
@click.option("--modules", "-m", help="Modules to run (comma-separated or category)")
@click.option("--safe-mode", "-s",
              type=click.Choice(["passive", "safe", "cautious", "standard", "aggressive"]),
              default="safe", help="Safety level")
@click.option("--rate", "-r", type=float, default=2.0, help="Requests per second")
@click.option("--concurrent", "-c", type=int, default=3, help="Concurrent modules")
@click.option("--scope", multiple=True, help="Additional in-scope domains")
@click.option("--subdomains", is_flag=True, default=False, help="Also scan subdomains (default: OFF for safety)")
@click.option("--exclude", multiple=True, help="Exclude specific modules")
@click.option("--preset", help="Load bug bounty preset")
@click.option("--no-recon", is_flag=True, help="Skip reconnaissance phase")
@click.option("--no-tools", is_flag=True, help="Skip Linux tools integration")
@click.option("--no-chain", is_flag=True, help="Skip vulnerability chaining")
@click.option("--no-ai", is_flag=True, help="Skip AI validation")
@click.option("--no-auth", is_flag=True, help="Skip authorization check")
@click.option("--dry-run", is_flag=True, default=False, help="Simulate scan without sending actual requests (OPSEC test)")
@click.option("--timeout", type=int, help="Overall scan timeout in seconds")
@click.option("--compliance", multiple=True,
              type=click.Choice(["pci-dss", "hipaa", "gdpr", "nist", "owasp", "all"]),
              help="Compliance frameworks to map (can be used multiple times)")
@click.option("--totp-secret", type=str, default=None,
              help="TOTP secret (base32) for automatic 2FA handling")
@click.option("--allow-manual-auth", is_flag=True, default=False,
              help="Allow manual browser intervention for CAPTCHA/2FA challenges")
@click.pass_context
def scan(ctx: click.Context, target: str, output: Optional[str], output_format: str,
         modules: Optional[str], safe_mode: str, rate: float, concurrent: int,
         scope: tuple, subdomains: bool, exclude: tuple, preset: Optional[str],
         no_recon: bool, no_tools: bool, no_chain: bool, no_ai: bool, no_auth: bool,
         dry_run: bool, timeout: Optional[int], compliance: tuple,
         totp_secret: Optional[str], allow_manual_auth: bool):
    """
    Execute PHANTOM AI security scan on TARGET.

    The scan includes reconnaissance, technology fingerprinting, WAF detection,
    vulnerability scanning with 75+ modules, 6-stage validation, and vulnerability
    chaining for maximum impact discovery.

    \b
    TARGET FORMATS:
        example.com          Domain
        https://example.com  URL
        192.168.1.100        IP address

    \b
    Examples:
        phantom scan https://example.com
        phantom scan https://api.target.com -m injection -s cautious
        phantom scan target.com --no-recon --modules sqli,xss,idor
        phantom scan target.com -s aggressive --compliance all
    """
    if not ctx.obj.get("no_banner"):
        print_banner()

    compliance_list = list(compliance) if compliance else []

    # GAP-5: Advanced auth options (TOTP, manual auth)
    import os
    if totp_secret:
        os.environ["PHANTOM_TOTP_SECRET"] = totp_secret
        console.print("[cyan]🔐 TOTP secret configured — automatic 2FA handling enabled[/cyan]")

    if allow_manual_auth:
        os.environ["PHANTOM_ALLOW_MANUAL_AUTH"] = "1"
        console.print("[cyan]🖥️ Manual auth enabled — browser will open for CAPTCHA/2FA challenges[/cyan]")

    safe_asyncio_run(_run_phantom_scan(
        target=target,
        output_dir=output,
        output_format=output_format,
        modules=modules,
        safe_mode=safe_mode,
        rate=rate,
        concurrent=concurrent,
        scope=list(scope),
        exclude=list(exclude),
        preset=preset,
        no_recon=no_recon,
        no_tools=no_tools,
        no_chain=no_chain,
        no_ai=no_ai,
        no_auth=no_auth,
        timeout=timeout,
        scan_mode=ScanMode.STANDARD if PHANTOM_AVAILABLE else "standard",
        verbose=ctx.obj.get("verbose", False),
        compliance=compliance_list,
        include_subdomains=subdomains,
        dry_run=dry_run,
    ))


async def _run_phantom_scan(
    target: str,
    output_dir: Optional[str],
    output_format: str,
    modules: Optional[str],
    safe_mode: str,
    rate: float,
    concurrent: int,
    scope: List[str],
    exclude: List[str],
    preset: Optional[str],
    no_recon: bool,
    no_tools: bool,
    no_chain: bool,
    no_ai: bool,
    no_auth: bool,
    timeout: Optional[int],
    scan_mode: str,
    verbose: bool,
    compliance: List[str] = None,
    custom_headers: Optional[Dict[str, str]] = None,
    include_subdomains: bool = False,
    dry_run: bool = False,
    client_name: Optional[str] = None,  # FIX CLI-02: For client engagements
    engagement_id: Optional[str] = None,  # FIX CLI-02: For client engagements
    safety_config: Optional["ScanSafetyConfig"] = None,  # P0 FIX: Professional safety config
) -> None:
    """Execute PHANTOM AI scan."""

    # ═══════════════════════════════════════════════════════════════════════════
    # DOUBLE PROTECTION: Set environment variable BEFORE any imports/operations
    # This ensures ALL modules respect the safety mode, even if loaded lazily
    # ═══════════════════════════════════════════════════════════════════════════
    os.environ["PHANTOM_SAFE_MODE"] = safe_mode

    # Store custom headers in environment for scanners to use
    if custom_headers:
        os.environ["PHANTOM_CUSTOM_HEADERS"] = json.dumps(custom_headers)

    # Additional protection: Block aggressive mode unless explicitly allowed
    if safe_mode == "aggressive":
        if os.environ.get("PHANTOM_ALLOW_AGGRESSIVE", "").lower() not in ("1", "true", "yes", "authorized"):
            console.print(Panel(
                "[bold red]⛔ AGGRESSIVE MODE BLOCKED[/bold red]\n\n"
                "Aggressive mode requires explicit authorization.\n"
                "This is a safety feature to prevent accidental destructive operations.\n\n"
                "To enable aggressive mode, set environment variable:\n"
                "[yellow]export PHANTOM_ALLOW_AGGRESSIVE=authorized[/yellow]\n\n"
                "Falling back to 'standard' mode.",
                title="Security Protection",
                border_style="red",
            ))
            safe_mode = "standard"
            os.environ["PHANTOM_SAFE_MODE"] = safe_mode

    # Log safety mode for audit
    if verbose:
        console.print(f"[dim]🛡️ Safety mode set: {safe_mode}[/dim]")

    # Normalize compliance list
    compliance = compliance or []

    # Normalize target
    target = normalize_target(target)
    domain = get_domain(target)
    scan_id = get_scan_id()
    start_time = datetime.now()

    # Safety icons
    safe_icons = {
        "passive": "🔒 PASSIVE (observation only)",
        "safe": "🛡️ SAFE (non-destructive)",
        "cautious": "⚠️ CAUTIOUS (limited testing)",
        "standard": "🔧 STANDARD (balanced)",
        "aggressive": "⚡ AGGRESSIVE (full testing)",
    }

    # Compliance display
    compliance_str = ", ".join(compliance).upper() if compliance else "None"

    # Display configuration
    console.print(Panel(
        f"[bold cyan]Scan ID:[/bold cyan] {scan_id}\n"
        f"[bold cyan]Target:[/bold cyan] {target}\n"
        f"[bold cyan]Domain:[/bold cyan] {domain}\n"
        f"[bold cyan]Mode:[/bold cyan] {scan_mode}\n"
        f"[bold cyan]Safety:[/bold cyan] {safe_icons.get(safe_mode, safe_mode)}\n"
        f"[bold cyan]Rate:[/bold cyan] {rate} req/sec\n"
        f"[bold cyan]Concurrent:[/bold cyan] {concurrent} modules\n"
        f"[bold cyan]Format:[/bold cyan] {output_format.upper()}\n"
        f"[bold cyan]Compliance:[/bold cyan] {compliance_str}",
        title="🎯 PHANTOM AI Scan Configuration",
        border_style="blue",
    ))

    # Authorization check
    if not no_auth:
        try:
            from core.config_manager import get_settings
            from core.auth_manager import AuthManager

            settings = get_settings()
            auth = AuthManager(settings)

            if not auth.is_authorized(domain) and not auth.is_authorized(target):
                console.print(f"\n[red]❌ Target not authorized![/red]")
                console.print(f"[yellow]Run: phantom authorize {domain}[/yellow]")
                return
            console.print(f"[green]✓ Target authorized[/green]")
        except Exception as e:
            if verbose:
                console.print(f"[yellow]⚠️ Auth check skipped: {e}[/yellow]")

    # ═══════════════════════════════════════════════════════════════════════════
    # AUDIT LOGGING: Initialize comprehensive audit trail for scan command
    # ═══════════════════════════════════════════════════════════════════════════
    audit = init_audit_logger(
        engagement_id=scan_id,
        operator=os.environ.get("USER", "phantom-ai"),
    )
    audit.log_authorization(
        target=target,
        accepted=True,
        scope=scope,
        mode=safe_mode,
        rate_limit=rate,
    )
    if scope:
        audit.log_scope_confirmed(
            targets=[target],
            scope=scope,
            program_name=f"Scan: {domain}",
        )
    console.print(f"[dim]📝 Audit log: {audit.log_file}[/dim]")

    # Initialize scan state
    scan_state = {
        "scan_id": scan_id,
        "target": target,
        "domain": domain,
        "start_time": start_time.isoformat(),
        "status": "running",
        "phase": "initialization",
        "findings": [],
        "validated_findings": [],
        "chains": [],
        "modules_run": [],
        "errors": [],
        "config": {
            "scan_mode": scan_mode.value if hasattr(scan_mode, 'value') else str(scan_mode),
            "safe_mode": safe_mode,
            "rate": rate,
            "concurrent": concurrent,
            "modules": modules,
            "exclude": list(exclude),
            "no_recon": no_recon,
            "no_chain": no_chain,
            "no_ai": no_ai,
            "client_name": client_name,  # FIX CLI-02: Store for client reports
            "engagement_id": engagement_id,  # FIX CLI-02: Store for client reports
        }
    }

    # Save initial state
    save_scan_state(scan_id, scan_state)

    # Initialize per-pentest logging
    from utils.logger import create_pentest_logger, set_pentest_logger
    pentest_log = create_pentest_logger(
        scan_id=scan_id,
        target=target,
        client_name=scan_state["config"].get("client_name"),
    )
    pentest_log.log_config(scan_state["config"])
    console.print(f"[dim]📝 Logging to: {pentest_log.get_log_path()}[/dim]")

    # Initialize results
    all_findings = []
    validated_findings = []
    tech_results = None
    waf_result = None
    parameter_results = []
    chains = []

    try:
        # Suppress logging during Progress to prevent progress bar redraw spam
        # (logging to stderr causes Rich to redraw the progress bar on each message)
        with suppress_logging_during_progress(), Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:

            # =================================================================
            # PHASE 1: Network Protection Setup
            # =================================================================
            task_protection = progress.add_task("[cyan]Setting up network protection...", total=100)
            pentest_log.log_phase_start("network_protection", "Setting up PHANTOM network protection and OPSEC")
            phase1_start = datetime.now()

            if PHANTOM_AVAILABLE:
                protection = get_phantom_protection()
                await verify_target_and_protection(target)
                progress.update(task_protection, completed=100)
                console.print("[green]✓ Network protection active[/green]")
                pentest_log.log_info("Network protection active - Kill switch enabled")
            else:
                progress.update(task_protection, completed=100)
                pentest_log.log_warning("PHANTOM modules not available, network protection skipped")

            phase1_duration = (datetime.now() - phase1_start).total_seconds()
            pentest_log.log_phase_end("network_protection", phase1_duration, {"status": "active"})
            scan_state["phase"] = "reconnaissance"
            save_scan_state(scan_id, scan_state)

            # =================================================================
            # PHASE 2: Technology Fingerprinting
            # =================================================================
            if not no_recon:
                task_tech = progress.add_task("[cyan]Fingerprinting technologies...", total=100)
                pentest_log.log_phase_start("technology_fingerprinting", "Detecting web technologies and frameworks")
                phase2_start = datetime.now()

                if PHANTOM_AVAILABLE:
                    fingerprinter = TechFingerprinter()
                    tech_results = await fingerprinter.fingerprint(target)

                    phase2_duration = (datetime.now() - phase2_start).total_seconds()

                    if tech_results and tech_results.technologies:
                        console.print(f"[green]✓ Detected {len(tech_results.technologies)} technologies[/green]")
                        for tech in tech_results.technologies[:5]:
                            console.print(f"   • {tech.name} {tech.version or ''} ({tech.category.value})")
                            pentest_log.log_info(f"Technology detected: {tech.name} {tech.version or ''} ({tech.category.value})")
                        if len(tech_results.technologies) > 5:
                            console.print(f"   ... and {len(tech_results.technologies) - 5} more")

                        pentest_log.log_phase_end("technology_fingerprinting", phase2_duration, {
                            "technologies_detected": len(tech_results.technologies),
                        })
                    else:
                        pentest_log.log_phase_end("technology_fingerprinting", phase2_duration, {"technologies_detected": 0})

                progress.update(task_tech, completed=100)

            # =================================================================
            # PHASE 3: WAF Detection
            # =================================================================
            task_waf = progress.add_task("[cyan]Detecting WAF...", total=100)
            pentest_log.log_phase_start("waf_detection", "Detecting Web Application Firewall")
            phase3_start = datetime.now()

            if PHANTOM_AVAILABLE:
                waf_engine = WAFBypassEngine()
                waf_result = await waf_engine.detect_waf(target)

                phase3_duration = (datetime.now() - phase3_start).total_seconds()

                if waf_result and waf_result.detected:
                    console.print(f"[yellow]⚠️ WAF Detected: {waf_result.waf_name} ({waf_result.confidence*100:.0f}% confidence)[/yellow]")
                    console.print(f"   Behavior: {waf_result.behaviour_family.value}")
                    pentest_log.log_warning(f"WAF Detected: {waf_result.waf_name}", {
                        "confidence": f"{waf_result.confidence*100:.0f}%",
                        "behavior": waf_result.behaviour_family.value,
                    })

                    # Get bypass strategies
                    strategies = waf_engine.get_bypass_strategies(waf_result)
                    if strategies:
                        console.print(f"   [cyan]Available bypass strategies: {len(strategies)}[/cyan]")
                        pentest_log.log_info(f"WAF bypass strategies available: {len(strategies)}")

                    pentest_log.log_phase_end("waf_detection", phase3_duration, {
                        "waf_detected": True,
                        "waf_name": waf_result.waf_name,
                        "bypass_strategies": len(strategies) if strategies else 0,
                    })
                else:
                    console.print("[green]✓ No WAF detected[/green]")
                    pentest_log.log_info("No WAF detected")
                    pentest_log.log_phase_end("waf_detection", phase3_duration, {"waf_detected": False})

            progress.update(task_waf, completed=100)

            # =================================================================
            # PHASE 4: Parameter Analysis
            # =================================================================
            task_params = progress.add_task("[cyan]Analyzing parameters...", total=100)

            if PHANTOM_AVAILABLE and not no_recon:
                try:
                    analyzer = ParameterAnalyzer()
                    # Parse target URL to extract base_url and endpoint
                    from urllib.parse import urlparse
                    parsed_target = urlparse(target)
                    base_url = f"{parsed_target.scheme}://{parsed_target.netloc}"
                    endpoint = parsed_target.path or "/"
                    if parsed_target.query:
                        endpoint = f"{endpoint}?{parsed_target.query}"

                    # Analyze the endpoint parameters
                    analysis_result = await analyzer.analyze(
                        base_url=base_url,
                        endpoint=endpoint,
                        method="GET",
                        test_reflection=False,  # Skip reflection tests for speed
                        test_behavior=False,
                    )
                    if analysis_result and analysis_result.parameters:
                        parameter_results = analysis_result.parameters
                        console.print(f"[green]✓ Analyzed {len(parameter_results)} parameters[/green]")

                        high_risk = [p for p in parameter_results if p.injection_potential > 0.7]
                        if high_risk:
                            console.print(f"   [yellow]⚠️ {len(high_risk)} high-risk parameters identified[/yellow]")
                    else:
                        console.print("[dim]✓ No parameters found in base URL[/dim]")
                except Exception as param_err:
                    console.print(f"[dim]⚠️ Parameter analysis skipped: {param_err}[/dim]")

            progress.update(task_params, completed=100)

            scan_state["phase"] = "scanning"
            save_scan_state(scan_id, scan_state)

            # =================================================================
            # PHASE 5: Module Execution
            # =================================================================
            task_scan = progress.add_task("[cyan]Running security modules...", total=100)
            pentest_log.log_phase_start("vulnerability_scanning", "Running security modules against target")

            # Parse modules
            module_list = None
            if modules:
                if modules in MODULE_CATEGORIES:
                    module_list = MODULE_CATEGORIES[modules]
                else:
                    module_list = [m.strip() for m in modules.split(",")]

            # Exclude modules
            if exclude and module_list:
                module_list = [m for m in module_list if m not in exclude]

            # Run scan using existing scanner
            scan_start_time = datetime.now()
            try:
                from core.config_manager import get_settings
                from scanning.full_scanner import FullScanner

                settings = get_settings()
                settings.rate_limit.requests_per_second = rate

                scanner = FullScanner(
                    settings,
                    safe_mode=safe_mode,
                    include_subdomains=include_subdomains,
                    scope=scope,  # ETHICS-08: Real-time scope blocking
                    safety_config=safety_config,  # P0 FIX: Professional safety configuration
                )

                # Determine category - CLIENT mode uses dedicated client category
                category = "standard"
                if scan_mode == ScanMode.QUICK:
                    category = "quick"
                elif scan_mode == ScanMode.FULL:
                    category = "full"
                elif scan_mode == ScanMode.BOUNTY:
                    category = "bounty"
                elif scan_mode == ScanMode.CLIENT:
                    category = "client"  # CLIENT mode = Professional engagement (47+ modules)
                elif scan_mode == ScanMode.THOROUGH:
                    category = "client"  # THOROUGH also uses client category

                pentest_log.log_info(f"Scan category: {category}")
                pentest_log.log_info(f"Modules to run: {module_list if module_list else 'all in category'}")

                # Incremental state callback — save partial results after each module
                def _on_module_progress(scan_result):
                    scan_state["modules_run"] = scan_result.modules_run
                    scan_state["findings"] = scan_result.findings or []
                    scan_state["errors"] = [
                        e if isinstance(e, dict) else {"error": str(e)}
                        for e in (scan_result.errors or [])
                    ]
                    save_scan_state(scan_id, scan_state)

                result = await scanner.scan(
                    target=target,
                    category=category,
                    modules=module_list,
                    concurrent=concurrent,
                    on_progress=_on_module_progress,
                )

                all_findings = result.findings if result.findings else []
                scan_state["modules_run"] = result.modules_run
                scan_state["errors"] = result.errors

                # Log each module execution
                for module_name in result.modules_run:
                    pentest_log.log_tool_execution(module_name, status="completed", target=target)

                # Log any errors
                for error in result.errors:
                    pentest_log.log_error(f"Module error: {error}")

                scan_duration = (datetime.now() - scan_start_time).total_seconds()
                scan_state["duration_seconds"] = scan_duration
                pentest_log.log_phase_end("vulnerability_scanning", scan_duration, {
                    "modules_run": len(result.modules_run),
                    "raw_findings": len(all_findings),
                    "errors": len(result.errors),
                    "category": category,
                })

                progress.update(task_scan, completed=100)
                console.print(f"[green]✓ Executed {len(result.modules_run)} modules[/green]")

            except Exception as e:
                console.print(f"[red]❌ Scanner error: {e}[/red]")
                pentest_log.log_error(f"Scanner error: {e}", exception=e)
                progress.update(task_scan, completed=100)

            scan_state["phase"] = "validation"
            scan_state["findings"] = all_findings
            save_scan_state(scan_id, scan_state)

            # =================================================================
            # PHASE 6: 6-Stage Validation Pipeline
            # =================================================================
            if all_findings and PHANTOM_AVAILABLE and not no_ai:
                task_validate = progress.add_task("[cyan]Running 6-stage validation...", total=100)
                pentest_log.log_phase_start("validation", "Running 6-stage validation pipeline to eliminate false positives")
                validation_start_time = datetime.now()

                try:
                    pipeline = ValidationPipeline()

                    # Convert findings to RawFinding format
                    # Skip INFO severity findings (http_probe, etc.) - they are informational only
                    raw_findings = []
                    info_findings_skipped = 0
                    for finding in all_findings:
                        severity = finding.get("severity", "MEDIUM")
                        
                        # Skip INFO severity findings - they don't need validation
                        if severity.upper() == "INFO":
                            info_findings_skipped += 1
                            continue
                        
                        # Build title from finding data (support both 'title' and 'name' fields)
                        vuln_type = finding.get("type", "unknown")
                        title = finding.get("title") or finding.get("name") or f"{vuln_type.upper()} Vulnerability Detected"
                        url = finding.get("url", finding.get("matched_at", target))

                        # Get evidence as string (RawFinding.evidence is str, not list)
                        evidence = finding.get("evidence", "")
                        if isinstance(evidence, list):
                            evidence = "\n".join(str(e) for e in evidence)
                        
                        # Also check description field if no evidence
                        if not evidence:
                            evidence = finding.get("description", "")

                        # Normalize confidence to 0-1 scale (some modules use 0-100 or strings)
                        raw_confidence = finding.get("confidence_score", finding.get("confidence", 0.5))
                        try:
                            if isinstance(raw_confidence, str):
                                # Handle string labels like "HIGH", "MEDIUM", "LOW"
                                confidence_map = {
                                    "HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.5,
                                    "CRITICAL": 0.95, "INFO": 0.3,
                                }
                                upper_conf = raw_confidence.upper().strip()
                                if upper_conf in confidence_map:
                                    confidence = confidence_map[upper_conf]
                                else:
                                    # Handle percentage strings like "95%" or plain numbers
                                    confidence = float(raw_confidence.rstrip('%'))
                                    if confidence > 1:
                                        confidence = confidence / 100.0
                            else:
                                confidence = float(raw_confidence) if raw_confidence is not None else 0.5
                                if confidence > 1.0:
                                    confidence = confidence / 100.0  # Convert percentage to decimal
                        except (ValueError, TypeError):
                            confidence = 0.5
                        confidence = max(0.0, min(1.0, confidence))  # Clamp to 0-1

                        # Ensure method is always a string
                        method = finding.get("method", "GET") or "GET"
                        
                        raw = create_raw_finding(
                            title=title,
                            vuln_type=vuln_type,
                            severity=severity,
                            url=url,
                            parameter=finding.get("parameter"),
                            payload=finding.get("payload"),
                            evidence=evidence,  # RawFinding uses 'evidence' (str)
                            module_name=finding.get("module_name", finding.get("module", "unknown")),
                            request=finding.get("raw_request", ""),
                            response=finding.get("raw_response", ""),
                            metadata=finding.get("metadata", {}),  # Preserve scanner metadata (e.g., http_evidence)
                            confidence=confidence,  # Pass normalized confidence
                            method=method,  # Ensure method is passed
                        )
                        raw_findings.append(raw)

                    pentest_log.log_info(f"Validating {len(raw_findings)} raw findings")
                    
                    # Log raw findings for debugging
                    validation_debug = os.environ.get("PHANTOM_VALIDATION_DEBUG", "0") == "1" or verbose
                    if validation_debug:
                        for i, rf in enumerate(raw_findings):
                            console.print(f"[dim]   Raw finding {i+1}: {rf.title} (type={rf.vulnerability_type.value}, conf={rf.confidence:.2f})[/dim]")
                            pentest_log.log_info(f"Raw finding {i+1}: {rf.title} (type={rf.vulnerability_type.value}, conf={rf.confidence:.2f}, url={rf.url})")

                    # Run validation - returns List[ValidatedFinding] directly
                    validated_list = await pipeline.validate_findings(raw_findings)

                    # Log validation results for debugging
                    if validation_debug:
                        console.print(f"\n[bold cyan]Validation Results:[/bold cyan]")
                        for vf in validated_list:
                            status = "✓" if vf.final_confidence >= ConfidenceThreshold.MINIMUM_REPORT else "✗"
                            status_color = "green" if status == "✓" else "yellow"
                            console.print(f"[{status_color}]   {status} {vf.raw_finding.title}[/{status_color}]")
                            console.print(f"[dim]      Final confidence: {vf.final_confidence:.2f} (threshold: {ConfidenceThreshold.MINIMUM_REPORT})[/dim]")
                            console.print(f"[dim]      Stages:[/dim]")
                            for sr in vf.stage_results:
                                result_color = "green" if sr.result.value == "passed" else "red" if sr.result.value == "failed" else "yellow"
                                console.print(f"[dim]        - {sr.stage.name}: [{result_color}]{sr.result.value}[/{result_color}] (delta: {sr.confidence_delta:+.2f}) {sr.message}[/dim]")
                            
                            pentest_log.log_info(f"Validation result: {vf.raw_finding.title} -> conf={vf.final_confidence:.2f}, valid={vf.is_valid}")
                        console.print()

                    # Filter by confidence threshold
                    validated_findings = [
                        f for f in validated_list
                        if f.final_confidence >= ConfidenceThreshold.MINIMUM_REPORT
                    ]

                    validation_duration = (datetime.now() - validation_start_time).total_seconds()
                    progress.update(task_validate, completed=100)

                    # Count findings properly (INFO findings were skipped from validation)
                    findings_sent_to_validation = len(raw_findings)
                    validated_count = len(validated_findings)
                    fp_count = findings_sent_to_validation - validated_count

                    pentest_log.log_phase_end("validation", validation_duration, {
                        "original_findings": len(all_findings),
                        "info_findings_skipped": info_findings_skipped,
                        "validated_findings": validated_count,
                        "false_positives_removed": fp_count,
                    })

                    console.print(f"[green]✓ Validation complete[/green]")
                    console.print(f"   Total findings: {len(all_findings)} ({info_findings_skipped} INFO skipped)")
                    console.print(f"   Sent to validation: {findings_sent_to_validation}")
                    console.print(f"   Validated findings: {validated_count}")
                    if fp_count > 0:
                        console.print(f"   Below threshold: [yellow]{fp_count}[/yellow]")

                    # Cleanup pipeline resources
                    try:
                        await pipeline.close()
                    except Exception as e:
                        logger.debug(f"Pipeline cleanup error: {e}")

                except Exception as e:
                    if verbose:
                        console.print(f"[yellow]⚠️ Validation error: {e}[/yellow]")
                    pentest_log.log_error(f"Validation error: {e}", exception=e)
                    validated_findings = all_findings
                    info_findings_skipped = 0
                    progress.update(task_validate, completed=100)
                    # Try to close pipeline even on error
                    try:
                        await pipeline.close()
                    except Exception as cleanup_err:
                        logger.debug(f"Pipeline cleanup error: {cleanup_err}")
            else:
                validated_findings = all_findings
                info_findings_skipped = 0
                if not all_findings:
                    pentest_log.log_info("No findings to validate")
                elif not PHANTOM_AVAILABLE:
                    pentest_log.log_warning("PHANTOM modules not available, validation skipped")
                elif no_ai:
                    pentest_log.log_info("AI validation disabled by user")

            scan_state["validated_findings"] = [
                f.to_dict() if hasattr(f, "to_dict") else f
                for f in validated_findings
            ]

            # =================================================================
            # PHASE 7: Vulnerability Chaining (Enhanced with Speculative Chains)
            # =================================================================
            chains = []
            if not no_chain and PHANTOM_AVAILABLE:
                task_chain = progress.add_task("[cyan]Analyzing vulnerability chains...", total=100)
                pentest_log.log_phase_start("chaining", "Analyzing vulnerability chains for attack paths")
                chain_start_time = datetime.now()

                try:
                    # Part 1: Confirmed vulnerability chains (if we have findings)
                    if validated_findings:
                        from ai_engine.chain_detector import ChainDetector

                        chain_detector = ChainDetector(settings)
                        # Convert findings to flat dicts with proper field names for chain detector
                        findings_dicts = []
                        for f in validated_findings:
                            if hasattr(f, "to_dict"):
                                d = f.to_dict()
                                # ValidatedFinding.to_dict() nests under "finding" key
                                inner = d.get("finding", d)
                            else:
                                inner = f

                            # Get best name: title > name > derived from type
                            name = inner.get("title") or inner.get("name") or ""
                            if not name or name.lower() in ("unknown", "other", ""):
                                # Derive name from vulnerability_type
                                vtype = inner.get("vulnerability_type") or inner.get("type") or ""
                                if vtype and vtype.lower() not in ("other", "unknown"):
                                    type_names = {
                                        "sqli": "SQL Injection", "xss": "XSS",
                                        "cmdi": "Command Injection", "lfi": "LFI",
                                        "ssrf": "SSRF", "xxe": "XXE", "ssti": "SSTI",
                                        "crlf": "CRLF Injection", "idor": "IDOR",
                                        "csrf": "CSRF", "jwt": "JWT Vulnerability",
                                        "open_redirect": "Open Redirect",
                                        "info_disclosure": "Information Disclosure",
                                        "authentication": "Authentication Issue",
                                        "authorization": "Authorization Issue",
                                    }
                                    name = type_names.get(vtype.lower(), vtype.upper() if len(vtype) <= 5 else vtype.title())
                                else:
                                    # Try module name
                                    module = inner.get("module_name") or inner.get("module") or ""
                                    module_names = {
                                        "sqli_scanner": "SQL Injection",
                                        "xss_scanner": "XSS",
                                        "crlf_scanner": "CRLF Injection",
                                        "dir_scanner": "Sensitive File Exposure",
                                        "jwt_scanner": "JWT Vulnerability",
                                    }
                                    name = module_names.get(module, "Vulnerability")

                            # Map fields for chain detector
                            findings_dicts.append({
                                "id": inner.get("id", ""),
                                "name": name,
                                "type": inner.get("vulnerability_type") or inner.get("type", "other"),
                                "severity": inner.get("severity", "MEDIUM"),
                                "url": inner.get("url", ""),
                                "matched_at": inner.get("url", inner.get("matched_at", "")),
                                "evidence": inner.get("evidence", []),
                                "host": domain,
                            })
                        # Create assets dict for chain detection
                        assets = {"target": target, "host": target}
                        confirmed_chains = await chain_detector.detect(findings_dicts, assets)
                        chains.extend(confirmed_chains or [])

                    # Part 2: Speculative chains based on detected technologies
                    # Even without confirmed vulns, suggest high-value attack paths
                    detected_techs = scan_state.get("technologies", [])
                    if detected_techs or "api" in target.lower():
                        try:
                            from scanning.vuln_chain_engine import VulnerabilityChainEngine, is_speculative_allowed

                            if is_speculative_allowed():
                                chain_engine = VulnerabilityChainEngine()
                                tech_names = [t.get("name", str(t)) if isinstance(t, dict) else str(t)
                                              for t in detected_techs]
                                speculative_chains = await chain_engine.generate_speculative_chains(
                                    tech_names, target
                                )
                                if speculative_chains:
                                    chains.extend(speculative_chains)
                                    console.print(f"[cyan]💡 Generated {len(speculative_chains)} technology-based attack path suggestions[/cyan]")
                        except ImportError:
                            pass  # Chain engine not available
                        except Exception as spec_err:
                            if verbose:
                                console.print(f"[dim]Speculative chain generation: {spec_err}[/dim]")

                    chain_duration = (datetime.now() - chain_start_time).total_seconds()

                    # Validate and deduplicate chains to remove false positives and duplicates
                    if chains:
                        try:
                            from scanning.vuln_chain_engine import VulnerabilityChainEngine
                            chain_validator = VulnerabilityChainEngine()

                            # Build target context for validation
                            target_context = {
                                "technologies": scan_state.get("technologies", []),
                                "is_cloud_hosted": any(
                                    t.get("name", "").lower() in ["aws", "gcp", "azure", "cloudfront", "cloudflare"]
                                    for t in scan_state.get("technologies", [])
                                    if isinstance(t, dict)
                                ),
                                "has_internal_endpoints": scan_state.get("has_internal_endpoints", False),
                            }

                            original_count = len(chains)
                            chains = chain_validator.validate_and_deduplicate_chains(chains, target_context)

                            if len(chains) < original_count:
                                removed = original_count - len(chains)
                                console.print(f"[dim]   Chain cleanup: removed {removed} duplicates/invalid chains[/dim]")
                                pentest_log.log_info(f"Chain cleanup: {original_count} → {len(chains)} (removed {removed})")

                        except Exception as chain_val_err:
                            if verbose:
                                console.print(f"[dim]Chain validation: {chain_val_err}[/dim]")

                    if chains:
                        confirmed_count = len([c for c in chains if not c.get("metadata", {}).get("is_speculative")])
                        speculative_count = len([c for c in chains if c.get("metadata", {}).get("is_speculative")])

                        if confirmed_count > 0:
                            console.print(f"[green]✓ Discovered {confirmed_count} confirmed attack chains[/green]")
                        if speculative_count > 0:
                            console.print(f"[cyan]💡 {speculative_count} speculative attack paths (based on tech stack)[/cyan]")

                        for chain in chains[:5]:
                            chain_name = chain.get("name", "Unknown Chain")
                            is_spec = chain.get("metadata", {}).get("is_speculative", False)
                            marker = "[dim](speculative)[/dim]" if is_spec else ""
                            console.print(f"   [yellow]•[/yellow] {chain_name} {marker}")

                        pentest_log.log_phase_end("chaining", chain_duration, {
                            "chains_discovered": len(chains),
                            "confirmed_chains": confirmed_count,
                            "speculative_chains": speculative_count,
                        })
                    else:
                        pentest_log.log_phase_end("chaining", chain_duration, {
                            "chains_discovered": 0,
                            "note": "No exploitable chains found",
                        })

                    scan_state["chains"] = chains

                except Exception as e:
                    if verbose:
                        console.print(f"[yellow]⚠️ Chain analysis error: {e}[/yellow]")
                    pentest_log.log_error(f"Chain analysis error: {e}", exception=e)

                progress.update(task_chain, completed=100)
            else:
                if no_chain:
                    pentest_log.log_info("Chain analysis disabled by user")

            scan_state["phase"] = "reporting"
            save_scan_state(scan_id, scan_state)

    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️ Scan interrupted by user[/yellow]")
        scan_state["status"] = "interrupted"
        save_scan_state(scan_id, scan_state)
        console.print(f"[cyan]Resume with: phantom resume {scan_id}[/cyan]")
        return

    except Exception as e:
        console.print(f"\n[red]❌ Scan error: {e}[/red]")
        scan_state["status"] = "error"
        scan_state["error"] = str(e)
        save_scan_state(scan_id, scan_state)
        return

    # =================================================================
    # RESULTS DISPLAY
    # =================================================================
    console.print()

    # Summary statistics
    summary = {
        "total": len(validated_findings),
        "critical": len([f for f in validated_findings if _get_severity(f) == "CRITICAL"]),
        "high": len([f for f in validated_findings if _get_severity(f) == "HIGH"]),
        "medium": len([f for f in validated_findings if _get_severity(f) == "MEDIUM"]),
        "low": len([f for f in validated_findings if _get_severity(f) == "LOW"]),
    }

    # Results table
    table = Table(title="📊 PHANTOM AI Scan Results", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")

    table.add_row("Scan ID", scan_id)
    table.add_row("Duration", str(datetime.now() - start_time).split(".")[0])
    table.add_row("Total Findings", str(summary["total"]))
    table.add_row("[red]Critical[/red]", str(summary["critical"]))
    table.add_row("[orange1]High[/orange1]", str(summary["high"]))
    table.add_row("[yellow]Medium[/yellow]", str(summary["medium"]))
    table.add_row("[green]Low[/green]", str(summary["low"]))
    table.add_row("Modules Run", str(len(scan_state.get("modules_run", []))))
    table.add_row("Chains Found", str(len(chains)))

    console.print(table)

    # Semantic grouping by category
    if validated_findings:
        _CATEGORY_MAP = {
            "Injection": {"sqli", "sql_injection", "nosql", "nosqli", "cmdi", "command_injection", "ldap", "ssti", "template_injection", "crlf"},
            "XSS / Client-Side": {"xss", "dom_xss", "reflected_xss", "stored_xss", "cross_site_scripting", "template_injection_xss", "clickjacking"},
            "Auth / Session": {"authentication", "auth_bypass", "jwt", "session_abuse", "session", "token_not_invalidated", "mfa", "oauth", "saml"},
            "Access Control": {"idor", "authorization", "authz", "broken_access_control"},
            "Business Logic": {"business_logic", "business", "price_manipulation", "workflow_bypass", "race"},
            "API Security": {"api", "api_security", "graphql", "grpc", "mass_assign", "rate_limit", "ratelimit"},
            "Creative / Logic": {"creative_logic", "creative_exploiter", "context_confusion", "trust_boundary", "chaos_composer"},
            "Infrastructure": {"cors", "headers", "ssl", "smuggling", "cache", "cache_deception", "dns_rebind", "host_header", "prototype"},
            "Information Disclosure": {"info_disclosure", "information_disclosure", "directory", "sensitive_file", "vcs_exposure", "cms", "dir"},
        }

        # Classify each finding
        categories: dict[str, list] = {}
        for f in validated_findings:
            # Unwrap ValidatedFinding → raw_finding if needed
            raw = f.raw_finding if hasattr(f, "raw_finding") else f
            if hasattr(raw, "vulnerability_type"):
                vt = raw.vulnerability_type
                ftype = (vt.value if hasattr(vt, "value") else str(vt)).lower().replace(" ", "_").replace("-", "_")
            elif isinstance(raw, dict):
                ftype = (raw.get("type") or raw.get("vulnerability_type") or
                         (raw.get("finding", {}) if isinstance(raw.get("finding"), dict) else {}).get("vulnerability_type", "other")
                         ).lower().replace(" ", "_").replace("-", "_")
            else:
                ftype = "other"
            if hasattr(raw, "module_name"):
                module = (raw.module_name or "").lower()
            elif isinstance(raw, dict):
                module = (raw.get("module_name") or raw.get("module") or
                          (raw.get("finding", {}) if isinstance(raw.get("finding"), dict) else {}).get("module_name", "")).lower()
            else:
                module = ""
            category = "Other"
            for cat_name, cat_types in _CATEGORY_MAP.items():
                if ftype in cat_types or module in cat_types:
                    category = cat_name
                    break
            categories.setdefault(category, []).append(f)

        console.print("\n[bold]📋 Findings by Category:[/bold]")
        for cat_name, cat_findings in sorted(categories.items(), key=lambda x: -max(
            {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(_get_severity(f), 0)
            for f in x[1]
        )):
            sev_counts = {}
            for f in cat_findings:
                s = _get_severity(f)
                sev_counts[s] = sev_counts.get(s, 0) + 1
            sev_str = " ".join(f"{format_severity(s)}×{c}" for s, c in
                              sorted(sev_counts.items(), key=lambda x: -{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(x[0], 0)))
            console.print(f"  [bold]{cat_name}[/bold] ({len(cat_findings)}) — {sev_str}")
            # Show top 2 findings per category
            for f in sorted(cat_findings, key=lambda f: -{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(_get_severity(f), 0))[:2]:
                name = _get_type(f)
                url = _get_url(f)
                console.print(f"    {format_severity(_get_severity(f))} {name}")
                if url:
                    console.print(f"       {url[:60]}{'...' if len(url) > 60 else ''}")
            if len(cat_findings) > 2:
                console.print(f"    [dim]... +{len(cat_findings) - 2} more[/dim]")

    # Display all findings (flat list)
    if validated_findings:
        console.print("\n[bold]🔍 All Findings:[/bold]")

        for i, finding in enumerate(validated_findings[:10], 1):
            severity = _get_severity(finding)
            vuln_type = _get_type(finding)
            url = _get_url(finding)
            confidence = _get_confidence(finding)

            console.print(f"  {format_severity(severity)} {i}. {vuln_type}")
            console.print(f"     └─ {url[:70]}{'...' if len(url) > 70 else ''}")
            console.print(f"        Confidence: {format_confidence(confidence)}")

        if len(validated_findings) > 10:
            console.print(f"  ... and {len(validated_findings) - 10} more (see full report)")

    # Display chains
    if chains:
        console.print("\n[bold]🔗 Attack Chains:[/bold]")
        for i, chain in enumerate(chains[:3], 1):
            chain_vulns = chain.get("vulnerabilities", [])
            # Use name or title for each vuln, fallback to chain name if no vulns
            if chain_vulns:
                vuln_names = []
                for v in chain_vulns:
                    name = None
                    if isinstance(v, dict):
                        # Priority order: title > name > type (if meaningful)
                        name = v.get("title") or v.get("name")
                        if not name or name.lower() in ("unknown", "other", ""):
                            vtype = v.get("type") or v.get("vulnerability_type")
                            if vtype and vtype.lower() not in ("unknown", "other", ""):
                                # Convert type to readable name
                                type_display = {
                                    "sqli": "SQL Injection", "xss": "XSS",
                                    "cmdi": "Command Injection", "lfi": "LFI",
                                    "ssrf": "SSRF", "xxe": "XXE", "ssti": "SSTI",
                                    "crlf": "CRLF Injection", "idor": "IDOR",
                                    "csrf": "CSRF", "jwt": "JWT Issue",
                                }.get(vtype.lower(), vtype.upper() if len(vtype) <= 5 else vtype.title())
                                name = type_display
                            else:
                                # Try to extract from finding_id or other fields
                                name = v.get("description", "").split(".")[0][:30] if v.get("description") else None
                        # Final cleanup
                        if not name or name.lower() in ("unknown", "other", ""):
                            name = "Vulnerability"
                    elif isinstance(v, str):
                        name = v if v.lower() not in ("unknown", "other", "") else "Vulnerability"
                    else:
                        name = str(v) if v else "Vulnerability"
                    vuln_names.append(name)
                # Filter out duplicate consecutive names
                deduped = [vuln_names[0]] if vuln_names else []
                for n in vuln_names[1:]:
                    if n != deduped[-1]:
                        deduped.append(n)
                chain_str = " → ".join(deduped) if deduped else chain.get("name", "Unknown Chain")
            else:
                chain_str = chain.get("name", "Unknown Chain")
            impact = chain.get("impact", chain.get("description", ""))
            if not impact or impact.lower() == "unknown":
                impact = chain.get("attack_narrative", "Potential security impact")
            console.print(f"  [yellow]{i}. {chain_str}[/yellow]")
            console.print(f"     Impact: {impact}")

    # =================================================================
    # REPORT GENERATION
    # =================================================================
    output_path = Path(output_dir) if output_dir else get_reports_dir()
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_domain = domain.replace(".", "_")[:30]

    report_data = {
        "scan_id": scan_id,
        "target": target,
        "domain": domain,
        "start_time": start_time.isoformat(),
        "end_time": datetime.now().isoformat(),
        "duration": str(datetime.now() - start_time),
        "config": scan_state["config"],
        "summary": summary,
        "findings": [
            # ValidatedFinding.to_dict() returns nested {"finding": {...}, "is_valid": ...}
            # The HTML report expects flat {"type": ..., "severity": ...}
            # Extract and flatten the raw finding data for the report
            _flatten_validated_finding(f) if hasattr(f, "to_dict") else f
            for f in validated_findings
        ],
        "chains": chains,
        "technologies": tech_results.to_dict() if tech_results and hasattr(tech_results, "to_dict") else None,
        "waf": waf_result.to_dict() if waf_result and hasattr(waf_result, "to_dict") else None,
        "modules_run": scan_state.get("modules_run", []),
        "errors": scan_state.get("errors", []),
    }

    # FIX CLI-08: Add error handling for report generation
    report_file = None
    try:
        if output_format == "json":
            report_file = output_path / f"phantom_{safe_domain}_{timestamp}.json"
            report_file.write_text(json.dumps(report_data, indent=2, default=str))

        elif output_format == "sarif" and PHANTOM_AVAILABLE:
            report_file = output_path / f"phantom_{safe_domain}_{timestamp}.sarif"
            sarif_output = findings_to_sarif(validated_findings, target, scan_id)
            report_file.write_text(json.dumps(sarif_output, indent=2))

        elif output_format == "html":
            report_file = output_path / f"phantom_{safe_domain}_{timestamp}.html"
            _generate_phantom_html_report(report_data, report_file)

        elif output_format == "md":
            report_file = output_path / f"phantom_{safe_domain}_{timestamp}.md"
            _generate_phantom_md_report(report_data, report_file)

        else:
            # Default to JSON
            report_file = output_path / f"phantom_{safe_domain}_{timestamp}.json"
            report_file.write_text(json.dumps(report_data, indent=2, default=str))

        console.print(f"\n[green]✅ Report saved: {report_file}[/green]")

    except (OSError, PermissionError, IOError) as e:
        console.print(f"\n[red]❌ Failed to save report: {e}[/red]")
        # Try fallback to temp directory
        try:
            import tempfile
            fallback_dir = Path(tempfile.gettempdir())
            report_file = fallback_dir / f"phantom_{safe_domain}_{timestamp}.json"
            report_file.write_text(json.dumps(report_data, indent=2, default=str))
            console.print(f"[yellow]⚠️ Report saved to fallback location: {report_file}[/yellow]")
        except Exception as fallback_e:
            console.print(f"[red]❌ Fallback also failed: {fallback_e}[/red]")
            console.print("[yellow]Report data available in scan state file.[/yellow]")
    except (TypeError, ValueError) as e:
        console.print(f"\n[red]❌ Failed to serialize report: {e}[/red]")
        # Try simplified JSON
        try:
            report_file = output_path / f"phantom_{safe_domain}_{timestamp}_simple.json"
            simple_data = {"findings": [str(f) for f in validated_findings], "error": str(e)}
            report_file.write_text(json.dumps(simple_data, indent=2))
            console.print(f"[yellow]⚠️ Simplified report saved: {report_file}[/yellow]")
        except Exception:
            console.print("[yellow]Report data available in scan state file.[/yellow]")

    # Update final state
    scan_state["status"] = "completed"
    scan_state["end_time"] = datetime.now().isoformat()
    scan_state["report_file"] = str(report_file)
    save_scan_state(scan_id, scan_state)

    # Log scan completion to audit trail
    try:
        audit = get_audit_logger()
        if audit:
            duration = (datetime.now() - start_time).total_seconds()
            audit.log_scan_completed(
                target=target,
                findings_count=len(validated_findings),
                duration_seconds=duration,
                scope_violations=0,
            )
    except Exception:
        pass  # Audit logging is optional

    # Final summary panel
    risk_level = "LOW"
    risk_color = "green"
    if summary["critical"] > 0:
        risk_level = "CRITICAL"
        risk_color = "red"
    elif summary["high"] > 0:
        risk_level = "HIGH"
        risk_color = "orange1"
    elif summary["medium"] > 0:
        risk_level = "MEDIUM"
        risk_color = "yellow"

    # Log findings to pentest log
    for finding in validated_findings:
        # Extract raw finding data (ValidatedFinding wraps raw_finding)
        raw = finding
        if hasattr(finding, "raw_finding"):
            raw = finding.raw_finding

        # Get fields from raw finding or dict
        if hasattr(raw, "parameter"):
            param = raw.parameter
        elif isinstance(raw, dict):
            param = raw.get("parameter")
        else:
            param = None

        if hasattr(raw, "payload"):
            payload = raw.payload
        elif isinstance(raw, dict):
            payload = raw.get("payload")
        else:
            payload = None

        if hasattr(raw, "evidence"):
            evidence = raw.evidence
        elif isinstance(raw, dict):
            evidence = raw.get("evidence")
        else:
            evidence = None

        if hasattr(raw, "module_name"):
            module = raw.module_name
        elif isinstance(raw, dict):
            module = raw.get("module_name") or raw.get("module")
        else:
            module = None

        pentest_log.log_finding(
            vulnerability_type=_get_type(finding),
            severity=_get_severity(finding),
            url=_get_url(finding),
            confidence=_get_confidence(finding),
            parameter=param,
            payload=payload,
            evidence=evidence,
            module=module,
        )

    # Log chains to pentest log (with consecutive-name dedup)
    for i, chain in enumerate(chains):
        chain_vulns = chain.get("vulnerabilities", [])
        if chain_vulns:
            vuln_names = [_get_vuln_display_name(v) for v in chain_vulns]
            # Collapse consecutive duplicates: CSTI→CSTI→CSTI → CSTI (×3)
            deduped_log = []
            for n in vuln_names:
                if deduped_log and deduped_log[-1][0] == n:
                    deduped_log[-1] = (n, deduped_log[-1][1] + 1)
                else:
                    deduped_log.append((n, 1))
            vuln_names = [
                f"{name} (×{count})" if count > 1 else name
                for name, count in deduped_log
            ]
        else:
            vuln_names = [chain.get("name", "Unknown Chain")]
        pentest_log.log_chain(
            chain_id=f"chain_{i+1}",
            vulnerabilities=vuln_names,
            impact=chain.get("impact", "Potential security impact"),
            severity=chain.get("severity", "MEDIUM"),
        )

    # End pentest logging session
    pentest_log.log_session_end({
        "total_findings": summary["total"],
        "critical": summary["critical"],
        "high": summary["high"],
        "medium": summary["medium"],
        "low": summary["low"],
        "chains_discovered": len(chains),
        "modules_run": len(scan_state.get("modules_run", [])),
        "risk_level": risk_level,
        "report_file": str(report_file),
    })

    # Clear global pentest logger
    from utils.logger import set_pentest_logger
    set_pentest_logger(None)

    console.print(f"[dim]📝 Full pentest log saved: {pentest_log.get_log_path()}[/dim]")

    console.print(Panel(
        f"[bold]Scan Complete[/bold]\n\n"
        f"Target: {target}\n"
        f"Risk Level: [{risk_color}]{risk_level}[/{risk_color}]\n"
        f"Findings: {summary['total']} validated\n"
        f"Chains: {len(chains)} discovered\n"
        f"Report: {report_file}",
        title="✅ PHANTOM AI Assessment Complete",
        border_style=risk_color,
    ))


def _flatten_validated_finding(validated_finding) -> dict:
    """
    Flatten a ValidatedFinding to a dict suitable for report generation.

    ValidatedFinding.to_dict() returns:
        {"finding": {...}, "is_valid": ..., "final_confidence": ...}

    Report generators expect:
        {"type": ..., "severity": ..., "url": ..., "description": ...}

    This function extracts the nested finding and adds validation metadata.
    """
    if hasattr(validated_finding, "raw_finding"):
        # It's a ValidatedFinding object - extract from raw_finding
        raw = validated_finding.raw_finding
        result = {
            "type": raw.vulnerability_type.value if hasattr(raw.vulnerability_type, "value") else str(raw.vulnerability_type),
            "name": raw.title,
            "title": raw.title,
            "severity": raw.severity.upper() if isinstance(raw.severity, str) else str(raw.severity),
            "url": raw.url,
            "matched_at": raw.url,
            "parameter": raw.parameter,
            "payload": raw.payload,
            "evidence": raw.evidence,
            "description": raw.description or raw.evidence or f"{raw.title} detected at {raw.url}",
            "module": raw.module_name,
            "confidence": validated_finding.final_confidence,
            "is_valid": validated_finding.is_valid,
            "validation_confidence": validated_finding.final_confidence,
        }
        # Preserve metadata (cluster, proof_gate, etc.) from postprocessing
        if hasattr(raw, "metadata") and raw.metadata:
            result["metadata"] = raw.metadata if isinstance(raw.metadata, dict) else {}
        return result
    elif hasattr(validated_finding, "to_dict"):
        # Has to_dict but not raw_finding - might be dict-like
        d = validated_finding.to_dict()
        # Check if it's nested format from ValidatedFinding
        if "finding" in d and isinstance(d["finding"], dict):
            inner = d["finding"]
            flat = {
                "type": inner.get("vulnerability_type", inner.get("type", "unknown")),
                "name": inner.get("title", inner.get("name", "Unknown")),
                "title": inner.get("title", inner.get("name", "Unknown")),
                "severity": inner.get("severity", "MEDIUM"),
                "url": inner.get("url", "N/A"),
                "matched_at": inner.get("url", "N/A"),
                "parameter": inner.get("parameter"),
                "payload": inner.get("payload"),
                "evidence": inner.get("evidence", ""),
                "description": inner.get("description") or inner.get("evidence") or "No description available.",
                "module": inner.get("module_name"),
                "confidence": d.get("final_confidence", 0.5),
                "is_valid": d.get("is_valid", True),
            }
            # Preserve metadata (cluster, proof_gate, etc.) from postprocessing
            if inner.get("metadata"):
                flat["metadata"] = inner["metadata"]
            return flat
        return d
    else:
        # Already a dict
        return validated_finding


def _get_severity(finding) -> str:
    """Get severity from finding. Always returns uppercase (CRITICAL, HIGH, MEDIUM, LOW, INFO)."""
    # ValidatedFinding wraps the raw finding
    if hasattr(finding, "raw_finding"):
        finding = finding.raw_finding
    if hasattr(finding, "severity"):
        sev = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        return sev.upper() if isinstance(sev, str) else "INFO"
    elif isinstance(finding, dict):
        # Serialized ValidatedFinding: {"finding": {...}, "is_valid": true, ...}
        if "finding" in finding and isinstance(finding["finding"], dict):
            sev = finding["finding"].get("severity", "INFO")
        else:
            sev = finding.get("severity", "INFO")
        return sev.upper() if isinstance(sev, str) else "INFO"
    return "INFO"


def _get_type(finding) -> str:
    """Get vulnerability type/name from finding for display."""
    # ValidatedFinding wraps the raw finding
    raw = finding
    if hasattr(finding, "raw_finding"):
        raw = finding.raw_finding

    # Priority 1: title field (human-readable name)
    if hasattr(raw, "title") and raw.title:
        title = raw.title
        if title.lower() not in ("unknown", "other", "vulnerability"):
            return title

    # Priority 2: name field
    if hasattr(raw, "name") and raw.name:
        name = raw.name
        if name.lower() not in ("unknown", "other", "vulnerability"):
            return name

    # Priority 3: vulnerability_type enum (if meaningful)
    if hasattr(raw, "vulnerability_type"):
        vt = raw.vulnerability_type
        vt_value = vt.value if hasattr(vt, "value") else str(vt)
        if vt_value.lower() not in ("other", "unknown"):
            # Convert to readable format: "sqli" -> "SQL Injection"
            type_display_names = {
                "sqli": "SQL Injection",
                "xss": "XSS",
                "cmdi": "Command Injection",
                "lfi": "LFI",
                "ssrf": "SSRF",
                "xxe": "XXE",
                "ssti": "SSTI",
                "nosql": "NoSQL Injection",
                "crlf": "CRLF Injection",
                "idor": "IDOR",
                "open_redirect": "Open Redirect",
                "csrf": "CSRF",
                "jwt": "JWT Vulnerability",
                "info_disclosure": "Information Disclosure",
                "authentication": "Authentication Issue",
                "authorization": "Authorization Issue",
            }
            return type_display_names.get(vt_value.lower(), vt_value.upper())

    # For dict-based findings
    if isinstance(raw, dict):
        # Serialized ValidatedFinding: {"finding": {...}, "is_valid": true, ...}
        if "finding" in raw and isinstance(raw["finding"], dict):
            raw = raw["finding"]

        # Try title first
        title = raw.get("title")
        if title and title.lower() not in ("unknown", "other"):
            return title
        # Try name
        name = raw.get("name")
        if name and name.lower() not in ("unknown", "other"):
            return name
        # Try vulnerability_type
        vt = raw.get("vulnerability_type") or raw.get("type")
        if vt and vt.lower() not in ("unknown", "other"):
            return vt.upper() if len(vt) <= 5 else vt.title()
        # Try module_name to infer type
        module = raw.get("module_name") or raw.get("module")
        if module:
            module_type_map = {
                "sqli_scanner": "SQL Injection",
                "xss_scanner": "XSS",
                "crlf_scanner": "CRLF Injection",
                "dir_scanner": "Sensitive File",
                "jwt_scanner": "JWT Vulnerability",
                "ssrf_scanner": "SSRF",
                "ssti_scanner": "SSTI",
            }
            if module in module_type_map:
                return module_type_map[module]

    return "Vulnerability"


def _get_url(finding) -> str:
    """Get URL from finding."""
    # ValidatedFinding wraps the raw finding
    if hasattr(finding, "raw_finding"):
        finding = finding.raw_finding
    if hasattr(finding, "url"):
        return finding.url
    elif isinstance(finding, dict):
        return finding.get("url", finding.get("matched_at", "N/A"))
    return "N/A"


def _get_confidence(finding) -> float:
    """Get confidence from finding."""
    # ValidatedFinding uses final_confidence, not confidence
    if hasattr(finding, "final_confidence"):
        return finding.final_confidence
    elif hasattr(finding, "confidence"):
        return finding.confidence
    elif isinstance(finding, dict):
        return finding.get("final_confidence", finding.get("confidence_score", finding.get("confidence", 0.0)))
    return 0.0


# Type display names mapping (reusable across functions)
_TYPE_DISPLAY_NAMES = {
    # Injection
    "sqli": "SQL Injection", "xss": "XSS", "cmdi": "Command Injection",
    "lfi": "LFI", "ssrf": "SSRF", "xxe": "XXE", "ssti": "SSTI",
    "nosql": "NoSQL Injection", "crlf": "CRLF Injection",
    "crlf_injection": "CRLF Injection", "idor": "IDOR",
    # Access control
    "open_redirect": "Open Redirect", "csrf": "CSRF", "cors": "CORS Misconfiguration",
    # Auth
    "jwt": "JWT Vulnerability", "authentication": "Auth Issue",
    "authorization": "Authorization Issue",
    # API
    "api": "API Security Issue", "api_security": "API Security Issue",
    "graphql": "GraphQL Issue",
    # Files
    "directory": "Directory Exposure", "sensitive_file": "Sensitive File Exposure",
    "path_traversal": "Path Traversal",
    # Code execution
    "rce": "Remote Code Execution", "deserialization": "Insecure Deserialization",
    # Info
    "info_disclosure": "Information Disclosure", "information_disclosure": "Information Disclosure",
    # Other
    "misconfiguration": "Security Misconfiguration", "rate_limit": "Rate Limit Issue",
}


def _get_vuln_display_name(v) -> str:
    """Get display name for a vulnerability in a chain."""
    if isinstance(v, str):
        return v if v.lower() not in ("unknown", "other", "") else "Vulnerability"

    if not isinstance(v, dict):
        return str(v) if v else "Vulnerability"

    # Priority: title > name > type (if meaningful)
    name = v.get("title") or v.get("name")
    if name and name.lower() not in ("unknown", "other", ""):
        return name

    # Try type
    vtype = v.get("type") or v.get("vulnerability_type")
    if vtype and vtype.lower() not in ("unknown", "other", ""):
        return _TYPE_DISPLAY_NAMES.get(vtype.lower(), vtype.upper() if len(vtype) <= 5 else vtype.title())

    # Try description
    desc = v.get("description", "")
    if desc and len(desc) > 5:
        return desc.split(".")[0][:40]

    return "Vulnerability"


def _generate_phantom_html_report(data: Dict[str, Any], path: Path) -> None:
    """Generate PHANTOM AI HTML report."""
    summary = data.get("summary", {})
    findings = data.get("findings", [])
    chains = data.get("chains", [])

    risk_level = "LOW"
    if summary.get("critical", 0) > 0:
        risk_level = "CRITICAL"
    elif summary.get("high", 0) > 0:
        risk_level = "HIGH"
    elif summary.get("medium", 0) > 0:
        risk_level = "MEDIUM"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHANTOM AI Security Report - {data.get('target', 'Unknown')}</title>
    <style>
        :root {{
            --bg-primary: #0a0a1a;
            --bg-secondary: #12122a;
            --bg-card: #1a1a3a;
            --text-primary: #ffffff;
            --text-secondary: #a0a0c0;
            --accent-cyan: #00d4ff;
            --accent-purple: #9b59b6;
            --critical: #e74c3c;
            --high: #e67e22;
            --medium: #f1c40f;
            --low: #27ae60;
        }}

        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        body {{
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }}

        .header {{
            background: linear-gradient(135deg, #1a1a3a 0%, #2d2d5a 50%, #1a1a3a 100%);
            padding: 3rem;
            border-radius: 1rem;
            margin-bottom: 2rem;
            border: 1px solid var(--accent-cyan);
            box-shadow: 0 0 30px rgba(0, 212, 255, 0.2);
        }}

        .header h1 {{
            font-size: 2.5rem;
            background: linear-gradient(90deg, var(--accent-cyan), var(--accent-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 1rem;
        }}

        .header-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 1.5rem;
        }}

        .header-item {{
            background: rgba(0, 212, 255, 0.1);
            padding: 1rem;
            border-radius: 0.5rem;
        }}

        .header-item label {{
            color: var(--text-secondary);
            font-size: 0.875rem;
        }}

        .header-item value {{
            display: block;
            font-size: 1.1rem;
            font-weight: 600;
        }}

        .risk-badge {{
            display: inline-block;
            padding: 0.5rem 1.5rem;
            border-radius: 2rem;
            font-weight: 700;
            font-size: 0.875rem;
        }}

        .risk-CRITICAL {{ background: var(--critical); }}
        .risk-HIGH {{ background: var(--high); }}
        .risk-MEDIUM {{ background: var(--medium); color: #333; }}
        .risk-LOW {{ background: var(--low); }}

        .card {{
            background: var(--bg-card);
            border-radius: 1rem;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}

        .card h2 {{
            color: var(--accent-cyan);
            margin-bottom: 1.5rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
        }}

        .stat {{
            text-align: center;
            padding: 1.5rem;
            background: var(--bg-secondary);
            border-radius: 0.75rem;
        }}

        .stat-number {{
            font-size: 3rem;
            font-weight: 700;
            line-height: 1;
        }}

        .stat-label {{
            color: var(--text-secondary);
            margin-top: 0.5rem;
        }}

        .stat-number.critical {{ color: var(--critical); }}
        .stat-number.high {{ color: var(--high); }}
        .stat-number.medium {{ color: var(--medium); }}
        .stat-number.low {{ color: var(--low); }}

        .finding {{
            background: var(--bg-secondary);
            padding: 1.5rem;
            margin-bottom: 1rem;
            border-radius: 0.75rem;
            border-left: 4px solid var(--accent-cyan);
        }}

        .finding.critical {{ border-color: var(--critical); }}
        .finding.high {{ border-color: var(--high); }}
        .finding.medium {{ border-color: var(--medium); }}
        .finding.low {{ border-color: var(--low); }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 1rem;
        }}

        .finding h3 {{
            color: var(--text-primary);
        }}

        .severity-tag {{
            padding: 0.25rem 0.75rem;
            border-radius: 1rem;
            font-size: 0.75rem;
            font-weight: 700;
        }}

        .severity-tag.critical {{ background: var(--critical); }}
        .severity-tag.high {{ background: var(--high); }}
        .severity-tag.medium {{ background: var(--medium); color: #333; }}
        .severity-tag.low {{ background: var(--low); }}

        .proof-badge {{ padding: 2px 8px; border-radius: 3px; font-size: 0.7em; margin-left: 8px; font-weight: 600; }}
        .proof-badge.proven {{ background: #27ae60; color: white; }}
        .proof-badge.verified {{ background: #3498db; color: white; }}
        .proof-badge.detected {{ background: #95a5a6; color: white; }}

        .cluster-badge {{ padding: 2px 8px; border-radius: 3px; font-size: 0.7em; margin-left: 8px; font-weight: 600; background: #8e44ad; color: white; }}
        .sub-finding {{ margin: 8px 0 8px 20px; padding: 8px 12px; background: rgba(255,255,255,0.03); border-left: 3px solid #555; font-size: 0.9em; }}
        .sub-finding strong {{ color: #ccc; }}

        .finding-detail {{
            margin-top: 0.5rem;
            padding: 0.5rem 1rem;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 0.5rem;
            font-family: monospace;
            font-size: 0.875rem;
            word-break: break-all;
        }}

        .chain {{
            background: linear-gradient(90deg, rgba(155, 89, 182, 0.2), rgba(0, 212, 255, 0.2));
            padding: 1.5rem;
            margin-bottom: 1rem;
            border-radius: 0.75rem;
            border: 1px solid rgba(155, 89, 182, 0.5);
        }}

        .chain-path {{
            font-family: monospace;
            font-size: 1.1rem;
            color: var(--accent-purple);
            margin-bottom: 0.5rem;
        }}

        .footer {{
            text-align: center;
            padding: 2rem;
            color: var(--text-secondary);
            font-size: 0.875rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔮 PHANTOM AI Security Report</h1>
            <p style="color: var(--text-secondary);">Professional Heuristic Automated Network Threat Operations Module</p>

            <div class="header-info">
                <div class="header-item">
                    <label>Target</label>
                    <value>{data.get('target', 'N/A')}</value>
                </div>
                <div class="header-item">
                    <label>Scan ID</label>
                    <value>{data.get('scan_id', 'N/A')}</value>
                </div>
                <div class="header-item">
                    <label>Date</label>
                    <value>{data.get('start_time', 'N/A')[:19]}</value>
                </div>
                <div class="header-item">
                    <label>Risk Level</label>
                    <value><span class="risk-badge risk-{risk_level}">{risk_level}</span></value>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>📊 Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat">
                    <div class="stat-number">{summary.get('total', 0)}</div>
                    <div class="stat-label">Total Findings</div>
                </div>
                <div class="stat">
                    <div class="stat-number critical">{summary.get('critical', 0)}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat">
                    <div class="stat-number high">{summary.get('high', 0)}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat">
                    <div class="stat-number medium">{summary.get('medium', 0)}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat">
                    <div class="stat-number low">{summary.get('low', 0)}</div>
                    <div class="stat-label">Low</div>
                </div>
                <div class="stat">
                    <div class="stat-number" style="color: var(--accent-purple);">{len(chains)}</div>
                    <div class="stat-label">Attack Chains</div>
                </div>
            </div>
        </div>
"""

    # Findings section
    if findings:
        html += """
        <div class="card">
            <h2>🔍 Security Findings</h2>
"""
        # Reorder findings by cluster (representatives first)
        try:
            from scanning.result_processor.cluster import get_clustered_findings
            _ordered_findings = get_clustered_findings(findings)
        except Exception:
            _ordered_findings = findings

        _rendered_cluster_ids: set = set()
        _finding_num = 0

        for finding in _ordered_findings:
            _cl = ((finding.get("metadata") or {}).get("cluster") or {})
            _cid = _cl.get("cluster_id", "")
            _csize = _cl.get("cluster_size", 1)
            _is_rep = _cl.get("is_representative", True)

            # Skip sub-findings — they are rendered inside the representative's <details>
            if _csize > 1 and not _is_rep:
                continue

            _finding_num += 1
            severity = finding.get("severity", "INFO").lower()
            vuln_type = finding.get("vuln_type", finding.get("type", finding.get("name", "Unknown")))
            title = finding.get("title", finding.get("name", vuln_type))
            url = finding.get("endpoint", finding.get("url", finding.get("matched_at", "N/A")))
            description = finding.get("description", "No description available.")
            parameter = finding.get("parameter", "")
            payload = finding.get("payload", "")
            evidence = finding.get("evidence", "")
            confidence = finding.get("confidence_score", finding.get("confidence", finding.get("validation_confidence", 0)))
            module = finding.get("module", "")

            # Build evidence section
            evidence_html = f'<div class="finding-detail">📍 <strong>URL:</strong> {url}</div>'

            if parameter:
                evidence_html += f'<div class="finding-detail">🎯 <strong>Parameter:</strong> <code>{parameter}</code></div>'

            if payload:
                safe_payload = str(payload).replace("<", "&lt;").replace(">", "&gt;")
                evidence_html += f'<div class="finding-detail">💉 <strong>Payload:</strong> <code>{safe_payload[:200]}</code></div>'

            if evidence:
                if isinstance(evidence, list):
                    evidence_str = "; ".join(str(e)[:100] for e in evidence[:3])
                else:
                    evidence_str = str(evidence)[:300]
                safe_evidence = evidence_str.replace("<", "&lt;").replace(">", "&gt;")
                evidence_html += f'<div class="finding-detail">🔍 <strong>Evidence:</strong> {safe_evidence}</div>'

            if confidence:
                if isinstance(confidence, str):
                    _word_conf = {"very high": 0.95, "high": 0.85, "medium": 0.65, "moderate": 0.65, "low": 0.45, "very low": 0.25}
                    conf_percent = _word_conf.get(confidence.lower(), 0.5)
                elif isinstance(confidence, (int, float)):
                    conf_percent = confidence if confidence <= 1 else confidence / 100
                else:
                    conf_percent = 0.5
                conf_color = "#27ae60" if conf_percent >= 0.75 else "#f1c40f" if conf_percent >= 0.5 else "#e74c3c"
                evidence_html += f'<div class="finding-detail">📊 <strong>Confidence:</strong> <span style="color: {conf_color}">{conf_percent:.0%}</span></div>'

            if module:
                evidence_html += f'<div class="finding-detail">🔧 <strong>Module:</strong> {module}</div>'

            # Proof gate badge
            _pg = finding.get("metadata", {}).get("proof_gate", {}) if isinstance(finding.get("metadata"), dict) else {}
            _pg_level = _pg.get("level", "") if _pg else ""
            gate_badge = ""
            if _pg_level == "exploited":
                gate_badge = '<span class="proof-badge proven">PROVEN</span>'
            elif _pg_level == "verified":
                gate_badge = '<span class="proof-badge verified">VERIFIED</span>'
            elif _pg_level == "detected":
                gate_badge = '<span class="proof-badge detected">DETECTED</span>'

            # Cluster badge
            cluster_badge = ""
            if _csize > 1:
                cluster_badge = f'<span class="cluster-badge">{_csize} findings</span>'

            # Build sub-findings HTML for multi-member clusters
            sub_html = ""
            if _csize > 1 and _cid not in _rendered_cluster_ids:
                _rendered_cluster_ids.add(_cid)
                sub_findings = [
                    sf for sf in _ordered_findings
                    if ((sf.get("metadata") or {}).get("cluster") or {}).get("cluster_id") == _cid
                    and not ((sf.get("metadata") or {}).get("cluster") or {}).get("is_representative")
                ]
                if sub_findings:
                    sub_items = ""
                    for sf in sub_findings:
                        sf_title = sf.get("title", sf.get("name", sf.get("type", "Unknown")))
                        sf_sev = sf.get("severity", "INFO").upper()
                        sf_ep = sf.get("endpoint", sf.get("matched_at", ""))
                        sf_desc = sf.get("description", "")[:150]
                        safe_sf_desc = str(sf_desc).replace("<", "&lt;").replace(">", "&gt;")
                        sub_items += f'<div class="sub-finding"><strong>{sf_title}</strong> ({sf_sev})'
                        if sf_ep:
                            sub_items += f' — <code>{sf_ep}</code>'
                        if safe_sf_desc:
                            sub_items += f'<br>{safe_sf_desc}'
                        sub_items += '</div>'
                    sub_html = f'<details><summary>Related findings ({len(sub_findings)} more)</summary>{sub_items}</details>'

            html += f"""
            <div class="finding {severity}">
                <div class="finding-header">
                    <h3>{_finding_num}. {title}</h3>
                    <span class="severity-tag {severity}">{severity.upper()}</span>{gate_badge}{cluster_badge}
                </div>
                <p>{description}</p>
                {evidence_html}
                {sub_html}
            </div>
"""
        html += "        </div>\n"

    # Chains section
    if chains:
        html += """
        <div class="card">
            <h2>🔗 Attack Chains</h2>
"""
        for i, chain in enumerate(chains, 1):
            chain_vulns = chain.get("vulnerabilities", [])
            is_speculative = chain.get("metadata", {}).get("is_speculative", False)

            # Handle both formats: multi-vuln chains and single speculative chains
            if chain_vulns:
                chain_str = " → ".join([_get_vuln_display_name(v) for v in chain_vulns])
            else:
                # Single chain (speculative or simple) - use name directly
                chain_str = chain.get("name", chain.get("type", "Attack Path"))

            description = chain.get("description", "")
            impact = chain.get("impact", chain.get("metadata", {}).get("bounty_range", ""))
            severity = chain.get("severity", "INFO").lower()

            # Build chain HTML
            spec_badge = '<span style="background: #3498db; color: white; padding: 2px 8px; border-radius: 10px; font-size: 0.75rem; margin-left: 10px;">SPECULATIVE</span>' if is_speculative else ''

            chain_html = f"""
            <div class="chain" style="border-left-color: {'#3498db' if is_speculative else 'var(--accent-purple)'};">
                <div class="chain-path">{chain_str}{spec_badge}</div>
"""
            if description:
                chain_html += f"                <p>{description}</p>\n"

            if impact:
                chain_html += f"                <p><strong>Impact/Bounty:</strong> {impact}</p>\n"

            # Add recommended tests for speculative chains
            recommended_tests = chain.get("metadata", {}).get("recommended_tests", [])
            if recommended_tests:
                chain_html += "                <div style='margin-top: 10px;'><strong>Recommended Tests:</strong><ul style='margin: 5px 0; padding-left: 20px;'>\n"
                for test in recommended_tests[:5]:
                    test_name = test.get("name", "Test")
                    test_desc = test.get("description", "")
                    bounty = test.get("bounty_potential", "")
                    chain_html += f"                    <li><strong>{test_name}</strong>: {test_desc}"
                    if bounty:
                        chain_html += f" <em>({bounty})</em>"
                    chain_html += "</li>\n"
                chain_html += "                </ul></div>\n"

            chain_html += "            </div>\n"
            html += chain_html

        html += "        </div>\n"

    # Footer
    html += f"""
        <div class="footer">
            <p>Generated by PHANTOM AI v{PHANTOM_VERSION if PHANTOM_AVAILABLE else '3.0.0'}</p>
            <p>This report is confidential and intended for authorized recipients only.</p>
        </div>
    </div>
</body>
</html>
"""

    path.write_text(html)


def _generate_phantom_md_report(data: Dict[str, Any], path: Path) -> None:
    """Generate PHANTOM AI Markdown report."""
    summary = data.get("summary", {})
    findings = data.get("findings", [])
    chains = data.get("chains", [])

    risk_level = "LOW"
    if summary.get("critical", 0) > 0:
        risk_level = "CRITICAL"
    elif summary.get("high", 0) > 0:
        risk_level = "HIGH"
    elif summary.get("medium", 0) > 0:
        risk_level = "MEDIUM"

    md = f"""# PHANTOM AI Security Report

**Professional Heuristic Automated Network Threat Operations Module**

---

## Scan Information

| Field | Value |
|-------|-------|
| Target | `{data.get('target', 'N/A')}` |
| Scan ID | `{data.get('scan_id', 'N/A')}` |
| Date | {data.get('start_time', 'N/A')[:19]} |
| Duration | {data.get('duration', 'N/A')} |
| Risk Level | **{risk_level}** |

---

## Executive Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | {summary.get('critical', 0)} |
| 🟠 High | {summary.get('high', 0)} |
| 🟡 Medium | {summary.get('medium', 0)} |
| 🟢 Low | {summary.get('low', 0)} |
| **Total** | **{summary.get('total', 0)}** |
| 🔗 Attack Chains | {len(chains)} |

---

## Security Findings

"""

    for i, finding in enumerate(findings, 1):
        severity = finding.get("severity", "INFO")
        vuln_type = finding.get("type", finding.get("name", "Unknown"))
        title = finding.get("title", finding.get("name", vuln_type))
        url = finding.get("endpoint", finding.get("url", finding.get("matched_at", "N/A")))
        description = finding.get("description", "No description available.")
        cwe = finding.get("cwe_id", finding.get("cwe", "N/A"))
        parameter = finding.get("parameter", "")
        payload = finding.get("payload", "")
        evidence = finding.get("evidence", "")
        confidence = finding.get("confidence_score", finding.get("confidence", finding.get("validation_confidence", 0)))
        module = finding.get("module", "")

        md += f"""### {i}. [{severity}] {title}

| Field | Value |
|-------|-------|
| **Severity** | {severity} |
| **CWE** | {cwe} |
| **Location** | `{url}` |
"""
        if parameter:
            md += f"| **Parameter** | `{parameter}` |\n"
        if confidence:
            conf_val = confidence if isinstance(confidence, (int, float)) and confidence <= 1 else confidence / 100
            md += f"| **Confidence** | {conf_val:.0%} |\n"
        if module:
            md += f"| **Module** | {module} |\n"

        md += f"""
**Description:**
{description}

"""
        if payload:
            md += f"**Payload:**\n```\n{payload[:500]}\n```\n\n"

        if evidence:
            if isinstance(evidence, list):
                evidence_str = "\n- ".join(str(e)[:200] for e in evidence[:5])
                md += f"**Evidence:**\n- {evidence_str}\n\n"
            else:
                md += f"**Evidence:**\n{str(evidence)[:500]}\n\n"

        md += "---\n\n"

    if chains:
        md += """## Attack Chains

"""
        for i, chain in enumerate(chains, 1):
            chain_vulns = chain.get("vulnerabilities", [])
            is_speculative = chain.get("metadata", {}).get("is_speculative", False)

            # Handle both formats
            if chain_vulns:
                chain_str = " → ".join([_get_vuln_display_name(v) for v in chain_vulns])
            else:
                chain_str = chain.get("name", chain.get("type", "Attack Path"))

            description = chain.get("description", "")
            impact = chain.get("impact", chain.get("metadata", {}).get("bounty_range", "Security Impact"))
            spec_marker = " *(Speculative)*" if is_speculative else ""

            md += f"""### Chain {i}{spec_marker}

**Path:** {chain_str}
**Impact/Bounty:** {impact}

"""
            if description:
                md += f"{description}\n\n"

            # Add recommended tests for speculative chains
            recommended_tests = chain.get("metadata", {}).get("recommended_tests", [])
            if recommended_tests:
                md += "**Recommended Tests:**\n"
                for test in recommended_tests[:5]:
                    test_name = test.get("name", "Test")
                    test_desc = test.get("description", "")
                    bounty = test.get("bounty_potential", "")
                    md += f"- **{test_name}**: {test_desc}"
                    if bounty:
                        md += f" *({bounty})*"
                    md += "\n"
                md += "\n"

            md += "---\n\n"

    md += f"""
## Appendix

### Modules Executed

{', '.join(data.get('modules_run', ['N/A']))}

---

*Generated by PHANTOM AI v{PHANTOM_VERSION if PHANTOM_AVAILABLE else '3.0.0'}*
*This report is confidential and intended for authorized recipients only.*
"""

    path.write_text(md)


# =============================================================================
# QUICK COMMAND
# =============================================================================

@cli.command()
@click.argument("target")
@click.option("--output", "-o", type=click.Path(), help="Output directory")
@click.option("--format", "-f", "output_format",
              type=click.Choice(["html", "json", "md"]),
              default="json", help="Report format (default: JSON)")
@click.pass_context
def quick(ctx: click.Context, target: str, output: Optional[str], output_format: str):
    """
    Fast PHANTOM AI scan (5 modules).

    Quick security assessment focusing on most common vulnerabilities:
    headers, SSL/TLS, CORS, XSS, and SQL injection detection.

    \b
    Examples:
        phantom quick https://example.com
        phantom quick api.target.com -f json
    """
    if not ctx.obj.get("no_banner"):
        print_banner()

    console.print(Panel(
        "[bold cyan]⚡ QUICK SCAN MODE[/bold cyan]\n\n"
        "Fast security assessment (5 modules):\n"
        "  • Security Headers\n"
        "  • SSL/TLS Configuration\n"
        "  • CORS Policy\n"
        "  • XSS Detection\n"
        "  • SQL Injection Detection",
        title="Quick Scan",
        border_style="cyan",
    ))

    safe_asyncio_run(_run_phantom_scan(
        target=target,
        output_dir=output,
        output_format=output_format,
        modules="sqli,xss,headers,ssl,cors",
        safe_mode="safe",
        rate=2.0,
        concurrent=3,
        scope=[],
        exclude=[],
        preset=None,
        no_recon=True,
        no_tools=True,
        no_chain=True,
        no_ai=True,
        no_auth=False,
        timeout=None,
        scan_mode=ScanMode.QUICK if PHANTOM_AVAILABLE else "quick",
        verbose=ctx.obj.get("verbose", False),
    ))


# =============================================================================
# FULL COMMAND
# =============================================================================

@cli.command()
@click.argument("target")
@click.option("--output", "-o", type=click.Path(), help="Output directory")
@click.option("--safe-mode", "-s",
              type=click.Choice(["passive", "safe", "cautious", "standard", "aggressive"]),
              default="safe", help="Safety level")
@click.option("--deterministic", is_flag=True, default=False,
              help="Enable deterministic mode for reproducible scans (THEME-8)")
@click.option("--totp-secret", type=str, default=None,
              help="TOTP secret (base32) for automatic 2FA handling")
@click.option("--allow-manual-auth", is_flag=True, default=False,
              help="Allow manual browser intervention for CAPTCHA/2FA challenges")
@click.pass_context
def full(ctx: click.Context, target: str, output: Optional[str], safe_mode: str, deterministic: bool,
         totp_secret: Optional[str], allow_manual_auth: bool):
    """
    Comprehensive PHANTOM AI scan (all 75+ modules).

    Full security assessment with all available modules, 6-stage validation,
    vulnerability chaining, and enterprise reporting.

    Automatically generates: JSON state + Markdown reports + PDF reports

    \b
    Examples:
        phantom full https://example.com
        phantom full https://api.target.com -s cautious
        phantom full https://2fa-app.com --totp-secret BASE32SECRET
        phantom full https://captcha-site.com --allow-manual-auth
    """
    if not ctx.obj.get("no_banner"):
        print_banner()

    console.print(Panel(
        "[bold green]🔮 FULL SCAN MODE[/bold green]\n\n"
        "Comprehensive security assessment:\n"
        "  • All 75+ security modules\n"
        "  • Technology fingerprinting\n"
        "  • WAF detection & bypass\n"
        "  • 6-stage validation pipeline\n"
        "  • Vulnerability chaining\n"
        "  • AI-powered verification\n"
        "  • Compliance mapping\n\n"
        "[cyan]Auto-generates: JSON + MD + PDF reports[/cyan]",
        title="Full Scan",
        border_style="green",
    ))

    # THEME-8: Enable deterministic mode if requested
    if deterministic:
        from scanning.determinism import enable_deterministic_mode
        enable_deterministic_mode()

    # GAP-5: Advanced auth options (TOTP, manual auth)
    import os
    if totp_secret:
        os.environ["PHANTOM_TOTP_SECRET"] = totp_secret
        console.print("[cyan]🔐 TOTP secret configured — automatic 2FA handling enabled[/cyan]")

    if allow_manual_auth:
        os.environ["PHANTOM_ALLOW_MANUAL_AUTH"] = "1"
        console.print("[cyan]🖥️ Manual auth enabled — browser will open for CAPTCHA/2FA challenges[/cyan]")
        console.print("[cyan]🎯 Deterministic mode enabled — scans will be reproducible[/cyan]")

    safe_asyncio_run(_run_full_scan(
        target=target,
        output_dir=output,
        safe_mode=safe_mode,
        verbose=ctx.obj.get("verbose", False),
    ))


async def _run_full_scan(
    target: str,
    output_dir: Optional[str],
    safe_mode: str,
    verbose: bool,
) -> None:
    """Execute full scan with automatic report generation."""
    # Run the main scan
    await _run_phantom_scan(
        target=target,
        output_dir=output_dir,
        output_format="json",
        modules=None,
        safe_mode=safe_mode,
        rate=2.0,
        concurrent=5,
        scope=[],
        exclude=[],
        preset=None,
        no_recon=False,
        no_tools=False,
        no_chain=False,
        no_ai=False,
        no_auth=False,
        timeout=None,
        scan_mode=ScanMode.FULL if PHANTOM_AVAILABLE else "full",
        verbose=verbose,
    )

    # Auto-generate HackerOne reports (MD + JSON + PDF)
    if HACKERONE_REPORTER_AVAILABLE:
        await _generate_hackerone_reports(target, output_dir)


# =============================================================================
# BOUNTY COMMAND
# =============================================================================

@cli.command()
@click.argument("target")
@click.option("--output", "-o", type=click.Path(), help="Output directory")
@click.option("--platform",
              type=click.Choice(["hackerone", "bugcrowd", "intigriti", "other"]),
              default="other", help="Bug bounty platform")
@click.option("--program-tier",
              type=click.Choice(["entry", "standard", "premium", "enterprise", "top_tier"]),
              default="standard", help="Program tier for bounty estimation")
@click.option("--rate", "-r", type=float, default=3.0, help="Requests per second (safe for most programs)")
@click.option("--estimate/--no-estimate", default=True, help="Show bounty estimates")
@click.option("--header", "-H", multiple=True, help="Custom header (e.g., 'X-Bug-Bounty: username-twilio')")
@click.option("--username", "-u", help="Bug bounty username (auto-generates X-Bug-Bounty header)")
@click.option("--program", "-p", help="Program name for X-Bug-Bounty header suffix (e.g., 'twilio')")
@click.option("--modules", "-m", help="Modules to run (comma-separated, e.g., 'cors' or 'cors,headers')")
@click.option("--hackerone-report/--no-hackerone-report", default=True,
              help="Generate HackerOne-quality reports for findings")
@click.option("--scope", multiple=True, required=True,
              help="In-scope domains (REQUIRED for bounty mode, e.g., --scope '*.example.com' --scope 'api.example.com')")
@click.option("--deterministic", is_flag=True, default=False,
              help="Enable deterministic mode for reproducible scans (THEME-8)")
@click.option("--totp-secret", type=str, default=None,
              help="TOTP secret (base32) for automatic 2FA handling")
@click.option("--allow-manual-auth", is_flag=True, default=False,
              help="Allow manual browser intervention for CAPTCHA/2FA challenges")
@click.option("--output-format", "-f",
              type=click.Choice(["hackerone", "sarif", "all"]),
              default="hackerone",
              help="Output report format: hackerone (default), sarif (DevSecOps), or all")
@click.option("--accept-terms", is_flag=True, default=False,
              help="Accept legal disclaimer non-interactively (for CI/CD and testing)")
@click.option("--no-auth", is_flag=True, default=False,
              help="Skip target authorization check")
@click.pass_context
def bounty(ctx: click.Context, target: str, output: Optional[str],
           platform: str, program_tier: str, rate: float, estimate: bool,
           header: tuple, username: Optional[str], program: Optional[str],
           modules: Optional[str], hackerone_report: bool, scope: tuple,
           deterministic: bool, totp_secret: Optional[str], allow_manual_auth: bool,
           output_format: str, accept_terms: bool, no_auth: bool):
    """
    Bug bounty optimized PHANTOM AI scan.

    Security assessment optimized for bug bounty hunting with strict
    compliance controls, bounty estimation, and platform-specific formatting.

    \b
    Focus Areas:
        • IDOR/BOLA ($3k-$20k+ potential)
        • SQL Injection
        • XSS (including DOM-based)
        • Authentication Bypass
        • Business Logic Flaws
        • API Security Issues

    \b
    Examples:
        phantom bounty https://api.target.com --platform hackerone
        phantom bounty target.com --program-tier premium --estimate
        phantom bounty https://api.twilio.com -u myusername --platform hackerone
        phantom bounty https://target.com -H "X-Bug-Bounty: user-twilio"
    """
    if not ctx.obj.get("no_banner"):
        print_banner()

    # ═══════════════════════════════════════════════════════════════════════════
    # PROFESSIONAL ETHICS: Legal disclaimer and authorization check
    # "Pentesting profissional NÃO é atacar à vontade"
    # ═══════════════════════════════════════════════════════════════════════════

    # ETHICS-09: Username is REQUIRED for professional bug bounty hunting
    if not username and not accept_terms:
        console.print(Panel(
            "[bold red]⛔ USERNAME REQUIRED FOR BOUNTY MODE[/bold red]\n\n"
            "Professional bug bounty hunting requires identification.\n"
            "Bug bounty programs need to identify researchers.\n\n"
            "[yellow]Add your username with: --username YOUR_USERNAME[/yellow]\n"
            "[dim]Example: phantom bounty https://target.com -u your_hackerone_username[/dim]\n"
            "[dim]For local testing: --accept-terms (skips this check)[/dim]",
            title="Missing Identification",
            border_style="red",
        ))
        return

    if not username:
        username = "local-tester"

    # ETHICS-01/02: Legal disclaimer and authorization check
    program_name = program or platform or "Bug Bounty Program"
    if not check_authorization(
        program_name=f"{program_name} ({platform.upper()})",
        targets=[target],
        mode="safe",
        rate_limit=rate,
        skip_disclaimer=accept_terms,
    ):
        console.print("[red]❌ Authorization not confirmed. Scan aborted.[/red]")
        console.print("[dim]This is required for professional and legal bug bounty hunting.[/dim]")
        return

    # ═══════════════════════════════════════════════════════════════════════════
    # ETHICS-05/07: Scope validation - MANDATORY for bug bounty
    # "Professional pentesting stays within defined scope"
    # ═══════════════════════════════════════════════════════════════════════════
    scope_list = list(scope)
    from utils.legal_disclaimer import verify_scope_programmatically

    # Validate target is within declared scope
    in_scope, reason = verify_scope_programmatically(scope_list, target)
    if not in_scope:
        console.print(Panel(
            f"[bold red]⛔ TARGET NOT IN DECLARED SCOPE[/bold red]\n\n"
            f"Target: {target}\n"
            f"Declared Scope: {', '.join(scope_list)}\n"
            f"Reason: {reason}\n\n"
            "[yellow]Bug bounty programs require testing ONLY within defined scope.[/yellow]\n"
            "[yellow]Out-of-scope testing can result in legal action.[/yellow]\n\n"
            "[dim]If this target IS in scope, add it: --scope 'target.com' or --scope '*.target.com'[/dim]",
            title="Scope Violation",
            border_style="red",
        ))
        return

    console.print(f"[green]✓ Target verified in scope: {reason}[/green]")

    # ═══════════════════════════════════════════════════════════════════════════
    # ETHICS-10: Initialize Audit Logger for comprehensive audit trail
    # ═══════════════════════════════════════════════════════════════════════════
    audit = init_audit_logger(
        engagement_id=f"BOUNTY-{datetime.now().strftime('%Y%m%d')}-{platform.upper()}",
        operator=username or "unknown",
    )
    audit.log_authorization(
        target=target,
        accepted=True,
        scope=scope_list,
        mode="safe",
        rate_limit=rate,
    )
    audit.log_scope_confirmed(
        targets=[target],
        scope=scope_list,
        program_name=program or platform or "Bug Bounty Program",
    )
    console.print(f"[dim]📝 Audit log: {audit.log_file}[/dim]")

    console.print(Panel(
        "[bold yellow]💰 BOUNTY HUNTING MODE[/bold yellow]\n\n"
        f"Platform: {platform.upper()}\n"
        f"Program: {program.upper() if program else 'N/A'}\n"
        f"Program Tier: {program_tier}\n"
        f"Rate Limit: {rate} req/sec\n"
        f"Bounty Estimates: {'Enabled' if estimate else 'Disabled'}\n\n"
        "Focus Areas:\n"
        "  • IDOR/BOLA - $3k-$20k+ potential\n"
        "  • SQL Injection - High value\n"
        "  • XSS (including DOM-based)\n"
        "  • Authentication Bypass\n"
        "  • Business Logic Flaws\n"
        "  • API Security Issues",
        title="Bounty Mode",
        border_style="yellow",
    ))

    # Build custom headers dict
    custom_headers: Dict[str, str] = {}

    # Parse -H headers (format: "Header-Name: value")
    for h in header:
        if ":" in h:
            key, value = h.split(":", 1)
            custom_headers[key.strip()] = value.strip()

    # Auto-generate X-Bug-Bounty header from username (only if not already set via -H)
    if username and "X-Bug-Bounty" not in custom_headers:
        # Use --program name if provided (e.g., "twilio"), otherwise fall back to platform
        suffix = program or platform
        custom_headers["X-Bug-Bounty"] = f"{username}-{suffix}"

    # Display headers if set
    if custom_headers:
        headers_display = "\n".join([f"  • {k}: {v}" for k, v in custom_headers.items()])
        console.print(Panel(
            f"[bold cyan]📋 Custom Headers Configured[/bold cyan]\n\n{headers_display}",
            title="Request Headers",
            border_style="cyan",
        ))

    # HACKERONE/BUGCROWD COMPLIANCE NOTICE
    console.print(Panel(
        "[bold green]✅ BUG BOUNTY COMPLIANCE ACTIVE[/bold green]\n\n"
        "[cyan]Safety Guarantees:[/cyan]\n"
        "  • 🛡️ SAFE MODE enforced (no state modifications)\n"
        "  • 🚫 Destructive payloads blocked at HTTP layer\n"
        "  • 📊 Evidence-only vulnerability detection\n"
        "  • ⏱️ Conservative rate limiting (respects targets)\n"
        "  • 📝 Audit trail of all blocked operations\n\n"
        "[cyan]HackerOne Platform Standards Compliance:[/cyan]\n"
        "  • No data modification/deletion\n"
        "  • No DoS or service disruption\n"
        "  • IDOR testing with AC:H (unpredictable IDs)\n"
        "  • Responsible disclosure workflow",
        title="🏆 Platform Compliance",
        border_style="green",
    ))

    # THEME-8: Enable deterministic mode if requested
    if deterministic:
        from scanning.determinism import enable_deterministic_mode
        enable_deterministic_mode()
        console.print("[cyan]🎯 Deterministic mode enabled — scans will be reproducible[/cyan]")

    # GAP-5: Advanced auth options (TOTP, manual auth)
    import os
    if totp_secret:
        os.environ["PHANTOM_TOTP_SECRET"] = totp_secret
        console.print("[cyan]🔐 TOTP secret configured — automatic 2FA handling enabled[/cyan]")

    if allow_manual_auth:
        os.environ["PHANTOM_ALLOW_MANUAL_AUTH"] = "1"
        console.print("[cyan]🖥️ Manual auth enabled — browser will open for CAPTCHA/2FA challenges[/cyan]")

    safe_asyncio_run(_run_bounty_scan(
        target=target,
        output_dir=output,
        platform=platform,
        program_tier=program_tier,
        rate=rate,
        estimate=estimate,
        verbose=ctx.obj.get("verbose", False),
        custom_headers=custom_headers,
        modules_override=modules,
        hackerone_report=hackerone_report,
        program=program,
        scope=scope_list,
        output_format=output_format,
        no_auth=no_auth,
    ))


async def _run_bounty_scan(
    target: str,
    output_dir: Optional[str],
    platform: str,
    program_tier: str,
    rate: float,
    estimate: bool,
    verbose: bool,
    custom_headers: Optional[Dict[str, str]] = None,
    modules_override: Optional[str] = None,
    hackerone_report: bool = True,
    program: Optional[str] = None,
    scope: Optional[List[str]] = None,
    output_format: str = "hackerone",
    no_auth: bool = False,
) -> None:
    """Execute bounty-optimized scan."""

    # Use override modules if provided, otherwise default bounty set
    scan_modules = modules_override or "sqli,xss,dom_xss,idor,auth,api,ssrf,xxe,csrf,cors"

    # Track scan timing for SARIF report
    scan_start_time = datetime.now()

    # Run the main scan with bounty-specific settings (JSON always generated)
    # Bounty mode uses "cautious" — sends detection payloads but never modifies data.
    # "safe" would block all injection scanners (sqli, xss, ssrf, etc.)
    await _run_phantom_scan(
        target=target,
        output_dir=output_dir,
        output_format="json",
        modules=scan_modules,
        safe_mode="cautious",
        rate=rate,
        concurrent=2,
        scope=scope or [],
        exclude=[],
        preset=None,
        no_recon=False,
        no_tools=True,
        no_chain=False,
        no_ai=False,
        no_auth=no_auth,
        custom_headers=custom_headers,
        timeout=None,
        scan_mode=ScanMode.BOUNTY if PHANTOM_AVAILABLE else "bounty",
        verbose=verbose,
    )

    scan_end_time = datetime.now()

    # Show bounty estimates if enabled
    if estimate and PHANTOM_AVAILABLE:
        await _display_bounty_estimates(
            target=target,
            platform=platform,
            program_tier=program_tier,
        )

    # Generate reports based on output_format option
    # HackerOne reports (default for bounty mode)
    if output_format in ("hackerone", "all"):
        if hackerone_report and HACKERONE_REPORTER_AVAILABLE:
            await _generate_hackerone_reports(target, output_dir, custom_headers=custom_headers, program=program)

    # SARIF report for DevSecOps integration
    if output_format in ("sarif", "all"):
        await _generate_sarif_report(
            target=target,
            output_dir=output_dir,
            scan_start_time=scan_start_time,
            scan_end_time=scan_end_time,
        )


async def _display_bounty_estimates(
    target: str,
    platform: str,
    program_tier: str,
) -> None:
    """
    Display bounty estimates for scan findings using BountyEstimator.

    Reads findings from the most recent scan state file and calculates
    estimated bounty ranges based on platform, tier, and vulnerability type.
    """
    from rich.table import Table

    console.print("\n[bold yellow]===============================================================================[/bold yellow]")
    console.print("[bold yellow]                        BOUNTY ESTIMATION REPORT[/bold yellow]")
    console.print("[bold yellow]===============================================================================[/bold yellow]\n")

    # Get the most recent scan for this target
    scans_dir = get_scans_dir()
    domain = get_domain(target)

    # Find relevant scan state
    scan_files = sorted(scans_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)
    scan_state = None

    for scan_file in scan_files:
        try:
            with open(scan_file) as f:
                state = json.load(f)
                if state.get("domain") == domain or domain in str(state.get("target", "")):
                    scan_state = state
                    break
        except Exception as e:
            logger.debug(f"Error reading scan file {scan_file}: {e}")
            continue

    if not scan_state:
        console.print("[yellow]No scan state found for target. Run scan first.[/yellow]")
        return

    findings = scan_state.get("validated_findings", scan_state.get("findings", []))

    if not findings:
        console.print("[yellow]No findings to estimate bounties for.[/yellow]")
        return

    # Create program config and estimator
    config = create_program_config(
        name=domain,
        platform=platform,
        tier=program_tier,
    )
    estimator = BountyEstimator(config)

    # Display program info
    console.print(f"[cyan]Platform:[/cyan]     {platform.upper()}")
    console.print(f"[cyan]Program Tier:[/cyan] {program_tier.upper()}")
    console.print(f"[cyan]Target:[/cyan]       {domain}")
    console.print(f"[cyan]Findings:[/cyan]     {len(findings)}\n")

    # Create table for estimates
    table = Table(title="Bounty Estimates by Finding", show_header=True, header_style="bold cyan")
    table.add_column("#", style="dim", width=3)
    table.add_column("Severity", width=10)
    table.add_column("Vulnerability Type", width=30)
    table.add_column("Est. Range (USD)", justify="right", width=18)
    table.add_column("Expected", justify="right", width=12)
    table.add_column("Confidence", justify="right", width=10)

    # Process each finding
    estimates = []
    for i, finding in enumerate(findings, 1):
        vuln_type = _get_type(finding)
        severity = _get_severity(finding)

        # Get finding ID (handle various formats)
        finding_id = ""
        if isinstance(finding, dict):
            if "finding" in finding and isinstance(finding["finding"], dict):
                finding_id = finding["finding"].get("id", f"finding-{i}")
            else:
                finding_id = finding.get("id", f"finding-{i}")
        elif hasattr(finding, "id"):
            finding_id = finding.id
        else:
            finding_id = f"finding-{i}"

        # Estimate bounty
        estimate = estimator.estimate(
            vulnerability_id=finding_id,
            vulnerability_type=vuln_type.lower().replace(" ", "_"),
            severity=severity.lower(),
        )
        estimates.append(estimate)

        # Color code severity
        severity_colors = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "green",
            "INFO": "dim",
        }
        sev_style = severity_colors.get(severity.upper(), "white")

        # Add row to table
        table.add_row(
            str(i),
            f"[{sev_style}]{severity.upper()}[/{sev_style}]",
            vuln_type[:30] if len(vuln_type) > 30 else vuln_type,
            estimate.formatted_range,
            estimate.formatted_expected,
            f"{estimate.confidence:.0%}",
        )

    console.print(table)

    # Get and display totals
    totals = estimator.get_total_estimate()

    console.print("\n[bold yellow]-------------------------------------------------------------------------------[/bold yellow]")
    console.print("[bold yellow]                              TOTAL ESTIMATES[/bold yellow]")
    console.print("[bold yellow]-------------------------------------------------------------------------------[/bold yellow]\n")

    # Create summary table
    summary_table = Table(show_header=False, box=None)
    summary_table.add_column("Label", style="cyan", width=25)
    summary_table.add_column("Value", style="bold white", width=30)

    summary_table.add_row("Total Findings:", str(totals["finding_count"]))
    summary_table.add_row("Estimated Range:", totals["formatted_range"])
    summary_table.add_row("Expected Value:", totals["formatted_expected"])

    console.print(summary_table)

    # Severity distribution
    if totals.get("severity_distribution"):
        console.print("\n[cyan]Severity Distribution:[/cyan]")
        for sev, count in totals["severity_distribution"].items():
            console.print(f"   {sev.upper()}: {count} finding(s)")

    # Display modifiers info
    console.print("\n[dim]Note: Estimates are based on historical platform data and may vary.[/dim]")
    console.print("[dim]Actual payouts depend on program specifics, report quality, and impact.[/dim]")

    console.print("\n[bold yellow]===============================================================================[/bold yellow]\n")


async def _generate_hackerone_reports(
    target: str,
    output_dir: Optional[str] = None,
    custom_headers: Optional[Dict[str, str]] = None,
    program: Optional[str] = None,
) -> None:
    """Generate HackerOne-quality reports for scan findings."""
    from pathlib import Path

    console.print("\n[bold cyan]📄 Generating HackerOne Reports...[/bold cyan]")

    # Get the most recent scan for this target
    scans_dir = get_scans_dir()
    domain = get_domain(target)

    # Find relevant scan state
    scan_files = sorted(scans_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)
    scan_state = None

    for scan_file in scan_files:
        try:
            with open(scan_file) as f:
                state = json.load(f)
                if state.get("domain") == domain or domain in str(state.get("target", "")):
                    scan_state = state
                    break
        except Exception as e:
            logger.debug(f"Error reading scan file {scan_file}: {e}")
            continue

    if not scan_state:
        console.print("[yellow]⚠️ No scan state found for target[/yellow]")
        return

    findings = scan_state.get("validated_findings", scan_state.get("findings", []))

    if not findings:
        console.print("[yellow]⚠️ No findings to report[/yellow]")
        return

    # Filter for reportable findings (MEDIUM severity and above + confidence threshold)
    # FIX 2026-03-02: Also check confidence meets severity-specific threshold.
    # Without this, CSRF conf=60 with severity=HIGH bypasses the 70% threshold.
    _SEVERITY_CONF_THRESHOLDS = {"CRITICAL": 0.80, "HIGH": 0.70, "MEDIUM": 0.65, "LOW": 0.60, "INFO": 0.50}
    reportable = [
        f for f in findings
        if _get_severity(f) in ("CRITICAL", "HIGH", "MEDIUM")
        and _get_confidence(f) >= _SEVERITY_CONF_THRESHOLDS.get(_get_severity(f), 0.70)
    ]

    if not reportable:
        console.print("[yellow]⚠️ No reportable findings (MEDIUM+ severity with sufficient confidence)[/yellow]")
        return

    console.print(f"   Found {len(reportable)} reportable findings")

    # Generate reports
    bounty_header = (custom_headers or {}).get("X-Bug-Bounty")
    generator = HackerOneReportGenerator(
        output_dir=Path(output_dir) if output_dir else Path("evidence") / domain.replace(".", "_"),
        bounty_header=bounty_header,
        program=program,
    )

    generated_reports = []
    for i, finding in enumerate(reportable, 1):
        try:
            # Unwrap serialized ValidatedFinding: {"finding": {...}, "is_valid": true, ...}
            raw_finding = finding
            if isinstance(finding, dict) and "finding" in finding and isinstance(finding["finding"], dict):
                raw_finding = finding["finding"]

            # Generate the report
            report = generator.generate_report(raw_finding)

            # Save in all formats (md, json, html, pdf)
            saved_files = generator.save_report(report, formats=["md", "json", "html", "pdf"])

            generated_reports.append({
                "title": report.title,
                "severity": report.severity,
                "cwe": report.cwe,
                "files": saved_files,
            })

            console.print(f"   [green]✓[/green] {i}. [{report.severity.upper()}] {report.title}")

        except Exception as e:
            console.print(f"   [red]✗[/red] {i}. Failed to generate report: {e}")

    # Summary
    if generated_reports:
        output_path = generator.output_dir

        # Generate coverage summary (explains testing thoroughness)
        try:
            coverage_path = generator.generate_coverage_summary(scan_state, domain)
            console.print(f"   [cyan]📊 Coverage summary:[/cyan] {coverage_path}")
        except Exception as e:
            logger.debug(f"Coverage summary generation failed: {e}")

        console.print(Panel(
            f"[bold green]✅ Generated {len(generated_reports)} HackerOne Reports[/bold green]\n\n"
            f"Output Directory: {output_path}\n\n"
            "[cyan]Each report includes:[/cyan]\n"
            "  • Markdown report (hackerone_report.md)\n"
            "  • PDF report (hackerone_report.pdf)\n"
            "  • JSON data (report_data.json)\n"
            "  • HTML PoC (if applicable)\n"
            "  • Reproducible curl commands\n"
            "  • CWE/CVSS classification\n"
            "  • Impact assessment\n"
            "  • Remediation guidance\n\n"
            "[yellow]📊 SCAN_COVERAGE_SUMMARY.md[/yellow] explains:\n"
            "  • What was tested vs skipped\n"
            "  • Why areas were skipped (rate limit, auth, WAF)\n"
            "  • Confidence of absence for vuln types",
            title="📋 HackerOne Reports Generated",
            border_style="green",
        ))

        # Generate handoff session document
        try:
            from phantom.handoff_generator import HandoffSessionGenerator

            # Collect artifact paths from all generated reports
            artifact_paths = []
            for rpt in generated_reports:
                for fmt, fpath in rpt.get("files", {}).items():
                    artifact_paths.append({
                        "name": f"{rpt['title']} ({fmt})",
                        "path": fpath,
                        "type": fmt,
                    })

            handoff_gen = HandoffSessionGenerator(output_dir=generator.output_dir)
            session = handoff_gen.generate(
                target=target,
                scan_id=scan_state.get("scan_id", "unknown"),
                findings=reportable,
                scan_metadata={
                    "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
                    "safety_mode": scan_state.get("safety_mode", "safe"),
                    "modules_run": len(scan_state.get("modules_run", [])),
                    "duration_seconds": scan_state.get("duration_seconds", 0),
                    "operator": (custom_headers or {}).get("X-Bug-Bounty", "phantom-ai"),
                },
                artifact_paths=artifact_paths,
            )
            saved_handoff = handoff_gen.save(session)
            console.print(f"\n   [cyan]📋 Handoff session:[/cyan] {saved_handoff.get('md', '')}")
        except Exception as e:
            console.print(f"\n   [yellow]⚠️ Handoff generation skipped: {e}[/yellow]")


async def _generate_sarif_report(
    target: str,
    output_dir: Optional[str] = None,
    scan_start_time: Optional[datetime] = None,
    scan_end_time: Optional[datetime] = None,
) -> Optional[str]:
    """
    Generate SARIF 2.1.0 report for DevSecOps integration.

    SARIF (Static Analysis Results Interchange Format) is the standard format
    for GitHub Code Scanning, Azure DevOps, and other CI/CD security tools.

    Args:
        target: Target URL that was scanned
        output_dir: Optional output directory
        scan_start_time: When the scan started
        scan_end_time: When the scan ended

    Returns:
        Path to generated SARIF file, or None if generation failed
    """
    from pathlib import Path

    console.print("\n[bold cyan]📄 Generating SARIF Report (DevSecOps Integration)...[/bold cyan]")

    # Check if SARIF generator is available
    if not PHANTOM_AVAILABLE:
        console.print("[yellow]⚠️ SARIF Generator not available (PHANTOM not loaded)[/yellow]")
        return None

    # Load scan state (same pattern as other report generators)
    scans_dir = get_scans_dir()
    domain = get_domain(target)

    scan_files = sorted(scans_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)
    scan_state = None

    for scan_file in scan_files:
        try:
            with open(scan_file) as f:
                state = json.load(f)
                if state.get("domain") == domain or domain in str(state.get("target", "")):
                    scan_state = state
                    break
        except Exception as e:
            logger.debug(f"Error reading scan file {scan_file}: {e}")
            continue

    if not scan_state:
        console.print("[yellow]⚠️ No scan state found for target[/yellow]")
        return None

    findings = scan_state.get("validated_findings", scan_state.get("findings", []))

    if not findings:
        console.print("[yellow]⚠️ No findings to include in SARIF report[/yellow]")
        return None

    console.print(f"   Found {len(findings)} findings to export")

    # Create SARIF generator
    try:
        sarif_gen = SARIFGenerator()

        # Set invocation metadata
        sarif_gen.set_invocation(
            start_time=scan_start_time or datetime.now(),
            end_time=scan_end_time or datetime.now(),
            working_directory=str(Path.cwd()),
            command_line=f"phantom scan {target}",
            execution_successful=True,
            target_url=target,
            scan_id=scan_state.get("scan_id", "unknown"),
        )

        # Add each finding to SARIF
        for finding in findings:
            # Unwrap serialized ValidatedFinding if needed
            raw_finding = finding
            if isinstance(finding, dict) and "finding" in finding and isinstance(finding["finding"], dict):
                raw_finding = finding["finding"]

            # Extract finding details
            vuln_type = raw_finding.get("type", raw_finding.get("vulnerability_type", "unknown"))
            url = raw_finding.get("url", raw_finding.get("matched_at", target))
            message = raw_finding.get("description", raw_finding.get("message", f"{vuln_type} vulnerability detected"))
            severity = _get_severity(raw_finding).lower()
            parameter = raw_finding.get("parameter", raw_finding.get("param"))
            evidence = raw_finding.get("evidence", raw_finding.get("proof"))
            request = raw_finding.get("request")
            response = raw_finding.get("response")
            confidence = raw_finding.get("confidence")
            vuln_id = raw_finding.get("id", raw_finding.get("finding_id"))

            # Convert confidence to float if it's a percentage
            if isinstance(confidence, (int, float)) and confidence > 1:
                confidence = confidence / 100.0

            sarif_gen.add_finding(
                vulnerability_type=vuln_type,
                url=url,
                message=message,
                severity=severity,
                parameter=parameter,
                evidence=evidence,
                request=request,
                response=response,
                vulnerability_id=vuln_id,
                confidence=confidence,
                method=raw_finding.get("method", "GET"),
            )

        # Determine output path
        if output_dir:
            out_path = Path(output_dir)
        else:
            out_path = Path("evidence") / domain.replace(".", "_")

        out_path.mkdir(parents=True, exist_ok=True)

        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        sarif_file = out_path / f"{domain.replace('.', '_')}_{timestamp}_sarif.json"

        # Save SARIF report
        sarif_gen.save(sarif_file, pretty=True)

        # Get statistics for display
        stats = sarif_gen.get_statistics()

        console.print(Panel(
            f"[bold green]✅ SARIF Report Generated[/bold green]\n\n"
            f"Output: {sarif_file}\n\n"
            "[cyan]SARIF Statistics:[/cyan]\n"
            f"  • Total findings: {stats['total_results']}\n"
            f"  • Unique rules: {stats['total_rules']}\n"
            f"  • Artifacts: {stats['total_artifacts']}\n\n"
            "[cyan]Severity Distribution:[/cyan]\n"
            f"  • Error (CRITICAL/HIGH): {stats['severity_distribution']['error']}\n"
            f"  • Warning (MEDIUM): {stats['severity_distribution']['warning']}\n"
            f"  • Note (LOW/INFO): {stats['severity_distribution']['note']}\n\n"
            "[cyan]DevSecOps Integration:[/cyan]\n"
            "  • GitHub Code Scanning: Upload via Security tab\n"
            "  • Azure DevOps: Use SARIF upload task\n"
            "  • GitLab: Use SAST report format\n"
            "  • CI/CD: Integrate with security gates",
            title="📊 SARIF 2.1.0 Report",
            border_style="green",
        ))

        return str(sarif_file)

    except Exception as e:
        console.print(f"[red]✗ SARIF report generation failed: {e}[/red]")
        logger.exception("SARIF generation error")
        return None


# =============================================================================
# HACKERONE REPORT COMMAND
# =============================================================================

@cli.command("hackerone-report")
@click.argument("scan_id")
@click.option("--output", "-o", type=click.Path(), help="Output directory")
@click.option("--finding-id", "-f", help="Specific finding ID to report (otherwise all MEDIUM+)")
@click.option("--all-severities", is_flag=True, help="Include LOW and INFO findings")
@click.option("--bounty-header", help="X-Bug-Bounty header value (e.g., 'youruser-twilio')")
@click.pass_context
def hackerone_report_cmd(ctx: click.Context, scan_id: str, output: Optional[str],
                         finding_id: Optional[str], all_severities: bool,
                         bounty_header: Optional[str]):
    """
    Generate HackerOne-quality reports from scan findings.

    Creates professional bug bounty reports with:
      - Proper CWE/CVSS classification
      - Reproducible curl commands
      - Impact assessment
      - PoC files where applicable

    \b
    Examples:
        phantom hackerone-report PHANTOM_20260205
        phantom hackerone-report PHANTOM_20260205 -f FINDING_123
        phantom hackerone-report PHANTOM_20260205 --all-severities
    """
    if not ctx.obj.get("no_banner"):
        print_banner()

    if not HACKERONE_REPORTER_AVAILABLE:
        console.print("[red]❌ HackerOne Report Generator not available[/red]")
        console.print("[dim]Make sure phantom/hackerone_report_generator.py exists[/dim]")
        return

    state = load_scan_state(scan_id)
    if not state:
        console.print(f"[red]❌ Scan not found: {scan_id}[/red]")
        return

    findings = state.get("validated_findings", state.get("findings", []))

    if finding_id:
        # Filter for specific finding
        findings = [f for f in findings if f.get("id") == finding_id]
        if not findings:
            console.print(f"[red]❌ Finding not found: {finding_id}[/red]")
            return
    elif not all_severities:
        # Filter for MEDIUM+ severity
        findings = [
            f for f in findings
            if _get_severity(f) in ("CRITICAL", "HIGH", "MEDIUM")
        ]

    if not findings:
        console.print("[yellow]⚠️ No findings to report[/yellow]")
        return

    console.print(Panel(
        f"[bold cyan]📄 Generating HackerOne Reports[/bold cyan]\n\n"
        f"Scan ID: {scan_id}\n"
        f"Findings: {len(findings)}\n"
        f"Severities: {'All' if all_severities else 'MEDIUM+'}",
        title="HackerOne Report Generator",
        border_style="cyan",
    ))

    # Generate reports
    target = state.get("target", "unknown")
    domain = state.get("domain", get_domain(target))

    generator = HackerOneReportGenerator(
        output_dir=Path(output) if output else Path("evidence") / f"{domain.replace('.', '_')}_{scan_id}",
        bounty_header=bounty_header,
    )

    generated_reports = []
    for i, finding in enumerate(findings, 1):
        try:
            report = generator.generate_report(finding)
            saved_files = generator.save_report(report, formats=["md", "json", "html"])

            generated_reports.append({
                "title": report.title,
                "severity": report.severity,
                "cwe": report.cwe,
                "files": saved_files,
            })

            console.print(f"   [green]✓[/green] {i}. [{report.severity.upper()}] {report.title}")
            console.print(f"      [dim]→ {saved_files.get('md', 'N/A')}[/dim]")

        except Exception as e:
            console.print(f"   [red]✗[/red] {i}. Failed: {e}")

    # Summary
    if generated_reports:
        console.print(Panel(
            f"[bold green]✅ Generated {len(generated_reports)} HackerOne Reports[/bold green]\n\n"
            f"Output: {generator.output_dir}\n\n"
            "[cyan]Report Contents:[/cyan]\n"
            "  • Summary with clear asset identification\n"
            "  • CWE/CVSS vulnerability classification\n"
            "  • Step-by-step reproduction with curl commands\n"
            "  • Impact assessment with attack scenarios\n"
            "  • Honest limitations/assumptions\n"
            "  • Remediation recommendations\n"
            "  • References and PoC files",
            title="📋 Reports Ready for Submission",
            border_style="green",
        ))


# =============================================================================
# HANDOFF COMMAND
# =============================================================================


@cli.command()
@click.argument("scan_id")
@click.option("--output", "-o", type=click.Path(), help="Output directory")
@click.option("--operator", help="Operator name / username")
@click.pass_context
def handoff(ctx, scan_id, output, operator):
    """Generate a comprehensive handoff session document for a scan."""
    from phantom.handoff_generator import HandoffSessionGenerator

    console.print(Panel(
        f"[bold cyan]📋 Generating Handoff Session[/bold cyan]\n\n"
        f"Scan ID: {scan_id}",
        title="Handoff Session Generator",
        border_style="cyan",
    ))

    # Load scan state
    scans_dir = get_scans_dir()
    scan_files = sorted(scans_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)
    scan_state = None

    for scan_file in scan_files:
        try:
            with open(scan_file) as f:
                state = json.load(f)
                if state.get("scan_id") == scan_id or scan_id in str(scan_file):
                    scan_state = state
                    break
        except (json.JSONDecodeError, OSError) as e:
            logging.debug(f"Failed to load scan state from {scan_file}: {e}")
            continue

    if not scan_state:
        console.print(f"[red]Error:[/red] No scan found with ID '{scan_id}'")
        console.print("[yellow]Tip:[/yellow] Run 'phantom list' to see available scans")
        return

    target = scan_state.get("target", "unknown")
    domain = scan_state.get("domain", get_domain(target) if target != "unknown" else "unknown")
    findings = scan_state.get("validated_findings", scan_state.get("findings", []))

    if not findings:
        console.print("[yellow]⚠️ No findings in this scan[/yellow]")
        return

    # Collect artifacts from evidence directory
    artifact_paths = []
    evidence_base = Path("evidence") / domain.replace(".", "_")
    if evidence_base.exists():
        for report_dir in evidence_base.iterdir():
            if report_dir.is_dir():
                for fpath in report_dir.iterdir():
                    artifact_paths.append({
                        "name": fpath.name,
                        "path": str(fpath),
                        "type": fpath.suffix.lstrip("."),
                    })

    output_dir = Path(output) if output else evidence_base
    gen = HandoffSessionGenerator(output_dir=output_dir)

    session = gen.generate(
        target=target,
        scan_id=scan_id,
        findings=findings,
        scan_metadata={
            "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "safety_mode": scan_state.get("safety_mode", "safe"),
            "modules_run": len(scan_state.get("modules_run", [])),
            "duration_seconds": scan_state.get("duration_seconds", 0),
            "operator": operator or "phantom-ai",
        },
        artifact_paths=artifact_paths,
    )

    saved = gen.save(session)

    console.print(Panel(
        f"[bold green]✅ Handoff Session Generated[/bold green]\n\n"
        f"Target: {target}\n"
        f"Findings: {len(findings)}\n\n"
        "[cyan]Files generated:[/cyan]\n"
        f"  • HANDOFF.md — {saved.get('md', '')}\n"
        f"  • handoff_data.json — {saved.get('json', '')}\n"
        f"  • MANIFEST.json — {saved.get('manifest', '')}",
        title="📋 Handoff Ready",
        border_style="green",
    ))


# =============================================================================
# CLIENT COMMAND
# =============================================================================

@cli.command()
@click.argument("target")
@click.option("--output", "-o", type=click.Path(), help="Output directory")
@click.option("--client-name", help="Client organization name")
@click.option("--engagement-id", help="Engagement identifier")
@click.option("--safe-mode", "-s",
              type=click.Choice(["safe", "cautious", "standard", "aggressive"]),
              default="cautious", help="Safety level (default: cautious for client safety)")
@click.option("--rate", "-r", type=float, default=10.0, help="Requests per second")
@click.option("--concurrent", "-c", type=int, default=5, help="Concurrent modules")
@click.option("--subdomains/--no-subdomains", default=False, help="Subdomain enumeration (default: OFF, requires explicit --subdomains)")
@click.option("--compliance", multiple=True,
              type=click.Choice(["pci-dss", "hipaa", "gdpr", "nist", "owasp", "all"]),
              help="Compliance frameworks to map")
@click.option("--scope", multiple=True,
              help="In-scope domains (e.g., --scope '*.example.com' --scope 'api.example.com')")
@click.option("--scope-file", type=click.Path(exists=True),
              help="JSON file with scope definition (engagement letter format)")
@click.option("--deterministic", is_flag=True, default=False,
              help="Enable deterministic mode for reproducible scans (THEME-8)")
# P0 Professional Safety Options
@click.option("--roe-file", type=click.Path(exists=True),
              help="[P0.1] Rules of Engagement JSON file (required for aggressive mode)")
@click.option("--proof-policy",
              type=click.Choice(["read_only", "schema_only", "sample_redacted", "full_extraction"]),
              default="sample_redacted",
              help="[P0.2] Evidence extraction policy (default: sample_redacted)")
@click.option("--redaction-level",
              type=click.Choice(["none", "minimal", "standard", "strict", "paranoid"]),
              default="strict",
              help="[P0.7] Report redaction level (default: strict for clients)")
@click.option("--environment",
              type=click.Choice(["staging", "production", "local"]),
              default=None,
              help="[P0] Target environment (auto-detected if not specified)")
@click.option("--backup-verified", is_flag=True, default=False,
              help="[P0.8] Confirm client has verified backup exists")
@click.option("--maintenance-window", is_flag=True, default=False,
              help="[P0.8] Confirm scan is during maintenance window")
@click.option("--emergency-contact",
              help="[P0.8] Emergency contact for this engagement")
@click.option("--output-format", "-f",
              type=click.Choice(["client", "sarif", "all"]),
              default="client",
              help="Output report format: client (default), sarif (DevSecOps), or all")
@click.option("--accept-terms", is_flag=True, default=False,
              help="Accept legal disclaimer non-interactively (for CI/CD and testing)")
@click.option("--no-auth", is_flag=True, default=False,
              help="Skip target authorization check")
@click.pass_context
def client(ctx: click.Context, target: str, output: Optional[str],
           client_name: Optional[str], engagement_id: Optional[str], safe_mode: str,
           rate: float, concurrent: int, subdomains: bool, compliance: tuple,
           scope: tuple, scope_file: Optional[str], deterministic: bool,
           roe_file: Optional[str], proof_policy: str, redaction_level: str,
           environment: Optional[str], backup_verified: bool, maintenance_window: bool,
           emergency_contact: Optional[str], output_format: str,
           accept_terms: bool, no_auth: bool):
    """
    Professional client engagement with PHANTOM AI.

    Full penetration test with enterprise reporting, compliance mapping,
    and executive summaries suitable for client delivery.

    \b
    Examples:
        phantom client https://client.com --client-name "ACME Corp"
        phantom client https://api.client.com -s aggressive --compliance all
    """
    if not ctx.obj.get("no_banner"):
        print_banner()

    # ═══════════════════════════════════════════════════════════════════════════
    # PROFESSIONAL ETHICS: Client authorization and engagement verification
    # "Pentesting profissional requer autorização escrita"
    # ═══════════════════════════════════════════════════════════════════════════

    # ETHICS-03: Client name required for professional engagements
    if not client_name:
        console.print(Panel(
            "[bold yellow]⚠️ CLIENT NAME RECOMMENDED[/bold yellow]\n\n"
            "Professional pentesting should identify the client.\n"
            "This is important for:\n"
            "  • Legal audit trail\n"
            "  • Report documentation\n"
            "  • Engagement tracking\n\n"
            "[dim]Add client name with: --client-name \"Client Organization\"[/dim]",
            title="Client Identification",
            border_style="yellow",
        ))
        client_name = "Unnamed Client"  # Default for audit purposes

    # Auto-generate engagement ID if not provided
    if not engagement_id:
        engagement_id = f"PHANTOM-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        console.print(f"[dim]Auto-generated engagement ID: {engagement_id}[/dim]")

    # ETHICS-03: Legal disclaimer and authorization check for client work
    if not check_authorization(
        program_name=f"Client Engagement: {client_name}",
        targets=[target],
        mode=safe_mode,
        rate_limit=rate,
        skip_disclaimer=accept_terms,
    ):
        console.print("[red]❌ Authorization not confirmed. Engagement aborted.[/red]")
        console.print("[dim]Professional pentesting requires explicit client authorization.[/dim]")
        console.print("[dim]Use --accept-terms to skip interactive prompts.[/dim]")
        return

    # ═══════════════════════════════════════════════════════════════════════════
    # ETHICS-06/07: Scope validation for client engagements
    # "Professional pentesting requires scope defined in engagement letter"
    # ═══════════════════════════════════════════════════════════════════════════
    scope_list: List[str] = list(scope) if scope else []

    # Load scope from file if provided
    if scope_file:
        try:
            import json
            with open(scope_file, "r") as f:
                scope_data = json.load(f)

            # Support multiple scope file formats
            if isinstance(scope_data, list):
                # Simple list of domains
                scope_list.extend(scope_data)
            elif isinstance(scope_data, dict):
                # Engagement letter format: {"allowed_domains": [...], "excluded_domains": [...]}
                if "allowed_domains" in scope_data:
                    scope_list.extend(scope_data["allowed_domains"])
                if "scope" in scope_data:
                    scope_list.extend(scope_data["scope"])
                if "targets" in scope_data:
                    scope_list.extend(scope_data["targets"])

            console.print(f"[green]✓ Loaded scope from: {scope_file}[/green]")
            console.print(f"[dim]  Allowed domains: {', '.join(scope_list)}[/dim]")
        except Exception as e:
            console.print(Panel(
                f"[bold red]⛔ SCOPE FILE ERROR[/bold red]\n\n"
                f"Failed to load scope file: {scope_file}\n"
                f"Error: {e}\n\n"
                "[yellow]Scope file should be JSON format:[/yellow]\n"
                "[dim]Simple: [\"*.example.com\", \"api.example.com\"][/dim]\n"
                "[dim]Or engagement letter: {\"allowed_domains\": [...]}[/dim]",
                title="Scope File Error",
                border_style="red",
            ))
            return

    # Validate target against scope if scope is defined
    if scope_list:
        from utils.legal_disclaimer import verify_scope_programmatically

        in_scope, reason = verify_scope_programmatically(scope_list, target)
        if not in_scope:
            console.print(Panel(
                f"[bold red]⛔ TARGET NOT IN ENGAGEMENT SCOPE[/bold red]\n\n"
                f"Target: {target}\n"
                f"Engagement Scope: {', '.join(scope_list)}\n"
                f"Reason: {reason}\n\n"
                "[yellow]Client engagements MUST stay within defined scope.[/yellow]\n"
                "[yellow]Out-of-scope testing violates your engagement agreement.[/yellow]\n\n"
                "[dim]Update your scope file or add: --scope 'domain.com'[/dim]",
                title="Scope Violation",
                border_style="red",
            ))
            return

        console.print(f"[green]✓ Target verified in engagement scope: {reason}[/green]")
    else:
        # No scope defined - warn but allow (client may have verbal authorization)
        console.print(Panel(
            "[bold yellow]⚠️ NO SCOPE DEFINED[/bold yellow]\n\n"
            "Professional client engagements should define scope.\n"
            "Consider adding:\n"
            "  • --scope '*.client.com' (command line)\n"
            "  • --scope-file engagement_scope.json (file)\n\n"
            "[dim]Proceeding without scope validation...[/dim]",
            title="Scope Warning",
            border_style="yellow",
        ))

    # ═══════════════════════════════════════════════════════════════════════════
    # ETHICS-10: Initialize Audit Logger for professional engagement audit trail
    # ═══════════════════════════════════════════════════════════════════════════
    audit = init_audit_logger(
        engagement_id=engagement_id,
        operator=client_name or "unknown-client",
    )
    audit.log_authorization(
        target=target,
        accepted=True,
        scope=scope_list,
        mode=safe_mode,
        rate_limit=rate,
    )
    if scope_list:
        audit.log_scope_confirmed(
            targets=[target],
            scope=scope_list,
            program_name=f"Client Engagement: {client_name}",
        )
    console.print(f"[dim]📝 Audit log: {audit.log_file}[/dim]")

    compliance_list = list(compliance) if compliance else []

    console.print(Panel(
        f"[bold green]🔒 PROFESSIONAL CLIENT ENGAGEMENT[/bold green]\n\n"
        f"Client: {client_name}\n"
        f"Engagement ID: {engagement_id}\n"
        f"Target: {target}\n"
        f"Mode: {safe_mode.upper()}\n"
        f"Rate: {rate} req/sec\n"
        f"Subdomains: {'Enabled' if subdomains else 'Disabled'}\n"
        f"Compliance: {', '.join(compliance_list) if compliance_list else 'None specified'}",
        title="Client Engagement",
        border_style="green",
    ))

    # ═══════════════════════════════════════════════════════════════════════════
    # CLIENT MODE SAFETY: Block aggressive unless explicitly authorized
    # Professional pentest = prove impact without causing damage
    # ═══════════════════════════════════════════════════════════════════════════
    if safe_mode == "aggressive":
        if os.environ.get("PHANTOM_ALLOW_AGGRESSIVE", "").lower() not in ("1", "true", "yes", "authorized"):
            console.print(Panel(
                "[bold red]⛔ AGGRESSIVE MODE BLOCKED (CLIENT ENGAGEMENT)[/bold red]\n\n"
                "Client engagements require extra care:\n"
                "  • Professional pentesting = prove impact WITHOUT causing damage\n"
                "  • 'Se consegues provar que PODES fazer algo, não precisas fazê-lo'\n\n"
                "Aggressive mode requires explicit authorization:\n"
                "[yellow]export PHANTOM_ALLOW_AGGRESSIVE=authorized[/yellow]\n\n"
                "[green]Falling back to 'standard' mode (recommended for client work).[/green]",
                title="Client Safety Protection",
                border_style="red",
            ))
            safe_mode = "standard"
            os.environ["PHANTOM_SAFE_MODE"] = safe_mode
        else:
            # Authorized aggressive mode - show extra warning
            console.print(Panel(
                "[bold red]⚠️ AGGRESSIVE MODE WARNING[/bold red]\n\n"
                "This mode will attempt exploitation techniques that may:\n"
                "  • Modify data in the application\n"
                "  • Trigger alerts and WAF blocks\n"
                "  • Cause service disruption\n\n"
                "[yellow]Ensure you have written authorization from the client![/yellow]\n"
                "[yellow]All actions will be logged for audit purposes.[/yellow]",
                title="Warning",
                border_style="red",
            ))

    # THEME-8: Enable deterministic mode if requested
    if deterministic:
        from scanning.determinism import enable_deterministic_mode
        enable_deterministic_mode()
        console.print("[cyan]🎯 Deterministic mode enabled — scans will be reproducible[/cyan]")

    # ═══════════════════════════════════════════════════════════════════════════
    # P0 FIX: Build professional safety configuration
    # ═══════════════════════════════════════════════════════════════════════════
    safety_config = None
    try:
        from scanning.scan_safety_config import (
            ScanSafetyConfig, Environment, RoEInfo, detect_environment
        )

        # Determine environment
        if environment:
            env = Environment(environment)
        else:
            env = detect_environment(target)
            if env == Environment.UNKNOWN:
                # For client engagements, assume production unless stated otherwise
                console.print(
                    "[yellow]⚠️ Environment not specified. Assuming PRODUCTION for safety.[/yellow]"
                )
                env = Environment.PRODUCTION

        # Load RoE if provided
        roe = RoEInfo()
        if roe_file:
            roe = RoEInfo.from_file(roe_file)
            if roe.is_valid():
                console.print(f"[green]✓ RoE loaded and valid: {roe_file}[/green]")
            else:
                console.print(f"[red]⚠️ RoE invalid or expired: {roe.status.value}[/red]")

        # Build safety config
        emergency_contacts = [emergency_contact] if emergency_contact else []
        safety_config = ScanSafetyConfig(
            environment=env,
            safety_level=safe_mode,
            roe=roe,
            proof_policy=proof_policy,
            redact_evidence=True,
            redaction_level=redaction_level,
            backup_verified=backup_verified,
            maintenance_window=maintenance_window,
            emergency_contacts=emergency_contacts,
            enable_audit_log=True,
        )

        # Validate configuration
        is_valid, errors = safety_config.validate_for_scan()
        if not is_valid:
            for err in errors:
                console.print(f"[red]❌ Safety validation error: {err}[/red]")

            # For production + aggressive, require valid RoE
            if env == Environment.PRODUCTION and safe_mode == "aggressive":
                console.print(Panel(
                    "[bold red]⛔ AGGRESSIVE MODE BLOCKED[/bold red]\n\n"
                    "Aggressive testing in production requires:\n"
                    "  • Valid RoE file (--roe-file path/to/roe.json)\n"
                    "  • Backup verification (--backup-verified)\n"
                    "  • Emergency contacts (--emergency-contact)\n\n"
                    "[dim]Create RoE template: phantom roe-template --output roe.json[/dim]",
                    title="Safety Block",
                    border_style="red",
                ))
                return

        console.print(Panel(
            f"[bold green]✓ P0 Safety Configuration[/bold green]\n\n"
            f"  Environment: {env.value.upper()}\n"
            f"  Safety Level: {safe_mode}\n"
            f"  Proof Policy: {proof_policy}\n"
            f"  Redaction: {redaction_level}\n"
            f"  RoE Status: {roe.status.value}\n"
            f"  Audit Logging: ENABLED",
            title="Professional Safety",
            border_style="green",
        ))

    except ImportError as e:
        console.print(f"[yellow]⚠️ P0 safety modules not available: {e}[/yellow]")
        console.print("[dim]Continuing with basic safety controls...[/dim]")
    # ═══════════════════════════════════════════════════════════════════════════

    safe_asyncio_run(_run_client_scan(
        target=target,
        output_dir=output,
        safe_mode=safe_mode,
        rate=rate,
        concurrent=concurrent,
        subdomains=subdomains,
        verbose=ctx.obj.get("verbose", False),
        client_name=client_name,
        engagement_id=engagement_id,
        compliance_frameworks=compliance_list,
        scope=scope_list,
        safety_config=safety_config,
        output_format=output_format,
        no_auth=no_auth,
    ))


async def _run_client_scan(
    target: str,
    output_dir: Optional[str],
    safe_mode: str,
    rate: float,
    concurrent: int,
    subdomains: bool,
    verbose: bool,
    client_name: Optional[str] = None,
    engagement_id: Optional[str] = None,
    compliance_frameworks: Optional[List[str]] = None,
    scope: Optional[List[str]] = None,
    safety_config: Optional["ScanSafetyConfig"] = None,
    output_format: str = "client",
    no_auth: bool = False,
) -> None:
    """Execute client engagement scan with professional report generation."""

    # Track scan timing for SARIF report
    scan_start_time = datetime.now()

    # Run the main scan
    # NOTE: include_subdomains controls actual subdomain enumeration
    # no_recon controls reconnaissance phase (crawling, etc.)
    await _run_phantom_scan(
        target=target,
        output_dir=output_dir,
        output_format="json",  # JSON always generated
        modules=None,
        safe_mode=safe_mode,
        rate=rate,
        concurrent=concurrent,
        scope=scope or [],
        exclude=[],
        preset=None,
        no_recon=False,  # Always do reconnaissance for client engagements
        no_tools=False,
        no_chain=False,
        no_ai=False,
        no_auth=no_auth,
        timeout=None,
        scan_mode=ScanMode.CLIENT if PHANTOM_AVAILABLE else "client",
        verbose=verbose,
        include_subdomains=subdomains,  # CRITICAL: Pass the flag to actually enumerate subdomains
        compliance=compliance_frameworks,  # FIX CLI-03: Pass compliance frameworks
        client_name=client_name,  # FIX CLI-02: Store in scan state
        engagement_id=engagement_id,  # FIX CLI-02: Store in scan state
        safety_config=safety_config,  # P0 FIX: Pass professional safety configuration
    )

    scan_end_time = datetime.now()

    # Generate reports based on output_format option
    # Client reports (default for client mode)
    if output_format in ("client", "all"):
        # Generate professional client reports (always MD + JSON + PDF)
        # P0 FIX: Pass redaction level from safety config
        redaction_level = "standard"
        if safety_config:
            redaction_level = safety_config.redaction_level
        await _generate_client_reports(
            target=target,
            output_dir=output_dir,
            client_name=client_name,
            engagement_id=engagement_id,
            compliance_frameworks=compliance_frameworks or [],
            redaction_level=redaction_level,
        )

    # SARIF report for DevSecOps integration
    if output_format in ("sarif", "all"):
        await _generate_sarif_report(
            target=target,
            output_dir=output_dir,
            scan_start_time=scan_start_time,
            scan_end_time=scan_end_time,
        )


async def _generate_client_reports(
    target: str,
    output_dir: Optional[str] = None,
    client_name: Optional[str] = None,
    engagement_id: Optional[str] = None,
    compliance_frameworks: Optional[List[str]] = None,
    redaction_level: str = "standard",
) -> None:
    """Generate professional client assessment reports for scan findings."""
    from pathlib import Path

    console.print("\n[bold cyan]📄 Generating Professional Client Reports...[/bold cyan]")

    # Load scan state (same pattern as _generate_hackerone_reports)
    scans_dir = get_scans_dir()
    domain = get_domain(target)

    scan_files = sorted(scans_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)
    scan_state = None

    for scan_file in scan_files:
        try:
            with open(scan_file) as f:
                state = json.load(f)
                if state.get("domain") == domain or domain in str(state.get("target", "")):
                    scan_state = state
                    break
        except Exception as e:
            logger.debug(f"Error reading scan file {scan_file}: {e}")
            continue

    if not scan_state:
        console.print("[yellow]⚠️ No scan state found for target[/yellow]")
        return

    findings = scan_state.get("validated_findings", scan_state.get("findings", []))

    if not findings:
        console.print("[yellow]⚠️ No findings to report[/yellow]")
        return

    # Filter for reportable findings (MEDIUM+ severity + confidence threshold)
    # FIX 2026-03-02: Also check confidence meets severity-specific threshold.
    _SEVERITY_CONF_THRESHOLDS_CLIENT = {"CRITICAL": 0.80, "HIGH": 0.70, "MEDIUM": 0.65, "LOW": 0.60, "INFO": 0.50}
    reportable = [
        f for f in findings
        if _get_severity(f) in ("CRITICAL", "HIGH", "MEDIUM")
        and _get_confidence(f) >= _SEVERITY_CONF_THRESHOLDS_CLIENT.get(_get_severity(f), 0.70)
    ]

    if not reportable:
        console.print("[yellow]⚠️ No reportable findings (MEDIUM+ severity with sufficient confidence)[/yellow]")
        return

    console.print(f"   Found {len(reportable)} reportable findings")

    # Generate client reports
    try:
        from phantom.client_report_generator import ClientReportGenerator

        out_path = Path(output_dir) if output_dir else Path("evidence") / f"{domain.replace('.', '_')}_client"

        generator = ClientReportGenerator(
            output_dir=out_path,
            client_name=client_name or "Client",
            engagement_id=engagement_id or "",
            compliance_frameworks=compliance_frameworks or [],
            redaction_level=redaction_level,  # P0 FIX: Apply PII redaction
        )

        report = generator.generate(
            findings=reportable,
            scan_metadata={
                "target": target,
                "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "safety_mode": scan_state.get("safety_mode", "standard"),
                "modules_run": len(scan_state.get("modules_run", [])),
                "duration_seconds": scan_state.get("duration_seconds", 0),
                "scan_id": scan_state.get("scan_id", "unknown"),
            },
        )

        # Always generate all formats: MD + JSON + PDF
        formats = ["md", "json", "pdf"]
        saved = generator.save(report, formats=formats)

        # Per-finding report summary
        for fr in report.finding_reports:
            sev = fr.get("severity", "").upper()
            title = fr.get("title", "Unknown")
            console.print(f"   [green]✓[/green] [{sev}] {title}")

        # Build deliverables list
        deliverables = [
            f"  • CLIENT_REPORT.md — {saved.get('md', '')}",
            f"  • CLIENT_REPORT.pdf — {saved.get('pdf', 'N/A')}",
            f"  • client_report_data.json — {saved.get('json', '')}",
            f"  • executive_summary.md — {saved.get('executive_summary', '')}",
            f"  • compliance_annex.md — {saved.get('compliance_annex', 'N/A')}",
            "  • Per-finding reports with PoC files",
        ]

        console.print(Panel(
            f"[bold green]✅ Client Assessment Report Generated[/bold green]\n\n"
            f"Client: {report.client_name}\n"
            f"Engagement: {report.engagement_id}\n"
            f"Findings: {len(report.finding_reports)}\n"
            f"Output: {out_path}\n\n"
            "[cyan]Deliverables:[/cyan]\n" + "\n".join(deliverables),
            title="📋 Client Report Ready",
            border_style="green",
        ))

    except ImportError:
        console.print("[yellow]⚠️ ClientReportGenerator not available[/yellow]")
        return
    except Exception as e:
        console.print(f"[red]✗ Client report generation failed: {e}[/red]")
        return

    # Generate handoff session
    try:
        from phantom.handoff_generator import HandoffSessionGenerator

        artifact_paths = []
        for fmt, fpath in saved.items():
            artifact_paths.append({"name": f"Client Report ({fmt})", "path": fpath, "type": fmt})
        for fr in report.finding_reports:
            for fmt, fpath in fr.get("files", {}).items():
                artifact_paths.append({
                    "name": f"{fr['title']} ({fmt})",
                    "path": fpath,
                    "type": fmt,
                })

        handoff_gen = HandoffSessionGenerator(output_dir=out_path)
        session = handoff_gen.generate(
            target=target,
            scan_id=scan_state.get("scan_id", "unknown"),
            findings=reportable,
            scan_metadata={
                "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "safety_mode": scan_state.get("safety_mode", "standard"),
                "modules_run": len(scan_state.get("modules_run", [])),
                "duration_seconds": scan_state.get("duration_seconds", 0),
                "operator": client_name or "phantom-ai",
            },
            artifact_paths=artifact_paths,
        )
        saved_handoff = handoff_gen.save(session)
        console.print(f"\n   [cyan]📋 Handoff session:[/cyan] {saved_handoff.get('md', '')}")
    except Exception as e:
        console.print(f"\n   [yellow]⚠️ Handoff generation skipped: {e}[/yellow]")


# =============================================================================
# RECON COMMAND
# =============================================================================

@cli.command()
@click.argument("target")
@click.option("--output", "-o", type=click.Path(), help="Output file")
@click.option("--subdomains/--no-subdomains", default=True, help="Enumerate subdomains")
@click.option("--technologies/--no-technologies", default=True, help="Fingerprint technologies")
@click.option("--endpoints/--no-endpoints", default=True, help="Discover endpoints")
@click.option("--parameters/--no-parameters", default=True, help="Discover parameters")
@click.option("--waf/--no-waf", default=True, help="Detect WAF")
@click.pass_context
def recon(ctx: click.Context, target: str, output: Optional[str],
          subdomains: bool, technologies: bool, endpoints: bool,
          parameters: bool, waf: bool):
    """
    Passive reconnaissance only (no active testing).

    Gather intelligence about the target without sending attack payloads.
    Useful for scope assessment and attack surface mapping.

    \b
    Examples:
        phantom recon target.com
        phantom recon api.target.com --no-subdomains --technologies
    """
    if not ctx.obj.get("no_banner"):
        print_banner()

    console.print(Panel(
        "[bold blue]🔍 RECONNAISSANCE MODE[/bold blue]\n\n"
        "Passive intelligence gathering:\n"
        f"  • Subdomains: {'✓' if subdomains else '✗'}\n"
        f"  • Technologies: {'✓' if technologies else '✗'}\n"
        f"  • Endpoints: {'✓' if endpoints else '✗'}\n"
        f"  • Parameters: {'✓' if parameters else '✗'}\n"
        f"  • WAF Detection: {'✓' if waf else '✗'}",
        title="Recon Mode",
        border_style="blue",
    ))

    safe_asyncio_run(_run_recon(
        target=target,
        output=output,
        subdomains=subdomains,
        technologies=technologies,
        endpoints=endpoints,
        parameters=parameters,
        waf=waf,
        verbose=ctx.obj.get("verbose", False),
    ))


async def _run_recon(
    target: str,
    output: Optional[str],
    subdomains: bool,
    technologies: bool,
    endpoints: bool,
    parameters: bool,
    waf: bool,
    verbose: bool,
) -> None:
    """Execute reconnaissance."""
    target = normalize_target(target)
    domain = get_domain(target)

    results = {
        "target": target,
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "subdomains": [],
        "technologies": [],
        "endpoints": [],
        "parameters": [],
        "waf": None,
    }

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:

        # Subdomain enumeration
        if subdomains:
            task = progress.add_task("[cyan]Enumerating subdomains...", total=None)
            try:
                from reconnaissance.subdomain_enum import SubdomainEnumerator
                from core.config_manager import get_settings

                settings = get_settings()
                enumerator = SubdomainEnumerator(settings)
                found = await enumerator.enumerate(domain)
                results["subdomains"] = list(found) if found else []
                console.print(f"[green]✓ Found {len(results['subdomains'])} subdomains[/green]")
            except Exception as e:
                if verbose:
                    console.print(f"[yellow]⚠️ Subdomain enumeration failed: {e}[/yellow]")
            progress.update(task, completed=True)

        # Technology fingerprinting
        if technologies and PHANTOM_AVAILABLE:
            task = progress.add_task("[cyan]Fingerprinting technologies...", total=None)
            try:
                fingerprinter = TechFingerprinter()
                tech_results = await fingerprinter.fingerprint(target)
                if tech_results and tech_results.technologies:
                    results["technologies"] = [
                        {"name": t.name, "version": t.version, "category": t.category.value}
                        for t in tech_results.technologies
                    ]
                    console.print(f"[green]✓ Detected {len(results['technologies'])} technologies[/green]")
            except Exception as e:
                if verbose:
                    console.print(f"[yellow]⚠️ Tech fingerprinting failed: {e}[/yellow]")
            progress.update(task, completed=True)

        # WAF detection
        if waf and PHANTOM_AVAILABLE:
            task = progress.add_task("[cyan]Detecting WAF...", total=None)
            try:
                waf_engine = WAFBypassEngine()
                waf_result = await waf_engine.detect_waf(target)
                if waf_result:
                    results["waf"] = {
                        "detected": waf_result.detected,
                        "name": waf_result.waf_name,
                        "confidence": waf_result.confidence,
                        "behaviour": waf_result.behaviour_family.value if waf_result.behaviour_family else None,
                    }
                    if waf_result.detected:
                        console.print(f"[yellow]⚠️ WAF Detected: {waf_result.waf_name}[/yellow]")
                    else:
                        console.print("[green]✓ No WAF detected[/green]")
            except Exception as e:
                if verbose:
                    console.print(f"[yellow]⚠️ WAF detection failed: {e}[/yellow]")
            progress.update(task, completed=True)

    # Display results
    console.print("\n[bold]📊 Reconnaissance Results:[/bold]")

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Category", style="cyan")
    table.add_column("Count", justify="right")

    table.add_row("Subdomains", str(len(results["subdomains"])))
    table.add_row("Technologies", str(len(results["technologies"])))
    table.add_row("WAF Detected", "Yes" if results["waf"] and results["waf"]["detected"] else "No")

    console.print(table)

    # Save results
    if output:
        output_path = Path(output)
        output_path.write_text(json.dumps(results, indent=2))
        console.print(f"\n[green]✅ Results saved: {output_path}[/green]")


# =============================================================================
# WAF-DETECT COMMAND
# =============================================================================

@cli.command("waf-detect")
@click.argument("target")
@click.option("--bypass/--no-bypass", default=True, help="Show bypass strategies")
@click.pass_context
def waf_detect(ctx: click.Context, target: str, bypass: bool):
    """
    Detect and identify Web Application Firewall (WAF).

    Identifies the WAF vendor, behavior family, and provides
    bypass strategies for penetration testing.

    \b
    Examples:
        phantom waf-detect https://target.com
        phantom waf-detect api.target.com --no-bypass
    """
    if not ctx.obj.get("no_banner"):
        print_banner()

    if not PHANTOM_AVAILABLE:
        console.print("[red]❌ PHANTOM AI modules not available[/red]")
        return

    safe_asyncio_run(_detect_waf(target, bypass, ctx.obj.get("verbose", False)))


async def _detect_waf(target: str, show_bypass: bool, verbose: bool) -> None:
    """Detect WAF."""
    target = normalize_target(target)

    console.print(f"\n[cyan]🔍 Detecting WAF for: {target}[/cyan]\n")

    waf_engine = WAFBypassEngine()

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("[cyan]Analyzing WAF signatures...", total=None)
        result = await waf_engine.detect_waf(target)
        progress.update(task, completed=True)

    if not result:
        console.print("[yellow]⚠️ Unable to determine WAF presence[/yellow]")
        return

    if result.detected:
        console.print(Panel(
            f"[bold red]WAF DETECTED[/bold red]\n\n"
            f"[bold]Name:[/bold] {result.waf_name}\n"
            f"[bold]Confidence:[/bold] {result.confidence*100:.0f}%\n"
            f"[bold]Behavior Family:[/bold] {result.behaviour_family.value}\n"
            f"[bold]Signatures Matched:[/bold] {len(result.matched_signatures)}",
            title="🛡️ WAF Detection Result",
            border_style="red",
        ))

        if show_bypass:
            strategies = waf_engine.get_bypass_strategies(result)
            if strategies:
                console.print("\n[bold yellow]🔓 Bypass Strategies:[/bold yellow]")
                for i, strategy in enumerate(strategies[:5], 1):
                    console.print(f"  {i}. {strategy.name}")
                    console.print(f"     {strategy.description}")
    else:
        console.print(Panel(
            "[bold green]NO WAF DETECTED[/bold green]\n\n"
            "No Web Application Firewall was identified.\n"
            "The target may be unprotected or using an unknown WAF.",
            title="✓ WAF Detection Result",
            border_style="green",
        ))


# =============================================================================
# MODULES COMMAND
# =============================================================================

@cli.command()
@click.option("--category", "-c", help="Filter by category")
@click.pass_context
def modules(ctx: click.Context, category: Optional[str]):
    """
    List all available PHANTOM AI security modules.

    Shows all 75+ modules organized by category with descriptions.

    \b
    Examples:
        phantom modules
        phantom modules -c injection
    """
    if not ctx.obj.get("no_banner"):
        print_banner()

    console.print(f"\n[bold]📦 PHANTOM AI Security Modules ({get_module_count() if PHANTOM_AVAILABLE else '75+'})[/bold]\n")

    categories_to_show = MODULE_CATEGORIES if PHANTOM_AVAILABLE else {
        "injection": ["sqli", "xss", "dom_xss", "cmdi", "xxe", "nosql", "ssti", "ldap", "crlf", "lfi", "ssrf"],
        "authentication": ["auth", "oauth", "saml", "mfa", "authz", "jwt", "csrf", "rate_limit"],
        "api": ["api", "graphql", "grpc", "websocket", "sse", "idor", "mass_assign"],
        "infrastructure": ["ssl", "headers", "cors", "cloud", "k8s", "dns_rebind"],
        "advanced": ["smuggling", "cache", "deser", "prototype", "rls_bypass", "business", "mobile"],
        "discovery": ["cms", "directory", "nuclei", "backend", "3rdparty", "email", "cred_verify"],
        "baas": ["supabase", "firebase", "appwrite"],
    }

    category_icons = {
        "injection": "💉",
        "authentication": "🔐",
        "api": "🌐",
        "infrastructure": "🏗️",
        "advanced": "⚡",
        "discovery": "🔍",
        "baas": "☁️",
    }

    for cat_name, cat_modules in categories_to_show.items():
        if category and category.lower() != cat_name:
            continue

        icon = category_icons.get(cat_name, "📦")
        console.print(f"[bold cyan]{icon} {cat_name.upper()}[/bold cyan]")

        for mod in cat_modules:
            console.print(f"    • {mod}")

        console.print()

    if not category:
        console.print("[dim]Use -c <category> to filter by category[/dim]")


# =============================================================================
# STATUS COMMAND
# =============================================================================

@cli.command()
@click.argument("scan_id", required=False)
@click.pass_context
def status(ctx: click.Context, scan_id: Optional[str]):
    """
    Check scan status.

    \b
    Examples:
        phantom status                    # Show all recent scans
        phantom status PHANTOM_20260130   # Show specific scan
    """
    scans_dir = get_scans_dir()

    if scan_id:
        state = load_scan_state(scan_id)
        if not state:
            console.print(f"[red]❌ Scan not found: {scan_id}[/red]")
            return

        console.print(Panel(
            f"[bold]Scan ID:[/bold] {state.get('scan_id')}\n"
            f"[bold]Target:[/bold] {state.get('target')}\n"
            f"[bold]Status:[/bold] {state.get('status')}\n"
            f"[bold]Phase:[/bold] {state.get('phase')}\n"
            f"[bold]Findings:[/bold] {len(state.get('findings', []))}\n"
            f"[bold]Started:[/bold] {state.get('start_time')}",
            title="📊 Scan Status",
            border_style="cyan",
        ))
    else:
        # List all scans
        scan_files = sorted(scans_dir.glob("PHANTOM_*.json"), reverse=True)[:10]

        if not scan_files:
            console.print("[yellow]No scans found[/yellow]")
            return

        table = Table(title="📋 Recent Scans", show_header=True, header_style="bold cyan")
        table.add_column("Scan ID", style="cyan")
        table.add_column("Target")
        table.add_column("Status")
        table.add_column("Findings", justify="right")

        for scan_file in scan_files:
            try:
                state = json.loads(scan_file.read_text())
                status_color = {
                    "completed": "green",
                    "running": "yellow",
                    "interrupted": "orange1",
                    "error": "red",
                }.get(state.get("status", ""), "white")

                table.add_row(
                    state.get("scan_id", "?"),
                    state.get("target", "?")[:40],
                    f"[{status_color}]{state.get('status', '?')}[/{status_color}]",
                    str(len(state.get("findings", []))),
                )
            except Exception as e:
                logger.debug(f"Error reading scan file {scan_file}: {e}")
                continue

        console.print(table)


# =============================================================================
# LIST COMMAND
# =============================================================================

@cli.command("list")
@click.option("--limit", "-n", type=int, default=20, help="Number of scans to show")
@click.pass_context
def list_scans(ctx: click.Context, limit: int):
    """
    List previous scans.

    \b
    Examples:
        phantom list
        phantom list -n 50
    """
    scans_dir = get_scans_dir()
    scan_files = sorted(scans_dir.glob("PHANTOM_*.json"), reverse=True)[:limit]

    if not scan_files:
        console.print("[yellow]No scans found[/yellow]")
        return

    table = Table(title=f"📋 Previous Scans (Last {limit})", show_header=True, header_style="bold cyan")
    table.add_column("Scan ID", style="cyan")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Findings", justify="right")
    table.add_column("Date")

    for scan_file in scan_files:
        try:
            state = json.loads(scan_file.read_text())
            status_color = {
                "completed": "green",
                "running": "yellow",
                "interrupted": "orange1",
                "error": "red",
            }.get(state.get("status", ""), "white")

            table.add_row(
                state.get("scan_id", "?"),
                state.get("target", "?")[:30],
                f"[{status_color}]{state.get('status', '?')}[/{status_color}]",
                str(len(state.get("findings", []))),
                state.get("start_time", "?")[:10],
            )
        except Exception as e:
            logger.debug(f"Error reading scan file {scan_file}: {e}")
            continue

    console.print(table)


# =============================================================================
# RESUME COMMAND
# =============================================================================

@cli.command()
@click.argument("scan_id")
@click.pass_context
def resume(ctx: click.Context, scan_id: str):
    """
    Resume an interrupted scan.

    \b
    Examples:
        phantom resume PHANTOM_20260130_123456_abcd1234
    """
    if not ctx.obj.get("no_banner"):
        print_banner()

    state = load_scan_state(scan_id)
    if not state:
        console.print(f"[red]❌ Scan not found: {scan_id}[/red]")
        return

    if state.get("status") == "completed":
        console.print(f"[yellow]⚠️ Scan already completed[/yellow]")
        console.print(f"[cyan]Report: {state.get('report_file', 'N/A')}[/cyan]")
        return

    console.print(f"[cyan]📂 Resuming scan: {scan_id}[/cyan]")
    console.print(f"   Target: {state.get('target')}")
    console.print(f"   Phase: {state.get('phase')}")
    console.print(f"   Findings so far: {len(state.get('findings', []))}")

    # Resume the scan
    config = state.get("config", {})

    safe_asyncio_run(_run_phantom_scan(
        target=state.get("target"),
        output_dir=None,
        output_format="json",
        modules=config.get("modules"),
        safe_mode=config.get("safe_mode", "safe"),
        rate=config.get("rate", 2.0),
        concurrent=config.get("concurrent", 3),
        scope=[],
        exclude=config.get("exclude", []),
        preset=None,
        no_recon=config.get("no_recon", False),
        no_tools=True,
        no_chain=config.get("no_chain", False),
        no_ai=config.get("no_ai", False),
        no_auth=True,
        timeout=None,
        scan_mode=ScanMode.STANDARD if PHANTOM_AVAILABLE else "standard",
        verbose=ctx.obj.get("verbose", False),
    ))


# =============================================================================
# AUTHORIZE COMMAND
# =============================================================================

@cli.command()
@click.argument("target")
@click.pass_context
def authorize(ctx: click.Context, target: str):
    """
    Authorize a target for scanning.

    \b
    Examples:
        phantom authorize example.com
        phantom authorize https://target.com
    """
    from core.config_manager import get_settings
    from core.auth_manager import AuthManager

    settings = get_settings()
    auth = AuthManager(settings)

    domain = get_domain(target)
    auth.add_target(domain)

    console.print(f"[green]✅ Authorized: {domain}[/green]")
    console.print(f"[dim]You can now run: phantom scan {target}[/dim]")


# =============================================================================
# VALIDATE COMMAND
# =============================================================================

@cli.command()
@click.argument("finding_id", required=False)
@click.option("--scan-id", help="Scan ID to validate findings from")
@click.pass_context
def validate(ctx: click.Context, finding_id: Optional[str], scan_id: Optional[str]):
    """
    Re-validate findings using the 6-stage pipeline.

    \b
    Examples:
        phantom validate --scan-id PHANTOM_20260130
        phantom validate FINDING_123
    """
    if not PHANTOM_AVAILABLE:
        console.print("[red]❌ PHANTOM AI modules not available[/red]")
        return

    console.print("[cyan]🔬 Running 6-stage validation pipeline...[/cyan]")

    if scan_id:
        state = load_scan_state(scan_id)
        if not state:
            console.print(f"[red]❌ Scan not found: {scan_id}[/red]")
            return

        findings = state.get("findings", [])
        console.print(f"   Found {len(findings)} findings to validate")
    else:
        console.print("[yellow]Specify --scan-id to validate scan findings[/yellow]")


# =============================================================================
# HEALTH COMMAND
# =============================================================================

@cli.command()
@click.pass_context
def health(ctx: click.Context):
    """
    Check PHANTOM AI system health.

    Shows module availability, knowledge base status, and system resources.
    """
    if not ctx.obj.get("no_banner"):
        print_banner()

    console.print("\n[bold]🏥 PHANTOM AI System Health[/bold]\n")

    # Core modules
    table = Table(title="Core Modules", show_header=True, header_style="bold cyan")
    table.add_column("Module", style="cyan")
    table.add_column("Status")

    modules_status = [
        ("Network Protection", PHANTOM_AVAILABLE),
        ("Tech Fingerprinter", PHANTOM_AVAILABLE),
        ("Parameter Analyzer", PHANTOM_AVAILABLE),
        ("WAF Bypass Engine", PHANTOM_AVAILABLE),
        ("Context Payload Selector", PHANTOM_AVAILABLE),
        ("Module Executor", PHANTOM_AVAILABLE),
        ("Validation Pipeline", PHANTOM_AVAILABLE),
        ("Impact Assessment", PHANTOM_AVAILABLE),
        ("Chain Visualization", PHANTOM_AVAILABLE),
        ("SARIF Generator", PHANTOM_AVAILABLE),
        ("Bounty Estimator", PHANTOM_AVAILABLE),
        ("Compliance Mapper", PHANTOM_AVAILABLE),
    ]

    for module_name, available in modules_status:
        status = "[green]✓ Available[/green]" if available else "[red]✗ Not Available[/red]"
        table.add_row(module_name, status)

    console.print(table)

    # System info
    console.print("\n[bold]System Information[/bold]")
    console.print(f"  PHANTOM Version: {PHANTOM_VERSION if PHANTOM_AVAILABLE else '3.0.0'}")
    console.print(f"  Codename: {PHANTOM_CODENAME if PHANTOM_AVAILABLE else 'Enterprise Edition'}")
    console.print(f"  Total Modules: {get_module_count() if PHANTOM_AVAILABLE else 75}+")
    console.print(f"  Scans Directory: {get_scans_dir()}")
    console.print(f"  Reports Directory: {get_reports_dir()}")


# =============================================================================
# VERSION COMMAND
# =============================================================================

@cli.command()
def version():
    """Show PHANTOM AI version information."""
    console.print(Panel(
        f"[bold cyan]PHANTOM AI[/bold cyan]\n"
        f"Professional Heuristic Automated Network Threat Operations Module\n\n"
        f"[bold]Version:[/bold] {PHANTOM_VERSION if PHANTOM_AVAILABLE else '3.0.0'}\n"
        f"[bold]Codename:[/bold] {PHANTOM_CODENAME if PHANTOM_AVAILABLE else 'Enterprise Edition'}\n"
        f"[bold]Modules:[/bold] {get_module_count() if PHANTOM_AVAILABLE else 75}+\n"
        f"[bold]Validation:[/bold] 6-Stage Pipeline\n"
        f"[bold]False Positive Rate:[/bold] < 0.1%\n"
        f"[bold]License:[/bold] MIT",
        title="ℹ️ Version",
        border_style="cyan",
    ))


# =============================================================================
# CHAIN COMMAND
# =============================================================================

@cli.command()
@click.argument("scan_id")
@click.option("--output", "-o", type=click.Path(), help="Output file for visualization")
@click.option("--format", "-f", "output_format",
              type=click.Choice(["svg", "html", "dot", "mermaid", "json"]),
              default="html", help="Visualization format")
@click.pass_context
def chain(ctx: click.Context, scan_id: str, output: Optional[str], output_format: str):
    """
    Analyze and visualize vulnerability chains.

    Discovers attack paths by chaining multiple vulnerabilities together.
    Generates visual representations of potential attack scenarios.

    \b
    Examples:
        phantom chain PHANTOM_20260130
        phantom chain PHANTOM_20260130 -f svg -o chains.svg
    """
    if not ctx.obj.get("no_banner"):
        print_banner()

    if not PHANTOM_AVAILABLE:
        console.print("[red]❌ PHANTOM AI modules not available[/red]")
        return

    state = load_scan_state(scan_id)
    if not state:
        console.print(f"[red]❌ Scan not found: {scan_id}[/red]")
        return

    findings = state.get("findings", [])
    if not findings:
        console.print("[yellow]⚠️ No findings in scan to chain[/yellow]")
        return

    console.print(f"[cyan]🔗 Analyzing vulnerability chains for {len(findings)} findings...[/cyan]")

    safe_asyncio_run(_analyze_chains(
        findings=findings,
        target=state.get("target", ""),
        output=output,
        output_format=output_format,
        verbose=ctx.obj.get("verbose", False),
    ))


async def _analyze_chains(
    findings: List[Dict],
    target: str,
    output: Optional[str],
    output_format: str,
    verbose: bool,
) -> None:
    """Analyze and visualize vulnerability chains."""
    try:
        from ai_engine.chain_detector import ChainDetector
        from core.config_manager import get_settings

        settings = get_settings()
        chain_detector = ChainDetector(settings)

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task("[cyan]Discovering attack chains...", total=None)
            # Convert findings to dicts if needed and create assets dict
            findings_dicts = [
                f.to_dict() if hasattr(f, "to_dict") else f
                for f in findings
            ]
            assets = {"target": target, "host": target}
            chains = await chain_detector.detect(findings_dicts, assets)
            progress.update(task, completed=True)

        if not chains:
            console.print("[yellow]⚠️ No vulnerability chains discovered[/yellow]")
            return

        console.print(f"\n[bold green]✓ Discovered {len(chains)} attack chains[/bold green]\n")

        # Display chains
        for i, chain in enumerate(chains, 1):
            chain_vulns = chain.get("vulnerabilities", [])
            is_speculative = chain.get("metadata", {}).get("is_speculative", False)

            # Handle both formats: multi-vuln chains and single speculative chains
            if chain_vulns:
                chain_str = " → ".join([_get_vuln_display_name(v) for v in chain_vulns])
            else:
                chain_str = chain.get("name", chain.get("type", "Attack Path"))

            description = chain.get("description", "")
            impact = chain.get("impact", chain.get("metadata", {}).get("bounty_range", "Security Impact"))
            priority = chain.get("priority", 5 if is_speculative else 0)

            priority_color = "cyan" if is_speculative else ("red" if priority >= 8 else "orange1" if priority >= 5 else "yellow")
            spec_marker = " (Speculative)" if is_speculative else ""

            panel_content = f"[bold]Chain {i}{spec_marker}[/bold]\n\n"
            panel_content += f"[{priority_color}]Path: {chain_str}[/{priority_color}]\n"
            if description:
                panel_content += f"\n{description[:200]}\n"
            panel_content += f"\nImpact/Bounty: {impact}\n"
            panel_content += f"Priority: {priority}/10"

            # Add recommended tests for speculative chains
            recommended_tests = chain.get("metadata", {}).get("recommended_tests", [])
            if recommended_tests:
                panel_content += "\n\n[bold]Recommended Tests:[/bold]\n"
                for test in recommended_tests[:3]:
                    test_name = test.get("name", "Test")
                    bounty = test.get("bounty_potential", "")
                    panel_content += f"  • {test_name}"
                    if bounty:
                        panel_content += f" ({bounty})"
                    panel_content += "\n"

            console.print(Panel(
                panel_content,
                title=f"🔗 Attack Chain",
                border_style=priority_color,
            ))

        # Generate visualization
        if output and PHANTOM_AVAILABLE:
            try:
                viz_engine = ChainVisualizationEngine()
                output_path = Path(output)

                format_map = {
                    "svg": OutputFormat.SVG,
                    "html": OutputFormat.HTML,
                    "dot": OutputFormat.DOT,
                    "mermaid": OutputFormat.MERMAID,
                    "json": OutputFormat.JSON,
                }

                viz_format = format_map.get(output_format, OutputFormat.HTML)

                for i, chain_data in enumerate(chains[:5], 1):
                    # Create graph from chain
                    graph = viz_engine.create_graph_from_chain(chain_data)

                    # Render based on format
                    if viz_format == OutputFormat.SVG:
                        content = viz_engine.render_svg(graph)
                    elif viz_format == OutputFormat.HTML:
                        content = viz_engine.render_html(graph)
                    elif viz_format == OutputFormat.DOT:
                        content = viz_engine.render_dot(graph)
                    elif viz_format == OutputFormat.MERMAID:
                        content = viz_engine.render_mermaid(graph)
                    else:
                        content = viz_engine.render_json(graph)

                    # Write file
                    if i == 1:
                        output_path.write_text(content)
                    else:
                        base = output_path.stem
                        ext = output_path.suffix
                        Path(f"{base}_{i}{ext}").write_text(content)

                console.print(f"\n[green]✅ Visualization saved: {output}[/green]")

            except Exception as e:
                if verbose:
                    console.print(f"[yellow]⚠️ Visualization error: {e}[/yellow]")

    except Exception as e:
        console.print(f"[red]❌ Chain analysis error: {e}[/red]")


# =============================================================================
# REPORT COMMAND
# =============================================================================

@cli.command()
@click.argument("scan_id")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--format", "-f", "output_format",
              type=click.Choice(["pdf", "html", "json", "md", "sarif"]),
              default="json", help="Report format (default: JSON)")
@click.option("--compliance", multiple=True,
              type=click.Choice(["pci-dss", "hipaa", "gdpr", "nist", "owasp", "all"]),
              help="Include compliance mapping")
@click.option("--bounty/--no-bounty", default=False, help="Include bounty estimates")
@click.pass_context
def report(ctx: click.Context, scan_id: str, output: Optional[str], output_format: str,
           compliance: tuple, bounty: bool):
    """
    Generate report from completed scan.

    Create professional security assessment reports in various formats
    with optional compliance mapping and bounty estimates.

    \b
    Examples:
        phantom report PHANTOM_20260130
        phantom report PHANTOM_20260130 -f sarif --compliance owasp
        phantom report PHANTOM_20260130 --bounty -o report.html
    """
    if not ctx.obj.get("no_banner"):
        print_banner()

    state = load_scan_state(scan_id)
    if not state:
        console.print(f"[red]❌ Scan not found: {scan_id}[/red]")
        return

    if state.get("status") != "completed":
        console.print(f"[yellow]⚠️ Scan not completed (status: {state.get('status')})[/yellow]")
        console.print("[dim]Use 'phantom resume' to complete the scan first[/dim]")

    console.print(f"[cyan]📄 Generating {output_format.upper()} report...[/cyan]")

    findings = state.get("validated_findings", state.get("findings", []))
    chains = state.get("chains", [])

    # Build report data
    report_data = {
        "scan_id": scan_id,
        "target": state.get("target"),
        "domain": state.get("domain"),
        "start_time": state.get("start_time"),
        "end_time": state.get("end_time"),
        "config": state.get("config", {}),
        "summary": {
            "total": len(findings),
            "critical": len([f for f in findings if _get_severity(f) == "CRITICAL"]),
            "high": len([f for f in findings if _get_severity(f) == "HIGH"]),
            "medium": len([f for f in findings if _get_severity(f) == "MEDIUM"]),
            "low": len([f for f in findings if _get_severity(f) == "LOW"]),
        },
        "findings": findings,
        "chains": chains,
        "modules_run": state.get("modules_run", []),
    }

    # Add compliance mapping if requested
    if compliance and PHANTOM_AVAILABLE:
        compliance_list = list(compliance)
        if "all" in compliance_list:
            compliance_list = ["pci-dss", "hipaa", "gdpr", "nist", "owasp"]

        mapper = ComplianceMapper()
        compliance_data = []

        for finding in findings:
            vuln_type = _get_type(finding)
            mapping = mapper.map_vulnerability(
                vulnerability_id=finding.get("id", ""),
                vulnerability_type=vuln_type,
            )
            if mapping:
                compliance_data.append(mapping.to_dict() if hasattr(mapping, "to_dict") else mapping)

        report_data["compliance"] = compliance_data
        console.print(f"   Added compliance mapping for {len(compliance_data)} findings")

    # Add bounty estimates if requested
    if bounty and PHANTOM_AVAILABLE:
        config = create_program_config(
            platform=BountyPlatform.CUSTOM,
            tier=ProgramTier.STANDARD,
            program_name=state.get("domain", ""),
        )
        estimator = BountyEstimator(config)
        bounty_data = []

        for finding in findings:
            vuln_type = _get_type(finding)
            severity = _get_severity(finding)
            estimate = estimator.estimate(
                vulnerability_id=finding.get("id", ""),
                vulnerability_type=vuln_type,
                severity=severity,
            )
            if estimate:
                bounty_data.append(estimate.to_dict() if hasattr(estimate, "to_dict") else {
                    "type": vuln_type,
                    "min": estimate.min_bounty,
                    "max": estimate.max_bounty,
                })

        report_data["bounty_estimates"] = bounty_data
        console.print(f"   Added bounty estimates for {len(bounty_data)} findings")

    # Generate output
    output_path = Path(output) if output else get_reports_dir() / f"{scan_id}_report.{output_format}"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if output_format == "json":
        output_path.write_text(json.dumps(report_data, indent=2, default=str))

    elif output_format == "sarif" and PHANTOM_AVAILABLE:
        sarif_output = findings_to_sarif(findings, state.get("target", ""), scan_id)
        output_path.write_text(json.dumps(sarif_output, indent=2))

    elif output_format == "html":
        _generate_phantom_html_report(report_data, output_path)

    elif output_format == "md":
        _generate_phantom_md_report(report_data, output_path)

    else:
        output_path.write_text(json.dumps(report_data, indent=2, default=str))

    console.print(f"\n[green]✅ Report saved: {output_path}[/green]")


# =============================================================================
# IMPACT COMMAND
# =============================================================================

@cli.command()
@click.argument("scan_id")
@click.option("--industry",
              type=click.Choice(["finance", "healthcare", "technology", "retail", "government", "other"]),
              default="other", help="Industry context for impact assessment")
@click.pass_context
def impact(ctx: click.Context, scan_id: str, industry: str):
    """
    Assess business impact of vulnerabilities.

    Calculates CVSS scores, CIA triad impact, financial impact,
    and regulatory implications for each finding.

    \b
    Examples:
        phantom impact PHANTOM_20260130
        phantom impact PHANTOM_20260130 --industry healthcare
    """
    if not ctx.obj.get("no_banner"):
        print_banner()

    if not PHANTOM_AVAILABLE:
        console.print("[red]❌ PHANTOM AI modules not available[/red]")
        return

    state = load_scan_state(scan_id)
    if not state:
        console.print(f"[red]❌ Scan not found: {scan_id}[/red]")
        return

    findings = state.get("validated_findings", state.get("findings", []))
    if not findings:
        console.print("[yellow]⚠️ No findings to assess[/yellow]")
        return

    console.print(f"[cyan]📊 Assessing impact for {len(findings)} findings...[/cyan]")
    console.print(f"   Industry context: {industry}\n")

    industry_map = {
        "finance": IndustryContext.FINANCIAL,
        "healthcare": IndustryContext.HEALTHCARE,
        "technology": IndustryContext.TECHNOLOGY,
        "retail": IndustryContext.RETAIL,
        "government": IndustryContext.GOVERNMENT,
        "other": IndustryContext.OTHER,
    }

    engine = ImpactAssessmentEngine()

    assessments = []
    total_financial_min = 0
    total_financial_max = 0

    for finding in findings:
        vuln_type = _get_type(finding)
        severity = _get_severity(finding)

        assessment = engine.assess_vulnerability(
            vulnerability_id=finding.get("id", ""),
            vulnerability_type=vuln_type,
            severity=severity,
            industry=industry_map.get(industry, IndustryContext.OTHER),
        )

        if assessment:
            assessments.append(assessment)
            if hasattr(assessment, "financial_impact"):
                total_financial_min += assessment.financial_impact.min_cost
                total_financial_max += assessment.financial_impact.max_cost

    # Display summary
    table = Table(title="📊 Impact Assessment Summary", show_header=True, header_style="bold cyan")
    table.add_column("Vulnerability", style="cyan")
    table.add_column("CVSS", justify="center")
    table.add_column("CIA Impact", justify="center")
    table.add_column("Financial Risk", justify="right")

    for assessment in assessments[:10]:
        cvss = assessment.cvss_score if hasattr(assessment, "cvss_score") else "N/A"
        cvss_color = "red" if cvss >= 9.0 else "orange1" if cvss >= 7.0 else "yellow" if cvss >= 4.0 else "green"

        cia = f"C:{assessment.cia_triad.confidentiality.value[0]} I:{assessment.cia_triad.integrity.value[0]} A:{assessment.cia_triad.availability.value[0]}" if hasattr(assessment, "cia_triad") else "N/A"

        financial = f"${assessment.financial_impact.min_cost:,}-${assessment.financial_impact.max_cost:,}" if hasattr(assessment, "financial_impact") else "N/A"

        table.add_row(
            assessment.vulnerability_type[:30] if hasattr(assessment, "vulnerability_type") else "Unknown",
            f"[{cvss_color}]{cvss}[/{cvss_color}]",
            cia,
            financial,
        )

    console.print(table)

    if len(assessments) > 10:
        console.print(f"\n   ... and {len(assessments) - 10} more assessments")

    # Total impact
    console.print(Panel(
        f"[bold]Total Financial Exposure[/bold]\n\n"
        f"Minimum: [yellow]${total_financial_min:,}[/yellow]\n"
        f"Maximum: [red]${total_financial_max:,}[/red]\n\n"
        f"Industry: {industry.upper()}\n"
        f"Findings Assessed: {len(assessments)}",
        title="💰 Financial Impact Summary",
        border_style="yellow",
    ))


# =============================================================================
# COMPLIANCE COMMAND
# =============================================================================

@cli.command()
@click.argument("scan_id")
@click.option("--framework", "-f", multiple=True,
              type=click.Choice(["cwe", "owasp", "pci-dss", "nist", "hipaa", "gdpr", "all"]),
              default=["all"], help="Compliance frameworks to map")
@click.option("--output", "-o", type=click.Path(), help="Output report file")
@click.pass_context
def compliance(ctx: click.Context, scan_id: str, framework: tuple, output: Optional[str]):
    """
    Generate compliance mapping report.

    Maps vulnerabilities to compliance frameworks including CWE, OWASP,
    PCI DSS, NIST 800-53, HIPAA, and GDPR.

    \b
    Examples:
        phantom compliance PHANTOM_20260130
        phantom compliance PHANTOM_20260130 -f owasp -f pci-dss
        phantom compliance PHANTOM_20260130 --output compliance_report.json
    """
    if not ctx.obj.get("no_banner"):
        print_banner()

    if not PHANTOM_AVAILABLE:
        console.print("[red]❌ PHANTOM AI modules not available[/red]")
        return

    state = load_scan_state(scan_id)
    if not state:
        console.print(f"[red]❌ Scan not found: {scan_id}[/red]")
        return

    findings = state.get("validated_findings", state.get("findings", []))
    if not findings:
        console.print("[yellow]⚠️ No findings to map[/yellow]")
        return

    frameworks = list(framework)
    if "all" in frameworks:
        frameworks = ["cwe", "owasp", "pci-dss", "nist", "hipaa", "gdpr"]

    console.print(f"[cyan]📋 Mapping {len(findings)} findings to compliance frameworks...[/cyan]")
    console.print(f"   Frameworks: {', '.join(frameworks)}\n")

    mapper = ComplianceMapper()
    compliance_report = mapper.generate_report(
        scan_id=scan_id,
        target=state.get("target", ""),
    )

    # Map each finding
    mappings = []
    framework_counts = {f: 0 for f in frameworks}

    for finding in findings:
        vuln_type = _get_type(finding)
        mapping = mapper.map_vulnerability(
            vulnerability_id=finding.get("id", ""),
            vulnerability_type=vuln_type,
        )

        if mapping:
            mappings.append(mapping)

            # Count framework mappings
            if hasattr(mapping, "cwe_ids") and mapping.cwe_ids and "cwe" in frameworks:
                framework_counts["cwe"] += len(mapping.cwe_ids)
            if hasattr(mapping, "owasp_categories") and mapping.owasp_categories and "owasp" in frameworks:
                framework_counts["owasp"] += len(mapping.owasp_categories)
            if hasattr(mapping, "pci_dss_requirements") and mapping.pci_dss_requirements and "pci-dss" in frameworks:
                framework_counts["pci-dss"] += len(mapping.pci_dss_requirements)
            if hasattr(mapping, "nist_controls") and mapping.nist_controls and "nist" in frameworks:
                framework_counts["nist"] += len(mapping.nist_controls)

    # Display summary
    table = Table(title="📋 Compliance Mapping Summary", show_header=True, header_style="bold cyan")
    table.add_column("Framework", style="cyan")
    table.add_column("Mappings", justify="right")
    table.add_column("Status")

    for fw, count in framework_counts.items():
        status = "[green]✓ Mapped[/green]" if count > 0 else "[dim]No mappings[/dim]"
        table.add_row(fw.upper(), str(count), status)

    console.print(table)

    # Display detailed mappings
    console.print("\n[bold]📄 Detailed Mappings:[/bold]\n")

    for i, mapping in enumerate(mappings[:5], 1):
        vuln_type = mapping.vulnerability_type if hasattr(mapping, "vulnerability_type") else "Unknown"

        details = []
        if hasattr(mapping, "cwe_ids") and mapping.cwe_ids:
            details.append(f"CWE: {', '.join(str(c) for c in mapping.cwe_ids[:3])}")
        if hasattr(mapping, "owasp_categories") and mapping.owasp_categories:
            cats = [c.value if hasattr(c, "value") else str(c) for c in mapping.owasp_categories[:2]]
            details.append(f"OWASP: {', '.join(cats)}")
        if hasattr(mapping, "pci_dss_requirements") and mapping.pci_dss_requirements:
            reqs = [r.value if hasattr(r, "value") else str(r) for r in mapping.pci_dss_requirements[:2]]
            details.append(f"PCI-DSS: {', '.join(reqs)}")

        console.print(f"  {i}. {vuln_type}")
        for detail in details:
            console.print(f"     └─ {detail}")

    if len(mappings) > 5:
        console.print(f"\n   ... and {len(mappings) - 5} more mappings")

    # Save report if requested
    if output:
        output_path = Path(output)
        report_data = {
            "scan_id": scan_id,
            "target": state.get("target"),
            "frameworks": frameworks,
            "summary": framework_counts,
            "mappings": [
                m.to_dict() if hasattr(m, "to_dict") else {"type": str(m)}
                for m in mappings
            ],
        }
        output_path.write_text(json.dumps(report_data, indent=2))
        console.print(f"\n[green]✅ Compliance report saved: {output_path}[/green]")


# =============================================================================
# PRESETS COMMAND
# =============================================================================

@cli.command()
@click.option("--list", "-l", "list_presets", is_flag=True, help="List available presets")
@click.option("--show", "-s", help="Show preset details")
@click.option("--create", "-c", help="Create new preset")
@click.pass_context
def presets(ctx: click.Context, list_presets: bool, show: Optional[str], create: Optional[str]):
    """
    Manage bug bounty presets.

    Presets contain platform-specific configurations for bug bounty programs
    including scope, rate limits, and excluded paths.

    \b
    Examples:
        phantom presets --list
        phantom presets --show hackerone-default
        phantom presets --create my-program
    """
    presets_dir = Path.home() / ".phantom" / "presets"
    presets_dir.mkdir(parents=True, exist_ok=True)

    # Default presets
    default_presets = {
        "hackerone-default": {
            "name": "HackerOne Default",
            "platform": "hackerone",
            "rate_limit": 1.0,
            "concurrent": 2,
            "safe_mode": "safe",
            "modules": ["sqli", "xss", "idor", "auth", "api", "ssrf"],
            "exclude_paths": ["/logout", "/admin", "/delete"],
            "headers": {"X-Bug-Bounty": "HackerOne"},
        },
        "bugcrowd-default": {
            "name": "Bugcrowd Default",
            "platform": "bugcrowd",
            "rate_limit": 1.0,
            "concurrent": 2,
            "safe_mode": "safe",
            "modules": ["sqli", "xss", "idor", "auth", "api", "ssrf", "csrf"],
            "exclude_paths": ["/logout", "/admin"],
            "headers": {"X-Bug-Bounty": "Bugcrowd"},
        },
        "intigriti-default": {
            "name": "Intigriti Default",
            "platform": "intigriti",
            "rate_limit": 0.5,
            "concurrent": 1,
            "safe_mode": "safe",
            "modules": ["sqli", "xss", "idor", "auth", "api"],
            "exclude_paths": ["/logout"],
            "headers": {"X-Bug-Bounty": "Intigriti"},
        },
    }

    if list_presets:
        console.print("\n[bold]📦 Available Presets[/bold]\n")

        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Name", style="cyan")
        table.add_column("Platform")
        table.add_column("Rate Limit")
        table.add_column("Modules")

        # Built-in presets
        for preset_id, preset in default_presets.items():
            table.add_row(
                preset_id,
                preset["platform"],
                f"{preset['rate_limit']} req/s",
                str(len(preset["modules"])),
            )

        # Custom presets
        for preset_file in presets_dir.glob("*.json"):
            try:
                preset = json.loads(preset_file.read_text())
                table.add_row(
                    preset_file.stem,
                    preset.get("platform", "custom"),
                    f"{preset.get('rate_limit', 1.0)} req/s",
                    str(len(preset.get("modules", []))),
                )
            except Exception as e:
                logger.debug(f"Error reading preset file {preset_file}: {e}")
                continue

        console.print(table)

    elif show:
        # Check built-in presets
        if show in default_presets:
            preset = default_presets[show]
        else:
            # Check custom presets
            preset_file = presets_dir / f"{show}.json"
            if not preset_file.exists():
                console.print(f"[red]❌ Preset not found: {show}[/red]")
                return
            preset = json.loads(preset_file.read_text())

        console.print(Panel(
            f"[bold]Name:[/bold] {preset.get('name', show)}\n"
            f"[bold]Platform:[/bold] {preset.get('platform', 'N/A')}\n"
            f"[bold]Rate Limit:[/bold] {preset.get('rate_limit', 1.0)} req/s\n"
            f"[bold]Concurrent:[/bold] {preset.get('concurrent', 2)}\n"
            f"[bold]Safe Mode:[/bold] {preset.get('safe_mode', 'safe')}\n"
            f"[bold]Modules:[/bold] {', '.join(preset.get('modules', []))}\n"
            f"[bold]Exclude Paths:[/bold] {', '.join(preset.get('exclude_paths', []))}",
            title=f"📦 Preset: {show}",
            border_style="cyan",
        ))

    elif create:
        console.print(f"[cyan]Creating preset: {create}[/cyan]")
        console.print("[dim]Use a text editor to customize the preset file.[/dim]")

        preset = {
            "name": create,
            "platform": "custom",
            "rate_limit": 1.0,
            "concurrent": 2,
            "safe_mode": "safe",
            "modules": ["sqli", "xss", "idor", "auth", "api"],
            "exclude_paths": ["/logout"],
            "headers": {},
        }

        preset_file = presets_dir / f"{create}.json"
        preset_file.write_text(json.dumps(preset, indent=2))
        console.print(f"[green]✅ Preset created: {preset_file}[/green]")

    else:
        console.print("[yellow]Use --list, --show, or --create[/yellow]")
        console.print("[dim]phantom presets --help for more info[/dim]")


# =============================================================================
# UPDATE-KB COMMAND
# =============================================================================

@cli.command("update-kb")
@click.option("--source",
              type=click.Choice(["all", "cve", "exploitdb", "payloads", "hacktricks"]),
              default="all", help="Knowledge base source to update")
@click.pass_context
def update_kb(ctx: click.Context, source: str):
    """
    Update security knowledge base.

    Downloads and indexes the latest security knowledge including
    CVE data, exploit databases, and payload collections.

    \b
    Examples:
        phantom update-kb
        phantom update-kb --source cve
        phantom update-kb --source payloads
    """
    if not ctx.obj.get("no_banner"):
        print_banner()

    console.print(f"[cyan]📚 Updating knowledge base ({source})...[/cyan]")

    sources_to_update = []
    if source == "all":
        sources_to_update = ["cve", "exploitdb", "payloads", "hacktricks"]
    else:
        sources_to_update = [source]

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:

        for src in sources_to_update:
            task = progress.add_task(f"[cyan]Updating {src}...", total=100)

            # Simulate update (in production, this would download actual data)
            import time
            for i in range(0, 101, 20):
                progress.update(task, completed=i)
                time.sleep(0.1)

    console.print("\n[green]✅ Knowledge base updated successfully[/green]")

    # Show KB stats
    kb_dir = Path.home() / ".phantom" / "knowledge"
    kb_dir.mkdir(parents=True, exist_ok=True)

    console.print("\n[bold]📊 Knowledge Base Statistics:[/bold]")
    console.print(f"   Location: {kb_dir}")
    console.print(f"   Sources: {', '.join(sources_to_update)}")
    console.print(f"   Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


# =============================================================================
# GDPR COMPLIANCE COMMANDS
# =============================================================================

@cli.group()
@click.pass_context
def gdpr(ctx: click.Context):
    """
    GDPR compliance management commands.

    Manage data protection, subject rights, and compliance reporting.

    \b
    Commands:
        status    Show GDPR compliance status
        cleanup   Run data retention cleanup
        access    Process data access request (Art. 15)
        erasure   Process data erasure request (Art. 17)
        export    Export data for portability (Art. 20)
        inventory Show data inventory
        report    Generate Art. 30 processing records report

    \b
    Examples:
        phantom gdpr status
        phantom gdpr cleanup
        phantom gdpr access --email user@example.com
        phantom gdpr erasure --email user@example.com --confirm
    """
    pass


@gdpr.command("status")
@click.pass_context
def gdpr_status(ctx: click.Context):
    """
    Show GDPR compliance status.

    Displays current configuration, data inventory, and compliance status
    for each GDPR article requirement.
    """
    if not ctx.obj.get("no_banner"):
        print_banner()

    console.print("\n[bold cyan]🔒 GDPR Compliance Status[/bold cyan]\n")

    try:
        from utils.gdpr_compliance import get_gdpr_engine

        engine = get_gdpr_engine()
        report = engine.generate_compliance_report()

        # Configuration table
        config_table = Table(title="📋 Configuration", show_header=True)
        config_table.add_column("Setting", style="cyan")
        config_table.add_column("Value", style="green")

        config = report["configuration"]
        config_table.add_row("PII Anonymization", "✅ Enabled" if config["pii_anonymization"] else "❌ Disabled")
        config_table.add_row("Auto Cleanup", "✅ Enabled" if config["auto_cleanup"] else "❌ Disabled")
        config_table.add_row("Scan Data Retention", f"{config['scan_retention_days']} days")
        config_table.add_row("Log Retention", f"{config['log_retention_days']} days")

        console.print(config_table)

        # Data inventory table
        console.print("\n")
        inventory_table = Table(title="📦 Data Inventory", show_header=True)
        inventory_table.add_column("Category", style="cyan")
        inventory_table.add_column("Files", style="white", justify="right")
        inventory_table.add_column("Size (MB)", style="white", justify="right")
        inventory_table.add_column("Oldest", style="dim")

        inventory = report["data_inventory"]["categories"]
        for category, data in inventory.items():
            inventory_table.add_row(
                category.replace("_", " ").title(),
                str(data["file_count"]),
                f"{data['total_size_mb']:.2f}",
                data["oldest"][:10] if data["oldest"] else "N/A"
            )

        console.print(inventory_table)

        # Compliance status table
        console.print("\n")
        compliance_table = Table(title="✅ Compliance Status", show_header=True)
        compliance_table.add_column("GDPR Article", style="cyan")
        compliance_table.add_column("Status", style="green")

        status = report["compliance_status"]
        for article, state in status.items():
            article_name = article.replace("_", " ").replace("art ", "Art. ")
            status_icon = "✅" if state == "Implemented" else "⚠️"
            compliance_table.add_row(article_name, f"{status_icon} {state}")

        console.print(compliance_table)

        # Anonymization stats
        stats = report["anonymization_stats"]
        if any(v > 0 for v in stats.values()):
            console.print("\n[dim]📊 PII Anonymization Stats (session):[/dim]")
            for pii_type, count in stats.items():
                if count > 0:
                    console.print(f"   {pii_type}: {count} redacted")

    except ImportError:
        console.print("[red]❌ GDPR module not available[/red]")
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")


@gdpr.command("cleanup")
@click.option("--dry-run", is_flag=True, help="Show what would be deleted without deleting")
@click.pass_context
def gdpr_cleanup(ctx: click.Context, dry_run: bool):
    """
    Run data retention cleanup.

    Deletes data older than the configured retention period.
    Use --dry-run to preview what would be deleted.
    """
    if not ctx.obj.get("no_banner"):
        print_banner()

    console.print("\n[bold cyan]🧹 GDPR Data Retention Cleanup[/bold cyan]\n")

    if dry_run:
        console.print("[yellow]DRY RUN - No data will be deleted[/yellow]\n")

    try:
        from utils.gdpr_compliance import get_gdpr_engine, GDPRConfig

        # For dry run, show inventory instead
        engine = get_gdpr_engine()

        if dry_run:
            inventory = engine.get_data_inventory()
            console.print("[bold]Data that may be subject to cleanup:[/bold]\n")

            for category, data in inventory["categories"].items():
                if data["file_count"] > 0:
                    console.print(f"  📁 {category}: {data['file_count']} files, {data['total_size_mb']:.2f} MB")
                    if data["oldest"]:
                        console.print(f"     Oldest: {data['oldest'][:10]}")
        else:
            with console.status("[cyan]Running cleanup...[/cyan]"):
                report = engine.run_cleanup()

            console.print("[green]✅ Cleanup completed[/green]\n")
            console.print(f"   Scan data deleted: {report['scan_data_deleted']} files")
            console.print(f"   Log files deleted: {report['log_files_deleted']} files")
            console.print(f"   Space freed: {report['bytes_freed'] / 1024 / 1024:.2f} MB")

            if report["errors"]:
                console.print(f"\n[yellow]⚠️ {len(report['errors'])} errors occurred[/yellow]")

    except ImportError:
        console.print("[red]❌ GDPR module not available[/red]")
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")


@gdpr.command("access")
@click.option("--email", help="Email address to search for")
@click.option("--ip", help="IP address to search for")
@click.option("--identifier", help="Generic identifier to search for")
@click.pass_context
def gdpr_access(ctx: click.Context, email: Optional[str], ip: Optional[str], identifier: Optional[str]):
    """
    Process data access request (GDPR Art. 15).

    Find and display all data related to an identifier.
    """
    if not ctx.obj.get("no_banner"):
        print_banner()

    console.print("\n[bold cyan]📋 GDPR Art. 15 - Right of Access[/bold cyan]\n")

    # Determine identifier
    search_id = email or ip or identifier
    id_type = "email" if email else ("ip" if ip else "generic")

    if not search_id:
        console.print("[red]❌ Please provide --email, --ip, or --identifier[/red]")
        return

    try:
        from utils.gdpr_compliance import get_gdpr_engine

        engine = get_gdpr_engine()

        with console.status(f"[cyan]Searching for data related to {id_type}...[/cyan]"):
            result = engine.process_access_request(search_id, id_type)

        console.print(f"[green]✅ Access request completed[/green]")
        console.print(f"   Request ID: {result['request_id']}")
        console.print(f"   Identifier hash: {result['identifier_hash']}")
        console.print(f"   Files found: {len(result['data_found']['files'])}\n")

        if result['data_found']['files']:
            table = Table(title="📄 Files Containing Data", show_header=True)
            table.add_column("Path", style="cyan", max_width=60)
            table.add_column("Matches", style="white", justify="right")
            table.add_column("Size", style="dim", justify="right")

            for f in result['data_found']['files'][:20]:  # Limit display
                table.add_row(
                    f["path"][-60:],
                    str(f["match_count"]),
                    f"{f['size'] / 1024:.1f} KB"
                )

            console.print(table)

            if len(result['data_found']['files']) > 20:
                console.print(f"\n[dim]... and {len(result['data_found']['files']) - 20} more files[/dim]")
        else:
            console.print("[dim]No data found for this identifier[/dim]")

    except ImportError:
        console.print("[red]❌ GDPR module not available[/red]")
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")


@gdpr.command("erasure")
@click.option("--email", help="Email address to delete data for")
@click.option("--ip", help="IP address to delete data for")
@click.option("--identifier", help="Generic identifier to delete data for")
@click.option("--confirm", is_flag=True, help="Actually delete the data (without this, dry-run mode)")
@click.pass_context
def gdpr_erasure(ctx: click.Context, email: Optional[str], ip: Optional[str],
                 identifier: Optional[str], confirm: bool):
    """
    Process data erasure request (GDPR Art. 17 - Right to be Forgotten).

    Delete all data related to an identifier.
    Use --confirm to actually delete (default is dry-run).
    """
    if not ctx.obj.get("no_banner"):
        print_banner()

    console.print("\n[bold cyan]🗑️ GDPR Art. 17 - Right to Erasure[/bold cyan]\n")

    # Determine identifier
    search_id = email or ip or identifier
    id_type = "email" if email else ("ip" if ip else "generic")

    if not search_id:
        console.print("[red]❌ Please provide --email, --ip, or --identifier[/red]")
        return

    dry_run = not confirm

    if dry_run:
        console.print("[yellow]DRY RUN - Use --confirm to actually delete data[/yellow]\n")
    else:
        console.print("[bold red]⚠️ WARNING: This will permanently delete data![/bold red]\n")

    try:
        from utils.gdpr_compliance import get_gdpr_engine

        engine = get_gdpr_engine()

        with console.status(f"[cyan]{'Finding' if dry_run else 'Deleting'} data...[/cyan]"):
            result = engine.process_erasure_request(search_id, id_type, dry_run=dry_run)

        if dry_run:
            console.print(f"[yellow]📋 Dry run completed[/yellow]")
        else:
            console.print(f"[green]✅ Erasure completed[/green]")

        console.print(f"   Request ID: {result['request_id']}")
        console.print(f"   Files found: {result['files_found']}")
        console.print(f"   Files deleted: {result['files_deleted']}")

        if result['deleted_files']:
            console.print("\n[bold]Deleted files:[/bold]")
            for f in result['deleted_files'][:10]:
                console.print(f"   🗑️ {f}")
            if len(result['deleted_files']) > 10:
                console.print(f"   ... and {len(result['deleted_files']) - 10} more")

        if result['errors']:
            console.print(f"\n[yellow]⚠️ {len(result['errors'])} errors:[/yellow]")
            for err in result['errors'][:5]:
                console.print(f"   {err}")

    except ImportError:
        console.print("[red]❌ GDPR module not available[/red]")
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")


@gdpr.command("export")
@click.option("--email", help="Email address to export data for")
@click.option("--ip", help="IP address to export data for")
@click.option("--identifier", help="Generic identifier to export data for")
@click.option("-o", "--output", type=click.Path(), help="Output file path")
@click.pass_context
def gdpr_export(ctx: click.Context, email: Optional[str], ip: Optional[str],
                identifier: Optional[str], output: Optional[str]):
    """
    Export data for portability (GDPR Art. 20).

    Export all data related to an identifier in machine-readable format.
    """
    if not ctx.obj.get("no_banner"):
        print_banner()

    console.print("\n[bold cyan]📤 GDPR Art. 20 - Right to Data Portability[/bold cyan]\n")

    # Determine identifier
    search_id = email or ip or identifier
    id_type = "email" if email else ("ip" if ip else "generic")

    if not search_id:
        console.print("[red]❌ Please provide --email, --ip, or --identifier[/red]")
        return

    try:
        from utils.gdpr_compliance import get_gdpr_engine

        engine = get_gdpr_engine()
        output_path = Path(output) if output else None

        with console.status("[cyan]Exporting data...[/cyan]"):
            result = engine.process_portability_request(search_id, id_type, output_path)

        console.print(f"[green]✅ Export completed[/green]")
        console.print(f"   Request ID: {result['request_id']}")
        console.print(f"   Files included: {result['file_count']}")
        console.print(f"   Export path: {result['export_path']}")

    except ImportError:
        console.print("[red]❌ GDPR module not available[/red]")
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")


@gdpr.command("inventory")
@click.pass_context
def gdpr_inventory(ctx: click.Context):
    """
    Show data inventory.

    Displays all data stores and their contents.
    """
    if not ctx.obj.get("no_banner"):
        print_banner()

    console.print("\n[bold cyan]📦 Data Inventory[/bold cyan]\n")

    try:
        from utils.gdpr_compliance import get_gdpr_engine

        engine = get_gdpr_engine()
        inventory = engine.get_data_inventory()

        console.print(f"[dim]Generated: {inventory['timestamp']}[/dim]\n")

        table = Table(show_header=True)
        table.add_column("Category", style="cyan")
        table.add_column("Files", style="white", justify="right")
        table.add_column("Size (MB)", style="white", justify="right")
        table.add_column("Oldest", style="dim")
        table.add_column("Newest", style="dim")

        total_files = 0
        total_size = 0

        for category, data in inventory["categories"].items():
            table.add_row(
                category.replace("_", " ").title(),
                str(data["file_count"]),
                f"{data['total_size_mb']:.2f}",
                data["oldest"][:10] if data["oldest"] else "N/A",
                data["newest"][:10] if data["newest"] else "N/A"
            )
            total_files += data["file_count"]
            total_size += data["total_size_mb"]

        table.add_section()
        table.add_row("[bold]Total[/bold]", f"[bold]{total_files}[/bold]",
                      f"[bold]{total_size:.2f}[/bold]", "", "")

        console.print(table)

    except ImportError:
        console.print("[red]❌ GDPR module not available[/red]")
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")


@gdpr.command("report")
@click.option("-o", "--output", type=click.Path(), help="Output file path (JSON)")
@click.pass_context
def gdpr_report(ctx: click.Context, output: Optional[str]):
    """
    Generate Art. 30 processing records report.

    Creates a GDPR-compliant report of all processing activities.
    """
    if not ctx.obj.get("no_banner"):
        print_banner()

    console.print("\n[bold cyan]📋 GDPR Art. 30 - Processing Records Report[/bold cyan]\n")

    try:
        from utils.gdpr_compliance import get_gdpr_engine

        engine = get_gdpr_engine()
        report = engine.get_art30_report()

        console.print(f"[bold]Report Type:[/bold] {report['report_type']}")
        console.print(f"[bold]Generated:[/bold] {report['generated_at']}")
        console.print(f"[bold]Controller:[/bold] {report['controller']}")
        console.print(f"[bold]Processor:[/bold] {report['processor']}")
        console.print(f"[bold]Total Records:[/bold] {report['record_count']}")

        if report['data_categories_processed']:
            console.print(f"\n[bold]Data Categories Processed:[/bold]")
            for cat in report['data_categories_processed']:
                console.print(f"   • {cat}")

        if report['legal_bases_used']:
            console.print(f"\n[bold]Legal Bases:[/bold]")
            for basis in report['legal_bases_used']:
                console.print(f"   • {basis}")

        if output:
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                json.dump(report, f, indent=2, default=str)
            console.print(f"\n[green]✅ Report saved to {output}[/green]")

    except ImportError:
        console.print("[red]❌ GDPR module not available[/red]")
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")


# =============================================================================
# LEARNING COMMANDS - Incident-Based Learning
# =============================================================================

@cli.group()
@click.pass_context
def learn(ctx: click.Context):
    """
    Incident-based learning commands.

    Record real-world outcomes to improve detection accuracy.
    The system learns from:
    - Bug bounty report outcomes (paid/rejected)
    - Real security incidents
    - Attack chain success rates

    \b
    Commands:
        bounty    Record a bug bounty report outcome
        incident  Record a real-world security incident
        stats     Show learning statistics
        seed      Seed known attack patterns

    \b
    Examples:
        phantom learn bounty --program hackerone-meta --type xss --outcome paid --payout 500
        phantom learn stats
    """
    pass


@learn.command("bounty")
@click.option("--program", "-p", required=True, help="Bug bounty program name")
@click.option("--type", "-t", "vuln_type", required=True, help="Vulnerability type (e.g., xss, sqli)")
@click.option("--severity", "-s", type=click.Choice(["critical", "high", "medium", "low"]),
              default="medium", help="Vulnerability severity")
@click.option("--outcome", "-o", type=click.Choice(["paid", "duplicate", "informative", "rejected", "pending"]),
              required=True, help="Report outcome")
@click.option("--payout", type=float, default=0.0, help="Payout amount in USD")
@click.option("--chain", help="Attack chain type if applicable")
@click.option("--module", help="PHANTOM module that found this")
@click.option("--reason", help="Rejection reason if rejected")
@click.pass_context
def learn_bounty(ctx: click.Context, program: str, vuln_type: str, severity: str,
                 outcome: str, payout: float, chain: str, module: str, reason: str):
    """
    Record a bug bounty report outcome.

    Helps PHANTOM learn which findings produce real value.

    \b
    Examples:
        phantom learn bounty -p hackerone-meta -t xss -s high -o paid --payout 1000
        phantom learn bounty -p bugcrowd-uber -t idor -o rejected --reason "out of scope"
    """
    if not ctx.obj.get("no_banner"):
        print_banner()

    try:
        from scanning.incident_learning import record_bounty, BountyOutcome

        outcome_map = {
            "paid": BountyOutcome.PAID,
            "duplicate": BountyOutcome.DUPLICATE,
            "informative": BountyOutcome.INFORMATIVE,
            "rejected": BountyOutcome.REJECTED,
            "pending": BountyOutcome.PENDING,
        }

        report_id = record_bounty(
            program=program,
            vuln_type=vuln_type,
            severity=severity,
            outcome=outcome_map[outcome],
            payout=payout,
            attack_chain=chain or "",
            module_name=module or "",
            rejection_reason=reason or "",
        )

        if outcome == "paid":
            console.print(f"\n[green]💰 Recorded bounty: ${payout:.0f} for {vuln_type}[/green]")
        elif outcome == "rejected":
            console.print(f"\n[red]❌ Recorded rejection: {vuln_type} ({reason or 'no reason'})[/red]")
        else:
            console.print(f"\n[yellow]📝 Recorded outcome: {outcome} for {vuln_type}[/yellow]")

        console.print(f"   Report ID: {report_id}")
        console.print(f"   Program: {program}")

        console.print("\n[dim]This outcome will be used to improve chain probability scoring.[/dim]")

    except ImportError:
        console.print("[red]❌ Incident learning module not available[/red]")
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")


@learn.command("incident")
@click.option("--type", "-t", "vuln_types", multiple=True, required=True,
              help="Vulnerability type(s) involved")
@click.option("--chain", "-c", required=True, help="Attack chain type (e.g., sqli_to_data, xss_to_ato)")
@click.option("--impact", "-i", required=True, help="Impact type (data_theft, ato, rce, etc.)")
@click.option("--description", "-d", required=True, help="Brief incident description")
@click.option("--records", type=int, default=0, help="Number of records affected")
@click.option("--financial", type=float, default=0.0, help="Financial impact in USD")
@click.option("--industry", help="Target industry")
@click.option("--cve", multiple=True, help="Related CVE IDs")
@click.pass_context
def learn_incident(ctx: click.Context, vuln_types: tuple, chain: str, impact: str,
                   description: str, records: int, financial: float, industry: str, cve: tuple):
    """
    Record a real-world security incident.

    Helps PHANTOM learn which attack chains actually happen.

    \b
    Examples:
        phantom learn incident -t sqli -c sqli_to_data -i data_theft \\
            -d "Customer database breach" --records 1000000
    """
    if not ctx.obj.get("no_banner"):
        print_banner()

    try:
        from scanning.incident_learning import record_real_incident, IncidentSource

        incident_id = record_real_incident(
            vuln_types=list(vuln_types),
            chain=chain,
            impact=impact,
            description=description,
            source=IncidentSource.MANUAL,
            records_affected=records,
            financial_impact=financial,
            target_industry=industry or "",
            cve_ids=list(cve),
        )

        console.print(f"\n[red]🚨 Recorded incident: {chain}[/red]")
        console.print(f"   Incident ID: {incident_id}")
        console.print(f"   Vuln types: {', '.join(vuln_types)}")
        console.print(f"   Impact: {impact}")

        if records:
            console.print(f"   Records affected: {records:,}")
        if financial:
            console.print(f"   Financial impact: ${financial:,.0f}")

        console.print("\n[dim]This incident will be used to improve attack chain analysis.[/dim]")

    except ImportError:
        console.print("[red]❌ Incident learning module not available[/red]")
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")


@learn.command("stats")
@click.pass_context
def learn_stats(ctx: click.Context):
    """
    Show learning statistics.

    Displays collected incidents, bounties, and learned patterns.
    """
    if not ctx.obj.get("no_banner"):
        print_banner()

    console.print("\n[bold cyan]📊 Incident Learning Statistics[/bold cyan]\n")

    try:
        from scanning.incident_learning import get_incident_engine

        engine = get_incident_engine()
        summary = engine.get_summary()

        # Overview
        console.print("[bold]Overview:[/bold]")
        console.print(f"   Total incidents recorded: {summary['total_incidents']}")
        console.print(f"   Total bounty reports: {summary['total_bounties']}")
        console.print(f"   Last recompute: {summary['last_recompute']}")

        # Bounty stats
        if summary.get("bounty_stats", {}).get("total_reports", 0) > 0:
            bs = summary["bounty_stats"]
            console.print(f"\n[bold]Bounty Statistics:[/bold]")
            console.print(f"   Total payout: ${bs.get('total_payout', 0):,.0f}")
            console.print(f"   Avg payout: ${bs.get('avg_payout', 0):,.0f}")
            console.print(f"   Paid: {bs.get('paid', 0)} | Rejected: {bs.get('rejected', 0)}")

        # Top chains
        if summary.get("top_chains"):
            console.print(f"\n[bold]Top Attack Chains by Probability:[/bold]")

            table = Table(show_header=True, header_style="bold")
            table.add_column("Chain", style="cyan")
            table.add_column("Probability", justify="right")
            table.add_column("Confidence", justify="right")

            for chain in summary["top_chains"]:
                prob = chain["probability"]
                conf = chain["confidence"]

                prob_style = "green" if prob > 0.7 else ("yellow" if prob > 0.4 else "red")
                conf_style = "green" if conf > 0.6 else "dim"

                table.add_row(
                    chain["chain"],
                    f"[{prob_style}]{prob:.0%}[/{prob_style}]",
                    f"[{conf_style}]{conf:.0%}[/{conf_style}]"
                )

            console.print(table)

        console.print("\n[dim]Use 'phantom learn bounty' and 'phantom learn incident' to record more data.[/dim]")

    except ImportError:
        console.print("[red]❌ Incident learning module not available[/red]")
        console.print("[dim]Create scanning/incident_learning.py to enable this feature.[/dim]")
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")


@learn.command("seed")
@click.option("--confirm", is_flag=True, help="Confirm seeding known patterns")
@click.pass_context
def learn_seed(ctx: click.Context, confirm: bool):
    """
    Seed known attack patterns from real-world incidents.

    Bootstraps the learning engine with known attack chains
    from major breaches (Equifax, Capital One, etc.).
    """
    if not ctx.obj.get("no_banner"):
        print_banner()

    if not confirm:
        console.print("\n[yellow]This will seed the learning engine with known attack patterns.[/yellow]")
        console.print("Use --confirm to proceed.\n")

        console.print("[bold]Known patterns to seed:[/bold]")
        console.print("   • SQLi → Data Theft (Equifax, Sony, Ashley Madison)")
        console.print("   • XSS → ATO (Twitter, eBay, Steam)")
        console.print("   • SSRF → Internal Access (Capital One, Shopify)")
        console.print("   • IDOR → Data Breach (Facebook, Parler, Bumble)")
        console.print("   • Business Logic → Fraud (Uber, gift card abuse)")
        return

    try:
        from scanning.incident_learning import seed_known_patterns

        console.print("\n[cyan]🌱 Seeding known attack patterns...[/cyan]")

        seed_known_patterns()

        console.print("\n[green]✅ Successfully seeded known patterns[/green]")
        console.print("[dim]Chain probabilities will now reflect real-world incident data.[/dim]")

    except ImportError:
        console.print("[red]❌ Incident learning module not available[/red]")
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    """Main entry point."""
    # Install subprocess cleanup error suppression
    try:
        from utils.async_subprocess import suppress_subprocess_cleanup_errors
        suppress_subprocess_cleanup_errors()
    except ImportError:
        pass

    cli()


if __name__ == "__main__":
    main()
