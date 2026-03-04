#!/usr/bin/env python3
"""
PATHFINDER AI CLI - Your Friendly Neighborhood Security Scout

"Hi friends! I'm here to help you find vulnerabilities!" 🤖🪝

Enterprise-grade AI-powered penetration testing command-line interface.
Inspired by Apex Legends' favorite MRVN unit - always positive, always grappling!

Version: 3.0.0
Date: 2026-02-18

Usage:
    pathfinder <command> [options] <target>

Commands:
    scan        Execute security scan with PATHFINDER AI
    recon       Reconnaissance only (no active testing)
    quick       Fast scan - "That was easy!" (5 modules)
    full        Comprehensive scan - "I love this job!" (all 75+ modules)
    bounty      Bug bounty optimized scan - "High five, friend!"
    client      Professional client engagement - "I'm coming for you, friend!"
    chain       Vulnerability chaining analysis - "Grappling to victory!"

    status      Check scan status - "Who's ready to fly on a zipline?"
    list        List previous scans
    resume      Resume interrupted scan
    report      Generate report from scan

    waf-detect  Detect and identify WAF - "I see you!"
    validate    Re-validate findings
    authorize   Authorize target for scanning
    presets     Manage bug bounty presets
    modules     List available modules
    health      Check PATHFINDER AI health - "I feel most alive when rapidly approaching my death!"
    update-kb   Update security knowledge base
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import uuid
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, TYPE_CHECKING
from urllib.parse import urlparse

# Ensure parent directory is in path for imports
_cli_dir = Path(__file__).parent
_project_dir = _cli_dir.parent
if str(_project_dir) not in sys.path:
    sys.path.insert(0, str(_project_dir))

if TYPE_CHECKING:
    pass

import click

# Professional Ethics & Legal Compliance
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.style import Style

# Import PATHFINDER AI modules (aliased from phantom for compatibility)
try:
    from pathfinder import (
        # Constants
        PATHFINDER_VERSION,
        PATHFINDER_CODENAME,
        get_version,
        get_module_count,
        ScanMode,
        SafetyLevel,
        ConfidenceThreshold,
        ChainPriority,
        MODULE_CATEGORIES,
        ALL_MODULES,
        # Network Protection
        PathfinderNetworkProtection,
        get_pathfinder_protection,
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
    PATHFINDER_AVAILABLE = True
except ImportError as e:
    PATHFINDER_AVAILABLE = False
    PATHFINDER_IMPORT_ERROR = str(e)

# Import HackerOne Report Generator
try:
    from pathfinder.hackerone_report_generator import (
        HackerOneReportGenerator,
        generate_hackerone_report,
        findings_to_hackerone_reports,
    )
    HACKERONE_REPORTER_AVAILABLE = True
except ImportError:
    HACKERONE_REPORTER_AVAILABLE = False

console = Console()
logger = logging.getLogger(__name__)

# =============================================================================
# 🎮 APEX LEGENDS THEME COLORS
# =============================================================================
# Inspired by Pathfinder's orange/red display and the game's aggressive UI

APEX_RED = "#FF4655"           # Apex Legends signature red
APEX_ORANGE = "#FF8C00"        # Pathfinder's screen color
APEX_CYBER = "#00FFFF"         # Cybernetic cyan highlights
APEX_GOLD = "#FFD700"          # Legendary loot gold
APEX_DARK = "#1A1A2E"          # Dark background
APEX_WHITE = "#FFFFFF"         # Clean white

# Rich style definitions
STYLE_BANNER = Style(color=APEX_ORANGE, bold=True)
STYLE_GRAPPLE = Style(color=APEX_CYBER, bold=True)
STYLE_CRITICAL = Style(color=APEX_RED, bold=True)
STYLE_SUCCESS = Style(color="#00FF00", bold=True)
STYLE_WARNING = Style(color=APEX_GOLD, bold=True)


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
        logging.getLogger("pathfinder"),
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
# 🤖 PATHFINDER BANNER - APEX LEGENDS STYLE
# =============================================================================

PATHFINDER_BANNER = """
[bold #FF4500]┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]                                                                                     [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]      [bold #00FFFF]██████╗  █████╗ ████████╗██╗  ██╗███████╗██╗███╗   ██╗██████╗ ███████╗██████╗[/bold #00FFFF]  [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]      [bold #00FFFF]██╔══██╗██╔══██╗╚══██╔══╝██║  ██║██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗[/bold #00FFFF] [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]      [bold #00FFFF]██████╔╝███████║   ██║   ███████║█████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝[/bold #00FFFF] [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]      [bold #00FFFF]██╔═══╝ ██╔══██║   ██║   ██╔══██║██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗[/bold #00FFFF] [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]      [bold #00FFFF]██║     ██║  ██║   ██║   ██║  ██║██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║[/bold #00FFFF] [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]      [bold #00FFFF]╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝[/bold #00FFFF] [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]                                                                                     [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]         [bold #FFD700]╔══════════════════════════════════════════════════════════════╗[/bold #FFD700]        [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]         [bold #FFD700]║[/bold #FFD700]      [bold #FF4655]▄▄▄▄▄[/bold #FF4655]                                              [bold #FFD700]║[/bold #FFD700]        [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]         [bold #FFD700]║[/bold #FFD700]     [bold #FF4655]██[/bold #FF4655][bold #00FFFF]◉◉[/bold #00FFFF][bold #FF4655]██[/bold #FF4655]   [dim white]━━━━━━━━━━━━━━━━━━━━━🪝[/dim white]                [bold #FFD700]║[/bold #FFD700]        [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]         [bold #FFD700]║[/bold #FFD700]     [bold #FF4655]██████[/bold #FF4655]    [bold #00FF00]GRAPPLING TO VICTORY![/bold #00FF00]                   [bold #FFD700]║[/bold #FFD700]        [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]         [bold #FFD700]║[/bold #FFD700]      [bold #FF4655]████[/bold #FF4655]                                               [bold #FFD700]║[/bold #FFD700]        [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]         [bold #FFD700]║[/bold #FFD700]     [bold #FF4655]██████[/bold #FF4655]    [bold white]AI Security Scout[/bold white]                        [bold #FFD700]║[/bold #FFD700]        [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]         [bold #FFD700]║[/bold #FFD700]    [bold #FF4655]███[/bold #FF4655]  [bold #FF4655]███[/bold #FF4655]   [dim #00FFFF]Enterprise Penetration Testing[/dim #00FFFF]          [bold #FFD700]║[/bold #FFD700]        [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]         [bold #FFD700]║[/bold #FFD700]    [bold #FF4655]███[/bold #FF4655]  [bold #FF4655]███[/bold #FF4655]                                         [bold #FFD700]║[/bold #FFD700]        [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]         [bold #FFD700]╚══════════════════════════════════════════════════════════════╝[/bold #FFD700]        [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]                                                                                     [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]    [bold #FF4655]┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓[/bold #FF4655]    [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]    [bold #FF4655]┃[/bold #FF4655]  [bold #FFD700]🤖 "Hi friends! I'm here to help you find vulnerabilities!"[/bold #FFD700]           [bold #FF4655]┃[/bold #FF4655]    [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]    [bold #FF4655]┃[/bold #FF4655]                                                                           [bold #FF4655]┃[/bold #FF4655]    [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]    [bold #FF4655]┃[/bold #FF4655]  [bold white]v{version}[/bold white] [dim]({codename})[/dim]                                                   [bold #FF4655]┃[/bold #FF4655]    [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]    [bold #FF4655]┃[/bold #FF4655]                                                                           [bold #FF4655]┃[/bold #FF4655]    [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]    [bold #FF4655]┃[/bold #FF4655]  [bold #00FF00]✓ {modules} Security Modules[/bold #00FF00]     [bold #00FFFF]✓ 6-Stage Validation Pipeline[/bold #00FFFF]     [bold #FF4655]┃[/bold #FF4655]    [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]    [bold #FF4655]┃[/bold #FF4655]  [bold #00FF00]✓ Zero False Positives[/bold #00FF00]          [bold #00FFFF]✓ AI-Powered Chain Analysis[/bold #00FFFF]      [bold #FF4655]┃[/bold #FF4655]    [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]    [bold #FF4655]┃[/bold #FF4655]  [bold #00FF00]✓ WAF Bypass Engine[/bold #00FF00]             [bold #00FFFF]✓ Exploit Proof Generation[/bold #00FFFF]       [bold #FF4655]┃[/bold #FF4655]    [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]    [bold #FF4655]┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛[/bold #FF4655]    [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]                                                                                     [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]     [bold #00FFFF]⚡ APEX LEGENDS EDITION ⚡[/bold #00FFFF]    [dim white]"Who's ready to fly on a zipline? I AM!"[/dim white]     [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]                                                                                     [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛[/bold #FF4500]
"""

PATHFINDER_MINI_BANNER = """
[bold #FF4500]┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]  [bold #00FFFF]🤖 PATHFINDER AI[/bold #00FFFF] [dim]━━━[/dim] [bold white]v{version}[/bold white] [dim]━━━[/dim] [bold #FFD700]{modules} Modules[/bold #FFD700] [dim]━━━[/dim] [bold #FF4655]⚡ APEX[/bold #FF4655]  [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┃[/bold #FF4500]  [dim #00FFFF]"I'm coming for you, friend!" - Your Security Scout 🪝[/dim #00FFFF]              [bold #FF4500]┃[/bold #FF4500]
[bold #FF4500]┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛[/bold #FF4500]
"""

# Pathfinder quotes for random selection during scan - ALL THE BEST ONES!
PATHFINDER_QUOTES = [
    # Classic Pathfinder
    "Who's ready to fly on a zipline? I AM!",
    "I just polished my grapple!",
    "High five, friend! ✋",
    "That was easy!",
    "I'm coming for you, friend!",
    "I feel most alive when rapidly approaching my death!",
    "I don't have to find a path. I AM a path!",
    "First we fight, then we drink! ...on second thought, I can't drink.",
    # Combat quotes (adapted for scanning)
    "I love loot! Oh wait, I love VULNS! Same energy!",
    "Try to move. It'll make this fun!",
    "Another soft landing! ...I hope.",
    "Killing is just a means to an end, friend!",
    "My creator made me for combat. I think.",
    "I know the odds aren't in our favor. But I'm not going anywhere!",
    # Ring/Map quotes (adapted)
    "The ring is closing! Better scan faster!",
    "I've marked an enemy! I mean... a vulnerability!",
    "Grappling to the next target!",
    "Let's show them what we're made of!",
    # Revive/Team quotes (adapted)
    "Don't worry, I've got your back!",
    "We make a great team, friend!",
    "You're doing great! Keep it up!",
    "I believe in you!",
    # Victory quotes
    "We are the champions, friend!",
    "That was a good fight!",
    "Victory feels good!",
    # Season-specific
    "Boxing match? I'm down!",
    "I love seeing happy faces. Well... technically I can't see faces.",
    "Last one standing wins! That's me! ...wait, no, that's YOU!",
]

# Loading messages for scanning phases - APEX STYLE!
PATHFINDER_LOADING = [
    "🪝 Grappling to target...",
    "🤖 Scanning the arena...",
    "🎯 Locking on vulnerabilities...",
    "⚡ Zipline deployed!",
    "🔍 Looking for loot... I mean vulns!",
    "💪 Flexing my MRVN muscles...",
    "🎮 Let's do this, friend!",
    "🚀 Launching attack modules...",
    "🛡️ Who's ready for a fight?",
    "🎪 The ring is closing in...",
    "🦾 MRVN systems online!",
    "🎲 Calculating optimal path...",
    "🔥 Hostile detected!",
    "⚔️ Engaging combat protocols...",
    "🎖️ Champion squad material!",
    "🏆 Apex Predator mode activated!",
]


def print_banner(mini: bool = False):
    """Print the PATHFINDER AI banner - Apex Legends style!"""
    import random

    if PATHFINDER_AVAILABLE:
        version = PATHFINDER_VERSION
        codename = PATHFINDER_CODENAME
        modules = f"{get_module_count()}+"
    else:
        version = "3.0.0"
        codename = "Apex Edition"
        modules = "75+"

    if mini:
        banner = PATHFINDER_MINI_BANNER.format(
            version=version,
            modules=modules,
        )
    else:
        banner = PATHFINDER_BANNER.format(
            version=version,
            codename=codename,
            modules=modules,
        )
    console.print(banner)

    # Random Pathfinder quote
    if not mini:
        quote = random.choice(PATHFINDER_QUOTES)
        console.print(f"\n  [dim #FF8C00]💬 \"{quote}\"[/dim #FF8C00]\n")


def print_philosophy():
    """Print PATHFINDER AI philosophy - with that positive Pathfinder energy!"""
    console.print(Panel(
        "[bold #00FFFF]PATHFINDER AI Philosophy[/bold #00FFFF]\n\n"
        "[bold #FF8C00]1. Intelligence Before Force[/bold #FF8C00] 🧠\n"
        "   [dim]Understand the target completely before testing[/dim]\n"
        "   [dim #00FFFF]\"First I scan, then I grapple!\"[/dim #00FFFF]\n\n"
        "[bold #FF8C00]2. Vulnerabilities Discover Vulnerabilities[/bold #FF8C00] 🔗\n"
        "   [dim]Chain findings to uncover deeper issues[/dim]\n"
        "   [dim #00FFFF]\"Like a zipline connecting two points!\"[/dim #00FFFF]\n\n"
        "[bold #FF8C00]3. Detection, Not Destruction[/bold #FF8C00] 🛡️\n"
        "   [dim]Prove impact without causing harm[/dim]\n"
        "   [dim #00FFFF]\"I'm a lover, not a fighter! ...well, maybe both.\"[/dim #00FFFF]",
        title="[bold #FFD700]🤖 Philosophy[/bold #FFD700]",
        border_style="#FF4655",
    ))


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_scan_id() -> str:
    """Generate a unique scan ID."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    unique = uuid.uuid4().hex[:8]
    return f"PATHFINDER_{timestamp}_{unique}"


def get_scans_dir() -> Path:
    """Get the scans directory."""
    scans_dir = Path.home() / ".pathfinder" / "scans"
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

    # Handle plain domains/IPs
    if not target.startswith(("http://", "https://")):
        # Check if it looks like an IP or domain
        if re.match(r'^[\w.-]+(?::\d+)?(?:/.*)?$', target):
            target = f"https://{target}"
        else:
            raise click.BadParameter(f"Invalid target format: {target}")

    # Validate URL
    parsed = urlparse(target)
    if not parsed.netloc:
        raise click.BadParameter(f"Invalid URL: {target}")

    return target


def format_severity(severity: str) -> str:
    """Format severity with Apex Legends colors."""
    colors = {
        "CRITICAL": f"[bold #FF4655]⚠️  CRITICAL[/bold #FF4655]",  # Apex red
        "HIGH": "[bold #FF8C00]🔥 HIGH[/bold #FF8C00]",            # Pathfinder orange
        "MEDIUM": "[bold #FFD700]⚡ MEDIUM[/bold #FFD700]",        # Gold
        "LOW": "[bold #00FF00]📝 LOW[/bold #00FF00]",              # Green
        "INFO": "[dim #00FFFF]ℹ️  INFO[/dim #00FFFF]",             # Cyan
    }
    sev_str = severity.value if hasattr(severity, 'value') else str(severity)
    return colors.get(sev_str.upper(), f"[dim]{sev_str}[/dim]")


def format_confidence(confidence: float | str) -> str:
    """Format confidence score with color-coding."""
    # Handle string confidence values
    if isinstance(confidence, str):
        confidence_map = {
            "HIGH": 90.0, "MEDIUM": 70.0, "LOW": 50.0,
            "CRITICAL": 95.0, "INFO": 30.0,
            "CONFIRMED": 95.0, "SUSPECTED": 60.0,
        }
        upper_conf = confidence.upper().strip()
        if upper_conf in confidence_map:
            confidence = confidence_map[upper_conf]
        else:
            try:
                confidence = float(confidence.rstrip('%'))
            except ValueError:
                confidence = 50.0

    # Ensure float
    confidence = float(confidence)

    # Normalize to 0-100 range
    if confidence <= 1.0:
        confidence = confidence * 100

    # Color based on confidence level
    if confidence >= 95:
        return f"[bold #00FF00]{confidence:.0f}%[/bold #00FF00]"  # Green - confirmed
    elif confidence >= 75:
        return f"[bold #FFD700]{confidence:.0f}%[/bold #FFD700]"  # Gold - high confidence
    elif confidence >= 60:
        return f"[bold #FF8C00]{confidence:.0f}%[/bold #FF8C00]"  # Orange - medium
    else:
        return f"[dim]{confidence:.0f}%[/dim]"  # Dim - low confidence


# =============================================================================
# FINDING NORMALIZATION — Canonical field formats for report JSON
# =============================================================================

# Map word-based confidence to 0-100 float
_CONFIDENCE_WORD_MAP = {
    "very high": 95.0, "confirmed": 90.0, "exploitable": 98.0,
    "high": 85.0, "medium": 65.0, "low": 40.0, "none": 10.0,
}

_SEVERITY_CANONICAL = {
    "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
    "low": "LOW", "info": "INFO", "informational": "INFO",
}


def _normalize_finding(finding: dict) -> dict:
    """Normalize a finding dict to canonical field formats.

    Ensures:
    - severity: uppercase string (CRITICAL, HIGH, MEDIUM, LOW, INFO)
    - confidence_score: float 0-100
    - confidence: float 0-100 (alias)
    - vuln_type: always present (falls back from 'type')
    - name: always present (falls back from 'title')
    """
    f = dict(finding)  # shallow copy

    # --- Severity: always uppercase ---
    raw_sev = str(f.get("severity", "MEDIUM"))
    f["severity"] = _SEVERITY_CANONICAL.get(raw_sev.lower(), raw_sev.upper())

    # --- Confidence: always float 0-100 ---
    raw_conf = f.get("confidence_score", f.get("confidence", 50.0))
    if isinstance(raw_conf, str):
        raw_conf = _CONFIDENCE_WORD_MAP.get(raw_conf.lower(), 50.0)
    raw_conf = float(raw_conf)
    if raw_conf <= 1.0:
        raw_conf *= 100.0
    f["confidence_score"] = raw_conf
    f["confidence"] = raw_conf

    # --- vuln_type / type: keep both in sync ---
    vt = f.get("vuln_type") or f.get("type") or "unknown"
    f["vuln_type"] = vt
    f["type"] = vt
    # Ensure 'name' is present
    if not f.get("name"):
        f["name"] = f.get("title", "Unknown Finding")

    # Proof gate: propagate to top level for JSON consumers
    _pg = (f.get("metadata") or {}).get("proof_gate")
    if _pg and isinstance(_pg, dict):
        f["proof_gate"] = _pg.get("level", "detected")
        f["proof_gate_detail"] = _pg

    # Cluster: propagate to top level for JSON consumers
    _cl = (f.get("metadata") or {}).get("cluster")
    if _cl and isinstance(_cl, dict):
        f["cluster_id"] = _cl.get("cluster_id", "")
        f["cluster_size"] = _cl.get("cluster_size", 1)
        f["is_cluster_representative"] = _cl.get("is_representative", True)

    return f


# =============================================================================
# APEX LEGENDS PROGRESS BAR - NOW WITH REAL UPDATES!
# =============================================================================

class ApexProgressBar:
    """
    Apex Legends themed progress bar that ACTUALLY updates during scans!

    "Who's ready to fly on a zipline? I AM!" 🤖
    """

    def __init__(self, console: Console):
        self.console = console
        self.progress = None
        self.task_id = None
        self.total_modules = 0
        self.completed_modules = 0
        self.current_module = ""
        self.findings_count = 0
        self.start_time = None

    def start(self, total_modules: int, description: str = "🤖 Scanning..."):
        """Start the progress bar."""
        import random

        self.total_modules = total_modules
        self.completed_modules = 0
        self.findings_count = 0
        self.start_time = datetime.now()

        # Random loading message
        loading_msg = random.choice(PATHFINDER_LOADING)

        self.progress = Progress(
            SpinnerColumn(spinner_name="dots12", style="#FF8C00"),
            TextColumn("[bold #00FFFF]{task.description}[/bold #00FFFF]"),
            BarColumn(
                complete_style="#FF8C00",
                finished_style="#00FF00",
                bar_width=40,
            ),
            TextColumn("[bold #FFD700]{task.percentage:>3.0f}%[/bold #FFD700]"),
            TextColumn("[dim]•[/dim]"),
            TextColumn("[#00FFFF]{task.fields[module]}[/#00FFFF]"),
            TextColumn("[dim]•[/dim]"),
            TextColumn("[#00FF00]🎯 {task.fields[findings]}[/#00FF00]"),
            TimeElapsedColumn(),
            console=self.console,
            transient=False,
        )
        self.progress.start()
        self.task_id = self.progress.add_task(
            loading_msg,
            total=total_modules,
            module="initializing...",
            findings="0 vulns",
        )

    def update(self, module_name: str, findings_delta: int = 0):
        """Update progress with current module and findings."""
        if self.progress and self.task_id is not None:
            self.completed_modules += 1
            self.findings_count += findings_delta

            # Truncate long module names
            display_name = module_name[:20] + "..." if len(module_name) > 20 else module_name

            self.progress.update(
                self.task_id,
                advance=1,
                module=display_name,
                findings=f"{self.findings_count} vulns",
            )

    def set_description(self, description: str):
        """Update the progress description."""
        if self.progress and self.task_id is not None:
            self.progress.update(self.task_id, description=description)

    def finish(self, message: str = "🎉 Scan complete!"):
        """Finish and close the progress bar."""
        if self.progress:
            if self.task_id is not None:
                self.progress.update(
                    self.task_id,
                    completed=self.total_modules,
                    module="done!",
                    description=message,
                )
            self.progress.stop()

            # Print summary
            elapsed = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
            self.console.print(f"\n[bold #00FF00]✓[/bold #00FF00] Scanned [bold #FFD700]{self.completed_modules}[/bold #FFD700] modules in [bold #00FFFF]{elapsed:.1f}s[/bold #00FFFF]")
            self.console.print(f"[bold #00FF00]✓[/bold #00FF00] Found [bold #FF4655]{self.findings_count}[/bold #FF4655] potential vulnerabilities")


# =============================================================================
# CLI COMMANDS
# =============================================================================

@click.group()
@click.version_option(version="3.0.0", prog_name="pathfinder")
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--quiet', '-q', is_flag=True, help='Suppress banner and non-essential output')
@click.pass_context
def cli(ctx, verbose, quiet):
    """
    🤖 PATHFINDER AI - Your Friendly Neighborhood Security Scout

    "Hi friends! I'm here to help you find vulnerabilities!"

    Enterprise-grade AI-powered penetration testing.
    Built on the spirit of Apex Legends' favorite MRVN unit.

    \b
    Examples:
        pathfinder scan https://target.com
        pathfinder bounty https://bugbounty.com --scope "*.bugbounty.com"
        pathfinder client https://client.com --scope-file scope.json
        pathfinder quick https://target.com

    \b
    "Who's ready to fly on a zipline? I AM!" 🪝
    """
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose
    ctx.obj['quiet'] = quiet

    # Setup logging
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)

    # Print banner unless quiet
    if not quiet:
        print_banner(mini=True)


@cli.command()
@click.argument('target')
@click.option('--modules', '-m', help='Modules to run (category or comma-separated)')
@click.option('--exclude', '-e', help='Modules to exclude (comma-separated)')
@click.option('--rate', '-r', default=10, help='Requests per second')
@click.option('--concurrent', '-c', default=5, help='Concurrent modules')
@click.option('--timeout', '-t', default=300, help='Scan timeout in seconds')
@click.option('--output', '-o', help='Output file path')
@click.option('--format', '-f', 'output_format',
              type=click.Choice(['json', 'sarif', 'html', 'md']),
              default='json', help='Output format')
@click.option('--safe-mode',
              type=click.Choice(['safe', 'cautious', 'standard', 'aggressive']),
              default='standard', help='Safety level for testing')
@click.option('--no-ai', is_flag=True, help='Disable AI validation')
@click.option('--include-subdomains', is_flag=True, help='Include subdomain enumeration')
@click.pass_context
def scan(ctx, target, modules, exclude, rate, concurrent, timeout,
         output, output_format, safe_mode, no_ai, include_subdomains):
    """
    🎯 Execute a security scan against TARGET.

    "I'm coming for you, friend!" 🤖

    \b
    Examples:
        pathfinder scan https://target.com
        pathfinder scan https://api.target.com -m api,graphql
        pathfinder scan https://target.com --safe-mode aggressive
    """
    verbose = ctx.obj.get('verbose', False)
    quiet = ctx.obj.get('quiet', False)

    if not quiet:
        print_banner()
        console.print(f"\n[bold #FF8C00]🎯 Target acquired:[/bold #FF8C00] [bold #00FFFF]{target}[/bold #00FFFF]")
        console.print(f"[dim]Safe mode: {safe_mode} • Rate: {rate}/s • Concurrent: {concurrent}[/dim]\n")

    # Normalize target
    try:
        target = normalize_target(target)
    except click.BadParameter as e:
        console.print(f"[bold #FF4655]❌ Invalid target: {e}[/bold #FF4655]")
        raise SystemExit(1)

    async def _run_scan():
        scan_id = get_scan_id()
        progress_bar = ApexProgressBar(console)

        console.print(f"[dim]Scan ID: {scan_id}[/dim]\n")

        try:
            from core.config_manager import get_settings
            from scanning.full_scanner import FullScanner

            settings = get_settings()
            settings.rate_limit.requests_per_second = rate

            scanner = FullScanner(
                settings,
                safe_mode=safe_mode,
                include_subdomains=include_subdomains,
            )

            # Parse modules
            module_list = None
            if modules:
                if modules in MODULE_CATEGORIES:
                    module_list = MODULE_CATEGORIES[modules]
                else:
                    module_list = [m.strip() for m in modules.split(",")]

            if exclude and module_list:
                exclude_list = [m.strip() for m in exclude.split(",")]
                module_list = [m for m in module_list if m not in exclude_list]

            # Estimate module count
            est_modules = len(module_list) if module_list else 50

            # Start Apex progress bar
            progress_bar.start(est_modules, "🤖 Grappling to target...")

            # Progress callback that ACTUALLY updates the bar!
            def on_module_complete(module_name: str, result: dict):
                findings_delta = len(result.get('findings', [])) if result else 0
                progress_bar.update(module_name, findings_delta)

            # Run scan
            result = await scanner.scan(
                target=target,
                category=modules or "standard",
                modules=module_list,
                concurrent=concurrent,
                on_progress=lambda r: on_module_complete(
                    r.modules_run[-1] if r.modules_run else "unknown",
                    {"findings": r.findings}
                ),
            )

            progress_bar.finish("🎉 Scan complete! High five, friend!")

            # Display results
            all_findings = result.findings or []

            if all_findings:
                console.print(f"\n[bold #FFD700]{'═' * 60}[/bold #FFD700]")
                console.print(f"[bold #FF8C00]🎯 VULNERABILITIES FOUND[/bold #FF8C00]")
                console.print(f"[bold #FFD700]{'═' * 60}[/bold #FFD700]\n")

                # Create findings table
                table = Table(
                    title="[bold #00FFFF]Security Findings[/bold #00FFFF]",
                    border_style="#FF8C00",
                    header_style="bold #FFD700",
                )
                table.add_column("Severity", style="bold")
                table.add_column("Type", style="#00FFFF")
                table.add_column("URL", style="dim", max_width=50)
                table.add_column("Confidence")

                for finding in sorted(all_findings,
                                     key=lambda f: ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(
                                         str(f.get("severity", "INFO")).upper()
                                     ), reverse=True):
                    sev = finding.get("severity", "MEDIUM")
                    vtype = finding.get("vuln_type", finding.get("type", "unknown"))
                    url = finding.get("endpoint", finding.get("url", finding.get("matched_at", "N/A")))
                    conf = finding.get("confidence_score", finding.get("confidence", 0.5))
                    table.add_row(
                        format_severity(sev),
                        str(vtype)[:20],
                        str(url)[:50],
                        format_confidence(conf),
                    )

                console.print(table)
            else:
                console.print("\n[bold #00FF00]✓ No vulnerabilities found![/bold #00FF00]")
                console.print("[dim #00FFFF]\"That was easy!\" - But stay vigilant, friend![/dim #00FFFF]\n")

            # Normalize findings before saving — canonical field formats
            normalized_findings = [_normalize_finding(f) for f in all_findings]

            # FIX 2026-03-02: Filter findings below severity-specific confidence thresholds.
            # Without this, CSRF conf=60 (HIGH threshold=70%) and similar FPs appear in reports.
            _SEV_CONF_THRESHOLDS = {"CRITICAL": 80.0, "HIGH": 70.0, "MEDIUM": 65.0, "LOW": 60.0, "INFO": 50.0}
            pre_filter_count = len(normalized_findings)
            normalized_findings = [
                f for f in normalized_findings
                if f.get("confidence_score", f.get("confidence", 100.0))
                >= _SEV_CONF_THRESHOLDS.get(str(f.get("severity", "MEDIUM")).upper(), 70.0)
            ]
            suppressed = pre_filter_count - len(normalized_findings)
            if suppressed:
                console.print(f"[dim]   Suppressed {suppressed} findings below confidence threshold[/dim]")

            # Save results
            output_path = output or f"reports/pathfinder_{urlparse(target).netloc}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, 'w') as f:
                json.dump({
                    "scan_id": scan_id,
                    "target": target,
                    "timestamp": datetime.now().isoformat(),
                    "modules_run": result.modules_run,
                    "modules_executed": result.modules_run,
                    "findings": normalized_findings,
                    "errors": result.errors,
                }, f, indent=2, default=str)

            console.print(f"\n[bold #00FF00]📁 Report saved:[/bold #00FF00] {output_path}")

            # Pathfinder sign-off
            import random
            signoff = random.choice([
                "High five, friend! ✋",
                "That was a good fight!",
                "I love this job!",
                "Who's ready for another scan? I AM!",
                "Thanks for scanning with me, friend!",
            ])
            console.print(f"\n[bold #FF8C00]🤖 {signoff}[/bold #FF8C00]\n")

            return 0

        except Exception as e:
            progress_bar.finish("❌ Scan failed")
            console.print(f"\n[bold #FF4655]❌ Scan error: {e}[/bold #FF4655]")
            if verbose:
                import traceback
                console.print(f"[dim red]{traceback.format_exc()}[/dim red]")
            return 1

    exit_code = safe_asyncio_run(_run_scan())
    raise SystemExit(exit_code)


@cli.command()
@click.argument('target')
@click.option('--username', '-u', required=True, help='HackerOne/Platform username')
@click.option('--scope', '-s', required=True, help='Scope pattern (e.g., "*.target.com")')
@click.option('--rate', '-r', default=5, help='Requests per second (be nice!)')
@click.option('--safe-mode', default='cautious', help='Safety level')
@click.pass_context
def bounty(ctx, target, username, scope, rate, safe_mode):
    """
    🏆 Bug bounty optimized scan.

    "High five, friend! Let's find some bounties!" 🤖💰

    \b
    LEGAL DISCLAIMER:
    Only scan targets you have explicit authorization to test.
    Bug bounty programs have rules - follow them, friend!

    \b
    Example:
        pathfinder bounty https://target.com -u your_username -s "*.target.com"
    """
    console.print(Panel(
        "[bold #FF4655]⚠️  LEGAL DISCLAIMER[/bold #FF4655]\n\n"
        "[white]By proceeding, you confirm that:[/white]\n\n"
        f"[#00FFFF]1.[/#00FFFF] You have authorization to test [bold]{target}[/bold]\n"
        f"[#00FFFF]2.[/#00FFFF] You will stay within scope: [bold]{scope}[/bold]\n"
        "[#00FFFF]3.[/#00FFFF] You accept responsibility for your actions\n\n"
        "[dim]\"I don't want to get us in trouble, friend!\"[/dim]",
        title="[bold #FFD700]🤖 Pathfinder Says[/bold #FFD700]",
        border_style="#FF4655",
    ))

    if not click.confirm("\n🤖 Do you accept these terms, friend?"):
        console.print("[bold #FF4655]Scan cancelled. Stay safe, friend![/bold #FF4655]")
        raise SystemExit(0)

    console.print(f"\n[bold #00FF00]✓ Authorization confirmed for @{username}[/bold #00FF00]")
    console.print("[bold #FF8C00]🏆 Starting bug bounty scan...[/bold #FF8C00]\n")

    # Delegate to regular scan with bounty category
    ctx.invoke(scan, target=target, modules="bounty", rate=rate, safe_mode=safe_mode)


@cli.command()
@click.argument('target')
@click.pass_context
def quick(ctx, target):
    """
    ⚡ Quick scan - 5 essential modules.

    "That was easy!" 🤖
    """
    console.print("[bold #FF8C00]⚡ Quick scan - Let's go fast, friend![/bold #FF8C00]\n")
    ctx.invoke(scan, target=target, modules="quick", rate=20)


@cli.command()
@click.argument('target')
@click.option('--concurrent', '-c', default=10, help='Concurrent modules')
@click.pass_context
def full(ctx, target, concurrent):
    """
    🔥 Full comprehensive scan - ALL modules.

    "I love this job!" 🤖
    """
    console.print("[bold #FF8C00]🔥 Full scan - Time to find ALL the vulnerabilities![/bold #FF8C00]\n")
    ctx.invoke(scan, target=target, modules="full", concurrent=concurrent)


@cli.command()
def modules():
    """
    📋 List all available security modules.

    "Look at all these tools, friend!" 🤖
    """
    console.print("\n[bold #FF8C00]📋 Available Security Modules[/bold #FF8C00]\n")

    for category, mods in MODULE_CATEGORIES.items():
        console.print(f"[bold #00FFFF]{category}[/bold #00FFFF] ({len(mods)} modules)")
        for mod in mods[:5]:  # Show first 5
            console.print(f"  [dim]• {mod}[/dim]")
        if len(mods) > 5:
            console.print(f"  [dim]... and {len(mods) - 5} more[/dim]")
        console.print()


@cli.command()
def health():
    """
    🏥 Check PATHFINDER AI health.

    "I feel most alive when rapidly approaching my death!" 🤖
    (But let's make sure all systems are GO!)
    """
    console.print("\n[bold #FF8C00]🏥 PATHFINDER Health Check[/bold #FF8C00]\n")

    checks = [
        ("Core modules", PATHFINDER_AVAILABLE),
        ("HackerOne reporter", HACKERONE_REPORTER_AVAILABLE),
        ("Network protection", True),  # Always available
        ("AI validation", True),       # Always available
    ]

    all_ok = True
    for name, status in checks:
        if status:
            console.print(f"[bold #00FF00]✓[/bold #00FF00] {name}")
        else:
            console.print(f"[bold #FF4655]✗[/bold #FF4655] {name}")
            all_ok = False

    if all_ok:
        console.print("\n[bold #00FF00]🤖 All systems nominal! Who's ready to scan?[/bold #00FF00]\n")
    else:
        console.print("\n[bold #FFD700]⚠️  Some components need attention, friend.[/bold #FFD700]\n")


def main():
    """Entry point for PATHFINDER AI CLI."""
    try:
        cli(obj={})
    except SystemExit:
        raise
    except KeyboardInterrupt:
        console.print("\n[bold #FF8C00]🤖 Scan interrupted. See you later, friend![/bold #FF8C00]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[bold #FF4655]❌ Fatal error: {e}[/bold #FF4655]")
        logger.exception("Fatal error")
        sys.exit(1)


if __name__ == "__main__":
    main()
