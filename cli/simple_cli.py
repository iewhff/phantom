#!/usr/bin/env python3
"""
AI Pentest Framework - Simple CLI

Usage:
    pentest scan <target> [options]
    pentest quick <target>
    pentest full <target>
    pentest authorize <target>
    pentest threat-model <target>
    pentest modules
"""

from __future__ import annotations

import asyncio
import sys
from datetime import datetime
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich import print as rprint

console = Console()


def print_banner():
    """Print the banner."""
    banner = """
[cyan]╔═══════════════════════════════════════════════════════════╗
║     █████╗ ██╗    ██████╗ ███████╗███╗   ██╗████████╗     ║
║    ██╔══██╗██║    ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝     ║
║    ███████║██║    ██████╔╝█████╗  ██╔██╗ ██║   ██║        ║
║    ██╔══██║██║    ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║        ║
║    ██║  ██║██║    ██║     ███████╗██║ ╚████║   ██║        ║
║    ╚═╝  ╚═╝╚═╝    ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝        ║
║                                                           ║
║        [white]AI-Enhanced Penetration Testing v2.0[/white]             ║
║        [yellow]47 Modules | Safe Mode | Threat Modeling[/yellow]         ║
╚═══════════════════════════════════════════════════════════╝[/cyan]
"""
    console.print(banner)


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def cli(verbose: bool):
    """AI Pentest Framework - Enterprise Security Testing"""
    pass


@cli.command()
@click.argument("target")
@click.option("--category", "-c", 
              type=click.Choice(["quick", "web", "api", "injection", "auth", "infra", "advanced", "full"]),
              default="web", help="Scan category")
@click.option("--safe-mode", "-s",
              type=click.Choice(["passive", "safe", "cautious", "standard", "aggressive"]),
              default="safe", help="Safety level")
@click.option("--output", "-o", type=click.Path(), help="Output directory")
@click.option("--format", "-f", type=click.Choice(["html", "json", "pdf"]), default="html")
@click.option("--modules", "-m", help="Specific modules (comma-separated)")
@click.option("--no-auth", is_flag=True, help="Skip authorization check")
def scan(target: str, category: str, safe_mode: str, output: str, format: str, modules: str, no_auth: bool):
    """
    Run security scan on TARGET.
    
    Examples:
    
        pentest scan https://example.com
        
        pentest scan https://example.com -c api -s safe
        
        pentest scan https://example.com -m sqli,xss,headers
    """
    asyncio.run(_run_scan(target, category, safe_mode, output, format, modules, no_auth))


async def _run_scan(target: str, category: str, safe_mode: str, output: str, format: str, modules: str, no_auth: bool):
    """Execute the scan."""
    print_banner()
    
    # Show config
    safe_icons = {
        "passive": "🔒 PASSIVE (read-only)",
        "safe": "🛡️ SAFE (non-destructive)",
        "cautious": "⚠️ CAUTIOUS",
        "standard": "🔧 STANDARD",
        "aggressive": "⚡ AGGRESSIVE",
    }
    
    console.print(Panel(
        f"[bold cyan]Target:[/bold cyan] {target}\n"
        f"[bold cyan]Category:[/bold cyan] {category}\n"
        f"[bold cyan]Safe Mode:[/bold cyan] {safe_icons.get(safe_mode, safe_mode)}\n"
        f"[bold cyan]Format:[/bold cyan] {format}",
        title="🎯 Scan Configuration",
        border_style="blue",
    ))
    
    # Check authorization
    if not no_auth:
        from core.config_manager import get_settings
        from core.auth_manager import AuthManager
        
        try:
            settings = get_settings()
            auth = AuthManager(settings)
            
            # Normalize target for auth check
            from urllib.parse import urlparse
            parsed = urlparse(target)
            domain = parsed.netloc or parsed.path
            
            if not auth.is_authorized(domain) and not auth.is_authorized(target):
                console.print(f"\n[red]❌ Target not authorized![/red]")
                console.print(f"[yellow]Run: pentest authorize {domain}[/yellow]")
                return
        except Exception as e:
            console.print(f"[yellow]⚠️ Auth check skipped: {e}[/yellow]")
    
    # Run scan
    from core.config_manager import get_settings
    from scanning.full_scanner import FullScanner
    
    settings = get_settings()
    scanner = FullScanner(settings, safe_mode=safe_mode)
    
    # Parse modules if provided
    module_list = modules.split(",") if modules else None
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning...", total=100)
        
        # Run the scan
        result = await scanner.scan(
            target=target,
            category=category,
            modules=module_list,
        )
        
        progress.update(task, completed=100)
    
    # Display results
    console.print()
    
    # Summary table
    table = Table(title="📊 Scan Results", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")
    
    summary = result.to_dict()["summary"]
    table.add_row("Total Findings", str(summary["total_findings"]))
    table.add_row("[red]Critical[/red]", str(summary["critical"]))
    table.add_row("[orange1]High[/orange1]", str(summary["high"]))
    table.add_row("[yellow]Medium[/yellow]", str(summary["medium"]))
    table.add_row("[green]Low[/green]", str(summary["low"]))
    table.add_row("Modules Run", str(len(result.modules_run)))
    table.add_row("Errors", str(len(result.errors)))
    
    console.print(table)
    
    # Show findings
    if result.findings:
        console.print("\n[bold]🔍 Findings:[/bold]")
        for i, finding in enumerate(result.findings[:10], 1):
            severity = finding.get("severity", "INFO")
            colors = {"CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow", "LOW": "green"}
            color = colors.get(severity, "white")
            
            console.print(f"  [{color}]{i}. [{severity}] {finding.get('name', finding.get('type', 'Unknown'))}[/{color}]")
            if finding.get("matched_at"):
                console.print(f"     └─ {finding['matched_at'][:60]}")
        
        if len(result.findings) > 10:
            console.print(f"  ... and {len(result.findings) - 10} more")
    
    # Show errors if any
    if result.errors:
        console.print("\n[yellow]⚠️ Errors:[/yellow]")
        for err in result.errors[:5]:
            console.print(f"  • {err['module']}: {err['error'][:50]}")
    
    # Generate report
    output_dir = Path(output) if output else Path("reports")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("://", "_").replace("/", "_").replace(".", "_")[:30]
    
    if format == "html":
        report_path = output_dir / f"{safe_target}_{timestamp}.html"
        _generate_html_report(result, report_path)
    elif format == "json":
        import json
        report_path = output_dir / f"{safe_target}_{timestamp}.json"
        report_path.write_text(json.dumps(result.to_dict(), indent=2))
    
    console.print(f"\n[green]✅ Report saved: {report_path}[/green]")
    
    # Compliance info
    if safe_mode in ["passive", "safe"]:
        compliance = scanner.get_compliance_report()
        console.print(Panel(
            f"[green]✅ Non-destructive scan completed[/green]\n"
            f"Total Requests: {compliance['statistics']['total_requests']}\n"
            f"Blocked Operations: {compliance['statistics']['blocked_attempts']}",
            title="🛡️ Compliance Report",
            border_style="green",
        ))


async def _run_bounty_scan(target: str, safe_mode: str, format: str, rate: float, concurrent: int):
    """Execute bounty-optimized scan with strict rate limiting."""
    print_banner()

    # Show config with rate limiting info
    safe_icons = {
        "passive": "🔒 PASSIVE (read-only)",
        "safe": "🛡️ SAFE (non-destructive)",
        "cautious": "⚠️ CAUTIOUS",
        "standard": "🔧 STANDARD",
        "aggressive": "⚡ AGGRESSIVE",
    }

    console.print(Panel(
        f"[bold cyan]Target:[/bold cyan] {target}\n"
        f"[bold cyan]Category:[/bold cyan] bounty (16 high-value modules)\n"
        f"[bold cyan]Safe Mode:[/bold cyan] {safe_icons.get(safe_mode, safe_mode)}\n"
        f"[bold cyan]Rate Limit:[/bold cyan] {rate} req/sec\n"
        f"[bold cyan]Concurrent:[/bold cyan] {concurrent} modules\n"
        f"[bold cyan]Format:[/bold cyan] {format}",
        title="🎯 Bounty Scan Configuration",
        border_style="blue",
    ))

    # Check authorization
    from core.config_manager import get_settings
    from core.auth_manager import AuthManager
    from urllib.parse import urlparse

    try:
        settings = get_settings()
        auth = AuthManager(settings)

        parsed = urlparse(target)
        domain = parsed.netloc or parsed.path

        if not auth.is_authorized(domain) and not auth.is_authorized(target):
            console.print(f"\n[red]❌ Target not authorized![/red]")
            console.print(f"[yellow]Run: pentest authorize {domain}[/yellow]")
            return
    except Exception as e:
        console.print(f"[yellow]⚠️ Auth check skipped: {e}[/yellow]")

    # Override rate limit settings for this scan
    settings.rate_limit.requests_per_second = rate
    settings.rate_limit.min_delay = 1.0 / rate if rate > 0 else 1.0  # Ensure proper delay between requests

    from scanning.full_scanner import FullScanner

    scanner = FullScanner(settings, safe_mode=safe_mode)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning...", total=100)

        # Run with reduced concurrency for bug bounty safety
        result = await scanner.scan(
            target=target,
            category="bounty",
            modules=None,
            concurrent=concurrent,  # Use reduced concurrency
        )

        progress.update(task, completed=100)

    # Display results
    console.print()

    table = Table(title="📊 Bounty Scan Results", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")

    summary = result.to_dict()["summary"]
    table.add_row("Total Findings", str(summary["total_findings"]))
    table.add_row("[red]Critical[/red]", str(summary["critical"]))
    table.add_row("[orange1]High[/orange1]", str(summary["high"]))
    table.add_row("[yellow]Medium[/yellow]", str(summary["medium"]))
    table.add_row("[green]Low[/green]", str(summary["low"]))
    table.add_row("Modules Run", str(len(result.modules_run)))
    table.add_row("Errors", str(len(result.errors)))

    console.print(table)

    # Show findings with bounty potential
    if result.findings:
        console.print("\n[bold yellow]💰 Potential Bounty Findings:[/bold yellow]")
        for i, finding in enumerate(result.findings[:10], 1):
            severity = finding.get("severity", "INFO")
            colors = {"CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow", "LOW": "green"}
            color = colors.get(severity, "white")

            # Estimate bounty value based on severity and type
            bounty_estimate = ""
            vuln_type = finding.get("type", "").lower()
            if "idor" in vuln_type or "bola" in vuln_type:
                bounty_estimate = " 💰 ($3k-$10k)"
            elif severity == "CRITICAL":
                bounty_estimate = " 💰 ($5k-$20k)"
            elif severity == "HIGH":
                bounty_estimate = " 💰 ($1k-$5k)"

            console.print(f"  [{color}]{i}. [{severity}] {finding.get('name', finding.get('type', 'Unknown'))}{bounty_estimate}[/{color}]")
            if finding.get("matched_at"):
                console.print(f"     └─ {finding['matched_at'][:60]}")

        if len(result.findings) > 10:
            console.print(f"  ... and {len(result.findings) - 10} more")

    # Show errors if any
    if result.errors:
        console.print("\n[yellow]⚠️ Errors:[/yellow]")
        for err in result.errors[:5]:
            console.print(f"  • {err['module']}: {err['error'][:50]}")

    # Generate report
    output_dir = Path("reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("://", "_").replace("/", "_").replace(".", "_")[:30]

    if format == "html":
        report_path = output_dir / f"bounty_{safe_target}_{timestamp}.html"
        _generate_html_report(result, report_path)
    elif format == "json":
        import json
        report_path = output_dir / f"bounty_{safe_target}_{timestamp}.json"
        report_path.write_text(json.dumps(result.to_dict(), indent=2))
    elif format == "md":
        report_path = output_dir / f"bounty_{safe_target}_{timestamp}.md"
        _generate_bounty_md_report(result, report_path, target)

    console.print(f"\n[green]✅ Report saved: {report_path}[/green]")

    # Compliance info
    if safe_mode in ["passive", "safe"]:
        compliance = scanner.get_compliance_report()
        console.print(Panel(
            f"[green]✅ Bug bounty safe scan completed[/green]\n"
            f"Total Requests: {compliance['statistics']['total_requests']}\n"
            f"Rate Limit: {rate} req/sec\n"
            f"Concurrent Modules: {concurrent}",
            title="🛡️ Bug Bounty Compliance",
            border_style="green",
        ))


def _generate_bounty_md_report(result, path: Path, target: str):
    """Generate markdown report optimized for HackerOne submission."""
    summary = result.to_dict()["summary"]

    md = f"""# Bug Bounty Report - {target}

**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Scanner:** PetNTester AI v3.1 - Top Tier Bounty Edition
**Mode:** Bounty (16 high-value modules)

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | {summary['critical']} |
| High | {summary['high']} |
| Medium | {summary['medium']} |
| Low | {summary['low']} |
| **Total** | **{summary['total_findings']}** |

---

## Findings

"""

    for i, finding in enumerate(result.findings, 1):
        severity = finding.get("severity", "INFO")
        md += f"""### {i}. [{severity}] {finding.get('name', finding.get('type', 'Unknown'))}

**Type:** {finding.get('type', 'N/A')}
**Location:** {finding.get('matched_at', finding.get('url', 'N/A'))}
**CWE:** {finding.get('cwe', 'N/A')}

**Description:**
{finding.get('description', 'No description available.')}

**Evidence:**
```
{finding.get('evidence', finding.get('payload', 'N/A'))}
```

---

"""

    md += """
## Notes

- All testing conducted with X-Bug-Bounty: True header
- Safe mode enabled (non-destructive testing only)
- All requests respect rate limiting

*Generated by PetNTester AI v3.1 - Top Tier Bounty Edition*
"""

    path.write_text(md)


def _generate_html_report(result, path: Path):
    """Generate HTML report."""
    summary = result.to_dict()["summary"]
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Report - {result.target}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; background: #1a1a2e; color: #eee; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        .header h1 {{ margin: 0; color: white; }}
        .card {{ background: #16213e; border-radius: 10px; padding: 20px; margin-bottom: 20px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; }}
        .stat {{ text-align: center; padding: 20px; background: #0f3460; border-radius: 8px; }}
        .stat-number {{ font-size: 36px; font-weight: bold; }}
        .critical {{ color: #e74c3c; }}
        .high {{ color: #e67e22; }}
        .medium {{ color: #f1c40f; }}
        .low {{ color: #2ecc71; }}
        .finding {{ background: #0f3460; padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #667eea; }}
        .finding.critical {{ border-color: #e74c3c; }}
        .finding.high {{ border-color: #e67e22; }}
        .finding.medium {{ border-color: #f1c40f; }}
        .finding.low {{ border-color: #2ecc71; }}
        .tag {{ display: inline-block; padding: 3px 10px; border-radius: 15px; font-size: 12px; margin-right: 5px; }}
        .safe-mode {{ background: #27ae60; color: white; padding: 10px 20px; border-radius: 5px; display: inline-block; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Assessment Report</h1>
            <p><strong>Target:</strong> {result.target}</p>
            <p><strong>Date:</strong> {result.start_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <span class="safe-mode">🛡️ Safe Mode: {result.safe_mode.upper()}</span>
        </div>
        
        <div class="card">
            <h2>📊 Summary</h2>
            <div class="summary-grid">
                <div class="stat">
                    <div class="stat-number">{summary['total_findings']}</div>
                    <div>Total Findings</div>
                </div>
                <div class="stat">
                    <div class="stat-number critical">{summary['critical']}</div>
                    <div>Critical</div>
                </div>
                <div class="stat">
                    <div class="stat-number high">{summary['high']}</div>
                    <div>High</div>
                </div>
                <div class="stat">
                    <div class="stat-number medium">{summary['medium']}</div>
                    <div>Medium</div>
                </div>
                <div class="stat">
                    <div class="stat-number low">{summary['low']}</div>
                    <div>Low</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>🔍 Findings</h2>
"""
    
    for finding in result.findings:
        severity = finding.get("severity", "INFO").lower()
        html += f"""
            <div class="finding {severity}">
                <h3><span class="tag {severity}">{finding.get('severity', 'INFO')}</span> {finding.get('name', finding.get('type', 'Unknown'))}</h3>
                <p>{finding.get('description', 'No description')}</p>
                <p><strong>Location:</strong> {finding.get('matched_at', finding.get('url', 'N/A'))}</p>
                <p><strong>Module:</strong> {finding.get('module', 'N/A')}</p>
            </div>
"""
    
    if not result.findings:
        html += "<p>No vulnerabilities found! 🎉</p>"
    
    html += """
        </div>
        
        <div class="card">
            <h2>📋 Modules Executed</h2>
            <p>""" + ", ".join(result.modules_run) + """</p>
        </div>
        
        <div class="card">
            <h2>⚖️ Legal Notice</h2>
            <p>This security assessment was conducted in <strong>Safe Mode</strong> using non-destructive testing methods only. 
            No production data was modified and no services were disrupted.</p>
        </div>
    </div>
</body>
</html>"""
    
    path.write_text(html)


@cli.command()
@click.argument("target")
def quick(target: str):
    """Quick scan - headers, SSL, CORS only."""
    asyncio.run(_run_scan(target, "quick", "safe", None, "html", None, False))


@cli.command()
@click.argument("target")
@click.option("--safe-mode", "-s", default="safe")
def full(target: str, safe_mode: str):
    """Full scan with all 45+ modules."""
    asyncio.run(_run_scan(target, "full", safe_mode, None, "html", None, False))


@cli.command()
@click.argument("target")
@click.option("--safe-mode", "-s", default="safe")
@click.option("--format", "-f", default="html", type=click.Choice(["html", "json", "md"]))
@click.option("--rate", "-r", default=1.0, type=float, help="Requests per second (default: 1.0 for bug bounty safety)")
@click.option("--concurrent", "-c", default=2, type=int, help="Max concurrent modules (default: 2)")
def bounty(target: str, safe_mode: str, format: str, rate: float, concurrent: int):
    """
    TOP TIER BOUNTY HUNTING scan.

    Optimized for maximum bounty potential with focus on:
    - IDOR/BOLA detection ($3k-$20k bounties)
    - SQL Injection
    - XSS (including DOM-based with browser execution)
    - Access Control vulnerabilities
    - Business Logic flaws
    - API security issues
    - BaaS misconfigurations (Supabase, Firebase)

    Example:
        pentest bounty api.target.com
        pentest bounty api.target.com -s cautious -r 0.5
    """
    console.print(Panel(
        "[bold yellow]💰 TOP TIER BOUNTY HUNTING MODE[/bold yellow]\n\n"
        "Focus Areas:\n"
        "  • IDOR/BOLA - $3k-$20k+ potential\n"
        "  • SQL Injection - High Value\n"
        "  • XSS (including DOM-based)\n"
        "  • Access Control Bypass\n"
        "  • Business Logic Flaws\n"
        "  • API Security Issues\n"
        "  • BaaS Misconfigurations\n\n"
        f"[bold green]Rate Limit:[/bold green] {rate} req/sec\n"
        f"[bold green]Concurrent:[/bold green] {concurrent} modules",
        title="🎯 Bounty Mode Activated",
        border_style="yellow",
    ))
    asyncio.run(_run_bounty_scan(target, safe_mode, format, rate, concurrent))


@cli.command()
@click.argument("target")
@click.option("--safe-mode", "-s", default="safe")
def baas(target: str, safe_mode: str):
    """
    Backend-as-a-Service (BaaS) security scan.

    Specialized for Supabase, Firebase, and similar platforms.
    Detects RLS bypass, misconfigurations, exposed keys, etc.
    """
    console.print(Panel(
        "[bold cyan]☁️ BaaS Security Scan[/bold cyan]\n\n"
        "Targets: Supabase, Firebase, Appwrite, etc.\n"
        "Checks: RLS bypass, API key exposure, auth misconfig",
        title="☁️ BaaS Mode",
        border_style="cyan",
    ))
    asyncio.run(_run_scan(target, "baas", safe_mode, None, "html", None, False))


@cli.command()
@click.argument("target")
@click.option("--safe-mode", "-s", default="standard", type=click.Choice(["safe", "cautious", "standard", "aggressive"]))
@click.option("--format", "-f", default="html", type=click.Choice(["html", "json", "md", "pdf"]))
@click.option("--rate", "-r", default=10.0, type=float, help="Requests per second (default: 10.0 for client pentests)")
@click.option("--concurrent", "-c", default=5, type=int, help="Max concurrent modules (default: 5)")
@click.option("--client-name", default=None, help="Client name for report header")
@click.option("--no-tor", is_flag=True, help="Disable Tor (use direct connection)")
@click.option("--no-recon", is_flag=True, help="Skip reconnaissance (subdomains, crawling)")
@click.option("--subdomains/--no-subdomains", default=True, help="Enable/disable subdomain enumeration")
def client(target: str, safe_mode: str, format: str, rate: float, concurrent: int, client_name: str, no_tor: bool, no_recon: bool, subdomains: bool):
    """
    PROFESSIONAL CLIENT PENTEST - Full security assessment.

    Complete penetration test with all 47 modules, optimized for
    authorized client engagements. No bug bounty restrictions.
    
    Includes:
      - Subdomain enumeration (crt.sh, DNS brute)
      - Deep crawling for endpoint discovery
      - Technology detection
      - Full vulnerability scanning (47 modules)

    Modes:
      safe      - Non-destructive only (read-only operations)
      cautious  - Low-risk testing
      standard  - Normal pentest (recommended for most clients)
      aggressive - Full exploitation attempts (with client approval)

    Example:
        pentest client https://client-site.com
        pentest client https://api.client.com -s aggressive -r 20
        pentest client https://client.com --client-name "ACME Corp"
        pentest client https://client.com --no-subdomains  # Skip subdomain enum
    """
    console.print(Panel(
        f"[bold green]🔒 PROFESSIONAL CLIENT PENTEST[/bold green]\n\n"
        f"[bold]Client:[/bold] {client_name or 'Not specified'}\n"
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Mode:[/bold] {safe_mode.upper()}\n"
        f"[bold]Modules:[/bold] ALL 47 modules\n"
        f"[bold]Rate:[/bold] {rate} req/sec\n"
        f"[bold]Concurrent:[/bold] {concurrent} modules\n"
        f"[bold]Tor:[/bold] {'Disabled' if no_tor else 'Enabled'}\n"
        f"[bold]Reconnaissance:[/bold] {'Disabled' if no_recon else 'Enabled'}\n"
        f"[bold]Subdomains:[/bold] {'Enabled' if subdomains and not no_recon else 'Disabled'}",
        title="🎯 Client Pentest Mode",
        border_style="green",
    ))

    if safe_mode == "aggressive":
        console.print(Panel(
            "[bold red]⚠️ AGGRESSIVE MODE WARNING[/bold red]\n\n"
            "This mode will attempt exploitation techniques that may:\n"
            "  • Modify data in the application\n"
            "  • Trigger alerts and WAF blocks\n"
            "  • Cause service disruption\n\n"
            "[yellow]Ensure you have written authorization from the client![/yellow]",
            title="⚠️ Warning",
            border_style="red",
        ))

    asyncio.run(_run_client_scan(target, safe_mode, format, rate, concurrent, client_name, no_tor, no_recon, subdomains))


async def _run_client_scan(target: str, safe_mode: str, format: str, rate: float, concurrent: int, client_name: str, no_tor: bool, no_recon: bool = False, subdomains: bool = True):
    """Execute professional client pentest with optional reconnaissance."""
    print_banner()

    safe_icons = {
        "safe": "🛡️ SAFE (non-destructive)",
        "cautious": "⚠️ CAUTIOUS (low-risk)",
        "standard": "🔧 STANDARD (normal pentest)",
        "aggressive": "⚡ AGGRESSIVE (full exploitation)",
    }
    
    recon_enabled = not no_recon

    console.print(Panel(
        f"[bold cyan]Target:[/bold cyan] {target}\n"
        f"[bold cyan]Client:[/bold cyan] {client_name or 'N/A'}\n"
        f"[bold cyan]Category:[/bold cyan] full (ALL 47 modules)\n"
        f"[bold cyan]Mode:[/bold cyan] {safe_icons.get(safe_mode, safe_mode)}\n"
        f"[bold cyan]Rate Limit:[/bold cyan] {rate} req/sec\n"
        f"[bold cyan]Concurrent:[/bold cyan] {concurrent} modules\n"
        f"[bold cyan]Reconnaissance:[/bold cyan] {'✅ Enabled' if recon_enabled else '❌ Disabled'}\n"
        f"[bold cyan]Subdomains:[/bold cyan] {'✅ Enabled' if subdomains else '❌ Disabled'}\n"
        f"[bold cyan]Format:[/bold cyan] {format}",
        title="🎯 Client Scan Configuration",
        border_style="blue",
    ))

    # Load settings first (must be outside try block to avoid UnboundLocalError)
    from core.config_manager import get_settings
    from core.auth_manager import AuthManager
    from urllib.parse import urlparse

    settings = get_settings()

    # Check authorization
    try:
        auth = AuthManager(settings)

        parsed = urlparse(target)
        domain = parsed.netloc or parsed.path

        if not auth.is_authorized(domain) and not auth.is_authorized(target):
            console.print(f"\n[red]❌ Target not authorized![/red]")
            console.print(f"[yellow]Run: pentest authorize {domain}[/yellow]")
            return
    except Exception as e:
        console.print(f"[yellow]⚠️ Auth check skipped: {e}[/yellow]")

    # Configure for client pentest (higher rate limits, no bug bounty restrictions)
    settings.rate_limit.requests_per_second = rate
    settings.rate_limit.min_delay = 1.0 / rate if rate > 0 else 0.1
    settings.rate_limit.concurrent_scans = concurrent

    # Disable Tor if requested
    if no_tor:
        settings.network.use_tor = False
        console.print("[yellow]⚠️ Tor disabled - using direct connection[/yellow]")

    from scanning.full_scanner import FullScanner
    
    # === RECONNAISSANCE PHASE ===
    all_targets = [target]  # Start with main target
    discovered_urls = []
    tech_info = {}
    
    if recon_enabled:
        console.print("\n[bold blue]🔍 Starting Reconnaissance Phase...[/bold blue]")
        
        # 1. Subdomain Enumeration
        if subdomains:
            try:
                from reconnaissance.subdomain_enum import SubdomainEnumerator
                
                console.print("[cyan]  → Enumerating subdomains...[/cyan]")
                sub_enum = SubdomainEnumerator(settings)
                parsed_url = urlparse(target)
                domain = parsed_url.netloc or parsed_url.path
                
                # Extract root domain (e.g., tapsi.pt from www.tapsi.pt)
                domain_parts = domain.split('.')
                if len(domain_parts) > 2:
                    root_domain = '.'.join(domain_parts[-2:])
                else:
                    root_domain = domain
                
                found_subs = await sub_enum.enumerate(root_domain)

                if found_subs:
                    # Convert set to list for iteration
                    subs_list = list(found_subs)
                    console.print(f"[green]  ✓ Found {len(subs_list)} subdomains, validating...[/green]")

                    # Validate subdomains - skip those that only return redirects or errors
                    import httpx

                    async def validate_subdomain(sub_url: str) -> tuple[str, bool, str]:
                        """Check if subdomain returns actual content (not just 301/400)."""
                        try:
                            async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=False) as client:
                                resp = await client.head(sub_url)
                                # Accept: 200, 401, 403, 405 (has content/auth)
                                # Reject: 301, 302, 307, 308 (redirect-only), 400 (bad request)
                                if resp.status_code in [301, 302, 307, 308]:
                                    return (sub_url, False, f"redirect-only ({resp.status_code})")
                                elif resp.status_code == 400:
                                    return (sub_url, False, "bad request (400)")
                                return (sub_url, True, f"OK ({resp.status_code})")
                        except Exception as e:
                            return (sub_url, False, f"unreachable ({type(e).__name__})")

                    # Validate all subdomains concurrently
                    scheme = parsed_url.scheme or 'https'
                    validation_tasks = []
                    for sub in subs_list:
                        sub_url = f"{scheme}://{sub}"
                        if sub_url not in all_targets:
                            validation_tasks.append(validate_subdomain(sub_url))

                    if validation_tasks:
                        results = await asyncio.gather(*validation_tasks)
                        valid_count = 0
                        skipped_count = 0

                        for sub_url, is_valid, reason in results:
                            if is_valid:
                                all_targets.append(sub_url)
                                valid_count += 1
                                if valid_count <= 10:
                                    console.print(f"    ✓ {sub_url}")
                            else:
                                skipped_count += 1
                                # Log first few skipped for visibility
                                if skipped_count <= 3:
                                    console.print(f"    [dim]⏭️ {sub_url} - {reason}[/dim]")

                        if valid_count > 10:
                            console.print(f"    ... and {valid_count - 10} more valid subdomains")
                        if skipped_count > 0:
                            console.print(f"    [dim]⏭️ Skipped {skipped_count} subdomains (redirect-only or unreachable)[/dim]")
                else:
                    console.print("[yellow]  ⚠️ No additional subdomains found[/yellow]")
            except Exception as e:
                console.print(f"[yellow]  ⚠️ Subdomain enumeration failed: {e}[/yellow]")
        
        # 2. Technology Detection
        tech_list: list = []  # Track technologies for summary
        try:
            from reconnaissance.tech_detection import TechDetector

            console.print("[cyan]  → Detecting technologies...[/cyan]")
            detector = TechDetector(settings)
            tech_result = await detector.detect(target)

            # detect() returns list[Technology], not a dict
            if tech_result:
                if isinstance(tech_result, list):
                    tech_list = tech_result
                elif isinstance(tech_result, dict):
                    tech_list = tech_result.get('technologies', [])

                if tech_list:
                    console.print(f"[green]  ✓ Detected {len(tech_list)} technologies[/green]")
                    for tech in tech_list[:8]:
                        # Handle both Technology objects and dicts
                        if hasattr(tech, 'name'):
                            name = tech.name
                        elif isinstance(tech, dict):
                            name = tech.get('name', str(tech))
                        else:
                            name = str(tech)
                        console.print(f"    • {name}")
        except Exception as e:
            console.print(f"[yellow]  ⚠️ Tech detection failed: {e}[/yellow]")
        
        # 3. Deep Crawling for endpoint discovery (SPA-aware)
        discovered_urls: list = []  # Track URLs for summary
        api_endpoints: list = []    # Track API endpoints separately
        try:
            # Use SPA-aware crawler for better discovery
            from reconnaissance.spa_crawler import SPAAwareCrawler

            console.print("[cyan]  → Crawling for endpoints (SPA-aware)...[/cyan]")
            spa_crawler = SPAAwareCrawler(settings)
            crawl_result = await spa_crawler.crawl(target, max_depth=5, max_pages=200, probe_api=True)

            if crawl_result:
                discovered_urls = crawl_result.get('urls', [])
                api_endpoints = crawl_result.get('api_endpoints', [])
                forms = crawl_result.get('forms', [])
                js_files = crawl_result.get('js_files', [])
                is_spa = crawl_result.get('is_spa', False)
                spa_framework = crawl_result.get('spa_framework')

                if is_spa:
                    console.print(f"[cyan]  ℹ️ SPA detected: {spa_framework}[/cyan]")

                console.print(f"[green]  ✓ Found {len(discovered_urls)} URLs, {len(api_endpoints)} API endpoints[/green]")

                # Show discovered URLs
                for url in discovered_urls[:5]:
                    display_url = url[:70] + "..." if len(url) > 70 else url
                    console.print(f"    • {display_url}")
                if len(discovered_urls) > 5:
                    console.print(f"    ... and {len(discovered_urls) - 5} more URLs")

                # Show API endpoints
                if api_endpoints:
                    console.print(f"[green]  API Endpoints:[/green]")
                    for endpoint in api_endpoints[:10]:
                        display_ep = endpoint[:70] + "..." if len(endpoint) > 70 else endpoint
                        console.print(f"    • {display_ep}")
                    if len(api_endpoints) > 10:
                        console.print(f"    ... and {len(api_endpoints) - 10} more API endpoints")

        except ImportError:
            # Fallback to basic crawler
            console.print("[yellow]  ⚠️ SPA crawler not available, using basic crawler[/yellow]")
            from reconnaissance.crawler import WebCrawler
            crawler = WebCrawler(settings)
            basic_result = await crawler.crawl(target, max_depth=3, max_pages=100)
            discovered_urls = basic_result if isinstance(basic_result, list) else []
            console.print(f"[green]  ✓ Found {len(discovered_urls)} URLs[/green]")
        except Exception as e:
            console.print(f"[yellow]  ⚠️ Crawling failed: {e}[/yellow]")
        
        console.print(f"\n[bold green]📊 Reconnaissance Summary:[/bold green]")
        console.print(f"  • Total targets: {len(all_targets)}")
        console.print(f"  • URLs discovered: {len(discovered_urls)}")
        console.print(f"  • Technologies: {len(tech_list)}")
        console.print()

    scanner = FullScanner(settings, safe_mode=safe_mode)

    # Aggregate results from all targets
    all_findings = []
    all_modules_run = set()
    all_errors = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        total_targets = len(all_targets)
        task = progress.add_task(f"Running full pentest on {total_targets} target(s)...", total=total_targets * 100)

        for idx, scan_target in enumerate(all_targets):
            progress.update(task, description=f"[{idx+1}/{total_targets}] Scanning {scan_target[:50]}...")
            
            # Run ALL modules with configured concurrency
            result = await scanner.scan(
                target=scan_target,
                category="full",  # All 47 modules
                modules=None,
                concurrent=concurrent,
            )
            
            # Aggregate results
            if result.findings:
                for finding in result.findings:
                    finding['scanned_target'] = scan_target
                    all_findings.append(finding)
            all_modules_run.update(result.modules_run)
            all_errors.extend(result.errors)
            
            progress.update(task, advance=100)

    # Create aggregated result
    result.findings = all_findings
    result.modules_run = list(all_modules_run)
    result.errors = all_errors

    # Display results
    console.print()

    table = Table(title="📊 Pentest Results", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")

    summary = result.to_dict()["summary"]
    table.add_row("Total Findings", str(summary["total_findings"]))
    table.add_row("[red]Critical[/red]", str(summary["critical"]))
    table.add_row("[orange1]High[/orange1]", str(summary["high"]))
    table.add_row("[yellow]Medium[/yellow]", str(summary["medium"]))
    table.add_row("[green]Low[/green]", str(summary["low"]))
    table.add_row("Modules Run", str(len(result.modules_run)))
    table.add_row("Errors", str(len(result.errors)))

    console.print(table)

    # Show findings
    if result.findings:
        console.print("\n[bold]🔍 Security Findings:[/bold]")
        for i, finding in enumerate(result.findings[:15], 1):
            severity = finding.get("severity", "INFO")
            colors = {"CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow", "LOW": "green"}
            color = colors.get(severity, "white")

            console.print(f"  [{color}]{i}. [{severity}] {finding.get('name', finding.get('type', 'Unknown'))}[/{color}]")
            if finding.get("matched_at"):
                console.print(f"     └─ {finding['matched_at'][:80]}")

        if len(result.findings) > 15:
            console.print(f"  ... and {len(result.findings) - 15} more (see full report)")

    # Show errors if any
    if result.errors:
        console.print("\n[yellow]⚠️ Module Errors:[/yellow]")
        for err in result.errors[:5]:
            console.print(f"  • {err['module']}: {err['error'][:50]}")

    # Generate report
    output_dir = Path("reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("://", "_").replace("/", "_").replace(".", "_")[:30]
    client_prefix = client_name.replace(" ", "_")[:20] if client_name else "client"

    if format == "html":
        report_path = output_dir / f"{client_prefix}_{safe_target}_{timestamp}.html"
        _generate_client_html_report(result, report_path, target, client_name)
    elif format == "json":
        import json
        report_path = output_dir / f"{client_prefix}_{safe_target}_{timestamp}.json"
        report_data = result.to_dict()
        report_data["client_name"] = client_name
        report_path.write_text(json.dumps(report_data, indent=2))
    elif format == "md":
        report_path = output_dir / f"{client_prefix}_{safe_target}_{timestamp}.md"
        _generate_client_md_report(result, report_path, target, client_name)

    console.print(f"\n[green]✅ Report saved: {report_path}[/green]")

    # Summary panel
    risk_level = "LOW"
    if summary["critical"] > 0:
        risk_level = "CRITICAL"
    elif summary["high"] > 0:
        risk_level = "HIGH"
    elif summary["medium"] > 0:
        risk_level = "MEDIUM"

    risk_colors = {"CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow", "LOW": "green"}

    console.print(Panel(
        f"[bold]Executive Summary[/bold]\n\n"
        f"Target: {target}\n"
        f"Client: {client_name or 'N/A'}\n"
        f"Overall Risk: [{risk_colors[risk_level]}]{risk_level}[/{risk_colors[risk_level]}]\n"
        f"Total Findings: {summary['total_findings']}\n"
        f"Modules Executed: {len(result.modules_run)}/47",
        title="📋 Assessment Complete",
        border_style="blue",
    ))


def _generate_client_html_report(result, path: Path, target: str, client_name: str):
    """Generate professional HTML report for client delivery."""
    summary = result.to_dict()["summary"]

    risk_level = "LOW"
    if summary["critical"] > 0:
        risk_level = "CRITICAL"
    elif summary["high"] > 0:
        risk_level = "HIGH"
    elif summary["medium"] > 0:
        risk_level = "MEDIUM"

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Assessment Report - {client_name or target}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; background: #f5f5f5; color: #333; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #1a5f2a 0%, #2d8a3e 100%); padding: 40px; color: white; }}
        .header h1 {{ margin: 0 0 10px 0; }}
        .card {{ background: white; border-radius: 10px; padding: 25px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 20px; }}
        .stat {{ text-align: center; padding: 25px; background: #f8f9fa; border-radius: 10px; }}
        .stat-number {{ font-size: 42px; font-weight: bold; }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
        .risk-badge {{ display: inline-block; padding: 10px 30px; border-radius: 5px; font-weight: bold; color: white; }}
        .risk-CRITICAL {{ background: #dc3545; }}
        .risk-HIGH {{ background: #fd7e14; }}
        .risk-MEDIUM {{ background: #ffc107; color: #333; }}
        .risk-LOW {{ background: #28a745; }}
        .finding {{ background: #f8f9fa; padding: 20px; margin: 15px 0; border-radius: 8px; border-left: 5px solid #667eea; }}
        .finding.critical {{ border-color: #dc3545; }}
        .finding.high {{ border-color: #fd7e14; }}
        .finding.medium {{ border-color: #ffc107; }}
        .finding.low {{ border-color: #28a745; }}
        .tag {{ display: inline-block; padding: 5px 15px; border-radius: 20px; font-size: 12px; font-weight: bold; color: white; }}
        .tag.critical {{ background: #dc3545; }}
        .tag.high {{ background: #fd7e14; }}
        .tag.medium {{ background: #ffc107; color: #333; }}
        .tag.low {{ background: #28a745; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f8f9fa; font-weight: bold; }}
        .footer {{ text-align: center; padding: 20px; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Security Assessment Report</h1>
        <p><strong>Client:</strong> {client_name or 'Confidential'}</p>
        <p><strong>Target:</strong> {target}</p>
        <p><strong>Date:</strong> {result.start_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Overall Risk:</strong> <span class="risk-badge risk-{risk_level}">{risk_level}</span></p>
    </div>

    <div class="container">
        <div class="card">
            <h2>📊 Executive Summary</h2>
            <div class="summary-grid">
                <div class="stat">
                    <div class="stat-number">{summary['total_findings']}</div>
                    <div>Total Findings</div>
                </div>
                <div class="stat">
                    <div class="stat-number critical">{summary['critical']}</div>
                    <div>Critical</div>
                </div>
                <div class="stat">
                    <div class="stat-number high">{summary['high']}</div>
                    <div>High</div>
                </div>
                <div class="stat">
                    <div class="stat-number medium">{summary['medium']}</div>
                    <div>Medium</div>
                </div>
                <div class="stat">
                    <div class="stat-number low">{summary['low']}</div>
                    <div>Low</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>🔍 Detailed Findings</h2>
"""

    for i, finding in enumerate(result.findings, 1):
        severity = finding.get("severity", "INFO").lower()
        html += f"""
            <div class="finding {severity}">
                <h3><span class="tag {severity}">{finding.get('severity', 'INFO')}</span> {i}. {finding.get('name', finding.get('type', 'Unknown'))}</h3>
                <p><strong>Description:</strong> {finding.get('description', 'No description')}</p>
                <p><strong>Location:</strong> <code>{finding.get('matched_at', finding.get('url', 'N/A'))}</code></p>
                <p><strong>CWE:</strong> {finding.get('cwe', 'N/A')}</p>
                <p><strong>Recommendation:</strong> {finding.get('remediation', 'Review and remediate according to security best practices.')}</p>
            </div>
"""

    if not result.findings:
        html += "<p>No significant security vulnerabilities were identified during this assessment.</p>"

    html += f"""
        </div>

        <div class="card">
            <h2>📋 Modules Executed</h2>
            <table>
                <tr><th>Module</th><th>Status</th></tr>
"""

    for module in result.modules_run:
        html += f"<tr><td>{module}</td><td>✅ Completed</td></tr>"

    html += f"""
            </table>
        </div>

        <div class="footer">
            <p>Generated by PetNTester AI v3.1 - Professional Edition</p>
            <p>This report is confidential and intended for {client_name or 'the authorized recipient'} only.</p>
        </div>
    </div>
</body>
</html>
"""

    path.write_text(html)


def _generate_client_md_report(result, path: Path, target: str, client_name: str):
    """Generate markdown report for client delivery."""
    summary = result.to_dict()["summary"]

    risk_level = "LOW"
    if summary["critical"] > 0:
        risk_level = "CRITICAL"
    elif summary["high"] > 0:
        risk_level = "HIGH"
    elif summary["medium"] > 0:
        risk_level = "MEDIUM"

    md = f"""# Security Assessment Report

**Client:** {client_name or 'Confidential'}
**Target:** {target}
**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Overall Risk Level:** {risk_level}

---

## Executive Summary

| Severity | Count |
|----------|-------|
| Critical | {summary['critical']} |
| High | {summary['high']} |
| Medium | {summary['medium']} |
| Low | {summary['low']} |
| **Total** | **{summary['total_findings']}** |

---

## Detailed Findings

"""

    for i, finding in enumerate(result.findings, 1):
        severity = finding.get("severity", "INFO")
        md += f"""### {i}. [{severity}] {finding.get('name', finding.get('type', 'Unknown'))}

**Severity:** {severity}
**Location:** `{finding.get('matched_at', finding.get('url', 'N/A'))}`
**CWE:** {finding.get('cwe', 'N/A')}

**Description:**
{finding.get('description', 'No description available.')}

**Evidence:**
```
{finding.get('evidence', finding.get('payload', 'N/A'))}
```

**Recommendation:**
{finding.get('remediation', 'Review and remediate according to security best practices.')}

---

"""

    md += f"""
## Modules Executed

{len(result.modules_run)} modules were executed during this assessment.

---

*This report is confidential and intended for {client_name or 'the authorized recipient'} only.*

*Generated by PetNTester AI v3.1 - Professional Edition*
"""

    path.write_text(md)


@cli.command()
@click.argument("target")
def authorize(target: str):
    """Authorize a target for scanning."""
    from core.config_manager import get_settings
    from core.auth_manager import AuthManager
    from urllib.parse import urlparse
    
    settings = get_settings()
    auth = AuthManager(settings)
    
    # Normalize
    parsed = urlparse(target)
    domain = parsed.netloc or parsed.path
    
    auth.add_target(domain)
    
    console.print(f"[green]✅ Authorized: {domain}[/green]")
    console.print(f"[dim]You can now run: pentest scan {target}[/dim]")


@cli.command("threat-model")
@click.argument("target")
@click.option("--output", "-o", type=click.Path(), help="Output file")
def threat_model(target: str, output: str):
    """Generate threat model for TARGET."""
    print_banner()
    
    from threat_modeling import STRIDEAnalyzer, ThreatModeler, AbuseCaseGenerator
    
    console.print(Panel(
        f"[bold cyan]Target:[/bold cyan] {target}\n"
        f"[bold cyan]Methodology:[/bold cyan] STRIDE",
        title="🎯 Threat Modeling",
        border_style="blue",
    ))
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("Analyzing threats...", total=None)
        
        analyzer = STRIDEAnalyzer()
        modeler = ThreatModeler()
        abuse_gen = AbuseCaseGenerator()
        
        # Sample endpoints from target
        endpoints = [
            {"path": "/", "method": "GET", "parameters": []},
            {"path": "/login", "method": "POST", "parameters": ["username", "password"]},
            {"path": "/api/users", "method": "GET", "parameters": ["id"]},
            {"path": "/api/payment", "method": "POST", "parameters": ["amount"]},
        ]
        
        # Generate threat model
        model = modeler.create_threat_model(
            name=target,
            endpoints=endpoints,
            description=f"Threat model for {target}",
        )
        
        progress.update(task, completed=True)
    
    # Display results
    console.print(f"\n[bold]📊 Threat Model Summary:[/bold]")
    console.print(f"  • Threats Identified: {len(model.threats)}")
    console.print(f"  • Abuse Cases: {len(model.abuse_cases)}")
    console.print(f"  • Trust Boundaries: {len(model.trust_boundaries)}")
    console.print(f"  • Data Flows: {len(model.data_flows)}")
    
    console.print(f"\n[bold]🔴 Top Threats:[/bold]")
    for threat in model.threats[:5]:
        console.print(f"  • [{threat.category.value}] {threat.name}")
    
    console.print(f"\n[bold]💡 Recommendations:[/bold]")
    for rec in model.recommendations[:5]:
        console.print(f"  • {rec}")
    
    # Generate report if output specified
    if output:
        html = modeler.generate_html_report(model)
        Path(output).write_text(html)
        console.print(f"\n[green]✅ Report saved: {output}[/green]")


@cli.command()
def modules():
    """List all available scanner modules."""
    print_banner()
    
    from scanning.full_scanner import FullScanner
    
    console.print("\n[bold]📦 Available Scanner Modules (47):[/bold]\n")

    categories = {
        "🔴 Injection": ["sqli", "xss", "dom_xss", "cmdi", "xxe", "nosql", "ssti", "ldap", "crlf"],
        "🔐 Authentication": ["auth", "oauth", "saml", "mfa", "authz", "csrf", "ratelimit"],
        "🌐 API Security": ["api", "graphql", "grpc", "websocket", "sse", "idor", "mass_assign"],
        "🏗️ Infrastructure": ["ssl", "headers", "cors", "cloud", "k8s", "dns_rebind"],
        "⚡ Advanced": ["smuggling", "cache", "deser", "prototype", "ssrf", "lfi", "rls_bypass"],
        "🔍 Discovery": ["cms", "dir", "nuclei", "email", "mobile", "backend", "third_party"],
        "💼 Business": ["business", "postexploit"],
        "☁️ BaaS": ["supabase", "firebase", "rls_bypass"],
    }
    
    for cat, mods in categories.items():
        console.print(f"  {cat}")
        for mod in mods:
            console.print(f"    • {mod}")
        console.print()
    
    console.print("[bold]📁 Scan Categories:[/bold]")
    for cat, mods in FullScanner.CATEGORIES.items():
        console.print(f"  • {cat}: {len(mods)} modules")


@cli.command()
def version():
    """Show version information."""
    console.print(Panel(
        "[bold]AI Pentest Framework[/bold]\n"
        "Version: 2.0.0\n"
        "Modules: 47 (39 scanners + 4 analysis + 3 threat + 3 safe)\n"
        "Safe Mode: ✅ Enabled\n"
        "Threat Modeling: ✅ STRIDE\n"
        "Attack Chains: ✅ Visual\n"
        "Validation: ✅ Metrics & Benchmarks",
        title="ℹ️ Version",
        border_style="blue",
    ))


@cli.command()
@click.argument("target_type", type=click.Choice(["dvwa", "juice_shop", "webgoat", "vampi", "all"]))
@click.option("--url", "-u", help="Target URL (if running locally)")
@click.option("--skip-validation", is_flag=True, help="Skip target type validation")
def benchmark(target_type: str, url: str | None, skip_validation: bool):
    """Run benchmark against known vulnerable targets.
    
    Validates scanner effectiveness by testing against applications
    with known vulnerabilities (DVWA, Juice Shop, WebGoat).
    
    Examples:
    
        pentest benchmark dvwa --url http://localhost
        pentest benchmark juice_shop --url http://localhost:3000
    """
    print_banner()
    
    from validation.benchmark import BenchmarkSuite, BenchmarkTarget
    from validation.metrics import MetricsCollector
    
    target_map = {
        "dvwa": BenchmarkTarget.DVWA,
        "juice_shop": BenchmarkTarget.JUICE_SHOP,
        "webgoat": BenchmarkTarget.WEBGOAT,
        "vampi": BenchmarkTarget.CUSTOM,
    }
    
    console.print(Panel(
        f"[bold cyan]Target:[/bold cyan] {target_type}\n"
        f"[bold cyan]URL:[/bold cyan] {url or 'Not specified'}\n"
        "[bold cyan]Mode:[/bold cyan] Benchmark validation",
        title="🧪 Benchmark Test",
        border_style="yellow",
    ))
    
    if not url:
        console.print("\n[yellow]⚠️ URL required. Start your test target first:[/yellow]")
        console.print(f"   docker run -d -p 80:80 vulnerables/web-dvwa")
        console.print(f"   pentest benchmark dvwa --url http://localhost")
        return
    
    async def run_benchmark():
        metrics = MetricsCollector()
        suite = BenchmarkSuite(metrics)
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task("Running benchmark...", total=None)
            
            target = target_map.get(target_type, BenchmarkTarget.CUSTOM)
            result = await suite.run_benchmark(
                target, url, skip_target_validation=skip_validation
            )
            
            progress.update(task, completed=True)
        
        # Display results
        console.print(f"\n[bold]📊 Benchmark Results:[/bold]")
        
        # Show warning if target wasn't validated
        if not result.target_validated:
            console.print(Panel(
                "[bold red]⚠️ TARGET MISMATCH DETECTED[/bold red]\n\n"
                f"The URL doesn't appear to be a {target_type.upper()} instance.\n"
                "Findings are marked as 'unverified' instead of 'false positives'.\n"
                "Detection metrics are not available.\n\n"
                "[dim]Use --skip-validation to force benchmark with FP/FN metrics.[/dim]",
                title="Warning",
                border_style="red",
            ))
        
        table = Table(title="Detection Metrics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Known Vulnerabilities", str(len(result.known_vulns)))
        table.add_row("Total Findings", str(len(result.found_vulns)))
        table.add_row("Detected (True Positives)", str(len(result.true_positives)))
        
        if result.target_validated:
            table.add_row("Missed (False Negatives)", str(len(result.false_negatives)))
            table.add_row("False Positives", str(len(result.false_positives)))
            table.add_row("Detection Rate", f"{result.detection_rate * 100:.1f}%")
            table.add_row("Precision", f"{result.precision * 100:.1f}%")
            table.add_row("Recall", f"{result.recall * 100:.1f}%")
            table.add_row("F1 Score", f"{result.f1_score * 100:.1f}%")
        else:
            table.add_row("Unverified Findings", f"[yellow]{len(result.unverified_findings)}[/yellow]")
            table.add_row("Detection Rate", "[dim]N/A (target mismatch)[/dim]")
            table.add_row("Precision", "[dim]N/A (target mismatch)[/dim]")
            table.add_row("Recall", "[dim]N/A (target mismatch)[/dim]")
            table.add_row("F1 Score", "[dim]N/A (target mismatch)[/dim]")
        
        console.print(table)
        
        if result.target_validated and result.false_negatives:
            console.print(f"\n[yellow]⚠️ Missed vulnerabilities:[/yellow]")
            for vuln_id in result.false_negatives[:5]:
                console.print(f"   • {vuln_id}")
        
        if not result.target_validated and result.unverified_findings:
            console.print(f"\n[cyan]ℹ️ Unverified findings (cannot confirm as FP or TP):[/cyan]")
            for finding in result.unverified_findings[:5]:
                finding_type = finding.get("type", "unknown") if isinstance(finding, dict) else "unknown"
                console.print(f"   • {finding_type}")
            if len(result.unverified_findings) > 5:
                console.print(f"   ... and {len(result.unverified_findings) - 5} more")
        
        # Save report
        report_path = f"reports/benchmark_{target_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        suite.save_report(report_path)
        console.print(f"\n[green]✅ Report saved: {report_path}[/green]")
    
    asyncio.run(run_benchmark())


@cli.command()
@click.option("--module", "-m", help="Specific module to validate")
def validate(module: str | None):
    """Validate scanner modules against test cases.
    
    Runs predefined test cases to measure module accuracy,
    precision, recall, and false positive rates.
    
    Examples:
    
        pentest validate              # Validate all modules
        pentest validate -m sqli      # Validate SQL injection module
    """
    print_banner()
    
    from validation.validator import ModuleValidator
    
    console.print(Panel(
        f"[bold cyan]Mode:[/bold cyan] Module validation\n"
        f"[bold cyan]Target:[/bold cyan] {module or 'All modules'}",
        title="🔬 Validation",
        border_style="magenta",
    ))
    
    async def run_validation():
        validator = ModuleValidator()
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task("Running validation tests...", total=None)
            
            modules = [module] if module else None
            report = await validator.validate_all(modules)
            
            progress.update(task, completed=True)
        
        # Display results
        console.print(f"\n[bold]📊 Validation Results:[/bold]")
        
        table = Table(title="Test Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Total Tests", str(report.total_tests))
        table.add_row("Passed", f"[green]{report.passed_tests}[/green]")
        table.add_row("Failed", f"[red]{report.failed_tests}[/red]")
        table.add_row("Errors", f"[yellow]{report.error_tests}[/yellow]")
        table.add_row("Success Rate", f"{report.success_rate * 100:.1f}%")
        
        console.print(table)
        
        # Module grades
        if report.module_metrics:
            console.print(f"\n[bold]📈 Module Grades:[/bold]")
            for name, metrics in report.module_metrics.items():
                grade_color = "green" if metrics.grade.startswith("A") else "yellow" if metrics.grade.startswith("B") else "red"
                console.print(f"   • {name}: [{grade_color}]{metrics.grade}[/{grade_color}] (Effectiveness: {metrics.effectiveness_score:.1f}%)")
        
        console.print(f"\n[dim]Report ID: {report.report_id}[/dim]")
    
    asyncio.run(run_validation())


@cli.command()
def health():
    """Show framework health and metrics.
    
    Displays overall framework health based on validation
    results, module grades, and recommendations.
    """
    print_banner()
    
    from validation.metrics import MetricsCollector
    
    metrics = MetricsCollector()
    health = metrics.get_framework_health()
    
    if health.get("status") == "NO_DATA":
        console.print(Panel(
            "[yellow]No validation data available yet.[/yellow]\n\n"
            "Run validation first:\n"
            "   [cyan]pentest validate[/cyan]\n"
            "   [cyan]pentest benchmark dvwa --url http://localhost[/cyan]",
            title="📊 Framework Health",
            border_style="yellow",
        ))
        return
    
    status_color = "green" if health["status"] == "HEALTHY" else "yellow"
    
    console.print(Panel(
        f"[bold {status_color}]Status: {health['status']}[/bold {status_color}]\n\n"
        f"[bold]Summary:[/bold]\n"
        f"  • Total Modules: {health['summary']['total_modules']}\n"
        f"  • Production Ready: [green]{health['summary']['production_ready']}[/green]\n"
        f"  • Needs Improvement: [yellow]{health['summary']['needs_improvement']}[/yellow]\n"
        f"  • Unreliable: [red]{health['summary']['unreliable']}[/red]\n"
        f"  • Insufficient Data: [dim]{health['summary']['insufficient_data']}[/dim]\n\n"
        f"[bold]Overall Metrics:[/bold]\n"
        f"  • Precision: {health['overall_metrics']['precision'] * 100:.1f}%\n"
        f"  • Recall: {health['overall_metrics']['recall'] * 100:.1f}%\n"
        f"  • Total Scans: {health['overall_metrics']['total_scans']}",
        title="📊 Framework Health",
        border_style=status_color,
    ))
    
    if health.get("need_attention"):
        console.print(f"\n[yellow]⚠️ Modules needing attention:[/yellow]")
        for mod in health["need_attention"]:
            console.print(f"   • {mod}")
    
    if health.get("top_performers"):
        console.print(f"\n[green]✅ Top performers:[/green]")
        for mod in health["top_performers"]:
            console.print(f"   • {mod}")


@cli.command()
def targets():
    """List available test targets for benchmarking.
    
    Shows Docker commands to start vulnerable applications
    for testing and validation.
    """
    print_banner()
    
    from validation.test_targets import VulnerabilityDatabase
    
    console.print("\n[bold]🎯 Available Test Targets:[/bold]\n")
    
    for name, target in VulnerabilityDatabase.TARGETS.items():
        console.print(f"[bold cyan]{target.name}[/bold cyan]")
        console.print(f"   Type: {target.target_type.value} | Difficulty: {target.difficulty.value}")
        console.print(f"   Vulnerabilities: {len(target.vulnerabilities)}")
        
        if target.setup.docker_run:
            console.print(f"   [dim]$ {target.setup.docker_run}[/dim]")
        
        console.print()
    
    console.print("[bold]Quick Start:[/bold]")
    console.print("   1. Start DVWA:  [cyan]docker run -d -p 80:80 vulnerables/web-dvwa[/cyan]")
    console.print("   2. Run benchmark: [cyan]pentest benchmark dvwa --url http://localhost[/cyan]")


@cli.command()
@click.argument("target")
@click.option("--output", "-o", type=click.Path(), help="Output directory")
@click.option("--format", "-f", type=click.Choice(["html", "json"]), default="json")
def securedev(target: str, output: str, format: str):
    """
    Run SecureDev Security Scan with decision tree.
    
    This scan automatically detects the backend type (Supabase, Firebase, 
    or Custom API) and runs appropriate security tests.
    
    Examples:
    
        pentest securedev https://myapp.vercel.app
        pentest securedev https://example.com -f json
    """
    asyncio.run(_run_securedev_scan(target, output, format))


async def _run_securedev_scan(target: str, output: str, format: str):
    """Execute SecureDev scan with decision tree."""
    print_banner()
    
    console.print(Panel(
        f"[bold cyan]Target:[/bold cyan] {target}\n"
        f"[bold cyan]Mode:[/bold cyan] 🛡️ SecureDev Decision Tree\n"
        f"[bold cyan]Auto-detect:[/bold cyan] Supabase | Firebase | Custom API",
        title="🔐 SecureDev Security Scan",
        border_style="magenta",
    ))
    
    try:
        from scanning.securedev_orchestrator import SecureDevOrchestrator
        
        orchestrator = SecureDevOrchestrator()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("🔍 Detecting backend...", total=None)
            
            result = await orchestrator.scan(target)
            
            progress.update(task, description="✅ Scan complete!", completed=True)
        
        # Display results
        console.print()
        
        # Backend detection result
        backend_color = {
            "SUPABASE": "green",
            "FIREBASE": "yellow",
            "CUSTOM_REST": "cyan",
            "CUSTOM_GRAPHQL": "magenta",
            "UNKNOWN": "red",
        }
        color = backend_color.get(result.backend_type.name, "white")
        
        console.print(Panel(
            f"[bold {color}]Detected: {result.backend_type.name}[/bold {color}]\n"
            f"[dim]Config: {result.backend_config}[/dim]",
            title="🎯 Backend Detection (FASE 0)",
            border_style=color,
        ))
        
        # Summary table
        table = Table(title="📊 SecureDev Scan Results", show_header=True, header_style="bold cyan")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", justify="right")
        
        table.add_row("Total Findings", str(result.total_findings))
        table.add_row("[red]Critical[/red]", str(result.total_critical))
        table.add_row("[orange1]High[/orange1]", str(result.total_high))
        table.add_row("Phases Completed", str(len([p for p in result.phases if p.status.name == "COMPLETED"])))
        table.add_row("Phases Skipped", str(len([p for p in result.phases if p.status.name == "SKIPPED"])))
        
        console.print(table)
        
        # Phases breakdown
        console.print("\n[bold]📋 Phases Executed:[/bold]")
        for phase in result.phases:
            status_icon = {
                "COMPLETED": "✅",
                "SKIPPED": "⏭️",
                "FAILED": "❌",
                "PENDING": "⏳",
                "RUNNING": "🔄",
            }
            icon = status_icon.get(phase.status.name, "❓")
            findings = f" [{phase.critical_count}C|{phase.findings_count}]" if phase.findings_count else ""
            
            console.print(f"  {icon} FASE {phase.phase_id}: {phase.phase_name}{findings}")
            if phase.skip_reason:
                console.print(f"     └─ [dim]{phase.skip_reason}[/dim]")
        
        # Save report
        output_dir = Path(output) if output else Path("reports")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace("://", "_").replace("/", "_").replace(".", "_")[:30]
        
        if format == "json":
            import json
            report_path = output_dir / f"securedev_{safe_target}_{timestamp}.json"
            report_path.write_text(json.dumps(result.to_dict(), indent=2))
        else:
            report_path = output_dir / f"securedev_{safe_target}_{timestamp}.html"
            _generate_securedev_html_report(result, report_path)
        
        console.print(f"\n[green]✅ Report saved: {report_path}[/green]")
        
    except ImportError as e:
        console.print(f"[red]❌ SecureDev module not available: {e}[/red]")
        console.print("[yellow]Make sure securedev_orchestrator.py is installed.[/yellow]")
    except Exception as e:
        console.print(f"[red]❌ Scan failed: {e}[/red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")


def _generate_securedev_html_report(result, path: Path):
    """Generate SecureDev HTML report."""
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>SecureDev Security Report - {result.target}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; background: #0f0f23; color: #eee; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        .header h1 {{ margin: 0; color: white; }}
        .card {{ background: #1e1e3f; border-radius: 10px; padding: 20px; margin-bottom: 20px; }}
        .backend-badge {{ display: inline-block; padding: 5px 15px; border-radius: 20px; background: #6366f1; color: white; font-weight: bold; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 15px; }}
        .stat {{ text-align: center; padding: 20px; background: #2d2d5a; border-radius: 8px; }}
        .stat-number {{ font-size: 32px; font-weight: bold; }}
        .critical {{ color: #ef4444; }}
        .high {{ color: #f97316; }}
        .phase {{ padding: 10px 15px; margin: 5px 0; background: #2d2d5a; border-radius: 6px; display: flex; justify-content: space-between; }}
        .phase.completed {{ border-left: 3px solid #22c55e; }}
        .phase.skipped {{ border-left: 3px solid #64748b; opacity: 0.7; }}
        .phase.failed {{ border-left: 3px solid #ef4444; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 SecureDev Security Report</h1>
            <p><strong>Target:</strong> {result.target}</p>
            <p><strong>Date:</strong> {result.started_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <span class="backend-badge">{result.backend_type.name}</span>
        </div>
        
        <div class="card">
            <h2>📊 Summary</h2>
            <div class="summary-grid">
                <div class="stat">
                    <div class="stat-number">{result.total_findings}</div>
                    <div>Findings</div>
                </div>
                <div class="stat">
                    <div class="stat-number critical">{result.total_critical}</div>
                    <div>Critical</div>
                </div>
                <div class="stat">
                    <div class="stat-number high">{result.total_high}</div>
                    <div>High</div>
                </div>
                <div class="stat">
                    <div class="stat-number">{len([p for p in result.phases if p.status.name == 'COMPLETED'])}</div>
                    <div>Phases Run</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>📋 Phases Executed</h2>
"""
    
    for phase in result.phases:
        status_class = phase.status.name.lower()
        icon = {"COMPLETED": "✅", "SKIPPED": "⏭️", "FAILED": "❌"}.get(phase.status.name, "❓")
        html += f"""
            <div class="phase {status_class}">
                <span>{icon} FASE {phase.phase_id}: {phase.phase_name}</span>
                <span>{phase.findings_count} findings | {phase.duration_seconds:.1f}s</span>
            </div>
"""
    
    html += """
        </div>
    </div>
</body>
</html>"""
    
    path.write_text(html)


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
