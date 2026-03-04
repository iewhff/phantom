"""
Report generator with multiple output formats.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import jinja2
from jinja2 import Environment, FileSystemLoader

from ai_engine.model_manager import ModelManager
from reporting.charts import integrate_charts_with_report
from utils.logger import get_logger

if TYPE_CHECKING:
    from core.config_manager import Settings
    from core.orchestrator import ScanContext

logger = get_logger(__name__)


def sanitize_filename(target: str, max_length: int = 100) -> str:
    """
    Sanitize target string for safe use as filename.

    SECURITY: Prevents path traversal attacks (CWE-22).

    Args:
        target: Raw target string (URL, domain, etc.)
        max_length: Maximum filename length

    Returns:
        Safe filename string containing only alphanumeric, dash, underscore
    """
    # Remove URL scheme
    clean = re.sub(r'^https?://', '', target)

    # Replace unsafe characters with underscore
    # Only allow alphanumeric, dash, underscore
    clean = re.sub(r'[^a-zA-Z0-9_-]', '_', clean)

    # Remove consecutive underscores
    clean = re.sub(r'_+', '_', clean)

    # Remove leading/trailing underscores
    clean = clean.strip('_')

    # Ensure not empty
    if not clean:
        clean = "unknown_target"

    # Truncate to max length
    if len(clean) > max_length:
        clean = clean[:max_length]

    return clean


def validate_output_path(output_dir: Path, filename: str) -> Path:
    """
    Validate that output path is within allowed directory.

    SECURITY: Final defense against path traversal (CWE-22).

    Args:
        output_dir: Allowed output directory
        filename: Sanitized filename

    Returns:
        Safe absolute path

    Raises:
        ValueError: If path would escape output directory
    """
    output_path = (output_dir / filename).resolve()
    output_dir_resolved = output_dir.resolve()

    # Ensure the resolved path is within the output directory
    if not str(output_path).startswith(str(output_dir_resolved)):
        raise ValueError(f"Path traversal attempt detected: {filename}")

    return output_path


class ReportGenerator:
    """
    Generates security assessment reports in multiple formats.
    
    Formats:
    - PDF (via WeasyPrint)
    - HTML
    - JSON
    - Markdown
    """
    
    def __init__(self, settings: Settings) -> None:
        """
        Initialize generator.
        
        Args:
            settings: Application settings
        """
        self.settings = settings
        self.config = settings.reporting
        
        # Initialize Jinja2
        templates_path = Path(self.config.templates_path)
        templates_path.mkdir(parents=True, exist_ok=True)
        
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(templates_path)),
            autoescape=True,
        )
        
        # Add custom filters
        self.jinja_env.filters["severity_color"] = self._severity_color
        self.jinja_env.filters["format_datetime"] = self._format_datetime
        
        self.model = ModelManager(settings)
        self.sanitizer = DataSanitizer(settings)
    
    async def generate(
        self,
        context: ScanContext,
        format: str = "pdf",
        template: str = "professional",
    ) -> str:
        """
        Generate a report.
        
        Args:
            context: Scan context with results
            format: Output format
            template: Template name
            
        Returns:
            Path to generated report
        """
        logger.info(f"Generating {format} report using template '{template}'")
        
        # Prepare data
        report_data = await self._prepare_data(context)
        
        # Generate based on format
        generators = {
            "pdf": self._generate_pdf,
            "html": self._generate_html,
            "json": self._generate_json,
            "markdown": self._generate_markdown,
        }
        
        generator = generators.get(format, self._generate_json)
        output_path = await generator(report_data, template)
        
        logger.info(f"Report generated: {output_path}")
        return output_path
    
    async def _prepare_data(self, context: ScanContext) -> dict[str, Any]:
        """Prepare data for report templates."""
        # Sanitize if configured
        findings = context.findings
        if self.config.anonymize_sensitive:
            findings = [self.sanitizer.sanitize_finding(f) for f in findings]
        
        # Filter by CVSS threshold
        threshold = self.config.cvss_threshold
        filtered_findings = [
            f for f in findings
            if f.get("cvss_score", 0) >= threshold or f.get("severity", "INFO") in ("CRITICAL", "HIGH")
        ]
        
        # Group by severity
        by_severity = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
            "INFO": [],
        }
        
        for f in filtered_findings:
            sev = f.get("severity", "INFO").upper()
            if sev in by_severity:
                by_severity[sev].append(f)
        
        # Calculate statistics
        stats = context.get_statistics()
        stats["filtered_findings"] = len(filtered_findings)
        stats["scan_duration"] = self._calculate_duration(context)
        stats["risk_score"] = self._calculate_risk_score(by_severity)
        
        # Get exploit chains
        chains = []
        for insight in context.ai_insights:
            if insight.get("type") == "exploit_chains":
                chains.extend(insight.get("data", []))
        
        # Generate executive summary
        exec_summary = await self._generate_executive_summary(
            context, by_severity, stats, chains
        )
        
        report_data = {
            "target": context.target,
            "scope": context.scope,
            "stats": stats,
            "executive_summary": exec_summary,
            "findings": filtered_findings,
            "findings_by_severity": by_severity,
            "exploit_chains": chains,
            "metadata": context.metadata,
            "generated_at": datetime.now().isoformat(),
            "generated_by": "AI-Pentest Framework v2.0",
            "company_name": self.config.company_name,
            "company_logo": self.config.company_logo,
        }

        # Generate charts (SVG) for visual reports
        report_data = integrate_charts_with_report(report_data)

        return report_data
    
    async def _generate_executive_summary(
        self,
        context: ScanContext,
        by_severity: dict,
        stats: dict,
        chains: list,
    ) -> str:
        """Generate AI executive summary."""
        # Load prompt
        prompt_path = Path("config/ai_prompts/report_generation.txt")
        
        if prompt_path.exists():
            template = prompt_path.read_text()
        else:
            template = "Generate executive summary for: {target}"
        
        # Format top vulnerabilities
        top_vulns = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM"]:
            for f in by_severity.get(sev, [])[:2]:
                top_vulns.append(f"- [{sev}] {f.get('name', 'Unknown')}")
        
        # Format chains
        chains_text = "\n".join([
            f"- {c.get('name', 'Unknown')}: {c.get('impact', '')}"
            for c in chains[:3]
        ]) or "No exploit chains detected"
        
        prompt = template.format(
            target=context.target,
            scope_count=len(context.scope),
            duration=stats.get("scan_duration", "N/A"),
            scan_date=datetime.now().strftime("%Y-%m-%d"),
            critical_count=stats["by_severity"].get("CRITICAL", 0),
            high_count=stats["by_severity"].get("HIGH", 0),
            medium_count=stats["by_severity"].get("MEDIUM", 0),
            low_count=stats["by_severity"].get("LOW", 0),
            info_count=stats["by_severity"].get("INFO", 0),
            top_vulns="\n".join(top_vulns) or "No critical vulnerabilities",
            exploit_chains=chains_text,
        )
        
        try:
            summary = await self.model.generate(
                prompt=prompt,
                temperature=0.5,
                max_tokens=600,
            )
            return summary.strip()
        except Exception as e:
            logger.warning(f"Executive summary generation failed: {e}")
            return "Executive summary generation failed. Please review the technical findings below."
    
    async def _generate_pdf(
        self,
        data: dict[str, Any],
        template: str,
    ) -> str:
        """Generate PDF report."""
        # First generate HTML
        html_content = self._render_template(data, template)
        
        # Convert to PDF
        try:
            from weasyprint import HTML, CSS
            
            output_dir = Path("data/reports")
            output_dir.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_clean = sanitize_filename(data["target"])
            filename = f"{target_clean}_{timestamp}.pdf"
            output_path = validate_output_path(output_dir, filename)
            
            # Load CSS
            css_path = Path(self.config.templates_path) / "styles.css"
            stylesheets = []
            if css_path.exists():
                stylesheets.append(CSS(filename=str(css_path)))
            
            HTML(string=html_content).write_pdf(
                str(output_path),
                stylesheets=stylesheets,
            )
            
            return str(output_path)
            
        except ImportError:
            logger.warning("WeasyPrint not installed, falling back to HTML")
            return await self._generate_html(data, template)
    
    async def _generate_html(
        self,
        data: dict[str, Any],
        template: str,
    ) -> str:
        """Generate HTML report."""
        html_content = self._render_template(data, template)
        
        output_dir = Path("data/reports")
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_clean = sanitize_filename(data["target"])
        filename = f"{target_clean}_{timestamp}.html"
        output_path = validate_output_path(output_dir, filename)

        output_path.write_text(html_content)
        return str(output_path)
    
    async def _generate_json(
        self,
        data: dict[str, Any],
        template: str,
    ) -> str:
        """Generate JSON report."""
        output_dir = Path("data/reports")
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_clean = sanitize_filename(data["target"])
        filename = f"{target_clean}_{timestamp}.json"
        output_path = validate_output_path(output_dir, filename)

        with open(output_path, "w") as f:
            json.dump(data, f, indent=2, default=str)

        return str(output_path)
    
    async def _generate_markdown(
        self,
        data: dict[str, Any],
        template: str,
    ) -> str:
        """Generate Markdown report."""
        md_content = self._render_markdown(data)

        output_dir = Path("data/reports")
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_clean = sanitize_filename(data["target"])
        filename = f"{target_clean}_{timestamp}.md"
        output_path = validate_output_path(output_dir, filename)

        output_path.write_text(md_content)
        return str(output_path)
    
    def _render_template(
        self,
        data: dict[str, Any],
        template: str,
    ) -> str:
        """Render Jinja2 template."""
        try:
            tmpl = self.jinja_env.get_template(f"{template}.j2")
            return tmpl.render(**data)
        except (jinja2.TemplateError, jinja2.TemplateNotFound) as e:
            # Use default template
            logger.debug(f"Template rendering failed, using default: {e}")
            return self._default_html_template(data)
    
    def _render_markdown(self, data: dict[str, Any]) -> str:
        """Render Markdown report."""
        lines = [
            f"# Security Assessment Report",
            f"",
            f"**Target:** {data['target']}",
            f"**Date:** {data['generated_at']}",
            f"**Generated by:** {data['generated_by']}",
            f"",
            f"## Executive Summary",
            f"",
            data["executive_summary"],
            f"",
            f"## Statistics",
            f"",
            f"- **Total Findings:** {data['stats']['total_findings']}",
            f"- **Critical:** {data['stats']['by_severity'].get('CRITICAL', 0)}",
            f"- **High:** {data['stats']['by_severity'].get('HIGH', 0)}",
            f"- **Medium:** {data['stats']['by_severity'].get('MEDIUM', 0)}",
            f"- **Low:** {data['stats']['by_severity'].get('LOW', 0)}",
            f"- **Risk Score:** {data['stats'].get('risk_score', 'N/A')}/10",
            f"",
            f"## Findings",
            f"",
        ]
        
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            findings = data["findings_by_severity"].get(severity, [])
            if findings:
                lines.append(f"### {severity} Severity")
                lines.append("")
                
                for f in findings:
                    lines.append(f"#### {f.get('name', 'Unknown')}")
                    lines.append(f"")
                    lines.append(f"- **Type:** {f.get('type', 'N/A')}")
                    lines.append(f"- **Location:** {f.get('matched_at', 'N/A')}")
                    lines.append(f"- **CVSS:** {f.get('cvss_score', 'N/A')}")
                    lines.append(f"")
                    lines.append(f.get("description", "No description"))
                    lines.append(f"")
                    
                    if f.get("remediation"):
                        lines.append(f"**Remediation:** {f['remediation']}")
                        lines.append(f"")
        
        if data.get("exploit_chains"):
            lines.append(f"## Exploit Chains")
            lines.append(f"")

            for chain in data["exploit_chains"]:
                lines.append(f"### {chain.get('name', 'Unknown')}")
                lines.append(f"")
                lines.append(f"- **Impact:** {chain.get('impact', 'N/A')}")
                lines.append(f"- **Difficulty:** {chain.get('difficulty', 'N/A')}")
                if chain.get("vulnerabilities"):
                    lines.append(f"- **Required Vulnerabilities:** {', '.join(chain['vulnerabilities'])}")
                lines.append(f"")
                if chain.get("poc_steps"):
                    lines.append("**Attack Steps:**")
                    for step in chain["poc_steps"]:
                        lines.append(f"  {step}")
                    lines.append(f"")

        # ═══════════════════════════════════════════════════════════════════
        # ATTACKER NEXT-STEP SUGGESTIONS (Advisory, NOT findings)
        # ═══════════════════════════════════════════════════════════════════
        if data.get("attacker_next_steps"):
            lines.append(f"## What an Attacker Would Likely Do Next")
            lines.append(f"")
            lines.append(f"> **Note:** These are advisory suggestions based on detected vulnerability chains.")
            lines.append(f"> They describe hypothetical attacker behavior, not confirmed exploitations.")
            lines.append(f"")

            for suggestion in data["attacker_next_steps"]:
                lines.append(f"### {suggestion.get('category', 'General').title()}")
                lines.append(f"")
                lines.append(f"*{suggestion.get('narrative', '')}*")
                lines.append(f"")
                if suggestion.get("steps"):
                    for step in suggestion["steps"]:
                        lines.append(f"- {step}")
                    lines.append(f"")
                if suggestion.get("risk_context"):
                    lines.append(f"**Context:** {suggestion['risk_context']}")
                    lines.append(f"")

        return "\n".join(lines)
    
    def _default_html_template(self, data: dict[str, Any]) -> str:
        """Generate default HTML template with charts."""
        charts = data.get("charts", {})
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Report - {data['target']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #1976d2; padding-bottom: 10px; }}
        h2 {{ color: #1976d2; margin-top: 30px; }}
        .critical {{ color: #d32f2f; }}
        .high {{ color: #f57c00; }}
        .medium {{ color: #fbc02d; }}
        .low {{ color: #388e3c; }}
        .finding {{ border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; background: #fafafa; }}
        .charts-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; margin: 20px 0; }}
        .chart-container {{ background: white; border: 1px solid #e0e0e0; border-radius: 8px; padding: 15px; }}
        .stats-box {{ display: flex; justify-content: space-around; padding: 20px; background: #f8f9fa; border-radius: 8px; margin: 20px 0; }}
        .stat {{ text-align: center; }}
        .stat-value {{ font-size: 32px; font-weight: bold; }}
        .stat-label {{ color: #666; font-size: 12px; }}
        .risk-score {{ text-align: center; margin: 20px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Assessment Report</h1>
        <p><strong>Target:</strong> {data['target']}</p>
        <p><strong>Date:</strong> {data['generated_at']}</p>
        <p><strong>Risk Score:</strong> <span style="font-size: 24px; font-weight: bold; color: {'#d32f2f' if data['stats'].get('risk_score', 0) >= 7 else '#f57c00' if data['stats'].get('risk_score', 0) >= 4 else '#388e3c'};">{data['stats'].get('risk_score', 0):.1f}/10</span></p>

        <h2>Executive Summary</h2>
        <p>{data['executive_summary']}</p>

        <h2>Findings Overview</h2>
        <div class="stats-box">
            <div class="stat">
                <div class="stat-value critical">{data['stats']['by_severity'].get('CRITICAL', 0)}</div>
                <div class="stat-label">CRITICAL</div>
            </div>
            <div class="stat">
                <div class="stat-value high">{data['stats']['by_severity'].get('HIGH', 0)}</div>
                <div class="stat-label">HIGH</div>
            </div>
            <div class="stat">
                <div class="stat-value medium">{data['stats']['by_severity'].get('MEDIUM', 0)}</div>
                <div class="stat-label">MEDIUM</div>
            </div>
            <div class="stat">
                <div class="stat-value low">{data['stats']['by_severity'].get('LOW', 0)}</div>
                <div class="stat-label">LOW</div>
            </div>
        </div>

        <div class="charts-grid">
            <div class="chart-container">
                {charts.get('severity_pie', '')}
            </div>
            <div class="chart-container">
                {charts.get('risk_gauge', '')}
            </div>
            <div class="chart-container">
                {charts.get('vuln_types', '')}
            </div>
            <div class="chart-container">
                {charts.get('owasp_coverage', '')}
            </div>
        </div>

        <h2>Detailed Findings</h2>
        {''.join(self._format_finding_html(f) for f in data['findings'])}
    </div>
</body>
</html>"""
    
    def _format_finding_html(self, finding: dict) -> str:
        """Format single finding as HTML."""
        sev = finding.get("severity", "INFO").lower()
        return f"""
    <div class="finding">
        <h3 class="{sev}">{finding.get('name', 'Unknown')}</h3>
        <p><strong>Severity:</strong> {finding.get('severity', 'N/A')}</p>
        <p><strong>Location:</strong> {finding.get('matched_at', 'N/A')}</p>
        <p>{finding.get('description', 'No description')}</p>
    </div>
"""
    
    def _calculate_duration(self, context: ScanContext) -> str:
        """Calculate scan duration."""
        started = context.metadata.get("started_at")
        completed = context.metadata.get("completed_at")
        
        if not started:
            return "N/A"
        
        try:
            start_dt = datetime.fromisoformat(started)
            end_dt = datetime.fromisoformat(completed) if completed else datetime.now()
            
            duration = end_dt - start_dt
            hours = duration.total_seconds() / 3600
            
            return f"{hours:.1f} hours"
        except Exception:
            return "N/A"
    
    def _calculate_risk_score(self, by_severity: dict) -> float:
        """Calculate overall risk score (0-10).

        Uses a diminishing returns model to prevent inflation:
        - Base score from highest severity finding (0-7)
        - Additional points for multiple findings (diminishing returns)
        - Maximum 10.0

        This prevents:
        - 50 LOW findings from exceeding 1 CRITICAL
        - Many duplicate findings from inflating the score
        """
        crit_count = len(by_severity.get("CRITICAL", []))
        high_count = len(by_severity.get("HIGH", []))
        med_count = len(by_severity.get("MEDIUM", []))
        low_count = len(by_severity.get("LOW", []))

        # Base score from highest severity present
        if crit_count > 0:
            base = 8.0  # CRITICAL starts at 8
        elif high_count > 0:
            base = 6.0  # HIGH starts at 6
        elif med_count > 0:
            base = 4.0  # MEDIUM starts at 4
        elif low_count > 0:
            base = 2.0  # LOW starts at 2
        else:
            return 0.0  # No findings

        # Diminishing returns for additional findings
        # Each additional finding adds less (log-like growth)
        import math
        additional = 0.0

        if crit_count > 1:
            additional += min(1.0, math.log(crit_count) * 0.5)
        if high_count > 0:
            # HIGH findings add 0.3-0.8 based on count (if CRITICAL is base)
            additional += min(0.8, math.log(high_count + 1) * 0.4)
        if med_count > 0:
            additional += min(0.5, math.log(med_count + 1) * 0.2)
        if low_count > 0:
            additional += min(0.2, math.log(low_count + 1) * 0.1)

        return min(10.0, round(base + additional, 1))
    
    @staticmethod
    def _severity_color(severity: str) -> str:
        """Get color for severity."""
        colors = {
            "CRITICAL": "#d32f2f",
            "HIGH": "#f57c00",
            "MEDIUM": "#fbc02d",
            "LOW": "#388e3c",
            "INFO": "#1976d2",
        }
        return colors.get(severity.upper(), "#666")
    
    @staticmethod
    def _format_datetime(dt_str: str) -> str:
        """Format datetime string."""
        try:
            dt = datetime.fromisoformat(dt_str)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return dt_str


class DataSanitizer:
    """Sanitizes sensitive data in reports."""
    
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        
        # Patterns to redact
        self.patterns = [
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL REDACTED]'),
            (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP REDACTED]'),
            (r'password["\s]*[:=]["\s]*[^\s,"]+', 'password: [REDACTED]'),
            (r'api[_-]?key["\s]*[:=]["\s]*[^\s,"]+', 'api_key: [REDACTED]'),
            (r'token["\s]*[:=]["\s]*[^\s,"]+', 'token: [REDACTED]'),
        ]
    
    def sanitize_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Sanitize a finding."""
        import re
        
        sanitized = finding.copy()
        
        # Sanitize string fields
        for field in ["description", "matched_at", "remediation"]:
            if field in sanitized and isinstance(sanitized[field], str):
                for pattern, replacement in self.patterns:
                    sanitized[field] = re.sub(pattern, replacement, sanitized[field], flags=re.IGNORECASE)
        
        # Sanitize evidence
        if "evidence" in sanitized:
            sanitized["evidence"] = [
                self._sanitize_string(e) if isinstance(e, str) else e
                for e in sanitized["evidence"]
            ]
        
        return sanitized
    
    def _sanitize_string(self, text: str) -> str:
        """Sanitize a string."""
        import re
        
        for pattern, replacement in self.patterns:
            text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
        
        return text
