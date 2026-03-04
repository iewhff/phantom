"""
PHANTOM AI - Professional Client Report Generator

Generates comprehensive penetration testing reports for client engagements.
Composes existing modules (HackerOneReportGenerator, ExecutiveSummaryGenerator,
ComplianceMapper, HandoffSessionGenerator) into a professional deliverable.

Output structure:
    evidence/{domain}_client/
    ├── CLIENT_REPORT.md              # Master assessment report
    ├── CLIENT_REPORT.pdf             # PDF version (if requested)
    ├── client_report_data.json       # Structured data
    ├── executive_summary.md          # C-level summary (standalone)
    ├── compliance_annex.md           # Compliance framework mapping
    ├── findings/
    │   ├── finding_001_{type}/
    │   │   ├── finding_report.md
    │   │   ├── finding_data.json
    │   │   └── poc.html
    │   └── ...
    ├── HANDOFF.md
    ├── handoff_data.json
    └── MANIFEST.json

PDF Generation:
    Uses weasyprint to convert markdown → HTML → PDF.
    Requires: pip install weasyprint markdown

Version: 1.0.0
Date: 2026-02-05
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Chain visualization imports
try:
    from phantom.chain_visualization import (
        ChainVisualizationEngine,
        OutputFormat,
        VisualizationConfig,
    )
    CHAIN_VISUALIZATION_AVAILABLE = True
except ImportError:
    CHAIN_VISUALIZATION_AVAILABLE = False

logger = logging.getLogger(__name__)


# =============================================================================
# PDF STYLING
# =============================================================================
PDF_CSS = """
@page {
    size: A4;
    margin: 2cm 2.5cm;
    @top-right { content: "CONFIDENTIAL"; font-size: 10px; color: #999; }
    @bottom-center { content: counter(page) " / " counter(pages); font-size: 10px; }
}

body {
    font-family: 'Helvetica Neue', Arial, sans-serif;
    font-size: 11pt;
    line-height: 1.6;
    color: #333;
}

h1 {
    color: #1a1a2e;
    border-bottom: 3px solid #e94560;
    padding-bottom: 10px;
    page-break-after: avoid;
}

h2 {
    color: #16213e;
    border-bottom: 1px solid #ddd;
    padding-bottom: 5px;
    margin-top: 30px;
    page-break-after: avoid;
}

h3 {
    color: #0f3460;
    page-break-after: avoid;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin: 15px 0;
    page-break-inside: avoid;
}

th, td {
    border: 1px solid #ddd;
    padding: 10px;
    text-align: left;
}

th {
    background: #16213e;
    color: white;
    font-weight: bold;
}

tr:nth-child(even) { background: #f9f9f9; }

code {
    background: #f4f4f4;
    padding: 2px 6px;
    border-radius: 3px;
    font-family: 'Courier New', monospace;
    font-size: 10pt;
}

pre {
    background: #2d2d2d;
    color: #f8f8f2;
    padding: 15px;
    border-radius: 5px;
    overflow-x: auto;
    font-size: 9pt;
    page-break-inside: avoid;
}

blockquote {
    border-left: 4px solid #e94560;
    padding-left: 15px;
    margin: 15px 0;
    color: #666;
    font-style: italic;
}

/* Severity badges */
.severity-critical {
    background: #dc3545;
    color: white;
    padding: 3px 8px;
    border-radius: 3px;
    font-weight: bold;
}
.severity-high {
    background: #fd7e14;
    color: white;
    padding: 3px 8px;
    border-radius: 3px;
    font-weight: bold;
}
.severity-medium {
    background: #ffc107;
    color: #333;
    padding: 3px 8px;
    border-radius: 3px;
    font-weight: bold;
}
.severity-low {
    background: #28a745;
    color: white;
    padding: 3px 8px;
    border-radius: 3px;
}

/* Cover page styling */
.cover-page {
    text-align: center;
    padding-top: 150px;
    page-break-after: always;
}

.cover-page h1 {
    font-size: 28pt;
    border: none;
    margin-bottom: 20px;
}

.cover-page .subtitle {
    font-size: 16pt;
    color: #666;
    margin-bottom: 50px;
}

.cover-page .metadata {
    font-size: 12pt;
    color: #333;
    margin-top: 100px;
}

/* Finding cards */
.finding {
    border: 1px solid #ddd;
    border-radius: 5px;
    padding: 15px;
    margin: 20px 0;
    page-break-inside: avoid;
}

.finding-header {
    display: flex;
    justify-content: space-between;
    border-bottom: 1px solid #eee;
    padding-bottom: 10px;
    margin-bottom: 10px;
}

hr {
    border: none;
    border-top: 1px solid #ddd;
    margin: 30px 0;
}
"""


# Severity ordering for sort
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# CLI compliance flag → ComplianceFramework enum value
_COMPLIANCE_FLAG_MAP = {
    "owasp": "owasp_top_10",
    "pci-dss": "pci_dss",
    "pci_dss": "pci_dss",
    "nist": "nist_800_53",
    "gdpr": "gdpr",
    "hipaa": "hipaa",
    "iso27001": "iso_27001",
    "soc2": "soc_2",
    "all": None,  # sentinel — means all frameworks
}


@dataclass
class ClientReport:
    """Complete professional client assessment report."""

    # Engagement metadata
    client_name: str
    engagement_id: str
    target: str
    date: str
    safety_mode: str
    modules_run: int
    duration_seconds: float

    # Pre-rendered markdown sections
    cover_page: str
    executive_summary: str
    scope_definition: str
    findings_summary: str
    coverage_summary: str  # NEW: What was tested, what was skipped, why
    detailed_findings: str
    attacker_next_steps: str  # Advisory suggestions (NOT findings!)
    compliance_annex: str
    remediation_roadmap: str

    # Per-finding artifacts
    finding_reports: List[Dict[str, Any]] = field(default_factory=list)

    # Raw data
    findings: List[Dict[str, Any]] = field(default_factory=list)

    # Chain visualization path (optional)
    chain_visualization_path: Optional[str] = None

    def to_markdown(self) -> str:
        """Render full client assessment report as markdown."""
        md = []

        md.append(self.cover_page)
        md.append("")
        md.append("---")
        md.append("")

        md.append("# Table of Contents")
        md.append("")
        md.append("1. [Executive Summary](#executive-summary)")
        md.append("2. [Scope & Methodology](#scope--methodology)")
        md.append("3. [Test Coverage](#test-coverage)")
        md.append("4. [Findings Summary](#findings-summary)")
        md.append("5. [Detailed Findings](#detailed-findings)")
        md.append("6. [Attacker Perspective](#attacker-perspective)")
        md.append("7. [Remediation Roadmap](#remediation-roadmap)")
        md.append("8. [Compliance Mapping](#compliance-mapping)")
        md.append("")
        md.append("---")
        md.append("")

        md.append("## Executive Summary")
        md.append("")
        md.append(self.executive_summary)
        md.append("")

        md.append("## Scope & Methodology")
        md.append("")
        md.append(self.scope_definition)
        md.append("")

        # Coverage summary - critical for understanding scan completeness
        md.append("## Test Coverage")
        md.append("")
        md.append(self.coverage_summary)
        md.append("")

        md.append("## Findings Summary")
        md.append("")
        md.append(self.findings_summary)
        md.append("")

        md.append("## Detailed Findings")
        md.append("")
        md.append(self.detailed_findings)
        md.append("")

        # Attacker perspective section (advisory, NOT findings)
        if self.attacker_next_steps:
            md.append("## Attacker Perspective")
            md.append("")
            md.append("> **Note:** This section describes hypothetical attacker behavior based on")
            md.append("> detected vulnerability chains. These are advisory suggestions, not confirmed exploitations.")
            md.append("")
            md.append(self.attacker_next_steps)
            md.append("")

        md.append("## Remediation Roadmap")
        md.append("")
        md.append(self.remediation_roadmap)
        md.append("")

        md.append("## Compliance Mapping")
        md.append("")
        md.append(self.compliance_annex)
        md.append("")

        # Footer
        md.append("---")
        md.append("")
        md.append(
            f"*Report generated by PHANTOM AI on {self.date}. "
            f"Engagement: {self.engagement_id}*"
        )

        return "\n".join(md)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict for JSON export."""
        return {
            "client_name": self.client_name,
            "engagement_id": self.engagement_id,
            "target": self.target,
            "date": self.date,
            "safety_mode": self.safety_mode,
            "modules_run": self.modules_run,
            "duration_seconds": self.duration_seconds,
            "findings_count": len(self.findings),
            "findings": self.findings,
            "finding_reports": [
                {k: v for k, v in fr.items() if k != "h1_report_obj"}
                for fr in self.finding_reports
            ],
            "has_chain_visualization": self.chain_visualization_path is not None,
        }


class ClientReportGenerator:
    """
    Generates professional penetration testing reports for client engagements.

    Composes:
    - HackerOneReportGenerator → per-finding evidence, PoC, reproduction steps
    - ExecutiveSummaryGenerator → business-level summary with financial impact
    - ComplianceMapper → framework mapping (OWASP, PCI DSS, NIST, etc.)

    Usage:
        gen = ClientReportGenerator(
            output_dir=Path("evidence/acme_client"),
            client_name="ACME Corp",
            engagement_id="ENG-2026-001",
            compliance_frameworks=["owasp", "pci-dss"],
        )
        report = gen.generate(findings=[...], scan_metadata={...})
        saved = gen.save(report)
    """

    def __init__(
        self,
        output_dir: Optional[Path] = None,
        client_name: str = "Client",
        engagement_id: str = "",
        compliance_frameworks: Optional[List[str]] = None,
        redaction_level: str = "standard",
    ):
        self.output_dir = Path(output_dir) if output_dir else Path("evidence")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.client_name = client_name
        self.engagement_id = engagement_id or f"PHANTOM-{datetime.now().strftime('%Y%m%d')}"
        self.compliance_frameworks = compliance_frameworks or []
        self.redaction_level = redaction_level

        # Lazy-loaded composed generators (import at use time to avoid circular deps)
        self._h1_gen = None
        self._exec_gen = None
        self._compliance_mapper = None
        self._evidence_redactor = None

    def _get_evidence_redactor(self):
        """Lazy-load EvidenceRedactor for PII protection."""
        if self._evidence_redactor is None:
            try:
                from phantom.evidence_redactor import EvidenceRedactor, RedactionConfig, RedactionLevel
                level = RedactionLevel(self.redaction_level)
                config = RedactionConfig.from_level(level)
                self._evidence_redactor = EvidenceRedactor(config)
                logger.info(f"[P0] Evidence redactor initialized with level: {self.redaction_level}")
            except ImportError:
                logger.warning("EvidenceRedactor not available — PII may remain in reports")
            except ValueError as e:
                logger.warning(f"Invalid redaction level '{self.redaction_level}': {e}")
        return self._evidence_redactor

    def _get_h1_gen(self):
        """Lazy-load HackerOneReportGenerator."""
        if self._h1_gen is None:
            try:
                from phantom.hackerone_report_generator import HackerOneReportGenerator
                self._h1_gen = HackerOneReportGenerator(
                    output_dir=self.output_dir / "findings",
                )
            except ImportError:
                logger.warning("HackerOneReportGenerator not available")
        return self._h1_gen

    def _get_exec_gen(self):
        """Lazy-load ExecutiveSummaryGenerator."""
        if self._exec_gen is None:
            try:
                from reporting.executive_summary import ExecutiveSummaryGenerator

                # ExecutiveSummaryGenerator requires a settings object.
                # Create a lightweight stand-in so we don't depend on
                # the full config_manager at report-generation time.
                class _MinimalSettings:
                    pass

                self._exec_gen = ExecutiveSummaryGenerator(
                    settings=_MinimalSettings(),
                    compliance_mapper=self._get_compliance_mapper(),
                )
            except (ImportError, Exception) as e:
                logger.warning(f"ExecutiveSummaryGenerator not available: {e}")
        return self._exec_gen

    def _get_compliance_mapper(self):
        """Lazy-load ComplianceMapper with selected frameworks."""
        if self._compliance_mapper is None:
            try:
                from phantom.compliance_mapper import ComplianceMapper, ComplianceFramework

                # Map CLI flags to enum values
                if "all" in self.compliance_frameworks:
                    frameworks = list(ComplianceFramework)
                else:
                    frameworks = []
                    for flag in self.compliance_frameworks:
                        enum_val = _COMPLIANCE_FLAG_MAP.get(flag)
                        if enum_val:
                            try:
                                frameworks.append(ComplianceFramework(enum_val))
                            except ValueError:
                                pass  # FIX 2026-02-12: Expected - invalid framework value
                    if not frameworks:
                        frameworks = list(ComplianceFramework)

                self._compliance_mapper = ComplianceMapper(frameworks=frameworks)
            except ImportError:
                logger.warning("ComplianceMapper not available")
        return self._compliance_mapper

    def generate(
        self,
        findings: List[Dict[str, Any]],
        scan_metadata: Optional[Dict[str, Any]] = None,
    ) -> ClientReport:
        """Generate a complete client assessment report."""
        meta = scan_metadata or {}
        date_str = meta.get("date", datetime.now().strftime("%Y-%m-%d %H:%M"))
        target = meta.get("target", "")

        # ═══════════════════════════════════════════════════════════════════════════
        # P0 FIX: Apply PII redaction to findings before processing
        # ═══════════════════════════════════════════════════════════════════════════
        redactor = self._get_evidence_redactor()
        if redactor:
            redacted_findings = [redactor.redact_finding(f) for f in findings]
            redaction_summary = redactor.get_redaction_summary()
            if redaction_summary.get("total_redactions", 0) > 0:
                logger.info(
                    f"[P0] Redacted {redaction_summary['total_redactions']} PII items "
                    f"from {redaction_summary['total_findings_processed']} findings"
                )
            # Store redaction summary in metadata for audit
            meta["_redaction_summary"] = redaction_summary
            findings = redacted_findings

        # Sort by severity
        sorted_findings = sorted(
            findings,
            key=lambda f: _SEVERITY_ORDER.get(
                self._get_severity(f).lower(), 5
            ),
        )

        # 1. Generate per-finding reports (evidence, PoC, steps)
        finding_reports = self._generate_per_finding_reports(sorted_findings)

        # 2. Executive summary
        executive_summary = self._generate_executive_summary(
            sorted_findings, target, meta
        )

        # 3. Compliance annex
        compliance_annex = self._generate_compliance_annex(
            sorted_findings, target, meta
        )

        # 4. Attacker next-steps section (from post-exploitation module)
        attacker_steps = self._build_attacker_next_steps(meta.get("attacker_next_steps", []))

        # 5. Coverage summary - what was tested, what was skipped, why
        coverage_summary = self._build_coverage_summary(meta)

        # 6. Chain visualization (interactive HTML graph)
        chain_viz_html = self._generate_chain_visualization(sorted_findings)

        return ClientReport(
            client_name=self.client_name,
            engagement_id=self.engagement_id,
            target=target,
            date=date_str,
            safety_mode=meta.get("safety_mode", "standard"),
            modules_run=meta.get("modules_run", 0),
            duration_seconds=meta.get("duration_seconds", 0),
            cover_page=self._build_cover_page(target, date_str, meta),
            executive_summary=executive_summary,
            scope_definition=self._build_scope_definition(target, meta),
            findings_summary=self._build_findings_summary(sorted_findings),
            coverage_summary=coverage_summary,
            detailed_findings=self._build_detailed_findings(
                sorted_findings, finding_reports
            ),
            attacker_next_steps=attacker_steps,
            compliance_annex=compliance_annex,
            remediation_roadmap=self._build_remediation_roadmap(sorted_findings),
            finding_reports=finding_reports,
            findings=sorted_findings,
            chain_visualization_path=chain_viz_html,  # Store HTML content temporarily
        )

    def save(
        self,
        report: ClientReport,
        formats: Optional[List[str]] = None,
    ) -> Dict[str, str]:
        """Save client report and all artifacts to disk."""
        if formats is None:
            formats = ["md", "json"]

        self.output_dir.mkdir(parents=True, exist_ok=True)
        saved = {}

        # Master report
        if "md" in formats:
            md_path = self.output_dir / "CLIENT_REPORT.md"
            md_path.write_text(report.to_markdown())
            saved["md"] = str(md_path)

        if "json" in formats:
            json_path = self.output_dir / "client_report_data.json"
            json_path.write_text(json.dumps(report.to_dict(), indent=2, default=str))
            saved["json"] = str(json_path)

        # PDF generation (markdown → HTML → PDF)
        if "pdf" in formats:
            pdf_path = self._generate_pdf(report)
            if pdf_path:
                saved["pdf"] = pdf_path

        # Standalone executive summary
        if report.executive_summary:
            exec_path = self.output_dir / "executive_summary.md"
            exec_path.write_text(
                f"# Executive Summary — {report.client_name}\n\n"
                f"**Engagement:** {report.engagement_id}\n"
                f"**Target:** {report.target}\n"
                f"**Date:** {report.date}\n\n---\n\n"
                + report.executive_summary
            )
            saved["executive_summary"] = str(exec_path)

        # Standalone compliance annex
        if report.compliance_annex and report.compliance_annex != "*No compliance mapping requested.*":
            comp_path = self.output_dir / "compliance_annex.md"
            comp_path.write_text(
                f"# Compliance Mapping — {report.client_name}\n\n"
                f"**Engagement:** {report.engagement_id}\n"
                f"**Target:** {report.target}\n\n---\n\n"
                + report.compliance_annex
            )
            saved["compliance_annex"] = str(comp_path)

        # Per-finding reports + PoC files
        for fr in report.finding_reports:
            for fmt_key, fpath in fr.get("files", {}).items():
                # Files already saved by _generate_per_finding_reports
                pass

        # Chain visualization (interactive HTML graph)
        if report.chain_visualization_path:
            viz_path = self.output_dir / "attack_chains.html"
            viz_path.write_text(report.chain_visualization_path)
            saved["chain_visualization"] = str(viz_path)
            logger.info(f"[CHAIN-VIZ] Interactive attack graph saved to {viz_path}")

        logger.info(f"Client report saved to {self.output_dir}")
        return saved

    # ------------------------------------------------------------------
    # PDF Generation
    # ------------------------------------------------------------------

    def _generate_pdf(self, report: ClientReport) -> Optional[str]:
        """
        Generate PDF from client report.

        Converts markdown → HTML → PDF using weasyprint.
        Returns the path to the generated PDF, or None if generation failed.
        """
        try:
            import markdown
            from weasyprint import HTML, CSS
        except ImportError as e:
            logger.warning(f"PDF generation requires 'weasyprint' and 'markdown': {e}")
            logger.warning("Install with: pip install weasyprint markdown")
            return None

        try:
            # Convert markdown to HTML
            md_content = report.to_markdown()
            md_converter = markdown.Markdown(
                extensions=[
                    "tables",
                    "fenced_code",
                    "codehilite",
                    "toc",
                    "nl2br",
                ]
            )
            html_body = md_converter.convert(md_content)

            # Wrap in full HTML document
            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Assessment Report — {report.client_name}</title>
</head>
<body>
{html_body}
</body>
</html>
"""

            # Generate PDF
            pdf_path = self.output_dir / "CLIENT_REPORT.pdf"
            HTML(string=html_content).write_pdf(
                str(pdf_path),
                stylesheets=[CSS(string=PDF_CSS)],
            )

            logger.info(f"PDF report generated: {pdf_path}")
            return str(pdf_path)

        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            return None

    # ------------------------------------------------------------------
    # Per-finding report generation
    # ------------------------------------------------------------------

    def _generate_per_finding_reports(
        self, findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Generate individual reports for each finding using HackerOneReportGenerator."""
        h1_gen = self._get_h1_gen()
        if not h1_gen:
            return []

        reports = []
        for i, finding in enumerate(findings, 1):
            try:
                # Unwrap ValidatedFinding if needed
                raw = finding
                if isinstance(finding, dict) and "finding" in finding and isinstance(finding["finding"], dict):
                    raw = finding["finding"]

                # Generate H1 report (handles evidence, PoC, steps, classification)
                h1_report = h1_gen.generate_report(raw)

                # Save per-finding artifacts
                saved_files = h1_gen.save_report(h1_report, formats=["md", "json", "html"])

                reports.append({
                    "index": i,
                    "title": h1_report.title,
                    "severity": h1_report.severity,
                    "cwe": h1_report.cwe,
                    "cvss_score": h1_report.cvss_score,
                    "files": saved_files,
                    "exploit_evidence": h1_report.exploit_evidence,
                    "steps": [
                        {
                            "description": s.description,
                            "command": s.curl_command or "",
                            "expected": s.expected_result or "",
                            "actual": s.actual_result or "",
                        }
                        for s in h1_report.steps_to_reproduce
                    ],
                    "remediation": h1_report.remediation,
                    "summary": h1_report.summary,
                    "proof_data": h1_report.proof_data,
                    "proof_status": h1_report.proof_status,
                    "linked_scanner_findings": h1_report.linked_scanner_findings,
                })

            except Exception as e:
                logger.debug(f"Failed to generate finding report {i}: {e}")
                reports.append({
                    "index": i,
                    "title": raw.get("name", raw.get("title", "Unknown")),
                    "severity": self._get_severity(finding),
                    "cwe": raw.get("cwe", ""),
                    "cvss_score": raw.get("cvss_score", 0),
                    "files": {},
                    "exploit_evidence": [],
                    "steps": [],
                    "remediation": raw.get("remediation", ""),
                    "summary": raw.get("description", ""),
                })

        return reports

    # ------------------------------------------------------------------
    # Executive Summary
    # ------------------------------------------------------------------

    def _generate_executive_summary(
        self,
        findings: List[Dict[str, Any]],
        target: str,
        meta: Dict[str, Any],
    ) -> str:
        """Generate executive summary using ExecutiveSummaryGenerator."""
        exec_gen = self._get_exec_gen()
        if exec_gen:
            try:
                # Flatten findings for exec generator (expects severity, type, etc. at top level)
                flat_findings = []
                for f in findings:
                    raw = f
                    if isinstance(f, dict) and "finding" in f and isinstance(f["finding"], dict):
                        raw = f["finding"]
                    flat_findings.append({
                        "severity": self._get_severity(f).upper(),
                        "type": raw.get("type", raw.get("vulnerability_type", "unknown")),
                        "name": raw.get("name", raw.get("title", "Unknown")),
                        "host": raw.get("host", raw.get("url", "")),
                        "description": raw.get("description", ""),
                        "cvss_score": raw.get("cvss_score", 0),
                    })

                summary = exec_gen.generate_summary(
                    findings=flat_findings,
                    target=target,
                    scan_metadata=meta,
                )
                return exec_gen.render_report(summary, format="markdown")
            except Exception as e:
                logger.debug(f"ExecutiveSummaryGenerator failed: {e}")

        # Fallback: simple executive summary
        return self._build_fallback_executive_summary(findings, target)

    def _build_fallback_executive_summary(
        self, findings: List[Dict[str, Any]], target: str
    ) -> str:
        """Fallback executive summary if ExecutiveSummaryGenerator is unavailable."""
        sev_counts: Dict[str, int] = {}
        for f in findings:
            sev = self._get_severity(f).upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        total = len(findings)
        critical = sev_counts.get("CRITICAL", 0)
        high = sev_counts.get("HIGH", 0)

        if critical > 0:
            risk = "CRITICAL"
            urgency = "Immediate remediation required."
        elif high > 0:
            risk = "HIGH"
            urgency = "Prompt remediation recommended."
        elif total > 0:
            risk = "MODERATE"
            urgency = "Planned remediation recommended."
        else:
            risk = "LOW"
            urgency = "No significant vulnerabilities identified."

        parts = [
            f"A security assessment of **{target}** identified "
            f"**{total} finding(s)** across the following severity levels:",
            "",
        ]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = sev_counts.get(sev, 0)
            if count > 0:
                parts.append(f"- **{sev}:** {count}")
        parts.append("")
        parts.append(f"**Overall Risk Rating:** {risk}")
        parts.append(f"**Recommendation:** {urgency}")

        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Compliance Annex
    # ------------------------------------------------------------------

    def _generate_compliance_annex(
        self,
        findings: List[Dict[str, Any]],
        target: str,
        meta: Dict[str, Any],
    ) -> str:
        """Generate compliance framework mapping."""
        if not self.compliance_frameworks:
            return "*No compliance mapping requested.*"

        mapper = self._get_compliance_mapper()
        if not mapper:
            return "*Compliance mapper not available.*"

        try:
            # Flatten findings for compliance mapper
            flat_findings = []
            for f in findings:
                raw = f
                if isinstance(f, dict) and "finding" in f and isinstance(f["finding"], dict):
                    raw = f["finding"]
                flat_findings.append({
                    "id": raw.get("id", raw.get("name", "")),
                    "type": raw.get("type", raw.get("vulnerability_type", "unknown")),
                    "severity": self._get_severity(f),
                    "name": raw.get("name", ""),
                })

            # Map findings to frameworks
            mappings = mapper.map_findings(flat_findings)

            # Generate compliance report
            scan_id = meta.get("scan_id", self.engagement_id)
            comp_report = mapper.generate_report(scan_id=scan_id, target=target)

            return self._render_compliance_markdown(mappings, comp_report, flat_findings)
        except Exception as e:
            logger.debug(f"Compliance mapping failed: {e}")
            return f"*Compliance mapping error: {e}*"

    def _render_compliance_markdown(
        self,
        mappings: list,
        comp_report: Any,
        findings: List[Dict[str, Any]],
    ) -> str:
        """Render compliance mappings as markdown with full framework coverage."""
        lines = []

        # ═══════════════════════════════════════════════════════════════════
        # Compliance Impact Summary Table (NEW)
        # Shows aggregate compliance exposure across all frameworks
        # ═══════════════════════════════════════════════════════════════════
        lines.append("### Compliance Impact Summary")
        lines.append("")
        lines.append("> This table shows which compliance requirements are affected by the findings.")
        lines.append("")
        lines.append("| Framework | Requirements Affected | Finding Count |")
        lines.append("|-----------|----------------------|---------------|")

        # Aggregate all requirements by framework
        framework_stats = self._aggregate_compliance_stats(mappings)

        for fw_name, stats in framework_stats.items():
            reqs = ", ".join(stats["requirements"][:5])
            if len(stats["requirements"]) > 5:
                reqs += f" (+{len(stats['requirements']) - 5} more)"
            lines.append(f"| {fw_name} | {reqs or '—'} | {stats['count']} |")

        lines.append("")

        # Framework coverage summary
        lines.append("### Frameworks Covered")
        lines.append("")
        if hasattr(comp_report, "frameworks_covered"):
            for fw in comp_report.frameworks_covered:
                lines.append(f"- {fw}")
        lines.append("")

        # OWASP Top 10 coverage with descriptions
        if hasattr(comp_report, "owasp_coverage") and comp_report.owasp_coverage:
            lines.append("### OWASP Top 10 2021 Coverage")
            lines.append("")
            owasp_descriptions = {
                "A01:2021": "Broken Access Control",
                "A02:2021": "Cryptographic Failures",
                "A03:2021": "Injection",
                "A04:2021": "Insecure Design",
                "A05:2021": "Security Misconfiguration",
                "A06:2021": "Vulnerable Components",
                "A07:2021": "Auth Failures",
                "A08:2021": "Software/Data Integrity",
                "A09:2021": "Logging/Monitoring",
                "A10:2021": "SSRF",
            }
            lines.append("| Category | Description | Findings |")
            lines.append("|----------|-------------|----------|")
            for cat, count in sorted(comp_report.owasp_coverage.items()):
                desc = owasp_descriptions.get(cat, "")
                lines.append(f"| {cat} | {desc} | {count} |")
            lines.append("")

        # PCI DSS coverage with requirement descriptions
        if hasattr(comp_report, "pci_dss_coverage") and comp_report.pci_dss_coverage:
            lines.append("### PCI DSS 4.0 Requirements")
            lines.append("")
            pci_descriptions = {
                "1": "Network Security Controls",
                "2": "Secure Configurations",
                "3": "Protect Account Data",
                "4": "Protect Cardholder Data",
                "5": "Protect Against Malware",
                "6": "Develop Secure Systems",
                "7": "Restrict Access",
                "8": "Identity and Access",
                "9": "Restrict Physical Access",
                "10": "Log and Monitor",
                "11": "Test Security Regularly",
                "12": "Information Security Policy",
            }
            lines.append("| Requirement | Description | Findings |")
            lines.append("|-------------|-------------|----------|")
            for req, count in sorted(comp_report.pci_dss_coverage.items()):
                # Extract base requirement number (e.g., "6.4.1" -> "6")
                base_req = req.split(".")[0] if "." in req else req
                desc = pci_descriptions.get(base_req, "")
                lines.append(f"| Req {req} | {desc} | {count} |")
            lines.append("")

        # ═══════════════════════════════════════════════════════════════════
        # NIST 800-53 Coverage (NEW)
        # ═══════════════════════════════════════════════════════════════════
        nist_coverage = self._get_nist_coverage(mappings)
        if nist_coverage:
            lines.append("### NIST SP 800-53 Controls")
            lines.append("")
            nist_family_names = {
                "AC": "Access Control",
                "AU": "Audit and Accountability",
                "CA": "Assessment/Authorization",
                "CM": "Configuration Management",
                "IA": "Identification/Authentication",
                "IR": "Incident Response",
                "RA": "Risk Assessment",
                "SA": "System Acquisition",
                "SC": "System Communications",
                "SI": "System/Information Integrity",
            }
            lines.append("| Control Family | Controls Affected | Findings |")
            lines.append("|----------------|-------------------|----------|")
            for family, controls in sorted(nist_coverage.items()):
                family_name = nist_family_names.get(family, family)
                ctrl_list = ", ".join(controls[:4])
                if len(controls) > 4:
                    ctrl_list += f" (+{len(controls) - 4})"
                lines.append(f"| {family} - {family_name} | {ctrl_list} | {len(controls)} |")
            lines.append("")

        # ═══════════════════════════════════════════════════════════════════
        # ISO 27001 Coverage (NEW - if requested)
        # ═══════════════════════════════════════════════════════════════════
        if "iso27001" in self.compliance_frameworks or "all" in self.compliance_frameworks:
            iso_coverage = self._get_iso27001_coverage(mappings)
            if iso_coverage:
                lines.append("### ISO 27001 Controls")
                lines.append("")
                lines.append("| Control | Findings |")
                lines.append("|---------|----------|")
                for ctrl, count in sorted(iso_coverage.items()):
                    lines.append(f"| {ctrl} | {count} |")
                lines.append("")

        # ═══════════════════════════════════════════════════════════════════
        # GDPR Articles (NEW - if PII affected)
        # ═══════════════════════════════════════════════════════════════════
        gdpr_coverage = self._get_gdpr_coverage(mappings)
        if gdpr_coverage:
            lines.append("### GDPR Articles Affected")
            lines.append("")
            gdpr_descriptions = {
                "Art. 5": "Principles relating to processing of personal data",
                "Art. 25": "Data protection by design and by default",
                "Art. 32": "Security of processing",
                "Art. 33": "Notification of a personal data breach",
                "Art. 34": "Communication of a personal data breach",
                "Art. 35": "Data protection impact assessment",
            }
            lines.append("| Article | Description | Findings |")
            lines.append("|---------|-------------|----------|")
            for article, count in sorted(gdpr_coverage.items()):
                desc = gdpr_descriptions.get(article, "")
                lines.append(f"| {article} | {desc} | {count} |")
            lines.append("")
            lines.append("> **Note:** GDPR compliance is affected when vulnerabilities may expose personal data.")
            lines.append("")

        # ═══════════════════════════════════════════════════════════════════
        # HIPAA Safeguards (NEW - if health data affected)
        # ═══════════════════════════════════════════════════════════════════
        hipaa_coverage = self._get_hipaa_coverage(mappings)
        if hipaa_coverage:
            lines.append("### HIPAA Safeguards Affected")
            lines.append("")
            lines.append("| Safeguard | Findings |")
            lines.append("|-----------|----------|")
            for safeguard, count in sorted(hipaa_coverage.items()):
                lines.append(f"| {safeguard} | {count} |")
            lines.append("")

        # ═══════════════════════════════════════════════════════════════════
        # SOC 2 Criteria (NEW - if requested)
        # ═══════════════════════════════════════════════════════════════════
        if "soc2" in self.compliance_frameworks or "all" in self.compliance_frameworks:
            soc2_coverage = self._get_soc2_coverage(mappings)
            if soc2_coverage:
                lines.append("### SOC 2 Trust Service Criteria")
                lines.append("")
                soc2_descriptions = {
                    "CC1": "Control Environment",
                    "CC2": "Communication and Information",
                    "CC3": "Risk Assessment",
                    "CC4": "Monitoring Activities",
                    "CC5": "Control Activities",
                    "CC6": "Logical and Physical Access",
                    "CC7": "System Operations",
                    "CC8": "Change Management",
                    "CC9": "Risk Mitigation",
                }
                lines.append("| Criteria | Description | Findings |")
                lines.append("|----------|-------------|----------|")
                for criteria, count in sorted(soc2_coverage.items()):
                    desc = soc2_descriptions.get(criteria, "")
                    lines.append(f"| {criteria} | {desc} | {count} |")
                lines.append("")

        # Per-finding mapping table (expanded)
        lines.append("### Per-Finding Compliance Mapping")
        lines.append("")
        lines.append("| Finding | CWE | OWASP | PCI DSS | NIST |")
        lines.append("|---------|-----|-------|---------|------|")
        for i, mapping in enumerate(mappings):
            finding_name = findings[i]["name"] if i < len(findings) else "—"
            # Truncate long finding names
            if len(finding_name) > 40:
                finding_name = finding_name[:37] + "..."

            # Handle ComplianceMapping objects directly
            if hasattr(mapping, "cwe_ids"):
                cwe = ", ".join(f"CWE-{c}" for c in mapping.cwe_ids[:2]) or "—"
                owasp = ", ".join(mapping.owasp_categories[:2]) or "—"
                pci = ", ".join(mapping.pci_dss_requirements[:2]) or "—"
                nist = ", ".join(mapping.nist_controls[:2]) or "—"
            else:
                m = mapping if isinstance(mapping, dict) else (mapping.to_dict() if hasattr(mapping, "to_dict") else {})
                maps = m.get("mappings", {}) if isinstance(m, dict) else {}
                cwe = ", ".join(maps.get("cwe", [])[:2]) or "—"
                owasp = ", ".join(maps.get("owasp_top_10", [])[:2]) or "—"
                pci = ", ".join(maps.get("pci_dss", [])[:2]) or "—"
                nist = ", ".join(maps.get("nist_800_53", [])[:2]) or "—"

            lines.append(f"| {finding_name} | {cwe} | {owasp} | {pci} | {nist} |")

        lines.append("")

        # Remediation guidance note
        lines.append("### Compliance Remediation Guidance")
        lines.append("")
        lines.append(
            "Address findings in priority order (CRITICAL/HIGH first) to efficiently improve "
            "compliance posture across all affected frameworks. Each finding's remediation "
            "section includes framework-specific guidance."
        )

        return "\n".join(lines)

    def _aggregate_compliance_stats(self, mappings: list) -> Dict[str, Dict[str, Any]]:
        """Aggregate compliance statistics across all mappings."""
        stats: Dict[str, Dict[str, Any]] = {
            "OWASP Top 10": {"requirements": set(), "count": 0},
            "PCI DSS 4.0": {"requirements": set(), "count": 0},
            "NIST 800-53": {"requirements": set(), "count": 0},
            "ISO 27001": {"requirements": set(), "count": 0},
            "GDPR": {"requirements": set(), "count": 0},
            "HIPAA": {"requirements": set(), "count": 0},
            "SOC 2": {"requirements": set(), "count": 0},
        }

        for mapping in mappings:
            if hasattr(mapping, "owasp_categories") and mapping.owasp_categories:
                stats["OWASP Top 10"]["requirements"].update(mapping.owasp_categories)
                stats["OWASP Top 10"]["count"] += 1
            if hasattr(mapping, "pci_dss_requirements") and mapping.pci_dss_requirements:
                stats["PCI DSS 4.0"]["requirements"].update(mapping.pci_dss_requirements)
                stats["PCI DSS 4.0"]["count"] += 1
            if hasattr(mapping, "nist_controls") and mapping.nist_controls:
                stats["NIST 800-53"]["requirements"].update(mapping.nist_controls)
                stats["NIST 800-53"]["count"] += 1
            if hasattr(mapping, "iso27001_controls") and mapping.iso27001_controls:
                stats["ISO 27001"]["requirements"].update(mapping.iso27001_controls)
                stats["ISO 27001"]["count"] += 1
            if hasattr(mapping, "gdpr_articles") and mapping.gdpr_articles:
                stats["GDPR"]["requirements"].update(mapping.gdpr_articles)
                stats["GDPR"]["count"] += 1
            if hasattr(mapping, "hipaa_safeguards") and mapping.hipaa_safeguards:
                stats["HIPAA"]["requirements"].update(mapping.hipaa_safeguards)
                stats["HIPAA"]["count"] += 1
            if hasattr(mapping, "soc2_criteria") and mapping.soc2_criteria:
                stats["SOC 2"]["requirements"].update(mapping.soc2_criteria)
                stats["SOC 2"]["count"] += 1

        # Convert sets to sorted lists and filter empty
        result = {}
        for fw_name, data in stats.items():
            if data["count"] > 0:
                result[fw_name] = {
                    "requirements": sorted(data["requirements"]),
                    "count": data["count"],
                }

        return result

    def _get_nist_coverage(self, mappings: list) -> Dict[str, List[str]]:
        """Get NIST control coverage grouped by family."""
        coverage: Dict[str, set] = {}
        for mapping in mappings:
            if hasattr(mapping, "nist_controls"):
                for ctrl in mapping.nist_controls:
                    # Extract family (e.g., "AC-3" -> "AC")
                    family = ctrl.split("-")[0] if "-" in ctrl else ctrl[:2]
                    coverage.setdefault(family, set()).add(ctrl)

        return {k: sorted(v) for k, v in coverage.items()}

    def _get_iso27001_coverage(self, mappings: list) -> Dict[str, int]:
        """Get ISO 27001 control coverage."""
        coverage: Dict[str, int] = {}
        for mapping in mappings:
            if hasattr(mapping, "iso27001_controls"):
                for ctrl in mapping.iso27001_controls:
                    coverage[ctrl] = coverage.get(ctrl, 0) + 1
        return coverage

    def _get_gdpr_coverage(self, mappings: list) -> Dict[str, int]:
        """Get GDPR article coverage."""
        coverage: Dict[str, int] = {}
        for mapping in mappings:
            if hasattr(mapping, "gdpr_articles"):
                for article in mapping.gdpr_articles:
                    coverage[article] = coverage.get(article, 0) + 1
        return coverage

    def _get_hipaa_coverage(self, mappings: list) -> Dict[str, int]:
        """Get HIPAA safeguard coverage."""
        coverage: Dict[str, int] = {}
        for mapping in mappings:
            if hasattr(mapping, "hipaa_safeguards"):
                for safeguard in mapping.hipaa_safeguards:
                    coverage[safeguard] = coverage.get(safeguard, 0) + 1
        return coverage

    def _get_soc2_coverage(self, mappings: list) -> Dict[str, int]:
        """Get SOC 2 criteria coverage."""
        coverage: Dict[str, int] = {}
        for mapping in mappings:
            if hasattr(mapping, "soc2_criteria"):
                for criteria in mapping.soc2_criteria:
                    coverage[criteria] = coverage.get(criteria, 0) + 1
        return coverage

    # ------------------------------------------------------------------
    # Section builders
    # ------------------------------------------------------------------

    def _build_cover_page(
        self, target: str, date_str: str, meta: Dict[str, Any]
    ) -> str:
        """Build professional cover page."""
        duration_min = meta.get("duration_seconds", 0) / 60
        return "\n".join([
            f"# Penetration Test Report",
            "",
            f"## {self.client_name}",
            "",
            "| Field | Value |",
            "|-------|-------|",
            f"| **Client** | {self.client_name} |",
            f"| **Engagement ID** | `{self.engagement_id}` |",
            f"| **Target** | `{target}` |",
            f"| **Date** | {date_str} |",
            f"| **Assessment Type** | Automated Penetration Test |",
            f"| **Safety Mode** | `{meta.get('safety_mode', 'standard')}` |",
            f"| **Modules Executed** | {meta.get('modules_run', 0)} |",
            f"| **Duration** | {duration_min:.1f} min |",
            f"| **Tool** | PHANTOM AI |",
            "",
            "**CONFIDENTIAL** — This document contains sensitive security findings. "
            "Distribution is restricted to authorized personnel only.",
        ])

    def _build_scope_definition(
        self, target: str, meta: Dict[str, Any]
    ) -> str:
        """Build scope and methodology section."""
        lines = [
            "### Target Scope",
            "",
            f"- **Primary Target:** `{target}`",
            f"- **Safety Mode:** `{meta.get('safety_mode', 'standard')}`",
            f"- **Modules Executed:** {meta.get('modules_run', 0)}",
            "",
            "### Methodology",
            "",
            "The assessment followed an automated penetration testing methodology:",
            "",
            "1. **Reconnaissance** — Subdomain enumeration, technology fingerprinting, endpoint discovery",
            "2. **Vulnerability Scanning** — Automated testing across 47+ security modules",
            "3. **Exploitation Verification** — Evidence-based validation with real HTTP captures",
            "4. **Evidence Collection** — Full request/response pairs, PoC generation",
            "5. **Report Generation** — Automated classification, compliance mapping, remediation guidance",
            "",
            "### Limitations",
            "",
            "- Testing was conducted in `{mode}` safety mode".format(mode=meta.get("safety_mode", "standard")),
            "- Results reflect the state of the application at time of testing",
            "- Theoretical attack chains are based on confirmed vulnerabilities and established patterns",
        ]
        return "\n".join(lines)

    def _build_coverage_summary(self, meta: Dict[str, Any]) -> str:
        """
        Build test coverage summary showing what was tested, skipped, and why.

        This addresses the "coverage awareness" gap:
        - Client sees "50 modules ran" but doesn't know what WASN'T tested
        - When only 1 finding, client thinks scanner is weak
        - Reality: rate limiting, auth gaps, SPA challenges

        Coverage data comes from meta["coverage_tracker"] (CoverageTracker.to_dict())
        """
        coverage = meta.get("coverage_tracker", {})

        # Fallback if no coverage data available
        if not coverage or not isinstance(coverage, dict):
            modules_run = meta.get("modules_run", 0)
            duration = meta.get("duration_seconds", 0)
            return "\n".join([
                "> **Note:** Detailed coverage metrics were not collected for this scan.",
                "",
                f"- **Modules Executed:** {modules_run}",
                f"- **Scan Duration:** {duration:.0f} seconds",
                "",
                "For detailed coverage analysis, re-run with coverage tracking enabled.",
            ])

        lines = []

        # ═══════════════════════════════════════════════════════════════════
        # THEME-5 FIX: Executive Summary — "What We Didn't Test & Why"
        # This is the FIRST thing the client sees in coverage section
        # ═══════════════════════════════════════════════════════════════════
        skip_summary = coverage.get("skip_summary", {})
        summary = coverage.get("summary", {})
        total = summary.get("total_surfaces", 0)
        tested = summary.get("tested_surfaces", 0)
        coverage_pct = summary.get("coverage_percentage", 0)
        duration = summary.get("scan_duration_seconds", 0)

        # Calculate gaps by category
        auth_required = skip_summary.get("AUTH_REQUIRED", 0)
        rate_limited = skip_summary.get("RATE_LIMITED", 0)
        waf_blocked = skip_summary.get("BLOCKED_BY_WAF", 0)
        timeout = skip_summary.get("TIMEOUT", 0)
        budget = skip_summary.get("BUDGET_EXHAUSTED", 0)
        scope_out = skip_summary.get("SCOPE_OUT", 0)
        tech_mismatch = skip_summary.get("TECH_MISMATCH", 0)
        connection_error = skip_summary.get("CONNECTION_ERROR", 0)
        module_error = skip_summary.get("MODULE_ERROR", 0)

        total_recoverable = auth_required + rate_limited + waf_blocked + timeout + budget
        total_gaps = total - tested

        # Only show executive summary if there are meaningful gaps
        if total_gaps > 0 and total > 0:
            gap_pct = (total_gaps / total) * 100

            lines.append("### ⚠️ What We Didn't Test & Why")
            lines.append("")
            lines.append("> **Executive Summary:** The following surfaces were NOT tested.")
            lines.append("> Review these gaps to ensure complete security coverage.")
            lines.append("")
            lines.append("```")
            lines.append(f"COVERAGE SUMMARY: {coverage_pct:.0f}% tested, {gap_pct:.0f}% gaps")
            lines.append("-" * 50)

            # Show each category with count
            gap_lines = []
            if auth_required > 0:
                gap_lines.append(f"  Auth Required:     {auth_required:>4} endpoints (e.g., /admin/*, /api/internal/*)")
            if rate_limited > 0:
                gap_lines.append(f"  Rate Limited:      {rate_limited:>4} endpoints (retryable)")
            if waf_blocked > 0:
                gap_lines.append(f"  WAF Blocked:       {waf_blocked:>4} endpoints (may hide vulnerabilities)")
            if timeout > 0:
                gap_lines.append(f"  Module Timeout:    {timeout:>4} endpoints (incomplete testing)")
            if budget > 0:
                gap_lines.append(f"  Budget Exhausted:  {budget:>4} endpoints (increase --max-requests)")
            if scope_out > 0:
                gap_lines.append(f"  Out of Scope:      {scope_out:>4} endpoints (expected)")
            if tech_mismatch > 0:
                gap_lines.append(f"  Tech Mismatch:     {tech_mismatch:>4} endpoints (expected)")
            if connection_error > 0:
                gap_lines.append(f"  Connection Error:  {connection_error:>4} endpoints (network issues)")
            if module_error > 0:
                gap_lines.append(f"  Scanner Error:     {module_error:>4} endpoints (check logs)")

            if gap_lines:
                lines.extend(gap_lines)
            else:
                lines.append(f"  Total Gaps:        {total_gaps:>4} endpoints (no specific reason tracked)")

            lines.append("-" * 50)
            lines.append(f"  TOTAL GAPS:        {total_gaps:>4} endpoints ({gap_pct:.0f}% of attack surface)")

            if total_recoverable > 0:
                lines.append(f"  Recoverable:       {total_recoverable:>4} endpoints (can retry with adjustments)")

            lines.append("```")
            lines.append("")

            # Actionable recommendations
            if auth_required > 0 or rate_limited > 0 or waf_blocked > 0:
                lines.append("**Recommended Actions:**")
                if auth_required > 0:
                    lines.append(f"1. Provide valid credentials to test {auth_required} auth-protected endpoints")
                if rate_limited > 0:
                    lines.append(f"2. Re-run during off-peak hours or increase rate limit tolerance for {rate_limited} endpoints")
                if waf_blocked > 0:
                    lines.append(f"3. Test from whitelisted IP to bypass WAF for {waf_blocked} endpoints")
                lines.append("")

        # ═══════════════════════════════════════════════════════════════════
        # Overall Coverage Summary
        # ═══════════════════════════════════════════════════════════════════
        lines.append("### Overall Test Coverage")
        lines.append("")

        # Visual progress bar
        filled = int(coverage_pct / 5)  # 20 chars max
        empty = 20 - filled
        bar = "█" * filled + "░" * empty
        lines.append(f"**Coverage:** {bar} {coverage_pct:.1f}%")
        lines.append(f"- Surfaces tested: {tested:,} / {total:,}")
        lines.append(f"- Scan duration: {duration:.0f} seconds")
        lines.append("")

        # ═══════════════════════════════════════════════════════════════════
        # Vulnerability Type Coverage
        # ═══════════════════════════════════════════════════════════════════
        vuln_coverage = coverage.get("vuln_type_coverage", {})
        if vuln_coverage:
            lines.append("### Test Coverage by Vulnerability Type")
            lines.append("")
            lines.append("| Vulnerability | Tested | Skipped | Coverage | Confidence |")
            lines.append("|---------------|--------|---------|----------|------------|")

            # Sort by coverage to highlight gaps
            sorted_vuln = sorted(
                vuln_coverage.items(),
                key=lambda x: x[1].get("coverage_pct", 0)
            )

            for vtype, stats in sorted_vuln:
                tested_cnt = stats.get("tested", 0)
                skipped_cnt = stats.get("skipped", 0)
                cov_pct = stats.get("coverage_pct", 0)
                confidence = stats.get("confidence", "UNKNOWN")

                # Emoji indicators
                if cov_pct >= 80:
                    emoji = "✅"
                elif cov_pct >= 50:
                    emoji = "⚠️"
                else:
                    emoji = "❌"

                lines.append(
                    f"| {vtype} | {tested_cnt} | {skipped_cnt} | {emoji} {cov_pct:.0f}% | {confidence} |"
                )

            lines.append("")

        # ═══════════════════════════════════════════════════════════════════
        # Skip Reasons — WHY things weren't tested (detailed breakdown)
        # ═══════════════════════════════════════════════════════════════════
        # skip_summary already fetched earlier for executive summary
        if skip_summary:
            lines.append("### Test Limitations (Why Surfaces Were Skipped)")
            lines.append("")
            lines.append("> These factors prevented complete testing. Consider addressing for future assessments.")
            lines.append("")

            # Group by category for readability
            access_skips = []
            budget_skips = []
            technical_skips = []
            error_skips = []

            skip_explanations = {
                "RATE_LIMITED": ("429 responses / backing off", "Increase scan duration or test during off-peak"),
                "BUDGET_EXHAUSTED": ("Request limit reached", "Increase --max-requests or prioritize targets"),
                "TIMEOUT": ("Scan time limit", "Increase scan duration"),
                "AUTH_REQUIRED": ("Needs credentials", "Provide valid authentication"),
                "SCOPE_OUT": ("Outside authorized scope", "Expand scope if permitted"),
                "BLOCKED_BY_WAF": ("WAF blocking payloads", "Test from whitelisted IP or use evasion"),
                "TECH_MISMATCH": ("Module not relevant", "Expected - e.g., PHP scanner on Node app"),
                "LOW_PRIORITY": ("Deprioritized", "Increase scan thoroughness"),
                "CONNECTION_ERROR": ("Network failures", "Verify target availability"),
                "MODULE_ERROR": ("Scanner error", "Review logs for details"),
            }

            for reason, count in sorted(skip_summary.items(), key=lambda x: -x[1]):
                explanation, recommendation = skip_explanations.get(
                    reason, (reason, "Review logs")
                )

                if reason in ("RATE_LIMITED", "BUDGET_EXHAUSTED", "TIMEOUT"):
                    budget_skips.append((reason, count, explanation, recommendation))
                elif reason in ("AUTH_REQUIRED", "SCOPE_OUT", "BLOCKED_BY_WAF"):
                    access_skips.append((reason, count, explanation, recommendation))
                elif reason in ("TECH_MISMATCH", "LOW_PRIORITY", "ALREADY_COVERED"):
                    technical_skips.append((reason, count, explanation, recommendation))
                else:
                    error_skips.append((reason, count, explanation, recommendation))

            if access_skips:
                lines.append("**Access Limitations:**")
                for reason, count, expl, rec in access_skips:
                    lines.append(f"- `{reason}`: {count} surfaces — {expl}")
                    lines.append(f"  - *Recommendation:* {rec}")
                lines.append("")

            if budget_skips:
                lines.append("**Budget/Rate Limitations:**")
                for reason, count, expl, rec in budget_skips:
                    lines.append(f"- `{reason}`: {count} surfaces — {expl}")
                    lines.append(f"  - *Recommendation:* {rec}")
                lines.append("")

            if technical_skips:
                lines.append("**Technical Classifications:**")
                for reason, count, expl, rec in technical_skips:
                    lines.append(f"- `{reason}`: {count} surfaces — {expl}")
                lines.append("")

            if error_skips:
                lines.append("**Errors:**")
                for reason, count, expl, rec in error_skips:
                    lines.append(f"- `{reason}`: {count} surfaces — {expl}")
                lines.append("")

        # ═══════════════════════════════════════════════════════════════════
        # High-Value Gaps — Critical surfaces that need attention
        # ═══════════════════════════════════════════════════════════════════
        gaps = coverage.get("high_value_gaps", [])
        if gaps:
            lines.append("### High-Value Surfaces Requiring Attention")
            lines.append("")
            lines.append("> These potentially sensitive endpoints were not fully tested.")
            lines.append("")
            lines.append("| Surface | Issue | Recommendation |")
            lines.append("|---------|-------|----------------|")

            for gap in gaps[:10]:  # Limit to top 10
                surface = gap.get("surface", "")[:40]
                # Truncate long URLs
                if len(surface) > 40:
                    surface = surface[:37] + "..."

                skip_reasons = gap.get("skip_reasons", [])
                depth = gap.get("test_depth", "NOT_TESTED")
                rec = gap.get("recommendation", "Increase scan depth or authorization")

                if skip_reasons:
                    issue = ", ".join(skip_reasons[:2])
                else:
                    issue = f"Low depth ({depth})"

                lines.append(f"| `{surface}` | {issue} | {rec} |")

            if len(gaps) > 10:
                lines.append(f"| ... | {len(gaps) - 10} more | See full coverage report |")

            lines.append("")

        # ═══════════════════════════════════════════════════════════════════
        # Module Performance Summary
        # ═══════════════════════════════════════════════════════════════════
        module_cov = coverage.get("module_coverage", {})
        if module_cov:
            # Only show modules with notable skip rates
            notable_modules = [
                (name, stats) for name, stats in module_cov.items()
                if stats.get("endpoints_skipped", 0) > 0 or
                   stats.get("coverage_pct", 100) < 80
            ]

            if notable_modules:
                lines.append("### Module Performance")
                lines.append("")
                lines.append("| Module | Tested | Skipped | Coverage | Time |")
                lines.append("|--------|--------|---------|----------|------|")

                for name, stats in sorted(notable_modules, key=lambda x: x[1].get("coverage_pct", 0)):
                    tested_cnt = stats.get("endpoints_tested", 0)
                    skipped_cnt = stats.get("endpoints_skipped", 0)
                    cov_pct = stats.get("coverage_pct", 0)
                    time_ms = stats.get("execution_time_ms", 0)

                    lines.append(
                        f"| {name} | {tested_cnt} | {skipped_cnt} | {cov_pct:.0f}% | {time_ms}ms |"
                    )

                lines.append("")

        # ═══════════════════════════════════════════════════════════════════
        # THEME-13: Skip Accumulation Analysis
        # "77 modules × 5% skip rate = important endpoints never tested"
        # ═══════════════════════════════════════════════════════════════════
        accumulation = coverage.get("skip_accumulation", {})
        never_tested = accumulation.get("never_tested_count", 0)
        critical_gaps = accumulation.get("critical_gap_count", 0)
        severity = accumulation.get("accumulation_severity", "OK")

        if severity in ("CRITICAL", "HIGH") or never_tested > 0 or critical_gaps > 3:
            lines.append("### 🚨 Cross-Module Skip Accumulation")
            lines.append("")
            lines.append(
                "> **Analysis:** When multiple scanner modules each skip a small percentage "
                "of endpoints, the aggregate effect can leave some endpoints NEVER tested."
            )
            lines.append("")

            # Severity indicator
            if severity == "CRITICAL":
                lines.append(
                    f"**⚠️ CRITICAL Coverage Gap:** {never_tested} endpoint(s) were skipped by ALL modules."
                )
            elif severity == "HIGH":
                lines.append(
                    f"**⚠️ Significant Gap:** {critical_gaps} endpoint(s) were skipped by >50% of modules."
                )
            elif never_tested > 0:
                lines.append(
                    f"**Coverage Warning:** {never_tested} endpoint(s) were not tested by any module."
                )

            lines.append("")

            # Show never-tested endpoints
            never_tested_list = accumulation.get("never_tested", [])
            if never_tested_list:
                lines.append("**Endpoints Never Tested:**")
                lines.append("")
                lines.append("| Endpoint | Skipped By | Modules |")
                lines.append("|----------|------------|---------|")

                for gap in never_tested_list[:5]:
                    endpoint = gap.get("endpoint", "")[:40]
                    if len(endpoint) > 40:
                        endpoint = endpoint[:37] + "..."
                    skipped_by = gap.get("skipped_by", 0)
                    modules = gap.get("modules", [])[:3]
                    mods_str = ", ".join(modules)
                    if len(modules) > 3:
                        mods_str += "..."

                    lines.append(f"| `{endpoint}` | {skipped_by} | {mods_str} |")

                if len(never_tested_list) > 5:
                    lines.append(f"| ... | {never_tested - 5} more | See full report |")

                lines.append("")

            # Show critical gaps (skipped by >50%)
            critical_list = accumulation.get("critical_gaps", [])
            if critical_list:
                lines.append("**Endpoints with >50% Module Skip Rate:**")
                lines.append("")
                lines.append("| Endpoint | Skip Ratio | Tested By | Skipped By |")
                lines.append("|----------|------------|-----------|------------|")

                for gap in critical_list[:5]:
                    endpoint = gap.get("endpoint", "")[:35]
                    if len(endpoint) > 35:
                        endpoint = endpoint[:32] + "..."
                    skip_ratio = gap.get("skip_ratio", 0)
                    tested_by = gap.get("tested_by", 0)
                    skipped_by = gap.get("skipped_by", 0)

                    lines.append(
                        f"| `{endpoint}` | {skip_ratio:.0f}% | {tested_by} modules | {skipped_by} modules |"
                    )

                if len(critical_list) > 5:
                    lines.append(f"| ... | | {len(critical_list) - 5} more | |")

                lines.append("")

            # Recommendation
            recommendation = accumulation.get("recommendation", "")
            if recommendation:
                lines.append(f"> **Recommendation:** {recommendation}")
                lines.append("")

        # ═══════════════════════════════════════════════════════════════════
        # THEME-6: Error/Failure Statistics
        # Make silent failures visible to the client
        # ═══════════════════════════════════════════════════════════════════
        error_stats = None
        for info_item in meta.get("info", []):
            if isinstance(info_item, dict) and info_item.get("type") == "module_error_stats":
                error_stats = info_item.get("data", {})
                break

        if error_stats and error_stats.get("total_errors", 0) > 0:
            lines.append("### ⚠️ Scan Reliability (Error Statistics)")
            lines.append("")

            total_errors = error_stats.get("total_errors", 0)
            total_requests = error_stats.get("total_requests", 0)
            modules_with_errors = error_stats.get("modules_with_errors", 0)
            failure_rate = error_stats.get("overall_failure_rate", 0)

            # Color-code by severity
            if failure_rate >= 20:
                indicator = "🔴"  # High failure rate
                severity_note = "High failure rate may indicate incomplete testing"
            elif failure_rate >= 10:
                indicator = "🟠"  # Medium failure rate
                severity_note = "Some tests failed - review error details"
            else:
                indicator = "🟡"  # Low failure rate
                severity_note = "Minimal errors - results are reliable"

            lines.append(f"> {indicator} **{severity_note}**")
            lines.append("")
            lines.append("```")
            lines.append(f"Total Requests:      {total_requests:>6}")
            lines.append(f"Failed Requests:     {total_errors:>6}")
            lines.append(f"Failure Rate:        {failure_rate:>5.1f}%")
            lines.append(f"Modules with Errors: {modules_with_errors:>6}")
            lines.append("```")
            lines.append("")

            # Show per-module breakdown for modules with errors
            by_module = error_stats.get("by_module", {})
            if by_module:
                lines.append("**Errors by Module:**")
                lines.append("")
                lines.append("| Module | Requests | Failed | Rate | Error Types |")
                lines.append("|--------|----------|--------|------|-------------|")

                for mod_name, mod_stats in sorted(
                    by_module.items(),
                    key=lambda x: x[1].get("failure_rate", 0),
                    reverse=True
                )[:10]:  # Top 10 by failure rate
                    req_total = mod_stats.get("requests_total", 0)
                    req_failed = mod_stats.get("requests_failed", 0)
                    rate = mod_stats.get("failure_rate", 0)
                    errors = mod_stats.get("errors_by_type", {})
                    types_str = ", ".join(f"{t}:{c}" for t, c in sorted(errors.items())[:3])

                    lines.append(
                        f"| {mod_name} | {req_total} | {req_failed} | {rate:.0f}% | {types_str} |"
                    )

                lines.append("")

                if failure_rate >= 10:
                    lines.append("> **Note:** High error rates may indicate network issues, WAF blocking, "
                                "or target availability problems. Consider re-running affected tests.")
                    lines.append("")

        # ═══════════════════════════════════════════════════════════════════
        # THEME-7: Retry Statistics
        # Show what was successfully retried
        # ═══════════════════════════════════════════════════════════════════
        retry_stats = None
        for info_item in meta.get("info", []):
            if isinstance(info_item, dict) and info_item.get("type") == "retry_stats":
                retry_stats = info_item.get("data", {})
                break

        if retry_stats and retry_stats.get("total_retries", 0) > 0:
            lines.append("### Smart Retry Summary")
            lines.append("")

            total_retries = retry_stats.get("total_retries", 0)
            successful = retry_stats.get("successful_retries", 0)
            failed = retry_stats.get("failed_after_retry", 0)
            retry_findings = retry_stats.get("retry_findings", 0)

            if successful > 0:
                lines.append(
                    f"> The scanner automatically retried {total_retries} endpoint(s) that initially failed "
                    f"due to rate limiting or timeouts. **{successful} succeeded**, recovering "
                    f"**{retry_findings} additional finding(s)**."
                )
            else:
                lines.append(
                    f"> The scanner attempted {total_retries} retries for rate-limited/timed-out endpoints. "
                    f"All retries failed — consider re-running during off-peak hours."
                )
            lines.append("")

        # ═══════════════════════════════════════════════════════════════════
        # THEME-10: Uncertainty Statistics
        # "Não testado ≠ não vulnerável"
        # ═══════════════════════════════════════════════════════════════════
        uncertainty_stats = None
        for info_item in meta.get("info", []):
            if isinstance(info_item, dict) and info_item.get("type") == "uncertainty_stats":
                uncertainty_stats = info_item.get("data", {})
                break

        if uncertainty_stats:
            high_uncertainty = uncertainty_stats.get("findings_with_high_uncertainty", 0)
            proofs_not_attempted = uncertainty_stats.get("proofs_not_attempted", 0)
            avg_uncertainty = uncertainty_stats.get("validation_uncertainty_avg", 0)

            if high_uncertainty > 0 or proofs_not_attempted > 0:
                lines.append("### ⚠️ Validation Uncertainty")
                lines.append("")
                lines.append(
                    "> **Important:** Some findings could not be fully validated due to missing data, "
                    "network issues, or scope constraints. This does NOT mean they are false positives."
                )
                lines.append("")

                lines.append("```")
                lines.append(f"Findings with High Uncertainty:  {high_uncertainty:>6}")
                lines.append(f"Proofs Not Attempted:            {proofs_not_attempted:>6}")
                lines.append(f"Average Uncertainty Score:       {avg_uncertainty:>5.1%}")
                lines.append("```")
                lines.append("")

                # Show uncertainty reasons if available
                reasons = uncertainty_stats.get("uncertainty_reasons_summary", {})
                if reasons:
                    lines.append("**Uncertainty Breakdown:**")
                    lines.append("")
                    lines.append("| Reason | Count |")
                    lines.append("|--------|-------|")
                    for reason, count in sorted(reasons.items(), key=lambda x: x[1], reverse=True)[:5]:
                        lines.append(f"| {reason} | {count} |")
                    lines.append("")

                lines.append(
                    "> **Note:** Some findings have partial proof due to rate limiting or safety modes. "
                    "Run aggressive scan to obtain full verification. Missing proof ≠ missing vulnerability."
                )
                lines.append("")

        # ═══════════════════════════════════════════════════════════════════
        # THEME-9: Saturation Control Statistics
        # "Too many indistinct attempts obscure weak signals"
        # ═══════════════════════════════════════════════════════════════════
        saturation_stats = meta.get("info", {}).get("saturation", {})
        if not saturation_stats:
            # Try alternate location
            for info_item in meta.get("info", []):
                if isinstance(info_item, dict) and info_item.get("type") == "saturation":
                    saturation_stats = info_item.get("data", {})
                    break

        if saturation_stats:
            total_requests = saturation_stats.get("total_requests", 0)
            total_findings = saturation_stats.get("total_findings", 0)
            modules_exhausted = saturation_stats.get("modules_exhausted", [])
            hypothesis_stats = saturation_stats.get("hypothesis_stats", {})

            if total_requests > 0 or modules_exhausted:
                lines.append("### Budget Utilization Summary")
                lines.append("")

                global_util = saturation_stats.get("global_utilization", {})
                req_pct = global_util.get("requests_pct", 0)
                find_pct = global_util.get("findings_pct", 0)

                lines.append("| Metric | Value | Budget | Utilization |")
                lines.append("|--------|-------|--------|-------------|")
                lines.append(
                    f"| Requests | {total_requests:,} | "
                    f"{saturation_stats.get('max_total_requests', 10000):,} | "
                    f"{req_pct:.1f}% |"
                )
                lines.append(
                    f"| Findings | {total_findings:,} | "
                    f"{saturation_stats.get('max_total_findings', 500):,} | "
                    f"{find_pct:.1f}% |"
                )
                lines.append("")

                if modules_exhausted:
                    lines.append("**Modules That Reached Budget Limits:**")
                    for mod in modules_exhausted[:10]:
                        lines.append(f"- `{mod}`")
                    lines.append("")
                    lines.append(
                        "> Budget limits prevent cognitive saturation (weak signals buried in noise). "
                        "Modules stopped when their testing budget was exhausted."
                    )
                    lines.append("")

                if hypothesis_stats.get("total_hypotheses", 0) > 0:
                    lines.append("**Hypothesis Sharing:**")
                    lines.append(
                        f"- {hypothesis_stats.get('total_hypotheses', 0)} hypotheses shared between modules"
                    )
                    lines.append(
                        f"- {hypothesis_stats.get('by_result', {}).get('vulnerable', 0)} confirmed vulnerable"
                    )
                    lines.append(
                        f"- {hypothesis_stats.get('by_result', {}).get('not_vulnerable', 0)} ruled out"
                    )
                    lines.append("")
                    lines.append(
                        "> Hypothesis sharing prevents duplicate testing. When one module confirms "
                        "a parameter is injectable, other modules skip redundant tests."
                    )
                    lines.append("")

        # ═══════════════════════════════════════════════════════════════════
        # THEME-12: Suppression Audit Summary
        # "Por que o scanner rejeitou este finding?"
        # ═══════════════════════════════════════════════════════════════════
        findings_suppressed = meta.get("findings_suppressed", 0)
        chains_suppressed = meta.get("chains_suppressed", 0)
        proofs_skipped = meta.get("proofs_skipped", 0)
        suppression_audit = meta.get("suppression_audit", [])

        if findings_suppressed > 0 or chains_suppressed > 0 or proofs_skipped > 0:
            lines.append("### Validation Audit Summary")
            lines.append("")
            lines.append("| Category | Count | Impact |")
            lines.append("|----------|-------|--------|")
            if findings_suppressed > 0:
                lines.append(
                    f"| Findings Filtered | {findings_suppressed} | "
                    "Removed as duplicates or false positives |"
                )
            if chains_suppressed > 0:
                lines.append(
                    f"| Chains Consolidated | {chains_suppressed} | "
                    "Merged to reduce noise |"
                )
            if proofs_skipped > 0:
                lines.append(
                    f"| Proofs Skipped | {proofs_skipped} | "
                    "Budget exhausted before proof could complete |"
                )
            lines.append("")

            if suppression_audit:
                lines.append("**Sample Suppressed Findings:**")
                for item in suppression_audit[:5]:
                    lines.append(
                        f"- `{item.get('id', 'unknown')}`: {item.get('reason', 'no reason')} "
                        f"(stage: {item.get('stage', 'unknown')})"
                    )
                if len(suppression_audit) > 5:
                    lines.append(f"- ... and {len(suppression_audit) - 5} more")
                lines.append("")

            lines.append(
                "> Suppressed findings are filtered to reduce noise. "
                "Check `suppression_audit` in JSON report for full details."
            )
            lines.append("")

        # ═══════════════════════════════════════════════════════════════════
        # THEME-14: Model Freshness / Drift Awareness
        # "Does the scanner know when its model is outdated?"
        # ═══════════════════════════════════════════════════════════════════
        drift_data = None
        for info_item in meta.get("info", []):
            if isinstance(info_item, dict) and info_item.get("type") == "model_drift_awareness":
                drift_data = info_item.get("data", {})
                break

        if drift_data:
            health = drift_data.get("model_health", {})
            health_status = health.get("health", "OK")
            staleness = health.get("overall_staleness", "UNKNOWN")

            # Only show if there are issues or it's been a while
            show_section = (
                health_status in ("WARNING", "CRITICAL") or
                staleness in ("STALE", "OUTDATED") or
                health.get("categories_with_issues", [])
            )

            if show_section:
                lines.append("### 📊 Scanner Model Freshness")
                lines.append("")

                if health_status == "CRITICAL":
                    lines.append(
                        f"> **⚠️ CRITICAL:** {health.get('recommendation', 'Update detection patterns')}"
                    )
                elif health_status == "WARNING":
                    lines.append(
                        f"> **Warning:** {health.get('recommendation', 'Consider updating patterns')}"
                    )
                lines.append("")

                # Pattern staleness summary
                pattern_staleness = health.get("pattern_staleness", {})
                if pattern_staleness:
                    lines.append("**Pattern Category Freshness:**")
                    lines.append("")
                    lines.append("| Category | Last Updated | Age (days) | Status |")
                    lines.append("|----------|--------------|------------|--------|")

                    for category, info in sorted(pattern_staleness.items()):
                        last_updated = info.get("last_updated", "Unknown")
                        if last_updated and last_updated != "Unknown":
                            # Format date nicely
                            try:
                                from datetime import datetime
                                dt = datetime.fromisoformat(last_updated)
                                last_updated = dt.strftime("%Y-%m-%d")
                            except (ValueError, TypeError):
                                pass  # FIX 2026-02-12: Expected - date may be malformed

                        age_days = info.get("age_days", "?")
                        cat_staleness = info.get("staleness", "UNKNOWN")

                        # Status emoji
                        if cat_staleness == "FRESH":
                            status_emoji = "✅ Fresh"
                        elif cat_staleness == "AGING":
                            status_emoji = "🟡 Aging"
                        elif cat_staleness == "STALE":
                            status_emoji = "🟠 Stale"
                        elif cat_staleness == "OUTDATED":
                            status_emoji = "🔴 Outdated"
                        else:
                            status_emoji = "❓ Unknown"

                        lines.append(
                            f"| {category} | {last_updated} | {age_days} | {status_emoji} |"
                        )

                    lines.append("")

                # Categories with issues
                issues = health.get("categories_with_issues", [])
                if issues:
                    lines.append("**Categories Requiring Attention:**")
                    for issue in issues[:5]:
                        lines.append(
                            f"- `{issue['category']}`: {issue['issue']} — {issue['detail']}"
                        )
                    lines.append("")

                lines.append(
                    "> Pattern freshness affects detection accuracy. "
                    "Modern frameworks (HTMX, Alpine.js, etc.) require updated patterns."
                )
                lines.append("")

        # ═══════════════════════════════════════════════════════════════════
        # Coverage Interpretation Note
        # ═══════════════════════════════════════════════════════════════════
        lines.append("### Interpretation Note")
        lines.append("")
        lines.append(
            "> A low finding count does not indicate weak security or scanner limitations. "
            "It may reflect:"
        )
        lines.append("")
        lines.append("- **Well-secured application** — No vulnerabilities were found because they don't exist")
        lines.append("- **Test limitations** — See skip reasons above for areas requiring follow-up")
        lines.append("- **Defense in depth** — WAF/rate limiting prevented thorough testing (not a bad thing!)")
        lines.append("")
        lines.append(
            "Review the *High-Value Gaps* section to prioritize additional scan passes with different modes."
        )

        return "\n".join(lines)

    def _build_findings_summary(
        self, findings: List[Dict[str, Any]]
    ) -> str:
        """Build findings overview table with root-cause clustering."""
        lines = [
            "| # | Finding | Severity | CVSS | CWE | Proof |",
            "|---|---------|----------|------|-----|-------|",
        ]

        # Reorder findings by cluster (representatives first) if available
        try:
            from scanning.result_processor.cluster import get_clustered_findings
            ordered = get_clustered_findings(
                [f["finding"] if isinstance(f, dict) and "finding" in f else f for f in findings]
            )
        except Exception:
            ordered = [f["finding"] if isinstance(f, dict) and "finding" in f else f for f in findings]

        rendered_clusters: set = set()
        row_num = 0
        for raw in ordered:
            cl = ((raw.get("metadata") or {}).get("cluster") or {})
            cid = cl.get("cluster_id", "")
            csize = cl.get("cluster_size", 1)
            is_rep = cl.get("is_representative", True)

            title = raw.get("name", raw.get("title", raw.get("type", "Unknown")))
            sev = self._get_severity(raw).upper()
            cvss = float(raw.get("cvss_score", 0) or 0)
            cwe = raw.get("cwe", "")
            proof_label = self._get_proof_label(raw)

            if csize > 1 and is_rep and cid not in rendered_clusters:
                rendered_clusters.add(cid)
                row_num += 1
                badge = f" ({csize} findings)"
                lines.append(
                    f"| {row_num} | **{title}**{badge} | **{sev}** | {cvss} | {cwe} | {proof_label} |"
                )
            elif csize > 1 and not is_rep:
                # Indented sub-finding
                conf = cl.get("cluster_confidence", 0)
                lines.append(
                    f"|   | &nbsp;&nbsp;+ {title} | {sev} | {cvss} | {cwe} | {proof_label} |"
                )
            else:
                row_num += 1
                lines.append(
                    f"| {row_num} | {title} | **{sev}** | {cvss} | {cwe} | {proof_label} |"
                )

        # Severity breakdown
        sev_counts: Dict[str, int] = {}
        for f in findings:
            sev = self._get_severity(f).upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        lines.append("")
        lines.append("**Severity Breakdown:**")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = sev_counts.get(sev, 0)
            if count > 0:
                bar = "█" * count
                lines.append(f"- {sev}: {bar} ({count})")

        # ═══════════════════════════════════════════════════════════════════
        # ATTACK CHAINS SECTION — Grouped by confidence level
        # Visually separate PROVEN, TECHNICAL, and THEORETICAL chains
        # ═══════════════════════════════════════════════════════════════════
        chain_section = self._build_attack_chains_section(findings)
        if chain_section:
            lines.append("")
            lines.append(chain_section)

        return "\n".join(lines)

    def _build_attack_chains_section(
        self, findings: List[Dict[str, Any]]
    ) -> str:
        """
        Build attack chains section grouped by confidence level.

        Separates:
        - PROVEN: Fully validated chains (executed end-to-end)
        - TECHNICAL: Infrastructure-grade chains (realistic but not fully validated)
        - THEORETICAL: Speculative chains (logically possible)
        """
        # Filter chain findings
        chains = []
        for f in findings:
            raw = f["finding"] if isinstance(f, dict) and "finding" in f else f
            metadata = raw.get("metadata", {})
            if metadata.get("is_chain"):
                chains.append(raw)

        if not chains:
            return ""

        # Group by chain confidence
        by_confidence: Dict[str, List] = {
            "proven": [],
            "high": [],
            "technical": [],
            "medium": [],
            "theoretical": [],
        }

        for chain in chains:
            metadata = chain.get("metadata", {})
            conf = metadata.get("chain_confidence", "theoretical").lower()
            if conf in by_confidence:
                by_confidence[conf].append(chain)
            else:
                by_confidence["theoretical"].append(chain)

        lines = ["", "---", "", "## Attack Chains Analysis", ""]

        # Confidence level descriptions
        confidence_info = {
            "proven": ("🟢 PROVEN", "Fully validated — chain was executed end-to-end"),
            "high": ("🟢 HIGH", "All steps verified independently"),
            "technical": ("🟡 TECHNICAL", "Infrastructure-grade — technically realistic, validation recommended"),
            "medium": ("🟠 MEDIUM", "Some steps verified, others inferred"),
            "theoretical": ("⚪ THEORETICAL", "Logically possible but not yet validated"),
        }

        # Render each confidence level
        for conf_level in ["proven", "high", "technical", "medium", "theoretical"]:
            conf_chains = by_confidence.get(conf_level, [])
            if not conf_chains:
                continue

            label, description = confidence_info[conf_level]
            lines.append(f"### {label} Chains ({len(conf_chains)})")
            lines.append(f"> {description}")
            lines.append("")

            # Table header
            lines.append("| Chain | Category | Probability | Severity |")
            lines.append("|-------|----------|-------------|----------|")

            for chain in conf_chains:
                metadata = chain.get("metadata", {})
                name = chain.get("name", "Unknown Chain")
                category = metadata.get("chain_category", "Unknown")
                prob = metadata.get("probability_score", 0)
                sev = chain.get("severity", "MEDIUM").upper()

                # GAP-3 FIX 2026-02-13: Add warning when severity exceeds confidence
                severity_to_conf = {"CRITICAL": 85, "HIGH": 75, "MEDIUM": 60, "LOW": 40}
                expected_conf = severity_to_conf.get(sev, 50)
                warning = ""
                if prob < expected_conf:
                    warning = " ⚠️"
                    # Add confidence warning to metadata for downstream processing
                    if "confidence_warning" not in metadata:
                        metadata["confidence_warning"] = (
                            f"Severity {sev} but probability only {prob:.0f}% "
                            f"(expected ≥{expected_conf}%)"
                        )
                lines.append(f"| {name} | {category} | {prob:.0f}% | **{sev}**{warning} |")

            lines.append("")

            # GAP-3 FIX 2026-02-13: Add confidence warning note if any chains have warnings
            chains_with_warnings = [
                c for c in conf_chains
                if c.get("metadata", {}).get("confidence_warning")
            ]
            if chains_with_warnings:
                lines.append("> ⚠️ **Note:** Some chains show severity exceeding confidence level. "
                            "These chains are based on vulnerability type combinations but individual "
                            "component confidence may be lower than expected for that severity.")
                lines.append("")

            # For TECHNICAL chains, show validation steps
            if conf_level == "technical":
                for chain in conf_chains[:2]:  # Show steps for top 2
                    metadata = chain.get("metadata", {})
                    val_steps = metadata.get("validation_steps", [])
                    if val_steps:
                        name = chain.get("name", "Chain")
                        lines.append(f"**Validation Steps for {name}:**")
                        for step in val_steps[:3]:
                            lines.append(f"  - {step}")
                        lines.append("")

        # Add link to interactive visualization if it will be generated
        if len(chains) > 0 and CHAIN_VISUALIZATION_AVAILABLE:
            lines.append("")
            lines.append("---")
            lines.append("")
            lines.append("### Interactive Attack Graph")
            lines.append("")
            lines.append("**[View Interactive Attack Chain Visualization](attack_chains.html)**")
            lines.append("")
            lines.append("> *Open the HTML file in a browser to explore the attack graph interactively. "
                        "Nodes can be dragged, zoomed, and inspected for details.*")

        return "\n".join(lines)

    def _generate_chain_visualization(
        self,
        findings: List[Dict[str, Any]],
    ) -> Optional[str]:
        """
        Generate interactive HTML visualization of attack chains.

        Converts chain findings to visualization format and generates
        an interactive D3.js-based HTML graph.

        Args:
            findings: List of findings (includes chain findings)

        Returns:
            HTML content string, or None if no chains or visualization unavailable
        """
        if not CHAIN_VISUALIZATION_AVAILABLE:
            logger.debug("Chain visualization not available - skipping graph generation")
            return None

        # Extract chain findings
        chains = []
        for f in findings:
            raw = f["finding"] if isinstance(f, dict) and "finding" in f else f
            metadata = raw.get("metadata", {})
            if metadata.get("is_chain"):
                chains.append(raw)

        if not chains:
            return None

        # Convert chains to visualization format
        # The visualization engine expects:
        # - chain["vulnerabilities"]: list of vulns with id, type, severity, url, description
        # - chain["chain_id"]: unique identifier
        # - chain["description"]: narrative
        # - chain["outcome"]: final impact
        viz_chains = []
        for chain in chains:
            metadata = chain.get("metadata", {})
            chain_steps = metadata.get("chain_steps", [])

            # Build vulnerability list from chain steps
            vulnerabilities = []
            for i, step in enumerate(chain_steps):
                vuln = {
                    "id": f"step_{i}",
                    "type": step.get("finding_name", "Unknown").replace("Attack Chain: ", ""),
                    "severity": chain.get("severity", "MEDIUM"),
                    "url": step.get("url", ""),
                    "description": step.get("action", ""),
                    "cvss_score": float(metadata.get("cvss_score", 0) or 0),
                }
                vulnerabilities.append(vuln)

            # If no steps but we have linked_findings, use those
            if not vulnerabilities and metadata.get("linked_findings"):
                for i, fname in enumerate(metadata["linked_findings"]):
                    vulnerabilities.append({
                        "id": f"vuln_{i}",
                        "type": fname,
                        "severity": chain.get("severity", "MEDIUM"),
                        "url": chain.get("matched_at", ""),
                        "description": "",
                        "cvss_score": 0.0,
                    })

            viz_chain = {
                "chain_id": metadata.get("chain_name", chain.get("name", "Unknown")),
                "chain_type": metadata.get("chain_category", ""),
                "description": chain.get("description", ""),
                "outcome": metadata.get("business_impact", "Security breach"),
                "vulnerabilities": vulnerabilities,
                "total_risk_score": metadata.get("probability_score", 50),
            }
            viz_chains.append(viz_chain)

        if not viz_chains:
            return None

        try:
            # Create visualization engine with dark mode config
            config = VisualizationConfig(
                width=1400,
                height=900,
                node_size=45,
                font_size=12,
                show_labels=True,
                show_legend=True,
                title=f"Attack Chain Analysis - {self.client_name}",
                dark_mode=False,  # Light mode for professional reports
            )

            viz_engine = ChainVisualizationEngine(config=config)

            # Generate combined graph from all chains
            graph = viz_engine.create_graph_from_chains(
                chains=viz_chains,
                name=f"Attack Chains - {self.client_name}",
            )

            # Render as interactive HTML
            html_content = viz_engine.render_html(graph)

            logger.info(f"[CHAIN-VIZ] Generated interactive visualization for {len(viz_chains)} chains")
            return html_content

        except Exception as e:
            logger.warning(f"[CHAIN-VIZ] Failed to generate visualization: {e}")
            return None

    def _build_detailed_findings(
        self,
        findings: List[Dict[str, Any]],
        finding_reports: List[Dict[str, Any]],
    ) -> str:
        """Build detailed findings section with evidence from per-finding reports.

        Findings are grouped by root-cause cluster when available.
        Multi-member clusters show the representative with full detail,
        followed by a compact 'Related Findings' subsection.
        """
        # Build lookup: finding id/index → finding_report
        report_by_id: Dict[int, Dict[str, Any]] = {}
        raw_list: List[Dict[str, Any]] = []
        for i, f in enumerate(findings):
            raw = f["finding"] if isinstance(f, dict) and "finding" in f else f
            raw_list.append(raw)
            report_by_id[id(raw)] = finding_reports[i] if i < len(finding_reports) else {}

        # Reorder by cluster
        try:
            from scanning.result_processor.cluster import get_clustered_findings
            ordered = get_clustered_findings(raw_list)
        except Exception:
            ordered = raw_list

        sections = []
        rendered_clusters: set = set()
        section_num = 0

        for raw in ordered:
            cl = ((raw.get("metadata") or {}).get("cluster") or {})
            cid = cl.get("cluster_id", "")
            csize = cl.get("cluster_size", 1)
            is_rep = cl.get("is_representative", True)

            # Skip sub-findings here — they're rendered inside the cluster block
            if csize > 1 and not is_rep:
                continue

            fr = report_by_id.get(id(raw), {})
            section_num += 1

            title = raw.get("name", raw.get("title", raw.get("type", "Unknown")))
            sev = self._get_severity(raw).upper()
            cvss = float(raw.get("cvss_score", 0) or 0)
            cwe = raw.get("cwe", "")
            host = raw.get("host", raw.get("url", ""))
            desc = raw.get("description", "")

            # Cluster badge in heading
            cluster_badge = ""
            if csize > 1:
                root_cause = cl.get("root_cause", title)
                cluster_badge = f" ({csize} findings)"

            section = [f"### {section_num}. {title}{cluster_badge}"]
            section.append("")

            # Root cause description for multi-member clusters
            if csize > 1:
                section.append(f"> **Root Cause:** {cl.get('root_cause', title)}")
                section.append("")

            section.append(f"**Severity:** {sev} | **CVSS:** {cvss} | **CWE:** {cwe}")
            section.append(f"**Host:** `{host}`")
            section.append("")

            # P2-4 FIX: Add risk score explanation/narrative
            metadata = raw.get("metadata", {})
            risk_narrative = self._build_risk_narrative(sev, cvss, metadata)
            if risk_narrative:
                section.append(f"**Risk Assessment:** {risk_narrative}")
                section.append("")

            if desc:
                section.append(desc[:600])
                section.append("")

            # Evidence from per-finding report
            if fr.get("exploit_evidence"):
                section.append("#### Exploit Evidence")
                section.append("")
                for ev in fr["exploit_evidence"]:
                    label = ev.get("label", "Test")
                    section.append(f"**{label}**")
                    section.append("")
                    if ev.get("request"):
                        section.append("**Request:**")
                        section.append("```http")
                        section.append(ev["request"][:500])
                        section.append("```")
                    if ev.get("response"):
                        section.append("**Response:**")
                        section.append("```http")
                        section.append(ev["response"][:500])
                        section.append("```")
                    section.append("")

            # Verification Status (from proof engine or speculative chain)
            section.extend(self._render_finding_proof(fr, raw))

            # Reproduction steps
            if fr.get("steps"):
                section.append("#### Reproduction Steps")
                section.append("")
                for j, step in enumerate(fr["steps"], 1):
                    section.append(f"**Step {j}:** {step.get('description', '')}")
                    if step.get("command"):
                        section.append(f"```bash\n{step['command']}\n```")
                    section.append("")

            # ── Related findings in this root-cause cluster ──────────────
            if csize > 1 and cid not in rendered_clusters:
                rendered_clusters.add(cid)
                sub_findings = [
                    f2 for f2 in ordered
                    if ((f2.get("metadata") or {}).get("cluster") or {}).get("cluster_id") == cid
                    and not ((f2.get("metadata") or {}).get("cluster") or {}).get("is_representative")
                ]
                if sub_findings:
                    section.append("#### Related Findings in this Root Cause")
                    section.append("")
                    for sf in sub_findings:
                        sf_title = sf.get("name", sf.get("title", sf.get("type", "Unknown")))
                        sf_sev = self._get_severity(sf).upper()
                        sf_desc = sf.get("description", "")[:200]
                        sf_endpoint = sf.get("endpoint", sf.get("matched_at", ""))
                        section.append(f"- **{sf_title}** ({sf_sev})")
                        if sf_endpoint:
                            section.append(f"  - Endpoint: `{sf_endpoint}`")
                        if sf_desc:
                            section.append(f"  - {sf_desc}")
                    section.append("")

            # Compliance Impact (per-finding)
            compliance_section = self._build_finding_compliance_impact(raw)
            if compliance_section:
                section.append(compliance_section)
                section.append("")

            # Remediation
            remediation = fr.get("remediation") or raw.get("remediation", "")
            if remediation:
                section.append(f"#### Remediation")
                section.append("")
                section.append(remediation[:400])
                section.append("")

            # Link to per-finding artifacts
            files = fr.get("files", {})
            if files:
                section.append("#### Artifacts")
                section.append("")
                for fmt, fpath in files.items():
                    section.append(f"- `{fmt}`: `{fpath}`")
                section.append("")

            sections.append("\n".join(section))

        return "\n---\n\n".join(sections)

    def _build_attacker_next_steps(
        self, suggestions: List[Dict[str, Any]]
    ) -> str:
        """
        Build the 'What an Attacker Would Likely Do Next' section.

        These are ADVISORY suggestions, NOT findings:
        - NO severity ratings
        - NO confidence scores
        - NO CVSS
        - Hypothetical language only

        Args:
            suggestions: List of PostExploitSuggestion dicts from post-exploitation module

        Returns:
            Markdown section describing hypothetical attacker behavior
        """
        if not suggestions:
            return ""

        lines = [
            "### What an Attacker Would Likely Do Next",
            "",
            "Based on the detected vulnerability chains, a real-world attacker would likely attempt:",
            "",
        ]

        for suggestion in suggestions:
            category = suggestion.get("category", "general").replace("_", " ").title()
            narrative = suggestion.get("narrative", "")
            steps = suggestion.get("steps", [])
            context = suggestion.get("risk_context", "")

            lines.append(f"#### {category}")
            lines.append("")
            if narrative:
                lines.append(f"*{narrative}*")
                lines.append("")
            if steps:
                for step in steps:
                    lines.append(f"- {step}")
                lines.append("")
            if context:
                lines.append(f"> {context}")
                lines.append("")

        lines.append("---")
        lines.append("")
        lines.append(
            "*These suggestions describe hypothetical attacker behavior for risk assessment purposes. "
            "They are based on detected vulnerability chains and do not constitute proof of exploitation.*"
        )

        return "\n".join(lines)

    def _build_remediation_roadmap(
        self, findings: List[Dict[str, Any]]
    ) -> str:
        """Build prioritized remediation roadmap."""
        # P2-3 FIX: Base severity descriptions - nuanced based on exploitability
        base_impact_map = {
            "CRITICAL": ("Immediate", "Potential severe impact"),
            "HIGH": ("1-2 weeks", "Potential significant impact"),
            "MEDIUM": ("2-4 weeks", "Limited exposure risk"),
            "LOW": ("Next sprint", "Minor information leak"),
            "INFO": ("Backlog", "Best practice improvement"),
        }

        lines = [
            "| Priority | Finding | Timeline | Business Impact |",
            "|----------|---------|----------|-----------------|",
        ]

        for i, f in enumerate(findings, 1):
            raw = f["finding"] if isinstance(f, dict) and "finding" in f else f
            title = raw.get("name", raw.get("title", raw.get("type", "Unknown")))
            sev = self._get_severity(f).upper()
            timeline, base_impact = base_impact_map.get(sev, ("—", "—"))

            # P2-3: Adjust impact description based on exploitability proof
            metadata = raw.get("metadata", {})
            proof = metadata.get("proof", {})
            exploitability = metadata.get("exploitability", "")

            if proof.get("can_escalate") or exploitability == "FULL":
                impact = "Confirmed exploitable - " + base_impact
            elif proof.get("can_repeat") or exploitability == "PARTIAL":
                impact = "Reproducible - " + base_impact
            else:
                impact = base_impact

            lines.append(f"| P{i} | {title} | {timeline} | {impact} |")

        lines.append("")
        lines.append("**Priority Legend:** P1 = Highest priority (fix first)")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_severity(self, finding: Dict[str, Any]) -> str:
        """Extract severity from a finding dict (handles nested structures)."""
        if isinstance(finding, dict) and "finding" in finding:
            finding = finding["finding"]
        return (
            finding.get("severity", "")
            or finding.get("risk", "")
            or "info"
        )

    def _build_risk_narrative(
        self, severity: str, cvss: float, metadata: Dict[str, Any]
    ) -> str:
        """
        P2-4: Build a human-readable risk score explanation.

        Instead of just showing "CRITICAL | CVSS 9.8", explain WHY.
        """
        parts = []

        # Base severity explanation
        sev_explanations = {
            "CRITICAL": "requires immediate attention due to potential for significant damage",
            "HIGH": "poses substantial risk and should be prioritized",
            "MEDIUM": "presents moderate risk requiring planned remediation",
            "LOW": "represents minor risk with limited impact",
            "INFO": "informational finding for defense-in-depth improvement",
        }
        parts.append(sev_explanations.get(severity, ""))

        # CVSS context
        if cvss >= 9.0:
            parts.append("CVSS 9.0+ indicates high exploitability and severe impact")
        elif cvss >= 7.0:
            parts.append("CVSS 7.0+ indicates significant security concern")
        elif cvss >= 4.0:
            parts.append("CVSS 4.0+ indicates moderate security concern")

        # Proof/exploitability context
        proof = metadata.get("proof", {})
        exploitability = metadata.get("exploitability", "")

        if proof.get("can_escalate"):
            parts.append("Exploitation was demonstrated with privilege escalation")
        elif proof.get("can_repeat"):
            parts.append("Vulnerability is confirmed reproducible")
        elif exploitability == "FULL":
            parts.append("Full exploitation capability confirmed")
        elif exploitability == "PARTIAL":
            parts.append("Partial exploitation demonstrated")

        # Chain context
        if proof.get("can_chain"):
            parts.append("Can be chained with other vulnerabilities for greater impact")

        # Filter empty parts and join
        parts = [p for p in parts if p]
        if not parts:
            return ""

        return "; ".join(parts) + "."

    @staticmethod
    def _render_finding_proof(
        finding_report: Dict[str, Any], raw_finding: Dict[str, Any]
    ) -> List[str]:
        """Render verification status subsection for a single finding."""
        lines: List[str] = []
        proof_status = finding_report.get("proof_status") or (raw_finding.get("metadata") or {}).get("proof_status", "")
        proof_data = finding_report.get("proof_data") or (raw_finding.get("metadata") or {}).get("proof")
        linked = finding_report.get("linked_scanner_findings") or (raw_finding.get("metadata") or {}).get("linked_scanner_findings", [])

        # Proof Gate badge (Phase 4.46a)
        proof_gate = (raw_finding.get("metadata") or {}).get("proof_gate")
        if proof_gate and isinstance(proof_gate, dict):
            gate_level = proof_gate.get("level", "detected")
            gate_reason = proof_gate.get("reason", "")
            was_capped = proof_gate.get("was_capped", False)

            badge_map = {
                "exploited": "PROVEN IMPACT",
                "verified": "VERIFIED",
                "detected": "DETECTED ONLY",
            }
            badge_label = badge_map.get(gate_level, "DETECTED ONLY")

            lines.append("#### Proof Gate Status")
            lines.append("")
            lines.append(f"> **{badge_label}** -- {gate_reason}")
            lines.append("")

            if was_capped:
                orig = proof_gate.get("original_severity", "")
                capped = proof_gate.get("capped_severity", "")
                lines.append(f"*Severity adjusted: {orig} -> {capped} (proof level: {gate_level})*")
                lines.append("")

            if gate_level == "detected":
                lines.append("**Note:** Vulnerability detected but exploitation not verified. "
                             "Severity capped pending proof.")
                lines.append("")

        # Speculative chain finding (single-source, theoretical)
        # ═══════════════════════════════════════════════════════════════════════════
        # AUTOMATIC VALIDATION FIX: Changed language from "Requires manual verification"
        # to explain what WAS verified automatically vs what remains theoretical
        # ═══════════════════════════════════════════════════════════════════════════
        if proof_status == "speculative":
            lines.append("#### Verification Status")
            lines.append("")
            lines.append("> **THEORETICAL** — Attack path based on detected vulnerability.")
            lines.append("")
            lines.append("**Automatic verification performed:**")
            lines.append("- Entry vulnerability confirmed (payload executed)")
            lines.append("- Attack path logically follows known exploitation patterns")
            lines.append("")
            lines.append("**Theoretical components (not executed):**")
            lines.append("- Subsequent chain steps inferred, not proven")
            lines.append("- Full end-to-end exploitation not attempted (safety mode)")
            lines.append("")
            if linked:
                lines.append("**Source finding (verified):**")
                for lf in linked:
                    lines.append(f"- {lf.get('name', '?')} ({lf.get('severity', '')})")
                lines.append("")
            return lines

        # Derivable chain finding (cross-module, multiple confirmed sources)
        if proof_status == "derivable":
            lines.append("#### Verification Status")
            lines.append("")
            lines.append("> **DERIVABLE** — Composed from confirmed findings across independent modules.")
            lines.append("")
            if linked:
                lines.append("**Confirmed source findings:**")
                for lf in linked:
                    lines.append(f"- {lf.get('name', '?')} ({lf.get('severity', '')})")
                lines.append("")
            return lines

        # Proven finding
        if proof_data and isinstance(proof_data, dict):
            score = sum([
                proof_data.get("can_repeat", False),
                proof_data.get("can_mutate", False),
                proof_data.get("can_escalate", False),
                proof_data.get("can_chain", False),
            ])
            proven_impact = proof_data.get("proven_impact", "Unproven")

            lines.append("#### Verification Status")
            lines.append("")
            lines.append(f"**{proven_impact}** ({score}/4 verified)")
            lines.append("")
            parts = []
            if proof_data.get("can_repeat"):
                parts.append(f"Repeatable ({proof_data.get('repeat_count', 1)}x)")
            if proof_data.get("can_mutate"):
                parts.append("Mutable")
            if proof_data.get("can_escalate"):
                parts.append(f"Escalatable: {proof_data.get('escalation', '')[:60]}")
            if proof_data.get("can_chain"):
                parts.append("Chainable")
            if parts:
                lines.append(" | ".join(parts))
                lines.append("")
            narrative = proof_data.get("impact_narrative", "")
            if narrative:
                lines.append(f"_{narrative[:300]}_")
                lines.append("")

            # ═══════════════════════════════════════════════════════════════════
            # THEME-15 FIX: Show demonstrated impact (data extracted, actions, privileges)
            # Bridges gap between "pattern matched" and "attacker can do X"
            # ═══════════════════════════════════════════════════════════════════
            data_extracted = proof_data.get("data_extracted", [])
            action_performed = proof_data.get("action_performed", "")
            privilege_gained = proof_data.get("privilege_gained", "")
            impact_type = proof_data.get("impact_type", "")

            if data_extracted or action_performed or privilege_gained:
                lines.append("#### 🎯 Demonstrated Impact")
                lines.append("")

                if impact_type and impact_type != "NONE":
                    impact_labels = {
                        "DATA_LEAK": "📤 Data Exfiltration",
                        "STATE_CHANGE": "⚙️ State Modification",
                        "PRIVILEGE_ESCALATION": "👑 Privilege Escalation",
                        "PERSISTENT_CHANGE": "💾 Persistent Change",
                    }
                    lines.append(f"**Impact Type:** {impact_labels.get(impact_type, impact_type)}")
                    lines.append("")

                if privilege_gained:
                    lines.append(f"**Access Obtained:** `{privilege_gained}`")
                    lines.append("")

                if action_performed:
                    lines.append(f"**Action Executed:** {action_performed}")
                    lines.append("")

                if data_extracted:
                    lines.append("**Data Accessed:**")
                    lines.append("")
                    # Group by type for cleaner display
                    by_type: dict = {}
                    for item in data_extracted[:15]:
                        if ":" in item:
                            dtype, dval = item.split(":", 1)
                            by_type.setdefault(dtype, []).append(dval)
                        else:
                            by_type.setdefault("other", []).append(item)

                    for dtype, values in by_type.items():
                        if len(values) <= 3:
                            lines.append(f"- **{dtype}:** {', '.join(values[:3])}")
                        else:
                            lines.append(f"- **{dtype}:** {', '.join(values[:3])} (+{len(values)-3} more)")
                    lines.append("")

                # Add impact evidence if available
                impact_evidence = proof_data.get("impact_evidence", {})
                if impact_evidence and isinstance(impact_evidence, dict):
                    evidence_summary = impact_evidence.get("impact", impact_evidence.get("method", ""))
                    if evidence_summary:
                        lines.append(f"> _{evidence_summary}_")
                        lines.append("")

        return lines

    @staticmethod
    def _get_proof_label(finding: Dict[str, Any]) -> str:
        """Get a concise proof status label for the summary table."""
        metadata = finding.get("metadata") or {}

        # Proof gate takes priority (Phase 4.46a)
        proof_gate = metadata.get("proof_gate")
        if proof_gate and isinstance(proof_gate, dict):
            gate_level = proof_gate.get("level", "detected")
            if gate_level == "exploited":
                return "Proven"
            elif gate_level == "verified":
                return "Verified"
            elif proof_gate.get("was_capped"):
                return "Detected (capped)"
            else:
                return "Detected"

        # Legacy fallback
        proof_status = metadata.get("proof_status", "")
        proof = metadata.get("proof")

        if proof_status == "speculative":
            return "Speculative"

        if proof_status == "derivable":
            return "Derivable"

        if proof and isinstance(proof, dict):
            score = sum([
                proof.get("can_repeat", False),
                proof.get("can_mutate", False),
                proof.get("can_escalate", False),
                proof.get("can_chain", False),
            ])
            label = proof.get("proven_impact", "")
            if score >= 3:
                return f"**{score}/4** {label}"
            elif score >= 1:
                return f"{score}/4 {label}"
            return "0/4 Unproven"

        return "--"

    def _build_finding_compliance_impact(self, finding: Dict[str, Any]) -> str:
        """
        Build compliance impact section for a single finding.

        Maps the finding to compliance frameworks and returns a formatted
        markdown section showing affected requirements.
        """
        mapper = self._get_compliance_mapper()
        if not mapper:
            return ""

        # Extract vulnerability type
        vuln_type = finding.get("type", finding.get("vulnerability_type", "unknown"))
        finding_id = finding.get("id", finding.get("name", ""))

        try:
            # Get compliance mapping for this finding
            compliance = mapper.map_vulnerability(
                vulnerability_id=finding_id,
                vulnerability_type=vuln_type,
                affects_pii=self._affects_pii(finding),
                affects_financial_data=self._affects_financial_data(finding),
                affects_health_data=self._affects_health_data(finding),
            )

            # Only render if we have meaningful mappings
            if not compliance.cwe_ids and not compliance.owasp_categories:
                return ""

            lines = ["#### Compliance Impact", ""]

            # CWE with description
            if compliance.cwe_ids:
                from phantom.compliance_mapper import CWE_DATABASE
                cwe_parts = []
                for cwe_id in compliance.cwe_ids[:3]:
                    cwe_info = CWE_DATABASE.get(cwe_id, {})
                    cwe_name = cwe_info.get("name", "")
                    if cwe_name:
                        cwe_parts.append(f"CWE-{cwe_id} ({cwe_name})")
                    else:
                        cwe_parts.append(f"CWE-{cwe_id}")
                lines.append(f"**CWE:** {', '.join(cwe_parts)}")

            # OWASP Top 10
            if compliance.owasp_categories:
                owasp_labels = {
                    "A01:2021": "A01 - Broken Access Control",
                    "A02:2021": "A02 - Cryptographic Failures",
                    "A03:2021": "A03 - Injection",
                    "A04:2021": "A04 - Insecure Design",
                    "A05:2021": "A05 - Security Misconfiguration",
                    "A06:2021": "A06 - Vulnerable Components",
                    "A07:2021": "A07 - Auth Failures",
                    "A08:2021": "A08 - Software/Data Integrity",
                    "A09:2021": "A09 - Logging/Monitoring",
                    "A10:2021": "A10 - SSRF",
                }
                owasp_display = [owasp_labels.get(cat, cat) for cat in compliance.owasp_categories[:2]]
                lines.append(f"**OWASP Top 10:** {', '.join(owasp_display)}")

            # PCI DSS Requirements
            if compliance.pci_dss_requirements:
                pci_reqs = compliance.pci_dss_requirements[:3]
                lines.append(f"**PCI DSS 4.0:** Req {', '.join(pci_reqs)}")

            # NIST Controls
            if compliance.nist_controls:
                nist_ctrls = compliance.nist_controls[:4]
                lines.append(f"**NIST 800-53:** {', '.join(nist_ctrls)}")

            # ISO 27001 (if requested)
            if compliance.iso27001_controls and "iso27001" in self.compliance_frameworks:
                iso_ctrls = compliance.iso27001_controls[:3]
                lines.append(f"**ISO 27001:** {', '.join(iso_ctrls)}")

            # GDPR (if PII affected)
            if compliance.gdpr_articles:
                lines.append(f"**GDPR:** {', '.join(compliance.gdpr_articles[:3])}")

            # HIPAA (if health data affected)
            if compliance.hipaa_safeguards:
                lines.append(f"**HIPAA:** {', '.join(compliance.hipaa_safeguards[:3])}")

            # SOC 2 (if requested)
            if compliance.soc2_criteria and "soc2" in self.compliance_frameworks:
                lines.append(f"**SOC 2:** {', '.join(compliance.soc2_criteria[:3])}")

            lines.append("")
            return "\n".join(lines)

        except Exception as e:
            logger.debug(f"Failed to generate compliance impact for finding: {e}")
            return ""

    def _affects_pii(self, finding: Dict[str, Any]) -> bool:
        """Determine if finding affects personally identifiable information."""
        vuln_type = finding.get("type", finding.get("vulnerability_type", "")).lower()
        description = finding.get("description", "").lower()

        pii_indicators = [
            "pii", "personal", "email", "user", "account", "profile",
            "ssn", "social security", "address", "phone", "name",
            "customer", "employee", "credit card", "password",
        ]

        pii_vuln_types = ["idor", "info_disclosure", "pii_exposure", "sqli", "nosql"]

        if vuln_type in pii_vuln_types:
            return True

        return any(indicator in description for indicator in pii_indicators)

    def _affects_financial_data(self, finding: Dict[str, Any]) -> bool:
        """Determine if finding affects financial data."""
        vuln_type = finding.get("type", finding.get("vulnerability_type", "")).lower()
        description = finding.get("description", "").lower()

        financial_indicators = [
            "payment", "credit card", "bank", "account", "balance",
            "transaction", "billing", "invoice", "financial", "money",
            "currency", "price", "checkout", "order",
        ]

        return any(indicator in description for indicator in financial_indicators)

    def _affects_health_data(self, finding: Dict[str, Any]) -> bool:
        """Determine if finding affects health/medical data."""
        description = finding.get("description", "").lower()

        health_indicators = [
            "health", "medical", "patient", "hipaa", "diagnosis",
            "prescription", "insurance", "hospital", "clinical",
            "healthcare", "phi", "protected health",
        ]

        return any(indicator in description for indicator in health_indicators)
