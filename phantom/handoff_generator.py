"""
PHANTOM AI - Handoff Session Generator

Generates a comprehensive handoff document that aggregates all findings,
evidence, and artifacts from a scan session into a single deliverable
for triagers, developers, or security team leads.

The handoff document enables someone who was NOT involved in the scan
to fully understand the context, reproduce the findings, and act on them.

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

logger = logging.getLogger(__name__)


# Severity ordering for sort
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class HandoffSession:
    """Complete handoff session document."""

    target: str
    scan_id: str
    date: str
    safety_mode: str
    modules_run: int
    duration_seconds: float
    operator: str

    # Content sections
    executive_summary: str
    findings_table: str
    risk_matrix: str
    detailed_findings: str
    remediation_roadmap: str
    artifacts_index: str
    handoff_checklist: str

    # Raw data
    findings: List[Dict[str, Any]] = field(default_factory=list)
    artifact_paths: List[Dict[str, str]] = field(default_factory=list)

    def to_markdown(self) -> str:
        """Render the full handoff document as markdown."""
        duration_min = self.duration_seconds / 60 if self.duration_seconds else 0

        md = []
        md.append(f"# Security Assessment Handoff — {self.target}")
        md.append("")

        # Session metadata
        md.append("## Session Metadata")
        md.append("")
        md.append("| Field | Value |")
        md.append("|-------|-------|")
        md.append(f"| Target | `{self.target}` |")
        md.append(f"| Scan ID | `{self.scan_id}` |")
        md.append(f"| Date | {self.date} |")
        md.append(f"| Safety Mode | `{self.safety_mode}` |")
        md.append(f"| Modules Run | {self.modules_run} |")
        md.append(f"| Duration | {duration_min:.1f} min |")
        md.append(f"| Operator | {self.operator} |")
        md.append("")

        # Executive summary
        md.append("## Executive Summary")
        md.append("")
        md.append(self.executive_summary)
        md.append("")

        # Findings overview table
        md.append("## Findings Overview")
        md.append("")
        md.append(self.findings_table)
        md.append("")

        # Risk matrix
        md.append("## Risk Matrix")
        md.append("")
        md.append(self.risk_matrix)
        md.append("")

        # Detailed findings
        md.append("## Detailed Findings")
        md.append("")
        md.append(self.detailed_findings)
        md.append("")

        # Remediation roadmap
        md.append("## Remediation Roadmap")
        md.append("")
        md.append(self.remediation_roadmap)
        md.append("")

        # Artifacts index
        md.append("## Artifacts Index")
        md.append("")
        md.append(self.artifacts_index)
        md.append("")

        # Handoff checklist
        md.append("## Handoff Checklist")
        md.append("")
        md.append(self.handoff_checklist)
        md.append("")

        return "\n".join(md)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict for JSON export."""
        return {
            "target": self.target,
            "scan_id": self.scan_id,
            "date": self.date,
            "safety_mode": self.safety_mode,
            "modules_run": self.modules_run,
            "duration_seconds": self.duration_seconds,
            "operator": self.operator,
            "findings_count": len(self.findings),
            "findings": self.findings,
            "artifact_paths": self.artifact_paths,
        }


class HandoffSessionGenerator:
    """
    Generates a comprehensive handoff session document.

    Usage:
        generator = HandoffSessionGenerator(output_dir=Path("evidence/target"))
        session = generator.generate(
            target="https://api.example.com",
            scan_id="PHANTOM_20260205",
            findings=[...],
            scan_metadata={...},
        )
        generator.save(session)
    """

    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = output_dir or Path("evidence")

    def generate(
        self,
        target: str,
        scan_id: str,
        findings: List[Dict[str, Any]],
        scan_metadata: Optional[Dict[str, Any]] = None,
        artifact_paths: Optional[List[Dict[str, str]]] = None,
    ) -> HandoffSession:
        """Generate a complete handoff session."""
        meta = scan_metadata or {}
        findings_sorted = sorted(
            findings,
            key=lambda f: _SEVERITY_ORDER.get(
                self._get_severity(f).lower(), 5
            ),
        )

        return HandoffSession(
            target=target,
            scan_id=scan_id,
            date=meta.get("date", datetime.now().strftime("%Y-%m-%d %H:%M")),
            safety_mode=meta.get("safety_mode", "safe"),
            modules_run=meta.get("modules_run", 0),
            duration_seconds=meta.get("duration_seconds", 0),
            operator=meta.get("operator", "phantom-ai"),
            executive_summary=self._build_executive_summary(
                target, findings_sorted
            ),
            findings_table=self._build_findings_table(findings_sorted),
            risk_matrix=self._build_risk_matrix(findings_sorted),
            detailed_findings=self._build_detailed_findings(findings_sorted),
            remediation_roadmap=self._build_remediation_roadmap(
                findings_sorted
            ),
            artifacts_index=self._build_artifacts_index(
                artifact_paths or []
            ),
            handoff_checklist=self._build_handoff_checklist(findings_sorted),
            findings=findings_sorted,
            artifact_paths=artifact_paths or [],
        )

    def save(
        self,
        session: HandoffSession,
        formats: Optional[List[str]] = None,
    ) -> Dict[str, str]:
        """Save the handoff session to disk."""
        if formats is None:
            formats = ["md", "json"]

        self.output_dir.mkdir(parents=True, exist_ok=True)
        saved = {}

        if "md" in formats:
            md_path = self.output_dir / "HANDOFF.md"
            md_path.write_text(session.to_markdown())
            saved["md"] = str(md_path)

        if "json" in formats:
            json_path = self.output_dir / "handoff_data.json"
            json_path.write_text(json.dumps(session.to_dict(), indent=2))
            saved["json"] = str(json_path)

        # Also generate MANIFEST.json
        manifest = {
            "scan_id": session.scan_id,
            "target": session.target,
            "generated_at": datetime.now().isoformat(),
            "artifacts": session.artifact_paths,
            "handoff_files": saved,
        }
        manifest_path = self.output_dir / "MANIFEST.json"
        manifest_path.write_text(json.dumps(manifest, indent=2))
        saved["manifest"] = str(manifest_path)

        logger.info(f"Handoff session saved to {self.output_dir}")
        return saved

    # ------------------------------------------------------------------
    # Private builders
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

    def _get_title(self, finding: Dict[str, Any]) -> str:
        if isinstance(finding, dict) and "finding" in finding:
            finding = finding["finding"]
        return (
            finding.get("name", "")
            or finding.get("title", "")
            or finding.get("type", "Unknown")
        )

    def _get_cvss(self, finding: Dict[str, Any]) -> float:
        if isinstance(finding, dict) and "finding" in finding:
            finding = finding["finding"]
        return float(finding.get("cvss_score", 0) or 0)

    def _get_cwe(self, finding: Dict[str, Any]) -> str:
        if isinstance(finding, dict) and "finding" in finding:
            finding = finding["finding"]
        return finding.get("cwe", "")

    def _get_host(self, finding: Dict[str, Any]) -> str:
        if isinstance(finding, dict) and "finding" in finding:
            finding = finding["finding"]
        return finding.get("host", "") or finding.get("url", "")

    def _build_executive_summary(
        self, target: str, findings: List[Dict[str, Any]]
    ) -> str:
        """Build a business-focused executive summary."""
        sev_counts: Dict[str, int] = {}
        for f in findings:
            sev = self._get_severity(f).upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        total = len(findings)
        critical = sev_counts.get("CRITICAL", 0)
        high = sev_counts.get("HIGH", 0)

        # Risk rating
        if critical > 0:
            risk = "CRITICAL"
            urgency = "Immediate action required."
        elif high > 0:
            risk = "HIGH"
            urgency = "Prompt remediation recommended."
        elif total > 0:
            risk = "MODERATE"
            urgency = "Remediation should be planned."
        else:
            risk = "LOW"
            urgency = "No significant vulnerabilities found."

        parts = []
        parts.append(
            f"A security assessment of **{target}** identified "
            f"**{total} finding(s)** across the following severity levels:"
        )
        parts.append("")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = sev_counts.get(sev, 0)
            if count > 0:
                parts.append(f"- **{sev}:** {count}")
        parts.append("")
        parts.append(f"**Overall Risk Rating:** {risk}")
        parts.append(f"**Recommendation:** {urgency}")

        return "\n".join(parts)

    def _build_findings_table(
        self, findings: List[Dict[str, Any]]
    ) -> str:
        """Build markdown table of all findings."""
        lines = [
            "| # | Finding | Severity | CVSS | CWE | Host |",
            "|---|---------|----------|------|-----|------|",
        ]
        for i, f in enumerate(findings, 1):
            title = self._get_title(f)
            sev = self._get_severity(f).upper()
            cvss = self._get_cvss(f)
            cwe = self._get_cwe(f)
            host = self._get_host(f)
            lines.append(
                f"| {i} | {title} | **{sev}** | {cvss} | {cwe} | `{host}` |"
            )
        return "\n".join(lines)

    def _build_risk_matrix(
        self, findings: List[Dict[str, Any]]
    ) -> str:
        """Build a text-based risk matrix."""
        sev_counts: Dict[str, int] = {}
        for f in findings:
            sev = self._get_severity(f).upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        max_bar = max(sev_counts.values()) if sev_counts else 1
        lines = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = sev_counts.get(sev, 0)
            bar_len = int((count / max_bar) * 20) if max_bar else 0
            bar = "#" * bar_len
            lines.append(f"| {sev:8s} | {'#' * bar_len:20s} | {count} |")

        return (
            "```\n"
            + "| Severity | Distribution           | Count |\n"
            + "|----------|------------------------|-------|\n"
            + "\n".join(lines)
            + "\n```"
        )

    def _build_detailed_findings(
        self, findings: List[Dict[str, Any]]
    ) -> str:
        """Build detailed section with inline summary for each finding."""
        sections = []
        for i, f in enumerate(findings, 1):
            raw = f["finding"] if isinstance(f, dict) and "finding" in f else f
            title = self._get_title(f)
            sev = self._get_severity(f).upper()
            cvss = self._get_cvss(f)
            cwe = self._get_cwe(f)
            desc = raw.get("description", "")
            remediation = raw.get("remediation", "")
            host = self._get_host(f)
            evidence = raw.get("evidence", [])

            section = [f"### {i}. {title}"]
            section.append("")
            section.append(f"**Severity:** {sev} | **CVSS:** {cvss} | **CWE:** {cwe}")
            section.append(f"**Host:** `{host}`")
            section.append("")
            if desc:
                section.append(desc[:500])
                section.append("")
            if evidence:
                section.append("**Key Evidence:**")
                for ev_item in evidence[:5]:
                    section.append(f"- `{ev_item}`")
                section.append("")
            if remediation:
                section.append(f"**Fix:** {remediation[:300]}")
                section.append("")

            sections.append("\n".join(section))

        return "\n---\n\n".join(sections)

    def _build_remediation_roadmap(
        self, findings: List[Dict[str, Any]]
    ) -> str:
        """Build prioritized remediation plan."""
        lines = [
            "| Priority | Finding | Effort | Impact |",
            "|----------|---------|--------|--------|",
        ]
        effort_map = {
            "CRITICAL": "Urgent",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
            "INFO": "Informational",
        }
        impact_map = {
            "CRITICAL": "Data breach / full compromise",
            "HIGH": "Sensitive data exposure",
            "MEDIUM": "Limited data exposure",
            "LOW": "Minor information leak",
            "INFO": "Best practice improvement",
        }

        for i, f in enumerate(findings, 1):
            title = self._get_title(f)
            sev = self._get_severity(f).upper()
            effort = effort_map.get(sev, "—")
            impact = impact_map.get(sev, "—")
            lines.append(f"| P{i} | {title} | {effort} | {impact} |")

        return "\n".join(lines)

    def _build_artifacts_index(
        self, artifact_paths: List[Dict[str, str]]
    ) -> str:
        """Build table of all generated artifacts."""
        if not artifact_paths:
            return "*No artifacts tracked for this session.*"

        lines = [
            "| Artifact | Path | Type |",
            "|----------|------|------|",
        ]
        for art in artifact_paths:
            name = art.get("name", "—")
            path = art.get("path", "—")
            art_type = art.get("type", "—")
            lines.append(f"| {name} | `{path}` | {art_type} |")

        return "\n".join(lines)

    def _build_handoff_checklist(
        self, findings: List[Dict[str, Any]]
    ) -> str:
        """Build handoff readiness checklist."""
        n = len(findings)
        items = [
            f"- [ ] All {n} finding(s) documented with evidence",
            "- [ ] All curl commands verified manually",
            "- [ ] PoC files tested in browser",
            "- [ ] Remediation steps reviewed for accuracy",
            "- [ ] Report reviewed for sensitive data redaction",
            "- [ ] Scope boundaries respected (no out-of-scope testing)",
            "- [ ] Handoff document shared with receiving party",
        ]
        return "\n".join(items)
