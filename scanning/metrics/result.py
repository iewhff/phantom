"""
Scan Result - Main result dataclass with metrics.

Contains:
- ScanResult: Comprehensive scan result with all metrics fields
- SEVERITY_TO_CONFIDENCE: Mapping for confidence normalization
- normalize_confidence: Convert severity/numeric to float confidence

Extracted from full_scanner.py for modularization.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional, Union

logger = logging.getLogger("phantom")


# Centralized severity-to-confidence mapping
# Eliminates duplicate mappings across codebase
SEVERITY_TO_CONFIDENCE: dict[str, float] = {
    "critical": 95.0,
    "high": 85.0,
    "medium": 65.0,
    "low": 40.0,
    "info": 20.0,
}


def normalize_confidence(value: Union[str, int, float, None]) -> float:
    """Normalize confidence value to float 0-100.

    Handles both numeric and string (severity-based) values.
    Used by dedup, chain analysis, and other components that need
    consistent confidence comparison.

    Args:
        value: Confidence as number or severity string

    Returns:
        Float confidence value 0-100
    """
    if value is None:
        return 50.0  # Default to medium
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        return SEVERITY_TO_CONFIDENCE.get(value.lower(), 50.0)
    return 50.0


@dataclass
class ScanResult:
    """Result of a full security scan.

    Contains all findings, errors, and comprehensive metrics
    from a scanning session.
    """
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None
    findings: list[dict] = field(default_factory=list)
    info: list[dict] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)
    modules_run: list[str] = field(default_factory=list)
    modules_requested: list[str] = field(default_factory=list)
    safe_mode: str = "safe"

    # Intelligent scanning metrics
    intelligent_mode: bool = False
    tests_skipped: int = 0
    modules_skipped: list[str] = field(default_factory=list)
    modules_not_executed: list[str] = field(default_factory=list)
    skip_reasons: dict = field(default_factory=dict)
    target_classification: str = "unknown"
    target_type_code: str = "unknown"
    classification_confidence: float = 0.0
    scope_violations: int = 0
    negative_control_validations: int = 0
    parameters_analyzed: int = 0
    endpoints_discovered: int = 0

    # Vulnerability chain metrics
    chain_findings: int = 0
    chains_triggered: int = 0
    escalations_attempted: int = 0

    # WAF/OPSEC metrics
    waf_detected: bool = False
    waf_type: str = ""
    rate_limited: bool = False
    circuit_breaker_triggered: int = 0
    total_requests_sent: int = 0

    # Coverage awareness metrics (meta-vision)
    coverage_percentage: float = 0.0
    high_value_gaps: int = 0
    skip_reasons_summary: dict = field(default_factory=dict)

    # Error tracking metrics (visibility for failures)
    total_module_errors: int = 0
    modules_with_errors: int = 0
    error_rate_overall: float = 0.0
    error_summary_by_module: dict = field(default_factory=dict)

    # Uncertainty tracking metrics
    findings_with_high_uncertainty: int = 0
    proofs_not_attempted: int = 0
    validation_uncertainty_avg: float = 0.0
    uncertainty_reasons_summary: dict = field(default_factory=dict)

    # Auditability tracking
    findings_suppressed: int = 0
    chains_suppressed: int = 0
    proofs_skipped: int = 0
    suppression_audit: list = field(default_factory=list)
    unproven_findings: list = field(default_factory=list)
    validation_stage_breakdown: dict = field(default_factory=dict)

    def add_finding(self, finding: Any) -> None:
        """Add a finding (supports dict or Finding dataclass).

        Args:
            finding: Finding as dict, dataclass, or other convertible type
        """
        # Convert Finding dataclass to dict if needed
        if hasattr(finding, "to_dict"):
            finding_dict = finding.to_dict()
        elif hasattr(finding, "__dataclass_fields__"):
            from dataclasses import asdict
            finding_dict = asdict(finding)
        elif isinstance(finding, dict):
            finding_dict = finding
        else:
            # Try to convert to dict
            try:
                finding_dict = dict(finding)
            except Exception:
                finding_dict = {"raw": str(finding)}

        if isinstance(finding_dict, dict):
            finding_dict["discovered_at"] = datetime.now().isoformat()
        self.findings.append(finding_dict)

    @property
    def duration_seconds(self) -> float:
        """Calculate scan duration in seconds."""
        if self.end_time and self.start_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0

    @property
    def findings_by_severity(self) -> dict[str, int]:
        """Get finding counts by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            if isinstance(f, dict):
                sev = f.get("severity", "").lower()
                if sev in counts:
                    counts[sev] += 1
        return counts

    @property
    def action_summary(self) -> dict[str, int]:
        """Get action-oriented summary (fix now, fix next sprint, etc.)."""
        by_sev = self.findings_by_severity
        return {
            "fix_now": by_sev["critical"] + by_sev["high"],
            "fix_next_sprint": by_sev["medium"],
            "fix_when_convenient": by_sev["low"],
        }

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        # Generate threat model for business context
        threat_report = None
        if self.findings:
            try:
                from utils.threat_model import generate_threat_report
                threat_report = generate_threat_report(self.findings)
            except Exception as e:
                logger.debug(f"Threat report generation failed: {e}")
                threat_report = None

        by_sev = self.findings_by_severity
        action = self.action_summary

        result = {
            # Methodology & Branding
            "report_metadata": {
                "methodology": "Cloud-First Security Review (CFSR) v2.0",
                "phases": ["Discover", "Classify", "Scan", "Analyze", "Report"],
                "framework": "PetNTester AI Enterprise",
                "version": "2.0.0",
                "generated_at": datetime.now().isoformat(),
            },

            # Scope Definition
            "scope": {
                "target": self.target,
                "what_was_tested": [
                    "Security headers analysis",
                    "SSL/TLS configuration",
                    "CORS policy validation",
                    "DOM-based XSS detection",
                ] + ([f"Module: {m}" for m in self.modules_run[:5]]),
                "what_was_not_tested": [
                    "Authenticated endpoints (no credentials provided)",
                    "Business logic vulnerabilities",
                    "Rate limiting effectiveness",
                    "WAF bypass techniques",
                    "Social engineering vectors",
                ] + ([f"Not executed: {m}" for m in self.modules_not_executed[:5]]),
                "limitations": [
                    "Non-destructive testing only (Safe Mode)",
                    "No access to source code",
                    "No access to internal network",
                    "Point-in-time assessment",
                ],
                "authorization": "Scan performed with --no-auth flag (educational/authorized use)",
            },

            "target": self.target,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds,
            "findings": self.findings,
            "info": self.info,
            "errors": self.errors,
            "modules_run": self.modules_run,
            "safe_mode": self.safe_mode,
            "intelligent_mode": self.intelligent_mode,

            "summary": {
                "total_findings": len(self.findings),
                "critical": by_sev["critical"],
                "high": by_sev["high"],
                "medium": by_sev["medium"],
                "low": by_sev["low"],
                "fix_now": action["fix_now"],
                "fix_next_sprint": action["fix_next_sprint"],
                "fix_when_convenient": action["fix_when_convenient"],
            },

            "classification": {
                "target_type": self.target_classification,
                "target_type_code": self.target_type_code,
                "confidence": self.classification_confidence,
                "modules_recommended_skip": self.modules_skipped,
                "modules_not_executed": self.modules_not_executed,
                "skip_reasons": self.skip_reasons,
            },

            "intelligent_metrics": {
                "tests_skipped": self.tests_skipped,
                "scope_violations": self.scope_violations,
                "negative_control_validations": self.negative_control_validations,
                "parameters_analyzed": self.parameters_analyzed,
                "endpoints_discovered": self.endpoints_discovered,
            },

            "chain_metrics": {
                "chain_findings": self.chain_findings,
                "chains_triggered": self.chains_triggered,
                "escalations_attempted": self.escalations_attempted,
            },

            "coverage_awareness": {
                "coverage_percentage": self.coverage_percentage,
                "high_value_gaps": self.high_value_gaps,
                "skip_reasons_summary": self.skip_reasons_summary,
            },

            "error_tracking": {
                "total_module_errors": self.total_module_errors,
                "modules_with_errors": self.modules_with_errors,
                "error_rate_overall": self.error_rate_overall,
                "error_summary_by_module": self.error_summary_by_module,
            },

            "uncertainty_tracking": {
                "findings_with_high_uncertainty": self.findings_with_high_uncertainty,
                "proofs_not_attempted": self.proofs_not_attempted,
                "validation_uncertainty_avg": self.validation_uncertainty_avg,
                "uncertainty_reasons_summary": self.uncertainty_reasons_summary,
            },

            "auditability": {
                "findings_suppressed": self.findings_suppressed,
                "chains_suppressed": self.chains_suppressed,
                "proofs_skipped": self.proofs_skipped,
                "suppression_audit": self.suppression_audit[:10],  # Limit for readability
                "unproven_findings": self.unproven_findings[:10],
                "validation_stage_breakdown": self.validation_stage_breakdown,
            },

            "waf_opsec": {
                "waf_detected": self.waf_detected,
                "waf_type": self.waf_type,
                "rate_limited": self.rate_limited,
                "circuit_breaker_triggered": self.circuit_breaker_triggered,
                "total_requests_sent": self.total_requests_sent,
            },
        }

        # Add threat model if generated
        if threat_report:
            result["threat_model"] = threat_report

        return result
