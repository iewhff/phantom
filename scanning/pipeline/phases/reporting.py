"""
Reporting Phase - Metrics Collection and Report Generation.

This phase handles:
- Phase 6: Finalize scan results
- Phase 6.5: Coverage and explosion metrics
- Report generation (HackerOne, Client, SARIF)

Author: PHANTOM AI
Version: 2.0.0
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional

from scanning.pipeline.base import Phase, PhaseResult, PhaseStatus, ScanContext
from utils.logger import get_logger

if TYPE_CHECKING:
    pass

logger = get_logger(__name__)


@dataclass
class ReportingConfig:
    """Configuration for reporting phase."""

    generate_hackerone: bool = False
    generate_client_report: bool = False
    generate_sarif: bool = False
    include_coverage_metrics: bool = True
    include_error_stats: bool = True
    include_auth_usage: bool = True
    output_dir: str = "./reports"


class ReportingPhase(Phase):
    """
    Reporting phase for metrics and report generation.

    Consolidates:
    - Phase 6: Finalize intelligent scan
    - Phase 6.5: Coverage and explosion metrics
    - Report generation
    """

    def __init__(self, config: Optional[ReportingConfig] = None):
        super().__init__("ReportingPhase")
        self.config = config or ReportingConfig()

    async def execute(self, context: ScanContext) -> PhaseResult:
        """Execute reporting phase."""
        reports_generated = []

        try:
            logger.info(f"[Reporting] Generating reports for {len(context.findings)} findings")

            # Collect metrics
            metrics = await self._collect_metrics(context)
            context.metadata["scan_metrics"] = metrics

            # Phase 6.5: Coverage metrics
            if self.config.include_coverage_metrics:
                coverage = self._collect_coverage_metrics(context)
                context.metadata["coverage_metrics"] = coverage

            # Phase 6.5: Error stats
            if self.config.include_error_stats:
                errors = self._collect_error_stats(context)
                context.metadata["error_stats"] = errors

            # Phase 6.5: Auth usage
            if self.config.include_auth_usage:
                auth_usage = self._collect_auth_usage(context)
                context.metadata["auth_usage"] = auth_usage

            # Generate reports
            if self.config.generate_hackerone:
                path = await self._generate_hackerone_report(context)
                if path:
                    reports_generated.append(("hackerone", path))

            if self.config.generate_client_report:
                path = await self._generate_client_report(context)
                if path:
                    reports_generated.append(("client", path))

            if self.config.generate_sarif:
                path = await self._generate_sarif_report(context)
                if path:
                    reports_generated.append(("sarif", path))

            logger.info(f"[Reporting] Complete: {len(reports_generated)} reports generated")

            return PhaseResult(
                phase_name=self.name,
                status=PhaseStatus.COMPLETED,
                findings_count=len(context.findings),
                data={
                    "reports_generated": reports_generated,
                    "metrics": metrics,
                },
            )

        except Exception as e:
            logger.error(f"[Reporting] Failed: {e}")
            return PhaseResult(
                phase_name=self.name,
                status=PhaseStatus.FAILED,
                error_message=str(e),
            )

    async def _collect_metrics(self, context: ScanContext) -> dict[str, Any]:
        """Collect scan metrics."""
        findings = context.findings

        # Count by severity
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = (
                getattr(f, "severity", "MEDIUM")
                if hasattr(f, "severity")
                else f.get("severity", "MEDIUM") if isinstance(f, dict)
                else "MEDIUM"
            )
            if sev in severity_counts:
                severity_counts[sev] += 1

        return {
            "total_findings": len(findings),
            "by_severity": severity_counts,
            "endpoints_tested": len(context.endpoints),
            "authenticated": context.is_authenticated,
            "tech_stack": context.tech_stack,
            "waf_detected": context.waf_detected,
            "scan_id": context.scan_id,
        }

    def _collect_coverage_metrics(self, context: ScanContext) -> dict[str, Any]:
        """Collect coverage transparency metrics."""
        try:
            from scanning.coverage_tracker import get_coverage_tracker

            tracker = get_coverage_tracker()
            if tracker:
                return tracker.to_dict()
            return {}
        except Exception:
            return {}

    def _collect_error_stats(self, context: ScanContext) -> dict[str, Any]:
        """Collect module error statistics."""
        error_stats = context.metadata.get("module_error_stats", {})

        if not error_stats:
            return {"total_errors": 0, "modules_with_errors": 0}

        total_errors = sum(m.get("requests_failed", 0) for m in error_stats.values())
        total_requests = sum(m.get("requests_total", 0) for m in error_stats.values())
        modules_with_errors = len(error_stats)

        return {
            "total_errors": total_errors,
            "total_requests": total_requests,
            "modules_with_errors": modules_with_errors,
            "error_rate": (total_errors / total_requests * 100) if total_requests > 0 else 0,
            "by_module": {
                name: data.get("error_summary", {})
                for name, data in error_stats.items()
            },
        }

    def _collect_auth_usage(self, context: ScanContext) -> dict[str, Any]:
        """Collect auth context usage information."""
        return {
            "authenticated": context.is_authenticated,
            "auth_method": context.metadata.get("auth_context", {}).get("method", "none"),
            "has_multi_user": bool(context.metadata.get("user_personas")),
        }

    async def _generate_hackerone_report(self, context: ScanContext) -> Optional[str]:
        """Generate HackerOne-format report."""
        try:
            from phantom.hackerone_report_generator import HackerOneReportGenerator

            generator = HackerOneReportGenerator()
            path = await generator.generate(
                findings=context.findings,
                target=context.target_url,
                output_dir=self.config.output_dir,
            )
            logger.info(f"[HackerOne] Report generated: {path}")
            return path

        except ImportError:
            logger.debug("[Reporting] HackerOneReportGenerator not available")
            return None
        except Exception as e:
            logger.warning(f"[HackerOne] Report generation failed: {e}")
            return None

    async def _generate_client_report(self, context: ScanContext) -> Optional[str]:
        """Generate client pentest report."""
        try:
            from phantom.client_report_generator import ClientReportGenerator

            generator = ClientReportGenerator()
            path = await generator.generate(
                findings=context.findings,
                target=context.target_url,
                metrics=context.metadata.get("scan_metrics", {}),
                output_dir=self.config.output_dir,
            )
            logger.info(f"[ClientReport] Report generated: {path}")
            return path

        except ImportError:
            logger.debug("[Reporting] ClientReportGenerator not available")
            return None
        except Exception as e:
            logger.warning(f"[ClientReport] Report generation failed: {e}")
            return None

    async def _generate_sarif_report(self, context: ScanContext) -> Optional[str]:
        """Generate SARIF-format report."""
        try:
            from reporting.report_generator import ReportGenerator

            generator = ReportGenerator()
            path = generator.generate_sarif(
                findings=context.findings,
                target=context.target_url,
                output_dir=self.config.output_dir,
            )
            logger.info(f"[SARIF] Report generated: {path}")
            return path

        except ImportError:
            logger.debug("[Reporting] ReportGenerator not available")
            return None
        except Exception as e:
            logger.warning(f"[SARIF] Report generation failed: {e}")
            return None
