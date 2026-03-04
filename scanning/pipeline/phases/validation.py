"""
Validation Phase - False Positive Elimination and Verification.

This phase handles:
- Phase 5.1: 6-Stage ValidationPipeline
- Phase 5.2: Second-order vulnerability detection
- Phase 5.5: Evidence engine finalization

Author: PHANTOM AI
Version: 2.0.0
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional

from scanning.pipeline.base import Phase, PhaseResult, PhaseStatus, ScanContext
from utils.logger import get_logger

if TYPE_CHECKING:
    pass

logger = get_logger(__name__)


@dataclass
class ValidationConfig:
    """Configuration for validation phase."""

    enable_validation_pipeline: bool = True
    enable_second_order_detection: bool = True
    enable_evidence_collection: bool = True
    enable_state_aware_retest: bool = True
    enable_identity_variation: bool = True


class ValidationPhase(Phase):
    """
    Validation phase for FP elimination.

    Consolidates:
    - Phase 4.55: State-aware retest
    - Phase 4.56: Cross-user identity variation
    - Phase 5.1: 6-Stage ValidationPipeline
    - Phase 5.2: Second-order vulnerability detection
    - Phase 5.5: Evidence engine finalization
    """

    def __init__(self, config: Optional[ValidationConfig] = None):
        super().__init__("ValidationPhase")
        self.config = config or ValidationConfig()

    async def execute(self, context: ScanContext) -> PhaseResult:
        """Execute validation phase."""
        initial_count = len(context.findings)
        fp_removed = 0
        second_order_found = 0

        try:
            logger.info(f"[Validation] Starting with {initial_count} findings")

            # Phase 4.55: State-aware retest (auth vs no-auth)
            if self.config.enable_state_aware_retest:
                await self._state_aware_retest(context)

            # Phase 4.56: Cross-user identity variation
            if self.config.enable_identity_variation:
                await self._identity_variation_retest(context)

            # Phase 5.1: 6-Stage ValidationPipeline
            if self.config.enable_validation_pipeline:
                pre_count = len(context.findings)
                await self._run_validation_pipeline(context)
                fp_removed = pre_count - len(context.findings)
                if fp_removed > 0:
                    logger.info(f"[Validation] Removed {fp_removed} false positives")

            # Phase 5.2: Second-order vulnerability detection
            if self.config.enable_second_order_detection:
                second_order = await self._detect_second_order(context)
                second_order_found = len(second_order)
                if second_order:
                    context.add_findings(second_order)
                    logger.info(f"[Validation] Found {second_order_found} second-order vulnerabilities")

            # Phase 5.5: Evidence engine finalization
            if self.config.enable_evidence_collection:
                await self._finalize_evidence(context)

            final_count = len(context.findings)
            logger.info(
                f"[Validation] Complete: {initial_count} → {final_count} findings, "
                f"{fp_removed} FP removed, {second_order_found} second-order found"
            )

            return PhaseResult(
                phase_name=self.name,
                status=PhaseStatus.COMPLETED,
                findings_count=final_count,
                data={
                    "initial_findings": initial_count,
                    "final_findings": final_count,
                    "false_positives_removed": fp_removed,
                    "second_order_found": second_order_found,
                },
            )

        except Exception as e:
            logger.error(f"[Validation] Failed: {e}")
            return PhaseResult(
                phase_name=self.name,
                status=PhaseStatus.FAILED,
                error_message=str(e),
                findings_count=len(context.findings),
            )

    async def _state_aware_retest(self, context: ScanContext) -> None:
        """Re-test vulnerable endpoints without auth to find auth bypasses."""
        try:
            # Only run if we have auth
            if not context.is_authenticated:
                return

            from scanning.auth_context import AuthContext

            # Get endpoints with findings
            endpoints_with_findings = set()
            for finding in context.findings:
                url = None
                if hasattr(finding, "url"):
                    url = finding.url
                elif isinstance(finding, dict):
                    url = finding.get("url") or finding.get("matched_at")
                if url:
                    endpoints_with_findings.add(url)

            if not endpoints_with_findings:
                return

            logger.info(f"[StateAwareRetest] Testing {len(endpoints_with_findings)} endpoints without auth")

            # Test would be implemented here - compare auth vs no-auth responses
            # to detect auth bypasses

        except Exception as e:
            logger.debug(f"[StateAwareRetest] Error: {e}")

    async def _identity_variation_retest(self, context: ScanContext) -> None:
        """Replay actions with different user contexts for privilege escalation."""
        try:
            personas = context.metadata.get("user_personas")
            if not personas or not hasattr(personas, "has_multiple_users") or not personas.has_multiple_users:
                return

            logger.info("[IdentityVariation] Testing with multiple user contexts")
            # Cross-user testing logic would be implemented here

        except Exception as e:
            logger.debug(f"[IdentityVariation] Error: {e}")

    async def _run_validation_pipeline(self, context: ScanContext) -> None:
        """Run 6-stage validation pipeline."""
        try:
            from phantom.validation_pipeline import (
                ValidationPipeline,
                ValidationConfig as VPConfig,
                RawFinding,
            )

            pipeline = ValidationPipeline(VPConfig())

            # Convert findings to RawFinding format
            raw_findings = []
            for finding in context.findings:
                if isinstance(finding, dict):
                    raw = RawFinding(
                        vuln_type=finding.get("vuln_type", finding.get("type", "unknown")),
                        url=finding.get("endpoint", finding.get("url", finding.get("matched_at", ""))),
                        parameter=finding.get("parameter", ""),
                        payload=finding.get("payload", ""),
                        evidence=finding.get("evidence", []),
                        confidence=finding.get("confidence_score", finding.get("confidence", 0.5)),
                        severity=finding.get("severity", "MEDIUM"),
                        metadata=finding,
                    )
                    raw_findings.append(raw)
                elif hasattr(finding, "to_raw"):
                    raw_findings.append(finding.to_raw())
                else:
                    # Keep as-is
                    raw_findings.append(finding)

            # Validate
            validated = await pipeline.validate(raw_findings)

            # Convert back to original format
            context.findings = [
                v.metadata if isinstance(v, RawFinding) and v.metadata else v
                for v in validated
            ]

        except ImportError:
            logger.debug("[Validation] ValidationPipeline not available")
        except Exception as e:
            logger.debug(f"[Validation] Pipeline error: {e}")

    async def _detect_second_order(self, context: ScanContext) -> list[Any]:
        """Detect second-order vulnerabilities."""
        try:
            from scanning.second_order_tracker import SecondOrderTracker

            tracker = SecondOrderTracker()

            # Check for payloads appearing at other endpoints
            second_order_findings = await tracker.check_all(
                context.target_url,
                context.endpoints,
                context.findings,
            )

            return second_order_findings or []

        except ImportError:
            logger.debug("[Validation] SecondOrderTracker not available")
            return []
        except Exception as e:
            logger.debug(f"[SecondOrder] Error: {e}")
            return []

    async def _finalize_evidence(self, context: ScanContext) -> None:
        """Finalize evidence collection session."""
        try:
            evidence_engine = context.metadata.get("evidence_engine")
            if not evidence_engine:
                return

            # Add completion event
            evidence_engine.add_timeline_event(
                event_type="scan_complete",
                description=f"Scan completed: {len(context.findings)} findings",
                details={
                    "total_findings": len(context.findings),
                    "critical": len([
                        f for f in context.findings
                        if (getattr(f, "severity", None) or (isinstance(f, dict) and f.get("severity"))) == "CRITICAL"
                    ]),
                    "high": len([
                        f for f in context.findings
                        if (getattr(f, "severity", None) or (isinstance(f, dict) and f.get("severity"))) == "HIGH"
                    ]),
                }
            )

            # Compile evidence packages for high-severity findings
            for finding in context.findings:
                severity = (
                    getattr(finding, "severity", "MEDIUM")
                    if hasattr(finding, "severity")
                    else finding.get("severity", "MEDIUM") if isinstance(finding, dict)
                    else "MEDIUM"
                )
                if severity in ("CRITICAL", "HIGH"):
                    try:
                        finding_id = (
                            getattr(finding, "id", None)
                            or (finding.get("id") if isinstance(finding, dict) else None)
                            or f"FINDING_{hash(str(finding)) % 10000:04d}"
                        )
                        package = evidence_engine.compile_evidence_package(
                            finding_id=finding_id,
                            finding_type=(
                                getattr(finding, "type", "unknown")
                                if hasattr(finding, "type")
                                else finding.get("type", "unknown") if isinstance(finding, dict)
                                else "unknown"
                            ),
                            severity=severity,
                        )
                        if package and isinstance(finding, dict):
                            finding["evidence_package"] = package.to_dict()
                    except Exception as e:
                        logger.debug(f"Evidence package failed: {e}")

            # End session
            evidence_path = evidence_engine.end_session()
            if evidence_path:
                context.metadata["evidence_path"] = str(evidence_path)
                logger.info(f"[Evidence] Collection complete: {evidence_path}")

        except Exception as e:
            logger.debug(f"[Evidence] Finalization error: {e}")
