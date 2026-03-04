"""
PHANTOM AI - Pattern Verification Stage
=========================================

Extracted from phantom/validation_pipeline.py (lines 1366-1521).

Stage 2: Pattern Verification
Verifies response patterns match expected vulnerability indicators.
"""

import re
import logging
import time
from typing import Dict, List, Any, Tuple

from phantom.validation.models import (
    ValidationStage,
    ValidationResult,
    ValidationConfig,
    RawFinding,
    StageResult,
    VulnerabilityType,
    CONFIDENCE_BOOST_PATTERN_MATCH,
    CONFIDENCE_BOOST_BLIND_VULN,
    CONFIDENCE_BOOST_BEHAVIOR_EVIDENCE,
    CONFIDENCE_PENALTY_MISSING_DATA,
    MAX_BEHAVIOR_BOOST,
)
from phantom.validation.utils.pattern_matcher import PatternMatcher

logger = logging.getLogger("phantom.validation.stages.pattern_verification")


class PatternVerificationStage:
    """
    Stage 2: Pattern Verification
    Verifies response patterns match expected vulnerability indicators.
    """

    def __init__(self, config: ValidationConfig) -> None:
        self.config = config
        self.matcher = PatternMatcher()

    def validate(self, finding: RawFinding) -> StageResult:
        """Verify patterns in the response."""
        start = time.time()

        # FIX 2026-02-12: Also check evidence field, not just response
        # Many scanners put evidence in finding.evidence, not finding.response
        response_text = finding.response or finding.evidence or ""
        if not response_text:
            # THEME-10 FIX: Missing data = uncertainty, should penalize
            return StageResult(
                stage=ValidationStage.PATTERN_VERIFICATION,
                result=ValidationResult.SKIPPED,
                confidence_delta=CONFIDENCE_PENALTY_MISSING_DATA,
                message="No response data to verify (data gap penalty applied)",
                duration_ms=(time.time() - start) * 1000,
            )

        # Check for vulnerability indicators
        has_indicators, indicator_confidence, matched = self.matcher.check_indicators(
            response_text, finding.vulnerability_type
        )

        # Check for false positive indicators
        has_fp, fp_confidence, fp_matched = self.matcher.check_false_positives(
            response_text
        )

        if has_indicators and not has_fp:
            return StageResult(
                stage=ValidationStage.PATTERN_VERIFICATION,
                result=ValidationResult.PASSED,
                confidence_delta=indicator_confidence * CONFIDENCE_BOOST_PATTERN_MATCH,
                message=f"Pattern verification passed",
                evidence=f"Matched patterns: {matched[:3]}",
                duration_ms=(time.time() - start) * 1000,
                metadata={"matched_patterns": matched},
            )

        elif has_fp:
            return StageResult(
                stage=ValidationStage.PATTERN_VERIFICATION,
                result=ValidationResult.FAILED,
                # LOGIC-V4 FIX: Symmetric with success multiplier (0.2x)
                confidence_delta=-fp_confidence * 0.2,
                message="False positive indicators detected",
                evidence=f"FP patterns: {fp_matched[:3]}",
                duration_ms=(time.time() - start) * 1000,
            )

        else:
            # THEME-10 FIX: INCONCLUSIVE should penalize confidence, not be neutral
            # "Nao conseguimos confirmar" != "esta limpo"
            from phantom.validation.models import CONFIDENCE_PENALTY_UNCERTAINTY
            return StageResult(
                stage=ValidationStage.PATTERN_VERIFICATION,
                result=ValidationResult.INCONCLUSIVE,
                confidence_delta=CONFIDENCE_PENALTY_UNCERTAINTY,
                message="No conclusive patterns found (uncertainty penalty applied)",
                duration_ms=(time.time() - start) * 1000,
            )
