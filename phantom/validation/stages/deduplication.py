"""
PHANTOM AI - Deduplication Stage
==================================

Extracted from phantom/validation_pipeline.py (lines 1313-1365).

Stage 1: Deduplication
Removes duplicate findings based on fingerprint similarity.
"""

import logging
import time
import threading
from typing import Dict, List, Any, Set

from phantom.validation.models import (
    ValidationStage,
    ValidationResult,
    ValidationConfig,
    RawFinding,
    StageResult,
    is_static_asset_url,
    VULN_TYPES_IMPOSSIBLE_ON_STATIC,
)

logger = logging.getLogger("phantom.validation.stages.deduplication")


class DeduplicationStage:
    """
    Stage 1: Deduplication
    Removes duplicate findings based on fingerprint similarity.
    Thread-safe via lock.
    """

    def __init__(self, config: ValidationConfig) -> None:
        self.config = config
        self._seen_fingerprints: Set[str] = set()
        self._lock = threading.Lock()

    def validate(
        self,
        finding: RawFinding,
        all_findings: List[RawFinding],
    ) -> StageResult:
        """Check if finding is a duplicate (thread-safe)."""
        start = time.time()

        fingerprint = finding.get_fingerprint()

        with self._lock:
            if fingerprint in self._seen_fingerprints:
                # AUDIT-FIX 2026-02-19: Changed from -1.0 to -0.15
                # Rationale: -1.0 kills legitimate findings when same vuln found by multiple modules
                # A duplicate should be penalized but not completely rejected
                # The first instance keeps full confidence, duplicates get -0.15 penalty
                return StageResult(
                    stage=ValidationStage.DEDUPLICATION,
                    result=ValidationResult.FAILED,
                    confidence_delta=-0.15,  # Moderate penalty, not death sentence
                    message="Duplicate finding detected (penalized, not rejected)",
                    evidence=f"Fingerprint: {fingerprint}",
                    duration_ms=(time.time() - start) * 1000,
                )

            self._seen_fingerprints.add(fingerprint)

        return StageResult(
            stage=ValidationStage.DEDUPLICATION,
            result=ValidationResult.PASSED,
            confidence_delta=0.0,
            message="Unique finding",
            duration_ms=(time.time() - start) * 1000,
        )

    def reset(self) -> None:
        """Reset seen fingerprints (thread-safe)."""
        with self._lock:
            self._seen_fingerprints.clear()
