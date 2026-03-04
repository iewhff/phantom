"""
Finding Sharing - Cross-Module Finding Communication.

Handles sharing of findings between scanner modules:
- Early sharing (before validation) for feedback loops
- Validated sharing (after validation) for confirmed findings
- Confidence thresholds for sharing decisions

Extracted from full_scanner.py for modularization.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional, Protocol

logger = logging.getLogger("phantom")


# Default confidence thresholds
EARLY_SHARE_THRESHOLD = 50.0  # Lower threshold for early feedback
VALIDATED_SHARE_THRESHOLD = 60.0  # Higher threshold for validated findings


class SharedFindingsStoreProtocol(Protocol):
    """Protocol for shared findings store."""

    async def add_finding(
        self,
        finding: dict,
        module: str = "",
    ) -> None:
        """Add a finding to the shared store."""
        ...


class AuditLoggerProtocol(Protocol):
    """Protocol for audit logger."""

    def log_vulnerability_found(
        self,
        url: str,
        vuln_type: str,
        severity: str,
        confidence: float,
        module: str = "",
    ) -> None:
        """Log a vulnerability finding to audit trail."""
        ...


async def share_findings_early(
    findings: list[dict],
    shared_store: SharedFindingsStoreProtocol,
    normalize_confidence_func: Callable[[Any], float],
    threshold: float = EARLY_SHARE_THRESHOLD,
) -> int:
    """Share findings early for cross-module feedback.

    Called after aggregation but BEFORE proof engine and analysis phases.
    Uses lower confidence threshold to enable feedback loops.

    Args:
        findings: List of aggregated findings (not yet validated)
        shared_store: Store for sharing findings between modules
        normalize_confidence_func: Function to normalize confidence values
        threshold: Minimum confidence threshold for sharing

    Returns:
        Number of findings shared
    """
    if not findings:
        return 0

    shared_count = 0

    for f in findings:
        if not isinstance(f, dict):
            continue

        confidence = normalize_confidence_func(f.get("confidence_score", f.get("confidence", 0)))

        if confidence < threshold:
            continue

        try:
            # Mark as early share so consumers know it's not fully validated
            f_copy = {**f, "_early_share": True}
            await shared_store.add_finding(f_copy, module=f.get("module", "unknown"))
            shared_count += 1
        except Exception as e:
            logger.debug(f"Could not early-share finding: {e}")

    if shared_count > 0:
        logger.debug(
            f"[EarlyShare] Shared {shared_count}/{len(findings)} findings "
            f"for cross-module feedback"
        )

    return shared_count


async def share_validated_findings(
    findings: list[dict],
    shared_store: SharedFindingsStoreProtocol,
    normalize_confidence_func: Callable[[Any], float],
    audit_logger: Optional[AuditLoggerProtocol] = None,
    threshold: float = VALIDATED_SHARE_THRESHOLD,
) -> int:
    """Share validated findings to SharedFindingsStore.

    Only called AFTER deduplication and validation.
    This prevents unvalidated findings from boosting other modules' confidence.

    Args:
        findings: List of validated, deduplicated findings
        shared_store: Store for sharing findings between modules
        normalize_confidence_func: Function to normalize confidence values
        audit_logger: Optional audit logger for compliance
        threshold: Minimum confidence threshold for sharing

    Returns:
        Number of findings shared
    """
    if not findings:
        return 0

    # Log findings to audit trail if logger available
    if audit_logger:
        _log_findings_to_audit(findings, audit_logger, normalize_confidence_func)

    shared_count = 0

    for f in findings:
        if not isinstance(f, dict):
            continue

        confidence = normalize_confidence_func(f.get("confidence_score", f.get("confidence", 0)))

        # Only share findings above threshold
        if confidence < threshold:
            continue

        try:
            await shared_store.add_finding(f, module=f.get("module", "unknown"))
            shared_count += 1
        except Exception as e:
            logger.debug(f"Could not share validated finding: {e}")

    if shared_count > 0:
        logger.debug(
            f"Shared {shared_count}/{len(findings)} validated findings "
            f"to SharedFindingsStore (confidence >= {threshold}%)"
        )

    return shared_count


def _log_findings_to_audit(
    findings: list[dict],
    audit_logger: AuditLoggerProtocol,
    normalize_confidence_func: Callable[[Any], float],
) -> None:
    """Log findings to audit trail.

    Args:
        findings: List of findings to log
        audit_logger: Audit logger instance
        normalize_confidence_func: Function to normalize confidence values
    """
    for f in findings:
        if not isinstance(f, dict):
            continue

        try:
            confidence = normalize_confidence_func(f.get("confidence_score", f.get("confidence", 0)))

            audit_logger.log_vulnerability_found(
                url=f.get("url", f.get("endpoint", f.get("matched_at", "unknown"))),
                vuln_type=f.get("vuln_type", f.get("type", f.get("vulnerability_type", "unknown"))),
                severity=f.get("severity", "UNKNOWN"),
                confidence=float(confidence),
                module=f.get("module", f.get("module_name", "")),
            )
        except Exception as e:
            logger.debug(f"Audit logging of finding failed: {e}")


class FindingSharer:
    """Manages sharing of findings between scanner modules.

    Provides both early sharing (for feedback loops) and validated
    sharing (for confirmed findings).
    """

    def __init__(
        self,
        shared_store: SharedFindingsStoreProtocol,
        normalize_confidence_func: Callable[[Any], float],
        audit_logger: Optional[AuditLoggerProtocol] = None,
        early_threshold: float = EARLY_SHARE_THRESHOLD,
        validated_threshold: float = VALIDATED_SHARE_THRESHOLD,
    ):
        """Initialize the finding sharer.

        Args:
            shared_store: Store for sharing findings
            normalize_confidence_func: Function to normalize confidence
            audit_logger: Optional audit logger
            early_threshold: Threshold for early sharing
            validated_threshold: Threshold for validated sharing
        """
        self.shared_store = shared_store
        self.normalize_confidence = normalize_confidence_func
        self.audit_logger = audit_logger
        self.early_threshold = early_threshold
        self.validated_threshold = validated_threshold

        # Statistics
        self._early_shared = 0
        self._validated_shared = 0

    @property
    def early_shared_count(self) -> int:
        """Get number of early-shared findings."""
        return self._early_shared

    @property
    def validated_shared_count(self) -> int:
        """Get number of validated shared findings."""
        return self._validated_shared

    def reset_stats(self) -> None:
        """Reset sharing statistics."""
        self._early_shared = 0
        self._validated_shared = 0

    async def share_early(self, findings: list[dict]) -> int:
        """Share findings early for feedback loops.

        Args:
            findings: List of findings to share

        Returns:
            Number of findings shared
        """
        count = await share_findings_early(
            findings=findings,
            shared_store=self.shared_store,
            normalize_confidence_func=self.normalize_confidence,
            threshold=self.early_threshold,
        )
        self._early_shared += count
        return count

    async def share_validated(self, findings: list[dict]) -> int:
        """Share validated findings.

        Args:
            findings: List of validated findings to share

        Returns:
            Number of findings shared
        """
        count = await share_validated_findings(
            findings=findings,
            shared_store=self.shared_store,
            normalize_confidence_func=self.normalize_confidence,
            audit_logger=self.audit_logger,
            threshold=self.validated_threshold,
        )
        self._validated_shared += count
        return count

    def get_stats(self) -> dict:
        """Get sharing statistics.

        Returns:
            Dictionary with sharing stats
        """
        return {
            "early_shared": self._early_shared,
            "validated_shared": self._validated_shared,
            "early_threshold": self.early_threshold,
            "validated_threshold": self.validated_threshold,
        }
