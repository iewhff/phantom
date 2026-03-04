"""
Finding Validator - Finding Validation and Filtering.

Provides validation utilities for scan findings:
- Confidence threshold validation
- Parameter context validation
- Finding discard logic

Extracted from full_scanner.py for modularization.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional, Protocol, Union

from scanning.constants import (
    normalize_confidence,
    MIN_CONFIDENCE,
    LOW_CONFIDENCE,
    MEDIUM_CONFIDENCE,
    HIGH_CONFIDENCE,
)

logger = logging.getLogger("phantom")


# ═══════════════════════════════════════════════════════════════════════════════
# Protocols
# ═══════════════════════════════════════════════════════════════════════════════


class IntelligentContextProtocol(Protocol):
    """Protocol for intelligent context."""

    parameter_analysis: dict
    endpoints_discovered: list


class IntelligentScannerProtocol(Protocol):
    """Protocol for intelligent scanner."""

    class Config(Protocol):
        min_confidence: float

    config: Config

    def should_test_parameter(
        self,
        context: IntelligentContextProtocol,
        url: str,
        param: str,
        vuln_type: str,
    ) -> tuple[bool, str]:
        """Check if parameter should be tested."""
        ...


# ═══════════════════════════════════════════════════════════════════════════════
# Validation Result
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class ValidationResult:
    """Result of finding validation."""

    is_valid: bool
    confidence: float
    discard_reason: Optional[str] = None
    warnings: list[str] = None

    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []

    @property
    def should_discard(self) -> bool:
        """Check if finding should be discarded."""
        return not self.is_valid

    def add_warning(self, warning: str) -> None:
        """Add a warning message."""
        self.warnings.append(warning)


# ═══════════════════════════════════════════════════════════════════════════════
# Finding Validator
# ═══════════════════════════════════════════════════════════════════════════════


class FindingValidator:
    """Validates findings against thresholds and context.

    Provides:
    - Confidence threshold validation
    - Parameter context validation
    - Evidence requirement checks
    """

    def __init__(
        self,
        min_confidence: float = MIN_CONFIDENCE,
        require_evidence: bool = False,
        intelligent_scanner: Optional[IntelligentScannerProtocol] = None,
        intelligent_context: Optional[IntelligentContextProtocol] = None,
    ):
        """Initialize validator.

        Args:
            min_confidence: Minimum confidence threshold (0-100)
            require_evidence: Whether to require evidence in findings
            intelligent_scanner: Optional intelligent scanner for context checks
            intelligent_context: Optional intelligent context for parameter validation
        """
        self.min_confidence = min_confidence
        self.require_evidence = require_evidence
        self.intelligent_scanner = intelligent_scanner
        self.intelligent_context = intelligent_context

        # Statistics
        self._validated = 0
        self._discarded = 0
        self._discard_reasons: dict[str, int] = {}

    @property
    def validated_count(self) -> int:
        """Get number of validated findings."""
        return self._validated

    @property
    def discarded_count(self) -> int:
        """Get number of discarded findings."""
        return self._discarded

    def reset_stats(self) -> None:
        """Reset validation statistics."""
        self._validated = 0
        self._discarded = 0
        self._discard_reasons.clear()

    def validate(self, finding: Union[dict, Any]) -> ValidationResult:
        """Validate a finding.

        Args:
            finding: Finding dict or dataclass

        Returns:
            ValidationResult with validation details
        """
        # Extract fields from finding
        if hasattr(finding, 'vuln_type'):
            # It's a Finding dataclass
            confidence_val = getattr(finding, 'confidence_score', 50) or 50
            vt = getattr(finding, 'vuln_type', None)
            vuln_type = (vt.value if hasattr(vt, 'value') else str(vt)) if vt else ""
            param = (
                getattr(finding, 'parameter', '')
                or (finding.metadata.get('parameter', '') if hasattr(finding, 'metadata') and finding.metadata else '')
            )
            url = getattr(finding, 'host', '') or getattr(finding, 'endpoint', '') or ""
            has_evidence = bool(getattr(finding, 'evidence', None)) or bool(
                finding.metadata.get('evidence') if hasattr(finding, 'metadata') and finding.metadata else False
            )
        else:
            # It's a dict
            confidence_val = finding.get("confidence_score", finding.get("confidence", 50))
            vuln_type = finding.get("vuln_type", finding.get("vulnerability_type", finding.get("type", "")))
            param = finding.get("parameter", "")
            url = finding.get("url", finding.get("endpoint", finding.get("matched_at", "")))
            has_evidence = bool(finding.get("evidence")) or bool(
                finding.get("metadata", {}).get("evidence")
            )

        # Normalize confidence to 0-100 range
        confidence = normalize_confidence(confidence_val) * 100 if confidence_val else 50.0

        # Check confidence threshold
        if confidence < self.min_confidence:
            self._discarded += 1
            reason = f"Low confidence: {confidence:.0f}% < {self.min_confidence:.0f}%"
            self._discard_reasons[reason] = self._discard_reasons.get(reason, 0) + 1
            return ValidationResult(
                is_valid=False,
                confidence=confidence,
                discard_reason=reason,
            )

        # Check evidence requirement
        if self.require_evidence and not has_evidence:
            self._discarded += 1
            reason = "Missing required evidence"
            self._discard_reasons[reason] = self._discard_reasons.get(reason, 0) + 1
            return ValidationResult(
                is_valid=False,
                confidence=confidence,
                discard_reason=reason,
            )

        # Check parameter context if intelligent scanner available
        if self.intelligent_scanner and self.intelligent_context and param and url:
            should_test, reason = self.intelligent_scanner.should_test_parameter(
                self.intelligent_context,
                url,
                param,
                vuln_type,
            )
            if not should_test:
                self._discarded += 1
                self._discard_reasons[reason] = self._discard_reasons.get(reason, 0) + 1
                return ValidationResult(
                    is_valid=False,
                    confidence=confidence,
                    discard_reason=reason,
                )

        # Finding is valid
        self._validated += 1
        result = ValidationResult(is_valid=True, confidence=confidence)

        # Add warnings for edge cases
        if confidence < MEDIUM_CONFIDENCE:
            result.add_warning(f"Low confidence finding: {confidence:.0f}%")

        return result

    def validate_and_mark(self, finding: Union[dict, Any]) -> Union[dict, Any]:
        """Validate finding and mark with discard flag if needed.

        Args:
            finding: Finding dict or dataclass

        Returns:
            Finding with _discarded flag if validation failed
        """
        result = self.validate(finding)

        if not result.is_valid:
            if hasattr(finding, 'metadata'):
                # It's a Finding dataclass
                if finding.metadata is None:
                    finding.metadata = {}
                finding.metadata["_discarded"] = True
                finding.metadata["_discard_reason"] = result.discard_reason
            else:
                # It's a dict
                finding["_discarded"] = True
                finding["_discard_reason"] = result.discard_reason

        return finding

    def get_stats(self) -> dict:
        """Get validation statistics.

        Returns:
            Dictionary with validation stats
        """
        return {
            "validated": self._validated,
            "discarded": self._discarded,
            "discard_reasons": dict(self._discard_reasons),
            "min_confidence": self.min_confidence,
            "require_evidence": self.require_evidence,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Convenience Functions
# ═══════════════════════════════════════════════════════════════════════════════


def validate_finding(
    finding: Union[dict, Any],
    min_confidence: float = MIN_CONFIDENCE,
) -> ValidationResult:
    """Validate a single finding.

    Args:
        finding: Finding dict or dataclass
        min_confidence: Minimum confidence threshold

    Returns:
        ValidationResult
    """
    validator = FindingValidator(min_confidence=min_confidence)
    return validator.validate(finding)


def filter_low_confidence(
    findings: list,
    min_confidence: float = MIN_CONFIDENCE,
) -> tuple[list, int]:
    """Filter out low confidence findings.

    Args:
        findings: List of findings
        min_confidence: Minimum confidence threshold

    Returns:
        Tuple of (valid_findings, removed_count)
    """
    validator = FindingValidator(min_confidence=min_confidence)
    valid = []

    for finding in findings:
        result = validator.validate(finding)
        if result.is_valid:
            valid.append(finding)

    return valid, validator.discarded_count


def is_finding_valid(
    finding: Union[dict, Any],
    min_confidence: float = MIN_CONFIDENCE,
) -> bool:
    """Check if a finding is valid.

    Args:
        finding: Finding dict or dataclass
        min_confidence: Minimum confidence threshold

    Returns:
        True if valid, False otherwise
    """
    result = validate_finding(finding, min_confidence)
    return result.is_valid


def get_confidence_level(confidence: float) -> str:
    """Get confidence level label.

    Args:
        confidence: Confidence value (0-100)

    Returns:
        Level string (low, medium, high, very_high)
    """
    if confidence >= HIGH_CONFIDENCE:
        return "high"
    elif confidence >= MEDIUM_CONFIDENCE:
        return "medium"
    elif confidence >= LOW_CONFIDENCE:
        return "low"
    else:
        return "very_low"
