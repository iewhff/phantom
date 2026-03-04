"""
Finding Enricher - Finding Enrichment and Metadata.

Provides enrichment utilities for scan findings:
- Metadata addition
- Evidence linking
- Timestamp and context enrichment
- Severity calculation

Extracted from full_scanner.py for modularization.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional, Union

from scanning.constants import (
    normalize_confidence,
    normalize_severity,
    normalize_vuln_type,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
)

logger = logging.getLogger("phantom")


# ═══════════════════════════════════════════════════════════════════════════════
# Severity Calculation
# ═══════════════════════════════════════════════════════════════════════════════

# Vulnerability type to base severity mapping
VULN_TYPE_SEVERITY: dict[str, str] = {
    # Critical vulnerabilities
    "cmdi": SEVERITY_CRITICAL,
    "rce": SEVERITY_CRITICAL,
    "sqli": SEVERITY_CRITICAL,
    "sqli_blind": SEVERITY_CRITICAL,
    "deserialization": SEVERITY_CRITICAL,

    # High vulnerabilities
    "xss": SEVERITY_HIGH,
    "dom_xss": SEVERITY_HIGH,
    "xxe": SEVERITY_HIGH,
    "ssti": SEVERITY_HIGH,
    "ssrf": SEVERITY_HIGH,
    "lfi": SEVERITY_HIGH,
    "auth_bypass": SEVERITY_HIGH,
    "idor": SEVERITY_HIGH,

    # Medium vulnerabilities
    "csrf": SEVERITY_MEDIUM,
    "nosqli": SEVERITY_MEDIUM,
    "open_redirect": SEVERITY_MEDIUM,
    "session": SEVERITY_MEDIUM,
    "business_logic": SEVERITY_MEDIUM,
    "cors": SEVERITY_MEDIUM,

    # Low vulnerabilities
    "info_disclosure": SEVERITY_LOW,
    "rate_limit": SEVERITY_LOW,
    "clickjacking": SEVERITY_LOW,

    # Info
    "enumeration": SEVERITY_INFO,
    "missing_headers": SEVERITY_INFO,
}

# Confidence to severity boost mapping
# Higher confidence can boost severity by one level
CONFIDENCE_BOOST_THRESHOLD = 90.0


def calculate_severity(
    vuln_type: str,
    confidence: float = 50.0,
    has_proof: bool = False,
    exploitable: bool = False,
) -> str:
    """Calculate severity based on vulnerability type and context.

    Args:
        vuln_type: Canonical vulnerability type
        confidence: Confidence value (0-100)
        has_proof: Whether finding has exploitation proof
        exploitable: Whether finding is confirmed exploitable

    Returns:
        Severity string (CRITICAL, HIGH, MEDIUM, LOW, INFO)
    """
    normalized_type = normalize_vuln_type(vuln_type)
    base_severity = VULN_TYPE_SEVERITY.get(normalized_type, SEVERITY_MEDIUM)

    # Boost severity if high confidence + proof/exploitable
    if confidence >= CONFIDENCE_BOOST_THRESHOLD and (has_proof or exploitable):
        severity_order = [SEVERITY_INFO, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL]
        current_idx = severity_order.index(base_severity)
        if current_idx < len(severity_order) - 1:
            return severity_order[current_idx + 1]

    return base_severity


# ═══════════════════════════════════════════════════════════════════════════════
# Enrichment Data
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class EnrichmentData:
    """Data to add to a finding during enrichment."""

    # Identifiers
    finding_id: Optional[str] = None
    scan_id: Optional[str] = None

    # Timestamps
    timestamp: Optional[float] = None
    discovered_at: Optional[str] = None

    # Context
    module_name: Optional[str] = None
    target: Optional[str] = None
    phase: Optional[str] = None

    # Classification
    normalized_type: Optional[str] = None
    severity: Optional[str] = None
    confidence_level: Optional[str] = None

    # Evidence
    evidence_id: Optional[str] = None
    proof_available: bool = False

    # Custom metadata
    custom: dict = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════════════════════
# Finding Enricher
# ═══════════════════════════════════════════════════════════════════════════════


class FindingEnricher:
    """Enriches findings with metadata and context.

    Provides:
    - Automatic ID generation
    - Timestamp addition
    - Severity calculation
    - Type normalization
    - Evidence linking
    """

    def __init__(
        self,
        scan_id: Optional[str] = None,
        target: Optional[str] = None,
        auto_severity: bool = True,
        auto_normalize_type: bool = True,
    ):
        """Initialize enricher.

        Args:
            scan_id: Scan identifier for linking findings
            target: Target URL being scanned
            auto_severity: Automatically calculate severity
            auto_normalize_type: Automatically normalize vuln type
        """
        self.scan_id = scan_id or str(uuid.uuid4())[:8]
        self.target = target or ""
        self.auto_severity = auto_severity
        self.auto_normalize_type = auto_normalize_type

        # Statistics
        self._enriched = 0

    @property
    def enriched_count(self) -> int:
        """Get number of enriched findings."""
        return self._enriched

    def reset_stats(self) -> None:
        """Reset enrichment statistics."""
        self._enriched = 0

    def enrich(
        self,
        finding: Union[dict, Any],
        module_name: Optional[str] = None,
        phase: Optional[str] = None,
        evidence_id: Optional[str] = None,
        custom_data: Optional[dict] = None,
    ) -> Union[dict, Any]:
        """Enrich a finding with metadata.

        Args:
            finding: Finding dict or dataclass
            module_name: Name of scanner module
            phase: Scan phase identifier
            evidence_id: Optional evidence package ID
            custom_data: Optional custom metadata

        Returns:
            Enriched finding
        """
        is_dict = not hasattr(finding, 'metadata') or isinstance(finding, dict)

        # Get or create metadata
        if is_dict:
            metadata = finding.setdefault("metadata", {})
        else:
            if finding.metadata is None:
                finding.metadata = {}
            metadata = finding.metadata

        # Generate finding ID if not present
        if "finding_id" not in metadata:
            metadata["finding_id"] = f"{self.scan_id}-{str(uuid.uuid4())[:8]}"

        # Add scan ID
        metadata["scan_id"] = self.scan_id

        # Add timestamp
        if "timestamp" not in metadata:
            metadata["timestamp"] = time.time()
            metadata["discovered_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Add context
        if module_name:
            metadata["module_name"] = module_name
            if is_dict:
                finding.setdefault("module", module_name)

        if phase:
            metadata["phase"] = phase

        if self.target:
            metadata["target"] = self.target

        # Add evidence link
        if evidence_id:
            metadata["evidence_id"] = evidence_id
            metadata["proof_available"] = True

        # Normalize vuln type
        if self.auto_normalize_type:
            if is_dict:
                raw_type = finding.get("vuln_type", finding.get("type", finding.get("vulnerability_type", "")))
            else:
                vt = getattr(finding, 'vuln_type', None)
                raw_type = (vt.value if hasattr(vt, 'value') else str(vt)) if vt else ""

            if raw_type:
                normalized = normalize_vuln_type(raw_type)
                metadata["normalized_type"] = normalized
                metadata["original_type"] = raw_type

        # Calculate severity if not present
        if self.auto_severity:
            if is_dict:
                current_severity = finding.get("severity", "")
                vuln_type = finding.get("vuln_type", finding.get("type", ""))
                confidence = normalize_confidence(finding.get("confidence_score", finding.get("confidence", 50))) * 100
                has_proof = bool(finding.get("proof")) or metadata.get("proof_available", False)
            else:
                sev = getattr(finding, 'severity', None)
                current_severity = (sev.value if hasattr(sev, 'value') else str(sev)) if sev else ""
                vt = getattr(finding, 'vuln_type', None)
                vuln_type = (vt.value if hasattr(vt, 'value') else str(vt)) if vt else ""
                confidence = normalize_confidence(getattr(finding, 'confidence_score', 50) or 50) * 100
                has_proof = bool(getattr(finding, 'proof', None)) or metadata.get("proof_available", False)

            if not current_severity and vuln_type:
                calculated = calculate_severity(
                    vuln_type=vuln_type,
                    confidence=confidence,
                    has_proof=has_proof,
                )
                if is_dict:
                    finding["severity"] = calculated
                else:
                    finding.severity = calculated
                metadata["severity_auto_calculated"] = True

        # Add confidence level
        if is_dict:
            confidence = normalize_confidence(finding.get("confidence_score", finding.get("confidence", 50))) * 100
        else:
            confidence = normalize_confidence(getattr(finding, 'confidence_score', 50) or 50) * 100

        if confidence >= 85:
            metadata["confidence_level"] = "high"
        elif confidence >= 65:
            metadata["confidence_level"] = "medium"
        elif confidence >= 45:
            metadata["confidence_level"] = "low"
        else:
            metadata["confidence_level"] = "very_low"

        # Add custom data
        if custom_data:
            for key, value in custom_data.items():
                metadata[key] = value

        self._enriched += 1
        return finding

    def enrich_batch(
        self,
        findings: list,
        module_name: Optional[str] = None,
        phase: Optional[str] = None,
    ) -> list:
        """Enrich a batch of findings.

        Args:
            findings: List of findings
            module_name: Name of scanner module
            phase: Scan phase identifier

        Returns:
            List of enriched findings
        """
        return [
            self.enrich(f, module_name=module_name, phase=phase)
            for f in findings
        ]

    def get_stats(self) -> dict:
        """Get enrichment statistics.

        Returns:
            Dictionary with enrichment stats
        """
        return {
            "enriched": self._enriched,
            "scan_id": self.scan_id,
            "target": self.target,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Convenience Functions
# ═══════════════════════════════════════════════════════════════════════════════


def enrich_finding(
    finding: Union[dict, Any],
    module_name: Optional[str] = None,
    scan_id: Optional[str] = None,
) -> Union[dict, Any]:
    """Enrich a single finding.

    Args:
        finding: Finding dict or dataclass
        module_name: Name of scanner module
        scan_id: Scan identifier

    Returns:
        Enriched finding
    """
    enricher = FindingEnricher(scan_id=scan_id)
    return enricher.enrich(finding, module_name=module_name)


def add_finding_id(finding: Union[dict, Any]) -> str:
    """Add a unique ID to a finding.

    Args:
        finding: Finding dict or dataclass

    Returns:
        Generated finding ID
    """
    finding_id = f"f-{str(uuid.uuid4())[:12]}"

    if hasattr(finding, 'metadata'):
        if finding.metadata is None:
            finding.metadata = {}
        finding.metadata["finding_id"] = finding_id
    else:
        finding.setdefault("metadata", {})
        finding["metadata"]["finding_id"] = finding_id

    return finding_id


def add_timestamp(finding: Union[dict, Any]) -> float:
    """Add timestamp to a finding.

    Args:
        finding: Finding dict or dataclass

    Returns:
        Added timestamp
    """
    timestamp = time.time()

    if hasattr(finding, 'metadata'):
        if finding.metadata is None:
            finding.metadata = {}
        finding.metadata["timestamp"] = timestamp
    else:
        finding.setdefault("metadata", {})
        finding["metadata"]["timestamp"] = timestamp

    return timestamp


def link_evidence(
    finding: Union[dict, Any],
    evidence_id: str,
    evidence_path: Optional[str] = None,
) -> None:
    """Link evidence to a finding.

    Args:
        finding: Finding dict or dataclass
        evidence_id: Evidence package ID
        evidence_path: Optional path to evidence file
    """
    if hasattr(finding, 'metadata'):
        if finding.metadata is None:
            finding.metadata = {}
        metadata = finding.metadata
    else:
        finding.setdefault("metadata", {})
        metadata = finding["metadata"]

    metadata["evidence_id"] = evidence_id
    metadata["proof_available"] = True
    if evidence_path:
        metadata["evidence_path"] = evidence_path
