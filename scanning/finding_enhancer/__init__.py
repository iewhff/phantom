"""
Finding Enhancer Module - Finding Validation and Enrichment.

Provides components for enhancing scan findings:
- FindingValidator: Validates findings against thresholds
- FindingEnricher: Enriches findings with metadata
- Severity calculation utilities

Extracted from full_scanner.py for modularization.
"""

from .validator import (
    # Classes
    ValidationResult,
    FindingValidator,
    # Protocols
    IntelligentContextProtocol,
    IntelligentScannerProtocol,
    # Functions
    validate_finding,
    filter_low_confidence,
    is_finding_valid,
    get_confidence_level,
)
from .enricher import (
    # Constants
    VULN_TYPE_SEVERITY,
    CONFIDENCE_BOOST_THRESHOLD,
    # Classes
    EnrichmentData,
    FindingEnricher,
    # Functions
    calculate_severity,
    enrich_finding,
    add_finding_id,
    add_timestamp,
    link_evidence,
)

__all__ = [
    # Validator classes
    "ValidationResult",
    "FindingValidator",
    # Validator protocols
    "IntelligentContextProtocol",
    "IntelligentScannerProtocol",
    # Validator functions
    "validate_finding",
    "filter_low_confidence",
    "is_finding_valid",
    "get_confidence_level",
    # Enricher constants
    "VULN_TYPE_SEVERITY",
    "CONFIDENCE_BOOST_THRESHOLD",
    # Enricher classes
    "EnrichmentData",
    "FindingEnricher",
    # Enricher functions
    "calculate_severity",
    "enrich_finding",
    "add_finding_id",
    "add_timestamp",
    "link_evidence",
]
