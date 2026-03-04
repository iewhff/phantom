"""
Scanner Metrics System.

Provides metrics collection, aggregation, and reporting:
- ScanResult: Main result dataclass with all metrics
- Severity/confidence mapping utilities
- Metrics constants

Extracted from full_scanner.py for modularization.
"""

from .result import (
    ScanResult,
    SEVERITY_TO_CONFIDENCE,
    normalize_confidence,
)

__all__ = [
    "ScanResult",
    "SEVERITY_TO_CONFIDENCE",
    "normalize_confidence",
]
