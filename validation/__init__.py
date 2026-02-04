"""
Validation Framework - Proving Real Coverage.

This module validates scanner effectiveness against known vulnerable targets
and tracks metrics like precision, recall, false positives, and false negatives.
"""

from validation.benchmark import BenchmarkSuite, BenchmarkResult
from validation.metrics import MetricsCollector, ScanMetrics, ModuleMetrics
from validation.test_targets import TestTarget, VulnerabilityDatabase
from validation.validator import ModuleValidator, ValidationReport

__all__ = [
    "BenchmarkSuite",
    "BenchmarkResult",
    "MetricsCollector",
    "ScanMetrics",
    "ModuleMetrics",
    "TestTarget",
    "VulnerabilityDatabase",
    "ModuleValidator",
    "ValidationReport",
]
