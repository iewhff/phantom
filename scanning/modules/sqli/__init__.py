"""
SQL Injection Scanner - Refactored Module.

This package contains the modular SQLi scanner with:
- sqli_base.py: Enums, dataclasses, constants
- sqli_scanner.py: Main orchestrator
- strategies/: Injection strategy implementations
- utils/: Helper classes (fingerprinter, mutator, analyzer)

Extracted from sqli_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

from scanning.modules.sqli.sqli_base import (
    # Version
    SQLI_SCANNER_VERSION,
    # Constants
    MAX_FINDINGS_PER_ENDPOINT,
    MAX_FINDINGS_PER_PARAM,
    MAX_TOTAL_FINDINGS,
    MAX_INTELLIGENT_PAYLOADS,
    MAX_FALLBACK_PAYLOADS,
    # Enums
    ConfidenceLevel,
    DetectionMethod,
    WAFType,
    DatabaseType,
    # Dataclasses
    ResponseFingerprint,
    ResponseCluster,
    InjectionContext,
    SQLiEvidence,
    SQLiResult,
    # Classes
    WAFDetector,
    # Functions
    is_spa_response,
    # Payload sets
    ERROR_PAYLOADS,
    BOOLEAN_PAYLOADS,
    TIME_PAYLOADS,
    OOB_MANDATORY_PAYLOADS,
    UNION_TEMPLATES,
    WAF_BYPASS_PAYLOADS,
    INJECTABLE_HEADERS,
    GRAPHQL_PAYLOADS,
    # FP patterns
    FP_INDICATORS,
    FP_CONTENT_PATTERNS,
    SPA_INDICATORS,
)

# Orchestrator and strategies
from scanning.modules.sqli.orchestrator import (
    SQLiOrchestrator,
    OrchestratorConfig,
    EndpointResult,
)

__all__ = [
    # Version
    "SQLI_SCANNER_VERSION",
    # Constants
    "MAX_FINDINGS_PER_ENDPOINT",
    "MAX_FINDINGS_PER_PARAM",
    "MAX_TOTAL_FINDINGS",
    "MAX_INTELLIGENT_PAYLOADS",
    "MAX_FALLBACK_PAYLOADS",
    # Enums
    "ConfidenceLevel",
    "DetectionMethod",
    "WAFType",
    "DatabaseType",
    # Dataclasses
    "ResponseFingerprint",
    "ResponseCluster",
    "InjectionContext",
    "SQLiEvidence",
    "SQLiResult",
    # Classes
    "WAFDetector",
    # Orchestrator
    "SQLiOrchestrator",
    "OrchestratorConfig",
    "EndpointResult",
    # Functions
    "is_spa_response",
    # Payload sets
    "ERROR_PAYLOADS",
    "BOOLEAN_PAYLOADS",
    "TIME_PAYLOADS",
    "OOB_MANDATORY_PAYLOADS",
    "UNION_TEMPLATES",
    "WAF_BYPASS_PAYLOADS",
    "INJECTABLE_HEADERS",
    "GRAPHQL_PAYLOADS",
    # FP patterns
    "FP_INDICATORS",
    "FP_CONTENT_PATTERNS",
    "SPA_INDICATORS",
]
