"""
XSS Scanner - Refactored Module.

This package contains the modular XSS scanner with:
- xss_base.py: Enums, dataclasses, constants
- orchestrator.py: Main scanner orchestrator
- strategies/: Detection strategy implementations
- utils/: Helper classes (payload mutator, CSP analyzer)

Extracted from xss_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

from scanning.modules.xss.xss_base import (
    # Version
    XSS_SCANNER_VERSION,
    # Constants
    MIN_CONFIDENCE_THRESHOLD,
    CROSS_VALIDATION_REQUIRED,
    # Enums
    XSSContext,
    WAFType,
    # Dataclasses
    XSSEvidence,
    XSSResult,
    TrackedInput,
    # Payloads
    POLYGLOT_PAYLOADS,
    PHP_LEGACY_BYPASS_PAYLOADS,
    PAYLOADS_BY_CONTEXT,
    WAF_BYPASS_PAYLOADS,
    TEMPLATE_INJECTION_PAYLOADS,
    TEMPLATE_MATH_RESULT,
    BLIND_XSS_PAYLOADS,
    # DOM XSS
    DOM_SOURCES,
    DOM_SINKS,
)

# Orchestrator and strategies
from scanning.modules.xss.orchestrator import (
    XSSOrchestrator,
    OrchestratorConfig,
    EndpointResult,
)

__all__ = [
    # Version
    "XSS_SCANNER_VERSION",
    # Constants
    "MIN_CONFIDENCE_THRESHOLD",
    "CROSS_VALIDATION_REQUIRED",
    # Enums
    "XSSContext",
    "WAFType",
    # Dataclasses
    "XSSEvidence",
    "XSSResult",
    "TrackedInput",
    # Orchestrator
    "XSSOrchestrator",
    "OrchestratorConfig",
    "EndpointResult",
    # Payloads
    "POLYGLOT_PAYLOADS",
    "PHP_LEGACY_BYPASS_PAYLOADS",
    "PAYLOADS_BY_CONTEXT",
    "WAF_BYPASS_PAYLOADS",
    "TEMPLATE_INJECTION_PAYLOADS",
    "TEMPLATE_MATH_RESULT",
    "BLIND_XSS_PAYLOADS",
    # DOM XSS
    "DOM_SOURCES",
    "DOM_SINKS",
]
