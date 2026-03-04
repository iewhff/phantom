"""
Insecure Deserialization Scanner (Refactored)

Split from scanning/modules/deserialization_scanner.py into:
- deser_base.py: Enums, dataclasses, constants
- orchestrator.py: DeserializationScanner (main class)
- formats/: Language-specific test implementations
"""

from scanning.modules.deserialization.deser_base import (
    DeserVulnType,
    GadgetChainType,
    SerializationFormat,
    DeserTestResult,
    FrameworkSignature,
    STATIC_EXTENSIONS,
    SPA_TRIVIAL_ENDPOINTS,
    GENERIC_ERROR_PATTERNS,
    DESER_SPECIFIC_PATTERNS,
    SAFE_CONTENT_TYPES,
    SEVERITY_SIGNAL_REQUIREMENTS,
)
from scanning.modules.deserialization.orchestrator import DeserializationScanner

__all__ = [
    "DeserializationScanner",
    "DeserVulnType",
    "GadgetChainType",
    "SerializationFormat",
    "DeserTestResult",
    "FrameworkSignature",
    "STATIC_EXTENSIONS",
    "SPA_TRIVIAL_ENDPOINTS",
    "GENERIC_ERROR_PATTERNS",
    "DESER_SPECIFIC_PATTERNS",
    "SAFE_CONTENT_TYPES",
    "SEVERITY_SIGNAL_REQUIREMENTS",
]
