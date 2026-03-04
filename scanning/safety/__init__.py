"""
Scanner Safety System.

Centralizes safety-related functionality:
- SafetyManager: Central safety orchestration
- Payload validation and filtering
- Evidence redaction
- Scope guard integration
- Safety level checking

Extracted from full_scanner.py for modularization.
"""

from .manager import (
    SafetyManager,
    SafetyComponents,
    initialize_safety,
)
from .validation import (
    validate_payload,
    filter_payloads,
    is_destructive_payload,
    DESTRUCTIVE_KEYWORDS,
)
from .levels import (
    SafetyMode,
    get_safety_index,
    is_mode_at_least,
    compare_safety_modes,
)

__all__ = [
    # Manager
    "SafetyManager",
    "SafetyComponents",
    "initialize_safety",
    # Validation
    "validate_payload",
    "filter_payloads",
    "is_destructive_payload",
    "DESTRUCTIVE_KEYWORDS",
    # Levels
    "SafetyMode",
    "get_safety_index",
    "is_mode_at_least",
    "compare_safety_modes",
]
