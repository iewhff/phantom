"""
Payload Safety Validation.

Provides utilities for validating and filtering payloads based on safety levels.

Extracted from full_scanner.py for modularization.
"""

from __future__ import annotations

import re
from typing import Optional, Callable

from .levels import SafetyMode, is_mode_at_least


# Destructive keywords that should be blocked in safe modes
DESTRUCTIVE_KEYWORDS: list[str] = [
    # SQL destructive
    "DROP", "DELETE", "TRUNCATE", "UPDATE", "INSERT",
    "ALTER TABLE", "CREATE TABLE", "GRANT", "REVOKE",
    # Command injection destructive
    "rm -rf", "shutdown", "reboot", "mkfs", "dd if=",
    "format", "fdisk", ":(){:|:&};:",  # fork bomb
    # File system destructive
    "deltree", "rmdir /s", "del /f",
]

# Patterns for more sophisticated destructive detection
DESTRUCTIVE_PATTERNS: list[re.Pattern] = [
    re.compile(r"\bDROP\s+(TABLE|DATABASE|INDEX|VIEW)\b", re.IGNORECASE),
    re.compile(r"\bDELETE\s+FROM\b", re.IGNORECASE),
    re.compile(r"\bTRUNCATE\s+TABLE\b", re.IGNORECASE),
    re.compile(r"\bUPDATE\s+\w+\s+SET\b", re.IGNORECASE),
    re.compile(r"\bINSERT\s+INTO\b", re.IGNORECASE),
    re.compile(r"rm\s+-[rf]+\s+", re.IGNORECASE),
    re.compile(r">\s*/dev/sd[a-z]", re.IGNORECASE),  # Writing to disk devices
    re.compile(r"mkfs\.", re.IGNORECASE),
]


def is_destructive_payload(payload: str) -> tuple[bool, Optional[str]]:
    """Check if a payload contains destructive patterns.

    Args:
        payload: The payload string to check

    Returns:
        Tuple of (is_destructive, matched_pattern)
    """
    payload_lower = payload.lower()

    # Check simple keywords
    for keyword in DESTRUCTIVE_KEYWORDS:
        if keyword.lower() in payload_lower:
            return True, keyword

    # Check regex patterns
    for pattern in DESTRUCTIVE_PATTERNS:
        match = pattern.search(payload)
        if match:
            return True, match.group(0)

    return False, None


def validate_payload(
    payload: str,
    category: str = "other",
    safe_mode: str = "safe",
    analyzer: Optional[object] = None,
) -> tuple[bool, str]:
    """Validate a payload against safety rules.

    Args:
        payload: The payload to validate
        category: Payload category (sqli, cmdi, xss, etc.)
        safe_mode: Current safety mode
        analyzer: Optional PayloadSafetyAnalyzer instance

    Returns:
        Tuple of (is_safe, reason_if_blocked)
    """
    # If we have a configured analyzer, use it
    if analyzer is not None and hasattr(analyzer, 'validate'):
        return analyzer.validate(payload, category)

    # Basic safety check for safe modes
    if safe_mode in ("passive", "safe"):
        is_destructive, matched = is_destructive_payload(payload)
        if is_destructive:
            return False, f"Destructive pattern '{matched}' blocked in {safe_mode} mode"

    return True, "OK"


def filter_payloads(
    payloads: list[str],
    category: str = "other",
    safe_mode: str = "safe",
    analyzer: Optional[object] = None,
) -> list[str]:
    """Filter a list of payloads, returning only safe ones.

    Args:
        payloads: List of payloads to filter
        category: Payload category
        safe_mode: Current safety mode
        analyzer: Optional PayloadSafetyAnalyzer instance

    Returns:
        List of safe payloads
    """
    if analyzer is not None and hasattr(analyzer, 'filter_payloads'):
        try:
            from scanning.destructive_controls import PayloadCategory
            try:
                cat_enum = PayloadCategory(category.lower())
            except ValueError:
                cat_enum = PayloadCategory.OTHER
            return analyzer.filter_payloads(payloads, cat_enum)
        except ImportError:
            pass

    # Basic filtering
    return [p for p in payloads if validate_payload(p, category, safe_mode)[0]]


def create_payload_validator(
    safe_mode: str,
    analyzer: Optional[object] = None,
) -> Callable[[str, str], tuple[bool, str]]:
    """Create a payload validator function with bound safety mode.

    Args:
        safe_mode: The safety mode to use
        analyzer: Optional PayloadSafetyAnalyzer instance

    Returns:
        A validator function that takes (payload, category) and returns (is_safe, reason)
    """
    def validator(payload: str, category: str = "other") -> tuple[bool, str]:
        return validate_payload(payload, category, safe_mode, analyzer)
    return validator
