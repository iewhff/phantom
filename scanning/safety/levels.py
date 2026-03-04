"""
Safety Level Management.

Defines safety modes and provides utilities for comparing them.

Extracted from full_scanner.py for modularization.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from scanning.config import SAFETY_HIERARCHY


class SafetyMode(str, Enum):
    """Safety mode enumeration with string values for compatibility."""
    PASSIVE = "passive"
    SAFE = "safe"
    CAUTIOUS = "cautious"
    STANDARD = "standard"
    AGGRESSIVE = "aggressive"
    UNRESTRICTED = "unrestricted"

    @classmethod
    def from_string(cls, value: str) -> "SafetyMode":
        """Convert string to SafetyMode, defaulting to SAFE."""
        try:
            return cls(value.lower())
        except ValueError:
            return cls.SAFE

    @property
    def index(self) -> int:
        """Get the index in the safety hierarchy (0=safest)."""
        return get_safety_index(self.value)

    def __ge__(self, other: "SafetyMode") -> bool:
        """Check if this mode is at least as permissive as other."""
        return self.index >= other.index

    def __gt__(self, other: "SafetyMode") -> bool:
        """Check if this mode is more permissive than other."""
        return self.index > other.index

    def __le__(self, other: "SafetyMode") -> bool:
        """Check if this mode is at most as permissive as other."""
        return self.index <= other.index

    def __lt__(self, other: "SafetyMode") -> bool:
        """Check if this mode is less permissive than other."""
        return self.index < other.index


def get_safety_index(mode: str) -> int:
    """Get the numeric index of a safety mode (higher = more permissive).

    Args:
        mode: Safety mode string

    Returns:
        Index in hierarchy (0=passive, 5=unrestricted)
    """
    try:
        return SAFETY_HIERARCHY.index(mode.lower())
    except (ValueError, AttributeError):
        return 1  # Default to "safe" level


def is_mode_at_least(current_mode: str, required_mode: str) -> bool:
    """Check if current mode is at least as permissive as required mode.

    Args:
        current_mode: The active safety mode
        required_mode: The minimum required mode

    Returns:
        True if current_mode >= required_mode in the hierarchy
    """
    current_idx = get_safety_index(current_mode)
    required_idx = get_safety_index(required_mode)
    return current_idx >= required_idx


def compare_safety_modes(mode_a: str, mode_b: str) -> int:
    """Compare two safety modes.

    Args:
        mode_a: First mode
        mode_b: Second mode

    Returns:
        -1 if mode_a < mode_b
         0 if mode_a == mode_b
         1 if mode_a > mode_b
    """
    idx_a = get_safety_index(mode_a)
    idx_b = get_safety_index(mode_b)

    if idx_a < idx_b:
        return -1
    elif idx_a > idx_b:
        return 1
    return 0


def get_mode_emoji(mode: str) -> str:
    """Get the emoji representation for a safety mode."""
    emoji_map = {
        "passive": "🔒",
        "safe": "🔒",
        "cautious": "⚠️",
        "standard": "🟡",
        "aggressive": "🔴",
        "unrestricted": "💀",
    }
    return emoji_map.get(mode.lower(), "🔒")


def get_mode_description(mode: str) -> dict[str, str]:
    """Get description of what a safety mode allows."""
    descriptions = {
        "passive": {
            "http_safety": "ENABLED",
            "destructive_blocking": "FULL",
            "methods_allowed": "GET only",
            "payload_checking": "STRICT",
        },
        "safe": {
            "http_safety": "ENABLED",
            "destructive_blocking": "FULL",
            "methods_allowed": "GET only",
            "payload_checking": "STRICT",
        },
        "cautious": {
            "http_safety": "ENABLED",
            "destructive_blocking": "ENABLED",
            "methods_allowed": "GET, POST (checked)",
            "payload_checking": "ENABLED",
        },
        "standard": {
            "http_safety": "ENABLED",
            "destructive_blocking": "ENABLED",
            "methods_allowed": "All (checked)",
            "payload_checking": "ENABLED",
        },
        "aggressive": {
            "http_safety": "MINIMAL",
            "destructive_blocking": "DISABLED",
            "methods_allowed": "All",
            "payload_checking": "DISABLED",
        },
        "unrestricted": {
            "http_safety": "DISABLED",
            "destructive_blocking": "DISABLED",
            "methods_allowed": "All",
            "payload_checking": "DISABLED",
        },
    }
    return descriptions.get(mode.lower(), descriptions["safe"])
