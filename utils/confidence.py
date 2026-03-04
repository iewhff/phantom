"""
Confidence Normalization Utilities

Provides consistent confidence value handling across all scanner modules.
Converts between string representations ("HIGH", "MEDIUM", "LOW") and
numeric values (0.0-1.0 scale).

Usage:
    from utils.confidence import normalize_confidence, confidence_to_string

    # Convert string to numeric
    conf = normalize_confidence("HIGH")  # Returns 0.90
    conf = normalize_confidence(0.75)    # Returns 0.75 (unchanged)

    # Convert numeric to string
    label = confidence_to_string(0.85)   # Returns "HIGH"
"""

from typing import Union

# Standard confidence scale
CONFIDENCE_SCALE = {
    # High confidence (0.80-1.0)
    "confirmed": 0.95,
    "exploitable": 0.95,
    "critical": 0.90,
    "high": 0.90,
    "verified": 0.90,

    # Medium confidence (0.50-0.79)
    "medium": 0.70,
    "moderate": 0.70,
    "likely": 0.65,
    "probable": 0.65,

    # Low confidence (0.20-0.49)
    "low": 0.40,
    "possible": 0.40,
    "weak": 0.30,

    # Very low confidence (0.0-0.19)
    "info": 0.20,
    "informational": 0.20,
    "suspected": 0.15,
    "none": 0.0,
}

# Reverse mapping for numeric to string
CONFIDENCE_THRESHOLDS = [
    (0.90, "CONFIRMED"),
    (0.80, "HIGH"),
    (0.60, "MEDIUM"),
    (0.40, "LOW"),
    (0.20, "INFO"),
    (0.0, "NONE"),
]


def normalize_confidence(value: Union[str, float, int, None]) -> float:
    """
    Normalize a confidence value to a float between 0.0 and 1.0.

    Args:
        value: Confidence value as string, float, int, or None

    Returns:
        Float between 0.0 and 1.0

    Examples:
        >>> normalize_confidence("HIGH")
        0.9
        >>> normalize_confidence("medium")
        0.7
        >>> normalize_confidence(0.85)
        0.85
        >>> normalize_confidence(85)  # Interpreted as percentage
        0.85
        >>> normalize_confidence(None)
        0.6
    """
    if value is None:
        # OVERFILTERING-FIX: Raised from 0.5 to 0.6
        # If a scanner detected something, it deserves baseline credit
        # 0.5 was too low - findings would fail validation after penalties
        return 0.6  # Default to medium-high (scanner found something)

    if isinstance(value, (int, float)):
        # If > 1, assume it's a percentage (0-100)
        if value > 1.0:
            return min(1.0, value / 100.0)
        return max(0.0, min(1.0, float(value)))

    if isinstance(value, str):
        normalized = value.lower().strip()

        # FIX #12 2026-02-12: Handle empty strings
        if not normalized:
            return 0.6  # Same as None - scanner found something

        # Check for known labels
        if normalized in CONFIDENCE_SCALE:
            return CONFIDENCE_SCALE[normalized]

        # Try to parse as number
        try:
            num_val = float(normalized.rstrip("%"))
            if num_val > 1.0:
                return min(1.0, num_val / 100.0)
            return max(0.0, min(1.0, num_val))
        except ValueError:
            pass

        # FIX #12 2026-02-12: Check for partial matches in string
        # e.g., "high_confidence" should match "high"
        for label, conf_value in CONFIDENCE_SCALE.items():
            if label in normalized:
                return conf_value

        # Unknown string - return medium
        return 0.50

    return 0.50


def confidence_to_string(value: Union[float, int, str, None]) -> str:
    """
    Convert a numeric confidence value to a string label.

    Args:
        value: Confidence value (0.0-1.0)

    Returns:
        String label: "CONFIRMED", "HIGH", "MEDIUM", "LOW", "INFO", or "NONE"

    Examples:
        >>> confidence_to_string(0.95)
        "CONFIRMED"
        >>> confidence_to_string(0.75)
        "MEDIUM"
        >>> confidence_to_string(0.3)
        "LOW"
    """
    if value is None:
        return "MEDIUM"

    if isinstance(value, str):
        value = normalize_confidence(value)

    if isinstance(value, (int, float)):
        if value > 1.0:
            value = value / 100.0

        for threshold, label in CONFIDENCE_THRESHOLDS:
            if value >= threshold:
                return label

    return "NONE"


def is_high_confidence(value: Union[str, float, int, None]) -> bool:
    """Check if confidence is HIGH or above (>= 0.80)."""
    return normalize_confidence(value) >= 0.80


def is_reportable_confidence(value: Union[str, float, int, None], min_threshold: float = 0.50) -> bool:
    """Check if confidence meets minimum reporting threshold."""
    return normalize_confidence(value) >= min_threshold


def compare_confidence(a: Union[str, float, None], b: Union[str, float, None]) -> int:
    """
    Compare two confidence values.

    Returns:
        -1 if a < b, 0 if a == b, 1 if a > b
    """
    a_norm = normalize_confidence(a)
    b_norm = normalize_confidence(b)

    if a_norm < b_norm:
        return -1
    elif a_norm > b_norm:
        return 1
    return 0


def max_confidence(*values: Union[str, float, None]) -> float:
    """Return the maximum confidence from a list of values."""
    if not values:
        return 0.0
    return max(normalize_confidence(v) for v in values)


def min_confidence(*values: Union[str, float, None]) -> float:
    """Return the minimum confidence from a list of values."""
    if not values:
        return 0.0
    return min(normalize_confidence(v) for v in values)


def average_confidence(*values: Union[str, float, None]) -> float:
    """Return the average confidence from a list of values."""
    if not values:
        return 0.0
    normalized = [normalize_confidence(v) for v in values]
    return sum(normalized) / len(normalized)


# Aliases for common patterns
to_numeric = normalize_confidence
to_label = confidence_to_string
