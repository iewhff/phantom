"""
Tests for utils/confidence.py - Confidence Normalization Utilities.

Covers:
- CONFIDENCE_SCALE constant
- CONFIDENCE_THRESHOLDS constant
- normalize_confidence() function
- confidence_to_string() function
- is_high_confidence() function
- is_reportable_confidence() function
- compare_confidence() function
- max_confidence() / min_confidence() / average_confidence() functions
"""

import pytest

from utils.confidence import (
    CONFIDENCE_SCALE,
    CONFIDENCE_THRESHOLDS,
    normalize_confidence,
    confidence_to_string,
    is_high_confidence,
    is_reportable_confidence,
    compare_confidence,
    max_confidence,
    min_confidence,
    average_confidence,
    to_numeric,
    to_label,
)


# =============================================================================
# CONFIDENCE_SCALE CONSTANT TESTS
# =============================================================================

class TestConfidenceScale:
    """Tests for CONFIDENCE_SCALE constant."""

    def test_scale_not_empty(self):
        """Test confidence scale is not empty."""
        assert len(CONFIDENCE_SCALE) > 0

    def test_high_confidence_values(self):
        """Test high confidence labels."""
        assert CONFIDENCE_SCALE["confirmed"] == 0.95
        assert CONFIDENCE_SCALE["high"] == 0.90
        assert CONFIDENCE_SCALE["verified"] == 0.90

    def test_medium_confidence_values(self):
        """Test medium confidence labels."""
        assert CONFIDENCE_SCALE["medium"] == 0.70
        assert CONFIDENCE_SCALE["moderate"] == 0.70
        assert CONFIDENCE_SCALE["likely"] == 0.65

    def test_low_confidence_values(self):
        """Test low confidence labels."""
        assert CONFIDENCE_SCALE["low"] == 0.40
        assert CONFIDENCE_SCALE["possible"] == 0.40
        assert CONFIDENCE_SCALE["weak"] == 0.30

    def test_info_confidence_values(self):
        """Test informational confidence labels."""
        assert CONFIDENCE_SCALE["info"] == 0.20
        assert CONFIDENCE_SCALE["informational"] == 0.20
        assert CONFIDENCE_SCALE["none"] == 0.0

    def test_all_values_in_valid_range(self):
        """Test all values are between 0.0 and 1.0."""
        for label, value in CONFIDENCE_SCALE.items():
            assert 0.0 <= value <= 1.0, f"Invalid value for {label}: {value}"


# =============================================================================
# CONFIDENCE_THRESHOLDS CONSTANT TESTS
# =============================================================================

class TestConfidenceThresholds:
    """Tests for CONFIDENCE_THRESHOLDS constant."""

    def test_thresholds_not_empty(self):
        """Test thresholds list is not empty."""
        assert len(CONFIDENCE_THRESHOLDS) > 0

    def test_thresholds_are_tuples(self):
        """Test each threshold is a tuple."""
        for threshold in CONFIDENCE_THRESHOLDS:
            assert isinstance(threshold, tuple)
            assert len(threshold) == 2

    def test_thresholds_sorted_descending(self):
        """Test thresholds are sorted in descending order."""
        values = [t[0] for t in CONFIDENCE_THRESHOLDS]
        assert values == sorted(values, reverse=True)

    def test_threshold_labels(self):
        """Test expected labels are present."""
        labels = [t[1] for t in CONFIDENCE_THRESHOLDS]
        assert "CONFIRMED" in labels
        assert "HIGH" in labels
        assert "MEDIUM" in labels
        assert "LOW" in labels
        assert "INFO" in labels
        assert "NONE" in labels


# =============================================================================
# NORMALIZE_CONFIDENCE FUNCTION TESTS
# =============================================================================

class TestNormalizeConfidence:
    """Tests for normalize_confidence() function."""

    def test_none_returns_default(self):
        """Test None returns default value (0.6)."""
        result = normalize_confidence(None)
        assert result == 0.6

    def test_empty_string_returns_default(self):
        """Test empty string returns default value."""
        result = normalize_confidence("")
        assert result == 0.6

    def test_high_string(self):
        """Test 'high' string normalization."""
        assert normalize_confidence("high") == 0.90
        assert normalize_confidence("HIGH") == 0.90
        assert normalize_confidence("High") == 0.90

    def test_medium_string(self):
        """Test 'medium' string normalization."""
        assert normalize_confidence("medium") == 0.70
        assert normalize_confidence("MEDIUM") == 0.70

    def test_low_string(self):
        """Test 'low' string normalization."""
        assert normalize_confidence("low") == 0.40
        assert normalize_confidence("LOW") == 0.40

    def test_confirmed_string(self):
        """Test 'confirmed' string normalization."""
        assert normalize_confidence("confirmed") == 0.95
        assert normalize_confidence("CONFIRMED") == 0.95

    def test_float_value_unchanged(self):
        """Test float values are returned unchanged (within bounds)."""
        assert normalize_confidence(0.75) == 0.75
        assert normalize_confidence(0.50) == 0.50
        assert normalize_confidence(0.0) == 0.0
        assert normalize_confidence(1.0) == 1.0

    def test_float_clamped_to_bounds(self):
        """Test float values are clamped to [0.0, 1.0]."""
        assert normalize_confidence(-0.5) == 0.0
        # Note: 1.5 is treated as a percentage (1.5%), not clamped
        # Only values <= 1.0 are treated as direct values
        assert normalize_confidence(1.5) == 0.015  # 1.5/100

    def test_percentage_conversion(self):
        """Test values > 1.0 are treated as percentages."""
        assert normalize_confidence(85) == 0.85
        assert normalize_confidence(100) == 1.0
        assert normalize_confidence(50) == 0.50
        assert normalize_confidence(150) == 1.0  # Clamped

    def test_string_percentage(self):
        """Test string percentages are converted."""
        assert normalize_confidence("85%") == 0.85
        assert normalize_confidence("75%") == 0.75
        assert normalize_confidence("100%") == 1.0

    def test_string_numeric(self):
        """Test string numeric values."""
        assert normalize_confidence("0.85") == 0.85
        assert normalize_confidence("0.5") == 0.50

    def test_partial_match(self):
        """Test partial matches in strings."""
        assert normalize_confidence("high_confidence") == 0.90
        assert normalize_confidence("very_low_risk") == 0.40

    def test_unknown_string(self):
        """Test unknown strings return medium."""
        assert normalize_confidence("unknown_label") == 0.50
        assert normalize_confidence("xyz") == 0.50


class TestNormalizeConfidenceEdgeCases:
    """Edge case tests for normalize_confidence()."""

    def test_whitespace_handling(self):
        """Test whitespace is stripped."""
        assert normalize_confidence("  high  ") == 0.90
        assert normalize_confidence("\thigh\n") == 0.90

    def test_integer_zero(self):
        """Test integer zero."""
        assert normalize_confidence(0) == 0.0

    def test_integer_one(self):
        """Test integer one."""
        assert normalize_confidence(1) == 1.0

    def test_large_percentage(self):
        """Test large percentage values are clamped."""
        assert normalize_confidence(200) == 1.0
        assert normalize_confidence(1000) == 1.0


# =============================================================================
# CONFIDENCE_TO_STRING FUNCTION TESTS
# =============================================================================

class TestConfidenceToString:
    """Tests for confidence_to_string() function."""

    def test_none_returns_medium(self):
        """Test None returns MEDIUM."""
        assert confidence_to_string(None) == "MEDIUM"

    def test_confirmed_threshold(self):
        """Test CONFIRMED threshold (>= 0.90)."""
        assert confidence_to_string(0.95) == "CONFIRMED"
        assert confidence_to_string(0.90) == "CONFIRMED"
        assert confidence_to_string(1.0) == "CONFIRMED"

    def test_high_threshold(self):
        """Test HIGH threshold (>= 0.80)."""
        assert confidence_to_string(0.85) == "HIGH"
        assert confidence_to_string(0.80) == "HIGH"
        assert confidence_to_string(0.89) == "HIGH"

    def test_medium_threshold(self):
        """Test MEDIUM threshold (>= 0.60)."""
        assert confidence_to_string(0.75) == "MEDIUM"
        assert confidence_to_string(0.60) == "MEDIUM"
        assert confidence_to_string(0.79) == "MEDIUM"

    def test_low_threshold(self):
        """Test LOW threshold (>= 0.40)."""
        assert confidence_to_string(0.50) == "LOW"
        assert confidence_to_string(0.40) == "LOW"
        assert confidence_to_string(0.59) == "LOW"

    def test_info_threshold(self):
        """Test INFO threshold (>= 0.20)."""
        assert confidence_to_string(0.30) == "INFO"
        assert confidence_to_string(0.20) == "INFO"
        assert confidence_to_string(0.39) == "INFO"

    def test_none_threshold(self):
        """Test NONE threshold (< 0.20)."""
        assert confidence_to_string(0.10) == "NONE"
        assert confidence_to_string(0.0) == "NONE"
        assert confidence_to_string(0.19) == "NONE"

    def test_string_input(self):
        """Test string input is normalized first."""
        # "high" normalizes to 0.90, which is >= CONFIRMED threshold (0.90)
        assert confidence_to_string("high") == "CONFIRMED"
        assert confidence_to_string("confirmed") == "CONFIRMED"
        # "medium" normalizes to 0.70, which is >= MEDIUM threshold (0.60)
        assert confidence_to_string("medium") == "MEDIUM"

    def test_percentage_input(self):
        """Test percentage input (> 1.0)."""
        assert confidence_to_string(95) == "CONFIRMED"
        assert confidence_to_string(85) == "HIGH"
        assert confidence_to_string(75) == "MEDIUM"


# =============================================================================
# IS_HIGH_CONFIDENCE FUNCTION TESTS
# =============================================================================

class TestIsHighConfidence:
    """Tests for is_high_confidence() function."""

    def test_high_values_return_true(self):
        """Test high values return True."""
        assert is_high_confidence(0.90) is True
        assert is_high_confidence(0.85) is True
        assert is_high_confidence(0.80) is True
        assert is_high_confidence(1.0) is True

    def test_medium_values_return_false(self):
        """Test medium values return False."""
        assert is_high_confidence(0.79) is False
        assert is_high_confidence(0.70) is False
        assert is_high_confidence(0.50) is False

    def test_string_input(self):
        """Test string input."""
        assert is_high_confidence("high") is True
        assert is_high_confidence("confirmed") is True
        assert is_high_confidence("medium") is False
        assert is_high_confidence("low") is False

    def test_none_input(self):
        """Test None input (default 0.6)."""
        assert is_high_confidence(None) is False  # 0.6 < 0.80


# =============================================================================
# IS_REPORTABLE_CONFIDENCE FUNCTION TESTS
# =============================================================================

class TestIsReportableConfidence:
    """Tests for is_reportable_confidence() function."""

    def test_default_threshold(self):
        """Test default threshold (0.50)."""
        assert is_reportable_confidence(0.50) is True
        assert is_reportable_confidence(0.60) is True
        assert is_reportable_confidence(0.49) is False

    def test_custom_threshold(self):
        """Test custom threshold."""
        assert is_reportable_confidence(0.70, min_threshold=0.60) is True
        assert is_reportable_confidence(0.50, min_threshold=0.60) is False
        assert is_reportable_confidence(0.30, min_threshold=0.20) is True

    def test_string_input(self):
        """Test string input."""
        assert is_reportable_confidence("high") is True
        assert is_reportable_confidence("medium") is True
        assert is_reportable_confidence("low") is False  # 0.40 < 0.50


# =============================================================================
# COMPARE_CONFIDENCE FUNCTION TESTS
# =============================================================================

class TestCompareConfidence:
    """Tests for compare_confidence() function."""

    def test_less_than(self):
        """Test a < b returns -1."""
        assert compare_confidence(0.50, 0.80) == -1
        assert compare_confidence("low", "high") == -1

    def test_greater_than(self):
        """Test a > b returns 1."""
        assert compare_confidence(0.80, 0.50) == 1
        assert compare_confidence("high", "low") == 1

    def test_equal(self):
        """Test a == b returns 0."""
        assert compare_confidence(0.80, 0.80) == 0
        assert compare_confidence("high", "high") == 0

    def test_mixed_types(self):
        """Test mixed input types."""
        assert compare_confidence(0.90, "high") == 0
        assert compare_confidence("low", 0.40) == 0


# =============================================================================
# MAX/MIN/AVERAGE CONFIDENCE FUNCTION TESTS
# =============================================================================

class TestMaxConfidence:
    """Tests for max_confidence() function."""

    def test_max_of_values(self):
        """Test max of multiple values."""
        assert max_confidence(0.50, 0.80, 0.60) == 0.80
        assert max_confidence(0.90, 0.70, 0.85) == 0.90

    def test_max_with_strings(self):
        """Test max with string values."""
        assert max_confidence("low", "high", "medium") == 0.90

    def test_max_empty(self):
        """Test max of empty returns 0.0."""
        assert max_confidence() == 0.0

    def test_max_single_value(self):
        """Test max of single value."""
        assert max_confidence(0.75) == 0.75


class TestMinConfidence:
    """Tests for min_confidence() function."""

    def test_min_of_values(self):
        """Test min of multiple values."""
        assert min_confidence(0.50, 0.80, 0.60) == 0.50
        assert min_confidence(0.90, 0.70, 0.85) == 0.70

    def test_min_with_strings(self):
        """Test min with string values."""
        assert min_confidence("low", "high", "medium") == 0.40

    def test_min_empty(self):
        """Test min of empty returns 0.0."""
        assert min_confidence() == 0.0

    def test_min_single_value(self):
        """Test min of single value."""
        assert min_confidence(0.75) == 0.75


class TestAverageConfidence:
    """Tests for average_confidence() function."""

    def test_average_of_values(self):
        """Test average of multiple values."""
        result = average_confidence(0.60, 0.80)
        assert result == 0.70

    def test_average_with_strings(self):
        """Test average with string values."""
        result = average_confidence("high", "low")  # 0.90 + 0.40 = 1.30 / 2 = 0.65
        assert result == 0.65

    def test_average_empty(self):
        """Test average of empty returns 0.0."""
        assert average_confidence() == 0.0

    def test_average_single_value(self):
        """Test average of single value."""
        assert average_confidence(0.75) == 0.75


# =============================================================================
# ALIAS TESTS
# =============================================================================

class TestAliases:
    """Tests for function aliases."""

    def test_to_numeric_alias(self):
        """Test to_numeric is alias for normalize_confidence."""
        assert to_numeric("high") == normalize_confidence("high")
        assert to_numeric(0.75) == normalize_confidence(0.75)

    def test_to_label_alias(self):
        """Test to_label is alias for confidence_to_string."""
        assert to_label(0.85) == confidence_to_string(0.85)
        assert to_label("high") == confidence_to_string("high")


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestConfidenceIntegration:
    """Integration tests for confidence utilities."""

    def test_round_trip_high(self):
        """Test round-trip conversion for high confidence."""
        original = 0.90
        string = confidence_to_string(original)  # CONFIRMED
        back = normalize_confidence(string)
        # "confirmed" maps to 0.95 in CONFIDENCE_SCALE
        assert back == 0.95

    def test_round_trip_medium(self):
        """Test round-trip conversion for medium confidence."""
        original = 0.70
        string = confidence_to_string(original)  # MEDIUM
        back = normalize_confidence(string)
        assert back == 0.70

    def test_round_trip_low(self):
        """Test round-trip conversion for low confidence."""
        original = 0.40
        string = confidence_to_string(original)  # LOW
        back = normalize_confidence(string)
        assert back == 0.40

    def test_consistent_comparison(self):
        """Test consistent comparison behavior."""
        values = [0.95, 0.85, 0.70, 0.40, 0.20]
        for i in range(len(values) - 1):
            assert compare_confidence(values[i], values[i+1]) == 1
            assert compare_confidence(values[i+1], values[i]) == -1

    def test_confidence_workflow(self):
        """Test typical confidence workflow."""
        # Start with string
        conf_str = "HIGH"
        # Convert to numeric
        conf_num = normalize_confidence(conf_str)
        assert conf_num == 0.90
        # Check if high
        assert is_high_confidence(conf_num) is True
        # Check if reportable
        assert is_reportable_confidence(conf_num) is True
        # Back to string
        conf_back = confidence_to_string(conf_num)
        assert conf_back == "CONFIRMED"  # 0.90 is CONFIRMED threshold
