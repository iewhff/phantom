"""
Tests for the scanning/safety/ module.

Tests SafetyMode, SafetyManager, payload validation, and safety level utilities.
"""

import pytest
from unittest.mock import Mock, patch

from scanning.safety import (
    SafetyMode,
    get_safety_index,
    is_mode_at_least,
    compare_safety_modes,
    validate_payload,
    filter_payloads,
    is_destructive_payload,
    DESTRUCTIVE_KEYWORDS,
    SafetyComponents,
)
from scanning.safety.levels import get_mode_emoji, get_mode_description


class TestSafetyMode:
    """Tests for SafetyMode enum."""

    def test_safety_mode_values(self):
        """Test that SafetyMode has expected values."""
        assert SafetyMode.PASSIVE.value == "passive"
        assert SafetyMode.SAFE.value == "safe"
        assert SafetyMode.CAUTIOUS.value == "cautious"
        assert SafetyMode.STANDARD.value == "standard"
        assert SafetyMode.AGGRESSIVE.value == "aggressive"
        assert SafetyMode.UNRESTRICTED.value == "unrestricted"

    def test_safety_mode_from_string(self):
        """Test SafetyMode.from_string() conversion."""
        assert SafetyMode.from_string("passive") == SafetyMode.PASSIVE
        assert SafetyMode.from_string("SAFE") == SafetyMode.SAFE
        assert SafetyMode.from_string("Cautious") == SafetyMode.CAUTIOUS
        assert SafetyMode.from_string("invalid") == SafetyMode.SAFE  # Default

    def test_safety_mode_comparison_gt(self):
        """Test SafetyMode > comparison."""
        assert SafetyMode.AGGRESSIVE > SafetyMode.SAFE
        assert SafetyMode.STANDARD > SafetyMode.CAUTIOUS
        assert not SafetyMode.PASSIVE > SafetyMode.SAFE

    def test_safety_mode_comparison_lt(self):
        """Test SafetyMode < comparison."""
        assert SafetyMode.SAFE < SafetyMode.AGGRESSIVE
        assert SafetyMode.PASSIVE < SafetyMode.CAUTIOUS
        assert not SafetyMode.AGGRESSIVE < SafetyMode.SAFE

    def test_safety_mode_comparison_ge(self):
        """Test SafetyMode >= comparison."""
        assert SafetyMode.AGGRESSIVE >= SafetyMode.SAFE
        assert SafetyMode.SAFE >= SafetyMode.SAFE
        assert not SafetyMode.PASSIVE >= SafetyMode.CAUTIOUS

    def test_safety_mode_comparison_le(self):
        """Test SafetyMode <= comparison."""
        assert SafetyMode.SAFE <= SafetyMode.AGGRESSIVE
        assert SafetyMode.SAFE <= SafetyMode.SAFE
        assert not SafetyMode.AGGRESSIVE <= SafetyMode.CAUTIOUS

    def test_safety_mode_index(self):
        """Test SafetyMode.index property."""
        assert SafetyMode.PASSIVE.index == 0
        assert SafetyMode.SAFE.index == 1
        assert SafetyMode.CAUTIOUS.index == 2
        assert SafetyMode.STANDARD.index == 3
        assert SafetyMode.AGGRESSIVE.index == 4
        assert SafetyMode.UNRESTRICTED.index == 5


class TestSafetyLevelUtils:
    """Tests for safety level utility functions."""

    def test_get_safety_index(self):
        """Test get_safety_index function."""
        assert get_safety_index("passive") == 0
        assert get_safety_index("safe") == 1
        assert get_safety_index("cautious") == 2
        assert get_safety_index("standard") == 3
        assert get_safety_index("aggressive") == 4
        assert get_safety_index("unrestricted") == 5
        # Invalid defaults to safe (1)
        assert get_safety_index("invalid") == 1

    def test_is_mode_at_least(self):
        """Test is_mode_at_least function."""
        # Standard is at least cautious
        assert is_mode_at_least("standard", "cautious")
        # Aggressive is at least safe
        assert is_mode_at_least("aggressive", "safe")
        # Safe is at least safe
        assert is_mode_at_least("safe", "safe")
        # Safe is NOT at least aggressive
        assert not is_mode_at_least("safe", "aggressive")
        # Passive is NOT at least cautious
        assert not is_mode_at_least("passive", "cautious")

    def test_compare_safety_modes(self):
        """Test compare_safety_modes function."""
        assert compare_safety_modes("aggressive", "safe") == 1
        assert compare_safety_modes("safe", "aggressive") == -1
        assert compare_safety_modes("standard", "standard") == 0

    def test_get_mode_emoji(self):
        """Test get_mode_emoji function."""
        assert get_mode_emoji("passive") == "🔒"
        assert get_mode_emoji("safe") == "🔒"
        assert get_mode_emoji("cautious") == "⚠️"
        assert get_mode_emoji("standard") == "🟡"
        assert get_mode_emoji("aggressive") == "🔴"
        assert get_mode_emoji("unrestricted") == "💀"
        assert get_mode_emoji("invalid") == "🔒"  # Default

    def test_get_mode_description(self):
        """Test get_mode_description function."""
        desc = get_mode_description("safe")
        assert desc["http_safety"] == "ENABLED"
        assert desc["destructive_blocking"] == "FULL"

        desc = get_mode_description("aggressive")
        assert desc["http_safety"] == "MINIMAL"
        assert desc["destructive_blocking"] == "DISABLED"


class TestDestructivePayloadDetection:
    """Tests for destructive payload detection."""

    def test_destructive_keywords_list(self):
        """Test DESTRUCTIVE_KEYWORDS contains expected patterns."""
        assert "DROP" in DESTRUCTIVE_KEYWORDS
        assert "DELETE" in DESTRUCTIVE_KEYWORDS
        assert "rm -rf" in DESTRUCTIVE_KEYWORDS
        assert "shutdown" in DESTRUCTIVE_KEYWORDS

    def test_is_destructive_payload_sql(self):
        """Test SQL destructive payload detection."""
        is_destructive, matched = is_destructive_payload("DROP TABLE users")
        assert is_destructive
        assert "DROP" in matched

        is_destructive, matched = is_destructive_payload("DELETE FROM accounts")
        assert is_destructive
        assert "DELETE" in matched

        is_destructive, matched = is_destructive_payload("TRUNCATE TABLE logs")
        assert is_destructive
        assert "TRUNCATE" in matched

    def test_is_destructive_payload_command(self):
        """Test command injection destructive payload detection."""
        is_destructive, matched = is_destructive_payload("rm -rf /")
        assert is_destructive
        assert "rm -rf" in matched

        is_destructive, matched = is_destructive_payload("shutdown now")
        assert is_destructive
        assert "shutdown" in matched

    def test_is_destructive_payload_safe(self):
        """Test safe payloads are not flagged."""
        is_destructive, matched = is_destructive_payload("' OR 1=1--")
        assert not is_destructive
        assert matched is None

        is_destructive, matched = is_destructive_payload("<script>alert(1)</script>")
        assert not is_destructive
        assert matched is None

        is_destructive, matched = is_destructive_payload("SELECT * FROM users")
        assert not is_destructive
        assert matched is None


class TestPayloadValidation:
    """Tests for payload validation functions."""

    def test_validate_payload_safe_mode(self):
        """Test payload validation in safe mode."""
        # Destructive payloads blocked
        is_safe, reason = validate_payload("DROP TABLE users", "sqli", "safe")
        assert not is_safe
        assert "DROP" in reason

        # Non-destructive payloads allowed
        is_safe, reason = validate_payload("' OR 1=1--", "sqli", "safe")
        assert is_safe
        assert reason == "OK"

    def test_validate_payload_passive_mode(self):
        """Test payload validation in passive mode."""
        # Destructive payloads blocked
        is_safe, reason = validate_payload("rm -rf /", "cmdi", "passive")
        assert not is_safe

    def test_validate_payload_aggressive_mode(self):
        """Test payload validation in aggressive mode."""
        # Destructive payloads allowed in aggressive mode
        is_safe, reason = validate_payload("DROP TABLE users", "sqli", "aggressive")
        assert is_safe
        assert reason == "OK"

    def test_filter_payloads_safe_mode(self):
        """Test payload filtering in safe mode."""
        payloads = [
            "' OR 1=1--",
            "DROP TABLE users",
            "SELECT * FROM users",
            "DELETE FROM accounts",
            "<script>alert(1)</script>",
        ]
        filtered = filter_payloads(payloads, "sqli", "safe")

        # Destructive payloads removed
        assert "DROP TABLE users" not in filtered
        assert "DELETE FROM accounts" not in filtered

        # Safe payloads kept
        assert "' OR 1=1--" in filtered
        assert "SELECT * FROM users" in filtered
        assert "<script>alert(1)</script>" in filtered

    def test_filter_payloads_aggressive_mode(self):
        """Test payload filtering in aggressive mode."""
        payloads = [
            "' OR 1=1--",
            "DROP TABLE users",
        ]
        filtered = filter_payloads(payloads, "sqli", "aggressive")

        # All payloads kept in aggressive mode
        assert len(filtered) == 2


class TestSafetyComponents:
    """Tests for SafetyComponents dataclass."""

    def test_default_components(self):
        """Test SafetyComponents default values."""
        components = SafetyComponents()
        assert components.mode == SafetyMode.SAFE
        assert components.payload_analyzer is None
        assert components.proof_config is None
        assert components.evidence_redactor is None
        assert components.scope_guard is None
        assert components.safe_scanner is None
        assert components.evidence_collector is None
        assert components.rate_limiter is None

    def test_components_with_mode(self):
        """Test SafetyComponents with custom mode."""
        components = SafetyComponents(mode=SafetyMode.AGGRESSIVE)
        assert components.mode == SafetyMode.AGGRESSIVE


class TestSafetyManagerIntegration:
    """Integration tests for SafetyManager with FullScanner."""

    def test_fullscanner_safety_manager_integration(self):
        """Test that FullScanner correctly uses SafetyManager."""
        from scanning.full_scanner import FullScanner
        from core.config_manager import Settings

        settings = Settings()
        scanner = FullScanner(settings, safe_mode="cautious")

        # Verify SafetyManager is used
        assert scanner._safety_manager is not None
        assert scanner._safety_manager.mode == SafetyMode.CAUTIOUS

        # Verify backwards compatible attributes
        assert scanner.safe_mode == "cautious"
        assert scanner.rate_limiter is not None
        assert scanner.safe_scanner is not None

    def test_fullscanner_safety_methods(self):
        """Test that FullScanner safety methods work."""
        from scanning.full_scanner import FullScanner
        from core.config_manager import Settings

        settings = Settings()
        scanner = FullScanner(settings, safe_mode="safe")

        # Test payload validation via SafetyManager
        is_allowed = scanner._safety_manager.is_mode_allowed("cautious")
        assert not is_allowed  # safe < cautious

        is_allowed = scanner._safety_manager.is_mode_allowed("passive")
        assert is_allowed  # safe >= passive

    def test_fullscanner_with_different_modes(self):
        """Test FullScanner with different safety modes."""
        from scanning.full_scanner import FullScanner
        from core.config_manager import Settings

        settings = Settings()

        # Test each mode
        for mode in ["passive", "safe", "cautious", "standard", "aggressive"]:
            scanner = FullScanner(settings, safe_mode=mode)
            assert scanner.safe_mode == mode
            assert scanner._safety_manager.mode.value == mode
