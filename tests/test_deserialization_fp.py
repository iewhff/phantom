"""
Unit tests for Deserialization Scanner FP Mitigation v3.0.

Tests:
1. SPA/trivial endpoint detection
2. Negative control mechanism
3. Generic vs specific error patterns
4. Confidence calculation with signals
5. Severity calculation from signals
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
import asyncio


class TestSPATrivialEndpoints:
    """Test SPA/trivial endpoint detection."""

    def test_detect_static_assets(self):
        """Should detect static asset URLs."""
        from scanning.modules.deserialization_scanner import DeserializationScanner

        scanner = DeserializationScanner(MagicMock())

        assert scanner._is_static_asset("/static/app.js") is True
        assert scanner._is_static_asset("/assets/style.css") is True
        assert scanner._is_static_asset("/images/logo.png") is True
        assert scanner._is_static_asset("/fonts/arial.woff2") is True

    def test_api_endpoints_not_static(self):
        """Should NOT flag API endpoints as static."""
        from scanning.modules.deserialization_scanner import DeserializationScanner

        scanner = DeserializationScanner(MagicMock())

        assert scanner._is_static_asset("/api/users") is False
        assert scanner._is_static_asset("/rest/data") is False
        assert scanner._is_static_asset("/graphql") is False

    def test_detect_spa_trivial_endpoints(self):
        """Should detect SPA trivial endpoints."""
        from scanning.modules.deserialization_scanner import DeserializationScanner

        scanner = DeserializationScanner(MagicMock())

        assert scanner._is_spa_trivial_endpoint("/") is True
        assert scanner._is_spa_trivial_endpoint("/index.html") is True
        assert scanner._is_spa_trivial_endpoint("/login") is True
        assert scanner._is_spa_trivial_endpoint("/swagger/ui") is True
        assert scanner._is_spa_trivial_endpoint("/api-docs/v1") is True
        assert scanner._is_spa_trivial_endpoint("/static/bundle.js") is True
        assert scanner._is_spa_trivial_endpoint("/assets/styles.css") is True

    def test_api_not_trivial(self):
        """Should NOT flag API endpoints as trivial."""
        from scanning.modules.deserialization_scanner import DeserializationScanner

        scanner = DeserializationScanner(MagicMock())

        # Real API endpoints should NOT be trivial
        assert scanner._is_spa_trivial_endpoint("/api/users/123") is False
        assert scanner._is_spa_trivial_endpoint("/rest/products") is False
        assert scanner._is_spa_trivial_endpoint("/data/export") is False
        assert scanner._is_spa_trivial_endpoint("/graphql") is False  # graphql != graphiql
        assert scanner._is_spa_trivial_endpoint("/users/profile") is False

    def test_detect_spa_catch_all_response(self):
        """Should detect SPA catch-all responses."""
        from scanning.modules.deserialization_scanner import DeserializationScanner

        scanner = DeserializationScanner(MagicMock())

        spa_response = """
        <!DOCTYPE html>
        <html>
        <head><title>My App</title></head>
        <body>
            <div id="app-root"></div>
            <script src="/static/bundle.js"></script>
            <script src="/static/vendor.js"></script>
        </body>
        </html>
        """
        assert scanner._is_spa_catch_all_response(spa_response) is True

    def test_normal_html_not_spa(self):
        """Should NOT flag normal HTML as SPA."""
        from scanning.modules.deserialization_scanner import DeserializationScanner

        scanner = DeserializationScanner(MagicMock())

        normal_html = """
        <!DOCTYPE html>
        <html>
        <body><h1>Welcome</h1><p>This is a normal page.</p></body>
        </html>
        """
        assert scanner._is_spa_catch_all_response(normal_html) is False


class TestErrorPatterns:
    """Test generic vs specific error detection."""

    def test_detect_generic_errors(self):
        """Should detect generic error patterns."""
        from scanning.modules.deserialization_scanner import DeserializationScanner

        scanner = DeserializationScanner(MagicMock())

        response_text = "Fatal error: Call to undefined method foo()"
        assert scanner._is_generic_error("fatal error", response_text) is True

    def test_specific_error_not_generic(self):
        """Should NOT flag specific deserialization errors as generic."""
        from scanning.modules.deserialization_scanner import DeserializationScanner

        scanner = DeserializationScanner(MagicMock())

        response_text = "java.io.StreamCorruptedException: invalid stream header"
        assert scanner._is_generic_error("StreamCorruptedException", response_text) is False

    def test_detect_java_specific_errors(self):
        """Should detect Java deserialization-specific errors."""
        from scanning.modules.deserialization_scanner import DeserializationScanner

        scanner = DeserializationScanner(MagicMock())

        response_text = "java.io.InvalidClassException: Mismatch during deserialization"
        is_specific, pattern = scanner._is_deser_specific_error("java", response_text)

        assert is_specific is True
        assert "InvalidClassException" in pattern

    def test_detect_php_specific_errors(self):
        """Should detect PHP deserialization-specific errors."""
        from scanning.modules.deserialization_scanner import DeserializationScanner

        scanner = DeserializationScanner(MagicMock())

        response_text = "unserialize() expects parameter 1 to be string, array given"
        is_specific, pattern = scanner._is_deser_specific_error("php", response_text)

        assert is_specific is True

    def test_detect_python_specific_errors(self):
        """Should detect Python deserialization-specific errors."""
        from scanning.modules.deserialization_scanner import DeserializationScanner

        scanner = DeserializationScanner(MagicMock())

        response_text = "pickle.UnpicklingError: invalid load key"
        is_specific, pattern = scanner._is_deser_specific_error("python", response_text)

        assert is_specific is True

    def test_no_specific_error_in_normal_response(self):
        """Should NOT find specific errors in normal responses."""
        from scanning.modules.deserialization_scanner import DeserializationScanner

        scanner = DeserializationScanner(MagicMock())

        response_text = '{"status": "ok", "data": []}'
        is_specific, pattern = scanner._is_deser_specific_error("java", response_text)

        assert is_specific is False
        assert pattern == ""


class TestConfidenceCalculation:
    """Test confidence calculation with multiple signals."""

    def test_negative_control_failed_is_low(self):
        """Negative control failure should always be LOW."""
        from scanning.modules.deserialization_scanner import DeserializationScanner

        scanner = DeserializationScanner(MagicMock())

        confidence = scanner._calculate_confidence(
            is_specific=True,
            status_code=200,
            baseline_matches=False,
            negative_control_failed=True,  # This should override everything
            tech_fingerprint_matches=True,
        )
        assert confidence == "LOW"

    def test_baseline_matches_is_low(self):
        """Baseline matching should be LOW confidence."""
        from scanning.modules.deserialization_scanner import DeserializationScanner

        scanner = DeserializationScanner(MagicMock())

        confidence = scanner._calculate_confidence(
            is_specific=True,
            status_code=200,
            baseline_matches=True,  # Same error on baseline
        )
        assert confidence == "LOW"

    def test_specific_pattern_200_is_high(self):
        """Specific pattern + 200 status should be HIGH."""
        from scanning.modules.deserialization_scanner import DeserializationScanner

        scanner = DeserializationScanner(MagicMock())

        confidence = scanner._calculate_confidence(
            is_specific=True,  # Specific pattern found
            status_code=200,
            baseline_matches=False,
            tech_fingerprint_matches=True,
        )
        assert confidence == "HIGH"

    def test_generic_pattern_is_medium_or_low(self):
        """Generic pattern should be MEDIUM or LOW."""
        from scanning.modules.deserialization_scanner import DeserializationScanner

        scanner = DeserializationScanner(MagicMock())

        confidence = scanner._calculate_confidence(
            is_specific=False,  # Generic pattern
            status_code=200,
            baseline_matches=False,
        )
        assert confidence in ["LOW", "MEDIUM"]


class TestSeverityCalculation:
    """Test severity calculation from signals."""

    def test_low_confidence_is_medium(self):
        """Low confidence should be MEDIUM at most."""
        from scanning.modules.deserialization_scanner import DeserializationScanner

        scanner = DeserializationScanner(MagicMock())

        severity = scanner._calculate_severity_from_signals(
            confidence=40.0,
            has_rce_indicator=True,
        )
        assert severity == "MEDIUM"

    def test_high_confidence_with_rce_is_critical(self):
        """High confidence + RCE indicator should be CRITICAL."""
        from scanning.modules.deserialization_scanner import DeserializationScanner

        scanner = DeserializationScanner(MagicMock())

        severity = scanner._calculate_severity_from_signals(
            confidence=85.0,
            has_rce_indicator=True,
        )
        assert severity == "CRITICAL"

    def test_high_confidence_no_rce_is_high(self):
        """High confidence without RCE should be HIGH."""
        from scanning.modules.deserialization_scanner import DeserializationScanner

        scanner = DeserializationScanner(MagicMock())

        severity = scanner._calculate_severity_from_signals(
            confidence=85.0,
            has_rce_indicator=False,
        )
        assert severity == "HIGH"


class TestErrorPageDetection:
    """Test error page detection."""

    def test_404_is_error_page(self):
        """404 status should be error page."""
        from scanning.modules.deserialization_scanner import DeserializationScanner

        scanner = DeserializationScanner(MagicMock())

        assert scanner._is_error_page(404, "Not Found", "text/html") is True

    def test_500_is_error_page_without_specific(self):
        """500 without specific error should be error page."""
        from scanning.modules.deserialization_scanner import DeserializationScanner

        scanner = DeserializationScanner(MagicMock())

        assert scanner._is_error_page(500, "Internal Server Error", "text/html") is True

    def test_500_with_deser_error_not_error_page(self):
        """500 WITH specific deserialization error is NOT an error page."""
        from scanning.modules.deserialization_scanner import DeserializationScanner

        scanner = DeserializationScanner(MagicMock())

        response_text = "java.io.StreamCorruptedException: invalid stream header"
        assert scanner._is_error_page(500, response_text, "text/html") is False

    def test_200_json_not_error_page(self):
        """200 with JSON is NOT an error page."""
        from scanning.modules.deserialization_scanner import DeserializationScanner

        scanner = DeserializationScanner(MagicMock())

        assert scanner._is_error_page(200, '{"status": "ok"}', "application/json") is False

    def test_short_html_is_error_page(self):
        """Very short HTML should be treated as error page."""
        from scanning.modules.deserialization_scanner import DeserializationScanner

        scanner = DeserializationScanner(MagicMock())

        assert scanner._is_error_page(200, "<html><body>Error</body></html>", "text/html") is True


class TestPatternConstants:
    """Test pattern constant definitions."""

    def test_deser_patterns_all_languages(self):
        """Deserialization patterns should cover all languages."""
        from scanning.modules.deserialization_scanner import DESER_SPECIFIC_PATTERNS

        required_techs = ["java", "php", "python", "dotnet"]
        for tech in required_techs:
            assert tech in DESER_SPECIFIC_PATTERNS, f"Missing tech: {tech}"
            assert len(DESER_SPECIFIC_PATTERNS[tech]) >= 3, f"Too few patterns for {tech}"

    def test_spa_trivial_includes_common(self):
        """SPA trivial list should include common paths."""
        from scanning.modules.deserialization_scanner import SPA_TRIVIAL_ENDPOINTS

        assert "/" in SPA_TRIVIAL_ENDPOINTS
        assert "/login" in SPA_TRIVIAL_ENDPOINTS
        assert "/swagger" in SPA_TRIVIAL_ENDPOINTS


class TestSeveritySignalRequirements:
    """Test severity signal requirements."""

    def test_critical_requires_3_signals(self):
        """CRITICAL should require 3+ signals."""
        from scanning.modules.deserialization_scanner import SEVERITY_SIGNAL_REQUIREMENTS

        assert SEVERITY_SIGNAL_REQUIREMENTS.get("CRITICAL", 0) >= 3

    def test_high_requires_2_signals(self):
        """HIGH should require 2+ signals."""
        from scanning.modules.deserialization_scanner import SEVERITY_SIGNAL_REQUIREMENTS

        assert SEVERITY_SIGNAL_REQUIREMENTS.get("HIGH", 0) >= 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
