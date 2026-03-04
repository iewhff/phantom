"""
Unit tests for HTTP Smuggling Scanner v3.0.

Tests:
1. SmugglingConfirmation tracking
2. Multi-method detection logic
3. Severity based on confirmation count
4. Re-check mechanisms
5. Response analysis
6. Sanity check logic
"""

import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from dataclasses import dataclass


class TestSmugglingConfirmation:
    """Test the SmugglingConfirmation dataclass."""

    def test_confirmation_count_empty(self):
        """Empty confirmation should have 0 count."""
        from scanning.modules.smuggling_scanner import (
            SmugglingConfirmation,
            SmugglingType,
        )

        conf = SmugglingConfirmation(smuggling_type=SmugglingType.CL_TE)
        assert conf.confirmation_count == 0
        assert conf.is_confirmed is False
        assert conf.confidence == 0.0

    def test_confirmation_count_single(self):
        """Single confirmation should not be confirmed (need 2+)."""
        from scanning.modules.smuggling_scanner import (
            SmugglingConfirmation,
            SmugglingType,
            DetectionMethod,
        )

        conf = SmugglingConfirmation(smuggling_type=SmugglingType.CL_TE)
        conf.add_confirmation(
            method="POST",
            detection_method=DetectionMethod.TIMING,
            timing_delta=5.0,
            evidence="Timing delay detected",
            technique="clte_post_timing",
        )

        assert conf.confirmation_count == 1
        assert conf.is_confirmed is False  # Need 2+ for confirmation
        assert conf.confidence == 0.60  # Low confidence for single method

    def test_confirmation_count_double(self):
        """Two confirmations should be confirmed."""
        from scanning.modules.smuggling_scanner import (
            SmugglingConfirmation,
            SmugglingType,
            DetectionMethod,
        )

        conf = SmugglingConfirmation(smuggling_type=SmugglingType.TE_CL)
        conf.add_confirmation(
            method="POST",
            detection_method=DetectionMethod.TIMING,
            timing_delta=5.0,
            evidence="POST timing delay",
            technique="tecl_post_timing",
        )
        conf.add_confirmation(
            method="GET",
            detection_method=DetectionMethod.TIMING,
            timing_delta=4.5,
            evidence="GET timing delay",
            technique="tecl_get_timing",
        )

        assert conf.confirmation_count == 2
        assert conf.is_confirmed is True
        assert conf.confidence == 0.85  # High confidence for 2 methods

    def test_confirmation_count_triple(self):
        """Three confirmations should have very high confidence."""
        from scanning.modules.smuggling_scanner import (
            SmugglingConfirmation,
            SmugglingType,
            DetectionMethod,
        )

        conf = SmugglingConfirmation(smuggling_type=SmugglingType.CL_TE)
        for method in ["POST", "GET", "HEAD"]:
            conf.add_confirmation(
                method=method,
                detection_method=DetectionMethod.TIMING,
                timing_delta=5.0,
                evidence=f"{method} timing delay",
                technique=f"clte_{method.lower()}_timing",
            )

        assert conf.confirmation_count == 3
        assert conf.is_confirmed is True
        assert conf.confidence == 0.95  # Very high confidence

    def test_duplicate_method_not_added(self):
        """Same method should not be added twice."""
        from scanning.modules.smuggling_scanner import (
            SmugglingConfirmation,
            SmugglingType,
            DetectionMethod,
        )

        conf = SmugglingConfirmation(smuggling_type=SmugglingType.CL_TE)
        conf.add_confirmation(
            method="POST",
            detection_method=DetectionMethod.TIMING,
            timing_delta=5.0,
            evidence="First detection",
            technique="clte_post_timing",
        )
        conf.add_confirmation(
            method="POST",  # Same method again
            detection_method=DetectionMethod.REFLECTION,
            timing_delta=6.0,
            evidence="Second detection",
            technique="clte_post_timing",
        )

        assert conf.confirmation_count == 1  # Still just 1


class TestSeverityLogic:
    """Test severity assignment based on confirmation count."""

    def test_single_method_is_high(self):
        """Single method confirmation should be HIGH, not CRITICAL."""
        from scanning.modules.smuggling_scanner import (
            HTTPSmugglingScanner,
            SmugglingConfirmation,
            SmugglingType,
            DetectionMethod,
        )

        scanner = HTTPSmugglingScanner(MagicMock())
        conf = SmugglingConfirmation(smuggling_type=SmugglingType.CL_TE)
        conf.add_confirmation(
            method="POST",
            detection_method=DetectionMethod.TIMING,
            timing_delta=5.0,
            evidence="Timing delay",
            technique="clte_post_timing",
        )

        finding = scanner._create_confirmed_finding(conf, "example.com", 443, SmugglingType.CL_TE)

        assert finding is not None
        assert finding["severity"] == "HIGH"  # Not CRITICAL
        assert finding["cvss_score"] == 7.5
        # Should have warning about manual verification
        evidence_str = str(finding["evidence"])
        assert "manual verification" in evidence_str.lower()

    def test_double_method_is_critical(self):
        """Two method confirmations should be CRITICAL."""
        from scanning.modules.smuggling_scanner import (
            HTTPSmugglingScanner,
            SmugglingConfirmation,
            SmugglingType,
            DetectionMethod,
        )

        scanner = HTTPSmugglingScanner(MagicMock())
        conf = SmugglingConfirmation(smuggling_type=SmugglingType.TE_CL)
        conf.add_confirmation(
            method="POST",
            detection_method=DetectionMethod.TIMING,
            timing_delta=5.0,
            evidence="POST timing",
            technique="tecl_post_timing",
        )
        conf.add_confirmation(
            method="GET",
            detection_method=DetectionMethod.TIMING,
            timing_delta=4.0,
            evidence="GET timing",
            technique="tecl_get_timing",
        )

        finding = scanner._create_confirmed_finding(conf, "example.com", 443, SmugglingType.TE_CL)

        assert finding is not None
        assert finding["severity"] == "CRITICAL"
        assert finding["cvss_score"] == 9.1

    def test_no_confirmation_no_finding(self):
        """Zero confirmations should return None."""
        from scanning.modules.smuggling_scanner import (
            HTTPSmugglingScanner,
            SmugglingConfirmation,
            SmugglingType,
        )

        scanner = HTTPSmugglingScanner(MagicMock())
        conf = SmugglingConfirmation(smuggling_type=SmugglingType.CL_TE)

        finding = scanner._create_confirmed_finding(conf, "example.com", 443, SmugglingType.CL_TE)

        assert finding is None


class TestResponseAnalysis:
    """Test response analysis for smuggling indicators."""

    def test_reflection_detection(self):
        """Should detect smuggled method prefix in response."""
        from scanning.modules.smuggling_scanner import (
            HTTPSmugglingScanner,
            SmugglingType,
            DetectionMethod,
        )

        scanner = HTTPSmugglingScanner(MagicMock())

        # Response contains "GPOST" indicator
        response = "HTTP/1.1 405 Method Not Allowed\r\nGPOST invalid"
        result = scanner._analyze_smuggling_response(
            response, elapsed=1.0, baseline=1.0,
            smuggling_type=SmugglingType.CL_TE,
            technique="test"
        )

        assert result.vulnerable is True
        assert result.detection_method == DetectionMethod.REFLECTION
        assert result.confidence == 0.9

    def test_multiple_responses_detection(self):
        """Should detect multiple HTTP responses."""
        from scanning.modules.smuggling_scanner import (
            HTTPSmugglingScanner,
            SmugglingType,
            DetectionMethod,
        )

        scanner = HTTPSmugglingScanner(MagicMock())

        # Response contains two HTTP/1.1 headers
        response = "HTTP/1.1 200 OK\r\n\r\nHTTP/1.1 200 OK"
        result = scanner._analyze_smuggling_response(
            response, elapsed=1.0, baseline=1.0,
            smuggling_type=SmugglingType.TE_CL,
            technique="test"
        )

        assert result.vulnerable is True
        assert result.detection_method == DetectionMethod.RESPONSE_DIFF
        assert result.confidence == 0.85

    def test_timing_detection(self):
        """Should detect timing anomaly."""
        from scanning.modules.smuggling_scanner import (
            HTTPSmugglingScanner,
            SmugglingType,
            DetectionMethod,
        )

        scanner = HTTPSmugglingScanner(MagicMock())
        scanner.timing_threshold = 5.0

        # Normal response but with timing delay
        response = "HTTP/1.1 200 OK\r\n\r\nHello"
        result = scanner._analyze_smuggling_response(
            response, elapsed=8.0, baseline=1.0,  # 8x baseline
            smuggling_type=SmugglingType.CL_TE,
            technique="test"
        )

        assert result.vulnerable is True
        assert result.detection_method == DetectionMethod.TIMING
        assert result.confidence == 0.7

    def test_normal_response_not_vulnerable(self):
        """Normal response should not be flagged."""
        from scanning.modules.smuggling_scanner import (
            HTTPSmugglingScanner,
            SmugglingType,
        )

        scanner = HTTPSmugglingScanner(MagicMock())

        response = "HTTP/1.1 200 OK\r\n\r\nHello World"
        result = scanner._analyze_smuggling_response(
            response, elapsed=1.0, baseline=1.0,
            smuggling_type=SmugglingType.CL_TE,
            technique="test"
        )

        assert result.vulnerable is False


class TestMultiMethodPayloads:
    """Test multi-method payload definitions."""

    def test_clte_payloads_have_all_methods(self):
        """CLTE payloads should have POST, GET, HEAD."""
        from scanning.modules.smuggling_scanner import CLTE_MULTI_METHOD

        assert "POST" in CLTE_MULTI_METHOD
        assert "GET" in CLTE_MULTI_METHOD
        assert "HEAD" in CLTE_MULTI_METHOD

    def test_tecl_payloads_have_all_methods(self):
        """TECL payloads should have POST, GET, HEAD."""
        from scanning.modules.smuggling_scanner import TECL_MULTI_METHOD

        assert "POST" in TECL_MULTI_METHOD
        assert "GET" in TECL_MULTI_METHOD
        assert "HEAD" in TECL_MULTI_METHOD

    def test_payloads_have_required_fields(self):
        """All payloads should have name, request, description."""
        from scanning.modules.smuggling_scanner import (
            CLTE_MULTI_METHOD,
            TECL_MULTI_METHOD,
        )

        for method, payload in CLTE_MULTI_METHOD.items():
            assert "name" in payload, f"CLTE {method} missing name"
            assert "request" in payload, f"CLTE {method} missing request"
            assert "description" in payload, f"CLTE {method} missing description"

        for method, payload in TECL_MULTI_METHOD.items():
            assert "name" in payload, f"TECL {method} missing name"
            assert "request" in payload, f"TECL {method} missing request"
            assert "description" in payload, f"TECL {method} missing description"

    def test_payloads_are_formattable(self):
        """Payloads should have {host} and {path} placeholders."""
        from scanning.modules.smuggling_scanner import (
            CLTE_MULTI_METHOD,
            TECL_MULTI_METHOD,
        )

        for method, payload in CLTE_MULTI_METHOD.items():
            # Should not raise exception
            formatted = payload["request"].format(host="example.com", path="/test")
            assert "example.com" in formatted
            assert "/test" in formatted

        for method, payload in TECL_MULTI_METHOD.items():
            formatted = payload["request"].format(host="example.com", path="/test")
            assert "example.com" in formatted
            assert "/test" in formatted


class TestChunkingVariations:
    """Test chunking variation definitions."""

    def test_chunking_variations_exist(self):
        """Should have multiple chunking variations."""
        from scanning.modules.smuggling_scanner import CHUNKING_VARIATIONS

        assert len(CHUNKING_VARIATIONS) >= 5  # At least 5 variations

    def test_chunking_variations_have_required_fields(self):
        """Each variation should have name and chunk."""
        from scanning.modules.smuggling_scanner import CHUNKING_VARIATIONS

        for var in CHUNKING_VARIATIONS:
            assert "name" in var
            assert "chunk" in var


class TestTEObfuscations:
    """Test TE obfuscation techniques."""

    def test_obfuscations_comprehensive(self):
        """Should have many obfuscation techniques."""
        from scanning.modules.smuggling_scanner import TE_OBFUSCATIONS

        assert len(TE_OBFUSCATIONS) >= 15  # Comprehensive list

    def test_obfuscations_have_structure(self):
        """Each obfuscation should have name, header, description."""
        from scanning.modules.smuggling_scanner import TE_OBFUSCATIONS

        for obf in TE_OBFUSCATIONS:
            assert hasattr(obf, "name")
            assert hasattr(obf, "header")
            assert hasattr(obf, "description")


class TestScannerVersion:
    """Test scanner version and configuration."""

    def test_version_is_v3(self):
        """Scanner should be v3.0."""
        from scanning.modules.smuggling_scanner import HTTPSmugglingScanner

        scanner = HTTPSmugglingScanner(MagicMock())
        assert "3.0" in scanner.version

    def test_min_confirmations_is_2(self):
        """Minimum confirmations for CRITICAL should be 2."""
        from scanning.modules.smuggling_scanner import HTTPSmugglingScanner

        scanner = HTTPSmugglingScanner(MagicMock())
        assert scanner.MIN_CONFIRMATIONS_FOR_CRITICAL == 2

    def test_sanity_check_count_default(self):
        """Should have sanity check count configured."""
        from scanning.modules.smuggling_scanner import HTTPSmugglingScanner

        scanner = HTTPSmugglingScanner(MagicMock())
        assert hasattr(scanner, "sanity_check_count")
        assert scanner.sanity_check_count >= 2


class TestSafetyModeBlocking:
    """Test safety mode blocking."""

    @pytest.mark.asyncio
    async def test_blocked_in_safe_mode(self):
        """Smuggling should be blocked in safe mode."""
        import os
        from scanning.modules.smuggling_scanner import HTTPSmugglingScanner
        from utils.rate_limiter import RateLimiter

        os.environ["PHANTOM_SAFE_MODE"] = "safe"

        scanner = HTTPSmugglingScanner(MagicMock())
        rate_limiter = RateLimiter()

        result = await scanner.scan("https://example.com", {}, rate_limiter)

        assert result.get("skipped") is True
        assert "Blocked" in result.get("reason", "")

        # Reset
        os.environ["PHANTOM_SAFE_MODE"] = "standard"

    @pytest.mark.asyncio
    async def test_blocked_in_cautious_mode(self):
        """Smuggling should be blocked in cautious mode."""
        import os
        from scanning.modules.smuggling_scanner import HTTPSmugglingScanner
        from utils.rate_limiter import RateLimiter

        os.environ["PHANTOM_SAFE_MODE"] = "cautious"

        scanner = HTTPSmugglingScanner(MagicMock())
        rate_limiter = RateLimiter()

        result = await scanner.scan("https://example.com", {}, rate_limiter)

        assert result.get("skipped") is True

        # Reset
        os.environ["PHANTOM_SAFE_MODE"] = "standard"


class TestFindingMetadata:
    """Test finding metadata fields."""

    def test_finding_has_multimethod_metadata(self):
        """Finding should include multi-method verification info."""
        from scanning.modules.smuggling_scanner import (
            HTTPSmugglingScanner,
            SmugglingConfirmation,
            SmugglingType,
            DetectionMethod,
        )

        scanner = HTTPSmugglingScanner(MagicMock())
        conf = SmugglingConfirmation(smuggling_type=SmugglingType.CL_TE)
        conf.add_confirmation(
            method="POST",
            detection_method=DetectionMethod.TIMING,
            timing_delta=5.0,
            evidence="Timing",
            technique="clte_post_timing",
        )
        conf.add_confirmation(
            method="GET",
            detection_method=DetectionMethod.TIMING,
            timing_delta=4.0,
            evidence="Timing",
            technique="clte_get_timing",
        )

        finding = scanner._create_confirmed_finding(conf, "example.com", 443, SmugglingType.CL_TE)

        assert finding is not None
        metadata = finding.get("metadata", {})
        assert "confirmation_count" in metadata
        assert metadata["confirmation_count"] == 2
        assert "confirmed_methods" in metadata
        assert "POST" in metadata["confirmed_methods"]
        assert "GET" in metadata["confirmed_methods"]
        assert metadata["multi_method_verified"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
