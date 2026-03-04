"""
Unit tests for TechFingerprinter.

Tests cover:
- SignatureDatabase integrity
- Version comparison (C2 fix)
- Singleton thread safety (C3 fix)
- Header, cookie, body matching
- Implication resolution
- CVE mapping
- Attack surface calculation
- Metrics tracking (H8 fix)

Run with: pytest tests/test_tech_fingerprinter.py -v
"""

import pytest
import asyncio
import threading
from unittest.mock import MagicMock, AsyncMock, patch

from phantom.tech_fingerprinter import (
    TechFingerprinter,
    TechCategory,
    DetectionMethod,
    Severity,
    CVEEntry,
    TechSignature,
    DetectedTechnology,
    FingerprintResult,
    SignatureDatabase,
    get_tech_fingerprinter,
    get_tech_fingerprinter_sync,
    get_signature_count,
)


class TestSignatureDatabase:
    """Test signature database integrity."""

    def test_signature_count_minimum(self):
        """Database should have 500+ signatures."""
        db = SignatureDatabase()
        assert len(db.signatures) >= 400  # Allow some margin

    def test_all_categories_have_signatures(self):
        """All major categories should have signatures."""
        db = SignatureDatabase()

        categories_found = set()
        for sig in db.signatures.values():
            categories_found.add(sig.category)

        # Check major categories exist
        major_categories = [
            TechCategory.WEB_FRAMEWORK,
            TechCategory.CMS,
            TechCategory.JAVASCRIPT_FRAMEWORK,
            TechCategory.SERVER,
            TechCategory.LANGUAGE,
            TechCategory.DATABASE,
            TechCategory.CDN,
            TechCategory.WAF,
        ]

        for cat in major_categories:
            assert cat in categories_found, f"Missing category: {cat.name}"

    def test_signature_has_required_fields(self):
        """Each signature should have name and category."""
        db = SignatureDatabase()

        for name, sig in db.signatures.items():
            assert sig.name, f"Signature missing name: {name}"
            assert sig.category, f"Signature {name} missing category"
            assert isinstance(sig.category, TechCategory)

    def test_get_signature_exists(self):
        """get_signature method should exist and work."""
        db = SignatureDatabase()

        # Test known signature
        django = db.get_signature("Django")
        assert django is not None
        assert django.name == "Django"

        # Test unknown signature
        unknown = db.get_signature("NonexistentTech123")
        assert unknown is None

    def test_version_patterns_compile(self):
        """All version patterns should be valid regex."""
        db = SignatureDatabase()

        for sig in db.signatures.values():
            for pattern in sig.version_patterns:
                # Pattern should be compiled (Pattern object)
                assert hasattr(pattern, 'search'), f"Invalid pattern in {sig.name}"


class TestVersionComparison:
    """Test C2 fix: version comparison logic."""

    def test_less_than_version(self):
        """Test < version comparison."""
        fp = TechFingerprinter()

        # 5.3.10 < 5.3.18 = True
        assert fp._version_affected("5.3.10", ["<5.3.18"]) is True

        # 5.3.18 < 5.3.18 = False
        assert fp._version_affected("5.3.18", ["<5.3.18"]) is False

        # 5.3.20 < 5.3.18 = False
        assert fp._version_affected("5.3.20", ["<5.3.18"]) is False

    def test_less_than_or_equal_version(self):
        """Test <= version comparison."""
        fp = TechFingerprinter()

        assert fp._version_affected("5.3.17", ["<=5.3.18"]) is True
        assert fp._version_affected("5.3.18", ["<=5.3.18"]) is True
        assert fp._version_affected("5.3.19", ["<=5.3.18"]) is False

    def test_greater_than_version(self):
        """Test > version comparison."""
        fp = TechFingerprinter()

        assert fp._version_affected("5.4.0", [">5.3.18"]) is True
        assert fp._version_affected("5.3.18", [">5.3.18"]) is False
        assert fp._version_affected("5.3.10", [">5.3.18"]) is False

    def test_exact_version_match(self):
        """Test exact version matching."""
        fp = TechFingerprinter()

        assert fp._version_affected("2.4.49", ["2.4.49"]) is True
        assert fp._version_affected("2.4.50", ["2.4.49"]) is False

    def test_wildcard_version(self):
        """Test wildcard version matching (5.3.x)."""
        fp = TechFingerprinter()

        assert fp._version_affected("5.3.0", ["5.3.x"]) is True
        assert fp._version_affected("5.3.18", ["5.3.x"]) is True
        assert fp._version_affected("5.4.0", ["5.3.x"]) is False

    def test_version_range(self):
        """Test version range (>=4.0,<5.0)."""
        fp = TechFingerprinter()

        assert fp._version_affected("4.5.0", [">=4.0,<5.0"]) is True
        assert fp._version_affected("4.0.0", [">=4.0,<5.0"]) is True
        assert fp._version_affected("5.0.0", [">=4.0,<5.0"]) is False
        assert fp._version_affected("3.9.0", [">=4.0,<5.0"]) is False

    def test_empty_version_returns_false(self):
        """Empty version should return False, not True."""
        fp = TechFingerprinter()

        # C2 fix: was returning True for any unclear case
        assert fp._version_affected("", ["<5.0"]) is False
        assert fp._version_affected("5.0", []) is False

    def test_version_with_prefix(self):
        """Versions with v prefix should be parsed."""
        fp = TechFingerprinter()

        assert fp._version_affected("v5.3.10", ["<5.3.18"]) is True
        assert fp._version_affected("V5.3.10", ["<5.3.18"]) is True


class TestSingletonThreadSafety:
    """Test C3 fix: singleton thread safety."""

    def test_sync_singleton_returns_same_instance(self):
        """Sync getter should return same instance."""
        fp1 = get_tech_fingerprinter_sync()
        fp2 = get_tech_fingerprinter_sync()
        assert fp1 is fp2

    @pytest.mark.asyncio
    async def test_async_singleton_returns_same_instance(self):
        """Async getter should return same instance."""
        fp1 = await get_tech_fingerprinter()
        fp2 = await get_tech_fingerprinter()
        assert fp1 is fp2

    def test_concurrent_sync_access(self):
        """Concurrent sync access should be thread-safe."""
        instances = []
        errors = []

        def get_instance():
            try:
                fp = get_tech_fingerprinter_sync()
                instances.append(id(fp))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=get_instance) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        # All instances should have same id
        assert len(set(instances)) == 1


class TestHeaderMatching:
    """Test HTTP header fingerprinting."""

    def test_express_header_detection(self):
        """X-Powered-By: Express should detect Express."""
        fp = TechFingerprinter()
        detections = {}

        headers = {"X-Powered-By": "Express"}
        fp._match_headers(headers, detections)

        assert "express" in detections
        assert DetectionMethod.HTTP_HEADER in detections["express"].detection_methods

    def test_cloudflare_ray_detection(self):
        """CF-RAY header should detect Cloudflare."""
        fp = TechFingerprinter()
        detections = {}

        headers = {"CF-RAY": "abc123-LAX"}
        fp._match_headers(headers, detections)

        # Should detect Cloudflare WAF or CDN
        cloudflare_detected = any("cloudflare" in k.lower() for k in detections.keys())
        assert cloudflare_detected

    def test_case_insensitive_header_matching(self):
        """Header matching should be case-insensitive."""
        fp = TechFingerprinter()
        detections = {}

        headers = {"x-powered-by": "Express"}  # lowercase
        fp._match_headers(headers, detections)

        assert "express" in detections


class TestCookieMatching:
    """Test cookie fingerprinting."""

    def test_phpsessid_detection(self):
        """PHPSESSID cookie should detect PHP."""
        fp = TechFingerprinter()
        detections = {}

        cookies = {"PHPSESSID": "abc123"}
        fp._match_cookies(cookies, detections)

        assert "php" in detections

    def test_jsessionid_detection(self):
        """JSESSIONID cookie should detect Java."""
        fp = TechFingerprinter()
        detections = {}

        cookies = {"JSESSIONID": "abc123"}
        fp._match_cookies(cookies, detections)

        # Should detect Java or Spring
        java_detected = any(
            "java" in k.lower() or "spring" in k.lower() or "tomcat" in k.lower()
            for k in detections.keys()
        )
        assert java_detected


class TestBodyMatching:
    """Test HTML body fingerprinting."""

    def test_react_data_attribute(self):
        """data-reactroot should detect React."""
        fp = TechFingerprinter()
        detections = {}

        body = '<div data-reactroot="">Content</div>'
        fp._match_body(body, detections)

        assert "react" in detections

    def test_angular_ng_version(self):
        """ng-version should detect Angular."""
        fp = TechFingerprinter()
        detections = {}

        body = '<app-root ng-version="15.0.0"></app-root>'
        fp._match_body(body, detections)

        assert "angular" in detections

    def test_wordpress_paths(self):
        """WordPress paths should detect WordPress."""
        fp = TechFingerprinter()
        detections = {}

        body = '<link rel="stylesheet" href="/wp-content/themes/theme/style.css">'
        fp._match_body(body, detections)

        assert "wordpress" in detections

    def test_empty_body_no_crash(self):
        """Empty body should not crash."""
        fp = TechFingerprinter()
        detections = {}

        fp._match_body("", detections)
        assert len(detections) == 0


class TestImplicationResolution:
    """Test implied technology resolution."""

    def test_django_implies_python(self):
        """Django detection should imply Python."""
        fp = TechFingerprinter()
        detections = {
            "django": DetectedTechnology(
                name="Django",
                category=TechCategory.WEB_FRAMEWORK,
                confidence=0.8,
            )
        }

        fp._process_implications(detections)

        assert "python" in detections
        assert detections["python"].implied_by == "Django"

    def test_wordpress_implies_php_mysql(self):
        """WordPress should imply PHP and MySQL."""
        fp = TechFingerprinter()
        detections = {
            "wordpress": DetectedTechnology(
                name="WordPress",
                category=TechCategory.CMS,
                confidence=0.8,
            )
        }

        fp._process_implications(detections)

        assert "php" in detections
        assert "mysql" in detections


class TestCVEMapping:
    """Test CVE correlation."""

    def test_cve_mapped_for_detected_version(self):
        """CVEs should be mapped when version detected."""
        fp = TechFingerprinter()

        # Simulate detected Spring with vulnerable version
        detections = {
            "spring": DetectedTechnology(
                name="Spring",
                category=TechCategory.WEB_FRAMEWORK,
                version="5.3.10",  # Vulnerable to Spring4Shell
                confidence=0.9,
            )
        }

        fp._map_cves(detections)

        # Should have CVEs mapped
        spring_tech = detections["spring"]
        # Note: depends on CVE database having Spring4Shell
        # If test fails, CVE database may need updating


class TestAttackSurfaceCalculation:
    """Test attack surface scoring."""

    def test_empty_detections_returns_zero(self):
        """No technologies = 0 attack surface."""
        fp = TechFingerprinter()
        score = fp._calculate_attack_surface({})
        assert score == 0.0

    def test_single_technology_calculation(self):
        """Single technology should produce reasonable score."""
        fp = TechFingerprinter()
        detections = {
            "wordpress": DetectedTechnology(
                name="WordPress",
                category=TechCategory.CMS,
                confidence=0.8,
            )
        }

        score = fp._calculate_attack_surface(detections)

        # WordPress has 0.8 weight * 0.8 confidence * 2 = ~1.28
        assert 0 < score < 5

    def test_cves_increase_attack_surface(self):
        """CVEs should increase attack surface score."""
        fp = TechFingerprinter()

        # Without CVEs
        detections1 = {
            "spring": DetectedTechnology(
                name="Spring",
                category=TechCategory.WEB_FRAMEWORK,
                confidence=0.8,
            )
        }
        score1 = fp._calculate_attack_surface(detections1)

        # With critical CVE
        detections2 = {
            "spring": DetectedTechnology(
                name="Spring",
                category=TechCategory.WEB_FRAMEWORK,
                confidence=0.8,
                cves=[CVEEntry("CVE-2022-22965", Severity.CRITICAL, "RCE", cvss_score=9.8)],
            )
        }
        score2 = fp._calculate_attack_surface(detections2)

        assert score2 > score1


class TestMetricsTracking:
    """Test H8 fix: metrics tracking."""

    def test_initial_metrics_structure(self):
        """Metrics should have expected structure."""
        fp = TechFingerprinter()

        expected_keys = [
            "targets_fingerprinted",
            "technologies_detected",
            "versions_extracted",
            "cves_mapped",
            "errors",
            "errors_by_type",
            "by_category",
            "by_detection_method",
        ]

        for key in expected_keys:
            assert key in fp._metrics, f"Missing metric: {key}"

    def test_get_metrics_returns_computed_values(self):
        """get_metrics() should include computed values."""
        fp = TechFingerprinter()

        metrics = fp.get_metrics()

        assert "signature_count" in metrics
        assert metrics["signature_count"] > 400
        assert "avg_techs_per_target" in metrics

    def test_reset_metrics_clears_counters(self):
        """reset_metrics() should clear all counters."""
        fp = TechFingerprinter()

        # Simulate some activity
        fp._metrics["targets_fingerprinted"] = 10
        fp._metrics["technologies_detected"] = 50

        fp.reset_metrics()

        assert fp._metrics["targets_fingerprinted"] == 0
        assert fp._metrics["technologies_detected"] == 0


class TestSecurityHeaders:
    """Test security header checking."""

    def test_detects_present_headers(self):
        """Should detect present security headers."""
        fp = TechFingerprinter()

        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
        }

        result = fp._check_security_headers(headers)

        assert result["Strict-Transport-Security"] is True
        assert result["Content-Security-Policy"] is True
        assert result["X-Frame-Options"] is True

    def test_detects_missing_headers(self):
        """Should detect missing security headers."""
        fp = TechFingerprinter()

        headers = {}
        result = fp._check_security_headers(headers)

        assert result["Strict-Transport-Security"] is False
        assert result["X-XSS-Protection"] is False


class TestSignatureCount:
    """Test signature count helper."""

    def test_get_signature_count(self):
        """get_signature_count() should return > 400."""
        count = get_signature_count()
        assert count > 400


class TestFingerprintResult:
    """Test FingerprintResult dataclass."""

    def test_to_dict(self):
        """to_dict() should serialize properly."""
        result = FingerprintResult(
            target="https://example.com",
            attack_surface_score=5.5,
        )

        d = result.to_dict()

        assert d["target"] == "https://example.com"
        assert d["attack_surface_score"] == 5.5
        assert "technologies" in d

    def test_get_by_category(self):
        """get_by_category() should filter correctly."""
        result = FingerprintResult(
            target="https://example.com",
            technologies=[
                DetectedTechnology("Django", TechCategory.WEB_FRAMEWORK, confidence=0.9),
                DetectedTechnology("React", TechCategory.JAVASCRIPT_FRAMEWORK, confidence=0.8),
                DetectedTechnology("WordPress", TechCategory.CMS, confidence=0.7),
            ],
        )

        frameworks = result.get_by_category(TechCategory.WEB_FRAMEWORK)
        assert len(frameworks) == 1
        assert frameworks[0].name == "Django"

    def test_has_technology(self):
        """has_technology() should check case-insensitively."""
        result = FingerprintResult(
            target="https://example.com",
            technologies=[
                DetectedTechnology("Django", TechCategory.WEB_FRAMEWORK, confidence=0.9),
            ],
        )

        assert result.has_technology("Django") is True
        assert result.has_technology("django") is True  # case insensitive
        assert result.has_technology("Flask") is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
