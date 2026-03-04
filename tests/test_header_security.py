"""
Tests for scanning/modules/header_security.py

Covers:
- HeaderSecurityChecker class attributes
- HEADER_CHECKS constant (9 headers)
- DANGEROUS_VALUES constant
- _get_business_impact() method
- _get_fix_priority() method
- Header coverage validation
"""

import pytest
from scanning.modules.header_security import HeaderSecurityChecker


# =============================================================================
# CLASS ATTRIBUTES
# =============================================================================

class TestHeaderSecurityCheckerClass:
    """Test HeaderSecurityChecker class attributes."""

    def test_name(self):
        assert HeaderSecurityChecker.name == "headers"

    def test_is_scan_module(self):
        from scanning.vuln_scanner import ScanModule
        assert issubclass(HeaderSecurityChecker, ScanModule)


# =============================================================================
# HEADER CHECKS
# =============================================================================

class TestHeaderChecks:
    """Test HEADER_CHECKS constant."""

    def test_not_empty(self):
        assert len(HeaderSecurityChecker.HEADER_CHECKS) > 0

    def test_has_hsts(self):
        assert "Strict-Transport-Security" in HeaderSecurityChecker.HEADER_CHECKS

    def test_has_csp(self):
        assert "Content-Security-Policy" in HeaderSecurityChecker.HEADER_CHECKS

    def test_has_xcto(self):
        assert "X-Content-Type-Options" in HeaderSecurityChecker.HEADER_CHECKS

    def test_has_xfo(self):
        assert "X-Frame-Options" in HeaderSecurityChecker.HEADER_CHECKS

    def test_has_permissions_policy(self):
        assert "Permissions-Policy" in HeaderSecurityChecker.HEADER_CHECKS

    def test_has_referrer_policy(self):
        assert "Referrer-Policy" in HeaderSecurityChecker.HEADER_CHECKS

    # Modern headers
    def test_has_coop(self):
        assert "Cross-Origin-Opener-Policy" in HeaderSecurityChecker.HEADER_CHECKS

    def test_has_coep(self):
        assert "Cross-Origin-Embedder-Policy" in HeaderSecurityChecker.HEADER_CHECKS

    def test_has_corp(self):
        assert "Cross-Origin-Resource-Policy" in HeaderSecurityChecker.HEADER_CHECKS

    # Structure validation
    def test_all_have_severity(self):
        for header, config in HeaderSecurityChecker.HEADER_CHECKS.items():
            assert "severity" in config, f"Missing severity for {header}"

    def test_all_have_cvss(self):
        for header, config in HeaderSecurityChecker.HEADER_CHECKS.items():
            assert "cvss" in config, f"Missing cvss for {header}"

    def test_all_have_cwe(self):
        for header, config in HeaderSecurityChecker.HEADER_CHECKS.items():
            assert "cwe" in config, f"Missing cwe for {header}"

    def test_all_have_description(self):
        for header, config in HeaderSecurityChecker.HEADER_CHECKS.items():
            assert "description" in config, f"Missing description for {header}"
            assert len(config["description"]) > 10

    def test_all_have_remediation(self):
        for header, config in HeaderSecurityChecker.HEADER_CHECKS.items():
            assert "remediation" in config, f"Missing remediation for {header}"
            assert len(config["remediation"]) > 10

    def test_all_have_example(self):
        for header, config in HeaderSecurityChecker.HEADER_CHECKS.items():
            assert "example" in config, f"Missing example for {header}"

    # Specific check content
    def test_hsts_severity(self):
        assert HeaderSecurityChecker.HEADER_CHECKS["Strict-Transport-Security"]["severity"] == "MEDIUM"

    def test_csp_cwe(self):
        assert HeaderSecurityChecker.HEADER_CHECKS["Content-Security-Policy"]["cwe"] == "CWE-79"

    def test_xcto_severity(self):
        assert HeaderSecurityChecker.HEADER_CHECKS["X-Content-Type-Options"]["severity"] == "LOW"

    def test_xfo_cwe(self):
        assert HeaderSecurityChecker.HEADER_CHECKS["X-Frame-Options"]["cwe"] == "CWE-1021"

    def test_hsts_example(self):
        example = HeaderSecurityChecker.HEADER_CHECKS["Strict-Transport-Security"]["example"]
        assert "max-age" in example
        assert "includeSubDomains" in example

    def test_csp_example(self):
        example = HeaderSecurityChecker.HEADER_CHECKS["Content-Security-Policy"]["example"]
        assert "default-src" in example

    def test_xcto_example(self):
        example = HeaderSecurityChecker.HEADER_CHECKS["X-Content-Type-Options"]["example"]
        assert "nosniff" in example


# =============================================================================
# DANGEROUS VALUES
# =============================================================================

class TestDangerousValues:
    """Test DANGEROUS_VALUES constant."""

    def test_not_empty(self):
        assert len(HeaderSecurityChecker.DANGEROUS_VALUES) > 0

    def test_has_csp_dangerous(self):
        assert "Content-Security-Policy" in HeaderSecurityChecker.DANGEROUS_VALUES

    def test_csp_has_unsafe_inline(self):
        csp = HeaderSecurityChecker.DANGEROUS_VALUES["Content-Security-Policy"]
        assert "unsafe-inline" in csp

    def test_csp_has_unsafe_eval(self):
        csp = HeaderSecurityChecker.DANGEROUS_VALUES["Content-Security-Policy"]
        assert "unsafe-eval" in csp

    def test_unsafe_inline_severity(self):
        config = HeaderSecurityChecker.DANGEROUS_VALUES["Content-Security-Policy"]["unsafe-inline"]
        assert config["severity"] == "MEDIUM"

    def test_unsafe_eval_severity(self):
        config = HeaderSecurityChecker.DANGEROUS_VALUES["Content-Security-Policy"]["unsafe-eval"]
        assert config["severity"] == "MEDIUM"

    def test_all_have_description(self):
        for header, values in HeaderSecurityChecker.DANGEROUS_VALUES.items():
            for value, config in values.items():
                assert "description" in config, f"Missing description for {header}/{value}"


# =============================================================================
# BUSINESS IMPACT
# =============================================================================

class TestGetBusinessImpact:
    """Test _get_business_impact method."""

    @pytest.fixture
    def checker(self):
        """Create checker with minimal mock settings."""
        from unittest.mock import MagicMock
        settings = MagicMock()
        settings.scanning.modules.get.return_value = {}
        return HeaderSecurityChecker(settings)

    def test_csp_impact(self, checker):
        impact = checker._get_business_impact("Content-Security-Policy")
        assert "XSS" in impact
        assert "IF" in impact  # Conditional language

    def test_xfo_impact(self, checker):
        impact = checker._get_business_impact("X-Frame-Options")
        assert "clickjacking" in impact.lower()

    def test_hsts_impact(self, checker):
        impact = checker._get_business_impact("Strict-Transport-Security")
        assert "MITM" in impact

    def test_permissions_policy_impact(self, checker):
        impact = checker._get_business_impact("Permissions-Policy")
        assert "camera" in impact.lower() or "microphone" in impact.lower()

    def test_referrer_policy_impact(self, checker):
        impact = checker._get_business_impact("Referrer-Policy")
        assert "leak" in impact.lower() or "Referer" in impact

    def test_xcto_impact(self, checker):
        impact = checker._get_business_impact("X-Content-Type-Options")
        assert "MIME" in impact or "sniffing" in impact.lower()

    def test_coop_impact(self, checker):
        impact = checker._get_business_impact("Cross-Origin-Opener-Policy")
        assert "SharedArrayBuffer" in impact or "cross-origin" in impact.lower()

    def test_coep_impact(self, checker):
        impact = checker._get_business_impact("Cross-Origin-Embedder-Policy")
        assert "cross-origin" in impact.lower()

    def test_corp_impact(self, checker):
        impact = checker._get_business_impact("Cross-Origin-Resource-Policy")
        assert "Spectre" in impact or "embed" in impact.lower()

    def test_unknown_header_impact(self, checker):
        impact = checker._get_business_impact("X-Unknown-Header")
        assert "missing" in impact.lower() or "Security" in impact


# =============================================================================
# FIX PRIORITY
# =============================================================================

class TestGetFixPriority:
    """Test _get_fix_priority method."""

    @pytest.fixture
    def checker(self):
        from unittest.mock import MagicMock
        settings = MagicMock()
        settings.scanning.modules.get.return_value = {}
        return HeaderSecurityChecker(settings)

    def test_critical_priority(self, checker):
        result = checker._get_fix_priority("CRITICAL")
        assert "24 hours" in result or "Now" in result

    def test_high_priority(self, checker):
        result = checker._get_fix_priority("HIGH")
        assert "Sprint" in result

    def test_medium_priority(self, checker):
        result = checker._get_fix_priority("MEDIUM")
        assert "Sprint" in result or "Next" in result

    def test_low_priority(self, checker):
        result = checker._get_fix_priority("LOW")
        assert "Convenient" in result

    def test_info_priority(self, checker):
        result = checker._get_fix_priority("INFO")
        assert "Optional" in result

    def test_unknown_priority(self, checker):
        result = checker._get_fix_priority("UNKNOWN")
        assert result is not None  # Should return default


# =============================================================================
# COVERAGE VALIDATION
# =============================================================================

class TestCoverageValidation:
    """Validate comprehensive header coverage."""

    def test_owasp_headers_covered(self):
        """All OWASP recommended headers should be checked."""
        owasp_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ]
        for header in owasp_headers:
            assert header in HeaderSecurityChecker.HEADER_CHECKS, f"OWASP header missing: {header}"

    def test_modern_security_headers_covered(self):
        """Modern cross-origin isolation headers should be checked."""
        modern_headers = [
            "Cross-Origin-Opener-Policy",
            "Cross-Origin-Embedder-Policy",
            "Cross-Origin-Resource-Policy",
        ]
        for header in modern_headers:
            assert header in HeaderSecurityChecker.HEADER_CHECKS, f"Modern header missing: {header}"

    def test_all_cvss_scores_valid(self):
        """All CVSS scores should be between 0 and 10."""
        for header, config in HeaderSecurityChecker.HEADER_CHECKS.items():
            cvss = config["cvss"]
            assert 0 <= cvss <= 10, f"Invalid CVSS for {header}: {cvss}"

    def test_all_severities_valid(self):
        """All severities should be valid levels."""
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        for header, config in HeaderSecurityChecker.HEADER_CHECKS.items():
            assert config["severity"] in valid, f"Invalid severity for {header}: {config['severity']}"

    def test_all_cwes_formatted(self):
        """All CWE IDs should follow CWE-NNN format."""
        for header, config in HeaderSecurityChecker.HEADER_CHECKS.items():
            assert config["cwe"].startswith("CWE-"), f"Bad CWE format for {header}: {config['cwe']}"
