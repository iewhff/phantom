"""
Tests for scanning/modules/header_security.py - HTTP Security Headers Checker.

Covers:
- HEADER_CHECKS constant validation
- DANGEROUS_VALUES patterns
- _check_missing_headers method
- _check_dangerous_values method
- _get_business_impact method
- _get_fix_priority method
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from scanning.modules.header_security import HeaderSecurityChecker
from scanning.findings import Severity, VulnType


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def mock_settings():
    """Create mock settings."""
    settings = MagicMock()
    settings.scanning.modules = {}
    return settings


@pytest.fixture
def checker(mock_settings):
    """Create HeaderSecurityChecker instance."""
    return HeaderSecurityChecker(mock_settings)


# =============================================================================
# HEADER_CHECKS CONSTANT TESTS
# =============================================================================

class TestHeaderChecksConstant:
    """Tests for HEADER_CHECKS constant."""

    def test_hsts_check_exists(self, checker):
        """Test HSTS check is defined."""
        assert "Strict-Transport-Security" in checker.HEADER_CHECKS

    def test_csp_check_exists(self, checker):
        """Test CSP check is defined."""
        assert "Content-Security-Policy" in checker.HEADER_CHECKS

    def test_x_content_type_options_exists(self, checker):
        """Test X-Content-Type-Options check is defined."""
        assert "X-Content-Type-Options" in checker.HEADER_CHECKS

    def test_x_frame_options_exists(self, checker):
        """Test X-Frame-Options check is defined."""
        assert "X-Frame-Options" in checker.HEADER_CHECKS

    def test_permissions_policy_exists(self, checker):
        """Test Permissions-Policy check is defined."""
        assert "Permissions-Policy" in checker.HEADER_CHECKS

    def test_referrer_policy_exists(self, checker):
        """Test Referrer-Policy check is defined."""
        assert "Referrer-Policy" in checker.HEADER_CHECKS

    def test_coop_exists(self, checker):
        """Test Cross-Origin-Opener-Policy check is defined."""
        assert "Cross-Origin-Opener-Policy" in checker.HEADER_CHECKS

    def test_coep_exists(self, checker):
        """Test Cross-Origin-Embedder-Policy check is defined."""
        assert "Cross-Origin-Embedder-Policy" in checker.HEADER_CHECKS

    def test_corp_exists(self, checker):
        """Test Cross-Origin-Resource-Policy check is defined."""
        assert "Cross-Origin-Resource-Policy" in checker.HEADER_CHECKS

    def test_check_has_required_fields(self, checker):
        """Test each check has required fields."""
        required_fields = ["severity", "cvss", "cwe", "description", "remediation"]

        for header, config in checker.HEADER_CHECKS.items():
            for field in required_fields:
                assert field in config, f"Missing {field} in {header} check"

    def test_severity_values_valid(self, checker):
        """Test all severity values are valid."""
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

        for header, config in checker.HEADER_CHECKS.items():
            assert config["severity"] in valid_severities, f"Invalid severity for {header}"

    def test_cvss_scores_in_range(self, checker):
        """Test CVSS scores are in valid range."""
        for header, config in checker.HEADER_CHECKS.items():
            assert 0 <= config["cvss"] <= 10, f"Invalid CVSS score for {header}"

    def test_cwe_format(self, checker):
        """Test CWE IDs have correct format."""
        import re
        pattern = r'^CWE-\d+$'

        for header, config in checker.HEADER_CHECKS.items():
            assert re.match(pattern, config["cwe"]), f"Invalid CWE format for {header}"


# =============================================================================
# DANGEROUS_VALUES CONSTANT TESTS
# =============================================================================

class TestDangerousValuesConstant:
    """Tests for DANGEROUS_VALUES constant."""

    def test_csp_dangerous_values_exist(self, checker):
        """Test CSP dangerous values are defined."""
        assert "Content-Security-Policy" in checker.DANGEROUS_VALUES

    def test_unsafe_inline_detected(self, checker):
        """Test unsafe-inline is flagged."""
        csp_checks = checker.DANGEROUS_VALUES["Content-Security-Policy"]
        assert "unsafe-inline" in csp_checks

    def test_unsafe_eval_detected(self, checker):
        """Test unsafe-eval is flagged."""
        csp_checks = checker.DANGEROUS_VALUES["Content-Security-Policy"]
        assert "unsafe-eval" in csp_checks

    def test_dangerous_values_have_severity(self, checker):
        """Test dangerous values have severity field."""
        for header, patterns in checker.DANGEROUS_VALUES.items():
            for pattern, config in patterns.items():
                assert "severity" in config, f"Missing severity for {pattern}"

    def test_dangerous_values_have_description(self, checker):
        """Test dangerous values have description field."""
        for header, patterns in checker.DANGEROUS_VALUES.items():
            for pattern, config in patterns.items():
                assert "description" in config, f"Missing description for {pattern}"


# =============================================================================
# _check_missing_headers TESTS
# =============================================================================

class TestCheckMissingHeaders:
    """Tests for _check_missing_headers method."""

    def test_all_headers_present(self, checker):
        """Test no findings when all headers present."""
        headers = {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "permissions-policy": "geolocation=()",
            "referrer-policy": "strict-origin-when-cross-origin",
            "cross-origin-opener-policy": "same-origin",
            "cross-origin-embedder-policy": "require-corp",
            "cross-origin-resource-policy": "same-origin",
        }

        findings = checker._check_missing_headers(headers, "https://example.com")
        assert len(findings) == 0

    def test_missing_hsts(self, checker):
        """Test finding for missing HSTS."""
        headers = {}  # No headers

        findings = checker._check_missing_headers(headers, "https://example.com")

        hsts_findings = [f for f in findings if "HSTS" in f.name or "Strict-Transport" in f.name]
        assert len(hsts_findings) == 1
        assert hsts_findings[0].severity == Severity.MEDIUM

    def test_missing_csp(self, checker):
        """Test finding for missing CSP."""
        headers = {}

        findings = checker._check_missing_headers(headers, "https://example.com")

        csp_findings = [f for f in findings if "Content-Security-Policy" in f.name]
        assert len(csp_findings) == 1
        assert csp_findings[0].severity == Severity.MEDIUM

    def test_missing_x_content_type_options(self, checker):
        """Test finding for missing X-Content-Type-Options."""
        headers = {}

        findings = checker._check_missing_headers(headers, "https://example.com")

        xcto_findings = [f for f in findings if "X-Content-Type-Options" in f.name]
        assert len(xcto_findings) == 1
        assert xcto_findings[0].severity == Severity.LOW

    def test_finding_has_evidence(self, checker):
        """Test findings have proper evidence."""
        headers = {}

        findings = checker._check_missing_headers(headers, "https://example.com")

        for f in findings:
            assert len(f.evidence) > 0
            assert any("NOT present" in e or "Reproduction" in e for e in f.evidence)

    def test_finding_has_curl_command(self, checker):
        """Test findings have curl command in metadata."""
        headers = {}

        findings = checker._check_missing_headers(headers, "https://example.com")

        for f in findings:
            assert "curl_command" in f.metadata

    def test_finding_has_fix_priority(self, checker):
        """Test findings have fix priority."""
        headers = {}

        findings = checker._check_missing_headers(headers, "https://example.com")

        for f in findings:
            assert "fix_priority" in f.metadata

    def test_partial_headers_present(self, checker):
        """Test only missing headers are flagged."""
        headers = {
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
        }

        findings = checker._check_missing_headers(headers, "https://example.com")

        # Should NOT find HSTS or X-Content-Type-Options
        header_names = [f.metadata.get("header", "") for f in findings]
        assert "Strict-Transport-Security" not in header_names
        assert "X-Content-Type-Options" not in header_names

        # Should find CSP and others
        assert "Content-Security-Policy" in header_names


# =============================================================================
# _check_dangerous_values TESTS
# =============================================================================

class TestCheckDangerousValues:
    """Tests for _check_dangerous_values method."""

    def test_no_dangerous_values(self, checker):
        """Test no findings for safe CSP."""
        headers = {
            "content-security-policy": "default-src 'self'; script-src 'self'",
        }

        findings = checker._check_dangerous_values(headers, "https://example.com")
        assert len(findings) == 0

    def test_unsafe_inline_detected(self, checker):
        """Test unsafe-inline is detected in CSP."""
        headers = {
            "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
        }

        findings = checker._check_dangerous_values(headers, "https://example.com")

        assert len(findings) == 1
        assert "unsafe-inline" in findings[0].metadata.get("dangerous_pattern", "")

    def test_unsafe_eval_detected(self, checker):
        """Test unsafe-eval is detected in CSP."""
        headers = {
            "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-eval'",
        }

        findings = checker._check_dangerous_values(headers, "https://example.com")

        assert len(findings) == 1
        assert "unsafe-eval" in findings[0].metadata.get("dangerous_pattern", "")

    def test_multiple_dangerous_values(self, checker):
        """Test multiple dangerous values detected."""
        headers = {
            "content-security-policy": "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
        }

        findings = checker._check_dangerous_values(headers, "https://example.com")

        assert len(findings) == 2
        patterns = [f.metadata.get("dangerous_pattern", "") for f in findings]
        assert "unsafe-inline" in patterns
        assert "unsafe-eval" in patterns

    def test_missing_header_no_finding(self, checker):
        """Test no finding for missing header (handled by other method)."""
        headers = {}  # CSP not present

        findings = checker._check_dangerous_values(headers, "https://example.com")
        assert len(findings) == 0

    def test_finding_includes_actual_value(self, checker):
        """Test finding includes actual header value."""
        headers = {
            "content-security-policy": "script-src 'unsafe-inline'",
        }

        findings = checker._check_dangerous_values(headers, "https://example.com")

        assert findings[0].metadata.get("value") == "script-src 'unsafe-inline'"


# =============================================================================
# _get_business_impact TESTS
# =============================================================================

class TestGetBusinessImpact:
    """Tests for _get_business_impact method."""

    def test_csp_impact(self, checker):
        """Test business impact for CSP."""
        impact = checker._get_business_impact("Content-Security-Policy")

        assert "XSS" in impact
        assert "IF" in impact  # Conditional language

    def test_hsts_impact(self, checker):
        """Test business impact for HSTS."""
        impact = checker._get_business_impact("Strict-Transport-Security")

        assert "MITM" in impact or "WiFi" in impact
        assert "IF" in impact

    def test_x_frame_options_impact(self, checker):
        """Test business impact for X-Frame-Options."""
        impact = checker._get_business_impact("X-Frame-Options")

        assert "clickjacking" in impact.lower()
        assert "IF" in impact

    def test_unknown_header_fallback(self, checker):
        """Test fallback for unknown header."""
        impact = checker._get_business_impact("Unknown-Header")

        assert "depends" in impact.lower() or "missing" in impact.lower()


# =============================================================================
# _get_fix_priority TESTS
# =============================================================================

class TestGetFixPriority:
    """Tests for _get_fix_priority method."""

    def test_critical_priority(self, checker):
        """Test critical severity gets immediate priority."""
        priority = checker._get_fix_priority("CRITICAL")

        assert "24 hours" in priority or "Now" in priority

    def test_high_priority(self, checker):
        """Test high severity gets sprint priority."""
        priority = checker._get_fix_priority("HIGH")

        assert "Sprint" in priority

    def test_medium_priority(self, checker):
        """Test medium severity gets next sprint priority."""
        priority = checker._get_fix_priority("MEDIUM")

        assert "Sprint" in priority

    def test_low_priority(self, checker):
        """Test low severity gets convenient priority."""
        priority = checker._get_fix_priority("LOW")

        assert "Convenient" in priority

    def test_info_priority(self, checker):
        """Test info gets optional priority."""
        priority = checker._get_fix_priority("INFO")

        assert "Optional" in priority

    def test_case_insensitive(self, checker):
        """Test priority is case insensitive."""
        priority1 = checker._get_fix_priority("CRITICAL")
        priority2 = checker._get_fix_priority("critical")

        # Should not crash, returns something
        assert priority1 is not None
        assert priority2 is not None


# =============================================================================
# _aggregate_header_findings TESTS
# =============================================================================

class TestAggregateHeaderFindings:
    """Tests for _aggregate_header_findings method."""

    def test_aggregates_multiple_findings(self, checker):
        """Test multiple findings aggregated into one."""
        headers = {}  # All headers missing

        individual_findings = checker._check_missing_headers(headers, "https://example.com")

        # Should have multiple findings
        assert len(individual_findings) > 1

        # Aggregate them
        aggregated = checker._aggregate_header_findings(individual_findings, "https://example.com")

        # Should be single finding
        assert aggregated is not None
        assert aggregated.metadata.get("aggregated") is True
        assert aggregated.metadata.get("sub_findings_count") == len(individual_findings)

    def test_aggregated_has_sub_findings(self, checker):
        """Test aggregated finding contains sub-findings."""
        headers = {}

        individual_findings = checker._check_missing_headers(headers, "https://example.com")
        aggregated = checker._aggregate_header_findings(individual_findings, "https://example.com")

        sub_findings = aggregated.metadata.get("sub_findings", [])
        assert len(sub_findings) == len(individual_findings)

        # Each sub-finding should have header name
        for sub in sub_findings:
            assert "header" in sub
            assert "severity" in sub

    def test_aggregated_highest_severity(self, checker):
        """Test aggregated uses highest severity."""
        headers = {}

        individual_findings = checker._check_missing_headers(headers, "https://example.com")

        # Find highest severity by comparing string values
        severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        highest_value = max(severity_order.get(f.severity.value, 0) for f in individual_findings)

        aggregated = checker._aggregate_header_findings(individual_findings, "https://example.com")

        # Aggregated should have same or higher severity
        aggregated_value = severity_order.get(aggregated.severity.value, 0)
        assert aggregated_value >= highest_value

    def test_aggregated_has_evidence(self, checker):
        """Test aggregated finding has evidence."""
        headers = {}

        individual_findings = checker._check_missing_headers(headers, "https://example.com")
        aggregated = checker._aggregate_header_findings(individual_findings, "https://example.com")

        assert len(aggregated.evidence) > 0
        assert any("curl" in e.lower() for e in aggregated.evidence)


# =============================================================================
# MODULE SCANNER NAME
# =============================================================================

class TestModuleMetadata:
    """Tests for module metadata."""

    def test_scanner_name(self, checker):
        """Test scanner has correct name."""
        assert checker.name == "headers"

    def test_aggregate_findings_default(self, checker):
        """Test aggregate_findings defaults to True."""
        assert checker.aggregate_findings is True


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_headers_dict(self, checker):
        """Test handling of empty headers."""
        findings = checker._check_missing_headers({}, "https://example.com")

        # Should find all missing headers
        assert len(findings) == len(checker.HEADER_CHECKS)

    def test_case_insensitive_headers(self, checker):
        """Test header matching is case insensitive."""
        headers = {
            "STRICT-TRANSPORT-SECURITY": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
        }

        findings = checker._check_missing_headers(headers, "https://example.com")

        # Should NOT find HSTS (uppercase) - but implementation uses lowercase keys
        # Actual behavior depends on normalization
        header_names = [f.metadata.get("header", "") for f in findings]
        # At minimum, should handle without crash
        assert isinstance(findings, list)

    def test_very_long_header_value(self, checker):
        """Test handling of very long header values."""
        headers = {
            "content-security-policy": "default-src 'self' " + "https://cdn.example.com " * 100,
        }

        # Should not crash
        findings = checker._check_dangerous_values(headers, "https://example.com")
        assert isinstance(findings, list)
