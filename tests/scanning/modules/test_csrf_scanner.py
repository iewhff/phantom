"""
Tests for scanning/modules/csrf_scanner.py - CSRF Vulnerability Scanner.

Covers:
- CSRFVulnType enum
- TokenAnalysis and CSRFFinding dataclasses
- TOKEN_PATTERNS constants
- ORIGIN_BYPASS_PAYLOADS and REFERER_BYPASS_PAYLOADS constants
- CSRFScanner class methods
- Token entropy analysis
- Endpoint impact classification
"""

import pytest
import math

from scanning.modules.csrf_scanner import (
    CSRFVulnType,
    TokenAnalysis,
    CSRFFinding,
    CSRFScanResult,
    TOKEN_PATTERNS,
    ORIGIN_BYPASS_PAYLOADS,
    REFERER_BYPASS_PAYLOADS,
    CONTENT_TYPE_PAYLOADS,
    JSON_CSRF_PAYLOADS,
    CSRFScanner,
)


# =============================================================================
# CSRF VULN TYPE ENUM TESTS
# =============================================================================

class TestCSRFVulnType:
    """Tests for CSRFVulnType enum."""

    def test_missing_token_exists(self):
        """Test MISSING_TOKEN type exists."""
        assert CSRFVulnType.MISSING_TOKEN

    def test_weak_token_exists(self):
        """Test WEAK_TOKEN type exists."""
        assert CSRFVulnType.WEAK_TOKEN

    def test_token_reuse_exists(self):
        """Test TOKEN_REUSE type exists."""
        assert CSRFVulnType.TOKEN_REUSE

    def test_token_leakage_exists(self):
        """Test TOKEN_LEAKAGE type exists."""
        assert CSRFVulnType.TOKEN_LEAKAGE

    def test_samesite_missing_exists(self):
        """Test SAMESITE_MISSING type exists."""
        assert CSRFVulnType.SAMESITE_MISSING

    def test_samesite_none_exists(self):
        """Test SAMESITE_NONE type exists."""
        assert CSRFVulnType.SAMESITE_NONE

    def test_origin_bypass_exists(self):
        """Test ORIGIN_BYPASS type exists."""
        assert CSRFVulnType.ORIGIN_BYPASS

    def test_referer_bypass_exists(self):
        """Test REFERER_BYPASS type exists."""
        assert CSRFVulnType.REFERER_BYPASS

    def test_json_csrf_exists(self):
        """Test JSON_CSRF type exists."""
        assert CSRFVulnType.JSON_CSRF

    def test_content_type_confusion_exists(self):
        """Test CONTENT_TYPE_CONFUSION type exists."""
        assert CSRFVulnType.CONTENT_TYPE_CONFUSION

    def test_double_submit_weak_exists(self):
        """Test DOUBLE_SUBMIT_WEAK type exists."""
        assert CSRFVulnType.DOUBLE_SUBMIT_WEAK

    def test_clickjacking_exists(self):
        """Test CLICKJACKING type exists."""
        assert CSRFVulnType.CLICKJACKING

    def test_websocket_csrf_exists(self):
        """Test WEBSOCKET_CSRF type exists."""
        assert CSRFVulnType.WEBSOCKET_CSRF

    def test_cors_csrf_combo_exists(self):
        """Test CORS_CSRF_COMBO type exists."""
        assert CSRFVulnType.CORS_CSRF_COMBO

    def test_token_fixation_exists(self):
        """Test TOKEN_FIXATION type exists."""
        assert CSRFVulnType.TOKEN_FIXATION

    def test_workflow_bypass_exists(self):
        """Test WORKFLOW_BYPASS type exists."""
        assert CSRFVulnType.WORKFLOW_BYPASS


# =============================================================================
# TOKEN ANALYSIS DATACLASS TESTS
# =============================================================================

class TestTokenAnalysis:
    """Tests for TokenAnalysis dataclass."""

    def test_basic_creation(self):
        """Test basic TokenAnalysis creation."""
        analysis = TokenAnalysis(
            token_value="abc123",
            entropy_bits=30.5,
            is_predictable=False,
            pattern_detected=None,
            is_bound_to_session=True,
            is_reusable=False,
            framework_hint="django"
        )
        assert analysis.token_value == "abc123"
        assert analysis.entropy_bits == 30.5
        assert analysis.is_predictable is False
        assert analysis.is_bound_to_session is True
        assert analysis.framework_hint == "django"

    def test_weak_token_characteristics(self):
        """Test characteristics of a weak token."""
        analysis = TokenAnalysis(
            token_value="1234",
            entropy_bits=10.0,
            is_predictable=True,
            pattern_detected="sequential",
            is_bound_to_session=False,
            is_reusable=True,
            framework_hint=None
        )
        assert analysis.entropy_bits < 64  # Weak entropy
        assert analysis.is_predictable is True
        assert analysis.is_reusable is True

    def test_strong_token_characteristics(self):
        """Test characteristics of a strong token."""
        analysis = TokenAnalysis(
            token_value="a" * 64,
            entropy_bits=128.0,
            is_predictable=False,
            pattern_detected=None,
            is_bound_to_session=True,
            is_reusable=False,
            framework_hint="django"
        )
        assert analysis.entropy_bits >= 64  # Strong entropy
        assert analysis.is_predictable is False
        assert analysis.is_bound_to_session is True


# =============================================================================
# CSRF FINDING DATACLASS TESTS
# =============================================================================

class TestCSRFFinding:
    """Tests for CSRFFinding dataclass."""

    def test_basic_creation(self):
        """Test basic CSRFFinding creation."""
        finding = CSRFFinding(
            url="https://example.com/transfer",
            method="POST",
            severity="HIGH",
            title="CSRF on Money Transfer",
            description="Money transfer endpoint lacks CSRF protection"
        )
        assert finding.url == "https://example.com/transfer"
        assert finding.method == "POST"
        assert finding.severity == "HIGH"
        assert finding.cwe == "CWE-352"  # Default

    def test_full_creation(self):
        """Test CSRFFinding with all fields."""
        finding = CSRFFinding(
            url="https://example.com/password",
            method="POST",
            severity="CRITICAL",
            title="CSRF on Password Change",
            description="Password change lacks CSRF token",
            evidence="No CSRF token in form",
            remediation="Add CSRF token to form",
            cwe="CWE-352",
            vuln_type=CSRFVulnType.MISSING_TOKEN,
            confidence="HIGH",
            cvss=8.8
        )
        assert finding.vuln_type == CSRFVulnType.MISSING_TOKEN
        assert finding.confidence == "HIGH"
        assert finding.cvss == 8.8

    def test_to_dict_method(self):
        """Test CSRFFinding to_dict conversion."""
        finding = CSRFFinding(
            url="https://example.com/api",
            method="POST",
            severity="MEDIUM",
            title="Test Finding",
            description="Test description",
            vuln_type=CSRFVulnType.JSON_CSRF
        )
        result = finding.to_dict()
        assert result["type"] == "CSRF"
        assert result["url"] == "https://example.com/api"
        assert result["vuln_type"] == "JSON_CSRF"

    def test_to_dict_without_vuln_type(self):
        """Test to_dict when vuln_type is None."""
        finding = CSRFFinding(
            url="https://example.com",
            method="POST",
            severity="LOW",
            title="Test",
            description="Test"
        )
        result = finding.to_dict()
        assert result["vuln_type"] is None


# =============================================================================
# CSRF SCAN RESULT DATACLASS TESTS
# =============================================================================

class TestCSRFScanResult:
    """Tests for CSRFScanResult dataclass."""

    def test_empty_result(self):
        """Test empty scan result."""
        result = CSRFScanResult()
        assert result.findings == []
        assert result.endpoints_tested == 0
        assert result.critical_count == 0
        assert result.high_count == 0
        assert result.medium_count == 0

    def test_with_findings(self):
        """Test scan result with findings."""
        result = CSRFScanResult()
        result.findings.append(CSRFFinding(
            url="https://example.com/1", method="POST",
            severity="CRITICAL", title="Test1", description="Test"
        ))
        result.findings.append(CSRFFinding(
            url="https://example.com/2", method="POST",
            severity="HIGH", title="Test2", description="Test"
        ))
        result.findings.append(CSRFFinding(
            url="https://example.com/3", method="POST",
            severity="HIGH", title="Test3", description="Test"
        ))
        result.findings.append(CSRFFinding(
            url="https://example.com/4", method="POST",
            severity="MEDIUM", title="Test4", description="Test"
        ))

        assert result.critical_count == 1
        assert result.high_count == 2
        assert result.medium_count == 1

    def test_frameworks_detected(self):
        """Test frameworks detected tracking."""
        result = CSRFScanResult()
        result.frameworks_detected.append("django")
        result.frameworks_detected.append("rails")
        assert "django" in result.frameworks_detected
        assert "rails" in result.frameworks_detected


# =============================================================================
# TOKEN PATTERNS CONSTANT TESTS
# =============================================================================

class TestTokenPatterns:
    """Tests for TOKEN_PATTERNS constant."""

    def test_django_pattern_exists(self):
        """Test Django CSRF token pattern."""
        assert "django" in TOKEN_PATTERNS
        # Django tokens are 64 alphanumeric characters
        assert TOKEN_PATTERNS["django"].match("a" * 64)
        assert not TOKEN_PATTERNS["django"].match("a" * 63)

    def test_rails_pattern_exists(self):
        """Test Rails authenticity_token pattern."""
        assert "rails" in TOKEN_PATTERNS
        # Rails tokens are base64 encoded
        assert TOKEN_PATTERNS["rails"].match("a" * 44)

    def test_laravel_pattern_exists(self):
        """Test Laravel CSRF token pattern."""
        assert "laravel" in TOKEN_PATTERNS
        # Laravel tokens are 40 alphanumeric characters
        assert TOKEN_PATTERNS["laravel"].match("a" * 40)

    def test_spring_pattern_exists(self):
        """Test Spring Security CSRF token pattern."""
        assert "spring" in TOKEN_PATTERNS
        # Spring uses UUID format
        uuid_token = "12345678-1234-1234-1234-123456789012"
        assert TOKEN_PATTERNS["spring"].match(uuid_token)

    def test_express_csurf_pattern_exists(self):
        """Test Express.js csurf pattern."""
        assert "express_csurf" in TOKEN_PATTERNS

    def test_asp_net_pattern_exists(self):
        """Test ASP.NET token pattern."""
        assert "asp_net" in TOKEN_PATTERNS


# =============================================================================
# ORIGIN BYPASS PAYLOADS TESTS
# =============================================================================

class TestOriginBypassPayloads:
    """Tests for ORIGIN_BYPASS_PAYLOADS constant."""

    def test_not_empty(self):
        """Test payloads list is not empty."""
        assert len(ORIGIN_BYPASS_PAYLOADS) > 0

    def test_null_origin_included(self):
        """Test null origin is included."""
        assert "null" in ORIGIN_BYPASS_PAYLOADS

    def test_evil_domain_included(self):
        """Test evil.com variations are included."""
        evil_count = sum(1 for p in ORIGIN_BYPASS_PAYLOADS if "evil.com" in p)
        assert evil_count > 0

    def test_subdomain_confusion_included(self):
        """Test subdomain confusion payloads."""
        subdomain_payloads = [p for p in ORIGIN_BYPASS_PAYLOADS if "target.com" in p and "evil" in p]
        assert len(subdomain_payloads) > 0


# =============================================================================
# REFERER BYPASS PAYLOADS TESTS
# =============================================================================

class TestRefererBypassPayloads:
    """Tests for REFERER_BYPASS_PAYLOADS constant."""

    def test_not_empty(self):
        """Test payloads list is not empty."""
        assert len(REFERER_BYPASS_PAYLOADS) > 0

    def test_empty_referer_included(self):
        """Test empty referer is included."""
        assert "" in REFERER_BYPASS_PAYLOADS

    def test_data_uri_included(self):
        """Test data: URI is included."""
        data_payloads = [p for p in REFERER_BYPASS_PAYLOADS if p.startswith("data:")]
        assert len(data_payloads) > 0


# =============================================================================
# CONTENT TYPE PAYLOADS TESTS
# =============================================================================

class TestContentTypePayloads:
    """Tests for CONTENT_TYPE_PAYLOADS constant."""

    def test_not_empty(self):
        """Test payloads list is not empty."""
        assert len(CONTENT_TYPE_PAYLOADS) > 0

    def test_json_included(self):
        """Test application/json is included."""
        assert "application/json" in CONTENT_TYPE_PAYLOADS

    def test_form_urlencoded_included(self):
        """Test form-urlencoded is included."""
        assert "application/x-www-form-urlencoded" in CONTENT_TYPE_PAYLOADS

    def test_text_plain_included(self):
        """Test text/plain is included."""
        assert "text/plain" in CONTENT_TYPE_PAYLOADS


# =============================================================================
# JSON CSRF PAYLOADS TESTS
# =============================================================================

class TestJSONCSRFPayloads:
    """Tests for JSON_CSRF_PAYLOADS constant."""

    def test_not_empty(self):
        """Test payloads list is not empty."""
        assert len(JSON_CSRF_PAYLOADS) > 0

    def test_valid_json_payloads(self):
        """Test payloads are valid JSON-like strings."""
        import json
        for payload in JSON_CSRF_PAYLOADS:
            # Should start with { or [ or /*
            assert payload[0] in ('{', '[', '/')


# =============================================================================
# CSRF SCANNER CLASS TESTS
# =============================================================================

class TestCSRFScanner:
    """Tests for CSRFScanner class."""

    def test_scanner_initialization(self):
        """Test scanner can be initialized."""
        scanner = CSRFScanner()
        assert scanner.result is not None
        assert scanner.timeout is not None

    def test_scanner_with_settings(self):
        """Test scanner can be initialized with settings."""
        from unittest.mock import Mock
        settings = Mock()
        scanner = CSRFScanner(settings=settings)
        assert scanner.settings is settings

    def test_state_changing_methods(self):
        """Test STATE_CHANGING_METHODS constant."""
        assert "POST" in CSRFScanner.STATE_CHANGING_METHODS
        assert "PUT" in CSRFScanner.STATE_CHANGING_METHODS
        assert "PATCH" in CSRFScanner.STATE_CHANGING_METHODS
        assert "DELETE" in CSRFScanner.STATE_CHANGING_METHODS
        assert "GET" not in CSRFScanner.STATE_CHANGING_METHODS


class TestCSRFScannerTokenNames:
    """Tests for CSRF token names."""

    def test_csrf_token_names_not_empty(self):
        """Test CSRF token names list is not empty."""
        assert len(CSRFScanner.CSRF_TOKEN_NAMES) > 0

    def test_common_token_names_included(self):
        """Test common token names are included."""
        common_names = ["csrf", "csrf_token", "_csrf", "xsrf", "authenticity_token"]
        for name in common_names:
            assert name in CSRFScanner.CSRF_TOKEN_NAMES, f"Missing token name: {name}"

    def test_framework_specific_tokens(self):
        """Test framework-specific token names are included."""
        # Django
        assert "csrfmiddlewaretoken" in CSRFScanner.CSRF_TOKEN_NAMES
        # Rails
        assert "authenticity_token" in CSRFScanner.CSRF_TOKEN_NAMES
        # ASP.NET
        assert "__RequestVerificationToken" in CSRFScanner.CSRF_TOKEN_NAMES

    def test_csrf_header_names_not_empty(self):
        """Test CSRF header names list is not empty."""
        assert len(CSRFScanner.CSRF_HEADER_NAMES) > 0

    def test_common_header_names_included(self):
        """Test common CSRF header names."""
        common_headers = ["X-CSRF-Token", "X-XSRF-Token", "X-Requested-With"]
        for header in common_headers:
            assert header in CSRFScanner.CSRF_HEADER_NAMES, f"Missing header: {header}"


class TestCSRFScannerEndpointPatterns:
    """Tests for high-impact endpoint pattern detection."""

    @pytest.fixture
    def scanner(self):
        """Create scanner instance."""
        return CSRFScanner()

    def test_password_patterns_exist(self):
        """Test password change patterns are defined."""
        assert len(CSRFScanner.PASSWORD_CHANGE_PATTERNS) > 0

    def test_email_patterns_exist(self):
        """Test email change patterns are defined."""
        assert len(CSRFScanner.EMAIL_CHANGE_PATTERNS) > 0

    def test_delete_patterns_exist(self):
        """Test account deletion patterns are defined."""
        assert len(CSRFScanner.ACCOUNT_DELETE_PATTERNS) > 0

    def test_high_impact_patterns_exist(self):
        """Test high-impact patterns are defined."""
        assert len(CSRFScanner.HIGH_IMPACT_PATTERNS) > 0

    def test_classify_password_endpoint(self, scanner):
        """Test classification of password change endpoint."""
        impact_type, severity, cvss = scanner._classify_endpoint_impact(
            "/api/user/password", "POST"
        )
        assert impact_type == "password_change"
        assert severity == "CRITICAL"
        assert cvss >= 8.0

    def test_classify_email_endpoint(self, scanner):
        """Test classification of email change endpoint."""
        impact_type, severity, cvss = scanner._classify_endpoint_impact(
            "/account/email", "POST"
        )
        assert impact_type == "email_change"
        assert severity == "CRITICAL"
        assert cvss >= 8.0

    def test_classify_delete_endpoint(self, scanner):
        """Test classification of account delete endpoint."""
        impact_type, severity, cvss = scanner._classify_endpoint_impact(
            "/user/delete-account", "POST"
        )
        assert impact_type == "account_delete"
        assert severity == "CRITICAL"
        assert cvss >= 8.0

    def test_classify_transfer_endpoint(self, scanner):
        """Test classification of money transfer endpoint."""
        impact_type, severity, cvss = scanner._classify_endpoint_impact(
            "/api/transfer", "POST"
        )
        # Transfer can be classified as "financial" or "high_impact" depending on pattern order
        assert impact_type in ["high_impact", "financial"]
        assert severity in ["HIGH", "CRITICAL"]

    def test_classify_normal_endpoint(self, scanner):
        """Test classification of normal endpoint."""
        impact_type, severity, cvss = scanner._classify_endpoint_impact(
            "/api/articles", "POST"
        )
        # Should be lower severity for non-critical endpoints
        assert severity in ["MEDIUM", "LOW", "HIGH"]


class TestCSRFScannerPatternMatching:
    """Tests for pattern matching functionality."""

    @pytest.fixture
    def scanner(self):
        """Create scanner instance with compiled patterns."""
        return CSRFScanner()

    def test_password_pattern_match(self, scanner):
        """Test password pattern matching."""
        test_urls = [
            "/user/change-password",
            "/settings/password",
            "/api/password/update",
            "/profile/update-password",
        ]
        for url in test_urls:
            matches = any(p.search(url) for p in scanner._password_patterns)
            assert matches, f"Should match password pattern: {url}"

    def test_email_pattern_match(self, scanner):
        """Test email pattern matching."""
        test_urls = [
            "/user/change-email",
            "/settings/email",
            "/profile/email-update",
        ]
        for url in test_urls:
            matches = any(p.search(url) for p in scanner._email_patterns)
            assert matches, f"Should match email pattern: {url}"

    def test_delete_pattern_match(self, scanner):
        """Test account deletion pattern matching."""
        test_urls = [
            "/delete-account",
            "/account/delete",
            "/user/delete",
        ]
        for url in test_urls:
            matches = any(p.search(url) for p in scanner._delete_patterns)
            assert matches, f"Should match delete pattern: {url}"

    def test_high_impact_pattern_match(self, scanner):
        """Test high-impact pattern matching."""
        test_urls = [
            "/transfer",
            "/payment",
            "/admin/users",
            "/api/orders",
            "/graphql",
        ]
        for url in test_urls:
            matches = any(p.search(url) for p in scanner._high_impact_patterns)
            assert matches, f"Should match high-impact pattern: {url}"


# =============================================================================
# ENTROPY CALCULATION TESTS
# =============================================================================

class TestEntropyCalculation:
    """Tests for token entropy analysis."""

    def test_low_entropy_detection(self):
        """Test detection of low entropy tokens."""
        # Sequential tokens have low entropy
        low_entropy_tokens = [
            "1234",
            "0000",
            "aaaa",
            "abcd",
        ]
        for token in low_entropy_tokens:
            # Calculate Shannon entropy
            if token:
                from collections import Counter
                counter = Counter(token)
                probs = [count / len(token) for count in counter.values()]
                entropy = -sum(p * math.log2(p) for p in probs if p > 0)
                bits = entropy * len(token)
                # Low entropy tokens should have less than 64 bits
                assert bits < 64, f"Token {token} should have low entropy"

    def test_high_entropy_token(self):
        """Test high entropy token calculation."""
        import secrets
        # Generate a truly random token
        high_entropy_token = secrets.token_hex(32)  # 64 hex chars

        from collections import Counter
        counter = Counter(high_entropy_token)
        probs = [count / len(high_entropy_token) for count in counter.values()]
        entropy = -sum(p * math.log2(p) for p in probs if p > 0)
        bits = entropy * len(high_entropy_token)

        # High entropy tokens should have more than 64 bits
        assert bits > 64, f"Token should have high entropy: {bits} bits"


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestCSRFScannerIntegration:
    """Integration tests for CSRF scanner."""

    @pytest.fixture
    def scanner(self):
        """Create scanner instance."""
        return CSRFScanner()

    def test_scanner_result_initialization(self, scanner):
        """Test scanner has initialized result."""
        assert isinstance(scanner.result, CSRFScanResult)
        assert scanner.result.findings == []
        assert scanner.result.endpoints_tested == 0

    def test_scanner_caches_initialization(self, scanner):
        """Test scanner caches are initialized."""
        assert scanner._token_cache == {}
        assert scanner._session_cookies == {}

    def test_multiple_findings_accumulation(self):
        """Test findings can be accumulated."""
        scanner = CSRFScanner()

        # Add multiple findings
        for i in range(3):
            scanner.result.findings.append(CSRFFinding(
                url=f"https://example.com/endpoint{i}",
                method="POST",
                severity="HIGH",
                title=f"Finding {i}",
                description=f"Description {i}"
            ))

        assert len(scanner.result.findings) == 3
        assert scanner.result.high_count == 3


class TestCSRFVulnerabilityScenarios:
    """Tests for specific CSRF vulnerability scenarios."""

    def test_missing_token_finding(self):
        """Test creation of missing token finding."""
        finding = CSRFFinding(
            url="https://example.com/password",
            method="POST",
            severity="CRITICAL",
            title="Missing CSRF Token on Password Change",
            description="Password change form lacks CSRF protection",
            vuln_type=CSRFVulnType.MISSING_TOKEN,
            cvss=8.8
        )
        assert finding.vuln_type == CSRFVulnType.MISSING_TOKEN
        assert finding.severity == "CRITICAL"

    def test_weak_token_finding(self):
        """Test creation of weak token finding."""
        finding = CSRFFinding(
            url="https://example.com/api",
            method="POST",
            severity="HIGH",
            title="Weak CSRF Token",
            description="CSRF token has insufficient entropy",
            vuln_type=CSRFVulnType.WEAK_TOKEN,
            evidence="Token entropy: 20 bits (minimum recommended: 64 bits)",
            cvss=6.5
        )
        assert finding.vuln_type == CSRFVulnType.WEAK_TOKEN

    def test_origin_bypass_finding(self):
        """Test creation of origin bypass finding."""
        finding = CSRFFinding(
            url="https://example.com/transfer",
            method="POST",
            severity="HIGH",
            title="Origin Header Bypass",
            description="Server accepts null Origin header",
            vuln_type=CSRFVulnType.ORIGIN_BYPASS,
            evidence="Request accepted with Origin: null",
            cvss=7.5
        )
        assert finding.vuln_type == CSRFVulnType.ORIGIN_BYPASS

    def test_json_csrf_finding(self):
        """Test creation of JSON CSRF finding."""
        finding = CSRFFinding(
            url="https://api.example.com/action",
            method="POST",
            severity="MEDIUM",
            title="JSON CSRF Vulnerability",
            description="API accepts JSON without CSRF token",
            vuln_type=CSRFVulnType.JSON_CSRF,
            cvss=5.3
        )
        assert finding.vuln_type == CSRFVulnType.JSON_CSRF

    def test_samesite_none_finding(self):
        """Test creation of SameSite=None finding."""
        finding = CSRFFinding(
            url="https://example.com/",
            method="POST",
            severity="MEDIUM",
            title="SameSite Cookie Missing",
            description="Session cookie lacks SameSite attribute",
            vuln_type=CSRFVulnType.SAMESITE_MISSING,
            evidence="Set-Cookie: session=abc123; Path=/",
            cvss=4.3
        )
        assert finding.vuln_type == CSRFVulnType.SAMESITE_MISSING
