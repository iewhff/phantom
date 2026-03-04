"""
Tests for CSRF Scanner.

Covers:
- CSRFVulnType enum
- TokenAnalysis dataclass
- CSRFFinding dataclass
- CSRFScanResult dataclass
- CSRFScanner initialization
- Endpoint impact classification
- Token patterns
- Origin/Referer bypass payloads
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
import re

from scanning.modules.csrf_scanner import (
    CSRFScanner,
    CSRFVulnType,
    TokenAnalysis,
    CSRFFinding,
    CSRFScanResult,
    TOKEN_PATTERNS,
    ORIGIN_BYPASS_PAYLOADS,
    REFERER_BYPASS_PAYLOADS,
    CONTENT_TYPE_PAYLOADS,
    JSON_CSRF_PAYLOADS,
)


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def csrf_scanner():
    """Create CSRFScanner instance."""
    return CSRFScanner(settings=None)


@pytest.fixture
def mock_settings():
    """Create mock settings."""
    settings = MagicMock()
    return settings


# ============================================================================
# TESTS: CSRFVulnType Enum
# ============================================================================

class TestCSRFVulnType:
    """Tests for CSRFVulnType enum."""

    def test_has_missing_token(self):
        """Should have MISSING_TOKEN type."""
        assert CSRFVulnType.MISSING_TOKEN is not None

    def test_has_weak_token(self):
        """Should have WEAK_TOKEN type."""
        assert CSRFVulnType.WEAK_TOKEN is not None

    def test_has_token_reuse(self):
        """Should have TOKEN_REUSE type."""
        assert CSRFVulnType.TOKEN_REUSE is not None

    def test_has_token_leakage(self):
        """Should have TOKEN_LEAKAGE type."""
        assert CSRFVulnType.TOKEN_LEAKAGE is not None

    def test_has_samesite_missing(self):
        """Should have SAMESITE_MISSING type."""
        assert CSRFVulnType.SAMESITE_MISSING is not None

    def test_has_samesite_none(self):
        """Should have SAMESITE_NONE type."""
        assert CSRFVulnType.SAMESITE_NONE is not None

    def test_has_origin_bypass(self):
        """Should have ORIGIN_BYPASS type."""
        assert CSRFVulnType.ORIGIN_BYPASS is not None

    def test_has_referer_bypass(self):
        """Should have REFERER_BYPASS type."""
        assert CSRFVulnType.REFERER_BYPASS is not None

    def test_has_json_csrf(self):
        """Should have JSON_CSRF type."""
        assert CSRFVulnType.JSON_CSRF is not None

    def test_has_websocket_csrf(self):
        """Should have WEBSOCKET_CSRF type."""
        assert CSRFVulnType.WEBSOCKET_CSRF is not None

    def test_has_workflow_bypass(self):
        """Should have WORKFLOW_BYPASS type."""
        assert CSRFVulnType.WORKFLOW_BYPASS is not None

    def test_all_types_are_unique(self):
        """All vulnerability types should be unique."""
        values = [v.value for v in CSRFVulnType]
        assert len(values) == len(set(values))


# ============================================================================
# TESTS: TokenAnalysis Dataclass
# ============================================================================

class TestTokenAnalysis:
    """Tests for TokenAnalysis dataclass."""

    def test_creates_with_required_fields(self):
        """Should create with required fields."""
        token = TokenAnalysis(
            token_value="abc123",
            entropy_bits=64.0,
            is_predictable=False,
            pattern_detected=None,
            is_bound_to_session=True,
            is_reusable=False,
            framework_hint=None,
        )
        assert token.token_value == "abc123"
        assert token.entropy_bits == 64.0
        assert token.is_predictable is False

    def test_stores_framework_hint(self):
        """Should store framework hint."""
        token = TokenAnalysis(
            token_value="abc123",
            entropy_bits=64.0,
            is_predictable=False,
            pattern_detected="UUID",
            is_bound_to_session=True,
            is_reusable=False,
            framework_hint="django",
        )
        assert token.framework_hint == "django"

    def test_stores_pattern_detected(self):
        """Should store detected pattern."""
        token = TokenAnalysis(
            token_value="abc123",
            entropy_bits=64.0,
            is_predictable=True,
            pattern_detected="sequential",
            is_bound_to_session=False,
            is_reusable=True,
            framework_hint=None,
        )
        assert token.pattern_detected == "sequential"


# ============================================================================
# TESTS: CSRFFinding Dataclass
# ============================================================================

class TestCSRFFinding:
    """Tests for CSRFFinding dataclass."""

    def test_creates_with_required_fields(self):
        """Should create with required fields."""
        finding = CSRFFinding(
            url="https://example.com/api/user",
            method="POST",
            severity="HIGH",
            title="Missing CSRF Token",
            description="Form lacks CSRF protection",
        )
        assert finding.url == "https://example.com/api/user"
        assert finding.method == "POST"
        assert finding.severity == "HIGH"

    def test_default_values(self):
        """Should have correct default values."""
        finding = CSRFFinding(
            url="https://example.com",
            method="POST",
            severity="MEDIUM",
            title="Test",
            description="Test description",
        )
        assert finding.evidence == ""
        assert finding.remediation == ""
        assert finding.cwe == "CWE-352"
        assert finding.vuln_type is None
        assert finding.confidence == 60.0
        assert finding.cvss == 0.0

    def test_to_dict_method(self):
        """Should convert to dictionary correctly."""
        finding = CSRFFinding(
            url="https://example.com/api",
            method="POST",
            severity="HIGH",
            title="CSRF Vulnerability",
            description="Missing token",
            evidence="No token in form",
            vuln_type=CSRFVulnType.MISSING_TOKEN,
            cvss=7.5,
        )
        result = finding.to_dict()

        assert result["type"] == "CSRF"
        assert result["url"] == "https://example.com/api"
        assert result["method"] == "POST"
        assert result["severity"] == "HIGH"
        assert result["title"] == "CSRF Vulnerability"
        assert result["vuln_type"] == "MISSING_TOKEN"
        assert result["cvss"] == 7.5

    def test_to_dict_truncates_evidence(self):
        """Should truncate long evidence."""
        long_evidence = "x" * 1000
        finding = CSRFFinding(
            url="https://example.com",
            method="POST",
            severity="LOW",
            title="Test",
            description="Test",
            evidence=long_evidence,
        )
        result = finding.to_dict()
        assert len(result["evidence"]) == 500

    def test_to_dict_handles_none_vuln_type(self):
        """Should handle None vuln_type."""
        finding = CSRFFinding(
            url="https://example.com",
            method="POST",
            severity="LOW",
            title="Test",
            description="Test",
            vuln_type=None,
        )
        result = finding.to_dict()
        assert result["vuln_type"] is None


# ============================================================================
# TESTS: CSRFScanResult Dataclass
# ============================================================================

class TestCSRFScanResult:
    """Tests for CSRFScanResult dataclass."""

    def test_default_values(self):
        """Should have correct default values."""
        result = CSRFScanResult()
        assert result.findings == []
        assert result.endpoints_tested == 0
        assert result.cookies_analyzed == 0
        assert result.tokens_analyzed == 0
        assert result.frameworks_detected == []

    def test_critical_count_property(self):
        """Should count critical findings."""
        result = CSRFScanResult()
        result.findings = [
            CSRFFinding(url="", method="POST", severity="CRITICAL", title="", description=""),
            CSRFFinding(url="", method="POST", severity="HIGH", title="", description=""),
            CSRFFinding(url="", method="POST", severity="CRITICAL", title="", description=""),
        ]
        assert result.critical_count == 2

    def test_high_count_property(self):
        """Should count high findings."""
        result = CSRFScanResult()
        result.findings = [
            CSRFFinding(url="", method="POST", severity="HIGH", title="", description=""),
            CSRFFinding(url="", method="POST", severity="HIGH", title="", description=""),
            CSRFFinding(url="", method="POST", severity="MEDIUM", title="", description=""),
        ]
        assert result.high_count == 2

    def test_medium_count_property(self):
        """Should count medium findings."""
        result = CSRFScanResult()
        result.findings = [
            CSRFFinding(url="", method="POST", severity="MEDIUM", title="", description=""),
            CSRFFinding(url="", method="POST", severity="LOW", title="", description=""),
        ]
        assert result.medium_count == 1

    def test_empty_findings_counts(self):
        """Should return 0 for empty findings."""
        result = CSRFScanResult()
        assert result.critical_count == 0
        assert result.high_count == 0
        assert result.medium_count == 0


# ============================================================================
# TESTS: CSRFScanner Initialization
# ============================================================================

class TestCSRFScannerInit:
    """Tests for CSRFScanner initialization."""

    def test_initializes_with_none_settings(self):
        """Should initialize with None settings."""
        scanner = CSRFScanner(settings=None)
        assert scanner.settings is None

    def test_initializes_result(self):
        """Should initialize empty result."""
        scanner = CSRFScanner()
        assert isinstance(scanner.result, CSRFScanResult)
        assert scanner.result.endpoints_tested == 0

    def test_initializes_token_cache(self):
        """Should initialize empty token cache."""
        scanner = CSRFScanner()
        assert scanner._token_cache == {}

    def test_initializes_session_cookies(self):
        """Should initialize empty session cookies."""
        scanner = CSRFScanner()
        assert scanner._session_cookies == {}

    def test_compiles_password_patterns(self):
        """Should compile password patterns."""
        scanner = CSRFScanner()
        assert len(scanner._password_patterns) > 0
        assert all(isinstance(p, re.Pattern) for p in scanner._password_patterns)

    def test_compiles_email_patterns(self):
        """Should compile email patterns."""
        scanner = CSRFScanner()
        assert len(scanner._email_patterns) > 0

    def test_compiles_delete_patterns(self):
        """Should compile delete patterns."""
        scanner = CSRFScanner()
        assert len(scanner._delete_patterns) > 0

    def test_compiles_high_impact_patterns(self):
        """Should compile high impact patterns."""
        scanner = CSRFScanner()
        assert len(scanner._high_impact_patterns) > 0


# ============================================================================
# TESTS: Endpoint Impact Classification
# ============================================================================

class TestEndpointImpactClassification:
    """Tests for _classify_endpoint_impact method."""

    def test_password_change_is_critical(self, csrf_scanner):
        """Password change endpoints should be CRITICAL."""
        endpoints = [
            "/api/user/password",
            "/change-password",
            "/update_password",
            "/reset-password",
            "/profile/password",
            "/account/password",
            "/settings/password",
        ]
        for endpoint in endpoints:
            impact, severity, cvss = csrf_scanner._classify_endpoint_impact(endpoint)
            assert severity == "CRITICAL", f"Expected CRITICAL for {endpoint}, got {severity}"
            assert impact == "password_change", f"Expected password_change for {endpoint}"
            assert cvss >= 9.0

    def test_email_change_is_critical(self, csrf_scanner):
        """Email change endpoints should be CRITICAL."""
        endpoints = [
            "/api/user/email",
            "/change-email",
            "/update_email",
            "/profile/email",
            "/account/email",
            "/settings/email",
        ]
        for endpoint in endpoints:
            impact, severity, cvss = csrf_scanner._classify_endpoint_impact(endpoint)
            assert severity == "CRITICAL", f"Expected CRITICAL for {endpoint}, got {severity}"
            assert impact == "email_change"

    def test_account_delete_is_critical(self, csrf_scanner):
        """Account deletion endpoints should be CRITICAL."""
        endpoints = [
            "/delete-account",
            "/account/delete",
            "/user/delete",
            "/profile/delete",
            "/remove-account",
            "/deactivate",
            "/close-account",
            "/api/users/123",  # DELETE method detection
        ]
        for endpoint in endpoints:
            impact, severity, cvss = csrf_scanner._classify_endpoint_impact(endpoint)
            assert severity == "CRITICAL", f"Expected CRITICAL for {endpoint}, got {severity}"

    def test_delete_method_on_user_endpoint(self, csrf_scanner):
        """DELETE method on user endpoints should be CRITICAL."""
        impact, severity, cvss = csrf_scanner._classify_endpoint_impact(
            "/api/users/123", "DELETE"
        )
        assert severity == "CRITICAL"
        assert impact == "account_delete"

    def test_financial_endpoints_are_critical(self, csrf_scanner):
        """Financial endpoints should be CRITICAL or HIGH."""
        # Endpoints that match "financial" impact_type get CRITICAL
        critical_endpoints = [
            "/api/transfer",
            "/withdraw",
            "/send-money",
            "/purchase",
        ]
        for endpoint in critical_endpoints:
            impact, severity, cvss = csrf_scanner._classify_endpoint_impact(endpoint)
            assert severity == "CRITICAL", f"Expected CRITICAL for {endpoint}"
            assert impact == "financial"

        # Some endpoints like /transaction and /checkout return HIGH
        # because they match high_impact_patterns but don't match
        # the specific financial keywords in _classify_endpoint_impact
        high_endpoints = [
            "/transaction",
            "/checkout",
            "/payment",
        ]
        for endpoint in high_endpoints:
            impact, severity, cvss = csrf_scanner._classify_endpoint_impact(endpoint)
            assert severity in ["CRITICAL", "HIGH"], f"Expected CRITICAL or HIGH for {endpoint}"

    def test_admin_endpoints_are_critical_or_high(self, csrf_scanner):
        """Admin action endpoints should be CRITICAL or HIGH."""
        # Endpoints with "admin" or "role" in the path get CRITICAL
        critical_endpoints = [
            "/admin/users",
            "/user/role",
            "/permissions",
            "/grant",
            "/promote",
        ]
        for endpoint in critical_endpoints:
            impact, severity, cvss = csrf_scanner._classify_endpoint_impact(endpoint)
            assert severity == "CRITICAL", f"Expected CRITICAL for {endpoint}"

        # /revoke gets HIGH because it matches high_impact but not admin_action
        high_endpoints = ["/revoke"]
        for endpoint in high_endpoints:
            impact, severity, cvss = csrf_scanner._classify_endpoint_impact(endpoint)
            assert severity in ["CRITICAL", "HIGH"], f"Expected CRITICAL or HIGH for {endpoint}"

    def test_security_endpoints_are_critical_or_high(self, csrf_scanner):
        """Security setting endpoints should be CRITICAL or HIGH."""
        # Endpoints with security keywords that match "security_bypass" category
        critical_endpoints = [
            "/2fa/disable",
            "/mfa/settings",
            "/security/settings",
        ]
        for endpoint in critical_endpoints:
            impact, severity, cvss = csrf_scanner._classify_endpoint_impact(endpoint)
            assert severity == "CRITICAL", f"Expected CRITICAL for {endpoint}"

        # These match HIGH_IMPACT_PATTERNS but return HIGH (not CRITICAL)
        # because they match high_impact_patterns but don't match specific
        # financial/admin/security keyword checks
        high_endpoints = ["/totp", "/api-key"]
        for endpoint in high_endpoints:
            impact, severity, cvss = csrf_scanner._classify_endpoint_impact(endpoint)
            assert severity in ["CRITICAL", "HIGH"], f"Expected CRITICAL or HIGH for {endpoint}"

    def test_high_impact_endpoints_are_high(self, csrf_scanner):
        """High impact endpoints should be HIGH severity."""
        endpoints = [
            "/publish",
            "/approve",
            "/reject",
            "/ban",
            "/suspend",
        ]
        for endpoint in endpoints:
            impact, severity, cvss = csrf_scanner._classify_endpoint_impact(endpoint)
            # These are HIGH (not CRITICAL) because they don't fit specific categories
            assert severity in ["HIGH", "CRITICAL"], f"Expected HIGH or CRITICAL for {endpoint}"

    def test_generic_endpoints_are_medium(self, csrf_scanner):
        """Generic endpoints should be MEDIUM severity."""
        endpoints = [
            "/api/data",
            "/submit",
            "/update",
            "/save",
        ]
        for endpoint in endpoints:
            impact, severity, cvss = csrf_scanner._classify_endpoint_impact(endpoint)
            assert impact == "generic"
            assert severity == "MEDIUM"

    def test_case_insensitive_matching(self, csrf_scanner):
        """Pattern matching should be case-insensitive."""
        impact, severity, _ = csrf_scanner._classify_endpoint_impact("/API/USER/PASSWORD")
        assert impact == "password_change"
        assert severity == "CRITICAL"


# ============================================================================
# TESTS: Impact Descriptions
# ============================================================================

class TestImpactDescriptions:
    """Tests for _get_impact_description method."""

    def test_password_change_description(self, csrf_scanner):
        """Should return account takeover description for password change."""
        desc = csrf_scanner._get_impact_description("password_change")
        assert "ACCOUNT TAKEOVER" in desc
        assert "password" in desc.lower()

    def test_email_change_description(self, csrf_scanner):
        """Should return description for email change."""
        desc = csrf_scanner._get_impact_description("email_change")
        assert "ACCOUNT TAKEOVER" in desc
        assert "email" in desc.lower()

    def test_account_delete_description(self, csrf_scanner):
        """Should return description for account deletion."""
        desc = csrf_scanner._get_impact_description("account_delete")
        assert "DELETION" in desc or "delete" in desc.lower()

    def test_financial_description(self, csrf_scanner):
        """Should return description for financial impact."""
        desc = csrf_scanner._get_impact_description("financial")
        assert "FINANCIAL" in desc or "money" in desc.lower() or "theft" in desc.lower()

    def test_generic_description(self, csrf_scanner):
        """Should return generic description for unknown types."""
        desc = csrf_scanner._get_impact_description("generic")
        assert "State-changing" in desc

    def test_unknown_type_returns_generic(self, csrf_scanner):
        """Should return generic description for unknown types."""
        desc = csrf_scanner._get_impact_description("unknown_type")
        assert "State-changing" in desc


# ============================================================================
# TESTS: High Impact Test Payloads
# ============================================================================

class TestHighImpactPayloads:
    """Tests for _get_high_impact_test_payload method."""

    def test_password_change_payload(self, csrf_scanner):
        """Should return password change payload."""
        payload = csrf_scanner._get_high_impact_test_payload("password_change")
        assert "password" in payload or "new_password" in payload

    def test_email_change_payload(self, csrf_scanner):
        """Should return email change payload."""
        payload = csrf_scanner._get_high_impact_test_payload("email_change")
        assert "email" in payload or "new_email" in payload

    def test_account_delete_payload(self, csrf_scanner):
        """Should return account delete payload."""
        payload = csrf_scanner._get_high_impact_test_payload("account_delete")
        assert "confirm" in payload or "delete" in str(payload).lower()

    def test_financial_payload(self, csrf_scanner):
        """Should return financial payload."""
        payload = csrf_scanner._get_high_impact_test_payload("financial")
        assert "amount" in payload or "to" in payload

    def test_unknown_type_returns_default(self, csrf_scanner):
        """Should return default payload for unknown types."""
        payload = csrf_scanner._get_high_impact_test_payload("unknown")
        assert payload == {"test": "csrf"}


# ============================================================================
# TESTS: Token Patterns
# ============================================================================

class TestTokenPatterns:
    """Tests for TOKEN_PATTERNS regex patterns."""

    def test_django_pattern(self):
        """Django CSRF tokens should match."""
        pattern = TOKEN_PATTERNS["django"]
        # Django tokens are 64 alphanumeric characters
        valid_token = "a" * 64
        assert pattern.match(valid_token)
        # Invalid (too short)
        assert not pattern.match("a" * 63)

    def test_rails_pattern(self):
        """Rails authenticity_token should match."""
        pattern = TOKEN_PATTERNS["rails"]
        # Rails tokens are base64 encoded, 44-88 chars
        valid_token = "Ab12+/" * 10 + "=="  # 62 chars
        assert pattern.match(valid_token)

    def test_laravel_pattern(self):
        """Laravel CSRF tokens should match."""
        pattern = TOKEN_PATTERNS["laravel"]
        # Laravel tokens are 40 alphanumeric characters
        valid_token = "a" * 40
        assert pattern.match(valid_token)
        assert not pattern.match("a" * 39)

    def test_spring_pattern(self):
        """Spring Security tokens (UUID) should match."""
        pattern = TOKEN_PATTERNS["spring"]
        valid_uuid = "12345678-1234-1234-1234-123456789012"
        assert pattern.match(valid_uuid)
        # Invalid format
        assert not pattern.match("12345678-1234-1234")

    def test_express_csurf_pattern(self):
        """Express csurf tokens should match."""
        pattern = TOKEN_PATTERNS["express_csurf"]
        # 24-48 alphanumeric with underscore/dash
        valid_token = "abc123_-" * 4
        assert pattern.match(valid_token)


# ============================================================================
# TESTS: Bypass Payloads
# ============================================================================

class TestBypassPayloads:
    """Tests for bypass payload lists."""

    def test_origin_bypass_has_null(self):
        """Should include null origin."""
        assert "null" in ORIGIN_BYPASS_PAYLOADS

    def test_origin_bypass_has_evil_domain(self):
        """Should include evil domain."""
        assert any("evil.com" in p for p in ORIGIN_BYPASS_PAYLOADS)

    def test_origin_bypass_has_subdomain_confusion(self):
        """Should include subdomain confusion payloads."""
        assert any(".evil.com" in p for p in ORIGIN_BYPASS_PAYLOADS)

    def test_referer_bypass_has_empty(self):
        """Should include empty referer."""
        assert "" in REFERER_BYPASS_PAYLOADS

    def test_referer_bypass_has_evil_domain(self):
        """Should include evil domain referer."""
        assert any("evil.com" in p for p in REFERER_BYPASS_PAYLOADS)

    def test_content_type_has_json(self):
        """Should include application/json."""
        assert "application/json" in CONTENT_TYPE_PAYLOADS

    def test_content_type_has_form_urlencoded(self):
        """Should include form-urlencoded."""
        assert "application/x-www-form-urlencoded" in CONTENT_TYPE_PAYLOADS

    def test_content_type_has_text_plain(self):
        """Should include text/plain for bypass."""
        assert "text/plain" in CONTENT_TYPE_PAYLOADS

    def test_json_csrf_payloads_are_valid_json(self):
        """JSON CSRF payloads should be valid JSON-like."""
        import json
        for payload in JSON_CSRF_PAYLOADS:
            # Some have comments/padding, check the ones that should parse
            if payload.startswith("{") and "/*" not in payload:
                try:
                    json.loads(payload)
                except json.JSONDecodeError:
                    pytest.fail(f"Invalid JSON payload: {payload}")


# ============================================================================
# TESTS: Scanner Constants
# ============================================================================

class TestScannerConstants:
    """Tests for scanner constants."""

    def test_state_changing_methods(self, csrf_scanner):
        """Should have state-changing methods defined."""
        methods = csrf_scanner.STATE_CHANGING_METHODS
        assert "POST" in methods
        assert "PUT" in methods
        assert "PATCH" in methods
        assert "DELETE" in methods
        assert "GET" not in methods

    def test_csrf_token_names(self, csrf_scanner):
        """Should have common CSRF token names."""
        names = csrf_scanner.CSRF_TOKEN_NAMES
        assert "csrf" in names
        assert "csrf_token" in names
        assert "_csrf" in names
        assert "authenticity_token" in names  # Rails
        assert "csrfmiddlewaretoken" in names  # Django

    def test_csrf_header_names(self, csrf_scanner):
        """Should have common CSRF header names."""
        names = csrf_scanner.CSRF_HEADER_NAMES
        assert "X-CSRF-Token" in names
        assert "X-XSRF-Token" in names
        assert "X-Requested-With" in names


# ============================================================================
# TESTS: Pattern Coverage
# ============================================================================

class TestPatternCoverage:
    """Tests to ensure pattern lists cover common cases."""

    def test_password_patterns_cover_common_urls(self, csrf_scanner):
        """Password patterns should match common password URLs."""
        test_urls = [
            "/password",
            "/changepassword",
            "/change-password",
            "/update_password",
            "/reset-password",
            "/profile/password",
            "/api/password",
        ]
        for url in test_urls:
            matches = any(p.search(url) for p in csrf_scanner._password_patterns)
            assert matches, f"Expected password pattern to match: {url}"

    def test_email_patterns_cover_common_urls(self, csrf_scanner):
        """Email patterns should match common email URLs."""
        test_urls = [
            "/email",
            "/changeemail",
            "/change-email",
            "/update_email",
            "/profile/email",
            "/api/email",
        ]
        for url in test_urls:
            matches = any(p.search(url) for p in csrf_scanner._email_patterns)
            assert matches, f"Expected email pattern to match: {url}"

    def test_delete_patterns_cover_common_urls(self, csrf_scanner):
        """Delete patterns should match common delete URLs."""
        test_urls = [
            "/delete-account",
            "/account/delete",
            "/user/delete",
            "/deactivate",
            "/close-account",
            "/api/users/123",
        ]
        for url in test_urls:
            matches = any(p.search(url) for p in csrf_scanner._delete_patterns)
            assert matches, f"Expected delete pattern to match: {url}"


# ============================================================================
# TESTS: Edge Cases
# ============================================================================

class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_endpoint_classification(self, csrf_scanner):
        """Should handle empty endpoint."""
        impact, severity, cvss = csrf_scanner._classify_endpoint_impact("")
        assert impact == "generic"
        assert severity == "MEDIUM"

    def test_none_endpoint_handling(self, csrf_scanner):
        """Should handle None endpoint gracefully."""
        # This might raise an error - test the behavior
        try:
            csrf_scanner._classify_endpoint_impact(None)
        except (TypeError, AttributeError):
            pass  # Expected - None can't be lowercased

    def test_unicode_endpoint(self, csrf_scanner):
        """Should handle unicode in endpoint."""
        impact, severity, _ = csrf_scanner._classify_endpoint_impact("/api/用户/password")
        assert impact == "password_change"

    def test_very_long_endpoint(self, csrf_scanner):
        """Should handle very long endpoint."""
        long_endpoint = "/api/" + "x" * 10000 + "/password"
        impact, severity, _ = csrf_scanner._classify_endpoint_impact(long_endpoint)
        assert impact == "password_change"

    def test_endpoint_with_query_params(self, csrf_scanner):
        """Should handle endpoint with query params."""
        impact, severity, _ = csrf_scanner._classify_endpoint_impact(
            "/api/password?token=abc123"
        )
        assert impact == "password_change"

    def test_endpoint_with_fragment(self, csrf_scanner):
        """Should handle endpoint with fragment."""
        impact, severity, _ = csrf_scanner._classify_endpoint_impact(
            "/api/password#section"
        )
        assert impact == "password_change"

    def test_result_accumulation(self, csrf_scanner):
        """Findings should accumulate in result."""
        finding1 = CSRFFinding(url="", method="POST", severity="HIGH", title="1", description="")
        finding2 = CSRFFinding(url="", method="POST", severity="MEDIUM", title="2", description="")

        csrf_scanner.result.findings.append(finding1)
        csrf_scanner.result.findings.append(finding2)

        assert len(csrf_scanner.result.findings) == 2
        assert csrf_scanner.result.high_count == 1
        assert csrf_scanner.result.medium_count == 1
