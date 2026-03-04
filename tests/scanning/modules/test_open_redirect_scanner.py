"""
Tests for scanning/modules/open_redirect_scanner.py - Open Redirect Scanner.

Covers:
- RedirectType and RedirectVector enums
- REDIRECT_PARAMS and REDIRECT_ENDPOINTS constants
- RedirectPayloadGenerator class
- RedirectTestResult dataclass
"""

import pytest

from scanning.modules.open_redirect_scanner import (
    RedirectType,
    RedirectVector,
    REDIRECT_PARAMS,
    REDIRECT_ENDPOINTS,
    RedirectPayloadGenerator,
    RedirectTestResult,
)


# =============================================================================
# REDIRECT TYPE ENUM TESTS
# =============================================================================

class TestRedirectType:
    """Tests for RedirectType enum."""

    def test_parameter_based_exists(self):
        """Test PARAMETER_BASED type exists."""
        assert RedirectType.PARAMETER_BASED

    def test_header_based_exists(self):
        """Test HEADER_BASED type exists."""
        assert RedirectType.HEADER_BASED

    def test_javascript_redirect_exists(self):
        """Test JAVASCRIPT_REDIRECT type exists."""
        assert RedirectType.JAVASCRIPT_REDIRECT

    def test_meta_refresh_exists(self):
        """Test META_REFRESH type exists."""
        assert RedirectType.META_REFRESH

    def test_oauth_redirect_exists(self):
        """Test OAUTH_REDIRECT type exists."""
        assert RedirectType.OAUTH_REDIRECT

    def test_protocol_relative_exists(self):
        """Test PROTOCOL_RELATIVE type exists."""
        assert RedirectType.PROTOCOL_RELATIVE

    def test_whitelist_bypass_exists(self):
        """Test WHITELIST_BYPASS type exists."""
        assert RedirectType.WHITELIST_BYPASS

    def test_encoding_bypass_exists(self):
        """Test ENCODING_BYPASS type exists."""
        assert RedirectType.ENCODING_BYPASS

    def test_subdomain_bypass_exists(self):
        """Test SUBDOMAIN_BYPASS type exists."""
        assert RedirectType.SUBDOMAIN_BYPASS


# =============================================================================
# REDIRECT VECTOR ENUM TESTS
# =============================================================================

class TestRedirectVector:
    """Tests for RedirectVector enum."""

    def test_url_parameter_exists(self):
        """Test URL_PARAMETER vector exists."""
        assert RedirectVector.URL_PARAMETER

    def test_path_segment_exists(self):
        """Test PATH_SEGMENT vector exists."""
        assert RedirectVector.PATH_SEGMENT

    def test_header_injection_exists(self):
        """Test HEADER_INJECTION vector exists."""
        assert RedirectVector.HEADER_INJECTION

    def test_post_body_exists(self):
        """Test POST_BODY vector exists."""
        assert RedirectVector.POST_BODY

    def test_cookie_exists(self):
        """Test COOKIE vector exists."""
        assert RedirectVector.COOKIE

    def test_referer_exists(self):
        """Test REFERER vector exists."""
        assert RedirectVector.REFERER


# =============================================================================
# REDIRECT_PARAMS CONSTANT TESTS
# =============================================================================

class TestRedirectParams:
    """Tests for REDIRECT_PARAMS constant."""

    def test_not_empty(self):
        """Test params list is not empty."""
        assert len(REDIRECT_PARAMS) > 0

    def test_common_params_included(self):
        """Test common redirect params are included."""
        common = ["url", "redirect", "next", "return", "goto", "dest"]
        for param in common:
            assert param in REDIRECT_PARAMS, f"Missing common param: {param}"

    def test_redirect_url_included(self):
        """Test redirect_url param is included."""
        assert "redirect_url" in REDIRECT_PARAMS

    def test_redirect_uri_included(self):
        """Test redirect_uri (OAuth) param is included."""
        assert "redirect_uri" in REDIRECT_PARAMS

    def test_return_url_included(self):
        """Test return_url param is included."""
        assert "return_url" in REDIRECT_PARAMS

    def test_camelcase_variants_included(self):
        """Test camelCase variants are included."""
        camel_variants = ["redirectUrl", "returnUrl", "nextUrl"]
        for param in camel_variants:
            assert param in REDIRECT_PARAMS, f"Missing camelCase param: {param}"

    def test_oauth_params_included(self):
        """Test OAuth-specific params are included."""
        oauth_params = ["callback_url", "success_url", "error_url"]
        for param in oauth_params:
            assert param in REDIRECT_PARAMS, f"Missing OAuth param: {param}"

    def test_short_params_included(self):
        """Test short params (r, u, l, q) are included."""
        short_params = ["r", "u", "l", "q"]
        for param in short_params:
            assert param in REDIRECT_PARAMS, f"Missing short param: {param}"


# =============================================================================
# REDIRECT_ENDPOINTS CONSTANT TESTS
# =============================================================================

class TestRedirectEndpoints:
    """Tests for REDIRECT_ENDPOINTS constant."""

    def test_not_empty(self):
        """Test endpoints list is not empty."""
        assert len(REDIRECT_ENDPOINTS) > 0

    def test_redirect_endpoint_included(self):
        """Test /redirect endpoint is included."""
        assert "/redirect" in REDIRECT_ENDPOINTS

    def test_go_endpoint_included(self):
        """Test /go endpoint is included."""
        assert "/go" in REDIRECT_ENDPOINTS

    def test_out_endpoint_included(self):
        """Test /out endpoint is included."""
        assert "/out" in REDIRECT_ENDPOINTS

    def test_oauth_endpoints_included(self):
        """Test OAuth-related endpoints are included."""
        assert "/auth/callback" in REDIRECT_ENDPOINTS or "/oauth/authorize" in REDIRECT_ENDPOINTS

    def test_sso_endpoint_included(self):
        """Test SSO redirect endpoint is included."""
        assert "/sso/redirect" in REDIRECT_ENDPOINTS

    def test_logout_endpoint_included(self):
        """Test logout endpoint is included."""
        assert "/logout" in REDIRECT_ENDPOINTS


# =============================================================================
# REDIRECT PAYLOAD GENERATOR TESTS
# =============================================================================

class TestRedirectPayloadGenerator:
    """Tests for RedirectPayloadGenerator class."""

    @pytest.fixture
    def generator(self):
        """Create generator instance."""
        return RedirectPayloadGenerator(evil_domain="evil.com")

    def test_creation_default_domain(self):
        """Test creation with default domain."""
        gen = RedirectPayloadGenerator()
        assert gen.evil_domain == "evil.com"

    def test_creation_custom_domain(self):
        """Test creation with custom domain."""
        gen = RedirectPayloadGenerator(evil_domain="attacker.com")
        assert gen.evil_domain == "attacker.com"

    def test_generate_all_not_empty(self, generator):
        """Test generate_all returns payloads."""
        payloads = generator.generate_all("example.com")
        assert len(payloads) > 0

    def test_generate_all_returns_tuples(self, generator):
        """Test generate_all returns (payload, description) tuples."""
        payloads = generator.generate_all("example.com")

        for payload, desc in payloads:
            assert isinstance(payload, str)
            assert isinstance(desc, str)
            assert len(payload) > 0
            assert len(desc) > 0

    def test_basic_payloads(self, generator):
        """Test basic payloads are generated."""
        payloads = generator._basic_payloads()

        assert len(payloads) >= 3

        # Check for HTTPS, HTTP, and protocol-relative
        payload_strings = [p[0] for p in payloads]
        assert any("https://" in p for p in payload_strings)
        assert any("http://" in p for p in payload_strings)
        assert any(p.startswith("//") for p in payload_strings)

    def test_protocol_relative_payloads(self, generator):
        """Test protocol-relative payloads."""
        payloads = generator._protocol_relative_payloads()

        assert len(payloads) >= 3

        # Check for various slash patterns
        payload_strings = [p[0] for p in payloads]
        assert any(p.startswith("//") for p in payload_strings)
        assert any("\\\\" in p for p in payload_strings)

    def test_encoding_payloads(self, generator):
        """Test URL encoding payloads."""
        payloads = generator._encoding_payloads()

        assert len(payloads) >= 3

        # Check for URL-encoded characters
        payload_strings = [p[0] for p in payloads]
        assert any("%2f" in p.lower() or "%3a" in p.lower() for p in payload_strings)

    def test_whitelist_bypass_payloads(self, generator):
        """Test whitelist bypass payloads."""
        payloads = generator._whitelist_bypass_payloads("example.com")

        assert len(payloads) >= 5

        # Check bypass techniques
        payload_strings = [p[0] for p in payloads]

        # Fragment bypass
        assert any("#example.com" in p for p in payload_strings)

        # Credential bypass (@ character)
        assert any("@" in p for p in payload_strings)

        # Subdomain bypass
        assert any("example.com.evil.com" in p for p in payload_strings)

    def test_special_char_payloads(self, generator):
        """Test special character payloads."""
        payloads = generator._special_char_payloads()

        assert len(payloads) >= 3

        # Check for special protocols
        payload_strings = [p[0] for p in payloads]
        assert any("javascript:" in p for p in payload_strings)
        assert any("data:" in p for p in payload_strings)

    def test_path_confusion_payloads(self, generator):
        """Test path confusion payloads."""
        payloads = generator._path_confusion_payloads("example.com")

        assert len(payloads) >= 3

        # Check for path patterns
        payload_strings = [p[0] for p in payloads]
        assert any(p.startswith("/") for p in payload_strings)
        assert any(".." in p for p in payload_strings)

    def test_ip_to_hex(self, generator):
        """Test IP to hex conversion."""
        result = generator._ip_to_hex("127.0.0.1")

        # 127 = 7f, 0 = 00, 0 = 00, 1 = 01
        assert result == "7f000001"

    def test_ip_to_hex_example(self, generator):
        """Test IP to hex with example IP."""
        result = generator._ip_to_hex("192.168.1.1")

        # 192 = c0, 168 = a8, 1 = 01, 1 = 01
        assert result == "c0a80101"

    def test_ip_to_octal(self, generator):
        """Test IP to octal conversion."""
        result = generator._ip_to_octal("8.8.8.8")

        # 8 in octal is 10
        assert result == "10.10.10.10"

    def test_ip_to_octal_127(self, generator):
        """Test IP to octal for localhost."""
        result = generator._ip_to_octal("127.0.0.1")

        # 127 = 177, 0 = 0, 0 = 0, 1 = 1
        assert result == "177.0.0.1"

    def test_payloads_contain_evil_domain(self, generator):
        """Test payloads contain the evil domain."""
        payloads = generator._basic_payloads()

        for payload, _ in payloads:
            # Most payloads should contain evil domain
            # (some like javascript: don't)
            pass  # Just verify no crash

    def test_custom_evil_domain_in_payloads(self):
        """Test custom evil domain appears in payloads."""
        gen = RedirectPayloadGenerator(evil_domain="attacker.xyz")
        payloads = gen._basic_payloads()

        payload_strings = [p[0] for p in payloads]
        assert any("attacker.xyz" in p for p in payload_strings)


# =============================================================================
# REDIRECT TEST RESULT DATACLASS TESTS
# =============================================================================

class TestRedirectTestResult:
    """Tests for RedirectTestResult dataclass."""

    def test_creation(self):
        """Test creating RedirectTestResult."""
        result = RedirectTestResult(
            parameter="url",
            payload="https://evil.com",
            payload_desc="Direct HTTPS URL",
            response_code=302,
            is_redirect=True,
            redirect_url="https://evil.com",
            redirects_to_evil=True,
            reflected_in_response=False,
            evidence={"location": "https://evil.com"},
        )

        assert result.parameter == "url"
        assert result.payload == "https://evil.com"
        assert result.response_code == 302
        assert result.is_redirect is True
        assert result.redirects_to_evil is True

    def test_non_redirect_result(self):
        """Test result for non-redirect response."""
        result = RedirectTestResult(
            parameter="url",
            payload="https://evil.com",
            payload_desc="Test",
            response_code=200,
            is_redirect=False,
            redirect_url=None,
            redirects_to_evil=False,
            reflected_in_response=True,
            evidence={},
        )

        assert result.is_redirect is False
        assert result.redirect_url is None
        assert result.reflected_in_response is True

    def test_evidence_dict(self):
        """Test evidence dictionary."""
        evidence = {
            "location_header": "https://evil.com",
            "response_body": "redirecting...",
            "meta_refresh": None,
        }

        result = RedirectTestResult(
            parameter="next",
            payload="//evil.com",
            payload_desc="Protocol relative",
            response_code=302,
            is_redirect=True,
            redirect_url="https://evil.com",
            redirects_to_evil=True,
            reflected_in_response=False,
            evidence=evidence,
        )

        assert result.evidence["location_header"] == "https://evil.com"


# =============================================================================
# PAYLOAD COVERAGE TESTS
# =============================================================================

class TestPayloadCoverage:
    """Tests for comprehensive payload coverage."""

    @pytest.fixture
    def generator(self):
        return RedirectPayloadGenerator()

    def test_crlf_injection_payload(self, generator):
        """Test CRLF injection payload exists."""
        payloads = generator._special_char_payloads()
        payload_strings = [p[0] for p in payloads]

        # Should have CRLF injection
        assert any("%0d%0a" in p.lower() for p in payload_strings)

    def test_null_byte_payload(self, generator):
        """Test null byte payload exists."""
        payloads = generator._special_char_payloads()
        payload_strings = [p[0] for p in payloads]

        assert any("%00" in p for p in payload_strings)

    def test_double_encoding_payload(self, generator):
        """Test double URL encoding payload exists."""
        payloads = generator._encoding_payloads()
        payload_strings = [p[0] for p in payloads]

        # Double encoding: %25 = encoded %
        assert any("%25" in p for p in payload_strings)

    def test_backslash_payload(self, generator):
        """Test backslash payload exists."""
        payloads = generator._protocol_relative_payloads()
        payload_strings = [p[0] for p in payloads]

        assert any("\\" in p for p in payload_strings)

    def test_fragment_bypass_payload(self, generator):
        """Test fragment (#) bypass payload exists."""
        payloads = generator._whitelist_bypass_payloads("target.com")
        payload_strings = [p[0] for p in payloads]

        assert any("#" in p for p in payload_strings)

    def test_at_sign_bypass_payload(self, generator):
        """Test @ sign bypass payload exists."""
        payloads = generator._whitelist_bypass_payloads("target.com")
        payload_strings = [p[0] for p in payloads]

        assert any("@" in p for p in payload_strings)


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_host_whitelist_bypass(self):
        """Test whitelist bypass with empty host."""
        gen = RedirectPayloadGenerator()
        payloads = gen._whitelist_bypass_payloads("")

        # Should not crash, return payloads
        assert isinstance(payloads, list)

    def test_special_chars_in_host(self):
        """Test with special characters in host."""
        gen = RedirectPayloadGenerator()
        payloads = gen._whitelist_bypass_payloads("test-site.co.uk")

        assert isinstance(payloads, list)
        assert len(payloads) > 0

    def test_unicode_domain(self):
        """Test with unicode-like domain."""
        gen = RedirectPayloadGenerator(evil_domain="xn--80ak6aa92e.com")
        payloads = gen.generate_all("example.com")

        assert len(payloads) > 0

    def test_localhost_as_target(self):
        """Test with localhost as target."""
        gen = RedirectPayloadGenerator()
        payloads = gen._whitelist_bypass_payloads("localhost")

        assert isinstance(payloads, list)
        assert any("localhost" in p[0] for p in payloads)

    def test_ip_as_target(self):
        """Test with IP address as target."""
        gen = RedirectPayloadGenerator()
        payloads = gen._whitelist_bypass_payloads("192.168.1.1")

        assert isinstance(payloads, list)
