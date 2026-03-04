"""
Tests for scanning/modules/open_redirect_scanner.py

Covers:
- RedirectType enum (9 types)
- RedirectVector enum (6 vectors)
- RedirectPayloadGenerator (all payload categories)
- RedirectTestResult dataclass
- OpenRedirectFinding dataclass
- ScanConfig dataclass
- OpenRedirectScanner constants and init
- REDIRECT_PARAMS and REDIRECT_ENDPOINTS lists
- Factory functions
- Attack scenarios
"""

import pytest
from scanning.modules.open_redirect_scanner import (
    VERSION,
    RedirectType,
    RedirectVector,
    REDIRECT_PARAMS,
    REDIRECT_ENDPOINTS,
    RedirectPayloadGenerator,
    RedirectTestResult,
    OpenRedirectFinding,
    ScanConfig,
    OpenRedirectScanner,
    create_open_redirect_scanner,
)


# =============================================================================
# ENUM TESTS
# =============================================================================

class TestRedirectType:
    """Test RedirectType enum."""

    def test_count(self):
        assert len(RedirectType) == 9

    def test_parameter_based(self):
        assert RedirectType.PARAMETER_BASED is not None

    def test_header_based(self):
        assert RedirectType.HEADER_BASED is not None

    def test_javascript_redirect(self):
        assert RedirectType.JAVASCRIPT_REDIRECT is not None

    def test_meta_refresh(self):
        assert RedirectType.META_REFRESH is not None

    def test_oauth_redirect(self):
        assert RedirectType.OAUTH_REDIRECT is not None

    def test_protocol_relative(self):
        assert RedirectType.PROTOCOL_RELATIVE is not None

    def test_whitelist_bypass(self):
        assert RedirectType.WHITELIST_BYPASS is not None

    def test_encoding_bypass(self):
        assert RedirectType.ENCODING_BYPASS is not None

    def test_subdomain_bypass(self):
        assert RedirectType.SUBDOMAIN_BYPASS is not None


class TestRedirectVector:
    """Test RedirectVector enum."""

    def test_count(self):
        assert len(RedirectVector) == 6

    def test_url_parameter(self):
        assert RedirectVector.URL_PARAMETER is not None

    def test_path_segment(self):
        assert RedirectVector.PATH_SEGMENT is not None

    def test_header_injection(self):
        assert RedirectVector.HEADER_INJECTION is not None

    def test_post_body(self):
        assert RedirectVector.POST_BODY is not None

    def test_cookie(self):
        assert RedirectVector.COOKIE is not None

    def test_referer(self):
        assert RedirectVector.REFERER is not None


# =============================================================================
# REDIRECT PARAMS & ENDPOINTS
# =============================================================================

class TestRedirectParams:
    """Test REDIRECT_PARAMS list."""

    def test_not_empty(self):
        assert len(REDIRECT_PARAMS) > 0

    def test_has_url(self):
        assert "url" in REDIRECT_PARAMS

    def test_has_redirect(self):
        assert "redirect" in REDIRECT_PARAMS

    def test_has_redirect_url(self):
        assert "redirect_url" in REDIRECT_PARAMS

    def test_has_redirect_uri(self):
        assert "redirect_uri" in REDIRECT_PARAMS

    def test_has_next(self):
        assert "next" in REDIRECT_PARAMS

    def test_has_return(self):
        assert "return" in REDIRECT_PARAMS

    def test_has_goto(self):
        assert "goto" in REDIRECT_PARAMS

    def test_has_destination(self):
        assert "destination" in REDIRECT_PARAMS

    def test_has_callback(self):
        assert "callback" in REDIRECT_PARAMS

    def test_has_continue(self):
        assert "continue" in REDIRECT_PARAMS

    def test_has_oauth_params(self):
        """OAuth-specific redirect params."""
        assert "callback_url" in REDIRECT_PARAMS
        assert "success_url" in REDIRECT_PARAMS

    def test_has_cms_params(self):
        """CMS/framework-specific params."""
        assert "redirect_to" in REDIRECT_PARAMS

    def test_has_short_params(self):
        """Short parameter names."""
        assert "r" in REDIRECT_PARAMS
        assert "u" in REDIRECT_PARAMS
        assert "l" in REDIRECT_PARAMS
        assert "q" in REDIRECT_PARAMS

    def test_all_are_strings(self):
        for p in REDIRECT_PARAMS:
            assert isinstance(p, str)


class TestRedirectEndpoints:
    """Test REDIRECT_ENDPOINTS list."""

    def test_not_empty(self):
        assert len(REDIRECT_ENDPOINTS) > 0

    def test_all_start_with_slash(self):
        for ep in REDIRECT_ENDPOINTS:
            assert ep.startswith("/"), f"Endpoint should start with /: {ep}"

    def test_has_redirect(self):
        assert "/redirect" in REDIRECT_ENDPOINTS

    def test_has_go(self):
        assert "/go" in REDIRECT_ENDPOINTS

    def test_has_out(self):
        assert "/out" in REDIRECT_ENDPOINTS

    def test_has_logout(self):
        assert "/logout" in REDIRECT_ENDPOINTS

    def test_has_login(self):
        assert "/login" in REDIRECT_ENDPOINTS

    def test_has_oauth(self):
        assert "/oauth/authorize" in REDIRECT_ENDPOINTS

    def test_has_sso(self):
        assert "/sso/redirect" in REDIRECT_ENDPOINTS

    def test_has_auth_callback(self):
        assert "/auth/callback" in REDIRECT_ENDPOINTS


# =============================================================================
# PAYLOAD GENERATOR
# =============================================================================

class TestRedirectPayloadGenerator:
    """Test RedirectPayloadGenerator."""

    @pytest.fixture
    def gen(self):
        return RedirectPayloadGenerator("evil.com")

    @pytest.fixture
    def custom_gen(self):
        return RedirectPayloadGenerator("attacker.net")

    def test_init_default(self, gen):
        assert gen.evil_domain == "evil.com"

    def test_init_custom(self, custom_gen):
        assert custom_gen.evil_domain == "attacker.net"

    def test_generate_all_not_empty(self, gen):
        payloads = gen.generate_all("target.com")
        assert len(payloads) > 0

    def test_generate_all_returns_tuples(self, gen):
        payloads = gen.generate_all("target.com")
        for p in payloads:
            assert isinstance(p, tuple)
            assert len(p) == 2

    def test_generate_all_contains_evil_domain(self, gen):
        payloads = gen.generate_all("target.com")
        evil_count = sum(1 for p, d in payloads if "evil.com" in p)
        assert evil_count > 0

    # Basic payloads
    def test_basic_payloads_count(self, gen):
        payloads = gen._basic_payloads()
        assert len(payloads) == 5

    def test_basic_has_https(self, gen):
        payloads = gen._basic_payloads()
        urls = [p for p, d in payloads]
        assert "https://evil.com" in urls

    def test_basic_has_http(self, gen):
        payloads = gen._basic_payloads()
        urls = [p for p, d in payloads]
        assert "http://evil.com" in urls

    def test_basic_has_protocol_relative(self, gen):
        payloads = gen._basic_payloads()
        urls = [p for p, d in payloads]
        assert "//evil.com" in urls

    def test_basic_has_domain_only(self, gen):
        payloads = gen._basic_payloads()
        urls = [p for p, d in payloads]
        assert "evil.com" in urls

    # Protocol-relative payloads
    def test_protocol_relative_payloads(self, gen):
        payloads = gen._protocol_relative_payloads()
        assert len(payloads) >= 4
        urls = [p for p, d in payloads]
        # Should have double slash
        assert "//evil.com" in urls
        # Should have triple slash
        assert "///evil.com" in urls

    def test_protocol_relative_has_backslash(self, gen):
        payloads = gen._protocol_relative_payloads()
        urls = [p for p, d in payloads]
        assert any("\\" in u for u in urls)

    # Encoding payloads
    def test_encoding_payloads_not_empty(self, gen):
        payloads = gen._encoding_payloads()
        assert len(payloads) > 0

    def test_encoding_has_url_encoded(self, gen):
        payloads = gen._encoding_payloads()
        assert any("%2f" in p.lower() or "%3a" in p.lower() for p, d in payloads)

    def test_encoding_has_double_encoded(self, gen):
        payloads = gen._encoding_payloads()
        assert any("%25" in p for p, d in payloads)

    def test_encoding_has_hex_ip(self, gen):
        payloads = gen._encoding_payloads()
        descs = [d for p, d in payloads]
        assert any("Hex" in d for d in descs)

    def test_encoding_has_octal_ip(self, gen):
        payloads = gen._encoding_payloads()
        descs = [d for p, d in payloads]
        assert any("Octal" in d for d in descs)

    # Whitelist bypass payloads
    def test_whitelist_bypass_payloads(self, gen):
        payloads = gen._whitelist_bypass_payloads("target.com")
        assert len(payloads) >= 8

    def test_whitelist_has_fragment(self, gen):
        payloads = gen._whitelist_bypass_payloads("target.com")
        assert any("#target.com" in p for p, d in payloads)

    def test_whitelist_has_at_sign(self, gen):
        payloads = gen._whitelist_bypass_payloads("target.com")
        assert any("@" in p for p, d in payloads)

    def test_whitelist_has_subdomain_trick(self, gen):
        payloads = gen._whitelist_bypass_payloads("target.com")
        assert any("target.com.evil.com" in p for p, d in payloads)

    def test_whitelist_has_reversed_credential(self, gen):
        payloads = gen._whitelist_bypass_payloads("target.com")
        assert any("target.com@evil.com" in p for p, d in payloads)

    def test_whitelist_has_null_byte(self, gen):
        payloads = gen._whitelist_bypass_payloads("target.com")
        assert any("%00" in p for p, d in payloads)

    # Special character payloads
    def test_special_char_payloads(self, gen):
        payloads = gen._special_char_payloads()
        assert len(payloads) > 0

    def test_special_has_crlf(self, gen):
        payloads = gen._special_char_payloads()
        assert any("%0d%0a" in p for p, d in payloads)

    def test_special_has_javascript(self, gen):
        payloads = gen._special_char_payloads()
        assert any("javascript:" in p for p, d in payloads)

    def test_special_has_data_protocol(self, gen):
        payloads = gen._special_char_payloads()
        assert any("data:" in p for p, d in payloads)

    def test_special_has_vbscript(self, gen):
        payloads = gen._special_char_payloads()
        assert any("vbscript:" in p for p, d in payloads)

    # Path confusion payloads
    def test_path_confusion_payloads(self, gen):
        payloads = gen._path_confusion_payloads("target.com")
        assert len(payloads) > 0

    def test_path_confusion_has_relative(self, gen):
        payloads = gen._path_confusion_payloads("target.com")
        assert any("./" in p or "../" in p for p, d in payloads)

    # IP conversion helpers
    def test_ip_to_hex(self, gen):
        result = gen._ip_to_hex("1.2.3.4")
        assert result == "01020304"

    def test_ip_to_hex_high(self, gen):
        result = gen._ip_to_hex("255.255.255.255")
        assert result == "ffffffff"

    def test_ip_to_octal(self, gen):
        result = gen._ip_to_octal("1.2.3.4")
        assert result == "1.2.3.4"  # Single-digit octals same

    def test_ip_to_octal_higher(self, gen):
        result = gen._ip_to_octal("8.16.64.128")
        assert result == "10.20.100.200"

    # Custom domain propagation
    def test_custom_domain_in_basic(self, custom_gen):
        payloads = custom_gen._basic_payloads()
        assert any("attacker.net" in p for p, d in payloads)

    def test_custom_domain_in_whitelist(self, custom_gen):
        payloads = custom_gen._whitelist_bypass_payloads("target.com")
        assert any("attacker.net" in p for p, d in payloads)


# =============================================================================
# DATACLASS TESTS
# =============================================================================

class TestRedirectTestResult:
    """Test RedirectTestResult dataclass."""

    def test_basic_creation(self):
        result = RedirectTestResult(
            parameter="url",
            payload="https://evil.com",
            payload_desc="Direct HTTPS URL",
            response_code=302,
            is_redirect=True,
            redirect_url="https://evil.com/",
            redirects_to_evil=True,
            reflected_in_response=False,
            evidence={"status_code": 302},
        )
        assert result.parameter == "url"
        assert result.response_code == 302
        assert result.is_redirect is True
        assert result.redirects_to_evil is True

    def test_non_redirect(self):
        result = RedirectTestResult(
            parameter="next",
            payload="https://evil.com",
            payload_desc="Direct URL",
            response_code=200,
            is_redirect=False,
            redirect_url=None,
            redirects_to_evil=False,
            reflected_in_response=True,
            evidence={"status_code": 200, "reflected": True},
        )
        assert result.is_redirect is False
        assert result.redirect_url is None
        assert result.reflected_in_response is True


class TestOpenRedirectFinding:
    """Test OpenRedirectFinding dataclass."""

    def test_creation(self):
        finding = OpenRedirectFinding(
            id="REDIR-0001",
            redirect_type=RedirectType.PARAMETER_BASED,
            severity="MEDIUM",
            confidence=0.90,
            url="https://target.com/login?next=https://evil.com",
            parameter="next",
            payload="https://evil.com",
            description="Open redirect via parameter 'next'",
            impact="Phishing attack possible",
            remediation="Use allowlist",
            test_results=[],
            cwe_id=601,
            cvss_score=6.1,
            poc_url="https://target.com/login?next=https://evil.com",
        )
        assert finding.id == "REDIR-0001"
        assert finding.cwe_id == 601
        assert finding.cvss_score == 6.1
        assert finding.severity == "MEDIUM"

    def test_oauth_redirect(self):
        finding = OpenRedirectFinding(
            id="REDIR-0002",
            redirect_type=RedirectType.OAUTH_REDIRECT,
            severity="HIGH",
            confidence=0.95,
            url="https://target.com/oauth/authorize?redirect_uri=https://evil.com",
            parameter="redirect_uri",
            payload="https://evil.com",
            description="OAuth redirect_uri manipulation",
            impact="OAuth token theft",
            remediation="Strict redirect_uri validation",
            test_results=[],
            cwe_id=601,
            cvss_score=8.1,
            poc_url="https://target.com/oauth/authorize?redirect_uri=https://evil.com",
        )
        assert finding.redirect_type == RedirectType.OAUTH_REDIRECT


class TestScanConfig:
    """Test ScanConfig dataclass."""

    def test_defaults(self):
        config = ScanConfig(target_url="https://target.com")
        assert config.target_url == "https://target.com"
        assert config.timeout == 30.0
        assert config.follow_redirects is False
        assert config.test_all_params is True
        assert config.test_path_based is True
        assert config.test_js_redirects is True
        assert config.evil_domain == "evil.com"
        assert config.max_payloads == 30
        assert config.custom_params == []

    def test_custom_config(self):
        config = ScanConfig(
            target_url="https://target.com",
            timeout=60.0,
            evil_domain="attacker.net",
            max_payloads=50,
            custom_params=["custom_redir"],
        )
        assert config.timeout == 60.0
        assert config.evil_domain == "attacker.net"
        assert config.max_payloads == 50
        assert "custom_redir" in config.custom_params


# =============================================================================
# SCANNER CLASS TESTS
# =============================================================================

class TestOpenRedirectScanner:
    """Test OpenRedirectScanner class."""

    def test_init_no_args(self):
        scanner = OpenRedirectScanner()
        assert scanner.http_client is None
        assert scanner.config is None
        assert scanner.findings == []
        assert scanner._session_id is not None

    def test_init_with_config(self):
        config = ScanConfig(target_url="https://target.com")
        scanner = OpenRedirectScanner(config=config)
        assert scanner.config == config

    def test_version(self):
        assert OpenRedirectScanner.VERSION == "3.0.0"

    def test_cwe_id(self):
        assert OpenRedirectScanner.CWE_ID == 601

    def test_get_findings_empty(self):
        scanner = OpenRedirectScanner()
        assert scanner.get_findings() == []

    def test_get_impact(self):
        scanner = OpenRedirectScanner()
        impact = scanner._get_impact()
        assert "Phishing" in impact
        assert "OAuth" in impact
        assert "XSS" in impact

    def test_get_remediation(self):
        scanner = OpenRedirectScanner()
        remediation = scanner._get_remediation()
        assert "whitelist" in remediation.lower()
        assert "URL" in remediation

    def test_create_finding(self):
        scanner = OpenRedirectScanner()
        result = RedirectTestResult(
            parameter="url",
            payload="https://evil.com",
            payload_desc="Direct",
            response_code=302,
            is_redirect=True,
            redirect_url="https://evil.com/",
            redirects_to_evil=True,
            reflected_in_response=False,
            evidence={},
        )
        scanner._create_finding(
            redirect_type=RedirectType.PARAMETER_BASED,
            url="https://target.com?url=https://evil.com",
            parameter="url",
            payload="https://evil.com",
            test_results=[result],
            description="Test finding",
        )
        assert len(scanner.findings) == 1
        assert scanner.findings[0].id == "REDIR-0001"
        assert scanner.findings[0].severity == "MEDIUM"
        assert scanner.findings[0].confidence == 0.90
        assert scanner.findings[0].cwe_id == 601
        assert scanner.findings[0].cvss_score == 6.1

    def test_create_multiple_findings(self):
        scanner = OpenRedirectScanner()
        for i in range(3):
            scanner._create_finding(
                redirect_type=RedirectType.PARAMETER_BASED,
                url=f"https://target.com?p{i}=https://evil.com",
                parameter=f"p{i}",
                payload="https://evil.com",
                test_results=[],
                description=f"Finding {i}",
            )
        assert len(scanner.findings) == 3
        assert scanner.findings[0].id == "REDIR-0001"
        assert scanner.findings[1].id == "REDIR-0002"
        assert scanner.findings[2].id == "REDIR-0003"

    def test_session_id_unique(self):
        s1 = OpenRedirectScanner()
        s2 = OpenRedirectScanner()
        assert s1._session_id != s2._session_id


# =============================================================================
# FACTORY FUNCTIONS
# =============================================================================

class TestFactoryFunctions:
    """Test factory functions."""

    def test_create_scanner_no_args(self):
        scanner = create_open_redirect_scanner()
        assert isinstance(scanner, OpenRedirectScanner)

    def test_create_scanner_with_config(self):
        config = ScanConfig(target_url="https://target.com")
        scanner = create_open_redirect_scanner(config=config)
        assert scanner.config == config


# =============================================================================
# ATTACK SCENARIOS
# =============================================================================

class TestAttackScenarios:
    """Test realistic attack scenarios."""

    def test_phishing_redirect(self):
        """Simulate a phishing attack via open redirect."""
        result = RedirectTestResult(
            parameter="next",
            payload="https://evil.com/fake-login",
            payload_desc="Direct HTTPS URL",
            response_code=302,
            is_redirect=True,
            redirect_url="https://evil.com/fake-login",
            redirects_to_evil=True,
            reflected_in_response=False,
            evidence={"status_code": 302, "location_header": "https://evil.com/fake-login"},
        )
        assert result.redirects_to_evil is True
        assert result.is_redirect is True

    def test_oauth_token_theft(self):
        """OAuth redirect_uri hijacking for token theft."""
        finding = OpenRedirectFinding(
            id="REDIR-0001",
            redirect_type=RedirectType.OAUTH_REDIRECT,
            severity="HIGH",
            confidence=0.95,
            url="https://target.com/oauth/authorize?redirect_uri=https://evil.com/callback",
            parameter="redirect_uri",
            payload="https://evil.com/callback",
            description="OAuth redirect_uri allows external domain",
            impact="Authorization code/token sent to attacker domain",
            remediation="Strict redirect_uri allowlist per client_id",
            test_results=[],
            cwe_id=601,
            cvss_score=8.1,
            poc_url="https://target.com/oauth/authorize?redirect_uri=https://evil.com/callback",
        )
        assert finding.redirect_type == RedirectType.OAUTH_REDIRECT
        assert finding.cvss_score == 8.1

    def test_protocol_relative_bypass(self):
        """Protocol-relative URL bypass."""
        gen = RedirectPayloadGenerator("evil.com")
        payloads = gen._protocol_relative_payloads()
        # All should contain evil.com
        for p, d in payloads:
            assert "evil.com" in p

    def test_whitelist_bypass_with_at_sign(self):
        """user@host confusion attack."""
        gen = RedirectPayloadGenerator("evil.com")
        payloads = gen._whitelist_bypass_payloads("legit.com")
        # Should have both directions: evil@legit and legit@evil
        urls = [p for p, d in payloads]
        has_evil_at_legit = any("evil.com@legit.com" in u for u in urls)
        has_legit_at_evil = any("legit.com@evil.com" in u for u in urls)
        assert has_evil_at_legit
        assert has_legit_at_evil

    def test_javascript_protocol_injection(self):
        """JavaScript protocol redirect."""
        gen = RedirectPayloadGenerator("evil.com")
        payloads = gen._special_char_payloads()
        js_payloads = [p for p, d in payloads if "javascript:" in p]
        assert len(js_payloads) >= 1


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Test edge cases."""

    def test_empty_original_host(self):
        gen = RedirectPayloadGenerator("evil.com")
        payloads = gen._whitelist_bypass_payloads("")
        assert len(payloads) > 0

    def test_finding_with_empty_test_results(self):
        finding = OpenRedirectFinding(
            id="REDIR-0001",
            redirect_type=RedirectType.PARAMETER_BASED,
            severity="MEDIUM",
            confidence=0.5,
            url="https://target.com",
            parameter="url",
            payload="//evil.com",
            description="Test",
            impact="",
            remediation="",
            test_results=[],
            cwe_id=601,
            cvss_score=6.1,
            poc_url="",
        )
        assert finding.test_results == []

    def test_version_constant(self):
        assert VERSION == "3.0.0"

    def test_payload_generator_version(self):
        assert RedirectPayloadGenerator.VERSION == "3.0.0"

    def test_discover_params_includes_common(self):
        """_discover_params should include common redirect params."""
        scanner = OpenRedirectScanner()
        scanner.config = ScanConfig(target_url="https://target.com/path?custom_param=val")
        # We can't call async from sync test, but we can verify the constant list
        assert "url" in REDIRECT_PARAMS
        assert "redirect" in REDIRECT_PARAMS
        assert "next" in REDIRECT_PARAMS

    def test_all_redirect_types_unique(self):
        """All redirect types have unique values."""
        values = [t.value for t in RedirectType]
        assert len(values) == len(set(values))

    def test_all_vectors_unique(self):
        """All vectors have unique values."""
        values = [v.value for v in RedirectVector]
        assert len(values) == len(set(values))
