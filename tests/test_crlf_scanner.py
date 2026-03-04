"""
Tests for scanning/modules/crlf_scanner.py

Covers:
- CRLFAttackType enum (10 types)
- InjectionContext enum (9 contexts)
- CRLFPayload dataclass
- CRLFVulnerability dataclass
- FrameworkSignature dataclass
- CRLFScanner payload constants (all categories)
- BASIC_CRLF_SEQUENCES
- HEADER_INJECTION_PAYLOADS
- COOKIE_INJECTION_PAYLOADS
- CACHE_POISONING_PAYLOADS
- XSS_CRLF_PAYLOADS
- LOG_INJECTION_PAYLOADS
- EMAIL_INJECTION_PAYLOADS
- WAF_BYPASS_PAYLOADS
- HTTP2_PAYLOADS
- FRAMEWORK_SIGNATURES
"""

import pytest
from scanning.modules.crlf_scanner import (
    CRLFAttackType,
    InjectionContext,
    CRLFPayload,
    CRLFVulnerability,
    FrameworkSignature,
    CRLFScanner,
)


# =============================================================================
# ENUM TESTS
# =============================================================================

class TestCRLFAttackType:
    """Test CRLFAttackType enum."""

    def test_count(self):
        assert len(CRLFAttackType) == 10

    def test_http_response_splitting(self):
        assert CRLFAttackType.HTTP_RESPONSE_SPLITTING.value == "http_response_splitting"

    def test_header_injection(self):
        assert CRLFAttackType.HEADER_INJECTION.value == "header_injection"

    def test_cookie_injection(self):
        assert CRLFAttackType.COOKIE_INJECTION.value == "cookie_injection"

    def test_cache_poisoning(self):
        assert CRLFAttackType.CACHE_POISONING.value == "cache_poisoning"

    def test_log_injection(self):
        assert CRLFAttackType.LOG_INJECTION.value == "log_injection"

    def test_xss_via_crlf(self):
        assert CRLFAttackType.XSS_VIA_CRLF.value == "xss_via_crlf"

    def test_email_header_injection(self):
        assert CRLFAttackType.EMAIL_HEADER_INJECTION.value == "email_header_injection"

    def test_smtp_injection(self):
        assert CRLFAttackType.SMTP_INJECTION.value == "smtp_injection"

    def test_open_redirect_crlf(self):
        assert CRLFAttackType.OPEN_REDIRECT_CRLF.value == "open_redirect_crlf"

    def test_content_injection(self):
        assert CRLFAttackType.CONTENT_INJECTION.value == "content_injection"


class TestInjectionContext:
    """Test InjectionContext enum."""

    def test_count(self):
        assert len(InjectionContext) == 9

    def test_url_parameter(self):
        assert InjectionContext.URL_PARAMETER.value == "url_parameter"

    def test_http_header(self):
        assert InjectionContext.HTTP_HEADER.value == "http_header"

    def test_redirect_location(self):
        assert InjectionContext.REDIRECT_LOCATION.value == "redirect_location"

    def test_cookie_value(self):
        assert InjectionContext.COOKIE_VALUE.value == "cookie_value"

    def test_log_message(self):
        assert InjectionContext.LOG_MESSAGE.value == "log_message"

    def test_email_header(self):
        assert InjectionContext.EMAIL_HEADER.value == "email_header"

    def test_path_segment(self):
        assert InjectionContext.PATH_SEGMENT.value == "path_segment"

    def test_fragment(self):
        assert InjectionContext.FRAGMENT.value == "fragment"

    def test_post_data(self):
        assert InjectionContext.POST_DATA.value == "post_data"


# =============================================================================
# DATACLASS TESTS
# =============================================================================

class TestCRLFPayload:
    """Test CRLFPayload dataclass."""

    def test_basic_creation(self):
        payload = CRLFPayload(
            payload="%0d%0aX-Injected: true",
            encoding="url_encoded",
            attack_type=CRLFAttackType.HEADER_INJECTION,
            description="Basic header injection",
        )
        assert payload.payload == "%0d%0aX-Injected: true"
        assert payload.encoding == "url_encoded"
        assert payload.attack_type == CRLFAttackType.HEADER_INJECTION
        assert payload.waf_bypass is False  # default
        assert payload.http2_compatible is True  # default
        assert payload.detection_pattern is None  # default

    def test_with_all_fields(self):
        payload = CRLFPayload(
            payload="%E5%98%8A%E5%98%8DX-Test: bypass",
            encoding="unicode",
            attack_type=CRLFAttackType.HEADER_INJECTION,
            description="Unicode bypass",
            waf_bypass=True,
            http2_compatible=False,
            detection_pattern="X-Test",
        )
        assert payload.waf_bypass is True
        assert payload.http2_compatible is False
        assert payload.detection_pattern == "X-Test"


class TestCRLFVulnerability:
    """Test CRLFVulnerability dataclass."""

    def test_creation(self):
        payload = CRLFPayload(
            payload="%0d%0aX-Injected: true",
            encoding="url_encoded",
            attack_type=CRLFAttackType.HEADER_INJECTION,
            description="Test",
        )
        vuln = CRLFVulnerability(
            attack_type=CRLFAttackType.HEADER_INJECTION,
            context=InjectionContext.URL_PARAMETER,
            payload=payload,
            url="https://target.com/path?param=value",
            parameter="param",
            evidence=["X-Injected: true found in response headers"],
            response_code=200,
            injected_headers=["X-Injected: true"],
            severity="HIGH",
            cwe="CWE-113",
            cvss=6.1,
        )
        assert vuln.attack_type == CRLFAttackType.HEADER_INJECTION
        assert vuln.context == InjectionContext.URL_PARAMETER
        assert vuln.severity == "HIGH"
        assert vuln.cwe == "CWE-113"
        assert len(vuln.injected_headers) == 1

    def test_cookie_injection_vuln(self):
        payload = CRLFPayload(
            payload="%0d%0aSet-Cookie: session=hijacked",
            encoding="url_encoded",
            attack_type=CRLFAttackType.COOKIE_INJECTION,
            description="Session hijack",
        )
        vuln = CRLFVulnerability(
            attack_type=CRLFAttackType.COOKIE_INJECTION,
            context=InjectionContext.URL_PARAMETER,
            payload=payload,
            url="https://target.com/redirect?url=val",
            parameter="url",
            evidence=["Set-Cookie: session=hijacked in response"],
            response_code=302,
            injected_headers=["Set-Cookie: session=hijacked"],
            severity="HIGH",
            cwe="CWE-113",
            cvss=7.5,
        )
        assert vuln.attack_type == CRLFAttackType.COOKIE_INJECTION


class TestFrameworkSignature:
    """Test FrameworkSignature dataclass."""

    def test_creation(self):
        sig = FrameworkSignature(
            name="Flask/Werkzeug",
            version_pattern=r"Werkzeug|Flask",
            vulnerable_params=["next", "url"],
            payload_pattern="%0d%0a",
            cve="CVE-2019-14806",
        )
        assert sig.name == "Flask/Werkzeug"
        assert sig.cve == "CVE-2019-14806"
        assert "next" in sig.vulnerable_params

    def test_without_cve(self):
        sig = FrameworkSignature(
            name="Custom",
            version_pattern=r"Custom/\d+",
            vulnerable_params=["param"],
            payload_pattern="%0d%0a",
        )
        assert sig.cve is None


# =============================================================================
# BASIC CRLF SEQUENCES
# =============================================================================

class TestBasicCRLFSequences:
    """Test BASIC_CRLF_SEQUENCES constant."""

    def test_not_empty(self):
        assert len(CRLFScanner.BASIC_CRLF_SEQUENCES) > 0

    def test_all_are_tuples(self):
        for seq in CRLFScanner.BASIC_CRLF_SEQUENCES:
            assert isinstance(seq, tuple)
            assert len(seq) == 3  # (payload, encoding, description)

    def test_has_standard_crlf(self):
        payloads = [s[0] for s in CRLFScanner.BASIC_CRLF_SEQUENCES]
        assert "%0d%0a" in payloads

    def test_has_cr_only(self):
        payloads = [s[0] for s in CRLFScanner.BASIC_CRLF_SEQUENCES]
        assert "%0d" in payloads

    def test_has_lf_only(self):
        payloads = [s[0] for s in CRLFScanner.BASIC_CRLF_SEQUENCES]
        assert "%0a" in payloads

    def test_has_raw_crlf(self):
        payloads = [s[0] for s in CRLFScanner.BASIC_CRLF_SEQUENCES]
        assert "\r\n" in payloads

    def test_has_double_encoded(self):
        encodings = [s[1] for s in CRLFScanner.BASIC_CRLF_SEQUENCES]
        assert "double_encoded" in encodings

    def test_has_unicode(self):
        encodings = [s[1] for s in CRLFScanner.BASIC_CRLF_SEQUENCES]
        assert "unicode" in encodings

    def test_has_mixed(self):
        encodings = [s[1] for s in CRLFScanner.BASIC_CRLF_SEQUENCES]
        assert "mixed" in encodings

    def test_has_null_terminated(self):
        encodings = [s[1] for s in CRLFScanner.BASIC_CRLF_SEQUENCES]
        assert "null_terminated" in encodings

    def test_has_base64(self):
        encodings = [s[1] for s in CRLFScanner.BASIC_CRLF_SEQUENCES]
        assert "base64" in encodings

    def test_has_double_crlf_for_body(self):
        """Double CRLF needed for HTTP response body injection."""
        payloads = [s[0] for s in CRLFScanner.BASIC_CRLF_SEQUENCES]
        assert "%0d%0a%0d%0a" in payloads

    def test_has_unicode_separators(self):
        """Unicode line/paragraph separators."""
        payloads = [s[0] for s in CRLFScanner.BASIC_CRLF_SEQUENCES]
        assert "\u2028" in payloads
        assert "\u2029" in payloads


# =============================================================================
# HEADER INJECTION PAYLOADS
# =============================================================================

class TestHeaderInjectionPayloads:
    """Test HEADER_INJECTION_PAYLOADS constant."""

    def test_not_empty(self):
        assert len(CRLFScanner.HEADER_INJECTION_PAYLOADS) > 0

    def test_all_are_crlf_payloads(self):
        for p in CRLFScanner.HEADER_INJECTION_PAYLOADS:
            assert isinstance(p, CRLFPayload)

    def test_has_basic_marker(self):
        patterns = [p.detection_pattern for p in CRLFScanner.HEADER_INJECTION_PAYLOADS if p.detection_pattern]
        assert "X-Injected" in patterns

    def test_has_cors_injection(self):
        patterns = [p.detection_pattern for p in CRLFScanner.HEADER_INJECTION_PAYLOADS if p.detection_pattern]
        assert "Access-Control-Allow-Origin" in patterns

    def test_has_xss_protection_bypass(self):
        descs = [p.description for p in CRLFScanner.HEADER_INJECTION_PAYLOADS]
        assert any("XSS" in d or "xss" in d.lower() for d in descs)

    def test_has_csp_injection(self):
        patterns = [p.detection_pattern for p in CRLFScanner.HEADER_INJECTION_PAYLOADS if p.detection_pattern]
        assert "Content-Security-Policy" in patterns

    def test_has_clickjacking_bypass(self):
        descs = [p.description for p in CRLFScanner.HEADER_INJECTION_PAYLOADS]
        assert any("Clickjacking" in d or "X-Frame" in d for d in descs)

    def test_has_hsts_downgrade(self):
        patterns = [p.detection_pattern for p in CRLFScanner.HEADER_INJECTION_PAYLOADS if p.detection_pattern]
        assert "max-age=0" in patterns

    def test_has_location_redirect(self):
        attack_types = [p.attack_type for p in CRLFScanner.HEADER_INJECTION_PAYLOADS]
        assert CRLFAttackType.OPEN_REDIRECT_CRLF in attack_types


# =============================================================================
# COOKIE INJECTION PAYLOADS
# =============================================================================

class TestCookieInjectionPayloads:
    """Test COOKIE_INJECTION_PAYLOADS constant."""

    def test_not_empty(self):
        assert len(CRLFScanner.COOKIE_INJECTION_PAYLOADS) > 0

    def test_all_are_cookie_type(self):
        for p in CRLFScanner.COOKIE_INJECTION_PAYLOADS:
            assert p.attack_type == CRLFAttackType.COOKIE_INJECTION

    def test_has_session_hijack(self):
        patterns = [p.detection_pattern for p in CRLFScanner.COOKIE_INJECTION_PAYLOADS if p.detection_pattern]
        assert any("session=" in p for p in patterns)

    def test_has_admin_privesc(self):
        patterns = [p.detection_pattern for p in CRLFScanner.COOKIE_INJECTION_PAYLOADS if p.detection_pattern]
        assert any("admin" in p for p in patterns)

    def test_has_csrf_manipulation(self):
        descs = [p.description for p in CRLFScanner.COOKIE_INJECTION_PAYLOADS]
        assert any("CSRF" in d or "csrf" in d for d in descs)

    def test_has_jwt_none_algorithm(self):
        patterns = [p.detection_pattern for p in CRLFScanner.COOKIE_INJECTION_PAYLOADS if p.detection_pattern]
        assert any("eyJhbGciOiJub25l" in p for p in patterns)

    def test_has_php_session_fixation(self):
        patterns = [p.detection_pattern for p in CRLFScanner.COOKIE_INJECTION_PAYLOADS if p.detection_pattern]
        assert any("PHPSESSID" in p for p in patterns)

    def test_has_java_session_fixation(self):
        patterns = [p.detection_pattern for p in CRLFScanner.COOKIE_INJECTION_PAYLOADS if p.detection_pattern]
        assert any("JSESSIONID" in p for p in patterns)

    def test_has_dotnet_session_fixation(self):
        patterns = [p.detection_pattern for p in CRLFScanner.COOKIE_INJECTION_PAYLOADS if p.detection_pattern]
        assert any("ASP.NET_SessionId" in p for p in patterns)


# =============================================================================
# CACHE POISONING PAYLOADS
# =============================================================================

class TestCachePoisoningPayloads:
    """Test CACHE_POISONING_PAYLOADS constant."""

    def test_not_empty(self):
        assert len(CRLFScanner.CACHE_POISONING_PAYLOADS) > 0

    def test_all_are_cache_type(self):
        for p in CRLFScanner.CACHE_POISONING_PAYLOADS:
            assert p.attack_type == CRLFAttackType.CACHE_POISONING

    def test_has_cache_control(self):
        patterns = [p.detection_pattern for p in CRLFScanner.CACHE_POISONING_PAYLOADS if p.detection_pattern]
        assert any("max-age" in p for p in patterns)

    def test_has_forwarded_host(self):
        descs = [p.description for p in CRLFScanner.CACHE_POISONING_PAYLOADS]
        assert any("Forwarded" in d or "forwarded" in d for d in descs)


# =============================================================================
# XSS VIA CRLF PAYLOADS
# =============================================================================

class TestXSSCRLFPayloads:
    """Test XSS_CRLF_PAYLOADS constant."""

    def test_not_empty(self):
        assert len(CRLFScanner.XSS_CRLF_PAYLOADS) > 0

    def test_all_are_xss_type(self):
        for p in CRLFScanner.XSS_CRLF_PAYLOADS:
            assert p.attack_type == CRLFAttackType.XSS_VIA_CRLF

    def test_has_script_injection(self):
        patterns = [p.detection_pattern for p in CRLFScanner.XSS_CRLF_PAYLOADS if p.detection_pattern]
        assert any("<script>" in p for p in patterns)

    def test_has_svg_xss(self):
        patterns = [p.detection_pattern for p in CRLFScanner.XSS_CRLF_PAYLOADS if p.detection_pattern]
        assert any("<svg" in p for p in patterns)

    def test_has_content_type_manipulation(self):
        descs = [p.description for p in CRLFScanner.XSS_CRLF_PAYLOADS]
        assert any("Content-Type" in d for d in descs)

    def test_has_utf7_bypass(self):
        descs = [p.description for p in CRLFScanner.XSS_CRLF_PAYLOADS]
        assert any("UTF-7" in d for d in descs)

    def test_has_body_onload(self):
        patterns = [p.detection_pattern for p in CRLFScanner.XSS_CRLF_PAYLOADS if p.detection_pattern]
        assert any("<body onload=" in p for p in patterns)


# =============================================================================
# LOG INJECTION PAYLOADS
# =============================================================================

class TestLogInjectionPayloads:
    """Test LOG_INJECTION_PAYLOADS constant."""

    def test_not_empty(self):
        assert len(CRLFScanner.LOG_INJECTION_PAYLOADS) > 0

    def test_all_are_log_type(self):
        for p in CRLFScanner.LOG_INJECTION_PAYLOADS:
            assert p.attack_type == CRLFAttackType.LOG_INJECTION

    def test_has_basic_log_forging(self):
        patterns = [p.detection_pattern for p in CRLFScanner.LOG_INJECTION_PAYLOADS if p.detection_pattern]
        assert any("[INJECTED]" in p for p in patterns)

    def test_has_apache_clf(self):
        descs = [p.description for p in CRLFScanner.LOG_INJECTION_PAYLOADS]
        assert any("Apache" in d or "CLF" in d for d in descs)

    def test_has_json_log(self):
        descs = [p.description for p in CRLFScanner.LOG_INJECTION_PAYLOADS]
        assert any("JSON" in d for d in descs)

    def test_has_php_code_injection(self):
        descs = [p.description for p in CRLFScanner.LOG_INJECTION_PAYLOADS]
        assert any("PHP" in d for d in descs)


# =============================================================================
# EMAIL INJECTION PAYLOADS
# =============================================================================

class TestEmailInjectionPayloads:
    """Test EMAIL_INJECTION_PAYLOADS constant."""

    def test_not_empty(self):
        assert len(CRLFScanner.EMAIL_INJECTION_PAYLOADS) > 0

    def test_all_are_email_type(self):
        for p in CRLFScanner.EMAIL_INJECTION_PAYLOADS:
            assert p.attack_type == CRLFAttackType.EMAIL_HEADER_INJECTION

    def test_has_bcc_injection(self):
        patterns = [p.detection_pattern for p in CRLFScanner.EMAIL_INJECTION_PAYLOADS if p.detection_pattern]
        assert any("Bcc:" in p for p in patterns)

    def test_has_cc_injection(self):
        patterns = [p.detection_pattern for p in CRLFScanner.EMAIL_INJECTION_PAYLOADS if p.detection_pattern]
        assert any("Cc:" in p for p in patterns)

    def test_has_subject_manipulation(self):
        patterns = [p.detection_pattern for p in CRLFScanner.EMAIL_INJECTION_PAYLOADS if p.detection_pattern]
        assert any("Subject:" in p for p in patterns)

    def test_has_from_spoofing(self):
        patterns = [p.detection_pattern for p in CRLFScanner.EMAIL_INJECTION_PAYLOADS if p.detection_pattern]
        assert any("From:" in p for p in patterns)

    def test_has_reply_to_hijacking(self):
        patterns = [p.detection_pattern for p in CRLFScanner.EMAIL_INJECTION_PAYLOADS if p.detection_pattern]
        assert any("Reply-To:" in p for p in patterns)


# =============================================================================
# WAF BYPASS PAYLOADS
# =============================================================================

class TestWAFBypassPayloads:
    """Test WAF_BYPASS_PAYLOADS constant."""

    def test_not_empty(self):
        assert len(CRLFScanner.WAF_BYPASS_PAYLOADS) > 0

    def test_all_are_waf_bypass(self):
        for p in CRLFScanner.WAF_BYPASS_PAYLOADS:
            assert p.waf_bypass is True

    def test_has_unicode_bypass(self):
        encodings = [p.encoding for p in CRLFScanner.WAF_BYPASS_PAYLOADS]
        assert "unicode" in encodings

    def test_has_overlong_utf8(self):
        encodings = [p.encoding for p in CRLFScanner.WAF_BYPASS_PAYLOADS]
        assert "overlong_utf8" in encodings

    def test_has_null_byte(self):
        encodings = [p.encoding for p in CRLFScanner.WAF_BYPASS_PAYLOADS]
        assert "null_byte" in encodings

    def test_has_unicode_escape(self):
        encodings = [p.encoding for p in CRLFScanner.WAF_BYPASS_PAYLOADS]
        assert "unicode_escape" in encodings

    def test_has_mixed_encoding(self):
        encodings = [p.encoding for p in CRLFScanner.WAF_BYPASS_PAYLOADS]
        assert "mixed" in encodings

    def test_has_tab_space(self):
        encodings = [p.encoding for p in CRLFScanner.WAF_BYPASS_PAYLOADS]
        assert "tab_space" in encodings

    def test_all_have_detection_pattern(self):
        for p in CRLFScanner.WAF_BYPASS_PAYLOADS:
            assert p.detection_pattern is not None


# =============================================================================
# HTTP/2 PAYLOADS
# =============================================================================

class TestHTTP2Payloads:
    """Test HTTP2_PAYLOADS constant."""

    def test_not_empty(self):
        assert len(CRLFScanner.HTTP2_PAYLOADS) > 0

    def test_all_http2_compatible(self):
        for p in CRLFScanner.HTTP2_PAYLOADS:
            assert p.http2_compatible is True

    def test_has_scheme_injection(self):
        patterns = [p.detection_pattern for p in CRLFScanner.HTTP2_PAYLOADS if p.detection_pattern]
        assert any(":scheme:" in p for p in patterns)

    def test_has_authority_injection(self):
        patterns = [p.detection_pattern for p in CRLFScanner.HTTP2_PAYLOADS if p.detection_pattern]
        assert any(":authority:" in p for p in patterns)

    def test_has_path_injection(self):
        patterns = [p.detection_pattern for p in CRLFScanner.HTTP2_PAYLOADS if p.detection_pattern]
        assert any(":path:" in p for p in patterns)

    def test_has_method_injection(self):
        patterns = [p.detection_pattern for p in CRLFScanner.HTTP2_PAYLOADS if p.detection_pattern]
        assert any(":method:" in p for p in patterns)


# =============================================================================
# FRAMEWORK SIGNATURES
# =============================================================================

class TestFrameworkSignatures:
    """Test FRAMEWORK_SIGNATURES constant."""

    def test_not_empty(self):
        assert len(CRLFScanner.FRAMEWORK_SIGNATURES) > 0

    def test_all_are_signatures(self):
        for sig in CRLFScanner.FRAMEWORK_SIGNATURES:
            assert isinstance(sig, FrameworkSignature)

    def test_has_flask(self):
        names = [sig.name for sig in CRLFScanner.FRAMEWORK_SIGNATURES]
        assert any("Flask" in n or "Werkzeug" in n for n in names)

    def test_has_php(self):
        names = [sig.name for sig in CRLFScanner.FRAMEWORK_SIGNATURES]
        assert any("PHP" in n for n in names)

    def test_has_tomcat(self):
        names = [sig.name for sig in CRLFScanner.FRAMEWORK_SIGNATURES]
        assert any("Tomcat" in n for n in names)

    def test_has_iis(self):
        names = [sig.name for sig in CRLFScanner.FRAMEWORK_SIGNATURES]
        assert any("IIS" in n for n in names)

    def test_all_have_vulnerable_params(self):
        for sig in CRLFScanner.FRAMEWORK_SIGNATURES:
            assert len(sig.vulnerable_params) > 0

    def test_all_have_crlf_pattern(self):
        for sig in CRLFScanner.FRAMEWORK_SIGNATURES:
            assert "%0d%0a" in sig.payload_pattern or "\\r\\n" in sig.payload_pattern


# =============================================================================
# SCANNER CLASS
# =============================================================================

class TestCRLFScannerClass:
    """Test CRLFScanner class attributes."""

    def test_name(self):
        assert CRLFScanner.name == "crlf_scanner"

    def test_is_scan_module(self):
        from scanning.vuln_scanner import ScanModule
        assert issubclass(CRLFScanner, ScanModule)


# =============================================================================
# ATTACK SCENARIOS
# =============================================================================

class TestAttackScenarios:
    """Test realistic CRLF injection attack scenarios."""

    def test_header_injection_scenario(self):
        """Header injection to add arbitrary headers."""
        payload = CRLFPayload(
            payload="%0d%0aX-Injected: true",
            encoding="url_encoded",
            attack_type=CRLFAttackType.HEADER_INJECTION,
            description="Basic header injection",
            detection_pattern="X-Injected",
        )
        vuln = CRLFVulnerability(
            attack_type=CRLFAttackType.HEADER_INJECTION,
            context=InjectionContext.URL_PARAMETER,
            payload=payload,
            url="https://target.com/path?param=%0d%0aX-Injected:%20true",
            parameter="param",
            evidence=["X-Injected: true in response"],
            response_code=200,
            injected_headers=["X-Injected: true"],
            severity="MEDIUM",
            cwe="CWE-113",
            cvss=6.1,
        )
        assert vuln.attack_type == CRLFAttackType.HEADER_INJECTION

    def test_session_fixation_scenario(self):
        """Session fixation via Set-Cookie injection."""
        payload = CRLFPayload(
            payload="%0d%0aSet-Cookie: PHPSESSID=evil123",
            encoding="url_encoded",
            attack_type=CRLFAttackType.COOKIE_INJECTION,
            description="PHP session fixation",
            detection_pattern="PHPSESSID=evil",
        )
        vuln = CRLFVulnerability(
            attack_type=CRLFAttackType.COOKIE_INJECTION,
            context=InjectionContext.REDIRECT_LOCATION,
            payload=payload,
            url="https://target.com/redirect?url=value",
            parameter="url",
            evidence=["Set-Cookie: PHPSESSID=evil123 in response"],
            response_code=302,
            injected_headers=["Set-Cookie: PHPSESSID=evil123; Path=/; HttpOnly"],
            severity="HIGH",
            cwe="CWE-113",
            cvss=7.5,
        )
        assert vuln.severity == "HIGH"

    def test_xss_via_response_splitting(self):
        """XSS through HTTP response body injection."""
        payload = CRLFPayload(
            payload="%0d%0a%0d%0a<script>alert('XSS')</script>",
            encoding="url_encoded",
            attack_type=CRLFAttackType.XSS_VIA_CRLF,
            description="XSS via response splitting",
            detection_pattern="<script>",
        )
        vuln = CRLFVulnerability(
            attack_type=CRLFAttackType.XSS_VIA_CRLF,
            context=InjectionContext.URL_PARAMETER,
            payload=payload,
            url="https://target.com/search?q=payload",
            parameter="q",
            evidence=["<script>alert('XSS')</script> in response body"],
            response_code=200,
            injected_headers=[],
            severity="HIGH",
            cwe="CWE-79",
            cvss=8.1,
        )
        assert vuln.cwe == "CWE-79"

    def test_cache_poisoning_scenario(self):
        """Cache poisoning via CRLF header injection."""
        payload = CRLFPayload(
            payload="%0d%0aCache-Control: public, max-age=31536000",
            encoding="url_encoded",
            attack_type=CRLFAttackType.CACHE_POISONING,
            description="Cache directive manipulation",
            detection_pattern="max-age=31536000",
        )
        assert payload.attack_type == CRLFAttackType.CACHE_POISONING

    def test_email_header_injection_scenario(self):
        """Email BCC injection for intercepting emails."""
        payload = CRLFPayload(
            payload="%0d%0aBcc: attacker@evil.com",
            encoding="url_encoded",
            attack_type=CRLFAttackType.EMAIL_HEADER_INJECTION,
            description="BCC injection",
            detection_pattern="Bcc:",
        )
        assert payload.attack_type == CRLFAttackType.EMAIL_HEADER_INJECTION

    def test_log_forging_scenario(self):
        """Log injection to forge audit trail."""
        payload = CRLFPayload(
            payload="%0d%0a[INJECTED] Admin login successful",
            encoding="url_encoded",
            attack_type=CRLFAttackType.LOG_INJECTION,
            description="Audit trail manipulation",
            detection_pattern="[INJECTED]",
        )
        assert payload.attack_type == CRLFAttackType.LOG_INJECTION


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Test edge cases."""

    def test_all_attack_types_unique(self):
        values = [t.value for t in CRLFAttackType]
        assert len(values) == len(set(values))

    def test_all_contexts_unique(self):
        values = [c.value for c in InjectionContext]
        assert len(values) == len(set(values))

    def test_payload_with_empty_detection_pattern(self):
        payload = CRLFPayload(
            payload="%0d%0a",
            encoding="url_encoded",
            attack_type=CRLFAttackType.HTTP_RESPONSE_SPLITTING,
            description="Plain CRLF",
        )
        assert payload.detection_pattern is None

    def test_vulnerability_with_multiple_evidence(self):
        payload = CRLFPayload(
            payload="%0d%0aMultiple: headers%0d%0aX-Extra: value",
            encoding="url_encoded",
            attack_type=CRLFAttackType.HEADER_INJECTION,
            description="Multiple header injection",
        )
        vuln = CRLFVulnerability(
            attack_type=CRLFAttackType.HEADER_INJECTION,
            context=InjectionContext.URL_PARAMETER,
            payload=payload,
            url="https://target.com",
            parameter="test",
            evidence=["Multiple: headers", "X-Extra: value"],
            response_code=200,
            injected_headers=["Multiple: headers", "X-Extra: value"],
            severity="HIGH",
            cwe="CWE-113",
            cvss=6.1,
        )
        assert len(vuln.evidence) == 2
        assert len(vuln.injected_headers) == 2

    def test_all_payload_categories_have_detection(self):
        """All CRLFPayload instances should have detection patterns."""
        all_payloads = (
            CRLFScanner.HEADER_INJECTION_PAYLOADS +
            CRLFScanner.COOKIE_INJECTION_PAYLOADS +
            CRLFScanner.XSS_CRLF_PAYLOADS +
            CRLFScanner.LOG_INJECTION_PAYLOADS +
            CRLFScanner.EMAIL_INJECTION_PAYLOADS +
            CRLFScanner.WAF_BYPASS_PAYLOADS +
            CRLFScanner.HTTP2_PAYLOADS
        )
        for p in all_payloads:
            assert p.detection_pattern is not None, f"Missing detection for: {p.description}"
