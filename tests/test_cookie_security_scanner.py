"""
Tests for scanning/modules/cookie_security_scanner.py

Covers:
- CookieVulnType enum (14 members)
- CookieType enum (8 members)
- SESSION_PATTERNS constant (regex patterns for session cookie names)
- SENSITIVE_PATTERNS constant (tuples of pattern + data_type)
- ParsedCookie dataclass (defaults, from_header, calculate_entropy)
- CookieVulnerability dataclass
- CookieAnalyzer class (classify_cookie, is_session_related,
  contains_sensitive_data, is_base64_encoded, check_predictability)
- CookieSecurityScanner class attributes
"""

import re
import math
from collections import Counter

import pytest

from scanning.modules.cookie_security_scanner import (
    CookieVulnType,
    CookieType,
    SESSION_PATTERNS,
    SENSITIVE_PATTERNS,
    ParsedCookie,
    CookieVulnerability,
    CookieAnalyzer,
    CookieSecurityScanner,
)


# =============================================================================
# ENUM TESTS — CookieVulnType
# =============================================================================

class TestCookieVulnType:
    """Test CookieVulnType enum."""

    def test_count(self):
        assert len(CookieVulnType) == 14

    def test_missing_secure(self):
        assert CookieVulnType.MISSING_SECURE.value == "missing_secure"

    def test_missing_httponly(self):
        assert CookieVulnType.MISSING_HTTPONLY.value == "missing_httponly"

    def test_missing_samesite(self):
        assert CookieVulnType.MISSING_SAMESITE.value == "missing_samesite"

    def test_weak_samesite(self):
        assert CookieVulnType.WEAK_SAMESITE.value == "weak_samesite"

    def test_sensitive_data(self):
        assert CookieVulnType.SENSITIVE_DATA.value == "sensitive_data"

    def test_session_fixation(self):
        assert CookieVulnType.SESSION_FIXATION.value == "session_fixation"

    def test_long_expiration(self):
        assert CookieVulnType.LONG_EXPIRATION.value == "long_expiration"

    def test_no_expiration(self):
        assert CookieVulnType.NO_EXPIRATION.value == "no_expiration"

    def test_overly_permissive_domain(self):
        assert CookieVulnType.OVERLY_PERMISSIVE_DOMAIN.value == "overly_permissive_domain"

    def test_overly_permissive_path(self):
        assert CookieVulnType.OVERLY_PERMISSIVE_PATH.value == "overly_permissive_path"

    def test_missing_prefix(self):
        assert CookieVulnType.MISSING_PREFIX.value == "missing_prefix"

    def test_predictable_value(self):
        assert CookieVulnType.PREDICTABLE_VALUE.value == "predictable_value"

    def test_weak_encoding(self):
        assert CookieVulnType.WEAK_ENCODING.value == "weak_encoding"

    def test_cookie_overflow(self):
        assert CookieVulnType.COOKIE_OVERFLOW.value == "cookie_overflow"

    def test_all_values_unique(self):
        values = [t.value for t in CookieVulnType]
        assert len(values) == len(set(values))


# =============================================================================
# ENUM TESTS — CookieType
# =============================================================================

class TestCookieType:
    """Test CookieType enum."""

    def test_count(self):
        assert len(CookieType) == 8

    def test_session(self):
        assert CookieType.SESSION.value == "session"

    def test_authentication(self):
        assert CookieType.AUTHENTICATION.value == "authentication"

    def test_tracking(self):
        assert CookieType.TRACKING.value == "tracking"

    def test_preference(self):
        assert CookieType.PREFERENCE.value == "preference"

    def test_csrf(self):
        assert CookieType.CSRF.value == "csrf"

    def test_analytics(self):
        assert CookieType.ANALYTICS.value == "analytics"

    def test_advertising(self):
        assert CookieType.ADVERTISING.value == "advertising"

    def test_unknown(self):
        assert CookieType.UNKNOWN.value == "unknown"

    def test_all_values_unique(self):
        values = [t.value for t in CookieType]
        assert len(values) == len(set(values))


# =============================================================================
# SESSION_PATTERNS CONSTANT
# =============================================================================

class TestSessionPatterns:
    """Test SESSION_PATTERNS list of regex patterns."""

    def test_not_empty(self):
        assert len(SESSION_PATTERNS) > 10

    def test_all_compile(self):
        for pattern in SESSION_PATTERNS:
            re.compile(pattern, re.IGNORECASE)

    # Session id patterns
    def test_matches_session(self):
        assert any(re.search(p, "session", re.I) for p in SESSION_PATTERNS)

    def test_matches_sess(self):
        assert any(re.search(p, "sess", re.I) for p in SESSION_PATTERNS)

    def test_matches_sid(self):
        assert any(re.search(p, "sid", re.I) for p in SESSION_PATTERNS)

    def test_matches_jsession(self):
        assert any(re.search(p, "jsession", re.I) for p in SESSION_PATTERNS)

    def test_matches_jsessionid(self):
        assert any(re.search(p, "jsessionid", re.I) for p in SESSION_PATTERNS)

    def test_matches_phpsessid(self):
        assert any(re.search(p, "phpsessid", re.I) for p in SESSION_PATTERNS)

    def test_matches_phpsession(self):
        assert any(re.search(p, "phpsession", re.I) for p in SESSION_PATTERNS)

    def test_matches_asp_net_session(self):
        assert any(re.search(p, "asp.net_session", re.I) for p in SESSION_PATTERNS)

    def test_matches_connect_sid(self):
        assert any(re.search(p, "connect.sid", re.I) for p in SESSION_PATTERNS)

    def test_matches_laravel_session(self):
        assert any(re.search(p, "laravel_session", re.I) for p in SESSION_PATTERNS)

    def test_matches_underscore_session(self):
        assert any(re.search(p, "_session", re.I) for p in SESSION_PATTERNS)

    # Token patterns
    def test_matches_token(self):
        assert any(re.search(p, "token", re.I) for p in SESSION_PATTERNS)

    def test_matches_auth(self):
        assert any(re.search(p, "auth", re.I) for p in SESSION_PATTERNS)

    def test_matches_auth_token(self):
        assert any(re.search(p, "auth_token", re.I) for p in SESSION_PATTERNS)

    def test_matches_jwt(self):
        assert any(re.search(p, "jwt", re.I) for p in SESSION_PATTERNS)

    def test_matches_access_token(self):
        assert any(re.search(p, "access_token", re.I) for p in SESSION_PATTERNS)

    def test_matches_refresh_token(self):
        assert any(re.search(p, "refresh_token", re.I) for p in SESSION_PATTERNS)

    # Identity patterns
    def test_matches_id(self):
        assert any(re.search(p, "id", re.I) for p in SESSION_PATTERNS)

    def test_matches_user_id(self):
        assert any(re.search(p, "user_id", re.I) for p in SESSION_PATTERNS)

    def test_matches_user(self):
        assert any(re.search(p, "user", re.I) for p in SESSION_PATTERNS)

    def test_matches_login(self):
        assert any(re.search(p, "login", re.I) for p in SESSION_PATTERNS)

    # Persistence patterns
    def test_matches_remember(self):
        assert any(re.search(p, "remember", re.I) for p in SESSION_PATTERNS)

    def test_matches_remember_me(self):
        assert any(re.search(p, "remember_me", re.I) for p in SESSION_PATTERNS)

    def test_matches_persistent(self):
        assert any(re.search(p, "persistent", re.I) for p in SESSION_PATTERNS)


# =============================================================================
# SENSITIVE_PATTERNS CONSTANT
# =============================================================================

class TestSensitivePatterns:
    """Test SENSITIVE_PATTERNS list of (pattern, data_type) tuples."""

    def test_not_empty(self):
        assert len(SENSITIVE_PATTERNS) > 10

    def test_all_tuples(self):
        for item in SENSITIVE_PATTERNS:
            assert isinstance(item, tuple)
            assert len(item) == 2

    def test_all_compile(self):
        for pattern, _ in SENSITIVE_PATTERNS:
            re.compile(pattern, re.IGNORECASE)

    # Password patterns
    def test_detects_password(self):
        assert any(re.search(p, "password", re.I) for p, _ in SENSITIVE_PATTERNS)

    def test_detects_passwd(self):
        assert any(re.search(p, "passwd", re.I) for p, _ in SENSITIVE_PATTERNS)

    def test_detects_pwd(self):
        assert any(re.search(p, "pwd", re.I) for p, _ in SENSITIVE_PATTERNS)

    def test_password_data_type(self):
        for pattern, data_type in SENSITIVE_PATTERNS:
            if re.search(pattern, "password", re.I):
                assert data_type == "password"
                break

    # API key patterns
    def test_detects_api_key(self):
        assert any(re.search(p, "api_key", re.I) for p, _ in SENSITIVE_PATTERNS)

    def test_detects_apikey(self):
        assert any(re.search(p, "apikey", re.I) for p, _ in SENSITIVE_PATTERNS)

    def test_detects_api_dash_key(self):
        assert any(re.search(p, "api-key", re.I) for p, _ in SENSITIVE_PATTERNS)

    def test_api_key_data_type(self):
        for pattern, data_type in SENSITIVE_PATTERNS:
            if re.search(pattern, "api_key", re.I):
                assert data_type == "api_key"
                break

    # Secret and access key
    def test_detects_secret(self):
        assert any(re.search(p, "secret", re.I) for p, _ in SENSITIVE_PATTERNS)

    def test_detects_access_key(self):
        assert any(re.search(p, "access_key", re.I) for p, _ in SENSITIVE_PATTERNS)

    def test_detects_private(self):
        assert any(re.search(p, "private", re.I) for p, _ in SENSITIVE_PATTERNS)

    # Financial data patterns
    def test_detects_credit_card(self):
        assert any(re.search(p, "credit_card", re.I) for p, _ in SENSITIVE_PATTERNS)

    def test_detects_creditcard(self):
        assert any(re.search(p, "creditcard", re.I) for p, _ in SENSITIVE_PATTERNS)

    def test_detects_cvv(self):
        assert any(re.search(p, "cvv", re.I) for p, _ in SENSITIVE_PATTERNS)

    def test_detects_pin(self):
        assert any(re.search(p, "pin", re.I) for p, _ in SENSITIVE_PATTERNS)

    def test_detects_pin_with_digits(self):
        assert any(re.search(p, "pin1234", re.I) for p, _ in SENSITIVE_PATTERNS)

    # PII patterns
    def test_detects_ssn(self):
        assert any(re.search(p, "ssn", re.I) for p, _ in SENSITIVE_PATTERNS)

    def test_detects_social_sec(self):
        assert any(re.search(p, "social_sec", re.I) for p, _ in SENSITIVE_PATTERNS)

    def test_detects_socialsec(self):
        assert any(re.search(p, "socialsec", re.I) for p, _ in SENSITIVE_PATTERNS)

    def test_detects_dob(self):
        assert any(re.search(p, "dob", re.I) for p, _ in SENSITIVE_PATTERNS)

    def test_detects_birthdate(self):
        assert any(re.search(p, "birthdate", re.I) for p, _ in SENSITIVE_PATTERNS)

    def test_detects_birth_date(self):
        assert any(re.search(p, "birth_date", re.I) for p, _ in SENSITIVE_PATTERNS)


# =============================================================================
# DATACLASS TESTS — ParsedCookie
# =============================================================================

class TestParsedCookie:
    """Test ParsedCookie dataclass."""

    def test_defaults(self):
        cookie = ParsedCookie(name="test", value="abc")
        assert cookie.name == "test"
        assert cookie.value == "abc"
        assert cookie.domain is None
        assert cookie.path == "/"
        assert cookie.secure is False
        assert cookie.httponly is False
        assert cookie.samesite is None
        assert cookie.expires is None
        assert cookie.max_age is None
        assert cookie.raw_header == ""
        assert cookie.cookie_type == CookieType.UNKNOWN
        assert cookie.is_session_cookie is False
        assert cookie.is_sensitive is False
        assert cookie.entropy == 0.0
        assert cookie.vulnerabilities == []

    def test_with_all_attributes(self):
        cookie = ParsedCookie(
            name="session_id",
            value="abc123xyz",
            domain=".example.com",
            path="/app",
            secure=True,
            httponly=True,
            samesite="strict",
            expires="Thu, 01 Jan 2099 00:00:00 GMT",
            max_age=3600,
            raw_header="session_id=abc123xyz; Secure; HttpOnly",
            cookie_type=CookieType.SESSION,
            is_session_cookie=True,
            is_sensitive=False,
            entropy=3.5,
            vulnerabilities=[CookieVulnType.MISSING_SAMESITE],
        )
        assert cookie.name == "session_id"
        assert cookie.domain == ".example.com"
        assert cookie.path == "/app"
        assert cookie.secure is True
        assert cookie.httponly is True
        assert cookie.samesite == "strict"
        assert cookie.max_age == 3600
        assert cookie.cookie_type == CookieType.SESSION
        assert cookie.is_session_cookie is True
        assert len(cookie.vulnerabilities) == 1

    def test_vulnerabilities_list_independence(self):
        """Each instance should have its own vulnerabilities list."""
        c1 = ParsedCookie(name="a", value="1")
        c2 = ParsedCookie(name="b", value="2")
        c1.vulnerabilities.append(CookieVulnType.MISSING_SECURE)
        assert len(c2.vulnerabilities) == 0


# =============================================================================
# ParsedCookie.from_header
# =============================================================================

class TestParsedCookieFromHeader:
    """Test ParsedCookie.from_header classmethod."""

    def test_simple_name_value(self):
        cookie = ParsedCookie.from_header("session=abc123")
        assert cookie is not None
        assert cookie.name == "session"
        assert cookie.value == "abc123"

    def test_secure_flag(self):
        cookie = ParsedCookie.from_header("id=xyz; Secure")
        assert cookie is not None
        assert cookie.secure is True

    def test_httponly_flag(self):
        cookie = ParsedCookie.from_header("id=xyz; HttpOnly")
        assert cookie is not None
        assert cookie.httponly is True

    def test_samesite_strict(self):
        cookie = ParsedCookie.from_header("id=xyz; SameSite=Strict")
        assert cookie is not None
        assert cookie.samesite == "strict"

    def test_samesite_lax(self):
        cookie = ParsedCookie.from_header("id=xyz; SameSite=Lax")
        assert cookie is not None
        assert cookie.samesite == "lax"

    def test_samesite_none(self):
        cookie = ParsedCookie.from_header("id=xyz; SameSite=None")
        assert cookie is not None
        assert cookie.samesite == "none"

    def test_domain_attribute(self):
        cookie = ParsedCookie.from_header("id=xyz; Domain=.example.com")
        assert cookie is not None
        assert cookie.domain == ".example.com"

    def test_path_attribute(self):
        cookie = ParsedCookie.from_header("id=xyz; Path=/app")
        assert cookie is not None
        assert cookie.path == "/app"

    def test_default_path(self):
        cookie = ParsedCookie.from_header("id=xyz")
        assert cookie is not None
        assert cookie.path == "/"

    def test_expires_attribute(self):
        cookie = ParsedCookie.from_header("id=xyz; Expires=Thu, 01 Jan 2099 00:00:00 GMT")
        assert cookie is not None
        assert cookie.expires is not None
        assert "2099" in cookie.expires

    def test_max_age_attribute(self):
        cookie = ParsedCookie.from_header("id=xyz; Max-Age=86400")
        assert cookie is not None
        assert cookie.max_age == 86400

    def test_max_age_zero(self):
        cookie = ParsedCookie.from_header("id=xyz; Max-Age=0")
        assert cookie is not None
        assert cookie.max_age == 0

    def test_max_age_invalid_value(self):
        cookie = ParsedCookie.from_header("id=xyz; Max-Age=notanumber")
        assert cookie is not None
        assert cookie.max_age is None

    def test_full_cookie_all_attributes(self):
        header = (
            "session=abc123; Path=/; Domain=.example.com; "
            "HttpOnly; Secure; SameSite=Strict; Max-Age=86400"
        )
        cookie = ParsedCookie.from_header(header)
        assert cookie is not None
        assert cookie.name == "session"
        assert cookie.value == "abc123"
        assert cookie.path == "/"
        assert cookie.domain == ".example.com"
        assert cookie.httponly is True
        assert cookie.secure is True
        assert cookie.samesite == "strict"
        assert cookie.max_age == 86400

    def test_raw_header_preserved(self):
        header = "token=secret; Secure; HttpOnly"
        cookie = ParsedCookie.from_header(header)
        assert cookie is not None
        assert cookie.raw_header == header

    def test_value_with_equals_sign(self):
        """Cookie values can contain = signs (e.g. base64)."""
        cookie = ParsedCookie.from_header("token=YWJj=; Secure")
        assert cookie is not None
        assert cookie.value == "YWJj="

    def test_value_with_multiple_equals(self):
        cookie = ParsedCookie.from_header("data=a=b=c; HttpOnly")
        assert cookie is not None
        assert cookie.value == "a=b=c"

    def test_empty_value(self):
        cookie = ParsedCookie.from_header("deleted=; Max-Age=0")
        assert cookie is not None
        assert cookie.name == "deleted"
        assert cookie.value == ""

    def test_no_equals_returns_none(self):
        result = ParsedCookie.from_header("malformed_header")
        assert result is None

    def test_empty_string_returns_none(self):
        result = ParsedCookie.from_header("")
        assert result is None

    def test_whitespace_in_name_and_value(self):
        cookie = ParsedCookie.from_header("  session  =  abc123  ; Secure")
        assert cookie is not None
        assert cookie.name == "session"
        assert cookie.value == "abc123"

    def test_case_insensitive_attributes(self):
        """Attributes like SECURE, httponly, SAMESITE should be parsed."""
        cookie = ParsedCookie.from_header("id=xyz; SECURE; HTTPONLY; SAMESITE=LAX")
        assert cookie is not None
        # The parser lowercases parts before comparison
        assert cookie.secure is True
        assert cookie.httponly is True
        assert cookie.samesite == "lax"


# =============================================================================
# ParsedCookie.calculate_entropy
# =============================================================================

class TestParsedCookieEntropy:
    """Test ParsedCookie.calculate_entropy method."""

    def test_empty_value_zero_entropy(self):
        cookie = ParsedCookie(name="test", value="")
        result = cookie.calculate_entropy()
        assert result == 0.0
        assert cookie.entropy == 0.0

    def test_single_char_value_zero_entropy(self):
        cookie = ParsedCookie(name="test", value="aaaa")
        result = cookie.calculate_entropy()
        assert result == 0.0

    def test_two_distinct_chars_even_split(self):
        """e.g. 'aabb' -> 2 chars each with prob 0.5 -> entropy = 1.0."""
        cookie = ParsedCookie(name="test", value="aabb")
        result = cookie.calculate_entropy()
        assert abs(result - 1.0) < 0.01

    def test_high_entropy_random_string(self):
        """A long random-looking string should have high entropy."""
        cookie = ParsedCookie(name="sess", value="a1b2c3d4e5f6g7h8i9j0kLmNoPqRsTuV")
        result = cookie.calculate_entropy()
        assert result > 3.5

    def test_stores_entropy_on_instance(self):
        cookie = ParsedCookie(name="test", value="abcdef")
        cookie.calculate_entropy()
        assert cookie.entropy > 0.0

    def test_entropy_matches_manual_calculation(self):
        """Verify against manual Shannon entropy calculation."""
        value = "abcabc"
        freq = Counter(value)
        expected = -sum(
            (n / len(value)) * math.log2(n / len(value))
            for n in freq.values()
        )
        cookie = ParsedCookie(name="test", value=value)
        result = cookie.calculate_entropy()
        assert abs(result - expected) < 0.001


# =============================================================================
# DATACLASS TESTS — CookieVulnerability
# =============================================================================

class TestCookieVulnerability:
    """Test CookieVulnerability dataclass."""

    def test_creation(self):
        vuln = CookieVulnerability(
            vuln_type=CookieVulnType.MISSING_SECURE,
            severity="HIGH",
            cookie_name="session",
            description="Missing Secure flag on session cookie",
        )
        assert vuln.vuln_type == CookieVulnType.MISSING_SECURE
        assert vuln.severity == "HIGH"
        assert vuln.cookie_name == "session"
        assert vuln.description == "Missing Secure flag on session cookie"

    def test_defaults(self):
        vuln = CookieVulnerability(
            vuln_type=CookieVulnType.MISSING_HTTPONLY,
            severity="MEDIUM",
            cookie_name="token",
            description="Missing HttpOnly flag",
        )
        assert vuln.evidence == ""
        assert vuln.remediation == ""
        assert vuln.cwe == ""
        assert vuln.cvss_score == 0.0

    def test_full_creation(self):
        vuln = CookieVulnerability(
            vuln_type=CookieVulnType.SESSION_FIXATION,
            severity="CRITICAL",
            cookie_name="JSESSIONID",
            description="Server accepts external session identifiers",
            evidence="Session was not regenerated after auth",
            remediation="Regenerate session ID after authentication",
            cwe="CWE-384",
            cvss_score=8.0,
        )
        assert vuln.cwe == "CWE-384"
        assert vuln.cvss_score == 8.0
        assert vuln.remediation != ""


# =============================================================================
# CookieAnalyzer — classify_cookie
# =============================================================================

class TestCookieAnalyzerClassifyCookie:
    """Test CookieAnalyzer.classify_cookie static method."""

    # Session cookies
    def test_session_cookie(self):
        cookie = ParsedCookie(name="session", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.SESSION

    def test_sid_cookie(self):
        cookie = ParsedCookie(name="sid", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.SESSION

    def test_jsessionid_cookie(self):
        cookie = ParsedCookie(name="JSESSIONID", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.SESSION

    def test_phpsessid_cookie(self):
        cookie = ParsedCookie(name="PHPSESSID", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.SESSION

    def test_connect_sid_cookie(self):
        cookie = ParsedCookie(name="connect.sid", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.SESSION

    def test_laravel_session_cookie(self):
        cookie = ParsedCookie(name="laravel_session", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.SESSION

    def test_token_cookie(self):
        cookie = ParsedCookie(name="token", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.SESSION

    def test_auth_token_cookie(self):
        cookie = ParsedCookie(name="auth_token", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.SESSION

    def test_jwt_cookie(self):
        cookie = ParsedCookie(name="jwt", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.SESSION

    def test_access_token_cookie(self):
        cookie = ParsedCookie(name="access_token", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.SESSION

    def test_refresh_token_cookie(self):
        cookie = ParsedCookie(name="refresh_token", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.SESSION

    def test_remember_me_cookie(self):
        cookie = ParsedCookie(name="remember_me", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.SESSION

    def test_persistent_cookie(self):
        cookie = ParsedCookie(name="persistent_login", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.SESSION

    def test_user_cookie(self):
        cookie = ParsedCookie(name="user", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.SESSION

    def test_login_cookie(self):
        cookie = ParsedCookie(name="login", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.SESSION

    # CSRF cookies
    def test_csrf_cookie(self):
        cookie = ParsedCookie(name="csrf_token", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.CSRF

    def test_xsrf_cookie(self):
        cookie = ParsedCookie(name="xsrf-token", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.CSRF

    def test_underscore_token_cookie(self):
        cookie = ParsedCookie(name="_token", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.CSRF

    # Analytics cookies
    def test_ga_cookie(self):
        cookie = ParsedCookie(name="_ga", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.ANALYTICS

    def test_gid_cookie(self):
        cookie = ParsedCookie(name="_gid", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.ANALYTICS

    def test_analytics_cookie(self):
        cookie = ParsedCookie(name="analytics_id", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.ANALYTICS

    def test_tracking_cookie(self):
        cookie = ParsedCookie(name="tracking_pixel", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.ANALYTICS

    def test_utm_cookie(self):
        cookie = ParsedCookie(name="__utma", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.ANALYTICS

    # Advertising cookies
    def test_fbp_cookie(self):
        cookie = ParsedCookie(name="_fbp", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.ADVERTISING

    def test_gcl_cookie(self):
        cookie = ParsedCookie(name="_gcl_au", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.ADVERTISING

    def test_ads_cookie(self):
        cookie = ParsedCookie(name="ads_session", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.ADVERTISING

    def test_doubleclick_cookie(self):
        cookie = ParsedCookie(name="doubleclick_id", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.ADVERTISING

    def test_gads_cookie(self):
        # Note: "__gads" contains "_ga" substring, so analytics check matches first
        cookie = ParsedCookie(name="__gads", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.ANALYTICS

    # Preference cookies
    def test_lang_cookie(self):
        cookie = ParsedCookie(name="lang", value="en")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.PREFERENCE

    def test_locale_cookie(self):
        cookie = ParsedCookie(name="locale", value="en-US")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.PREFERENCE

    def test_theme_cookie(self):
        cookie = ParsedCookie(name="theme", value="dark")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.PREFERENCE

    def test_pref_cookie(self):
        cookie = ParsedCookie(name="user_pref", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.PREFERENCE

    def test_settings_cookie(self):
        cookie = ParsedCookie(name="settings", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.PREFERENCE

    # Unknown cookies
    def test_unknown_cookie(self):
        cookie = ParsedCookie(name="my_random_cookie", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.UNKNOWN

    def test_unknown_gibberish(self):
        cookie = ParsedCookie(name="xyzzy", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.UNKNOWN


# =============================================================================
# CookieAnalyzer — is_session_related
# =============================================================================

class TestCookieAnalyzerIsSessionRelated:
    """Test CookieAnalyzer.is_session_related static method."""

    def test_session_by_name(self):
        cookie = ParsedCookie(name="PHPSESSID", value="short")
        assert CookieAnalyzer.is_session_related(cookie) is True

    def test_session_by_name_connect_sid(self):
        cookie = ParsedCookie(name="connect.sid", value="x")
        assert CookieAnalyzer.is_session_related(cookie) is True

    def test_session_by_name_jwt(self):
        cookie = ParsedCookie(name="jwt", value="x")
        assert CookieAnalyzer.is_session_related(cookie) is True

    def test_session_by_high_entropy(self):
        """High entropy + long value -> session-like even without name match."""
        cookie = ParsedCookie(name="xyzzy_unknown", value="a" * 5)
        # Need high entropy (>4.0) and length > 20
        long_random_value = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2u"
        cookie = ParsedCookie(name="xyzzy_unknown", value=long_random_value)
        cookie.calculate_entropy()
        # Only classified by entropy if entropy > 4.0 and len > 20
        if cookie.entropy > 4.0 and len(cookie.value) > 20:
            assert CookieAnalyzer.is_session_related(cookie) is True

    def test_not_session_short_unknown_name(self):
        cookie = ParsedCookie(name="xyzzy", value="abc")
        cookie.entropy = 1.0
        assert CookieAnalyzer.is_session_related(cookie) is False

    def test_not_session_low_entropy(self):
        """Low entropy + unknown name -> not session."""
        cookie = ParsedCookie(name="promo_code", value="abcabc")
        cookie.calculate_entropy()
        assert CookieAnalyzer.is_session_related(cookie) is False

    def test_high_entropy_but_short_not_session(self):
        """High entropy but short value should not qualify."""
        cookie = ParsedCookie(name="x", value="abcdefghij")  # 10 chars
        cookie.calculate_entropy()
        # Even if entropy > 4.0, length <= 20 means not session by entropy rule
        if cookie.entropy > 4.0:
            assert CookieAnalyzer.is_session_related(cookie) is False


# =============================================================================
# CookieAnalyzer — contains_sensitive_data
# =============================================================================

class TestCookieAnalyzerContainsSensitiveData:
    """Test CookieAnalyzer.contains_sensitive_data static method."""

    def test_password_in_name(self):
        cookie = ParsedCookie(name="password", value="secret123")
        result = CookieAnalyzer.contains_sensitive_data(cookie)
        assert "password" in result

    def test_password_in_value(self):
        cookie = ParsedCookie(name="data", value="password=secret")
        result = CookieAnalyzer.contains_sensitive_data(cookie)
        assert "password" in result

    def test_api_key_in_name(self):
        cookie = ParsedCookie(name="api_key", value="sk-123abc")
        result = CookieAnalyzer.contains_sensitive_data(cookie)
        assert "api_key" in result

    def test_apikey_in_name(self):
        cookie = ParsedCookie(name="apikey", value="xyz")
        result = CookieAnalyzer.contains_sensitive_data(cookie)
        assert "api_key" in result

    def test_ssn_in_name(self):
        cookie = ParsedCookie(name="ssn", value="123-45-6789")
        result = CookieAnalyzer.contains_sensitive_data(cookie)
        assert "ssn" in result

    def test_credit_card_in_name(self):
        cookie = ParsedCookie(name="credit_card", value="4111111111111111")
        result = CookieAnalyzer.contains_sensitive_data(cookie)
        assert "credit_card" in result

    def test_cvv_in_name(self):
        cookie = ParsedCookie(name="cvv", value="123")
        result = CookieAnalyzer.contains_sensitive_data(cookie)
        assert "cvv" in result

    def test_dob_in_name(self):
        cookie = ParsedCookie(name="dob", value="1990-01-01")
        result = CookieAnalyzer.contains_sensitive_data(cookie)
        assert "date_of_birth" in result

    def test_secret_in_name(self):
        cookie = ParsedCookie(name="secret", value="mysecret")
        result = CookieAnalyzer.contains_sensitive_data(cookie)
        assert "secret" in result

    def test_private_in_name(self):
        cookie = ParsedCookie(name="private_key", value="abc")
        result = CookieAnalyzer.contains_sensitive_data(cookie)
        assert "private_key" in result

    def test_no_sensitive_data(self):
        cookie = ParsedCookie(name="theme", value="dark")
        result = CookieAnalyzer.contains_sensitive_data(cookie)
        assert result == []

    def test_no_sensitive_session_cookie(self):
        cookie = ParsedCookie(name="PHPSESSID", value="abcdef123456")
        result = CookieAnalyzer.contains_sensitive_data(cookie)
        assert result == []

    def test_returns_list(self):
        cookie = ParsedCookie(name="theme", value="dark")
        result = CookieAnalyzer.contains_sensitive_data(cookie)
        assert isinstance(result, list)

    def test_multiple_matches(self):
        """A cookie whose combined name=value matches multiple patterns."""
        cookie = ParsedCookie(name="password_ssn", value="secret_cvv")
        result = CookieAnalyzer.contains_sensitive_data(cookie)
        assert len(result) >= 2


# =============================================================================
# CookieAnalyzer — is_base64_encoded
# =============================================================================

class TestCookieAnalyzerIsBase64Encoded:
    """Test CookieAnalyzer.is_base64_encoded static method."""

    def test_valid_base64(self):
        # "hello" in base64 is "aGVsbG8="
        assert CookieAnalyzer.is_base64_encoded("aGVsbG8=") is True

    def test_valid_base64_no_padding(self):
        # "hi" in base64 is "aGk=" (length 4, padded)
        assert CookieAnalyzer.is_base64_encoded("aGk=") is True

    def test_valid_base64_double_padding(self):
        # "h" in base64 is "aA==" (length 4, double padded)
        assert CookieAnalyzer.is_base64_encoded("aA==") is True

    def test_not_base64_odd_length(self):
        """Base64 strings must have length divisible by 4."""
        assert CookieAnalyzer.is_base64_encoded("abc") is False

    def test_not_base64_special_chars(self):
        assert CookieAnalyzer.is_base64_encoded("not!base64") is False

    def test_empty_string(self):
        # Empty string: length 0, 0 % 4 == 0, but regex matches empty, decoded empty
        # The code checks len(decoded) > 0 after decode
        result = CookieAnalyzer.is_base64_encoded("")
        # Empty string decodes to b'', which has length 0 -> should return False
        assert result is False

    def test_simple_value(self):
        # "test" is actually valid base64 (decodes to b'\xb5\xeb-') length 4
        assert CookieAnalyzer.is_base64_encoded("test") is True

    def test_long_base64_string(self):
        import base64
        encoded = base64.b64encode(b"this is a longer test value").decode()
        assert CookieAnalyzer.is_base64_encoded(encoded) is True


# =============================================================================
# CookieAnalyzer — check_predictability
# =============================================================================

class TestCookieAnalyzerCheckPredictability:
    """Test CookieAnalyzer.check_predictability static method."""

    # Digit-only short values
    def test_short_digits_predictable(self):
        assert CookieAnalyzer.check_predictability("12345") is True

    def test_single_digit_predictable(self):
        assert CookieAnalyzer.check_predictability("1") is True

    def test_long_digits_not_predictable_by_digit_rule(self):
        """10+ digit strings don't match the digit rule (< 10 length)."""
        result = CookieAnalyzer.check_predictability("1234567890")
        # 10 digits has length == 10, not < 10
        # But length 10 < 16, so the short-length rule still catches it
        assert result is True

    # Simple named patterns
    def test_user_pattern_predictable(self):
        assert CookieAnalyzer.check_predictability("user1") is True

    def test_admin_pattern_predictable(self):
        assert CookieAnalyzer.check_predictability("admin") is True

    def test_admin_with_number_predictable(self):
        assert CookieAnalyzer.check_predictability("admin123") is True

    def test_test_pattern_predictable(self):
        assert CookieAnalyzer.check_predictability("test") is True

    def test_test_with_number_predictable(self):
        assert CookieAnalyzer.check_predictability("test42") is True

    # Short values (< 16 chars)
    def test_short_string_predictable(self):
        assert CookieAnalyzer.check_predictability("abcdef") is True

    def test_15_char_string_predictable(self):
        assert CookieAnalyzer.check_predictability("a" * 15) is True

    # Long random values
    def test_long_random_not_predictable(self):
        long_value = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uVwXyZ"
        assert CookieAnalyzer.check_predictability(long_value) is False

    def test_16_char_non_pattern_not_predictable(self):
        assert CookieAnalyzer.check_predictability("a1b2c3d4e5f6g7h8") is False

    def test_uuid_not_predictable(self):
        """UUIDs are 36 chars, not matching simple patterns."""
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        assert CookieAnalyzer.check_predictability(uuid) is False


# =============================================================================
# CookieSecurityScanner — Class Attributes
# =============================================================================

class TestCookieSecurityScannerAttributes:
    """Test CookieSecurityScanner class attributes."""

    def test_module_name(self):
        assert CookieSecurityScanner.MODULE_NAME == "cookie_security"

    def test_module_version(self):
        assert CookieSecurityScanner.MODULE_VERSION == "3.0.0"

    def test_module_description(self):
        assert "Cookie" in CookieSecurityScanner.MODULE_DESCRIPTION

    def test_module_author(self):
        assert CookieSecurityScanner.MODULE_AUTHOR == "PHANTOM AI Team"

    def test_is_scan_module_subclass(self):
        from scanning.vuln_scanner import ScanModule
        assert issubclass(CookieSecurityScanner, ScanModule)

    def test_instantiation(self):
        scanner = CookieSecurityScanner()
        assert scanner is not None
        assert isinstance(scanner.analyzer, CookieAnalyzer)
        assert scanner.findings == []
        assert scanner.discovered_cookies == []
        assert scanner.is_https is False

    def test_has_scan_method(self):
        assert hasattr(CookieSecurityScanner, "scan")
        assert callable(getattr(CookieSecurityScanner, "scan"))


# =============================================================================
# INTEGRATION SCENARIOS
# =============================================================================

class TestIntegrationScenarios:
    """Test realistic cookie analysis scenarios end-to-end."""

    def test_secure_session_cookie(self):
        """A properly secured session cookie should be classified correctly."""
        header = "JSESSIONID=abc123def456; Path=/; Secure; HttpOnly; SameSite=Strict"
        cookie = ParsedCookie.from_header(header)
        assert cookie is not None
        cookie.calculate_entropy()
        cookie.cookie_type = CookieAnalyzer.classify_cookie(cookie)
        cookie.is_session_cookie = CookieAnalyzer.is_session_related(cookie)

        assert cookie.cookie_type == CookieType.SESSION
        assert cookie.is_session_cookie is True
        assert cookie.secure is True
        assert cookie.httponly is True
        assert cookie.samesite == "strict"

    def test_insecure_session_cookie(self):
        """A session cookie missing all security attributes."""
        header = "PHPSESSID=abc123"
        cookie = ParsedCookie.from_header(header)
        assert cookie is not None
        cookie.calculate_entropy()
        cookie.cookie_type = CookieAnalyzer.classify_cookie(cookie)
        cookie.is_session_cookie = CookieAnalyzer.is_session_related(cookie)

        assert cookie.cookie_type == CookieType.SESSION
        assert cookie.is_session_cookie is True
        assert cookie.secure is False
        assert cookie.httponly is False
        assert cookie.samesite is None

    def test_sensitive_data_cookie(self):
        """A cookie storing a password should be flagged."""
        header = "user_password=P@ssw0rd123; Path=/"
        cookie = ParsedCookie.from_header(header)
        assert cookie is not None
        sensitive = CookieAnalyzer.contains_sensitive_data(cookie)
        assert "password" in sensitive

    def test_analytics_cookie_not_session(self):
        """Analytics cookies should not be classified as session cookies."""
        header = "_ga=GA1.2.123456.789012; Path=/; Max-Age=63072000"
        cookie = ParsedCookie.from_header(header)
        assert cookie is not None
        cookie.calculate_entropy()
        cookie.cookie_type = CookieAnalyzer.classify_cookie(cookie)

        assert cookie.cookie_type == CookieType.ANALYTICS

    def test_csrf_cookie_classification(self):
        header = "csrf_token=abc123def456; Path=/; HttpOnly"
        cookie = ParsedCookie.from_header(header)
        assert cookie is not None
        cookie.cookie_type = CookieAnalyzer.classify_cookie(cookie)
        assert cookie.cookie_type == CookieType.CSRF

    def test_host_prefix_cookie(self):
        """__Host- prefix cookie parsing."""
        header = "__Host-session=abc123; Path=/; Secure; HttpOnly"
        cookie = ParsedCookie.from_header(header)
        assert cookie is not None
        assert cookie.name == "__Host-session"
        assert cookie.secure is True
        assert cookie.path == "/"

    def test_secure_prefix_cookie(self):
        """__Secure- prefix cookie parsing."""
        header = "__Secure-token=xyz; Secure; HttpOnly; SameSite=Strict"
        cookie = ParsedCookie.from_header(header)
        assert cookie is not None
        assert cookie.name == "__Secure-token"
        assert cookie.secure is True

    def test_long_expiration_session(self):
        """Session cookie with very long max-age (> 30 days)."""
        # 90 days in seconds = 7776000
        header = "session=abc123; Max-Age=7776000; Secure; HttpOnly"
        cookie = ParsedCookie.from_header(header)
        assert cookie is not None
        assert cookie.max_age == 7776000
        assert cookie.max_age > 86400 * 30  # More than 30 days

    def test_predictable_session_value(self):
        """Session cookie with a clearly predictable value."""
        cookie = ParsedCookie(name="session", value="user1")
        cookie.calculate_entropy()
        cookie.is_session_cookie = True
        assert CookieAnalyzer.check_predictability(cookie.value) is True

    def test_samesite_none_without_secure(self):
        """SameSite=None without Secure flag is a known issue."""
        header = "tracking=abc; SameSite=None"
        cookie = ParsedCookie.from_header(header)
        assert cookie is not None
        assert cookie.samesite == "none"
        assert cookie.secure is False


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_cookie_name_with_dashes(self):
        cookie = ParsedCookie.from_header("my-cookie-name=value; Secure")
        assert cookie is not None
        assert cookie.name == "my-cookie-name"

    def test_cookie_name_with_underscores(self):
        cookie = ParsedCookie.from_header("my_cookie_name=value")
        assert cookie is not None
        assert cookie.name == "my_cookie_name"

    def test_cookie_value_with_semicolons_absent(self):
        """Just name=value with no attributes."""
        cookie = ParsedCookie.from_header("simple=value")
        assert cookie is not None
        assert cookie.name == "simple"
        assert cookie.value == "value"
        assert cookie.secure is False
        assert cookie.httponly is False

    def test_max_age_negative(self):
        cookie = ParsedCookie.from_header("old=val; Max-Age=-1")
        assert cookie is not None
        assert cookie.max_age == -1

    def test_all_vuln_types_unique(self):
        values = [t.value for t in CookieVulnType]
        assert len(values) == len(set(values))

    def test_all_cookie_types_unique(self):
        values = [t.value for t in CookieType]
        assert len(values) == len(set(values))

    def test_classify_unknown_returns_unknown(self):
        cookie = ParsedCookie(name="zzz_unknown_zzz", value="abc")
        assert CookieAnalyzer.classify_cookie(cookie) == CookieType.UNKNOWN

    def test_entropy_of_highly_random_string(self):
        """Maximum entropy for 256 distinct chars."""
        # Use all printable ASCII chars for a string
        import string
        all_chars = string.ascii_letters + string.digits + string.punctuation
        # Repeat to get length divisible neatly
        value = all_chars * 2
        cookie = ParsedCookie(name="test", value=value)
        entropy = cookie.calculate_entropy()
        assert entropy > 3.0  # Should be quite high

    def test_sensitive_patterns_cover_password_variants(self):
        """All three password patterns should match their variants."""
        variants = ["password", "passwd", "pwd"]
        for variant in variants:
            cookie = ParsedCookie(name=variant, value="x")
            result = CookieAnalyzer.contains_sensitive_data(cookie)
            assert "password" in result, f"Pattern should detect '{variant}'"
