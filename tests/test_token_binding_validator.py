"""
Tests for scanning/modules/token_binding_validator.py

Covers:
- Module-level lists: TOKEN_LOCATIONS, WHOAMI_ENDPOINTS, REFRESH_ENDPOINTS
- TokenInfo dataclass (defaults, full creation)
- TokenBindingValidator scanner identity (name, ScanModule subclass)
- TokenBindingValidator class-level attributes (description, version, author, tags, min_safety_level)
- _resolve_base_url logic
- _analyze_token logic (JWT, session, api_key, short/empty rejection)
- _base64_decode helper
- Regex patterns used in _analyze_token (session and api_key patterns)

Run with: pytest tests/test_token_binding_validator.py -v
"""

import re
import pytest

from scanning.modules.token_binding_validator import (
    TOKEN_LOCATIONS,
    WHOAMI_ENDPOINTS,
    REFRESH_ENDPOINTS,
    TokenInfo,
    TokenBindingValidator,
)
from scanning.vuln_scanner import ScanModule


# =============================================================================
# MODULE-LEVEL LISTS
# =============================================================================


class TestTokenLocations:
    """Test TOKEN_LOCATIONS list."""

    def test_type_is_list(self):
        assert isinstance(TOKEN_LOCATIONS, list)

    def test_count(self):
        assert len(TOKEN_LOCATIONS) == 5

    def test_has_authorization(self):
        assert "Authorization" in TOKEN_LOCATIONS

    def test_has_x_access_token(self):
        assert "X-Access-Token" in TOKEN_LOCATIONS

    def test_has_x_auth_token(self):
        assert "X-Auth-Token" in TOKEN_LOCATIONS

    def test_has_x_api_key(self):
        assert "X-API-Key" in TOKEN_LOCATIONS

    def test_has_cookie(self):
        assert "Cookie" in TOKEN_LOCATIONS

    def test_all_entries_are_strings(self):
        for loc in TOKEN_LOCATIONS:
            assert isinstance(loc, str)

    def test_no_duplicates(self):
        assert len(TOKEN_LOCATIONS) == len(set(TOKEN_LOCATIONS))


class TestWhoamiEndpoints:
    """Test WHOAMI_ENDPOINTS list."""

    def test_type_is_list(self):
        assert isinstance(WHOAMI_ENDPOINTS, list)

    def test_count(self):
        assert len(WHOAMI_ENDPOINTS) == 15

    def test_all_start_with_slash(self):
        for ep in WHOAMI_ENDPOINTS:
            assert ep.startswith("/"), f"Endpoint does not start with /: {ep}"

    def test_all_entries_are_strings(self):
        for ep in WHOAMI_ENDPOINTS:
            assert isinstance(ep, str)

    def test_no_duplicates(self):
        assert len(WHOAMI_ENDPOINTS) == len(set(WHOAMI_ENDPOINTS))

    def test_has_api_user(self):
        assert "/api/user" in WHOAMI_ENDPOINTS

    def test_has_api_me(self):
        assert "/api/me" in WHOAMI_ENDPOINTS

    def test_has_api_profile(self):
        assert "/api/profile" in WHOAMI_ENDPOINTS

    def test_has_api_whoami(self):
        assert "/api/whoami" in WHOAMI_ENDPOINTS

    def test_has_me(self):
        assert "/me" in WHOAMI_ENDPOINTS

    def test_has_whoami(self):
        assert "/whoami" in WHOAMI_ENDPOINTS

    def test_has_profile(self):
        assert "/profile" in WHOAMI_ENDPOINTS

    def test_has_account(self):
        assert "/account" in WHOAMI_ENDPOINTS

    def test_has_api_account(self):
        assert "/api/account" in WHOAMI_ENDPOINTS

    def test_has_api_users_current(self):
        assert "/api/users/current" in WHOAMI_ENDPOINTS


class TestRefreshEndpoints:
    """Test REFRESH_ENDPOINTS list."""

    def test_type_is_list(self):
        assert isinstance(REFRESH_ENDPOINTS, list)

    def test_count(self):
        assert len(REFRESH_ENDPOINTS) == 8

    def test_all_start_with_slash(self):
        for ep in REFRESH_ENDPOINTS:
            assert ep.startswith("/"), f"Endpoint does not start with /: {ep}"

    def test_all_entries_are_strings(self):
        for ep in REFRESH_ENDPOINTS:
            assert isinstance(ep, str)

    def test_no_duplicates(self):
        assert len(REFRESH_ENDPOINTS) == len(set(REFRESH_ENDPOINTS))

    def test_has_api_auth_refresh(self):
        assert "/api/auth/refresh" in REFRESH_ENDPOINTS

    def test_has_auth_refresh(self):
        assert "/auth/refresh" in REFRESH_ENDPOINTS

    def test_has_oauth_token(self):
        assert "/oauth/token" in REFRESH_ENDPOINTS

    def test_has_token_refresh(self):
        assert "/token/refresh" in REFRESH_ENDPOINTS

    def test_has_api_token_refresh(self):
        assert "/api/token/refresh" in REFRESH_ENDPOINTS


# =============================================================================
# DATACLASS TESTS
# =============================================================================


class TestTokenInfo:
    """Test TokenInfo dataclass."""

    def test_creation_with_defaults(self):
        t = TokenInfo(value="abc123", location="Authorization", token_type="jwt")
        assert t.value == "abc123"
        assert t.location == "Authorization"
        assert t.token_type == "jwt"
        assert t.claims == {}
        assert t.expiry == 0

    def test_creation_full(self):
        claims = {"sub": "user1", "exp": 9999999999}
        t = TokenInfo(
            value="eyJ.payload.sig",
            location="Cookie:session",
            token_type="jwt",
            claims=claims,
            expiry=9999999999,
        )
        assert t.value == "eyJ.payload.sig"
        assert t.location == "Cookie:session"
        assert t.token_type == "jwt"
        assert t.claims == claims
        assert t.expiry == 9999999999

    def test_default_claims_is_empty_dict(self):
        t = TokenInfo(value="x", location="y", token_type="z")
        assert t.claims == {}
        assert isinstance(t.claims, dict)

    def test_default_expiry_is_zero(self):
        t = TokenInfo(value="x", location="y", token_type="z")
        assert t.expiry == 0

    def test_claims_default_not_shared(self):
        """Ensure default_factory gives independent dicts."""
        t1 = TokenInfo(value="a", location="b", token_type="c")
        t2 = TokenInfo(value="d", location="e", token_type="f")
        t1.claims["key"] = "val"
        assert "key" not in t2.claims

    def test_token_type_session(self):
        t = TokenInfo(value="sessionid123", location="Cookie:sid", token_type="session")
        assert t.token_type == "session"

    def test_token_type_api_key(self):
        t = TokenInfo(value="sk-live-abc123", location="X-API-Key", token_type="api_key")
        assert t.token_type == "api_key"


# =============================================================================
# SCANNER IDENTITY
# =============================================================================


class TestTokenBindingValidatorIdentity:
    """Test TokenBindingValidator class identity and attributes."""

    def test_is_scan_module_subclass(self):
        assert issubclass(TokenBindingValidator, ScanModule)

    def test_name_attribute(self):
        assert TokenBindingValidator.name == "token_binding"

    def test_description_attribute(self):
        assert isinstance(TokenBindingValidator.description, str)
        assert len(TokenBindingValidator.description) > 0

    def test_version_attribute(self):
        assert TokenBindingValidator.version == "1.0.0"

    def test_author_attribute(self):
        assert TokenBindingValidator.author == "PHANTOM AI"

    def test_tags_attribute(self):
        assert isinstance(TokenBindingValidator.tags, list)
        assert len(TokenBindingValidator.tags) == 5

    def test_tags_values(self):
        tags = TokenBindingValidator.tags
        assert "token" in tags
        assert "session" in tags
        assert "binding" in tags
        assert "oauth" in tags
        assert "jwt" in tags

    def test_min_safety_level(self):
        assert TokenBindingValidator.min_safety_level == "standard"

    def test_instantiation(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = TokenBindingValidator(settings)
        assert scanner is not None

    def test_instance_has_name(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = TokenBindingValidator(settings)
        assert scanner.name == "token_binding"

    def test_initial_state(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = TokenBindingValidator(settings)
        assert scanner._base_url == ""
        assert scanner._auth_headers == {}
        assert scanner._discovered_tokens == []
        assert scanner._whoami_endpoint == ""


# =============================================================================
# _resolve_base_url TESTS
# =============================================================================


class TestResolveBaseUrl:
    """Test TokenBindingValidator._resolve_base_url method."""

    def setup_method(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        self.scanner = TokenBindingValidator(settings)

    def test_http_url_passthrough(self):
        result = self.scanner._resolve_base_url("http://example.com", None)
        assert result == "http://example.com"

    def test_https_url_passthrough(self):
        result = self.scanner._resolve_base_url("https://example.com", None)
        assert result == "https://example.com"

    def test_strips_trailing_slash(self):
        result = self.scanner._resolve_base_url("http://example.com/", None)
        assert result == "http://example.com"

    def test_port_443_uses_https(self):
        result = self.scanner._resolve_base_url("example.com", 443)
        assert result == "https://example.com"

    def test_port_8443_uses_https(self):
        result = self.scanner._resolve_base_url("example.com", 8443)
        assert result == "https://example.com:8443"

    def test_port_80_uses_http_no_port(self):
        result = self.scanner._resolve_base_url("example.com", 80)
        assert result == "http://example.com"

    def test_port_none_uses_http_no_port(self):
        result = self.scanner._resolve_base_url("example.com", None)
        assert result == "http://example.com"

    def test_custom_port_included(self):
        result = self.scanner._resolve_base_url("example.com", 8080)
        assert result == "http://example.com:8080"

    def test_custom_port_3000(self):
        result = self.scanner._resolve_base_url("example.com", 3000)
        assert result == "http://example.com:3000"


# =============================================================================
# _analyze_token TESTS
# =============================================================================


class TestAnalyzeToken:
    """Test TokenBindingValidator._analyze_token method."""

    def setup_method(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        self.scanner = TokenBindingValidator(settings)

    def test_empty_value_returns_none(self):
        assert self.scanner._analyze_token("", "Authorization") is None

    def test_none_value_returns_none(self):
        assert self.scanner._analyze_token(None, "Authorization") is None

    def test_short_value_returns_none(self):
        """Values shorter than 10 chars are rejected."""
        assert self.scanner._analyze_token("abc", "Authorization") is None
        assert self.scanner._analyze_token("123456789", "X-Token") is None

    def test_jwt_token_detected(self):
        """A valid JWT (3 base64 parts) should be detected."""
        # Minimal JWT: header.payload.signature
        # header: {"alg":"HS256","typ":"JWT"}
        # payload: {"sub":"user1","exp":9999999999}
        import base64, json
        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "user1", "exp": 9999999999}).encode()).rstrip(b"=").decode()
        sig = base64.urlsafe_b64encode(b"fakesignature").rstrip(b"=").decode()
        jwt_token = f"{header}.{payload}.{sig}"

        result = self.scanner._analyze_token(jwt_token, "Authorization")
        assert result is not None
        assert result.token_type == "jwt"
        assert result.claims["sub"] == "user1"
        assert result.expiry == 9999999999
        assert result.location == "Authorization"

    def test_jwt_with_bearer_prefix(self):
        """Bearer prefix should be stripped before analysis."""
        import base64, json
        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "test"}).encode()).rstrip(b"=").decode()
        sig = base64.urlsafe_b64encode(b"sig").rstrip(b"=").decode()
        jwt_token = f"Bearer {header}.{payload}.{sig}"

        result = self.scanner._analyze_token(jwt_token, "Authorization")
        assert result is not None
        assert result.token_type == "jwt"
        assert result.claims["sub"] == "test"

    def test_session_token_detected(self):
        """A long alphanumeric string should be detected as session."""
        session_id = "abcdefghijklmnopqrstuvwxyz1234567890"
        result = self.scanner._analyze_token(session_id, "Cookie:PHPSESSID")
        assert result is not None
        assert result.token_type == "session"
        assert result.location == "Cookie:PHPSESSID"

    def test_api_key_detected(self):
        """An alphanumeric+underscore+dash string should be detected as api_key."""
        api_key = "sk_live_abc123def456ghi789"
        result = self.scanner._analyze_token(api_key, "X-API-Key")
        assert result is not None
        assert result.token_type == "api_key"
        assert result.location == "X-API-Key"

    def test_session_regex_pattern_compiles(self):
        """The session regex pattern used in _analyze_token should compile."""
        pattern = re.compile(r"^[A-Za-z0-9+/=-]+$")
        assert pattern is not None

    def test_session_regex_matches_expected(self):
        pattern = re.compile(r"^[A-Za-z0-9+/=-]+$")
        assert pattern.match("abcdef1234567890ABCDEF")
        assert pattern.match("abc+def/ghi=jkl-mno")
        assert not pattern.match("abc def")
        assert not pattern.match("abc!def")

    def test_api_key_regex_pattern_compiles(self):
        """The api_key regex pattern used in _analyze_token should compile."""
        pattern = re.compile(r"^[A-Za-z0-9_-]+$")
        assert pattern is not None

    def test_api_key_regex_matches_expected(self):
        pattern = re.compile(r"^[A-Za-z0-9_-]+$")
        assert pattern.match("sk_live_abc123")
        assert pattern.match("api-key-test-123")
        assert not pattern.match("has spaces")
        assert not pattern.match("has+plus")

    def test_invalid_jwt_falls_through_to_session(self):
        """A string with two dots but invalid base64 should not be JWT."""
        # Three parts but not valid JSON when decoded
        bad_jwt = "notbase64xx.notbase64yy.notbase64zz"
        result = self.scanner._analyze_token(bad_jwt, "Authorization")
        # It has 2 dots and >= 20 chars, so if JWT decode fails it may fall through
        # to session or api_key detection depending on chars
        if result is not None:
            assert result.token_type in ("session", "api_key")


# =============================================================================
# _base64_decode TESTS
# =============================================================================


class TestBase64Decode:
    """Test TokenBindingValidator._base64_decode method."""

    def setup_method(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        self.scanner = TokenBindingValidator(settings)

    def test_standard_base64(self):
        import base64
        encoded = base64.b64encode(b"hello world").decode()
        result = self.scanner._base64_decode(encoded)
        assert result == "hello world"

    def test_url_safe_base64(self):
        """URL-safe chars (-_) should be translated to (+/)."""
        import base64
        data = b"\xfb\xff\xfe"
        encoded = base64.urlsafe_b64encode(data).decode().rstrip("=")
        result = self.scanner._base64_decode(encoded)
        # Should not raise, should return something
        assert isinstance(result, str)

    def test_missing_padding_handled(self):
        import base64
        encoded = base64.b64encode(b"test").decode().rstrip("=")
        result = self.scanner._base64_decode(encoded)
        assert result == "test"

    def test_empty_string(self):
        result = self.scanner._base64_decode("")
        # Empty string with padding becomes "====" which decodes to empty
        assert isinstance(result, str)

    def test_json_payload_decode(self):
        """Typical JWT payload decoding."""
        import base64, json
        payload = json.dumps({"sub": "user1", "exp": 12345})
        encoded = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
        result = self.scanner._base64_decode(encoded)
        parsed = json.loads(result)
        assert parsed["sub"] == "user1"
        assert parsed["exp"] == 12345
