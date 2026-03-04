"""
Tests for scanning/modules/cors_checker.py

Covers:
- SENSITIVE_DATA_PATTERNS constant
- PUBLIC_DATA_PATTERNS constant
- contains_sensitive_data() function
- is_public_endpoint() function
- CORSChecker class attributes
- _generate_bypass_origins() method
"""

import pytest
import re
from scanning.modules.cors_checker import (
    SENSITIVE_DATA_PATTERNS,
    PUBLIC_DATA_PATTERNS,
    contains_sensitive_data,
    is_public_endpoint,
    CORSChecker,
)


# =============================================================================
# SENSITIVE DATA PATTERNS
# =============================================================================

class TestSensitiveDataPatterns:
    def test_not_empty(self):
        assert len(SENSITIVE_DATA_PATTERNS) > 0

    def test_all_compile(self):
        for pattern in SENSITIVE_DATA_PATTERNS:
            re.compile(pattern)

    # PII patterns
    def test_detects_email(self):
        body = '{"email": "user@example.com"}'
        assert any(re.search(p, body, re.I) for p in SENSITIVE_DATA_PATTERNS)

    def test_detects_password(self):
        body = '{"password": "secret123"}'
        assert any(re.search(p, body, re.I) for p in SENSITIVE_DATA_PATTERNS)

    def test_detects_phone(self):
        body = '{"phone": "+1-555-123-4567"}'
        assert any(re.search(p, body, re.I) for p in SENSITIVE_DATA_PATTERNS)

    def test_detects_ssn(self):
        body = '{"ssn": "123-45-6789"}'
        assert any(re.search(p, body, re.I) for p in SENSITIVE_DATA_PATTERNS)

    def test_detects_credit_card(self):
        body = '{"credit_card": "4111-1111-1111-1111"}'
        assert any(re.search(p, body, re.I) for p in SENSITIVE_DATA_PATTERNS)

    # Auth tokens
    def test_detects_access_token(self):
        body = '{"access_token": "abc123"}'
        assert any(re.search(p, body, re.I) for p in SENSITIVE_DATA_PATTERNS)

    def test_detects_access_token_camelcase(self):
        body = '{"accessToken": "abc123"}'
        assert any(re.search(p, body, re.I) for p in SENSITIVE_DATA_PATTERNS)

    def test_detects_refresh_token(self):
        body = '{"refresh_token": "xyz789"}'
        assert any(re.search(p, body, re.I) for p in SENSITIVE_DATA_PATTERNS)

    def test_detects_refresh_token_camelcase(self):
        body = '{"refreshToken": "xyz789"}'
        assert any(re.search(p, body, re.I) for p in SENSITIVE_DATA_PATTERNS)

    def test_detects_api_key(self):
        body = '{"api_key": "sk-test123"}'
        assert any(re.search(p, body, re.I) for p in SENSITIVE_DATA_PATTERNS)

    def test_detects_api_key_camelcase(self):
        body = '{"apiKey": "sk-test123"}'
        assert any(re.search(p, body, re.I) for p in SENSITIVE_DATA_PATTERNS)

    def test_detects_bearer_token(self):
        body = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.xyz"
        assert any(re.search(p, body, re.I) for p in SENSITIVE_DATA_PATTERNS)

    def test_detects_jwt(self):
        body = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig"
        assert any(re.search(p, body, re.I) for p in SENSITIVE_DATA_PATTERNS)

    def test_detects_session_id(self):
        body = '{"session_id": "abc123"}'
        assert any(re.search(p, body, re.I) for p in SENSITIVE_DATA_PATTERNS)

    def test_detects_session_id_camelcase(self):
        body = '{"sessionId": "abc123"}'
        assert any(re.search(p, body, re.I) for p in SENSITIVE_DATA_PATTERNS)

    # Admin data
    def test_detects_admin_true(self):
        body = '{"admin": true}'
        assert any(re.search(p, body, re.I) for p in SENSITIVE_DATA_PATTERNS)

    def test_detects_is_admin_camelcase(self):
        body = '{"isAdmin": true}'
        assert any(re.search(p, body, re.I) for p in SENSITIVE_DATA_PATTERNS)

    def test_detects_role_admin(self):
        body = '{"role": "admin"}'
        assert any(re.search(p, body, re.I) for p in SENSITIVE_DATA_PATTERNS)

    def test_detects_permissions(self):
        body = '{"permissions": ["read", "write"]}'
        assert any(re.search(p, body, re.I) for p in SENSITIVE_DATA_PATTERNS)

    # Financial
    def test_detects_balance(self):
        body = '{"balance": 1234.56}'
        assert any(re.search(p, body, re.I) for p in SENSITIVE_DATA_PATTERNS)

    def test_detects_account_number(self):
        body = '{"account_number": "123456789"}'
        assert any(re.search(p, body, re.I) for p in SENSITIVE_DATA_PATTERNS)

    # User data
    def test_detects_user_id(self):
        body = '{"user_id": 42}'
        assert any(re.search(p, body, re.I) for p in SENSITIVE_DATA_PATTERNS)

    def test_detects_user_id_camelcase(self):
        body = '{"userId": 42}'
        assert any(re.search(p, body, re.I) for p in SENSITIVE_DATA_PATTERNS)

    def test_detects_username(self):
        body = '{"username": "john"}'
        assert any(re.search(p, body, re.I) for p in SENSITIVE_DATA_PATTERNS)

    def test_detects_first_name(self):
        body = '{"first_name": "John"}'
        assert any(re.search(p, body, re.I) for p in SENSITIVE_DATA_PATTERNS)

    def test_detects_first_name_camelcase(self):
        body = '{"firstName": "John"}'
        assert any(re.search(p, body, re.I) for p in SENSITIVE_DATA_PATTERNS)


# =============================================================================
# PUBLIC DATA PATTERNS
# =============================================================================

class TestPublicDataPatterns:
    def test_not_empty(self):
        assert len(PUBLIC_DATA_PATTERNS) > 0

    def test_all_compile(self):
        for pattern in PUBLIC_DATA_PATTERNS:
            re.compile(pattern)

    def test_detects_version(self):
        body = '{"version": "1.2.3"}'
        assert any(re.search(p, body, re.I) for p in PUBLIC_DATA_PATTERNS)

    def test_detects_health_ok(self):
        body = '{"status": "ok"}'
        assert any(re.search(p, body, re.I) for p in PUBLIC_DATA_PATTERNS)

    def test_detects_empty_array(self):
        body = '{"data": []}'
        assert any(re.search(p, body, re.I) for p in PUBLIC_DATA_PATTERNS)

    def test_detects_public_true(self):
        body = '{"public": true}'
        assert any(re.search(p, body, re.I) for p in PUBLIC_DATA_PATTERNS)


# =============================================================================
# contains_sensitive_data()
# =============================================================================

class TestContainsSensitiveData:
    def test_empty_body(self):
        result, patterns = contains_sensitive_data("")
        assert result is False
        assert patterns == []

    def test_none_body(self):
        result, patterns = contains_sensitive_data(None)
        assert result is False

    def test_sensitive_email(self):
        body = '{"email": "user@example.com", "name": "John"}'
        result, patterns = contains_sensitive_data(body)
        assert result is True
        assert len(patterns) > 0

    def test_sensitive_token(self):
        body = '{"access_token": "abc123xyz"}'
        result, patterns = contains_sensitive_data(body)
        assert result is True

    def test_non_sensitive(self):
        body = '{"status": "ok", "version": "1.0"}'
        result, patterns = contains_sensitive_data(body)
        assert result is False

    def test_multiple_sensitive(self):
        body = '{"email": "a@b.com", "password": "secret", "admin": true}'
        result, patterns = contains_sensitive_data(body)
        assert result is True
        assert len(patterns) >= 2


# =============================================================================
# is_public_endpoint()
# =============================================================================

class TestIsPublicEndpoint:
    def test_public_url(self):
        assert is_public_endpoint("data", "/public/api") is True

    def test_static_url(self):
        assert is_public_endpoint("data", "/static/app.js") is True

    def test_health_url(self):
        assert is_public_endpoint("data", "/health") is True

    def test_user_url_not_public(self):
        assert is_public_endpoint("", "/api/user/1") is False

    def test_account_url_not_public(self):
        assert is_public_endpoint("", "/api/accounts/42") is False

    def test_admin_url_not_public(self):
        assert is_public_endpoint("", "/admin/settings") is False

    def test_session_url_not_public(self):
        assert is_public_endpoint("", "/session") is False

    def test_short_response_public(self):
        assert is_public_endpoint("ok", "/api/check") is True

    def test_short_jwt_not_public(self):
        body = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"
        assert is_public_endpoint(body, "/api/data") is False

    def test_short_token_field_not_public(self):
        body = '{"token": "abc"}'
        assert is_public_endpoint(body, "/api/data") is False

    def test_css_file_public(self):
        assert is_public_endpoint("body{}", "/assets/style.css") is True

    def test_favicon_public(self):
        assert is_public_endpoint("", "/favicon.ico") is True

    def test_multiple_public_patterns(self):
        body = '{"status": "ok", "version": "1.0", "data": []}'
        assert is_public_endpoint(body, "/api/some-endpoint") is True


# =============================================================================
# CORSChecker CLASS
# =============================================================================

class TestCORSCheckerClass:
    def test_name(self):
        assert CORSChecker.name == "cors"

    def test_version(self):
        assert CORSChecker.version == "2.0.0"

    def test_is_scan_module(self):
        from scanning.vuln_scanner import ScanModule
        assert issubclass(CORSChecker, ScanModule)


# =============================================================================
# BYPASS ORIGINS
# =============================================================================

class TestGenerateBypassOrigins:
    @pytest.fixture
    def checker(self):
        from unittest.mock import MagicMock
        settings = MagicMock()
        settings.scanning.modules.get.return_value = {}
        return CORSChecker(settings)

    def test_not_empty(self, checker):
        origins = checker._generate_bypass_origins("https://example.com")
        assert len(origins) > 0

    def test_has_null_origin(self, checker):
        origins = checker._generate_bypass_origins("https://example.com")
        types = [o["type"] for o in origins]
        assert "null_origin" in types

    def test_has_arbitrary(self, checker):
        origins = checker._generate_bypass_origins("https://example.com")
        types = [o["type"] for o in origins]
        assert "arbitrary" in types

    def test_has_subdomain_inject(self, checker):
        origins = checker._generate_bypass_origins("https://example.com")
        types = [o["type"] for o in origins]
        assert "subdomain_inject" in types

    def test_has_suffix_bypass(self, checker):
        origins = checker._generate_bypass_origins("https://example.com")
        types = [o["type"] for o in origins]
        assert "suffix_bypass" in types

    def test_has_prefix_bypass(self, checker):
        origins = checker._generate_bypass_origins("https://example.com")
        types = [o["type"] for o in origins]
        assert "prefix_bypass" in types

    def test_has_protocol_downgrade(self, checker):
        origins = checker._generate_bypass_origins("https://example.com")
        types = [o["type"] for o in origins]
        assert "protocol_downgrade" in types

    def test_has_regex_bypass(self, checker):
        origins = checker._generate_bypass_origins("https://example.com")
        types = [o["type"] for o in origins]
        assert "regex_bypass" in types

    def test_has_null_byte(self, checker):
        origins = checker._generate_bypass_origins("https://example.com")
        types = [o["type"] for o in origins]
        assert "null_byte" in types

    def test_has_localhost(self, checker):
        origins = checker._generate_bypass_origins("https://example.com")
        types = [o["type"] for o in origins]
        assert "localhost" in types

    def test_subdomain_contains_target(self, checker):
        origins = checker._generate_bypass_origins("https://target.com")
        subdomain = [o for o in origins if o["type"] == "subdomain_inject"]
        assert any("target.com" in o["origin"] for o in subdomain)

    def test_suffix_contains_target(self, checker):
        origins = checker._generate_bypass_origins("https://target.com")
        suffix = [o for o in origins if o["type"] == "suffix_bypass"]
        assert any("target.com" in o["origin"] for o in suffix)

    def test_protocol_downgrade_http(self, checker):
        origins = checker._generate_bypass_origins("https://target.com")
        downgrade = [o for o in origins if o["type"] == "protocol_downgrade"]
        assert any(o["origin"].startswith("http://") for o in downgrade)

    def test_all_have_description(self, checker):
        origins = checker._generate_bypass_origins("https://example.com")
        for origin in origins:
            assert "description" in origin
            assert len(origin["description"]) > 0

    def test_all_have_type(self, checker):
        origins = checker._generate_bypass_origins("https://example.com")
        for origin in origins:
            assert "type" in origin

    def test_with_port(self, checker):
        origins = checker._generate_bypass_origins("https://example.com:8443")
        assert len(origins) > 0

    def test_with_subdomain(self, checker):
        origins = checker._generate_bypass_origins("https://www.example.com")
        assert len(origins) > 0


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    def test_sensitive_pattern_count(self):
        assert len(SENSITIVE_DATA_PATTERNS) >= 40

    def test_public_pattern_count(self):
        assert len(PUBLIC_DATA_PATTERNS) >= 5

    def test_all_sensitive_patterns_are_strings(self):
        for p in SENSITIVE_DATA_PATTERNS:
            assert isinstance(p, str)

    def test_all_public_patterns_are_strings(self):
        for p in PUBLIC_DATA_PATTERNS:
            assert isinstance(p, str)
