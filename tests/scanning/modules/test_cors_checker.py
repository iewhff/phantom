"""
Tests for scanning/modules/cors_checker.py - CORS Misconfiguration Checker.

Covers:
- SENSITIVE_DATA_PATTERNS regex patterns
- PUBLIC_DATA_PATTERNS regex patterns
- contains_sensitive_data function
- is_public_endpoint function
"""

import pytest

from scanning.modules.cors_checker import (
    SENSITIVE_DATA_PATTERNS,
    PUBLIC_DATA_PATTERNS,
    contains_sensitive_data,
    is_public_endpoint,
)


# =============================================================================
# SENSITIVE_DATA_PATTERNS TESTS
# =============================================================================

class TestSensitiveDataPatterns:
    """Tests for SENSITIVE_DATA_PATTERNS constant."""

    def test_patterns_list_not_empty(self):
        """Test patterns list is not empty."""
        assert len(SENSITIVE_DATA_PATTERNS) > 0

    def test_email_pattern_matches(self):
        """Test email pattern matches JSON email field."""
        import re
        response = '{"email": "user@example.com"}'

        matches = [p for p in SENSITIVE_DATA_PATTERNS if re.search(p, response, re.I)]
        assert len(matches) > 0

    def test_password_pattern_matches(self):
        """Test password pattern matches."""
        import re
        response = '{"password": "secret123"}'

        matches = [p for p in SENSITIVE_DATA_PATTERNS if re.search(p, response, re.I)]
        assert len(matches) > 0

    def test_token_pattern_matches(self):
        """Test token pattern matches."""
        import re
        response = '{"token": "abc123-def456"}'

        matches = [p for p in SENSITIVE_DATA_PATTERNS if re.search(p, response, re.I)]
        assert len(matches) > 0

    def test_access_token_pattern_matches(self):
        """Test access_token pattern matches."""
        import re
        response = '{"access_token": "eyJhbGciOiJIUzI1NiJ9..."}'

        matches = [p for p in SENSITIVE_DATA_PATTERNS if re.search(p, response, re.I)]
        assert len(matches) > 0

    def test_camelcase_accesstoken_matches(self):
        """Test camelCase accessToken pattern matches."""
        import re
        response = '{"accessToken": "token123"}'

        matches = [p for p in SENSITIVE_DATA_PATTERNS if re.search(p, response, re.I)]
        assert len(matches) > 0

    def test_jwt_pattern_matches(self):
        """Test JWT token pattern matches."""
        import re
        response = '{"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"}'

        matches = [p for p in SENSITIVE_DATA_PATTERNS if re.search(p, response, re.I)]
        assert len(matches) > 0

    def test_bearer_token_matches(self):
        """Test Bearer token pattern matches."""
        import re
        response = 'Authorization: Bearer abc123-token'

        matches = [p for p in SENSITIVE_DATA_PATTERNS if re.search(p, response, re.I)]
        assert len(matches) > 0

    def test_user_id_pattern_matches(self):
        """Test user_id pattern matches."""
        import re
        response = '{"user_id": 12345}'

        matches = [p for p in SENSITIVE_DATA_PATTERNS if re.search(p, response, re.I)]
        assert len(matches) > 0

    def test_camelcase_userid_matches(self):
        """Test camelCase userId pattern matches."""
        import re
        response = '{"userId": 12345}'

        matches = [p for p in SENSITIVE_DATA_PATTERNS if re.search(p, response, re.I)]
        assert len(matches) > 0

    def test_admin_flag_matches(self):
        """Test admin flag pattern matches."""
        import re
        response = '{"admin": true}'

        matches = [p for p in SENSITIVE_DATA_PATTERNS if re.search(p, response, re.I)]
        assert len(matches) > 0

    def test_camelcase_isadmin_matches(self):
        """Test camelCase isAdmin pattern matches (audit fix)."""
        import re
        response = '{"isAdmin": true}'

        matches = [p for p in SENSITIVE_DATA_PATTERNS if re.search(p, response, re.I)]
        assert len(matches) > 0

    def test_balance_pattern_matches(self):
        """Test balance pattern matches."""
        import re
        response = '{"balance": 1234.56}'

        matches = [p for p in SENSITIVE_DATA_PATTERNS if re.search(p, response, re.I)]
        assert len(matches) > 0

    def test_credit_card_pattern_matches(self):
        """Test credit_card pattern matches."""
        import re
        response = '{"credit_card": "4111111111111111"}'

        matches = [p for p in SENSITIVE_DATA_PATTERNS if re.search(p, response, re.I)]
        assert len(matches) > 0

    def test_ssn_pattern_matches(self):
        """Test SSN pattern matches."""
        import re
        response = '{"ssn": "123-45-6789"}'

        matches = [p for p in SENSITIVE_DATA_PATTERNS if re.search(p, response, re.I)]
        assert len(matches) > 0

    def test_profile_object_matches(self):
        """Test profile object pattern matches."""
        import re
        response = '{"profile": {"name": "John"}}'

        matches = [p for p in SENSITIVE_DATA_PATTERNS if re.search(p, response, re.I)]
        assert len(matches) > 0

    def test_username_pattern_matches(self):
        """Test username pattern matches."""
        import re
        response = '{"username": "johndoe"}'

        matches = [p for p in SENSITIVE_DATA_PATTERNS if re.search(p, response, re.I)]
        assert len(matches) > 0


# =============================================================================
# PUBLIC_DATA_PATTERNS TESTS
# =============================================================================

class TestPublicDataPatterns:
    """Tests for PUBLIC_DATA_PATTERNS constant."""

    def test_patterns_list_not_empty(self):
        """Test patterns list is not empty."""
        assert len(PUBLIC_DATA_PATTERNS) > 0

    def test_html_page_matches(self):
        """Test HTML page pattern matches."""
        import re
        response = '<html><head><title>Welcome</title></head></html>'

        matches = [p for p in PUBLIC_DATA_PATTERNS if re.search(p, response, re.I | re.S)]
        assert len(matches) > 0

    def test_version_info_matches(self):
        """Test version info pattern matches."""
        import re
        response = '{"version": "1.2.3"}'

        matches = [p for p in PUBLIC_DATA_PATTERNS if re.search(p, response, re.I)]
        assert len(matches) > 0

    def test_health_check_matches(self):
        """Test health check pattern matches."""
        import re
        response = '{"status": "ok"}'

        matches = [p for p in PUBLIC_DATA_PATTERNS if re.search(p, response, re.I)]
        assert len(matches) > 0

    def test_empty_json_object_matches(self):
        """Test empty JSON object pattern matches."""
        import re
        response = '   {  }   '

        matches = [p for p in PUBLIC_DATA_PATTERNS if re.search(p, response, re.I)]
        assert len(matches) > 0

    def test_empty_array_matches(self):
        """Test empty array pattern matches."""
        import re
        response = '{"data": []}'

        matches = [p for p in PUBLIC_DATA_PATTERNS if re.search(p, response, re.I)]
        assert len(matches) > 0

    def test_public_flag_matches(self):
        """Test public flag pattern matches."""
        import re
        response = '{"public": true}'

        matches = [p for p in PUBLIC_DATA_PATTERNS if re.search(p, response, re.I)]
        assert len(matches) > 0


# =============================================================================
# contains_sensitive_data TESTS
# =============================================================================

class TestContainsSensitiveData:
    """Tests for contains_sensitive_data function."""

    def test_empty_response(self):
        """Test empty response returns False."""
        has_sensitive, patterns = contains_sensitive_data("")

        assert has_sensitive is False
        assert patterns == []

    def test_none_response(self):
        """Test None response returns False."""
        has_sensitive, patterns = contains_sensitive_data(None)

        assert has_sensitive is False
        assert patterns == []

    def test_sensitive_email(self):
        """Test email field detected as sensitive."""
        response = '{"email": "user@example.com"}'

        has_sensitive, patterns = contains_sensitive_data(response)

        assert has_sensitive is True
        assert len(patterns) > 0

    def test_sensitive_password(self):
        """Test password field detected as sensitive."""
        response = '{"password": "secret"}'

        has_sensitive, patterns = contains_sensitive_data(response)

        assert has_sensitive is True

    def test_sensitive_token(self):
        """Test token detected as sensitive."""
        response = '{"access_token": "abc123"}'

        has_sensitive, patterns = contains_sensitive_data(response)

        assert has_sensitive is True

    def test_sensitive_jwt(self):
        """Test JWT token detected as sensitive."""
        response = '{"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}'

        has_sensitive, patterns = contains_sensitive_data(response)

        assert has_sensitive is True

    def test_sensitive_admin_flag(self):
        """Test admin flag detected as sensitive."""
        response = '{"isAdmin": true}'

        has_sensitive, patterns = contains_sensitive_data(response)

        assert has_sensitive is True

    def test_sensitive_financial_data(self):
        """Test financial data detected as sensitive."""
        response = '{"balance": 1234.56, "accountNumber": "123456789"}'

        has_sensitive, patterns = contains_sensitive_data(response)

        assert has_sensitive is True

    def test_non_sensitive_public_data(self):
        """Test public data is not flagged as sensitive."""
        response = '{"version": "1.0.0", "status": "ok"}'

        has_sensitive, patterns = contains_sensitive_data(response)

        assert has_sensitive is False

    def test_plain_text_no_sensitive(self):
        """Test plain text without sensitive patterns."""
        response = "Welcome to our website!"

        has_sensitive, patterns = contains_sensitive_data(response)

        assert has_sensitive is False

    def test_multiple_sensitive_patterns(self):
        """Test multiple sensitive patterns detected."""
        response = '{"email": "a@b.com", "password": "x", "userId": 123}'

        has_sensitive, patterns = contains_sensitive_data(response)

        assert has_sensitive is True
        assert len(patterns) >= 2

    def test_case_insensitive(self):
        """Test pattern matching is case insensitive."""
        response = '{"EMAIL": "user@example.com"}'

        has_sensitive, patterns = contains_sensitive_data(response)

        assert has_sensitive is True

    def test_returns_matched_patterns(self):
        """Test function returns list of matched patterns."""
        response = '{"email": "test@test.com"}'

        has_sensitive, patterns = contains_sensitive_data(response)

        assert has_sensitive is True
        assert isinstance(patterns, list)
        assert len(patterns) > 0


# =============================================================================
# is_public_endpoint TESTS
# =============================================================================

class TestIsPublicEndpoint:
    """Tests for is_public_endpoint function."""

    def test_health_endpoint_public(self):
        """Test /health endpoint is public."""
        result = is_public_endpoint("{}", "https://api.example.com/health")

        assert result is True

    def test_status_endpoint_public(self):
        """Test /status endpoint is public."""
        result = is_public_endpoint("{}", "https://api.example.com/status")

        assert result is True

    def test_version_endpoint_public(self):
        """Test /version endpoint is public."""
        result = is_public_endpoint("{}", "https://api.example.com/version")

        assert result is True

    def test_ping_endpoint_public(self):
        """Test /ping endpoint is public."""
        result = is_public_endpoint("{}", "https://api.example.com/ping")

        assert result is True

    def test_static_assets_public(self):
        """Test /static/ path is public."""
        result = is_public_endpoint("{}", "https://example.com/static/style.css")

        assert result is True

    def test_css_file_public(self):
        """Test CSS file is public."""
        result = is_public_endpoint("{}", "https://example.com/app.css")

        assert result is True

    def test_js_file_public(self):
        """Test JS file is public."""
        result = is_public_endpoint("{}", "https://example.com/app.js")

        assert result is True

    def test_image_file_public(self):
        """Test image file is public."""
        result = is_public_endpoint("{}", "https://example.com/logo.png")

        assert result is True

    def test_user_endpoint_not_public(self):
        """Test /user/ endpoint is NOT public (protected)."""
        result = is_public_endpoint("{}", "https://api.example.com/user/123")

        assert result is False

    def test_users_endpoint_not_public(self):
        """Test /users/ endpoint is NOT public (protected)."""
        result = is_public_endpoint("{}", "https://api.example.com/users/list")

        assert result is False

    def test_account_endpoint_not_public(self):
        """Test /account/ endpoint is NOT public (protected)."""
        result = is_public_endpoint("{}", "https://api.example.com/account/settings")

        assert result is False

    def test_profile_endpoint_not_public(self):
        """Test /profile/ endpoint is NOT public (protected)."""
        # URL pattern expects /profile/ with trailing slash
        result = is_public_endpoint("{}", "https://api.example.com/profile/settings")

        assert result is False

    def test_admin_endpoint_not_public(self):
        """Test /admin/ endpoint is NOT public (protected)."""
        result = is_public_endpoint("{}", "https://api.example.com/admin/users")

        assert result is False

    def test_auth_endpoint_not_public(self):
        """Test /auth/ endpoint is NOT public (protected)."""
        result = is_public_endpoint("{}", "https://api.example.com/auth/login")

        assert result is False

    def test_token_endpoint_not_public(self):
        """Test /token endpoint is NOT public (protected)."""
        result = is_public_endpoint("{}", "https://api.example.com/oauth/token")

        assert result is False

    def test_me_endpoint_not_public(self):
        """Test /me endpoint is NOT public (protected)."""
        result = is_public_endpoint("{}", "https://api.example.com/api/me")

        assert result is False

    def test_private_path_not_public(self):
        """Test /private/ path is NOT public (protected)."""
        result = is_public_endpoint("{}", "https://api.example.com/private/data")

        assert result is False

    def test_settings_endpoint_not_public(self):
        """Test /settings/ endpoint is NOT public (protected)."""
        result = is_public_endpoint("{}", "https://api.example.com/user/settings/")

        assert result is False

    def test_preferences_endpoint_not_public(self):
        """Test /preferences/ endpoint is NOT public (audit fix)."""
        # Audit found: /api/user/1/preferences returning empty [] was skipped
        result = is_public_endpoint("[]", "https://api.example.com/api/user/1/preferences")

        assert result is False

    def test_payment_endpoint_not_public(self):
        """Test /payment endpoint is NOT public (protected)."""
        result = is_public_endpoint("{}", "https://api.example.com/payment/process")

        assert result is False

    def test_order_endpoint_not_public(self):
        """Test /order endpoint is NOT public (protected)."""
        result = is_public_endpoint("{}", "https://api.example.com/order/12345")

        assert result is False

    def test_transaction_endpoint_not_public(self):
        """Test /transaction endpoint is NOT public (protected)."""
        result = is_public_endpoint("{}", "https://api.example.com/transaction/history")

        assert result is False

    def test_generic_api_endpoint(self):
        """Test generic API endpoint with public response."""
        # Empty JSON with no protected URL patterns
        result = is_public_endpoint('{"status": "ok"}', "https://api.example.com/api/items")

        # Not a protected URL, response has public pattern
        # Behavior depends on implementation - check it doesn't crash
        assert isinstance(result, bool)

    def test_case_insensitive_url(self):
        """Test URL matching is case insensitive."""
        result = is_public_endpoint("{}", "https://api.example.com/ADMIN/users")

        assert result is False

    def test_favicon_public(self):
        """Test favicon is public."""
        result = is_public_endpoint("{}", "https://example.com/favicon.ico")

        assert result is True

    def test_svg_file_public(self):
        """Test SVG file is public."""
        result = is_public_endpoint("{}", "https://example.com/icon.svg")

        assert result is True

    def test_public_path_prefix(self):
        """Test /public/ path prefix is public."""
        result = is_public_endpoint("{}", "https://example.com/public/docs")

        assert result is True

    def test_assets_path_prefix(self):
        """Test /assets/ path prefix is public."""
        result = is_public_endpoint("{}", "https://example.com/assets/image.jpg")

        assert result is True


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestSensitiveDataIntegration:
    """Integration tests combining functions."""

    def test_sensitive_data_on_protected_endpoint(self):
        """Test sensitive data on protected endpoint."""
        response = '{"email": "user@example.com", "balance": 1000}'
        url = "https://api.example.com/user/profile"

        has_sensitive, _ = contains_sensitive_data(response)
        is_public = is_public_endpoint(response, url)

        # Has sensitive data AND not public
        assert has_sensitive is True
        assert is_public is False

    def test_empty_response_on_protected_endpoint(self):
        """Test empty response on protected endpoint (audit fix)."""
        # Audit found: empty array on /preferences was incorrectly skipped
        response = "[]"
        url = "https://api.example.com/api/user/1/preferences"

        has_sensitive, _ = contains_sensitive_data(response)
        is_public = is_public_endpoint(response, url)

        # No sensitive data, but endpoint should still be protected
        assert has_sensitive is False
        assert is_public is False  # Preferences is protected URL

    def test_public_data_on_public_endpoint(self):
        """Test public data on public endpoint."""
        response = '{"status": "ok", "version": "1.0"}'
        url = "https://api.example.com/health"

        has_sensitive, _ = contains_sensitive_data(response)
        is_public = is_public_endpoint(response, url)

        assert has_sensitive is False
        assert is_public is True

    def test_mixed_data_scenario(self):
        """Test scenario with both sensitive and public patterns."""
        # Response has both public and sensitive data
        response = '{"status": "ok", "userId": 123, "email": "test@test.com"}'
        url = "https://api.example.com/user/data"

        has_sensitive, patterns = contains_sensitive_data(response)
        is_public = is_public_endpoint(response, url)

        # Should detect sensitive data
        assert has_sensitive is True
        assert len(patterns) >= 1

        # Should NOT be public (user endpoint)
        assert is_public is False
