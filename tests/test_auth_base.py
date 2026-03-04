"""
Tests for Authentication Scanner Base Module.

Covers:
- AuthVulnType enum
- PrivilegeEscalationType enum
- Data classes (AuthTestResult, JWTAnalysis, OAuthConfig, SessionInfo, PrivescTestResult)
- Credential payloads
- JWT payloads
- OAuth payloads
- Auth bypass payloads
- IDOR patterns
- MFA bypass techniques
- Privilege escalation payloads
- Utility functions
"""

import pytest
import re

from scanning.modules.auth.auth_base import (
    # Enums
    AuthVulnType,
    PrivilegeEscalationType,
    # Data classes
    AuthTestResult,
    JWTAnalysis,
    OAuthConfig,
    SessionInfo,
    PrivescTestResult,
    # Payloads
    ENTERPRISE_CREDENTIALS,
    JWT_WEAK_SECRETS,
    OAUTH_REDIRECT_PAYLOADS,
    AUTH_BYPASS_HEADERS,
    IDOR_PATTERNS,
    MFA_BYPASS_TECHNIQUES,
    ROLE_MANIPULATION_PAYLOADS,
    ADMIN_PATHS_FORCED_BROWSING,
    HTTP_METHOD_TAMPERING,
    MASS_ASSIGNMENT_PAYLOADS,
    PARAM_POLLUTION_PAYLOADS,
    PRIVILEGED_FUNCTIONS,
    PATH_TRAVERSAL_AUTHZ_PAYLOADS,
    LOGIN_PATHS,
    OAUTH_PATHS,
    PROTECTED_PATHS,
    # Utility functions
    extract_form_fields,
    check_successful_login,
    is_jwt,
)


# ============================================================================
# TESTS: AuthVulnType Enum
# ============================================================================

class TestAuthVulnType:
    """Tests for AuthVulnType enum."""

    def test_has_default_credentials(self):
        """Should have DEFAULT_CREDENTIALS type."""
        assert AuthVulnType.DEFAULT_CREDENTIALS is not None

    def test_has_weak_password(self):
        """Should have WEAK_PASSWORD type."""
        assert AuthVulnType.WEAK_PASSWORD is not None

    def test_has_brute_force(self):
        """Should have BRUTE_FORCE type."""
        assert AuthVulnType.BRUTE_FORCE is not None

    def test_has_session_fixation(self):
        """Should have SESSION_FIXATION type."""
        assert AuthVulnType.SESSION_FIXATION is not None

    def test_has_jwt_none_alg(self):
        """Should have JWT_NONE_ALG type."""
        assert AuthVulnType.JWT_NONE_ALG is not None

    def test_has_jwt_key_confusion(self):
        """Should have JWT_KEY_CONFUSION type."""
        assert AuthVulnType.JWT_KEY_CONFUSION is not None

    def test_has_jwt_weak_secret(self):
        """Should have JWT_WEAK_SECRET type."""
        assert AuthVulnType.JWT_WEAK_SECRET is not None

    def test_has_oauth_redirect(self):
        """Should have OAUTH_REDIRECT type."""
        assert AuthVulnType.OAUTH_REDIRECT is not None

    def test_has_oauth_state_missing(self):
        """Should have OAUTH_STATE_MISSING type."""
        assert AuthVulnType.OAUTH_STATE_MISSING is not None

    def test_has_saml_signature_bypass(self):
        """Should have SAML_SIGNATURE_BYPASS type."""
        assert AuthVulnType.SAML_SIGNATURE_BYPASS is not None

    def test_has_idor(self):
        """Should have IDOR type."""
        assert AuthVulnType.IDOR is not None

    def test_has_privilege_escalation(self):
        """Should have PRIVILEGE_ESCALATION type."""
        assert AuthVulnType.PRIVILEGE_ESCALATION is not None

    def test_has_mfa_bypass(self):
        """Should have MFA_BYPASS type."""
        assert AuthVulnType.MFA_BYPASS is not None

    def test_has_auth_bypass(self):
        """Should have AUTH_BYPASS type."""
        assert AuthVulnType.AUTH_BYPASS is not None

    def test_all_types_are_unique(self):
        """All vulnerability types should be unique."""
        values = [v.value for v in AuthVulnType]
        assert len(values) == len(set(values))


# ============================================================================
# TESTS: PrivilegeEscalationType Enum
# ============================================================================

class TestPrivilegeEscalationType:
    """Tests for PrivilegeEscalationType enum."""

    def test_has_horizontal_idor(self):
        """Should have HORIZONTAL_IDOR type."""
        assert PrivilegeEscalationType.HORIZONTAL_IDOR is not None

    def test_has_vertical_escalation(self):
        """Should have VERTICAL_ESCALATION type."""
        assert PrivilegeEscalationType.VERTICAL_ESCALATION is not None

    def test_has_role_manipulation(self):
        """Should have ROLE_MANIPULATION type."""
        assert PrivilegeEscalationType.ROLE_MANIPULATION is not None

    def test_has_forced_browsing(self):
        """Should have FORCED_BROWSING type."""
        assert PrivilegeEscalationType.FORCED_BROWSING is not None

    def test_has_http_method_tampering(self):
        """Should have HTTP_METHOD_TAMPERING type."""
        assert PrivilegeEscalationType.HTTP_METHOD_TAMPERING is not None

    def test_has_parameter_pollution(self):
        """Should have PARAMETER_POLLUTION type."""
        assert PrivilegeEscalationType.PARAMETER_POLLUTION is not None

    def test_has_mass_assignment(self):
        """Should have MASS_ASSIGNMENT type."""
        assert PrivilegeEscalationType.MASS_ASSIGNMENT is not None

    def test_has_path_traversal_authz(self):
        """Should have PATH_TRAVERSAL_AUTHZ type."""
        assert PrivilegeEscalationType.PATH_TRAVERSAL_AUTHZ is not None

    def test_has_function_level_access(self):
        """Should have FUNCTION_LEVEL_ACCESS type."""
        assert PrivilegeEscalationType.FUNCTION_LEVEL_ACCESS is not None


# ============================================================================
# TESTS: AuthTestResult Dataclass
# ============================================================================

class TestAuthTestResult:
    """Tests for AuthTestResult dataclass."""

    def test_creates_with_required_fields(self):
        """Should create with required fields."""
        result = AuthTestResult(
            test_type=AuthVulnType.DEFAULT_CREDENTIALS,
            success=True,
        )
        assert result.test_type == AuthVulnType.DEFAULT_CREDENTIALS
        assert result.success is True

    def test_default_values(self):
        """Should have correct default values."""
        result = AuthTestResult(
            test_type=AuthVulnType.WEAK_PASSWORD,
            success=False,
        )
        assert result.severity == "INFO"
        assert result.confidence == 0.0
        assert result.evidence == []
        assert result.payload == ""
        assert result.response_data == {}

    def test_stores_evidence_list(self):
        """Should store evidence list."""
        result = AuthTestResult(
            test_type=AuthVulnType.BRUTE_FORCE,
            success=True,
            evidence=["Login successful", "No rate limiting"],
        )
        assert len(result.evidence) == 2

    def test_stores_payload(self):
        """Should store payload."""
        result = AuthTestResult(
            test_type=AuthVulnType.JWT_NONE_ALG,
            success=True,
            payload="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.",
        )
        assert "none" in result.payload.lower() or "eyJ" in result.payload


# ============================================================================
# TESTS: JWTAnalysis Dataclass
# ============================================================================

class TestJWTAnalysis:
    """Tests for JWTAnalysis dataclass."""

    def test_creates_with_defaults(self):
        """Should create with default values."""
        analysis = JWTAnalysis()
        assert analysis.header == {}
        assert analysis.payload == {}
        assert analysis.signature == ""
        assert analysis.algorithm == ""
        assert analysis.is_expired is False
        assert analysis.vulnerabilities == []

    def test_stores_header_and_payload(self):
        """Should store header and payload."""
        analysis = JWTAnalysis(
            header={"alg": "HS256", "typ": "JWT"},
            payload={"sub": "1234567890", "name": "Test"},
            algorithm="HS256",
        )
        assert analysis.header["alg"] == "HS256"
        assert analysis.payload["sub"] == "1234567890"
        assert analysis.algorithm == "HS256"

    def test_stores_vulnerabilities(self):
        """Should store vulnerabilities."""
        analysis = JWTAnalysis(
            vulnerabilities=["none_algorithm", "weak_secret"],
        )
        assert len(analysis.vulnerabilities) == 2
        assert "none_algorithm" in analysis.vulnerabilities

    def test_stores_expiry(self):
        """Should store expiry information."""
        analysis = JWTAnalysis(
            is_expired=True,
            expiry_time=1609459200,
        )
        assert analysis.is_expired is True
        assert analysis.expiry_time == 1609459200


# ============================================================================
# TESTS: OAuthConfig Dataclass
# ============================================================================

class TestOAuthConfig:
    """Tests for OAuthConfig dataclass."""

    def test_creates_with_defaults(self):
        """Should create with default values."""
        config = OAuthConfig()
        assert config.authorization_endpoint == ""
        assert config.token_endpoint == ""
        assert config.client_id == ""
        assert config.state_param is False
        assert config.pkce_supported is False

    def test_stores_endpoints(self):
        """Should store OAuth endpoints."""
        config = OAuthConfig(
            authorization_endpoint="https://auth.example.com/oauth/authorize",
            token_endpoint="https://auth.example.com/oauth/token",
            client_id="client123",
            redirect_uri="https://app.example.com/callback",
        )
        assert "authorize" in config.authorization_endpoint
        assert "token" in config.token_endpoint

    def test_stores_security_features(self):
        """Should store security features."""
        config = OAuthConfig(
            state_param=True,
            pkce_supported=True,
        )
        assert config.state_param is True
        assert config.pkce_supported is True


# ============================================================================
# TESTS: SessionInfo Dataclass
# ============================================================================

class TestSessionInfo:
    """Tests for SessionInfo dataclass."""

    def test_creates_with_defaults(self):
        """Should create with default values."""
        info = SessionInfo()
        assert info.cookie_name == ""
        assert info.cookie_value == ""
        assert info.has_secure is False
        assert info.has_httponly is False
        assert info.has_samesite is False
        assert info.entropy == 0.0
        assert info.is_predictable is False

    def test_stores_cookie_info(self):
        """Should store cookie information."""
        info = SessionInfo(
            cookie_name="SESSIONID",
            cookie_value="abc123xyz",
            has_secure=True,
            has_httponly=True,
            has_samesite=True,
            samesite_value="Strict",
        )
        assert info.cookie_name == "SESSIONID"
        assert info.has_secure is True
        assert info.samesite_value == "Strict"

    def test_stores_entropy(self):
        """Should store entropy information."""
        info = SessionInfo(
            entropy=128.5,
            is_predictable=False,
        )
        assert info.entropy == 128.5
        assert info.is_predictable is False


# ============================================================================
# TESTS: PrivescTestResult Dataclass
# ============================================================================

class TestPrivescTestResult:
    """Tests for PrivescTestResult dataclass."""

    def test_creates_with_required_fields(self):
        """Should create with required fields."""
        result = PrivescTestResult(
            test_type=PrivilegeEscalationType.HORIZONTAL_IDOR,
            vulnerable=True,
        )
        assert result.test_type == PrivilegeEscalationType.HORIZONTAL_IDOR
        assert result.vulnerable is True

    def test_default_values(self):
        """Should have correct default values."""
        result = PrivescTestResult(
            test_type=PrivilegeEscalationType.VERTICAL_ESCALATION,
            vulnerable=False,
        )
        assert result.severity == "INFO"
        assert result.confidence == 0.0
        assert result.endpoint == ""
        assert result.evidence == []

    def test_stores_responses(self):
        """Should store original and exploit responses."""
        result = PrivescTestResult(
            test_type=PrivilegeEscalationType.ROLE_MANIPULATION,
            vulnerable=True,
            original_response='{"role": "user"}',
            exploit_response='{"role": "admin"}',
        )
        assert "user" in result.original_response
        assert "admin" in result.exploit_response


# ============================================================================
# TESTS: Enterprise Credentials
# ============================================================================

class TestEnterpriseCredentials:
    """Tests for ENTERPRISE_CREDENTIALS list."""

    def test_contains_admin_admin(self):
        """Should contain admin:admin."""
        assert ("admin", "admin") in ENTERPRISE_CREDENTIALS

    def test_contains_admin_password(self):
        """Should contain admin:password."""
        assert ("admin", "password") in ENTERPRISE_CREDENTIALS

    def test_contains_root_root(self):
        """Should contain root:root."""
        assert ("root", "root") in ENTERPRISE_CREDENTIALS

    def test_contains_test_test(self):
        """Should contain test:test."""
        assert ("test", "test") in ENTERPRISE_CREDENTIALS

    def test_contains_empty_password(self):
        """Should contain credentials with empty password."""
        empty_passwords = [(u, p) for u, p in ENTERPRISE_CREDENTIALS if p == ""]
        assert len(empty_passwords) > 0

    def test_contains_database_defaults(self):
        """Should contain database default credentials."""
        usernames = [u for u, p in ENTERPRISE_CREDENTIALS]
        assert "postgres" in usernames
        assert "mysql" in usernames

    def test_contains_tomcat_defaults(self):
        """Should contain Tomcat defaults."""
        assert ("tomcat", "tomcat") in ENTERPRISE_CREDENTIALS

    def test_all_are_tuples(self):
        """All credentials should be tuples."""
        assert all(isinstance(c, tuple) for c in ENTERPRISE_CREDENTIALS)
        assert all(len(c) == 2 for c in ENTERPRISE_CREDENTIALS)


# ============================================================================
# TESTS: JWT Weak Secrets
# ============================================================================

class TestJWTWeakSecrets:
    """Tests for JWT_WEAK_SECRETS list."""

    def test_contains_secret(self):
        """Should contain 'secret'."""
        assert "secret" in JWT_WEAK_SECRETS

    def test_contains_password(self):
        """Should contain 'password'."""
        assert "password" in JWT_WEAK_SECRETS

    def test_contains_numeric(self):
        """Should contain numeric weak secrets."""
        assert "123456" in JWT_WEAK_SECRETS

    def test_contains_common_patterns(self):
        """Should contain common weak patterns."""
        patterns = ["jwt_secret", "jwt-secret", "secretkey"]
        for pattern in patterns:
            assert pattern in JWT_WEAK_SECRETS

    def test_all_are_strings(self):
        """All secrets should be strings."""
        assert all(isinstance(s, str) for s in JWT_WEAK_SECRETS)


# ============================================================================
# TESTS: OAuth Redirect Payloads
# ============================================================================

class TestOAuthRedirectPayloads:
    """Tests for OAUTH_REDIRECT_PAYLOADS list."""

    def test_contains_double_slash(self):
        """Should contain double slash bypass."""
        assert "//evil.com" in OAUTH_REDIRECT_PAYLOADS

    def test_contains_https_evil(self):
        """Should contain https evil domain."""
        assert "https://evil.com" in OAUTH_REDIRECT_PAYLOADS

    def test_contains_encoding_bypass(self):
        """Should contain URL encoding bypass."""
        encoded = [p for p in OAUTH_REDIRECT_PAYLOADS if "%" in p]
        assert len(encoded) > 0

    def test_contains_subdomain_confusion(self):
        """Should contain subdomain confusion."""
        subdomain = [p for p in OAUTH_REDIRECT_PAYLOADS if "legitimate.com" in p.lower()]
        assert len(subdomain) > 0


# ============================================================================
# TESTS: Auth Bypass Headers
# ============================================================================

class TestAuthBypassHeaders:
    """Tests for AUTH_BYPASS_HEADERS list."""

    def test_contains_x_original_url(self):
        """Should contain X-Original-URL."""
        headers = AUTH_BYPASS_HEADERS
        assert any("X-Original-URL" in h for h in headers)

    def test_contains_x_forwarded_for(self):
        """Should contain X-Forwarded-For."""
        headers = AUTH_BYPASS_HEADERS
        assert any("X-Forwarded-For" in h for h in headers)

    def test_contains_localhost_ip(self):
        """Should contain localhost IP."""
        headers = AUTH_BYPASS_HEADERS
        assert any("127.0.0.1" in str(h) for h in headers)

    def test_all_are_dicts(self):
        """All bypass headers should be dicts."""
        assert all(isinstance(h, dict) for h in AUTH_BYPASS_HEADERS)


# ============================================================================
# TESTS: IDOR Patterns
# ============================================================================

class TestIDORPatterns:
    """Tests for IDOR_PATTERNS list."""

    def test_contains_numeric_patterns(self):
        """Should contain numeric manipulation patterns."""
        numeric = [p for p in IDOR_PATTERNS if "original" in p and p.get("original") == "1"]
        assert len(numeric) > 0

    def test_contains_uuid_pattern(self):
        """Should contain UUID pattern."""
        uuid_patterns = [p for p in IDOR_PATTERNS if "pattern" in p]
        assert len(uuid_patterns) > 0

    def test_numeric_has_test_values(self):
        """Numeric patterns should have test values."""
        for pattern in IDOR_PATTERNS:
            if "test" in pattern:
                assert len(pattern["test"]) > 0


# ============================================================================
# TESTS: MFA Bypass Techniques
# ============================================================================

class TestMFABypassTechniques:
    """Tests for MFA_BYPASS_TECHNIQUES list."""

    def test_contains_null_code(self):
        """Should contain null code technique."""
        techniques = [t["name"] for t in MFA_BYPASS_TECHNIQUES]
        assert "null_code" in techniques

    def test_contains_zero_code(self):
        """Should contain zero code technique."""
        techniques = [t["name"] for t in MFA_BYPASS_TECHNIQUES]
        assert "zero_code" in techniques

    def test_contains_array_injection(self):
        """Should contain array injection technique."""
        techniques = [t["name"] for t in MFA_BYPASS_TECHNIQUES]
        assert "array_code" in techniques

    def test_all_have_description(self):
        """All techniques should have description."""
        for technique in MFA_BYPASS_TECHNIQUES:
            assert "description" in technique
            assert len(technique["description"]) > 0


# ============================================================================
# TESTS: Role Manipulation Payloads
# ============================================================================

class TestRoleManipulationPayloads:
    """Tests for ROLE_MANIPULATION_PAYLOADS list."""

    def test_contains_role_param(self):
        """Should contain role parameter."""
        params = [p["param"] for p in ROLE_MANIPULATION_PAYLOADS]
        assert "role" in params

    def test_contains_is_admin(self):
        """Should contain is_admin parameter."""
        params = [p["param"] for p in ROLE_MANIPULATION_PAYLOADS]
        assert "is_admin" in params or "isAdmin" in params

    def test_contains_admin_value(self):
        """Should contain 'admin' as test value."""
        for payload in ROLE_MANIPULATION_PAYLOADS:
            if "admin" in payload.get("values", []):
                return
        pytest.fail("No payload contains 'admin' value")

    def test_all_have_values(self):
        """All payloads should have values list."""
        for payload in ROLE_MANIPULATION_PAYLOADS:
            assert "values" in payload
            assert len(payload["values"]) > 0


# ============================================================================
# TESTS: Admin Paths
# ============================================================================

class TestAdminPaths:
    """Tests for ADMIN_PATHS_FORCED_BROWSING list."""

    def test_contains_admin(self):
        """Should contain /admin."""
        assert "/admin" in ADMIN_PATHS_FORCED_BROWSING

    def test_contains_admin_dashboard(self):
        """Should contain /admin/dashboard."""
        assert "/admin/dashboard" in ADMIN_PATHS_FORCED_BROWSING

    def test_contains_api_admin(self):
        """Should contain /api/admin."""
        assert "/api/admin" in ADMIN_PATHS_FORCED_BROWSING

    def test_contains_phpmyadmin(self):
        """Should contain /phpmyadmin."""
        assert "/phpmyadmin" in ADMIN_PATHS_FORCED_BROWSING

    def test_contains_wp_admin(self):
        """Should contain /wp-admin."""
        assert "/wp-admin" in ADMIN_PATHS_FORCED_BROWSING


# ============================================================================
# TESTS: HTTP Method Tampering
# ============================================================================

class TestHTTPMethodTampering:
    """Tests for HTTP_METHOD_TAMPERING list."""

    def test_contains_standard_methods(self):
        """Should contain standard HTTP methods."""
        methods = [t["method"] for t in HTTP_METHOD_TAMPERING]
        assert "GET" in methods
        assert "POST" in methods
        assert "PUT" in methods
        assert "DELETE" in methods

    def test_contains_override_headers(self):
        """Should contain method override headers."""
        override = [t for t in HTTP_METHOD_TAMPERING if "headers" in t]
        assert len(override) > 0
        # Check for X-HTTP-Method-Override
        assert any("X-HTTP-Method-Override" in str(t.get("headers", {})) for t in override)

    def test_contains_form_method_override(self):
        """Should contain form _method override."""
        form_override = [t for t in HTTP_METHOD_TAMPERING if "params" in t]
        assert len(form_override) > 0


# ============================================================================
# TESTS: Mass Assignment Payloads
# ============================================================================

class TestMassAssignmentPayloads:
    """Tests for MASS_ASSIGNMENT_PAYLOADS list."""

    def test_contains_role_admin(self):
        """Should contain role: admin payload."""
        assert {"role": "admin"} in MASS_ASSIGNMENT_PAYLOADS

    def test_contains_is_admin(self):
        """Should contain isAdmin payload."""
        assert {"isAdmin": True} in MASS_ASSIGNMENT_PAYLOADS

    def test_contains_verified(self):
        """Should contain verified payload."""
        assert {"verified": True} in MASS_ASSIGNMENT_PAYLOADS

    def test_contains_sensitive_fields(self):
        """Should contain sensitive field payloads."""
        all_keys = []
        for payload in MASS_ASSIGNMENT_PAYLOADS:
            all_keys.extend(payload.keys())
        assert "password" in all_keys
        assert "balance" in all_keys or "credits" in all_keys


# ============================================================================
# TESTS: Path Traversal Authorization
# ============================================================================

class TestPathTraversalAuthz:
    """Tests for PATH_TRAVERSAL_AUTHZ_PAYLOADS list."""

    def test_contains_basic_traversal(self):
        """Should contain basic path traversal."""
        assert "/admin/../admin" in PATH_TRAVERSAL_AUTHZ_PAYLOADS

    def test_contains_encoded_traversal(self):
        """Should contain URL encoded traversal."""
        encoded = [p for p in PATH_TRAVERSAL_AUTHZ_PAYLOADS if "%2f" in p.lower()]
        assert len(encoded) > 0

    def test_contains_case_manipulation(self):
        """Should contain case manipulation."""
        assert "/ADMIN" in PATH_TRAVERSAL_AUTHZ_PAYLOADS

    def test_contains_null_byte(self):
        """Should contain null byte injection."""
        null_byte = [p for p in PATH_TRAVERSAL_AUTHZ_PAYLOADS if "%00" in p]
        assert len(null_byte) > 0


# ============================================================================
# TESTS: Common Paths
# ============================================================================

class TestCommonPaths:
    """Tests for common path lists."""

    def test_login_paths_contain_login(self):
        """LOGIN_PATHS should contain /login."""
        assert "/login" in LOGIN_PATHS

    def test_login_paths_contain_admin(self):
        """LOGIN_PATHS should contain /admin."""
        assert "/admin" in LOGIN_PATHS

    def test_oauth_paths_contain_authorize(self):
        """OAUTH_PATHS should contain authorize endpoint."""
        authorize = [p for p in OAUTH_PATHS if "authorize" in p]
        assert len(authorize) > 0

    def test_oauth_paths_contain_well_known(self):
        """OAUTH_PATHS should contain .well-known."""
        well_known = [p for p in OAUTH_PATHS if ".well-known" in p]
        assert len(well_known) > 0

    def test_protected_paths_contain_admin(self):
        """PROTECTED_PATHS should contain admin paths."""
        assert "/admin" in PROTECTED_PATHS

    def test_protected_paths_contain_api(self):
        """PROTECTED_PATHS should contain API paths."""
        api = [p for p in PROTECTED_PATHS if "/api" in p]
        assert len(api) > 0


# ============================================================================
# TESTS: extract_form_fields Function
# ============================================================================

class TestExtractFormFields:
    """Tests for extract_form_fields function."""

    def test_extracts_form_action(self):
        """Should extract form action."""
        html = '<form action="/login" method="POST">'
        result = extract_form_fields(html)
        assert result["action"] == "/login"

    def test_extracts_password_field(self):
        """Should extract password field name."""
        html = '<input type="password" name="password">'
        result = extract_form_fields(html)
        assert result["password_field"] == "password"

    def test_extracts_password_field_reverse_order(self):
        """Should extract password field with reversed attribute order."""
        html = '<input name="pwd" type="password">'
        result = extract_form_fields(html)
        assert result["password_field"] == "pwd"

    def test_extracts_hidden_fields(self):
        """Should extract hidden fields."""
        html = '<input type="hidden" name="csrf_token" value="abc123">'
        result = extract_form_fields(html)
        assert result["hidden_fields"]["csrf_token"] == "abc123"

    def test_handles_empty_html(self):
        """Should handle empty HTML."""
        result = extract_form_fields("")
        assert result["username_field"] is None
        assert result["password_field"] is None
        assert result["action"] is None

    def test_handles_no_form(self):
        """Should handle HTML without form."""
        html = "<div>No form here</div>"
        result = extract_form_fields(html)
        assert result["action"] is None


# ============================================================================
# TESTS: is_jwt Function
# ============================================================================

class TestIsJWT:
    """Tests for is_jwt function."""

    def test_valid_jwt_returns_true(self):
        """Valid JWT should return True."""
        # JWT with 3 parts, each > 10 chars
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        assert is_jwt(jwt) is True

    def test_two_parts_returns_false(self):
        """String with 2 parts should return False."""
        assert is_jwt("part1.part2") is False

    def test_short_parts_returns_false(self):
        """String with short parts should return False."""
        assert is_jwt("short.shor.shor") is False

    def test_four_parts_returns_false(self):
        """String with 4 parts should return False."""
        assert is_jwt("part1.part2.part3.part4") is False

    def test_empty_string_returns_false(self):
        """Empty string should return False."""
        assert is_jwt("") is False

    def test_no_dots_returns_false(self):
        """String without dots should return False."""
        assert is_jwt("nodots") is False


# ============================================================================
# TESTS: Edge Cases
# ============================================================================

class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_extract_form_fields_with_unicode(self):
        """Should handle unicode in HTML."""
        html = '<form action="/用户登录"><input name="密码" type="password"></form>'
        result = extract_form_fields(html)
        # Should not raise
        assert result is not None

    def test_extract_form_fields_with_quotes(self):
        """Should handle both single and double quotes."""
        html_double = '<form action="/login">'
        html_single = "<form action='/login'>"
        result_double = extract_form_fields(html_double)
        result_single = extract_form_fields(html_single)
        assert result_double["action"] == "/login"
        assert result_single["action"] == "/login"

    def test_is_jwt_with_spaces(self):
        """Should handle JWT with spaces."""
        jwt_with_spaces = " eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test "
        # strip() not called in is_jwt, so spaces make parts short
        assert is_jwt(jwt_with_spaces) is False

    def test_payload_lists_not_empty(self):
        """All payload lists should not be empty."""
        assert len(ENTERPRISE_CREDENTIALS) > 0
        assert len(JWT_WEAK_SECRETS) > 0
        assert len(OAUTH_REDIRECT_PAYLOADS) > 0
        assert len(AUTH_BYPASS_HEADERS) > 0
        assert len(IDOR_PATTERNS) > 0
        assert len(MFA_BYPASS_TECHNIQUES) > 0
        assert len(ROLE_MANIPULATION_PAYLOADS) > 0
        assert len(ADMIN_PATHS_FORCED_BROWSING) > 0
        assert len(HTTP_METHOD_TAMPERING) > 0
        assert len(MASS_ASSIGNMENT_PAYLOADS) > 0
        assert len(PATH_TRAVERSAL_AUTHZ_PAYLOADS) > 0
        assert len(LOGIN_PATHS) > 0
        assert len(OAUTH_PATHS) > 0
        assert len(PROTECTED_PATHS) > 0
