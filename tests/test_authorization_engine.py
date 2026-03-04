"""
Tests for scanning/modules/authorization_engine.py

Covers:
- Role dataclass
- AuthzTestCase dataclass
- AuthorizationEngine class attributes and constants
- STRONG_EVIDENCE_PATTERNS (compilation + matching)
- WEAK_EVIDENCE_KEYWORDS
- ROLE_INDICATORS
- PRIVESC_PARAMS
- TENANT_PARAMS
- HIDDEN_ADMIN_PATHS
- BYPASS_HEADERS
- PATH_BYPASS_PATTERNS
- Confidence tier constants
"""

import re

import pytest

from scanning.modules.authorization_engine import (
    AuthorizationEngine,
    AuthzTestCase,
    Role,
)


# =============================================================================
# ROLE DATACLASS
# =============================================================================

class TestRoleDataclass:
    def test_required_fields(self):
        role = Role(name="admin", level=10)
        assert role.name == "admin"
        assert role.level == 10

    def test_optional_token_default_none(self):
        role = Role(name="user", level=1)
        assert role.token is None

    def test_optional_token_set(self):
        role = Role(name="admin", level=10, token="Bearer abc123")
        assert role.token == "Bearer abc123"

    def test_session_default_empty_dict(self):
        role = Role(name="guest", level=0)
        assert role.session == {}
        assert isinstance(role.session, dict)

    def test_session_set(self):
        role = Role(name="user", level=1, session={"cookie": "abc"})
        assert role.session == {"cookie": "abc"}

    def test_accessible_endpoints_default_empty_list(self):
        role = Role(name="guest", level=0)
        assert role.accessible_endpoints == []
        assert isinstance(role.accessible_endpoints, list)

    def test_accessible_endpoints_set(self):
        role = Role(name="admin", level=10, accessible_endpoints=["/admin", "/users"])
        assert role.accessible_endpoints == ["/admin", "/users"]

    def test_default_factory_isolation(self):
        """Each Role instance should get its own session dict and endpoints list."""
        role_a = Role(name="a", level=1)
        role_b = Role(name="b", level=2)
        role_a.session["x"] = "1"
        role_a.accessible_endpoints.append("/a")
        assert role_b.session == {}
        assert role_b.accessible_endpoints == []


# =============================================================================
# AUTHZTESTCASE DATACLASS
# =============================================================================

class TestAuthzTestCaseDataclass:
    def test_required_fields(self):
        tc = AuthzTestCase(
            name="vert-escalation",
            source_role="user",
            target_role="admin",
            endpoint="/admin/dashboard",
            method="GET",
            expected_denied=True,
        )
        assert tc.name == "vert-escalation"
        assert tc.source_role == "user"
        assert tc.target_role == "admin"
        assert tc.endpoint == "/admin/dashboard"
        assert tc.method == "GET"
        assert tc.expected_denied is True

    def test_payload_default_none(self):
        tc = AuthzTestCase(
            name="test",
            source_role="user",
            target_role="admin",
            endpoint="/api/users",
            method="POST",
            expected_denied=True,
        )
        assert tc.payload is None

    def test_payload_set(self):
        tc = AuthzTestCase(
            name="test",
            source_role="user",
            target_role="admin",
            endpoint="/api/users",
            method="POST",
            expected_denied=True,
            payload={"role": "admin"},
        )
        assert tc.payload == {"role": "admin"}

    def test_expected_denied_false(self):
        tc = AuthzTestCase(
            name="same-role-access",
            source_role="user",
            target_role="user",
            endpoint="/api/profile",
            method="GET",
            expected_denied=False,
        )
        assert tc.expected_denied is False


# =============================================================================
# AUTHORIZATION ENGINE CLASS BASICS
# =============================================================================

class TestAuthorizationEngineClass:
    def test_name(self):
        assert AuthorizationEngine.name == "authorization_engine"

    def test_is_scan_module(self):
        from scanning.vuln_scanner import ScanModule
        assert issubclass(AuthorizationEngine, ScanModule)


# =============================================================================
# CONFIDENCE TIER CONSTANTS
# =============================================================================

class TestConfidenceTiers:
    def test_tier_1_value(self):
        assert AuthorizationEngine.CONFIDENCE_TIER_1_ACCESSIBLE == 65.0

    def test_tier_2_value(self):
        assert AuthorizationEngine.CONFIDENCE_TIER_2_SENSITIVE == 75.0

    def test_tier_3_value(self):
        assert AuthorizationEngine.CONFIDENCE_TIER_3_EXPLOITABLE == 85.0

    def test_tier_4_value(self):
        assert AuthorizationEngine.CONFIDENCE_TIER_4_IMPACTFUL == 95.0

    def test_tiers_ascending(self):
        """Higher tiers should have higher confidence."""
        assert (
            AuthorizationEngine.CONFIDENCE_TIER_1_ACCESSIBLE
            < AuthorizationEngine.CONFIDENCE_TIER_2_SENSITIVE
            < AuthorizationEngine.CONFIDENCE_TIER_3_EXPLOITABLE
            < AuthorizationEngine.CONFIDENCE_TIER_4_IMPACTFUL
        )

    def test_all_tiers_are_float(self):
        assert isinstance(AuthorizationEngine.CONFIDENCE_TIER_1_ACCESSIBLE, float)
        assert isinstance(AuthorizationEngine.CONFIDENCE_TIER_2_SENSITIVE, float)
        assert isinstance(AuthorizationEngine.CONFIDENCE_TIER_3_EXPLOITABLE, float)
        assert isinstance(AuthorizationEngine.CONFIDENCE_TIER_4_IMPACTFUL, float)


# =============================================================================
# STRONG EVIDENCE PATTERNS
# =============================================================================

class TestStrongEvidencePatterns:
    def test_count(self):
        assert len(AuthorizationEngine.STRONG_EVIDENCE_PATTERNS) == 7

    def test_all_are_strings(self):
        for pattern in AuthorizationEngine.STRONG_EVIDENCE_PATTERNS:
            assert isinstance(pattern, str)

    def test_all_compile(self):
        for pattern in AuthorizationEngine.STRONG_EVIDENCE_PATTERNS:
            compiled = re.compile(pattern, re.IGNORECASE)
            assert compiled is not None

    def test_detects_email(self):
        body = '{"email": "user@example.com"}'
        assert any(
            re.search(p, body, re.IGNORECASE)
            for p in AuthorizationEngine.STRONG_EVIDENCE_PATTERNS
        )

    def test_detects_phone(self):
        body = '{"phone": "555-123-4567"}'
        assert any(
            re.search(p, body, re.IGNORECASE)
            for p in AuthorizationEngine.STRONG_EVIDENCE_PATTERNS
        )

    def test_detects_ssn(self):
        body = '{"ssn": "123-45-6789"}'
        assert any(
            re.search(p, body, re.IGNORECASE)
            for p in AuthorizationEngine.STRONG_EVIDENCE_PATTERNS
        )

    def test_detects_password_in_json(self):
        body = '{"password": "s3cret!"}'
        assert any(
            re.search(p, body, re.IGNORECASE)
            for p in AuthorizationEngine.STRONG_EVIDENCE_PATTERNS
        )

    def test_detects_secret_in_json(self):
        body = '{"secret": "my-secret-value"}'
        assert any(
            re.search(p, body, re.IGNORECASE)
            for p in AuthorizationEngine.STRONG_EVIDENCE_PATTERNS
        )

    def test_detects_api_key_in_json(self):
        body = '{"api_key": "sk-abc123"}'
        assert any(
            re.search(p, body, re.IGNORECASE)
            for p in AuthorizationEngine.STRONG_EVIDENCE_PATTERNS
        )

    def test_detects_api_key_with_dash(self):
        body = '{"api-key": "sk-abc123"}'
        assert any(
            re.search(p, body, re.IGNORECASE)
            for p in AuthorizationEngine.STRONG_EVIDENCE_PATTERNS
        )

    def test_detects_token_in_json(self):
        body = '{"token": "eyJhbGciOiJIUzI1NiJ9"}'
        assert any(
            re.search(p, body, re.IGNORECASE)
            for p in AuthorizationEngine.STRONG_EVIDENCE_PATTERNS
        )

    def test_no_match_benign_content(self):
        body = '{"status": "ok", "version": "1.0.0"}'
        assert not any(
            re.search(p, body, re.IGNORECASE)
            for p in AuthorizationEngine.STRONG_EVIDENCE_PATTERNS
        )


# =============================================================================
# WEAK EVIDENCE KEYWORDS
# =============================================================================

class TestWeakEvidenceKeywords:
    def test_count(self):
        assert len(AuthorizationEngine.WEAK_EVIDENCE_KEYWORDS) == 5

    def test_all_are_strings(self):
        for kw in AuthorizationEngine.WEAK_EVIDENCE_KEYWORDS:
            assert isinstance(kw, str)

    def test_contains_admin(self):
        assert "admin" in AuthorizationEngine.WEAK_EVIDENCE_KEYWORDS

    def test_contains_dashboard(self):
        assert "dashboard" in AuthorizationEngine.WEAK_EVIDENCE_KEYWORDS

    def test_contains_management(self):
        assert "management" in AuthorizationEngine.WEAK_EVIDENCE_KEYWORDS

    def test_contains_users(self):
        assert "users" in AuthorizationEngine.WEAK_EVIDENCE_KEYWORDS

    def test_contains_settings(self):
        assert "settings" in AuthorizationEngine.WEAK_EVIDENCE_KEYWORDS

    def test_all_lowercase(self):
        for kw in AuthorizationEngine.WEAK_EVIDENCE_KEYWORDS:
            assert kw == kw.lower()


# =============================================================================
# ROLE INDICATORS
# =============================================================================

class TestRoleIndicators:
    def test_is_dict(self):
        assert isinstance(AuthorizationEngine.ROLE_INDICATORS, dict)

    def test_has_four_keys(self):
        assert len(AuthorizationEngine.ROLE_INDICATORS) == 4

    def test_has_admin_key(self):
        assert "admin" in AuthorizationEngine.ROLE_INDICATORS

    def test_has_moderator_key(self):
        assert "moderator" in AuthorizationEngine.ROLE_INDICATORS

    def test_has_user_key(self):
        assert "user" in AuthorizationEngine.ROLE_INDICATORS

    def test_has_guest_key(self):
        assert "guest" in AuthorizationEngine.ROLE_INDICATORS

    def test_admin_contains_admin(self):
        assert "admin" in AuthorizationEngine.ROLE_INDICATORS["admin"]

    def test_admin_contains_superuser(self):
        assert "superuser" in AuthorizationEngine.ROLE_INDICATORS["admin"]

    def test_admin_contains_root(self):
        assert "root" in AuthorizationEngine.ROLE_INDICATORS["admin"]

    def test_moderator_contains_manager(self):
        assert "manager" in AuthorizationEngine.ROLE_INDICATORS["moderator"]

    def test_user_contains_customer(self):
        assert "customer" in AuthorizationEngine.ROLE_INDICATORS["user"]

    def test_guest_contains_anonymous(self):
        assert "anonymous" in AuthorizationEngine.ROLE_INDICATORS["guest"]

    def test_guest_contains_visitor(self):
        assert "visitor" in AuthorizationEngine.ROLE_INDICATORS["guest"]

    def test_all_values_are_lists(self):
        for key, value in AuthorizationEngine.ROLE_INDICATORS.items():
            assert isinstance(value, list), f"Value for '{key}' is not a list"

    def test_all_values_are_nonempty(self):
        for key, value in AuthorizationEngine.ROLE_INDICATORS.items():
            assert len(value) > 0, f"Value for '{key}' is empty"


# =============================================================================
# PRIVESC PARAMS
# =============================================================================

class TestPrivescParams:
    def test_count(self):
        assert len(AuthorizationEngine.PRIVESC_PARAMS) >= 18

    def test_all_are_strings(self):
        for param in AuthorizationEngine.PRIVESC_PARAMS:
            assert isinstance(param, str)

    def test_contains_role(self):
        assert "role" in AuthorizationEngine.PRIVESC_PARAMS

    def test_contains_is_admin(self):
        assert "is_admin" in AuthorizationEngine.PRIVESC_PARAMS

    def test_contains_isAdmin(self):
        assert "isAdmin" in AuthorizationEngine.PRIVESC_PARAMS

    def test_contains_admin(self):
        assert "admin" in AuthorizationEngine.PRIVESC_PARAMS

    def test_contains_privilege(self):
        assert "privilege" in AuthorizationEngine.PRIVESC_PARAMS

    def test_contains_permission(self):
        assert "permission" in AuthorizationEngine.PRIVESC_PARAMS

    def test_contains_permissions(self):
        assert "permissions" in AuthorizationEngine.PRIVESC_PARAMS

    def test_contains_access_level(self):
        assert "access_level" in AuthorizationEngine.PRIVESC_PARAMS

    def test_contains_accessLevel(self):
        assert "accessLevel" in AuthorizationEngine.PRIVESC_PARAMS

    def test_contains_user_type(self):
        assert "user_type" in AuthorizationEngine.PRIVESC_PARAMS

    def test_contains_userType(self):
        assert "userType" in AuthorizationEngine.PRIVESC_PARAMS

    def test_contains_group(self):
        assert "group" in AuthorizationEngine.PRIVESC_PARAMS

    def test_contains_groups(self):
        assert "groups" in AuthorizationEngine.PRIVESC_PARAMS

    def test_contains_tier(self):
        assert "tier" in AuthorizationEngine.PRIVESC_PARAMS

    def test_no_duplicates(self):
        assert len(AuthorizationEngine.PRIVESC_PARAMS) == len(set(AuthorizationEngine.PRIVESC_PARAMS))


# =============================================================================
# TENANT PARAMS
# =============================================================================

class TestTenantParams:
    def test_count(self):
        assert len(AuthorizationEngine.TENANT_PARAMS) == 18

    def test_all_are_strings(self):
        for param in AuthorizationEngine.TENANT_PARAMS:
            assert isinstance(param, str)

    def test_contains_tenant_id(self):
        assert "tenant_id" in AuthorizationEngine.TENANT_PARAMS

    def test_contains_tenantId(self):
        assert "tenantId" in AuthorizationEngine.TENANT_PARAMS

    def test_contains_org_id(self):
        assert "org_id" in AuthorizationEngine.TENANT_PARAMS

    def test_contains_orgId(self):
        assert "orgId" in AuthorizationEngine.TENANT_PARAMS

    def test_contains_company_id(self):
        assert "company_id" in AuthorizationEngine.TENANT_PARAMS

    def test_contains_companyId(self):
        assert "companyId" in AuthorizationEngine.TENANT_PARAMS

    def test_contains_account_id(self):
        assert "account_id" in AuthorizationEngine.TENANT_PARAMS

    def test_contains_accountId(self):
        assert "accountId" in AuthorizationEngine.TENANT_PARAMS

    def test_contains_workspace(self):
        assert "workspace" in AuthorizationEngine.TENANT_PARAMS

    def test_contains_workspace_id(self):
        assert "workspace_id" in AuthorizationEngine.TENANT_PARAMS

    def test_contains_team(self):
        assert "team" in AuthorizationEngine.TENANT_PARAMS

    def test_contains_team_id(self):
        assert "team_id" in AuthorizationEngine.TENANT_PARAMS

    def test_contains_teamId(self):
        assert "teamId" in AuthorizationEngine.TENANT_PARAMS

    def test_no_duplicates(self):
        assert len(AuthorizationEngine.TENANT_PARAMS) == len(set(AuthorizationEngine.TENANT_PARAMS))


# =============================================================================
# HIDDEN ADMIN PATHS
# =============================================================================

class TestHiddenAdminPaths:
    def test_count(self):
        assert len(AuthorizationEngine.HIDDEN_ADMIN_PATHS) >= 60

    def test_all_are_strings(self):
        for path in AuthorizationEngine.HIDDEN_ADMIN_PATHS:
            assert isinstance(path, str)

    def test_all_start_with_slash_or_dot(self):
        for path in AuthorizationEngine.HIDDEN_ADMIN_PATHS:
            assert path.startswith("/") or path.startswith("."), (
                f"Path '{path}' does not start with / or ."
            )

    # Spring Boot Actuator
    def test_has_actuator(self):
        assert "/actuator" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_has_actuator_env(self):
        assert "/actuator/env" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_has_actuator_heapdump(self):
        assert "/actuator/heapdump" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_has_actuator_metrics(self):
        assert "/actuator/metrics" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_has_actuator_prometheus(self):
        assert "/actuator/prometheus" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_has_actuator_jolokia(self):
        assert "/actuator/jolokia" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    # Laravel/PHP
    def test_has_telescope(self):
        assert "/telescope" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_has_horizon(self):
        assert "/horizon" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_has_nova(self):
        assert "/nova" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_has_debugbar(self):
        assert "/_debugbar" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_has_clockwork(self):
        assert "/clockwork" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_has_phpinfo(self):
        assert "/phpinfo.php" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    # Django
    def test_has_django_debug(self):
        assert "/__debug__" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_has_silk(self):
        assert "/silk" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    # Node.js
    def test_has_health(self):
        assert "/health" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_has_healthcheck(self):
        assert "/healthcheck" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_has_metrics(self):
        assert "/metrics" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    # General admin
    def test_has_admin(self):
        assert "/admin" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_has_administrator(self):
        assert "/administrator" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_has_wp_admin(self):
        assert "/wp-admin" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_has_dashboard(self):
        assert "/dashboard" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_has_console(self):
        assert "/console" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    # Debug/internal
    def test_has_debug(self):
        assert "/debug" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_has_internal(self):
        assert "/internal" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_has_private(self):
        assert "/private" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    # Swagger/API docs
    def test_has_swagger(self):
        assert "/swagger" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_has_swagger_ui(self):
        assert "/swagger-ui" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_has_api_docs(self):
        assert "/api-docs" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_has_openapi_json(self):
        assert "/openapi.json" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    # GraphQL
    def test_has_graphql(self):
        assert "/graphql" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_has_graphiql(self):
        assert "/graphiql" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_has_playground(self):
        assert "/playground" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    # Config exposure
    def test_has_config(self):
        assert "/config" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_has_env(self):
        assert "/env" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_has_dot_env(self):
        assert "/.env" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_has_config_json(self):
        assert "/config.json" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    # Version control
    def test_has_git_config(self):
        assert "/.git/config" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_has_svn_entries(self):
        assert "/.svn/entries" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_has_hg_store(self):
        assert "/.hg/store" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    # Backup/export
    def test_has_backup(self):
        assert "/backup" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_has_export(self):
        assert "/export" in AuthorizationEngine.HIDDEN_ADMIN_PATHS

    def test_no_duplicates(self):
        paths = AuthorizationEngine.HIDDEN_ADMIN_PATHS
        assert len(paths) == len(set(paths)), "HIDDEN_ADMIN_PATHS contains duplicates"


# =============================================================================
# BYPASS HEADERS
# =============================================================================

class TestBypassHeaders:
    def test_count(self):
        assert len(AuthorizationEngine.BYPASS_HEADERS) >= 13

    def test_all_are_dicts(self):
        for header in AuthorizationEngine.BYPASS_HEADERS:
            assert isinstance(header, dict)

    def test_all_have_exactly_one_key(self):
        for header in AuthorizationEngine.BYPASS_HEADERS:
            assert len(header) == 1, f"Header {header} has {len(header)} keys, expected 1"

    def test_all_keys_are_strings(self):
        for header in AuthorizationEngine.BYPASS_HEADERS:
            for key in header:
                assert isinstance(key, str)

    def test_all_values_are_strings(self):
        for header in AuthorizationEngine.BYPASS_HEADERS:
            for value in header.values():
                assert isinstance(value, str)

    def test_has_x_forwarded_for_127(self):
        assert {"X-Forwarded-For": "127.0.0.1"} in AuthorizationEngine.BYPASS_HEADERS

    def test_has_x_forwarded_for_ipv6(self):
        assert {"X-Forwarded-For": "::1"} in AuthorizationEngine.BYPASS_HEADERS

    def test_has_x_forwarded_host(self):
        assert {"X-Forwarded-Host": "localhost"} in AuthorizationEngine.BYPASS_HEADERS

    def test_has_x_original_url(self):
        assert {"X-Original-URL": "/admin"} in AuthorizationEngine.BYPASS_HEADERS

    def test_has_x_rewrite_url(self):
        assert {"X-Rewrite-URL": "/admin"} in AuthorizationEngine.BYPASS_HEADERS

    def test_has_x_custom_ip_authorization(self):
        assert {"X-Custom-IP-Authorization": "127.0.0.1"} in AuthorizationEngine.BYPASS_HEADERS

    def test_has_x_real_ip(self):
        assert {"X-Real-IP": "127.0.0.1"} in AuthorizationEngine.BYPASS_HEADERS

    def test_has_x_originating_ip(self):
        assert {"X-Originating-IP": "127.0.0.1"} in AuthorizationEngine.BYPASS_HEADERS

    def test_has_x_remote_ip(self):
        assert {"X-Remote-IP": "127.0.0.1"} in AuthorizationEngine.BYPASS_HEADERS

    def test_has_x_client_ip(self):
        assert {"X-Client-IP": "127.0.0.1"} in AuthorizationEngine.BYPASS_HEADERS

    def test_has_x_host(self):
        assert {"X-Host": "localhost"} in AuthorizationEngine.BYPASS_HEADERS

    def test_has_host_localhost(self):
        assert {"Host": "localhost"} in AuthorizationEngine.BYPASS_HEADERS

    def test_has_x_forwarded_proto(self):
        assert {"X-Forwarded-Proto": "https"} in AuthorizationEngine.BYPASS_HEADERS

    def test_has_x_forwarded_scheme(self):
        assert {"X-Forwarded-Scheme": "https"} in AuthorizationEngine.BYPASS_HEADERS


# =============================================================================
# PATH BYPASS PATTERNS
# =============================================================================

class TestPathBypassPatterns:
    def test_count(self):
        assert len(AuthorizationEngine.PATH_BYPASS_PATTERNS) >= 13

    def test_all_are_strings(self):
        for pattern in AuthorizationEngine.PATH_BYPASS_PATTERNS:
            assert isinstance(pattern, str)

    def test_has_trailing_slash(self):
        assert "/" in AuthorizationEngine.PATH_BYPASS_PATTERNS

    def test_has_trailing_dot(self):
        assert "/." in AuthorizationEngine.PATH_BYPASS_PATTERNS

    def test_has_dot_segment(self):
        assert "/./" in AuthorizationEngine.PATH_BYPASS_PATTERNS

    def test_has_double_slash(self):
        assert "//" in AuthorizationEngine.PATH_BYPASS_PATTERNS

    def test_has_parent(self):
        assert "/.." in AuthorizationEngine.PATH_BYPASS_PATTERNS

    def test_has_url_encoded_dot(self):
        assert "%2e" in AuthorizationEngine.PATH_BYPASS_PATTERNS

    def test_has_url_encoded_dot_slash(self):
        assert "%2e/" in AuthorizationEngine.PATH_BYPASS_PATTERNS

    def test_has_query_start(self):
        assert "?" in AuthorizationEngine.PATH_BYPASS_PATTERNS

    def test_has_query_param(self):
        assert "?anything" in AuthorizationEngine.PATH_BYPASS_PATTERNS

    def test_has_fragment(self):
        assert "#" in AuthorizationEngine.PATH_BYPASS_PATTERNS

    def test_has_semicolon(self):
        assert ";" in AuthorizationEngine.PATH_BYPASS_PATTERNS

    def test_has_json_extension(self):
        assert ".json" in AuthorizationEngine.PATH_BYPASS_PATTERNS

    def test_has_html_extension(self):
        assert ".html" in AuthorizationEngine.PATH_BYPASS_PATTERNS
