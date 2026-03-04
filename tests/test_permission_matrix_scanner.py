"""
Tests for scanning/modules/permission_matrix_scanner.py

Covers:
- Permission dataclass (defaults, full creation)
- PermissionTest dataclass (defaults, full creation)
- PERMISSION_PATTERNS list (count, compilable, key matches)
- JWT_PERMISSION_CLAIMS list (count, key entries)
- PERMISSION_ENDPOINTS dict (count, key entries, types)
- PermissionMatrixScanner identity (name, ScanModule subclass)
- _resolve_base_url method (URL resolution logic)
- _extract_jwt_permissions method (JWT decoding)
"""

import base64
import json
import re

import pytest
from scanning.modules.permission_matrix_scanner import (
    Permission,
    PermissionTest,
    PERMISSION_PATTERNS,
    JWT_PERMISSION_CLAIMS,
    PERMISSION_ENDPOINTS,
    PermissionMatrixScanner,
)
from scanning.vuln_scanner import ScanModule


# =============================================================================
# DATACLASS TESTS
# =============================================================================

class TestPermission:
    """Test Permission dataclass."""

    def test_defaults(self):
        perm = Permission(name="read_users")
        assert perm.name == "read_users"
        assert perm.resource == ""
        assert perm.action == ""
        assert perm.scope == ""
        assert perm.source == ""

    def test_full_creation(self):
        perm = Permission(
            name="write_orders",
            resource="orders",
            action="write",
            scope="org",
            source="jwt",
        )
        assert perm.name == "write_orders"
        assert perm.resource == "orders"
        assert perm.action == "write"
        assert perm.scope == "org"
        assert perm.source == "jwt"

    def test_name_required(self):
        with pytest.raises(TypeError):
            Permission()

    def test_different_sources(self):
        for src in ["jwt", "response", "header", "cookie"]:
            perm = Permission(name="test", source=src)
            assert perm.source == src


class TestPermissionTest:
    """Test PermissionTest dataclass."""

    def test_defaults(self):
        pt = PermissionTest(
            permissions=["admin"],
            operator="AND",
            expected_denied=True,
            endpoint="/api/admin",
        )
        assert pt.permissions == ["admin"]
        assert pt.operator == "AND"
        assert pt.expected_denied is True
        assert pt.endpoint == "/api/admin"
        assert pt.method == "GET"

    def test_full_creation(self):
        pt = PermissionTest(
            permissions=["read_users", "write_users"],
            operator="OR",
            expected_denied=False,
            endpoint="/api/users",
            method="POST",
        )
        assert pt.permissions == ["read_users", "write_users"]
        assert pt.operator == "OR"
        assert pt.expected_denied is False
        assert pt.endpoint == "/api/users"
        assert pt.method == "POST"

    def test_operators(self):
        for op in ["AND", "OR", "NOT", "NAND"]:
            pt = PermissionTest(
                permissions=["a"],
                operator=op,
                expected_denied=True,
                endpoint="/test",
            )
            assert pt.operator == op

    def test_multiple_permissions(self):
        pt = PermissionTest(
            permissions=["read", "write", "delete", "admin"],
            operator="AND",
            expected_denied=True,
            endpoint="/test",
        )
        assert len(pt.permissions) == 4


# =============================================================================
# PERMISSION_PATTERNS TESTS
# =============================================================================

class TestPermissionPatterns:
    """Test PERMISSION_PATTERNS list."""

    def test_count(self):
        assert len(PERMISSION_PATTERNS) == 13

    def test_all_compilable(self):
        for pattern in PERMISSION_PATTERNS:
            compiled = re.compile(pattern, re.IGNORECASE)
            assert compiled is not None, f"Pattern failed to compile: {pattern}"

    def test_matches_can_read(self):
        matched = False
        for pattern in PERMISSION_PATTERNS:
            if re.match(pattern, "can_read_users", re.IGNORECASE):
                matched = True
                break
        assert matched, "No pattern matched 'can_read_users'"

    def test_matches_has_write(self):
        matched = False
        for pattern in PERMISSION_PATTERNS:
            if re.match(pattern, "has_write_orders", re.IGNORECASE):
                matched = True
                break
        assert matched, "No pattern matched 'has_write_orders'"

    def test_matches_can_delete(self):
        matched = False
        for pattern in PERMISSION_PATTERNS:
            if re.match(pattern, "can_delete_users", re.IGNORECASE):
                matched = True
                break
        assert matched, "No pattern matched 'can_delete_users'"

    def test_matches_is_admin(self):
        matched = False
        for pattern in PERMISSION_PATTERNS:
            if re.match(pattern, "is_admin", re.IGNORECASE):
                matched = True
                break
        assert matched, "No pattern matched 'is_admin'"

    def test_matches_is_moderator(self):
        matched = False
        for pattern in PERMISSION_PATTERNS:
            if re.match(pattern, "is_moderator", re.IGNORECASE):
                matched = True
                break
        assert matched, "No pattern matched 'is_moderator'"

    def test_matches_is_editor(self):
        matched = False
        for pattern in PERMISSION_PATTERNS:
            if re.match(pattern, "is_editor", re.IGNORECASE):
                matched = True
                break
        assert matched, "No pattern matched 'is_editor'"

    def test_matches_is_viewer(self):
        matched = False
        for pattern in PERMISSION_PATTERNS:
            if re.match(pattern, "is_viewer", re.IGNORECASE):
                matched = True
                break
        assert matched, "No pattern matched 'is_viewer'"

    def test_matches_scope_colon(self):
        matched = False
        for pattern in PERMISSION_PATTERNS:
            if re.match(pattern, "users:read", re.IGNORECASE):
                matched = True
                break
        assert matched, "No pattern matched 'users:read'"

    def test_matches_scope_prefix(self):
        matched = False
        for pattern in PERMISSION_PATTERNS:
            if re.match(pattern, "scope:admin", re.IGNORECASE):
                matched = True
                break
        assert matched, "No pattern matched 'scope:admin'"

    def test_matches_feature_flag(self):
        matched = False
        for pattern in PERMISSION_PATTERNS:
            if re.match(pattern, "feature_dashboard", re.IGNORECASE):
                matched = True
                break
        assert matched, "No pattern matched 'feature_dashboard'"

    def test_matches_beta_flag(self):
        matched = False
        for pattern in PERMISSION_PATTERNS:
            if re.match(pattern, "beta_analytics", re.IGNORECASE):
                matched = True
                break
        assert matched, "No pattern matched 'beta_analytics'"

    def test_matches_enabled_flag(self):
        matched = False
        for pattern in PERMISSION_PATTERNS:
            if re.match(pattern, "mfa_enabled", re.IGNORECASE):
                matched = True
                break
        assert matched, "No pattern matched 'mfa_enabled'"

    def test_matches_can_update(self):
        matched = False
        for pattern in PERMISSION_PATTERNS:
            if re.match(pattern, "can_update_profile", re.IGNORECASE):
                matched = True
                break
        assert matched, "No pattern matched 'can_update_profile'"

    def test_all_strings(self):
        for pattern in PERMISSION_PATTERNS:
            assert isinstance(pattern, str)


# =============================================================================
# JWT_PERMISSION_CLAIMS TESTS
# =============================================================================

class TestJwtPermissionClaims:
    """Test JWT_PERMISSION_CLAIMS list."""

    def test_count(self):
        assert len(JWT_PERMISSION_CLAIMS) == 15

    def test_all_strings(self):
        for claim in JWT_PERMISSION_CLAIMS:
            assert isinstance(claim, str)

    def test_has_permissions(self):
        assert "permissions" in JWT_PERMISSION_CLAIMS

    def test_has_perms(self):
        assert "perms" in JWT_PERMISSION_CLAIMS

    def test_has_scopes(self):
        assert "scopes" in JWT_PERMISSION_CLAIMS

    def test_has_scope(self):
        assert "scope" in JWT_PERMISSION_CLAIMS

    def test_has_roles(self):
        assert "roles" in JWT_PERMISSION_CLAIMS

    def test_has_role(self):
        assert "role" in JWT_PERMISSION_CLAIMS

    def test_has_groups(self):
        assert "groups" in JWT_PERMISSION_CLAIMS

    def test_has_authorities(self):
        assert "authorities" in JWT_PERMISSION_CLAIMS

    def test_has_grants(self):
        assert "grants" in JWT_PERMISSION_CLAIMS

    def test_has_access(self):
        assert "access" in JWT_PERMISSION_CLAIMS

    def test_has_rights(self):
        assert "rights" in JWT_PERMISSION_CLAIMS

    def test_has_capabilities(self):
        assert "capabilities" in JWT_PERMISSION_CLAIMS

    def test_has_features(self):
        assert "features" in JWT_PERMISSION_CLAIMS

    def test_has_flags(self):
        assert "flags" in JWT_PERMISSION_CLAIMS

    def test_has_claims(self):
        assert "claims" in JWT_PERMISSION_CLAIMS

    def test_all_unique(self):
        assert len(JWT_PERMISSION_CLAIMS) == len(set(JWT_PERMISSION_CLAIMS))

    def test_all_lowercase(self):
        for claim in JWT_PERMISSION_CLAIMS:
            assert claim == claim.lower(), f"Claim should be lowercase: {claim}"


# =============================================================================
# PERMISSION_ENDPOINTS TESTS
# =============================================================================

class TestPermissionEndpoints:
    """Test PERMISSION_ENDPOINTS dict."""

    def test_count(self):
        assert len(PERMISSION_ENDPOINTS) == 8

    def test_is_dict(self):
        assert isinstance(PERMISSION_ENDPOINTS, dict)

    def test_has_admin(self):
        assert "admin" in PERMISSION_ENDPOINTS

    def test_has_users(self):
        assert "users" in PERMISSION_ENDPOINTS

    def test_has_delete(self):
        assert "delete" in PERMISSION_ENDPOINTS

    def test_has_write(self):
        assert "write" in PERMISSION_ENDPOINTS

    def test_has_billing(self):
        assert "billing" in PERMISSION_ENDPOINTS

    def test_has_settings(self):
        assert "settings" in PERMISSION_ENDPOINTS

    def test_has_reports(self):
        assert "reports" in PERMISSION_ENDPOINTS

    def test_has_audit(self):
        assert "audit" in PERMISSION_ENDPOINTS

    def test_admin_endpoints(self):
        admin = PERMISSION_ENDPOINTS["admin"]
        assert "/admin" in admin
        assert "/api/admin" in admin
        assert "/management" in admin
        assert "/system" in admin

    def test_users_endpoints(self):
        users = PERMISSION_ENDPOINTS["users"]
        assert "/api/users" in users
        assert "/users" in users

    def test_billing_endpoints(self):
        billing = PERMISSION_ENDPOINTS["billing"]
        assert "/api/billing" in billing
        assert "/api/payments" in billing
        assert "/api/invoices" in billing
        assert "/api/subscriptions" in billing

    def test_audit_endpoints(self):
        audit = PERMISSION_ENDPOINTS["audit"]
        assert "/api/audit" in audit
        assert "/api/logs" in audit
        assert "/api/activity" in audit

    def test_all_values_are_lists(self):
        for key, value in PERMISSION_ENDPOINTS.items():
            assert isinstance(value, list), f"Value for '{key}' should be a list"

    def test_all_endpoints_are_strings(self):
        for key, endpoints in PERMISSION_ENDPOINTS.items():
            for ep in endpoints:
                assert isinstance(ep, str), f"Endpoint in '{key}' should be a string"

    def test_all_endpoints_start_with_slash(self):
        for key, endpoints in PERMISSION_ENDPOINTS.items():
            for ep in endpoints:
                assert ep.startswith("/"), f"Endpoint '{ep}' in '{key}' should start with /"

    def test_all_lists_non_empty(self):
        for key, endpoints in PERMISSION_ENDPOINTS.items():
            assert len(endpoints) > 0, f"Endpoint list for '{key}' should not be empty"


# =============================================================================
# SCANNER IDENTITY TESTS
# =============================================================================

class TestPermissionMatrixScannerIdentity:
    """Test PermissionMatrixScanner class identity and attributes."""

    def test_is_scan_module_subclass(self):
        assert issubclass(PermissionMatrixScanner, ScanModule)

    def test_name_attribute(self):
        assert PermissionMatrixScanner.name == "permission_matrix"

    def test_description_attribute(self):
        assert PermissionMatrixScanner.description is not None
        assert len(PermissionMatrixScanner.description) > 0

    def test_version_attribute(self):
        assert PermissionMatrixScanner.version == "1.0.0"

    def test_author_attribute(self):
        assert PermissionMatrixScanner.author == "PHANTOM AI"

    def test_tags_attribute(self):
        tags = PermissionMatrixScanner.tags
        assert isinstance(tags, list)
        assert "permissions" in tags
        assert "authorization" in tags
        assert "rbac" in tags
        assert "abac" in tags
        assert "access_control" in tags

    def test_tags_count(self):
        assert len(PermissionMatrixScanner.tags) == 5

    def test_min_safety_level(self):
        assert PermissionMatrixScanner.min_safety_level == "standard"

    def test_instantiation(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = PermissionMatrixScanner(settings)
        assert scanner is not None

    def test_instance_base_url_default(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = PermissionMatrixScanner(settings)
        assert scanner._base_url == ""

    def test_instance_auth_headers_default(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = PermissionMatrixScanner(settings)
        assert scanner._auth_headers == {}

    def test_instance_discovered_permissions_default(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = PermissionMatrixScanner(settings)
        assert scanner._discovered_permissions == []

    def test_instance_endpoint_permissions_default(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = PermissionMatrixScanner(settings)
        assert len(scanner._endpoint_permissions) == 0


# =============================================================================
# _resolve_base_url TESTS
# =============================================================================

class TestResolveBaseUrl:
    """Test _resolve_base_url method."""

    def setup_method(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        self.scanner = PermissionMatrixScanner(settings)

    def test_http_url_passthrough(self):
        result = self.scanner._resolve_base_url("http://example.com", None)
        assert result == "http://example.com"

    def test_https_url_passthrough(self):
        result = self.scanner._resolve_base_url("https://example.com", None)
        assert result == "https://example.com"

    def test_trailing_slash_stripped(self):
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

    def test_custom_port_included(self):
        result = self.scanner._resolve_base_url("example.com", 8080)
        assert result == "http://example.com:8080"

    def test_no_port_uses_http(self):
        result = self.scanner._resolve_base_url("example.com", None)
        assert result == "http://example.com"


# =============================================================================
# _extract_jwt_permissions TESTS
# =============================================================================

class TestExtractJwtPermissions:
    """Test _extract_jwt_permissions method."""

    def setup_method(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        self.scanner = PermissionMatrixScanner(settings)
        self.scanner._discovered_permissions = []

    def _make_jwt(self, payload: dict) -> str:
        """Create a minimal JWT token with the given payload."""
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        body = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b"=").decode()
        sig = base64.urlsafe_b64encode(b"fakesig").rstrip(b"=").decode()
        return f"{header}.{body}.{sig}"

    def test_invalid_jwt_no_dots(self):
        self.scanner._extract_jwt_permissions("notajwt")
        assert len(self.scanner._discovered_permissions) == 0

    def test_invalid_jwt_two_dots(self):
        self.scanner._extract_jwt_permissions("a.b")
        assert len(self.scanner._discovered_permissions) == 0

    def test_empty_payload(self):
        token = self._make_jwt({})
        self.scanner._extract_jwt_permissions(token)
        assert len(self.scanner._discovered_permissions) == 0

    def test_permissions_list(self):
        token = self._make_jwt({"permissions": ["read:users", "write:orders"]})
        self.scanner._extract_jwt_permissions(token)
        names = [p.name for p in self.scanner._discovered_permissions]
        assert "read:users" in names
        assert "write:orders" in names

    def test_permissions_string_comma_separated(self):
        token = self._make_jwt({"permissions": "read:users,write:orders"})
        self.scanner._extract_jwt_permissions(token)
        names = [p.name for p in self.scanner._discovered_permissions]
        assert "read:users" in names
        assert "write:orders" in names

    def test_permissions_string_space_separated(self):
        token = self._make_jwt({"scope": "openid profile email"})
        self.scanner._extract_jwt_permissions(token)
        names = [p.name for p in self.scanner._discovered_permissions]
        assert "openid" in names
        assert "profile" in names
        assert "email" in names

    def test_role_claim_string(self):
        token = self._make_jwt({"role": "admin"})
        self.scanner._extract_jwt_permissions(token)
        names = [p.name for p in self.scanner._discovered_permissions]
        assert "role:admin" in names

    def test_roles_claim_list(self):
        token = self._make_jwt({"roles": ["admin", "editor"]})
        self.scanner._extract_jwt_permissions(token)
        names = [p.name for p in self.scanner._discovered_permissions]
        assert "role:admin" in names
        assert "role:editor" in names

    def test_groups_claim(self):
        token = self._make_jwt({"groups": ["staff", "dev"]})
        self.scanner._extract_jwt_permissions(token)
        names = [p.name for p in self.scanner._discovered_permissions]
        assert "role:staff" in names
        assert "role:dev" in names

    def test_source_is_jwt(self):
        token = self._make_jwt({"permissions": ["admin"]})
        self.scanner._extract_jwt_permissions(token)
        for perm in self.scanner._discovered_permissions:
            assert perm.source == "jwt"

    def test_multiple_claim_types(self):
        token = self._make_jwt({
            "permissions": ["read"],
            "roles": ["admin"],
            "scope": "openid",
        })
        self.scanner._extract_jwt_permissions(token)
        assert len(self.scanner._discovered_permissions) >= 3

    def test_empty_string_permission_skipped(self):
        token = self._make_jwt({"permissions": ["", "admin", ""]})
        self.scanner._extract_jwt_permissions(token)
        names = [p.name for p in self.scanner._discovered_permissions]
        assert "" not in names
        assert "admin" in names

    def test_non_list_non_string_skipped(self):
        token = self._make_jwt({"permissions": 12345})
        self.scanner._extract_jwt_permissions(token)
        assert len(self.scanner._discovered_permissions) == 0
