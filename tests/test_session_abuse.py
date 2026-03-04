"""
Tests for scanning/modules/session_abuse_scanner.py

Covers:
- Module-level endpoint path lists (counts, key entries, types)
- ROLE_CLAIM_NAMES list
- ESCALATION_VALUES dict (keys, value types, coverage)
- SESSION_COOKIE_NAMES list
- PASSWORD_CHANGE_BODIES list (count, callable)
- SessionAbuseScanner class identity (name, ScanModule subclass)
- SessionAbuseScanner._extract_user_id (static logic)
- SessionAbuseScanner._find_role_claims (static logic)
- SessionAbuseScanner._is_real_data (static logic)
- SessionAbuseScanner._get_jwt_exp_info (static logic)
- _deep_set helper function
"""

import pytest
from unittest.mock import MagicMock

from scanning.modules.session_abuse_scanner import (
    GENERIC_WHOAMI_PATHS,
    GENERIC_LOGOUT_PATHS,
    GENERIC_ADMIN_PATHS,
    GENERIC_PASSWORD_CHANGE_PATHS,
    GENERIC_LOGIN_PATHS,
    GENERIC_REFRESH_PATHS,
    GENERIC_SESSIONS_PATHS,
    ROLE_CLAIM_NAMES,
    ESCALATION_VALUES,
    SESSION_COOKIE_NAMES,
    PASSWORD_CHANGE_BODIES,
    SessionAbuseScanner,
    _deep_set,
)
from scanning.vuln_scanner import ScanModule


# =============================================================================
# GENERIC ENDPOINT PATH LISTS
# =============================================================================

class TestGenericWhoamiPaths:
    """Tests for GENERIC_WHOAMI_PATHS list."""

    def test_count(self):
        assert len(GENERIC_WHOAMI_PATHS) == 14

    def test_not_empty(self):
        assert len(GENERIC_WHOAMI_PATHS) > 0

    def test_all_start_with_slash(self):
        for path in GENERIC_WHOAMI_PATHS:
            assert path.startswith("/"), f"Path should start with /: {path}"

    def test_all_are_strings(self):
        for path in GENERIC_WHOAMI_PATHS:
            assert isinstance(path, str)

    def test_no_duplicates(self):
        assert len(GENERIC_WHOAMI_PATHS) == len(set(GENERIC_WHOAMI_PATHS))

    def test_has_api_me(self):
        assert "/api/me" in GENERIC_WHOAMI_PATHS

    def test_has_api_user(self):
        assert "/api/user" in GENERIC_WHOAMI_PATHS

    def test_has_api_profile(self):
        assert "/api/profile" in GENERIC_WHOAMI_PATHS

    def test_has_api_account(self):
        assert "/api/account" in GENERIC_WHOAMI_PATHS

    def test_has_rest_user_whoami(self):
        assert "/rest/user/whoami" in GENERIC_WHOAMI_PATHS

    def test_has_userinfo(self):
        assert "/userinfo" in GENERIC_WHOAMI_PATHS

    def test_has_me(self):
        assert "/me" in GENERIC_WHOAMI_PATHS


class TestGenericLogoutPaths:
    """Tests for GENERIC_LOGOUT_PATHS list."""

    def test_count(self):
        assert len(GENERIC_LOGOUT_PATHS) == 12

    def test_not_empty(self):
        assert len(GENERIC_LOGOUT_PATHS) > 0

    def test_all_start_with_slash(self):
        for path in GENERIC_LOGOUT_PATHS:
            assert path.startswith("/"), f"Path should start with /: {path}"

    def test_no_duplicates(self):
        assert len(GENERIC_LOGOUT_PATHS) == len(set(GENERIC_LOGOUT_PATHS))

    def test_has_logout(self):
        assert "/logout" in GENERIC_LOGOUT_PATHS

    def test_has_signout(self):
        assert "/signout" in GENERIC_LOGOUT_PATHS

    def test_has_api_logout(self):
        assert "/api/logout" in GENERIC_LOGOUT_PATHS

    def test_has_api_auth_logout(self):
        assert "/api/auth/logout" in GENERIC_LOGOUT_PATHS

    def test_has_session_destroy(self):
        assert "/session/destroy" in GENERIC_LOGOUT_PATHS

    def test_has_oauth_revoke(self):
        assert "/oauth/revoke" in GENERIC_LOGOUT_PATHS


class TestGenericAdminPaths:
    """Tests for GENERIC_ADMIN_PATHS list."""

    def test_count(self):
        assert len(GENERIC_ADMIN_PATHS) == 12

    def test_not_empty(self):
        assert len(GENERIC_ADMIN_PATHS) > 0

    def test_all_start_with_slash(self):
        for path in GENERIC_ADMIN_PATHS:
            assert path.startswith("/"), f"Path should start with /: {path}"

    def test_no_duplicates(self):
        assert len(GENERIC_ADMIN_PATHS) == len(set(GENERIC_ADMIN_PATHS))

    def test_has_api_admin(self):
        assert "/api/admin" in GENERIC_ADMIN_PATHS

    def test_has_api_users(self):
        assert "/api/users" in GENERIC_ADMIN_PATHS

    def test_has_rest_admin_config(self):
        assert "/rest/admin/application-configuration" in GENERIC_ADMIN_PATHS

    def test_has_management_users(self):
        assert "/management/users" in GENERIC_ADMIN_PATHS


class TestGenericPasswordChangePaths:
    """Tests for GENERIC_PASSWORD_CHANGE_PATHS list."""

    def test_count(self):
        assert len(GENERIC_PASSWORD_CHANGE_PATHS) == 9

    def test_not_empty(self):
        assert len(GENERIC_PASSWORD_CHANGE_PATHS) > 0

    def test_all_start_with_slash(self):
        for path in GENERIC_PASSWORD_CHANGE_PATHS:
            assert path.startswith("/"), f"Path should start with /: {path}"

    def test_no_duplicates(self):
        assert len(GENERIC_PASSWORD_CHANGE_PATHS) == len(set(GENERIC_PASSWORD_CHANGE_PATHS))

    def test_has_api_user_change_password(self):
        assert "/api/user/change-password" in GENERIC_PASSWORD_CHANGE_PATHS

    def test_has_rest_user_change_password(self):
        assert "/rest/user/change-password" in GENERIC_PASSWORD_CHANGE_PATHS

    def test_has_api_account_password(self):
        assert "/api/account/password" in GENERIC_PASSWORD_CHANGE_PATHS


class TestGenericLoginPaths:
    """Tests for GENERIC_LOGIN_PATHS list."""

    def test_count(self):
        assert len(GENERIC_LOGIN_PATHS) == 7

    def test_not_empty(self):
        assert len(GENERIC_LOGIN_PATHS) > 0

    def test_all_start_with_slash(self):
        for path in GENERIC_LOGIN_PATHS:
            assert path.startswith("/"), f"Path should start with /: {path}"

    def test_no_duplicates(self):
        assert len(GENERIC_LOGIN_PATHS) == len(set(GENERIC_LOGIN_PATHS))

    def test_has_rest_user_login(self):
        assert "/rest/user/login" in GENERIC_LOGIN_PATHS

    def test_has_api_login(self):
        assert "/api/login" in GENERIC_LOGIN_PATHS

    def test_has_login(self):
        assert "/login" in GENERIC_LOGIN_PATHS

    def test_has_auth_login(self):
        assert "/auth/login" in GENERIC_LOGIN_PATHS


class TestGenericRefreshPaths:
    """Tests for GENERIC_REFRESH_PATHS list."""

    def test_count(self):
        assert len(GENERIC_REFRESH_PATHS) == 13

    def test_not_empty(self):
        assert len(GENERIC_REFRESH_PATHS) > 0

    def test_all_start_with_slash(self):
        for path in GENERIC_REFRESH_PATHS:
            assert path.startswith("/"), f"Path should start with /: {path}"

    def test_no_duplicates(self):
        assert len(GENERIC_REFRESH_PATHS) == len(set(GENERIC_REFRESH_PATHS))

    def test_has_api_token_refresh(self):
        assert "/api/token/refresh" in GENERIC_REFRESH_PATHS

    def test_has_oauth_token(self):
        assert "/oauth/token" in GENERIC_REFRESH_PATHS

    def test_has_refresh(self):
        assert "/refresh" in GENERIC_REFRESH_PATHS


class TestGenericSessionsPaths:
    """Tests for GENERIC_SESSIONS_PATHS list."""

    def test_count(self):
        assert len(GENERIC_SESSIONS_PATHS) == 8

    def test_not_empty(self):
        assert len(GENERIC_SESSIONS_PATHS) > 0

    def test_all_start_with_slash(self):
        for path in GENERIC_SESSIONS_PATHS:
            assert path.startswith("/"), f"Path should start with /: {path}"

    def test_no_duplicates(self):
        assert len(GENERIC_SESSIONS_PATHS) == len(set(GENERIC_SESSIONS_PATHS))

    def test_has_api_sessions(self):
        assert "/api/sessions" in GENERIC_SESSIONS_PATHS

    def test_has_api_user_sessions(self):
        assert "/api/user/sessions" in GENERIC_SESSIONS_PATHS

    def test_has_api_me_sessions(self):
        assert "/api/me/sessions" in GENERIC_SESSIONS_PATHS


# =============================================================================
# ROLE_CLAIM_NAMES
# =============================================================================

class TestRoleClaimNames:
    """Tests for ROLE_CLAIM_NAMES list."""

    def test_count(self):
        assert len(ROLE_CLAIM_NAMES) == 15

    def test_not_empty(self):
        assert len(ROLE_CLAIM_NAMES) > 0

    def test_all_are_strings(self):
        for name in ROLE_CLAIM_NAMES:
            assert isinstance(name, str)

    def test_no_duplicates(self):
        assert len(ROLE_CLAIM_NAMES) == len(set(ROLE_CLAIM_NAMES))

    def test_has_role(self):
        assert "role" in ROLE_CLAIM_NAMES

    def test_has_roles(self):
        assert "roles" in ROLE_CLAIM_NAMES

    def test_has_admin(self):
        assert "admin" in ROLE_CLAIM_NAMES

    def test_has_is_admin(self):
        assert "is_admin" in ROLE_CLAIM_NAMES

    def test_has_isAdmin(self):
        assert "isAdmin" in ROLE_CLAIM_NAMES

    def test_has_scope(self):
        assert "scope" in ROLE_CLAIM_NAMES

    def test_has_scopes(self):
        assert "scopes" in ROLE_CLAIM_NAMES

    def test_has_permissions(self):
        assert "permissions" in ROLE_CLAIM_NAMES

    def test_has_groups(self):
        assert "groups" in ROLE_CLAIM_NAMES

    def test_has_level(self):
        assert "level" in ROLE_CLAIM_NAMES

    def test_has_user_type(self):
        assert "user_type" in ROLE_CLAIM_NAMES

    def test_has_userType(self):
        assert "userType" in ROLE_CLAIM_NAMES

    def test_has_privilege(self):
        assert "privilege" in ROLE_CLAIM_NAMES

    def test_has_access_level(self):
        assert "access_level" in ROLE_CLAIM_NAMES


# =============================================================================
# ESCALATION_VALUES
# =============================================================================

class TestEscalationValues:
    """Tests for ESCALATION_VALUES dict."""

    def test_is_dict(self):
        assert isinstance(ESCALATION_VALUES, dict)

    def test_key_count(self):
        assert len(ESCALATION_VALUES) == 15

    def test_all_keys_are_strings(self):
        for key in ESCALATION_VALUES:
            assert isinstance(key, str)

    def test_all_values_are_lists(self):
        for key, val in ESCALATION_VALUES.items():
            assert isinstance(val, list), f"ESCALATION_VALUES[{key!r}] should be a list"

    def test_no_empty_values(self):
        for key, val in ESCALATION_VALUES.items():
            assert len(val) > 0, f"ESCALATION_VALUES[{key!r}] should not be empty"

    def test_every_role_claim_has_escalation(self):
        """Every entry in ROLE_CLAIM_NAMES that has an exact key in ESCALATION_VALUES."""
        # Not all role claims must have entries (e.g., 'type' is generic),
        # but the primary ones should
        for key in ["role", "roles", "admin", "is_admin", "isAdmin", "scope",
                     "permissions", "groups", "level"]:
            assert key in ESCALATION_VALUES, f"{key} should be in ESCALATION_VALUES"

    def test_role_has_admin_value(self):
        assert "admin" in ESCALATION_VALUES["role"]

    def test_admin_has_true_value(self):
        assert True in ESCALATION_VALUES["admin"]

    def test_is_admin_has_true_value(self):
        assert True in ESCALATION_VALUES["is_admin"]

    def test_level_has_numeric_values(self):
        for val in ESCALATION_VALUES["level"]:
            assert isinstance(val, int)

    def test_roles_has_list_values(self):
        """roles escalation values should be lists of lists."""
        for val in ESCALATION_VALUES["roles"]:
            assert isinstance(val, list)

    def test_permissions_has_list_values(self):
        for val in ESCALATION_VALUES["permissions"]:
            assert isinstance(val, list)

    def test_groups_has_list_values(self):
        for val in ESCALATION_VALUES["groups"]:
            assert isinstance(val, list)

    def test_scope_has_admin_wildcard(self):
        assert "*" in ESCALATION_VALUES["scope"]

    def test_privilege_has_admin(self):
        assert "admin" in ESCALATION_VALUES["privilege"]


# =============================================================================
# SESSION_COOKIE_NAMES
# =============================================================================

class TestSessionCookieNames:
    """Tests for SESSION_COOKIE_NAMES list."""

    def test_count(self):
        assert len(SESSION_COOKIE_NAMES) == 16

    def test_not_empty(self):
        assert len(SESSION_COOKIE_NAMES) > 0

    def test_all_are_strings(self):
        for name in SESSION_COOKIE_NAMES:
            assert isinstance(name, str)

    def test_has_connect_sid(self):
        assert "connect.sid" in SESSION_COOKIE_NAMES

    def test_has_phpsessid(self):
        assert "PHPSESSID" in SESSION_COOKIE_NAMES

    def test_has_jsessionid(self):
        assert "JSESSIONID" in SESSION_COOKIE_NAMES

    def test_has_session(self):
        assert "session" in SESSION_COOKIE_NAMES

    def test_has_aspnet_sessionid(self):
        assert "ASP.NET_SessionId" in SESSION_COOKIE_NAMES

    def test_has_laravel_session(self):
        assert "laravel_session" in SESSION_COOKIE_NAMES

    def test_has_flask_session(self):
        assert "flask_session" in SESSION_COOKIE_NAMES

    def test_has_ci_session(self):
        assert "ci_session" in SESSION_COOKIE_NAMES

    def test_has_token(self):
        assert "token" in SESSION_COOKIE_NAMES


# =============================================================================
# PASSWORD_CHANGE_BODIES
# =============================================================================

class TestPasswordChangeBodies:
    """Tests for PASSWORD_CHANGE_BODIES list."""

    def test_count(self):
        assert len(PASSWORD_CHANGE_BODIES) == 5

    def test_not_empty(self):
        assert len(PASSWORD_CHANGE_BODIES) > 0

    def test_all_are_callable(self):
        for body_fn in PASSWORD_CHANGE_BODIES:
            assert callable(body_fn)

    def test_all_return_dicts(self):
        for body_fn in PASSWORD_CHANGE_BODIES:
            result = body_fn("old_pass", "new_pass")
            assert isinstance(result, dict), "Each body function should return a dict"

    def test_all_contain_new_password(self):
        """Each body function should include the new password in the dict."""
        for i, body_fn in enumerate(PASSWORD_CHANGE_BODIES):
            result = body_fn("old_pass", "new_pass")
            values = list(result.values())
            assert "new_pass" in values, (
                f"PASSWORD_CHANGE_BODIES[{i}] result should contain the new password"
            )

    def test_first_body_format(self):
        result = PASSWORD_CHANGE_BODIES[0]("old_pass", "new_pass")
        assert "password" in result
        assert "current" in result

    def test_second_body_format(self):
        result = PASSWORD_CHANGE_BODIES[1]("old_pass", "new_pass")
        assert "old_password" in result
        assert "new_password" in result

    def test_third_body_format(self):
        result = PASSWORD_CHANGE_BODIES[2]("old_pass", "new_pass")
        assert "currentPassword" in result
        assert "newPassword" in result

    def test_fourth_body_format(self):
        result = PASSWORD_CHANGE_BODIES[3]("old_pass", "new_pass")
        assert "current" in result
        assert "new" in result
        assert "repeat" in result

    def test_fifth_body_format(self):
        result = PASSWORD_CHANGE_BODIES[4]("old_pass", "new_pass")
        assert "oldPassword" in result
        assert "newPassword" in result
        assert "confirmPassword" in result


# =============================================================================
# SCANNER IDENTITY
# =============================================================================

class TestSessionAbuseScannerIdentity:
    """Tests for SessionAbuseScanner class identity."""

    def test_is_subclass_of_scan_module(self):
        assert issubclass(SessionAbuseScanner, ScanModule)

    def test_name_attribute(self):
        assert SessionAbuseScanner.name == "session_abuse"

    def test_instantiation_with_mock_settings(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = SessionAbuseScanner(settings)
        assert scanner is not None

    def test_name_on_instance(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = SessionAbuseScanner(settings)
        assert scanner.name == "session_abuse"

    def test_discovered_dict_initialized_empty(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = SessionAbuseScanner(settings)
        assert scanner._discovered == {}

    def test_cracked_secret_initialized_none(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = SessionAbuseScanner(settings)
        assert scanner._cracked_secret is None

    def test_role_escalation_proved_initialized_false(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = SessionAbuseScanner(settings)
        assert scanner._role_escalation_proved is False

    def test_has_scan_method(self):
        assert hasattr(SessionAbuseScanner, "scan")
        assert callable(getattr(SessionAbuseScanner, "scan"))

    def test_has_extract_user_id_method(self):
        assert hasattr(SessionAbuseScanner, "_extract_user_id")

    def test_has_find_role_claims_method(self):
        assert hasattr(SessionAbuseScanner, "_find_role_claims")

    def test_has_get_jwt_exp_info_method(self):
        assert hasattr(SessionAbuseScanner, "_get_jwt_exp_info")

    def test_has_is_real_data_method(self):
        assert hasattr(SessionAbuseScanner, "_is_real_data")


# =============================================================================
# _extract_user_id LOGIC
# =============================================================================

class TestExtractUserId:
    """Tests for SessionAbuseScanner._extract_user_id method."""

    def _make_scanner(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        return SessionAbuseScanner(settings)

    def test_returns_none_for_empty_dict(self):
        scanner = self._make_scanner()
        assert scanner._extract_user_id({}) is None

    def test_returns_none_for_none(self):
        scanner = self._make_scanner()
        assert scanner._extract_user_id(None) is None

    def test_extracts_id_field(self):
        scanner = self._make_scanner()
        result = scanner._extract_user_id({"id": 123, "email": "a@b.com"})
        assert result == "123"

    def test_extracts_user_id_field(self):
        scanner = self._make_scanner()
        result = scanner._extract_user_id({"user_id": "abc-def"})
        assert result == "abc-def"

    def test_extracts_userId_field(self):
        scanner = self._make_scanner()
        result = scanner._extract_user_id({"userId": 456})
        assert result == "456"

    def test_extracts_uid_field(self):
        scanner = self._make_scanner()
        result = scanner._extract_user_id({"uid": "u100"})
        assert result == "u100"

    def test_extracts_sub_field(self):
        scanner = self._make_scanner()
        result = scanner._extract_user_id({"sub": "auth0|12345"})
        assert result == "auth0|12345"

    def test_extracts_email_when_no_id(self):
        scanner = self._make_scanner()
        result = scanner._extract_user_id({"email": "user@example.com", "name": "Test"})
        assert result == "user@example.com"

    def test_extracts_username_when_no_id_or_email(self):
        scanner = self._make_scanner()
        result = scanner._extract_user_id({"username": "johndoe"})
        assert result == "johndoe"

    def test_extracts_from_nested_user_object(self):
        scanner = self._make_scanner()
        result = scanner._extract_user_id({"status": "ok", "user": {"id": 789}})
        assert result == "789"

    def test_extracts_from_nested_data_object(self):
        scanner = self._make_scanner()
        result = scanner._extract_user_id({"data": {"email": "nested@test.com"}})
        assert result == "nested@test.com"

    def test_extracts_from_nested_profile_object(self):
        scanner = self._make_scanner()
        result = scanner._extract_user_id({"profile": {"id": 42}})
        assert result == "42"

    def test_priority_order_id_over_email(self):
        """id field should be preferred over email."""
        scanner = self._make_scanner()
        result = scanner._extract_user_id({"id": 1, "email": "e@e.com"})
        assert result == "1"

    def test_skips_falsy_values(self):
        scanner = self._make_scanner()
        result = scanner._extract_user_id({"id": 0, "email": "e@e.com"})
        assert result == "e@e.com"


# =============================================================================
# _find_role_claims LOGIC
# =============================================================================

class TestFindRoleClaims:
    """Tests for SessionAbuseScanner._find_role_claims method."""

    def _make_scanner(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        return SessionAbuseScanner(settings)

    def test_returns_empty_for_no_claims(self):
        scanner = self._make_scanner()
        result = scanner._find_role_claims({"sub": "123", "name": "user"})
        assert result == []

    def test_finds_top_level_role(self):
        scanner = self._make_scanner()
        result = scanner._find_role_claims({"role": "user", "sub": "123"})
        assert ("role", "user") in result

    def test_finds_top_level_admin(self):
        scanner = self._make_scanner()
        result = scanner._find_role_claims({"admin": False})
        assert ("admin", False) in result

    def test_finds_top_level_isAdmin(self):
        scanner = self._make_scanner()
        result = scanner._find_role_claims({"isAdmin": True})
        assert ("isAdmin", True) in result

    def test_finds_multiple_claims(self):
        scanner = self._make_scanner()
        result = scanner._find_role_claims({"role": "user", "admin": False, "level": 1})
        assert len(result) == 3

    def test_finds_nested_claim_in_data(self):
        scanner = self._make_scanner()
        result = scanner._find_role_claims({"data": {"role": "customer"}})
        assert ("data.role", "customer") in result

    def test_finds_nested_claim_in_user(self):
        scanner = self._make_scanner()
        result = scanner._find_role_claims({"user": {"admin": True}})
        assert ("user.admin", True) in result

    def test_finds_nested_claim_in_realm_access(self):
        scanner = self._make_scanner()
        result = scanner._find_role_claims({"realm_access": {"roles": ["user"]}})
        assert ("realm_access.roles", ["user"]) in result

    def test_finds_nested_claim_in_claims(self):
        scanner = self._make_scanner()
        result = scanner._find_role_claims({"claims": {"scope": "read"}})
        assert ("claims.scope", "read") in result

    def test_finds_nested_claim_in_resource_access(self):
        scanner = self._make_scanner()
        result = scanner._find_role_claims({"resource_access": {"roles": ["admin"]}})
        assert ("resource_access.roles", ["admin"]) in result

    def test_finds_both_top_and_nested(self):
        scanner = self._make_scanner()
        result = scanner._find_role_claims({"role": "user", "data": {"role": "user"}})
        paths = [r[0] for r in result]
        assert "role" in paths
        assert "data.role" in paths


# =============================================================================
# _is_real_data LOGIC
# =============================================================================

class TestIsRealData:
    """Tests for SessionAbuseScanner._is_real_data method."""

    def _make_scanner(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        return SessionAbuseScanner(settings)

    def test_json_object_is_real(self):
        scanner = self._make_scanner()
        assert scanner._is_real_data('{"users": []}', "/api/admin") is True

    def test_json_array_is_real(self):
        scanner = self._make_scanner()
        assert scanner._is_real_data('[{"id": 1}]', "/api/users") is True

    def test_html_on_api_path_is_not_real(self):
        scanner = self._make_scanner()
        assert scanner._is_real_data('<html><body>SPA</body></html>', "/api/admin") is False

    def test_html_on_rest_path_is_not_real(self):
        scanner = self._make_scanner()
        assert scanner._is_real_data('<html>...</html>', "/rest/user/data") is False

    def test_plain_text_on_non_api_path_is_not_real(self):
        scanner = self._make_scanner()
        assert scanner._is_real_data("some text", "/whatever") is False

    def test_json_body_with_whitespace(self):
        scanner = self._make_scanner()
        assert scanner._is_real_data('  {"ok": true}  ', "/api/admin") is True


# =============================================================================
# _deep_set HELPER FUNCTION
# =============================================================================

class TestDeepSet:
    """Tests for _deep_set helper function."""

    def test_sets_top_level_key(self):
        d = {"role": "user"}
        result = _deep_set(d, "role", "admin")
        assert result["role"] == "admin"

    def test_sets_nested_key(self):
        d = {"data": {"role": "customer"}}
        result = _deep_set(d, "data.role", "admin")
        assert result["data"]["role"] == "admin"

    def test_creates_intermediate_dicts(self):
        d = {}
        result = _deep_set(d, "data.role", "admin")
        assert result["data"]["role"] == "admin"

    def test_deeply_nested_path(self):
        d = {"a": {"b": {"c": "old"}}}
        result = _deep_set(d, "a.b.c", "new")
        assert result["a"]["b"]["c"] == "new"

    def test_returns_modified_dict(self):
        d = {"x": 1}
        result = _deep_set(d, "x", 2)
        assert result is d  # modifies in place and returns same dict

    def test_replaces_non_dict_intermediate(self):
        d = {"data": "not_a_dict"}
        result = _deep_set(d, "data.role", "admin")
        assert result["data"]["role"] == "admin"

    def test_sets_list_value(self):
        d = {"roles": []}
        result = _deep_set(d, "roles", ["admin"])
        assert result["roles"] == ["admin"]

    def test_sets_boolean_value(self):
        d = {"admin": False}
        result = _deep_set(d, "admin", True)
        assert result["admin"] is True

    def test_sets_integer_value(self):
        d = {"level": 0}
        result = _deep_set(d, "level", 99)
        assert result["level"] == 99


# =============================================================================
# CROSS-COVERAGE: All path lists contain only strings starting with /
# =============================================================================

class TestAllPathListsConsistency:
    """Cross-check that all endpoint path lists follow the same conventions."""

    ALL_PATH_LISTS = {
        "GENERIC_WHOAMI_PATHS": GENERIC_WHOAMI_PATHS,
        "GENERIC_LOGOUT_PATHS": GENERIC_LOGOUT_PATHS,
        "GENERIC_ADMIN_PATHS": GENERIC_ADMIN_PATHS,
        "GENERIC_PASSWORD_CHANGE_PATHS": GENERIC_PASSWORD_CHANGE_PATHS,
        "GENERIC_LOGIN_PATHS": GENERIC_LOGIN_PATHS,
        "GENERIC_REFRESH_PATHS": GENERIC_REFRESH_PATHS,
        "GENERIC_SESSIONS_PATHS": GENERIC_SESSIONS_PATHS,
    }

    def test_all_lists_are_non_empty(self):
        for name, paths in self.ALL_PATH_LISTS.items():
            assert len(paths) > 0, f"{name} should not be empty"

    def test_all_entries_are_strings(self):
        for name, paths in self.ALL_PATH_LISTS.items():
            for path in paths:
                assert isinstance(path, str), f"{name} entry {path!r} should be a string"

    def test_all_entries_start_with_slash(self):
        for name, paths in self.ALL_PATH_LISTS.items():
            for path in paths:
                assert path.startswith("/"), f"{name} entry {path!r} should start with /"

    def test_no_trailing_slashes(self):
        for name, paths in self.ALL_PATH_LISTS.items():
            for path in paths:
                if len(path) > 1:
                    assert not path.endswith("/"), (
                        f"{name} entry {path!r} should not have trailing slash"
                    )

    def test_no_duplicates_within_lists(self):
        for name, paths in self.ALL_PATH_LISTS.items():
            assert len(paths) == len(set(paths)), f"{name} has duplicates"


# =============================================================================
# ESCALATION_VALUES alignment with ROLE_CLAIM_NAMES
# =============================================================================

class TestEscalationValuesAlignment:
    """Ensure ESCALATION_VALUES keys align with ROLE_CLAIM_NAMES."""

    def test_all_escalation_keys_in_role_claims(self):
        """Every key in ESCALATION_VALUES should be a recognized role claim name."""
        for key in ESCALATION_VALUES:
            assert key in ROLE_CLAIM_NAMES, (
                f"ESCALATION_VALUES key {key!r} not found in ROLE_CLAIM_NAMES"
            )

    def test_role_claim_coverage(self):
        """Most role claim names should have escalation values."""
        covered = sum(1 for name in ROLE_CLAIM_NAMES if name in ESCALATION_VALUES)
        # At least 90% coverage
        assert covered / len(ROLE_CLAIM_NAMES) >= 0.9
