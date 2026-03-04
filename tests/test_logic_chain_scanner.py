"""
Tests for scanning/modules/logic_chain_scanner.py

Covers:
- Module-level variables: SAFE_MODE, ALLOW_WRITES
- ResponseAnalyzer.SENSITIVE_PATTERNS (28+ regex patterns)
- ResponseAnalyzer.PRIVILEGE_PATTERNS (14+ regex patterns)
- ResponseAnalyzer.USER_DATA_FIELDS (16+ string fields)
- ResponseAnalyzer.ARRAY_IDOR_FIELDS (8+ strings)
- ResponseAnalyzer.has_sensitive_data() with matching/non-matching text
- ResponseAnalyzer.has_privilege_indicators() with matching/non-matching text
- ResponseAnalyzer.has_user_data() with matching/non-matching text
"""

import pytest
from scanning.modules.logic_chain_scanner import (
    SAFE_MODE,
    ALLOW_WRITES,
    ResponseAnalyzer,
)


# =============================================================================
# MODULE-LEVEL VARIABLE TESTS
# =============================================================================


class TestModuleVariables:
    """Test module-level safety variables."""

    def test_safe_mode_is_string(self):
        assert isinstance(SAFE_MODE, str)

    def test_safe_mode_is_lowercase(self):
        assert SAFE_MODE == SAFE_MODE.lower()

    def test_allow_writes_is_bool(self):
        assert isinstance(ALLOW_WRITES, bool)

    def test_allow_writes_consistent_with_safe_mode(self):
        """ALLOW_WRITES should be True only when SAFE_MODE is standard or aggressive."""
        if SAFE_MODE in ("standard", "aggressive"):
            assert ALLOW_WRITES is True
        else:
            assert ALLOW_WRITES is False


# =============================================================================
# SENSITIVE_PATTERNS TESTS
# =============================================================================


class TestSensitivePatterns:
    """Test ResponseAnalyzer.SENSITIVE_PATTERNS list."""

    def test_minimum_count(self):
        assert len(ResponseAnalyzer.SENSITIVE_PATTERNS) >= 28

    def test_all_entries_are_strings(self):
        for pattern in ResponseAnalyzer.SENSITIVE_PATTERNS:
            assert isinstance(pattern, str)

    def test_contains_password_patterns(self):
        joined = " ".join(ResponseAnalyzer.SENSITIVE_PATTERNS)
        assert "password" in joined
        assert "passwd" in joined
        assert "pwd" in joined

    def test_contains_token_patterns(self):
        joined = " ".join(ResponseAnalyzer.SENSITIVE_PATTERNS)
        assert "token" in joined
        assert "api_key" in joined
        assert "apikey" in joined

    def test_contains_credit_card_patterns(self):
        joined = " ".join(ResponseAnalyzer.SENSITIVE_PATTERNS)
        assert "credit_card" in joined
        assert "creditcard" in joined
        assert "card_number" in joined

    def test_contains_ssn_patterns(self):
        joined = " ".join(ResponseAnalyzer.SENSITIVE_PATTERNS)
        assert "ssn" in joined
        assert "social_security" in joined

    def test_contains_bank_patterns(self):
        joined = " ".join(ResponseAnalyzer.SENSITIVE_PATTERNS)
        assert "account_number" in joined
        assert "routing_number" in joined
        assert "bank_account" in joined
        assert "iban" in joined
        assert "swift" in joined

    def test_contains_session_patterns(self):
        joined = " ".join(ResponseAnalyzer.SENSITIVE_PATTERNS)
        assert "session_id" in joined
        assert "sessionid" in joined
        assert "auth_token" in joined

    def test_contains_oauth_token_patterns(self):
        joined = " ".join(ResponseAnalyzer.SENSITIVE_PATTERNS)
        assert "refresh_token" in joined
        assert "access_token" in joined
        assert "bearer" in joined

    def test_contains_pii_patterns(self):
        joined = " ".join(ResponseAnalyzer.SENSITIVE_PATTERNS)
        assert "phone" in joined
        assert "mobile" in joined
        assert "address" in joined
        assert "street" in joined

    def test_contains_cvv_patterns(self):
        joined = " ".join(ResponseAnalyzer.SENSITIVE_PATTERNS)
        assert "cvv" in joined
        assert "cvc" in joined

    def test_contains_secret_pattern(self):
        joined = " ".join(ResponseAnalyzer.SENSITIVE_PATTERNS)
        assert "secret" in joined

    def test_contains_private_key_pattern(self):
        joined = " ".join(ResponseAnalyzer.SENSITIVE_PATTERNS)
        assert "private_key" in joined

    def test_no_duplicates(self):
        assert len(ResponseAnalyzer.SENSITIVE_PATTERNS) == len(
            set(ResponseAnalyzer.SENSITIVE_PATTERNS)
        )


# =============================================================================
# PRIVILEGE_PATTERNS TESTS
# =============================================================================


class TestPrivilegePatterns:
    """Test ResponseAnalyzer.PRIVILEGE_PATTERNS list."""

    def test_minimum_count(self):
        assert len(ResponseAnalyzer.PRIVILEGE_PATTERNS) >= 14

    def test_all_entries_are_strings(self):
        for pattern in ResponseAnalyzer.PRIVILEGE_PATTERNS:
            assert isinstance(pattern, str)

    def test_contains_role_admin_pattern(self):
        joined = " ".join(ResponseAnalyzer.PRIVILEGE_PATTERNS)
        assert "role" in joined
        assert "admin" in joined

    def test_contains_is_admin_patterns(self):
        joined = " ".join(ResponseAnalyzer.PRIVILEGE_PATTERNS)
        assert "isAdmin" in joined
        assert "is_admin" in joined

    def test_contains_superuser_pattern(self):
        joined = " ".join(ResponseAnalyzer.PRIVILEGE_PATTERNS)
        assert "superuser" in joined

    def test_contains_permissions_pattern(self):
        joined = " ".join(ResponseAnalyzer.PRIVILEGE_PATTERNS)
        assert "permissions" in joined

    def test_contains_staff_pattern(self):
        joined = " ".join(ResponseAnalyzer.PRIVILEGE_PATTERNS)
        assert "staff" in joined

    def test_contains_moderator_pattern(self):
        joined = " ".join(ResponseAnalyzer.PRIVILEGE_PATTERNS)
        assert "moderator" in joined

    def test_contains_access_level_pattern(self):
        joined = " ".join(ResponseAnalyzer.PRIVILEGE_PATTERNS)
        assert "access_level" in joined

    def test_contains_privilege_pattern(self):
        joined = " ".join(ResponseAnalyzer.PRIVILEGE_PATTERNS)
        assert "privilege" in joined

    def test_contains_user_type_patterns(self):
        joined = " ".join(ResponseAnalyzer.PRIVILEGE_PATTERNS)
        assert "userType" in joined
        assert "user_type" in joined

    def test_contains_level_pattern(self):
        joined = " ".join(ResponseAnalyzer.PRIVILEGE_PATTERNS)
        assert "level" in joined

    def test_no_duplicates(self):
        assert len(ResponseAnalyzer.PRIVILEGE_PATTERNS) == len(
            set(ResponseAnalyzer.PRIVILEGE_PATTERNS)
        )


# =============================================================================
# USER_DATA_FIELDS TESTS
# =============================================================================


class TestUserDataFields:
    """Test ResponseAnalyzer.USER_DATA_FIELDS list."""

    def test_minimum_count(self):
        assert len(ResponseAnalyzer.USER_DATA_FIELDS) >= 16

    def test_all_entries_are_strings(self):
        for field in ResponseAnalyzer.USER_DATA_FIELDS:
            assert isinstance(field, str)

    def test_contains_identity_fields(self):
        fields = ResponseAnalyzer.USER_DATA_FIELDS
        assert "email" in fields
        assert "username" in fields
        assert "name" in fields

    def test_contains_name_parts(self):
        fields = ResponseAnalyzer.USER_DATA_FIELDS
        assert "first_name" in fields
        assert "last_name" in fields

    def test_contains_contact_fields(self):
        fields = ResponseAnalyzer.USER_DATA_FIELDS
        assert "phone" in fields
        assert "address" in fields

    def test_contains_financial_fields(self):
        fields = ResponseAnalyzer.USER_DATA_FIELDS
        assert "balance" in fields
        assert "wallet" in fields
        assert "credit" in fields
        assert "payment" in fields

    def test_contains_commerce_fields(self):
        fields = ResponseAnalyzer.USER_DATA_FIELDS
        assert "order" in fields
        assert "basket" in fields
        assert "cart" in fields

    def test_contains_subscription_field(self):
        fields = ResponseAnalyzer.USER_DATA_FIELDS
        assert "subscription" in fields

    def test_contains_user_id_fields(self):
        fields = ResponseAnalyzer.USER_DATA_FIELDS
        assert "userid" in fields
        assert "user_id" in fields

    def test_contains_ugc_fields(self):
        fields = ResponseAnalyzer.USER_DATA_FIELDS
        assert "comment" in fields
        assert "rating" in fields
        assert "feedback" in fields

    def test_no_duplicates(self):
        assert len(ResponseAnalyzer.USER_DATA_FIELDS) == len(
            set(ResponseAnalyzer.USER_DATA_FIELDS)
        )


# =============================================================================
# ARRAY_IDOR_FIELDS TESTS
# =============================================================================


class TestArrayIdorFields:
    """Test ResponseAnalyzer.ARRAY_IDOR_FIELDS list."""

    def test_minimum_count(self):
        assert len(ResponseAnalyzer.ARRAY_IDOR_FIELDS) >= 8

    def test_all_entries_are_strings(self):
        for field in ResponseAnalyzer.ARRAY_IDOR_FIELDS:
            assert isinstance(field, str)

    def test_contains_user_id_fields(self):
        fields = ResponseAnalyzer.ARRAY_IDOR_FIELDS
        assert "userid" in fields
        assert "user_id" in fields

    def test_contains_identity_fields(self):
        fields = ResponseAnalyzer.ARRAY_IDOR_FIELDS
        assert "email" in fields
        assert "username" in fields

    def test_contains_ownership_fields(self):
        fields = ResponseAnalyzer.ARRAY_IDOR_FIELDS
        assert "author" in fields
        assert "owner" in fields

    def test_contains_creator_fields(self):
        fields = ResponseAnalyzer.ARRAY_IDOR_FIELDS
        assert "createdby" in fields or "created_by" in fields
        assert "created_by" in fields

    def test_contains_submitter_field(self):
        fields = ResponseAnalyzer.ARRAY_IDOR_FIELDS
        assert "submittedby" in fields

    def test_no_duplicates(self):
        assert len(ResponseAnalyzer.ARRAY_IDOR_FIELDS) == len(
            set(ResponseAnalyzer.ARRAY_IDOR_FIELDS)
        )


# =============================================================================
# has_sensitive_data() TESTS
# =============================================================================


class TestHasSensitiveData:
    """Test ResponseAnalyzer.has_sensitive_data() class method."""

    def test_returns_list(self):
        result = ResponseAnalyzer.has_sensitive_data("")
        assert isinstance(result, list)

    def test_empty_text_returns_empty(self):
        result = ResponseAnalyzer.has_sensitive_data("")
        assert result == []

    def test_no_match_returns_empty(self):
        result = ResponseAnalyzer.has_sensitive_data(
            '{"status": "ok", "count": 42}'
        )
        assert result == []

    def test_detects_password_field(self):
        text = '{"username": "admin", "password": "secret123"}'
        result = ResponseAnalyzer.has_sensitive_data(text)
        assert len(result) > 0
        found_lower = [r.lower() for r in result]
        assert any("password" in item for item in found_lower)

    def test_detects_token_field(self):
        text = '{"token": "abc123def456"}'
        result = ResponseAnalyzer.has_sensitive_data(text)
        assert len(result) > 0

    def test_detects_api_key_field(self):
        text = '{"api_key": "sk-1234567890abcdef"}'
        result = ResponseAnalyzer.has_sensitive_data(text)
        assert len(result) > 0

    def test_detects_credit_card_field(self):
        text = '{"credit_card": "4111111111111111"}'
        result = ResponseAnalyzer.has_sensitive_data(text)
        assert len(result) > 0

    def test_detects_ssn_field(self):
        text = '{"ssn": "123-45-6789"}'
        result = ResponseAnalyzer.has_sensitive_data(text)
        assert len(result) > 0

    def test_detects_bank_account_field(self):
        text = '{"bank_account": "1234567890"}'
        result = ResponseAnalyzer.has_sensitive_data(text)
        assert len(result) > 0

    def test_detects_session_id_field(self):
        text = '{"session_id": "abc123xyz"}'
        result = ResponseAnalyzer.has_sensitive_data(text)
        assert len(result) > 0

    def test_detects_access_token_field(self):
        text = '{"access_token": "eyJhbGciOiJIUzI1NiJ9"}'
        result = ResponseAnalyzer.has_sensitive_data(text)
        assert len(result) > 0

    def test_detects_refresh_token_field(self):
        text = '{"refresh_token": "dGhpcyBpcyBhIHRlc3Q"}'
        result = ResponseAnalyzer.has_sensitive_data(text)
        assert len(result) > 0

    def test_detects_iban_field(self):
        text = '{"iban": "DE89370400440532013000"}'
        result = ResponseAnalyzer.has_sensitive_data(text)
        assert len(result) > 0

    def test_detects_cvv_field(self):
        text = '{"cvv": "123"}'
        result = ResponseAnalyzer.has_sensitive_data(text)
        assert len(result) > 0

    def test_case_insensitive(self):
        text = '{"PASSWORD": "hunter2"}'
        result = ResponseAnalyzer.has_sensitive_data(text)
        assert len(result) > 0

    def test_multiple_sensitive_fields(self):
        text = '{"password": "pass", "token": "tok", "ssn": "000-00-0000"}'
        result = ResponseAnalyzer.has_sensitive_data(text)
        assert len(result) >= 3

    def test_no_false_positive_on_innocent_text(self):
        text = '{"product_name": "Widget", "price": 9.99, "quantity": 5}'
        result = ResponseAnalyzer.has_sensitive_data(text)
        assert result == []

    def test_no_false_positive_on_html(self):
        text = "<html><body><h1>Welcome</h1><p>Hello world</p></body></html>"
        result = ResponseAnalyzer.has_sensitive_data(text)
        assert result == []

    def test_deduplicates_results(self):
        text = '{"password": "a", "password": "b"}'
        result = ResponseAnalyzer.has_sensitive_data(text)
        # Even if password appears twice, result should be deduplicated
        password_matches = [r for r in result if "password" in r.lower()]
        assert len(password_matches) == 1

    def test_detects_bearer_field(self):
        text = '{"bearer": "eyJhbGciOiJSUzI1NiJ9"}'
        result = ResponseAnalyzer.has_sensitive_data(text)
        assert len(result) > 0

    def test_detects_private_key_field(self):
        text = '{"private_key": "-----BEGIN RSA PRIVATE KEY-----"}'
        result = ResponseAnalyzer.has_sensitive_data(text)
        assert len(result) > 0

    def test_detects_routing_number_field(self):
        text = '{"routing_number": "021000021"}'
        result = ResponseAnalyzer.has_sensitive_data(text)
        assert len(result) > 0


# =============================================================================
# has_privilege_indicators() TESTS
# =============================================================================


class TestHasPrivilegeIndicators:
    """Test ResponseAnalyzer.has_privilege_indicators() class method."""

    def test_returns_list(self):
        result = ResponseAnalyzer.has_privilege_indicators("")
        assert isinstance(result, list)

    def test_empty_text_returns_empty(self):
        result = ResponseAnalyzer.has_privilege_indicators("")
        assert result == []

    def test_no_match_returns_empty(self):
        result = ResponseAnalyzer.has_privilege_indicators(
            '{"username": "john", "status": "active"}'
        )
        assert result == []

    def test_detects_role_admin(self):
        text = '{"role": "admin"}'
        result = ResponseAnalyzer.has_privilege_indicators(text)
        assert len(result) > 0

    def test_detects_role_administrator(self):
        text = '{"role": "administrator"}'
        result = ResponseAnalyzer.has_privilege_indicators(text)
        assert len(result) > 0

    def test_detects_is_admin_true(self):
        text = '{"isAdmin": true}'
        result = ResponseAnalyzer.has_privilege_indicators(text)
        assert len(result) > 0

    def test_detects_is_admin_snake_case(self):
        text = '{"is_admin": true}'
        result = ResponseAnalyzer.has_privilege_indicators(text)
        assert len(result) > 0

    def test_detects_superuser_true(self):
        text = '{"superuser": true}'
        result = ResponseAnalyzer.has_privilege_indicators(text)
        assert len(result) > 0

    def test_detects_staff_true(self):
        text = '{"staff": true}'
        result = ResponseAnalyzer.has_privilege_indicators(text)
        assert len(result) > 0

    def test_detects_moderator_true(self):
        text = '{"moderator": true}'
        result = ResponseAnalyzer.has_privilege_indicators(text)
        assert len(result) > 0

    def test_detects_permissions_array(self):
        text = '{"permissions": ["read", "write", "admin"]}'
        result = ResponseAnalyzer.has_privilege_indicators(text)
        assert len(result) > 0

    def test_detects_access_level_full(self):
        text = '{"access_level": "full"}'
        result = ResponseAnalyzer.has_privilege_indicators(text)
        assert len(result) > 0

    def test_detects_user_type_admin(self):
        text = '{"userType": "admin"}'
        result = ResponseAnalyzer.has_privilege_indicators(text)
        assert len(result) > 0

    def test_detects_user_type_snake_case_admin(self):
        text = '{"user_type": "admin"}'
        result = ResponseAnalyzer.has_privilege_indicators(text)
        assert len(result) > 0

    def test_detects_admin_true(self):
        text = '{"admin": true}'
        result = ResponseAnalyzer.has_privilege_indicators(text)
        assert len(result) > 0

    def test_detects_level_zero(self):
        text = '{"level": 0}'
        result = ResponseAnalyzer.has_privilege_indicators(text)
        assert len(result) > 0

    def test_case_insensitive(self):
        text = '{"ROLE": "ADMIN"}'
        result = ResponseAnalyzer.has_privilege_indicators(text)
        assert len(result) > 0

    def test_no_false_positive_regular_user(self):
        text = '{"role": "user", "isAdmin": false, "staff": false}'
        result = ResponseAnalyzer.has_privilege_indicators(text)
        # "role": "user" should not match "role": "admin"
        # "isAdmin": false should not match "isAdmin": true
        # Only check that there is no false match for admin role patterns
        admin_role_matches = [
            p for p in result if "admin" in p and "role" in p
        ]
        assert len(admin_role_matches) == 0

    def test_multiple_indicators(self):
        text = '{"role": "admin", "isAdmin": true, "staff": true}'
        result = ResponseAnalyzer.has_privilege_indicators(text)
        assert len(result) >= 3

    def test_result_contains_pattern_strings(self):
        text = '{"role": "admin"}'
        result = ResponseAnalyzer.has_privilege_indicators(text)
        # has_privilege_indicators returns the pattern that matched
        assert all(isinstance(item, str) for item in result)


# =============================================================================
# has_user_data() TESTS
# =============================================================================


class TestHasUserData:
    """Test ResponseAnalyzer.has_user_data() class method."""

    def test_returns_list(self):
        result = ResponseAnalyzer.has_user_data("")
        assert isinstance(result, list)

    def test_empty_text_returns_empty(self):
        result = ResponseAnalyzer.has_user_data("")
        assert result == []

    def test_no_match_returns_empty(self):
        result = ResponseAnalyzer.has_user_data(
            '{"status": "ok", "version": "1.0"}'
        )
        assert result == []

    def test_detects_email_field_double_quotes(self):
        text = '{"email": "user@example.com"}'
        result = ResponseAnalyzer.has_user_data(text)
        assert "email" in result

    def test_detects_email_field_single_quotes(self):
        text = "{'email': 'user@example.com'}"
        result = ResponseAnalyzer.has_user_data(text)
        assert "email" in result

    def test_detects_username_field(self):
        text = '{"username": "johndoe"}'
        result = ResponseAnalyzer.has_user_data(text)
        assert "username" in result

    def test_detects_name_field(self):
        text = '{"name": "John Doe"}'
        result = ResponseAnalyzer.has_user_data(text)
        assert "name" in result

    def test_detects_first_name_field(self):
        text = '{"first_name": "John"}'
        result = ResponseAnalyzer.has_user_data(text)
        assert "first_name" in result

    def test_detects_last_name_field(self):
        text = '{"last_name": "Doe"}'
        result = ResponseAnalyzer.has_user_data(text)
        assert "last_name" in result

    def test_detects_phone_field(self):
        text = '{"phone": "+1234567890"}'
        result = ResponseAnalyzer.has_user_data(text)
        assert "phone" in result

    def test_detects_address_field(self):
        text = '{"address": "123 Main St"}'
        result = ResponseAnalyzer.has_user_data(text)
        assert "address" in result

    def test_detects_balance_field(self):
        text = '{"balance": 100.50}'
        result = ResponseAnalyzer.has_user_data(text)
        assert "balance" in result

    def test_detects_order_field(self):
        text = '{"order": {"id": 1, "total": 29.99}}'
        result = ResponseAnalyzer.has_user_data(text)
        assert "order" in result

    def test_detects_basket_field(self):
        text = '{"basket": [{"product": "item1"}]}'
        result = ResponseAnalyzer.has_user_data(text)
        assert "basket" in result

    def test_detects_cart_field(self):
        text = '{"cart": {"items": []}}'
        result = ResponseAnalyzer.has_user_data(text)
        assert "cart" in result

    def test_detects_payment_field(self):
        text = '{"payment": {"method": "card"}}'
        result = ResponseAnalyzer.has_user_data(text)
        assert "payment" in result

    def test_detects_subscription_field(self):
        text = '{"subscription": "premium"}'
        result = ResponseAnalyzer.has_user_data(text)
        assert "subscription" in result

    def test_detects_userid_field(self):
        text = '{"userid": 42}'
        result = ResponseAnalyzer.has_user_data(text)
        assert "userid" in result

    def test_detects_user_id_field(self):
        text = '{"user_id": 42}'
        result = ResponseAnalyzer.has_user_data(text)
        assert "user_id" in result

    def test_detects_comment_field(self):
        text = '{"comment": "Great product!"}'
        result = ResponseAnalyzer.has_user_data(text)
        assert "comment" in result

    def test_detects_rating_field(self):
        text = '{"rating": 5}'
        result = ResponseAnalyzer.has_user_data(text)
        assert "rating" in result

    def test_detects_feedback_field(self):
        text = '{"feedback": "Nice service"}'
        result = ResponseAnalyzer.has_user_data(text)
        assert "feedback" in result

    def test_detects_wallet_field(self):
        text = '{"wallet": 250.00}'
        result = ResponseAnalyzer.has_user_data(text)
        assert "wallet" in result

    def test_detects_credit_field(self):
        text = '{"credit": 50}'
        result = ResponseAnalyzer.has_user_data(text)
        assert "credit" in result

    def test_multiple_fields_detected(self):
        text = '{"email": "a@b.com", "username": "john", "phone": "123"}'
        result = ResponseAnalyzer.has_user_data(text)
        assert "email" in result
        assert "username" in result
        assert "phone" in result
        assert len(result) >= 3

    def test_case_insensitive_matching(self):
        text = '{"EMAIL": "user@example.com", "USERNAME": "admin"}'
        result = ResponseAnalyzer.has_user_data(text)
        # The method lowercases the text, so uppercase keys get matched
        assert len(result) >= 2

    def test_no_false_positive_without_quotes(self):
        # The method checks for quoted field names specifically
        text = "The email system is working and the username is required"
        result = ResponseAnalyzer.has_user_data(text)
        assert result == []

    def test_no_false_positive_on_plain_json_values(self):
        text = '{"type": "invoice", "status": "paid", "amount": 100}'
        result = ResponseAnalyzer.has_user_data(text)
        assert result == []
