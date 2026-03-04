"""
Tests for scanning/modules/mobile_api_scanner.py

Covers:
- MobileAPIScanner class identity (name, inheritance)
- MOBILE_ENDPOINTS constant (count, required entries)
- AUTH_ENDPOINTS constant (count, required entries)
- MOBILE_USER_AGENTS constant (keys)
- SENSITIVE_PATTERNS constant (keys, regex compilation, matching)
"""

import re

import pytest

from scanning.modules.mobile_api_scanner import MobileAPIScanner
from scanning.vuln_scanner import ScanModule


# =============================================================================
# CLASS IDENTITY
# =============================================================================

class TestMobileAPIScannerIdentity:
    def test_name(self):
        assert MobileAPIScanner.name == "mobile_api_scanner"

    def test_is_scan_module_subclass(self):
        assert issubclass(MobileAPIScanner, ScanModule)


# =============================================================================
# MOBILE_ENDPOINTS
# =============================================================================

class TestMobileEndpoints:
    def test_count(self):
        assert len(MobileAPIScanner.MOBILE_ENDPOINTS) == 11

    def test_all_are_strings(self):
        for ep in MobileAPIScanner.MOBILE_ENDPOINTS:
            assert isinstance(ep, str)

    def test_all_start_with_slash(self):
        for ep in MobileAPIScanner.MOBILE_ENDPOINTS:
            assert ep.startswith("/"), f"{ep} does not start with /"

    def test_contains_api_v1_mobile(self):
        assert "/api/v1/mobile" in MobileAPIScanner.MOBILE_ENDPOINTS

    def test_contains_api_mobile(self):
        assert "/api/mobile" in MobileAPIScanner.MOBILE_ENDPOINTS

    def test_contains_mobile_api(self):
        assert "/mobile/api" in MobileAPIScanner.MOBILE_ENDPOINTS


# =============================================================================
# AUTH_ENDPOINTS
# =============================================================================

class TestAuthEndpoints:
    def test_count(self):
        assert len(MobileAPIScanner.AUTH_ENDPOINTS) == 13

    def test_all_are_strings(self):
        for ep in MobileAPIScanner.AUTH_ENDPOINTS:
            assert isinstance(ep, str)

    def test_all_start_with_slash(self):
        for ep in MobileAPIScanner.AUTH_ENDPOINTS:
            assert ep.startswith("/"), f"{ep} does not start with /"

    def test_contains_biometric_auth(self):
        assert "/api/biometric/auth" in MobileAPIScanner.AUTH_ENDPOINTS

    def test_contains_faceid_verify(self):
        assert "/api/faceid/verify" in MobileAPIScanner.AUTH_ENDPOINTS

    def test_contains_touchid_verify(self):
        assert "/api/touchid/verify" in MobileAPIScanner.AUTH_ENDPOINTS

    def test_contains_pin_verify(self):
        assert "/api/pin/verify" in MobileAPIScanner.AUTH_ENDPOINTS

    def test_contains_otp_verify(self):
        assert "/api/otp/verify" in MobileAPIScanner.AUTH_ENDPOINTS


# =============================================================================
# MOBILE_USER_AGENTS
# =============================================================================

class TestMobileUserAgents:
    def test_is_dict(self):
        assert isinstance(MobileAPIScanner.MOBILE_USER_AGENTS, dict)

    def test_has_four_keys(self):
        assert len(MobileAPIScanner.MOBILE_USER_AGENTS) == 4

    def test_has_ios_key(self):
        assert "ios" in MobileAPIScanner.MOBILE_USER_AGENTS

    def test_has_android_key(self):
        assert "android" in MobileAPIScanner.MOBILE_USER_AGENTS

    def test_has_ios_app_key(self):
        assert "ios_app" in MobileAPIScanner.MOBILE_USER_AGENTS

    def test_has_android_app_key(self):
        assert "android_app" in MobileAPIScanner.MOBILE_USER_AGENTS

    def test_all_values_are_strings(self):
        for key, value in MobileAPIScanner.MOBILE_USER_AGENTS.items():
            assert isinstance(value, str), f"Value for {key} is not a string"

    def test_all_values_non_empty(self):
        for key, value in MobileAPIScanner.MOBILE_USER_AGENTS.items():
            assert len(value) > 0, f"Value for {key} is empty"


# =============================================================================
# SENSITIVE_PATTERNS — structure
# =============================================================================

class TestSensitivePatternsStructure:
    def test_is_dict(self):
        assert isinstance(MobileAPIScanner.SENSITIVE_PATTERNS, dict)

    def test_has_nine_keys(self):
        assert len(MobileAPIScanner.SENSITIVE_PATTERNS) == 9

    def test_has_api_key(self):
        assert "api_key" in MobileAPIScanner.SENSITIVE_PATTERNS

    def test_has_secret_key(self):
        assert "secret_key" in MobileAPIScanner.SENSITIVE_PATTERNS

    def test_has_push_token(self):
        assert "push_token" in MobileAPIScanner.SENSITIVE_PATTERNS

    def test_has_device_id(self):
        assert "device_id" in MobileAPIScanner.SENSITIVE_PATTERNS

    def test_has_private_key(self):
        assert "private_key" in MobileAPIScanner.SENSITIVE_PATTERNS

    def test_has_jwt_secret(self):
        assert "jwt_secret" in MobileAPIScanner.SENSITIVE_PATTERNS

    def test_has_firebase_key(self):
        assert "firebase_key" in MobileAPIScanner.SENSITIVE_PATTERNS

    def test_has_google_api(self):
        assert "google_api" in MobileAPIScanner.SENSITIVE_PATTERNS

    def test_has_aws_key(self):
        assert "aws_key" in MobileAPIScanner.SENSITIVE_PATTERNS

    def test_all_values_are_strings(self):
        for key, value in MobileAPIScanner.SENSITIVE_PATTERNS.items():
            assert isinstance(value, str), f"Pattern for {key} is not a string"

    def test_all_values_compile_as_regex(self):
        for key, value in MobileAPIScanner.SENSITIVE_PATTERNS.items():
            compiled = re.compile(value, re.IGNORECASE)
            assert compiled is not None, f"Pattern for {key} failed to compile"


# =============================================================================
# SENSITIVE_PATTERNS — regex matching
# =============================================================================

class TestSensitivePatternsMatching:
    def test_api_key_matches(self):
        pattern = MobileAPIScanner.SENSITIVE_PATTERNS["api_key"]
        text = '"api_key": "abcdefghijklmnopqrstuvwxyz1234"'
        assert re.search(pattern, text, re.IGNORECASE)

    def test_api_key_matches_hyphenated(self):
        pattern = MobileAPIScanner.SENSITIVE_PATTERNS["api_key"]
        text = '"api-key" = "abcdefghijklmnopqrstuvwxyz1234"'
        assert re.search(pattern, text, re.IGNORECASE)

    def test_api_key_matches_no_separator(self):
        pattern = MobileAPIScanner.SENSITIVE_PATTERNS["api_key"]
        text = '"apikey": "abcdefghijklmnopqrstuvwxyz1234"'
        assert re.search(pattern, text, re.IGNORECASE)

    def test_secret_key_matches(self):
        pattern = MobileAPIScanner.SENSITIVE_PATTERNS["secret_key"]
        text = '"secret_key": "ABCDEFGHIJKLMNOPQRSTUVWXYZ"'
        assert re.search(pattern, text, re.IGNORECASE)

    def test_secret_key_matches_no_separator(self):
        pattern = MobileAPIScanner.SENSITIVE_PATTERNS["secret_key"]
        text = '"secretkey": "ABCDEFGHIJKLMNOPQRSTUVWXYZ"'
        assert re.search(pattern, text, re.IGNORECASE)

    def test_push_token_matches_fcm(self):
        pattern = MobileAPIScanner.SENSITIVE_PATTERNS["push_token"]
        # 50+ char token value
        token = "a" * 60
        text = f'"fcm_token": "{token}"'
        assert re.search(pattern, text, re.IGNORECASE)

    def test_push_token_matches_apns(self):
        pattern = MobileAPIScanner.SENSITIVE_PATTERNS["push_token"]
        token = "b" * 60
        text = f'"apns_token": "{token}"'
        assert re.search(pattern, text, re.IGNORECASE)

    def test_push_token_matches_device_token(self):
        pattern = MobileAPIScanner.SENSITIVE_PATTERNS["push_token"]
        token = "c" * 60
        text = f'"device_token": "{token}"'
        assert re.search(pattern, text, re.IGNORECASE)

    def test_device_id_matches_uuid(self):
        pattern = MobileAPIScanner.SENSITIVE_PATTERNS["device_id"]
        text = '"device_id": "550e8400-e29b-41d4-a716-446655440000"'
        assert re.search(pattern, text, re.IGNORECASE)

    def test_device_id_matches_android_id(self):
        pattern = MobileAPIScanner.SENSITIVE_PATTERNS["device_id"]
        text = '"android_id": "abcdef0123456789"'
        assert re.search(pattern, text, re.IGNORECASE)

    def test_device_id_matches_udid(self):
        pattern = MobileAPIScanner.SENSITIVE_PATTERNS["device_id"]
        text = '"udid": "AABBCCDD00112233EEFF"'
        assert re.search(pattern, text, re.IGNORECASE)

    def test_private_key_matches_rsa(self):
        pattern = MobileAPIScanner.SENSITIVE_PATTERNS["private_key"]
        text = "-----BEGIN RSA PRIVATE KEY-----"
        assert re.search(pattern, text, re.IGNORECASE)

    def test_private_key_matches_ec(self):
        pattern = MobileAPIScanner.SENSITIVE_PATTERNS["private_key"]
        text = "-----BEGIN EC PRIVATE KEY-----"
        assert re.search(pattern, text, re.IGNORECASE)

    def test_private_key_matches_generic(self):
        pattern = MobileAPIScanner.SENSITIVE_PATTERNS["private_key"]
        text = "-----BEGIN PRIVATE KEY-----"
        assert re.search(pattern, text, re.IGNORECASE)

    def test_jwt_secret_matches(self):
        pattern = MobileAPIScanner.SENSITIVE_PATTERNS["jwt_secret"]
        text = '"jwt_secret": "mysupersecretkey1234"'
        assert re.search(pattern, text, re.IGNORECASE)

    def test_jwt_secret_matches_token_secret(self):
        pattern = MobileAPIScanner.SENSITIVE_PATTERNS["jwt_secret"]
        text = '"token_secret": "anothersecretkey12"'
        assert re.search(pattern, text, re.IGNORECASE)

    def test_firebase_key_matches(self):
        pattern = MobileAPIScanner.SENSITIVE_PATTERNS["firebase_key"]
        # AIza followed by exactly 35 chars (39 total)
        text = "AIzaSyA1234567890abcdefghijklmnopqrstuv"
        assert re.search(pattern, text, re.IGNORECASE)

    def test_google_api_matches(self):
        pattern = MobileAPIScanner.SENSITIVE_PATTERNS["google_api"]
        text = "AIzaSyB1234567890abcdefghijklmnopqrstuv"
        assert re.search(pattern, text, re.IGNORECASE)

    def test_aws_key_matches(self):
        pattern = MobileAPIScanner.SENSITIVE_PATTERNS["aws_key"]
        # AKIA followed by 16 uppercase alphanumeric chars
        text = "AKIAIOSFODNN7EXAMPLE"
        assert re.search(pattern, text, re.IGNORECASE)

    def test_api_key_rejects_short_value(self):
        pattern = MobileAPIScanner.SENSITIVE_PATTERNS["api_key"]
        text = '"api_key": "short"'
        assert not re.search(pattern, text, re.IGNORECASE)

    def test_push_token_rejects_short_value(self):
        pattern = MobileAPIScanner.SENSITIVE_PATTERNS["push_token"]
        text = '"push_token": "tooshort"'
        assert not re.search(pattern, text, re.IGNORECASE)

    def test_aws_key_rejects_wrong_prefix(self):
        pattern = MobileAPIScanner.SENSITIVE_PATTERNS["aws_key"]
        text = "BKIAIOSFODNN7EXAMPLE"
        assert not re.search(pattern, text, re.IGNORECASE)
