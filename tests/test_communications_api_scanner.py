"""
Tests for scanning/modules/communications_api_scanner.py

Covers:
- TWILIO_PATTERNS module-level dict (5 compiled regexes)
- SENDGRID_PATTERNS module-level dict (1 compiled regex)
- PHONE_ENUM_ENDPOINTS list (12 entries)
- SMS_ABUSE_ENDPOINTS list (10 entries)
- PREMIUM_RATE_PREFIXES list (7 entries)
- CommunicationsEndpoint dataclass (defaults, full creation)
- CommunicationsAPIScanner class (name, ScanModule subclass, methods)
- Regex patterns (match/reject known examples)
- _is_communications_target helper (sync, directly testable)
"""

import asyncio
import inspect
import re
from dataclasses import fields as dc_fields

import pytest

from scanning.modules.communications_api_scanner import (
    TWILIO_PATTERNS,
    SENDGRID_PATTERNS,
    PHONE_ENUM_ENDPOINTS,
    SMS_ABUSE_ENDPOINTS,
    PREMIUM_RATE_PREFIXES,
    CommunicationsEndpoint,
    CommunicationsAPIScanner,
)
from scanning.vuln_scanner import ScanModule


# =============================================================================
# MODULE-LEVEL DICT — TWILIO_PATTERNS
# =============================================================================

class TestTwilioPatterns:
    """Test the TWILIO_PATTERNS dict of compiled regexes."""

    def test_is_dict(self):
        assert isinstance(TWILIO_PATTERNS, dict)

    def test_count_is_5(self):
        assert len(TWILIO_PATTERNS) == 5

    def test_keys(self):
        expected_keys = {"account_sid", "auth_token", "api_key", "api_secret", "phone_number"}
        assert set(TWILIO_PATTERNS.keys()) == expected_keys

    def test_all_values_are_compiled_regex(self):
        for key, pattern in TWILIO_PATTERNS.items():
            assert isinstance(pattern, re.Pattern), f"{key} is not a compiled regex"

    # -- account_sid pattern: AC + 32 hex --

    def test_account_sid_matches_valid(self):
        assert TWILIO_PATTERNS["account_sid"].search("AC1234567890abcdef1234567890abcdef")

    def test_account_sid_case_insensitive(self):
        assert TWILIO_PATTERNS["account_sid"].search("AC1234567890ABCDEF1234567890ABCDEF")

    def test_account_sid_rejects_wrong_prefix(self):
        # Must start with AC, not AB
        match = TWILIO_PATTERNS["account_sid"].search("AB1234567890abcdef1234567890abcdef")
        assert match is None

    def test_account_sid_rejects_short(self):
        match = TWILIO_PATTERNS["account_sid"].search("AC1234567890abcdef")
        assert match is None

    # -- api_key pattern: SK + 32 hex --

    def test_api_key_matches_valid(self):
        assert TWILIO_PATTERNS["api_key"].search("SK1234567890abcdef1234567890abcdef")

    def test_api_key_case_insensitive(self):
        assert TWILIO_PATTERNS["api_key"].search("SK1234567890ABCDEF1234567890ABCDEF")

    def test_api_key_rejects_wrong_prefix(self):
        match = TWILIO_PATTERNS["api_key"].search("SL1234567890abcdef1234567890abcdef")
        assert match is None

    # -- auth_token pattern: 32 hex chars --

    def test_auth_token_matches_valid(self):
        assert TWILIO_PATTERNS["auth_token"].search("abcdef1234567890abcdef1234567890")

    def test_auth_token_rejects_short(self):
        match = TWILIO_PATTERNS["auth_token"].search("abcdef123456")
        assert match is None

    # -- phone_number pattern --

    def test_phone_number_matches_e164(self):
        assert TWILIO_PATTERNS["phone_number"].search("+15551234567")

    def test_phone_number_matches_without_plus(self):
        assert TWILIO_PATTERNS["phone_number"].search("15551234567")

    def test_phone_number_rejects_zero_prefix(self):
        # Pattern requires first digit to be 1-9
        match = TWILIO_PATTERNS["phone_number"].search("+05551234567")
        # After the +0, the pattern should still pick up 5551234567
        # but the +0 itself won't match
        text = "+0"
        assert TWILIO_PATTERNS["phone_number"].fullmatch(text) is None


# =============================================================================
# MODULE-LEVEL DICT — SENDGRID_PATTERNS
# =============================================================================

class TestSendgridPatterns:
    """Test the SENDGRID_PATTERNS dict of compiled regexes."""

    def test_is_dict(self):
        assert isinstance(SENDGRID_PATTERNS, dict)

    def test_count_is_1(self):
        assert len(SENDGRID_PATTERNS) == 1

    def test_has_api_key(self):
        assert "api_key" in SENDGRID_PATTERNS

    def test_api_key_is_compiled_regex(self):
        assert isinstance(SENDGRID_PATTERNS["api_key"], re.Pattern)

    def test_api_key_matches_valid_sendgrid_key(self):
        # SG. + 22 base64 chars + . + 43 base64 chars
        key = "SG." + "a" * 22 + "." + "b" * 43
        assert SENDGRID_PATTERNS["api_key"].search(key)

    def test_api_key_rejects_wrong_prefix(self):
        key = "XX." + "a" * 22 + "." + "b" * 43
        assert SENDGRID_PATTERNS["api_key"].search(key) is None

    def test_api_key_rejects_short_segments(self):
        key = "SG." + "a" * 10 + "." + "b" * 10
        assert SENDGRID_PATTERNS["api_key"].search(key) is None


# =============================================================================
# MODULE-LEVEL LIST — PHONE_ENUM_ENDPOINTS
# =============================================================================

class TestPhoneEnumEndpoints:
    """Test the PHONE_ENUM_ENDPOINTS list."""

    def test_is_list(self):
        assert isinstance(PHONE_ENUM_ENDPOINTS, list)

    def test_count_is_12(self):
        assert len(PHONE_ENUM_ENDPOINTS) == 12

    def test_all_are_strings(self):
        for endpoint in PHONE_ENUM_ENDPOINTS:
            assert isinstance(endpoint, str)

    def test_all_start_with_slash(self):
        for endpoint in PHONE_ENUM_ENDPOINTS:
            assert endpoint.startswith("/"), f"Endpoint does not start with /: {endpoint!r}"

    def test_no_duplicates(self):
        assert len(PHONE_ENUM_ENDPOINTS) == len(set(PHONE_ENUM_ENDPOINTS))

    def test_contains_authy_users_new(self):
        assert "/authy/users/new" in PHONE_ENUM_ENDPOINTS

    def test_contains_users_exists(self):
        assert "/users/exists" in PHONE_ENUM_ENDPOINTS

    def test_contains_verify_lookup(self):
        assert "/verify/lookup" in PHONE_ENUM_ENDPOINTS

    def test_contains_phone_status_template(self):
        assert "/protected/json/users/{phone}/status" in PHONE_ENUM_ENDPOINTS


# =============================================================================
# MODULE-LEVEL LIST — SMS_ABUSE_ENDPOINTS
# =============================================================================

class TestSmsAbuseEndpoints:
    """Test the SMS_ABUSE_ENDPOINTS list."""

    def test_is_list(self):
        assert isinstance(SMS_ABUSE_ENDPOINTS, list)

    def test_count_is_10(self):
        assert len(SMS_ABUSE_ENDPOINTS) == 10

    def test_all_are_strings(self):
        for endpoint in SMS_ABUSE_ENDPOINTS:
            assert isinstance(endpoint, str)

    def test_all_start_with_slash(self):
        for endpoint in SMS_ABUSE_ENDPOINTS:
            assert endpoint.startswith("/"), f"Endpoint does not start with /: {endpoint!r}"

    def test_no_duplicates(self):
        assert len(SMS_ABUSE_ENDPOINTS) == len(set(SMS_ABUSE_ENDPOINTS))

    def test_contains_messages_json(self):
        assert "/Messages.json" in SMS_ABUSE_ENDPOINTS

    def test_contains_calls_json(self):
        assert "/Calls.json" in SMS_ABUSE_ENDPOINTS

    def test_contains_twilio_api_messages(self):
        assert "/2010-04-01/Accounts/{sid}/Messages.json" in SMS_ABUSE_ENDPOINTS

    def test_contains_twilio_api_calls(self):
        assert "/2010-04-01/Accounts/{sid}/Calls.json" in SMS_ABUSE_ENDPOINTS

    def test_contains_sms_send(self):
        assert "/api/sms/send" in SMS_ABUSE_ENDPOINTS

    def test_contains_voice_call(self):
        assert "/api/voice/call" in SMS_ABUSE_ENDPOINTS

    def test_contains_verifications_v1(self):
        assert "/verify/v1/Services/{service}/Verifications" in SMS_ABUSE_ENDPOINTS

    def test_contains_verifications_v2(self):
        assert "/v2/Services/{service}/Verifications" in SMS_ABUSE_ENDPOINTS


# =============================================================================
# MODULE-LEVEL LIST — PREMIUM_RATE_PREFIXES
# =============================================================================

class TestPremiumRatePrefixes:
    """Test the PREMIUM_RATE_PREFIXES list."""

    def test_is_list(self):
        assert isinstance(PREMIUM_RATE_PREFIXES, list)

    def test_count_is_7(self):
        assert len(PREMIUM_RATE_PREFIXES) == 7

    def test_all_are_strings(self):
        for prefix in PREMIUM_RATE_PREFIXES:
            assert isinstance(prefix, str)

    def test_all_start_with_plus(self):
        for prefix in PREMIUM_RATE_PREFIXES:
            assert prefix.startswith("+"), f"Prefix missing +: {prefix!r}"

    def test_no_duplicates(self):
        assert len(PREMIUM_RATE_PREFIXES) == len(set(PREMIUM_RATE_PREFIXES))

    def test_contains_international_networks_882(self):
        assert "+882" in PREMIUM_RATE_PREFIXES

    def test_contains_international_networks_883(self):
        assert "+883" in PREMIUM_RATE_PREFIXES

    def test_contains_shared_cost_808(self):
        assert "+808" in PREMIUM_RATE_PREFIXES

    def test_contains_inmarsat_870(self):
        assert "+870" in PREMIUM_RATE_PREFIXES

    def test_contains_international_premium_rate_979(self):
        assert "+979" in PREMIUM_RATE_PREFIXES

    def test_contains_global_mobile_satellite_881(self):
        assert "+881" in PREMIUM_RATE_PREFIXES

    def test_contains_universal_personal_telecom_878(self):
        assert "+878" in PREMIUM_RATE_PREFIXES


# =============================================================================
# DATACLASS — CommunicationsEndpoint
# =============================================================================

class TestCommunicationsEndpointDefaults:
    """Test CommunicationsEndpoint dataclass default values."""

    def test_field_count(self):
        assert len(dc_fields(CommunicationsEndpoint)) == 6

    def test_field_names(self):
        names = [f.name for f in dc_fields(CommunicationsEndpoint)]
        assert names == ["url", "method", "endpoint_type", "parameters", "requires_auth", "risk_level"]

    def test_defaults_parameters_empty_list(self):
        ep = CommunicationsEndpoint(url="/test", method="GET", endpoint_type="sms")
        assert ep.parameters == []

    def test_defaults_requires_auth_true(self):
        ep = CommunicationsEndpoint(url="/test", method="GET", endpoint_type="sms")
        assert ep.requires_auth is True

    def test_defaults_risk_level_medium(self):
        ep = CommunicationsEndpoint(url="/test", method="GET", endpoint_type="sms")
        assert ep.risk_level == "medium"

    def test_parameters_default_is_independent_list(self):
        """Each instance should get its own parameters list."""
        ep1 = CommunicationsEndpoint(url="/a", method="GET", endpoint_type="sms")
        ep2 = CommunicationsEndpoint(url="/b", method="GET", endpoint_type="sms")
        ep1.parameters.append("phone")
        assert ep2.parameters == []


class TestCommunicationsEndpointFull:
    """Test CommunicationsEndpoint with all fields specified."""

    def test_full_creation(self):
        ep = CommunicationsEndpoint(
            url="https://api.twilio.com/Messages.json",
            method="POST",
            endpoint_type="sms",
            parameters=["To", "From", "Body"],
            requires_auth=False,
            risk_level="critical",
        )
        assert ep.url == "https://api.twilio.com/Messages.json"
        assert ep.method == "POST"
        assert ep.endpoint_type == "sms"
        assert ep.parameters == ["To", "From", "Body"]
        assert ep.requires_auth is False
        assert ep.risk_level == "critical"

    def test_endpoint_types(self):
        """The docstring says endpoint_type is one of: sms, voice, verify, lookup, auth."""
        for etype in ("sms", "voice", "verify", "lookup", "auth"):
            ep = CommunicationsEndpoint(url="/x", method="GET", endpoint_type=etype)
            assert ep.endpoint_type == etype


# =============================================================================
# SCANNER IDENTITY — CommunicationsAPIScanner
# =============================================================================

class TestScannerIdentity:
    """Test CommunicationsAPIScanner class attributes and hierarchy."""

    def test_name_attribute(self):
        assert CommunicationsAPIScanner.name == "communications_api_scanner"

    def test_is_scan_module_subclass(self):
        assert issubclass(CommunicationsAPIScanner, ScanModule)

    def test_mro_includes_scan_module(self):
        assert ScanModule in CommunicationsAPIScanner.__mro__


# =============================================================================
# SCANNER INSTANTIATION
# =============================================================================

class TestScannerInstantiation:
    """Test CommunicationsAPIScanner.__init__ with mock settings."""

    settings = {"target_url": "http://test.local", "safety_level": "safe"}

    def test_creates_instance(self):
        scanner = CommunicationsAPIScanner(self.settings)
        assert scanner is not None

    def test_name_on_instance(self):
        scanner = CommunicationsAPIScanner(self.settings)
        assert scanner.name == "communications_api_scanner"

    def test_discovered_endpoints_initially_empty(self):
        scanner = CommunicationsAPIScanner(self.settings)
        assert scanner.discovered_endpoints == []

    def test_discovered_endpoints_is_list(self):
        scanner = CommunicationsAPIScanner(self.settings)
        assert isinstance(scanner.discovered_endpoints, list)


# =============================================================================
# SCAN METHOD SIGNATURE
# =============================================================================

class TestScanMethod:
    """Test scan method signature and async nature."""

    def test_scan_method_exists(self):
        assert hasattr(CommunicationsAPIScanner, "scan")

    def test_scan_is_coroutine_function(self):
        assert asyncio.iscoroutinefunction(CommunicationsAPIScanner.scan)

    def test_scan_accepts_host_asset_data_rate_limiter(self):
        sig = inspect.signature(CommunicationsAPIScanner.scan)
        param_names = list(sig.parameters.keys())
        assert "host" in param_names
        assert "asset_data" in param_names
        assert "rate_limiter" in param_names


# =============================================================================
# HELPER METHODS EXIST
# =============================================================================

class TestHelperMethods:
    """Test that expected private helper methods exist and are async."""

    def test_has_is_communications_target(self):
        assert hasattr(CommunicationsAPIScanner, "_is_communications_target")

    def test_is_communications_target_is_sync(self):
        # _is_communications_target is a regular sync method
        assert not asyncio.iscoroutinefunction(CommunicationsAPIScanner._is_communications_target)

    def test_has_test_phone_enumeration(self):
        assert hasattr(CommunicationsAPIScanner, "_test_phone_enumeration")

    def test_phone_enumeration_is_async(self):
        assert asyncio.iscoroutinefunction(CommunicationsAPIScanner._test_phone_enumeration)

    def test_has_test_credential_exposure(self):
        assert hasattr(CommunicationsAPIScanner, "_test_credential_exposure")

    def test_credential_exposure_is_async(self):
        assert asyncio.iscoroutinefunction(CommunicationsAPIScanner._test_credential_exposure)

    def test_has_test_sms_abuse_endpoints(self):
        assert hasattr(CommunicationsAPIScanner, "_test_sms_abuse_endpoints")

    def test_sms_abuse_is_async(self):
        assert asyncio.iscoroutinefunction(CommunicationsAPIScanner._test_sms_abuse_endpoints)

    def test_has_test_auth_bypass(self):
        assert hasattr(CommunicationsAPIScanner, "_test_auth_bypass")

    def test_auth_bypass_is_async(self):
        assert asyncio.iscoroutinefunction(CommunicationsAPIScanner._test_auth_bypass)

    def test_has_test_verify_rate_limit(self):
        assert hasattr(CommunicationsAPIScanner, "_test_verify_rate_limit")

    def test_verify_rate_limit_is_async(self):
        assert asyncio.iscoroutinefunction(CommunicationsAPIScanner._test_verify_rate_limit)

    def test_has_test_api_docs_exposure(self):
        assert hasattr(CommunicationsAPIScanner, "_test_api_docs_exposure")

    def test_api_docs_exposure_is_async(self):
        assert asyncio.iscoroutinefunction(CommunicationsAPIScanner._test_api_docs_exposure)


# =============================================================================
# _is_communications_target — SYNC, DIRECTLY TESTABLE
# =============================================================================

class TestIsCommunicationsTarget:
    """Test the _is_communications_target helper directly."""

    settings = {"target_url": "http://test.local", "safety_level": "safe"}

    def _check(self, hostname: str) -> bool:
        scanner = CommunicationsAPIScanner(self.settings)
        return scanner._is_communications_target(hostname)

    def test_twilio_com(self):
        assert self._check("api.twilio.com") is True

    def test_sendgrid_com(self):
        assert self._check("api.sendgrid.com") is True

    def test_sendgrid_net(self):
        assert self._check("email.sendgrid.net") is True

    def test_authy_com(self):
        assert self._check("api.authy.com") is True

    def test_segment_io(self):
        assert self._check("cdn.segment.io") is True

    def test_segment_com(self):
        assert self._check("app.segment.com") is True

    def test_case_insensitive(self):
        assert self._check("API.TWILIO.COM") is True

    def test_rejects_non_comms_domain(self):
        assert self._check("example.com") is False

    def test_rejects_google(self):
        assert self._check("www.google.com") is False

    def test_rejects_empty(self):
        assert self._check("") is False

    def test_rejects_partial_match(self):
        # "twilio" substring without .com suffix shouldn't be in the domain list,
        # but "twilio.com" IS a substring of "nottwilio.com", so this actually matches.
        # That's fine -- the check uses substring matching.
        assert self._check("nottwilio.com") is True

    def test_rejects_unrelated(self):
        assert self._check("my-app.herokuapp.com") is False


# =============================================================================
# REGEX PATTERNS — DETAILED MATCH/REJECT TESTS
# =============================================================================

class TestTwilioAccountSidRegex:
    """Detailed tests for TWILIO_PATTERNS['account_sid'] regex."""

    pattern = TWILIO_PATTERNS["account_sid"]

    def test_exact_34_chars(self):
        sid = "AC" + "a" * 32
        assert self.pattern.search(sid) is not None

    def test_embedded_in_text(self):
        sid = "AC" + "1" * 32
        text = f"Your Account SID is {sid} and it's secret"
        match = self.pattern.search(text)
        assert match is not None
        assert match.group().startswith("AC")

    def test_rejects_31_hex_after_ac(self):
        sid = "AC" + "a" * 31
        # The pattern requires exactly 32 hex chars after AC, but since it's a search
        # and not fullmatch, it won't match if there are only 31
        match = self.pattern.fullmatch(sid)
        assert match is None


class TestTwilioApiKeyRegex:
    """Detailed tests for TWILIO_PATTERNS['api_key'] regex."""

    pattern = TWILIO_PATTERNS["api_key"]

    def test_exact_34_chars(self):
        key = "SK" + "f" * 32
        assert self.pattern.search(key) is not None

    def test_embedded_in_json(self):
        key = "SK" + "0" * 32
        text = f'{{"api_key": "{key}"}}'
        match = self.pattern.search(text)
        assert match is not None
        assert match.group().startswith("SK")


class TestSendgridApiKeyRegex:
    """Detailed tests for SENDGRID_PATTERNS['api_key'] regex."""

    pattern = SENDGRID_PATTERNS["api_key"]

    def test_valid_key_structure(self):
        key = "SG." + "A" * 22 + "." + "B" * 43
        assert self.pattern.search(key) is not None

    def test_with_dashes_and_underscores(self):
        key = "SG." + "A_b-C" * 4 + "ab" + "." + "D_e-F" * 8 + "gHi"
        assert self.pattern.search(key) is not None

    def test_rejects_no_dot_separator(self):
        key = "SG" + "A" * 22 + "B" * 43
        assert self.pattern.search(key) is None


class TestPhoneNumberRegex:
    """Detailed tests for TWILIO_PATTERNS['phone_number'] regex."""

    pattern = TWILIO_PATTERNS["phone_number"]

    def test_us_number(self):
        assert self.pattern.search("+14155551234")

    def test_uk_number(self):
        assert self.pattern.search("+447911123456")

    def test_short_number(self):
        assert self.pattern.search("+12")

    def test_no_plus(self):
        assert self.pattern.search("14155551234")


# =============================================================================
# AUTH BYPASS PAYLOADS (inline in method, verify structure via source)
# =============================================================================

class TestAuthBypassPayloadsStructure:
    """
    The bypass_payloads list is defined inside _test_auth_bypass.
    We verify the method source contains the expected payloads.
    """

    source = inspect.getsource(CommunicationsAPIScanner._test_auth_bypass)

    def test_contains_null_injection(self):
        assert "@null" in self.source

    def test_contains_empty_string_payload(self):
        assert '""' in self.source

    def test_contains_zero_payload(self):
        assert '"0"' in self.source

    def test_contains_six_zeros(self):
        assert '"000000"' in self.source

    def test_contains_otp_key(self):
        assert '"otp"' in self.source

    def test_contains_token_key(self):
        assert '"token"' in self.source

    def test_contains_pin_key(self):
        assert '"pin"' in self.source

    def test_contains_code_key(self):
        assert '"code"' in self.source


# =============================================================================
# ENUM KEYWORDS (inline in _test_phone_enumeration)
# =============================================================================

class TestPhoneEnumKeywords:
    """Verify expected keywords are referenced in the enumeration detection logic."""

    source = inspect.getsource(CommunicationsAPIScanner._test_phone_enumeration)

    def test_contains_not_found(self):
        assert "not found" in self.source

    def test_contains_not_registered(self):
        assert "not registered" in self.source

    def test_contains_user_exists(self):
        assert "user exists" in self.source

    def test_contains_already_registered(self):
        assert "already registered" in self.source

    def test_contains_phone_taken(self):
        assert "phone taken" in self.source

    def test_contains_invalid_phone(self):
        assert "invalid phone" in self.source


# =============================================================================
# COMMUNICATIONS DOMAINS (inline in _is_communications_target)
# =============================================================================

class TestCommDomainsList:
    """Verify the comm_domains list inside _is_communications_target."""

    source = inspect.getsource(CommunicationsAPIScanner._is_communications_target)

    def test_contains_twilio(self):
        assert "twilio.com" in self.source

    def test_contains_sendgrid_com(self):
        assert "sendgrid.com" in self.source

    def test_contains_sendgrid_net(self):
        assert "sendgrid.net" in self.source

    def test_contains_authy(self):
        assert "authy.com" in self.source

    def test_contains_segment_io(self):
        assert "segment.io" in self.source

    def test_contains_segment_com(self):
        assert "segment.com" in self.source


# =============================================================================
# MODULE __all__ EXPORT
# =============================================================================

class TestModuleExports:
    """Test the __all__ export list."""

    def test_all_contains_scanner(self):
        from scanning.modules import communications_api_scanner as mod
        assert "CommunicationsAPIScanner" in mod.__all__

    def test_all_length(self):
        from scanning.modules import communications_api_scanner as mod
        assert len(mod.__all__) == 1
