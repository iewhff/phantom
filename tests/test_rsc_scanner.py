"""
Tests for scanning/modules/rsc_scanner.py

Covers:
- RSCVulnType enum (8 members, auto() values, uniqueness)
- NextJSRouter enum (3 members, string values, uniqueness)
- RSCEndpoint dataclass (defaults, full creation, field independence)
- RSCTestResult dataclass (defaults, full creation, field independence)
- RSCScanner class attributes:
  - Scanner identity (name, version, ScanModule subclass)
  - NEXTJS_INDICATORS dict (2 keys: headers + body)
  - APP_ROUTER_PATTERNS list (8 entries, regex compilation)
  - SERVER_ACTION_PATTERNS list (5 entries, regex compilation)
  - SENSITIVE_PATTERNS list (10 entries, regex compilation + matching)
- Module-level constant RSC_SCANNER_VERSION
- Regex pattern compilation and matching
"""

import re
import pytest
from dataclasses import fields

from scanning.modules.rsc_scanner import (
    RSCVulnType,
    NextJSRouter,
    RSCEndpoint,
    RSCTestResult,
    RSCScanner,
    RSC_SCANNER_VERSION,
)


# =============================================================================
# RSC_SCANNER_VERSION MODULE CONSTANT
# =============================================================================

class TestRSCScannerVersion:
    def test_version_is_string(self):
        assert isinstance(RSC_SCANNER_VERSION, str)

    def test_version_value(self):
        assert RSC_SCANNER_VERSION == "1.0.0"

    def test_version_semver_format(self):
        parts = RSC_SCANNER_VERSION.split(".")
        assert len(parts) == 3
        for part in parts:
            assert part.isdigit()


# =============================================================================
# RSCVulnType ENUM
# =============================================================================

class TestRSCVulnTypeEnum:
    def test_member_count(self):
        assert len(RSCVulnType) == 8

    def test_csrf_bypass_exists(self):
        assert RSCVulnType.CSRF_BYPASS is not None

    def test_auth_bypass_exists(self):
        assert RSCVulnType.AUTH_BYPASS is not None

    def test_action_id_tampering_exists(self):
        assert RSCVulnType.ACTION_ID_TAMPERING is not None

    def test_mass_assignment_exists(self):
        assert RSCVulnType.MASS_ASSIGNMENT is not None

    def test_data_leakage_exists(self):
        assert RSCVulnType.DATA_LEAKAGE is not None

    def test_server_only_exposure_exists(self):
        assert RSCVulnType.SERVER_ONLY_EXPOSURE is not None

    def test_parallel_route_exploit_exists(self):
        assert RSCVulnType.PARALLEL_ROUTE_EXPLOIT is not None

    def test_serialization_injection_exists(self):
        assert RSCVulnType.SERIALIZATION_INJECTION is not None

    def test_all_values_unique(self):
        values = [m.value for m in RSCVulnType]
        assert len(values) == len(set(values))

    def test_all_members_are_auto(self):
        """auto() produces int values."""
        for member in RSCVulnType:
            assert isinstance(member.value, int)


# =============================================================================
# NextJSRouter ENUM
# =============================================================================

class TestNextJSRouterEnum:
    def test_member_count(self):
        assert len(NextJSRouter) == 3

    def test_app_router(self):
        assert NextJSRouter.APP_ROUTER.value == "app"

    def test_pages_router(self):
        assert NextJSRouter.PAGES_ROUTER.value == "pages"

    def test_unknown(self):
        assert NextJSRouter.UNKNOWN.value == "unknown"

    def test_all_values_unique(self):
        values = [m.value for m in NextJSRouter]
        assert len(values) == len(set(values))

    def test_all_values_are_strings(self):
        for member in NextJSRouter:
            assert isinstance(member.value, str)

    def test_all_values_lowercase(self):
        for member in NextJSRouter:
            assert member.value == member.value.lower()


# =============================================================================
# RSCEndpoint DATACLASS
# =============================================================================

class TestRSCEndpointDataclass:
    def test_required_fields(self):
        """url and router_type are required."""
        ep = RSCEndpoint(url="https://example.com/", router_type=NextJSRouter.APP_ROUTER)
        assert ep.url == "https://example.com/"
        assert ep.router_type == NextJSRouter.APP_ROUTER

    def test_default_nextjs_version(self):
        ep = RSCEndpoint(url="https://x.com", router_type=NextJSRouter.UNKNOWN)
        assert ep.nextjs_version == "unknown"

    def test_default_has_server_actions(self):
        ep = RSCEndpoint(url="https://x.com", router_type=NextJSRouter.UNKNOWN)
        assert ep.has_server_actions is False

    def test_default_action_ids(self):
        ep = RSCEndpoint(url="https://x.com", router_type=NextJSRouter.UNKNOWN)
        assert ep.action_ids == []
        assert isinstance(ep.action_ids, list)

    def test_default_parallel_routes(self):
        ep = RSCEndpoint(url="https://x.com", router_type=NextJSRouter.UNKNOWN)
        assert ep.parallel_routes == []
        assert isinstance(ep.parallel_routes, list)

    def test_full_creation(self):
        ep = RSCEndpoint(
            url="https://example.com/app/",
            router_type=NextJSRouter.APP_ROUTER,
            nextjs_version="14.1.0",
            has_server_actions=True,
            action_ids=["abc123", "def456"],
            parallel_routes=["modal", "sidebar"],
        )
        assert ep.url == "https://example.com/app/"
        assert ep.router_type == NextJSRouter.APP_ROUTER
        assert ep.nextjs_version == "14.1.0"
        assert ep.has_server_actions is True
        assert ep.action_ids == ["abc123", "def456"]
        assert ep.parallel_routes == ["modal", "sidebar"]

    def test_field_count(self):
        assert len(fields(RSCEndpoint)) == 6

    def test_action_ids_default_factory_independence(self):
        """Each instance gets its own list."""
        ep1 = RSCEndpoint(url="a", router_type=NextJSRouter.APP_ROUTER)
        ep2 = RSCEndpoint(url="b", router_type=NextJSRouter.APP_ROUTER)
        ep1.action_ids.append("x")
        assert ep2.action_ids == []

    def test_parallel_routes_default_factory_independence(self):
        """Each instance gets its own list."""
        ep1 = RSCEndpoint(url="a", router_type=NextJSRouter.APP_ROUTER)
        ep2 = RSCEndpoint(url="b", router_type=NextJSRouter.APP_ROUTER)
        ep1.parallel_routes.append("modal")
        assert ep2.parallel_routes == []


# =============================================================================
# RSCTestResult DATACLASS
# =============================================================================

class TestRSCTestResultDataclass:
    def test_required_fields(self):
        """vulnerable, vuln_type, confidence, payload are required."""
        r = RSCTestResult(
            vulnerable=True,
            vuln_type=RSCVulnType.CSRF_BYPASS,
            confidence=85,
            payload="test payload",
        )
        assert r.vulnerable is True
        assert r.vuln_type == RSCVulnType.CSRF_BYPASS
        assert r.confidence == 85
        assert r.payload == "test payload"

    def test_default_response_data(self):
        r = RSCTestResult(
            vulnerable=False,
            vuln_type=RSCVulnType.DATA_LEAKAGE,
            confidence=0,
            payload="",
        )
        assert r.response_data == ""

    def test_default_evidence(self):
        r = RSCTestResult(
            vulnerable=False,
            vuln_type=RSCVulnType.DATA_LEAKAGE,
            confidence=0,
            payload="",
        )
        assert r.evidence == []
        assert isinstance(r.evidence, list)

    def test_default_severity(self):
        r = RSCTestResult(
            vulnerable=False,
            vuln_type=RSCVulnType.DATA_LEAKAGE,
            confidence=0,
            payload="",
        )
        assert r.severity == "MEDIUM"

    def test_default_data_leaked(self):
        r = RSCTestResult(
            vulnerable=False,
            vuln_type=RSCVulnType.DATA_LEAKAGE,
            confidence=0,
            payload="",
        )
        assert r.data_leaked is False

    def test_full_creation(self):
        r = RSCTestResult(
            vulnerable=True,
            vuln_type=RSCVulnType.DATA_LEAKAGE,
            confidence=90,
            payload="RSC stream request",
            response_data="api_key: sk_live_xxx",
            evidence=["Sensitive data in RSC payload", "API key exposed"],
            severity="HIGH",
            data_leaked=True,
        )
        assert r.vulnerable is True
        assert r.vuln_type == RSCVulnType.DATA_LEAKAGE
        assert r.confidence == 90
        assert r.payload == "RSC stream request"
        assert r.response_data == "api_key: sk_live_xxx"
        assert r.evidence == ["Sensitive data in RSC payload", "API key exposed"]
        assert r.severity == "HIGH"
        assert r.data_leaked is True

    def test_field_count(self):
        assert len(fields(RSCTestResult)) == 8

    def test_evidence_default_factory_independence(self):
        """Each instance gets its own list."""
        r1 = RSCTestResult(vulnerable=False, vuln_type=RSCVulnType.CSRF_BYPASS, confidence=0, payload="")
        r2 = RSCTestResult(vulnerable=False, vuln_type=RSCVulnType.CSRF_BYPASS, confidence=0, payload="")
        r1.evidence.append("leak")
        assert r2.evidence == []


# =============================================================================
# RSCScanner CLASS IDENTITY
# =============================================================================

class TestRSCScannerIdentity:
    def test_name(self):
        assert RSCScanner.name == "rsc_scanner"

    def test_version(self):
        assert RSCScanner.version == "1.0.0"

    def test_version_matches_module_constant(self):
        assert RSCScanner.version == RSC_SCANNER_VERSION

    def test_is_scan_module(self):
        from scanning.vuln_scanner import ScanModule
        assert issubclass(RSCScanner, ScanModule)


# =============================================================================
# NEXTJS_INDICATORS DICT
# =============================================================================

class TestNextJSIndicators:
    def test_top_level_key_count(self):
        assert len(RSCScanner.NEXTJS_INDICATORS) == 2

    def test_headers_key_exists(self):
        assert "headers" in RSCScanner.NEXTJS_INDICATORS

    def test_body_key_exists(self):
        assert "body" in RSCScanner.NEXTJS_INDICATORS

    def test_headers_count(self):
        assert len(RSCScanner.NEXTJS_INDICATORS["headers"]) == 5

    def test_body_count(self):
        assert len(RSCScanner.NEXTJS_INDICATORS["body"]) == 6

    def test_headers_are_tuples_of_two_strings(self):
        for entry in RSCScanner.NEXTJS_INDICATORS["headers"]:
            assert isinstance(entry, tuple), f"Entry is not a tuple: {entry}"
            assert len(entry) == 2, f"Tuple has {len(entry)} elements"
            assert isinstance(entry[0], str)
            assert isinstance(entry[1], str)

    def test_body_entries_are_strings(self):
        for entry in RSCScanner.NEXTJS_INDICATORS["body"]:
            assert isinstance(entry, str)

    def test_headers_contain_x_nextjs_cache(self):
        names = [h[0] for h in RSCScanner.NEXTJS_INDICATORS["headers"]]
        assert "x-nextjs-cache" in names

    def test_headers_contain_x_nextjs_matched_path(self):
        names = [h[0] for h in RSCScanner.NEXTJS_INDICATORS["headers"]]
        assert "x-nextjs-matched-path" in names

    def test_headers_contain_x_middleware_rewrite(self):
        names = [h[0] for h in RSCScanner.NEXTJS_INDICATORS["headers"]]
        assert "x-middleware-rewrite" in names

    def test_headers_contain_x_middleware_redirect(self):
        names = [h[0] for h in RSCScanner.NEXTJS_INDICATORS["headers"]]
        assert "x-middleware-redirect" in names

    def test_headers_contain_x_vercel_cache(self):
        names = [h[0] for h in RSCScanner.NEXTJS_INDICATORS["headers"]]
        assert "x-vercel-cache" in names

    def test_body_contains_next_static(self):
        assert r"/_next/static" in RSCScanner.NEXTJS_INDICATORS["body"]

    def test_body_contains_next_data(self):
        assert r"__NEXT_DATA__" in RSCScanner.NEXTJS_INDICATORS["body"]

    def test_body_contains_next_dist(self):
        assert r"next/dist" in RSCScanner.NEXTJS_INDICATORS["body"]

    def test_body_contains_dunder_next(self):
        assert r"__next" in RSCScanner.NEXTJS_INDICATORS["body"]

    def test_body_contains_data_nextjs(self):
        assert r"data-nextjs" in RSCScanner.NEXTJS_INDICATORS["body"]

    def test_body_contains_next_router(self):
        assert r"NextRouter" in RSCScanner.NEXTJS_INDICATORS["body"]

    def test_header_patterns_compile_as_regex(self):
        for header_name, pattern in RSCScanner.NEXTJS_INDICATORS["headers"]:
            compiled = re.compile(pattern, re.IGNORECASE)
            assert compiled is not None, f"Failed to compile: {pattern}"

    def test_body_patterns_compile_as_regex(self):
        for pattern in RSCScanner.NEXTJS_INDICATORS["body"]:
            compiled = re.compile(pattern, re.IGNORECASE)
            assert compiled is not None, f"Failed to compile: {pattern}"


# =============================================================================
# NEXTJS_INDICATORS REGEX MATCHING
# =============================================================================

class TestNextJSIndicatorsRegexMatching:
    def test_header_wildcard_matches_any_value(self):
        """All header patterns are .* so they match anything."""
        for header_name, pattern in RSCScanner.NEXTJS_INDICATORS["headers"]:
            assert re.search(pattern, "some-value", re.IGNORECASE)

    def test_body_next_static_matches_script_src(self):
        body_patterns = RSCScanner.NEXTJS_INDICATORS["body"]
        pattern = r"/_next/static"
        assert pattern in body_patterns
        assert re.search(pattern, '<script src="/_next/static/chunks/main.js">')

    def test_body_next_data_matches_script_tag(self):
        body_patterns = RSCScanner.NEXTJS_INDICATORS["body"]
        pattern = r"__NEXT_DATA__"
        assert pattern in body_patterns
        assert re.search(pattern, '<script id="__NEXT_DATA__" type="application/json">')

    def test_body_next_dist_matches_import(self):
        pattern = r"next/dist"
        assert re.search(pattern, 'import "next/dist/client/router"')

    def test_body_dunder_next_matches_div(self):
        pattern = r"__next"
        assert re.search(pattern, '<div id="__next">')

    def test_body_data_nextjs_matches_attribute(self):
        pattern = r"data-nextjs"
        assert re.search(pattern, '<div data-nextjs-page="/">')

    def test_body_next_router_matches_reference(self):
        pattern = r"NextRouter"
        assert re.search(pattern, "window.__NEXT_ROUTER_BASEPATH || NextRouter.push")


# =============================================================================
# APP_ROUTER_PATTERNS LIST
# =============================================================================

class TestAppRouterPatterns:
    def test_count(self):
        assert len(RSCScanner.APP_ROUTER_PATTERNS) == 8

    def test_all_entries_are_strings(self):
        for p in RSCScanner.APP_ROUTER_PATTERNS:
            assert isinstance(p, str)

    def test_all_patterns_compile_as_regex(self):
        for p in RSCScanner.APP_ROUTER_PATTERNS:
            compiled = re.compile(p)
            assert compiled is not None, f"Failed to compile: {p}"

    def test_contains_next_f_pattern(self):
        assert r"__next_f" in RSCScanner.APP_ROUTER_PATTERNS

    def test_contains_action_id_marker(self):
        assert r"\$ACTION_ID" in RSCScanner.APP_ROUTER_PATTERNS

    def test_contains_next_action_id(self):
        assert r"__next_action_id" in RSCScanner.APP_ROUTER_PATTERNS

    def test_contains_not_found_pattern(self):
        assert r"/_not-found" in RSCScanner.APP_ROUTER_PATTERNS

    def test_contains_parallel_route_pattern(self):
        assert r"@[a-z]+/" in RSCScanner.APP_ROUTER_PATTERNS


# =============================================================================
# APP_ROUTER_PATTERNS REGEX MATCHING
# =============================================================================

class TestAppRouterPatternsRegexMatching:
    def test_next_f_matches_flight_data(self):
        pattern = r"__next_f"
        assert re.search(pattern, '<script>self.__next_f.push([1,"data"])</script>')

    def test_action_id_matches_marker(self):
        pattern = r"\$ACTION_ID"
        assert re.search(pattern, 'name="$ACTION_ID_abc123"')

    def test_next_action_id_matches_form(self):
        pattern = r"__next_action_id"
        assert re.search(pattern, '<input type="hidden" name="__next_action_id" value="abc123">')

    def test_hidden_action_input_matches(self):
        pattern = r'type="hidden"\s+name="\$ACTION'
        assert re.search(pattern, 'type="hidden" name="$ACTION_REF_0"')

    def test_rsc_payload_format_0_matches(self):
        pattern = r"0:[^\]]+\]"
        assert re.search(pattern, '0:["$","div",null,{}]')

    def test_rsc_payload_format_1_matches(self):
        pattern = r"1:[^\]]+\]"
        assert re.search(pattern, '1:["$L2",null,{}]')

    def test_not_found_matches(self):
        pattern = r"/_not-found"
        assert re.search(pattern, "/_not-found")

    def test_parallel_route_matches_modal(self):
        pattern = r"@[a-z]+/"
        assert re.search(pattern, "@modal/page.tsx")

    def test_parallel_route_matches_sidebar(self):
        pattern = r"@[a-z]+/"
        assert re.search(pattern, "@sidebar/default.tsx")


# =============================================================================
# SERVER_ACTION_PATTERNS LIST
# =============================================================================

class TestServerActionPatterns:
    def test_count(self):
        assert len(RSCScanner.SERVER_ACTION_PATTERNS) == 5

    def test_all_entries_are_strings(self):
        for p in RSCScanner.SERVER_ACTION_PATTERNS:
            assert isinstance(p, str)

    def test_all_patterns_compile_as_regex(self):
        for p in RSCScanner.SERVER_ACTION_PATTERNS:
            compiled = re.compile(p)
            assert compiled is not None, f"Failed to compile: {p}"

    def test_contains_action_form_pattern(self):
        assert r'action="[^"]*\$ACTION' in RSCScanner.SERVER_ACTION_PATTERNS

    def test_contains_form_action_pattern(self):
        assert r"formAction.*\$ACTION" in RSCScanner.SERVER_ACTION_PATTERNS

    def test_contains_next_action_id_hex(self):
        assert r"__next_action_id=[a-f0-9]+" in RSCScanner.SERVER_ACTION_PATTERNS

    def test_contains_action_ref_pattern(self):
        assert r'name="\$ACTION_REF_\d+"' in RSCScanner.SERVER_ACTION_PATTERNS

    def test_contains_action_numbered_pattern(self):
        assert r'name="\$ACTION_\d+:\d+"' in RSCScanner.SERVER_ACTION_PATTERNS


# =============================================================================
# SERVER_ACTION_PATTERNS REGEX MATCHING
# =============================================================================

class TestServerActionPatternsRegexMatching:
    def test_action_form_matches(self):
        pattern = r'action="[^"]*\$ACTION'
        assert re.search(pattern, 'action="/submit$ACTION_ID_abc123"')

    def test_form_action_dollar_matches(self):
        pattern = r"formAction.*\$ACTION"
        assert re.search(pattern, 'formAction="$ACTION_REF_0"')

    def test_next_action_id_hex_matches(self):
        pattern = r"__next_action_id=[a-f0-9]+"
        assert re.search(pattern, "__next_action_id=abc123def456")

    def test_action_ref_matches(self):
        pattern = r'name="\$ACTION_REF_\d+"'
        assert re.search(pattern, 'name="$ACTION_REF_0"')
        assert re.search(pattern, 'name="$ACTION_REF_12"')

    def test_action_numbered_matches(self):
        pattern = r'name="\$ACTION_\d+:\d+"'
        assert re.search(pattern, 'name="$ACTION_0:1"')
        assert re.search(pattern, 'name="$ACTION_5:10"')

    def test_next_action_id_rejects_non_hex(self):
        pattern = r"__next_action_id=[a-f0-9]+"
        # 'g' is not valid hex
        match = re.search(pattern, "__next_action_id=xyz")
        assert match is None


# =============================================================================
# SENSITIVE_PATTERNS LIST
# =============================================================================

class TestSensitivePatterns:
    def test_count(self):
        assert len(RSCScanner.SENSITIVE_PATTERNS) == 10

    def test_all_entries_are_strings(self):
        for p in RSCScanner.SENSITIVE_PATTERNS:
            assert isinstance(p, str)

    def test_all_patterns_compile_as_regex(self):
        for p in RSCScanner.SENSITIVE_PATTERNS:
            compiled = re.compile(p, re.IGNORECASE)
            assert compiled is not None, f"Failed to compile: {p}"


# =============================================================================
# SENSITIVE_PATTERNS REGEX MATCHING
# =============================================================================

class TestSensitivePatternsRegexMatching:
    def test_password_pattern_matches(self):
        patterns = RSCScanner.SENSITIVE_PATTERNS
        test_str = 'password: "mysecretpass"'
        assert any(re.search(p, test_str, re.IGNORECASE) for p in patterns)

    def test_api_key_pattern_matches(self):
        patterns = RSCScanner.SENSITIVE_PATTERNS
        test_str = 'api_key: "sk_live_abc123"'
        assert any(re.search(p, test_str, re.IGNORECASE) for p in patterns)

    def test_api_key_hyphenated_matches(self):
        patterns = RSCScanner.SENSITIVE_PATTERNS
        test_str = 'api-key: "sk_live_abc123"'
        assert any(re.search(p, test_str, re.IGNORECASE) for p in patterns)

    def test_secret_pattern_matches(self):
        patterns = RSCScanner.SENSITIVE_PATTERNS
        test_str = 'secret = "super_secret_value"'
        assert any(re.search(p, test_str, re.IGNORECASE) for p in patterns)

    def test_token_pattern_matches(self):
        patterns = RSCScanner.SENSITIVE_PATTERNS
        test_str = 'token: "eyJhbGciOiJIUzI1NiJ9.xxxx"'
        assert any(re.search(p, test_str, re.IGNORECASE) for p in patterns)

    def test_private_key_pattern_matches(self):
        patterns = RSCScanner.SENSITIVE_PATTERNS
        test_str = 'private_key: "-----BEGIN RSA PRIVATE KEY-----"'
        assert any(re.search(p, test_str, re.IGNORECASE) for p in patterns)

    def test_private_key_hyphenated_matches(self):
        patterns = RSCScanner.SENSITIVE_PATTERNS
        test_str = 'private-key: "somekeyvalue"'
        assert any(re.search(p, test_str, re.IGNORECASE) for p in patterns)

    def test_database_url_pattern_matches(self):
        patterns = RSCScanner.SENSITIVE_PATTERNS
        test_str = 'database_url: "postgres://user:pass@host/db"'
        assert any(re.search(p, test_str, re.IGNORECASE) for p in patterns)

    def test_connection_string_pattern_matches(self):
        patterns = RSCScanner.SENSITIVE_PATTERNS
        test_str = 'connection_string: "mongodb://user:pass@host/db"'
        assert any(re.search(p, test_str, re.IGNORECASE) for p in patterns)

    def test_email_pattern_matches(self):
        patterns = RSCScanner.SENSITIVE_PATTERNS
        test_str = '"email": "user@example.com"'
        assert any(re.search(p, test_str, re.IGNORECASE) for p in patterns)

    def test_ssn_pattern_matches(self):
        patterns = RSCScanner.SENSITIVE_PATTERNS
        test_str = '"ssn": "123-45-6789"'
        assert any(re.search(p, test_str, re.IGNORECASE) for p in patterns)

    def test_credit_card_pattern_matches(self):
        patterns = RSCScanner.SENSITIVE_PATTERNS
        test_str = '"credit_card": "4111111111111111"'
        assert any(re.search(p, test_str, re.IGNORECASE) for p in patterns)

    def test_no_match_on_innocent_text(self):
        patterns = RSCScanner.SENSITIVE_PATTERNS
        test_str = "This is a normal paragraph with no secrets."
        assert not any(re.search(p, test_str, re.IGNORECASE) for p in patterns)
