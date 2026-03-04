"""
Tests for scanning/modules/client_hardening_scanner.py

Covers:
- CSP_DIRECTIVES dict (14 entries, key directives, value types)
- CSP_DANGEROUS_VALUES dict (8 entries, key values, safe vs dangerous)
- JSONP_PATTERNS list (7 entries, regex compilation, known matches)
- CSP_BYPASS_CDNS list (6 entries, known CDNs)
- CSPPolicy dataclass (defaults, full creation, properties)
- ClientHardeningScanner class identity (name, ScanModule subclass, attributes)
- _parse_csp method (directive parsing, edge cases)
- _resolve_base_url method (protocol inference, port handling)
"""

import re

import pytest

from scanning.modules.client_hardening_scanner import (
    CSP_DIRECTIVES,
    CSP_DANGEROUS_VALUES,
    JSONP_PATTERNS,
    CSP_BYPASS_CDNS,
    CSPPolicy,
    ClientHardeningScanner,
)
from scanning.vuln_scanner import ScanModule


# =============================================================================
# CSP_DIRECTIVES DICT
# =============================================================================

class TestCSPDirectives:
    """Test CSP_DIRECTIVES module-level dict."""

    def test_count(self):
        assert len(CSP_DIRECTIVES) == 14

    def test_is_dict(self):
        assert isinstance(CSP_DIRECTIVES, dict)

    def test_all_keys_are_strings(self):
        for key in CSP_DIRECTIVES:
            assert isinstance(key, str), f"Key should be str: {key}"

    def test_all_values_are_strings(self):
        for key, val in CSP_DIRECTIVES.items():
            assert isinstance(val, str), f"Value for {key} should be str"

    def test_has_default_src(self):
        assert "default-src" in CSP_DIRECTIVES

    def test_has_script_src(self):
        assert "script-src" in CSP_DIRECTIVES

    def test_has_style_src(self):
        assert "style-src" in CSP_DIRECTIVES

    def test_has_img_src(self):
        assert "img-src" in CSP_DIRECTIVES

    def test_has_connect_src(self):
        assert "connect-src" in CSP_DIRECTIVES

    def test_has_font_src(self):
        assert "font-src" in CSP_DIRECTIVES

    def test_has_object_src(self):
        assert "object-src" in CSP_DIRECTIVES

    def test_has_media_src(self):
        assert "media-src" in CSP_DIRECTIVES

    def test_has_frame_src(self):
        assert "frame-src" in CSP_DIRECTIVES

    def test_has_frame_ancestors(self):
        assert "frame-ancestors" in CSP_DIRECTIVES

    def test_has_form_action(self):
        assert "form-action" in CSP_DIRECTIVES

    def test_has_base_uri(self):
        assert "base-uri" in CSP_DIRECTIVES

    def test_has_report_uri(self):
        assert "report-uri" in CSP_DIRECTIVES

    def test_has_report_to(self):
        assert "report-to" in CSP_DIRECTIVES

    def test_script_src_description_mentions_javascript(self):
        assert "JavaScript" in CSP_DIRECTIVES["script-src"]

    def test_frame_ancestors_description_mentions_iframe(self):
        desc = CSP_DIRECTIVES["frame-ancestors"]
        assert "iframe" in desc.lower()

    def test_all_keys_lowercase(self):
        for key in CSP_DIRECTIVES:
            assert key == key.lower(), f"Key should be lowercase: {key}"


# =============================================================================
# CSP_DANGEROUS_VALUES DICT
# =============================================================================

class TestCSPDangerousValues:
    """Test CSP_DANGEROUS_VALUES module-level dict."""

    def test_count(self):
        assert len(CSP_DANGEROUS_VALUES) == 8

    def test_is_dict(self):
        assert isinstance(CSP_DANGEROUS_VALUES, dict)

    def test_has_unsafe_inline(self):
        assert "unsafe-inline" in CSP_DANGEROUS_VALUES

    def test_has_unsafe_eval(self):
        assert "unsafe-eval" in CSP_DANGEROUS_VALUES

    def test_has_unsafe_hashes(self):
        assert "unsafe-hashes" in CSP_DANGEROUS_VALUES

    def test_has_wildcard(self):
        assert "*" in CSP_DANGEROUS_VALUES

    def test_has_data_uri(self):
        assert "data:" in CSP_DANGEROUS_VALUES

    def test_has_blob_uri(self):
        assert "blob:" in CSP_DANGEROUS_VALUES

    def test_has_none(self):
        assert "'none'" in CSP_DANGEROUS_VALUES

    def test_has_self(self):
        assert "'self'" in CSP_DANGEROUS_VALUES

    def test_none_is_safe(self):
        assert CSP_DANGEROUS_VALUES["'none'"] is None

    def test_self_is_safe(self):
        assert CSP_DANGEROUS_VALUES["'self'"] is None

    def test_unsafe_inline_is_dangerous(self):
        assert CSP_DANGEROUS_VALUES["unsafe-inline"] is not None
        assert "XSS" in CSP_DANGEROUS_VALUES["unsafe-inline"]

    def test_unsafe_eval_is_dangerous(self):
        assert CSP_DANGEROUS_VALUES["unsafe-eval"] is not None
        assert "eval" in CSP_DANGEROUS_VALUES["unsafe-eval"]

    def test_wildcard_is_dangerous(self):
        assert CSP_DANGEROUS_VALUES["*"] is not None
        assert "any" in CSP_DANGEROUS_VALUES["*"].lower()

    def test_data_uri_is_dangerous(self):
        assert CSP_DANGEROUS_VALUES["data:"] is not None
        assert "data:" in CSP_DANGEROUS_VALUES["data:"]

    def test_dangerous_values_have_descriptions(self):
        for key, val in CSP_DANGEROUS_VALUES.items():
            if val is not None:
                assert isinstance(val, str), f"Description for {key} should be str"
                assert len(val) > 5, f"Description for {key} too short"


# =============================================================================
# JSONP_PATTERNS LIST
# =============================================================================

class TestJSONPPatterns:
    """Test JSONP_PATTERNS list of regex patterns."""

    def test_count(self):
        assert len(JSONP_PATTERNS) == 7

    def test_is_list(self):
        assert isinstance(JSONP_PATTERNS, list)

    def test_all_are_strings(self):
        for pattern in JSONP_PATTERNS:
            assert isinstance(pattern, str)

    def test_all_compile(self):
        for pattern in JSONP_PATTERNS:
            compiled = re.compile(pattern)
            assert compiled is not None, f"Pattern should compile: {pattern}"

    def test_matches_callback_param(self):
        assert any(re.search(p, "callback=myFunc") for p in JSONP_PATTERNS)

    def test_matches_jsonp_param(self):
        assert any(re.search(p, "jsonp=handler") for p in JSONP_PATTERNS)

    def test_matches_cb_param(self):
        assert any(re.search(p, "cb=myCallback") for p in JSONP_PATTERNS)

    def test_matches_jsonpcallback_param(self):
        assert any(re.search(p, "jsonpcallback=fn") for p in JSONP_PATTERNS)

    def test_matches_jsonp_extension(self):
        assert any(re.search(p, "data.jsonp") for p in JSONP_PATTERNS)

    def test_matches_json_in_script(self):
        assert any(re.search(p, "json-in-script") for p in JSONP_PATTERNS)

    def test_has_callback_pattern(self):
        assert r"callback=" in JSONP_PATTERNS

    def test_has_jsonp_pattern(self):
        assert r"jsonp=" in JSONP_PATTERNS

    def test_has_cb_pattern(self):
        assert r"cb=" in JSONP_PATTERNS


# =============================================================================
# CSP_BYPASS_CDNS LIST
# =============================================================================

class TestCSPBypassCDNs:
    """Test CSP_BYPASS_CDNS list of known bypass CDN domains."""

    def test_count(self):
        assert len(CSP_BYPASS_CDNS) == 6

    def test_is_list(self):
        assert isinstance(CSP_BYPASS_CDNS, list)

    def test_all_are_strings(self):
        for cdn in CSP_BYPASS_CDNS:
            assert isinstance(cdn, str)

    def test_has_cdnjs_cloudflare(self):
        assert "cdnjs.cloudflare.com" in CSP_BYPASS_CDNS

    def test_has_jsdelivr(self):
        assert "cdn.jsdelivr.net" in CSP_BYPASS_CDNS

    def test_has_unpkg(self):
        assert "unpkg.com" in CSP_BYPASS_CDNS

    def test_has_ajax_googleapis(self):
        assert "ajax.googleapis.com" in CSP_BYPASS_CDNS

    def test_has_code_jquery(self):
        assert "code.jquery.com" in CSP_BYPASS_CDNS

    def test_has_stackpath_bootstrap(self):
        assert "stackpath.bootstrapcdn.com" in CSP_BYPASS_CDNS

    def test_all_are_domains(self):
        for cdn in CSP_BYPASS_CDNS:
            assert "." in cdn, f"CDN should be a domain: {cdn}"
            assert " " not in cdn, f"CDN should not contain spaces: {cdn}"
            assert not cdn.startswith("http"), f"CDN should be domain only: {cdn}"

    def test_all_unique(self):
        assert len(CSP_BYPASS_CDNS) == len(set(CSP_BYPASS_CDNS))


# =============================================================================
# CSPPolicy DATACLASS
# =============================================================================

class TestCSPPolicy:
    """Test CSPPolicy dataclass."""

    def test_defaults(self):
        policy = CSPPolicy(raw="default-src 'self'")
        assert policy.raw == "default-src 'self'"
        assert policy.directives == {}
        assert policy.report_only is False

    def test_full_creation(self):
        policy = CSPPolicy(
            raw="script-src 'self' https://cdn.example.com; style-src 'unsafe-inline'",
            directives={
                "script-src": ["'self'", "https://cdn.example.com"],
                "style-src": ["'unsafe-inline'"],
            },
            report_only=True,
        )
        assert policy.raw.startswith("script-src")
        assert "script-src" in policy.directives
        assert len(policy.directives["script-src"]) == 2
        assert policy.report_only is True

    def test_empty_raw(self):
        policy = CSPPolicy(raw="")
        assert policy.raw == ""
        assert policy.directives == {}

    def test_directives_default_is_new_dict_each_time(self):
        policy1 = CSPPolicy(raw="a")
        policy2 = CSPPolicy(raw="b")
        policy1.directives["test"] = ["value"]
        assert "test" not in policy2.directives

    def test_report_only_false_by_default(self):
        policy = CSPPolicy(raw="default-src 'none'")
        assert policy.report_only is False

    def test_report_only_true(self):
        policy = CSPPolicy(raw="default-src 'none'", report_only=True)
        assert policy.report_only is True


# =============================================================================
# SCANNER IDENTITY
# =============================================================================

class TestClientHardeningScannerIdentity:
    """Test ClientHardeningScanner class identity and attributes."""

    def test_is_scan_module_subclass(self):
        assert issubclass(ClientHardeningScanner, ScanModule)

    def test_name_attribute(self):
        assert ClientHardeningScanner.name == "client_hardening"

    def test_description_attribute(self):
        assert hasattr(ClientHardeningScanner, "description")
        assert isinstance(ClientHardeningScanner.description, str)
        assert len(ClientHardeningScanner.description) > 10

    def test_version_attribute(self):
        assert ClientHardeningScanner.version == "1.0.0"

    def test_author_attribute(self):
        assert ClientHardeningScanner.author == "PHANTOM AI"

    def test_tags_attribute(self):
        assert isinstance(ClientHardeningScanner.tags, list)
        assert len(ClientHardeningScanner.tags) == 5

    def test_tags_contains_csp(self):
        assert "csp" in ClientHardeningScanner.tags

    def test_tags_contains_sri(self):
        assert "sri" in ClientHardeningScanner.tags

    def test_tags_contains_postmessage(self):
        assert "postmessage" in ClientHardeningScanner.tags

    def test_tags_contains_client(self):
        assert "client" in ClientHardeningScanner.tags

    def test_tags_contains_browser(self):
        assert "browser" in ClientHardeningScanner.tags

    def test_instantiation(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = ClientHardeningScanner(settings)
        assert scanner is not None

    def test_instance_is_scan_module(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = ClientHardeningScanner(settings)
        assert isinstance(scanner, ScanModule)

    def test_instance_base_url_empty(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = ClientHardeningScanner(settings)
        assert scanner._base_url == ""

    def test_instance_csp_policy_none(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = ClientHardeningScanner(settings)
        assert scanner._csp_policy is None

    def test_instance_page_content_empty(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = ClientHardeningScanner(settings)
        assert scanner._page_content == ""


# =============================================================================
# _parse_csp METHOD (synchronous, no HTTP)
# =============================================================================

class TestParseCSP:
    """Test ClientHardeningScanner._parse_csp method."""

    def _make_scanner(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        return ClientHardeningScanner(settings)

    def test_simple_policy(self):
        scanner = self._make_scanner()
        policy = scanner._parse_csp("default-src 'self'")
        assert isinstance(policy, CSPPolicy)
        assert "default-src" in policy.directives
        assert "'self'" in policy.directives["default-src"]

    def test_multiple_directives(self):
        scanner = self._make_scanner()
        raw = "default-src 'none'; script-src 'self' https://cdn.example.com; style-src 'unsafe-inline'"
        policy = scanner._parse_csp(raw)
        assert len(policy.directives) == 3
        assert "default-src" in policy.directives
        assert "script-src" in policy.directives
        assert "style-src" in policy.directives

    def test_script_src_values(self):
        scanner = self._make_scanner()
        raw = "script-src 'self' https://cdn.example.com https://other.com"
        policy = scanner._parse_csp(raw)
        assert len(policy.directives["script-src"]) == 3

    def test_report_only_flag(self):
        scanner = self._make_scanner()
        policy = scanner._parse_csp("default-src 'self'", report_only=True)
        assert policy.report_only is True

    def test_report_only_default_false(self):
        scanner = self._make_scanner()
        policy = scanner._parse_csp("default-src 'self'")
        assert policy.report_only is False

    def test_empty_string(self):
        scanner = self._make_scanner()
        policy = scanner._parse_csp("")
        assert policy.directives == {}

    def test_raw_preserved(self):
        scanner = self._make_scanner()
        raw = "default-src 'self'; script-src 'unsafe-inline'"
        policy = scanner._parse_csp(raw)
        assert policy.raw == raw

    def test_directive_lowercase(self):
        scanner = self._make_scanner()
        policy = scanner._parse_csp("Script-Src 'self'")
        assert "script-src" in policy.directives

    def test_directive_with_no_values(self):
        scanner = self._make_scanner()
        # Upgrade-insecure-requests has no values typically
        policy = scanner._parse_csp("upgrade-insecure-requests")
        assert "upgrade-insecure-requests" in policy.directives
        assert policy.directives["upgrade-insecure-requests"] == []

    def test_trailing_semicolons(self):
        scanner = self._make_scanner()
        policy = scanner._parse_csp("default-src 'self';;; ")
        assert "default-src" in policy.directives
        assert len(policy.directives) == 1

    def test_wildcard_value(self):
        scanner = self._make_scanner()
        policy = scanner._parse_csp("script-src *")
        assert "*" in policy.directives["script-src"]


# =============================================================================
# _resolve_base_url METHOD (synchronous, no HTTP)
# =============================================================================

class TestResolveBaseURL:
    """Test ClientHardeningScanner._resolve_base_url method."""

    def _make_scanner(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        return ClientHardeningScanner(settings)

    def test_http_url_passthrough(self):
        scanner = self._make_scanner()
        result = scanner._resolve_base_url("http://example.com", None)
        assert result == "http://example.com"

    def test_https_url_passthrough(self):
        scanner = self._make_scanner()
        result = scanner._resolve_base_url("https://example.com", None)
        assert result == "https://example.com"

    def test_url_trailing_slash_stripped(self):
        scanner = self._make_scanner()
        result = scanner._resolve_base_url("http://example.com/", None)
        assert result == "http://example.com"

    def test_port_443_uses_https(self):
        scanner = self._make_scanner()
        result = scanner._resolve_base_url("example.com", 443)
        assert result == "https://example.com"

    def test_port_8443_uses_https(self):
        scanner = self._make_scanner()
        result = scanner._resolve_base_url("example.com", 8443)
        assert result == "https://example.com:8443"

    def test_port_80_uses_http_no_port(self):
        scanner = self._make_scanner()
        result = scanner._resolve_base_url("example.com", 80)
        assert result == "http://example.com"

    def test_port_none_uses_http(self):
        scanner = self._make_scanner()
        result = scanner._resolve_base_url("example.com", None)
        assert result == "http://example.com"

    def test_custom_port_included(self):
        scanner = self._make_scanner()
        result = scanner._resolve_base_url("example.com", 8080)
        assert result == "http://example.com:8080"

    def test_custom_https_port(self):
        scanner = self._make_scanner()
        # Port 9443 is not in the HTTPS list, should use http with port
        result = scanner._resolve_base_url("example.com", 9443)
        assert result == "http://example.com:9443"

    def test_full_url_ignores_port(self):
        scanner = self._make_scanner()
        result = scanner._resolve_base_url("https://example.com:9090", 443)
        assert result == "https://example.com:9090"


# =============================================================================
# REGEX PATTERNS USED IN SCAN METHODS
# =============================================================================

class TestRegexPatterns:
    """Test regex patterns used internally by the scanner methods."""

    def test_csp_meta_tag_pattern_compiles(self):
        """The CSP meta tag pattern used in _fetch_main_page should compile."""
        pattern = r'<meta[^>]+http-equiv=["\']Content-Security-Policy["\'][^>]+content=["\']([^"\']+)["\']'
        compiled = re.compile(pattern, re.IGNORECASE)
        assert compiled is not None

    def test_csp_meta_tag_matches_double_quotes(self):
        pattern = r'<meta[^>]+http-equiv=["\']Content-Security-Policy["\'][^>]+content=["\']([^"\']+)["\']'
        html = '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'">'
        match = re.search(pattern, html, re.IGNORECASE)
        assert match is not None
        assert "default-src" in match.group(1)

    def test_csp_meta_tag_matches_single_quotes(self):
        pattern = r'<meta[^>]+http-equiv=["\']Content-Security-Policy["\'][^>]+content=["\']([^"\']+)["\']'
        html = "<meta http-equiv='Content-Security-Policy' content='default-src *'>"
        match = re.search(pattern, html, re.IGNORECASE)
        assert match is not None

    def test_script_src_pattern_compiles(self):
        pattern = r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>'
        compiled = re.compile(pattern, re.IGNORECASE)
        assert compiled is not None

    def test_script_src_matches(self):
        pattern = r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>'
        html = '<script src="https://cdn.example.com/app.js"></script>'
        match = re.search(pattern, html, re.IGNORECASE)
        assert match is not None
        assert match.group(1) == "https://cdn.example.com/app.js"

    def test_link_css_pattern_compiles(self):
        pattern = r'<link[^>]+href=["\']([^"\']+\.css)["\'][^>]*>'
        compiled = re.compile(pattern, re.IGNORECASE)
        assert compiled is not None

    def test_link_css_matches(self):
        pattern = r'<link[^>]+href=["\']([^"\']+\.css)["\'][^>]*>'
        html = '<link rel="stylesheet" href="https://cdn.example.com/style.css">'
        match = re.search(pattern, html, re.IGNORECASE)
        assert match is not None
        assert match.group(1) == "https://cdn.example.com/style.css"

    def test_postmessage_listener_pattern_compiles(self):
        pattern = r'addEventListener\s*\(\s*["\']message["\']'
        compiled = re.compile(pattern)
        assert compiled is not None

    def test_postmessage_listener_matches(self):
        pattern = r'addEventListener\s*\(\s*["\']message["\']'
        code = 'window.addEventListener("message", function(e) {});'
        assert re.search(pattern, code) is not None

    def test_onmessage_pattern_matches(self):
        pattern = r'onmessage\s*='
        code = "window.onmessage = function(e) {};"
        assert re.search(pattern, code) is not None

    def test_origin_check_pattern_compiles(self):
        pattern = r'event\.origin'
        compiled = re.compile(pattern)
        assert compiled is not None

    def test_origin_check_matches(self):
        pattern = r'event\.origin'
        code = 'if (event.origin !== "https://trusted.com") return;'
        assert re.search(pattern, code) is not None

    def test_dangerous_sink_innerHTML_pattern(self):
        pattern = r'innerHTML\s*=.*event\.data'
        code = 'element.innerHTML = event.data;'
        assert re.search(pattern, code, re.IGNORECASE) is not None

    def test_dangerous_sink_eval_pattern(self):
        pattern = r'eval\s*\(.*event\.data'
        code = 'eval(event.data);'
        assert re.search(pattern, code, re.IGNORECASE) is not None

    def test_dangerous_sink_document_write_pattern(self):
        pattern = r'document\.write\s*\(.*event\.data'
        code = 'document.write(event.data);'
        assert re.search(pattern, code, re.IGNORECASE) is not None

    def test_localstorage_sensitive_pattern(self):
        pattern = r'localStorage\.setItem\s*\(\s*["\'](?:token|jwt|auth|session|password|secret|api_key)'
        code = 'localStorage.setItem("token", myToken);'
        assert re.search(pattern, code, re.IGNORECASE) is not None

    def test_sessionstorage_sensitive_pattern(self):
        pattern = r'sessionStorage\.setItem\s*\(\s*["\'](?:token|jwt|auth|session|password|secret|api_key)'
        code = 'sessionStorage.setItem("jwt", value);'
        assert re.search(pattern, code, re.IGNORECASE) is not None

    def test_localstorage_nonsensitive_no_match(self):
        pattern = r'localStorage\.setItem\s*\(\s*["\'](?:token|jwt|auth|session|password|secret|api_key)'
        code = 'localStorage.setItem("theme", "dark");'
        assert re.search(pattern, code, re.IGNORECASE) is None

    def test_id_attribute_pattern(self):
        pattern = r'id=["\']([^"\']+)["\']'
        html = '<div id="config-panel">Content</div>'
        match = re.search(pattern, html)
        assert match is not None
        assert match.group(1) == "config-panel"

    def test_name_attribute_pattern(self):
        pattern = r'name=["\']([^"\']+)["\']'
        html = '<input name="auth_token" type="hidden">'
        match = re.search(pattern, html)
        assert match is not None
        assert match.group(1) == "auth_token"


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Test edge cases and structural properties."""

    def test_all_csp_directive_keys_unique(self):
        keys = list(CSP_DIRECTIVES.keys())
        assert len(keys) == len(set(keys))

    def test_all_csp_dangerous_keys_unique(self):
        keys = list(CSP_DANGEROUS_VALUES.keys())
        assert len(keys) == len(set(keys))

    def test_all_jsonp_patterns_unique(self):
        assert len(JSONP_PATTERNS) == len(set(JSONP_PATTERNS))

    def test_all_bypass_cdns_unique(self):
        assert len(CSP_BYPASS_CDNS) == len(set(CSP_BYPASS_CDNS))

    def test_scanner_has_scan_method(self):
        assert hasattr(ClientHardeningScanner, "scan")

    def test_scanner_has_parse_csp_method(self):
        assert hasattr(ClientHardeningScanner, "_parse_csp")

    def test_scanner_has_resolve_base_url_method(self):
        assert hasattr(ClientHardeningScanner, "_resolve_base_url")

    def test_scanner_has_analyze_csp_method(self):
        assert hasattr(ClientHardeningScanner, "_analyze_csp")

    def test_scanner_has_analyze_sri_method(self):
        assert hasattr(ClientHardeningScanner, "_analyze_sri")

    def test_scanner_has_analyze_postmessage_method(self):
        assert hasattr(ClientHardeningScanner, "_analyze_postmessage")

    def test_scanner_has_analyze_client_storage_method(self):
        assert hasattr(ClientHardeningScanner, "_analyze_client_storage")

    def test_scanner_has_analyze_security_headers_method(self):
        assert hasattr(ClientHardeningScanner, "_analyze_security_headers")

    def test_scanner_has_analyze_dom_clobbering_method(self):
        assert hasattr(ClientHardeningScanner, "_analyze_dom_clobbering")

    def test_csp_policy_directives_mutable(self):
        policy = CSPPolicy(raw="test")
        policy.directives["new-directive"] = ["value"]
        assert "new-directive" in policy.directives

    def test_parse_csp_complex_policy(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = ClientHardeningScanner(settings)
        raw = (
            "default-src 'none'; "
            "script-src 'self' 'unsafe-inline' https://cdn.example.com; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "font-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        policy = scanner._parse_csp(raw)
        assert len(policy.directives) == 9
        assert "'unsafe-inline'" in policy.directives["script-src"]
        assert "data:" in policy.directives["img-src"]
        assert "'none'" in policy.directives["frame-ancestors"]
