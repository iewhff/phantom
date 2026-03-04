"""
Tests for scanning/modules/ldap_xpath_scanner.py

Covers:
- LDAPXPathScanner class identity and inheritance
- LDAP_PRIORITY_PAYLOADS (4 items)
- LDAP_PAYLOADS (~19 items)
- XPATH_PRIORITY_PAYLOADS (4 items)
- XPATH_PAYLOADS (~18 items)
- LDAP_ERRORS (~30 strings, multi-language coverage)
- XPATH_ERRORS (~30 strings, multi-language coverage)
- KNOWN_LDAP_PATHS and KNOWN_XPATH_PATHS
- Error detection helpers (_check_ldap_error, _check_xpath_error)
- _check_auth_bypass helper
- _is_target_applicable heuristic
- Payload integrity (no empty strings, all strings)
- Error pattern lowercase-safety analysis
"""

import pytest
from unittest.mock import MagicMock, patch

from scanning.modules.ldap_xpath_scanner import LDAPXPathScanner
from scanning.vuln_scanner import ScanModule


# =============================================================================
# HELPERS: Minimal Settings mock for instantiation
# =============================================================================

def _make_settings():
    """Create a minimal Settings mock for LDAPXPathScanner.__init__."""
    settings = MagicMock()
    settings.timeouts.request_timeout = 10.0
    return settings


def _make_scanner():
    """Instantiate a LDAPXPathScanner with mocked settings."""
    return LDAPXPathScanner(_make_settings())


# =============================================================================
# CLASS IDENTITY & INHERITANCE
# =============================================================================

class TestLDAPXPathScannerIdentity:
    """Test class name, inheritance, and basic attributes."""

    def test_name(self):
        assert LDAPXPathScanner.name == "ldap_xpath_scanner"

    def test_is_scan_module_subclass(self):
        assert issubclass(LDAPXPathScanner, ScanModule)

    def test_instance_is_scan_module(self):
        scanner = _make_scanner()
        assert isinstance(scanner, ScanModule)

    def test_has_scan_method(self):
        assert callable(getattr(LDAPXPathScanner, "scan", None))

    def test_max_scan_duration(self):
        assert LDAPXPathScanner.MAX_SCAN_DURATION == 120.0


# =============================================================================
# LDAP PRIORITY PAYLOADS
# =============================================================================

class TestLDAPPriorityPayloads:
    """Test LDAP_PRIORITY_PAYLOADS list."""

    def test_count(self):
        assert len(LDAPXPathScanner.LDAP_PRIORITY_PAYLOADS) == 4

    def test_not_empty(self):
        assert len(LDAPXPathScanner.LDAP_PRIORITY_PAYLOADS) > 0

    def test_all_strings(self):
        for p in LDAPXPathScanner.LDAP_PRIORITY_PAYLOADS:
            assert isinstance(p, str), f"Expected str, got {type(p)}: {p!r}"

    def test_no_empty_strings(self):
        for p in LDAPXPathScanner.LDAP_PRIORITY_PAYLOADS:
            assert len(p) > 0, "Empty string found in LDAP_PRIORITY_PAYLOADS"

    def test_has_wildcard(self):
        assert "*" in LDAPXPathScanner.LDAP_PRIORITY_PAYLOADS

    def test_has_filter_break(self):
        assert "*)(&" in LDAPXPathScanner.LDAP_PRIORITY_PAYLOADS

    def test_has_special_chars(self):
        assert "*()|&'" in LDAPXPathScanner.LDAP_PRIORITY_PAYLOADS

    def test_has_filter_manipulation(self):
        assert ")(cn=*" in LDAPXPathScanner.LDAP_PRIORITY_PAYLOADS


# =============================================================================
# LDAP PAYLOADS (full list)
# =============================================================================

class TestLDAPPayloads:
    """Test LDAP_PAYLOADS list."""

    def test_count(self):
        assert len(LDAPXPathScanner.LDAP_PAYLOADS) == 19

    def test_not_empty(self):
        assert len(LDAPXPathScanner.LDAP_PAYLOADS) > 0

    def test_all_strings(self):
        for p in LDAPXPathScanner.LDAP_PAYLOADS:
            assert isinstance(p, str), f"Expected str, got {type(p)}: {p!r}"

    def test_no_empty_strings(self):
        for p in LDAPXPathScanner.LDAP_PAYLOADS:
            assert len(p) > 0, "Empty string found in LDAP_PAYLOADS"

    def test_has_auth_bypass_admin(self):
        assert "admin)(&)" in LDAPXPathScanner.LDAP_PAYLOADS

    def test_has_auth_bypass_password(self):
        assert "admin)(|(password=*))" in LDAPXPathScanner.LDAP_PAYLOADS

    def test_has_wildcard_abuse(self):
        assert "a*" in LDAPXPathScanner.LDAP_PAYLOADS
        assert "*a*" in LDAPXPathScanner.LDAP_PAYLOADS

    def test_has_dn_injection(self):
        assert "admin,dc=*" in LDAPXPathScanner.LDAP_PAYLOADS

    def test_has_escape_sequences(self):
        assert "admin\\00" in LDAPXPathScanner.LDAP_PAYLOADS
        assert "admin%00" in LDAPXPathScanner.LDAP_PAYLOADS

    def test_has_blind_ldap(self):
        assert "admin)(|(objectClass=*" in LDAPXPathScanner.LDAP_PAYLOADS

    def test_has_filter_manipulation(self):
        assert ")(cn=*" in LDAPXPathScanner.LDAP_PAYLOADS
        assert ")(|(cn=*)(sn=*" in LDAPXPathScanner.LDAP_PAYLOADS


# =============================================================================
# XPATH PRIORITY PAYLOADS
# =============================================================================

class TestXPathPriorityPayloads:
    """Test XPATH_PRIORITY_PAYLOADS list."""

    def test_count(self):
        assert len(LDAPXPathScanner.XPATH_PRIORITY_PAYLOADS) == 4

    def test_not_empty(self):
        assert len(LDAPXPathScanner.XPATH_PRIORITY_PAYLOADS) > 0

    def test_all_strings(self):
        for p in LDAPXPathScanner.XPATH_PRIORITY_PAYLOADS:
            assert isinstance(p, str), f"Expected str, got {type(p)}: {p!r}"

    def test_no_empty_strings(self):
        for p in LDAPXPathScanner.XPATH_PRIORITY_PAYLOADS:
            assert len(p) > 0, "Empty string found in XPATH_PRIORITY_PAYLOADS"

    def test_has_classic_boolean(self):
        assert "' or '1'='1" in LDAPXPathScanner.XPATH_PRIORITY_PAYLOADS

    def test_has_empty_string_match(self):
        assert "' or ''='" in LDAPXPathScanner.XPATH_PRIORITY_PAYLOADS

    def test_has_numeric_injection(self):
        assert "1 or 1=1" in LDAPXPathScanner.XPATH_PRIORITY_PAYLOADS

    def test_has_node_traversal(self):
        assert "']/*" in LDAPXPathScanner.XPATH_PRIORITY_PAYLOADS


# =============================================================================
# XPATH PAYLOADS (full list)
# =============================================================================

class TestXPathPayloads:
    """Test XPATH_PAYLOADS list."""

    def test_count(self):
        assert len(LDAPXPathScanner.XPATH_PAYLOADS) == 18

    def test_not_empty(self):
        assert len(LDAPXPathScanner.XPATH_PAYLOADS) > 0

    def test_all_strings(self):
        for p in LDAPXPathScanner.XPATH_PAYLOADS:
            assert isinstance(p, str), f"Expected str, got {type(p)}: {p!r}"

    def test_no_empty_strings(self):
        for p in LDAPXPathScanner.XPATH_PAYLOADS:
            assert len(p) > 0, "Empty string found in XPATH_PAYLOADS"

    def test_has_auth_bypass(self):
        assert "admin' or '1'='1" in LDAPXPathScanner.XPATH_PAYLOADS

    def test_has_admin_comment(self):
        assert "admin'--" in LDAPXPathScanner.XPATH_PAYLOADS

    def test_has_blind_xpath(self):
        assert "' or 1=1 or '" in LDAPXPathScanner.XPATH_PAYLOADS
        assert "' or count(//user)>0 or '" in LDAPXPathScanner.XPATH_PAYLOADS

    def test_has_boolean_extraction(self):
        assert "' or substring(//user[1]/username,1,1)='a" in LDAPXPathScanner.XPATH_PAYLOADS
        assert "' or starts-with(//user[1]/username,'a') or '" in LDAPXPathScanner.XPATH_PAYLOADS

    def test_has_node_extraction(self):
        assert "' | //user/* | '" in LDAPXPathScanner.XPATH_PAYLOADS
        assert "' or //* or '" in LDAPXPathScanner.XPATH_PAYLOADS

    def test_has_numeric_injection(self):
        assert "1 or 1=1" in LDAPXPathScanner.XPATH_PAYLOADS
        assert "1 and 1=1" in LDAPXPathScanner.XPATH_PAYLOADS

    def test_has_comment_injection(self):
        assert "admin'/*" in LDAPXPathScanner.XPATH_PAYLOADS
        assert "admin'//" in LDAPXPathScanner.XPATH_PAYLOADS


# =============================================================================
# LDAP ERRORS
# =============================================================================

class TestLDAPErrors:
    """Test LDAP_ERRORS list — multi-language error string coverage."""

    def test_count(self):
        assert len(LDAPXPathScanner.LDAP_ERRORS) == 33

    def test_not_empty(self):
        assert len(LDAPXPathScanner.LDAP_ERRORS) > 0

    def test_all_strings(self):
        for e in LDAPXPathScanner.LDAP_ERRORS:
            assert isinstance(e, str), f"Expected str, got {type(e)}: {e!r}"

    def test_no_empty_strings(self):
        for e in LDAPXPathScanner.LDAP_ERRORS:
            assert len(e) > 0, "Empty string found in LDAP_ERRORS"

    # --- PHP LDAP errors ---
    def test_php_ldap_search(self):
        assert "ldap_search" in LDAPXPathScanner.LDAP_ERRORS

    def test_php_ldap_bind(self):
        assert "ldap_bind" in LDAPXPathScanner.LDAP_ERRORS

    def test_php_ldap_parse(self):
        assert "ldap_parse" in LDAPXPathScanner.LDAP_ERRORS

    def test_php_ldap_connect(self):
        assert "ldap_connect" in LDAPXPathScanner.LDAP_ERRORS

    def test_php_ldap_add(self):
        assert "ldap_add" in LDAPXPathScanner.LDAP_ERRORS

    def test_php_ldap_modify(self):
        assert "ldap_modify" in LDAPXPathScanner.LDAP_ERRORS

    # --- Java LDAP errors ---
    def test_java_javax_naming(self):
        assert any("javax.naming" in e for e in LDAPXPathScanner.LDAP_ERRORS)

    def test_java_jndi(self):
        assert any("com.sun.jndi" in e for e in LDAPXPathScanner.LDAP_ERRORS)

    def test_java_naming_exception(self):
        assert any("NamingException" in e for e in LDAPXPathScanner.LDAP_ERRORS)

    def test_java_invalid_search_filter(self):
        assert any("InvalidSearchFilter" in e for e in LDAPXPathScanner.LDAP_ERRORS)

    # --- Python LDAP errors ---
    def test_python_ldap_filter_error(self):
        assert any("ldap.FILTER_ERROR" in e for e in LDAPXPathScanner.LDAP_ERRORS)

    def test_python_ldap_lib(self):
        assert "python-ldap" in LDAPXPathScanner.LDAP_ERRORS

    # --- .NET LDAP errors ---
    def test_dotnet_directory_services(self):
        assert any("System.DirectoryServices" in e for e in LDAPXPathScanner.LDAP_ERRORS)

    def test_dotnet_directory_searcher(self):
        assert any("DirectorySearcher" in e for e in LDAPXPathScanner.LDAP_ERRORS)

    # --- Ruby LDAP errors ---
    def test_ruby_net_ldap(self):
        assert any("Net::LDAP" in e for e in LDAPXPathScanner.LDAP_ERRORS)

    def test_ruby_ldap_result_error(self):
        assert any("LDAP::ResultError" in e for e in LDAPXPathScanner.LDAP_ERRORS)

    # --- General / filter errors ---
    def test_general_ldap_error(self):
        assert "ldap error" in LDAPXPathScanner.LDAP_ERRORS

    def test_bad_search_filter(self):
        assert "bad search filter" in LDAPXPathScanner.LDAP_ERRORS

    def test_invalid_filter(self):
        assert "invalid filter" in LDAPXPathScanner.LDAP_ERRORS

    # --- Modern frameworks ---
    def test_spring_ldap(self):
        assert "spring-ldap" in LDAPXPathScanner.LDAP_ERRORS

    def test_unboundid(self):
        assert "unboundid" in LDAPXPathScanner.LDAP_ERRORS

    def test_apache_directory(self):
        assert "apache directory" in LDAPXPathScanner.LDAP_ERRORS


# =============================================================================
# LDAP ERRORS — LOWERCASE-SAFETY ANALYSIS
# =============================================================================

class TestLDAPErrorsLowercaseSafety:
    """
    The scanner does text.lower() then checks 'error in text_lower'.
    Error patterns that contain uppercase will NEVER match .lower() text.
    These tests document which patterns are lowercase-safe and which are not.
    """

    def test_lowercase_safe_patterns_exist(self):
        """At least some patterns are fully lowercase and will match."""
        lowercase_patterns = [e for e in LDAPXPathScanner.LDAP_ERRORS if e == e.lower()]
        assert len(lowercase_patterns) >= 19, (
            f"Only {len(lowercase_patterns)} of {len(LDAPXPathScanner.LDAP_ERRORS)} "
            "LDAP error patterns are lowercase-safe"
        )

    def test_mixed_case_patterns_documented(self):
        """
        Some patterns have mixed case (e.g. Net::LDAP, System.DirectoryServices).
        These will NOT match when the scanner does text.lower() comparison
        unless the error message itself appears in the exact same case.
        This test documents which patterns are affected.
        """
        mixed_case = [e for e in LDAPXPathScanner.LDAP_ERRORS if e != e.lower()]
        # These are the known mixed-case patterns
        expected_mixed = {
            "javax.naming.NamingException",
            "InvalidSearchFilterException",
            "ldap.FILTER_ERROR",
            "ldap.INVALID_DN_SYNTAX",
            "System.DirectoryServices",
            "DirectorySearcher",
            "SearchResultCollection",
            "Net::LDAP",
            "LDAP::ResultError",
        }
        actual_mixed = set(mixed_case)
        assert actual_mixed == expected_mixed

    def test_php_patterns_all_lowercase(self):
        """PHP LDAP function names are lowercase, so they match correctly."""
        php_patterns = ["ldap_search", "ldap_bind", "ldap_parse", "ldap_connect", "ldap_add", "ldap_modify"]
        for p in php_patterns:
            assert p == p.lower()
            assert p in LDAPXPathScanner.LDAP_ERRORS


# =============================================================================
# XPATH ERRORS
# =============================================================================

class TestXPathErrors:
    """Test XPATH_ERRORS list — multi-language error string coverage."""

    def test_count(self):
        assert len(LDAPXPathScanner.XPATH_ERRORS) == 32

    def test_not_empty(self):
        assert len(LDAPXPathScanner.XPATH_ERRORS) > 0

    def test_all_strings(self):
        for e in LDAPXPathScanner.XPATH_ERRORS:
            assert isinstance(e, str), f"Expected str, got {type(e)}: {e!r}"

    def test_no_empty_strings(self):
        for e in LDAPXPathScanner.XPATH_ERRORS:
            assert len(e) > 0, "Empty string found in XPATH_ERRORS"

    # --- Generic XPath ---
    def test_generic_xpath(self):
        assert "xpath" in LDAPXPathScanner.XPATH_ERRORS

    def test_generic_xpatherror(self):
        assert "xpatherror" in LDAPXPathScanner.XPATH_ERRORS

    def test_generic_xpathexception(self):
        assert "xpathexception" in LDAPXPathScanner.XPATH_ERRORS

    def test_invalid_expression(self):
        assert "invalid expression" in LDAPXPathScanner.XPATH_ERRORS

    def test_invalid_predicate(self):
        assert "invalid predicate" in LDAPXPathScanner.XPATH_ERRORS

    def test_missing_closing_quote(self):
        assert "missing closing quote" in LDAPXPathScanner.XPATH_ERRORS

    # --- PHP XML/XPath ---
    def test_php_domxpath(self):
        assert any("DOMXPath" in e for e in LDAPXPathScanner.XPATH_ERRORS)

    def test_php_domdocument(self):
        assert any("DOMDocument" in e for e in LDAPXPathScanner.XPATH_ERRORS)

    def test_php_simplexmlelement(self):
        assert any("SimpleXMLElement" in e for e in LDAPXPathScanner.XPATH_ERRORS)

    def test_php_libxml(self):
        assert "libxml error" in LDAPXPathScanner.XPATH_ERRORS

    # --- Java XPath ---
    def test_java_javax_xml_xpath(self):
        assert any("javax.xml.xpath" in e for e in LDAPXPathScanner.XPATH_ERRORS)

    def test_java_xpath_expression_exception(self):
        assert any("XPathExpressionException" in e for e in LDAPXPathScanner.XPATH_ERRORS)

    def test_java_sax_parse(self):
        assert any("saxparseexception" in e for e in LDAPXPathScanner.XPATH_ERRORS)

    def test_java_transformer(self):
        assert any("TransformerException" in e for e in LDAPXPathScanner.XPATH_ERRORS)

    # --- Python XPath ---
    def test_python_lxml_etree(self):
        assert any("lxml.etree" in e for e in LDAPXPathScanner.XPATH_ERRORS)

    def test_python_xpath_eval_error(self):
        assert any("XPathEvalError" in e for e in LDAPXPathScanner.XPATH_ERRORS)

    def test_python_xpath_syntax_error(self):
        assert any("XPathSyntaxError" in e for e in LDAPXPathScanner.XPATH_ERRORS)

    # --- .NET XPath ---
    def test_dotnet_system_xml_xpath(self):
        assert any("System.Xml.XPath" in e for e in LDAPXPathScanner.XPATH_ERRORS)

    def test_dotnet_xpath_navigator(self):
        assert any("XPathNavigator" in e for e in LDAPXPathScanner.XPATH_ERRORS)

    def test_dotnet_xpath_exception(self):
        assert any("XPathException" in e for e in LDAPXPathScanner.XPATH_ERRORS)

    # --- Ruby XPath ---
    def test_ruby_nokogiri(self):
        assert any("Nokogiri" in e for e in LDAPXPathScanner.XPATH_ERRORS)

    def test_ruby_rexml(self):
        assert any("REXML" in e for e in LDAPXPathScanner.XPATH_ERRORS)

    # --- Node.js XPath ---
    def test_nodejs_xpath_evaluator(self):
        assert "xpath-evaluator" in LDAPXPathScanner.XPATH_ERRORS

    def test_nodejs_xmldom(self):
        assert "xmldom" in LDAPXPathScanner.XPATH_ERRORS

    # --- Modern errors ---
    def test_syntax_error_in_xpath(self):
        assert "syntax error in xpath" in LDAPXPathScanner.XPATH_ERRORS

    def test_xpath_query_failed(self):
        assert "xpath query failed" in LDAPXPathScanner.XPATH_ERRORS

    def test_invalid_xpath_expression(self):
        assert "invalid xpath expression" in LDAPXPathScanner.XPATH_ERRORS


# =============================================================================
# XPATH ERRORS — LOWERCASE-SAFETY ANALYSIS
# =============================================================================

class TestXPathErrorsLowercaseSafety:
    """
    Same analysis as LDAP: patterns with uppercase will not match text.lower().
    """

    def test_lowercase_safe_patterns_exist(self):
        lowercase_patterns = [e for e in LDAPXPathScanner.XPATH_ERRORS if e == e.lower()]
        assert len(lowercase_patterns) >= 18, (
            f"Only {len(lowercase_patterns)} of {len(LDAPXPathScanner.XPATH_ERRORS)} "
            "XPath error patterns are lowercase-safe"
        )

    def test_mixed_case_patterns_documented(self):
        mixed_case = [e for e in LDAPXPathScanner.XPATH_ERRORS if e != e.lower()]
        expected_mixed = {
            "SimpleXMLElement",
            "DOMXPath",
            "DOMDocument",
            "XPathExpressionException",
            "TransformerException",
            "XPathEvalError",
            "XPathSyntaxError",
            "System.Xml.XPath",
            "XPathNavigator",
            "XPathException",
            "Nokogiri::XML",
            "REXML::XPath",
        }
        actual_mixed = set(mixed_case)
        assert actual_mixed == expected_mixed


# =============================================================================
# KNOWN LDAP PATHS
# =============================================================================

class TestKnownLDAPPaths:
    """Test KNOWN_LDAP_PATHS list."""

    def test_count(self):
        assert len(LDAPXPathScanner.KNOWN_LDAP_PATHS) == 16

    def test_not_empty(self):
        assert len(LDAPXPathScanner.KNOWN_LDAP_PATHS) > 0

    def test_all_strings(self):
        for p in LDAPXPathScanner.KNOWN_LDAP_PATHS:
            assert isinstance(p, str)

    def test_no_empty_strings(self):
        for p in LDAPXPathScanner.KNOWN_LDAP_PATHS:
            assert len(p) > 0

    def test_all_start_with_slash(self):
        for p in LDAPXPathScanner.KNOWN_LDAP_PATHS:
            assert p.startswith("/"), f"Path does not start with /: {p!r}"

    def test_has_bwapp_ldap(self):
        assert "/bWAPP/ldapi.php" in LDAPXPathScanner.KNOWN_LDAP_PATHS

    def test_has_generic_ldap_search(self):
        assert "/ldap/search" in LDAPXPathScanner.KNOWN_LDAP_PATHS

    def test_has_api_ldap_auth(self):
        assert "/api/ldap/auth" in LDAPXPathScanner.KNOWN_LDAP_PATHS


# =============================================================================
# KNOWN XPATH PATHS
# =============================================================================

class TestKnownXPathPaths:
    """Test KNOWN_XPATH_PATHS list."""

    def test_count(self):
        assert len(LDAPXPathScanner.KNOWN_XPATH_PATHS) == 13

    def test_not_empty(self):
        assert len(LDAPXPathScanner.KNOWN_XPATH_PATHS) > 0

    def test_all_strings(self):
        for p in LDAPXPathScanner.KNOWN_XPATH_PATHS:
            assert isinstance(p, str)

    def test_no_empty_strings(self):
        for p in LDAPXPathScanner.KNOWN_XPATH_PATHS:
            assert len(p) > 0

    def test_all_start_with_slash(self):
        for p in LDAPXPathScanner.KNOWN_XPATH_PATHS:
            assert p.startswith("/"), f"Path does not start with /: {p!r}"

    def test_has_bwapp_xpath(self):
        assert "/bWAPP/xmli_1.php" in LDAPXPathScanner.KNOWN_XPATH_PATHS

    def test_has_xml_search(self):
        assert "/xml/search" in LDAPXPathScanner.KNOWN_XPATH_PATHS

    def test_has_soap_endpoint(self):
        assert "/soap/" in LDAPXPathScanner.KNOWN_XPATH_PATHS


# =============================================================================
# ERROR DETECTION HELPERS
# =============================================================================

class TestCheckLDAPError:
    """Test _check_ldap_error method."""

    def test_detects_ldap_search_error(self):
        scanner = _make_scanner()
        assert scanner._check_ldap_error("PHP Warning: ldap_search(): Search error") is True

    def test_detects_bad_search_filter(self):
        scanner = _make_scanner()
        assert scanner._check_ldap_error("Error: bad search filter in query") is True

    def test_detects_ldap_error_generic(self):
        scanner = _make_scanner()
        assert scanner._check_ldap_error("An ldap error occurred during processing") is True

    def test_case_insensitive_for_lowercase_patterns(self):
        scanner = _make_scanner()
        # The scanner lowercases the text, so LDAP_SEARCH in text becomes ldap_search
        assert scanner._check_ldap_error("LDAP_SEARCH failed") is True

    def test_no_false_positive_on_clean_text(self):
        scanner = _make_scanner()
        assert scanner._check_ldap_error("Welcome to our website!") is False

    def test_no_false_positive_on_empty(self):
        scanner = _make_scanner()
        assert scanner._check_ldap_error("") is False

    def test_detects_spring_ldap(self):
        scanner = _make_scanner()
        assert scanner._check_ldap_error("spring-ldap connection pool exhausted") is True


class TestCheckXPathError:
    """Test _check_xpath_error method."""

    def test_detects_xpath_keyword(self):
        scanner = _make_scanner()
        assert scanner._check_xpath_error("Error in xpath evaluation") is True

    def test_detects_xpatherror(self):
        scanner = _make_scanner()
        assert scanner._check_xpath_error("XPathError: invalid syntax") is True

    def test_detects_invalid_expression(self):
        scanner = _make_scanner()
        assert scanner._check_xpath_error("XML parsing failed: invalid expression") is True

    def test_detects_libxml_error(self):
        scanner = _make_scanner()
        assert scanner._check_xpath_error("libxml error: parser failed") is True

    def test_detects_xpath_query_failed(self):
        scanner = _make_scanner()
        assert scanner._check_xpath_error("xpath query failed at position 5") is True

    def test_no_false_positive_on_clean_text(self):
        scanner = _make_scanner()
        assert scanner._check_xpath_error("Hello World") is False

    def test_no_false_positive_on_empty(self):
        scanner = _make_scanner()
        assert scanner._check_xpath_error("") is False


# =============================================================================
# AUTH BYPASS DETECTION
# =============================================================================

class TestCheckAuthBypass:
    """Test _check_auth_bypass method."""

    def test_detects_dashboard_indicator(self):
        scanner = _make_scanner()
        assert scanner._check_auth_bypass("Welcome to your dashboard!", "Please login") is True

    def test_detects_logout_indicator(self):
        scanner = _make_scanner()
        assert scanner._check_auth_bypass("Click logout to exit", "Please login") is True

    def test_no_bypass_when_indicator_in_baseline(self):
        scanner = _make_scanner()
        # If "dashboard" is already in baseline, it's not a bypass
        assert scanner._check_auth_bypass("dashboard content", "dashboard login page") is False

    def test_no_bypass_on_generic_response(self):
        scanner = _make_scanner()
        assert scanner._check_auth_bypass("Page not found", "Login page") is False

    def test_case_insensitive(self):
        scanner = _make_scanner()
        assert scanner._check_auth_bypass("WELCOME TO YOUR DASHBOARD!", "Please login") is True


# =============================================================================
# TARGET APPLICABILITY HEURISTIC
# =============================================================================

class TestIsTargetApplicable:
    """Test _is_target_applicable method."""

    def test_applicable_with_ldap_indicator(self):
        scanner = _make_scanner()
        baseline = {"content": "Enter your username and password to login", "content_type": "text/html"}
        assert scanner._is_target_applicable(baseline) is True

    def test_applicable_with_xml_content_type(self):
        scanner = _make_scanner()
        baseline = {"content": "some data", "content_type": "application/xml"}
        assert scanner._is_target_applicable(baseline) is True

    def test_applicable_with_xpath_indicator(self):
        scanner = _make_scanner()
        baseline = {"content": "<?xml version='1.0'?>", "content_type": "text/html"}
        assert scanner._is_target_applicable(baseline) is True

    def test_not_applicable_pure_json_api(self):
        scanner = _make_scanner()
        baseline = {"content": '{"status": "ok", "data": []}', "content_type": "application/json"}
        assert scanner._is_target_applicable(baseline) is False

    def test_applicable_json_api_with_login(self):
        scanner = _make_scanner()
        baseline = {"content": '{"login": "/api/auth"}', "content_type": "application/json"}
        assert scanner._is_target_applicable(baseline) is True

    def test_applicable_default_conservative(self):
        scanner = _make_scanner()
        # If no strong indicators either way, default is True (conservative)
        baseline = {"content": "<html><body>Welcome</body></html>", "content_type": "text/html"}
        assert scanner._is_target_applicable(baseline) is True

    def test_handles_missing_keys_gracefully(self):
        scanner = _make_scanner()
        baseline = {}
        # Should not raise; defaults to True (conservative)
        assert scanner._is_target_applicable(baseline) is True


# =============================================================================
# PAYLOAD LIST CROSS-CHECKS
# =============================================================================

class TestPayloadCrossChecks:
    """Cross-cutting checks across all payload lists."""

    def test_ldap_priority_payloads_are_distinct_list(self):
        """Priority payloads are a separate curated list, not necessarily a subset."""
        # All 4 priority payloads should also appear in the full list
        # (the source code has duplicates like "*", "*)(&", "*()|&'", ")(cn=*")
        for p in LDAPXPathScanner.LDAP_PRIORITY_PAYLOADS:
            assert p in LDAPXPathScanner.LDAP_PAYLOADS, (
                f"Priority payload {p!r} not in full LDAP_PAYLOADS"
            )

    def test_xpath_priority_payloads_mostly_in_full_list(self):
        """Most priority payloads should also appear in the full list.

        Note: "']/*" is a priority-only payload for fast node traversal
        detection and does not appear in the full XPATH_PAYLOADS list.
        """
        in_full = [p for p in LDAPXPathScanner.XPATH_PRIORITY_PAYLOADS
                    if p in LDAPXPathScanner.XPATH_PAYLOADS]
        # At least 3 of 4 priority payloads should be in the full list
        assert len(in_full) >= 3

    def test_xpath_priority_has_node_traversal_exclusive(self):
        """The node traversal priority payload is exclusive to priority list."""
        assert "']/*" in LDAPXPathScanner.XPATH_PRIORITY_PAYLOADS
        assert "']/*" not in LDAPXPathScanner.XPATH_PAYLOADS

    def test_no_overlap_between_ldap_and_xpath_payloads(self):
        """LDAP and XPath payloads should be disjoint (different syntax families)."""
        ldap_set = set(LDAPXPathScanner.LDAP_PAYLOADS)
        xpath_set = set(LDAPXPathScanner.XPATH_PAYLOADS)
        overlap = ldap_set & xpath_set
        assert len(overlap) == 0, f"Unexpected overlap: {overlap}"

    def test_no_overlap_between_ldap_and_xpath_errors(self):
        """LDAP and XPath error patterns should be disjoint."""
        ldap_set = set(LDAPXPathScanner.LDAP_ERRORS)
        xpath_set = set(LDAPXPathScanner.XPATH_ERRORS)
        overlap = ldap_set & xpath_set
        assert len(overlap) == 0, f"Unexpected overlap: {overlap}"

    def test_all_payload_lists_have_no_duplicates(self):
        """Each payload list should not contain exact duplicates."""
        lists_to_check = {
            "LDAP_PRIORITY_PAYLOADS": LDAPXPathScanner.LDAP_PRIORITY_PAYLOADS,
            "XPATH_PRIORITY_PAYLOADS": LDAPXPathScanner.XPATH_PRIORITY_PAYLOADS,
            "XPATH_PAYLOADS": LDAPXPathScanner.XPATH_PAYLOADS,
            "LDAP_ERRORS": LDAPXPathScanner.LDAP_ERRORS,
            "XPATH_ERRORS": LDAPXPathScanner.XPATH_ERRORS,
        }
        for name, lst in lists_to_check.items():
            assert len(lst) == len(set(lst)), (
                f"{name} contains duplicates: "
                f"{[x for x in lst if lst.count(x) > 1]}"
            )

    def test_all_error_lists_have_no_duplicates(self):
        """Error lists should not contain exact duplicates."""
        for name, lst in [
            ("LDAP_ERRORS", LDAPXPathScanner.LDAP_ERRORS),
            ("XPATH_ERRORS", LDAPXPathScanner.XPATH_ERRORS),
        ]:
            assert len(lst) == len(set(lst)), f"{name} contains duplicates"


# =============================================================================
# INSTANTIATION
# =============================================================================

class TestInstantiation:
    """Test that LDAPXPathScanner can be instantiated with various settings."""

    def test_basic_instantiation(self):
        scanner = _make_scanner()
        assert scanner is not None
        assert scanner.name == "ldap_xpath_scanner"

    def test_timeout_from_settings(self):
        settings = MagicMock()
        settings.timeouts.request_timeout = 25.0
        scanner = LDAPXPathScanner(settings)
        assert scanner.timeout == 25.0

    def test_timeout_default_when_no_timeouts_attr(self):
        settings = MagicMock(spec=[])
        # hasattr(settings, 'timeouts') is False
        scanner = LDAPXPathScanner(settings)
        assert scanner.timeout == 30.0

    def test_accepts_findings_store(self):
        store = MagicMock()
        scanner = LDAPXPathScanner(_make_settings(), findings_store=store)
        assert scanner is not None

    def test_accepts_rate_limiter(self):
        limiter = MagicMock()
        scanner = LDAPXPathScanner(_make_settings(), rate_limiter=limiter)
        assert scanner is not None
