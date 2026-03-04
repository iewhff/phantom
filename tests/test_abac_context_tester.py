"""
Tests for scanning/modules/abac_context_tester.py

Covers:
- Module-level constants: INTERNAL_IPS, IP_SPOOF_HEADERS, USER_AGENTS, ORIGIN_VALUES, TIME_HEADERS
- ContextTestResult dataclass (defaults, full creation)
- ABACContextTester scanner identity (name, ScanModule subclass, class attributes)
- ABACContextTester._resolve_base_url (pure logic, no HTTP)
"""

import pytest
from scanning.modules.abac_context_tester import (
    INTERNAL_IPS,
    IP_SPOOF_HEADERS,
    USER_AGENTS,
    ORIGIN_VALUES,
    TIME_HEADERS,
    ContextTestResult,
    ABACContextTester,
)
from scanning.vuln_scanner import ScanModule


# =============================================================================
# MODULE-LEVEL CONSTANTS: INTERNAL_IPS
# =============================================================================

class TestInternalIPs:
    """Test INTERNAL_IPS list."""

    def test_count(self):
        assert len(INTERNAL_IPS) == 7

    def test_is_list(self):
        assert isinstance(INTERNAL_IPS, list)

    def test_all_strings(self):
        for ip in INTERNAL_IPS:
            assert isinstance(ip, str), f"Expected str, got {type(ip)}: {ip}"

    def test_has_loopback_ipv4(self):
        assert "127.0.0.1" in INTERNAL_IPS

    def test_has_loopback_ipv6(self):
        assert "::1" in INTERNAL_IPS

    def test_has_localhost(self):
        assert "localhost" in INTERNAL_IPS

    def test_has_10_network(self):
        assert "10.0.0.1" in INTERNAL_IPS

    def test_has_172_network(self):
        assert "172.16.0.1" in INTERNAL_IPS

    def test_has_192_168_1(self):
        assert "192.168.1.1" in INTERNAL_IPS

    def test_has_192_168_0(self):
        assert "192.168.0.1" in INTERNAL_IPS

    def test_all_unique(self):
        assert len(INTERNAL_IPS) == len(set(INTERNAL_IPS))


# =============================================================================
# MODULE-LEVEL CONSTANTS: IP_SPOOF_HEADERS
# =============================================================================

class TestIPSpoofHeaders:
    """Test IP_SPOOF_HEADERS list."""

    def test_count(self):
        assert len(IP_SPOOF_HEADERS) == 13

    def test_is_list(self):
        assert isinstance(IP_SPOOF_HEADERS, list)

    def test_all_strings(self):
        for header in IP_SPOOF_HEADERS:
            assert isinstance(header, str), f"Expected str, got {type(header)}: {header}"

    def test_has_x_forwarded_for(self):
        assert "X-Forwarded-For" in IP_SPOOF_HEADERS

    def test_has_x_real_ip(self):
        assert "X-Real-IP" in IP_SPOOF_HEADERS

    def test_has_x_originating_ip(self):
        assert "X-Originating-IP" in IP_SPOOF_HEADERS

    def test_has_x_remote_ip(self):
        assert "X-Remote-IP" in IP_SPOOF_HEADERS

    def test_has_x_remote_addr(self):
        assert "X-Remote-Addr" in IP_SPOOF_HEADERS

    def test_has_x_client_ip(self):
        assert "X-Client-IP" in IP_SPOOF_HEADERS

    def test_has_client_ip(self):
        assert "Client-IP" in IP_SPOOF_HEADERS

    def test_has_true_client_ip(self):
        assert "True-Client-IP" in IP_SPOOF_HEADERS

    def test_has_cf_connecting_ip(self):
        assert "CF-Connecting-IP" in IP_SPOOF_HEADERS

    def test_has_fastly_client_ip(self):
        assert "Fastly-Client-IP" in IP_SPOOF_HEADERS

    def test_has_x_cluster_client_ip(self):
        assert "X-Cluster-Client-IP" in IP_SPOOF_HEADERS

    def test_has_x_azure_client_ip(self):
        assert "X-Azure-ClientIP" in IP_SPOOF_HEADERS

    def test_has_x_appengine_user_ip(self):
        assert "X-Appengine-User-IP" in IP_SPOOF_HEADERS

    def test_all_unique(self):
        assert len(IP_SPOOF_HEADERS) == len(set(IP_SPOOF_HEADERS))


# =============================================================================
# MODULE-LEVEL CONSTANTS: USER_AGENTS
# =============================================================================

class TestUserAgents:
    """Test USER_AGENTS dict."""

    def test_count(self):
        assert len(USER_AGENTS) == 10

    def test_is_dict(self):
        assert isinstance(USER_AGENTS, dict)

    def test_all_keys_are_strings(self):
        for key in USER_AGENTS:
            assert isinstance(key, str), f"Expected str key, got {type(key)}: {key}"

    def test_all_values_are_strings(self):
        for key, value in USER_AGENTS.items():
            assert isinstance(value, str), f"Expected str value for '{key}', got {type(value)}"

    def test_has_desktop_chrome(self):
        assert "desktop_chrome" in USER_AGENTS

    def test_has_desktop_firefox(self):
        assert "desktop_firefox" in USER_AGENTS

    def test_has_mobile_android(self):
        assert "mobile_android" in USER_AGENTS

    def test_has_mobile_ios(self):
        assert "mobile_ios" in USER_AGENTS

    def test_has_bot_google(self):
        assert "bot_google" in USER_AGENTS

    def test_has_bot_bing(self):
        assert "bot_bing" in USER_AGENTS

    def test_has_curl(self):
        assert "curl" in USER_AGENTS

    def test_has_python(self):
        assert "python" in USER_AGENTS

    def test_has_admin_tool(self):
        assert "admin_tool" in USER_AGENTS

    def test_has_internal_service(self):
        assert "internal_service" in USER_AGENTS

    def test_desktop_chrome_contains_chrome(self):
        assert "Chrome" in USER_AGENTS["desktop_chrome"]

    def test_mobile_android_contains_android(self):
        assert "Android" in USER_AGENTS["mobile_android"]

    def test_mobile_ios_contains_iphone(self):
        assert "iPhone" in USER_AGENTS["mobile_ios"]

    def test_bot_google_contains_googlebot(self):
        assert "Googlebot" in USER_AGENTS["bot_google"]

    def test_bot_bing_contains_bingbot(self):
        assert "bingbot" in USER_AGENTS["bot_bing"]

    def test_curl_contains_curl(self):
        assert "curl" in USER_AGENTS["curl"]

    def test_python_contains_requests(self):
        assert "requests" in USER_AGENTS["python"]

    def test_all_values_unique(self):
        values = list(USER_AGENTS.values())
        assert len(values) == len(set(values))


# =============================================================================
# MODULE-LEVEL CONSTANTS: ORIGIN_VALUES
# =============================================================================

class TestOriginValues:
    """Test ORIGIN_VALUES list."""

    def test_count(self):
        assert len(ORIGIN_VALUES) == 7

    def test_is_list(self):
        assert isinstance(ORIGIN_VALUES, list)

    def test_all_strings(self):
        for val in ORIGIN_VALUES:
            assert isinstance(val, str), f"Expected str, got {type(val)}: {val}"

    def test_has_empty_string(self):
        assert "" in ORIGIN_VALUES

    def test_has_null(self):
        assert "null" in ORIGIN_VALUES

    def test_has_localhost(self):
        assert "http://localhost" in ORIGIN_VALUES

    def test_has_127_0_0_1(self):
        assert "http://127.0.0.1" in ORIGIN_VALUES

    def test_has_internal_local(self):
        assert "http://internal.local" in ORIGIN_VALUES

    def test_has_admin_internal(self):
        assert "http://admin.internal" in ORIGIN_VALUES

    def test_has_file_protocol(self):
        assert "file://" in ORIGIN_VALUES


# =============================================================================
# MODULE-LEVEL CONSTANTS: TIME_HEADERS
# =============================================================================

class TestTimeHeaders:
    """Test TIME_HEADERS dict."""

    def test_count(self):
        assert len(TIME_HEADERS) == 4

    def test_is_dict(self):
        assert isinstance(TIME_HEADERS, dict)

    def test_has_x_request_time(self):
        assert "X-Request-Time" in TIME_HEADERS

    def test_has_x_timestamp(self):
        assert "X-Timestamp" in TIME_HEADERS

    def test_has_date(self):
        assert "Date" in TIME_HEADERS

    def test_has_x_date(self):
        assert "X-Date" in TIME_HEADERS

    def test_all_values_are_none(self):
        for key, value in TIME_HEADERS.items():
            assert value is None, f"Expected None for '{key}', got {value}"


# =============================================================================
# DATACLASS: ContextTestResult
# =============================================================================

class TestContextTestResult:
    """Test ContextTestResult dataclass."""

    def test_defaults(self):
        result = ContextTestResult(
            context_type="ip_spoofing",
            header_name="X-Forwarded-For",
            header_value="127.0.0.1",
            baseline_status=403,
            test_status=200,
            baseline_size=100,
            test_size=500,
        )
        assert result.context_type == "ip_spoofing"
        assert result.header_name == "X-Forwarded-For"
        assert result.header_value == "127.0.0.1"
        assert result.baseline_status == 403
        assert result.test_status == 200
        assert result.baseline_size == 100
        assert result.test_size == 500
        assert result.access_granted is False
        assert result.new_data_exposed is False

    def test_full_creation(self):
        result = ContextTestResult(
            context_type="user_agent",
            header_name="User-Agent",
            header_value="Googlebot/2.1",
            baseline_status=401,
            test_status=200,
            baseline_size=50,
            test_size=2000,
            access_granted=True,
            new_data_exposed=True,
        )
        assert result.context_type == "user_agent"
        assert result.access_granted is True
        assert result.new_data_exposed is True

    def test_access_granted_default_false(self):
        result = ContextTestResult(
            context_type="origin",
            header_name="Origin",
            header_value="http://localhost",
            baseline_status=403,
            test_status=403,
            baseline_size=100,
            test_size=100,
        )
        assert result.access_granted is False

    def test_new_data_exposed_default_false(self):
        result = ContextTestResult(
            context_type="time",
            header_name="Date",
            header_value="Mon, 01 Jan 2026 03:00:00 GMT",
            baseline_status=403,
            test_status=403,
            baseline_size=100,
            test_size=100,
        )
        assert result.new_data_exposed is False


# =============================================================================
# SCANNER IDENTITY: ABACContextTester
# =============================================================================

class TestABACContextTesterIdentity:
    """Test ABACContextTester scanner identity and class attributes."""

    def test_is_scan_module_subclass(self):
        assert issubclass(ABACContextTester, ScanModule)

    def test_name_attribute(self):
        assert ABACContextTester.name == "abac_context"

    def test_description_attribute(self):
        assert ABACContextTester.description == "Tests attribute-based access control via context manipulation"

    def test_version_attribute(self):
        assert ABACContextTester.version == "1.0.0"

    def test_author_attribute(self):
        assert ABACContextTester.author == "PHANTOM AI"

    def test_tags_attribute(self):
        assert isinstance(ABACContextTester.tags, list)
        assert len(ABACContextTester.tags) == 4

    def test_tags_contains_abac(self):
        assert "abac" in ABACContextTester.tags

    def test_tags_contains_access_control(self):
        assert "access_control" in ABACContextTester.tags

    def test_tags_contains_context(self):
        assert "context" in ABACContextTester.tags

    def test_tags_contains_bypass(self):
        assert "bypass" in ABACContextTester.tags

    def test_min_safety_level(self):
        assert ABACContextTester.min_safety_level == "standard"


# =============================================================================
# SCANNER INSTANTIATION
# =============================================================================

class TestABACContextTesterInstantiation:
    """Test ABACContextTester instantiation with mock settings."""

    def test_instantiates_with_mock_settings(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = ABACContextTester(settings)
        assert scanner is not None

    def test_instantiates_with_none_settings(self):
        scanner = ABACContextTester(None)
        assert scanner is not None

    def test_initial_base_url_empty(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = ABACContextTester(settings)
        assert scanner._base_url == ""

    def test_initial_auth_headers_empty(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = ABACContextTester(settings)
        assert scanner._auth_headers == {}

    def test_initial_discovered_endpoints_empty(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = ABACContextTester(settings)
        assert scanner._discovered_endpoints == []

    def test_has_scan_method(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = ABACContextTester(settings)
        assert hasattr(scanner, "scan")
        assert callable(scanner.scan)


# =============================================================================
# _resolve_base_url (pure logic, no HTTP)
# =============================================================================

class TestResolveBaseUrl:
    """Test ABACContextTester._resolve_base_url method."""

    def _make_scanner(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        return ABACContextTester(settings)

    def test_http_url_passthrough(self):
        scanner = self._make_scanner()
        result = scanner._resolve_base_url("http://example.com", None)
        assert result == "http://example.com"

    def test_https_url_passthrough(self):
        scanner = self._make_scanner()
        result = scanner._resolve_base_url("https://example.com", None)
        assert result == "https://example.com"

    def test_strips_trailing_slash(self):
        scanner = self._make_scanner()
        result = scanner._resolve_base_url("http://example.com/", None)
        assert result == "http://example.com"

    def test_host_with_port_443_uses_https(self):
        scanner = self._make_scanner()
        result = scanner._resolve_base_url("example.com", 443)
        assert result == "https://example.com"

    def test_host_with_port_8443_uses_https(self):
        scanner = self._make_scanner()
        result = scanner._resolve_base_url("example.com", 8443)
        assert result == "https://example.com:8443"

    def test_host_with_port_80_uses_http(self):
        scanner = self._make_scanner()
        result = scanner._resolve_base_url("example.com", 80)
        assert result == "http://example.com"

    def test_host_with_port_none_uses_http(self):
        scanner = self._make_scanner()
        result = scanner._resolve_base_url("example.com", None)
        assert result == "http://example.com"

    def test_host_with_custom_port(self):
        scanner = self._make_scanner()
        result = scanner._resolve_base_url("example.com", 8080)
        assert result == "http://example.com:8080"

    def test_host_with_port_3000(self):
        scanner = self._make_scanner()
        result = scanner._resolve_base_url("example.com", 3000)
        assert result == "http://example.com:3000"


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Test edge cases and cross-cutting concerns."""

    def test_internal_ips_covers_all_rfc1918_ranges(self):
        """Ensure at least one IP from each RFC 1918 range is present."""
        has_10 = any(ip.startswith("10.") for ip in INTERNAL_IPS)
        has_172 = any(ip.startswith("172.") for ip in INTERNAL_IPS)
        has_192 = any(ip.startswith("192.168.") for ip in INTERNAL_IPS)
        assert has_10
        assert has_172
        assert has_192

    def test_ip_spoof_headers_all_start_with_uppercase_or_known(self):
        """All header names should be properly cased HTTP headers."""
        for header in IP_SPOOF_HEADERS:
            assert header[0].isupper(), f"Header should start uppercase: {header}"

    def test_user_agents_all_non_empty(self):
        for key, value in USER_AGENTS.items():
            assert len(value) > 0, f"User agent '{key}' should not be empty"

    def test_origin_values_include_bypass_vectors(self):
        """Origin list should include common bypass vectors."""
        # null origin (used in sandboxed iframes, data URIs)
        assert "null" in ORIGIN_VALUES
        # empty origin
        assert "" in ORIGIN_VALUES
        # file protocol (local file access)
        assert "file://" in ORIGIN_VALUES

    def test_context_test_result_is_dataclass(self):
        from dataclasses import fields
        field_names = [f.name for f in fields(ContextTestResult)]
        assert "context_type" in field_names
        assert "header_name" in field_names
        assert "header_value" in field_names
        assert "baseline_status" in field_names
        assert "test_status" in field_names
        assert "baseline_size" in field_names
        assert "test_size" in field_names
        assert "access_granted" in field_names
        assert "new_data_exposed" in field_names

    def test_context_test_result_field_count(self):
        from dataclasses import fields
        assert len(fields(ContextTestResult)) == 9
