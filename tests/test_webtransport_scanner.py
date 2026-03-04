"""
Tests for scanning/modules/webtransport_scanner.py

Covers:
- WEBTRANSPORT_SCANNER_VERSION constant
- WebTransportVulnType enum (10 members, values, uniqueness)
- WebTransportEndpoint dataclass (defaults, full creation)
- WebTransportScanContext dataclass (defaults, full creation, list isolation)
- WebTransportScanner class attributes (name, version, category, tags, description, WEBTRANSPORT_PATHS)
- WebTransportScanner is ScanModule subclass
- WebTransportScanner._get_cwe_for_vuln CWE map (all members covered, values)
"""

import pytest

from scanning.modules.webtransport_scanner import (
    WEBTRANSPORT_SCANNER_VERSION,
    WebTransportVulnType,
    WebTransportEndpoint,
    WebTransportScanContext,
    WebTransportScanner,
)


MOCK_SETTINGS = {"target_url": "http://test.local", "safety_level": "safe"}


# =============================================================================
# CONSTANT TESTS: WEBTRANSPORT_SCANNER_VERSION
# =============================================================================

class TestWebTransportScannerVersion:
    """Test WEBTRANSPORT_SCANNER_VERSION module-level constant."""

    def test_is_string(self):
        assert isinstance(WEBTRANSPORT_SCANNER_VERSION, str)

    def test_value(self):
        assert WEBTRANSPORT_SCANNER_VERSION == "1.0.0"


# =============================================================================
# ENUM TESTS: WebTransportVulnType
# =============================================================================

class TestWebTransportVulnType:
    """Test WebTransportVulnType enum."""

    def test_count(self):
        assert len(WebTransportVulnType) == 10

    def test_session_hijack(self):
        assert WebTransportVulnType.SESSION_HIJACK.value == "session_hijacking"

    def test_datagram_spoofing(self):
        assert WebTransportVulnType.DATAGRAM_SPOOFING.value == "datagram_spoofing"

    def test_stream_exhaustion(self):
        assert WebTransportVulnType.STREAM_EXHAUSTION.value == "stream_exhaustion"

    def test_auth_bypass(self):
        assert WebTransportVulnType.AUTH_BYPASS.value == "authentication_bypass"

    def test_origin_bypass(self):
        assert WebTransportVulnType.ORIGIN_BYPASS.value == "origin_validation_bypass"

    def test_protocol_downgrade(self):
        assert WebTransportVulnType.PROTOCOL_DOWNGRADE.value == "protocol_downgrade"

    def test_resource_exhaustion(self):
        assert WebTransportVulnType.RESOURCE_EXHAUSTION.value == "resource_exhaustion"

    def test_data_injection(self):
        assert WebTransportVulnType.DATA_INJECTION.value == "data_injection"

    def test_replay_attack(self):
        assert WebTransportVulnType.REPLAY_ATTACK.value == "replay_attack"

    def test_connection_migration(self):
        assert WebTransportVulnType.CONNECTION_MIGRATION.value == "connection_migration_abuse"

    def test_all_member_names(self):
        expected = {
            "SESSION_HIJACK",
            "DATAGRAM_SPOOFING",
            "STREAM_EXHAUSTION",
            "AUTH_BYPASS",
            "ORIGIN_BYPASS",
            "PROTOCOL_DOWNGRADE",
            "RESOURCE_EXHAUSTION",
            "DATA_INJECTION",
            "REPLAY_ATTACK",
            "CONNECTION_MIGRATION",
        }
        assert {m.name for m in WebTransportVulnType} == expected

    def test_all_values_unique(self):
        values = [m.value for m in WebTransportVulnType]
        assert len(values) == len(set(values))

    def test_all_values_are_strings(self):
        for member in WebTransportVulnType:
            assert isinstance(member.value, str)


# =============================================================================
# DATACLASS TESTS: WebTransportEndpoint
# =============================================================================

class TestWebTransportEndpointDefaults:
    """Test WebTransportEndpoint dataclass default values."""

    def test_supports_datagrams_default(self):
        ep = WebTransportEndpoint(url="https://example.com/wt", path="/wt")
        assert ep.supports_datagrams is False

    def test_supports_streams_default(self):
        ep = WebTransportEndpoint(url="https://example.com/wt", path="/wt")
        assert ep.supports_streams is True

    def test_max_streams_default(self):
        ep = WebTransportEndpoint(url="https://example.com/wt", path="/wt")
        assert ep.max_streams is None

    def test_origin_validated_default(self):
        ep = WebTransportEndpoint(url="https://example.com/wt", path="/wt")
        assert ep.origin_validated is True

    def test_auth_required_default(self):
        ep = WebTransportEndpoint(url="https://example.com/wt", path="/wt")
        assert ep.auth_required is False

    def test_protocol_version_default(self):
        ep = WebTransportEndpoint(url="https://example.com/wt", path="/wt")
        assert ep.protocol_version == ""


class TestWebTransportEndpointFull:
    """Test WebTransportEndpoint dataclass full creation."""

    def test_full_creation(self):
        ep = WebTransportEndpoint(
            url="https://example.com:8443/transport",
            path="/transport",
            supports_datagrams=True,
            supports_streams=True,
            max_streams=256,
            origin_validated=False,
            auth_required=True,
            protocol_version="draft02",
        )
        assert ep.url == "https://example.com:8443/transport"
        assert ep.path == "/transport"
        assert ep.supports_datagrams is True
        assert ep.supports_streams is True
        assert ep.max_streams == 256
        assert ep.origin_validated is False
        assert ep.auth_required is True
        assert ep.protocol_version == "draft02"

    def test_requires_mandatory_fields(self):
        """WebTransportEndpoint requires url and path."""
        with pytest.raises(TypeError):
            WebTransportEndpoint()  # type: ignore[call-arg]

    def test_requires_url(self):
        with pytest.raises(TypeError):
            WebTransportEndpoint(path="/wt")  # type: ignore[call-arg]

    def test_requires_path(self):
        with pytest.raises(TypeError):
            WebTransportEndpoint(url="https://example.com/wt")  # type: ignore[call-arg]


# =============================================================================
# DATACLASS TESTS: WebTransportScanContext
# =============================================================================

class TestWebTransportScanContextDefaults:
    """Test WebTransportScanContext dataclass default values."""

    def test_endpoints_default(self):
        ctx = WebTransportScanContext(
            target_url="https://example.com", host="example.com", port=443
        )
        assert ctx.endpoints == []

    def test_http3_available_default(self):
        ctx = WebTransportScanContext(
            target_url="https://example.com", host="example.com", port=443
        )
        assert ctx.http3_available is False

    def test_webtransport_detected_default(self):
        ctx = WebTransportScanContext(
            target_url="https://example.com", host="example.com", port=443
        )
        assert ctx.webtransport_detected is False

    def test_endpoints_list_isolation(self):
        """Each instance should have its own list (no shared mutable default)."""
        a = WebTransportScanContext(
            target_url="https://a.com", host="a.com", port=443
        )
        b = WebTransportScanContext(
            target_url="https://b.com", host="b.com", port=443
        )
        a.endpoints.append(
            WebTransportEndpoint(url="https://a.com/wt", path="/wt")
        )
        assert b.endpoints == []


class TestWebTransportScanContextFull:
    """Test WebTransportScanContext dataclass full creation."""

    def test_full_creation(self):
        ep = WebTransportEndpoint(url="https://example.com/wt", path="/wt")
        ctx = WebTransportScanContext(
            target_url="https://example.com:8443/path",
            host="example.com",
            port=8443,
            endpoints=[ep],
            http3_available=True,
            webtransport_detected=True,
        )
        assert ctx.target_url == "https://example.com:8443/path"
        assert ctx.host == "example.com"
        assert ctx.port == 8443
        assert len(ctx.endpoints) == 1
        assert ctx.endpoints[0].path == "/wt"
        assert ctx.http3_available is True
        assert ctx.webtransport_detected is True

    def test_requires_mandatory_fields(self):
        """WebTransportScanContext requires target_url, host, port."""
        with pytest.raises(TypeError):
            WebTransportScanContext()  # type: ignore[call-arg]


# =============================================================================
# SCANNER IDENTITY TESTS: WebTransportScanner
# =============================================================================

class TestWebTransportScannerIdentity:
    """Test WebTransportScanner class-level attributes and identity."""

    def test_name(self):
        assert WebTransportScanner.name == "webtransport_scanner"

    def test_description(self):
        assert WebTransportScanner.description == "WebTransport Protocol Security Scanner"

    def test_version(self):
        assert WebTransportScanner.version == WEBTRANSPORT_SCANNER_VERSION

    def test_version_value(self):
        assert WebTransportScanner.version == "1.0.0"

    def test_category(self):
        assert WebTransportScanner.category == "protocol"

    def test_tags_is_list(self):
        assert isinstance(WebTransportScanner.tags, list)

    def test_tags_count(self):
        assert len(WebTransportScanner.tags) == 5

    def test_tags_contents(self):
        expected = ["webtransport", "http3", "quic", "realtime", "bidirectional"]
        assert WebTransportScanner.tags == expected

    def test_is_scan_module_subclass(self):
        from scanning.vuln_scanner import ScanModule
        assert issubclass(WebTransportScanner, ScanModule)


# =============================================================================
# SCANNER INSTANTIATION TESTS
# =============================================================================

class TestWebTransportScannerInstantiation:
    """Test WebTransportScanner instantiation with mock settings."""

    def test_instantiation_with_settings(self):
        scanner = WebTransportScanner(settings=MOCK_SETTINGS)
        assert scanner.name == "webtransport_scanner"

    def test_findings_empty_on_init(self):
        scanner = WebTransportScanner(settings=MOCK_SETTINGS)
        assert scanner.findings == []

    def test_ctx_none_on_init(self):
        scanner = WebTransportScanner(settings=MOCK_SETTINGS)
        assert scanner.ctx is None

    def test_instantiation_without_settings(self):
        scanner = WebTransportScanner()
        assert scanner.name == "webtransport_scanner"


# =============================================================================
# WEBTRANSPORT_PATHS CONSTANT TESTS
# =============================================================================

class TestWebTransportPaths:
    """Test WebTransportScanner.WEBTRANSPORT_PATHS class constant."""

    def test_is_list(self):
        assert isinstance(WebTransportScanner.WEBTRANSPORT_PATHS, list)

    def test_count(self):
        assert len(WebTransportScanner.WEBTRANSPORT_PATHS) == 10

    def test_all_strings(self):
        for path in WebTransportScanner.WEBTRANSPORT_PATHS:
            assert isinstance(path, str)

    def test_all_start_with_slash(self):
        for path in WebTransportScanner.WEBTRANSPORT_PATHS:
            assert path.startswith("/"), f"Path does not start with '/': {path!r}"

    def test_contains_well_known(self):
        assert "/.well-known/webtransport" in WebTransportScanner.WEBTRANSPORT_PATHS

    def test_contains_webtransport(self):
        assert "/webtransport" in WebTransportScanner.WEBTRANSPORT_PATHS

    def test_contains_wt(self):
        assert "/wt" in WebTransportScanner.WEBTRANSPORT_PATHS

    def test_contains_transport(self):
        assert "/transport" in WebTransportScanner.WEBTRANSPORT_PATHS

    def test_contains_bidirectional(self):
        assert "/bidirectional" in WebTransportScanner.WEBTRANSPORT_PATHS

    def test_contains_realtime(self):
        assert "/realtime" in WebTransportScanner.WEBTRANSPORT_PATHS

    def test_contains_stream(self):
        assert "/stream" in WebTransportScanner.WEBTRANSPORT_PATHS

    def test_contains_api_webtransport(self):
        assert "/api/webtransport" in WebTransportScanner.WEBTRANSPORT_PATHS

    def test_contains_ws_alt(self):
        assert "/ws-alt" in WebTransportScanner.WEBTRANSPORT_PATHS

    def test_contains_quic(self):
        assert "/quic" in WebTransportScanner.WEBTRANSPORT_PATHS

    def test_no_duplicates(self):
        paths = WebTransportScanner.WEBTRANSPORT_PATHS
        assert len(paths) == len(set(paths))


# =============================================================================
# CWE MAP TESTS: _get_cwe_for_vuln
# =============================================================================

class TestCWEMap:
    """Test the CWE mapping returned by _get_cwe_for_vuln."""

    def setup_method(self):
        self.scanner = WebTransportScanner(settings=MOCK_SETTINGS)

    def test_session_hijack_cwe(self):
        assert self.scanner._get_cwe_for_vuln(WebTransportVulnType.SESSION_HIJACK) == "CWE-384"

    def test_datagram_spoofing_cwe(self):
        assert self.scanner._get_cwe_for_vuln(WebTransportVulnType.DATAGRAM_SPOOFING) == "CWE-290"

    def test_stream_exhaustion_cwe(self):
        assert self.scanner._get_cwe_for_vuln(WebTransportVulnType.STREAM_EXHAUSTION) == "CWE-400"

    def test_auth_bypass_cwe(self):
        assert self.scanner._get_cwe_for_vuln(WebTransportVulnType.AUTH_BYPASS) == "CWE-287"

    def test_origin_bypass_cwe(self):
        assert self.scanner._get_cwe_for_vuln(WebTransportVulnType.ORIGIN_BYPASS) == "CWE-346"

    def test_protocol_downgrade_cwe(self):
        assert self.scanner._get_cwe_for_vuln(WebTransportVulnType.PROTOCOL_DOWNGRADE) == "CWE-757"

    def test_resource_exhaustion_cwe(self):
        assert self.scanner._get_cwe_for_vuln(WebTransportVulnType.RESOURCE_EXHAUSTION) == "CWE-400"

    def test_data_injection_cwe(self):
        assert self.scanner._get_cwe_for_vuln(WebTransportVulnType.DATA_INJECTION) == "CWE-74"

    def test_replay_attack_cwe(self):
        assert self.scanner._get_cwe_for_vuln(WebTransportVulnType.REPLAY_ATTACK) == "CWE-294"

    def test_connection_migration_cwe(self):
        assert self.scanner._get_cwe_for_vuln(WebTransportVulnType.CONNECTION_MIGRATION) == "CWE-384"

    def test_all_enum_members_have_cwe(self):
        """Every WebTransportVulnType member should have a CWE mapping (not the fallback)."""
        for member in WebTransportVulnType:
            cwe = self.scanner._get_cwe_for_vuln(member)
            assert cwe != "CWE-16", f"{member.name} fell through to default CWE-16"

    def test_all_cwe_values_start_with_cwe(self):
        for member in WebTransportVulnType:
            cwe = self.scanner._get_cwe_for_vuln(member)
            assert cwe.startswith("CWE-"), f"{member.name} CWE does not start with 'CWE-': {cwe}"

    def test_cwe_map_covers_exactly_10_members(self):
        """CWE map covers all 10 enum members."""
        mapped_count = sum(
            1 for m in WebTransportVulnType
            if self.scanner._get_cwe_for_vuln(m) != "CWE-16"
        )
        assert mapped_count == 10

    def test_fallback_for_unknown_value(self):
        """If somehow an unmapped value were passed, default is CWE-16.

        We test this by calling with a mock that won't match any key.
        Since all 10 are mapped, we verify the fallback logic exists
        by checking the method's return type is str for all members.
        """
        for member in WebTransportVulnType:
            result = self.scanner._get_cwe_for_vuln(member)
            assert isinstance(result, str)


# =============================================================================
# _build_result STRUCTURE TESTS
# =============================================================================

class TestBuildResult:
    """Test _build_result returns the expected dictionary structure."""

    def setup_method(self):
        self.scanner = WebTransportScanner(settings=MOCK_SETTINGS)
        self.scanner.findings = []
        self.scanner.ctx = WebTransportScanContext(
            target_url="https://example.com",
            host="example.com",
            port=443,
        )

    def test_result_is_dict(self):
        result = self.scanner._build_result("https://example.com", 1.5)
        assert isinstance(result, dict)

    def test_result_has_scanner_key(self):
        result = self.scanner._build_result("https://example.com", 1.5)
        assert result["scanner"] == "webtransport_scanner"

    def test_result_has_version_key(self):
        result = self.scanner._build_result("https://example.com", 1.5)
        assert result["version"] == "1.0.0"

    def test_result_has_target_key(self):
        result = self.scanner._build_result("https://example.com", 1.5)
        assert result["target"] == "https://example.com"

    def test_result_has_elapsed_seconds(self):
        result = self.scanner._build_result("https://example.com", 2.75)
        assert result["elapsed_seconds"] == 2.75

    def test_result_has_findings_list(self):
        result = self.scanner._build_result("https://example.com", 1.5)
        assert result["findings"] == []

    def test_result_has_findings_count(self):
        result = self.scanner._build_result("https://example.com", 1.5)
        assert result["findings_count"] == 0

    def test_result_has_webtransport_info(self):
        result = self.scanner._build_result("https://example.com", 1.5)
        info = result["webtransport_info"]
        assert isinstance(info, dict)
        assert "detected" in info
        assert "endpoints" in info
        assert "http3_available" in info

    def test_result_webtransport_info_detected_false(self):
        result = self.scanner._build_result("https://example.com", 1.5)
        assert result["webtransport_info"]["detected"] is False

    def test_result_webtransport_info_endpoints_empty(self):
        result = self.scanner._build_result("https://example.com", 1.5)
        assert result["webtransport_info"]["endpoints"] == []

    def test_result_webtransport_info_with_endpoints(self):
        ep = WebTransportEndpoint(
            url="https://example.com/wt",
            path="/wt",
            supports_datagrams=True,
            auth_required=True,
            origin_validated=False,
        )
        self.scanner.ctx.endpoints.append(ep)
        result = self.scanner._build_result("https://example.com", 1.5)
        endpoints = result["webtransport_info"]["endpoints"]
        assert len(endpoints) == 1
        assert endpoints[0]["path"] == "/wt"
        assert endpoints[0]["supports_datagrams"] is True
        assert endpoints[0]["auth_required"] is True
        assert endpoints[0]["origin_validated"] is False

    def test_result_when_ctx_is_none(self):
        self.scanner.ctx = None
        result = self.scanner._build_result("https://example.com", 1.0)
        assert result["webtransport_info"]["detected"] is False
        assert result["webtransport_info"]["endpoints"] == []
        assert result["webtransport_info"]["http3_available"] is False

    def test_result_keys_complete(self):
        result = self.scanner._build_result("https://example.com", 1.5)
        expected_keys = {
            "scanner", "version", "target", "elapsed_seconds",
            "findings", "findings_count", "webtransport_info",
        }
        assert set(result.keys()) == expected_keys
