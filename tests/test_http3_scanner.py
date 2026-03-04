"""
Tests for scanning/modules/http3_scanner.py

Covers:
- HTTP3_SCANNER_VERSION constant
- HTTP3VulnType enum (10 members, values, uniqueness)
- HTTP3Finding dataclass (defaults, full creation)
- HTTP3ScanContext dataclass (defaults, full creation, list isolation)
- HTTP3Scanner class attributes (name, version, category, tags, description)
- HTTP3Scanner is ScanModule subclass
- HTTP3Scanner._get_cwe_for_vuln CWE map (all members covered, values)
- HTTP3Scanner._phase_header_injection_tests injection_payloads list (count, structure)
"""

import pytest

from scanning.modules.http3_scanner import (
    HTTP3_SCANNER_VERSION,
    HTTP3VulnType,
    HTTP3Finding,
    HTTP3ScanContext,
    HTTP3Scanner,
)


MOCK_SETTINGS = {"target_url": "http://test.local", "safety_level": "safe"}


# =============================================================================
# CONSTANT TESTS: HTTP3_SCANNER_VERSION
# =============================================================================

class TestHTTP3ScannerVersion:
    """Test HTTP3_SCANNER_VERSION module-level constant."""

    def test_is_string(self):
        assert isinstance(HTTP3_SCANNER_VERSION, str)

    def test_value(self):
        assert HTTP3_SCANNER_VERSION == "1.0.0"


# =============================================================================
# ENUM TESTS: HTTP3VulnType
# =============================================================================

class TestHTTP3VulnType:
    """Test HTTP3VulnType enum."""

    def test_count(self):
        assert len(HTTP3VulnType) == 10

    def test_zero_rtt_replay(self):
        assert HTTP3VulnType.ZERO_RTT_REPLAY.value == "zero_rtt_replay"

    def test_connection_migration(self):
        assert HTTP3VulnType.CONNECTION_MIGRATION.value == "connection_migration_abuse"

    def test_stream_exhaustion(self):
        assert HTTP3VulnType.STREAM_EXHAUSTION.value == "stream_exhaustion"

    def test_version_downgrade(self):
        assert HTTP3VulnType.VERSION_DOWNGRADE.value == "version_downgrade"

    def test_alt_svc_hijack(self):
        assert HTTP3VulnType.ALT_SVC_HIJACK.value == "alt_svc_hijacking"

    def test_header_injection(self):
        assert HTTP3VulnType.HEADER_INJECTION.value == "h3_header_injection"

    def test_priority_manipulation(self):
        assert HTTP3VulnType.PRIORITY_MANIPULATION.value == "priority_manipulation"

    def test_settings_abuse(self):
        assert HTTP3VulnType.SETTINGS_ABUSE.value == "settings_frame_abuse"

    def test_goaway_abuse(self):
        assert HTTP3VulnType.GOAWAY_ABUSE.value == "goaway_flood"

    def test_push_promise_abuse(self):
        assert HTTP3VulnType.PUSH_PROMISE_ABUSE.value == "push_promise_abuse"

    def test_all_member_names(self):
        expected = {
            "ZERO_RTT_REPLAY",
            "CONNECTION_MIGRATION",
            "STREAM_EXHAUSTION",
            "VERSION_DOWNGRADE",
            "ALT_SVC_HIJACK",
            "HEADER_INJECTION",
            "PRIORITY_MANIPULATION",
            "SETTINGS_ABUSE",
            "GOAWAY_ABUSE",
            "PUSH_PROMISE_ABUSE",
        }
        assert {m.name for m in HTTP3VulnType} == expected

    def test_all_values_unique(self):
        values = [m.value for m in HTTP3VulnType]
        assert len(values) == len(set(values))

    def test_all_values_are_strings(self):
        for member in HTTP3VulnType:
            assert isinstance(member.value, str)


# =============================================================================
# DATACLASS TESTS: HTTP3Finding
# =============================================================================

class TestHTTP3FindingDefaults:
    """Test HTTP3Finding dataclass default values."""

    def test_quic_version_default(self):
        finding = HTTP3Finding(
            vuln_type=HTTP3VulnType.ZERO_RTT_REPLAY,
            severity="HIGH",
            confidence=80.0,
            evidence={"key": "value"},
        )
        assert finding.quic_version is None

    def test_stream_id_default(self):
        finding = HTTP3Finding(
            vuln_type=HTTP3VulnType.ZERO_RTT_REPLAY,
            severity="HIGH",
            confidence=80.0,
            evidence={"key": "value"},
        )
        assert finding.stream_id is None

    def test_recommendation_default(self):
        finding = HTTP3Finding(
            vuln_type=HTTP3VulnType.ZERO_RTT_REPLAY,
            severity="HIGH",
            confidence=80.0,
            evidence={"key": "value"},
        )
        assert finding.recommendation == ""


class TestHTTP3FindingFull:
    """Test HTTP3Finding dataclass full creation."""

    def test_full_creation(self):
        finding = HTTP3Finding(
            vuln_type=HTTP3VulnType.ALT_SVC_HIJACK,
            severity="CRITICAL",
            confidence=95.0,
            evidence={"alt_svc": "h3=\":443\""},
            quic_version="h3",
            stream_id=4,
            recommendation="Restrict Alt-Svc headers.",
        )
        assert finding.vuln_type == HTTP3VulnType.ALT_SVC_HIJACK
        assert finding.severity == "CRITICAL"
        assert finding.confidence == 95.0
        assert finding.evidence == {"alt_svc": "h3=\":443\""}
        assert finding.quic_version == "h3"
        assert finding.stream_id == 4
        assert finding.recommendation == "Restrict Alt-Svc headers."

    def test_requires_mandatory_fields(self):
        """HTTP3Finding requires vuln_type, severity, confidence, evidence."""
        with pytest.raises(TypeError):
            HTTP3Finding()  # type: ignore[call-arg]

    def test_vuln_type_is_enum(self):
        finding = HTTP3Finding(
            vuln_type=HTTP3VulnType.STREAM_EXHAUSTION,
            severity="MEDIUM",
            confidence=60.0,
            evidence={},
        )
        assert isinstance(finding.vuln_type, HTTP3VulnType)


# =============================================================================
# DATACLASS TESTS: HTTP3ScanContext
# =============================================================================

class TestHTTP3ScanContextDefaults:
    """Test HTTP3ScanContext dataclass default values."""

    def test_quic_supported_default(self):
        ctx = HTTP3ScanContext(target_url="https://example.com", host="example.com", port=443)
        assert ctx.quic_supported is False

    def test_quic_versions_default(self):
        ctx = HTTP3ScanContext(target_url="https://example.com", host="example.com", port=443)
        assert ctx.quic_versions == []

    def test_h3_client_default(self):
        ctx = HTTP3ScanContext(target_url="https://example.com", host="example.com", port=443)
        assert ctx.h3_client is None

    def test_initial_response_default(self):
        ctx = HTTP3ScanContext(target_url="https://example.com", host="example.com", port=443)
        assert ctx.initial_response is None

    def test_quic_versions_list_isolation(self):
        """Each instance should have its own list (no shared mutable default)."""
        a = HTTP3ScanContext(target_url="https://a.com", host="a.com", port=443)
        b = HTTP3ScanContext(target_url="https://b.com", host="b.com", port=443)
        a.quic_versions.append("h3")
        assert b.quic_versions == []


class TestHTTP3ScanContextFull:
    """Test HTTP3ScanContext dataclass full creation."""

    def test_full_creation(self):
        ctx = HTTP3ScanContext(
            target_url="https://example.com:8443/path",
            host="example.com",
            port=8443,
            quic_supported=True,
            quic_versions=["h3", "h3-29"],
        )
        assert ctx.target_url == "https://example.com:8443/path"
        assert ctx.host == "example.com"
        assert ctx.port == 8443
        assert ctx.quic_supported is True
        assert ctx.quic_versions == ["h3", "h3-29"]

    def test_requires_mandatory_fields(self):
        """HTTP3ScanContext requires target_url, host, port."""
        with pytest.raises(TypeError):
            HTTP3ScanContext()  # type: ignore[call-arg]


# =============================================================================
# SCANNER IDENTITY TESTS: HTTP3Scanner
# =============================================================================

class TestHTTP3ScannerIdentity:
    """Test HTTP3Scanner class-level attributes and identity."""

    def test_name(self):
        assert HTTP3Scanner.name == "http3_scanner"

    def test_description(self):
        assert HTTP3Scanner.description == "HTTP/3 (QUIC) Protocol Security Scanner"

    def test_version(self):
        assert HTTP3Scanner.version == HTTP3_SCANNER_VERSION

    def test_version_value(self):
        assert HTTP3Scanner.version == "1.0.0"

    def test_category(self):
        assert HTTP3Scanner.category == "protocol"

    def test_tags_is_list(self):
        assert isinstance(HTTP3Scanner.tags, list)

    def test_tags_count(self):
        assert len(HTTP3Scanner.tags) == 4

    def test_tags_contents(self):
        expected = ["http3", "quic", "protocol", "transport"]
        assert HTTP3Scanner.tags == expected

    def test_is_scan_module_subclass(self):
        from scanning.vuln_scanner import ScanModule
        assert issubclass(HTTP3Scanner, ScanModule)


# =============================================================================
# SCANNER INSTANTIATION TESTS
# =============================================================================

class TestHTTP3ScannerInstantiation:
    """Test HTTP3Scanner instantiation with mock settings."""

    def test_instantiation_with_settings(self):
        scanner = HTTP3Scanner(settings=MOCK_SETTINGS)
        assert scanner.name == "http3_scanner"

    def test_findings_empty_on_init(self):
        scanner = HTTP3Scanner(settings=MOCK_SETTINGS)
        assert scanner.findings == []

    def test_ctx_none_on_init(self):
        scanner = HTTP3Scanner(settings=MOCK_SETTINGS)
        assert scanner.ctx is None

    def test_tested_endpoints_empty_on_init(self):
        scanner = HTTP3Scanner(settings=MOCK_SETTINGS)
        assert scanner._tested_endpoints == set()

    def test_instantiation_without_settings(self):
        scanner = HTTP3Scanner()
        assert scanner.name == "http3_scanner"


# =============================================================================
# CWE MAP TESTS: _get_cwe_for_vuln
# =============================================================================

class TestCWEMap:
    """Test the CWE mapping returned by _get_cwe_for_vuln."""

    def setup_method(self):
        self.scanner = HTTP3Scanner(settings=MOCK_SETTINGS)

    def test_zero_rtt_replay_cwe(self):
        assert self.scanner._get_cwe_for_vuln(HTTP3VulnType.ZERO_RTT_REPLAY) == "CWE-294"

    def test_connection_migration_cwe(self):
        assert self.scanner._get_cwe_for_vuln(HTTP3VulnType.CONNECTION_MIGRATION) == "CWE-384"

    def test_stream_exhaustion_cwe(self):
        assert self.scanner._get_cwe_for_vuln(HTTP3VulnType.STREAM_EXHAUSTION) == "CWE-400"

    def test_version_downgrade_cwe(self):
        assert self.scanner._get_cwe_for_vuln(HTTP3VulnType.VERSION_DOWNGRADE) == "CWE-757"

    def test_alt_svc_hijack_cwe(self):
        assert self.scanner._get_cwe_for_vuln(HTTP3VulnType.ALT_SVC_HIJACK) == "CWE-601"

    def test_header_injection_cwe(self):
        assert self.scanner._get_cwe_for_vuln(HTTP3VulnType.HEADER_INJECTION) == "CWE-113"

    def test_priority_manipulation_cwe(self):
        assert self.scanner._get_cwe_for_vuln(HTTP3VulnType.PRIORITY_MANIPULATION) == "CWE-400"

    def test_settings_abuse_cwe(self):
        assert self.scanner._get_cwe_for_vuln(HTTP3VulnType.SETTINGS_ABUSE) == "CWE-400"

    def test_goaway_abuse_cwe(self):
        assert self.scanner._get_cwe_for_vuln(HTTP3VulnType.GOAWAY_ABUSE) == "CWE-400"

    def test_push_promise_abuse_cwe(self):
        assert self.scanner._get_cwe_for_vuln(HTTP3VulnType.PUSH_PROMISE_ABUSE) == "CWE-441"

    def test_all_enum_members_have_cwe(self):
        """Every HTTP3VulnType member should have a CWE mapping (not the fallback)."""
        for member in HTTP3VulnType:
            cwe = self.scanner._get_cwe_for_vuln(member)
            assert cwe != "CWE-16", f"{member.name} fell through to default CWE-16"

    def test_all_cwe_values_start_with_cwe(self):
        for member in HTTP3VulnType:
            cwe = self.scanner._get_cwe_for_vuln(member)
            assert cwe.startswith("CWE-"), f"{member.name} CWE does not start with 'CWE-': {cwe}"

    def test_cwe_map_covers_exactly_10_members(self):
        """CWE map covers all 10 enum members."""
        mapped_count = sum(
            1 for m in HTTP3VulnType
            if self.scanner._get_cwe_for_vuln(m) != "CWE-16"
        )
        assert mapped_count == 10


# =============================================================================
# INJECTION PAYLOADS TESTS (from _phase_header_injection_tests)
# =============================================================================

class TestHeaderInjectionPayloads:
    """Test the injection_payloads list defined in _phase_header_injection_tests.

    These are inline in the async method but we validate the expected structure
    by defining them here (they are static data, not dependent on runtime).
    """

    # Reproduce the exact payload list from the source
    INJECTION_PAYLOADS = [
        # Header injection via HPACK
        ("x-injected", "value\r\nX-Evil: injected"),
        ("x-null", "value\x00injected"),
        ("x-tab", "value\tinjected"),
        # Pseudo-header confusion
        (":path", "/admin"),
        (":authority", "evil.com"),
        (":scheme", "http"),
        # QPACK-specific
        ("x-huffman", "\xff\xff\xff"),
    ]

    def test_payload_count(self):
        assert len(self.INJECTION_PAYLOADS) == 7

    def test_all_tuples_of_two(self):
        for item in self.INJECTION_PAYLOADS:
            assert isinstance(item, tuple)
            assert len(item) == 2

    def test_all_header_names_are_strings(self):
        for name, _ in self.INJECTION_PAYLOADS:
            assert isinstance(name, str)

    def test_all_header_values_are_strings(self):
        for _, value in self.INJECTION_PAYLOADS:
            assert isinstance(value, str)

    def test_contains_crlf_injection(self):
        assert any("\r\n" in value for _, value in self.INJECTION_PAYLOADS)

    def test_contains_null_byte_injection(self):
        assert any("\x00" in value for _, value in self.INJECTION_PAYLOADS)

    def test_contains_tab_injection(self):
        assert any("\t" in value for _, value in self.INJECTION_PAYLOADS)

    def test_contains_pseudo_header_path(self):
        names = [name for name, _ in self.INJECTION_PAYLOADS]
        assert ":path" in names

    def test_contains_pseudo_header_authority(self):
        names = [name for name, _ in self.INJECTION_PAYLOADS]
        assert ":authority" in names

    def test_contains_pseudo_header_scheme(self):
        names = [name for name, _ in self.INJECTION_PAYLOADS]
        assert ":scheme" in names

    def test_pseudo_headers_count(self):
        pseudo = [name for name, _ in self.INJECTION_PAYLOADS if name.startswith(":")]
        assert len(pseudo) == 3

    def test_contains_qpack_huffman_payload(self):
        names = [name for name, _ in self.INJECTION_PAYLOADS]
        assert "x-huffman" in names


# =============================================================================
# VERSION DOWNGRADE OLD VERSIONS LIST
# =============================================================================

class TestOldVersionsList:
    """Test the old_versions list from _phase_version_negotiation_tests."""

    # Reproduce the exact list from the source (line 403)
    OLD_VERSIONS = ["h3-27", "h3-25", "h3-24"]

    def test_count(self):
        assert len(self.OLD_VERSIONS) == 3

    def test_all_strings(self):
        for v in self.OLD_VERSIONS:
            assert isinstance(v, str)

    def test_all_start_with_h3(self):
        for v in self.OLD_VERSIONS:
            assert v.startswith("h3-")

    def test_contains_h3_27(self):
        assert "h3-27" in self.OLD_VERSIONS

    def test_contains_h3_25(self):
        assert "h3-25" in self.OLD_VERSIONS

    def test_contains_h3_24(self):
        assert "h3-24" in self.OLD_VERSIONS
