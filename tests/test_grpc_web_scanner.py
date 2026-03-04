"""
Tests for scanning/modules/grpc_web_scanner.py

Covers:
- GRPCWebVulnType enum (8 vuln types, auto values, uniqueness)
- GRPCWebMode enum (2 modes, string values)
- GRPCEndpoint dataclass (defaults, full creation)
- GRPCTestResult dataclass (defaults, full creation)
- GRPCWebMessage static helpers (encode_frame, decode_frame, encode_text,
  decode_text, create_simple_message, _encode_varint)
- GRPCWebScanner class identity (name, version, ScanModule subclass)
- GRPCWebScanner class-level constants:
    GRPC_ENDPOINTS, COMMON_SERVICES, CONTENT_TYPES, PROXY_PATTERNS
- Module-level constant GRPC_WEB_SCANNER_VERSION
"""

import base64
import struct

import pytest

from scanning.modules.grpc_web_scanner import (
    GRPC_WEB_SCANNER_VERSION,
    GRPCEndpoint,
    GRPCTestResult,
    GRPCWebMessage,
    GRPCWebMode,
    GRPCWebScanner,
    GRPCWebVulnType,
)
from scanning.vuln_scanner import ScanModule


# =============================================================================
# MODULE-LEVEL CONSTANTS
# =============================================================================

class TestGRPCWebScannerVersion:
    """GRPC_WEB_SCANNER_VERSION module constant."""

    def test_value(self):
        assert GRPC_WEB_SCANNER_VERSION == "1.0.0"

    def test_type(self):
        assert isinstance(GRPC_WEB_SCANNER_VERSION, str)


# =============================================================================
# ENUM: GRPCWebVulnType
# =============================================================================

class TestGRPCWebVulnType:
    """GRPCWebVulnType enum — 8 vulnerability types using auto()."""

    def test_member_count(self):
        assert len(GRPCWebVulnType) == 8

    def test_all_member_names(self):
        expected = {
            "AUTH_BYPASS",
            "FIELD_MANIPULATION",
            "TYPE_CONFUSION",
            "REFLECTION_ABUSE",
            "STREAMING_ABUSE",
            "METADATA_INJECTION",
            "SERVICE_ENUM",
            "MESSAGE_TAMPERING",
        }
        assert {m.name for m in GRPCWebVulnType} == expected

    def test_auth_bypass_exists(self):
        assert GRPCWebVulnType.AUTH_BYPASS is not None

    def test_field_manipulation_exists(self):
        assert GRPCWebVulnType.FIELD_MANIPULATION is not None

    def test_type_confusion_exists(self):
        assert GRPCWebVulnType.TYPE_CONFUSION is not None

    def test_reflection_abuse_exists(self):
        assert GRPCWebVulnType.REFLECTION_ABUSE is not None

    def test_streaming_abuse_exists(self):
        assert GRPCWebVulnType.STREAMING_ABUSE is not None

    def test_metadata_injection_exists(self):
        assert GRPCWebVulnType.METADATA_INJECTION is not None

    def test_service_enum_exists(self):
        assert GRPCWebVulnType.SERVICE_ENUM is not None

    def test_message_tampering_exists(self):
        assert GRPCWebVulnType.MESSAGE_TAMPERING is not None

    def test_values_are_unique(self):
        values = [m.value for m in GRPCWebVulnType]
        assert len(values) == len(set(values))

    def test_values_are_auto_ints(self):
        for m in GRPCWebVulnType:
            assert isinstance(m.value, int)


# =============================================================================
# ENUM: GRPCWebMode
# =============================================================================

class TestGRPCWebMode:
    """GRPCWebMode enum — 2 transport modes with string values."""

    def test_member_count(self):
        assert len(GRPCWebMode) == 2

    def test_text_value(self):
        assert GRPCWebMode.TEXT.value == "text"

    def test_binary_value(self):
        assert GRPCWebMode.BINARY.value == "binary"

    def test_all_member_names(self):
        assert {m.name for m in GRPCWebMode} == {"TEXT", "BINARY"}

    def test_values_are_strings(self):
        for m in GRPCWebMode:
            assert isinstance(m.value, str)


# =============================================================================
# DATACLASS: GRPCEndpoint
# =============================================================================

class TestGRPCEndpointDefaults:
    """GRPCEndpoint dataclass — default field values."""

    def test_services_default_empty_list(self):
        ep = GRPCEndpoint(url="http://test.local/grpc", mode=GRPCWebMode.TEXT)
        assert ep.services == []

    def test_methods_default_empty_list(self):
        ep = GRPCEndpoint(url="http://test.local/grpc", mode=GRPCWebMode.TEXT)
        assert ep.methods == []

    def test_has_reflection_default_false(self):
        ep = GRPCEndpoint(url="http://test.local/grpc", mode=GRPCWebMode.TEXT)
        assert ep.has_reflection is False

    def test_proxy_type_default_empty(self):
        ep = GRPCEndpoint(url="http://test.local/grpc", mode=GRPCWebMode.TEXT)
        assert ep.proxy_type == ""

    def test_services_list_independence(self):
        """Each instance gets its own list (no shared mutable default)."""
        ep1 = GRPCEndpoint(url="http://a.local", mode=GRPCWebMode.TEXT)
        ep2 = GRPCEndpoint(url="http://b.local", mode=GRPCWebMode.BINARY)
        ep1.services.append("UserService")
        assert ep2.services == []


class TestGRPCEndpointFull:
    """GRPCEndpoint dataclass — fully populated."""

    def test_full_creation(self):
        ep = GRPCEndpoint(
            url="http://test.local/grpc",
            mode=GRPCWebMode.BINARY,
            services=["UserService", "AdminService"],
            methods=["Get", "List"],
            has_reflection=True,
            proxy_type="envoy",
        )
        assert ep.url == "http://test.local/grpc"
        assert ep.mode == GRPCWebMode.BINARY
        assert ep.services == ["UserService", "AdminService"]
        assert ep.methods == ["Get", "List"]
        assert ep.has_reflection is True
        assert ep.proxy_type == "envoy"


# =============================================================================
# DATACLASS: GRPCTestResult
# =============================================================================

class TestGRPCTestResultDefaults:
    """GRPCTestResult dataclass — default field values."""

    def test_response_data_default_empty(self):
        r = GRPCTestResult(
            vulnerable=True,
            vuln_type=GRPCWebVulnType.AUTH_BYPASS,
            confidence=80,
            payload="test",
        )
        assert r.response_data == ""

    def test_evidence_default_empty_list(self):
        r = GRPCTestResult(
            vulnerable=True,
            vuln_type=GRPCWebVulnType.AUTH_BYPASS,
            confidence=80,
            payload="test",
        )
        assert r.evidence == []

    def test_severity_default_medium(self):
        r = GRPCTestResult(
            vulnerable=True,
            vuln_type=GRPCWebVulnType.AUTH_BYPASS,
            confidence=80,
            payload="test",
        )
        assert r.severity == "MEDIUM"

    def test_data_leaked_default_false(self):
        r = GRPCTestResult(
            vulnerable=True,
            vuln_type=GRPCWebVulnType.AUTH_BYPASS,
            confidence=80,
            payload="test",
        )
        assert r.data_leaked is False

    def test_evidence_list_independence(self):
        r1 = GRPCTestResult(
            vulnerable=True,
            vuln_type=GRPCWebVulnType.AUTH_BYPASS,
            confidence=80,
            payload="p1",
        )
        r2 = GRPCTestResult(
            vulnerable=False,
            vuln_type=GRPCWebVulnType.SERVICE_ENUM,
            confidence=50,
            payload="p2",
        )
        r1.evidence.append("leaked")
        assert r2.evidence == []


class TestGRPCTestResultFull:
    """GRPCTestResult dataclass — fully populated."""

    def test_full_creation(self):
        r = GRPCTestResult(
            vulnerable=True,
            vuln_type=GRPCWebVulnType.REFLECTION_ABUSE,
            confidence=90,
            payload="ServerReflection/Info",
            response_data="0a0b73657276696365",
            evidence=["reflection enabled", "schema exposed"],
            severity="HIGH",
            data_leaked=True,
        )
        assert r.vulnerable is True
        assert r.vuln_type == GRPCWebVulnType.REFLECTION_ABUSE
        assert r.confidence == 90
        assert r.payload == "ServerReflection/Info"
        assert r.response_data == "0a0b73657276696365"
        assert r.evidence == ["reflection enabled", "schema exposed"]
        assert r.severity == "HIGH"
        assert r.data_leaked is True

    def test_required_fields_only(self):
        """Positional fields: vulnerable, vuln_type, confidence, payload."""
        r = GRPCTestResult(False, GRPCWebVulnType.STREAMING_ABUSE, 0, "")
        assert r.vulnerable is False
        assert r.confidence == 0
        assert r.payload == ""


# =============================================================================
# GRPCWebMessage — Static encode/decode helpers
# =============================================================================

class TestGRPCWebMessageEncodeFrame:
    """GRPCWebMessage.encode_frame() — gRPC-Web frame encoding."""

    def test_empty_data_frame(self):
        frame = GRPCWebMessage.encode_frame(b"")
        # 1 byte flags (0) + 4 bytes length (0) = 5 bytes
        assert len(frame) == 5
        assert frame[0] == 0  # flags = data
        assert struct.unpack(">I", frame[1:5])[0] == 0

    def test_data_frame_flags(self):
        frame = GRPCWebMessage.encode_frame(b"hello")
        assert frame[0] == 0  # not trailer

    def test_trailer_frame_flags(self):
        frame = GRPCWebMessage.encode_frame(b"trailer", is_trailer=True)
        assert frame[0] == 128

    def test_frame_length_field(self):
        data = b"hello world"
        frame = GRPCWebMessage.encode_frame(data)
        length = struct.unpack(">I", frame[1:5])[0]
        assert length == len(data)

    def test_frame_payload(self):
        data = b"test payload"
        frame = GRPCWebMessage.encode_frame(data)
        assert frame[5:] == data

    def test_total_frame_size(self):
        data = b"x" * 100
        frame = GRPCWebMessage.encode_frame(data)
        assert len(frame) == 5 + 100


class TestGRPCWebMessageDecodeFrame:
    """GRPCWebMessage.decode_frame() — gRPC-Web frame decoding."""

    def test_too_short_returns_empty(self):
        is_trailer, data = GRPCWebMessage.decode_frame(b"\x00\x00")
        assert is_trailer is False
        assert data == b""

    def test_empty_frame_decode(self):
        # 5-byte header with 0 length
        frame = struct.pack(">BI", 0, 0)
        is_trailer, data = GRPCWebMessage.decode_frame(frame)
        assert is_trailer is False
        assert data == b""

    def test_roundtrip_data_frame(self):
        original = b"roundtrip test"
        frame = GRPCWebMessage.encode_frame(original)
        is_trailer, data = GRPCWebMessage.decode_frame(frame)
        assert is_trailer is False
        assert data == original

    def test_roundtrip_trailer_frame(self):
        original = b"grpc-status:0"
        frame = GRPCWebMessage.encode_frame(original, is_trailer=True)
        is_trailer, data = GRPCWebMessage.decode_frame(frame)
        assert is_trailer is True
        assert data == original


class TestGRPCWebMessageEncodeText:
    """GRPCWebMessage.encode_text() — base64 gRPC-Web-Text encoding."""

    def test_returns_string(self):
        result = GRPCWebMessage.encode_text(b"hello")
        assert isinstance(result, str)

    def test_is_valid_base64(self):
        result = GRPCWebMessage.encode_text(b"hello")
        # Should not raise
        decoded = base64.b64decode(result)
        assert len(decoded) >= 5  # At least header

    def test_empty_data(self):
        result = GRPCWebMessage.encode_text(b"")
        assert isinstance(result, str)
        assert len(result) > 0  # Still has frame header


class TestGRPCWebMessageDecodeText:
    """GRPCWebMessage.decode_text() — base64 gRPC-Web-Text decoding."""

    def test_roundtrip(self):
        original = b"decode test"
        encoded = GRPCWebMessage.encode_text(original)
        decoded = GRPCWebMessage.decode_text(encoded)
        assert decoded == original

    def test_invalid_base64_returns_empty(self):
        result = GRPCWebMessage.decode_text("!!!not-valid-base64!!!")
        assert result == b""

    def test_empty_frame_returns_empty(self):
        # Base64 of a 5-byte header with 0 length
        frame = struct.pack(">BI", 0, 0)
        encoded = base64.b64encode(frame).decode("ascii")
        result = GRPCWebMessage.decode_text(encoded)
        assert result == b""


class TestGRPCWebMessageCreateSimpleMessage:
    """GRPCWebMessage.create_simple_message() — protobuf wire format."""

    def test_empty_fields_returns_empty_bytes(self):
        result = GRPCWebMessage.create_simple_message({})
        assert result == b""

    def test_string_field_produces_bytes(self):
        result = GRPCWebMessage.create_simple_message({1: "hello"})
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_int_field_produces_bytes(self):
        result = GRPCWebMessage.create_simple_message({1: 42})
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_bytes_field_produces_bytes(self):
        result = GRPCWebMessage.create_simple_message({1: b"\xDE\xAD"})
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_multiple_fields(self):
        result = GRPCWebMessage.create_simple_message({
            1: "name",
            2: 100,
            3: b"\x00",
        })
        assert isinstance(result, bytes)
        # Should be longer than any single field
        assert len(result) > 5

    def test_string_field_contains_payload(self):
        msg = GRPCWebMessage.create_simple_message({1: "admin"})
        assert b"admin" in msg

    def test_bytes_field_contains_payload(self):
        payload = b"\xCA\xFE\xBA\xBE"
        msg = GRPCWebMessage.create_simple_message({1: payload})
        assert payload in msg


class TestGRPCWebMessageEncodeVarint:
    """GRPCWebMessage._encode_varint() — protobuf varint encoding."""

    def test_zero(self):
        result = GRPCWebMessage._encode_varint(0)
        assert result == b"\x00"

    def test_small_value(self):
        # 1 fits in single byte (< 128)
        result = GRPCWebMessage._encode_varint(1)
        assert result == b"\x01"

    def test_127_single_byte(self):
        result = GRPCWebMessage._encode_varint(127)
        assert result == b"\x7f"

    def test_128_two_bytes(self):
        result = GRPCWebMessage._encode_varint(128)
        assert len(result) == 2
        # 128 = 0x80 -> varint: 0x80 0x01
        assert result == b"\x80\x01"

    def test_300_two_bytes(self):
        result = GRPCWebMessage._encode_varint(300)
        assert len(result) == 2
        # 300 = 0x12C -> varint: 0xAC 0x02
        assert result == b"\xac\x02"

    def test_large_value_multiple_bytes(self):
        result = GRPCWebMessage._encode_varint(100000)
        assert len(result) > 2
        assert isinstance(result, bytes)


# =============================================================================
# GRPCWebScanner CLASS — Identity & Hierarchy
# =============================================================================

class TestGRPCWebScannerIdentity:
    """GRPCWebScanner — class attributes and hierarchy."""

    def test_name(self):
        assert GRPCWebScanner.name == "grpc_web_scanner"

    def test_version_matches_module_constant(self):
        assert GRPCWebScanner.version == GRPC_WEB_SCANNER_VERSION

    def test_is_scan_module_subclass(self):
        assert issubclass(GRPCWebScanner, ScanModule)

    def test_scan_method_exists(self):
        assert hasattr(GRPCWebScanner, "scan")
        assert callable(getattr(GRPCWebScanner, "scan"))


# =============================================================================
# GRPCWebScanner.GRPC_ENDPOINTS
# =============================================================================

class TestGRPCEndpointsList:
    """GRPCWebScanner.GRPC_ENDPOINTS — common endpoint path patterns."""

    def test_count(self):
        assert len(GRPCWebScanner.GRPC_ENDPOINTS) == 8

    def test_is_list(self):
        assert isinstance(GRPCWebScanner.GRPC_ENDPOINTS, list)

    def test_all_strings(self):
        for ep in GRPCWebScanner.GRPC_ENDPOINTS:
            assert isinstance(ep, str), f"Entry {ep!r} is not a string"

    def test_contains_grpc_slash(self):
        assert "/grpc/" in GRPCWebScanner.GRPC_ENDPOINTS

    def test_contains_api_grpc_slash(self):
        assert "/api/grpc/" in GRPCWebScanner.GRPC_ENDPOINTS

    def test_contains_grpc_web_slash(self):
        assert "/grpc-web/" in GRPCWebScanner.GRPC_ENDPOINTS

    def test_contains_rpc_slash(self):
        assert "/rpc/" in GRPCWebScanner.GRPC_ENDPOINTS

    def test_contains_api_rpc_slash(self):
        assert "/api/rpc/" in GRPCWebScanner.GRPC_ENDPOINTS

    def test_contains_proto_slash(self):
        assert "/proto/" in GRPCWebScanner.GRPC_ENDPOINTS

    def test_contains_api_proto_slash(self):
        assert "/api/proto/" in GRPCWebScanner.GRPC_ENDPOINTS

    def test_contains_twirp_slash(self):
        assert "/twirp/" in GRPCWebScanner.GRPC_ENDPOINTS

    def test_all_start_with_slash(self):
        for ep in GRPCWebScanner.GRPC_ENDPOINTS:
            assert ep.startswith("/"), f"Endpoint {ep!r} does not start with /"

    def test_all_end_with_slash(self):
        for ep in GRPCWebScanner.GRPC_ENDPOINTS:
            assert ep.endswith("/"), f"Endpoint {ep!r} does not end with /"


# =============================================================================
# GRPCWebScanner.COMMON_SERVICES
# =============================================================================

class TestCommonServices:
    """GRPCWebScanner.COMMON_SERVICES — known gRPC service names."""

    def test_count(self):
        assert len(GRPCWebScanner.COMMON_SERVICES) == 9

    def test_is_list(self):
        assert isinstance(GRPCWebScanner.COMMON_SERVICES, list)

    def test_all_strings(self):
        for s in GRPCWebScanner.COMMON_SERVICES:
            assert isinstance(s, str)

    def test_contains_reflection_service(self):
        assert "grpc.reflection.v1alpha.ServerReflection" in GRPCWebScanner.COMMON_SERVICES

    def test_contains_health_service(self):
        assert "grpc.health.v1.Health" in GRPCWebScanner.COMMON_SERVICES

    def test_contains_user_service(self):
        assert "UserService" in GRPCWebScanner.COMMON_SERVICES

    def test_contains_auth_service(self):
        assert "AuthService" in GRPCWebScanner.COMMON_SERVICES

    def test_contains_admin_service(self):
        assert "AdminService" in GRPCWebScanner.COMMON_SERVICES

    def test_contains_payment_service(self):
        assert "PaymentService" in GRPCWebScanner.COMMON_SERVICES

    def test_contains_order_service(self):
        assert "OrderService" in GRPCWebScanner.COMMON_SERVICES

    def test_contains_account_service(self):
        assert "AccountService" in GRPCWebScanner.COMMON_SERVICES

    def test_no_empty_entries(self):
        for s in GRPCWebScanner.COMMON_SERVICES:
            assert s.strip() != ""


# =============================================================================
# GRPCWebScanner.CONTENT_TYPES
# =============================================================================

class TestContentTypes:
    """GRPCWebScanner.CONTENT_TYPES — mode-to-content-type mapping."""

    def test_is_dict(self):
        assert isinstance(GRPCWebScanner.CONTENT_TYPES, dict)

    def test_key_count(self):
        assert len(GRPCWebScanner.CONTENT_TYPES) == 2

    def test_keys_are_grpc_web_modes(self):
        assert set(GRPCWebScanner.CONTENT_TYPES.keys()) == {
            GRPCWebMode.TEXT,
            GRPCWebMode.BINARY,
        }

    def test_text_mode_count(self):
        assert len(GRPCWebScanner.CONTENT_TYPES[GRPCWebMode.TEXT]) == 2

    def test_binary_mode_count(self):
        assert len(GRPCWebScanner.CONTENT_TYPES[GRPCWebMode.BINARY]) == 2

    def test_text_mode_entries(self):
        expected = [
            "application/grpc-web-text",
            "application/grpc-web-text+proto",
        ]
        assert GRPCWebScanner.CONTENT_TYPES[GRPCWebMode.TEXT] == expected

    def test_binary_mode_entries(self):
        expected = [
            "application/grpc-web",
            "application/grpc-web+proto",
        ]
        assert GRPCWebScanner.CONTENT_TYPES[GRPCWebMode.BINARY] == expected

    def test_all_values_are_strings(self):
        for mode, ct_list in GRPCWebScanner.CONTENT_TYPES.items():
            for ct in ct_list:
                assert isinstance(ct, str), f"{ct!r} under {mode.name} is not a string"

    def test_all_values_start_with_application(self):
        for ct_list in GRPCWebScanner.CONTENT_TYPES.values():
            for ct in ct_list:
                assert ct.startswith("application/"), f"{ct!r} missing application/ prefix"


# =============================================================================
# GRPCWebScanner.PROXY_PATTERNS
# =============================================================================

class TestProxyPatterns:
    """GRPCWebScanner.PROXY_PATTERNS — proxy detection mapping."""

    def test_is_dict(self):
        assert isinstance(GRPCWebScanner.PROXY_PATTERNS, dict)

    def test_key_count(self):
        assert len(GRPCWebScanner.PROXY_PATTERNS) == 4

    def test_keys(self):
        expected_keys = {"envoy", "grpc-gateway", "improbable", "connect"}
        assert set(GRPCWebScanner.PROXY_PATTERNS.keys()) == expected_keys

    def test_envoy_patterns(self):
        patterns = GRPCWebScanner.PROXY_PATTERNS["envoy"]
        assert isinstance(patterns, list)
        assert len(patterns) == 3
        assert "envoy" in patterns
        assert "x-envoy-" in patterns
        assert "server: envoy" in patterns

    def test_grpc_gateway_patterns(self):
        patterns = GRPCWebScanner.PROXY_PATTERNS["grpc-gateway"]
        assert isinstance(patterns, list)
        assert len(patterns) == 2
        assert "grpc-gateway" in patterns
        assert "x-grpc-web" in patterns

    def test_improbable_patterns(self):
        patterns = GRPCWebScanner.PROXY_PATTERNS["improbable"]
        assert isinstance(patterns, list)
        assert len(patterns) == 2
        assert "improbable-eng" in patterns
        assert "@improbable-eng" in patterns

    def test_connect_patterns(self):
        patterns = GRPCWebScanner.PROXY_PATTERNS["connect"]
        assert isinstance(patterns, list)
        assert len(patterns) == 2
        assert "connect-protocol" in patterns
        assert "connect-rpc" in patterns

    def test_all_pattern_values_are_strings(self):
        for proxy_name, patterns in GRPCWebScanner.PROXY_PATTERNS.items():
            for p in patterns:
                assert isinstance(p, str), (
                    f"Pattern {p!r} under {proxy_name!r} is not a string"
                )

    def test_no_empty_patterns(self):
        for proxy_name, patterns in GRPCWebScanner.PROXY_PATTERNS.items():
            for p in patterns:
                assert p.strip() != "", (
                    f"Empty pattern under {proxy_name!r}"
                )
