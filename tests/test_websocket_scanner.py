"""
Tests for scanning/modules/websocket_scanner.py

Covers:
- WSOpcode enum (6 opcodes)
- WSFrame dataclass defaults and to_bytes() encoding
- WSConnectionResult dataclass defaults
- WSInjectionResult dataclass fields
- WS_INJECTION_PAYLOADS constant (7 categories)
- WS_PROTOCOL_ATTACKS constant (4 categories)
- SOCKETIO_PAYLOADS constant (6 payloads)
- WebSocketScanner class attributes (name, version, endpoints, subprotocols, payloads)
"""

import os
import struct

import pytest

from scanning.modules.websocket_scanner import (
    WSOpcode,
    WSFrame,
    WSConnectionResult,
    WSInjectionResult,
    WS_INJECTION_PAYLOADS,
    WS_PROTOCOL_ATTACKS,
    SOCKETIO_PAYLOADS,
    WebSocketScanner,
)


# =============================================================================
# ENUM TESTS
# =============================================================================

class TestWSOpcode:
    """Test WSOpcode enum."""

    def test_count(self):
        assert len(WSOpcode) == 6

    def test_continuation(self):
        assert WSOpcode.CONTINUATION.value == 0x0

    def test_text(self):
        assert WSOpcode.TEXT.value == 0x1

    def test_binary(self):
        assert WSOpcode.BINARY.value == 0x2

    def test_close(self):
        assert WSOpcode.CLOSE.value == 0x8

    def test_ping(self):
        assert WSOpcode.PING.value == 0x9

    def test_pong(self):
        assert WSOpcode.PONG.value == 0xA

    def test_all_members(self):
        expected = {"CONTINUATION", "TEXT", "BINARY", "CLOSE", "PING", "PONG"}
        assert {m.name for m in WSOpcode} == expected


# =============================================================================
# DATACLASS TESTS: WSFrame
# =============================================================================

class TestWSFrameDefaults:
    """Test WSFrame dataclass default values."""

    def test_fin_default(self):
        frame = WSFrame()
        assert frame.fin is True

    def test_opcode_default(self):
        frame = WSFrame()
        assert frame.opcode == WSOpcode.TEXT

    def test_mask_default(self):
        frame = WSFrame()
        assert frame.mask is True

    def test_payload_default(self):
        frame = WSFrame()
        assert frame.payload == b""

    def test_masking_key_default_length(self):
        frame = WSFrame()
        assert len(frame.masking_key) == 4

    def test_masking_key_is_random(self):
        """Each frame gets a unique masking key."""
        frame_a = WSFrame()
        frame_b = WSFrame()
        # Statistically this will not collide on 4 random bytes.
        # We accept the negligible chance because the factory calls os.urandom.
        assert isinstance(frame_a.masking_key, bytes)
        assert isinstance(frame_b.masking_key, bytes)


class TestWSFrameToBytes:
    """Test WSFrame.to_bytes() encoding for various payload sizes."""

    # -- Small payload (< 126 bytes) -----------------------------------------

    def test_small_payload_first_byte_fin_set(self):
        """FIN bit (0x80) should be set when fin=True."""
        frame = WSFrame(payload=b"hello", masking_key=b"\x00\x00\x00\x00")
        raw = frame.to_bytes()
        assert raw[0] & 0x80 == 0x80

    def test_small_payload_first_byte_opcode(self):
        """Lower nibble of first byte should be the opcode value."""
        frame = WSFrame(payload=b"hello", masking_key=b"\x00\x00\x00\x00")
        raw = frame.to_bytes()
        assert raw[0] & 0x0F == WSOpcode.TEXT.value

    def test_small_payload_second_byte_mask_bit(self):
        """MASK bit (0x80) should be set when mask=True."""
        frame = WSFrame(payload=b"hello", masking_key=b"\x00\x00\x00\x00")
        raw = frame.to_bytes()
        assert raw[1] & 0x80 == 0x80

    def test_small_payload_second_byte_length(self):
        """Payload length should be encoded in the lower 7 bits."""
        payload = b"hello"
        frame = WSFrame(payload=payload, masking_key=b"\x00\x00\x00\x00")
        raw = frame.to_bytes()
        assert raw[1] & 0x7F == len(payload)

    def test_small_payload_masking_key_present(self):
        """Masking key bytes follow the second byte."""
        key = b"\xAA\xBB\xCC\xDD"
        frame = WSFrame(payload=b"hi", masking_key=key)
        raw = frame.to_bytes()
        assert raw[2:6] == key

    def test_small_payload_masked_correctly(self):
        """Payload bytes must be XORed with masking key."""
        payload = b"test"
        key = b"\x01\x02\x03\x04"
        frame = WSFrame(payload=payload, masking_key=key)
        raw = frame.to_bytes()
        masked_payload = raw[6:]  # 1 (first byte) + 1 (second byte) + 4 (key)
        expected = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
        assert masked_payload == expected

    def test_small_payload_total_length(self):
        """Total = 2 header bytes + 4 masking key + payload length."""
        payload = b"hello"
        frame = WSFrame(payload=payload, masking_key=b"\x00\x00\x00\x00")
        raw = frame.to_bytes()
        assert len(raw) == 2 + 4 + len(payload)

    def test_small_payload_no_mask(self):
        """Without mask, no masking key or XOR applied."""
        payload = b"hello"
        frame = WSFrame(mask=False, payload=payload)
        raw = frame.to_bytes()
        assert raw[1] & 0x80 == 0x00  # MASK bit not set
        assert raw[1] & 0x7F == len(payload)
        assert raw[2:] == payload  # Raw payload, no key prefix
        assert len(raw) == 2 + len(payload)

    def test_small_payload_fin_false(self):
        """FIN=False should clear the FIN bit."""
        frame = WSFrame(fin=False, payload=b"x", masking_key=b"\x00\x00\x00\x00")
        raw = frame.to_bytes()
        assert raw[0] & 0x80 == 0x00

    def test_small_payload_binary_opcode(self):
        """BINARY opcode should appear in first byte."""
        frame = WSFrame(
            opcode=WSOpcode.BINARY,
            payload=b"\x00\x01",
            masking_key=b"\x00\x00\x00\x00",
        )
        raw = frame.to_bytes()
        assert raw[0] & 0x0F == WSOpcode.BINARY.value

    def test_small_payload_ping_opcode(self):
        frame = WSFrame(
            opcode=WSOpcode.PING,
            payload=b"ping",
            masking_key=b"\x00\x00\x00\x00",
        )
        raw = frame.to_bytes()
        assert raw[0] & 0x0F == WSOpcode.PING.value

    def test_small_payload_close_opcode(self):
        frame = WSFrame(
            opcode=WSOpcode.CLOSE,
            payload=b"",
            masking_key=b"\x00\x00\x00\x00",
        )
        raw = frame.to_bytes()
        assert raw[0] & 0x0F == WSOpcode.CLOSE.value

    def test_empty_payload(self):
        """Empty payload should produce minimal frame."""
        frame = WSFrame(payload=b"", masking_key=b"\x00\x00\x00\x00")
        raw = frame.to_bytes()
        assert raw[1] & 0x7F == 0
        assert len(raw) == 2 + 4  # header + masking key, no payload

    def test_empty_payload_no_mask(self):
        frame = WSFrame(mask=False, payload=b"")
        raw = frame.to_bytes()
        assert len(raw) == 2  # header only

    # -- Medium payload (126..65535 bytes, 16-bit extended length) -----------

    def test_medium_payload_extended_length_marker(self):
        """Payloads 126-65535 should use the 126 marker + 2-byte extended length."""
        payload = b"A" * 200
        frame = WSFrame(payload=payload, masking_key=b"\x00\x00\x00\x00")
        raw = frame.to_bytes()
        assert raw[1] & 0x7F == 126

    def test_medium_payload_extended_length_value(self):
        payload = b"A" * 200
        frame = WSFrame(payload=payload, masking_key=b"\x00\x00\x00\x00")
        raw = frame.to_bytes()
        extended_len = struct.unpack(">H", raw[2:4])[0]
        assert extended_len == 200

    def test_medium_payload_total_length(self):
        """Total = 2 header + 2 extended length + 4 masking key + payload."""
        payload = b"B" * 300
        frame = WSFrame(payload=payload, masking_key=b"\x00\x00\x00\x00")
        raw = frame.to_bytes()
        assert len(raw) == 2 + 2 + 4 + 300

    def test_medium_payload_masked_correctly(self):
        payload = b"C" * 130
        key = b"\x11\x22\x33\x44"
        frame = WSFrame(payload=payload, masking_key=key)
        raw = frame.to_bytes()
        # Offset: 2 header + 2 extended + 4 key = 8
        masked_payload = raw[8:]
        expected = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
        assert masked_payload == expected

    def test_medium_payload_no_mask(self):
        payload = b"D" * 500
        frame = WSFrame(mask=False, payload=payload)
        raw = frame.to_bytes()
        assert raw[1] & 0x80 == 0x00
        assert raw[1] & 0x7F == 126
        extended_len = struct.unpack(">H", raw[2:4])[0]
        assert extended_len == 500
        assert raw[4:] == payload
        assert len(raw) == 2 + 2 + 500

    def test_medium_payload_boundary_126(self):
        """Exactly 126 bytes triggers extended 16-bit length."""
        payload = b"E" * 126
        frame = WSFrame(payload=payload, masking_key=b"\x00\x00\x00\x00")
        raw = frame.to_bytes()
        assert raw[1] & 0x7F == 126
        extended_len = struct.unpack(">H", raw[2:4])[0]
        assert extended_len == 126

    def test_small_payload_boundary_125(self):
        """Exactly 125 bytes stays in the single-byte length range."""
        payload = b"F" * 125
        frame = WSFrame(payload=payload, masking_key=b"\x00\x00\x00\x00")
        raw = frame.to_bytes()
        assert raw[1] & 0x7F == 125

    def test_medium_payload_boundary_65535(self):
        """Exactly 65535 bytes should still use 16-bit extended length."""
        payload = b"G" * 65535
        frame = WSFrame(payload=payload, masking_key=b"\x00\x00\x00\x00")
        raw = frame.to_bytes()
        assert raw[1] & 0x7F == 126
        extended_len = struct.unpack(">H", raw[2:4])[0]
        assert extended_len == 65535

    # -- Large payload (>= 65536 bytes, 64-bit extended length) --------------

    def test_large_payload_extended_length_marker(self):
        """Payloads >= 65536 should use the 127 marker + 8-byte extended length."""
        payload = b"H" * 65536
        frame = WSFrame(payload=payload, masking_key=b"\x00\x00\x00\x00")
        raw = frame.to_bytes()
        assert raw[1] & 0x7F == 127

    def test_large_payload_extended_length_value(self):
        payload = b"I" * 65536
        frame = WSFrame(payload=payload, masking_key=b"\x00\x00\x00\x00")
        raw = frame.to_bytes()
        extended_len = struct.unpack(">Q", raw[2:10])[0]
        assert extended_len == 65536

    def test_large_payload_total_length(self):
        """Total = 2 header + 8 extended length + 4 masking key + payload."""
        size = 65536
        payload = b"J" * size
        frame = WSFrame(payload=payload, masking_key=b"\x00\x00\x00\x00")
        raw = frame.to_bytes()
        assert len(raw) == 2 + 8 + 4 + size

    def test_large_payload_masked_correctly(self):
        payload = b"K" * 65540
        key = b"\xDE\xAD\xBE\xEF"
        frame = WSFrame(payload=payload, masking_key=key)
        raw = frame.to_bytes()
        # Offset: 2 header + 8 extended + 4 key = 14
        masked_payload = raw[14:]
        expected = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
        assert masked_payload == expected

    def test_large_payload_no_mask(self):
        size = 70000
        payload = b"L" * size
        frame = WSFrame(mask=False, payload=payload)
        raw = frame.to_bytes()
        assert raw[1] & 0x80 == 0x00
        assert raw[1] & 0x7F == 127
        extended_len = struct.unpack(">Q", raw[2:10])[0]
        assert extended_len == size
        assert raw[10:] == payload
        assert len(raw) == 2 + 8 + size


# =============================================================================
# DATACLASS TESTS: WSConnectionResult
# =============================================================================

class TestWSConnectionResult:
    """Test WSConnectionResult dataclass defaults."""

    def test_connected_default(self):
        result = WSConnectionResult()
        assert result.connected is False

    def test_handshake_response_default(self):
        result = WSConnectionResult()
        assert result.handshake_response is None

    def test_accepted_origin_default(self):
        result = WSConnectionResult()
        assert result.accepted_origin is None

    def test_accepted_protocol_default(self):
        result = WSConnectionResult()
        assert result.accepted_protocol is None

    def test_server_extensions_default(self):
        result = WSConnectionResult()
        assert result.server_extensions == []

    def test_error_default(self):
        result = WSConnectionResult()
        assert result.error is None

    def test_timing_ms_default(self):
        result = WSConnectionResult()
        assert result.timing_ms == 0.0

    def test_server_extensions_isolation(self):
        """Each instance should have its own list (no shared mutable default)."""
        a = WSConnectionResult()
        b = WSConnectionResult()
        a.server_extensions.append("ext1")
        assert b.server_extensions == []


# =============================================================================
# DATACLASS TESTS: WSInjectionResult
# =============================================================================

class TestWSInjectionResult:
    """Test WSInjectionResult dataclass fields."""

    def test_creation_with_all_fields(self):
        result = WSInjectionResult(
            payload="<script>alert(1)</script>",
            response_received=True,
            response_contains_payload=True,
            response_reflected=True,
            response_time_ms=12.5,
            error_triggered=False,
        )
        assert result.payload == "<script>alert(1)</script>"
        assert result.response_received is True
        assert result.response_contains_payload is True
        assert result.response_reflected is True
        assert result.response_time_ms == 12.5
        assert result.error_triggered is False

    def test_creation_negative_case(self):
        result = WSInjectionResult(
            payload="' OR '1'='1",
            response_received=False,
            response_contains_payload=False,
            response_reflected=False,
            response_time_ms=0.0,
            error_triggered=True,
        )
        assert result.response_received is False
        assert result.error_triggered is True

    def test_requires_all_fields(self):
        """WSInjectionResult has no defaults, so all fields are required."""
        with pytest.raises(TypeError):
            WSInjectionResult()  # type: ignore[call-arg]


# =============================================================================
# CONSTANTS TESTS: WS_INJECTION_PAYLOADS
# =============================================================================

class TestWSInjectionPayloads:
    """Test WS_INJECTION_PAYLOADS constant."""

    def test_is_dict(self):
        assert isinstance(WS_INJECTION_PAYLOADS, dict)

    def test_has_seven_categories(self):
        assert len(WS_INJECTION_PAYLOADS) == 7

    def test_category_keys(self):
        expected_keys = {
            "xss", "sqli", "nosql", "command",
            "prototype_pollution", "path_traversal", "ssti",
        }
        assert set(WS_INJECTION_PAYLOADS.keys()) == expected_keys

    def test_xss_count(self):
        assert len(WS_INJECTION_PAYLOADS["xss"]) == 7

    def test_sqli_count(self):
        assert len(WS_INJECTION_PAYLOADS["sqli"]) == 7

    def test_nosql_count(self):
        assert len(WS_INJECTION_PAYLOADS["nosql"]) == 4

    def test_command_count(self):
        assert len(WS_INJECTION_PAYLOADS["command"]) == 7

    def test_prototype_pollution_count(self):
        assert len(WS_INJECTION_PAYLOADS["prototype_pollution"]) == 3

    def test_path_traversal_count(self):
        assert len(WS_INJECTION_PAYLOADS["path_traversal"]) == 3

    def test_ssti_count(self):
        assert len(WS_INJECTION_PAYLOADS["ssti"]) == 6

    def test_all_payloads_are_strings(self):
        for category, payloads in WS_INJECTION_PAYLOADS.items():
            for payload in payloads:
                assert isinstance(payload, str), (
                    f"Payload in '{category}' is not a string: {payload!r}"
                )

    def test_xss_contains_script_tag(self):
        assert any("<script>" in p for p in WS_INJECTION_PAYLOADS["xss"])

    def test_sqli_contains_union(self):
        assert any("UNION" in p for p in WS_INJECTION_PAYLOADS["sqli"])

    def test_ssti_contains_template_expression(self):
        assert any("{{" in p for p in WS_INJECTION_PAYLOADS["ssti"])

    def test_command_contains_id(self):
        assert any("id" in p for p in WS_INJECTION_PAYLOADS["command"])


# =============================================================================
# CONSTANTS TESTS: WS_PROTOCOL_ATTACKS
# =============================================================================

class TestWSProtocolAttacks:
    """Test WS_PROTOCOL_ATTACKS constant."""

    def test_is_dict(self):
        assert isinstance(WS_PROTOCOL_ATTACKS, dict)

    def test_has_four_categories(self):
        assert len(WS_PROTOCOL_ATTACKS) == 4

    def test_category_keys(self):
        expected_keys = {
            "fragmentation", "control_frame_flood",
            "large_frame", "invalid_utf8",
        }
        assert set(WS_PROTOCOL_ATTACKS.keys()) == expected_keys

    def test_fragmentation_has_entries(self):
        assert len(WS_PROTOCOL_ATTACKS["fragmentation"]) >= 1

    def test_fragmentation_entry_has_fragments(self):
        entry = WS_PROTOCOL_ATTACKS["fragmentation"][0]
        assert "fragments" in entry

    def test_control_frame_flood_has_entries(self):
        assert len(WS_PROTOCOL_ATTACKS["control_frame_flood"]) >= 1

    def test_control_frame_flood_entry_has_type(self):
        entry = WS_PROTOCOL_ATTACKS["control_frame_flood"][0]
        assert entry["type"] == "ping"
        assert entry["count"] == 100

    def test_large_frame_has_entries(self):
        assert len(WS_PROTOCOL_ATTACKS["large_frame"]) == 2

    def test_large_frame_sizes(self):
        sizes = [e["size"] for e in WS_PROTOCOL_ATTACKS["large_frame"]]
        assert 1024 * 1024 in sizes  # 1MB
        assert 16 * 1024 * 1024 in sizes  # 16MB

    def test_invalid_utf8_has_entries(self):
        assert len(WS_PROTOCOL_ATTACKS["invalid_utf8"]) == 3

    def test_invalid_utf8_entries_are_bytes(self):
        for entry in WS_PROTOCOL_ATTACKS["invalid_utf8"]:
            assert isinstance(entry, bytes)


# =============================================================================
# CONSTANTS TESTS: SOCKETIO_PAYLOADS
# =============================================================================

class TestSocketIOPayloads:
    """Test SOCKETIO_PAYLOADS constant."""

    def test_is_list(self):
        assert isinstance(SOCKETIO_PAYLOADS, list)

    def test_count(self):
        assert len(SOCKETIO_PAYLOADS) == 6

    def test_all_strings(self):
        for payload in SOCKETIO_PAYLOADS:
            assert isinstance(payload, str)

    def test_contains_connect_packet(self):
        assert "0" in SOCKETIO_PAYLOADS

    def test_contains_namespace_connect(self):
        assert "40" in SOCKETIO_PAYLOADS

    def test_contains_binary_event(self):
        assert "5" in SOCKETIO_PAYLOADS

    def test_contains_xss_payload(self):
        assert any("<script>" in p for p in SOCKETIO_PAYLOADS)

    def test_contains_proto_pollution(self):
        assert any("__proto__" in p for p in SOCKETIO_PAYLOADS)


# =============================================================================
# CLASS ATTRIBUTE TESTS: WebSocketScanner
# =============================================================================

class TestWebSocketScannerAttributes:
    """Test WebSocketScanner class-level attributes."""

    def test_name(self):
        assert WebSocketScanner.name == "websocket_scanner"

    def test_version(self):
        assert WebSocketScanner.version == "2.0-enterprise"

    def test_ws_endpoints_is_list(self):
        assert isinstance(WebSocketScanner.WS_ENDPOINTS, list)

    def test_ws_endpoints_count(self):
        assert len(WebSocketScanner.WS_ENDPOINTS) == 33

    def test_ws_endpoints_start_with_slash(self):
        for ep in WebSocketScanner.WS_ENDPOINTS:
            assert ep.startswith("/"), f"Endpoint does not start with '/': {ep!r}"

    def test_ws_endpoints_contains_common_paths(self):
        eps = WebSocketScanner.WS_ENDPOINTS
        assert "/ws" in eps
        assert "/websocket" in eps
        assert "/socket.io/" in eps
        assert "/chat" in eps
        assert "/graphql" in eps

    def test_ws_endpoints_contains_enterprise_paths(self):
        eps = WebSocketScanner.WS_ENDPOINTS
        assert "/signalr" in eps
        assert "/_blazor" in eps
        assert "/cable" in eps
        assert "/phoenix/websocket" in eps
        assert "/ws/mqtt" in eps
        assert "/stomp" in eps

    def test_subprotocols_is_list(self):
        assert isinstance(WebSocketScanner.SUBPROTOCOLS, list)

    def test_subprotocols_count(self):
        assert len(WebSocketScanner.SUBPROTOCOLS) == 7

    def test_subprotocols_contains_graphql_ws(self):
        assert "graphql-ws" in WebSocketScanner.SUBPROTOCOLS

    def test_subprotocols_contains_mqtt(self):
        assert "mqtt" in WebSocketScanner.SUBPROTOCOLS

    def test_subprotocols_contains_stomp(self):
        assert "stomp" in WebSocketScanner.SUBPROTOCOLS

    def test_injection_payloads_is_list(self):
        assert isinstance(WebSocketScanner.INJECTION_PAYLOADS, list)

    def test_injection_payloads_count(self):
        assert len(WebSocketScanner.INJECTION_PAYLOADS) == 12

    def test_injection_payloads_all_strings(self):
        for p in WebSocketScanner.INJECTION_PAYLOADS:
            assert isinstance(p, str)

    def test_is_scan_module_subclass(self):
        from scanning.vuln_scanner import ScanModule
        assert issubclass(WebSocketScanner, ScanModule)
