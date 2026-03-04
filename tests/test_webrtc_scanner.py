"""Tests for scanning.modules.webrtc_scanner — static structure tests."""

import re

import pytest

from scanning.modules.webrtc_scanner import (
    ICE_INTERNAL_IP_PATTERNS,
    SDP_SECURITY_PATTERNS,
    SIGNALING_PATTERNS,
    TURN_PATTERNS,
    WEBRTC_SCANNER_VERSION,
    WebRTCEndpoint,
    WebRTCScanner,
    WebRTCTestResult,
    WebRTCVulnType,
)
from scanning.vuln_scanner import ScanModule


# =============================================================================
# ENUM: WebRTCVulnType
# =============================================================================

class TestWebRTCVulnType:
    """Test WebRTCVulnType enum."""

    def test_member_count(self):
        assert len(WebRTCVulnType) == 8

    def test_ice_candidate_leak(self):
        assert WebRTCVulnType.ICE_CANDIDATE_LEAK is not None

    def test_turn_misconfiguration(self):
        assert WebRTCVulnType.TURN_MISCONFIGURATION is not None

    def test_signaling_injection(self):
        assert WebRTCVulnType.SIGNALING_INJECTION is not None

    def test_dtls_weakness(self):
        assert WebRTCVulnType.DTLS_WEAKNESS is not None

    def test_srtp_weakness(self):
        assert WebRTCVulnType.SRTP_WEAKNESS is not None

    def test_credential_exposure(self):
        assert WebRTCVulnType.CREDENTIAL_EXPOSURE is not None

    def test_cross_origin_signaling(self):
        assert WebRTCVulnType.CROSS_ORIGIN_SIGNALING is not None

    def test_overbroad_permissions(self):
        assert WebRTCVulnType.OVERBROAD_PERMISSIONS is not None

    def test_unique_values(self):
        values = [m.value for m in WebRTCVulnType]
        assert len(values) == len(set(values))


# =============================================================================
# DATACLASS: WebRTCEndpoint
# =============================================================================

class TestWebRTCEndpoint:
    """Test WebRTCEndpoint dataclass."""

    def test_creation(self):
        ep = WebRTCEndpoint(
            url="wss://example.com/ws",
            endpoint_type="signaling",
            protocol="wss",
        )
        assert ep.url == "wss://example.com/ws"
        assert ep.endpoint_type == "signaling"
        assert ep.protocol == "wss"

    def test_defaults(self):
        ep = WebRTCEndpoint(url="/ws", endpoint_type="api", protocol="https")
        assert ep.detected_features == []


# =============================================================================
# DATACLASS: WebRTCTestResult
# =============================================================================

class TestWebRTCTestResult:
    """Test WebRTCTestResult dataclass."""

    def test_creation(self):
        r = WebRTCTestResult(
            vulnerable=True,
            vuln_type=WebRTCVulnType.ICE_CANDIDATE_LEAK,
            confidence=85,
        )
        assert r.vulnerable is True

    def test_defaults(self):
        r = WebRTCTestResult(
            vulnerable=False,
            vuln_type=WebRTCVulnType.DTLS_WEAKNESS,
            confidence=50,
        )
        assert r.evidence == []
        assert r.severity == "MEDIUM"
        assert r.cwe == "CWE-200"
        assert r.leaked_data == {}


# =============================================================================
# CONSTANT: SIGNALING_PATTERNS
# =============================================================================

class TestSignalingPatterns:
    """Test SIGNALING_PATTERNS list."""

    def test_is_list(self):
        assert isinstance(SIGNALING_PATTERNS, list)

    def test_count(self):
        assert len(SIGNALING_PATTERNS) == 11

    def test_all_compile(self):
        for p in SIGNALING_PATTERNS:
            compiled = re.compile(p)
            assert compiled is not None

    def test_contains_ws_pattern(self):
        assert any("ws" in p for p in SIGNALING_PATTERNS)

    def test_contains_signaling_pattern(self):
        assert any("signaling" in p for p in SIGNALING_PATTERNS)

    def test_contains_webrtc_pattern(self):
        assert any("webrtc" in p for p in SIGNALING_PATTERNS)

    def test_contains_socket_io(self):
        assert any("socket" in p for p in SIGNALING_PATTERNS)

    @pytest.mark.parametrize("url", [
        "/ws", "/ws/", "/websocket", "/signaling/", "/rtc/", "/webrtc/",
    ])
    def test_matches_expected_urls(self, url):
        matched = any(re.search(p, url) for p in SIGNALING_PATTERNS)
        assert matched, f"No pattern matched {url}"


# =============================================================================
# CONSTANT: TURN_PATTERNS
# =============================================================================

class TestTurnPatterns:
    """Test TURN_PATTERNS list."""

    def test_is_list(self):
        assert isinstance(TURN_PATTERNS, list)

    def test_count(self):
        assert len(TURN_PATTERNS) == 4

    def test_all_compile(self):
        for p in TURN_PATTERNS:
            compiled = re.compile(p)
            assert compiled is not None

    def test_matches_turn_url(self):
        assert any(re.search(p, "turn:example.com:3478") for p in TURN_PATTERNS)

    def test_matches_stun_url(self):
        assert any(re.search(p, "stun:stun.example.com:3478") for p in TURN_PATTERNS)


# =============================================================================
# CONSTANT: ICE_INTERNAL_IP_PATTERNS
# =============================================================================

class TestIceInternalIpPatterns:
    """Test ICE_INTERNAL_IP_PATTERNS list."""

    def test_is_list(self):
        assert isinstance(ICE_INTERNAL_IP_PATTERNS, list)

    def test_count(self):
        assert len(ICE_INTERNAL_IP_PATTERNS) == 5

    def test_all_compile(self):
        for p in ICE_INTERNAL_IP_PATTERNS:
            compiled = re.compile(p)
            assert compiled is not None

    def test_matches_10_network(self):
        candidate = "candidate:1 1 udp 2122260223 10.0.0.5 54321 typ host"
        assert any(re.search(p, candidate) for p in ICE_INTERNAL_IP_PATTERNS)

    def test_matches_192_168_network(self):
        candidate = "candidate:1 1 udp 2122260223 192.168.1.100 54321 typ host"
        assert any(re.search(p, candidate) for p in ICE_INTERNAL_IP_PATTERNS)


# =============================================================================
# CONSTANT: SDP_SECURITY_PATTERNS
# =============================================================================

class TestSdpSecurityPatterns:
    """Test SDP_SECURITY_PATTERNS dict."""

    def test_is_dict(self):
        assert isinstance(SDP_SECURITY_PATTERNS, dict)

    def test_key_count(self):
        assert len(SDP_SECURITY_PATTERNS) == 4

    def test_has_no_srtp(self):
        assert "no_srtp" in SDP_SECURITY_PATTERNS

    def test_has_weak_crypto(self):
        assert "weak_crypto" in SDP_SECURITY_PATTERNS

    def test_has_no_dtls(self):
        assert "no_dtls" in SDP_SECURITY_PATTERNS

    def test_has_fingerprint(self):
        assert "fingerprint" in SDP_SECURITY_PATTERNS

    def test_patterns_compile(self):
        for key, pattern in SDP_SECURITY_PATTERNS.items():
            compiled = re.compile(pattern)
            assert compiled is not None, f"Pattern for '{key}' failed"

    def test_no_srtp_matches_plain_rtp(self):
        sdp_line = "m=audio 9 RTP/AVP 0 8"
        assert re.search(SDP_SECURITY_PATTERNS["no_srtp"], sdp_line)


# =============================================================================
# SCANNER IDENTITY
# =============================================================================

class TestScannerIdentity:
    """Test WebRTCScanner scanner identity."""

    def test_is_scan_module_subclass(self):
        assert issubclass(WebRTCScanner, ScanModule)

    def test_name_attribute(self):
        assert WebRTCScanner.name == "webrtc_scanner"

    def test_version(self):
        assert WebRTCScanner.version == WEBRTC_SCANNER_VERSION

    def test_category(self):
        assert WebRTCScanner.category == "webrtc"

    def test_instantiation(self):
        scanner = WebRTCScanner(
            settings={"target_url": "http://test.local", "safety_level": "safe"}
        )
        assert scanner is not None
