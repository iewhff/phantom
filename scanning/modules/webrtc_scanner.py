"""
WebRTC Security Scanner v1.0

Tests WebRTC implementations for security vulnerabilities:
- ICE candidate leakage (internal IP disclosure)
- TURN server misconfiguration
- Signaling server vulnerabilities
- DTLS/SRTP weaknesses
- Cross-origin signaling issues
- Credential exposure
- Overbroad ICE permissions

LOW Priority - 3 days effort

CWE Coverage:
- CWE-200: Exposure of Sensitive Information
- CWE-319: Cleartext Transmission of Sensitive Information
- CWE-346: Origin Validation Error
- CWE-522: Insufficiently Protected Credentials
- CWE-295: Improper Certificate Validation

Bug Bounty Value: $500 - $3,000 for WebRTC vulnerabilities
Reference: WebRTC is often overlooked, internal IP leaks are common
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse

import httpx

from scanning.findings import Finding, Severity
from scanning.vuln_scanner import ScanModule
from utils.logger import get_logger
from utils.http_client import create_protected_client, get_configured_ssl_verify
from scanning.scan_context import ScanContext

if TYPE_CHECKING:
    from utils.rate_limiter import RateLimiter

logger = get_logger(__name__)

WEBRTC_SCANNER_VERSION = "1.0.0"


class WebRTCVulnType(Enum):
    """Types of WebRTC vulnerabilities."""
    ICE_CANDIDATE_LEAK = auto()      # Internal IP disclosure
    TURN_MISCONFIGURATION = auto()   # TURN server issues
    SIGNALING_INJECTION = auto()     # Signaling message manipulation
    DTLS_WEAKNESS = auto()           # DTLS certificate issues
    SRTP_WEAKNESS = auto()           # Media encryption issues
    CREDENTIAL_EXPOSURE = auto()     # TURN/STUN credentials leaked
    CROSS_ORIGIN_SIGNALING = auto()  # CORS on signaling server
    OVERBROAD_PERMISSIONS = auto()   # Excessive media permissions


@dataclass
class WebRTCEndpoint:
    """Detected WebRTC endpoint."""
    url: str
    endpoint_type: str  # "signaling", "turn", "stun", "api"
    protocol: str  # "ws", "wss", "http", "https"
    detected_features: list[str] = field(default_factory=list)


@dataclass
class WebRTCTestResult:
    """Result of a WebRTC security test."""
    vulnerable: bool
    vuln_type: WebRTCVulnType
    confidence: int
    evidence: list[str] = field(default_factory=list)
    severity: str = "MEDIUM"
    cwe: str = "CWE-200"
    leaked_data: dict[str, Any] = field(default_factory=dict)


# WebRTC signaling endpoint patterns
SIGNALING_PATTERNS = [
    r"/ws/?$",
    r"/websocket/?$",
    r"/socket\.io/?",
    r"/signaling/?",
    r"/rtc/?",
    r"/webrtc/?",
    r"/peer/?",
    r"/call/?",
    r"/video/?",
    r"/audio/?",
    r"/stream/?",
]

# TURN/STUN server patterns
TURN_PATTERNS = [
    r"turn:[^:]+:\d+",
    r"turns:[^:]+:\d+",
    r"stun:[^:]+:\d+",
    r"stuns:[^:]+:\d+",
]

# ICE candidate patterns that leak internal IPs
ICE_INTERNAL_IP_PATTERNS = [
    r"candidate:.*\s10\.\d+\.\d+\.\d+\s",      # 10.x.x.x
    r"candidate:.*\s172\.(1[6-9]|2\d|3[01])\.\d+\.\d+\s",  # 172.16-31.x.x
    r"candidate:.*\s192\.168\.\d+\.\d+\s",     # 192.168.x.x
    r"candidate:.*\sfd[0-9a-f]{2}:",           # IPv6 ULA
    r"candidate:.*\sfe80:",                     # IPv6 link-local
]

# SDP patterns for security analysis
SDP_SECURITY_PATTERNS = {
    "no_srtp": r"m=audio.*RTP/AVP",            # Plain RTP (not SRTP)
    "weak_crypto": r"a=crypto:.*AES_CM_128",   # Weak crypto suite
    "no_dtls": r"a=setup:(actpass|active|passive)",  # DTLS setup
    "fingerprint": r"a=fingerprint:(\S+)\s",   # Certificate fingerprint
}


class WebRTCScanner(ScanModule):
    """
    WebRTC Security Scanner.

    Tests for vulnerabilities in WebRTC implementations:
    - Internal IP leakage via ICE candidates
    - TURN/STUN server misconfigurations
    - Signaling server injection
    - DTLS/SRTP weaknesses
    - Credential exposure
    """

    name = "webrtc_scanner"
    version = WEBRTC_SCANNER_VERSION
    category = "webrtc"

    def __init__(
        self,
        settings: Any = None,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.findings: list[dict[str, Any]] = []
        self.webrtc_endpoints: list[WebRTCEndpoint] = []
        self._ssl_verify = get_configured_ssl_verify()

    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any] | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> dict[str, Any]:
        """Execute WebRTC security scan."""
        asset_data = asset_data or {}

        # SCAN CONTEXT
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        self.findings = []
        self.webrtc_endpoints = []

        base_url = f"https://{host}" if not host.startswith("http") else host
        urls = asset_data.get("urls", [])
        js_files = asset_data.get("js_files", [])

        logger.info(f"WebRTC Scanner v{self.version} starting on {host}")

        client = create_protected_client(
            timeout=30.0,
            verify_ssl=self._ssl_verify,
            follow_redirects=True,
            custom_headers=self._auth_headers,
        )

        async with client:
            # Phase 1: Detect WebRTC usage and endpoints
            await self._detect_webrtc_usage(client, base_url, urls, js_files, rate_limiter)

            if not self.webrtc_endpoints:
                logger.info("No WebRTC endpoints detected")
                return {
                    "module": self.name,
                    "version": self.version,
                    "findings": [],
                    "webrtc_detected": False,
                }

            logger.info(f"Found {len(self.webrtc_endpoints)} WebRTC endpoints")

            # Phase 2: Test for ICE candidate leakage
            await self._test_ice_candidate_leak(client, base_url, rate_limiter)

            # Phase 3: Test TURN/STUN configuration
            await self._test_turn_configuration(client, base_url, rate_limiter)

            # Phase 4: Test signaling server security
            await self._test_signaling_security(client, rate_limiter)

            # Phase 5: Test for credential exposure
            await self._test_credential_exposure(client, base_url, rate_limiter)

            # Phase 6: Test SDP handling
            await self._test_sdp_security(client, rate_limiter)

            # Phase 7: Test cross-origin signaling
            await self._test_cross_origin_signaling(client, rate_limiter)

        logger.info(f"WebRTC scan complete. Found {len(self.findings)} vulnerabilities")

        return {
            "module": self.name,
            "version": self.version,
            "findings": self.findings,
            "webrtc_detected": True,
            "endpoints": [
                {
                    "url": ep.url,
                    "type": ep.endpoint_type,
                    "protocol": ep.protocol,
                    "features": ep.detected_features,
                }
                for ep in self.webrtc_endpoints
            ],
        }

    async def _detect_webrtc_usage(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        js_files: list[str],
        rate_limiter: RateLimiter | None,
    ) -> None:
        """Detect WebRTC usage in the application."""
        logger.debug("Phase 1: Detecting WebRTC usage")

        # WebRTC indicators in JavaScript
        webrtc_js_patterns = [
            r"RTCPeerConnection",
            r"RTCSessionDescription",
            r"RTCIceCandidate",
            r"getUserMedia",
            r"getDisplayMedia",
            r"createOffer",
            r"createAnswer",
            r"setLocalDescription",
            r"setRemoteDescription",
            r"addIceCandidate",
            r"iceServers",
            r"peerConnection",
            r"webrtc",
            r"socket\.io",
            r"signaling",
        ]

        # Check main page
        if rate_limiter:
            await rate_limiter.acquire()

        try:
            response = await client.get(base_url)
            body = response.text

            # Check for WebRTC patterns
            webrtc_detected = False
            for pattern in webrtc_js_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    webrtc_detected = True
                    break

            if webrtc_detected:
                self.webrtc_endpoints.append(WebRTCEndpoint(
                    url=base_url,
                    endpoint_type="page",
                    protocol=urlparse(base_url).scheme,
                    detected_features=["webrtc_usage"],
                ))

        except Exception as e:
            logger.debug(f"Main page check error: {e}")

        # Check JavaScript files
        for js_url in js_files[:10]:
            if rate_limiter:
                await rate_limiter.acquire()

            try:
                full_url = urljoin(base_url, js_url)
                response = await client.get(full_url)
                js_content = response.text

                features = []
                for pattern in webrtc_js_patterns:
                    if re.search(pattern, js_content, re.IGNORECASE):
                        features.append(pattern.replace("\\", ""))

                if features:
                    # Look for signaling endpoints
                    for sig_pattern in SIGNALING_PATTERNS:
                        matches = re.findall(sig_pattern, js_content, re.IGNORECASE)
                        for match in matches:
                            self.webrtc_endpoints.append(WebRTCEndpoint(
                                url=urljoin(base_url, match),
                                endpoint_type="signaling",
                                protocol="wss" if "wss" in match else "ws",
                            ))

                    # Look for TURN/STUN servers
                    for turn_pattern in TURN_PATTERNS:
                        matches = re.findall(turn_pattern, js_content, re.IGNORECASE)
                        for match in matches:
                            server_type = "turn" if "turn" in match.lower() else "stun"
                            self.webrtc_endpoints.append(WebRTCEndpoint(
                                url=match,
                                endpoint_type=server_type,
                                protocol="turns" if "turns:" in match else server_type,
                            ))

                    # Look for ICE server configuration
                    ice_config = re.search(
                        r'iceServers\s*:\s*\[([^\]]+)\]',
                        js_content,
                        re.IGNORECASE | re.DOTALL
                    )
                    if ice_config:
                        self.webrtc_endpoints.append(WebRTCEndpoint(
                            url=full_url,
                            endpoint_type="ice_config",
                            protocol="https",
                            detected_features=["ice_servers_config"],
                        ))

            except Exception as e:
                logger.debug(f"JS file check error: {e}")

        # Probe common signaling endpoints
        signaling_endpoints = [
            "/ws", "/websocket", "/socket.io", "/signaling",
            "/rtc", "/webrtc", "/peer", "/call",
            "/api/rtc", "/api/signaling", "/api/call",
        ]

        for endpoint in signaling_endpoints:
            if rate_limiter:
                await rate_limiter.acquire()

            url = urljoin(base_url, endpoint)
            try:
                response = await client.get(url)

                # Check for WebSocket upgrade or signaling indicators
                if response.status_code in [200, 101, 400, 426]:
                    upgrade = response.headers.get("upgrade", "").lower()
                    if "websocket" in upgrade or response.status_code == 426:
                        self.webrtc_endpoints.append(WebRTCEndpoint(
                            url=url,
                            endpoint_type="signaling",
                            protocol="wss",
                        ))

            except Exception:
                pass

    async def _test_ice_candidate_leak(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter | None,
    ) -> None:
        """Test for ICE candidate internal IP leakage."""
        logger.debug("Phase 2: Testing ICE candidate leakage")

        # Look for ICE candidates in responses
        for endpoint in self.webrtc_endpoints:
            if endpoint.endpoint_type not in ["signaling", "api", "page"]:
                continue

            if rate_limiter:
                await rate_limiter.acquire()

            try:
                response = await client.get(endpoint.url)
                body = response.text

                # Check for internal IP leakage
                leaked_ips = []
                for pattern in ICE_INTERNAL_IP_PATTERNS:
                    matches = re.findall(pattern, body)
                    if matches:
                        # Extract the IP
                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+|fd[0-9a-f:]+|fe80[0-9a-f:]+)', pattern)
                        if ip_match:
                            leaked_ips.append(ip_match.group())

                if leaked_ips:
                    result = WebRTCTestResult(
                        vulnerable=True,
                        vuln_type=WebRTCVulnType.ICE_CANDIDATE_LEAK,
                        confidence_score=85,
                        evidence=[
                            "Internal IP addresses exposed via ICE candidates",
                            f"Leaked IPs: {leaked_ips[:5]}",
                            "Attackers can enumerate internal network topology",
                        ],
                        severity=Severity.MEDIUM,
                        cwe_id="CWE-200",
                        leaked_data={"internal_ips": leaked_ips},
                    )

                    self._add_finding(
                        name="ICE Candidate Internal IP Leak",
                        description=(
                            "WebRTC ICE candidates expose internal IP addresses. "
                            "This allows attackers to discover internal network topology "
                            "and potentially identify internal services."
                        ),
                        endpoint=endpoint.url,
                        result=result,
                    )

            except Exception as e:
                logger.debug(f"ICE leak test error: {e}")

        # Also check for IP leak APIs
        ip_leak_endpoints = [
            "/api/ice/candidates",
            "/api/rtc/candidates",
            "/api/webrtc/config",
            "/api/stun/config",
        ]

        for ep_path in ip_leak_endpoints:
            if rate_limiter:
                await rate_limiter.acquire()

            url = urljoin(base_url, ep_path)
            try:
                response = await client.get(url)

                if response.status_code == 200:
                    body = response.text

                    # Look for internal IPs
                    internal_ip_pattern = r'(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)'
                    matches = re.findall(internal_ip_pattern, body)

                    if matches:
                        result = WebRTCTestResult(
                            vulnerable=True,
                            vuln_type=WebRTCVulnType.ICE_CANDIDATE_LEAK,
                            confidence_score=90,
                            evidence=[
                                f"Internal IPs exposed at: {url}",
                                f"Found: {list(set(matches))[:5]}",
                            ],
                            severity=Severity.MEDIUM,
                            cwe_id="CWE-200",
                        )

                        self._add_finding(
                            name="WebRTC API Internal IP Exposure",
                            description=f"API endpoint {ep_path} exposes internal IP addresses.",
                            endpoint=url,
                            result=result,
                        )

            except Exception:
                pass

    async def _test_turn_configuration(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter | None,
    ) -> None:
        """Test TURN/STUN server configuration."""
        logger.debug("Phase 3: Testing TURN/STUN configuration")

        turn_endpoints = [ep for ep in self.webrtc_endpoints if ep.endpoint_type in ["turn", "stun"]]

        for endpoint in turn_endpoints:
            # Check for insecure TURN (not TURNS)
            if endpoint.protocol == "turn":
                result = WebRTCTestResult(
                    vulnerable=True,
                    vuln_type=WebRTCVulnType.TURN_MISCONFIGURATION,
                    confidence_score=75,
                    evidence=[
                        f"TURN server using unencrypted connection: {endpoint.url}",
                        "Media relay traffic is not encrypted",
                        "Should use TURNS (TLS) for secure relay",
                    ],
                    severity=Severity.MEDIUM,
                    cwe_id="CWE-319",
                )

                self._add_finding(
                    name="Unencrypted TURN Server",
                    description=(
                        f"TURN server at {endpoint.url} uses unencrypted connection. "
                        "Media relay traffic can be intercepted. Use TURNS with TLS."
                    ),
                    endpoint=endpoint.url,
                    result=result,
                )

        # Check for TURN credential exposure
        turn_config_endpoints = [
            "/api/turn/credentials",
            "/api/rtc/credentials",
            "/api/ice/credentials",
            "/api/webrtc/turn",
            "/turn",
            "/stun",
        ]

        for ep_path in turn_config_endpoints:
            if rate_limiter:
                await rate_limiter.acquire()

            url = urljoin(base_url, ep_path)
            try:
                response = await client.get(url)

                if response.status_code == 200:
                    body = response.text

                    # Look for credentials
                    cred_patterns = [
                        r'"username"\s*:\s*"([^"]+)"',
                        r'"credential"\s*:\s*"([^"]+)"',
                        r'"password"\s*:\s*"([^"]+)"',
                    ]

                    found_creds = {}
                    for pattern in cred_patterns:
                        match = re.search(pattern, body)
                        if match:
                            field = pattern.split('"')[1]
                            found_creds[field] = match.group(1)[:20] + "..."

                    if found_creds:
                        result = WebRTCTestResult(
                            vulnerable=True,
                            vuln_type=WebRTCVulnType.CREDENTIAL_EXPOSURE,
                            confidence_score=90,
                            evidence=[
                                f"TURN credentials exposed at: {url}",
                                f"Found fields: {list(found_creds.keys())}",
                                "Credentials can be used to abuse TURN server",
                            ],
                            severity=Severity.HIGH,
                            cwe_id="CWE-522",
                            leaked_data=found_creds,
                        )

                        self._add_finding(
                            name="TURN Server Credentials Exposed",
                            description=(
                                "TURN server credentials are exposed via API endpoint. "
                                "Attackers can use these credentials to relay traffic "
                                "through the TURN server, potentially for abuse."
                            ),
                            endpoint=url,
                            result=result,
                        )

            except Exception:
                pass

    async def _test_signaling_security(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter | None,
    ) -> None:
        """Test signaling server security."""
        logger.debug("Phase 4: Testing signaling server security")

        signaling_endpoints = [ep for ep in self.webrtc_endpoints if ep.endpoint_type == "signaling"]

        for endpoint in signaling_endpoints:
            if rate_limiter:
                await rate_limiter.acquire()

            # Test for SDP injection
            try:
                # Malicious SDP that could cause issues
                malicious_sdp = {
                    "type": "offer",
                    "sdp": (
                        "v=0\r\n"
                        "o=- 0 0 IN IP4 0.0.0.0\r\n"
                        "s=-\r\n"
                        "t=0 0\r\n"
                        "a=group:BUNDLE audio\r\n"
                        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
                        "c=IN IP4 127.0.0.1\r\n"  # Localhost injection
                        "a=rtcp:9 IN IP4 0.0.0.0\r\n"
                        "a=ice-ufrag:AAAA\r\n"
                        "a=ice-pwd:AAAAAAAAAAAAAAAAAAAAAA\r\n"
                        "a=fingerprint:sha-256 AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA\r\n"
                        "a=setup:actpass\r\n"
                    )
                }

                # Try HTTP endpoint
                http_url = endpoint.url.replace("wss://", "https://").replace("ws://", "http://")

                response = await client.post(
                    http_url,
                    json=malicious_sdp,
                    headers={"Content-Type": "application/json"},
                )

                if response.status_code == 200:
                    body = response.text

                    # Check if SDP was processed without validation
                    if "answer" in body.lower() or "sdp" in body.lower():
                        result = WebRTCTestResult(
                            vulnerable=True,
                            vuln_type=WebRTCVulnType.SIGNALING_INJECTION,
                            confidence_score=70,
                            evidence=[
                                "Signaling server accepted potentially malicious SDP",
                                "Minimal validation on offer content",
                                "Could allow SSRF via media connections",
                            ],
                            severity=Severity.MEDIUM,
                            cwe_id="CWE-20",
                        )

                        self._add_finding(
                            name="Signaling Server SDP Injection",
                            description=(
                                "Signaling server accepts SDP offers without proper validation. "
                                "Attackers could inject malicious media endpoints."
                            ),
                            endpoint=endpoint.url,
                            result=result,
                        )

            except Exception as e:
                logger.debug(f"Signaling test error: {e}")

    async def _test_credential_exposure(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter | None,
    ) -> None:
        """Test for WebRTC credential exposure."""
        logger.debug("Phase 5: Testing credential exposure")

        # Already covered in TURN test, check additional patterns
        credential_endpoints = [
            "/api/room/create",
            "/api/room/join",
            "/api/call/init",
            "/api/peer/config",
        ]

        for ep_path in credential_endpoints:
            if rate_limiter:
                await rate_limiter.acquire()

            url = urljoin(base_url, ep_path)
            try:
                response = await client.post(url, json={"room": "test"})

                if response.status_code in [200, 201]:
                    body = response.text

                    # Check for exposed secrets
                    secret_patterns = [
                        (r'"apiKey"\s*:\s*"([^"]{10,})"', "API Key"),
                        (r'"secret"\s*:\s*"([^"]{10,})"', "Secret"),
                        (r'"token"\s*:\s*"([^"]{20,})"', "Token"),
                        (r'"iceServers".*"credential"\s*:\s*"([^"]+)"', "ICE Credential"),
                    ]

                    for pattern, name in secret_patterns:
                        match = re.search(pattern, body, re.IGNORECASE)
                        if match:
                            result = WebRTCTestResult(
                                vulnerable=True,
                                vuln_type=WebRTCVulnType.CREDENTIAL_EXPOSURE,
                                confidence_score=85,
                                evidence=[
                                    f"{name} exposed in response",
                                    f"Endpoint: {url}",
                                    f"Value (partial): {match.group(1)[:15]}...",
                                ],
                                severity=Severity.HIGH,
                                cwe_id="CWE-522",
                            )

                            self._add_finding(
                                name=f"WebRTC {name} Exposure",
                                description=f"WebRTC endpoint exposes {name} in response.",
                                endpoint=url,
                                result=result,
                            )
                            break

            except Exception:
                pass

    async def _test_sdp_security(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter | None,
    ) -> None:
        """Test SDP (Session Description Protocol) security."""
        logger.debug("Phase 6: Testing SDP security")

        for endpoint in self.webrtc_endpoints:
            if endpoint.endpoint_type not in ["signaling", "api"]:
                continue

            if rate_limiter:
                await rate_limiter.acquire()

            try:
                # Request SDP/offer
                http_url = endpoint.url.replace("wss://", "https://").replace("ws://", "http://")
                response = await client.get(http_url)

                if response.status_code == 200:
                    body = response.text

                    # Check SDP security patterns
                    issues = []

                    # Check for plain RTP (not SRTP)
                    if re.search(SDP_SECURITY_PATTERNS["no_srtp"], body):
                        issues.append("Uses plain RTP instead of SRTP (unencrypted media)")

                    # Check for weak crypto
                    if re.search(SDP_SECURITY_PATTERNS["weak_crypto"], body):
                        issues.append("Uses weak crypto suite")

                    # Check for missing DTLS
                    if "a=fingerprint:" not in body and "RTP" in body:
                        issues.append("Missing DTLS fingerprint (no certificate verification)")

                    if issues:
                        severity = "HIGH" if "unencrypted" in str(issues).lower() else "MEDIUM"

                        result = WebRTCTestResult(
                            vulnerable=True,
                            vuln_type=WebRTCVulnType.SRTP_WEAKNESS if "RTP" in str(issues) else WebRTCVulnType.DTLS_WEAKNESS,
                            confidence_score=75,
                            evidence=issues + [f"Endpoint: {endpoint.url}"],
                            severity=severity,
                            cwe_id="CWE-319" if "unencrypted" in str(issues).lower() else "CWE-295",
                        )

                        self._add_finding(
                            name="WebRTC Media Security Weakness",
                            description=(
                                "WebRTC implementation has media security weaknesses. "
                                f"Issues: {', '.join(issues)}"
                            ),
                            endpoint=endpoint.url,
                            result=result,
                        )

            except Exception as e:
                logger.debug(f"SDP security test error: {e}")

    async def _test_cross_origin_signaling(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter | None,
    ) -> None:
        """Test cross-origin access to signaling server."""
        logger.debug("Phase 7: Testing cross-origin signaling")

        signaling_endpoints = [ep for ep in self.webrtc_endpoints if ep.endpoint_type == "signaling"]

        for endpoint in signaling_endpoints:
            if rate_limiter:
                await rate_limiter.acquire()

            try:
                http_url = endpoint.url.replace("wss://", "https://").replace("ws://", "http://")

                # Test with cross-origin headers
                response = await client.options(
                    http_url,
                    headers={
                        "Origin": "https://evil.com",
                        "Access-Control-Request-Method": "POST",
                    }
                )

                # Check CORS headers
                acao = response.headers.get("access-control-allow-origin", "")
                acac = response.headers.get("access-control-allow-credentials", "")

                if acao == "*":
                    result = WebRTCTestResult(
                        vulnerable=True,
                        vuln_type=WebRTCVulnType.CROSS_ORIGIN_SIGNALING,
                        confidence_score=80,
                        evidence=[
                            "Signaling server allows any origin (ACAO: *)",
                            "Cross-site WebSocket hijacking may be possible",
                            f"Endpoint: {endpoint.url}",
                        ],
                        severity=Severity.MEDIUM,
                        cwe_id="CWE-346",
                    )

                    self._add_finding(
                        name="Permissive CORS on Signaling Server",
                        description=(
                            "WebRTC signaling server has permissive CORS policy. "
                            "Attackers from any origin can interact with the signaling server."
                        ),
                        endpoint=endpoint.url,
                        result=result,
                    )

                elif acao == "https://evil.com":
                    severity = "HIGH" if acac.lower() == "true" else "MEDIUM"

                    result = WebRTCTestResult(
                        vulnerable=True,
                        vuln_type=WebRTCVulnType.CROSS_ORIGIN_SIGNALING,
                        confidence_score=90,
                        evidence=[
                            "Signaling server reflects origin without validation",
                            f"Credentials allowed: {acac}",
                            "Cross-site call hijacking possible",
                        ],
                        severity=severity,
                        cwe_id="CWE-346",
                    )

                    self._add_finding(
                        name="Signaling Server Origin Reflection",
                        description=(
                            "WebRTC signaling server reflects arbitrary origins. "
                            "Attackers can hijack WebRTC sessions from malicious sites."
                        ),
                        endpoint=endpoint.url,
                        result=result,
                    )

            except Exception as e:
                logger.debug(f"Cross-origin test error: {e}")

    def _add_finding(
        self,
        name: str,
        description: str,
        endpoint: str,
        result: WebRTCTestResult,
    ) -> None:
        """Add a finding to the results."""
        finding = Finding(
            vuln_type=VulnType.OTHER,
            name=name,
            severity=result.severity,
            confidence_score=float(result.confidence),
            description=description,
            url=endpoint,
            endpoint=endpoint,
            evidence=result.evidence,
            metadata={
                "webrtc_vuln_type": result.vuln_type.name,
                "cwe": result.cwe,
                "leaked_data": result.leaked_data if result.leaked_data else None,
            },
        )

        self.findings.append(finding.to_dict())

        logger.info(
            f"WebRTC vulnerability [{result.severity}]: {name} "
            f"| Confidence: {result.confidence}%"
        )


# Export
__all__ = [
    "WebRTCScanner",
    "WebRTCVulnType",
    "WEBRTC_SCANNER_VERSION",
]
