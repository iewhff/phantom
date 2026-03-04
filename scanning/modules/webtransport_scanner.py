"""
WebTransport Security Scanner for PHANTOM AI.

WebTransport is a protocol providing bidirectional communication between
client and server over HTTP/3 (QUIC). It offers lower latency than WebSockets
and supports both reliable streams and unreliable datagrams.

Tests for WebTransport-specific vulnerabilities:
- Session hijacking via connection ID manipulation
- Datagram spoofing/injection
- Stream multiplexing abuse
- Authentication bypass
- Origin validation bypass
- Resource exhaustion via streams

Version: 1.0.0
"""

import asyncio
import time
import base64
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlparse

from scanning.findings import Finding, Severity
from scanning.vuln_scanner import ScanModule
from utils.logger import get_logger

logger = get_logger(__name__)

WEBTRANSPORT_SCANNER_VERSION = "1.0.0"

# Try to import HTTP/3 client for WebTransport over QUIC
try:
    from utils.http3_client import HTTP3Client, is_http3_available
    HTTP3_AVAILABLE = is_http3_available()
except ImportError:
    HTTP3_AVAILABLE = False

    def is_http3_available():
        return False


class WebTransportVulnType(Enum):
    """WebTransport specific vulnerability types."""
    SESSION_HIJACK = "session_hijacking"
    DATAGRAM_SPOOFING = "datagram_spoofing"
    STREAM_EXHAUSTION = "stream_exhaustion"
    AUTH_BYPASS = "authentication_bypass"
    ORIGIN_BYPASS = "origin_validation_bypass"
    PROTOCOL_DOWNGRADE = "protocol_downgrade"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    DATA_INJECTION = "data_injection"
    REPLAY_ATTACK = "replay_attack"
    CONNECTION_MIGRATION = "connection_migration_abuse"


@dataclass
class WebTransportEndpoint:
    """Detected WebTransport endpoint information."""
    url: str
    path: str
    supports_datagrams: bool = False
    supports_streams: bool = True
    max_streams: int | None = None
    origin_validated: bool = True
    auth_required: bool = False
    protocol_version: str = ""


@dataclass
class WebTransportScanContext:
    """Context for WebTransport scanning session."""
    target_url: str
    host: str
    port: int
    endpoints: list[WebTransportEndpoint] = field(default_factory=list)
    http3_available: bool = False
    webtransport_detected: bool = False


class WebTransportScanner(ScanModule):
    """
    WebTransport Protocol Security Scanner.

    Detects and tests for vulnerabilities in WebTransport implementations:
    - Session handling and hijacking risks
    - Datagram injection and spoofing
    - Stream multiplexing abuse
    - Authentication and authorization bypasses
    - Origin validation issues
    """

    name = "webtransport_scanner"
    description = "WebTransport Protocol Security Scanner"
    version = WEBTRANSPORT_SCANNER_VERSION
    category = "protocol"
    tags = ["webtransport", "http3", "quic", "realtime", "bidirectional"]

    # Common WebTransport paths
    WEBTRANSPORT_PATHS = [
        "/.well-known/webtransport",
        "/webtransport",
        "/wt",
        "/transport",
        "/bidirectional",
        "/realtime",
        "/stream",
        "/api/webtransport",
        "/ws-alt",  # WebSocket alternative
        "/quic",
    ]

    def __init__(
        self,
        settings: Any = None,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.findings: list[Finding] = []
        self.ctx: WebTransportScanContext | None = None

    async def scan(
        self,
        target_url: str,
        asset_data: dict | None = None,
        auth_context: Any | None = None,
    ) -> dict:
        """
        Perform WebTransport security scan.

        Args:
            target_url: Target URL to scan
            asset_data: Additional asset information
            auth_context: Authentication context

        Returns:
            Scan results dictionary
        """
        self.findings = []
        start_time = time.time()

        logger.info(f"[WebTransport] Starting scan on {target_url}")

        # Initialize context
        parsed = urlparse(target_url)
        self.ctx = WebTransportScanContext(
            target_url=target_url,
            host=parsed.hostname or "localhost",
            port=parsed.port or 443,
            http3_available=HTTP3_AVAILABLE,
        )

        try:
            # Phase 1: Detect WebTransport endpoints
            await self._phase_detect_endpoints()

            if not self.ctx.webtransport_detected:
                logger.info("[WebTransport] No WebTransport endpoints detected")
                return self._build_result(target_url, time.time() - start_time)

            # Phase 2: Test authentication bypass
            await self._phase_auth_bypass_tests()

            # Phase 3: Test origin validation
            await self._phase_origin_validation_tests()

            # Phase 4: Test session handling
            await self._phase_session_tests()

            # Phase 5: Test datagram security
            await self._phase_datagram_tests()

            # Phase 6: Test stream multiplexing
            await self._phase_stream_tests()

            # Phase 7: Test replay attacks
            await self._phase_replay_tests()

            # Phase 8: Test protocol downgrade
            await self._phase_downgrade_tests()

            # Phase 9: Test resource exhaustion
            await self._phase_resource_exhaustion_tests()

        except Exception as e:
            logger.error(f"[WebTransport] Scan error: {e}")

        elapsed = time.time() - start_time
        logger.info(f"[WebTransport] Scan complete: {len(self.findings)} findings in {elapsed:.2f}s")

        return self._build_result(target_url, elapsed)

    async def _phase_detect_endpoints(self):
        """Phase 1: Detect WebTransport endpoints."""
        logger.debug("[WebTransport] Phase 1: Detecting endpoints")

        import httpx

        async with httpx.AsyncClient(http2=True, timeout=10.0, verify=False) as client:
            for path in self.WEBTRANSPORT_PATHS:
                try:
                    url = f"https://{self.ctx.host}:{self.ctx.port}{path}"

                    # Try CONNECT request (WebTransport handshake)
                    # Note: httpx doesn't support CONNECT directly, so we probe with OPTIONS
                    response = await client.request(
                        "OPTIONS",
                        url,
                        headers={
                            "Origin": f"https://{self.ctx.host}",
                            "Access-Control-Request-Method": "CONNECT",
                            "Sec-WebTransport-Http3-Draft": "draft02",
                        },
                    )

                    # Check for WebTransport indicators
                    if self._is_webtransport_response(response):
                        endpoint = WebTransportEndpoint(
                            url=url,
                            path=path,
                            supports_datagrams=self._supports_datagrams(response),
                            origin_validated="access-control-allow-origin" in response.headers,
                            protocol_version=response.headers.get("sec-webtransport-http3-draft", ""),
                        )
                        self.ctx.endpoints.append(endpoint)
                        self.ctx.webtransport_detected = True
                        logger.info(f"[WebTransport] Found endpoint: {path}")

                    # Also check HEAD for .well-known
                    if path == "/.well-known/webtransport":
                        head_resp = await client.head(url)
                        if head_resp.status_code in (200, 204):
                            if not any(e.path == path for e in self.ctx.endpoints):
                                endpoint = WebTransportEndpoint(url=url, path=path)
                                self.ctx.endpoints.append(endpoint)
                                self.ctx.webtransport_detected = True

                except Exception as e:
                    logger.debug(f"[WebTransport] Probe failed for {path}: {e}")

    def _is_webtransport_response(self, response) -> bool:
        """Check if response indicates WebTransport support."""
        indicators = [
            "sec-webtransport" in str(response.headers).lower(),
            "webtransport" in response.headers.get("upgrade", "").lower(),
            response.status_code == 200 and "connect" in response.headers.get(
                "access-control-allow-methods", ""
            ).lower(),
            "application/webtransport" in response.headers.get("content-type", ""),
        ]
        return any(indicators)

    def _supports_datagrams(self, response) -> bool:
        """Check if endpoint supports unreliable datagrams."""
        datagram_header = response.headers.get("sec-webtransport-http3-draft02-datagrams", "")
        return datagram_header.lower() == "1" or "datagram" in str(response.headers).lower()

    async def _phase_auth_bypass_tests(self):
        """Phase 2: Test authentication bypass on WebTransport endpoints."""
        logger.debug("[WebTransport] Phase 2: Testing authentication bypass")

        import httpx

        for endpoint in self.ctx.endpoints:
            try:
                async with httpx.AsyncClient(http2=True, timeout=10.0, verify=False) as client:
                    # Test 1: Access without auth token
                    no_auth_resp = await client.request(
                        "OPTIONS",
                        endpoint.url,
                        headers={
                            "Origin": f"https://{self.ctx.host}",
                            "Access-Control-Request-Method": "CONNECT",
                        },
                    )

                    if no_auth_resp.status_code in (200, 204):
                        self._add_finding(
                            vuln_type=WebTransportVulnType.AUTH_BYPASS,
                            severity=Severity.HIGH,
                            confidence_score=75.0,
                            evidence={
                                "endpoint": endpoint.path,
                                "status_code": no_auth_resp.status_code,
                                "test": "no_auth_token",
                            },
                            recommendation="Implement authentication for WebTransport endpoints. "
                                           "Require valid session tokens before establishing connection.",
                        )
                        endpoint.auth_required = False

                    # Test 2: Access with invalid token
                    invalid_token_resp = await client.request(
                        "OPTIONS",
                        endpoint.url,
                        headers={
                            "Origin": f"https://{self.ctx.host}",
                            "Authorization": "Bearer invalid_token_12345",
                            "Access-Control-Request-Method": "CONNECT",
                        },
                    )

                    if invalid_token_resp.status_code in (200, 204):
                        self._add_finding(
                            vuln_type=WebTransportVulnType.AUTH_BYPASS,
                            severity=Severity.CRITICAL,
                            confidence_score=85.0,
                            evidence={
                                "endpoint": endpoint.path,
                                "status_code": invalid_token_resp.status_code,
                                "test": "invalid_token_accepted",
                            },
                            recommendation="Validate authentication tokens properly. "
                                           "Reject invalid or malformed tokens.",
                        )

                    # Test 3: Expired session test (if we have auth context)
                    # Simulated with old timestamp in token
                    old_token = base64.b64encode(
                        b'{"exp": 0, "iat": 0, "sub": "test"}'
                    ).decode()
                    expired_resp = await client.request(
                        "OPTIONS",
                        endpoint.url,
                        headers={
                            "Origin": f"https://{self.ctx.host}",
                            "Authorization": f"Bearer {old_token}",
                        },
                    )

                    if expired_resp.status_code in (200, 204):
                        self._add_finding(
                            vuln_type=WebTransportVulnType.AUTH_BYPASS,
                            severity=Severity.HIGH,
                            confidence_score=70.0,
                            evidence={
                                "endpoint": endpoint.path,
                                "test": "expired_token_accepted",
                            },
                            recommendation="Implement proper token expiration validation.",
                        )

            except Exception as e:
                logger.debug(f"[WebTransport] Auth bypass test error: {e}")

    async def _phase_origin_validation_tests(self):
        """Phase 3: Test origin validation bypass."""
        logger.debug("[WebTransport] Phase 3: Testing origin validation")

        import httpx

        malicious_origins = [
            "https://evil.com",
            "https://attacker.example.com",
            f"https://{self.ctx.host}.evil.com",
            "null",
            "",
            "https://localhost",
            "file://",
            f"https://{self.ctx.host}@evil.com",
        ]

        for endpoint in self.ctx.endpoints:
            try:
                async with httpx.AsyncClient(http2=True, timeout=10.0, verify=False) as client:
                    for origin in malicious_origins:
                        try:
                            response = await client.request(
                                "OPTIONS",
                                endpoint.url,
                                headers={
                                    "Origin": origin,
                                    "Access-Control-Request-Method": "CONNECT",
                                },
                            )

                            # Check if origin is allowed
                            allowed_origin = response.headers.get("access-control-allow-origin", "")

                            if allowed_origin == "*":
                                self._add_finding(
                                    vuln_type=WebTransportVulnType.ORIGIN_BYPASS,
                                    severity=Severity.HIGH,
                                    confidence_score=90.0,
                                    evidence={
                                        "endpoint": endpoint.path,
                                        "allowed_origin": "*",
                                        "issue": "Wildcard origin allowed",
                                    },
                                    recommendation="Do not use wildcard (*) for WebTransport origins. "
                                                   "Explicitly list allowed origins.",
                                )
                                endpoint.origin_validated = False
                                break

                            if origin in allowed_origin or allowed_origin == origin:
                                self._add_finding(
                                    vuln_type=WebTransportVulnType.ORIGIN_BYPASS,
                                    severity=Severity.CRITICAL if "evil" in origin else "MEDIUM",
                                    confidence_score=85.0,
                                    evidence={
                                        "endpoint": endpoint.path,
                                        "malicious_origin": origin,
                                        "allowed_origin": allowed_origin,
                                    },
                                    recommendation=f"Origin {origin} should not be allowed. "
                                                   "Implement strict origin validation.",
                                )
                                endpoint.origin_validated = False

                        except Exception:
                            pass

            except Exception as e:
                logger.debug(f"[WebTransport] Origin validation test error: {e}")

    async def _phase_session_tests(self):
        """Phase 4: Test session handling vulnerabilities."""
        logger.debug("[WebTransport] Phase 4: Testing session handling")

        import httpx

        for endpoint in self.ctx.endpoints:
            try:
                async with httpx.AsyncClient(http2=True, timeout=10.0, verify=False) as client:
                    # Test 1: Session fixation attempt
                    # Try to set a predictable session ID
                    predictable_session = "session_" + "A" * 32

                    response = await client.request(
                        "OPTIONS",
                        endpoint.url,
                        headers={
                            "Origin": f"https://{self.ctx.host}",
                            "X-Session-ID": predictable_session,
                            "Cookie": f"wt_session={predictable_session}",
                        },
                    )

                    # Check if session was accepted
                    set_cookie = response.headers.get("set-cookie", "")
                    if predictable_session in set_cookie or predictable_session in str(response.headers):
                        self._add_finding(
                            vuln_type=WebTransportVulnType.SESSION_HIJACK,
                            severity=Severity.HIGH,
                            confidence_score=75.0,
                            evidence={
                                "endpoint": endpoint.path,
                                "predictable_session": predictable_session[:20] + "...",
                                "issue": "Server accepted client-provided session ID",
                            },
                            recommendation="Generate session IDs server-side with cryptographically "
                                           "secure random values. Never accept client-provided session IDs.",
                        )

                    # Test 2: Connection ID manipulation (for HTTP/3)
                    if self.ctx.http3_available:
                        # Try manipulating connection ID in headers
                        manipulated_cid = "0" * 16

                        cid_response = await client.request(
                            "OPTIONS",
                            endpoint.url,
                            headers={
                                "Origin": f"https://{self.ctx.host}",
                                "X-Connection-ID": manipulated_cid,
                            },
                        )

                        if cid_response.status_code in (200, 204):
                            self._add_finding(
                                vuln_type=WebTransportVulnType.SESSION_HIJACK,
                                severity=Severity.MEDIUM,
                                confidence_score=60.0,
                                evidence={
                                    "endpoint": endpoint.path,
                                    "manipulated_cid": manipulated_cid,
                                    "issue": "Custom connection ID header accepted",
                                },
                                recommendation="Ignore client-provided connection IDs. "
                                               "Use QUIC's built-in connection ID management.",
                            )

            except Exception as e:
                logger.debug(f"[WebTransport] Session test error: {e}")

    async def _phase_datagram_tests(self):
        """Phase 5: Test datagram security (unreliable transport)."""
        logger.debug("[WebTransport] Phase 5: Testing datagram security")

        for endpoint in self.ctx.endpoints:
            if not endpoint.supports_datagrams:
                continue

            # Note: Full datagram testing requires actual QUIC connection
            # We test for configuration issues via HTTP

            try:
                import httpx

                async with httpx.AsyncClient(http2=True, timeout=10.0, verify=False) as client:
                    # Test 1: Datagram size limits
                    # Large datagrams might cause issues
                    response = await client.request(
                        "OPTIONS",
                        endpoint.url,
                        headers={
                            "Origin": f"https://{self.ctx.host}",
                            "Sec-WebTransport-Http3-Draft02-Datagrams": "1",
                            "X-Max-Datagram-Size": "65535",  # Very large
                        },
                    )

                    if response.status_code in (200, 204):
                        datagram_size = response.headers.get("x-max-datagram-size", "")
                        if datagram_size and int(datagram_size) > 32768:
                            self._add_finding(
                                vuln_type=WebTransportVulnType.DATAGRAM_SPOOFING,
                                severity=Severity.LOW,
                                confidence_score=50.0,
                                evidence={
                                    "endpoint": endpoint.path,
                                    "max_datagram_size": datagram_size,
                                    "issue": "Large datagram size allowed",
                                },
                                recommendation="Limit maximum datagram size to prevent "
                                               "resource exhaustion attacks.",
                            )

                    # Note: Actual datagram injection testing would require:
                    # 1. Establishing QUIC connection
                    # 2. Sending UDP datagrams directly
                    # This is logged as a note for manual testing
                    if endpoint.supports_datagrams:
                        self._add_finding(
                            vuln_type=WebTransportVulnType.DATAGRAM_SPOOFING,
                            severity=Severity.INFO,
                            confidence_score=40.0,
                            evidence={
                                "endpoint": endpoint.path,
                                "datagrams_enabled": True,
                                "note": "Endpoint supports unreliable datagrams - manual testing recommended",
                            },
                            recommendation="Ensure datagram authentication and integrity verification. "
                                           "Consider rate limiting datagram reception.",
                        )

            except Exception as e:
                logger.debug(f"[WebTransport] Datagram test error: {e}")

    async def _phase_stream_tests(self):
        """Phase 6: Test stream multiplexing abuse."""
        logger.debug("[WebTransport] Phase 6: Testing stream multiplexing")

        import httpx

        for endpoint in self.ctx.endpoints:
            try:
                async with httpx.AsyncClient(http2=True, timeout=10.0, verify=False) as client:
                    # Test 1: Request many streams simultaneously
                    # Via HTTP we can only probe the configuration

                    response = await client.request(
                        "OPTIONS",
                        endpoint.url,
                        headers={
                            "Origin": f"https://{self.ctx.host}",
                            "X-Requested-Streams": "1000",
                        },
                    )

                    max_streams = response.headers.get("x-max-streams", "")
                    if max_streams:
                        try:
                            stream_limit = int(max_streams)
                            if stream_limit > 500:
                                self._add_finding(
                                    vuln_type=WebTransportVulnType.STREAM_EXHAUSTION,
                                    severity=Severity.LOW,
                                    confidence_score=55.0,
                                    evidence={
                                        "endpoint": endpoint.path,
                                        "max_streams": stream_limit,
                                    },
                                    recommendation=f"Max streams ({stream_limit}) is high. "
                                                   "Consider lowering to prevent resource exhaustion.",
                                )
                                endpoint.max_streams = stream_limit
                        except ValueError:
                            pass

                    # Test 2: Priority abuse via headers
                    priority_response = await client.request(
                        "OPTIONS",
                        endpoint.url,
                        headers={
                            "Origin": f"https://{self.ctx.host}",
                            "Priority": "u=0, i",  # Highest urgency
                            "X-Stream-Priority": "0",
                        },
                    )

                    if priority_response.status_code in (200, 204):
                        # Check if priority was reflected
                        if "priority" in str(priority_response.headers).lower():
                            self._add_finding(
                                vuln_type=WebTransportVulnType.STREAM_EXHAUSTION,
                                severity=Severity.LOW,
                                confidence_score=45.0,
                                evidence={
                                    "endpoint": endpoint.path,
                                    "issue": "Client priority hints reflected",
                                },
                                recommendation="Implement server-side priority enforcement. "
                                               "Do not fully trust client priority hints.",
                            )

            except Exception as e:
                logger.debug(f"[WebTransport] Stream test error: {e}")

    async def _phase_replay_tests(self):
        """Phase 7: Test replay attack vulnerabilities."""
        logger.debug("[WebTransport] Phase 7: Testing replay attacks")

        import httpx

        for endpoint in self.ctx.endpoints:
            try:
                async with httpx.AsyncClient(http2=True, timeout=10.0, verify=False) as client:
                    # Generate a nonce for testing
                    nonce = hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]

                    # First request with nonce
                    first_response = await client.request(
                        "OPTIONS",
                        endpoint.url,
                        headers={
                            "Origin": f"https://{self.ctx.host}",
                            "X-Request-Nonce": nonce,
                            "X-Timestamp": str(int(time.time())),
                        },
                    )

                    # Replay same request
                    replay_response = await client.request(
                        "OPTIONS",
                        endpoint.url,
                        headers={
                            "Origin": f"https://{self.ctx.host}",
                            "X-Request-Nonce": nonce,
                            "X-Timestamp": str(int(time.time())),
                        },
                    )

                    # Both accepted = potential replay vulnerability
                    if (first_response.status_code in (200, 204) and
                            replay_response.status_code in (200, 204)):
                        self._add_finding(
                            vuln_type=WebTransportVulnType.REPLAY_ATTACK,
                            severity=Severity.MEDIUM,
                            confidence_score=60.0,
                            evidence={
                                "endpoint": endpoint.path,
                                "nonce_used": nonce,
                                "first_status": first_response.status_code,
                                "replay_status": replay_response.status_code,
                            },
                            recommendation="Implement nonce tracking to prevent replay attacks. "
                                           "Store and validate nonces server-side.",
                        )

                    # Test old timestamp acceptance
                    old_timestamp = int(time.time()) - 3600  # 1 hour ago

                    old_response = await client.request(
                        "OPTIONS",
                        endpoint.url,
                        headers={
                            "Origin": f"https://{self.ctx.host}",
                            "X-Timestamp": str(old_timestamp),
                        },
                    )

                    if old_response.status_code in (200, 204):
                        self._add_finding(
                            vuln_type=WebTransportVulnType.REPLAY_ATTACK,
                            severity=Severity.MEDIUM,
                            confidence_score=55.0,
                            evidence={
                                "endpoint": endpoint.path,
                                "old_timestamp": old_timestamp,
                                "current_time": int(time.time()),
                                "time_diff_seconds": int(time.time()) - old_timestamp,
                            },
                            recommendation="Implement timestamp validation with a reasonable window. "
                                           "Reject requests with timestamps older than 5-10 minutes.",
                        )

            except Exception as e:
                logger.debug(f"[WebTransport] Replay test error: {e}")

    async def _phase_downgrade_tests(self):
        """Phase 8: Test protocol downgrade vulnerabilities."""
        logger.debug("[WebTransport] Phase 8: Testing protocol downgrade")

        import httpx

        for endpoint in self.ctx.endpoints:
            try:
                async with httpx.AsyncClient(http2=True, timeout=10.0, verify=False) as client:
                    # Test 1: Request WebSocket fallback
                    ws_fallback = await client.request(
                        "OPTIONS",
                        endpoint.url,
                        headers={
                            "Origin": f"https://{self.ctx.host}",
                            "Upgrade": "websocket",
                            "Connection": "Upgrade",
                        },
                    )

                    if ws_fallback.status_code == 101 or "websocket" in ws_fallback.headers.get("upgrade", "").lower():
                        self._add_finding(
                            vuln_type=WebTransportVulnType.PROTOCOL_DOWNGRADE,
                            severity=Severity.LOW,
                            confidence_score=65.0,
                            evidence={
                                "endpoint": endpoint.path,
                                "fallback_protocol": "websocket",
                                "status": ws_fallback.status_code,
                            },
                            recommendation="If WebSocket fallback is intentional, ensure it has "
                                           "equivalent security controls. Consider warning users of downgrade.",
                        )

                    # Test 2: Request HTTP/2 only (no HTTP/3)
                    h2_response = await client.request(
                        "OPTIONS",
                        endpoint.url,
                        headers={
                            "Origin": f"https://{self.ctx.host}",
                            "Accept-Protocol": "http/2",
                        },
                    )

                    if h2_response.status_code in (200, 204) and h2_response.http_version == "HTTP/2":
                        self._add_finding(
                            vuln_type=WebTransportVulnType.PROTOCOL_DOWNGRADE,
                            severity=Severity.INFO,
                            confidence_score=50.0,
                            evidence={
                                "endpoint": endpoint.path,
                                "protocol": "HTTP/2",
                                "note": "WebTransport typically requires HTTP/3",
                            },
                            recommendation="True WebTransport requires HTTP/3 (QUIC). "
                                           "Consider requiring HTTP/3 for WebTransport connections.",
                        )

            except Exception as e:
                logger.debug(f"[WebTransport] Downgrade test error: {e}")

    async def _phase_resource_exhaustion_tests(self):
        """Phase 9: Test resource exhaustion vulnerabilities."""
        logger.debug("[WebTransport] Phase 9: Testing resource exhaustion")

        import httpx

        for endpoint in self.ctx.endpoints:
            try:
                async with httpx.AsyncClient(http2=True, timeout=10.0, verify=False) as client:
                    # Test 1: Many concurrent OPTIONS requests
                    tasks = []
                    for _ in range(20):
                        task = client.request(
                            "OPTIONS",
                            endpoint.url,
                            headers={"Origin": f"https://{self.ctx.host}"},
                        )
                        tasks.append(task)

                    try:
                        results = await asyncio.wait_for(
                            asyncio.gather(*tasks, return_exceptions=True),
                            timeout=15.0,
                        )

                        successful = sum(1 for r in results if hasattr(r, "status_code") and r.status_code < 500)

                        if successful >= 18:
                            self._add_finding(
                                vuln_type=WebTransportVulnType.RESOURCE_EXHAUSTION,
                                severity=Severity.LOW,
                                confidence_score=50.0,
                                evidence={
                                    "endpoint": endpoint.path,
                                    "concurrent_requests": 20,
                                    "successful": successful,
                                },
                                recommendation="Consider implementing rate limiting for "
                                               "WebTransport connection attempts.",
                            )

                    except asyncio.TimeoutError:
                        # Timeout might indicate server is struggling
                        self._add_finding(
                            vuln_type=WebTransportVulnType.RESOURCE_EXHAUSTION,
                            severity=Severity.MEDIUM,
                            confidence_score=60.0,
                            evidence={
                                "endpoint": endpoint.path,
                                "issue": "Server timed out under concurrent load",
                            },
                            recommendation="Implement connection rate limiting and "
                                           "timeout handling for WebTransport.",
                        )

                    # Test 2: Large header size
                    large_headers = {
                        "Origin": f"https://{self.ctx.host}",
                        "X-Large-Data": "A" * 8192,  # 8KB header
                    }

                    large_header_resp = await client.request(
                        "OPTIONS",
                        endpoint.url,
                        headers=large_headers,
                    )

                    if large_header_resp.status_code in (200, 204):
                        self._add_finding(
                            vuln_type=WebTransportVulnType.RESOURCE_EXHAUSTION,
                            severity=Severity.LOW,
                            confidence_score=45.0,
                            evidence={
                                "endpoint": endpoint.path,
                                "header_size": 8192,
                                "status": large_header_resp.status_code,
                            },
                            recommendation="Implement header size limits to prevent "
                                           "memory exhaustion attacks.",
                        )

            except Exception as e:
                logger.debug(f"[WebTransport] Resource exhaustion test error: {e}")

    def _add_finding(
        self,
        vuln_type: WebTransportVulnType,
        severity: str,
        confidence: float,
        evidence: dict,
        recommendation: str = "",
    ):
        """Add a finding to the results."""
        finding = Finding(
            name=f"WebTransport {vuln_type.value.replace('_', ' ').title()}",
            description=f"WebTransport protocol vulnerability: {vuln_type.value}",
            severity=severity,
            confidence_score=confidence,
            vuln_type=VulnType.OTHER,
            host=self.ctx.host if self.ctx else "",
            endpoint=self.ctx.target_url if self.ctx else "",
            evidence=[str(evidence)],
            metadata={
                "webtransport_vuln_type": vuln_type.value,
                "endpoints": [e.path for e in self.ctx.endpoints] if self.ctx else [],
                "evidence": evidence,
                "recommendation": recommendation,
                "cwe": self._get_cwe_for_vuln(vuln_type),
                "scanner": self.name,
                "scanner_version": self.version,
            },
        )
        self.findings.append(finding)
        logger.info(f"[WebTransport] Finding: {vuln_type.value} ({severity})")

    def _get_cwe_for_vuln(self, vuln_type: WebTransportVulnType) -> str:
        """Map vulnerability type to CWE."""
        cwe_map = {
            WebTransportVulnType.SESSION_HIJACK: "CWE-384",  # Session Fixation
            WebTransportVulnType.DATAGRAM_SPOOFING: "CWE-290",  # Authentication Bypass by Spoofing
            WebTransportVulnType.STREAM_EXHAUSTION: "CWE-400",  # Uncontrolled Resource Consumption
            WebTransportVulnType.AUTH_BYPASS: "CWE-287",  # Improper Authentication
            WebTransportVulnType.ORIGIN_BYPASS: "CWE-346",  # Origin Validation Error
            WebTransportVulnType.PROTOCOL_DOWNGRADE: "CWE-757",  # Selection of Less-Secure Algorithm
            WebTransportVulnType.RESOURCE_EXHAUSTION: "CWE-400",  # Resource Exhaustion
            WebTransportVulnType.DATA_INJECTION: "CWE-74",  # Injection
            WebTransportVulnType.REPLAY_ATTACK: "CWE-294",  # Authentication Bypass by Capture-replay
            WebTransportVulnType.CONNECTION_MIGRATION: "CWE-384",  # Session Fixation
        }
        return cwe_map.get(vuln_type, "CWE-16")  # Configuration

    def _build_result(self, target_url: str, elapsed: float) -> dict:
        """Build scan result dictionary."""
        return {
            "scanner": self.name,
            "version": self.version,
            "target": target_url,
            "elapsed_seconds": elapsed,
            "findings": self.findings,
            "findings_count": len(self.findings),
            "webtransport_info": {
                "detected": self.ctx.webtransport_detected if self.ctx else False,
                "endpoints": [
                    {
                        "path": e.path,
                        "supports_datagrams": e.supports_datagrams,
                        "auth_required": e.auth_required,
                        "origin_validated": e.origin_validated,
                    }
                    for e in (self.ctx.endpoints if self.ctx else [])
                ],
                "http3_available": self.ctx.http3_available if self.ctx else False,
            },
        }


# ============================================================
# Convenience Functions
# ============================================================

async def quick_webtransport_scan(url: str) -> dict:
    """
    Quick WebTransport security scan of a URL.

    Returns:
        Scan results dictionary
    """
    scanner = WebTransportScanner()
    return await scanner.scan(url)


async def detect_webtransport(url: str) -> bool:
    """
    Check if a URL supports WebTransport.

    Returns:
        True if WebTransport is detected
    """
    result = await quick_webtransport_scan(url)
    return result.get("webtransport_info", {}).get("detected", False)


# ============================================================
# CLI Entry Point
# ============================================================

if __name__ == "__main__":
    import sys

    async def main():
        if len(sys.argv) < 2:
            print("Usage: python webtransport_scanner.py <url>")
            sys.exit(1)

        url = sys.argv[1]
        print(f"Scanning {url} for WebTransport vulnerabilities...")

        result = await quick_webtransport_scan(url)

        print(f"\nWebTransport Detected: {result['webtransport_info']['detected']}")
        print(f"Endpoints: {len(result['webtransport_info']['endpoints'])}")
        print(f"Findings: {result['findings_count']}")

        for finding in result["findings"]:
            print(f"\n[{finding.severity}] {finding.name}")
            print(f"  Confidence: {finding.confidence}%")
            print(f"  CWE: {finding.metadata.get('cwe')}")

    asyncio.run(main())
