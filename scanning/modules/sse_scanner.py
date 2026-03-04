"""
Server-Sent Events (SSE) Security Scanner.
Tests for SSE-specific vulnerabilities.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

import httpx

from scanning.findings import Finding, Severity
from scanning.vuln_scanner import ScanModule
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter
from utils.scan_client import get_scan_client
from scanning.scan_context import ScanContext

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


class SSEScanner(ScanModule):
    """
    Server-Sent Events Security Scanner.
    
    Tests for:
    - SSE injection vulnerabilities
    - Cross-origin SSE access
    - SSE data leakage
    - Event stream hijacking
    - SSE DoS vectors
    - Authentication bypass in SSE
    """
    
    name = "sse_scanner"
    
    # Common SSE endpoints - EXPANDED 2026-02-19
    SSE_ENDPOINTS = [
        "/events",
        "/sse",
        "/stream",
        "/realtime",
        "/notifications",
        "/updates",
        "/api/events",
        "/api/sse",
        "/api/stream",
        "/subscribe",
        # Additional patterns
        "/api/v1/events",
        "/api/v1/sse",
        "/api/v1/stream",
        "/api/v2/events",
        "/ws/events",  # WebSocket-style paths sometimes serve SSE
        "/push",
        "/feed",
        "/live",
        "/changes",
        "/webhook/stream",
        "/graphql/subscriptions",  # GraphQL SSE fallback
        "/.well-known/mercure",  # Mercure hub
    ]
    
    def __init__(
        self,
        settings: Settings,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.timeout = settings.timeouts.request_timeout if hasattr(settings, 'timeouts') else 30.0
    
    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Scan for SSE vulnerabilities."""

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        findings: list[Finding] = []
        
        base_url = f"https://{host}" if not host.startswith("http") else host
        
        async with get_scan_client(verify_ssl=False, timeout=self.timeout) as client:
            # Discover SSE endpoints
            sse_endpoints = await self._discover_sse(client, base_url, rate_limiter)
            
            for endpoint in sse_endpoints:
                # Test CORS on SSE
                cors_findings = await self._test_sse_cors(
                    client, endpoint, rate_limiter
                )
                findings.extend(cors_findings)

                # Test authentication
                auth_findings = await self._test_sse_auth(
                    client, endpoint, rate_limiter
                )
                findings.extend(auth_findings)

                # Test injection (EXPANDED 2026-02-19)
                injection_findings = await self._test_sse_injection(
                    client, endpoint, rate_limiter
                )
                findings.extend(injection_findings)

                # Test event type abuse (NEW 2026-02-19)
                event_type_findings = await self._test_sse_event_type_abuse(
                    client, endpoint, rate_limiter
                )
                findings.extend(event_type_findings)

                # Test data exposure
                exposure_findings = await self._test_data_exposure(
                    client, endpoint, rate_limiter
                )
                findings.extend(exposure_findings)

        return findings
    
    async def _discover_sse(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[str]:
        """Discover SSE endpoints."""
        discovered = []
        
        for path in self.SSE_ENDPOINTS:
            await rate_limiter.acquire()
            
            try:
                url = urljoin(base_url, path)
                
                response = await client.get(
                    url,
                    headers={"Accept": "text/event-stream"},
                    timeout=5.0
                )
                
                content_type = response.headers.get("content-type", "")
                
                if "text/event-stream" in content_type:
                    discovered.append(url)
                    logger.info(f"SSE endpoint found: {url}")
                    
            except Exception as e:
                logger.debug(f"Error checking SSE at {path}: {e}")
        
        return discovered
    
    async def _test_sse_cors(
        self,
        client: httpx.AsyncClient,
        endpoint: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test CORS configuration on SSE endpoint."""
        findings = []
        
        malicious_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null",
        ]
        
        for origin in malicious_origins:
            await rate_limiter.acquire()
            
            try:
                response = await client.get(
                    endpoint,
                    headers={
                        "Accept": "text/event-stream",
                        "Origin": origin,
                    },
                    timeout=5.0
                )
                
                acao = response.headers.get("access-control-allow-origin", "")
                acac = response.headers.get("access-control-allow-credentials", "")
                
                if acao == origin or acao == "*":
                    severity = "HIGH" if acac.lower() == "true" else "MEDIUM"
                    
                    findings.append(Finding(
                        name="SSE Cross-Origin Access Allowed",
                        severity=severity,
                        confidence_score=85.0,
                        description=f"SSE endpoint allows cross-origin access from {origin}",
                        endpoint=endpoint,
                        evidence=[
                            f"Origin: {origin}",
                            f"ACAO: {acao}",
                            f"Credentials: {acac}",
                        ],
                        cwe_id="CWE-942",
                        cvss_score=7.5 if acac.lower() == "true" else 5.3,
                        remediation="Restrict SSE CORS to trusted origins only.",
                    ))
                    break
                    
            except Exception as e:
                logger.debug(f"Error testing SSE CORS: {e}")
        
        return findings
    
    async def _test_sse_auth(
        self,
        client: httpx.AsyncClient,
        endpoint: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test authentication on SSE endpoint."""
        findings = []
        
        await rate_limiter.acquire()
        
        try:
            # Test without authentication
            response = await client.get(
                endpoint,
                headers={"Accept": "text/event-stream"},
                timeout=10.0
            )
            
            if response.status_code == 200:
                content_type = response.headers.get("content-type", "")
                
                if "text/event-stream" in content_type:
                    # Check if we receive any data
                    content = response.text[:1000]
                    
                    if "data:" in content or "event:" in content:
                        # Check for sensitive data indicators
                        sensitive_patterns = ["email", "user", "password", "token", "secret", "private", "internal"]
                        
                        has_sensitive = any(p in content.lower() for p in sensitive_patterns)
                        
                        findings.append(Finding(
                            name="SSE Endpoint Without Authentication",
                            severity=Severity.HIGH if has_sensitive else "MEDIUM",
                            confidence_score=85.0,
                            description="SSE endpoint accessible without authentication",
                            endpoint=endpoint,
                            evidence=[
                                "SSE data received without auth",
                                f"Contains sensitive data: {has_sensitive}",
                            ],
                            cwe_id="CWE-306",
                            cvss_score=7.5 if has_sensitive else 5.3,
                            remediation="Implement authentication for SSE endpoints. "
                                       "Use tokens in query params or cookies.",
                        ))
                        
        except Exception as e:
            logger.debug(f"Error testing SSE auth: {e}")
        
        return findings
    
    async def _test_sse_injection(
        self,
        client: httpx.AsyncClient,
        endpoint: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """
        Test for SSE event injection vulnerabilities.

        EXPANDED 2026-02-19: Comprehensive SSE injection testing including:
        - Event field injection (event:, data:, id:, retry:)
        - XSS via SSE data field
        - JSON injection in data payloads
        - Multi-line injection attacks
        - Encoding bypass attempts
        """
        findings = []

        # ═══════════════════════════════════════════════════════════════════════
        # EXPANDED SSE INJECTION PAYLOADS
        # ═══════════════════════════════════════════════════════════════════════

        # 1. Event field injection - inject new events
        event_injection_payloads = [
            # Basic newline injection
            ("\n\nevent:malicious\ndata:injected\n\n", "malicious"),
            ("\r\n\r\nevent:evil\ndata:payload\r\n\r\n", "evil"),
            # URL encoded
            ("%0A%0Aevent:phantom_test%0Adata:injected%0A%0A", "phantom_test"),
            # Double URL encoded
            ("%250A%250Aevent:double_enc%250Adata:test%250A%250A", "double_enc"),
            # Unicode newlines
            ("\u2028\u2028event:unicode_nl\ndata:test\u2028\u2028", "unicode_nl"),
            # Mixed CRLF/LF
            ("\r\nevent:mixed\ndata:test\r\n\n", "mixed"),
        ]

        # 2. ID field manipulation - can cause replay issues
        id_injection_payloads = [
            ("\n\nid:999999\ndata:id_inject\n\n", "id_inject"),
            ("\n\nid:-1\ndata:negative_id\n\n", "negative_id"),
            ("\n\nid:a]><script>\ndata:xss_id\n\n", "xss_id"),
        ]

        # 3. Retry field manipulation - DoS vector
        retry_injection_payloads = [
            ("\n\nretry:1\ndata:fast_retry\n\n", "fast_retry"),  # Very fast reconnect
            ("\n\nretry:0\ndata:instant_retry\n\n", "instant_retry"),  # Instant reconnect
            ("\n\nretry:999999999\ndata:slow_retry\n\n", "slow_retry"),  # Slow reconnect
        ]

        # 4. XSS via SSE data field
        xss_payloads = [
            ("\n\ndata:<script>alert('SSE_XSS')</script>\n\n", "<script>"),
            ("\n\ndata:<img src=x onerror=alert('SSE')>\n\n", "onerror="),
            ("\n\ndata:{\"html\":\"<script>alert(1)</script>\"}\n\n", "<script>"),
            ("\n\nevent:message\ndata:<svg onload=alert(1)>\n\n", "onload="),
        ]

        # 5. JSON injection in data field
        json_injection_payloads = [
            ('\n\ndata:{"user":"test","admin":true}\n\n', '"admin":true'),
            ('\n\ndata:{"role":"admin","__proto__":{"isAdmin":true}}\n\n', '__proto__'),
            ('\n\ndata:{"constructor":{"prototype":{"admin":1}}}\n\n', 'constructor'),
        ]

        # Test via query parameters
        common_params = ["id", "user", "channel", "room", "topic", "filter", "query", "message", "data"]

        all_payloads = (
            event_injection_payloads +
            id_injection_payloads +
            retry_injection_payloads +
            xss_payloads +
            json_injection_payloads
        )

        for param in common_params[:5]:  # Limit params to avoid excessive requests
            for payload, marker in all_payloads[:10]:  # Limit payloads per param
                if not self.can_make_request(param):
                    break

                await rate_limiter.acquire()

                try:
                    test_url = f"{endpoint}?{param}={payload}"

                    response = await client.get(
                        test_url,
                        headers={
                            "Accept": "text/event-stream",
                            **self._auth_headers,
                        },
                        timeout=5.0
                    )

                    if response.status_code == 200:
                        response_text = response.text.lower()
                        marker_lower = marker.lower()

                        # Check if injection payload appears in response
                        if marker_lower in response_text:
                            # Determine severity based on injection type
                            if "<script>" in payload or "onerror=" in payload or "onload=" in payload:
                                severity = "HIGH"
                                vuln_type = "SSE XSS Injection"
                                cwe = "CWE-79"
                                cvss = 8.1
                            elif "retry:" in payload:
                                severity = "MEDIUM"
                                vuln_type = "SSE Retry Manipulation"
                                cwe = "CWE-400"
                                cvss = 5.3
                            elif "__proto__" in payload or "constructor" in payload:
                                severity = "HIGH"
                                vuln_type = "SSE Prototype Pollution"
                                cwe = "CWE-1321"
                                cvss = 7.5
                            else:
                                severity = "HIGH"
                                vuln_type = "SSE Event Injection"
                                cwe = "CWE-74"
                                cvss = 7.5

                            findings.append(Finding(
                                name=vuln_type,
                                severity=severity,
                                confidence_score=85.0,
                                description=f"SSE endpoint vulnerable to {vuln_type.lower()}. "
                                           f"Attacker can inject malicious events into the stream.",
                                endpoint=test_url,
                                evidence=[
                                    f"Parameter: {param}",
                                    f"Payload: {payload[:50]}...",
                                    f"Marker '{marker}' found in response",
                                ],
                                cwe_id=cwe,
                                cvss_score=cvss,
                                remediation="Sanitize all user input before including in SSE stream. "
                                           "Escape newlines (\\n, \\r) and special characters. "
                                           "Validate and encode data field content.",
                                metadata={
                                    "param": param,
                                    "injection_type": vuln_type,
                                    "payload_sample": payload[:100],
                                },
                            ))

                            # Continue testing other types, but don't duplicate same type
                            break

                except Exception as e:
                    logger.debug(f"Error testing SSE injection at {endpoint}: {e}")

        return findings

    async def _test_sse_event_type_abuse(
        self,
        client: httpx.AsyncClient,
        endpoint: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """
        Test for event type abuse in SSE.

        NEW 2026-02-19: Tests if attacker can trigger privileged event types.
        """
        findings = []

        # Privileged event types that shouldn't be client-triggerable
        privileged_events = [
            "admin",
            "system",
            "error",
            "auth",
            "internal",
            "broadcast",
            "global",
            "all_users",
            "debug",
        ]

        # Parameters that might control event type
        event_params = ["event", "type", "eventType", "event_type", "action"]

        for param in event_params:
            for event_type in privileged_events:
                if not self.can_make_request(param):
                    break

                await rate_limiter.acquire()

                try:
                    test_url = f"{endpoint}?{param}={event_type}"

                    response = await client.get(
                        test_url,
                        headers={
                            "Accept": "text/event-stream",
                            **self._auth_headers,
                        },
                        timeout=5.0
                    )

                    if response.status_code == 200:
                        # Check if privileged event type appears
                        if f"event:{event_type}" in response.text.lower():
                            findings.append(Finding(
                                name="SSE Event Type Abuse",
                                severity=Severity.MEDIUM,
                                confidence_score=75.0,
                                description=f"SSE endpoint allows subscription to privileged event type '{event_type}'",
                                endpoint=test_url,
                                evidence=[
                                    f"Parameter: {param}={event_type}",
                                    f"Privileged event type accessible",
                                ],
                                cwe_id="CWE-284",
                                cvss_score=5.4,
                                remediation="Validate event types server-side. "
                                           "Implement authorization checks for privileged events.",
                            ))
                            break

                except Exception as e:
                    logger.debug(f"Error testing event type abuse: {e}")

        return findings
    
    async def _test_data_exposure(
        self,
        client: httpx.AsyncClient,
        endpoint: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for sensitive data exposure in SSE."""
        findings = []
        
        await rate_limiter.acquire()
        
        try:
            # Read SSE stream for a few seconds
            response = await client.get(
                endpoint,
                headers={"Accept": "text/event-stream"},
                timeout=10.0
            )
            
            if response.status_code == 200:
                content = response.text
                
                # Check for sensitive data patterns
                sensitive_findings = []
                
                # API keys
                if any(p in content.lower() for p in ["api_key", "apikey", "api-key"]):
                    sensitive_findings.append("API keys")
                
                # Tokens
                if any(p in content.lower() for p in ["jwt", "bearer", "token", "session"]):
                    sensitive_findings.append("Tokens/Sessions")
                
                # Personal data
                if any(p in content.lower() for p in ["email", "phone", "address", "ssn"]):
                    sensitive_findings.append("Personal data")
                
                # Credentials
                if any(p in content.lower() for p in ["password", "credential", "secret"]):
                    sensitive_findings.append("Credentials")
                
                # Internal info
                if any(p in content.lower() for p in ["internal", "debug", "stack", "trace"]):
                    sensitive_findings.append("Internal information")
                
                if sensitive_findings:
                    findings.append(Finding(
                        name="SSE Sensitive Data Exposure",
                        severity=Severity.HIGH,
                        confidence_score=65.0,
                        description=f"SSE stream may contain sensitive data: {', '.join(sensitive_findings)}",
                        endpoint=endpoint,
                        evidence=sensitive_findings,
                        cwe_id="CWE-200",
                        cvss_score=7.5,
                        remediation="Review SSE data for sensitive information. "
                                   "Implement data filtering and access controls.",
                    ))
                    
        except Exception as e:
            logger.debug(f"Error testing SSE data exposure: {e}")
        
        return findings
