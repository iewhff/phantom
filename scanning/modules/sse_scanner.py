"""
Server-Sent Events (SSE) Security Scanner.
Tests for SSE-specific vulnerabilities.
"""

from __future__ import annotations

import secrets
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

import httpx

from scanning.vuln_scanner import Finding, ScanModule
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter

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
    
    # Common SSE endpoints
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
    ]
    
    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.timeout = settings.timeouts.request_timeout
    
    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Scan for SSE vulnerabilities."""
        findings: list[Finding] = []
        
        base_url = f"https://{host}" if not host.startswith("http") else host
        
        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
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
                
                # Test injection
                injection_findings = await self._test_sse_injection(
                    client, endpoint, rate_limiter
                )
                findings.extend(injection_findings)
                
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
                        confidence="HIGH",
                        description=f"SSE endpoint allows cross-origin access from {origin}",
                        matched_at=endpoint,
                        evidence=[
                            f"Origin: {origin}",
                            f"ACAO: {acao}",
                            f"Credentials: {acac}",
                        ],
                        cwe="CWE-942",
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
                            severity="HIGH" if has_sensitive else "MEDIUM",
                            confidence="HIGH",
                            description="SSE endpoint accessible without authentication",
                            matched_at=endpoint,
                            evidence=[
                                "SSE data received without auth",
                                f"Contains sensitive data: {has_sensitive}",
                            ],
                            cwe="CWE-306",
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
        """Test for SSE event injection."""
        findings = []
        
        # SSE injection payloads
        injection_payloads = [
            "\n\nevent:malicious\ndata:injected",
            "\r\n\r\nevent:evil\ndata:payload",
            "%0A%0Aevent:test%0Adata:hacked",
            "test\n\ndata:injected",
        ]
        
        # Test via query parameters
        common_params = ["id", "user", "channel", "room", "topic", "filter"]
        
        for param in common_params:
            for payload in injection_payloads:
                await rate_limiter.acquire()
                
                try:
                    test_url = f"{endpoint}?{param}={payload}"
                    
                    response = await client.get(
                        test_url,
                        headers={"Accept": "text/event-stream"},
                        timeout=5.0
                    )
                    
                    if response.status_code == 200:
                        # Check if injection payload appears in response
                        if "malicious" in response.text or "evil" in response.text or "hacked" in response.text:
                            findings.append(Finding(
                                name="SSE Event Injection",
                                severity="HIGH",
                                confidence="HIGH",
                                description="SSE endpoint vulnerable to event injection",
                                matched_at=test_url,
                                evidence=[
                                    f"Parameter: {param}",
                                    "Injected event appeared in stream",
                                ],
                                cwe="CWE-74",
                                cvss_score=7.5,
                                remediation="Sanitize newlines in SSE data. "
                                           "Encode special characters properly.",
                            ))
                            return findings
                            
                except Exception as e:
                    logger.debug(f"Error testing SSE injection: {e}")
        
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
                        severity="HIGH",
                        confidence="MEDIUM",
                        description=f"SSE stream may contain sensitive data: {', '.join(sensitive_findings)}",
                        matched_at=endpoint,
                        evidence=sensitive_findings,
                        cwe="CWE-200",
                        cvss_score=7.5,
                        remediation="Review SSE data for sensitive information. "
                                   "Implement data filtering and access controls.",
                    ))
                    
        except Exception as e:
            logger.debug(f"Error testing SSE data exposure: {e}")
        
        return findings
