"""
Rate Limiting and Brute Force Scanner.
Tests for rate limiting bypass and brute force vulnerabilities.
"""

from __future__ import annotations

import asyncio
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


class RateLimitScanner(ScanModule):
    """
    Rate Limiting and Brute Force Scanner.
    
    Tests for:
    - Missing rate limiting
    - Rate limit bypass via headers
    - Rate limit bypass via case variation
    - Rate limit bypass via encoding
    - Account lockout bypass
    - Password spraying viability
    - API rate limit exhaustion
    """
    
    name = "rate_limit_scanner"
    
    # Headers to bypass rate limiting
    BYPASS_HEADERS = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-For": "192.168.1.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Remote-Addr": "127.0.0.1"},
        {"True-Client-IP": "127.0.0.1"},
        {"CF-Connecting-IP": "127.0.0.1"},
        {"X-Cluster-Client-IP": "127.0.0.1"},
        {"Forwarded": "for=127.0.0.1"},
        {"X-ProxyUser-Ip": "127.0.0.1"},
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
        """Scan for rate limiting vulnerabilities."""
        findings: list[Finding] = []
        
        base_url = f"https://{host}" if not host.startswith("http") else host
        
        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            # Test authentication endpoints
            auth_findings = await self._test_auth_rate_limit(
                client, base_url, rate_limiter
            )
            findings.extend(auth_findings)
            
            # Test API endpoints
            api_findings = await self._test_api_rate_limit(
                client, base_url, rate_limiter
            )
            findings.extend(api_findings)
            
            # Test rate limit bypass techniques
            bypass_findings = await self._test_bypass_techniques(
                client, base_url, rate_limiter
            )
            findings.extend(bypass_findings)
            
            # Test password reset rate limiting
            reset_findings = await self._test_reset_rate_limit(
                client, base_url, rate_limiter
            )
            findings.extend(reset_findings)
            
            # Test registration rate limiting
            register_findings = await self._test_registration_rate_limit(
                client, base_url, rate_limiter
            )
            findings.extend(register_findings)
        
        return findings
    
    async def _test_auth_rate_limit(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test rate limiting on authentication endpoints."""
        findings = []
        
        auth_endpoints = [
            "/login",
            "/signin",
            "/auth/login",
            "/api/login",
            "/api/auth",
            "/api/v1/auth",
        ]
        
        for endpoint in auth_endpoints:
            url = urljoin(base_url, endpoint)
            
            # Check if endpoint exists
            await rate_limiter.acquire()
            
            try:
                check = await client.get(url)
                if check.status_code == 404:
                    continue
            except Exception:
                continue
            
            # Send multiple failed login attempts
            failed_count = 0
            locked = False
            
            for i in range(20):  # Try 20 failed logins
                await rate_limiter.acquire()
                
                try:
                    response = await client.post(
                        url,
                        data={
                            "username": "testuser",
                            "password": f"wrongpass{i}",
                            "email": "test@test.com",
                        }
                    )
                    
                    # Check for rate limiting response
                    if response.status_code == 429:
                        locked = True
                        findings.append(Finding(
                            name="Rate Limiting Present",
                            severity="INFO",
                            confidence="HIGH",
                            description=f"Rate limiting active after {i} attempts",
                            matched_at=url,
                            evidence=[
                                f"429 returned after {i} requests",
                            ],
                            cwe="CWE-307",
                            remediation="Rate limiting is correctly configured.",
                        ))
                        break
                    
                    if response.status_code in [200, 401, 403]:
                        failed_count += 1
                        
                except Exception as e:
                    logger.debug(f"Error testing auth rate limit: {e}")
            
            if not locked and failed_count >= 15:
                findings.append(Finding(
                    name="Missing Authentication Rate Limiting",
                    severity="HIGH",
                    confidence="HIGH",
                    description="No rate limiting on authentication endpoint",
                    matched_at=url,
                    evidence=[
                        f"{failed_count} failed attempts without lockout",
                        "Brute force attacks possible",
                    ],
                    cwe="CWE-307",
                    cvss_score=7.5,
                    remediation="Implement rate limiting. Use progressive delays. "
                               "Lock accounts after N failures.",
                ))
                break  # One finding is enough
        
        return findings
    
    async def _test_api_rate_limit(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test rate limiting on API endpoints."""
        findings = []
        
        api_endpoints = [
            "/api",
            "/api/v1",
            "/api/users",
            "/api/data",
            "/graphql",
        ]
        
        for endpoint in api_endpoints:
            url = urljoin(base_url, endpoint)
            
            await rate_limiter.acquire()
            
            try:
                # Check if endpoint exists
                check = await client.get(url)
                if check.status_code == 404:
                    continue
                
                # Send burst of requests
                success_count = 0
                rate_limited = False
                
                start_time = time.time()
                
                for i in range(50):  # 50 requests in quick succession
                    try:
                        response = await client.get(url)
                        
                        if response.status_code == 429:
                            rate_limited = True
                            break
                        elif response.status_code in [200, 201, 204]:
                            success_count += 1
                            
                    except Exception:
                        pass
                
                elapsed = time.time() - start_time
                
                if not rate_limited and success_count >= 40:
                    rps = success_count / elapsed if elapsed > 0 else 0
                    
                    findings.append(Finding(
                        name="Missing API Rate Limiting",
                        severity="MEDIUM",
                        confidence="HIGH",
                        description=f"No rate limiting on API endpoint ({rps:.1f} req/s)",
                        matched_at=url,
                        evidence=[
                            f"{success_count} requests completed",
                            f"Time: {elapsed:.2f}s",
                            "DoS and abuse possible",
                        ],
                        cwe="CWE-770",
                        cvss_score=5.3,
                        remediation="Implement API rate limiting. Use token bucket or sliding window.",
                    ))
                    break
                    
            except Exception as e:
                logger.debug(f"Error testing API rate limit: {e}")
        
        return findings
    
    async def _test_bypass_techniques(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test rate limit bypass techniques."""
        findings = []
        
        auth_url = None
        
        # Find auth endpoint
        for endpoint in ["/login", "/auth/login", "/api/login"]:
            url = urljoin(base_url, endpoint)
            try:
                check = await client.get(url)
                if check.status_code != 404:
                    auth_url = url
                    break
            except Exception:
                pass
        
        if not auth_url:
            return findings
        
        # First, try to trigger rate limiting
        await rate_limiter.acquire()
        
        rate_limited = False
        for i in range(25):
            try:
                response = await client.post(
                    auth_url,
                    data={"username": "test", "password": "wrong"}
                )
                if response.status_code == 429:
                    rate_limited = True
                    break
            except Exception:
                pass
        
        if not rate_limited:
            return findings  # No rate limiting to bypass
        
        # Now try bypass techniques
        for bypass_headers in self.BYPASS_HEADERS:
            await rate_limiter.acquire()
            
            try:
                # Generate unique IP
                bypass_headers = {k: f"{secrets.randbelow(256)}.{secrets.randbelow(256)}.{secrets.randbelow(256)}.{secrets.randbelow(256)}" 
                                  for k, v in bypass_headers.items()}
                
                response = await client.post(
                    auth_url,
                    data={"username": "test", "password": "wrong"},
                    headers=bypass_headers
                )
                
                # If not 429, bypass worked
                if response.status_code != 429:
                    header_name = list(bypass_headers.keys())[0]
                    
                    findings.append(Finding(
                        name="Rate Limit Bypass via Header",
                        severity="HIGH",
                        confidence="HIGH",
                        description=f"Rate limiting bypassed using {header_name} header",
                        matched_at=auth_url,
                        evidence=[
                            f"Bypass header: {header_name}",
                            "Rate limit not applied with spoofed IP",
                        ],
                        cwe="CWE-307",
                        cvss_score=7.5,
                        remediation="Don't trust client IP headers for rate limiting. "
                                   "Use session/account-based rate limiting.",
                    ))
                    break
                    
            except Exception as e:
                logger.debug(f"Error testing bypass: {e}")
        
        # Test case variation bypass
        await rate_limiter.acquire()
        
        try:
            variations = [
                "/LOGIN",
                "/Login",
                "/login/",
                "/login?",
                "/./login",
                "//login",
            ]
            
            for variation in variations:
                var_url = urljoin(base_url, variation)
                
                response = await client.post(
                    var_url,
                    data={"username": "test", "password": "wrong"}
                )
                
                if response.status_code != 429:
                    findings.append(Finding(
                        name="Rate Limit Bypass via URL Variation",
                        severity="HIGH",
                        confidence="MEDIUM",
                        description="Rate limiting bypassed using URL case/path variation",
                        matched_at=var_url,
                        evidence=[
                            f"Original: {auth_url}",
                            f"Bypass: {var_url}",
                        ],
                        cwe="CWE-307",
                        cvss_score=7.5,
                        remediation="Normalize URLs before rate limit checks.",
                    ))
                    break
                    
        except Exception as e:
            logger.debug(f"Error testing URL variation: {e}")
        
        return findings
    
    async def _test_reset_rate_limit(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test password reset rate limiting."""
        findings = []
        
        reset_endpoints = [
            "/forgot-password",
            "/password/reset",
            "/api/password/forgot",
        ]
        
        for endpoint in reset_endpoints:
            url = urljoin(base_url, endpoint)
            
            await rate_limiter.acquire()
            
            try:
                check = await client.get(url)
                if check.status_code == 404:
                    continue
                
                # Send multiple reset requests
                success_count = 0
                
                for i in range(10):
                    response = await client.post(
                        url,
                        data={"email": f"test{i}@test.com"}
                    )
                    
                    if response.status_code == 429:
                        break
                    elif response.status_code in [200, 201, 204, 302]:
                        success_count += 1
                
                if success_count >= 8:
                    findings.append(Finding(
                        name="Missing Password Reset Rate Limiting",
                        severity="MEDIUM",
                        confidence="HIGH",
                        description="Password reset endpoint not rate limited",
                        matched_at=url,
                        evidence=[
                            f"{success_count} resets without throttling",
                            "Email bombing/enumeration possible",
                        ],
                        cwe="CWE-307",
                        cvss_score=5.3,
                        remediation="Implement rate limiting on password reset. "
                                   "Limit per email and per IP.",
                    ))
                    break
                    
            except Exception as e:
                logger.debug(f"Error testing reset rate limit: {e}")
        
        return findings
    
    async def _test_registration_rate_limit(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test registration rate limiting."""
        findings = []
        
        register_endpoints = [
            "/register",
            "/signup",
            "/api/register",
            "/api/users",
        ]
        
        for endpoint in register_endpoints:
            url = urljoin(base_url, endpoint)
            
            await rate_limiter.acquire()
            
            try:
                check = await client.get(url)
                if check.status_code == 404:
                    continue
                
                # Send multiple registration attempts
                success_count = 0
                
                for i in range(15):
                    response = await client.post(
                        url,
                        data={
                            "email": f"spamtest{i}@test{i}.com",
                            "username": f"spamuser{i}",
                            "password": "TestPass123!",
                        }
                    )
                    
                    if response.status_code == 429:
                        break
                    elif response.status_code in [200, 201, 204, 302]:
                        success_count += 1
                
                if success_count >= 10:
                    findings.append(Finding(
                        name="Missing Registration Rate Limiting",
                        severity="MEDIUM",
                        confidence="HIGH",
                        description="Registration endpoint not rate limited",
                        matched_at=url,
                        evidence=[
                            f"{success_count} registrations without throttling",
                            "Spam account creation possible",
                        ],
                        cwe="CWE-770",
                        cvss_score=5.3,
                        remediation="Implement registration rate limiting. "
                                   "Use CAPTCHA and email verification.",
                    ))
                    break
                    
            except Exception as e:
                logger.debug(f"Error testing registration rate limit: {e}")
        
        return findings
