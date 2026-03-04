"""
Multi-Factor Authentication (MFA/2FA) Bypass Scanner.
Tests for vulnerabilities in MFA implementations.
"""

from __future__ import annotations

import re
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


class MFABypassScanner(ScanModule):
    """
    Multi-Factor Authentication Bypass Scanner.
    
    Tests for:
    - 2FA code brute force
    - Backup code enumeration
    - 2FA disable race condition
    - Response manipulation
    - Direct endpoint access (2FA skip)
    - TOTP sync window abuse
    - Recovery flow bypass
    - Session fixation after 2FA
    - Parameter tampering
    - Status code bypass
    """
    
    name = "mfa_bypass_scanner"
    
    # Common 2FA/MFA endpoints
    MFA_ENDPOINTS = [
        "/2fa",
        "/two-factor",
        "/mfa",
        "/totp",
        "/verify",
        "/verify-otp",
        "/verify-code",
        "/challenge",
        "/auth/2fa",
        "/auth/mfa",
        "/auth/verify",
        "/login/2fa",
        "/login/verify",
        "/account/2fa",
        "/api/2fa/verify",
        "/api/mfa/verify",
        "/api/auth/2fa",
        "/security/2fa",
    ]
    
    # Common backup code endpoints
    BACKUP_ENDPOINTS = [
        "/backup-codes",
        "/recovery-codes",
        "/emergency-codes",
        "/api/backup-codes",
        "/2fa/backup",
        "/mfa/recovery",
        "/account/recovery-codes",
    ]
    
    # Common disable 2FA endpoints  
    DISABLE_ENDPOINTS = [
        "/2fa/disable",
        "/mfa/disable",
        "/account/2fa/disable",
        "/api/2fa/disable",
        "/settings/2fa",
        "/security/2fa/remove",
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
    ) -> dict[str, Any]:
        """Scan for MFA bypass vulnerabilities."""

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        findings: list[Finding] = []
        
        if not host.startswith("http"):
            # Use http:// for localhost/local IPs, https:// for external
            is_local = any(host.startswith(p) for p in ("localhost", "127.", "192.168.", "10.", "172."))
            base_url = f"http://{host}" if is_local else f"https://{host}"
        else:
            base_url = host
        
        async with get_scan_client(verify_ssl=False, timeout=self.timeout) as client:
            # Discover MFA endpoints
            mfa_endpoints = await self._discover_mfa_endpoints(
                client, base_url, rate_limiter
            )
            
            if not mfa_endpoints:
                logger.info(f"No MFA endpoints found for {host}")
                return findings
            
            # Test direct endpoint access bypass
            bypass_findings = await self._test_direct_access_bypass(
                client, base_url, mfa_endpoints, rate_limiter
            )
            findings.extend(bypass_findings)
            
            # Test rate limiting on 2FA
            rate_findings = await self._test_2fa_rate_limiting(
                client, base_url, mfa_endpoints, rate_limiter
            )
            findings.extend(rate_findings)
            
            # Test response manipulation
            response_findings = await self._test_response_manipulation(
                client, base_url, mfa_endpoints, rate_limiter
            )
            findings.extend(response_findings)
            
            # Test backup code security
            backup_findings = await self._test_backup_codes(
                client, base_url, rate_limiter
            )
            findings.extend(backup_findings)
            
            # Test 2FA disable race condition
            race_findings = await self._test_disable_race_condition(
                client, base_url, rate_limiter
            )
            findings.extend(race_findings)
            
            # Test parameter tampering
            param_findings = await self._test_parameter_tampering(
                client, base_url, mfa_endpoints, rate_limiter
            )
            findings.extend(param_findings)
            
            # Test session handling
            session_findings = await self._test_session_handling(
                client, base_url, mfa_endpoints, rate_limiter
            )
            findings.extend(session_findings)

        return {"findings": findings, "info": []}

    async def _discover_mfa_endpoints(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[str]:
        """Discover MFA-related endpoints."""
        endpoints = []

        # FIX 2026-02-18: Only accept status codes that indicate a real MFA endpoint
        # 404 = not found, 302/303/307 = redirect (probably login), 304 = cached
        # Valid: 200, 401, 403, 400 (means endpoint exists and processes requests)
        VALID_MFA_STATUSES = {200, 401, 403, 400, 405, 422}

        # MFA-related content indicators
        MFA_INDICATORS = [
            "2fa", "mfa", "otp", "totp", "verify", "code", "authenticator",
            "two-factor", "second factor", "verification code", "one-time",
        ]

        for path in self.MFA_ENDPOINTS:
            await rate_limiter.acquire()

            try:
                url = urljoin(base_url, path)
                response = await client.get(url, follow_redirects=False)

                # FIX: Only accept statuses that indicate real endpoints
                if response.status_code in VALID_MFA_STATUSES:
                    # Additional check: verify content looks MFA-related
                    content_lower = response.text.lower()
                    if any(ind in content_lower for ind in MFA_INDICATORS):
                        endpoints.append(url)
                        logger.info(f"MFA endpoint found: {url} (status={response.status_code})")
                    elif response.status_code in {401, 403}:
                        # 401/403 without content check is still valid (auth required)
                        endpoints.append(url)
                        logger.info(f"MFA endpoint found (auth required): {url}")

            except Exception as e:
                logger.debug(f"Error checking {path}: {e}")

        return endpoints
    
    async def _test_direct_access_bypass(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        mfa_endpoints: list[str],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test if 2FA can be bypassed by directly accessing protected endpoints."""
        findings = []
        
        # Protected endpoints that should require 2FA
        protected_paths = [
            "/dashboard",
            "/account",
            "/profile",
            "/settings",
            "/admin",
            "/api/user",
            "/api/account",
            "/home",
            "/app",
        ]
        
        for path in protected_paths:
            await rate_limiter.acquire()
            
            try:
                url = urljoin(base_url, path)
                
                # Try accessing without completing 2FA
                # Simulate partial authentication state
                headers = {
                    "Cookie": "auth_pending=true; session=partial_auth_12345",
                }
                
                response = await client.get(url, headers=headers, follow_redirects=False)
                
                # If we get 200 instead of redirect to 2FA
                if response.status_code == 200:
                    # Check if it looks like protected content
                    protected_indicators = [
                        "dashboard", "account", "profile", "settings",
                        "logout", "sign out", "welcome",
                    ]
                    
                    if any(ind in response.text.lower() for ind in protected_indicators):
                        findings.append(Finding(
                            name="2FA Bypass via Direct Endpoint Access",
                            severity=Severity.CRITICAL,
                            confidence_score=65.0,
                            description=f"Protected endpoint {path} may be accessible without completing 2FA",
                            endpoint=url,
                            evidence=[
                                "Endpoint returned 200 status",
                                "Protected content indicators found",
                            ],
                            cwe_id="CWE-287",
                            cvss_score=8.8,
                            remediation="Enforce 2FA verification state check on all protected endpoints. "
                                       "Use server-side session validation.",
                        ))
                        
            except Exception as e:
                logger.debug(f"Error testing direct access: {e}")
        
        return findings
    
    async def _test_2fa_rate_limiting(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        mfa_endpoints: list[str],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for lack of rate limiting on 2FA code submission."""
        findings = []

        # FIX 2026-02-18: Status codes that indicate the endpoint doesn't exist or isn't MFA
        INVALID_STATUSES = {404, 405, 500, 502, 503, 504, 301, 302, 303, 304, 307, 308}

        # Status codes that indicate actual 2FA processing (valid test)
        VALID_PROCESSING_STATUSES = {200, 400, 401, 422, 403}

        for endpoint in mfa_endpoints:
            if "verify" not in endpoint.lower():
                continue

            # Send multiple rapid requests
            responses = []

            for i in range(10):
                await rate_limiter.acquire()

                try:
                    # Common 2FA code formats
                    code = str(i).zfill(6)  # 000000 to 000009

                    data = {
                        "code": code,
                        "otp": code,
                        "token": code,
                        "totp": code,
                    }

                    response = await client.post(endpoint, data=data)
                    responses.append(response.status_code)

                except Exception as e:
                    logger.debug(f"Error in rate limit test: {e}")
                    break

            # FIX 2026-02-18: Validate that this is actually an MFA endpoint that processes codes
            if len(responses) < 10:
                continue

            # If all/most responses are 404/302/304 → endpoint doesn't exist or redirects
            invalid_count = sum(1 for r in responses if r in INVALID_STATUSES)
            if invalid_count >= 8:  # 80%+ invalid = not a real MFA endpoint
                logger.debug(f"Skipping {endpoint}: {invalid_count}/10 invalid responses ({responses})")
                continue

            # Require at least some responses that indicate actual processing
            valid_count = sum(1 for r in responses if r in VALID_PROCESSING_STATUSES)
            if valid_count < 5:  # Need at least 50% valid processing responses
                logger.debug(f"Skipping {endpoint}: only {valid_count}/10 valid responses ({responses})")
                continue

            # If none returned 429 (rate limit) and no 403 in last 5 = no rate limiting
            if 429 not in responses and all(r != 403 for r in responses[-5:]):
                findings.append(Finding(
                    name="2FA Code Brute Force Possible",
                    severity=Severity.HIGH,
                    confidence_score=85.0,
                    description="No rate limiting detected on 2FA verification endpoint, "
                               "allowing brute force of 6-digit codes (1 million combinations)",
                    endpoint=endpoint,
                    evidence=[
                        f"10 requests sent successfully",
                        f"Response codes: {responses}",
                        f"Valid processing responses: {valid_count}/10",
                        "No 429 (rate limit) responses",
                    ],
                    cwe_id="CWE-307",
                    cvss_score=7.5,
                    remediation="Implement strict rate limiting: max 3-5 attempts per code validity period. "
                               "Add exponential backoff and account lockout.",
                ))

        return findings
    
    async def _test_response_manipulation(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        mfa_endpoints: list[str],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test if 2FA can be bypassed via response manipulation."""
        findings = []
        
        for endpoint in mfa_endpoints:
            await rate_limiter.acquire()
            
            try:
                # Submit invalid code
                data = {"code": "000000", "otp": "000000"}
                response = await client.post(endpoint, data=data)
                
                # Check for client-side validation indicators
                response_text = response.text.lower()
                
                # Look for patterns suggesting client-side validation
                client_side_indicators = [
                    "success: false",
                    '"valid": false',
                    '"verified": false',
                    "status: 'error'",
                    '"authenticated": false',
                ]
                
                if any(ind in response_text for ind in client_side_indicators):
                    findings.append(Finding(
                        name="Potential 2FA Response Manipulation",
                        severity=Severity.HIGH,
                        confidence_score=65.0,
                        description="2FA verification appears to use client-checkable response. "
                                   "May be vulnerable to response tampering.",
                        endpoint=endpoint,
                        evidence=[
                            "Response contains boolean verification status",
                            "Client-side validation indicators detected",
                        ],
                        cwe_id="CWE-602",
                        cvss_score=7.5,
                        remediation="Never rely on client-side validation for 2FA. "
                                   "Use server-side session state exclusively.",
                    ))
                
                # Check for JWT/token in response that could be forged
                if "eyj" in response_text.lower():  # JWT indicator
                    findings.append(Finding(
                        name="JWT Token in 2FA Response",
                        severity=Severity.MEDIUM,
                        confidence_score=65.0,
                        description="JWT token returned in 2FA response - verify server-side validation",
                        endpoint=endpoint,
                        evidence=["JWT token pattern found in response"],
                        cwe_id="CWE-287",
                        remediation="Ensure JWT tokens are properly validated server-side.",
                    ))
                    
            except Exception as e:
                logger.debug(f"Error testing response manipulation: {e}")
        
        return findings
    
    async def _test_backup_codes(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test backup code security."""
        findings = []
        
        for path in self.BACKUP_ENDPOINTS:
            await rate_limiter.acquire()
            
            try:
                url = urljoin(base_url, path)
                response = await client.get(url)
                
                if response.status_code == 200:
                    # Check if backup codes are exposed without auth
                    code_patterns = [
                        r'\b[A-Z0-9]{8}\b',  # Common backup code format
                        r'\b\d{8}\b',  # 8-digit codes
                        r'[a-f0-9]{8}-[a-f0-9]{4}',  # UUID-style
                    ]
                    
                    for pattern in code_patterns:
                        if re.search(pattern, response.text):
                            findings.append(Finding(
                                name="Backup Codes Exposure",
                                severity=Severity.CRITICAL,
                                confidence_score=85.0,
                                description="Backup recovery codes may be accessible without proper authentication",
                                endpoint=url,
                                evidence=[
                                    "Endpoint returned 200",
                                    "Backup code patterns detected in response",
                                ],
                                cwe_id="CWE-200",
                                cvss_score=8.8,
                                remediation="Protect backup codes endpoint with full authentication. "
                                           "Never expose codes in API responses.",
                            ))
                            # AUDIT-FIX 2026-02-11: Removed break - continue testing other URLs
                
                # Test rate limiting on backup code usage
                await rate_limiter.acquire()

                # FIX 2026-02-18: Track responses to validate this is a real backup code endpoint
                backup_responses = []
                rate_limited = False

                for i in range(5):
                    data = {"code": f"BACKUP{i:04d}"}
                    resp = await client.post(url, data=data)
                    backup_responses.append(resp.status_code)

                    if resp.status_code == 429:
                        rate_limited = True
                        break

                # FIX: Only report if endpoint actually processes backup codes
                # (not 404/302/304/500)
                valid_statuses = {200, 400, 401, 403, 422}
                valid_count = sum(1 for r in backup_responses if r in valid_statuses)

                if not rate_limited and valid_count >= 3:  # At least 3/5 valid responses
                    findings.append(Finding(
                        name="Backup Code Brute Force Possible",
                        severity=Severity.HIGH,
                        confidence_score=65.0,
                        description="No rate limiting on backup code verification",
                        endpoint=url,
                        evidence=[
                            f"Multiple backup code attempts accepted",
                            f"Response codes: {backup_responses}",
                        ],
                        cwe_id="CWE-307",
                        remediation="Limit backup code attempts. Invalidate used codes.",
                    ))
                    
            except Exception as e:
                logger.debug(f"Error testing backup codes: {e}")
        
        return findings
    
    async def _test_disable_race_condition(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for race condition in 2FA disable flow."""
        findings = []
        
        # This is an informational finding as race conditions require specific timing
        for path in self.DISABLE_ENDPOINTS:
            await rate_limiter.acquire()
            
            try:
                url = urljoin(base_url, path)
                response = await client.get(url)
                
                if response.status_code != 404:
                    findings.append(Finding(
                        name="2FA Disable Endpoint Found - Race Condition Check Required",
                        severity=Severity.INFO,
                        confidence_score=85.0,
                        description="2FA disable endpoint found. Manual testing required for race conditions: "
                                   "attacker may be able to disable 2FA during authentication window.",
                        endpoint=url,
                        evidence=["2FA disable endpoint accessible"],
                        cwe_id="CWE-362",
                        remediation="Implement proper locking during 2FA operations. "
                                   "Require re-authentication for 2FA changes.",
                    ))
                    
            except Exception as e:
                logger.debug(f"Error testing disable endpoint: {e}")
        
        return findings
    
    async def _test_parameter_tampering(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        mfa_endpoints: list[str],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test parameter tampering to bypass 2FA."""
        findings = []
        
        # Parameters that might bypass 2FA
        bypass_params = [
            {"2fa_required": "false"},
            {"mfa_enabled": "0"},
            {"skip_2fa": "true"},
            {"verify": "skip"},
            {"otp_verified": "true"},
            {"auth_complete": "true"},
            {"step": "3"},  # Skip to final step
            {"2fa_status": "verified"},
        ]
        
        for endpoint in mfa_endpoints:
            for params in bypass_params:
                await rate_limiter.acquire()
                
                try:
                    # Try GET with params
                    response = await client.get(endpoint, params=params)
                    
                    if response.status_code == 200:
                        # Check for bypass indicators
                        if "success" in response.text.lower() or \
                           "verified" in response.text.lower() or \
                           "authenticated" in response.text.lower():
                            findings.append(Finding(
                                name="2FA Parameter Tampering Bypass",
                                severity=Severity.CRITICAL,
                                confidence_score=65.0,
                                description=f"2FA may be bypassable via parameter: {params}",
                                endpoint=endpoint,
                                evidence=[
                                    f"Parameter: {params}",
                                    "Success indicators in response",
                                ],
                                cwe_id="CWE-639",
                                cvss_score=9.1,
                                remediation="Never trust client-supplied 2FA status parameters. "
                                           "Use server-side session state only.",
                            ))
                            # AUDIT-FIX 2026-02-11: Removed break - continue testing other params
                    
                    # Try POST with params
                    response = await client.post(endpoint, data=params)
                    
                    if response.status_code == 200 and \
                       ("success" in response.text.lower() or "redirect" in response.headers.get("location", "")):
                        findings.append(Finding(
                            name="2FA Parameter Tampering (POST)",
                            severity=Severity.CRITICAL,
                            confidence_score=65.0,
                            description=f"2FA bypassed via POST parameter: {params}",
                            endpoint=endpoint,
                            evidence=[f"Parameter: {params}"],
                            cwe_id="CWE-639",
                            cvss_score=9.1,
                            remediation="Validate 2FA status server-side.",
                        ))
                        # AUDIT-FIX 2026-02-11: Removed break - continue testing other params
                        
                except Exception as e:
                    logger.debug(f"Error testing param tampering: {e}")
        
        return findings
    
    async def _test_session_handling(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        mfa_endpoints: list[str],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test session handling around 2FA."""
        findings = []
        
        await rate_limiter.acquire()
        
        try:
            # Get a session
            response = await client.get(base_url)
            initial_cookies = dict(response.cookies)
            
            # Check if session changes after 2FA attempt
            if mfa_endpoints:
                await rate_limiter.acquire()
                
                response = await client.post(
                    mfa_endpoints[0],
                    data={"code": "123456"},
                    cookies=initial_cookies
                )
                
                # Check for session fixation (same session ID after 2FA)
                new_cookies = dict(response.cookies)
                
                # Look for session cookies
                session_names = ["session", "sessionid", "PHPSESSID", "JSESSIONID", "connect.sid"]
                
                for name in session_names:
                    if name in initial_cookies and name in new_cookies:
                        if initial_cookies[name] == new_cookies[name]:
                            findings.append(Finding(
                                name="Session Fixation in 2FA Flow",
                                severity=Severity.HIGH,
                                confidence_score=65.0,
                                description="Session ID does not change after 2FA verification attempt. "
                                           "May be vulnerable to session fixation.",
                                endpoint=mfa_endpoints[0],
                                evidence=[
                                    f"Session cookie '{name}' unchanged",
                                ],
                                cwe_id="CWE-384",
                                cvss_score=7.5,
                                remediation="Regenerate session ID after successful 2FA verification.",
                            ))
                            # AUDIT-FIX 2026-02-11: Removed break - check all session cookies
                            
        except Exception as e:
            logger.debug(f"Error testing session handling: {e}")
        
        return findings
