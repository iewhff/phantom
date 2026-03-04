"""
Mobile API Security Scanner.
Tests for mobile-specific API vulnerabilities and security misconfigurations.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

import httpx

from scanning.findings import Finding, Severity, VulnType
from scanning.vuln_scanner import ScanModule
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter
from utils.scan_client import get_scan_client
from scanning.scan_context import ScanContext

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


class MobileAPIScanner(ScanModule):
    """
    Mobile API Security Scanner.
    
    Tests for:
    - Certificate pinning bypass indicators
    - Device binding bypass
    - Mobile-specific authentication weaknesses
    - API key exposure in responses
    - Push notification token exposure
    - Biometric bypass patterns
    - Root/Jailbreak detection bypass
    - Session handling weaknesses
    - Insecure data storage indicators
    - Deep link vulnerabilities
    """
    
    name = "mobile_api_scanner"
    
    # Common mobile API endpoints
    MOBILE_ENDPOINTS = [
        "/api/v1/mobile",
        "/api/mobile",
        "/mobile/api",
        "/app/api",
        "/api/app",
        "/m/api",
        "/api/m",
        "/api/v1/app",
        "/api/v2/mobile",
        "/api/v1/device",
        "/api/device",
    ]
    
    # Mobile authentication endpoints
    AUTH_ENDPOINTS = [
        "/api/auth/mobile",
        "/api/mobile/login",
        "/api/mobile/auth",
        "/api/device/register",
        "/api/device/auth",
        "/api/biometric/auth",
        "/api/fingerprint/verify",
        "/api/faceid/verify",
        "/api/touchid/verify",
        "/api/pin/verify",
        "/api/otp/verify",
        "/api/push/register",
        "/api/token/refresh",
    ]
    
    # Common mobile User-Agents
    MOBILE_USER_AGENTS = {
        "ios": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
        "android": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "ios_app": "MyApp/1.0 (iOS 17.0; iPhone14,2)",
        "android_app": "MyApp/1.0 (Android 14; Pixel 8)",
    }
    
    # Sensitive data patterns in mobile responses
    SENSITIVE_PATTERNS = {
        "api_key": r'["\']?(api[_-]?key|apikey)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
        "secret_key": r'["\']?(secret[_-]?key|secretkey)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
        "push_token": r'["\']?(push[_-]?token|fcm[_-]?token|apns[_-]?token|device[_-]?token)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-:]{50,})["\']?',
        "device_id": r'["\']?(device[_-]?id|udid|android[_-]?id|idfa|idfv)["\']?\s*[:=]\s*["\']?([a-fA-F0-9\-]{16,})["\']?',
        "private_key": r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',
        "jwt_secret": r'["\']?(jwt[_-]?secret|token[_-]?secret)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?',
        "firebase_key": r'AIza[0-9A-Za-z\-_]{35}',
        "google_api": r'AIza[0-9A-Za-z_-]{35}',
        "aws_key": r'AKIA[0-9A-Z]{16}',
    }
    
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
        """Scan for mobile API security vulnerabilities."""

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        findings: list[Finding] = []
        
        base_url = f"https://{host}" if not host.startswith("http") else host
        
        async with get_scan_client(verify_ssl=False, timeout=self.timeout) as client:
            # Discover mobile endpoints
            mobile_endpoints = await self._discover_mobile_endpoints(
                client, base_url, rate_limiter
            )
            
            # Test certificate pinning indicators
            pinning_findings = await self._test_cert_pinning(
                client, base_url, rate_limiter
            )
            findings.extend(pinning_findings)
            
            # Test device binding
            binding_findings = await self._test_device_binding(
                client, base_url, mobile_endpoints, rate_limiter
            )
            findings.extend(binding_findings)
            
            # Test biometric bypass
            biometric_findings = await self._test_biometric_bypass(
                client, base_url, rate_limiter
            )
            findings.extend(biometric_findings)
            
            # Test root/jailbreak detection
            root_findings = await self._test_root_detection_bypass(
                client, base_url, mobile_endpoints, rate_limiter
            )
            findings.extend(root_findings)
            
            # Test sensitive data exposure
            exposure_findings = await self._test_data_exposure(
                client, base_url, mobile_endpoints, rate_limiter
            )
            findings.extend(exposure_findings)
            
            # Test push notification security
            push_findings = await self._test_push_notification_security(
                client, base_url, rate_limiter
            )
            findings.extend(push_findings)
            
            # Test deep link vulnerabilities
            deeplink_findings = await self._test_deep_links(
                client, base_url, rate_limiter
            )
            findings.extend(deeplink_findings)
            
            # Test mobile session handling
            session_findings = await self._test_mobile_session(
                client, base_url, rate_limiter
            )
            findings.extend(session_findings)
            
            # Test API versioning issues
            version_findings = await self._test_api_versioning(
                client, base_url, rate_limiter
            )
            findings.extend(version_findings)
        
        return findings
    
    async def _discover_mobile_endpoints(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[str]:
        """Discover mobile-specific API endpoints."""
        endpoints = []
        
        all_endpoints = self.MOBILE_ENDPOINTS + self.AUTH_ENDPOINTS
        
        for path in all_endpoints:
            await rate_limiter.acquire()
            
            try:
                url = urljoin(base_url, path)
                headers = {"User-Agent": self.MOBILE_USER_AGENTS["ios"]}
                
                response = await client.get(url, headers=headers)
                
                if response.status_code != 404:
                    endpoints.append(url)
                    logger.info(f"Mobile endpoint found: {url}")
                    
            except Exception as e:
                logger.debug(f"Error checking {path}: {e}")
        
        return endpoints
    
    async def _test_cert_pinning(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Check for certificate pinning configuration indicators."""
        findings = []
        
        await rate_limiter.acquire()
        
        try:
            # Check for common pinning configuration endpoints
            config_endpoints = [
                "/.well-known/security.txt",
                "/api/config",
                "/api/mobile/config",
                "/api/app/config",
            ]
            
            for endpoint in config_endpoints:
                url = urljoin(base_url, endpoint)
                response = await client.get(url)
                
                if response.status_code == 200:
                    # Check for pinning configuration
                    response_text = response.text.lower()
                    
                    if "pin-sha256" in response_text or "certificate" in response_text:
                        # Check if pinning is mentioned but might be misconfigured
                        if "disable" in response_text or "bypass" in response_text:
                            findings.append(Finding(
                                name="Certificate Pinning Bypass Indicator",
                                severity=Severity.HIGH,
                                confidence_score=65.0,
                                description="Certificate pinning configuration suggests bypass capability",
                                endpoint=url,
                                evidence=["Pinning bypass indicators found in config"],
                                cwe_id="CWE-295",
                                cvss_score=7.4,
                                remediation="Enforce certificate pinning without bypass options. "
                                           "Remove debug/bypass flags in production.",
                            ))
            
            # Check if API accepts requests without proper cert validation
            # Since we use verify=False, if it works, pinning may not be enforced server-side
            response = await client.get(base_url, headers={
                "User-Agent": self.MOBILE_USER_AGENTS["ios_app"]
            })
            
            if response.status_code == 200:
                findings.append(Finding(
                    vuln_type=VulnType.SSL_TLS_ISSUE,
                    name="Server-Side Certificate Pinning Not Enforced",
                    severity=Severity.INFO,
                    confidence_score=65.0,
                    description="Server accepts connections without mutual TLS/cert pinning. "
                               "Client-side pinning should still be tested on mobile app.",
                    endpoint=base_url,
                    evidence=["API responds without certificate validation"],
                    cwe_id="CWE-295",
                    remediation="Consider implementing mutual TLS for sensitive mobile APIs.",
                ))
                
        except Exception as e:
            logger.debug(f"Error testing cert pinning: {e}")
        
        return findings
    
    async def _test_device_binding(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        mobile_endpoints: list[str],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test device binding security."""
        findings = []
        
        # Generate fake device IDs
        fake_device_ids = [
            secrets.token_hex(16),  # Random
            "00000000-0000-0000-0000-000000000000",  # Null UUID
            "ffffffff-ffff-ffff-ffff-ffffffffffff",  # Max UUID
            "device_id_test_123",  # Simple test
            "emulator",  # Emulator indicator
        ]
        
        device_headers_sets = [
            {
                "X-Device-ID": fake_device_ids[0],
                "X-Device-Type": "iOS",
                "X-App-Version": "1.0.0",
            },
            {
                "X-Device-Id": fake_device_ids[1],
                "X-Platform": "Android",
            },
            {
                "Device-ID": fake_device_ids[2],
                "X-Device-Model": "iPhone14,2",
            },
            {
                "X-UDID": fake_device_ids[3],
                "X-Device-Fingerprint": secrets.token_hex(32),
            },
        ]
        
        # Test device registration/binding endpoints
        binding_endpoints = [
            "/api/device/register",
            "/api/device/bind",
            "/api/mobile/register",
            "/api/app/register",
        ]
        
        for endpoint in binding_endpoints:
            url = urljoin(base_url, endpoint)
            
            for headers in device_headers_sets:
                await rate_limiter.acquire()
                
                try:
                    headers["User-Agent"] = self.MOBILE_USER_AGENTS["ios_app"]
                    
                    # Try POST with device info
                    payload = {
                        "device_id": fake_device_ids[0],
                        "device_type": "ios",
                        "push_token": "fake_push_token_" + secrets.token_hex(20),
                    }
                    
                    response = await client.post(url, json=payload, headers=headers)
                    
                    if response.status_code in [200, 201]:
                        try:
                            data = response.json()
                            
                            # Check if device was registered without validation
                            if "token" in str(data).lower() or "success" in str(data).lower():
                                findings.append(Finding(
                                    name="Weak Device Binding",
                                    severity=Severity.HIGH,
                                    confidence_score=65.0,
                                    description="Device registration accepts arbitrary device IDs "
                                               "without proper validation",
                                    endpoint=url,
                                    evidence=[
                                        f"Fake device ID accepted: {fake_device_ids[0][:16]}...",
                                        "Device registered successfully",
                                    ],
                                    cwe_id="CWE-287",
                                    cvss_score=7.5,
                                    remediation="Implement proper device attestation (SafetyNet/DeviceCheck). "
                                               "Validate device fingerprints server-side.",
                                ))
                                # BUG-FIX 2026-02-08: Removed break - continue testing other variations
                        except json.JSONDecodeError:
                            pass
                            
                except Exception as e:
                    logger.debug(f"Error testing device binding: {e}")
        
        return findings
    
    async def _test_biometric_bypass(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test biometric authentication bypass."""
        findings = []
        
        biometric_endpoints = [
            "/api/biometric/verify",
            "/api/biometric/auth",
            "/api/fingerprint/verify",
            "/api/faceid/verify",
            "/api/touchid/verify",
            "/api/auth/biometric",
        ]
        
        bypass_payloads = [
            # Direct bypass attempts
            {"biometric_verified": True, "bypass": True},
            {"verified": True, "result": "success"},
            {"auth_result": "authenticated", "method": "biometric"},
            {"status": "verified", "biometric": True},
            # Replay attack simulation
            {"biometric_token": "cached_token_123", "timestamp": 0},
            # Type confusion
            {"verified": 1},
            {"verified": "true"},
        ]
        
        for endpoint in biometric_endpoints:
            url = urljoin(base_url, endpoint)
            
            await rate_limiter.acquire()
            
            try:
                # Check if endpoint exists
                check = await client.get(url, headers={
                    "User-Agent": self.MOBILE_USER_AGENTS["ios_app"]
                })
                
                if check.status_code == 404:
                    continue
                
                for payload in bypass_payloads:
                    await rate_limiter.acquire()
                    
                    response = await client.post(
                        url,
                        json=payload,
                        headers={"User-Agent": self.MOBILE_USER_AGENTS["ios_app"]}
                    )
                    
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            
                            # Check for successful auth
                            success_indicators = ["token", "authenticated", "success", "valid"]
                            if any(ind in str(data).lower() for ind in success_indicators):
                                findings.append(Finding(
                                    name="Biometric Authentication Bypass",
                                    severity=Severity.CRITICAL,
                                    confidence_score=65.0,
                                    description="Biometric verification may be bypassable via "
                                               "parameter manipulation",
                                    endpoint=url,
                                    evidence=[
                                        f"Bypass payload: {json.dumps(payload)}",
                                        "Authentication success indicators in response",
                                    ],
                                    cwe_id="CWE-287",
                                    cvss_score=9.1,
                                    remediation="Verify biometric results server-side. "
                                               "Use platform APIs (LAContext, BiometricPrompt) properly. "
                                               "Never trust client-supplied verification results.",
                                ))
                                # BUG-FIX 2026-02-08: Removed break - continue testing other variations
                        except json.JSONDecodeError:
                            pass
                            
            except Exception as e:
                logger.debug(f"Error testing biometric bypass: {e}")
        
        return findings
    
    async def _test_root_detection_bypass(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        mobile_endpoints: list[str],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test root/jailbreak detection bypass."""
        findings = []
        
        # Headers indicating rooted/jailbroken device
        rooted_headers = [
            {"X-Device-Rooted": "false"},
            {"X-Jailbroken": "false"},
            {"X-Integrity-Check": "passed"},
            {"X-Device-Integrity": "valid"},
            {"X-SafetyNet": "true"},
            {"X-Device-Attestation": base64.b64encode(b'{"integrity":true}').decode()},
        ]
        
        for endpoint in mobile_endpoints[:5]:  # Test first 5 endpoints
            for headers in rooted_headers:
                await rate_limiter.acquire()
                
                try:
                    headers["User-Agent"] = self.MOBILE_USER_AGENTS["android_app"]
                    
                    response = await client.get(endpoint, headers=headers)
                    
                    if response.status_code == 200:
                        # Check if request succeeded with fake attestation
                        if "X-Device-Attestation" in headers:
                            findings.append(Finding(
                                name="Client-Side Root Detection Only",
                                severity=Severity.MEDIUM,
                                confidence_score=40.0,
                                description="API accepts self-reported device integrity status. "
                                           "Root/jailbreak detection may be bypassable.",
                                endpoint=endpoint,
                                evidence=[
                                    "Request with fake integrity headers accepted",
                                    f"Headers: {list(headers.keys())}",
                                ],
                                cwe_id="CWE-602",
                                cvss_score=5.3,
                                remediation="Implement server-side device attestation verification "
                                           "(SafetyNet Attestation API, DeviceCheck). "
                                           "Don't trust client-reported integrity status.",
                            ))
                            # BUG-FIX 2026-02-08: Removed break - continue testing other payloads
                            
                except Exception as e:
                    logger.debug(f"Error testing root detection: {e}")
        
        return findings
    
    async def _test_data_exposure(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        mobile_endpoints: list[str],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for sensitive data exposure in API responses."""
        findings = []
        
        # Test all mobile endpoints and common sensitive paths
        test_urls = mobile_endpoints + [
            urljoin(base_url, "/api/config"),
            urljoin(base_url, "/api/settings"),
            urljoin(base_url, "/api/user"),
            urljoin(base_url, "/api/debug"),
            urljoin(base_url, "/.env"),
            urljoin(base_url, "/config.json"),
        ]
        
        for url in test_urls:
            await rate_limiter.acquire()
            
            try:
                response = await client.get(url, headers={
                    "User-Agent": self.MOBILE_USER_AGENTS["ios_app"]
                })
                
                if response.status_code != 200:
                    continue
                
                response_text = response.text
                
                # Check for sensitive patterns
                for pattern_name, pattern in self.SENSITIVE_PATTERNS.items():
                    matches = re.findall(pattern, response_text, re.IGNORECASE)
                    
                    if matches:
                        # Redact sensitive values for evidence
                        redacted = [m[:8] + "..." if isinstance(m, str) else m[0][:8] + "..." for m in matches[:3]]
                        
                        severity = "CRITICAL" if pattern_name in ["private_key", "aws_key", "jwt_secret"] else "HIGH"
                        
                        findings.append(Finding(
                            name=f"Sensitive Data Exposure - {pattern_name}",
                            severity=severity,
                            confidence_score=85.0,
                            description=f"API response contains exposed {pattern_name}",
                            endpoint=url,
                            evidence=[
                                f"Pattern: {pattern_name}",
                                f"Matches found: {len(matches)}",
                                f"Sample (redacted): {redacted}",
                            ],
                            cwe_id="CWE-200",
                            cvss_score=7.5 if severity == "HIGH" else 9.1,
                            remediation="Remove sensitive data from API responses. "
                                       "Use environment variables for secrets. "
                                       "Implement proper access controls.",
                        ))
                        
            except Exception as e:
                logger.debug(f"Error testing data exposure: {e}")
        
        return findings
    
    async def _test_push_notification_security(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test push notification token security."""
        findings = []
        
        push_endpoints = [
            "/api/push/register",
            "/api/push/token",
            "/api/notifications/register",
            "/api/device/push",
            "/api/fcm/register",
            "/api/apns/register",
        ]
        
        for endpoint in push_endpoints:
            url = urljoin(base_url, endpoint)
            
            await rate_limiter.acquire()
            
            try:
                # Try registering with fake push token
                payload = {
                    "push_token": "fake_fcm_token_" + secrets.token_hex(30),
                    "device_id": secrets.token_hex(16),
                    "platform": "android",
                }
                
                response = await client.post(
                    url,
                    json=payload,
                    headers={"User-Agent": self.MOBILE_USER_AGENTS["android_app"]}
                )
                
                if response.status_code in [200, 201]:
                    findings.append(Finding(
                        name="Push Token Registration Without Validation",
                        severity=Severity.MEDIUM,
                        confidence_score=65.0,
                        description="Push notification tokens can be registered without validation",
                        endpoint=url,
                        evidence=[
                            "Arbitrary push token accepted",
                            "Could allow push notification hijacking",
                        ],
                        cwe_id="CWE-287",
                        cvss_score=5.3,
                        remediation="Validate push tokens with FCM/APNs before registration. "
                                   "Tie tokens to authenticated sessions.",
                    ))
                    
                # Test token enumeration
                await rate_limiter.acquire()
                
                list_response = await client.get(
                    urljoin(base_url, "/api/push/tokens"),
                    headers={"User-Agent": self.MOBILE_USER_AGENTS["ios_app"]}
                )
                
                if list_response.status_code == 200:
                    try:
                        data = list_response.json()
                        if isinstance(data, list) and len(data) > 0:
                            findings.append(Finding(
                                name="Push Token Enumeration",
                                severity=Severity.MEDIUM,
                                confidence_score=85.0,
                                description="Push notification tokens can be enumerated",
                                endpoint=urljoin(base_url, "/api/push/tokens"),
                                evidence=["Token list endpoint accessible"],
                                cwe_id="CWE-200",
                                remediation="Restrict access to push token lists.",
                            ))
                    except json.JSONDecodeError:
                        pass
                        
            except Exception as e:
                logger.debug(f"Error testing push security: {e}")
        
        return findings
    
    async def _test_deep_links(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test deep link/universal link security."""
        findings = []
        
        # Check for deep link configuration files
        config_files = [
            "/.well-known/assetlinks.json",  # Android App Links
            "/.well-known/apple-app-site-association",  # iOS Universal Links
            "/apple-app-site-association",
        ]
        
        for config_file in config_files:
            await rate_limiter.acquire()
            
            try:
                url = urljoin(base_url, config_file)
                response = await client.get(url)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        
                        # Check for overly permissive configurations
                        data_str = json.dumps(data).lower()
                        
                        if "*" in data_str or "wildcard" in data_str:
                            findings.append(Finding(
                                name="Overly Permissive Deep Link Configuration",
                                severity=Severity.MEDIUM,
                                confidence_score=85.0,
                                description="Deep link configuration contains wildcards",
                                endpoint=url,
                                evidence=["Wildcard patterns in app links config"],
                                cwe_id="CWE-284",
                                cvss_score=5.3,
                                remediation="Use specific path patterns. Avoid wildcards.",
                            ))
                        
                        # Check for missing signature verification (Android)
                        if "assetlinks" in config_file:
                            if "sha256_cert_fingerprints" not in data_str:
                                findings.append(Finding(
                                    name="Missing Certificate Fingerprint in App Links",
                                    severity=Severity.MEDIUM,
                                    confidence_score=85.0,
                                    description="Android App Links missing certificate fingerprint",
                                    endpoint=url,
                                    evidence=["No sha256_cert_fingerprints found"],
                                    cwe_id="CWE-295",
                                    remediation="Add SHA256 certificate fingerprints to assetlinks.json",
                                ))
                                
                    except json.JSONDecodeError:
                        pass
                        
            except Exception as e:
                logger.debug(f"Error testing deep links: {e}")
        
        return findings
    
    async def _test_mobile_session(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test mobile session security."""
        findings = []
        
        await rate_limiter.acquire()
        
        try:
            # Check for long-lived mobile tokens
            login_endpoints = [
                "/api/mobile/login",
                "/api/auth/mobile",
                "/api/login",
            ]
            
            for endpoint in login_endpoints:
                url = urljoin(base_url, endpoint)
                
                response = await client.post(
                    url,
                    json={"username": "test", "password": "test"},
                    headers={"User-Agent": self.MOBILE_USER_AGENTS["ios_app"]}
                )
                
                if response.status_code in [200, 401]:
                    # Check token expiration in response
                    try:
                        data = response.json()
                        
                        # Look for very long expiration times
                        if "expires" in str(data).lower() or "exp" in str(data):
                            exp_patterns = [
                                r'"expires_in"\s*:\s*(\d+)',
                                r'"exp"\s*:\s*(\d+)',
                            ]
                            
                            for pattern in exp_patterns:
                                match = re.search(pattern, response.text)
                                if match:
                                    exp_value = int(match.group(1))
                                    
                                    # If expiration > 30 days (in seconds)
                                    if exp_value > 2592000:
                                        findings.append(Finding(
                                            name="Long-Lived Mobile Session Token",
                                            severity=Severity.MEDIUM,
                                            confidence_score=85.0,
                                            description=f"Mobile token has very long expiration: {exp_value} seconds",
                                            endpoint=url,
                                            evidence=[f"Token expires in {exp_value // 86400} days"],
                                            cwe_id="CWE-613",
                                            remediation="Use shorter token lifetimes with refresh tokens. "
                                                       "Implement proper session management.",
                                        ))
                                        # BUG-FIX 2026-02-08: Removed break - continue testing other endpoints
                                        
                    except (json.JSONDecodeError, ValueError):
                        pass
                        
        except Exception as e:
            logger.debug(f"Error testing mobile session: {e}")
        
        return findings
    
    async def _test_api_versioning(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for deprecated/vulnerable API versions."""
        findings = []
        
        api_versions = [
            "/api/v1/",
            "/api/v2/",
            "/api/v3/",
            "/api/v0/",  # Development version
            "/api/beta/",
            "/api/dev/",
            "/api/debug/",
            "/api/test/",
        ]
        
        found_versions = []
        
        for version in api_versions:
            await rate_limiter.acquire()
            
            try:
                url = urljoin(base_url, version)
                response = await client.get(url, headers={
                    "User-Agent": self.MOBILE_USER_AGENTS["ios_app"]
                })
                
                # Only 2xx responses prove the endpoint exists
                # 404 = not found, 5xx = server error, neither is evidence
                if 200 <= response.status_code < 300:
                    found_versions.append(version)

                    # Check for debug/dev versions in production
                    if any(x in version for x in ["dev", "debug", "test", "beta", "v0"]):
                        findings.append(Finding(
                            name="Development API Version Exposed",
                            severity=Severity.HIGH,
                            confidence_score=85.0,
                            description=f"Development/debug API version accessible: {version}",
                            endpoint=url,
                            evidence=[
                                f"Endpoint: {version}",
                                f"Status: {response.status_code}",
                            ],
                            cwe_id="CWE-489",
                            cvss_score=6.5,
                            remediation="Disable development API versions in production. "
                                       "Use proper environment separation.",
                        ))
                        
            except Exception as e:
                logger.debug(f"Error testing API version: {e}")
        
        # Check if multiple versions are available
        if len(found_versions) > 2:
            findings.append(Finding(
                name="Multiple API Versions Exposed",
                severity=Severity.LOW,
                confidence_score=85.0,
                description="Multiple API versions accessible - older versions may have vulnerabilities",
                endpoint=base_url,
                evidence=[f"Found versions: {found_versions}"],
                cwe_id="CWE-1104",
                remediation="Deprecate and remove old API versions. "
                           "Document supported versions.",
            ))
        
        return findings
