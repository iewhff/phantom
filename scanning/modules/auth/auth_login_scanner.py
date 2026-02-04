"""
Login and Credential Security Scanner

Enterprise-grade login security testing including:
- Default credential testing with smart form detection
- Brute force protection assessment
- Password policy checking
- Account enumeration detection
- MFA bypass testing
- Password reset flow vulnerabilities

CWE Coverage:
- CWE-287: Improper Authentication
- CWE-307: Improper Restriction of Excessive Authentication Attempts
- CWE-521: Weak Password Requirements
- CWE-640: Weak Password Recovery Mechanism
- CWE-798: Use of Hard-coded Credentials

Author: PetNTester AI Enterprise
Version: 2.0.0
"""

from __future__ import annotations

import re
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

import httpx

from scanning.vuln_scanner import Finding
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter
from utils.http_client import is_brute_force_allowed, is_bug_bounty_mode

from .auth_base import (
    ENTERPRISE_CREDENTIALS,
    LOGIN_PATHS,
    extract_form_fields,
    check_successful_login,
)

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


class LoginScanner:
    """
    Login and Credential Security Scanner

    Tests for login-related vulnerabilities including default credentials,
    brute force protection, password policy, and account enumeration.
    """

    def __init__(self, settings: Settings) -> None:
        self.timeout = settings.timeouts.request_timeout
        self.max_attempts = 5  # Limit to avoid lockout
        self.discovered_login_pages: list[str] = []

        # BUG BOUNTY SAFETY: Check if brute force is allowed
        self._brute_force_allowed = is_brute_force_allowed()
        self._bug_bounty_mode = is_bug_bounty_mode()

        if self._bug_bounty_mode and not self._brute_force_allowed:
            logger.info(
                "🛡️ LoginScanner: Brute force testing DISABLED in bug bounty mode - "
                "credential testing will be limited to avoid account lockouts"
            )

    async def scan(
        self,
        base_url: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Comprehensive login security scan.

        Args:
            base_url: Target base URL
            asset_data: Asset information from discovery
            rate_limiter: Rate limiter instance
        """
        findings = []

        # Find login pages
        login_pages = await self._find_login_pages(base_url, rate_limiter)
        self.discovered_login_pages = login_pages

        for login_url in login_pages:
            # BUG BOUNTY SAFETY: Skip credential testing if brute force is disabled
            if self._brute_force_allowed:
                # Test default credentials
                cred_findings = await self._test_default_credentials(login_url, rate_limiter)
                findings.extend(cred_findings)

                # Check brute force protection
                brute_findings = await self._check_brute_force_protection(login_url, rate_limiter)
                findings.extend(brute_findings)
            else:
                logger.info(
                    f"🛡️ Skipping credential testing for {login_url} - brute force disabled"
                )

            # Check password policy (safe - doesn't try credentials)
            policy_findings = await self._check_password_policy(base_url, login_url, rate_limiter)
            findings.extend(policy_findings)

            # Account enumeration (limited testing)
            if self._brute_force_allowed:
                enum_findings = await self._check_account_enumeration(login_url, rate_limiter)
                findings.extend(enum_findings)
            else:
                logger.debug("Skipping account enumeration - brute force disabled")

        # MFA bypass detection
        mfa_findings = await self._check_mfa_bypass(base_url, asset_data, rate_limiter)
        findings.extend(mfa_findings)

        # Password reset vulnerabilities
        reset_findings = await self._check_password_reset_flaws(base_url, rate_limiter)
        findings.extend(reset_findings)

        return findings

    async def _find_login_pages(
        self,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[str]:
        """Find login pages on the target."""
        login_pages = []

        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for path in LOGIN_PATHS:
                await rate_limiter.acquire()

                url = urljoin(base_url, path)
                try:
                    response = await client.get(url, follow_redirects=True)

                    if response.status_code == 200:
                        content = response.text.lower()

                        login_indicators = [
                            'type="password"',
                            "type='password'",
                            'name="password"',
                            'id="password"',
                            'login',
                            'signin',
                            'authenticate',
                        ]

                        if any(indicator in content for indicator in login_indicators):
                            login_pages.append(str(response.url))
                            logger.info(f"Found login page: {response.url}")

                except (httpx.HTTPError, httpx.TimeoutException, OSError) as e:
                    logger.debug(f"Error checking {url}: {e}")

        return list(set(login_pages))

    async def _test_default_credentials(
        self,
        login_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test for default credentials."""
        findings = []

        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                response = await client.get(login_url)
                form_data = extract_form_fields(response.text)

                if not form_data:
                    return findings

                username_field = form_data.get("username_field", "username")
                password_field = form_data.get("password_field", "password")
                action = form_data.get("action", login_url)

                # Test limited credentials to avoid lockout
                for username, password in ENTERPRISE_CREDENTIALS[:self.max_attempts]:
                    await rate_limiter.acquire()

                    test_data = {
                        username_field: username,
                        password_field: password,
                    }

                    # Include hidden fields
                    for field, value in form_data.get("hidden_fields", {}).items():
                        test_data[field] = value

                    try:
                        login_response = await client.post(
                            action,
                            data=test_data,
                            follow_redirects=True,
                        )

                        if check_successful_login(login_response, response):
                            findings.append(Finding(
                                type="authentication",
                                name="Default Credentials",
                                severity="CRITICAL",
                                description=f"Default credentials found: {username}:{password}. "
                                           f"The application accepts commonly known default credentials.",
                                host=login_url,
                                matched_at=login_url,
                                evidence=[
                                    f"Username: {username}",
                                    f"Password: {password}",
                                    "Response indicates successful login",
                                ],
                                cvss_score=9.8,
                                cwe="CWE-798",
                                remediation="Change all default credentials immediately. "
                                           "Implement strong password requirements. "
                                           "Force password change on first login.",
                                references=[
                                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials"
                                ],
                            ).to_dict())
                            return findings

                    except (httpx.HTTPError, httpx.TimeoutException, OSError) as e:
                        logger.debug(f"Login test failed: {e}")

        except (httpx.HTTPError, httpx.TimeoutException, OSError) as e:
            logger.debug(f"Default credential test failed: {e}")

        return findings

    async def _check_brute_force_protection(
        self,
        login_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Check for brute force protection mechanisms."""
        findings = []

        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                response = await client.get(login_url)
                form_data = extract_form_fields(response.text)

                if not form_data:
                    return findings

                username_field = form_data.get("username_field", "username")
                password_field = form_data.get("password_field", "password")
                action = form_data.get("action", login_url)

                failed_attempts = 0
                blocked = False

                for i in range(10):
                    await rate_limiter.acquire()

                    test_data = {
                        username_field: "testuser",
                        password_field: f"wrongpassword{i}",
                    }

                    try:
                        login_response = await client.post(action, data=test_data)

                        if login_response.status_code == 429:
                            blocked = True
                            break

                        response_text = login_response.text.lower()
                        if any(word in response_text for word in ["locked", "blocked", "too many"]):
                            blocked = True
                            break

                        failed_attempts += 1

                    except (httpx.HTTPError, httpx.TimeoutException, OSError):
                        break

                if not blocked and failed_attempts >= 10:
                    findings.append(Finding(
                        type="authentication",
                        name="Missing Brute Force Protection",
                        severity="MEDIUM",
                        description="The login page does not implement brute force protection. "
                                   "An attacker could attempt unlimited password guesses.",
                        host=login_url,
                        matched_at=login_url,
                        evidence=[
                            f"Completed {failed_attempts} failed login attempts",
                            "No rate limiting or account lockout detected",
                        ],
                        cvss_score=5.3,
                        cwe="CWE-307",
                        remediation="Implement account lockout after failed attempts. "
                                   "Add CAPTCHA after failed attempts. "
                                   "Implement rate limiting on login endpoints.",
                        references=[
                            "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks"
                        ],
                    ).to_dict())

        except (httpx.HTTPError, httpx.TimeoutException, OSError) as e:
            logger.debug(f"Brute force protection check failed: {e}")

        return findings

    async def _check_password_policy(
        self,
        base_url: str,
        login_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Check password policy enforcement."""
        findings = []

        registration_paths = ["/register", "/signup", "/create-account", "/join"]

        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for path in registration_paths:
                await rate_limiter.acquire()

                url = urljoin(base_url, path)
                try:
                    response = await client.get(url)

                    if response.status_code == 200 and 'password' in response.text.lower():
                        content = response.text.lower()

                        has_policy_indicator = any([
                            "minimum" in content and "character" in content,
                            "at least" in content,
                            "must contain" in content,
                            "password requirements" in content,
                            "strong password" in content,
                        ])

                        if not has_policy_indicator:
                            findings.append(Finding(
                                type="authentication",
                                name="Weak Password Policy Indicators",
                                severity="LOW",
                                description="Registration page does not appear to enforce or communicate "
                                           "password complexity requirements.",
                                host=base_url,
                                matched_at=url,
                                evidence=["No password policy indicators found on registration page"],
                                cvss_score=3.7,
                                cwe="CWE-521",
                                remediation="Implement and display password complexity requirements.",
                            ).to_dict())
                        break

                except (httpx.HTTPError, httpx.TimeoutException, OSError) as e:
                    logger.debug(f"Error checking registration: {e}")

        return findings

    async def _check_account_enumeration(
        self,
        login_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Check for account enumeration via timing and response differences."""
        findings = []

        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                response = await client.get(login_url)
                form_data = extract_form_fields(response.text)

                if not form_data.get("password_field"):
                    return findings

                username_field = form_data.get("username_field", "username")
                password_field = form_data.get("password_field", "password")
                action = form_data.get("action", login_url)

                test_users = ["admin", "test", "user", "nonexistent_user_xyz123"]
                timings = {}
                responses_text = {}

                for username in test_users:
                    await rate_limiter.acquire()

                    test_data = {
                        username_field: username,
                        password_field: "wrongpassword123",
                    }

                    for field, value in form_data.get("hidden_fields", {}).items():
                        test_data[field] = value

                    start_time = time.time()
                    try:
                        resp = await client.post(action, data=test_data)
                        elapsed = time.time() - start_time
                        timings[username] = elapsed
                        responses_text[username] = resp.text[:500]
                    except (httpx.HTTPError, httpx.TimeoutException, OSError):
                        continue

                if len(timings) < 2:
                    return findings

                # Analyze timing differences
                avg_timing = sum(timings.values()) / len(timings)
                for user, timing in timings.items():
                    if abs(timing - avg_timing) > 0.5:
                        findings.append(Finding(
                            type="authentication",
                            name="Account Enumeration via Timing",
                            severity="MEDIUM",
                            description=f"Timing difference detected for user '{user}'. "
                                       f"This may allow attackers to enumerate valid usernames.",
                            host=login_url,
                            matched_at=login_url,
                            evidence=[
                                f"User '{user}' timing: {timing:.3f}s",
                                f"Average timing: {avg_timing:.3f}s",
                                f"Difference: {abs(timing - avg_timing):.3f}s",
                            ],
                            cvss_score=5.3,
                            cwe="CWE-203",
                            remediation="Ensure consistent response times for all login attempts. "
                                       "Use constant-time comparison functions.",
                        ).to_dict())
                        break

                # Analyze response differences
                unique_responses = set()
                for user, text in responses_text.items():
                    normalized = re.sub(r'[0-9]+', 'N', text.lower())
                    unique_responses.add(normalized)

                if len(unique_responses) > 1:
                    findings.append(Finding(
                        type="authentication",
                        name="Account Enumeration via Response Differences",
                        severity="MEDIUM",
                        description="Different error messages for valid vs invalid usernames. "
                                   "This allows attackers to enumerate valid accounts.",
                        host=login_url,
                        matched_at=login_url,
                        evidence=["Response messages differ based on username existence"],
                        cvss_score=5.3,
                        cwe="CWE-204",
                        remediation="Use identical error messages for all failed login attempts. "
                                   "e.g., 'Invalid username or password'",
                    ).to_dict())

        except (httpx.HTTPError, httpx.TimeoutException, OSError) as e:
            logger.debug(f"Account enumeration check failed: {e}")

        return findings

    async def _check_mfa_bypass(
        self,
        base_url: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Check for MFA bypass vulnerabilities."""
        findings = []

        mfa_paths = [
            "/mfa", "/2fa", "/otp", "/verify", "/confirm",
            "/api/mfa", "/api/2fa", "/auth/mfa", "/auth/verify",
        ]

        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for path in mfa_paths:
                await rate_limiter.acquire()

                url = urljoin(base_url, path)

                try:
                    resp = await client.get(url)

                    if resp.status_code not in [200, 302]:
                        continue

                    findings.append(Finding(
                        type="authentication",
                        name="MFA Endpoint Discovered",
                        severity="INFO",
                        description=f"MFA endpoint found at {path}. Manual testing recommended.",
                        host=base_url,
                        matched_at=url,
                        evidence=[f"Endpoint: {url}", f"Status: {resp.status_code}"],
                        cvss_score=0.0,
                        cwe="CWE-287",
                        remediation="Ensure MFA cannot be bypassed. Test all bypass techniques.",
                    ).to_dict())

                    # Test direct access bypass
                    protected_paths = ["/dashboard", "/home", "/api/me", "/profile"]
                    for protected in protected_paths:
                        await rate_limiter.acquire()
                        try:
                            bypass_resp = await client.get(urljoin(base_url, protected))
                            if bypass_resp.status_code == 200 and len(bypass_resp.text) > 500:
                                findings.append(Finding(
                                    type="authentication",
                                    name="Potential MFA Bypass - Direct Access",
                                    severity="HIGH",
                                    description="Protected resource accessible without completing MFA. "
                                               "User may be able to skip MFA step.",
                                    host=base_url,
                                    matched_at=urljoin(base_url, protected),
                                    evidence=[
                                        f"MFA at: {url}",
                                        f"Protected resource: {protected}",
                                        f"Response length: {len(bypass_resp.text)}",
                                    ],
                                    cvss_score=8.1,
                                    cwe="CWE-287",
                                    remediation="Enforce MFA completion before allowing access. "
                                               "Use server-side session state to track MFA status.",
                                ).to_dict())
                                break
                        except (httpx.HTTPError, httpx.TimeoutException, OSError):
                            continue

                    break

                except (httpx.HTTPError, httpx.TimeoutException, OSError) as e:
                    logger.debug(f"MFA check failed for {url}: {e}")

        return findings

    async def _check_password_reset_flaws(
        self,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Check for password reset flow vulnerabilities."""
        findings = []

        reset_paths = [
            "/password/reset", "/forgot-password", "/reset-password",
            "/password-reset", "/account/recover", "/auth/forgot",
            "/api/password/reset", "/api/forgot-password",
        ]

        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for path in reset_paths:
                await rate_limiter.acquire()

                url = urljoin(base_url, path)

                try:
                    resp = await client.get(url)

                    if resp.status_code != 200:
                        continue

                    findings.append(Finding(
                        type="authentication",
                        name="Password Reset Endpoint Found",
                        severity="INFO",
                        description=f"Password reset functionality at {path}.",
                        host=base_url,
                        matched_at=url,
                        evidence=[f"Endpoint: {url}"],
                        cvss_score=0.0,
                        cwe="CWE-640",
                        remediation="Review password reset flow for security issues.",
                    ).to_dict())

                    # Check for host header injection
                    await rate_limiter.acquire()
                    try:
                        evil_host_resp = await client.get(
                            url,
                            headers={"Host": "evil.com"}
                        )

                        if "evil.com" in evil_host_resp.text:
                            findings.append(Finding(
                                type="authentication",
                                name="Password Reset Host Header Injection",
                                severity="HIGH",
                                description="Password reset may be vulnerable to host header injection. "
                                           "Reset links could be sent to attacker-controlled domain.",
                                host=base_url,
                                matched_at=url,
                                evidence=[
                                    "Host header reflected in response",
                                    "Test header: Host: evil.com",
                                ],
                                cvss_score=8.1,
                                cwe="CWE-640",
                                remediation="Use a whitelist for allowed hosts. "
                                           "Generate absolute URLs from configuration, not headers.",
                            ).to_dict())
                    except (httpx.HTTPError, httpx.TimeoutException, OSError):
                        pass

                    break

                except (httpx.HTTPError, httpx.TimeoutException, OSError) as e:
                    logger.debug(f"Password reset check failed: {e}")

        return findings

    def get_discovered_login_pages(self) -> list[str]:
        """Return discovered login pages."""
        return self.discovered_login_pages.copy()
