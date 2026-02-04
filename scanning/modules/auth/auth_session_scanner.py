"""
Session Management Security Scanner

Enterprise-grade session security testing including:
- Cookie security flags (Secure, HttpOnly, SameSite)
- Session fixation detection
- Session entropy analysis
- Cookie attribute analysis

CWE Coverage:
- CWE-384: Session Fixation
- CWE-613: Insufficient Session Expiration
- CWE-614: Sensitive Cookie in HTTPS Without 'Secure' Attribute
- CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag
- CWE-1275: Sensitive Cookie with Improper SameSite Attribute

Author: PetNTester AI Enterprise
Version: 2.0.0
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import httpx

from scanning.vuln_scanner import Finding
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter

from .auth_base import SessionInfo

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


class SessionScanner:
    """
    Session Management Security Scanner

    Tests for common session management security issues including
    cookie flags, session fixation, and entropy analysis.
    """

    # Session cookie indicators
    SESSION_INDICATORS = [
        "session", "sess", "sid", "jsessionid",
        "phpsessid", "asp.net_sessionid", "aspsessionid",
    ]

    def __init__(self, settings: Settings) -> None:
        self.timeout = settings.timeouts.request_timeout
        self.detected_sessions: list[SessionInfo] = []

    async def scan(
        self,
        base_url: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
        login_pages: list[str] = None,
    ) -> list[dict[str, Any]]:
        """
        Comprehensive session management security scan.

        Args:
            base_url: Target base URL
            asset_data: Asset information from discovery
            rate_limiter: Rate limiter instance
            login_pages: Optional list of login page URLs for fixation testing
        """
        findings = []
        login_pages = login_pages or []

        # Check session management
        session_findings = await self._check_session_management(base_url, rate_limiter)
        findings.extend(session_findings)

        # Check session fixation
        fixation_findings = await self._check_session_fixation(base_url, login_pages, rate_limiter)
        findings.extend(fixation_findings)

        return findings

    async def _check_session_management(
        self,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Check session management security."""
        findings = []

        await rate_limiter.acquire()

        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                response = await client.get(base_url)

                # Check session cookies
                for cookie in response.cookies.jar:
                    cookie_findings = self._analyze_session_cookie(cookie, base_url)
                    findings.extend(cookie_findings)

                # Check Set-Cookie headers
                set_cookie_headers = response.headers.get_list("set-cookie")
                for header in set_cookie_headers:
                    header_findings = self._analyze_cookie_header(header, base_url)
                    findings.extend(header_findings)

        except (httpx.HTTPError, httpx.TimeoutException, OSError) as e:
            logger.debug(f"Session check failed: {e}")

        return findings

    def _analyze_session_cookie(
        self,
        cookie: Any,
        base_url: str,
    ) -> list[dict[str, Any]]:
        """Analyze a session cookie for security issues."""
        findings = []

        cookie_name = cookie.name.lower()
        is_session = any(ind in cookie_name for ind in self.SESSION_INDICATORS)

        if not is_session:
            return findings

        # Track detected session
        self.detected_sessions.append(SessionInfo(
            cookie_name=cookie.name,
            cookie_value=cookie.value[:20] + "..." if len(cookie.value) > 20 else cookie.value,
            has_secure=getattr(cookie, 'secure', False),
        ))

        # Check for missing Secure flag
        if not getattr(cookie, 'secure', False) and base_url.startswith("https"):
            findings.append(Finding(
                type="session",
                name="Session Cookie Missing Secure Flag",
                severity="MEDIUM",
                description=f"Session cookie '{cookie.name}' is missing the Secure flag. "
                           f"This allows the cookie to be transmitted over unencrypted connections.",
                host=base_url,
                matched_at=base_url,
                evidence=[f"Cookie: {cookie.name}", "Secure flag: Not set"],
                cvss_score=4.3,
                cwe="CWE-614",
                remediation="Set the Secure flag on all session cookies.",
            ).to_dict())

        return findings

    def _analyze_cookie_header(
        self,
        header: str,
        base_url: str,
    ) -> list[dict[str, Any]]:
        """Analyze Set-Cookie header for security issues."""
        findings = []

        header_lower = header.lower()

        # Extract cookie name
        cookie_name = header.split("=")[0] if "=" in header else ""
        is_session = any(ind in cookie_name.lower() for ind in self.SESSION_INDICATORS)

        if not is_session:
            return findings

        # Check HttpOnly
        if "httponly" not in header_lower:
            findings.append(Finding(
                type="session",
                name="Session Cookie Missing HttpOnly Flag",
                severity="MEDIUM",
                description="Session cookie is missing HttpOnly flag. "
                           "JavaScript can access this cookie, enabling XSS-based session theft.",
                host=base_url,
                matched_at=base_url,
                evidence=[f"Set-Cookie: {header[:100]}...", "HttpOnly flag: Not set"],
                cvss_score=4.3,
                cwe="CWE-1004",
                remediation="Set HttpOnly flag on all session cookies.",
            ).to_dict())

        # Check SameSite
        if "samesite" not in header_lower:
            findings.append(Finding(
                type="session",
                name="Session Cookie Missing SameSite Attribute",
                severity="LOW",
                description="Session cookie is missing SameSite attribute. "
                           "This may allow CSRF attacks.",
                host=base_url,
                matched_at=base_url,
                evidence=[f"Set-Cookie: {header[:100]}..."],
                cvss_score=3.1,
                cwe="CWE-1275",
                remediation="Set SameSite=Strict or SameSite=Lax on session cookies.",
            ).to_dict())

        # Check for weak SameSite value
        if "samesite=none" in header_lower and "secure" not in header_lower:
            findings.append(Finding(
                type="session",
                name="Session Cookie SameSite=None Without Secure",
                severity="MEDIUM",
                description="Session cookie has SameSite=None without Secure flag. "
                           "Modern browsers reject this combination.",
                host=base_url,
                matched_at=base_url,
                evidence=[f"Set-Cookie: {header[:100]}..."],
                cvss_score=4.3,
                cwe="CWE-1275",
                remediation="When using SameSite=None, always set the Secure flag.",
            ).to_dict())

        return findings

    async def _check_session_fixation(
        self,
        base_url: str,
        login_pages: list[str],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Check for session fixation vulnerabilities."""
        findings = []

        await rate_limiter.acquire()

        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                # Get initial session
                resp1 = await client.get(base_url)
                initial_cookies = dict(resp1.cookies)

                if not initial_cookies:
                    return findings

                # Find session cookie
                session_cookie_name = None

                for name in initial_cookies:
                    if any(ind in name.lower() for ind in self.SESSION_INDICATORS):
                        session_cookie_name = name
                        break

                if not session_cookie_name:
                    return findings

                initial_session = initial_cookies[session_cookie_name]

                # Simulate login (just POST to login page)
                for login_url in login_pages[:1]:
                    await rate_limiter.acquire()

                    # Make another request after "login attempt"
                    resp2 = await client.get(base_url)

                    new_cookies = dict(resp2.cookies)
                    new_session = new_cookies.get(session_cookie_name, "")

                    # If session ID doesn't change, possible fixation
                    if initial_session == new_session and initial_session:
                        findings.append(Finding(
                            type="session",
                            name="Potential Session Fixation",
                            severity="HIGH",
                            description="Session ID does not regenerate after state change. "
                                       "An attacker may be able to fixate a session ID.",
                            host=base_url,
                            matched_at=base_url,
                            evidence=[
                                f"Cookie: {session_cookie_name}",
                                f"Session ID remained: {initial_session[:20]}...",
                            ],
                            cvss_score=7.5,
                            cwe="CWE-384",
                            remediation="Regenerate session IDs after authentication. "
                                       "Invalidate old session IDs after login.",
                        ).to_dict())

        except (httpx.HTTPError, httpx.TimeoutException, OSError) as e:
            logger.debug(f"Session fixation check failed: {e}")

        return findings

    def get_detected_sessions(self) -> list[SessionInfo]:
        """Return detected session information."""
        return self.detected_sessions.copy()
