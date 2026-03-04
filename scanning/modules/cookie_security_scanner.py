"""
Cookie Security Scanner - PHANTOM AI Enterprise Edition v3.0

Comprehensive cookie security testing module for detecting
cookie-related vulnerabilities and misconfigurations.

Features:
- Cookie attribute analysis (Secure, HttpOnly, SameSite)
- Session fixation detection
- Cookie scope issues (Path, Domain)
- Sensitive data in cookies
- Cookie expiration analysis
- Cookie encryption detection
- Session management testing
- Cookie prefixes validation (__Host-, __Secure-)

CWE Coverage:
- CWE-315: Cleartext Storage of Sensitive Information in Cookie
- CWE-614: Sensitive Cookie in HTTPS Without 'Secure' Attribute
- CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag
- CWE-1275: Sensitive Cookie with Improper SameSite Attribute
- CWE-384: Session Fixation
- CWE-613: Insufficient Session Expiration

Based on:
- OWASP Cookie Security Testing
- RFC 6265 - HTTP State Management Mechanism
- Modern browser security requirements

Author: PHANTOM AI Team
Version: 3.0.0
"""

from __future__ import annotations

import re
import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional, List, Set
from urllib.parse import urljoin, urlparse
from enum import Enum

import httpx

from scanning.findings import Finding, Severity, VulnType
from scanning.vuln_scanner import ScanModule
from utils.scan_client import get_scan_client
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


# =============================================================================
# ENUMS AND CONSTANTS
# =============================================================================

class CookieVulnType(Enum):
    """Types of cookie vulnerabilities."""
    MISSING_SECURE = "missing_secure"
    MISSING_HTTPONLY = "missing_httponly"
    MISSING_SAMESITE = "missing_samesite"
    WEAK_SAMESITE = "weak_samesite"
    SENSITIVE_DATA = "sensitive_data"
    SESSION_FIXATION = "session_fixation"
    LONG_EXPIRATION = "long_expiration"
    NO_EXPIRATION = "no_expiration"
    OVERLY_PERMISSIVE_DOMAIN = "overly_permissive_domain"
    OVERLY_PERMISSIVE_PATH = "overly_permissive_path"
    MISSING_PREFIX = "missing_prefix"
    PREDICTABLE_VALUE = "predictable_value"
    WEAK_ENCODING = "weak_encoding"
    COOKIE_OVERFLOW = "cookie_overflow"


class CookieType(Enum):
    """Classification of cookie types."""
    SESSION = "session"
    AUTHENTICATION = "authentication"
    TRACKING = "tracking"
    PREFERENCE = "preference"
    CSRF = "csrf"
    ANALYTICS = "analytics"
    ADVERTISING = "advertising"
    UNKNOWN = "unknown"


# Session-related cookie patterns
SESSION_PATTERNS = [
    r"^sess(ion)?",
    r"^sid$",
    r"^jsess(ion)?",
    r"^phpsess(ion)?",
    r"^asp\.net_session",
    r"^connect\.sid$",
    r"^laravel_session$",
    r"^_session",
    r"^token$",
    r"^auth(_token)?$",
    r"^jwt$",
    r"^access_token$",
    r"^refresh_token$",
    r"^id$",
    r"^user_id$",
    r"^user$",
    r"^login$",
    r"^remember",
    r"^persistent",
]

# Sensitive data patterns in cookie values
SENSITIVE_PATTERNS = [
    (r'password', 'password'),
    (r'passwd', 'password'),
    (r'pwd', 'password'),
    (r'secret', 'secret'),
    (r'api_key', 'api_key'),
    (r'apikey', 'api_key'),
    (r'api-key', 'api_key'),
    (r'access_key', 'access_key'),
    (r'private', 'private_key'),
    (r'credit.?card', 'credit_card'),
    (r'ssn', 'ssn'),
    (r'social.?sec', 'ssn'),
    (r'cvv', 'cvv'),
    (r'pin\d*$', 'pin'),
    (r'dob', 'date_of_birth'),
    (r'birth.?date', 'date_of_birth'),
]


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class ParsedCookie:
    """Parsed cookie with all attributes."""
    name: str
    value: str
    domain: Optional[str] = None
    path: str = "/"
    secure: bool = False
    httponly: bool = False
    samesite: Optional[str] = None
    expires: Optional[str] = None
    max_age: Optional[int] = None
    raw_header: str = ""

    # Analysis results
    cookie_type: CookieType = CookieType.UNKNOWN
    is_session_cookie: bool = False
    is_sensitive: bool = False
    entropy: float = 0.0
    vulnerabilities: List[CookieVulnType] = field(default_factory=list)

    @classmethod
    def from_header(cls, set_cookie_header: str) -> Optional["ParsedCookie"]:
        """Parse a Set-Cookie header."""
        try:
            parts = set_cookie_header.split(";")
            if not parts:
                return None

            # Parse name=value
            name_value = parts[0].strip()
            if "=" not in name_value:
                return None

            name, value = name_value.split("=", 1)
            cookie = cls(
                name=name.strip(),
                value=value.strip(),
                raw_header=set_cookie_header,
            )

            # Parse attributes
            for part in parts[1:]:
                part = part.strip().lower()

                if part == "secure":
                    cookie.secure = True
                elif part == "httponly":
                    cookie.httponly = True
                elif part.startswith("samesite="):
                    cookie.samesite = part.split("=", 1)[1].strip()
                elif part.startswith("domain="):
                    cookie.domain = part.split("=", 1)[1].strip()
                elif part.startswith("path="):
                    cookie.path = part.split("=", 1)[1].strip()
                elif part.startswith("expires="):
                    cookie.expires = part.split("=", 1)[1].strip()
                elif part.startswith("max-age="):
                    try:
                        cookie.max_age = int(part.split("=", 1)[1].strip())
                    except ValueError:
                        pass

            return cookie
        except Exception:
            return None

    def calculate_entropy(self) -> float:
        """Calculate Shannon entropy of cookie value."""
        if not self.value:
            return 0.0

        import math
        from collections import Counter

        prob = [n / len(self.value) for n in Counter(self.value).values()]
        entropy = -sum(p * math.log2(p) for p in prob if p > 0)
        self.entropy = entropy
        return entropy


@dataclass
class CookieVulnerability:
    """Cookie vulnerability finding."""
    vuln_type: CookieVulnType
    severity: str
    cookie_name: str
    description: str
    evidence: str = ""
    remediation: str = ""
    cwe: str = ""
    cvss_score: float = 0.0


# =============================================================================
# COOKIE ANALYZER
# =============================================================================

class CookieAnalyzer:
    """Utility class for cookie analysis."""

    @staticmethod
    def classify_cookie(cookie: ParsedCookie) -> CookieType:
        """Classify cookie type based on name and value."""
        name_lower = cookie.name.lower()

        # Check session patterns
        for pattern in SESSION_PATTERNS:
            if re.search(pattern, name_lower, re.IGNORECASE):
                return CookieType.SESSION

        # Check CSRF patterns
        if any(x in name_lower for x in ["csrf", "xsrf", "_token"]):
            return CookieType.CSRF

        # Check tracking/analytics patterns
        if any(x in name_lower for x in ["_ga", "_gid", "analytics", "tracking", "__utm"]):
            return CookieType.ANALYTICS

        # Check advertising patterns
        if any(x in name_lower for x in ["_fbp", "_gcl", "ads", "doubleclick", "__gads"]):
            return CookieType.ADVERTISING

        # Check preference patterns
        if any(x in name_lower for x in ["lang", "locale", "theme", "pref", "settings"]):
            return CookieType.PREFERENCE

        return CookieType.UNKNOWN

    @staticmethod
    def is_session_related(cookie: ParsedCookie) -> bool:
        """Check if cookie is session-related."""
        name_lower = cookie.name.lower()

        for pattern in SESSION_PATTERNS:
            if re.search(pattern, name_lower, re.IGNORECASE):
                return True

        # High entropy values often indicate session tokens
        if cookie.entropy > 4.0 and len(cookie.value) > 20:
            return True

        return False

    @staticmethod
    def contains_sensitive_data(cookie: ParsedCookie) -> List[str]:
        """Check if cookie contains sensitive data patterns."""
        found = []
        combined = f"{cookie.name}={cookie.value}".lower()

        for pattern, data_type in SENSITIVE_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                found.append(data_type)

        return found

    @staticmethod
    def is_base64_encoded(value: str) -> bool:
        """Check if value appears to be Base64 encoded."""
        import base64
        try:
            if len(value) % 4 == 0 and re.match(r'^[A-Za-z0-9+/]*={0,2}$', value):
                decoded = base64.b64decode(value)
                return len(decoded) > 0
        except Exception:
            pass
        return False

    @staticmethod
    def check_predictability(value: str) -> bool:
        """Check if cookie value appears predictable."""
        # Check for sequential patterns
        if value.isdigit() and len(value) < 10:
            return True

        # Check for simple patterns
        if re.match(r'^(user|admin|test)\d*$', value, re.IGNORECASE):
            return True

        # Check for low entropy
        if len(value) < 16:
            return True

        return False


# =============================================================================
# COOKIE SECURITY SCANNER
# =============================================================================

class CookieSecurityScanner(ScanModule):
    """
    PHANTOM AI Cookie Security Scanner.

    Comprehensive testing for cookie security issues including
    missing security flags, session management, and sensitive data exposure.
    """

    MODULE_NAME = "cookie_security"
    MODULE_DESCRIPTION = "Cookie Security Scanner - Flags, session management, sensitive data"
    MODULE_VERSION = "3.0.0"
    MODULE_AUTHOR = "PHANTOM AI Team"

    def __init__(
        self,
        settings: Optional["Settings"] = None,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        """Initialize the cookie scanner."""
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.rate_limiter = rate_limiter or RateLimiter(default_rate=10.0)
        self.client: Optional[httpx.AsyncClient] = None
        self.findings: List[Finding] = []
        self.discovered_cookies: List[ParsedCookie] = []
        self.analyzer = CookieAnalyzer()
        self.is_https: bool = False

    async def scan(
        self,
        target: str,
        endpoints: Optional[List[str]] = None,
        **kwargs,
    ) -> List[Finding]:
        """
        Execute cookie security scan.

        Args:
            target: Target URL
            endpoints: List of endpoints to analyze
            **kwargs: Additional parameters

        Returns:
            List of findings
        """
        self.findings = []
        self.discovered_cookies = []
        self.is_https = target.startswith("https://")

        logger.info(f"[Cookie Scanner] Starting scan of {target}")

        async with get_scan_client(
            timeout=30.0,
            follow_redirects=True,
            verify_ssl=False,
        ) as self.client:

            # Phase 1: Cookie Discovery
            await self._discover_cookies(target, endpoints or [])

            logger.info(f"[Cookie Scanner] Found {len(self.discovered_cookies)} cookies")

            # Phase 2: Cookie Analysis
            for cookie in self.discovered_cookies:
                await self._analyze_cookie(target, cookie)

            # Phase 3: Session Fixation Test
            await self._test_session_fixation(target)

            # Phase 4: Cookie Overflow Test
            await self._test_cookie_overflow(target)

        logger.info(f"[Cookie Scanner] Scan complete. Found {len(self.findings)} issues")

        return self.findings

    async def _discover_cookies(
        self,
        target: str,
        endpoints: List[str],
    ) -> None:
        """Discover cookies from various endpoints."""
        test_endpoints = endpoints or [
            "/", "/login", "/signin", "/auth", "/api",
            "/api/v1", "/api/v2", "/account", "/profile",
            "/dashboard", "/admin", "/user",
        ]

        seen_cookies: Set[str] = set()

        for endpoint in test_endpoints:
            url = urljoin(target, endpoint)

            try:
                await self.rate_limiter.acquire()
                response = await self.client.get(url)

                # Parse Set-Cookie headers
                for header in response.headers.get_list("set-cookie"):
                    cookie = ParsedCookie.from_header(header)
                    if cookie and cookie.name not in seen_cookies:
                        seen_cookies.add(cookie.name)

                        # Calculate entropy
                        cookie.calculate_entropy()

                        # Classify cookie
                        cookie.cookie_type = self.analyzer.classify_cookie(cookie)
                        cookie.is_session_cookie = self.analyzer.is_session_related(cookie)

                        # Check for sensitive data
                        sensitive = self.analyzer.contains_sensitive_data(cookie)
                        cookie.is_sensitive = len(sensitive) > 0

                        self.discovered_cookies.append(cookie)

            except Exception as e:
                logger.debug(f"[Cookie Scanner] Error scanning {endpoint}: {e}")

    async def _analyze_cookie(self, target: str, cookie: ParsedCookie) -> None:
        """Analyze a single cookie for security issues."""

        # 1. Check Secure flag (for HTTPS sites)
        if self.is_https and not cookie.secure:
            severity = "HIGH" if cookie.is_session_cookie else "MEDIUM"
            self._add_finding(
                title=f"Cookie '{cookie.name}' Missing Secure Flag",
                severity=severity,
                vulnerability=CookieVulnerability(
                    vuln_type=CookieVulnType.MISSING_SECURE,
                    severity=severity,
                    cookie_name=cookie.name,
                    description=f"Cookie '{cookie.name}' is transmitted over HTTPS but lacks the Secure flag",
                    evidence=f"Set-Cookie: {cookie.name}=... (no Secure flag)",
                    remediation="Add the Secure flag to prevent transmission over unencrypted connections",
                    cwe_id="CWE-614",
                    cvss_score=6.5 if cookie.is_session_cookie else 4.0,
                ),
                target=target,
                confidence_score=90.0 if cookie.is_session_cookie else 85.0,
            )

        # 2. Check HttpOnly flag
        if not cookie.httponly and (cookie.is_session_cookie or cookie.is_sensitive):
            severity = "HIGH" if cookie.is_session_cookie else "MEDIUM"
            self._add_finding(
                title=f"Session Cookie '{cookie.name}' Missing HttpOnly Flag",
                severity=severity,
                vulnerability=CookieVulnerability(
                    vuln_type=CookieVulnType.MISSING_HTTPONLY,
                    severity=severity,
                    cookie_name=cookie.name,
                    description=f"Session cookie '{cookie.name}' is accessible to JavaScript (XSS risk)",
                    evidence=f"Set-Cookie: {cookie.name}=... (no HttpOnly flag)",
                    remediation="Add the HttpOnly flag to prevent JavaScript access",
                    cwe_id="CWE-1004",
                    cvss_score=6.0,
                ),
                target=target,
                confidence_score=90.0 if cookie.is_session_cookie else 85.0,
            )

        # 3. Check SameSite attribute
        if cookie.samesite is None:
            self._add_finding(
                title=f"Cookie '{cookie.name}' Missing SameSite Attribute",
                severity=Severity.MEDIUM,
                vulnerability=CookieVulnerability(
                    vuln_type=CookieVulnType.MISSING_SAMESITE,
                    severity=Severity.MEDIUM,
                    cookie_name=cookie.name,
                    description=f"Cookie '{cookie.name}' lacks SameSite attribute, may be vulnerable to CSRF",
                    evidence=f"Set-Cookie: {cookie.name}=... (no SameSite)",
                    remediation="Add SameSite=Strict or SameSite=Lax to prevent CSRF attacks",
                    cwe_id="CWE-1275",
                    cvss_score=5.0,
                ),
                target=target,
                confidence_score=85.0,
            )
        elif cookie.samesite.lower() == "none" and not cookie.secure:
            self._add_finding(
                title=f"Cookie '{cookie.name}' Has SameSite=None Without Secure",
                severity=Severity.HIGH,
                vulnerability=CookieVulnerability(
                    vuln_type=CookieVulnType.WEAK_SAMESITE,
                    severity=Severity.HIGH,
                    cookie_name=cookie.name,
                    description="SameSite=None requires Secure flag in modern browsers",
                    evidence=f"Set-Cookie: {cookie.name}=...; SameSite=None (no Secure)",
                    remediation="Add Secure flag when using SameSite=None",
                    cwe_id="CWE-1275",
                    cvss_score=6.0,
                ),
                target=target,
                confidence_score=90.0,
            )

        # 4. Check for sensitive data in cookies
        sensitive_data = self.analyzer.contains_sensitive_data(cookie)
        if sensitive_data:
            self._add_finding(
                title=f"Sensitive Data in Cookie '{cookie.name}'",
                severity=Severity.HIGH,
                vulnerability=CookieVulnerability(
                    vuln_type=CookieVulnType.SENSITIVE_DATA,
                    severity=Severity.HIGH,
                    cookie_name=cookie.name,
                    description=f"Cookie may contain sensitive data types: {', '.join(sensitive_data)}",
                    evidence=f"Cookie name/value pattern matches: {', '.join(sensitive_data)}",
                    remediation="Never store sensitive data in cookies; use server-side sessions",
                    cwe_id="CWE-315",
                    cvss_score=7.0,
                ),
                target=target,
                confidence_score=90.0,
            )

        # 5. Check cookie expiration
        if cookie.is_session_cookie:
            if cookie.max_age and cookie.max_age > 86400 * 30:  # 30 days
                self._add_finding(
                    title=f"Session Cookie '{cookie.name}' Has Long Expiration",
                    severity=Severity.MEDIUM,
                    vulnerability=CookieVulnerability(
                        vuln_type=CookieVulnType.LONG_EXPIRATION,
                        severity=Severity.MEDIUM,
                        cookie_name=cookie.name,
                        description=f"Session cookie expires in {cookie.max_age // 86400} days",
                        evidence=f"Max-Age: {cookie.max_age} seconds",
                        remediation="Use shorter session lifetimes and implement sliding expiration",
                        cwe_id="CWE-613",
                        cvss_score=4.0,
                    ),
                    target=target,
                    confidence_score=85.0,
                )

        # 6. Check cookie domain scope
        if cookie.domain:
            parsed = urlparse(target)
            if cookie.domain.startswith(".") and cookie.domain.count(".") < 2:
                self._add_finding(
                    title=f"Cookie '{cookie.name}' Has Overly Permissive Domain",
                    severity=Severity.MEDIUM,
                    vulnerability=CookieVulnerability(
                        vuln_type=CookieVulnType.OVERLY_PERMISSIVE_DOMAIN,
                        severity=Severity.MEDIUM,
                        cookie_name=cookie.name,
                        description=f"Cookie domain '{cookie.domain}' is too broad",
                        evidence=f"Domain: {cookie.domain}",
                        remediation="Restrict cookie domain to specific subdomain",
                        cwe_id="CWE-1004",
                        cvss_score=4.5,
                    ),
                    target=target,
                    confidence_score=85.0,
                )

        # 7. Check cookie path scope
        if cookie.path == "/" and cookie.is_session_cookie:
            # This is common but can be overly permissive
            pass  # Info level, not a vulnerability

        # 8. Check for __Host- and __Secure- prefix compliance
        if cookie.name.startswith("__Host-"):
            if not cookie.secure or cookie.domain or cookie.path != "/":
                self._add_finding(
                    title=f"Invalid __Host- Cookie Prefix Usage",
                    severity=Severity.MEDIUM,
                    vulnerability=CookieVulnerability(
                        vuln_type=CookieVulnType.MISSING_PREFIX,
                        severity=Severity.MEDIUM,
                        cookie_name=cookie.name,
                        description="__Host- prefix requires Secure, no Domain, and Path=/",
                        evidence=f"Cookie: {cookie.name} (Secure={cookie.secure}, Domain={cookie.domain})",
                        remediation="Ensure __Host- cookies have Secure flag, no Domain, and Path=/",
                        cwe_id="CWE-614",
                        cvss_score=4.0,
                    ),
                    target=target,
                    confidence_score=85.0,
                )

        if cookie.name.startswith("__Secure-"):
            if not cookie.secure:
                self._add_finding(
                    title=f"Invalid __Secure- Cookie Prefix Usage",
                    severity=Severity.MEDIUM,
                    vulnerability=CookieVulnerability(
                        vuln_type=CookieVulnType.MISSING_PREFIX,
                        severity=Severity.MEDIUM,
                        cookie_name=cookie.name,
                        description="__Secure- prefix requires Secure flag",
                        evidence=f"Cookie: {cookie.name} (Secure={cookie.secure})",
                        remediation="Add Secure flag to __Secure- prefixed cookies",
                        cwe_id="CWE-614",
                        cvss_score=4.0,
                    ),
                    target=target,
                    confidence_score=85.0,
                )

        # 9. Check for predictable cookie values
        if cookie.is_session_cookie and self.analyzer.check_predictability(cookie.value):
            self._add_finding(
                title=f"Session Cookie '{cookie.name}' Has Predictable Value",
                severity=Severity.HIGH,
                vulnerability=CookieVulnerability(
                    vuln_type=CookieVulnType.PREDICTABLE_VALUE,
                    severity=Severity.HIGH,
                    cookie_name=cookie.name,
                    description="Session cookie value appears predictable or has low entropy",
                    evidence=f"Cookie entropy: {cookie.entropy:.2f} bits, length: {len(cookie.value)}",
                    remediation="Use cryptographically random session identifiers with high entropy",
                    cwe_id="CWE-330",
                    cvss_score=8.0,
                ),
                target=target,
                confidence_score=90.0,
            )

    async def _test_session_fixation(self, target: str) -> None:
        """Test for session fixation vulnerability."""
        # Find session cookies
        session_cookies = [c for c in self.discovered_cookies if c.is_session_cookie]

        if not session_cookies:
            return

        try:
            # Get initial session
            await self.rate_limiter.acquire()
            initial_response = await self.client.get(target)
            initial_cookies = {}

            for header in initial_response.headers.get_list("set-cookie"):
                cookie = ParsedCookie.from_header(header)
                if cookie and cookie.is_session_cookie:
                    initial_cookies[cookie.name] = cookie.value

            # Try to set our own session and see if it's accepted
            await self.rate_limiter.acquire()

            forced_cookies = {name: "attacker_controlled_session" for name in initial_cookies}
            response = await self.client.get(target, cookies=forced_cookies)

            # Check if the server accepted our cookies without regenerating
            for header in response.headers.get_list("set-cookie"):
                cookie = ParsedCookie.from_header(header)
                if cookie and cookie.name in forced_cookies:
                    if cookie.value == forced_cookies[cookie.name]:
                        self._add_finding(
                            title="Potential Session Fixation Vulnerability",
                            severity=Severity.CRITICAL,
                            vulnerability=CookieVulnerability(
                                vuln_type=CookieVulnType.SESSION_FIXATION,
                                severity=Severity.CRITICAL,
                                cookie_name=cookie.name,
                                description="Server accepts externally set session identifiers",
                                evidence=f"Set session '{cookie.name}' to arbitrary value, server did not regenerate",
                                remediation="Regenerate session ID after authentication and validate session origin",
                                cwe_id="CWE-384",
                                cvss_score=8.0,
                            ),
                            target=target,
                            confidence_score=95.0,
                        )

        except Exception as e:
            logger.debug(f"[Cookie Scanner] Session fixation test error: {e}")

    async def _test_cookie_overflow(self, target: str) -> None:
        """Test for cookie overflow/bomb vulnerability."""
        try:
            # Create many cookies
            overflow_cookies = {
                f"test_cookie_{i}": "A" * 4000
                for i in range(50)
            }

            await self.rate_limiter.acquire()
            response = await self.client.get(target, cookies=overflow_cookies)

            # Check if server handles it gracefully
            if response.status_code >= 500:
                self._add_finding(
                    title="Cookie Overflow Causes Server Error",
                    severity=Severity.MEDIUM,
                    vulnerability=CookieVulnerability(
                        vuln_type=CookieVulnType.COOKIE_OVERFLOW,
                        severity=Severity.MEDIUM,
                        cookie_name="(multiple)",
                        description="Server crashes or errors when receiving many/large cookies",
                        evidence=f"Response status: {response.status_code}",
                        remediation="Implement cookie limits and handle overflow gracefully",
                        cwe_id="CWE-400",
                        cvss_score=5.0,
                    ),
                    target=target,
                    confidence_score=85.0,
                )

        except Exception as e:
            # Connection errors might also indicate vulnerability
            if "overflow" in str(e).lower() or "too large" in str(e).lower():
                self._add_finding(
                    title="Cookie Overflow Denial of Service",
                    severity=Severity.MEDIUM,
                    vulnerability=CookieVulnerability(
                        vuln_type=CookieVulnType.COOKIE_OVERFLOW,
                        severity=Severity.MEDIUM,
                        cookie_name="(multiple)",
                        description=f"Server cannot handle cookie overflow: {e}",
                        evidence=str(e),
                        remediation="Implement cookie size and count limits",
                        cwe_id="CWE-400",
                        cvss_score=5.0,
                    ),
                    target=target,
                    confidence_score=85.0,
                )

    def _add_finding(
        self,
        title: str,
        severity: str,
        vulnerability: CookieVulnerability,
        target: str,
        confidence: float = 85.0,
    ) -> None:
        """Add a finding to the results."""
        # G-10 FIX: Use correct Finding field names (name, matched_at, type, category)
        # Also wrap evidence string in list as Finding.evidence expects list[str]
        evidence_list = [vulnerability.evidence] if vulnerability.evidence else []
        finding = Finding(
            name=title,  # was: title (incorrect kwarg)
            vuln_type=vulnerability.vuln_type,
            severity=severity,
            endpoint=target,  # was: url (incorrect kwarg)
            description=vulnerability.description,
            evidence=evidence_list,
            remediation=vulnerability.remediation,
            cwe_id=vulnerability.cwe,
            cvss_score=vulnerability.cvss_score,
            confidence_score=confidence,
            category=self.MODULE_NAME,  # was: module (incorrect kwarg)
            metadata={
                "vuln_type": vulnerability.vuln_type.value,
                "cookie_name": vulnerability.cookie_name,
            },
        )
        self.findings.append(finding)
        logger.info(f"[Cookie Scanner] Found: {title} ({severity})")


# =============================================================================
# MODULE TEST
# =============================================================================

if __name__ == "__main__":
    import asyncio

    async def test_cookie_scanner():
        """Test the cookie scanner."""
        print("=" * 60)
        print("PHANTOM AI - Cookie Security Scanner Test")
        print("=" * 60)

        scanner = CookieSecurityScanner()
        analyzer = CookieAnalyzer()

        # Test cookie parsing
        test_header = "session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400"
        cookie = ParsedCookie.from_header(test_header)

        if cookie:
            print(f"\n✅ Cookie parsed successfully")
            print(f"   Name: {cookie.name}")
            print(f"   Value: {cookie.value}")
            print(f"   Path: {cookie.path}")
            print(f"   Secure: {cookie.secure}")
            print(f"   HttpOnly: {cookie.httponly}")
            print(f"   SameSite: {cookie.samesite}")
            print(f"   Max-Age: {cookie.max_age}")

            # Test entropy
            cookie.calculate_entropy()
            print(f"   Entropy: {cookie.entropy:.2f} bits")

            # Test classification
            cookie.cookie_type = analyzer.classify_cookie(cookie)
            print(f"   Type: {cookie.cookie_type.value}")

            # Test session detection
            is_session = analyzer.is_session_related(cookie)
            print(f"   Is Session: {is_session}")

        # Test vulnerable cookie
        print(f"\n🔍 Vulnerable Cookie Test:")
        vuln_header = "password=secret123; Path=/"
        vuln_cookie = ParsedCookie.from_header(vuln_header)

        if vuln_cookie:
            sensitive = analyzer.contains_sensitive_data(vuln_cookie)
            print(f"   Name: {vuln_cookie.name}")
            print(f"   Secure: {vuln_cookie.secure}")
            print(f"   HttpOnly: {vuln_cookie.httponly}")
            print(f"   Sensitive Data: {sensitive}")

        print("\n" + "=" * 60)
        print("✅ Cookie Scanner test complete!")
        print("=" * 60)

    asyncio.run(test_cookie_scanner())
