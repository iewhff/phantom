"""
PHANTOM AI - Web Cache Deception Scanner

Enterprise-grade web cache deception vulnerability detection covering:
- Path confusion attacks
- Delimiter injection (;, ?, #)
- Static extension caching (.js, .css, .png)
- Normalized vs original path differences
- Query string caching behavior
- User-specific data caching
- Cache key manipulation
- Response header analysis
- Cache-Control bypass
- CDN-specific behaviors

Based on PortSwigger Web Security Academy - Web Cache Deception (5 labs)

Web Cache Deception differs from Cache Poisoning:
- Deception: Trick cache into storing victim's private data
- Poisoning: Inject malicious content into cached responses

Version: 3.0.0
Author: PHANTOM AI Team
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import random
import re
import string
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urljoin, urlparse, quote

logger = logging.getLogger(__name__)


# =============================================================================
# CONSTANTS & CONFIGURATIONS
# =============================================================================

VERSION = "3.0.0"


class CacheDeceptionType(Enum):
    """Types of cache deception vulnerabilities."""

    PATH_CONFUSION = auto()             # /profile/nonexistent.css
    DELIMITER_INJECTION = auto()        # /profile;.css or /profile%3b.css
    EXTENSION_APPEND = auto()           # /profile.css caches /profile
    QUERY_CACHING = auto()              # ?cachebuster=x
    FRAGMENT_CACHING = auto()           # #fragment handling
    NORMALIZATION_DIFF = auto()         # Path normalization differences
    CACHE_KEY_MANIPULATION = auto()     # Vary header bypass


class CacheIndicator(Enum):
    """Cache status indicators."""

    HIT = "HIT"
    MISS = "MISS"
    EXPIRED = "EXPIRED"
    STALE = "STALE"
    BYPASS = "BYPASS"
    UNKNOWN = "UNKNOWN"


# Static file extensions that are commonly cached
STATIC_EXTENSIONS = [
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico",
    ".svg", ".woff", ".woff2", ".ttf", ".eot", ".webp",
    ".pdf", ".txt", ".xml", ".json", ".map",
]

# Delimiters that might cause path confusion
PATH_DELIMITERS = [
    ";",        # Semicolon
    "%3b",      # URL-encoded semicolon
    "%3B",      # URL-encoded semicolon (uppercase)
    "?",        # Query string
    "%3f",      # URL-encoded question mark
    "#",        # Fragment (client-side, but test anyway)
    "%23",      # URL-encoded hash
    "%00",      # Null byte
    "/.",       # Dot segment
    "//",       # Double slash
    "/..",      # Parent directory
]

# Cache header names to check
CACHE_HEADERS = [
    "X-Cache",
    "X-Cache-Hit",
    "X-Cache-Status",
    "CF-Cache-Status",      # Cloudflare
    "X-Varnish",            # Varnish
    "Age",                  # Cache age
    "X-Served-By",          # CDN info
    "X-Cache-Hits",         # Hit count
    "X-Proxy-Cache",
    "X-Drupal-Cache",
    "X-VC-Cache",           # Varnish Cache
    "Fastly-Debug-Digest",  # Fastly
    "X-Akamai-Cache-Status", # Akamai
]


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class CacheStatus:
    """Cache status for a response."""

    is_cached: bool = False
    indicator: CacheIndicator = CacheIndicator.UNKNOWN
    cache_header: Optional[str] = None
    cache_value: Optional[str] = None
    age: Optional[int] = None
    max_age: Optional[int] = None
    vary_headers: List[str] = field(default_factory=list)
    cdn_detected: Optional[str] = None


@dataclass
class DeceptionTestResult:
    """Result of a cache deception test."""

    test_type: CacheDeceptionType
    original_url: str
    deception_url: str
    original_response_hash: str
    cached_response_hash: str
    content_matches: bool
    private_data_cached: bool
    cache_status: CacheStatus
    evidence: Dict[str, Any]


@dataclass
class CacheDeceptionFinding:
    """Cache deception vulnerability finding."""

    id: str
    vuln_type: CacheDeceptionType
    severity: str
    confidence: float
    original_url: str
    deception_url: str
    description: str
    impact: str
    remediation: str
    test_results: List[DeceptionTestResult]
    cwe_id: int
    cvss_score: float
    poc_steps: List[str]


@dataclass
class ScanConfig:
    """Cache deception scanner configuration."""

    target_url: str
    timeout: float = 30.0
    test_extensions: List[str] = field(default_factory=lambda: STATIC_EXTENSIONS[:10])
    test_delimiters: List[str] = field(default_factory=lambda: PATH_DELIMITERS[:6])
    cache_wait_time: float = 2.0
    iterations: int = 3
    auth_cookie: Optional[str] = None
    session_header: Optional[str] = None


# =============================================================================
# CACHE ANALYSIS
# =============================================================================

class CacheAnalyzer:
    """Analyze cache behavior from response headers."""

    VERSION = "3.0.0"

    def analyze(self, headers: Dict[str, str]) -> CacheStatus:
        """Analyze cache status from headers."""
        status = CacheStatus()

        # Check cache indicator headers
        for header in CACHE_HEADERS:
            value = headers.get(header, "")
            if value:
                status.cache_header = header
                status.cache_value = value

                if any(hit in value.upper() for hit in ["HIT", "TCP_HIT", "MEM_HIT"]):
                    status.is_cached = True
                    status.indicator = CacheIndicator.HIT
                    break
                elif any(miss in value.upper() for miss in ["MISS", "TCP_MISS"]):
                    status.indicator = CacheIndicator.MISS
                elif "EXPIRED" in value.upper():
                    status.indicator = CacheIndicator.EXPIRED
                elif "BYPASS" in value.upper():
                    status.indicator = CacheIndicator.BYPASS

        # Check Age header
        age = headers.get("Age")
        if age:
            try:
                status.age = int(age)
                if status.age > 0:
                    status.is_cached = True
            except ValueError:
                pass

        # Check Cache-Control
        cache_control = headers.get("Cache-Control", "")
        if cache_control:
            max_age_match = re.search(r"max-age=(\d+)", cache_control)
            if max_age_match:
                status.max_age = int(max_age_match.group(1))

        # Check Vary headers
        vary = headers.get("Vary", "")
        if vary:
            status.vary_headers = [v.strip() for v in vary.split(",")]

        # Detect CDN
        status.cdn_detected = self._detect_cdn(headers)

        return status

    def _detect_cdn(self, headers: Dict[str, str]) -> Optional[str]:
        """Detect CDN from headers."""
        cdn_indicators = {
            "CF-Cache-Status": "Cloudflare",
            "CF-RAY": "Cloudflare",
            "X-Served-By": "Fastly" if "cache" in headers.get("X-Served-By", "").lower() else None,
            "X-Varnish": "Varnish",
            "X-Akamai-Cache-Status": "Akamai",
            "X-Amz-Cf-Id": "CloudFront",
            "X-Azure-Ref": "Azure CDN",
            "X-Cache-Request-Id": "KeyCDN",
        }

        for header, cdn in cdn_indicators.items():
            if header in headers and cdn:
                return cdn

        return None


# =============================================================================
# MAIN SCANNER CLASS
# =============================================================================

class CacheDeceptionScanner:
    """
    Enterprise-grade web cache deception vulnerability scanner.

    Attack scenario:
    1. Victim visits authenticated page (e.g., /account)
    2. Attacker crafts deceptive URL (e.g., /account/nonexistent.css)
    3. Cache stores response thinking it's a static file
    4. Attacker requests same URL, gets victim's cached data

    Detects:
    - Path confusion vulnerabilities
    - Delimiter injection attacks
    - Static extension caching abuse
    - Normalization differences
    - Cache key manipulation

    Usage:
        scanner = CacheDeceptionScanner()
        findings = await scanner.scan("https://target.com/account")
    """

    VERSION = "3.0.0"
    CWE_ID = 525  # CWE-525: Use of Web Browser Cache Containing Sensitive Information

    def __init__(
        self,
        http_client: Any = None,
        config: Optional[ScanConfig] = None,
    ):
        """Initialize the scanner."""
        self.http_client = http_client
        self.config = config
        self.cache_analyzer = CacheAnalyzer()
        self.findings: List[CacheDeceptionFinding] = []
        self._session_id = str(uuid.uuid4())[:8]

    async def scan(
        self,
        target_url: str,
        **kwargs,
    ) -> List[CacheDeceptionFinding]:
        """
        Scan for web cache deception vulnerabilities.

        Args:
            target_url: Target URL to scan (should be authenticated endpoint)
            **kwargs: Additional configuration

        Returns:
            List of discovered vulnerabilities
        """
        logger.info(f"[CacheDeception] Starting scan: {target_url}")

        # Create config if not provided
        if not self.config:
            self.config = ScanConfig(target_url=target_url)

        # Get original response for comparison
        original_response = await self._get_response(target_url)
        if not original_response:
            logger.warning("[CacheDeception] Could not fetch original URL")
            return []

        original_hash = self._hash_content(original_response["body"])

        # Test path confusion with extensions
        await self._test_extension_confusion(target_url, original_hash, original_response)

        # Test delimiter injection
        await self._test_delimiter_injection(target_url, original_hash, original_response)

        # Test query string caching
        await self._test_query_caching(target_url, original_hash, original_response)

        # Test path normalization
        await self._test_normalization(target_url, original_hash, original_response)

        logger.info(f"[CacheDeception] Scan complete. Found {len(self.findings)} vulnerabilities")
        return self.findings

    async def _get_response(self, url: str, headers: Optional[Dict[str, str]] = None) -> Optional[Dict[str, Any]]:
        """Get response from URL."""
        try:
            all_headers = headers or {}
            if self.config and self.config.auth_cookie:
                all_headers["Cookie"] = self.config.auth_cookie
            if self.config and self.config.session_header:
                # Parse "Name: Value" format
                if ": " in self.config.session_header:
                    name, value = self.config.session_header.split(": ", 1)
                    all_headers[name] = value

            if self.http_client:
                response = await self.http_client.get(
                    url,
                    headers=all_headers,
                    timeout=self.config.timeout if self.config else 30.0,
                )
                return {
                    "code": response.status_code,
                    "body": response.text if hasattr(response, 'text') else str(response.content),
                    "headers": dict(response.headers) if hasattr(response, 'headers') else {},
                }
            else:
                # Simulation
                return {
                    "code": 200,
                    "body": f"<html><body>User: test@example.com Balance: $1000 Session: {self._session_id}</body></html>",
                    "headers": {"Content-Type": "text/html"},
                }
        except Exception as e:
            logger.debug(f"[CacheDeception] Request failed: {e}")
            return None

    def _hash_content(self, content: str) -> str:
        """Create hash of content for comparison."""
        return hashlib.md5(content.encode()).hexdigest()

    def _contains_private_data(self, content: str) -> bool:
        """Check if content contains private/sensitive data."""
        # Patterns indicating private data
        private_patterns = [
            r"email.*?[\w.-]+@[\w.-]+",
            r"balance.*?\$?\d+",
            r"account.*?\d+",
            r"session.*?[a-zA-Z0-9]+",
            r"token.*?[a-zA-Z0-9]+",
            r"api.?key.*?[a-zA-Z0-9]+",
            r"user.*?name",
            r"(first|last).?name",
            r"phone.*?\d+",
            r"address",
            r"credit.?card",
            r"password",
        ]

        content_lower = content.lower()
        return any(re.search(pattern, content_lower, re.I) for pattern in private_patterns)

    async def _test_extension_confusion(
        self,
        target_url: str,
        original_hash: str,
        original_response: Dict[str, Any],
    ) -> None:
        """Test path confusion with static file extensions."""
        logger.debug("[CacheDeception] Testing extension confusion")

        extensions = self.config.test_extensions if self.config else STATIC_EXTENSIONS[:10]

        for ext in extensions:
            # Create deception URL
            deception_url = f"{target_url}/nonexistent{ext}"

            results = await self._perform_deception_test(
                target_url,
                deception_url,
                original_hash,
                original_response,
                CacheDeceptionType.PATH_CONFUSION,
            )

            if results and results.private_data_cached:
                self._create_finding(
                    vuln_type=CacheDeceptionType.PATH_CONFUSION,
                    original_url=target_url,
                    deception_url=deception_url,
                    test_results=[results],
                    description=f"Cache deception via path confusion with {ext} extension. "
                               f"Private content is cached when accessing {deception_url}",
                )
                return  # One finding per type is enough

    async def _test_delimiter_injection(
        self,
        target_url: str,
        original_hash: str,
        original_response: Dict[str, Any],
    ) -> None:
        """Test delimiter injection for cache deception."""
        logger.debug("[CacheDeception] Testing delimiter injection")

        delimiters = self.config.test_delimiters if self.config else PATH_DELIMITERS[:6]

        for delimiter in delimiters:
            for ext in [".css", ".js", ".png"]:
                # Create deception URL with delimiter
                deception_url = f"{target_url}{delimiter}fake{ext}"

                results = await self._perform_deception_test(
                    target_url,
                    deception_url,
                    original_hash,
                    original_response,
                    CacheDeceptionType.DELIMITER_INJECTION,
                )

                if results and results.private_data_cached:
                    self._create_finding(
                        vuln_type=CacheDeceptionType.DELIMITER_INJECTION,
                        original_url=target_url,
                        deception_url=deception_url,
                        test_results=[results],
                        description=f"Cache deception via delimiter injection. "
                                   f"Using delimiter '{delimiter}' causes private content caching.",
                    )
                    return

    async def _test_query_caching(
        self,
        target_url: str,
        original_hash: str,
        original_response: Dict[str, Any],
    ) -> None:
        """Test query string caching behavior."""
        logger.debug("[CacheDeception] Testing query caching")

        # Test if cache ignores query string
        cache_buster = uuid.uuid4().hex[:8]
        test_url = f"{target_url}?cb={cache_buster}"

        results = await self._perform_deception_test(
            target_url,
            test_url,
            original_hash,
            original_response,
            CacheDeceptionType.QUERY_CACHING,
        )

        if results and results.cache_status.is_cached:
            # Cache might be ignoring query string
            self._create_finding(
                vuln_type=CacheDeceptionType.QUERY_CACHING,
                original_url=target_url,
                deception_url=test_url,
                test_results=[results],
                description="Cache may be ignoring query string parameters, "
                           "allowing cache key manipulation.",
            )

    async def _test_normalization(
        self,
        target_url: str,
        original_hash: str,
        original_response: Dict[str, Any],
    ) -> None:
        """Test path normalization differences."""
        logger.debug("[CacheDeception] Testing path normalization")

        parsed = urlparse(target_url)
        base_path = parsed.path

        # Normalization tests
        normalization_paths = [
            f"{base_path}/../{base_path.split('/')[-1]}",  # Path traversal
            f"{base_path}/./",                              # Current dir
            f"{base_path}//",                               # Double slash
            f"{base_path}%2f",                              # Encoded slash
        ]

        for test_path in normalization_paths:
            test_url = f"{parsed.scheme}://{parsed.netloc}{test_path}"

            results = await self._perform_deception_test(
                target_url,
                test_url,
                original_hash,
                original_response,
                CacheDeceptionType.NORMALIZATION_DIFF,
            )

            if results and results.content_matches and results.cache_status.is_cached:
                self._create_finding(
                    vuln_type=CacheDeceptionType.NORMALIZATION_DIFF,
                    original_url=target_url,
                    deception_url=test_url,
                    test_results=[results],
                    description="Path normalization difference between origin and cache. "
                               "Different paths resolve to same content but cache separately.",
                )
                return

    async def _perform_deception_test(
        self,
        original_url: str,
        deception_url: str,
        original_hash: str,
        original_response: Dict[str, Any],
        test_type: CacheDeceptionType,
    ) -> Optional[DeceptionTestResult]:
        """Perform cache deception test."""
        # First request - should populate cache if vulnerable
        response1 = await self._get_response(deception_url)
        if not response1 or response1["code"] != 200:
            return None

        # Check if response matches original (indicates path confusion worked)
        response1_hash = self._hash_content(response1["body"])
        content_matches = self._content_similarity(original_response["body"], response1["body"]) > 0.8

        if not content_matches:
            return None  # Deception URL returns different content

        # Wait for cache to store
        wait_time = self.config.cache_wait_time if self.config else 2.0
        await asyncio.sleep(wait_time)

        # Second request without auth - check if cached
        response2 = await self._get_response(deception_url, headers={"Cookie": ""})
        if not response2:
            return None

        # Analyze cache status
        cache_status = self.cache_analyzer.analyze(response2["headers"])

        # Check if private data was cached
        has_private_data = self._contains_private_data(original_response["body"])
        response2_has_private = self._contains_private_data(response2["body"])

        private_data_cached = has_private_data and response2_has_private and cache_status.is_cached

        return DeceptionTestResult(
            test_type=test_type,
            original_url=original_url,
            deception_url=deception_url,
            original_response_hash=original_hash,
            cached_response_hash=self._hash_content(response2["body"]),
            content_matches=content_matches,
            private_data_cached=private_data_cached,
            cache_status=cache_status,
            evidence={
                "original_length": len(original_response["body"]),
                "cached_length": len(response2["body"]),
                "cache_headers": {h: response2["headers"].get(h) for h in CACHE_HEADERS if h in response2["headers"]},
            },
        )

    def _content_similarity(self, content1: str, content2: str) -> float:
        """Calculate content similarity (0.0 to 1.0)."""
        if not content1 or not content2:
            return 0.0

        # Simple length-based similarity for efficiency
        len1, len2 = len(content1), len(content2)
        if len1 == 0 and len2 == 0:
            return 1.0
        if len1 == 0 or len2 == 0:
            return 0.0

        # Length ratio
        length_ratio = min(len1, len2) / max(len1, len2)

        # Hash comparison (exact match)
        if self._hash_content(content1) == self._hash_content(content2):
            return 1.0

        return length_ratio * 0.8  # Adjust for non-exact match

    def _create_finding(
        self,
        vuln_type: CacheDeceptionType,
        original_url: str,
        deception_url: str,
        test_results: List[DeceptionTestResult],
        description: str,
    ) -> None:
        """Create and store a finding."""
        finding = CacheDeceptionFinding(
            id=f"CACHE-DEC-{len(self.findings)+1:04d}",
            vuln_type=vuln_type,
            severity="HIGH",
            confidence=0.85,
            original_url=original_url,
            deception_url=deception_url,
            description=description,
            impact="Attackers can steal private user data by tricking the cache into storing "
                  "authenticated responses and then accessing them without authentication.",
            remediation=self._generate_remediation(),
            test_results=test_results,
            cwe_id=self.CWE_ID,
            cvss_score=7.5,
            poc_steps=self._generate_poc_steps(original_url, deception_url),
        )

        self.findings.append(finding)
        logger.info(f"[CacheDeception] Found: {vuln_type.name}")

    def _generate_remediation(self) -> str:
        """Generate remediation advice."""
        return """
Web Cache Deception Prevention:

1. Cache Configuration:
   - Only cache files with known static extensions
   - Validate Content-Type matches expected type for cached resources
   - Use Cache-Control: private for authenticated content
   - Add Cache-Control: no-store for sensitive pages

2. Origin Server:
   - Return 404 for non-existent paths like /account/fake.css
   - Validate file extensions on the server
   - Don't serve dynamic content when path ends with static extension

3. CDN/Cache Rules:
   - Configure cache to check Content-Type before caching
   - Use Vary: Cookie to prevent cross-user caching
   - Implement cache key normalization

4. Path Handling:
   - Normalize paths before processing
   - Reject requests with suspicious delimiters
   - Use strict URL parsing
"""

    def _generate_poc_steps(self, original_url: str, deception_url: str) -> List[str]:
        """Generate PoC steps."""
        return [
            f"1. Victim is logged in and visits: {original_url}",
            f"2. Attacker sends victim a link: {deception_url}",
            "3. Victim clicks the link (while authenticated)",
            "4. Cache stores the authenticated response thinking it's a static file",
            f"5. Attacker (unauthenticated) visits: {deception_url}",
            "6. Attacker receives victim's cached private data",
        ]

    def get_findings(self) -> List[CacheDeceptionFinding]:
        """Get all findings."""
        return self.findings


# =============================================================================
# FACTORY FUNCTIONS
# =============================================================================

def create_cache_deception_scanner(
    http_client: Any = None,
    config: Optional[ScanConfig] = None,
) -> CacheDeceptionScanner:
    """Create a configured cache deception scanner instance."""
    return CacheDeceptionScanner(http_client=http_client, config=config)


async def scan_cache_deception(
    target_url: str,
    http_client: Any = None,
    **kwargs,
) -> List[CacheDeceptionFinding]:
    """Convenience function to scan for cache deception."""
    scanner = create_cache_deception_scanner(http_client=http_client)
    return await scanner.scan(target_url, **kwargs)


__all__ = [
    "VERSION",
    "CacheDeceptionType",
    "CacheIndicator",
    "CacheStatus",
    "DeceptionTestResult",
    "CacheDeceptionFinding",
    "ScanConfig",
    "CacheDeceptionScanner",
    "CacheAnalyzer",
    "STATIC_EXTENSIONS",
    "PATH_DELIMITERS",
    "CACHE_HEADERS",
    "create_cache_deception_scanner",
    "scan_cache_deception",
]
