"""
HTTP Transport Engine - Enterprise-Grade Request Handling v1.0.0

This module provides a global HTTP transport layer that handles:
- Automatic redirect following with protocol upgrade (HTTP → HTTPS)
- Canonical URL resolution BEFORE scanning
- Request classification (transport_layer vs application_layer)
- Loop protection and intelligent backoff
- Proper evidence collection (only counts requests that reach the app)

This is the FOUNDATION for all scanner modules.

Author: PenTester AI
Date: Janeiro 2026
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Callable
from urllib.parse import urljoin, urlparse, urlunparse

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

if TYPE_CHECKING:
    from core.config_manager import Settings

from utils.logger import get_logger

logger = get_logger(__name__)


# =============================================================================
# VERSION & CONSTANTS
# =============================================================================

HTTP_TRANSPORT_VERSION = "1.0.0-ENTERPRISE"

# Transport layer status codes (redirect, not reaching app)
TRANSPORT_LAYER_CODES = {301, 302, 303, 307, 308}

# Application layer status codes (reaching the app)
APPLICATION_LAYER_CODES = {
    200, 201, 202, 204,  # Success
    400, 401, 403, 404, 405, 406, 415, 422, 429,  # Client errors
    500, 501, 502, 503, 504,  # Server errors
}

# Max redirects before giving up (loop protection)
MAX_REDIRECTS = 5

# Default timeouts
DEFAULT_TIMEOUT = 30.0
CONNECT_TIMEOUT = 10.0


# =============================================================================
# ENUMS
# =============================================================================

class ResponseLayer(Enum):
    """Classification of where the response originated."""
    TRANSPORT = auto()      # Response from redirect/proxy layer
    APPLICATION = auto()    # Response from actual application
    UNKNOWN = auto()        # Cannot determine


class RequestStatus(Enum):
    """Status of a test request."""
    REACHED_APP = auto()          # Payload reached application layer
    REDIRECTED = auto()           # Was redirected, need to follow
    REDIRECT_LOOP = auto()        # Caught in redirect loop
    NOT_TESTED = auto()           # Never reached application
    PROTOCOL_UPGRADE = auto()     # HTTP→HTTPS upgrade occurred
    CONNECTION_FAILED = auto()    # Network/connection error
    TIMEOUT = auto()              # Request timed out


class ProtocolPolicy(Enum):
    """How to handle HTTP/HTTPS."""
    PREFER_HTTPS = auto()        # Try HTTPS first, fallback to HTTP
    FORCE_HTTPS = auto()         # Always use HTTPS, error if not available
    ALLOW_HTTP = auto()          # Allow HTTP (not recommended)
    AUTO_UPGRADE = auto()        # Auto upgrade HTTP→HTTPS on redirect


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class TransportResult:
    """
    Result of an HTTP request through the transport engine.
    
    Contains both the response AND metadata about how the request was handled.
    """
    # Response data
    response: httpx.Response | None = None
    status_code: int = 0
    final_url: str = ""
    content: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    
    # Transport metadata
    request_status: RequestStatus = RequestStatus.NOT_TESTED
    response_layer: ResponseLayer = ResponseLayer.UNKNOWN
    original_url: str = ""
    redirect_chain: list[str] = field(default_factory=list)
    redirect_count: int = 0
    protocol_upgraded: bool = False
    
    # Timing
    total_time_ms: float = 0.0
    
    # Error info
    error: str | None = None
    
    @property
    def reached_application(self) -> bool:
        """Check if request actually reached the application layer."""
        # PROTOCOL_UPGRADE still means we reached the app (just with a protocol change)
        return (
            self.request_status in (RequestStatus.REACHED_APP, RequestStatus.PROTOCOL_UPGRADE) and
            self.response_layer == ResponseLayer.APPLICATION
        )
    
    @property
    def is_valid_test(self) -> bool:
        """Check if this should count as a valid test attempt."""
        return self.reached_application
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging/storage."""
        return {
            "status_code": self.status_code,
            "final_url": self.final_url,
            "original_url": self.original_url,
            "request_status": self.request_status.name,
            "response_layer": self.response_layer.name,
            "redirect_chain": self.redirect_chain,
            "redirect_count": self.redirect_count,
            "protocol_upgraded": self.protocol_upgraded,
            "total_time_ms": self.total_time_ms,
            "reached_application": self.reached_application,
            "error": self.error,
        }


@dataclass
class CanonicalURL:
    """
    Resolved canonical URL for a target.
    
    Contains the normalized, working URL that should be used for all scans.
    """
    original: str
    canonical: str
    scheme: str
    host: str
    port: int | None
    path: str
    
    # Resolution info
    was_redirected: bool = False
    protocol_upgraded: bool = False
    www_normalized: bool = False
    
    # Validation
    is_valid: bool = False
    reachable: bool = False
    final_status_code: int = 0
    
    # Server info discovered during resolution
    server: str = ""
    detected_waf: str | None = None
    
    def __str__(self) -> str:
        return self.canonical


@dataclass
class TransportStats:
    """Statistics for transport layer operations."""
    total_requests: int = 0
    requests_reached_app: int = 0
    requests_redirected: int = 0
    requests_failed: int = 0
    protocol_upgrades: int = 0
    redirect_loops_detected: int = 0
    
    # Timing
    total_time_ms: float = 0.0
    avg_response_time_ms: float = 0.0
    
    # URLs
    unique_urls_tested: set[str] = field(default_factory=set)
    
    def record_request(self, result: TransportResult) -> None:
        """Record a request result."""
        self.total_requests += 1
        self.total_time_ms += result.total_time_ms
        
        if result.reached_application:
            self.requests_reached_app += 1
            self.unique_urls_tested.add(result.final_url)
        elif result.request_status == RequestStatus.REDIRECTED:
            self.requests_redirected += 1
        elif result.request_status == RequestStatus.REDIRECT_LOOP:
            self.redirect_loops_detected += 1
        elif result.request_status in (RequestStatus.CONNECTION_FAILED, RequestStatus.TIMEOUT):
            self.requests_failed += 1
        
        if result.protocol_upgraded:
            self.protocol_upgrades += 1
        
        # Update average
        if self.total_requests > 0:
            self.avg_response_time_ms = self.total_time_ms / self.total_requests
    
    def get_summary(self) -> dict[str, Any]:
        """Get summary statistics."""
        return {
            "total_requests": self.total_requests,
            "requests_reached_app": self.requests_reached_app,
            "requests_redirected": self.requests_redirected,
            "requests_failed": self.requests_failed,
            "protocol_upgrades": self.protocol_upgrades,
            "redirect_loops_detected": self.redirect_loops_detected,
            "unique_urls_tested": len(self.unique_urls_tested),
            "avg_response_time_ms": round(self.avg_response_time_ms, 2),
            "app_reach_rate": round(
                (self.requests_reached_app / self.total_requests * 100) 
                if self.total_requests > 0 else 0, 2
            ),
        }


# =============================================================================
# URL CANONICALIZER
# =============================================================================

class URLCanonicalizer:
    """
    Resolves and normalizes URLs to their canonical form.
    
    This should be called ONCE before scanning to determine:
    - The correct protocol (HTTP vs HTTPS)
    - The correct hostname (www vs non-www)
    - The actual endpoint that accepts requests
    
    Usage:
        canonicalizer = URLCanonicalizer()
        canonical = await canonicalizer.resolve("http://www.example.com")
        # canonical.canonical = "https://example.com"
    """
    
    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        verify_ssl: bool = False,  # Don't fail on bad certs during resolution
        protocol_policy: ProtocolPolicy = ProtocolPolicy.AUTO_UPGRADE,
    ):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.protocol_policy = protocol_policy
        self._cache: dict[str, CanonicalURL] = {}
    
    async def resolve(self, url: str) -> CanonicalURL:
        """
        Resolve a URL to its canonical form.
        
        Args:
            url: The URL to resolve
            
        Returns:
            CanonicalURL with the resolved, working URL
        """
        # Check cache first
        cache_key = self._normalize_for_cache(url)
        if cache_key in self._cache:
            logger.debug(f"URL canonical cache hit: {url}")
            return self._cache[cache_key]
        
        # Parse original URL
        parsed = self._parse_url(url)
        original_url = self._build_url(parsed)
        
        logger.info(f"🔍 Resolving canonical URL for: {original_url}")
        
        # Try HTTPS first if policy allows
        urls_to_try = self._get_urls_to_try(parsed)
        
        result = CanonicalURL(
            original=original_url,
            canonical=original_url,
            scheme=parsed["scheme"],
            host=parsed["host"],
            port=parsed["port"],
            path=parsed["path"],
        )
        
        for test_url in urls_to_try:
            try:
                resolution = await self._try_resolve(test_url)
                
                if resolution["reachable"]:
                    result.canonical = resolution["final_url"]
                    result.is_valid = True
                    result.reachable = True
                    result.final_status_code = resolution["status_code"]
                    result.was_redirected = resolution["was_redirected"]
                    result.server = resolution.get("server", "")
                    result.detected_waf = resolution.get("waf")
                    
                    # Check if protocol was upgraded
                    original_scheme = urlparse(original_url).scheme
                    final_scheme = urlparse(resolution["final_url"]).scheme
                    result.protocol_upgraded = (
                        original_scheme == "http" and final_scheme == "https"
                    )
                    
                    # Check if www was normalized
                    original_host = urlparse(original_url).netloc.lower()
                    final_host = urlparse(resolution["final_url"]).netloc.lower()
                    result.www_normalized = (
                        original_host.startswith("www.") and 
                        not final_host.startswith("www.")
                    ) or (
                        not original_host.startswith("www.") and
                        final_host.startswith("www.")
                    )
                    
                    # Update parsed info from final URL
                    final_parsed = urlparse(resolution["final_url"])
                    result.scheme = final_parsed.scheme
                    result.host = final_parsed.netloc.split(":")[0]
                    result.port = (
                        int(final_parsed.netloc.split(":")[1])
                        if ":" in final_parsed.netloc
                        else None
                    )
                    result.path = final_parsed.path or "/"
                    
                    logger.info(
                        f"✅ Canonical URL resolved: {result.canonical} "
                        f"(upgraded={result.protocol_upgraded}, "
                        f"www_normalized={result.www_normalized})"
                    )
                    break
                    
            except Exception as e:
                logger.debug(f"Failed to resolve {test_url}: {e}")
                continue
        
        if not result.reachable:
            logger.warning(f"⚠️ Could not resolve canonical URL for: {original_url}")
            result.canonical = original_url
        
        # Cache result
        self._cache[cache_key] = result
        return result
    
    async def _try_resolve(self, url: str) -> dict[str, Any]:
        """Try to resolve a single URL."""
        result = {
            "final_url": url,
            "reachable": False,
            "was_redirected": False,
            "status_code": 0,
            "server": "",
            "waf": None,
        }
        
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                max_redirects=MAX_REDIRECTS,
                verify=self.verify_ssl,
            ) as client:
                response = await client.get(url)
                
                result["final_url"] = str(response.url)
                result["status_code"] = response.status_code
                result["reachable"] = response.status_code not in TRANSPORT_LAYER_CODES
                result["was_redirected"] = str(response.url) != url
                result["server"] = response.headers.get("server", "")
                
                # Basic WAF detection
                result["waf"] = self._detect_waf(response.headers)
                
        except Exception as e:
            logger.debug(f"Resolution failed for {url}: {e}")
        
        return result
    
    def _detect_waf(self, headers: httpx.Headers) -> str | None:
        """Detect WAF from response headers."""
        waf_signatures = {
            "cloudflare": ["cf-ray", "cf-cache-status", "__cfduid"],
            "akamai": ["x-akamai-", "akamai-"],
            "aws_waf": ["x-amz-", "x-amzn-"],
            "imperva": ["x-cdn", "incap_ses"],
            "sucuri": ["x-sucuri-"],
            "f5_big_ip": ["x-wa-info", "bigipserver"],
            "fortinet": ["fortigate", "fortiwafsid"],
            "barracuda": ["barra_counter_session"],
            "azure_waf": ["x-azure-"],
        }
        
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for waf_name, signatures in waf_signatures.items():
            for sig in signatures:
                for header in headers_lower:
                    if sig in header:
                        return waf_name
        
        return None
    
    def _get_urls_to_try(self, parsed: dict) -> list[str]:
        """Get list of URLs to try based on policy."""
        urls = []
        base_host = parsed["host"]
        path = parsed["path"]
        
        # Handle www variations
        hosts = [base_host]
        if base_host.startswith("www."):
            hosts.append(base_host[4:])  # Without www
        else:
            hosts.append(f"www.{base_host}")  # With www
        
        if self.protocol_policy in (ProtocolPolicy.PREFER_HTTPS, ProtocolPolicy.FORCE_HTTPS, ProtocolPolicy.AUTO_UPGRADE):
            # Try HTTPS first
            for host in hosts:
                urls.append(f"https://{host}{path}")
            if self.protocol_policy != ProtocolPolicy.FORCE_HTTPS:
                for host in hosts:
                    urls.append(f"http://{host}{path}")
        else:
            # Original scheme first
            for host in hosts:
                urls.append(f"{parsed['scheme']}://{host}{path}")
        
        return urls
    
    def _parse_url(self, url: str) -> dict:
        """Parse URL into components."""
        # Add scheme if missing
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        
        parsed = urlparse(url)
        
        return {
            "scheme": parsed.scheme or "https",
            "host": parsed.netloc.split(":")[0].lower(),
            "port": (
                int(parsed.netloc.split(":")[1])
                if ":" in parsed.netloc
                else None
            ),
            "path": parsed.path or "/",
            "query": parsed.query,
        }
    
    def _build_url(self, parsed: dict) -> str:
        """Build URL from components."""
        host = parsed["host"]
        if parsed["port"]:
            host = f"{host}:{parsed['port']}"
        
        url = f"{parsed['scheme']}://{host}{parsed['path']}"
        if parsed.get("query"):
            url += f"?{parsed['query']}"
        
        return url
    
    def _normalize_for_cache(self, url: str) -> str:
        """Normalize URL for cache key."""
        parsed = self._parse_url(url)
        # Remove www for caching
        host = parsed["host"]
        if host.startswith("www."):
            host = host[4:]
        return f"{host}{parsed['path']}"
    
    def clear_cache(self) -> None:
        """Clear the URL cache."""
        self._cache.clear()


# =============================================================================
# HTTP TRANSPORT ENGINE
# =============================================================================

class HTTPTransportEngine:
    """
    Enterprise-grade HTTP transport engine for security scanning.
    
    This engine ensures that:
    1. All redirects are followed automatically
    2. Protocol upgrades (HTTP→HTTPS) are handled
    3. Only requests that REACH the application are counted
    4. Loop protection prevents infinite redirects
    5. Proper evidence is collected for valid tests only
    
    Usage:
        engine = HTTPTransportEngine()
        
        # Resolve canonical URL first
        canonical = await engine.resolve_canonical(target)
        
        # Make requests using canonical URL
        result = await engine.request("GET", canonical.canonical, params={"id": "1"})
        
        if result.reached_application:
            # This is a valid test attempt
            analyze_response(result.response)
        else:
            # NOT a valid test - don't count this
            log_transport_issue(result)
    """
    
    def __init__(
        self,
        settings: Any | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_redirects: int = MAX_REDIRECTS,
        verify_ssl: bool = False,
        protocol_policy: ProtocolPolicy = ProtocolPolicy.AUTO_UPGRADE,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    ):
        """
        Initialize transport engine.
        
        Args:
            settings: Application settings
            timeout: Request timeout in seconds
            max_redirects: Maximum number of redirects to follow
            verify_ssl: Whether to verify SSL certificates
            protocol_policy: How to handle HTTP/HTTPS
            user_agent: Default User-Agent header
        """
        self.settings = settings
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.verify_ssl = verify_ssl
        self.protocol_policy = protocol_policy
        self.user_agent = user_agent
        
        # Components
        self._canonicalizer = URLCanonicalizer(
            timeout=timeout,
            verify_ssl=verify_ssl,
            protocol_policy=protocol_policy,
        )
        
        # Statistics
        self.stats = TransportStats()
        
        # Client cache
        self._client: httpx.AsyncClient | None = None
        
        logger.info(f"HTTPTransportEngine v{HTTP_TRANSPORT_VERSION} initialized")
    
    async def __aenter__(self) -> HTTPTransportEngine:
        """Enter async context."""
        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            max_redirects=self.max_redirects,
            verify=self.verify_ssl,
            headers={"User-Agent": self.user_agent},
        )
        return self
    
    async def __aexit__(self, *args: Any) -> None:
        """Exit async context."""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    async def resolve_canonical(self, url: str) -> CanonicalURL:
        """
        Resolve a URL to its canonical form.
        
        This should be called ONCE before scanning to get the correct URL.
        
        Args:
            url: Target URL
            
        Returns:
            CanonicalURL with the resolved, working URL
        """
        return await self._canonicalizer.resolve(url)
    
    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        content: bytes | None = None,
        timeout: float | None = None,
        follow_redirects: bool = True,
    ) -> TransportResult:
        """
        Make an HTTP request with full transport handling.
        
        Args:
            method: HTTP method
            url: Request URL
            headers: Request headers
            params: Query parameters
            data: Form data
            json_data: JSON body
            content: Raw body content
            timeout: Custom timeout
            follow_redirects: Whether to follow redirects
            
        Returns:
            TransportResult with response and metadata
        """
        start_time = time.time()
        
        result = TransportResult(
            original_url=url,
            final_url=url,
        )
        
        # Merge headers
        request_headers = {"User-Agent": self.user_agent}
        if headers:
            request_headers.update(headers)
        
        try:
            # Create client if not in context manager
            client = self._client
            should_close = False
            
            if client is None:
                client = httpx.AsyncClient(
                    timeout=timeout or self.timeout,
                    follow_redirects=follow_redirects,
                    max_redirects=self.max_redirects,
                    verify=self.verify_ssl,
                )
                should_close = True
            
            try:
                # Make request
                response = await client.request(
                    method=method,
                    url=url,
                    headers=request_headers,
                    params=params,
                    data=data,
                    json=json_data,
                    content=content,
                )
                
                # Build result
                result.response = response
                result.status_code = response.status_code
                result.final_url = str(response.url)
                result.content = response.content
                result.headers = dict(response.headers)
                
                # Track redirect chain from history
                if response.history:
                    result.redirect_chain = [str(r.url) for r in response.history]
                    result.redirect_count = len(response.history)
                    result.protocol_upgraded = (
                        urlparse(url).scheme == "http" and
                        urlparse(str(response.url)).scheme == "https"
                    )
                
                # Classify response
                result.response_layer = self._classify_response(response)
                result.request_status = self._determine_status(result)
                
            finally:
                if should_close:
                    await client.aclose()
                    
        except httpx.TooManyRedirects:
            result.request_status = RequestStatus.REDIRECT_LOOP
            result.error = "Too many redirects - possible redirect loop"
            logger.warning(f"Redirect loop detected: {url}")
            
        except httpx.TimeoutException:
            result.request_status = RequestStatus.TIMEOUT
            result.error = "Request timed out"
            
        except httpx.ConnectError as e:
            result.request_status = RequestStatus.CONNECTION_FAILED
            result.error = f"Connection failed: {e}"
            
        except Exception as e:
            result.request_status = RequestStatus.CONNECTION_FAILED
            result.error = str(e)
            logger.error(f"Request failed: {url} - {e}")
        
        # Calculate timing
        result.total_time_ms = (time.time() - start_time) * 1000
        
        # Record stats
        self.stats.record_request(result)
        
        # Log appropriately
        self._log_request(result)
        
        return result
    
    async def get(self, url: str, **kwargs: Any) -> TransportResult:
        """Make GET request."""
        return await self.request("GET", url, **kwargs)
    
    async def post(self, url: str, **kwargs: Any) -> TransportResult:
        """Make POST request."""
        return await self.request("POST", url, **kwargs)
    
    async def put(self, url: str, **kwargs: Any) -> TransportResult:
        """Make PUT request."""
        return await self.request("PUT", url, **kwargs)
    
    async def delete(self, url: str, **kwargs: Any) -> TransportResult:
        """Make DELETE request."""
        return await self.request("DELETE", url, **kwargs)
    
    async def head(self, url: str, **kwargs: Any) -> TransportResult:
        """Make HEAD request."""
        return await self.request("HEAD", url, **kwargs)
    
    async def options(self, url: str, **kwargs: Any) -> TransportResult:
        """Make OPTIONS request."""
        return await self.request("OPTIONS", url, **kwargs)
    
    def _classify_response(self, response: httpx.Response) -> ResponseLayer:
        """Classify which layer the response came from."""
        status = response.status_code
        
        # Still a redirect (shouldn't happen with follow_redirects=True)
        if status in TRANSPORT_LAYER_CODES:
            return ResponseLayer.TRANSPORT
        
        # Application layer response
        if status in APPLICATION_LAYER_CODES or status >= 200:
            return ResponseLayer.APPLICATION
        
        return ResponseLayer.UNKNOWN
    
    def _determine_status(self, result: TransportResult) -> RequestStatus:
        """Determine the overall request status."""
        if result.error:
            if "redirect" in result.error.lower():
                return RequestStatus.REDIRECT_LOOP
            if "timeout" in result.error.lower():
                return RequestStatus.TIMEOUT
            return RequestStatus.CONNECTION_FAILED
        
        if result.response_layer == ResponseLayer.APPLICATION:
            if result.protocol_upgraded:
                return RequestStatus.PROTOCOL_UPGRADE
            return RequestStatus.REACHED_APP
        
        if result.response_layer == ResponseLayer.TRANSPORT:
            return RequestStatus.REDIRECTED
        
        return RequestStatus.NOT_TESTED
    
    def _log_request(self, result: TransportResult) -> None:
        """Log request with appropriate level."""
        if result.reached_application:
            logger.debug(
                f"✅ {result.status_code} {result.final_url} "
                f"({result.total_time_ms:.0f}ms)"
            )
        elif result.request_status == RequestStatus.PROTOCOL_UPGRADE:
            logger.info(
                f"🔄 Protocol upgrade: {result.original_url} → {result.final_url}"
            )
        elif result.request_status == RequestStatus.REDIRECT_LOOP:
            logger.warning(
                f"⚠️ Redirect loop: {result.original_url}"
            )
        elif result.request_status in (RequestStatus.CONNECTION_FAILED, RequestStatus.TIMEOUT):
            logger.warning(
                f"❌ Request failed: {result.original_url} - {result.error}"
            )
        else:
            logger.debug(
                f"🔶 Transport layer response: {result.original_url} "
                f"(status={result.request_status.name})"
            )
    
    def get_stats(self) -> dict[str, Any]:
        """Get transport statistics."""
        return self.stats.get_summary()
    
    def reset_stats(self) -> None:
        """Reset statistics."""
        self.stats = TransportStats()


# =============================================================================
# SMART BACKOFF / RATE LIMITING
# =============================================================================

class SmartBackoff:
    """
    Intelligent backoff based on transport layer responses.
    
    If we're getting many 301s (redirect only), backs off to avoid
    wasting requests on URLs that don't reach the app.
    """
    
    def __init__(
        self,
        initial_delay: float = 0.1,
        max_delay: float = 5.0,
        backoff_factor: float = 2.0,
        consecutive_redirects_threshold: int = 3,
    ):
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.backoff_factor = backoff_factor
        self.threshold = consecutive_redirects_threshold
        
        self._current_delay = initial_delay
        self._consecutive_redirects = 0
        self._consecutive_successes = 0
    
    async def wait(self) -> None:
        """Wait according to current backoff level."""
        if self._current_delay > 0:
            await asyncio.sleep(self._current_delay)
    
    def record_result(self, result: TransportResult) -> None:
        """Record a result and adjust backoff."""
        if result.reached_application:
            self._consecutive_successes += 1
            self._consecutive_redirects = 0
            
            # Reduce delay on consecutive successes
            if self._consecutive_successes >= 3:
                self._current_delay = max(
                    self.initial_delay,
                    self._current_delay / self.backoff_factor
                )
                self._consecutive_successes = 0
        else:
            self._consecutive_redirects += 1
            self._consecutive_successes = 0
            
            # Increase delay on consecutive redirects
            if self._consecutive_redirects >= self.threshold:
                self._current_delay = min(
                    self.max_delay,
                    self._current_delay * self.backoff_factor
                )
                logger.warning(
                    f"⏳ Backoff increased to {self._current_delay:.1f}s "
                    f"(consecutive non-app responses: {self._consecutive_redirects})"
                )
    
    def reset(self) -> None:
        """Reset backoff state."""
        self._current_delay = self.initial_delay
        self._consecutive_redirects = 0
        self._consecutive_successes = 0


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

async def resolve_target_url(target: str) -> CanonicalURL:
    """
    Convenience function to resolve a target URL.
    
    Args:
        target: Target URL or domain
        
    Returns:
        CanonicalURL with resolved URL
    """
    canonicalizer = URLCanonicalizer()
    return await canonicalizer.resolve(target)


async def make_smart_request(
    method: str,
    url: str,
    **kwargs: Any,
) -> TransportResult:
    """
    Convenience function for single requests.
    
    Args:
        method: HTTP method
        url: Request URL
        **kwargs: Additional arguments
        
    Returns:
        TransportResult
    """
    async with HTTPTransportEngine() as engine:
        return await engine.request(method, url, **kwargs)


def is_application_response(status_code: int) -> bool:
    """Check if status code indicates application layer response."""
    return status_code not in TRANSPORT_LAYER_CODES


def should_count_as_test(result: TransportResult) -> bool:
    """Check if a result should count as a valid test attempt."""
    return result.reached_application


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Version
    "HTTP_TRANSPORT_VERSION",
    
    # Enums
    "ResponseLayer",
    "RequestStatus",
    "ProtocolPolicy",
    
    # Data classes
    "TransportResult",
    "CanonicalURL",
    "TransportStats",
    
    # Main classes
    "URLCanonicalizer",
    "HTTPTransportEngine",
    "SmartBackoff",
    
    # Constants
    "TRANSPORT_LAYER_CODES",
    "APPLICATION_LAYER_CODES",
    "MAX_REDIRECTS",
    
    # Helper functions
    "resolve_target_url",
    "make_smart_request",
    "is_application_response",
    "should_count_as_test",
]
