"""
Network utility functions.
"""

from __future__ import annotations

import asyncio
import socket
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse

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

# Local network prefixes for protocol detection
_LOCAL_PREFIXES = ("localhost", "127.", "192.168.", "10.", "172.16.", "172.17.",
                   "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                   "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                   "172.30.", "172.31.", "[::1]", "0.0.0.0")


def resolve_base_url(host: str) -> str:
    """
    Resolve a host to a full base URL with appropriate protocol.

    Uses http:// for localhost/local IPs, https:// for external hosts.
    If the host already has a protocol, returns it as-is.

    Args:
        host: Hostname, IP, or full URL

    Returns:
        Full URL with protocol (e.g., "https://example.com")
    """
    if host.startswith(("http://", "https://")):
        return host.rstrip("/")

    # Check if it's a local address
    host_lower = host.lower()
    is_local = any(host_lower.startswith(p) for p in _LOCAL_PREFIXES)

    protocol = "http://" if is_local else "https://"
    return f"{protocol}{host}".rstrip("/")


class NetworkError(Exception):
    """Network-related error."""
    pass


class TimeoutError(NetworkError):
    """Request timeout."""
    pass


class ConnectionError(NetworkError):
    """Connection failed."""
    pass


@retry(
    retry=retry_if_exception_type((httpx.TimeoutException, httpx.ConnectError)),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
)
async def async_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: dict[str, Any] | None = None,
    json_data: dict[str, Any] | None = None,
    timeout: float = 30.0,
    follow_redirects: bool = True,
    verify_ssl: bool = True,
    proxy: str | None = None,
) -> httpx.Response:
    """
    Make an async HTTP request with retry logic.
    
    Args:
        url: Request URL
        method: HTTP method
        headers: Request headers
        data: Form data
        json_data: JSON data
        timeout: Request timeout in seconds
        follow_redirects: Follow redirects
        verify_ssl: Verify SSL certificates
        proxy: Proxy URL
        
    Returns:
        HTTP response
        
    Raises:
        NetworkError: On network failures
    """
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=follow_redirects,
            verify=verify_ssl,
            proxy=proxy,
        ) as client:
            response = await client.request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                json=json_data,
            )
            return response
            
    except httpx.TimeoutException:
        raise TimeoutError(f"Request timed out: {url}")
    except httpx.ConnectError as e:
        raise ConnectionError(f"Connection failed: {url} - {e}")
    except httpx.RequestError as e:
        raise NetworkError(f"Request failed: {url} - {e}")


async def async_get(
    url: str,
    **kwargs: Any,
) -> httpx.Response:
    """
    Make async GET request.
    
    Args:
        url: Request URL
        **kwargs: Additional arguments for async_request
        
    Returns:
        HTTP response
    """
    return await async_request(url, method="GET", **kwargs)


async def async_post(
    url: str,
    **kwargs: Any,
) -> httpx.Response:
    """
    Make async POST request.
    
    Args:
        url: Request URL
        **kwargs: Additional arguments for async_request
        
    Returns:
        HTTP response
    """
    return await async_request(url, method="POST", **kwargs)


async def resolve_domain(
    domain: str,
    record_type: str = "A",
    timeout: float = 10.0,
) -> list[str]:
    """
    Resolve domain to IP addresses with timeout protection.

    SECURITY: Uses timeout to prevent indefinite blocking (CWE-833).

    Args:
        domain: Domain name
        record_type: DNS record type (A, AAAA, etc.)
        timeout: DNS resolution timeout in seconds (default 10s)

    Returns:
        List of resolved IPs
    """
    try:
        loop = asyncio.get_event_loop()

        if record_type == "A":
            family = socket.AF_INET
        elif record_type == "AAAA":
            family = socket.AF_INET6
        else:
            family = socket.AF_UNSPEC

        # Wrap in timeout to prevent indefinite blocking
        result = await asyncio.wait_for(
            loop.getaddrinfo(
                domain,
                None,
                family=family,
                type=socket.SOCK_STREAM,
            ),
            timeout=timeout,
        )

        ips = list({addr[4][0] for addr in result})
        return ips

    except asyncio.TimeoutError:
        logger.warning(f"DNS resolution timeout for {domain} after {timeout}s")
        return []
    except socket.gaierror as e:
        logger.debug(f"DNS resolution failed for {domain}: {e}")
        return []
    except (socket.herror, OSError) as e:
        logger.error(f"DNS resolution error for {domain}: {e}")
        return []


async def reverse_dns(ip: str, timeout: float = 10.0) -> str | None:
    """
    Perform reverse DNS lookup with timeout protection.

    SECURITY: Uses timeout to prevent indefinite blocking (CWE-833).

    Args:
        ip: IP address
        timeout: DNS lookup timeout in seconds (default 10s)

    Returns:
        Hostname or None
    """
    try:
        loop = asyncio.get_event_loop()
        result = await asyncio.wait_for(
            loop.getnameinfo((ip, 0), socket.NI_NAMEREQD),
            timeout=timeout,
        )
        return result[0]
    except asyncio.TimeoutError:
        logger.debug(f"Reverse DNS timeout for {ip}")
        return None
    except (socket.herror, socket.gaierror, OSError):
        return None


async def check_port(
    host: str,
    port: int,
    timeout: float = 3.0,
) -> bool:
    """
    Check if port is open.
    
    Args:
        host: Target host
        port: Port number
        timeout: Connection timeout
        
    Returns:
        True if port is open
    """
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
        return False


async def grab_banner(
    host: str,
    port: int,
    timeout: float = 5.0,
) -> str | None:
    """
    Grab service banner from port.
    
    Args:
        host: Target host
        port: Port number
        timeout: Connection timeout
        
    Returns:
        Banner string or None
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        
        # Try to read banner
        try:
            banner = await asyncio.wait_for(
                reader.read(1024),
                timeout=timeout,
            )
            return banner.decode("utf-8", errors="ignore").strip()
        except asyncio.TimeoutError:
            # Some services need stimulus
            writer.write(b"\r\n")
            await writer.drain()
            
            banner = await asyncio.wait_for(
                reader.read(1024),
                timeout=timeout,
            )
            return banner.decode("utf-8", errors="ignore").strip()
        finally:
            writer.close()
            await writer.wait_closed()

    except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
        return None


def normalize_url(url: str, base_url: str | None = None) -> str:
    """
    Normalize URL.
    
    Args:
        url: URL to normalize
        base_url: Optional base URL for relative URLs
        
    Returns:
        Normalized URL
    """
    url = url.strip()
    
    # Handle relative URLs
    if base_url and not url.startswith(("http://", "https://")):
        url = urljoin(base_url, url)
    
    # Parse and rebuild
    parsed = urlparse(url)
    
    # Normalize scheme
    scheme = parsed.scheme.lower() or "https"
    
    # Normalize host
    host = parsed.netloc.lower()
    
    # Normalize path
    path = parsed.path or "/"
    path = path.rstrip("/") if path != "/" else path
    
    # Rebuild
    normalized = f"{scheme}://{host}{path}"
    
    if parsed.query:
        normalized += f"?{parsed.query}"
    
    return normalized


def extract_links(html: str, base_url: str) -> list[str]:
    """
    Extract links from HTML.
    
    Args:
        html: HTML content
        base_url: Base URL for relative links
        
    Returns:
        List of absolute URLs
    """
    import re
    
    links = set()
    
    # Find href attributes
    href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
    for match in href_pattern.finditer(html):
        href = match.group(1)
        if not href.startswith(("javascript:", "mailto:", "tel:", "#")):
            links.add(normalize_url(href, base_url))
    
    # Find src attributes
    src_pattern = re.compile(r'src=["\']([^"\']+)["\']', re.IGNORECASE)
    for match in src_pattern.finditer(html):
        src = match.group(1)
        if not src.startswith("data:"):
            links.add(normalize_url(src, base_url))
    
    return list(links)


def is_same_domain(url1: str, url2: str) -> bool:
    """
    Check if two URLs are on the same domain.
    
    Args:
        url1: First URL
        url2: Second URL
        
    Returns:
        True if same domain
    """
    try:
        host1 = urlparse(url1).netloc.lower().split(":")[0]
        host2 = urlparse(url2).netloc.lower().split(":")[0]
        return host1 == host2
    except (ValueError, AttributeError):
        return False


def get_root_domain(url: str) -> str:
    """
    Get root domain from URL.
    
    Args:
        url: URL string
        
    Returns:
        Root domain
    """
    from utils.validators import extract_base_domain
    
    parsed = urlparse(url)
    host = parsed.netloc.split(":")[0]
    return extract_base_domain(host)


class HTTPClient:
    """
    Reusable HTTP client with session management.
    
    Supports rate limiting and concurrent request management.
    """
    
    def __init__(
        self,
        settings: Settings | None = None,
        timeout: float = 30.0,
        max_connections: int = 100,
        verify_ssl: bool = True,
    ) -> None:
        """
        Initialize client.
        
        Args:
            settings: Application settings
            timeout: Default timeout
            max_connections: Max concurrent connections
            verify_ssl: Verify SSL certificates
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        
        limits = httpx.Limits(
            max_connections=max_connections,
            max_keepalive_connections=20,
        )
        
        self._client: httpx.AsyncClient | None = None
        self._limits = limits
    
    async def __aenter__(self) -> HTTPClient:
        """Enter async context."""
        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            verify=self.verify_ssl,
            limits=self._limits,
            follow_redirects=True,
        )
        return self
    
    async def __aexit__(self, *args: Any) -> None:
        """Exit async context."""
        if self._client:
            await self._client.aclose()
    
    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        """Make GET request."""
        if not self._client:
            raise RuntimeError("Client not initialized. Use async with.")
        return await self._client.get(url, **kwargs)
    
    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        """Make POST request."""
        if not self._client:
            raise RuntimeError("Client not initialized. Use async with.")
        return await self._client.post(url, **kwargs)
    
    async def request(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response:
        """Make HTTP request."""
        if not self._client:
            raise RuntimeError("Client not initialized. Use async with.")
        return await self._client.request(method, url, **kwargs)
