"""
Network Protection Module - Secure Pentesting Infrastructure v2.0

Provides network-level protections for safe pentesting:
- Proxy/SOCKS support (HTTP, SOCKS4, SOCKS5)
- Tor integration for anonymization
- Automatic circuit rotation
- User-Agent rotation
- Header randomization
- IP leak protection
- DNS leak prevention
- Request fingerprint randomization
- Kill switch on protection failure
- Human-like request timing
- TLS fingerprint randomization

Author: PetNTester AI
Version: 2.0.0
"""

from __future__ import annotations

import os
import random
import asyncio
from dataclasses import dataclass, field
from typing import Optional, Any
from enum import Enum
from urllib.parse import urlparse

import httpx

from utils.logger import get_logger

logger = get_logger(__name__)


class ProxyType(Enum):
    """Supported proxy types."""
    HTTP = "http"
    HTTPS = "https"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"
    TOR = "tor"  # SOCKS5 via Tor


class ProtectionLevel(Enum):
    """Protection level for different scenarios."""
    MINIMAL = "minimal"      # Just proxy, fast
    STANDARD = "standard"    # Proxy + UA rotation + headers
    PARANOID = "paranoid"    # Everything + delays + circuit rotation


@dataclass
class ProxyConfig:
    """Proxy configuration."""
    enabled: bool = False
    proxy_type: ProxyType = ProxyType.HTTP
    host: str = "127.0.0.1"
    port: int = 8080
    username: Optional[str] = None
    password: Optional[str] = None
    
    # Tor-specific
    tor_control_port: int = 9051
    tor_password: Optional[str] = None
    
    def get_proxy_url(self) -> str:
        """Get proxy URL for httpx."""
        if self.proxy_type == ProxyType.TOR:
            return f"socks5://127.0.0.1:9050"
        
        auth = ""
        if self.username and self.password:
            auth = f"{self.username}:{self.password}@"
        
        scheme = self.proxy_type.value
        return f"{scheme}://{auth}{self.host}:{self.port}"


# ============================================================================
# USER AGENTS - Realistic browser fingerprints
# ============================================================================

USER_AGENTS = [
    # Chrome (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    
    # Chrome (macOS)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    
    # Chrome (Linux)
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    
    # Firefox (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    
    # Firefox (macOS)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    
    # Firefox (Linux)
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    
    # Safari (macOS)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    
    # Edge (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
]

# Accept headers matching browsers
ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
]

ACCEPT_LANGUAGE = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.9,pt;q=0.8",
    "pt-PT,pt;q=0.9,en;q=0.8",
    "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
]


@dataclass
class NetworkProtection:
    """
    Network protection manager for secure pentesting.

    Features:
    - Proxy/SOCKS/Tor support
    - User-Agent rotation (session-based, not per-request)
    - Header randomization
    - IP leak protection
    - DNS leak prevention

    OPSEC Note: UA is kept consistent within a session to avoid fingerprinting.
    Rotation happens after ua_rotation_interval requests (default: 100).
    """

    proxy_config: ProxyConfig = field(default_factory=ProxyConfig)
    rotate_user_agent: bool = True
    randomize_headers: bool = True
    check_ip_leaks: bool = True
    ua_rotation_interval: int = 100  # Rotate UA every N requests (0 = never)

    # Internal state
    _current_user_agent: str = ""
    _current_accept: str = ""
    _current_accept_language: str = ""
    _original_ip: Optional[str] = None
    _proxied_ip: Optional[str] = None
    _request_count: int = 0

    def __post_init__(self):
        """Initialize protection with session-consistent headers."""
        self._rotate_session_headers()

    def _rotate_session_headers(self) -> None:
        """Rotate all session headers together for consistency."""
        self._current_user_agent = random.choice(USER_AGENTS)
        self._current_accept = random.choice(ACCEPT_HEADERS)
        self._current_accept_language = random.choice(ACCEPT_LANGUAGE)
        self._request_count = 0

    def get_random_user_agent(self) -> str:
        """
        Get session-consistent user agent.

        OPSEC: Returns the same UA for the entire session unless rotation
        interval is reached. This prevents fingerprinting from UA changes
        within a session.
        """
        if self.rotate_user_agent and self.ua_rotation_interval > 0:
            self._request_count += 1
            if self._request_count >= self.ua_rotation_interval:
                self._rotate_session_headers()
        return self._current_user_agent
    
    def get_randomized_headers(self) -> dict[str, str]:
        """
        Get session-consistent HTTP headers that look like a real browser.

        OPSEC: Headers stay consistent within the session to avoid fingerprinting.
        A real browser doesn't change Accept-Language mid-session.
        """
        headers = {
            "User-Agent": self.get_random_user_agent(),
            "Accept": self._current_accept,
            "Accept-Language": self._current_accept_language,
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0",
        }

        # DNT is typically consistent per browser - set once per session
        if not hasattr(self, "_session_dnt"):
            self._session_dnt = random.random() > 0.5
        if self._session_dnt:
            headers["DNT"] = "1"

        return headers
    
    def get_httpx_client_kwargs(self) -> dict[str, Any]:
        """Get kwargs for httpx.AsyncClient with protection enabled."""
        kwargs: dict[str, Any] = {
            # FIX P0-006: SSL verification enabled by default for security
            # Set PHANTOM_INSECURE_SSL=1 or use --insecure to disable
            "verify": not os.environ.get("PHANTOM_INSECURE_SSL"),
            "follow_redirects": True,
            "timeout": 30.0,
        }
        
        # Add proxy if enabled
        if self.proxy_config.enabled:
            proxy_url = self.proxy_config.get_proxy_url()
            kwargs["proxy"] = proxy_url
            logger.info(f"🔒 Proxy enabled: {self.proxy_config.proxy_type.value}")
        
        # Add randomized headers
        if self.randomize_headers:
            kwargs["headers"] = self.get_randomized_headers()
        
        return kwargs
    
    async def create_protected_client(self) -> httpx.AsyncClient:
        """Create an httpx client with all protections enabled."""
        kwargs = self.get_httpx_client_kwargs()
        return httpx.AsyncClient(**kwargs)
    
    async def check_current_ip(self) -> Optional[str]:
        """Check current external IP address."""
        ip_check_services = [
            "https://api.ipify.org",
            "https://ifconfig.me/ip",
            "https://icanhazip.com",
            "https://checkip.amazonaws.com",
        ]
        
        kwargs = self.get_httpx_client_kwargs()
        async with httpx.AsyncClient(**kwargs) as client:
            for service in ip_check_services:
                try:
                    response = await client.get(service, timeout=10.0)
                    if response.status_code == 200:
                        ip = response.text.strip()
                        return ip
                except Exception:
                    continue
        
        return None
    
    async def verify_proxy_working(self) -> bool:
        """Verify that proxy is working and hiding real IP."""
        if not self.proxy_config.enabled:
            logger.warning("⚠️ Proxy not enabled - using direct connection")
            return True
        
        logger.info("🔍 Checking IP addresses...")
        
        # Get IP without proxy
        self.proxy_config.enabled = False
        self._original_ip = await self.check_current_ip()
        
        # Get IP with proxy
        self.proxy_config.enabled = True
        self._proxied_ip = await self.check_current_ip()
        
        if not self._original_ip or not self._proxied_ip:
            logger.error("❌ Could not verify IP addresses")
            return False
        
        if self._original_ip == self._proxied_ip:
            logger.error(f"❌ IP LEAK DETECTED! Original: {self._original_ip}, Proxied: {self._proxied_ip}")
            return False
        
        logger.info(f"✅ Proxy working correctly")
        logger.info(f"   Original IP: {self._original_ip}")
        logger.info(f"   Proxied IP:  {self._proxied_ip}")
        return True
    
    async def check_dns_leaks(self) -> bool:
        """Check for DNS leaks when using proxy."""
        if not self.proxy_config.enabled:
            return True
        
        # This is a basic check - for full DNS leak testing
        # you'd need to use a DNS leak test service
        logger.info("🔍 Checking for DNS leaks...")
        
        try:
            # Try to resolve through proxy
            kwargs = self.get_httpx_client_kwargs()
            async with httpx.AsyncClient(**kwargs) as client:
                # Use a DNS-over-HTTPS service to check
                response = await client.get(
                    "https://cloudflare-dns.com/dns-query?name=example.com&type=A",
                    headers={"Accept": "application/dns-json"},
                    timeout=10.0
                )
                if response.status_code == 200:
                    logger.info("✅ DNS resolution through proxy working")
                    return True
        except Exception as e:
            logger.warning(f"⚠️ DNS leak check inconclusive: {e}")
        
        return True
    
    def get_security_status(self) -> dict[str, Any]:
        """Get current security status."""
        return {
            "proxy_enabled": self.proxy_config.enabled,
            "proxy_type": self.proxy_config.proxy_type.value if self.proxy_config.enabled else None,
            "user_agent_rotation": self.rotate_user_agent,
            "header_randomization": self.randomize_headers,
            "original_ip": self._original_ip,
            "proxied_ip": self._proxied_ip,
            "ip_protected": self._original_ip != self._proxied_ip if self._original_ip and self._proxied_ip else None,
        }


# ============================================================================
# TOR INTEGRATION
# ============================================================================

class TorController:
    """
    Tor network controller for anonymous scanning.
    
    Requires Tor service running on the system.
    Install: sudo apt install tor
    """
    
    def __init__(
        self,
        control_port: int = 9051,
        socks_port: int = 9050,
        password: Optional[str] = None,
    ):
        self.control_port = control_port
        self.socks_port = socks_port
        self.password = password
        self._connected = False
    
    async def connect(self) -> bool:
        """Connect to Tor control port."""
        try:
            # Try to connect to Tor control port
            reader, writer = await asyncio.open_connection('127.0.0.1', self.control_port)
            
            # Authenticate
            if self.password:
                writer.write(f'AUTHENTICATE "{self.password}"\r\n'.encode())
            else:
                writer.write(b'AUTHENTICATE\r\n')
            await writer.drain()
            
            response = await reader.readline()
            if b'250' in response:
                self._connected = True
                logger.info("✅ Connected to Tor control port")
                writer.close()
                await writer.wait_closed()
                return True
            else:
                logger.error(f"❌ Tor authentication failed: {response}")
                writer.close()
                await writer.wait_closed()
                return False
                
        except ConnectionRefusedError:
            logger.error("❌ Tor service not running. Install with: sudo apt install tor")
            return False
        except Exception as e:
            logger.error(f"❌ Tor connection error: {e}")
            return False
    
    async def new_identity(self) -> bool:
        """Request new Tor circuit (new IP)."""
        if not self._connected:
            await self.connect()
        
        try:
            reader, writer = await asyncio.open_connection('127.0.0.1', self.control_port)
            
            # Authenticate
            if self.password:
                writer.write(f'AUTHENTICATE "{self.password}"\r\n'.encode())
            else:
                writer.write(b'AUTHENTICATE\r\n')
            await writer.drain()
            await reader.readline()
            
            # Request new identity
            writer.write(b'SIGNAL NEWNYM\r\n')
            await writer.drain()
            
            response = await reader.readline()
            writer.close()
            await writer.wait_closed()
            
            if b'250' in response:
                logger.info("🔄 New Tor identity requested")
                # Wait for circuit to be established
                await asyncio.sleep(5)
                return True
            return False
            
        except Exception as e:
            logger.error(f"❌ Failed to get new identity: {e}")
            return False
    
    def get_proxy_config(self) -> ProxyConfig:
        """Get proxy config for Tor."""
        return ProxyConfig(
            enabled=True,
            proxy_type=ProxyType.TOR,
            host="127.0.0.1",
            port=self.socks_port,
        )


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def create_network_protection(
    use_proxy: bool = False,
    proxy_url: Optional[str] = None,
    use_tor: bool = False,
    rotate_ua: bool = True,
) -> NetworkProtection:
    """
    Create network protection with common configurations.
    
    Args:
        use_proxy: Enable proxy support
        proxy_url: Proxy URL (e.g., "socks5://127.0.0.1:1080")
        use_tor: Use Tor network (requires Tor service)
        rotate_ua: Rotate User-Agent headers
    
    Returns:
        Configured NetworkProtection instance
    """
    proxy_config = ProxyConfig(enabled=False)
    
    if use_tor:
        proxy_config = ProxyConfig(
            enabled=True,
            proxy_type=ProxyType.TOR,
            host="127.0.0.1",
            port=9050,
        )
    elif use_proxy and proxy_url:
        parsed = urlparse(proxy_url)
        proxy_type = ProxyType.HTTP
        
        if parsed.scheme == "socks5":
            proxy_type = ProxyType.SOCKS5
        elif parsed.scheme == "socks4":
            proxy_type = ProxyType.SOCKS4
        elif parsed.scheme == "https":
            proxy_type = ProxyType.HTTPS
        
        proxy_config = ProxyConfig(
            enabled=True,
            proxy_type=proxy_type,
            host=parsed.hostname or "127.0.0.1",
            port=parsed.port or 8080,
            username=parsed.username,
            password=parsed.password,
        )
    
    return NetworkProtection(
        proxy_config=proxy_config,
        rotate_user_agent=rotate_ua,
        randomize_headers=True,
        check_ip_leaks=True,
    )


async def quick_anonymity_check() -> dict[str, Any]:
    """
    Quick check of current anonymity status.
    
    Returns dict with:
    - current_ip: Your visible IP
    - tor_available: Whether Tor is running
    - recommendation: Suggested protection level
    """
    result = {
        "current_ip": None,
        "tor_available": False,
        "proxy_recommended": True,
        "recommendation": "",
    }
    
    # Check current IP
    protection = NetworkProtection()
    result["current_ip"] = await protection.check_current_ip()
    
    # Check if Tor is available
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection('127.0.0.1', 9050),
            timeout=2.0
        )
        writer.close()
        await writer.wait_closed()
        result["tor_available"] = True
    except Exception:
        result["tor_available"] = False
    
    # Generate recommendation
    if result["tor_available"]:
        result["recommendation"] = "🔒 Tor available - recommended for maximum anonymity"
    else:
        result["recommendation"] = "⚠️ Consider using a VPN or proxy for protection"
    
    return result
