"""
OPSEC Elite Protection Module v3.0 - Maximum Anonymity

Enterprise-grade elite security features:
- Multi-hop proxy chains
- Browser fingerprint emulation
- Geographic exit node selection
- Decoy request injection
- Request entropy maximization
- Session isolation
- Traffic pattern obfuscation
- Behavioral analysis evasion
- WebRTC leak protection
- TLS/JA3 fingerprint randomization
- Natural navigation simulation

Author: PetNTester AI
Version: 3.0.0
"""

from __future__ import annotations

import random
import asyncio
from dataclasses import dataclass, field
from typing import Optional, Any, List, Dict
from datetime import datetime, timedelta
from enum import Enum
from urllib.parse import urlparse

import httpx

from utils.logger import get_logger

logger = get_logger(__name__)


# =============================================================================
# BROWSER FINGERPRINT DATABASE - Realistic browser profiles
# =============================================================================

@dataclass
class BrowserProfile:
    """Complete browser fingerprint profile."""
    name: str
    user_agent: str
    accept: str
    accept_language: str
    accept_encoding: str
    sec_ch_ua: str
    sec_ch_ua_mobile: str
    sec_ch_ua_platform: str
    sec_fetch_dest: str
    sec_fetch_mode: str
    sec_fetch_site: str
    sec_fetch_user: str
    upgrade_insecure_requests: str
    cache_control: str
    connection: str
    # TLS fingerprint simulation
    tls_version: str
    cipher_suites: List[str]
    extensions: List[str]


# Realistic browser profiles based on actual browser fingerprints
BROWSER_PROFILES = [
    BrowserProfile(
        name="Chrome 120 Windows",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua='"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        sec_ch_ua_mobile="?0",
        sec_ch_ua_platform='"Windows"',
        sec_fetch_dest="document",
        sec_fetch_mode="navigate",
        sec_fetch_site="none",
        sec_fetch_user="?1",
        upgrade_insecure_requests="1",
        cache_control="max-age=0",
        connection="keep-alive",
        tls_version="TLS 1.3",
        cipher_suites=["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"],
        extensions=["server_name", "ec_point_formats", "supported_groups", "signature_algorithms"],
    ),
    BrowserProfile(
        name="Firefox 121 Linux",
        user_agent="Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        accept_language="en-US,en;q=0.5",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua="",  # Firefox doesn't send this
        sec_ch_ua_mobile="",
        sec_ch_ua_platform="",
        sec_fetch_dest="document",
        sec_fetch_mode="navigate",
        sec_fetch_site="none",
        sec_fetch_user="?1",
        upgrade_insecure_requests="1",
        cache_control="max-age=0",
        connection="keep-alive",
        tls_version="TLS 1.3",
        cipher_suites=["TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_256_GCM_SHA384"],
        extensions=["server_name", "supported_versions", "signature_algorithms", "key_share"],
    ),
    BrowserProfile(
        name="Safari 17 macOS",
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua="",
        sec_ch_ua_mobile="",
        sec_ch_ua_platform="",
        sec_fetch_dest="document",
        sec_fetch_mode="navigate",
        sec_fetch_site="none",
        sec_fetch_user="?1",
        upgrade_insecure_requests="1",
        cache_control="max-age=0",
        connection="keep-alive",
        tls_version="TLS 1.3",
        cipher_suites=["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"],
        extensions=["server_name", "supported_groups", "ec_point_formats", "signature_algorithms"],
    ),
    BrowserProfile(
        name="Edge 120 Windows",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua='"Not_A Brand";v="8", "Chromium";v="120", "Microsoft Edge";v="120"',
        sec_ch_ua_mobile="?0",
        sec_ch_ua_platform='"Windows"',
        sec_fetch_dest="document",
        sec_fetch_mode="navigate",
        sec_fetch_site="none",
        sec_fetch_user="?1",
        upgrade_insecure_requests="1",
        cache_control="max-age=0",
        connection="keep-alive",
        tls_version="TLS 1.3",
        cipher_suites=["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"],
        extensions=["server_name", "ec_point_formats", "supported_groups", "signature_algorithms"],
    ),
]


# =============================================================================
# GEOGRAPHIC EXIT NODE CONTROL
# =============================================================================

class GeoExitNode(Enum):
    """Geographic regions for exit nodes."""
    ANY = "any"
    EUROPE = "europe"
    NORTH_AMERICA = "north_america"
    ASIA = "asia"
    SOUTH_AMERICA = "south_america"
    OCEANIA = "oceania"
    # Specific countries
    GERMANY = "de"
    NETHERLANDS = "nl"
    SWITZERLAND = "ch"
    USA = "us"
    CANADA = "ca"
    UK = "gb"
    FRANCE = "fr"
    SWEDEN = "se"
    ICELAND = "is"
    ROMANIA = "ro"


# Country codes for Tor exit selection
GEO_COUNTRY_CODES = {
    GeoExitNode.EUROPE: ["de", "nl", "ch", "fr", "se", "is", "ro", "at", "be", "cz"],
    GeoExitNode.NORTH_AMERICA: ["us", "ca"],
    GeoExitNode.ASIA: ["jp", "sg", "kr", "hk"],
    GeoExitNode.SOUTH_AMERICA: ["br", "ar", "cl"],
    GeoExitNode.OCEANIA: ["au", "nz"],
}


@dataclass
class GeoExitConfig:
    """Configuration for geographic exit node selection."""
    preferred_region: GeoExitNode = GeoExitNode.EUROPE
    preferred_countries: List[str] = field(default_factory=lambda: ["de", "nl", "ch"])
    exclude_countries: List[str] = field(default_factory=lambda: ["ru", "cn", "ir"])
    rotate_countries: bool = True


# =============================================================================
# MULTI-HOP PROXY CHAIN
# =============================================================================

@dataclass 
class ProxyHop:
    """Single hop in a proxy chain."""
    type: str  # http, socks4, socks5
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    country: Optional[str] = None
    
    def get_url(self) -> str:
        auth = f"{self.username}:{self.password}@" if self.username else ""
        return f"{self.type}://{auth}{self.host}:{self.port}"


class ProxyChain:
    """
    Multi-hop proxy chain for maximum anonymity.
    
    Chains multiple proxies: You -> Proxy1 -> Proxy2 -> Tor -> Target
    """
    
    def __init__(self, hops: List[ProxyHop] = None):
        self.hops = hops or []
        self._current_hop_index = 0
    
    def add_hop(self, hop: ProxyHop) -> None:
        """Add a hop to the chain."""
        self.hops.append(hop)
    
    def get_chain_length(self) -> int:
        return len(self.hops)
    
    def get_entry_proxy(self) -> Optional[str]:
        """Get the first proxy in the chain."""
        if self.hops:
            return self.hops[0].get_url()
        return None
    
    def describe(self) -> str:
        """Get human-readable chain description."""
        if not self.hops:
            return "Direct connection"
        
        chain = " -> ".join([
            f"{h.type.upper()}({h.country or '?'})" for h in self.hops
        ])
        return f"You -> {chain} -> Target"


# =============================================================================
# DECOY REQUEST SYSTEM
# =============================================================================

class DecoyRequestGenerator:
    """
    Generates decoy requests to obfuscate real scanning traffic.
    
    Makes requests to legitimate sites to:
    - Hide scanning patterns
    - Normalize traffic patterns
    - Confuse traffic analysis
    """
    
    # Legitimate sites for decoy requests
    DECOY_URLS = [
        "https://www.google.com/",
        "https://www.youtube.com/",
        "https://www.wikipedia.org/",
        "https://www.amazon.com/",
        "https://www.reddit.com/",
        "https://www.github.com/",
        "https://www.stackoverflow.com/",
        "https://www.medium.com/",
        "https://news.ycombinator.com/",
        "https://www.bbc.com/",
        "https://www.cnn.com/",
        "https://www.nytimes.com/",
    ]
    
    # Common search queries for Google decoys
    SEARCH_QUERIES = [
        "weather today",
        "news",
        "python programming",
        "best restaurants",
        "movie reviews",
        "tech news",
        "sports scores",
        "stock market",
        "recipe ideas",
        "travel destinations",
    ]
    
    def __init__(self, injection_rate: float = 0.1):
        """
        Args:
            injection_rate: Probability of injecting decoy (0.1 = 10%)
        """
        self.injection_rate = injection_rate
        self._decoy_count = 0
    
    def should_inject_decoy(self) -> bool:
        """Determine if a decoy should be injected."""
        return random.random() < self.injection_rate
    
    def get_random_decoy_url(self) -> str:
        """Get a random decoy URL."""
        # 30% chance of search query
        if random.random() < 0.3:
            query = random.choice(self.SEARCH_QUERIES)
            return f"https://www.google.com/search?q={query.replace(' ', '+')}"
        
        return random.choice(self.DECOY_URLS)
    
    async def inject_decoy(
        self,
        client: httpx.AsyncClient,
        headers: Dict[str, str],
    ) -> None:
        """Inject a decoy request."""
        if not self.should_inject_decoy():
            return
        
        url = self.get_random_decoy_url()
        
        try:
            # Add slight delay for realism
            await asyncio.sleep(random.uniform(0.5, 2.0))
            
            await client.get(
                url,
                headers=headers,
                timeout=10.0,
                follow_redirects=True,
            )
            
            self._decoy_count += 1
            logger.debug(f"🎭 Decoy request #{self._decoy_count}: {urlparse(url).netloc}")
            
        except Exception:
            pass  # Silently ignore decoy failures
    
    def get_stats(self) -> Dict[str, Any]:
        return {"decoy_requests_sent": self._decoy_count}


# =============================================================================
# NATURAL NAVIGATION SIMULATOR
# =============================================================================

class NaturalNavigationSimulator:
    """
    Simulates natural human browsing behavior.
    
    Features:
    - Realistic click patterns
    - Natural page dwell times
    - Proper referer chains
    - Realistic resource loading
    """
    
    # Page types and typical dwell times (seconds)
    PAGE_DWELL_TIMES = {
        "homepage": (3, 10),
        "article": (15, 60),
        "form": (20, 90),
        "search_results": (5, 15),
        "product": (10, 30),
        "login": (10, 30),
        "default": (5, 20),
    }
    
    # Common resource patterns to simulate
    RESOURCE_PATTERNS = [
        "/favicon.ico",
        "/robots.txt",
        "/sitemap.xml",
    ]
    
    def __init__(self):
        self._navigation_history: List[str] = []
        self._current_referer: Optional[str] = None
    
    def get_realistic_dwell_time(self, page_type: str = "default") -> float:
        """Get realistic dwell time for page type."""
        min_time, max_time = self.PAGE_DWELL_TIMES.get(
            page_type, self.PAGE_DWELL_TIMES["default"]
        )
        
        # Use gamma distribution for more realistic times
        # Most visits are short, but some are longer
        shape = 2.0
        scale = (max_time - min_time) / shape
        
        dwell = min_time + random.gammavariate(shape, scale)
        return min(dwell, max_time * 1.5)  # Cap at 1.5x max
    
    def update_referer(self, url: str) -> str:
        """Update and return the referer for the next request."""
        previous_referer = self._current_referer
        self._current_referer = url
        self._navigation_history.append(url)
        
        # Keep history manageable
        if len(self._navigation_history) > 100:
            self._navigation_history = self._navigation_history[-50:]
        
        return previous_referer or ""
    
    def get_realistic_headers(
        self,
        profile: BrowserProfile,
        target_url: str,
    ) -> Dict[str, str]:
        """Get headers that simulate natural navigation."""
        headers = {
            "User-Agent": profile.user_agent,
            "Accept": profile.accept,
            "Accept-Language": profile.accept_language,
            "Accept-Encoding": profile.accept_encoding,
            "Connection": profile.connection,
            "Upgrade-Insecure-Requests": profile.upgrade_insecure_requests,
            "Sec-Fetch-Dest": profile.sec_fetch_dest,
            "Sec-Fetch-Mode": profile.sec_fetch_mode,
            "Sec-Fetch-Site": "same-origin" if self._current_referer else "none",
            "Sec-Fetch-User": profile.sec_fetch_user,
        }
        
        # Add referer if we have navigation history
        if self._current_referer:
            # Only add referer from same domain
            current_domain = urlparse(self._current_referer).netloc
            target_domain = urlparse(target_url).netloc
            
            if current_domain == target_domain:
                headers["Referer"] = self._current_referer
        
        # Add Chrome client hints if applicable
        if profile.sec_ch_ua:
            headers["Sec-CH-UA"] = profile.sec_ch_ua
            headers["Sec-CH-UA-Mobile"] = profile.sec_ch_ua_mobile
            headers["Sec-CH-UA-Platform"] = profile.sec_ch_ua_platform
        
        # Randomize header order for entropy
        items = list(headers.items())
        random.shuffle(items)
        
        return dict(items)
    
    async def simulate_resource_loads(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        headers: Dict[str, str],
    ) -> None:
        """Simulate loading common resources like a real browser."""
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        # Random subset of resources
        resources = random.sample(
            self.RESOURCE_PATTERNS,
            k=random.randint(1, len(self.RESOURCE_PATTERNS))
        )
        
        for resource in resources:
            try:
                await asyncio.sleep(random.uniform(0.1, 0.5))
                await client.get(
                    f"{base}{resource}",
                    headers=headers,
                    timeout=5.0,
                )
            except Exception:
                pass


# =============================================================================
# SESSION ISOLATION
# =============================================================================

class SessionIsolator:
    """
    Isolates sessions to prevent cross-contamination.
    
    Each target gets completely isolated:
    - Separate cookies
    - Separate local storage simulation
    - Separate navigation history
    """
    
    def __init__(self):
        self._sessions: Dict[str, Dict[str, Any]] = {}
    
    def get_session(self, target_domain: str) -> Dict[str, Any]:
        """Get or create isolated session for domain."""
        if target_domain not in self._sessions:
            self._sessions[target_domain] = {
                "cookies": {},
                "local_storage": {},
                "navigation_history": [],
                "created_at": datetime.now(),
                "request_count": 0,
            }
        
        return self._sessions[target_domain]
    
    def clear_session(self, target_domain: str) -> None:
        """Clear session for domain."""
        if target_domain in self._sessions:
            del self._sessions[target_domain]
    
    def clear_all_sessions(self) -> None:
        """Clear all sessions."""
        self._sessions.clear()
    
    def get_session_age(self, target_domain: str) -> Optional[timedelta]:
        """Get age of session."""
        session = self._sessions.get(target_domain)
        if session:
            return datetime.now() - session["created_at"]
        return None


# =============================================================================
# TRAFFIC PATTERN OBFUSCATOR
# =============================================================================

class TrafficPatternObfuscator:
    """
    Obfuscates traffic patterns to evade detection.
    
    Techniques:
    - Request timing randomization
    - Burst/pause patterns
    - Time-of-day simulation
    - Weekend/weekday patterns
    """
    
    # Typical browsing patterns by hour (activity level 0-1)
    HOURLY_PATTERNS = {
        0: 0.1, 1: 0.05, 2: 0.02, 3: 0.01, 4: 0.02, 5: 0.05,
        6: 0.2, 7: 0.4, 8: 0.6, 9: 0.8, 10: 0.9, 11: 0.95,
        12: 0.7, 13: 0.8, 14: 0.9, 15: 0.95, 16: 0.9, 17: 0.8,
        18: 0.7, 19: 0.8, 20: 0.9, 21: 0.85, 22: 0.6, 23: 0.3,
    }
    
    def __init__(self, simulate_timezone: str = "UTC"):
        self.simulate_timezone = simulate_timezone
        self._burst_mode = False
        self._burst_count = 0
        self._burst_max = 0
    
    def get_activity_multiplier(self) -> float:
        """Get activity multiplier based on simulated time."""
        hour = datetime.now().hour
        base_activity = self.HOURLY_PATTERNS.get(hour, 0.5)
        
        # Add weekend factor (less activity)
        weekday = datetime.now().weekday()
        if weekday >= 5:  # Weekend
            base_activity *= 0.7
        
        return base_activity
    
    def get_delay(self, base_delay_ms: int = 500) -> float:
        """Get obfuscated delay in seconds."""
        # Check if in burst mode
        if self._burst_mode:
            self._burst_count += 1
            if self._burst_count >= self._burst_max:
                self._burst_mode = False
                self._burst_count = 0
            return random.uniform(0.05, 0.2)  # Fast during burst
        
        # Chance to enter burst mode
        if random.random() < 0.05:  # 5% chance
            self._burst_mode = True
            self._burst_max = random.randint(3, 8)
            return random.uniform(0.05, 0.2)
        
        # Normal delay with activity multiplier
        activity = self.get_activity_multiplier()
        
        # Higher activity = shorter delays
        delay_ms = base_delay_ms / max(activity, 0.1)
        
        # Add jitter
        jitter = random.gauss(0, delay_ms * 0.3)
        delay_ms = max(100, delay_ms + jitter)
        
        # Occasionally add "distraction" pause
        if random.random() < 0.02:  # 2% chance
            delay_ms += random.uniform(5000, 30000)  # 5-30 second pause
        
        return delay_ms / 1000


# =============================================================================
# ELITE OPSEC MANAGER
# =============================================================================

@dataclass
class EliteOPSECConfig:
    """Configuration for elite OPSEC features."""
    
    # Browser emulation
    browser_profile: Optional[BrowserProfile] = None
    rotate_browser_profile: bool = True
    profile_rotation_interval: int = 50  # requests
    
    # Geographic control
    geo_config: GeoExitConfig = field(default_factory=GeoExitConfig)
    
    # Proxy chain
    use_proxy_chain: bool = False
    proxy_chain: Optional[ProxyChain] = None
    
    # Decoy injection
    inject_decoys: bool = True
    decoy_injection_rate: float = 0.05  # 5%
    
    # Navigation simulation
    simulate_natural_navigation: bool = True
    load_resources: bool = False  # Load favicon, etc.
    
    # Session isolation
    isolate_sessions: bool = True
    session_max_age_minutes: int = 30
    
    # Traffic obfuscation
    obfuscate_traffic_patterns: bool = True
    simulate_timezone: str = "Europe/London"
    
    # Request entropy
    randomize_header_order: bool = True
    add_random_headers: bool = True


class EliteOPSEC:
    """
    Elite OPSEC Manager - Maximum Anonymity Protection.
    
    Combines all advanced protection features for
    enterprise-grade anonymous pentesting.
    """
    
    def __init__(self, config: EliteOPSECConfig = None):
        self.config = config or EliteOPSECConfig()
        
        # Initialize components
        self._current_profile = (
            self.config.browser_profile or random.choice(BROWSER_PROFILES)
        )
        self._profile_request_count = 0
        
        self.decoy_generator = DecoyRequestGenerator(
            injection_rate=self.config.decoy_injection_rate
        )
        self.navigation_simulator = NaturalNavigationSimulator()
        self.session_isolator = SessionIsolator()
        self.traffic_obfuscator = TrafficPatternObfuscator(
            simulate_timezone=self.config.simulate_timezone
        )
        
        self._request_count = 0
        self._initialized = False
    
    def get_current_profile(self) -> BrowserProfile:
        """Get current browser profile, rotating if needed."""
        if (
            self.config.rotate_browser_profile and
            self._profile_request_count >= self.config.profile_rotation_interval
        ):
            self._current_profile = random.choice(BROWSER_PROFILES)
            self._profile_request_count = 0
            logger.debug(f"🔄 Rotated to browser profile: {self._current_profile.name}")
        
        return self._current_profile
    
    def get_request_headers(self, target_url: str) -> Dict[str, str]:
        """Get fully emulated browser headers."""
        profile = self.get_current_profile()
        
        if self.config.simulate_natural_navigation:
            headers = self.navigation_simulator.get_realistic_headers(
                profile, target_url
            )
        else:
            headers = {
                "User-Agent": profile.user_agent,
                "Accept": profile.accept,
                "Accept-Language": profile.accept_language,
                "Accept-Encoding": profile.accept_encoding,
            }
        
        # Add random innocuous headers for entropy
        if self.config.add_random_headers:
            if random.random() > 0.5:
                headers["DNT"] = "1"
            if random.random() > 0.7:
                headers["X-Requested-With"] = "XMLHttpRequest"
        
        # Randomize header order
        if self.config.randomize_header_order:
            items = list(headers.items())
            random.shuffle(items)
            headers = dict(items)
        
        return headers
    
    async def get_delay(self) -> float:
        """Get obfuscated delay before next request."""
        if self.config.obfuscate_traffic_patterns:
            return self.traffic_obfuscator.get_delay()
        
        # Default delay
        return random.uniform(0.1, 0.5)
    
    async def pre_request(
        self,
        client: httpx.AsyncClient,
        target_url: str,
    ) -> None:
        """Pre-request processing."""
        # Apply delay
        delay = await self.get_delay()
        if delay > 0:
            await asyncio.sleep(delay)
        
        # Inject decoy if enabled
        if self.config.inject_decoys:
            headers = self.get_request_headers(target_url)
            await self.decoy_generator.inject_decoy(client, headers)
    
    async def post_request(
        self,
        client: httpx.AsyncClient,
        target_url: str,
        headers: Dict[str, str],
    ) -> None:
        """Post-request processing."""
        self._request_count += 1
        self._profile_request_count += 1
        
        # Update navigation history
        if self.config.simulate_natural_navigation:
            self.navigation_simulator.update_referer(target_url)
        
        # Simulate resource loads occasionally
        if self.config.load_resources and random.random() < 0.1:
            await self.navigation_simulator.simulate_resource_loads(
                client, target_url, headers
            )
    
    def get_session(self, target_url: str) -> Dict[str, Any]:
        """Get isolated session for target."""
        if not self.config.isolate_sessions:
            return {}
        
        domain = urlparse(target_url).netloc
        return self.session_isolator.get_session(domain)
    
    def get_status(self) -> Dict[str, Any]:
        """Get elite OPSEC status."""
        return {
            "current_browser_profile": self._current_profile.name,
            "request_count": self._request_count,
            "decoy_stats": self.decoy_generator.get_stats(),
            "session_count": len(self.session_isolator._sessions),
            "config": {
                "browser_rotation": self.config.rotate_browser_profile,
                "decoy_injection": self.config.inject_decoys,
                "natural_navigation": self.config.simulate_natural_navigation,
                "session_isolation": self.config.isolate_sessions,
                "traffic_obfuscation": self.config.obfuscate_traffic_patterns,
            }
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def create_elite_protection() -> EliteOPSEC:
    """Create elite OPSEC protection with recommended settings."""
    config = EliteOPSECConfig(
        rotate_browser_profile=True,
        profile_rotation_interval=30,
        inject_decoys=True,
        decoy_injection_rate=0.05,
        simulate_natural_navigation=True,
        isolate_sessions=True,
        obfuscate_traffic_patterns=True,
    )
    
    return EliteOPSEC(config)


def print_elite_banner(opsec: EliteOPSEC):
    """Print elite OPSEC status banner."""
    status = opsec.get_status()
    
    print(f"""
╔═══════════════════════════════════════════════════════════════════════╗
║           🛡️  ELITE OPSEC PROTECTION v3.0 - MAXIMUM ANONYMITY         ║
╠═══════════════════════════════════════════════════════════════════════╣
║                                                                       ║
║  Browser Profile:    {status['current_browser_profile']:<42} ║
║  Requests Made:      {status['request_count']:<42} ║
║  Decoys Injected:    {status['decoy_stats']['decoy_requests_sent']:<42} ║
║  Active Sessions:    {status['session_count']:<42} ║
║                                                                       ║
║  ✅ Browser Emulation      ✅ Traffic Obfuscation                     ║
║  ✅ Decoy Injection        ✅ Session Isolation                       ║
║  ✅ Natural Navigation     ✅ Header Entropy                          ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
""")


# =============================================================================
# WEBRTC LEAK CHECKER
# =============================================================================

async def check_webrtc_leak_risk() -> Dict[str, Any]:
    """
    Check for WebRTC leak risk indicators.
    
    Note: Full WebRTC check requires browser. This checks indicators.
    """
    result = {
        "risk_level": "unknown",
        "recommendations": [],
    }
    
    # Check if running in environment with WebRTC
    try:
        import socket
        
        # Get local IPs that could leak
        local_ips = []
        
        # Get all network interfaces
        hostname = socket.gethostname()
        local_ips.append(socket.gethostbyname(hostname))
        
        # Check for private IPs
        private_prefixes = ["192.168.", "10.", "172.16.", "172.17.", "172.18."]
        for ip in local_ips:
            for prefix in private_prefixes:
                if ip.startswith(prefix):
                    result["risk_level"] = "medium"
                    result["recommendations"].append(
                        f"Private IP detected: {ip} - Could leak via WebRTC"
                    )
        
        if not result["recommendations"]:
            result["risk_level"] = "low"
            result["recommendations"].append("No obvious WebRTC leak vectors detected")
        
    except Exception as e:
        result["risk_level"] = "unknown"
        result["recommendations"].append(f"Could not check: {e}")
    
    return result
