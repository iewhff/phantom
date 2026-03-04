"""
Protected HTTP Client - Centralized Network Protection v3.0

This module provides a global HTTP client factory that automatically
applies network protection settings (proxy, Tor, header randomization).

Now with Advanced OPSEC v2.0 + Elite v3.0 features:
- Kill switch (stops traffic on protection failure)
- Continuous IP verification
- Automatic Tor circuit rotation
- Human-like request timing
- Evidence cleanup
- Browser fingerprint emulation
- Decoy request injection
- Natural navigation simulation
- Session isolation
- Traffic pattern obfuscation

All scanner modules should use get_http_client() instead of creating
httpx.AsyncClient directly.

Author: PetNTester AI
Version: 3.0.0
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any, Optional
from contextlib import asynccontextmanager

import httpx
import yaml

from utils.logger import get_logger
from utils.network_protection import (
    NetworkProtection,
    ProxyConfig,
    ProxyType,
)

# Try to import elite OPSEC (optional but recommended)
try:
    from utils.elite_opsec import (
        EliteOPSEC,
        EliteOPSECConfig,
        BROWSER_PROFILES,
        create_elite_protection,
    )
    ELITE_OPSEC_AVAILABLE = True
except ImportError:
    ELITE_OPSEC_AVAILABLE = False

if TYPE_CHECKING:
    pass

logger = get_logger(__name__)


# =============================================================================
# GLOBAL STATE
# =============================================================================

# SECURITY: Thread-safe access to global state using asyncio locks
# This prevents race conditions when multiple coroutines access shared state
import threading

_state_lock = threading.RLock()  # Reentrant lock for nested access

_global_protection: Optional[NetworkProtection] = None
_elite_protection: Optional["EliteOPSEC"] = None
_protection_verified: bool = False
_settings_loaded: bool = False
_kill_switch_active: bool = False
_ssl_verify_default: bool = True  # SECURE DEFAULT: SSL verification enabled
_global_required_headers: dict[str, str] = {}  # BUG BOUNTY: Required headers for all requests
_active_preset_name: Optional[str] = None  # Active bug bounty preset name


# =============================================================================
# KILL SWITCH - Emergency traffic stop
# =============================================================================

class KillSwitchActive(Exception):
    """
    Exception raised when kill switch is active.

    This exception is raised when attempting to make HTTP requests while
    the kill switch is engaged. The kill switch is a security mechanism
    that blocks all outbound traffic when network protection fails.

    To resume operations:
        1. Investigate why the kill switch was activated
        2. Fix the underlying issue (e.g., proxy configuration)
        3. Call deactivate_kill_switch() to resume traffic
    """

    def __init__(self, message: str = ""):
        default_msg = (
            "Kill switch is active - all outbound traffic blocked. "
            "Use deactivate_kill_switch() to resume."
        )
        super().__init__(message or default_msg)


def activate_kill_switch(reason: str = "Manual activation") -> None:
    """
    Activate the kill switch - stops ALL outbound traffic.

    SECURITY: This is a critical safety mechanism that prevents
    data exfiltration if protection fails.
    Thread-safe: Uses lock for concurrent access.
    """
    global _kill_switch_active
    with _state_lock:
        _kill_switch_active = True
    logger.critical(f"🛑 KILL SWITCH ACTIVATED: {reason}")
    logger.critical("   All outbound traffic is now BLOCKED!")


def deactivate_kill_switch() -> None:
    """Deactivate the kill switch - allows traffic again. Thread-safe."""
    global _kill_switch_active
    with _state_lock:
        _kill_switch_active = False
    logger.warning("⚠️  Kill switch deactivated - traffic allowed")


def is_kill_switch_active() -> bool:
    """Check if kill switch is currently active. Thread-safe."""
    with _state_lock:
        return _kill_switch_active


def set_ssl_verify_default(verify: bool) -> None:
    """
    Set the default SSL verification behavior.

    SECURITY: SSL verification should be enabled by default.
    Only disable for specific pentesting scenarios where
    self-signed certificates are expected.
    Thread-safe: Uses lock for concurrent access.
    """
    global _ssl_verify_default
    with _state_lock:
        _ssl_verify_default = verify
    if not verify:
        logger.warning("⚠️  SSL verification disabled globally - use with caution!")


def get_ssl_verify_default() -> bool:
    """Get the default SSL verification setting. Thread-safe."""
    with _state_lock:
        return _ssl_verify_default


# =============================================================================
# BUG BOUNTY REQUIRED HEADERS
# =============================================================================

# Headers that should have their values masked in logs
_SENSITIVE_HEADER_NAMES = frozenset([
    "authorization", "x-api-key", "api-key", "x-auth-token", "x-access-token",
    "cookie", "set-cookie", "x-csrf-token", "x-xsrf-token", "bearer",
    "x-session-token", "x-secret", "password", "apikey", "token",
])


def _mask_header_value(key: str, value: str) -> str:
    """Mask sensitive header values for safe logging."""
    if key.lower() in _SENSITIVE_HEADER_NAMES:
        if len(value) <= 4:
            return "****"
        return f"{value[:2]}***{value[-2:]}"
    return value


def set_required_headers(headers: dict[str, str], preset_name: str = "") -> None:
    """
    Set required headers that will be included in ALL HTTP requests.

    CRITICAL FOR BUG BOUNTY COMPLIANCE:
    Many bug bounty programs require specific headers (e.g., X-Bug-Bounty)
    to be included in all requests to identify the tester and ensure
    compliance with program rules.
    Thread-safe: Uses lock for concurrent access.

    Args:
        headers: Dict of header name -> value (e.g., {"X-Bug-Bounty": "username-twilio"})
        preset_name: Name of the bug bounty preset for logging

    Example:
        set_required_headers({"X-Bug-Bounty": "youruser-twilio"}, "twilio")
    """
    global _global_required_headers, _active_preset_name
    with _state_lock:
        _global_required_headers = headers.copy()
        _active_preset_name = preset_name

    if headers:
        logger.info(f"🎯 Bug bounty headers configured: {list(headers.keys())}")
        if preset_name:
            logger.info(f"   Active preset: {preset_name}")
        for key, value in headers.items():
            logger.debug(f"   {key}: {_mask_header_value(key, value)}")


def get_required_headers() -> dict[str, str]:
    """Get the global required headers. Thread-safe."""
    with _state_lock:
        return _global_required_headers.copy()


def get_active_preset() -> Optional[str]:
    """Get the name of the active bug bounty preset. Thread-safe."""
    with _state_lock:
        return _active_preset_name


def clear_required_headers() -> None:
    """Clear all required headers (use when switching presets). Thread-safe."""
    global _global_required_headers, _active_preset_name
    with _state_lock:
        _global_required_headers = {}
        _active_preset_name = None
    logger.debug("Bug bounty required headers cleared")


# =============================================================================
# CONFIGURATION LOADING
# =============================================================================

def _load_full_settings() -> dict[str, Any]:
    """Load full settings from config file."""
    config_paths = [
        "config/settings.yaml",
        os.path.expanduser("~/.config/petntester/settings.yaml"),
        "/etc/petntester/settings.yaml",
    ]
    
    for path in config_paths:
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    return yaml.safe_load(f) or {}
            except Exception as e:
                logger.warning(f"Failed to load config from {path}: {e}")
    
    return {}


def _load_network_settings() -> dict[str, Any]:
    """Load network protection settings from config file."""
    config = _load_full_settings()
    return config.get('network_protection', {})


def load_bug_bounty_preset(preset_name: str) -> bool:
    """
    Load a bug bounty preset and configure required headers.
    
    CRITICAL: Call this before starting a bug bounty scan to ensure
    all requests include the required headers.
    
    Args:
        preset_name: Name of the preset (e.g., "twilio")
        
    Returns:
        True if preset was loaded successfully
        
    Example:
        load_bug_bounty_preset("twilio")
        # Now all requests will include X-Bug-Bounty header
    """
    config = _load_full_settings()
    bug_bounty = config.get('bug_bounty', {})
    presets = bug_bounty.get('presets', {})
    
    if preset_name not in presets:
        logger.error(f"Bug bounty preset '{preset_name}' not found in config")
        logger.info(f"Available presets: {list(presets.keys())}")
        return False
    
    preset = presets[preset_name]
    headers = preset.get('required_headers', {})
    
    if headers:
        set_required_headers(headers, preset_name)
        logger.info(f"✅ Loaded bug bounty preset: {preset_name}")
        return True
    else:
        logger.warning(f"Preset '{preset_name}' has no required_headers configured")
        return False


def get_available_presets() -> list[str]:
    """Get list of available bug bounty presets."""
    config = _load_full_settings()
    presets = config.get('bug_bounty', {}).get('presets', {})
    return list(presets.keys())


def _is_tor_running(socks_port: int = 9050) -> bool:
    """
    Check if Tor SOCKS proxy is accepting connections AND can route traffic.

    Phase 1: TCP connect to SOCKS port (1s timeout)
    Phase 2: SOCKS5 handshake to verify it's a real SOCKS proxy (2s timeout)
    """
    import socket as _sock

    # BUG-FIX 2026-02-08: Use try/finally to ensure socket is always closed
    s = None
    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect(("127.0.0.1", socks_port))

        # SOCKS5 greeting: version=5, 1 auth method, method=0 (no auth)
        s.sendall(b"\x05\x01\x00")
        resp = s.recv(2)

        if len(resp) == 2 and resp[0] == 0x05 and resp[1] == 0x00:
            # Valid SOCKS5 handshake — Tor is accepting connections
            return True
        logger.debug("Tor port %d responded but SOCKS5 handshake failed: %r", socks_port, resp)
        return False
    except (ConnectionRefusedError, OSError, TimeoutError):
        return False
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass  # Ignore close errors


def _create_protection_from_settings(settings: dict[str, Any]) -> NetworkProtection:
    """Create NetworkProtection from settings dict."""
    proxy_config = ProxyConfig(enabled=False)

    # Check if network protection is enabled
    if not settings.get('enabled', False):
        logger.debug("Network protection disabled in config")
        return NetworkProtection(
            proxy_config=proxy_config,
            rotate_user_agent=settings.get('user_agent', {}).get('rotate', True),
            randomize_headers=settings.get('headers', {}).get('randomize', True),
        )

    # Tor configuration (highest priority) — with auto-detection
    # FIX 2026-02-12: Add environment variable to disable Tor (for localhost testing)
    # Support both PATHFINDER_NO_TOR and legacy PHANTOM_NO_TOR
    # FIX 2026-02-20: Also check PHANTOM_LOCALHOST_TARGET (set by full_scanner for localhost targets)
    tor_disabled = (
        os.environ.get("PATHFINDER_NO_TOR", "").lower() in ("1", "true", "yes") or
        os.environ.get("PHANTOM_NO_TOR", "").lower() in ("1", "true", "yes") or
        os.environ.get("PATHFINDER_LOCALHOST_TARGET", "").lower() in ("1", "true", "yes") or
        os.environ.get("PHANTOM_LOCALHOST_TARGET", "").lower() in ("1", "true", "yes")
    )
    tor_settings = settings.get('tor', {})
    if tor_settings.get('enabled', False) and not tor_disabled:
        socks_port = tor_settings.get('socks_port', 9050)
        if _is_tor_running(socks_port):
            proxy_config = ProxyConfig(
                enabled=True,
                proxy_type=ProxyType.TOR,
                host="127.0.0.1",
                port=socks_port,
                tor_control_port=tor_settings.get('control_port', 9051),
                tor_password=tor_settings.get('password'),
            )
            logger.info("🧅 Tor detected and enabled — traffic routed through Tor network")
        else:
            logger.warning(
                "⚠️  Tor enabled in config but NOT RUNNING on port %d. "
                "Start with: sudo systemctl start tor  |  "
                "Continuing WITHOUT Tor anonymity.", socks_port
            )
            # proxy_config stays disabled — no Tor, no hang
    elif tor_disabled:
        logger.info("🧅 Tor DISABLED via PATHFINDER_NO_TOR environment variable")
    
    # Proxy configuration (if Tor not enabled)
    elif settings.get('proxy', {}).get('enabled', False):
        proxy_settings = settings['proxy']
        proxy_type_str = proxy_settings.get('type', 'http').lower()
        
        type_map = {
            'http': ProxyType.HTTP,
            'https': ProxyType.HTTPS,
            'socks4': ProxyType.SOCKS4,
            'socks5': ProxyType.SOCKS5,
            'tor': ProxyType.TOR,
        }
        
        proxy_config = ProxyConfig(
            enabled=True,
            proxy_type=type_map.get(proxy_type_str, ProxyType.HTTP),
            host=proxy_settings.get('host', '127.0.0.1'),
            port=proxy_settings.get('port', 8080),
            username=proxy_settings.get('username'),
            password=proxy_settings.get('password'),
        )
        logger.info(f"🔌 Proxy protection enabled: {proxy_type_str}")
    
    return NetworkProtection(
        proxy_config=proxy_config,
        rotate_user_agent=settings.get('user_agent', {}).get('rotate', True),
        randomize_headers=settings.get('headers', {}).get('randomize', True),
        check_ip_leaks=settings.get('leak_protection', {}).get('check_before_scan', True),
    )


# =============================================================================
# GLOBAL PROTECTION MANAGEMENT
# =============================================================================

def get_network_protection() -> NetworkProtection:
    """
    Get the global network protection instance.

    Loads settings from config file on first call.
    Thread-safe: Uses lock for concurrent access.
    """
    global _global_protection, _settings_loaded, _ssl_verify_default

    with _state_lock:
        if _global_protection is None:
            settings = _load_network_settings()
            _global_protection = _create_protection_from_settings(settings)
            _settings_loaded = True

            # Load SSL verification settings
            ssl_settings = settings.get('ssl', {})
            ssl_verify = ssl_settings.get('verify_ssl', True)  # Default: True (secure)
            if not ssl_verify:
                logger.warning("⚠️  SSL verification disabled in config - SECURITY RISK!")
            _ssl_verify_default = ssl_verify

        return _global_protection


def reset_network_protection() -> None:
    """
    Reset the cached network protection instance.

    Call this after setting PHANTOM_LOCALHOST_TARGET or PHANTOM_NO_TOR
    environment variables to force re-evaluation of Tor/proxy settings.

    FIX 2026-02-20: Needed because full_scanner sets PHANTOM_LOCALHOST_TARGET
    AFTER the http_client module is imported, but the protection is cached
    on first use. This allows the cache to be cleared and re-created with
    the updated environment variables.
    """
    global _global_protection, _settings_loaded

    with _state_lock:
        _global_protection = None
        _settings_loaded = False
        logger.info("🔄 Network protection cache reset — will re-evaluate Tor/proxy settings")


def get_elite_protection() -> Optional["EliteOPSEC"]:
    """
    Get the global elite OPSEC protection instance.

    Returns None if elite features are disabled or unavailable.
    Thread-safe: Uses lock for concurrent access.
    """
    global _elite_protection

    if not ELITE_OPSEC_AVAILABLE:
        return None

    with _state_lock:
        if _elite_protection is None:
            settings = _load_network_settings()
            elite_settings = settings.get('elite', {})

            # Check if elite features are enabled
            browser_enabled = elite_settings.get('browser_emulation', {}).get('enabled', False)
            if browser_enabled or settings.get('level') == 'paranoid':
                from utils.elite_opsec import EliteOPSEC, EliteOPSECConfig

                config = EliteOPSECConfig(
                    rotate_browser_profile=elite_settings.get('browser_emulation', {}).get('rotate_profile', True),
                    profile_rotation_interval=elite_settings.get('browser_emulation', {}).get('rotation_interval', 30),
                    inject_decoys=elite_settings.get('decoy_injection', {}).get('enabled', False),
                    decoy_injection_rate=elite_settings.get('decoy_injection', {}).get('rate', 0.05),
                    simulate_natural_navigation=elite_settings.get('natural_navigation', {}).get('enabled', True),
                    isolate_sessions=elite_settings.get('session_isolation', {}).get('enabled', True),
                    obfuscate_traffic_patterns=elite_settings.get('traffic_obfuscation', {}).get('enabled', True),
                )

                _elite_protection = EliteOPSEC(config)
                logger.info("🛡️ Elite OPSEC v3.0 initialized")

        return _elite_protection


def set_network_protection(protection: NetworkProtection) -> None:
    """
    Set a custom network protection instance.

    Useful for testing or runtime configuration changes.
    Thread-safe: Uses lock for concurrent access.
    """
    global _global_protection
    with _state_lock:
        _global_protection = protection


async def verify_protection(auto_kill_switch: bool = True) -> bool:
    """
    Verify that network protection is working correctly.

    Should be called before starting scans.
    Returns True if protection is verified or not required.
    Thread-safe: Uses lock for concurrent access.

    Args:
        auto_kill_switch: If True, activates kill switch on protection failure

    SECURITY: When auto_kill_switch is enabled (default), any protection
    failure will immediately block all outbound traffic to prevent IP leaks.
    """
    global _protection_verified

    protection = get_network_protection()

    if not protection.proxy_config.enabled:
        logger.warning("⚠️  Network protection DISABLED - your IP is visible!")
        with _state_lock:
            _protection_verified = True
        return True

    # Check if proxy is working
    logger.info("🔍 Verifying network protection...")

    try:
        result = await protection.verify_proxy_working()
        with _state_lock:
            _protection_verified = result

        if result:
            logger.info("✅ Network protection verified - IP is hidden")
        else:
            logger.error("❌ PROTECTION FAILED - IP leak detected!")
            if auto_kill_switch:
                activate_kill_switch("IP leak detected during protection verification")

        return result

    except Exception as e:
        logger.error(f"❌ Failed to verify protection: {e}")
        with _state_lock:
            _protection_verified = False
        if auto_kill_switch:
            activate_kill_switch(f"Protection verification failed: {e}")
        return False


def is_protection_enabled() -> bool:
    """Check if network protection is currently enabled."""
    protection = get_network_protection()
    return protection.proxy_config.enabled


def get_protection_status() -> dict[str, Any]:
    """Get current protection status."""
    protection = get_network_protection()
    elite = get_elite_protection()

    status = {
        "enabled": protection.proxy_config.enabled,
        "type": protection.proxy_config.proxy_type.value if protection.proxy_config.enabled else None,
        "verified": _protection_verified,
        "user_agent_rotation": protection.rotate_user_agent,
        "header_randomization": protection.randomize_headers,
        "elite_opsec": elite is not None,
        "kill_switch_active": _kill_switch_active,
        "ssl_verify_default": _ssl_verify_default,
    }

    if elite:
        elite_status = elite.get_status()
        status["elite_details"] = elite_status

    return status


# =============================================================================
# HTTP CLIENT FACTORY
# =============================================================================

def get_http_client_kwargs(
    timeout: float = 30.0,
    verify_ssl: bool | None = None,
    follow_redirects: bool = True,
    custom_headers: dict[str, str] | None = None,
    http2: bool = False,
) -> dict[str, Any]:
    """
    Get kwargs for httpx.AsyncClient with protection applied.

    Args:
        timeout: Request timeout
        verify_ssl: Verify SSL certificates (None = use global default)
        follow_redirects: Follow redirects
        custom_headers: Additional headers to include
        http2: Enable HTTP/2 support (requires h2 package)

    Returns:
        Dict of kwargs for httpx.AsyncClient

    Raises:
        KillSwitchActive: If kill switch is active

    SECURITY:
        - SSL verification defaults to True (secure default)
        - Kill switch blocks all traffic when active
        - Bug bounty required headers are automatically included
    """
    # Check kill switch FIRST
    if _kill_switch_active:
        raise KillSwitchActive(
            "Kill switch is active - all outbound traffic blocked. "
            "Use deactivate_kill_switch() to resume."
        )

    protection = get_network_protection()
    kwargs = protection.get_httpx_client_kwargs()

    # ═══════════════════════════════════════════════════════════════════════════
    # DEFENSIVE PROXY BYPASS (2026-02-16)
    # ═══════════════════════════════════════════════════════════════════════════
    # Even if protection was cached with proxy enabled, remove it now if:
    # 1. PATHFINDER_NO_TOR=1 is set (explicitly requested no Tor)
    # 2. PATHFINDER_LOCALHOST_TARGET=1 is set (scanning localhost)
    # This is a RUNTIME check that overrides any cached settings.
    bypass_proxy = (
        os.environ.get("PATHFINDER_NO_TOR", "").lower() in ("1", "true", "yes") or
        os.environ.get("PHANTOM_NO_TOR", "").lower() in ("1", "true", "yes") or
        os.environ.get("PATHFINDER_LOCALHOST_TARGET", "").lower() in ("1", "true", "yes") or
        os.environ.get("PHANTOM_LOCALHOST_TARGET", "").lower() in ("1", "true", "yes")
    )
    if bypass_proxy and "proxy" in kwargs:
        logger.info("🔌 [HTTP-CLIENT] Proxy REMOVED (PATHFINDER_NO_TOR or localhost)")
        del kwargs["proxy"]
    # ═══════════════════════════════════════════════════════════════════════════

    # Override with provided values
    kwargs["timeout"] = timeout
    # Use provided value, or global default (True = secure)
    kwargs["verify"] = verify_ssl if verify_ssl is not None else _ssl_verify_default
    kwargs["follow_redirects"] = follow_redirects

    # Start with required headers (bug bounty compliance - ALWAYS included)
    headers = kwargs.get("headers", {})

    # Add global required headers FIRST (e.g., X-Bug-Bounty)
    # THREAD-SAFE: Use getter which acquires lock and returns a copy
    required = get_required_headers()
    if required:
        headers.update(required)
    
    # Then merge custom headers (can override if needed)
    if custom_headers:
        headers.update(custom_headers)

    kwargs["headers"] = headers

    # HTTP/2 support (requires h2 package: pip install httpx[http2])
    # HTTP/2 provides: multiplexing, header compression, server push
    # Useful for modern targets that require or prefer HTTP/2
    if http2:
        kwargs["http2"] = True

    return kwargs


@asynccontextmanager
async def get_http_client(
    timeout: float = 30.0,
    verify_ssl: bool | None = None,
    follow_redirects: bool = True,
    custom_headers: dict[str, str] | None = None,
    target_url: str | None = None,
    http2: bool = False,
):
    """
    Get a protected HTTP client as an async context manager.

    Usage:
        async with get_http_client() as client:
            response = await client.get(url)

        # With HTTP/2 support:
        async with get_http_client(http2=True) as client:
            response = await client.get(url)

    This automatically applies:
    - Kill switch check (blocks if active)
    - SSL verification (enabled by default)
    - Proxy/Tor if configured
    - User-Agent rotation
    - Header randomization
    - HTTP/2 support (if enabled)
    - Elite OPSEC features (if enabled):
      - Browser fingerprint emulation
      - Natural navigation simulation
      - Session isolation
      - Traffic pattern obfuscation

    Raises:
        KillSwitchActive: If kill switch is active

    SECURITY:
        - Checks kill switch before creating client
        - SSL verification defaults to True
    """
    # This will raise KillSwitchActive if kill switch is on
    kwargs = get_http_client_kwargs(
        timeout=timeout,
        verify_ssl=verify_ssl,
        follow_redirects=follow_redirects,
        custom_headers=custom_headers,
        http2=http2,
    )

    # Apply elite OPSEC headers if available
    elite = get_elite_protection()
    if elite and target_url:
        elite_headers = elite.get_request_headers(target_url)
        headers = kwargs.get("headers", {})
        # Elite headers take priority
        headers.update(elite_headers)
        kwargs["headers"] = headers

    async with httpx.AsyncClient(**kwargs) as client:
        yield client


def create_protected_client(
    timeout: float = 30.0,
    verify_ssl: bool | None = None,
    follow_redirects: bool = True,
    custom_headers: dict[str, str] | None = None,
    http2: bool = False,
) -> httpx.AsyncClient:
    """
    Create a protected httpx.AsyncClient instance.

    USE THIS instead of httpx.AsyncClient() directly in scanner modules!

    This function creates a client with:
    - Kill switch protection
    - Bug bounty required headers (X-Bug-Bounty, etc.)
    - Proxy/Tor configuration
    - User-Agent rotation
    - SSL verification defaults
    - HTTP/2 support (if enabled)

    Example:
        # WRONG - Don't use this:
        async with httpx.AsyncClient(timeout=30.0) as client:
            ...

        # CORRECT - Use this instead:
        async with create_protected_client(timeout=30.0) as client:
            ...

        # With HTTP/2:
        async with create_protected_client(http2=True) as client:
            ...

    Returns:
        httpx.AsyncClient instance configured with all protections

    Raises:
        KillSwitchActive: If kill switch is active
    """
    kwargs = get_http_client_kwargs(
        timeout=timeout,
        verify_ssl=verify_ssl,
        follow_redirects=follow_redirects,
        custom_headers=custom_headers,
        http2=http2,
    )
    return httpx.AsyncClient(**kwargs)


async def protected_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: dict[str, Any] | None = None,
    json_data: dict[str, Any] | None = None,
    timeout: float = 30.0,
    follow_redirects: bool = True,
    verify_ssl: bool | None = None,
    http2: bool = False,
) -> httpx.Response:
    """
    Make a single protected HTTP request.

    Convenience function for one-off requests.
    Includes elite OPSEC features like delays and decoys.

    Args:
        url: Target URL
        method: HTTP method (GET, POST, etc.)
        headers: Custom headers
        data: Form data
        json_data: JSON body
        timeout: Request timeout
        follow_redirects: Follow redirects
        verify_ssl: Verify SSL certificates
        http2: Enable HTTP/2 support

    Raises:
        KillSwitchActive: If kill switch is active

    SECURITY:
        - Checks kill switch before making request
        - SSL verification defaults to True
        - Bug bounty required headers automatically included
    """
    elite = get_elite_protection()

    async with get_http_client(
        timeout=timeout,
        verify_ssl=verify_ssl,
        follow_redirects=follow_redirects,
        custom_headers=headers,
        target_url=url,
        http2=http2,
    ) as client:
        # Pre-request processing (delay, decoy injection)
        if elite:
            await elite.pre_request(client, url)

        response = await client.request(
            method=method,
            url=url,
            data=data,
            json=json_data,
        )

        # Post-request processing (update navigation history)
        if elite:
            request_headers = headers or {}
            await elite.post_request(client, url, request_headers)

        return response


# =============================================================================
# PROTECTION STATUS DISPLAY
# =============================================================================

def print_protection_banner():
    """Print network protection status banner."""
    status = get_protection_status()

    # Kill switch warning takes priority
    if status.get("kill_switch_active"):
        print("""
╔════════════════════════════════════════════════════════════════╗
║  🛑 KILL SWITCH ACTIVE - ALL TRAFFIC BLOCKED                   ║
╠════════════════════════════════════════════════════════════════╣
║  All outbound network traffic is currently blocked.            ║
║  Use deactivate_kill_switch() to resume scanning.              ║
╚════════════════════════════════════════════════════════════════╝
""")
        return

    if status["enabled"]:
        elite_status = "✅ ELITE v3.0" if status.get("elite_opsec") else "❌ Off"
        ssl_status = "✅ Enabled" if status.get("ssl_verify_default") else "⚠️ Disabled"

        print(f"""
╔════════════════════════════════════════════════════════════════╗
║  🔒 NETWORK PROTECTION ACTIVE - v3.0                           ║
╠════════════════════════════════════════════════════════════════╣
║  Type: {status['type']:<10}  Verified: {'✅' if status['verified'] else '⏳'}                          ║
║  User-Agent Rotation: {'✅' if status['user_agent_rotation'] else '❌'}                                  ║
║  Header Randomization: {'✅' if status['header_randomization'] else '❌'}                                 ║
║  SSL Verification: {ssl_status:<15}                                 ║
║  Elite OPSEC: {elite_status:<20}                               ║
║  Kill Switch: Ready (auto-triggers on protection failure)      ║
╚════════════════════════════════════════════════════════════════╝
""")
        
        # Show required headers if set (bug bounty compliance)
        required_headers = get_required_headers()
        preset_name = get_active_preset()
        if required_headers:
            print("┌─ Bug Bounty Required Headers ───────────────────────────────┐")
            if preset_name:
                print(f"│  Active Preset: {preset_name:<40} │")
            for key, value in required_headers.items():
                masked = _mask_header_value(key, value)
                display_value = masked if len(masked) <= 35 else masked[:32] + "..."
                print(f"│  {key}: {display_value:<45} │")
            print("└──────────────────────────────────────────────────────────────┘\n")

        # Show elite details if available
        if status.get("elite_opsec") and status.get("elite_details"):
            details = status["elite_details"]
            print(f"""
┌─ Elite OPSEC Details ────────────────────────────────────────┐
│  Browser Profile: {details.get('current_browser_profile', 'N/A'):<35} │
│  Requests: {details.get('request_count', 0):<43} │
│  Decoys Sent: {details.get('decoy_stats', {}).get('decoy_requests_sent', 0):<40} │
│  Sessions: {details.get('session_count', 0):<43} │
└──────────────────────────────────────────────────────────────┘
""")
    else:
        ssl_status = "✅ Enabled" if get_ssl_verify_default() else "⚠️ Disabled"
        print(f"""
╔════════════════════════════════════════════════════════════════╗
║  ⚠️  NETWORK PROTECTION DISABLED                               ║
╠════════════════════════════════════════════════════════════════╣
║  Your real IP is VISIBLE to targets!                           ║
║  SSL Verification: {ssl_status:<15}                                 ║
╚════════════════════════════════════════════════════════════════╝
""")

        # Show required headers if set (bug bounty compliance)
        required_headers = get_required_headers()
        preset_name = get_active_preset()
        if required_headers:
            print("┌─ Bug Bounty Required Headers ───────────────────────────────┐")
            if preset_name:
                print(f"│  Active Preset: {preset_name:<40} │")
            for key, value in required_headers.items():
                masked = _mask_header_value(key, value)
                display_value = masked if len(masked) <= 35 else masked[:32] + "..."
                print(f"│  {key}: {display_value:<45} │")
            print("└──────────────────────────────────────────────────────────────┘\n")


# =============================================================================
# BUG BOUNTY MODE INTEGRATION
# =============================================================================

def is_bug_bounty_mode() -> bool:
    """
    Check if bug bounty mode is enabled in settings.

    Returns:
        True if bug bounty mode is enabled
    """
    config = _load_full_settings()
    return config.get("bug_bounty", {}).get("enabled", False)


def get_ssrf_protection_enabled() -> bool:
    """
    Check if SSRF protection is enabled.

    Returns:
        True if SSRF protection should block dangerous targets
    """
    config = _load_full_settings()
    bb_config = config.get("bug_bounty", {})

    if not bb_config.get("enabled", False):
        return False

    ssrf_config = bb_config.get("ssrf_protection", {})
    return ssrf_config.get("block_cloud_metadata", True) or \
           ssrf_config.get("block_private_ips", True) or \
           ssrf_config.get("block_localhost", True)


def is_brute_force_allowed() -> bool:
    """
    Check if brute force attacks are allowed.

    SECURITY: In bug bounty mode, brute force is typically disabled
    to comply with program rules and prevent account lockouts.

    Returns:
        True if brute force attacks are allowed
    """
    config = _load_full_settings()
    bb_config = config.get("bug_bounty", {})

    if not bb_config.get("enabled", False):
        return True  # No restrictions if bug bounty mode disabled

    brute_force = bb_config.get("brute_force", {})
    return brute_force.get("enabled", False)


def get_configured_ssl_verify() -> bool:
    """
    Get the SSL verification setting from configuration.

    SECURITY: In production/bug bounty mode, SSL verification
    should generally be enabled. Only disable for specific
    pentesting scenarios with self-signed certificates.

    Returns:
        True if SSL should be verified (secure default)
    """
    config = _load_full_settings()

    # Check bug bounty mode first
    bb_config = config.get("bug_bounty", {})
    if bb_config.get("enabled", False):
        # In bug bounty mode, respect the configured setting but warn if disabled
        ssl_config = config.get("network_protection", {}).get("ssl", {})
        return ssl_config.get("verify_ssl", True)

    # For pentest mode, check network protection settings
    ssl_config = config.get("network_protection", {}).get("ssl", {})
    return ssl_config.get("verify_ssl", True)  # Secure default
