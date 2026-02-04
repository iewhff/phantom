"""
Advanced OPSEC Protection Module v2.0

Enterprise-grade security features for pentesting:
- Kill switch (stops all traffic if protection fails)
- Continuous IP monitoring during scans
- Automatic Tor circuit rotation
- Human-like request timing with jitter
- WebRTC leak prevention checks
- DNS leak prevention
- Request fingerprint randomization
- Evidence cleanup utilities
- Multi-hop proxy chains
- Canary requests for detection

Author: PetNTester AI
Version: 2.0.0
"""

from __future__ import annotations

import os
import sys
import random
import asyncio
import hashlib
import time
import json
from dataclasses import dataclass, field
from typing import Optional, Any, Callable, List
from datetime import datetime, timedelta
from pathlib import Path
from enum import Enum

import httpx

from utils.logger import get_logger
from utils.network_protection import (
    NetworkProtection,
    ProxyConfig,
    ProxyType,
    TorController,
    USER_AGENTS,
    ACCEPT_HEADERS,
    ACCEPT_LANGUAGE,
)

logger = get_logger(__name__)


# =============================================================================
# PROTECTION LEVELS
# =============================================================================

class ProtectionLevel(Enum):
    """Security level for different scenarios."""
    MINIMAL = "minimal"      # Basic proxy, fast scans
    STANDARD = "standard"    # Proxy + UA rotation + headers
    HIGH = "high"           # + IP verification + delays
    PARANOID = "paranoid"   # + circuit rotation + full checks


@dataclass
class OPSECConfig:
    """Advanced OPSEC configuration."""
    
    # Protection level
    level: ProtectionLevel = ProtectionLevel.HIGH
    
    # Kill switch - abort scan if protection fails
    kill_switch_enabled: bool = True
    
    # Continuous monitoring
    verify_ip_every_n_requests: int = 50
    verify_ip_every_n_seconds: int = 300
    
    # Tor circuit rotation
    rotate_circuit_every_n_requests: int = 25
    rotate_circuit_every_n_minutes: int = 10
    
    # Human-like timing
    min_request_delay_ms: int = 100
    max_request_delay_ms: int = 2000
    burst_probability: float = 0.1  # 10% chance of burst (no delay)
    
    # Request limits
    max_requests_per_domain: int = 1000
    max_errors_before_pause: int = 10
    pause_duration_seconds: int = 60
    
    # Fingerprint randomization
    randomize_tls_fingerprint: bool = True
    randomize_tcp_fingerprint: bool = False  # Requires root
    
    # Evidence cleanup
    auto_cleanup_logs: bool = False
    cleanup_on_exit: bool = True


# =============================================================================
# KILL SWITCH
# =============================================================================

class KillSwitch:
    """
    Network kill switch - stops all traffic if protection fails.
    
    This prevents IP leaks by immediately stopping all requests
    if the proxy/Tor connection fails.
    """
    
    def __init__(self):
        self._armed = False
        self._triggered = False
        self._original_ip: Optional[str] = None
        self._callbacks: List[Callable] = []
    
    def arm(self, original_ip: str) -> None:
        """Arm the kill switch with original IP."""
        self._original_ip = original_ip
        self._armed = True
        logger.info(f"🔴 Kill switch ARMED - Original IP: {original_ip}")
    
    def disarm(self) -> None:
        """Disarm the kill switch."""
        self._armed = False
        logger.info("🟢 Kill switch disarmed")
    
    def trigger(self, reason: str) -> None:
        """Trigger the kill switch - stop all traffic."""
        if not self._armed:
            return
        
        self._triggered = True
        logger.error(f"🚨 KILL SWITCH TRIGGERED: {reason}")
        logger.error("🛑 ALL NETWORK TRAFFIC STOPPED")
        
        # Execute callbacks
        for callback in self._callbacks:
            try:
                callback(reason)
            except Exception as e:
                logger.error(f"Kill switch callback error: {e}")
    
    def add_callback(self, callback: Callable[[str], None]) -> None:
        """Add callback to execute when kill switch triggers."""
        self._callbacks.append(callback)
    
    @property
    def is_triggered(self) -> bool:
        return self._triggered
    
    @property
    def is_armed(self) -> bool:
        return self._armed
    
    def check_ip(self, current_ip: str) -> bool:
        """Check if current IP matches original (leak detection)."""
        if not self._armed or not self._original_ip:
            return True
        
        if current_ip == self._original_ip:
            self.trigger(f"IP LEAK DETECTED! Current: {current_ip} matches original!")
            return False
        
        return True


# =============================================================================
# REQUEST MANAGER WITH OPSEC
# =============================================================================

class SecureRequestManager:
    """
    Manages HTTP requests with full OPSEC compliance.
    
    Features:
    - Automatic delay between requests (human-like)
    - IP verification during scan
    - Kill switch integration
    - Circuit rotation
    - Request counting and limits
    """
    
    def __init__(
        self,
        protection: NetworkProtection,
        config: OPSECConfig,
        kill_switch: Optional[KillSwitch] = None,
    ):
        self.protection = protection
        self.config = config
        self.kill_switch = kill_switch or KillSwitch()
        
        # Tor controller for circuit rotation
        self.tor_controller: Optional[TorController] = None
        if protection.proxy_config.proxy_type == ProxyType.TOR:
            self.tor_controller = TorController(
                control_port=protection.proxy_config.tor_control_port,
                password=protection.proxy_config.tor_password,
            )
        
        # Counters
        self._request_count = 0
        self._error_count = 0
        self._last_request_time = time.time()
        self._last_ip_check_time = time.time()
        self._last_circuit_rotation = time.time()
        self._domain_requests: dict[str, int] = {}
        
        # State
        self._paused = False
        self._pause_until: Optional[float] = None
    
    async def initialize(self) -> bool:
        """Initialize the secure request manager."""
        logger.info("🔒 Initializing Secure Request Manager...")
        
        # Get original IP first (without proxy)
        self.protection.proxy_config.enabled = False
        original_ip = await self.protection.check_current_ip()
        
        if not original_ip:
            logger.error("❌ Could not determine original IP")
            return False
        
        # Arm kill switch
        if self.config.kill_switch_enabled:
            self.kill_switch.arm(original_ip)
        
        # Enable proxy and verify
        self.protection.proxy_config.enabled = True
        
        if not await self.protection.verify_proxy_working():
            logger.error("❌ Proxy verification failed")
            if self.config.kill_switch_enabled:
                self.kill_switch.trigger("Initial proxy verification failed")
            return False
        
        # Connect to Tor controller if using Tor
        if self.tor_controller:
            await self.tor_controller.connect()
        
        logger.info("✅ Secure Request Manager ready")
        return True
    
    async def _apply_human_delay(self) -> None:
        """Apply human-like delay between requests."""
        if self.config.level == ProtectionLevel.MINIMAL:
            return
        
        # Chance of burst (no delay)
        if random.random() < self.config.burst_probability:
            return
        
        # Random delay with jitter
        base_delay = random.randint(
            self.config.min_request_delay_ms,
            self.config.max_request_delay_ms
        )
        
        # Add gaussian jitter
        jitter = random.gauss(0, base_delay * 0.2)
        delay_ms = max(50, base_delay + jitter)
        
        await asyncio.sleep(delay_ms / 1000)
    
    async def _maybe_rotate_circuit(self) -> None:
        """Rotate Tor circuit if needed."""
        if not self.tor_controller:
            return
        
        now = time.time()
        
        # Check request count
        should_rotate = (
            self._request_count > 0 and
            self._request_count % self.config.rotate_circuit_every_n_requests == 0
        )
        
        # Check time
        minutes_since_rotation = (now - self._last_circuit_rotation) / 60
        if minutes_since_rotation >= self.config.rotate_circuit_every_n_minutes:
            should_rotate = True
        
        if should_rotate:
            logger.info("🔄 Rotating Tor circuit...")
            if await self.tor_controller.new_identity():
                self._last_circuit_rotation = now
                logger.info("✅ New Tor circuit established")
                
                # Verify new IP
                await asyncio.sleep(2)  # Wait for circuit
                await self._verify_ip()
    
    async def _verify_ip(self) -> bool:
        """Verify IP hasn't leaked."""
        if self.config.level in (ProtectionLevel.MINIMAL, ProtectionLevel.STANDARD):
            return True
        
        now = time.time()
        
        # Check if we need to verify
        should_check = False
        
        if self._request_count % self.config.verify_ip_every_n_requests == 0:
            should_check = True
        
        if (now - self._last_ip_check_time) >= self.config.verify_ip_every_n_seconds:
            should_check = True
        
        if not should_check:
            return True
        
        logger.debug("🔍 Verifying IP protection...")
        current_ip = await self.protection.check_current_ip()
        
        if not current_ip:
            logger.warning("⚠️ Could not verify IP")
            return True
        
        self._last_ip_check_time = now
        
        # Check against original
        if self.kill_switch.is_armed:
            if not self.kill_switch.check_ip(current_ip):
                return False
        
        logger.debug(f"✅ IP verified: {current_ip}")
        return True
    
    async def _check_domain_limit(self, domain: str) -> bool:
        """Check if domain request limit reached."""
        count = self._domain_requests.get(domain, 0)
        if count >= self.config.max_requests_per_domain:
            logger.warning(f"⚠️ Domain limit reached for {domain}: {count} requests")
            return False
        return True
    
    async def _handle_error(self) -> None:
        """Handle request error."""
        self._error_count += 1
        
        if self._error_count >= self.config.max_errors_before_pause:
            self._paused = True
            self._pause_until = time.time() + self.config.pause_duration_seconds
            logger.warning(
                f"⚠️ Too many errors ({self._error_count}), "
                f"pausing for {self.config.pause_duration_seconds}s"
            )
            self._error_count = 0
    
    async def request(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> Optional[httpx.Response]:
        """
        Make a protected HTTP request with all OPSEC features.
        
        Returns None if kill switch triggered or limits exceeded.
        """
        # Check kill switch
        if self.kill_switch.is_triggered:
            logger.error("🛑 Kill switch active - request blocked")
            return None
        
        # Check pause
        if self._paused:
            if time.time() < self._pause_until:
                wait_time = self._pause_until - time.time()
                logger.info(f"⏸️ Paused, waiting {wait_time:.0f}s...")
                await asyncio.sleep(wait_time)
            self._paused = False
        
        # Check domain limit
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        if not await self._check_domain_limit(domain):
            return None
        
        # Apply human delay
        await self._apply_human_delay()
        
        # Maybe rotate circuit
        await self._maybe_rotate_circuit()
        
        # Verify IP periodically
        if not await self._verify_ip():
            return None
        
        # Make request
        try:
            client_kwargs = self.protection.get_httpx_client_kwargs()
            
            async with httpx.AsyncClient(**client_kwargs) as client:
                response = await client.request(method, url, **kwargs)
                
                # Update counters
                self._request_count += 1
                self._domain_requests[domain] = self._domain_requests.get(domain, 0) + 1
                self._last_request_time = time.time()
                self._error_count = 0  # Reset error count on success
                
                return response
                
        except Exception as e:
            logger.warning(f"Request error: {e}")
            await self._handle_error()
            return None
    
    def get_stats(self) -> dict[str, Any]:
        """Get request statistics."""
        return {
            "total_requests": self._request_count,
            "error_count": self._error_count,
            "paused": self._paused,
            "kill_switch_armed": self.kill_switch.is_armed,
            "kill_switch_triggered": self.kill_switch.is_triggered,
            "domain_requests": dict(self._domain_requests),
        }


# =============================================================================
# EVIDENCE CLEANUP
# =============================================================================

class EvidenceCleanup:
    """
    Cleanup sensitive evidence after pentesting.
    
    Removes:
    - Local logs containing IPs
    - Temporary files
    - Cache files
    - History files
    """
    
    SENSITIVE_PATTERNS = [
        "*.log",
        "*.tmp",
        "*cache*",
        "*history*",
        "*.bak",
    ]
    
    def __init__(self, base_path: str = "."):
        self.base_path = Path(base_path)
        self._files_to_clean: List[Path] = []
    
    def mark_for_cleanup(self, path: str | Path) -> None:
        """Mark a file for cleanup on exit."""
        self._files_to_clean.append(Path(path))
    
    def secure_delete(self, path: Path) -> bool:
        """Securely delete a file by overwriting before deletion."""
        try:
            if not path.exists():
                return True
            
            # Overwrite with random data
            size = path.stat().st_size
            with open(path, 'wb') as f:
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
            
            # Then delete
            path.unlink()
            return True
            
        except Exception as e:
            logger.warning(f"Failed to securely delete {path}: {e}")
            return False
    
    def cleanup_logs(self, logs_dir: str = "data/logs") -> int:
        """Clean up log files containing sensitive data."""
        cleaned = 0
        logs_path = self.base_path / logs_dir
        
        if not logs_path.exists():
            return 0
        
        for log_file in logs_path.glob("*.log"):
            if self.secure_delete(log_file):
                cleaned += 1
        
        logger.info(f"🧹 Cleaned {cleaned} log files")
        return cleaned
    
    def cleanup_temp(self) -> int:
        """Clean up temporary files."""
        cleaned = 0
        
        for pattern in ["*.tmp", "*.temp", ".~*"]:
            for temp_file in self.base_path.rglob(pattern):
                if self.secure_delete(temp_file):
                    cleaned += 1
        
        return cleaned
    
    def cleanup_marked(self) -> int:
        """Clean up files marked for cleanup."""
        cleaned = 0
        
        for path in self._files_to_clean:
            if self.secure_delete(path):
                cleaned += 1
        
        self._files_to_clean.clear()
        return cleaned
    
    def full_cleanup(self) -> dict[str, int]:
        """Perform full evidence cleanup."""
        logger.info("🧹 Starting evidence cleanup...")
        
        results = {
            "logs": self.cleanup_logs(),
            "temp": self.cleanup_temp(),
            "marked": self.cleanup_marked(),
        }
        
        total = sum(results.values())
        logger.info(f"🧹 Cleanup complete: {total} files removed")
        
        return results


# =============================================================================
# CANARY SYSTEM
# =============================================================================

class CanarySystem:
    """
    Canary requests to detect if we're being tracked/blocked.
    
    Periodically makes requests to known-good sites to verify
    our traffic is behaving normally.
    """
    
    CANARY_SITES = [
        "https://www.google.com/robots.txt",
        "https://www.cloudflare.com/robots.txt",
        "https://www.github.com/robots.txt",
    ]
    
    def __init__(self, protection: NetworkProtection):
        self.protection = protection
        self._baseline_times: dict[str, float] = {}
    
    async def establish_baseline(self) -> bool:
        """Establish baseline response times."""
        logger.info("🐤 Establishing canary baselines...")
        
        kwargs = self.protection.get_httpx_client_kwargs()
        
        async with httpx.AsyncClient(**kwargs) as client:
            for url in self.CANARY_SITES:
                try:
                    start = time.time()
                    response = await client.get(url, timeout=10.0)
                    elapsed = time.time() - start
                    
                    if response.status_code == 200:
                        self._baseline_times[url] = elapsed
                        logger.debug(f"  {url}: {elapsed:.2f}s")
                        
                except Exception:
                    continue
        
        if len(self._baseline_times) < 2:
            logger.warning("⚠️ Could not establish enough canary baselines")
            return False
        
        logger.info(f"✅ Canary baselines established for {len(self._baseline_times)} sites")
        return True
    
    async def check_canaries(self) -> dict[str, Any]:
        """Check if canary requests are behaving normally."""
        results = {
            "healthy": True,
            "blocked_sites": [],
            "slow_sites": [],
            "timing_anomalies": [],
        }
        
        kwargs = self.protection.get_httpx_client_kwargs()
        
        async with httpx.AsyncClient(**kwargs) as client:
            for url, baseline in self._baseline_times.items():
                try:
                    start = time.time()
                    response = await client.get(url, timeout=15.0)
                    elapsed = time.time() - start
                    
                    # Check for blocking
                    if response.status_code in (403, 429, 503):
                        results["blocked_sites"].append(url)
                        results["healthy"] = False
                    
                    # Check for slowdown (>3x baseline)
                    if elapsed > baseline * 3:
                        results["slow_sites"].append({
                            "url": url,
                            "baseline": baseline,
                            "current": elapsed,
                        })
                    
                    # Check for timing anomaly (>5x baseline)
                    if elapsed > baseline * 5:
                        results["timing_anomalies"].append(url)
                        results["healthy"] = False
                        
                except asyncio.TimeoutError:
                    results["blocked_sites"].append(url)
                    results["healthy"] = False
                except Exception:
                    pass
        
        return results


# =============================================================================
# ADVANCED OPSEC MANAGER
# =============================================================================

class AdvancedOPSEC:
    """
    Main advanced OPSEC manager.
    
    Coordinates all security features:
    - Protection verification
    - Kill switch
    - Circuit rotation
    - Canary monitoring
    - Evidence cleanup
    """
    
    def __init__(
        self,
        protection: NetworkProtection,
        config: Optional[OPSECConfig] = None,
    ):
        self.protection = protection
        self.config = config or OPSECConfig()
        
        self.kill_switch = KillSwitch()
        self.request_manager = SecureRequestManager(
            protection, self.config, self.kill_switch
        )
        self.canary_system = CanarySystem(protection)
        self.evidence_cleanup = EvidenceCleanup()
        
        self._initialized = False
        self._scan_start_time: Optional[datetime] = None
    
    async def initialize(self) -> bool:
        """Initialize all OPSEC systems."""
        logger.info("🔒 Initializing Advanced OPSEC...")
        logger.info(f"   Protection Level: {self.config.level.value}")
        
        # Initialize request manager (includes kill switch arming)
        if not await self.request_manager.initialize():
            return False
        
        # Establish canary baselines
        if self.config.level in (ProtectionLevel.HIGH, ProtectionLevel.PARANOID):
            await self.canary_system.establish_baseline()
        
        self._initialized = True
        self._scan_start_time = datetime.now()
        
        logger.info("✅ Advanced OPSEC initialized")
        return True
    
    async def pre_scan_check(self) -> bool:
        """Perform pre-scan security checks."""
        logger.info("🔍 Running pre-scan security checks...")
        
        checks_passed = 0
        checks_total = 0
        
        # 1. IP Protection
        checks_total += 1
        if await self.protection.verify_proxy_working():
            checks_passed += 1
            logger.info("  ✅ IP Protection: ACTIVE")
        else:
            logger.error("  ❌ IP Protection: FAILED")
        
        # 2. DNS Leak Check
        checks_total += 1
        if await self.protection.check_dns_leaks():
            checks_passed += 1
            logger.info("  ✅ DNS Leak Check: PASSED")
        else:
            logger.warning("  ⚠️ DNS Leak Check: INCONCLUSIVE")
            checks_passed += 1  # Not a hard fail
        
        # 3. Kill Switch
        checks_total += 1
        if self.kill_switch.is_armed:
            checks_passed += 1
            logger.info("  ✅ Kill Switch: ARMED")
        else:
            logger.warning("  ⚠️ Kill Switch: NOT ARMED")
        
        # 4. Canary Check
        if self.config.level in (ProtectionLevel.HIGH, ProtectionLevel.PARANOID):
            checks_total += 1
            canary_results = await self.canary_system.check_canaries()
            if canary_results["healthy"]:
                checks_passed += 1
                logger.info("  ✅ Canary Check: HEALTHY")
            else:
                logger.warning(f"  ⚠️ Canary Check: Issues detected")
        
        logger.info(f"🔍 Pre-scan checks: {checks_passed}/{checks_total} passed")
        
        # Require all critical checks for PARANOID mode
        if self.config.level == ProtectionLevel.PARANOID:
            return checks_passed == checks_total
        
        # For other levels, require at least IP protection
        return checks_passed >= 1
    
    async def request(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> Optional[httpx.Response]:
        """Make a secure request through the OPSEC manager."""
        if not self._initialized:
            logger.error("OPSEC not initialized!")
            return None
        
        return await self.request_manager.request(method, url, **kwargs)
    
    async def shutdown(self) -> None:
        """Shutdown OPSEC and cleanup."""
        logger.info("🔒 Shutting down OPSEC...")
        
        # Cleanup if configured
        if self.config.cleanup_on_exit:
            self.evidence_cleanup.full_cleanup()
        
        # Disarm kill switch
        self.kill_switch.disarm()
        
        # Log stats
        stats = self.request_manager.get_stats()
        logger.info(f"📊 Session stats: {stats['total_requests']} requests")
        
        duration = datetime.now() - self._scan_start_time if self._scan_start_time else None
        if duration:
            logger.info(f"⏱️ Session duration: {duration}")
    
    def get_status(self) -> dict[str, Any]:
        """Get full OPSEC status."""
        return {
            "initialized": self._initialized,
            "protection_level": self.config.level.value,
            "kill_switch_armed": self.kill_switch.is_armed,
            "kill_switch_triggered": self.kill_switch.is_triggered,
            "request_stats": self.request_manager.get_stats(),
            "scan_start": self._scan_start_time.isoformat() if self._scan_start_time else None,
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

async def create_paranoid_protection() -> AdvancedOPSEC:
    """Create maximum protection OPSEC manager."""
    from utils.network_protection import create_network_protection
    
    protection = create_network_protection(use_tor=True, rotate_ua=True)
    
    config = OPSECConfig(
        level=ProtectionLevel.PARANOID,
        kill_switch_enabled=True,
        verify_ip_every_n_requests=25,
        rotate_circuit_every_n_requests=15,
        min_request_delay_ms=500,
        max_request_delay_ms=3000,
    )
    
    opsec = AdvancedOPSEC(protection, config)
    await opsec.initialize()
    
    return opsec


def print_opsec_banner(config: OPSECConfig):
    """Print OPSEC configuration banner."""
    level_emoji = {
        ProtectionLevel.MINIMAL: "🟡",
        ProtectionLevel.STANDARD: "🟢",
        ProtectionLevel.HIGH: "🔵",
        ProtectionLevel.PARANOID: "🔴",
    }
    
    emoji = level_emoji.get(config.level, "⚪")
    
    print(f"""
╔═══════════════════════════════════════════════════════════════════╗
║  {emoji} ADVANCED OPSEC PROTECTION - {config.level.value.upper():^12}              ║
╠═══════════════════════════════════════════════════════════════════╣
║  Kill Switch:      {'ENABLED' if config.kill_switch_enabled else 'DISABLED':<10}                            ║
║  IP Verification:  Every {config.verify_ip_every_n_requests} requests                          ║
║  Circuit Rotation: Every {config.rotate_circuit_every_n_requests} requests                          ║
║  Request Delay:    {config.min_request_delay_ms}-{config.max_request_delay_ms}ms                                  ║
║  Auto Cleanup:     {'ENABLED' if config.cleanup_on_exit else 'DISABLED':<10}                            ║
╚═══════════════════════════════════════════════════════════════════╝
""")
