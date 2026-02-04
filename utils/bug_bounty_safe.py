"""
Bug Bounty Safety Module - CRITICAL FOR NOT GETTING BANNED

This module enforces strict safety rules for bug bounty programs:
1. Hard allowlist enforcement - ONLY scan permitted targets
2. Rate limiting - 1-3 req/sec maximum
3. SSRF protection - Block dangerous IPs and protocols
4. Fingerprint consistency - Don't look like a bot
5. Kill switch - Instant stop capability
6. Complete logging - Full audit trail

IMPORTANT: This module is designed to prevent:
- Getting banned from bug bounty platforms
- Legal issues from unauthorized access
- Accidental DoS attacks
- Scope violations

Version: 1.0.0
Author: PetNTester AI Team
"""

import asyncio
import ipaddress
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from utils.logger import get_logger

logger = get_logger(__name__)


class BugBountyMode(Enum):
    """Bug bounty operation modes."""

    # SAFE - Default for bug bounty (RECOMMENDED)
    # - 1-2 req/sec
    # - No dangerous payloads
    # - No SSRF to internal IPs
    # - No brute force
    SAFE = "safe"

    # MODERATE - For programs that allow more testing
    # - 3-5 req/sec
    # - Some injection testing
    # - Still blocks dangerous SSRF
    MODERATE = "moderate"

    # AGGRESSIVE - Only with explicit written permission
    # - Higher rate limits
    # - Full payload testing
    # - Requires confirmation
    AGGRESSIVE = "aggressive"


@dataclass
class BugBountyConfig:
    """Configuration for bug bounty safe mode."""

    mode: BugBountyMode = BugBountyMode.SAFE

    # Rate limits per mode
    rate_limits: dict = field(default_factory=lambda: {
        BugBountyMode.SAFE: 1.5,      # 1.5 req/sec
        BugBountyMode.MODERATE: 3.0,   # 3 req/sec
        BugBountyMode.AGGRESSIVE: 10.0 # 10 req/sec (needs confirmation)
    })

    # Burst limits (max requests in quick succession)
    burst_limits: dict = field(default_factory=lambda: {
        BugBountyMode.SAFE: 3,
        BugBountyMode.MODERATE: 5,
        BugBountyMode.AGGRESSIVE: 15
    })

    # Jitter range (seconds) for timing randomization
    jitter_range: tuple = (0.3, 1.5)

    # Maximum requests per domain per minute
    max_requests_per_domain_per_minute: int = 60

    # Enable kill switch
    kill_switch_enabled: bool = True

    # Log all requests for accountability
    log_all_requests: bool = True

    # Block dangerous operations
    block_dangerous_ssrf: bool = True
    block_brute_force: bool = True
    block_dos_payloads: bool = True

    # Require explicit scope confirmation
    require_scope_confirmation: bool = True


# Dangerous IP ranges that MUST be blocked for bug bounty
BLOCKED_IP_RANGES = [
    # Cloud metadata services - NEVER ACCESS WITHOUT PERMISSION
    ipaddress.ip_network("169.254.169.254/32"),  # AWS/GCP/Azure metadata
    ipaddress.ip_network("100.100.100.200/32"),  # Alibaba metadata
    ipaddress.ip_network("192.0.0.192/32"),      # Oracle metadata

    # Link-local (can leak to metadata)
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),

    # Loopback
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),

    # Private networks (unless explicitly allowed)
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),

    # IPv6 private
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fd00::/8"),
]

# Dangerous protocols for SSRF
BLOCKED_PROTOCOLS = [
    "file://",      # Local file access
    "gopher://",    # Protocol smuggling
    "dict://",      # Dictionary server
    "ftp://",       # FTP access
    "ldap://",      # LDAP injection
    "tftp://",      # TFTP access
    "jar://",       # Java archive
    "netdoc://",    # Network document
]

# Dangerous paths that could cause issues
BLOCKED_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/.aws/credentials",
    "/.ssh/",
    "/proc/",
    "/sys/",
    "/.env",
    "/wp-config.php",
    "/config.php",
]

# Patterns that indicate brute force attempts
BRUTE_FORCE_PATTERNS = [
    r"/login",
    r"/signin",
    r"/auth",
    r"/oauth",
    r"/api/v\d+/auth",
    r"/password",
    r"/reset",
    r"/otp",
    r"/verify",
    r"/2fa",
    r"/mfa",
]


class BugBountySafetyGuard:
    """
    Central safety controller for bug bounty operations.

    This class MUST be used for all bug bounty testing to ensure:
    - No accidental scope violations
    - No dangerous SSRF to internal IPs
    - Proper rate limiting
    - Complete audit logging
    - Instant kill switch capability

    Usage:
        guard = BugBountySafetyGuard(allowed_domains=["example.com", "*.example.com"])

        # Check if request is allowed
        if await guard.is_request_allowed(url):
            # Make request
            await guard.log_request(url, method, response_code)
    """

    def __init__(
        self,
        allowed_domains: list[str],
        config: Optional[BugBountyConfig] = None,
        program_name: str = "unknown",
        log_file: Optional[Path] = None,
    ):
        self.allowed_domains = [d.lower().strip() for d in allowed_domains]
        self.config = config or BugBountyConfig()
        self.program_name = program_name
        self.log_file = log_file or Path("logs/bug_bounty_audit.jsonl")

        # Kill switch state
        self._killed = False
        self._kill_reason: Optional[str] = None

        # Rate limiting state
        self._request_times: dict[str, list[float]] = {}
        self._lock = asyncio.Lock()

        # Request counter for audit
        self._total_requests = 0
        self._blocked_requests = 0
        self._scope_violations = 0

        # Brute force detection
        self._endpoint_hits: dict[str, int] = {}

        # Ensure log directory exists
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

        logger.info(
            f"BugBountySafetyGuard initialized",
            program=program_name,
            mode=self.config.mode.value,
            domains=len(self.allowed_domains),
        )

    # ==================== KILL SWITCH ====================

    def kill(self, reason: str = "Manual kill switch activated") -> None:
        """
        EMERGENCY STOP - Immediately halt all operations.

        Use this when:
        - Program owner requests stop
        - Unexpected behavior detected
        - Any suspicious activity
        """
        self._killed = True
        self._kill_reason = reason

        logger.critical(
            "KILL SWITCH ACTIVATED",
            reason=reason,
            total_requests=self._total_requests,
            blocked=self._blocked_requests,
        )

        # Log kill event
        self._log_event({
            "event": "KILL_SWITCH",
            "reason": reason,
            "timestamp": datetime.now().isoformat(),
            "stats": {
                "total_requests": self._total_requests,
                "blocked_requests": self._blocked_requests,
                "scope_violations": self._scope_violations,
            }
        })

    def is_killed(self) -> bool:
        """Check if kill switch is active."""
        return self._killed

    def revive(self, confirmation: str) -> bool:
        """
        Revive after kill switch (requires confirmation).

        Args:
            confirmation: Must be "I confirm revive after reviewing logs"
        """
        if confirmation != "I confirm revive after reviewing logs":
            logger.warning("Invalid revive confirmation")
            return False

        self._killed = False
        self._kill_reason = None
        logger.warning("Kill switch deactivated - operations resumed")
        return True

    # ==================== SCOPE VALIDATION ====================

    def is_domain_allowed(self, url: str) -> tuple[bool, str]:
        """
        Check if domain is in allowed scope.

        Returns:
            Tuple of (allowed: bool, reason: str)
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # Remove port if present
            if ":" in domain:
                domain = domain.split(":")[0]

            # Check exact match
            if domain in self.allowed_domains:
                return True, "Exact domain match"

            # Check wildcard match (*.example.com)
            for allowed in self.allowed_domains:
                if allowed.startswith("*."):
                    base_domain = allowed[2:]  # Remove *.
                    if domain == base_domain or domain.endswith("." + base_domain):
                        return True, f"Wildcard match: {allowed}"

            return False, f"Domain '{domain}' not in allowed scope"

        except Exception as e:
            return False, f"Invalid URL: {e}"

    def is_ip_safe(self, url: str) -> tuple[bool, str]:
        """
        Check if target IP is safe (not internal/metadata).

        Returns:
            Tuple of (safe: bool, reason: str)
        """
        try:
            parsed = urlparse(url)
            host = parsed.netloc.lower()

            # Remove port if present
            if ":" in host:
                host = host.split(":")[0]

            # Check if it's an IP address
            try:
                ip = ipaddress.ip_address(host)

                # Check against blocked ranges
                for blocked_range in BLOCKED_IP_RANGES:
                    if ip in blocked_range:
                        return False, f"BLOCKED: IP {ip} is in dangerous range {blocked_range}"

                return True, "IP is safe"

            except ValueError:
                # Not an IP address, it's a hostname - need to resolve
                # For now, allow hostnames (they'll be validated by domain check)
                return True, "Hostname (not IP)"

        except Exception as e:
            return False, f"Error checking IP: {e}"

    def is_protocol_safe(self, url: str) -> tuple[bool, str]:
        """
        Check if protocol is safe (no file://, gopher://, etc.).

        Returns:
            Tuple of (safe: bool, reason: str)
        """
        url_lower = url.lower()

        for blocked in BLOCKED_PROTOCOLS:
            if url_lower.startswith(blocked):
                return False, f"BLOCKED: Protocol '{blocked}' is dangerous"

        # Only allow http and https
        if not (url_lower.startswith("http://") or url_lower.startswith("https://")):
            return False, f"BLOCKED: Only HTTP/HTTPS protocols allowed"

        return True, "Protocol is safe"

    def is_path_safe(self, url: str) -> tuple[bool, str]:
        """
        Check if path doesn't contain dangerous patterns.

        Returns:
            Tuple of (safe: bool, reason: str)
        """
        try:
            parsed = urlparse(url)
            path = parsed.path.lower()

            for blocked in BLOCKED_PATHS:
                if blocked in path:
                    return False, f"BLOCKED: Path contains dangerous pattern '{blocked}'"

            return True, "Path is safe"

        except Exception as e:
            return False, f"Error checking path: {e}"

    # ==================== REQUEST VALIDATION ====================

    async def is_request_allowed(
        self,
        url: str,
        method: str = "GET",
        check_rate_limit: bool = True,
    ) -> tuple[bool, str]:
        """
        Comprehensive check if request is allowed.

        This is the MAIN validation method - use this for every request.

        Returns:
            Tuple of (allowed: bool, reason: str)
        """
        # Check kill switch first
        if self._killed:
            return False, f"KILLED: {self._kill_reason}"

        # Check domain scope
        domain_ok, domain_reason = self.is_domain_allowed(url)
        if not domain_ok:
            self._scope_violations += 1
            self._blocked_requests += 1
            await self._log_blocked_request(url, method, domain_reason)
            return False, domain_reason

        # Check IP safety (for SSRF protection)
        if self.config.block_dangerous_ssrf:
            ip_ok, ip_reason = self.is_ip_safe(url)
            if not ip_ok:
                self._blocked_requests += 1
                await self._log_blocked_request(url, method, ip_reason)
                return False, ip_reason

        # Check protocol safety
        protocol_ok, protocol_reason = self.is_protocol_safe(url)
        if not protocol_ok:
            self._blocked_requests += 1
            await self._log_blocked_request(url, method, protocol_reason)
            return False, protocol_reason

        # Check path safety
        path_ok, path_reason = self.is_path_safe(url)
        if not path_ok:
            self._blocked_requests += 1
            await self._log_blocked_request(url, method, path_reason)
            return False, path_reason

        # Check brute force patterns
        if self.config.block_brute_force:
            bf_ok, bf_reason = await self._check_brute_force(url, method)
            if not bf_ok:
                self._blocked_requests += 1
                await self._log_blocked_request(url, method, bf_reason)
                return False, bf_reason

        # Check rate limit
        if check_rate_limit:
            rate_ok, rate_reason = await self._check_rate_limit(url)
            if not rate_ok:
                return False, rate_reason

        return True, "Request allowed"

    async def _check_rate_limit(self, url: str) -> tuple[bool, str]:
        """Check if request respects rate limits."""
        async with self._lock:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            current_time = time.time()

            # Get rate limit for current mode
            rate_limit = self.config.rate_limits[self.config.mode]
            min_interval = 1.0 / rate_limit

            # Initialize domain tracking
            if domain not in self._request_times:
                self._request_times[domain] = []

            # Clean old entries (older than 1 minute)
            self._request_times[domain] = [
                t for t in self._request_times[domain]
                if current_time - t < 60
            ]

            # Check requests per minute limit
            if len(self._request_times[domain]) >= self.config.max_requests_per_domain_per_minute:
                return False, f"Rate limit: Max {self.config.max_requests_per_domain_per_minute} req/min exceeded"

            # Check minimum interval
            if self._request_times[domain]:
                last_request = self._request_times[domain][-1]
                if current_time - last_request < min_interval:
                    wait_time = min_interval - (current_time - last_request)
                    return False, f"Rate limit: Wait {wait_time:.2f}s"

            # Record this request
            self._request_times[domain].append(current_time)

            return True, "Rate limit OK"

    async def _check_brute_force(self, url: str, method: str) -> tuple[bool, str]:
        """Check for brute force patterns."""
        if method.upper() not in ["POST", "PUT", "PATCH"]:
            return True, "GET request - no brute force check needed"

        parsed = urlparse(url)
        path = parsed.path.lower()

        # Check against brute force patterns
        for pattern in BRUTE_FORCE_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                endpoint_key = f"{parsed.netloc}{path}"

                async with self._lock:
                    self._endpoint_hits[endpoint_key] = self._endpoint_hits.get(endpoint_key, 0) + 1

                    # Allow max 5 attempts to auth endpoints
                    if self._endpoint_hits[endpoint_key] > 5:
                        return False, f"BLOCKED: Brute force protection - max 5 attempts to auth endpoints"

        return True, "No brute force detected"

    # ==================== LOGGING ====================

    async def log_request(
        self,
        url: str,
        method: str,
        response_code: int,
        response_time_ms: float,
        payload: Optional[str] = None,
    ) -> None:
        """Log successful request for audit trail."""
        self._total_requests += 1

        if self.config.log_all_requests:
            await self._log_event({
                "event": "REQUEST",
                "timestamp": datetime.now().isoformat(),
                "program": self.program_name,
                "url": url,
                "method": method,
                "response_code": response_code,
                "response_time_ms": response_time_ms,
                "payload_hash": hash(payload) if payload else None,
                "request_number": self._total_requests,
            })

    async def _log_blocked_request(
        self,
        url: str,
        method: str,
        reason: str,
    ) -> None:
        """Log blocked request."""
        await self._log_event({
            "event": "BLOCKED",
            "timestamp": datetime.now().isoformat(),
            "program": self.program_name,
            "url": url,
            "method": method,
            "reason": reason,
            "blocked_count": self._blocked_requests,
        })

        logger.warning(
            "Request blocked",
            url=url,
            reason=reason,
        )

    def _log_event(self, event: dict) -> None:
        """Write event to log file."""
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

    # ==================== STATISTICS ====================

    def get_stats(self) -> dict:
        """Get current statistics."""
        return {
            "program": self.program_name,
            "mode": self.config.mode.value,
            "killed": self._killed,
            "total_requests": self._total_requests,
            "blocked_requests": self._blocked_requests,
            "scope_violations": self._scope_violations,
            "allowed_domains": len(self.allowed_domains),
            "rate_limit": self.config.rate_limits[self.config.mode],
        }

    def print_stats(self) -> None:
        """Print current statistics."""
        stats = self.get_stats()
        print("\n" + "=" * 50)
        print("BUG BOUNTY SAFETY STATISTICS")
        print("=" * 50)
        print(f"Program: {stats['program']}")
        print(f"Mode: {stats['mode']}")
        print(f"Kill Switch: {'ACTIVE' if stats['killed'] else 'OFF'}")
        print(f"Total Requests: {stats['total_requests']}")
        print(f"Blocked Requests: {stats['blocked_requests']}")
        print(f"Scope Violations: {stats['scope_violations']}")
        print(f"Rate Limit: {stats['rate_limit']} req/sec")
        print("=" * 50 + "\n")


class ConsistentFingerprint:
    """
    Provides consistent HTTP fingerprint to avoid bot detection.

    IMPORTANT: For bug bounty, we need to look like a real browser,
    not a bot. This means:
    - Fixed User-Agent (no rotation)
    - Consistent header order
    - Real browser headers
    - No random variations
    """

    # Chrome 120 on Windows 11 - realistic and common
    DEFAULT_USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )

    def __init__(self, user_agent: Optional[str] = None):
        self.user_agent = user_agent or self.DEFAULT_USER_AGENT

    def get_headers(self, referer: Optional[str] = None) -> dict[str, str]:
        """
        Get consistent browser-like headers.

        IMPORTANT: Headers are in EXACT browser order - do not shuffle!
        """
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0",
        }

        if referer:
            headers["Referer"] = referer
            headers["Sec-Fetch-Site"] = "same-origin"

        return headers

    def get_api_headers(self, content_type: str = "application/json") -> dict[str, str]:
        """Get headers for API requests."""
        return {
            "User-Agent": self.user_agent,
            "Accept": content_type,
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Content-Type": content_type,
        }


def validate_hackerone_scope(scope_text: str) -> list[str]:
    """
    Parse HackerOne scope text into allowed domains.

    Example input:
        "*.example.com
         api.example.com
         www.example.com"

    Returns:
        List of normalized domains
    """
    domains = []

    for line in scope_text.strip().split("\n"):
        line = line.strip().lower()

        # Skip empty lines and comments
        if not line or line.startswith("#"):
            continue

        # Remove protocol if present
        if "://" in line:
            line = line.split("://")[1]

        # Remove path if present
        if "/" in line:
            line = line.split("/")[0]

        # Remove port if present
        if ":" in line:
            line = line.split(":")[0]

        if line:
            domains.append(line)

    return domains


def create_safety_guard_from_hackerone(
    scope_text: str,
    program_name: str,
    mode: BugBountyMode = BugBountyMode.SAFE,
) -> BugBountySafetyGuard:
    """
    Create a safety guard from HackerOne scope.

    Usage:
        scope = '''
        *.example.com
        api.example.com
        '''
        guard = create_safety_guard_from_hackerone(scope, "Example Bug Bounty")
    """
    domains = validate_hackerone_scope(scope_text)
    config = BugBountyConfig(mode=mode)

    return BugBountySafetyGuard(
        allowed_domains=domains,
        config=config,
        program_name=program_name,
    )


# Convenience function for quick setup
def quick_setup(
    domains: list[str],
    program_name: str = "Bug Bounty",
) -> BugBountySafetyGuard:
    """
    Quick setup for bug bounty testing.

    Usage:
        guard = quick_setup(["example.com", "*.example.com"], "Example Program")
    """
    return BugBountySafetyGuard(
        allowed_domains=domains,
        config=BugBountyConfig(mode=BugBountyMode.SAFE),
        program_name=program_name,
    )
