"""
SSRF Safety Filter - CRITICAL FOR BUG BOUNTY

This module MUST be used before any SSRF testing to prevent:
1. Accessing cloud metadata (169.254.169.254) - ILLEGAL without permission
2. Accessing internal networks - ILLEGAL without permission
3. Using dangerous protocols (file://, gopher://) - VERY RISKY
4. DNS rebinding to internal IPs - ILLEGAL

Usage:
    from utils.ssrf_safety import SSRFSafetyFilter

    filter = SSRFSafetyFilter(mode="bug_bounty")

    # Before testing any URL
    is_safe, reason = filter.is_url_safe(url)
    if not is_safe:
        logger.warning(f"SSRF blocked: {reason}")
        return None

Version: 1.0.0
"""

import ipaddress
import re
import socket
from dataclasses import dataclass
from enum import Enum
from typing import Optional
from urllib.parse import urlparse

from utils.logger import get_logger

logger = get_logger(__name__)


class SSRFMode(Enum):
    """Safety modes for SSRF testing."""

    # BUG BOUNTY - Maximum safety (DEFAULT)
    # Blocks ALL dangerous targets and protocols
    BUG_BOUNTY = "bug_bounty"

    # AUTHORIZED PENTEST - With explicit written permission
    # Allows internal network testing
    PENTEST = "pentest"

    # FULL - No restrictions (DANGEROUS - requires confirmation)
    FULL = "full"


@dataclass
class SSRFSafetyConfig:
    """Configuration for SSRF safety filter."""

    mode: SSRFMode = SSRFMode.BUG_BOUNTY

    # Block cloud metadata (169.254.169.254, etc.)
    block_cloud_metadata: bool = True

    # Block private IP ranges
    block_private_ips: bool = True

    # Block localhost
    block_localhost: bool = True

    # Block dangerous protocols
    block_dangerous_protocols: bool = True

    # Resolve hostnames to check IP
    resolve_hostnames: bool = True

    # Allowed protocols (only these are permitted)
    allowed_protocols: tuple = ("http", "https")

    # Log blocked attempts
    log_blocked: bool = True


# Cloud metadata IPs that MUST be blocked
CLOUD_METADATA_IPS = [
    "169.254.169.254",     # AWS, GCP, Azure, most cloud providers
    "100.100.100.200",     # Alibaba Cloud
    "192.0.0.192",         # Oracle Cloud
    "fd00:ec2::254",       # AWS IPv6 metadata
]

# Cloud metadata hostnames
CLOUD_METADATA_HOSTNAMES = [
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "kubernetes.default.svc",
    "kubernetes.default",
]

# Private IP ranges (RFC1918 + others)
PRIVATE_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local (includes metadata)
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
    ipaddress.ip_network("fc00::/7"),         # IPv6 unique local
]

# Dangerous protocols that should never be used in bug bounty
DANGEROUS_PROTOCOLS = [
    "file",     # Local file access
    "gopher",   # Protocol smuggling
    "dict",     # Dictionary server
    "ldap",     # LDAP injection
    "ldaps",    # LDAP over SSL
    "tftp",     # Trivial FTP
    "sftp",     # SSH FTP
    "ftp",      # FTP access
    "netdoc",   # Network document
    "jar",      # Java archive
    "php",      # PHP streams
    "phar",     # PHP archive
    "expect",   # Expect protocol
    "data",     # Data URI (can be used for encoding)
    "javascript",  # XSS vector
]

# Dangerous path patterns
DANGEROUS_PATHS = [
    r"/latest/meta-data",      # AWS metadata
    r"/metadata/v1",           # GCP metadata
    r"/metadata/instance",     # Azure metadata
    r"/opc/v1",                # Oracle metadata
    r"\.aws/credentials",      # AWS credentials file
    r"\.ssh/",                 # SSH keys
    r"/etc/passwd",            # System files
    r"/etc/shadow",
    r"/proc/",                 # Process info
    r"/sys/",                  # System info
]

# DNS rebinding service patterns
DNS_REBINDING_PATTERNS = [
    r"\.nip\.io$",
    r"\.xip\.io$",
    r"\.sslip\.io$",
    r"\.localtest\.me$",
    r"\.vcap\.me$",
    r"rebind\.",
    r"\.1u\.ms$",
    r"burpcollaborator\.net",
    r"oastify\.com",
    r"interact\.sh",
]


class SSRFSafetyFilter:
    """
    SSRF Safety Filter for Bug Bounty Programs.

    This filter MUST be used before testing any URL for SSRF to prevent:
    1. Legal issues from accessing unauthorized systems
    2. Getting banned from bug bounty programs
    3. Accidentally causing harm

    Example:
        filter = SSRFSafetyFilter()

        # Check URL before testing
        is_safe, reason = filter.is_url_safe("http://169.254.169.254/")
        # is_safe = False
        # reason = "BLOCKED: Cloud metadata IP"
    """

    def __init__(self, config: Optional[SSRFSafetyConfig] = None):
        self.config = config or SSRFSafetyConfig()
        self._blocked_count = 0
        self._allowed_count = 0

        logger.info(
            f"SSRFSafetyFilter initialized",
            mode=self.config.mode.value,
            block_metadata=self.config.block_cloud_metadata,
            block_private=self.config.block_private_ips,
        )

    def is_url_safe(self, url: str) -> tuple[bool, str]:
        """
        Check if a URL is safe to test for SSRF.

        Args:
            url: The URL to check

        Returns:
            Tuple of (is_safe: bool, reason: str)
        """
        try:
            parsed = urlparse(url)

            # Check protocol first
            protocol_safe, protocol_reason = self._check_protocol(parsed.scheme)
            if not protocol_safe:
                self._log_blocked(url, protocol_reason)
                return False, protocol_reason

            # Get hostname
            hostname = parsed.netloc.lower()
            if ":" in hostname:
                hostname = hostname.split(":")[0]

            # Check for DNS rebinding patterns
            rebind_safe, rebind_reason = self._check_dns_rebinding(hostname)
            if not rebind_safe:
                self._log_blocked(url, rebind_reason)
                return False, rebind_reason

            # Check cloud metadata hostnames
            if self.config.block_cloud_metadata:
                meta_safe, meta_reason = self._check_cloud_metadata_hostname(hostname)
                if not meta_safe:
                    self._log_blocked(url, meta_reason)
                    return False, meta_reason

            # Check if hostname is an IP address
            ip_addr = self._get_ip_address(hostname)
            if ip_addr:
                # Check cloud metadata IPs
                if self.config.block_cloud_metadata:
                    meta_ip_safe, meta_ip_reason = self._check_cloud_metadata_ip(ip_addr)
                    if not meta_ip_safe:
                        self._log_blocked(url, meta_ip_reason)
                        return False, meta_ip_reason

                # Check private IP ranges
                if self.config.block_private_ips:
                    private_safe, private_reason = self._check_private_ip(ip_addr)
                    if not private_safe:
                        self._log_blocked(url, private_reason)
                        return False, private_reason

                # Check localhost
                if self.config.block_localhost:
                    localhost_safe, localhost_reason = self._check_localhost(ip_addr)
                    if not localhost_safe:
                        self._log_blocked(url, localhost_reason)
                        return False, localhost_reason

            # Check dangerous paths
            path_safe, path_reason = self._check_dangerous_path(parsed.path)
            if not path_safe:
                self._log_blocked(url, path_reason)
                return False, path_reason

            self._allowed_count += 1
            return True, "URL is safe for SSRF testing"

        except Exception as e:
            reason = f"Error checking URL: {e}"
            self._log_blocked(url, reason)
            return False, reason

    def _check_protocol(self, scheme: str) -> tuple[bool, str]:
        """Check if protocol is safe."""
        if not scheme:
            return False, "BLOCKED: No protocol specified"

        scheme = scheme.lower()

        if self.config.block_dangerous_protocols:
            if scheme in DANGEROUS_PROTOCOLS:
                return False, f"BLOCKED: Dangerous protocol '{scheme}'"

        if scheme not in self.config.allowed_protocols:
            return False, f"BLOCKED: Protocol '{scheme}' not in allowed list"

        return True, "Protocol is safe"

    def _check_dns_rebinding(self, hostname: str) -> tuple[bool, str]:
        """Check for DNS rebinding service patterns."""
        for pattern in DNS_REBINDING_PATTERNS:
            if re.search(pattern, hostname, re.IGNORECASE):
                return False, f"BLOCKED: DNS rebinding service detected ({pattern})"

        return True, "No DNS rebinding detected"

    def _check_cloud_metadata_hostname(self, hostname: str) -> tuple[bool, str]:
        """Check for cloud metadata hostnames."""
        for meta_host in CLOUD_METADATA_HOSTNAMES:
            if hostname == meta_host or hostname.endswith("." + meta_host):
                return False, f"BLOCKED: Cloud metadata hostname '{hostname}'"

        return True, "Not a cloud metadata hostname"

    def _check_cloud_metadata_ip(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[bool, str]:
        """Check for cloud metadata IPs."""
        ip_str = str(ip)

        for meta_ip in CLOUD_METADATA_IPS:
            if ip_str == meta_ip:
                return False, f"BLOCKED: Cloud metadata IP '{ip_str}' - ILLEGAL WITHOUT PERMISSION"

        return True, "Not a cloud metadata IP"

    def _check_private_ip(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[bool, str]:
        """Check for private IP ranges."""
        for network in PRIVATE_IP_RANGES:
            try:
                if ip in network:
                    return False, f"BLOCKED: Private IP range '{ip}' in {network}"
            except TypeError:
                # IPv4 address in IPv6 network or vice versa
                continue

        return True, "Not a private IP"

    def _check_localhost(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[bool, str]:
        """Check for localhost."""
        if ip.is_loopback:
            return False, f"BLOCKED: Localhost IP '{ip}'"

        return True, "Not localhost"

    def _check_dangerous_path(self, path: str) -> tuple[bool, str]:
        """Check for dangerous path patterns."""
        for pattern in DANGEROUS_PATHS:
            if re.search(pattern, path, re.IGNORECASE):
                return False, f"BLOCKED: Dangerous path pattern '{pattern}'"

        return True, "Path is safe"

    def _get_ip_address(self, hostname: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        """Get IP address from hostname."""
        # First try to parse as IP directly
        try:
            return ipaddress.ip_address(hostname)
        except ValueError:
            pass

        # If resolve is enabled, try DNS resolution
        if self.config.resolve_hostnames:
            try:
                resolved = socket.gethostbyname(hostname)
                return ipaddress.ip_address(resolved)
            except (socket.gaierror, OSError):
                pass

        return None

    def _log_blocked(self, url: str, reason: str) -> None:
        """Log blocked URL."""
        self._blocked_count += 1

        if self.config.log_blocked:
            logger.warning(
                "SSRF URL BLOCKED",
                url=url[:100],  # Truncate for safety
                reason=reason,
                blocked_total=self._blocked_count,
            )

    def get_stats(self) -> dict:
        """Get filter statistics."""
        return {
            "mode": self.config.mode.value,
            "blocked_count": self._blocked_count,
            "allowed_count": self._allowed_count,
            "block_rate": (
                self._blocked_count / (self._blocked_count + self._allowed_count)
                if (self._blocked_count + self._allowed_count) > 0
                else 0
            ),
        }

    def filter_urls(self, urls: list[str]) -> list[str]:
        """
        Filter a list of URLs, returning only safe ones.

        Args:
            urls: List of URLs to filter

        Returns:
            List of safe URLs
        """
        safe_urls = []

        for url in urls:
            is_safe, _ = self.is_url_safe(url)
            if is_safe:
                safe_urls.append(url)

        return safe_urls

    def filter_payloads(self, payloads: list[str], base_url: str) -> list[str]:
        """
        Filter SSRF payloads, removing dangerous ones.

        Args:
            payloads: List of SSRF payloads
            base_url: Base URL for context

        Returns:
            List of safe payloads
        """
        safe_payloads = []

        for payload in payloads:
            # Check if payload contains dangerous targets
            is_dangerous = False

            # Check for cloud metadata IPs
            for meta_ip in CLOUD_METADATA_IPS:
                if meta_ip in payload:
                    is_dangerous = True
                    logger.debug(f"Payload blocked: contains cloud metadata IP {meta_ip}")
                    break

            # Check for dangerous protocols
            if not is_dangerous:
                for proto in DANGEROUS_PROTOCOLS:
                    if payload.lower().startswith(f"{proto}://") or f":{proto}://" in payload.lower():
                        is_dangerous = True
                        logger.debug(f"Payload blocked: contains dangerous protocol {proto}")
                        break

            # Check for private IP patterns
            if not is_dangerous:
                private_patterns = [
                    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
                    r"172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}",
                    r"192\.168\.\d{1,3}\.\d{1,3}",
                    r"127\.\d{1,3}\.\d{1,3}\.\d{1,3}",
                    r"169\.254\.\d{1,3}\.\d{1,3}",
                ]
                for pattern in private_patterns:
                    if re.search(pattern, payload):
                        is_dangerous = True
                        logger.debug(f"Payload blocked: contains private IP pattern")
                        break

            if not is_dangerous:
                safe_payloads.append(payload)

        logger.info(
            f"Filtered payloads: {len(safe_payloads)}/{len(payloads)} safe",
            original=len(payloads),
            safe=len(safe_payloads),
            blocked=len(payloads) - len(safe_payloads),
        )

        return safe_payloads


def create_bug_bounty_filter() -> SSRFSafetyFilter:
    """Create a filter configured for bug bounty safety."""
    return SSRFSafetyFilter(
        config=SSRFSafetyConfig(
            mode=SSRFMode.BUG_BOUNTY,
            block_cloud_metadata=True,
            block_private_ips=True,
            block_localhost=True,
            block_dangerous_protocols=True,
            resolve_hostnames=True,
            log_blocked=True,
        )
    )


# Example usage and testing
if __name__ == "__main__":
    # Create bug bounty safe filter
    filter = create_bug_bounty_filter()

    # Test various URLs
    test_urls = [
        "https://example.com/api/v1",           # SAFE
        "http://169.254.169.254/latest/",       # BLOCKED - cloud metadata
        "http://10.0.0.1/internal",             # BLOCKED - private IP
        "http://127.0.0.1/admin",               # BLOCKED - localhost
        "file:///etc/passwd",                   # BLOCKED - dangerous protocol
        "gopher://127.0.0.1:6379/",             # BLOCKED - gopher
        "http://127.0.0.1.nip.io/",             # BLOCKED - DNS rebinding
        "http://metadata.google.internal/",     # BLOCKED - cloud hostname
        "https://api.example.com/v2/users",     # SAFE
    ]

    print("\n" + "=" * 60)
    print("SSRF Safety Filter Test Results")
    print("=" * 60)

    for url in test_urls:
        is_safe, reason = filter.is_url_safe(url)
        status = "SAFE" if is_safe else "BLOCKED"
        print(f"\n[{status}] {url}")
        print(f"  Reason: {reason}")

    print("\n" + "=" * 60)
    print(f"Statistics: {filter.get_stats()}")
    print("=" * 60)
