"""
Input validators for targets, URLs, IPs, etc.

SECURITY: Provides comprehensive input validation to prevent:
- CWE-20: Improper Input Validation
- CWE-79: Cross-site Scripting (via output encoding)
- CWE-74: Injection attacks
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import urlparse

from utils.logger import get_logger

logger = get_logger(__name__)


# Security limits
MAX_TARGET_LENGTH = 2048  # Maximum target string length
MAX_DOMAIN_LENGTH = 253   # DNS limit
MAX_URL_LENGTH = 2048     # Reasonable URL limit

# Domain regex pattern
DOMAIN_PATTERN = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
    r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
)

# URL regex pattern
URL_PATTERN = re.compile(
    r'^https?://'
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
    r'localhost|'
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    r'(?::\d+)?'
    r'(?:/?|[/?]\S+)$',
    re.IGNORECASE,
)

# Dangerous characters that should never appear in targets
CONTROL_CHARS = re.compile(r'[\x00-\x1f\x7f-\x9f]')


class ValidationError(Exception):
    """Raised when validation fails."""
    pass


def _sanitize_input(value: str, max_length: int = MAX_TARGET_LENGTH) -> str:
    """
    Sanitize input string for security.

    SECURITY: Prevents injection attacks via:
    - Length limiting (CWE-20)
    - Control character removal (CWE-74)
    - Unicode normalization (homograph attacks)

    Args:
        value: Input string to sanitize
        max_length: Maximum allowed length

    Returns:
        Sanitized string

    Raises:
        ValidationError: If input contains dangerous patterns
    """
    if not isinstance(value, str):
        raise ValidationError("Input must be a string")

    # Length check
    if len(value) > max_length:
        raise ValidationError(f"Input too long (max {max_length} characters)")

    # Remove leading/trailing whitespace
    value = value.strip()

    # Check for control characters (potential injection)
    if CONTROL_CHARS.search(value):
        raise ValidationError("Input contains invalid control characters")

    # Normalize Unicode to prevent homograph attacks
    # NFKC normalizes visually similar characters to their base form
    value = unicodedata.normalize('NFKC', value)

    return value


def validate_target(target: str) -> str:
    """
    Validate and normalize a target.

    SECURITY: Comprehensive input validation (CWE-20).

    Accepts:
    - Domain names (example.com)
    - URLs (https://example.com)
    - IP addresses (192.168.1.1)
    - CIDR ranges (192.168.1.0/24)

    Args:
        target: Target string to validate

    Returns:
        Normalized target string

    Raises:
        ValidationError: If target is invalid
    """
    # Sanitize input first
    target = _sanitize_input(target, MAX_TARGET_LENGTH)

    if not target:
        raise ValidationError("Target cannot be empty")
    
    # Check if URL
    if target.startswith(("http://", "https://")):
        return validate_url(target)
    
    # Check if CIDR
    if "/" in target:
        return validate_cidr(target)
    
    # Check if IP
    if _looks_like_ip(target):
        return validate_ip(target)
    
    # Assume domain
    return validate_domain(target)


def validate_url(url: str) -> str:
    """
    Validate a URL.
    
    Args:
        url: URL to validate
        
    Returns:
        Normalized URL
        
    Raises:
        ValidationError: If URL is invalid
    """
    url = url.strip()
    
    try:
        parsed = urlparse(url)
        
        if parsed.scheme not in ("http", "https"):
            raise ValidationError(f"Invalid URL scheme: {parsed.scheme}")
        
        if not parsed.netloc:
            raise ValidationError("URL missing host")
        
        # Validate host
        host = parsed.netloc.split(":")[0]
        if _looks_like_ip(host):
            validate_ip(host)
        else:
            validate_domain(host)
        
        # Normalize: remove trailing slash if no path
        normalized = url.rstrip("/") if parsed.path in ("", "/") else url
        return normalized
        
    except ValidationError:
        raise
    except Exception as e:
        raise ValidationError(f"Invalid URL: {e}")


def validate_domain(domain: str) -> str:
    """
    Validate a domain name.
    
    Args:
        domain: Domain to validate
        
    Returns:
        Normalized domain (lowercase)
        
    Raises:
        ValidationError: If domain is invalid
    """
    domain = domain.strip().lower()
    
    if not domain:
        raise ValidationError("Domain cannot be empty")
    
    if len(domain) > 253:
        raise ValidationError("Domain name too long (max 253 characters)")
    
    # Remove trailing dot if present
    domain = domain.rstrip(".")
    
    # Check each label
    labels = domain.split(".")
    if len(labels) < 2:
        raise ValidationError("Domain must have at least two labels")
    
    for label in labels:
        if not label:
            raise ValidationError("Empty label in domain")
        if len(label) > 63:
            raise ValidationError(f"Label too long: {label}")
        if label.startswith("-") or label.endswith("-"):
            raise ValidationError(f"Label cannot start/end with hyphen: {label}")
        if not re.match(r'^[a-z0-9-]+$', label):
            raise ValidationError(f"Invalid characters in label: {label}")
    
    return domain


def validate_ip(ip: str) -> str:
    """
    Validate an IP address.
    
    Args:
        ip: IP address to validate
        
    Returns:
        Normalized IP string
        
    Raises:
        ValidationError: If IP is invalid
    """
    ip = ip.strip()
    
    try:
        addr = ipaddress.ip_address(ip)
        return str(addr)
    except ValueError as e:
        raise ValidationError(f"Invalid IP address: {e}")


def validate_cidr(cidr: str) -> str:
    """
    Validate a CIDR range.
    
    Args:
        cidr: CIDR notation (e.g., 192.168.1.0/24)
        
    Returns:
        Normalized CIDR string
        
    Raises:
        ValidationError: If CIDR is invalid
    """
    cidr = cidr.strip()
    
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return str(network)
    except ValueError as e:
        raise ValidationError(f"Invalid CIDR range: {e}")


def validate_port(port: int | str) -> int:
    """
    Validate a port number.
    
    Args:
        port: Port number
        
    Returns:
        Port as integer
        
    Raises:
        ValidationError: If port is invalid
    """
    try:
        port_int = int(port)
    except (ValueError, TypeError):
        raise ValidationError(f"Invalid port: {port}")
    
    if not 1 <= port_int <= 65535:
        raise ValidationError(f"Port out of range: {port_int}")
    
    return port_int


def validate_port_range(port_range: str) -> tuple[int, int]:
    """
    Validate a port range.
    
    Args:
        port_range: Range string (e.g., "1-1000" or "80")
        
    Returns:
        Tuple of (start_port, end_port)
        
    Raises:
        ValidationError: If range is invalid
    """
    port_range = port_range.strip()
    
    if "-" in port_range:
        parts = port_range.split("-")
        if len(parts) != 2:
            raise ValidationError(f"Invalid port range format: {port_range}")
        
        start = validate_port(parts[0])
        end = validate_port(parts[1])
        
        if start > end:
            raise ValidationError(f"Invalid port range: start > end ({start} > {end})")
        
        return (start, end)
    
    port = validate_port(port_range)
    return (port, port)


def validate_email(email: str) -> str:
    """
    Validate an email address.
    
    Args:
        email: Email to validate
        
    Returns:
        Normalized email (lowercase)
        
    Raises:
        ValidationError: If email is invalid
    """
    email = email.strip().lower()
    
    pattern = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    
    if not pattern.match(email):
        raise ValidationError(f"Invalid email address: {email}")
    
    return email


def is_private_ip(ip: str) -> bool:
    """
    Check if IP is private/internal.
    
    Args:
        ip: IP address string
        
    Returns:
        True if private, False otherwise
    """
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private
    except ValueError:
        return False


def is_loopback(ip: str) -> bool:
    """
    Check if IP is loopback.
    
    Args:
        ip: IP address string
        
    Returns:
        True if loopback, False otherwise
    """
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_loopback
    except ValueError:
        return False


def extract_domain_from_url(url: str) -> str:
    """
    Extract domain from URL.
    
    Args:
        url: URL string
        
    Returns:
        Domain part of URL
    """
    parsed = urlparse(url)
    host = parsed.netloc.split(":")[0]
    return host.lower()


def extract_base_domain(domain: str) -> str:
    """
    Extract base domain (remove subdomains).
    
    Simple implementation - for production use tldextract.
    
    Args:
        domain: Full domain
        
    Returns:
        Base domain (e.g., "example.com" from "sub.example.com")
    """
    parts = domain.lower().split(".")
    
    # Handle common multi-part TLDs
    multi_tlds = {"co.uk", "com.br", "co.jp", "com.au"}
    
    if len(parts) >= 3:
        potential_tld = ".".join(parts[-2:])
        if potential_tld in multi_tlds:
            return ".".join(parts[-3:])
    
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    
    return domain


def _looks_like_ip(s: str) -> bool:
    """Check if string looks like an IP address."""
    # IPv4
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', s):
        return True
    # IPv6
    if ":" in s and not "/" in s:
        return True
    return False
