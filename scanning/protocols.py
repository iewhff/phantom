"""
Scanning Protocols - Protocol interfaces for dependency injection.

This module defines Protocol classes (PEP 544) for all shared dependencies
in the scanning system. Using Protocols enables:
1. Static type checking with mypy/pyright
2. Runtime duck typing (no inheritance required)
3. Easy mocking in unit tests
4. Decoupled, testable scanner modules

Part of Phase 8: Dependency Inversion (2026-02-26)

Usage:
    from scanning.protocols import HttpClientProtocol, RateLimiterProtocol

    class MyScanner(ScanModule):
        def __init__(
            self,
            http_client: HttpClientProtocol,
            rate_limiter: RateLimiterProtocol,
        ):
            self.http = http_client
            self.limiter = rate_limiter
"""

from __future__ import annotations

from typing import (
    TYPE_CHECKING,
    Any,
    AsyncContextManager,
    Callable,
    Dict,
    List,
    Optional,
    Protocol,
    Set,
    runtime_checkable,
)

if TYPE_CHECKING:
    from datetime import datetime


# =============================================================================
# HTTP CLIENT PROTOCOL
# =============================================================================


@runtime_checkable
class HttpResponseProtocol(Protocol):
    """Protocol for HTTP response objects."""

    @property
    def status_code(self) -> int:
        """HTTP status code."""
        ...

    @property
    def text(self) -> str:
        """Response body as text."""
        ...

    @property
    def content(self) -> bytes:
        """Response body as bytes."""
        ...

    @property
    def headers(self) -> Dict[str, str]:
        """Response headers."""
        ...

    @property
    def url(self) -> str:
        """Final URL after redirects."""
        ...

    @property
    def elapsed(self) -> float:
        """Request duration in seconds."""
        ...

    def json(self) -> Any:
        """Parse response body as JSON."""
        ...


@runtime_checkable
class HttpClientProtocol(Protocol):
    """Protocol for async HTTP clients.

    This protocol abstracts httpx.AsyncClient, allowing:
    - Easy mocking in tests
    - Swapping implementations (httpx, aiohttp, etc.)
    - Consistent interface across scanners
    """

    async def get(
        self,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        follow_redirects: bool = True,
        **kwargs: Any,
    ) -> HttpResponseProtocol:
        """Send a GET request."""
        ...

    async def post(
        self,
        url: str,
        *,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        follow_redirects: bool = True,
        **kwargs: Any,
    ) -> HttpResponseProtocol:
        """Send a POST request."""
        ...

    async def put(
        self,
        url: str,
        *,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        **kwargs: Any,
    ) -> HttpResponseProtocol:
        """Send a PUT request."""
        ...

    async def delete(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        **kwargs: Any,
    ) -> HttpResponseProtocol:
        """Send a DELETE request."""
        ...

    async def patch(
        self,
        url: str,
        *,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        **kwargs: Any,
    ) -> HttpResponseProtocol:
        """Send a PATCH request."""
        ...

    async def head(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        **kwargs: Any,
    ) -> HttpResponseProtocol:
        """Send a HEAD request."""
        ...

    async def options(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        **kwargs: Any,
    ) -> HttpResponseProtocol:
        """Send an OPTIONS request."""
        ...

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        follow_redirects: bool = True,
        **kwargs: Any,
    ) -> HttpResponseProtocol:
        """Send a request with arbitrary method."""
        ...


# =============================================================================
# RATE LIMITER PROTOCOL
# =============================================================================


@runtime_checkable
class RateLimiterProtocol(Protocol):
    """Protocol for rate limiting.

    Controls request rate to avoid overwhelming targets
    and triggering rate limits/WAF blocks.
    """

    async def acquire(self, domain: str = "default") -> None:
        """Acquire permission to make a request (blocks if rate exceeded)."""
        ...

    async def try_acquire(self, domain: str = "default") -> bool:
        """Try to acquire without blocking. Returns True if acquired."""
        ...

    async def set_rate(self, domain: str, rate: float) -> None:
        """Set requests-per-second rate for a domain."""
        ...

    async def signal_rate_limited(self, domain: str = "default") -> float:
        """Signal that a 429 was received. Returns recommended wait time."""
        ...

    @property
    def request_count(self) -> int:
        """Total requests made through this limiter."""
        ...


# =============================================================================
# PAYLOAD LIBRARY PROTOCOL
# =============================================================================


@runtime_checkable
class PayloadProtocol(Protocol):
    """Protocol for individual payload objects."""

    @property
    def raw(self) -> str:
        """Raw payload string."""
        ...

    @property
    def category(self) -> Any:
        """Payload category (SQLi, XSS, etc.)."""
        ...

    @property
    def description(self) -> str:
        """Human-readable description."""
        ...

    @property
    def success_indicators(self) -> List[str]:
        """Strings indicating successful injection."""
        ...

    def get_variants(self, max_variants: int = 5) -> List[str]:
        """Generate WAF bypass variants of the payload."""
        ...


@runtime_checkable
class PayloadLibraryProtocol(Protocol):
    """Protocol for centralized payload library.

    Provides categorized payloads for different vulnerability types
    with WAF bypass variants.
    """

    def get_payloads(
        self,
        category: Any,
        *,
        db_type: Optional[str] = None,
        context: Optional[str] = None,
        max_payloads: int = 100,
    ) -> List[PayloadProtocol]:
        """Get payloads for a category."""
        ...

    def get_raw_payloads(
        self,
        category: Any,
        *,
        db_type: Optional[str] = None,
        context: Optional[str] = None,
        max_payloads: int = 100,
    ) -> List[str]:
        """Get raw payload strings for a category."""
        ...

    def get_success_indicators(self, category: Any) -> List[str]:
        """Get success indicators for a category."""
        ...

    def encode_payload(self, payload: str, encoding: str) -> str:
        """Encode a payload using specified technique."""
        ...


# =============================================================================
# OOB ENGINE PROTOCOL
# =============================================================================


@runtime_checkable
class OOBTokenProtocol(Protocol):
    """Protocol for OOB callback tokens."""

    @property
    def token(self) -> str:
        """Unique token string."""
        ...

    @property
    def correlation_id(self) -> str:
        """Correlation ID for tracking."""
        ...

    @property
    def has_callback(self) -> bool:
        """Whether a callback was received."""
        ...

    @property
    def is_expired(self) -> bool:
        """Whether the token has expired."""
        ...

    @property
    def callbacks_received(self) -> List[Dict[str, Any]]:
        """List of received callbacks."""
        ...


@runtime_checkable
class OOBEngineProtocol(Protocol):
    """Protocol for Out-of-Band detection engine.

    Used for blind vulnerabilities (SSRF, XXE, RCE) where
    callback confirmation is needed.
    """

    def generate_token(
        self,
        scan_id: str,
        payload_type: str,
        target_url: str,
        parameter: str,
    ) -> OOBTokenProtocol:
        """Generate a unique callback token."""
        ...

    def get_callback_url(self, token: str, protocol: str = "http") -> str:
        """Get the callback URL for a token."""
        ...

    def get_dns_callback_domain(self, token: str) -> str:
        """Get the DNS callback domain for a token."""
        ...

    async def check_callback(self, token: str, timeout: float = 5.0) -> bool:
        """Check if a callback was received for a token."""
        ...

    def get_token_info(self, token: str) -> Optional[OOBTokenProtocol]:
        """Get token information."""
        ...

    def generate_payload(
        self,
        template_name: str,
        token: str,
    ) -> str:
        """Generate a payload with embedded callback token."""
        ...


# =============================================================================
# WAF BYPASS ENGINE PROTOCOL
# =============================================================================


@runtime_checkable
class WAFDetectionProtocol(Protocol):
    """Protocol for WAF detection results."""

    @property
    def detected(self) -> bool:
        """Whether a WAF was detected."""
        ...

    @property
    def waf_name(self) -> Optional[str]:
        """Detected WAF name (if known)."""
        ...

    @property
    def behaviour_family(self) -> Optional[str]:
        """WAF behaviour family classification."""
        ...

    @property
    def confidence(self) -> float:
        """Detection confidence (0.0 - 1.0)."""
        ...


@runtime_checkable
class WAFBypassEngineProtocol(Protocol):
    """Protocol for WAF bypass engine.

    Detects and bypasses Web Application Firewalls using
    behavioural classification and adaptive techniques.
    """

    async def detect_waf(
        self,
        target_url: str,
        timeout: float = 15.0,
    ) -> WAFDetectionProtocol:
        """Detect WAF on target."""
        ...

    def apply_bypass(
        self,
        payload: str,
        detection: WAFDetectionProtocol,
        *,
        max_variants: int = 10,
    ) -> List[str]:
        """Generate bypass variants for a payload."""
        ...

    def mutate_payload(
        self,
        payload: str,
        technique: str,
    ) -> str:
        """Apply a specific mutation technique to a payload."""
        ...

    def get_bypass_techniques(
        self,
        detection: WAFDetectionProtocol,
    ) -> List[str]:
        """Get recommended bypass techniques for detected WAF."""
        ...


# =============================================================================
# LOGGER PROTOCOL
# =============================================================================


@runtime_checkable
class LoggerProtocol(Protocol):
    """Protocol for logging.

    Abstracts logging to enable testing and custom log handlers.
    """

    def debug(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log debug message."""
        ...

    def info(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log info message."""
        ...

    def warning(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log warning message."""
        ...

    def error(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log error message."""
        ...

    def critical(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log critical message."""
        ...

    def exception(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log exception with traceback."""
        ...


# =============================================================================
# FINDINGS STORE PROTOCOL
# =============================================================================


@runtime_checkable
class FindingProtocol(Protocol):
    """Protocol for vulnerability findings."""

    @property
    def id(self) -> str:
        """Unique finding ID."""
        ...

    @property
    def name(self) -> str:
        """Vulnerability name."""
        ...

    @property
    def severity(self) -> str:
        """Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)."""
        ...

    @property
    def url(self) -> str:
        """Affected URL."""
        ...

    @property
    def evidence(self) -> List[str]:
        """Evidence strings."""
        ...

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        ...


@runtime_checkable
class FindingsStoreProtocol(Protocol):
    """Protocol for shared findings storage.

    Enables cross-module finding sharing and deduplication.
    """

    def add_finding(self, finding: FindingProtocol) -> str:
        """Add a finding. Returns finding ID."""
        ...

    def get_finding(self, finding_id: str) -> Optional[FindingProtocol]:
        """Get a finding by ID."""
        ...

    def get_all_findings(self) -> List[FindingProtocol]:
        """Get all findings."""
        ...

    def get_findings_by_severity(self, severity: str) -> List[FindingProtocol]:
        """Get findings by severity level."""
        ...

    def get_findings_by_type(self, vuln_type: str) -> List[FindingProtocol]:
        """Get findings by vulnerability type."""
        ...

    def deduplicate(self) -> int:
        """Deduplicate findings. Returns number removed."""
        ...

    def share_extracted_data(
        self,
        data_type: str,
        value: Any,
        source_module: str,
    ) -> None:
        """Share extracted data (tokens, credentials, etc.) for other modules."""
        ...

    def get_shared_data(self, data_type: str) -> List[Any]:
        """Get shared data of a specific type."""
        ...


# =============================================================================
# SCAN CONTEXT PROTOCOL
# =============================================================================


@runtime_checkable
class ScanContextProtocol(Protocol):
    """Protocol for scan context.

    Provides shared state and configuration for scanner modules.
    """

    @property
    def target_url(self) -> str:
        """Target base URL."""
        ...

    @property
    def host(self) -> str:
        """Target host."""
        ...

    @property
    def endpoints(self) -> List[str]:
        """Discovered endpoints."""
        ...

    @property
    def auth_headers(self) -> Dict[str, str]:
        """Authentication headers."""
        ...

    @property
    def cookies(self) -> Dict[str, str]:
        """Session cookies."""
        ...

    @property
    def timeout(self) -> float:
        """Request timeout in seconds."""
        ...

    @property
    def safety_mode(self) -> str:
        """Current safety mode (safe, moderate, aggressive)."""
        ...

    @property
    def tech_stack(self) -> Dict[str, Any]:
        """Detected technology stack."""
        ...


# =============================================================================
# SCANNER MODULE PROTOCOL
# =============================================================================


@runtime_checkable
class ScannerModuleProtocol(Protocol):
    """Protocol for scanner modules.

    Defines the interface that all scanner modules must implement.
    """

    @property
    def name(self) -> str:
        """Module name."""
        ...

    @property
    def description(self) -> str:
        """Module description."""
        ...

    @property
    def category(self) -> str:
        """Module category (injection, auth, api, etc.)."""
        ...

    async def scan(
        self,
        context: ScanContextProtocol,
    ) -> List[FindingProtocol]:
        """Execute scan and return findings."""
        ...

    def get_coverage_report(self) -> Dict[str, Any]:
        """Get coverage report (what was tested, what was skipped)."""
        ...


# =============================================================================
# TYPE ALIASES FOR CONVENIENCE
# =============================================================================

# Factory types for DI container
HttpClientFactory = Callable[[], AsyncContextManager[HttpClientProtocol]]
RateLimiterFactory = Callable[[], RateLimiterProtocol]
PayloadLibraryFactory = Callable[[], PayloadLibraryProtocol]
OOBEngineFactory = Callable[[], OOBEngineProtocol]
WAFBypassEngineFactory = Callable[[], WAFBypassEngineProtocol]
LoggerFactory = Callable[[str], LoggerProtocol]
FindingsStoreFactory = Callable[[], FindingsStoreProtocol]


__all__ = [
    # HTTP
    "HttpResponseProtocol",
    "HttpClientProtocol",
    # Rate Limiting
    "RateLimiterProtocol",
    # Payloads
    "PayloadProtocol",
    "PayloadLibraryProtocol",
    # OOB
    "OOBTokenProtocol",
    "OOBEngineProtocol",
    # WAF
    "WAFDetectionProtocol",
    "WAFBypassEngineProtocol",
    # Logging
    "LoggerProtocol",
    # Findings
    "FindingProtocol",
    "FindingsStoreProtocol",
    # Context
    "ScanContextProtocol",
    # Scanner
    "ScannerModuleProtocol",
    # Factory types
    "HttpClientFactory",
    "RateLimiterFactory",
    "PayloadLibraryFactory",
    "OOBEngineFactory",
    "WAFBypassEngineFactory",
    "LoggerFactory",
    "FindingsStoreFactory",
]
