"""
XSS Scanner - Strategy Base Types.

Defines the XSSStrategy Protocol and StrategyContext for
the Strategy Pattern implementation.

Extracted from xss_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Protocol, runtime_checkable

if TYPE_CHECKING:
    import httpx
    from utils.rate_limiter import RateLimiter
    from scanning.modules.xss.xss_base import XSSContext, XSSEvidence, WAFType


@dataclass
class XSSStrategyResult:
    """Result from a strategy execution."""
    found: bool
    evidence: list["XSSEvidence"] = field(default_factory=list)
    attempts: int = 0
    errors: list[str] = field(default_factory=list)

    @classmethod
    def not_found(cls, attempts: int = 0, errors: list[str] | None = None) -> "XSSStrategyResult":
        """Create a not-found result."""
        return cls(found=False, evidence=[], attempts=attempts, errors=errors or [])

    @classmethod
    def vulnerable(cls, evidence: list["XSSEvidence"], attempts: int = 0) -> "XSSStrategyResult":
        """Create a vulnerable result."""
        return cls(found=True, evidence=evidence, attempts=attempts)


@dataclass
class XSSStrategyContext:
    """Context for XSS strategy execution.

    Bundles all the dependencies needed by strategies to avoid
    tight coupling to the scanner class.
    """
    # Request context
    base_url: str
    param_name: str
    params: dict[str, list[str]]
    method: str = "GET"

    # HTTP dependencies
    auth_headers: dict[str, str] = field(default_factory=dict)
    timeout: float = 30.0
    host: str = ""

    # Configuration
    mutation_level: int = 3
    max_payloads: int = 20

    # Detected context
    detected_waf: "WAFType | None" = None
    detected_context: "XSSContext | None" = None
    csp_analysis: dict[str, Any] = field(default_factory=dict)

    # Callbacks (injected from scanner)
    rate_limiter_acquire: Callable[..., Any] | None = None
    get_payload_mutations: Callable[..., list[str]] | None = None

    # Asset data (from scanner)
    asset_data: dict[str, Any] = field(default_factory=dict)

    # Forms data for form testing
    forms: list[dict[str, Any]] = field(default_factory=list)

    async def acquire_rate_limit(self) -> None:
        """Acquire rate limit if callback is set."""
        if self.rate_limiter_acquire:
            await self.rate_limiter_acquire(self.host)


@runtime_checkable
class XSSStrategy(Protocol):
    """Protocol for XSS detection strategies.

    Each strategy implements a specific detection method:
    - URL parameter: Query string testing
    - Form: HTML form field testing
    - Header: HTTP header injection
    - JSON body: JSON payload testing
    - Template injection: SSTI detection
    - Stored XSS: Persistence testing
    - Second-order: Cross-endpoint detection
    """

    @property
    def name(self) -> str:
        """Strategy name for logging."""
        ...

    async def test(self, ctx: XSSStrategyContext) -> XSSStrategyResult:
        """
        Execute the XSS detection strategy.

        Args:
            ctx: Strategy execution context with all dependencies

        Returns:
            XSSStrategyResult indicating if vulnerability was found
        """
        ...


class BaseXSSStrategy(ABC):
    """Abstract base class for XSS strategies.

    Provides common utilities used by all strategies.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Strategy name for logging."""
        pass

    @abstractmethod
    async def test(self, ctx: XSSStrategyContext) -> XSSStrategyResult:
        """Execute the XSS detection strategy."""
        pass

    def _build_test_url(
        self,
        ctx: XSSStrategyContext,
        payload: str,
        append: bool = True,
    ) -> str:
        """Build test URL with injected payload.

        Args:
            ctx: Strategy context
            payload: Payload to inject
            append: If True, append to original value; if False, replace

        Returns:
            URL with injected parameter
        """
        from urllib.parse import urlencode

        test_params = ctx.params.copy()
        original = (test_params.get(ctx.param_name) or [""])[0]

        if append:
            test_params[ctx.param_name] = [original + payload]
        else:
            test_params[ctx.param_name] = [payload]

        return f"{ctx.base_url}?{urlencode(test_params, doseq=True)}"

    def _get_mutations(self, ctx: XSSStrategyContext, payload: str) -> list[str]:
        """Get payload mutations from context callback."""
        if ctx.get_payload_mutations:
            return ctx.get_payload_mutations(payload, ctx.mutation_level)
        return [payload]

    def _check_reflection(self, payload: str, content: str) -> bool:
        """Check if payload is reflected in content."""
        # Direct reflection
        if payload in content:
            return True

        # Case-insensitive
        if payload.lower() in content.lower():
            return True

        # URL-decoded
        from urllib.parse import unquote
        if unquote(payload) in content:
            return True

        return False

    def _extract_snippet(self, payload: str, content: str, context_size: int = 100) -> str:
        """Extract snippet around reflected payload."""
        pos = content.lower().find(payload.lower())
        if pos == -1:
            return ""

        start = max(0, pos - context_size)
        end = min(len(content), pos + len(payload) + context_size)

        return content[start:end]


__all__ = [
    "XSSStrategy",
    "BaseXSSStrategy",
    "XSSStrategyContext",
    "XSSStrategyResult",
]
