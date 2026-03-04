"""
SQL Injection Scanner - Strategy Base Types.

Defines the InjectionStrategy Protocol and StrategyContext for
the Strategy Pattern implementation.

Extracted from sqli_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Protocol, runtime_checkable

if TYPE_CHECKING:
    import httpx
    from utils.rate_limiter import RateLimiter
    from scanning.modules.sqli.sqli_base import (
        DatabaseType, DetectionMethod, InjectionContext, ResponseCluster,
        SQLiEvidence, WAFType,
    )
    from scanning.modules.sqli.utils.response_analysis import AnomalyDetector


@dataclass
class StrategyResult:
    """Result from a strategy execution."""
    found: bool
    evidence: "SQLiEvidence | None" = None
    attempts: int = 0
    errors: list[str] = field(default_factory=list)

    @classmethod
    def not_found(cls, attempts: int = 0, errors: list[str] | None = None) -> "StrategyResult":
        """Create a not-found result."""
        return cls(found=False, evidence=None, attempts=attempts, errors=errors or [])

    @classmethod
    def vulnerable(cls, evidence: "SQLiEvidence", attempts: int = 0) -> "StrategyResult":
        """Create a vulnerable result."""
        return cls(found=True, evidence=evidence, attempts=attempts)


@dataclass
class StrategyContext:
    """Context for strategy execution.

    Bundles all the dependencies needed by strategies to avoid
    tight coupling to the scanner class.
    """
    # Request context
    base_url: str
    param_name: str
    params: dict[str, list[str]]
    injection_ctx: "InjectionContext"

    # Baseline data
    cluster: "ResponseCluster | None" = None
    detector: "AnomalyDetector | None" = None

    # HTTP dependencies
    auth_headers: dict[str, str] = field(default_factory=dict)
    timeout: float = 30.0
    host: str = ""

    # Configuration
    time_delay: int = 5
    max_mutations: int = 5
    max_payloads: int = 15

    # Detected context
    detected_waf: "WAFType | None" = None
    detected_db: "DatabaseType | None" = None

    # Callbacks (injected from scanner)
    rate_limiter_acquire: Callable[..., Any] | None = None
    is_false_positive: Callable[[str, int], bool] | None = None
    quick_negative_control: Callable[..., Any] | None = None
    get_intelligent_payloads: Callable[..., Any] | None = None
    get_payload_mutations: Callable[..., list[str]] | None = None

    # Asset data (from scanner)
    asset_data: dict[str, Any] = field(default_factory=dict)

    async def acquire_rate_limit(self) -> None:
        """Acquire rate limit if callback is set."""
        if self.rate_limiter_acquire:
            await self.rate_limiter_acquire(self.host)

    def check_false_positive(self, content: str, status_code: int) -> bool:
        """Check if response is a false positive."""
        if self.is_false_positive:
            return self.is_false_positive(content, status_code)
        return False


@runtime_checkable
class InjectionStrategy(Protocol):
    """Protocol for SQL injection detection strategies.

    Each strategy implements a specific detection method:
    - Error-based: Triggers SQL errors in response
    - Boolean-blind: True/false response differences
    - Time-blind: Response time delays
    - Union-based: Column enumeration via UNION
    - Stacked queries: Multiple SQL statements
    - Out-of-band: DNS/HTTP callbacks
    """

    @property
    def name(self) -> str:
        """Strategy name for logging."""
        ...

    @property
    def detection_method(self) -> "DetectionMethod":
        """Detection method enum value."""
        ...

    async def test(self, ctx: StrategyContext) -> StrategyResult:
        """
        Execute the injection strategy.

        Args:
            ctx: Strategy execution context with all dependencies

        Returns:
            StrategyResult indicating if vulnerability was found
        """
        ...


class BaseStrategy(ABC):
    """Abstract base class for injection strategies.

    Provides common utilities used by all strategies.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Strategy name for logging."""
        pass

    @property
    @abstractmethod
    def detection_method(self) -> "DetectionMethod":
        """Detection method enum value."""
        pass

    @abstractmethod
    async def test(self, ctx: StrategyContext) -> StrategyResult:
        """Execute the injection strategy."""
        pass

    def _build_test_url(
        self,
        ctx: StrategyContext,
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

    def _get_mutations(self, ctx: StrategyContext, payload: str) -> list[str]:
        """Get payload mutations from context callback."""
        if ctx.get_payload_mutations:
            return ctx.get_payload_mutations(payload, ctx.detected_waf)
        return [payload]  # No mutations available


__all__ = [
    "InjectionStrategy",
    "BaseStrategy",
    "StrategyContext",
    "StrategyResult",
]
