"""
Business Logic Scanner - Category Base Types.

Defines the BusinessCategory Protocol and CategoryContext for
the Strategy Pattern implementation.

Extracted from business_logic_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Protocol, runtime_checkable

if TYPE_CHECKING:
    import httpx
    from scanning.modules.business_logic.business_base import TransactionContext
    from scanning.modules.business_logic.utils.anomaly_detector import AnomalyDetector


@dataclass
class CategoryResult:
    """Result from a category execution."""
    found: bool
    findings: list[dict[str, Any]] = field(default_factory=list)
    attempts: int = 0
    errors: list[str] = field(default_factory=list)

    @classmethod
    def not_found(cls, attempts: int = 0, errors: list[str] | None = None) -> "CategoryResult":
        """Create a not-found result."""
        return cls(found=False, findings=[], attempts=attempts, errors=errors or [])

    @classmethod
    def vulnerable(cls, findings: list[dict[str, Any]], attempts: int = 0) -> "CategoryResult":
        """Create a vulnerable result."""
        return cls(found=True, findings=findings, attempts=attempts)


@dataclass
class CategoryContext:
    """Context for category execution.

    Bundles all the dependencies needed by categories to avoid
    tight coupling to the scanner class.
    """
    # Request context
    base_url: str
    host: str
    endpoints: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)

    # HTTP dependencies
    auth_headers: dict[str, str] = field(default_factory=dict)
    timeout: float = 30.0

    # Asset data
    asset_data: dict[str, Any] = field(default_factory=dict)
    domain_classification: Any = None

    # Transaction context
    transaction_ctx: "TransactionContext | None" = None

    # Anomaly detector
    anomaly_detector: "AnomalyDetector | None" = None

    # Callbacks (injected from scanner)
    rate_limiter_acquire: Callable[..., Any] | None = None

    # Safety settings
    allow_writes: bool = True
    allow_destructive: bool = False

    async def acquire_rate_limit(self) -> None:
        """Acquire rate limit if callback is set."""
        if self.rate_limiter_acquire:
            await self.rate_limiter_acquire(self.host)

    def get_endpoints_matching(self, patterns: list[str]) -> list[str]:
        """Get endpoints matching any of the patterns."""
        matching = []
        for endpoint in self.endpoints:
            endpoint_lower = endpoint.lower()
            if any(p.lower() in endpoint_lower for p in patterns):
                matching.append(endpoint)
        return matching


@runtime_checkable
class BusinessCategory(Protocol):
    """Protocol for business logic vulnerability categories.

    Each category implements a specific type of testing:
    - Financial edge cases: Price manipulation, overflow
    - Race conditions: Concurrent request testing
    - Workflow bypass: State machine attacks
    - IDOR testing: Authorization bypass
    - Idempotency abuse: Replay attacks
    - Inventory manipulation: Stock abuse
    """

    @property
    def name(self) -> str:
        """Category name for logging."""
        ...

    @property
    def priority_tier(self) -> int:
        """Priority tier (1=CRITICAL, 2=HIGH, 3=MEDIUM, 4=LOW)."""
        ...

    async def test(self, ctx: CategoryContext) -> CategoryResult:
        """Execute the business logic category tests.

        Args:
            ctx: Category execution context with all dependencies

        Returns:
            CategoryResult indicating if vulnerabilities were found
        """
        ...


class BaseBusinessCategory(ABC):
    """Abstract base class for business logic categories.

    Provides common utilities used by all categories.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Category name for logging."""
        pass

    @property
    @abstractmethod
    def priority_tier(self) -> int:
        """Priority tier (1=CRITICAL, 2=HIGH, 3=MEDIUM, 4=LOW)."""
        pass

    @abstractmethod
    async def test(self, ctx: CategoryContext) -> CategoryResult:
        """Execute the business logic category tests."""
        pass

    def _create_finding(
        self,
        name: str,
        severity: str,
        description: str,
        host: str,
        endpoint: str,
        evidence: list[str],
        cvss_score: float = 7.0,
        cwe_id: str = "CWE-840",
        confidence: float = 85.0,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a standardized finding dictionary."""
        return {
            "type": "business_logic",
            "name": name,
            "severity": severity,
            "description": description,
            "host": host,
            "endpoint": endpoint,
            "evidence": evidence,
            "cvss_score": cvss_score,
            "cwe_id": cwe_id,
            "confidence_score": confidence,
            "metadata": metadata or {},
        }

    def _extract_numeric_fields(self, data: dict[str, Any]) -> dict[str, float]:
        """Extract numeric fields from response data."""
        numeric = {}
        for key, value in data.items():
            if isinstance(value, (int, float)):
                numeric[key] = float(value)
            elif isinstance(value, str):
                try:
                    numeric[key] = float(value)
                except ValueError:
                    pass
        return numeric


__all__ = [
    "BusinessCategory",
    "BaseBusinessCategory",
    "CategoryContext",
    "CategoryResult",
]
