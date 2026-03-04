"""
Business Logic Scanner - Orchestrator.

Coordinates the execution of all business logic vulnerability categories.
Provides the main entry point for business logic scanning.

Extracted from business_logic_scanner.py as part of Phase 7 refactoring (2026-02-26).
Updated for DI support as part of Phase 8 (2026-02-26).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Optional
from urllib.parse import urlparse

from utils.logger import get_logger

from scanning.modules.business_logic.business_base import (
    BUSINESS_LOGIC_SCANNER_VERSION,
    ALLOW_WRITES,
    ALLOW_DESTRUCTIVE,
    get_business_priority,
    TransactionContext,
)
from scanning.modules.business_logic.categories import (
    CategoryContext,
    CategoryResult,
    FinancialEdgeCasesCategory,
    RaceConditionsCategory,
    WorkflowBypassCategory,
    IDORTestingCategory,
    IdempotencyAbuseCategory,
    InventoryManipulationCategory,
)
from scanning.modules.business_logic.utils.anomaly_detector import AnomalyDetector
from scanning.modules.business_logic.utils.transaction_context import (
    TransactionManager,
    create_transaction_context,
)

if TYPE_CHECKING:
    from scanning.protocols import (
        RateLimiterProtocol,
        FindingsStoreProtocol,
    )

logger = get_logger(__name__)


@dataclass
class OrchestratorConfig:
    """Configuration for Business Logic orchestrator."""
    # Timeout settings
    timeout: float = 30.0
    category_timeout: float = 60.0

    # Safety settings
    allow_writes: bool = ALLOW_WRITES
    allow_destructive: bool = ALLOW_DESTRUCTIVE

    # Category enable/disable
    enable_financial: bool = True
    enable_race_conditions: bool = True
    enable_workflow_bypass: bool = True
    enable_idor: bool = True
    enable_idempotency: bool = True
    enable_inventory: bool = True

    # Priority filtering
    min_priority_tier: int = 4  # Include all tiers by default


@dataclass
class ScanResult:
    """Result from business logic scan."""
    host: str
    categories_tested: list[str] = field(default_factory=list)
    category_results: dict[str, CategoryResult] = field(default_factory=dict)
    total_findings: int = 0
    total_attempts: int = 0
    errors: list[str] = field(default_factory=list)


class BusinessLogicOrchestrator:
    """Orchestrator for business logic vulnerability categories.

    Coordinates the execution of all business logic categories:
    - FinancialEdgeCasesCategory: Price manipulation, overflow
    - RaceConditionsCategory: Concurrent request testing
    - WorkflowBypassCategory: State machine attacks
    - IDORTestingCategory: Authorization bypass
    - IdempotencyAbuseCategory: Replay attacks
    - InventoryManipulationCategory: Stock manipulation

    Supports dependency injection (Phase 8) while maintaining backward compatibility.

    Usage:
        # Legacy usage (backward compatible)
        orchestrator = BusinessLogicOrchestrator(settings, rate_limiter, auth_headers)

        # DI usage (Phase 8)
        orchestrator = BusinessLogicOrchestrator(
            settings=settings,
            rate_limiter=rate_limiter,  # RateLimiterProtocol
            findings_store=store,  # FindingsStoreProtocol (optional)
        )
        result = await orchestrator.scan(url, endpoints, asset_data)
    """

    def __init__(
        self,
        settings: dict[str, Any] | None = None,
        rate_limiter: Optional["RateLimiterProtocol"] = None,
        auth_headers: dict[str, str] | None = None,
        config: OrchestratorConfig | None = None,
        # Phase 8: Optional injected dependencies
        findings_store: Optional["FindingsStoreProtocol"] = None,
    ) -> None:
        """Initialize the Business Logic orchestrator.

        Args:
            settings: Application settings
            rate_limiter: Rate limiter (RateLimiterProtocol)
            auth_headers: Authentication headers
            config: Orchestrator configuration
            findings_store: Optional shared findings store (FindingsStoreProtocol)
        """
        self.settings = settings or {}
        self.rate_limiter = rate_limiter
        self.auth_headers = auth_headers or {}
        self.config = config or OrchestratorConfig()

        # Phase 8: Store injected dependencies
        self._findings_store = findings_store

        # State
        self._anomaly_detector = AnomalyDetector()
        self._transaction_manager = TransactionManager()

        # Initialize categories
        self._categories = self._init_categories()

        logger.debug(
            f"[BizLogic] Orchestrator v{BUSINESS_LOGIC_SCANNER_VERSION} "
            f"initialized with {len(self._categories)} categories"
        )

    def _init_categories(self) -> list[tuple[str, Any, int]]:
        """Initialize enabled categories with their priority tiers."""
        categories = []

        if self.config.enable_financial:
            cat = FinancialEdgeCasesCategory()
            categories.append((cat.name, cat, cat.priority_tier))

        if self.config.enable_race_conditions:
            cat = RaceConditionsCategory()
            categories.append((cat.name, cat, cat.priority_tier))

        if self.config.enable_workflow_bypass:
            cat = WorkflowBypassCategory()
            categories.append((cat.name, cat, cat.priority_tier))

        if self.config.enable_idor:
            cat = IDORTestingCategory()
            categories.append((cat.name, cat, cat.priority_tier))

        if self.config.enable_idempotency:
            cat = IdempotencyAbuseCategory()
            categories.append((cat.name, cat, cat.priority_tier))

        if self.config.enable_inventory:
            cat = InventoryManipulationCategory()
            categories.append((cat.name, cat, cat.priority_tier))

        # Sort by priority tier (lower = higher priority)
        categories.sort(key=lambda x: x[2])

        return categories

    async def scan(
        self,
        url: str,
        endpoints: list[str] | None = None,
        asset_data: dict[str, Any] | None = None,
        domain_classification: Any = None,
    ) -> ScanResult:
        """Scan for business logic vulnerabilities.

        Args:
            url: Base URL to test
            endpoints: List of discovered endpoints
            asset_data: Asset data from discovery phase
            domain_classification: Domain classification result

        Returns:
            ScanResult with all category results
        """
        parsed = urlparse(url)
        host = parsed.netloc

        result = ScanResult(host=host)

        # Build category context
        ctx = CategoryContext(
            base_url=url,
            host=host,
            endpoints=endpoints or [],
            forms=asset_data.get("forms", []) if asset_data else [],
            auth_headers=self.auth_headers,
            timeout=self.config.timeout,
            asset_data=asset_data or {},
            domain_classification=domain_classification,
            transaction_ctx=create_transaction_context(),
            anomaly_detector=self._anomaly_detector,
            rate_limiter_acquire=self._create_rate_limiter_callback(host),
            allow_writes=self.config.allow_writes,
            allow_destructive=self.config.allow_destructive,
        )

        # Run each category
        for cat_name, category, priority_tier in self._categories:
            # Skip if below minimum priority
            if priority_tier > self.config.min_priority_tier:
                continue

            try:
                logger.debug(f"[BizLogic] Running {cat_name} category on {url}")
                result.categories_tested.append(cat_name)

                cat_result = await asyncio.wait_for(
                    category.test(ctx),
                    timeout=self.config.category_timeout,
                )
                result.category_results[cat_name] = cat_result
                result.total_attempts += cat_result.attempts
                result.total_findings += len(cat_result.findings)
                result.errors.extend(cat_result.errors)

                if cat_result.found:
                    logger.info(
                        f"[BizLogic] {cat_name} found {len(cat_result.findings)} "
                        f"vulnerabilities at {url}"
                    )

                    # Phase 8: Share findings with injected store if available
                    if self._findings_store is not None:
                        for finding in cat_result.findings:
                            try:
                                self._findings_store.share_extracted_data(
                                    data_type="business_logic_finding",
                                    value=finding,
                                    source_module=f"business_logic.{cat_name}",
                                )
                            except Exception as e:
                                logger.debug(f"[BizLogic] Failed to share finding: {e}")

            except asyncio.TimeoutError:
                result.errors.append(f"{cat_name}: timeout")
                logger.debug(f"[BizLogic] {cat_name} timed out on {url}")

            except Exception as e:
                result.errors.append(f"{cat_name}: {str(e)}")
                logger.debug(f"[BizLogic] {cat_name} error: {e}")

        return result

    def _create_rate_limiter_callback(self, host: str) -> Callable[..., Any]:
        """Create rate limiter callback for category context."""
        async def acquire(h: str | None = None) -> None:
            if self.rate_limiter:
                await self.rate_limiter.acquire(h or host)
        return acquire

    def get_all_findings(self, result: ScanResult) -> list[dict[str, Any]]:
        """Extract all findings from scan result."""
        all_findings = []
        for cat_result in result.category_results.values():
            all_findings.extend(cat_result.findings)
        return all_findings

    def get_findings_by_severity(
        self,
        result: ScanResult,
    ) -> dict[str, list[dict[str, Any]]]:
        """Group findings by severity."""
        by_severity: dict[str, list[dict[str, Any]]] = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
        }

        for finding in self.get_all_findings(result):
            severity = finding.get("severity", "MEDIUM")
            if severity in by_severity:
                by_severity[severity].append(finding)

        return by_severity

    def get_summary(self, result: ScanResult) -> dict[str, Any]:
        """Get summary of scan results."""
        findings_by_category: dict[str, int] = {}
        findings_by_severity: dict[str, int] = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0
        }

        for cat_name, cat_result in result.category_results.items():
            findings_by_category[cat_name] = len(cat_result.findings)
            for finding in cat_result.findings:
                sev = finding.get("severity", "MEDIUM")
                if sev in findings_by_severity:
                    findings_by_severity[sev] += 1

        return {
            "version": BUSINESS_LOGIC_SCANNER_VERSION,
            "host": result.host,
            "categories_tested": result.categories_tested,
            "total_findings": result.total_findings,
            "total_attempts": result.total_attempts,
            "findings_by_category": findings_by_category,
            "findings_by_severity": findings_by_severity,
            "errors_count": len(result.errors),
        }


__all__ = [
    "BusinessLogicOrchestrator",
    "OrchestratorConfig",
    "ScanResult",
]
