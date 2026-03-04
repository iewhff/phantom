"""
SQL Injection Scanner - Strategy Orchestrator.

This module provides the orchestration layer that coordinates all SQLi detection
strategies. It replaces the monolithic detection methods with a clean strategy-based
approach.

Usage:
    # Legacy usage (backward compatible)
    orchestrator = SQLiOrchestrator(settings, rate_limiter, auth_headers)

    # DI usage (Phase 8)
    orchestrator = SQLiOrchestrator(
        settings=settings,
        rate_limiter=rate_limiter,  # RateLimiterProtocol
        auth_headers=auth_headers,
        waf_bypass_engine=waf_engine,  # WAFBypassEngineProtocol (optional)
        oob_engine=oob_engine,  # OOBEngineProtocol (optional)
    )
    results = await orchestrator.scan_endpoint(url, params, asset_data)

Extracted from sqli_scanner.py as part of Phase 7 refactoring (2026-02-26).
Updated for DI support as part of Phase 8 (2026-02-26).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Optional
from urllib.parse import parse_qs, urlparse

from utils.logger import get_logger
from utils.scan_client import get_scan_client

from scanning.modules.sqli.sqli_base import (
    DatabaseType, DetectionMethod, InjectionContext, ResponseCluster,
    ResponseFingerprint, SQLiEvidence, WAFType, is_spa_response,
    FP_INDICATORS, MAX_FINDINGS_PER_ENDPOINT, MAX_FINDINGS_PER_PARAM,
)
from scanning.modules.sqli.utils.database_fingerprinter import DatabaseFingerprinter
from scanning.modules.sqli.utils.payload_mutator import PayloadMutator
from scanning.modules.sqli.utils.response_analysis import AnomalyDetector
from scanning.modules.sqli.strategies import (
    InjectionStrategy,
    StrategyContext,
    StrategyResult,
    ErrorBasedStrategy,
    BooleanBlindStrategy,
    TimeBlindStrategy,
    UnionBasedStrategy,
    StackedQueriesStrategy,
    OutOfBandStrategy,
)

if TYPE_CHECKING:
    from core.config_manager import Settings
    from scanning.protocols import (
        RateLimiterProtocol,
        WAFBypassEngineProtocol,
        OOBEngineProtocol,
    )

logger = get_logger(__name__)


@dataclass
class OrchestratorConfig:
    """Configuration for the SQLi orchestrator."""
    timeout: float = 30.0
    time_delay: int = 5
    max_mutations: int = 5
    max_payloads: int = 15
    baseline_samples: int = 5
    enable_error_based: bool = True
    enable_boolean_blind: bool = True
    enable_time_blind: bool = True
    enable_union_based: bool = True
    enable_stacked: bool = True
    enable_oob: bool = True


@dataclass
class EndpointResult:
    """Result from scanning an endpoint."""
    url: str
    findings: list[SQLiEvidence] = field(default_factory=list)
    strategies_tested: list[str] = field(default_factory=list)
    total_attempts: int = 0
    errors: list[str] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""


class SQLiOrchestrator:
    """Orchestrates SQLi detection strategies.

    This class coordinates the execution of all SQLi detection strategies,
    managing:
    - Strategy selection based on target characteristics
    - Baseline response collection for comparison
    - Finding deduplication
    - Early exit when sufficient findings are found

    Supports dependency injection (Phase 8) while maintaining backward compatibility.
    """

    def __init__(
        self,
        settings: Any,
        rate_limiter: "RateLimiterProtocol",
        auth_headers: dict[str, str] | None = None,
        config: OrchestratorConfig | None = None,
        # Phase 8: Optional injected dependencies
        waf_bypass_engine: Optional["WAFBypassEngineProtocol"] = None,
        oob_engine: Optional["OOBEngineProtocol"] = None,
    ):
        """Initialize the SQLi orchestrator.

        Args:
            settings: Application settings
            rate_limiter: Rate limiter (RateLimiterProtocol)
            auth_headers: Authentication headers
            config: Orchestrator configuration
            waf_bypass_engine: Optional WAF bypass engine (WAFBypassEngineProtocol)
            oob_engine: Optional OOB detection engine (OOBEngineProtocol)
        """
        self.settings = settings
        self.rate_limiter = rate_limiter
        self.auth_headers = auth_headers or {}
        self.config = config or OrchestratorConfig()

        # Phase 8: Store injected dependencies
        self._waf_bypass_engine = waf_bypass_engine
        self._oob_engine = oob_engine

        # Initialize strategies
        self._strategies: list[InjectionStrategy] = []
        self._init_strategies()

        # FP checking callback
        self._is_false_positive = self._default_fp_check

    def _init_strategies(self) -> None:
        """Initialize enabled detection strategies."""
        if self.config.enable_error_based:
            self._strategies.append(ErrorBasedStrategy())
        if self.config.enable_boolean_blind:
            self._strategies.append(BooleanBlindStrategy())
        if self.config.enable_time_blind:
            self._strategies.append(TimeBlindStrategy())
        if self.config.enable_union_based:
            self._strategies.append(UnionBasedStrategy())
        if self.config.enable_stacked:
            self._strategies.append(StackedQueriesStrategy())
        if self.config.enable_oob:
            self._strategies.append(OutOfBandStrategy())

        logger.debug(f"[SQLi] Initialized {len(self._strategies)} strategies")

    async def scan_endpoint(
        self,
        url: str,
        params: dict[str, list[str]] | None = None,
        asset_data: dict[str, Any] | None = None,
    ) -> EndpointResult:
        """Scan an endpoint for SQL injection vulnerabilities.

        Args:
            url: Target URL
            params: Query parameters to test (extracted from URL if not provided)
            asset_data: Asset data from scanner (tech fingerprint, WAF detection, etc.)

        Returns:
            EndpointResult with findings from all strategies
        """
        result = EndpointResult(url=url)

        # Parse URL and extract params if not provided
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if params is None:
            params = parse_qs(parsed.query)

        if not params:
            result.skipped = True
            result.skip_reason = "No parameters to test"
            return result

        # Collect baseline responses
        cluster, detector = await self._collect_baseline(base_url, params)

        # Check for SPA (false positive prone)
        if cluster and cluster.fingerprints:
            fp = cluster.fingerprints[0]
            # Would need to fetch content for SPA check
            # Skip for now

        # Detect WAF and DB type from asset_data
        detected_waf = self._extract_waf_type(asset_data)
        detected_db = self._extract_db_type(asset_data)

        # Test each parameter
        for param_name in params:
            param_findings = await self._scan_parameter(
                base_url=base_url,
                param_name=param_name,
                params=params,
                cluster=cluster,
                detector=detector,
                detected_waf=detected_waf,
                detected_db=detected_db,
                asset_data=asset_data or {},
            )

            result.findings.extend(param_findings.findings)
            result.strategies_tested.extend(param_findings.strategies_tested)
            result.total_attempts += param_findings.total_attempts
            result.errors.extend(param_findings.errors)

            # Early exit if enough findings
            if len(result.findings) >= MAX_FINDINGS_PER_ENDPOINT:
                logger.debug(f"[SQLi] Early exit: {len(result.findings)} findings found")
                break

        return result

    async def _scan_parameter(
        self,
        base_url: str,
        param_name: str,
        params: dict[str, list[str]],
        cluster: ResponseCluster | None,
        detector: AnomalyDetector | None,
        detected_waf: WAFType,
        detected_db: DatabaseType,
        asset_data: dict[str, Any],
    ) -> EndpointResult:
        """Scan a single parameter with all strategies."""
        result = EndpointResult(url=base_url)

        # Build injection context
        injection_ctx = InjectionContext(
            url=base_url,
            method="GET",
            param_name=param_name,
            param_value=(params.get(param_name) or [""])[0],
            param_type="query",
        )

        # Build strategy context with all dependencies
        strategy_ctx = StrategyContext(
            base_url=base_url,
            param_name=param_name,
            params=params,
            injection_ctx=injection_ctx,
            cluster=cluster,
            detector=detector,
            auth_headers=self.auth_headers,
            timeout=self.config.timeout,
            host=urlparse(base_url).netloc,
            time_delay=self.config.time_delay,
            max_mutations=self.config.max_mutations,
            max_payloads=self.config.max_payloads,
            detected_waf=detected_waf,
            detected_db=detected_db,
            rate_limiter_acquire=self._acquire_rate_limit,
            is_false_positive=self._is_false_positive,
            get_payload_mutations=self._get_payload_mutations,
            asset_data=asset_data,
        )

        # Run each strategy
        for strategy in self._strategies:
            try:
                logger.debug(f"[SQLi] Testing {strategy.name} on {param_name}")
                strategy_result = await strategy.test(strategy_ctx)

                result.strategies_tested.append(strategy.name)
                result.total_attempts += strategy_result.attempts
                result.errors.extend(strategy_result.errors)

                if strategy_result.found and strategy_result.evidence:
                    result.findings.append(strategy_result.evidence)
                    logger.info(
                        f"[SQLi] {strategy.name} found vulnerability in {param_name}"
                    )

                    # Early exit if enough findings for this param
                    if len(result.findings) >= MAX_FINDINGS_PER_PARAM:
                        break

            except Exception as e:
                result.errors.append(f"{strategy.name}: {e}")
                logger.debug(f"[SQLi] Strategy {strategy.name} failed: {e}")

        return result

    async def _collect_baseline(
        self,
        base_url: str,
        params: dict[str, list[str]],
    ) -> tuple[ResponseCluster | None, AnomalyDetector | None]:
        """Collect baseline responses for comparison."""
        from urllib.parse import urlencode

        cluster = ResponseCluster()
        detector = AnomalyDetector(baseline_samples=self.config.baseline_samples)

        baseline_url = f"{base_url}?{urlencode(params, doseq=True)}"

        async with get_scan_client(timeout=self.config.timeout) as client:
            for _ in range(self.config.baseline_samples):
                try:
                    await self._acquire_rate_limit(urlparse(base_url).netloc)
                    import time
                    start = time.time()
                    response = await client.get(baseline_url, headers=self.auth_headers)
                    elapsed = time.time() - start

                    fp = ResponseFingerprint.from_response(response, elapsed)
                    cluster.add(fp)
                    detector.add_baseline(fp)

                except Exception as e:
                    logger.debug(f"[SQLi] Baseline collection failed: {e}")

        if not cluster.fingerprints:
            return None, None

        return cluster, detector

    async def _acquire_rate_limit(self, host: str) -> None:
        """Acquire rate limit for a host."""
        await self.rate_limiter.acquire(host)

    def _default_fp_check(self, content: str, status_code: int) -> bool:
        """Default false positive check."""
        import re
        content_lower = content.lower()

        # Check status code
        if status_code in (403, 404, 429):
            return True

        # Check FP indicators
        for pattern in FP_INDICATORS:
            if re.search(pattern, content_lower, re.IGNORECASE):
                return True

        return False

    def _get_payload_mutations(
        self,
        payload: str,
        waf_type: WAFType | None = None,
    ) -> list[str]:
        """Get payload mutations using injected WAF bypass engine or local mutator.

        Phase 8: Uses injected WAFBypassEngineProtocol if available,
        falls back to local PayloadMutator for backward compatibility.
        """
        # Try injected WAF bypass engine first
        if self._waf_bypass_engine is not None:
            try:
                # Use the apply_bypass method with a mock detection
                return self._waf_bypass_engine.apply_bypass(
                    payload,
                    detection=None,  # No specific detection
                    max_variants=self.config.max_mutations,
                )
            except Exception as e:
                logger.debug(f"[SQLi] WAF bypass engine failed, using local mutator: {e}")

        # Fallback to local PayloadMutator
        return PayloadMutator.mutate(payload, waf_type)

    def _extract_waf_type(self, asset_data: dict[str, Any] | None) -> WAFType:
        """Extract WAF type from asset data."""
        if not asset_data:
            return WAFType.NONE

        waf_detection = asset_data.get("waf_detection")
        if waf_detection and hasattr(waf_detection, "waf_name"):
            # Try to map waf_name to WAFType
            waf_name = waf_detection.waf_name.lower()
            for waf_type in WAFType:
                if waf_type.value.lower() in waf_name or waf_name in waf_type.value.lower():
                    return waf_type

        return WAFType.NONE

    def _extract_db_type(self, asset_data: dict[str, Any] | None) -> DatabaseType:
        """Extract database type from asset data."""
        if not asset_data:
            return DatabaseType.UNKNOWN

        # Check tech fingerprint
        tech = asset_data.get("technology", {})
        if isinstance(tech, dict):
            db_tech = tech.get("database", "").lower()
            for db_type in DatabaseType:
                if db_type.value.lower() in db_tech:
                    return db_type

        return DatabaseType.UNKNOWN


__all__ = ["SQLiOrchestrator", "OrchestratorConfig", "EndpointResult"]
