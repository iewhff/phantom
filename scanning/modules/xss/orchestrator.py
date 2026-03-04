"""
XSS Scanner - Orchestrator.

Coordinates the execution of all XSS detection strategies.
Provides the main entry point for XSS scanning.

Extracted from xss_scanner.py as part of Phase 7 refactoring (2026-02-26).
Updated for DI support as part of Phase 8 (2026-02-26).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Optional
from urllib.parse import urlparse

from utils.logger import get_logger

from scanning.modules.xss.xss_base import (
    XSS_SCANNER_VERSION,
    MIN_CONFIDENCE_THRESHOLD,
    XSSContext,
    XSSEvidence,
    XSSResult,
    WAFType,
)
from scanning.modules.xss.strategies import (
    XSSStrategyContext,
    XSSStrategyResult,
    URLParamStrategy,
    FormTestStrategy,
    HeaderTestStrategy,
    JSONBodyStrategy,
    TemplateInjectionStrategy,
    StoredXSSStrategy,
    SecondOrderStrategy,
)

if TYPE_CHECKING:
    from scanning.protocols import (
        RateLimiterProtocol,
        WAFBypassEngineProtocol,
        PayloadLibraryProtocol,
    )

logger = get_logger(__name__)


@dataclass
class OrchestratorConfig:
    """Configuration for XSS orchestrator."""
    # Timeout settings
    timeout: float = 30.0
    endpoint_timeout: float = 10.0

    # Strategy settings
    max_payloads_per_param: int = 30
    mutation_level: int = 3

    # Strategy enable/disable
    enable_url_param: bool = True
    enable_form_test: bool = True
    enable_header_test: bool = True
    enable_json_body: bool = True
    enable_template_injection: bool = True
    enable_stored_xss: bool = True
    enable_second_order: bool = True


@dataclass
class EndpointResult:
    """Result from testing an endpoint."""
    endpoint: str
    strategy_results: dict[str, XSSStrategyResult] = field(default_factory=dict)
    total_attempts: int = 0
    findings_count: int = 0
    errors: list[str] = field(default_factory=list)


class XSSOrchestrator:
    """Orchestrator for XSS detection strategies.

    Coordinates the execution of all XSS strategies:
    - URLParamStrategy: Query string parameter testing
    - FormTestStrategy: HTML form field testing
    - HeaderTestStrategy: HTTP header injection
    - JSONBodyStrategy: JSON API testing
    - TemplateInjectionStrategy: CSTI detection
    - StoredXSSStrategy: Persistence verification
    - SecondOrderStrategy: Cross-endpoint detection

    Supports dependency injection (Phase 8) while maintaining backward compatibility.

    Usage:
        # Legacy usage (backward compatible)
        orchestrator = XSSOrchestrator(settings, rate_limiter, auth_headers)

        # DI usage (Phase 8)
        orchestrator = XSSOrchestrator(
            settings=settings,
            rate_limiter=rate_limiter,  # RateLimiterProtocol
            waf_bypass_engine=waf_engine,  # WAFBypassEngineProtocol (optional)
            payload_library=payloads,  # PayloadLibraryProtocol (optional)
        )
        result = await orchestrator.scan_endpoint(url, params, asset_data)
    """

    def __init__(
        self,
        settings: dict[str, Any] | None = None,
        rate_limiter: Optional["RateLimiterProtocol"] = None,
        auth_headers: dict[str, str] | None = None,
        config: OrchestratorConfig | None = None,
        # Phase 8: Optional injected dependencies
        waf_bypass_engine: Optional["WAFBypassEngineProtocol"] = None,
        payload_library: Optional["PayloadLibraryProtocol"] = None,
    ) -> None:
        """Initialize the XSS orchestrator.

        Args:
            settings: Application settings
            rate_limiter: Rate limiter (RateLimiterProtocol)
            auth_headers: Authentication headers
            config: Orchestrator configuration
            waf_bypass_engine: Optional WAF bypass engine (WAFBypassEngineProtocol)
            payload_library: Optional payload library (PayloadLibraryProtocol)
        """
        self.settings = settings or {}
        self.rate_limiter = rate_limiter
        self.auth_headers = auth_headers or {}
        self.config = config or OrchestratorConfig()

        # Phase 8: Store injected dependencies
        self._waf_bypass_engine = waf_bypass_engine
        self._payload_library = payload_library

        # State
        self._detected_waf: WAFType = WAFType.NONE
        self._csp_analysis: dict[str, Any] = {}

        # Initialize strategies
        self._strategies = self._init_strategies()

        logger.debug(f"[XSS] Orchestrator v{XSS_SCANNER_VERSION} initialized with {len(self._strategies)} strategies")

    def _init_strategies(self) -> list[tuple[str, Any]]:
        """Initialize enabled strategies."""
        strategies = []

        if self.config.enable_url_param:
            strategies.append(("url_param", URLParamStrategy()))

        if self.config.enable_form_test:
            strategies.append(("form_test", FormTestStrategy()))

        if self.config.enable_header_test:
            strategies.append(("header_test", HeaderTestStrategy()))

        if self.config.enable_json_body:
            strategies.append(("json_body", JSONBodyStrategy()))

        if self.config.enable_template_injection:
            strategies.append(("template_injection", TemplateInjectionStrategy()))

        if self.config.enable_stored_xss:
            strategies.append(("stored_xss", StoredXSSStrategy()))

        if self.config.enable_second_order:
            strategies.append(("second_order", SecondOrderStrategy()))

        return strategies

    async def scan_endpoint(
        self,
        url: str,
        params: dict[str, list[str]] | None = None,
        asset_data: dict[str, Any] | None = None,
        forms: list[dict[str, Any]] | None = None,
    ) -> EndpointResult:
        """Scan an endpoint for XSS vulnerabilities.

        Args:
            url: Base URL to test
            params: Query parameters to test
            asset_data: Asset data from discovery phase
            forms: HTML forms to test

        Returns:
            EndpointResult with all strategy results
        """
        result = EndpointResult(endpoint=url)

        # Parse URL
        parsed = urlparse(url)
        host = parsed.netloc

        # Build strategy context
        ctx = XSSStrategyContext(
            base_url=url,
            param_name="",  # Set per-strategy
            params=params or {},
            method="GET",
            auth_headers=self.auth_headers,
            timeout=self.config.timeout,
            host=host,
            mutation_level=self.config.mutation_level,
            max_payloads=self.config.max_payloads_per_param,
            detected_waf=self._detected_waf,
            detected_context=None,
            csp_analysis=self._csp_analysis,
            rate_limiter_acquire=self._create_rate_limiter_callback(host),
            get_payload_mutations=self._get_payload_mutations,
            asset_data=asset_data or {},
            forms=forms or [],
        )

        # Run each strategy
        for strategy_name, strategy in self._strategies:
            try:
                logger.debug(f"[XSS] Running {strategy_name} strategy on {url}")
                strategy_result = await asyncio.wait_for(
                    strategy.test(ctx),
                    timeout=self.config.endpoint_timeout * 3,
                )
                result.strategy_results[strategy_name] = strategy_result
                result.total_attempts += strategy_result.attempts
                result.findings_count += len(strategy_result.evidence)
                result.errors.extend(strategy_result.errors)

                if strategy_result.found:
                    logger.info(
                        f"[XSS] {strategy_name} found {len(strategy_result.evidence)} "
                        f"vulnerabilities at {url}"
                    )

            except asyncio.TimeoutError:
                result.errors.append(f"{strategy_name}: timeout")
                logger.debug(f"[XSS] {strategy_name} timed out on {url}")

            except Exception as e:
                result.errors.append(f"{strategy_name}: {str(e)}")
                logger.debug(f"[XSS] {strategy_name} error: {e}")

        return result

    async def scan_all(
        self,
        endpoints: list[str],
        asset_data: dict[str, Any] | None = None,
    ) -> list[EndpointResult]:
        """Scan multiple endpoints for XSS.

        Args:
            endpoints: List of URLs to test
            asset_data: Asset data from discovery phase

        Returns:
            List of EndpointResult for each endpoint
        """
        results = []
        forms = asset_data.get("forms", []) if asset_data else []

        for endpoint in endpoints:
            # Extract params from URL
            parsed = urlparse(endpoint)
            params = {}
            if parsed.query:
                from urllib.parse import parse_qs
                params = parse_qs(parsed.query)

            result = await self.scan_endpoint(
                endpoint,
                params=params,
                asset_data=asset_data,
                forms=forms,
            )
            results.append(result)

        return results

    def set_waf_detected(self, waf_type: WAFType) -> None:
        """Set detected WAF type."""
        self._detected_waf = waf_type
        logger.debug(f"[XSS] WAF detected: {waf_type.name}")

    def set_csp_analysis(self, csp_analysis: dict[str, Any]) -> None:
        """Set CSP analysis results."""
        self._csp_analysis = csp_analysis

    def _create_rate_limiter_callback(self, host: str) -> Callable[..., Any]:
        """Create rate limiter callback for strategy context."""
        async def acquire(h: str | None = None) -> None:
            if self.rate_limiter:
                await self.rate_limiter.acquire(h or host)
        return acquire

    def _get_payload_mutations(
        self,
        payload: str,
        mutation_level: int = 3,
    ) -> list[str]:
        """Get payload mutations for WAF bypass.

        Phase 8: Uses injected WAFBypassEngineProtocol if available,
        falls back to local mutation logic for backward compatibility.
        """
        # Try injected WAF bypass engine first
        if self._waf_bypass_engine is not None:
            try:
                return self._waf_bypass_engine.apply_bypass(
                    payload,
                    detection=None,
                    max_variants=mutation_level * 3,
                )
            except Exception as e:
                logger.debug(f"[XSS] WAF bypass engine failed, using local mutator: {e}")

        # Fallback to local mutation logic
        mutations = [payload]

        if mutation_level >= 1:
            # URL encoding
            from urllib.parse import quote
            mutations.append(quote(payload))

        if mutation_level >= 2:
            # Case variations
            mutations.append(payload.upper())
            mutations.append(payload.lower())
            # Double URL encoding
            from urllib.parse import quote
            mutations.append(quote(quote(payload)))

        if mutation_level >= 3:
            # HTML entity encoding
            mutations.append(payload.replace("<", "&lt;").replace(">", "&gt;"))
            # Mixed case
            result = ""
            for i, c in enumerate(payload):
                result += c.upper() if i % 2 else c.lower()
            mutations.append(result)

        # Deduplicate
        return list(dict.fromkeys(mutations))

    def get_all_evidence(self, results: list[EndpointResult]) -> list[XSSEvidence]:
        """Extract all evidence from results."""
        all_evidence = []
        for result in results:
            for strategy_result in result.strategy_results.values():
                all_evidence.extend(strategy_result.evidence)
        return all_evidence

    def get_summary(self, results: list[EndpointResult]) -> dict[str, Any]:
        """Get summary of scan results."""
        total_findings = 0
        total_attempts = 0
        findings_by_strategy: dict[str, int] = {}
        findings_by_context: dict[str, int] = {}

        for result in results:
            total_attempts += result.total_attempts
            for strategy_name, strategy_result in result.strategy_results.items():
                if strategy_result.found:
                    count = len(strategy_result.evidence)
                    total_findings += count
                    findings_by_strategy[strategy_name] = findings_by_strategy.get(strategy_name, 0) + count

                    for evidence in strategy_result.evidence:
                        ctx_name = evidence.context.name
                        findings_by_context[ctx_name] = findings_by_context.get(ctx_name, 0) + 1

        return {
            "version": XSS_SCANNER_VERSION,
            "total_findings": total_findings,
            "total_attempts": total_attempts,
            "endpoints_tested": len(results),
            "findings_by_strategy": findings_by_strategy,
            "findings_by_context": findings_by_context,
            "waf_detected": self._detected_waf.name,
            "csp_present": self._csp_analysis.get("present", False),
        }


__all__ = [
    "XSSOrchestrator",
    "OrchestratorConfig",
    "EndpointResult",
]
