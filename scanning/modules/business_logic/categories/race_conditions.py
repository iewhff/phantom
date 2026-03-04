"""
Business Logic Scanner - Race Conditions Category.

Tests for race conditions, double-spend, and TOCTOU vulnerabilities
through concurrent request analysis.

Extracted from business_logic_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

from utils.logger import get_logger
from utils.scan_client import get_scan_client

from scanning.modules.business_logic.business_base import (
    RACE_CONDITION_SCENARIOS,
    FINANCIAL_RACE_PAYLOADS,
    RaceConditionResult,
)
from scanning.modules.business_logic.categories.base import (
    BaseBusinessCategory,
    CategoryContext,
    CategoryResult,
)

if TYPE_CHECKING:
    import httpx

logger = get_logger(__name__)


class RaceConditionsCategory(BaseBusinessCategory):
    """Race conditions testing category.

    Tests for:
    - Double-spend attacks (coupons, credits)
    - Concurrent checkout exploitation
    - Balance transfer race conditions
    - Inventory overselling
    - Idempotency key bypass
    """

    # Number of concurrent requests for race testing
    CONCURRENCY_LEVELS = [5, 10, 20]
    # Maximum race tests per endpoint
    MAX_RACE_TESTS = 5

    @property
    def name(self) -> str:
        return "race_conditions"

    @property
    def priority_tier(self) -> int:
        return 1  # CRITICAL tier (financial impact)

    async def test(self, ctx: CategoryContext) -> CategoryResult:
        """Test for race condition vulnerabilities."""
        findings: list[dict[str, Any]] = []
        attempts = 0
        errors: list[str] = []

        if not ctx.allow_writes:
            logger.debug("[BizLogic-Race] Skipping - writes not allowed")
            return CategoryResult.not_found(0, ["Writes not allowed"])

        async with get_scan_client(timeout=ctx.timeout) as client:
            # Test each race condition scenario
            for scenario in RACE_CONDITION_SCENARIOS[:10]:
                matching_endpoints = ctx.get_endpoints_matching(scenario["endpoints"])

                for endpoint in matching_endpoints[:2]:
                    race_result = await self._test_race_condition(
                        client, ctx, endpoint, scenario
                    )
                    attempts += 1

                    if race_result and race_result.vulnerability_confidence > 0.7:
                        findings.append(self._create_race_finding(
                            ctx, endpoint, scenario, race_result
                        ))

            # Test domain-specific race conditions if domain is known
            if ctx.domain_classification:
                domain_findings = await self._test_domain_race_conditions(
                    client, ctx
                )
                findings.extend(domain_findings)
                attempts += 5

        if findings:
            return CategoryResult.vulnerable(findings, attempts)
        return CategoryResult.not_found(attempts, errors)

    async def _test_race_condition(
        self,
        client: "httpx.AsyncClient",
        ctx: CategoryContext,
        endpoint: str,
        scenario: dict[str, Any],
    ) -> RaceConditionResult | None:
        """Test a single endpoint for race conditions."""
        results = []

        # Get payload for this scenario
        payload = FINANCIAL_RACE_PAYLOADS.get(scenario["name"], {})
        if not payload:
            payload = {"action": "test", "value": 1}

        for concurrency in self.CONCURRENCY_LEVELS[:2]:
            await ctx.acquire_rate_limit()

            # Create concurrent requests
            tasks = []
            start_time = time.time()

            for _ in range(concurrency):
                task = client.post(
                    endpoint,
                    json=payload,
                    headers={"Content-Type": "application/json", **ctx.auth_headers},
                )
                tasks.append(task)

            try:
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                elapsed = time.time() - start_time

                # Analyze responses
                successful = 0
                response_hashes = []

                for resp in responses:
                    if isinstance(resp, Exception):
                        continue
                    if resp.status_code in (200, 201):
                        successful += 1
                        resp_hash = hashlib.md5(resp.text.encode()).hexdigest()[:8]
                        response_hashes.append(resp_hash)

                # Calculate timing variance
                timing_variance = elapsed * 1000 / concurrency

                # Check for duplicate effects (same response for multiple requests)
                unique_responses = len(set(response_hashes))
                duplicate_effects = unique_responses < successful and successful > 1

                results.append(RaceConditionResult(
                    endpoint=endpoint,
                    concurrent_requests=concurrency,
                    successful_requests=successful,
                    duplicate_effects=duplicate_effects,
                    timing_variance_ms=timing_variance,
                    response_patterns=response_hashes,
                    vulnerability_confidence=self._calculate_race_confidence(
                        successful, concurrency, duplicate_effects
                    ),
                ))

            except asyncio.TimeoutError:
                logger.debug(f"[BizLogic-Race] Timeout at {endpoint}")
            except Exception as e:
                logger.debug(f"[BizLogic-Race] Error: {e}")

        # Return the result with highest confidence
        if results:
            return max(results, key=lambda r: r.vulnerability_confidence)
        return None

    async def _test_domain_race_conditions(
        self,
        client: "httpx.AsyncClient",
        ctx: CategoryContext,
    ) -> list[dict[str, Any]]:
        """Test domain-specific race conditions."""
        findings = []
        domain = ctx.domain_classification

        if not domain:
            return findings

        # E-commerce specific
        if hasattr(domain, 'primary') and domain.primary.value in ("ecommerce", "marketplace"):
            # Test checkout race
            checkout_eps = ctx.get_endpoints_matching(["checkout", "order", "purchase"])
            for ep in checkout_eps[:1]:
                result = await self._test_race_condition(
                    client, ctx, ep,
                    {"name": "checkout_race", "endpoints": ["checkout"], "severity": "CRITICAL"}
                )
                if result and result.vulnerability_confidence > 0.7:
                    findings.append(self._create_finding(
                        name="E-commerce Checkout Race Condition",
                        severity="CRITICAL",
                        description=(
                            f"Race condition detected at checkout endpoint {ep}. "
                            f"Concurrent requests may allow double-ordering or payment bypass."
                        ),
                        host=ctx.host,
                        endpoint=ep,
                        evidence=[
                            f"Concurrent requests: {result.concurrent_requests}",
                            f"Successful: {result.successful_requests}",
                            f"Duplicate effects: {result.duplicate_effects}",
                        ],
                        cvss_score=9.0,
                        cwe_id="CWE-362",
                    ))

        # Fintech specific
        if hasattr(domain, 'primary') and domain.primary.value == "fintech":
            transfer_eps = ctx.get_endpoints_matching(["transfer", "send", "withdraw"])
            for ep in transfer_eps[:1]:
                result = await self._test_race_condition(
                    client, ctx, ep,
                    {"name": "transfer_race", "endpoints": ["transfer"], "severity": "CRITICAL"}
                )
                if result and result.vulnerability_confidence > 0.7:
                    findings.append(self._create_finding(
                        name="Financial Transfer Race Condition",
                        severity="CRITICAL",
                        description=(
                            f"Race condition in financial transfer at {ep}. "
                            f"Double-spend or balance manipulation possible."
                        ),
                        host=ctx.host,
                        endpoint=ep,
                        evidence=[
                            f"Concurrent requests: {result.concurrent_requests}",
                            f"Successful: {result.successful_requests}",
                        ],
                        cvss_score=9.5,
                        cwe_id="CWE-362",
                    ))

        return findings

    def _calculate_race_confidence(
        self,
        successful: int,
        total: int,
        duplicate_effects: bool,
    ) -> float:
        """Calculate confidence score for race condition detection."""
        if total == 0:
            return 0.0

        base_confidence = 0.3
        success_rate = successful / total

        # High success rate with duplicates = high confidence
        if success_rate > 0.8 and duplicate_effects:
            base_confidence += 0.5
        elif success_rate > 0.5 and duplicate_effects:
            base_confidence += 0.3
        elif duplicate_effects:
            base_confidence += 0.2

        # More successful concurrent requests = higher confidence
        if successful > 5:
            base_confidence += 0.1
        if successful > 10:
            base_confidence += 0.1

        return min(base_confidence, 1.0)

    def _create_race_finding(
        self,
        ctx: CategoryContext,
        endpoint: str,
        scenario: dict[str, Any],
        result: RaceConditionResult,
    ) -> dict[str, Any]:
        """Create a finding for race condition vulnerability."""
        return self._create_finding(
            name=f"Race Condition: {scenario['name'].replace('_', ' ').title()}",
            severity=scenario.get("severity", "HIGH"),
            description=(
                f"Race condition vulnerability detected at {endpoint}. "
                f"{scenario.get('impact', 'Concurrent exploitation possible')}. "
                f"Confidence: {result.vulnerability_confidence:.0%}"
            ),
            host=ctx.host,
            endpoint=endpoint,
            evidence=[
                f"Scenario: {scenario['name']}",
                f"Concurrent requests: {result.concurrent_requests}",
                f"Successful requests: {result.successful_requests}",
                f"Duplicate effects: {result.duplicate_effects}",
                f"Timing variance: {result.timing_variance_ms:.2f}ms",
            ],
            cvss_score=9.0 if scenario.get("severity") == "CRITICAL" else 7.5,
            cwe_id="CWE-362",
            metadata={
                "scenario": scenario["name"],
                "concurrency": result.concurrent_requests,
                "duplicate_effects": result.duplicate_effects,
            }
        )


__all__ = ["RaceConditionsCategory"]
