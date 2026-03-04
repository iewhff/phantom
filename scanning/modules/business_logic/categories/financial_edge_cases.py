"""
Business Logic Scanner - Financial Edge Cases Category.

Tests for price manipulation, negative values, integer overflow,
and other financial abuse scenarios.

Extracted from business_logic_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

from utils.logger import get_logger
from utils.scan_client import get_scan_client

from scanning.modules.business_logic.business_base import (
    FINANCIAL_TEST_CASES,
    FinancialTestCase,
    get_business_priority,
)
from scanning.modules.business_logic.categories.base import (
    BaseBusinessCategory,
    CategoryContext,
    CategoryResult,
)

if TYPE_CHECKING:
    import httpx

logger = get_logger(__name__)


# Endpoints likely to handle financial operations
FINANCIAL_ENDPOINTS = [
    "cart", "basket", "checkout", "order", "payment", "pay",
    "price", "total", "amount", "quantity", "discount", "coupon",
    "product", "item", "add", "update", "purchase", "buy",
]


class FinancialEdgeCasesCategory(BaseBusinessCategory):
    """Financial edge cases testing category.

    Tests for:
    - Negative price/quantity exploitation
    - Zero value bypass
    - Integer overflow/underflow
    - Precision attacks (rounding)
    - Scientific notation abuse
    - Currency manipulation
    """

    @property
    def name(self) -> str:
        return "financial_edge_cases"

    @property
    def priority_tier(self) -> int:
        return 1  # CRITICAL tier

    async def test(self, ctx: CategoryContext) -> CategoryResult:
        """Test for financial edge case vulnerabilities."""
        findings: list[dict[str, Any]] = []
        attempts = 0
        errors: list[str] = []

        if not ctx.allow_writes:
            logger.debug("[BizLogic-Financial] Skipping - writes not allowed")
            return CategoryResult.not_found(0, ["Writes not allowed in safe mode"])

        # Find financial endpoints
        financial_endpoints = ctx.get_endpoints_matching(FINANCIAL_ENDPOINTS)
        if not financial_endpoints:
            # Try common paths
            financial_endpoints = [
                urljoin(ctx.base_url, "/api/cart"),
                urljoin(ctx.base_url, "/api/basket"),
                urljoin(ctx.base_url, "/api/BasketItems"),  # Juice Shop
                urljoin(ctx.base_url, "/rest/basket"),
            ]

        async with get_scan_client(timeout=ctx.timeout) as client:
            # Test negative values
            neg_findings = await self._test_negative_values(
                client, ctx, financial_endpoints
            )
            findings.extend(neg_findings)
            attempts += len(FINANCIAL_TEST_CASES) * len(financial_endpoints[:5])

            # Test price manipulation
            price_findings = await self._test_price_manipulation(
                client, ctx, financial_endpoints
            )
            findings.extend(price_findings)
            attempts += 10

        if findings:
            return CategoryResult.vulnerable(findings, attempts)
        return CategoryResult.not_found(attempts, errors)

    async def _test_negative_values(
        self,
        client: "httpx.AsyncClient",
        ctx: CategoryContext,
        endpoints: list[str],
    ) -> list[dict[str, Any]]:
        """Test negative value attacks."""
        findings = []

        # Test cases for negative/zero values
        negative_cases = [tc for tc in FINANCIAL_TEST_CASES
                         if "negative" in tc.name or "zero" in tc.name]

        for endpoint in endpoints[:5]:
            for test_case in negative_cases[:6]:
                await ctx.acquire_rate_limit()

                try:
                    response = await client.post(
                        endpoint,
                        json=test_case.payload,
                        headers={"Content-Type": "application/json", **ctx.auth_headers},
                    )

                    # Check if negative value was accepted (vulnerability)
                    if response.status_code in (200, 201):
                        # Parse response to check if manipulation worked
                        try:
                            resp_data = response.json()
                            # Look for signs the negative value affected totals
                            if self._check_negative_effect(resp_data, test_case):
                                severity, _, _, _ = get_business_priority(test_case.name)
                                findings.append(self._create_finding(
                                    name=f"Financial Edge Case: {test_case.description}",
                                    severity=severity,
                                    description=(
                                        f"{test_case.description} vulnerability detected. "
                                        f"The application accepted {test_case.payload} "
                                        f"which could lead to financial manipulation."
                                    ),
                                    host=ctx.host,
                                    endpoint=endpoint,
                                    evidence=[
                                        f"Test case: {test_case.name}",
                                        f"Payload: {test_case.payload}",
                                        f"Response status: {response.status_code}",
                                        f"Response: {response.text[:500]}",
                                    ],
                                    cvss_score=9.0 if severity == "CRITICAL" else 7.5,
                                    cwe_id="CWE-20",
                                    metadata={
                                        "test_case": test_case.name,
                                        "payload": test_case.payload,
                                    }
                                ))
                                logger.info(f"[BizLogic] Financial edge case: {test_case.name} at {endpoint}")

                        except json.JSONDecodeError:
                            pass

                except asyncio.TimeoutError:
                    pass
                except Exception as e:
                    logger.debug(f"[BizLogic-Financial] Error testing {endpoint}: {e}")

        return findings

    async def _test_price_manipulation(
        self,
        client: "httpx.AsyncClient",
        ctx: CategoryContext,
        endpoints: list[str],
    ) -> list[dict[str, Any]]:
        """Test price manipulation attacks."""
        findings = []

        # Price manipulation payloads
        price_payloads = [
            {"price": 0.01, "name": "ultra_low_price"},
            {"price": -1, "name": "negative_price"},
            {"total": 0, "name": "zero_total"},
            {"amount": 0.001, "name": "precision_attack"},
            {"quantity": -5, "price": 100, "name": "negative_qty"},
        ]

        for endpoint in endpoints[:3]:
            if not any(kw in endpoint.lower() for kw in ["cart", "basket", "order", "checkout"]):
                continue

            for payload in price_payloads:
                await ctx.acquire_rate_limit()
                payload_name = payload.pop("name", "unknown")

                try:
                    # Try PUT for update
                    response = await client.put(
                        endpoint,
                        json=payload,
                        headers={"Content-Type": "application/json", **ctx.auth_headers},
                    )

                    if response.status_code in (200, 201):
                        try:
                            resp_data = response.json()
                            # Check if price/total was manipulated
                            if self._check_price_manipulation(resp_data, payload):
                                findings.append(self._create_finding(
                                    name="Price Manipulation Vulnerability",
                                    severity="CRITICAL",
                                    description=(
                                        f"Price manipulation detected at {endpoint}. "
                                        f"The application accepted manipulated price values, "
                                        f"potentially allowing purchases at reduced or zero cost."
                                    ),
                                    host=ctx.host,
                                    endpoint=endpoint,
                                    evidence=[
                                        f"Attack: {payload_name}",
                                        f"Payload: {payload}",
                                        f"Response: {response.text[:500]}",
                                    ],
                                    cvss_score=9.5,
                                    cwe_id="CWE-20",
                                    metadata={"attack_type": payload_name}
                                ))
                                logger.info(f"[BizLogic] Price manipulation at {endpoint}")

                        except json.JSONDecodeError:
                            pass

                except asyncio.TimeoutError:
                    pass
                except Exception as e:
                    logger.debug(f"[BizLogic-Price] Error: {e}")

                payload["name"] = payload_name  # Restore for next iteration

        return findings

    def _check_negative_effect(
        self,
        response: dict[str, Any],
        test_case: FinancialTestCase,
    ) -> bool:
        """Check if negative value had an effect on the response."""
        # Look for negative totals in response
        for key in ["total", "price", "amount", "sum", "balance"]:
            if key in response:
                value = response[key]
                if isinstance(value, (int, float)) and value < 0:
                    return True

        # Check if quantity was accepted as negative
        if "quantity" in test_case.payload:
            qty = test_case.payload["quantity"]
            if isinstance(qty, (int, float)) and qty < 0:
                # Response didn't reject it
                if "error" not in str(response).lower():
                    return True

        return False

    def _check_price_manipulation(
        self,
        response: dict[str, Any],
        payload: dict[str, Any],
    ) -> bool:
        """Check if price manipulation was successful."""
        # If we sent a low price and got a success, it's vulnerable
        if "price" in payload and payload["price"] <= 0.01:
            # Check response doesn't contain validation error
            resp_str = str(response).lower()
            if "error" not in resp_str and "invalid" not in resp_str:
                return True

        # Check if total became very low or negative
        for key in ["total", "price", "amount"]:
            if key in response:
                value = response[key]
                if isinstance(value, (int, float)) and value <= 0.01:
                    return True

        return False


__all__ = ["FinancialEdgeCasesCategory"]
