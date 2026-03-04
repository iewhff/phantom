"""
Business Logic Scanner - Inventory Manipulation Category.

Tests for stock manipulation, limit bypass, and
inventory-related business logic vulnerabilities.

Extracted from business_logic_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

from utils.logger import get_logger
from utils.scan_client import get_scan_client

from scanning.modules.business_logic.categories.base import (
    BaseBusinessCategory,
    CategoryContext,
    CategoryResult,
)

if TYPE_CHECKING:
    import httpx

logger = get_logger(__name__)


# Inventory-related endpoints
INVENTORY_PATTERNS = [
    "cart", "basket", "stock", "inventory", "reserve",
    "product", "item", "quantity", "add", "update",
]

# Limit-related endpoints
LIMIT_PATTERNS = [
    "limit", "max", "quota", "allocation", "restriction",
    "cap", "threshold", "allowance",
]


class InventoryManipulationCategory(BaseBusinessCategory):
    """Inventory manipulation testing category.

    Tests for:
    - Stock exhaustion attacks
    - Quantity limit bypass
    - Cart/basket manipulation
    - Reservation abuse
    - Purchase limit bypass
    """

    @property
    def name(self) -> str:
        return "inventory_manipulation"

    @property
    def priority_tier(self) -> int:
        return 2  # HIGH tier

    async def test(self, ctx: CategoryContext) -> CategoryResult:
        """Test for inventory manipulation vulnerabilities."""
        findings: list[dict[str, Any]] = []
        attempts = 0
        errors: list[str] = []

        if not ctx.allow_writes:
            return CategoryResult.not_found(0, ["Writes not allowed"])

        async with get_scan_client(timeout=ctx.timeout) as client:
            # Test inventory manipulation
            inv_findings = await self._test_inventory_manipulation(client, ctx)
            findings.extend(inv_findings)
            attempts += 15

            # Test limit bypass
            limit_findings = await self._test_limit_bypass(client, ctx)
            findings.extend(limit_findings)
            attempts += 10

            # Test cart/basket abuse
            cart_findings = await self._test_cart_abuse(client, ctx)
            findings.extend(cart_findings)
            attempts += 8

        if findings:
            return CategoryResult.vulnerable(findings, attempts)
        return CategoryResult.not_found(attempts, errors)

    async def _test_inventory_manipulation(
        self,
        client: "httpx.AsyncClient",
        ctx: CategoryContext,
    ) -> list[dict[str, Any]]:
        """Test for inventory manipulation vulnerabilities."""
        findings = []

        inv_endpoints = ctx.get_endpoints_matching(INVENTORY_PATTERNS)
        if not inv_endpoints:
            inv_endpoints = [
                urljoin(ctx.base_url, "/api/cart"),
                urljoin(ctx.base_url, "/api/basket"),
                urljoin(ctx.base_url, "/api/BasketItems"),
            ]

        # Manipulation payloads
        manipulation_payloads = [
            {"quantity": 999999, "name": "massive_quantity"},
            {"quantity": -10, "name": "negative_quantity"},
            {"quantity": 0, "name": "zero_quantity"},
            {"stock": 999999, "name": "stock_overflow"},
            {"reserved": 999999, "name": "reservation_abuse"},
        ]

        for endpoint in inv_endpoints[:5]:
            for payload in manipulation_payloads:
                payload_name = payload.pop("name", "unknown")
                await ctx.acquire_rate_limit()

                try:
                    # Try POST
                    response = await client.post(
                        endpoint,
                        json=payload,
                        headers={"Content-Type": "application/json", **ctx.auth_headers},
                    )

                    if response.status_code in (200, 201):
                        # Check if manipulation was accepted
                        if self._check_manipulation_success(response.text, payload):
                            severity = "CRITICAL" if "negative" in payload_name else "HIGH"
                            findings.append(self._create_finding(
                                name=f"Inventory Manipulation: {payload_name.replace('_', ' ').title()}",
                                severity=severity,
                                description=(
                                    f"Inventory manipulation detected at {endpoint}. "
                                    f"The application accepted {payload}, which could lead to "
                                    f"stock depletion, negative inventory, or reservation abuse."
                                ),
                                host=ctx.host,
                                endpoint=endpoint,
                                evidence=[
                                    f"Attack: {payload_name}",
                                    f"Payload: {payload}",
                                    f"Response: {response.text[:500]}",
                                ],
                                cvss_score=8.5 if severity == "CRITICAL" else 7.0,
                                cwe_id="CWE-20",
                                metadata={"attack_type": payload_name}
                            ))
                            logger.info(f"[BizLogic] Inventory manipulation: {payload_name}")

                except asyncio.TimeoutError:
                    pass
                except Exception as e:
                    logger.debug(f"[BizLogic-Inv] Error: {e}")

                payload["name"] = payload_name

        return findings

    async def _test_limit_bypass(
        self,
        client: "httpx.AsyncClient",
        ctx: CategoryContext,
    ) -> list[dict[str, Any]]:
        """Test for purchase/quantity limit bypass."""
        findings = []

        # Find endpoints with limits
        limit_endpoints = ctx.get_endpoints_matching(LIMIT_PATTERNS + ["cart", "order", "purchase"])

        # Limit bypass payloads
        bypass_payloads = [
            {"quantity": 100, "bypass_limit": True},
            {"quantity": 999, "override_max": True},
            {"items": [{"id": 1, "qty": 50}, {"id": 1, "qty": 50}]},  # Split to bypass
            {"quantity": "100", "type": "string"},  # Type confusion
        ]

        for endpoint in limit_endpoints[:5]:
            for payload in bypass_payloads:
                await ctx.acquire_rate_limit()

                try:
                    response = await client.post(
                        endpoint,
                        json=payload,
                        headers={"Content-Type": "application/json", **ctx.auth_headers},
                    )

                    if response.status_code in (200, 201):
                        resp_lower = response.text.lower()
                        # Check for bypass indicators
                        if "limit" not in resp_lower or "exceed" not in resp_lower:
                            if "success" in resp_lower or "added" in resp_lower:
                                findings.append(self._create_finding(
                                    name="Purchase Limit Bypass",
                                    severity="HIGH",
                                    description=(
                                        f"Limit bypass detected at {endpoint}. "
                                        f"Purchase/quantity limits can be bypassed, "
                                        f"allowing excessive ordering or stock manipulation."
                                    ),
                                    host=ctx.host,
                                    endpoint=endpoint,
                                    evidence=[
                                        f"Payload: {payload}",
                                        f"Response: {response.text[:300]}",
                                    ],
                                    cvss_score=7.5,
                                    cwe_id="CWE-770",
                                ))
                                break

                except asyncio.TimeoutError:
                    pass
                except Exception as e:
                    logger.debug(f"[BizLogic-Limit] Error: {e}")

        return findings

    async def _test_cart_abuse(
        self,
        client: "httpx.AsyncClient",
        ctx: CategoryContext,
    ) -> list[dict[str, Any]]:
        """Test for cart/basket abuse vulnerabilities."""
        findings = []

        cart_endpoints = ctx.get_endpoints_matching(["cart", "basket"])

        for endpoint in cart_endpoints[:3]:
            # Test accessing other users' carts
            other_cart_ids = ["1", "2", "admin", "0"]

            for cart_id in other_cart_ids:
                await ctx.acquire_rate_limit()

                try:
                    test_url = f"{endpoint}/{cart_id}"
                    response = await client.get(test_url, headers=ctx.auth_headers)

                    if response.status_code == 200:
                        resp_lower = response.text.lower()
                        # Check for other user's cart data
                        if any(kw in resp_lower for kw in ["item", "product", "quantity", "price"]):
                            findings.append(self._create_finding(
                                name="Cart/Basket IDOR",
                                severity="HIGH",
                                description=(
                                    f"Cart IDOR detected at {test_url}. "
                                    f"Access to other users' shopping carts is possible, "
                                    f"potentially exposing items, prices, and user behavior."
                                ),
                                host=ctx.host,
                                endpoint=test_url,
                                evidence=[
                                    f"Cart ID accessed: {cart_id}",
                                    f"Response status: {response.status_code}",
                                    f"Response length: {len(response.text)}",
                                ],
                                cvss_score=7.0,
                                cwe_id="CWE-639",
                                metadata={"cart_id": cart_id}
                            ))
                            break

                except asyncio.TimeoutError:
                    pass
                except Exception as e:
                    logger.debug(f"[BizLogic-Cart] Error: {e}")

        return findings

    def _check_manipulation_success(
        self,
        response_text: str,
        payload: dict[str, Any],
    ) -> bool:
        """Check if inventory manipulation was successful."""
        resp_lower = response_text.lower()

        # Check for error indicators (manipulation failed)
        if any(kw in resp_lower for kw in ["error", "invalid", "rejected", "limit", "maximum"]):
            return False

        # Check for success indicators
        if any(kw in resp_lower for kw in ["success", "added", "updated", "created"]):
            return True

        # Check if negative quantity was accepted
        if "quantity" in payload and payload["quantity"] < 0:
            if "error" not in resp_lower:
                return True

        return False


__all__ = ["InventoryManipulationCategory"]
