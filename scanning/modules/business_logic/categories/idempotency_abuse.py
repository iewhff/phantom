"""
Business Logic Scanner - Idempotency Abuse Category.

Tests for replay attacks, idempotency key bypass,
and time-based business rule bypass vulnerabilities.

Extracted from business_logic_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

import asyncio
import time
import uuid
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


# Endpoints likely to have idempotency requirements
IDEMPOTENCY_PATTERNS = [
    "payment", "transfer", "order", "checkout", "purchase",
    "redeem", "claim", "withdraw", "deposit", "submit",
]

# Time-sensitive endpoints
TIME_SENSITIVE_PATTERNS = [
    "coupon", "promo", "discount", "offer", "deal",
    "trial", "subscription", "sale", "flash",
]


class IdempotencyAbuseCategory(BaseBusinessCategory):
    """Idempotency and time-based bypass testing category.

    Tests for:
    - Idempotency key bypass/reuse
    - Transaction replay attacks
    - Time-based business rule bypass
    - Expired token/coupon reuse
    - Rate limit time window abuse
    """

    @property
    def name(self) -> str:
        return "idempotency_abuse"

    @property
    def priority_tier(self) -> int:
        return 2  # HIGH tier

    async def test(self, ctx: CategoryContext) -> CategoryResult:
        """Test for idempotency and time-based vulnerabilities."""
        findings: list[dict[str, Any]] = []
        attempts = 0
        errors: list[str] = []

        if not ctx.allow_writes:
            return CategoryResult.not_found(0, ["Writes not allowed"])

        async with get_scan_client(timeout=ctx.timeout) as client:
            # Test idempotency key abuse
            idem_findings = await self._test_idempotency_abuse(client, ctx)
            findings.extend(idem_findings)
            attempts += 15

            # Test time-based bypass
            time_findings = await self._test_time_based_bypass(client, ctx)
            findings.extend(time_findings)
            attempts += 10

            # Test replay attacks
            replay_findings = await self._test_replay_attacks(client, ctx)
            findings.extend(replay_findings)
            attempts += 8

        if findings:
            return CategoryResult.vulnerable(findings, attempts)
        return CategoryResult.not_found(attempts, errors)

    async def _test_idempotency_abuse(
        self,
        client: "httpx.AsyncClient",
        ctx: CategoryContext,
    ) -> list[dict[str, Any]]:
        """Test for idempotency key bypass vulnerabilities."""
        findings = []

        idem_endpoints = ctx.get_endpoints_matching(IDEMPOTENCY_PATTERNS)

        for endpoint in idem_endpoints[:5]:
            await ctx.acquire_rate_limit()

            # Generate idempotency key
            idem_key = str(uuid.uuid4())
            test_payload = {"amount": 100, "action": "test"}

            try:
                # First request with idempotency key
                headers = {
                    "Content-Type": "application/json",
                    "Idempotency-Key": idem_key,
                    "X-Idempotency-Key": idem_key,
                    "X-Request-Id": idem_key,
                    **ctx.auth_headers,
                }

                response1 = await client.post(endpoint, json=test_payload, headers=headers)

                if response1.status_code not in (200, 201):
                    continue

                # Wait briefly
                await asyncio.sleep(0.5)
                await ctx.acquire_rate_limit()

                # Second request with SAME idempotency key
                response2 = await client.post(endpoint, json=test_payload, headers=headers)

                # If both succeed with different effects, idempotency is broken
                if response2.status_code in (200, 201):
                    # Check if responses indicate duplicate processing
                    if response1.text != response2.text:
                        findings.append(self._create_finding(
                            name="Idempotency Key Bypass",
                            severity="HIGH",
                            description=(
                                f"Idempotency key bypass detected at {endpoint}. "
                                f"Duplicate requests with the same idempotency key "
                                f"were processed separately, enabling replay attacks."
                            ),
                            host=ctx.host,
                            endpoint=endpoint,
                            evidence=[
                                f"Idempotency key: {idem_key}",
                                f"Response 1 length: {len(response1.text)}",
                                f"Response 2 length: {len(response2.text)}",
                                "Responses differ - duplicate processing confirmed",
                            ],
                            cvss_score=8.0,
                            cwe_id="CWE-352",
                            metadata={"idempotency_key": idem_key}
                        ))
                        logger.info(f"[BizLogic] Idempotency bypass at {endpoint}")

            except asyncio.TimeoutError:
                pass
            except Exception as e:
                logger.debug(f"[BizLogic-Idem] Error: {e}")

        return findings

    async def _test_time_based_bypass(
        self,
        client: "httpx.AsyncClient",
        ctx: CategoryContext,
    ) -> list[dict[str, Any]]:
        """Test for time-based business rule bypass."""
        findings = []

        time_endpoints = ctx.get_endpoints_matching(TIME_SENSITIVE_PATTERNS)

        # Test payloads with manipulated timestamps
        time_payloads = [
            {"timestamp": 0, "code": "EXPIRED"},  # Unix epoch
            {"timestamp": int(time.time()) - 86400 * 365, "code": "OLDCODE"},  # 1 year ago
            {"valid_until": "2099-12-31", "code": "FUTURE"},  # Far future
            {"expires_at": None, "code": "NOEXPIRY"},  # No expiry
        ]

        for endpoint in time_endpoints[:5]:
            for payload in time_payloads:
                await ctx.acquire_rate_limit()

                try:
                    response = await client.post(
                        endpoint,
                        json=payload,
                        headers={"Content-Type": "application/json", **ctx.auth_headers},
                    )

                    if response.status_code == 200:
                        resp_lower = response.text.lower()
                        # Check if time manipulation worked
                        if "success" in resp_lower or "applied" in resp_lower or "valid" in resp_lower:
                            findings.append(self._create_finding(
                                name="Time-Based Business Rule Bypass",
                                severity="MEDIUM",
                                description=(
                                    f"Time-based bypass detected at {endpoint}. "
                                    f"Manipulated timestamp/expiry values were accepted, "
                                    f"potentially allowing use of expired or future-dated items."
                                ),
                                host=ctx.host,
                                endpoint=endpoint,
                                evidence=[
                                    f"Payload: {payload}",
                                    f"Response status: {response.status_code}",
                                    f"Response: {response.text[:300]}",
                                ],
                                cvss_score=6.5,
                                cwe_id="CWE-840",
                                metadata={"time_payload": payload}
                            ))
                            break

                except asyncio.TimeoutError:
                    pass
                except Exception as e:
                    logger.debug(f"[BizLogic-Time] Error: {e}")

        return findings

    async def _test_replay_attacks(
        self,
        client: "httpx.AsyncClient",
        ctx: CategoryContext,
    ) -> list[dict[str, Any]]:
        """Test for transaction replay vulnerabilities."""
        findings = []

        replay_endpoints = ctx.get_endpoints_matching(["redeem", "claim", "use", "apply"])

        for endpoint in replay_endpoints[:3]:
            await ctx.acquire_rate_limit()

            # Create a "used" token/code scenario
            test_payload = {"code": "TESTCODE", "action": "redeem"}

            try:
                # First redemption
                response1 = await client.post(
                    endpoint,
                    json=test_payload,
                    headers={"Content-Type": "application/json", **ctx.auth_headers},
                )

                if response1.status_code not in (200, 201):
                    continue

                await asyncio.sleep(0.3)
                await ctx.acquire_rate_limit()

                # Replay the same request
                response2 = await client.post(
                    endpoint,
                    json=test_payload,
                    headers={"Content-Type": "application/json", **ctx.auth_headers},
                )

                # Both succeeded = replay vulnerability
                if response2.status_code in (200, 201):
                    resp1_lower = response1.text.lower()
                    resp2_lower = response2.text.lower()

                    # Check if both indicate success
                    if ("success" in resp1_lower or "redeemed" in resp1_lower) and \
                       ("success" in resp2_lower or "redeemed" in resp2_lower):
                        findings.append(self._create_finding(
                            name="Transaction Replay Vulnerability",
                            severity="HIGH",
                            description=(
                                f"Transaction replay detected at {endpoint}. "
                                f"The same redemption request can be sent multiple times, "
                                f"enabling double-spend or coupon reuse attacks."
                            ),
                            host=ctx.host,
                            endpoint=endpoint,
                            evidence=[
                                f"Payload: {test_payload}",
                                f"First response: {response1.status_code}",
                                f"Replay response: {response2.status_code}",
                                "Both requests succeeded",
                            ],
                            cvss_score=8.5,
                            cwe_id="CWE-294",
                        ))
                        logger.info(f"[BizLogic] Replay vulnerability at {endpoint}")

            except asyncio.TimeoutError:
                pass
            except Exception as e:
                logger.debug(f"[BizLogic-Replay] Error: {e}")

        return findings


__all__ = ["IdempotencyAbuseCategory"]
