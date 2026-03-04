"""
Business Logic Scanner - IDOR Testing Category.

Tests for Insecure Direct Object Reference, account enumeration,
and response fingerprinting vulnerabilities.

Extracted from business_logic_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

import asyncio
import hashlib
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


# IDOR test endpoints
IDOR_PATTERNS = [
    "user", "profile", "account", "basket", "cart", "order",
    "document", "file", "invoice", "transaction", "message",
]

# Enumeration endpoints
ENUM_PATTERNS = [
    "login", "signin", "register", "signup", "forgot", "reset",
    "email", "username", "check", "exist", "validate",
]


class IDORTestingCategory(BaseBusinessCategory):
    """IDOR and enumeration testing category.

    Tests for:
    - Insecure Direct Object Reference
    - Account enumeration via error messages
    - Response fingerprinting for user enumeration
    - Basket/cart IDOR
    - Document/resource IDOR
    """

    @property
    def name(self) -> str:
        return "idor_testing"

    @property
    def priority_tier(self) -> int:
        return 2  # HIGH tier

    async def test(self, ctx: CategoryContext) -> CategoryResult:
        """Test for IDOR and enumeration vulnerabilities."""
        findings: list[dict[str, Any]] = []
        attempts = 0
        errors: list[str] = []

        async with get_scan_client(timeout=ctx.timeout) as client:
            # Test account enumeration
            enum_findings = await self._test_account_enumeration(client, ctx)
            findings.extend(enum_findings)
            attempts += 10

            # Test response fingerprinting
            fp_findings = await self._test_response_fingerprinting(client, ctx)
            findings.extend(fp_findings)
            attempts += 8

            # Test IDOR on resource endpoints
            idor_findings = await self._test_resource_idor(client, ctx)
            findings.extend(idor_findings)
            attempts += 12

        if findings:
            return CategoryResult.vulnerable(findings, attempts)
        return CategoryResult.not_found(attempts, errors)

    async def _test_account_enumeration(
        self,
        client: "httpx.AsyncClient",
        ctx: CategoryContext,
    ) -> list[dict[str, Any]]:
        """Test for account enumeration via error messages."""
        findings = []

        enum_endpoints = ctx.get_endpoints_matching(ENUM_PATTERNS)
        if not enum_endpoints:
            enum_endpoints = [
                urljoin(ctx.base_url, "/api/login"),
                urljoin(ctx.base_url, "/login"),
                urljoin(ctx.base_url, "/api/forgot-password"),
            ]

        # Test payloads for enumeration
        test_cases = [
            {"email": "definitely_not_real_user@test.com", "password": "test123"},
            {"email": "admin@example.com", "password": "wrong"},
            {"username": "admin", "password": "wrong"},
            {"username": "nonexistent_user_12345", "password": "test"},
        ]

        responses_by_existence = {"exists": [], "not_exists": []}

        for endpoint in enum_endpoints[:3]:
            for payload in test_cases[:2]:
                await ctx.acquire_rate_limit()

                try:
                    response = await client.post(
                        endpoint,
                        json=payload,
                        headers={"Content-Type": "application/json", **ctx.auth_headers},
                    )

                    resp_hash = hashlib.md5(response.text.encode()).hexdigest()
                    resp_len = len(response.text)

                    # Categorize response
                    resp_lower = response.text.lower()
                    if any(kw in resp_lower for kw in ["not found", "doesn't exist", "no user", "invalid user"]):
                        responses_by_existence["not_exists"].append((resp_hash, resp_len, response.status_code))
                    elif any(kw in resp_lower for kw in ["incorrect password", "wrong password", "invalid password"]):
                        responses_by_existence["exists"].append((resp_hash, resp_len, response.status_code))

                except asyncio.TimeoutError:
                    pass
                except Exception as e:
                    logger.debug(f"[BizLogic-Enum] Error: {e}")

            # Check if responses differ based on user existence
            if responses_by_existence["exists"] and responses_by_existence["not_exists"]:
                exists_hashes = set(h for h, _, _ in responses_by_existence["exists"])
                not_exists_hashes = set(h for h, _, _ in responses_by_existence["not_exists"])

                if exists_hashes != not_exists_hashes:
                    findings.append(self._create_finding(
                        name="Account Enumeration via Error Messages",
                        severity="MEDIUM",
                        description=(
                            f"Account enumeration detected at {endpoint}. "
                            f"Different error messages for existing vs non-existing accounts "
                            f"allow attackers to discover valid usernames."
                        ),
                        host=ctx.host,
                        endpoint=endpoint,
                        evidence=[
                            f"Existing account response hash: {list(exists_hashes)[0][:8]}",
                            f"Non-existing account response hash: {list(not_exists_hashes)[0][:8]}",
                            "Different responses indicate account existence",
                        ],
                        cvss_score=5.3,
                        cwe_id="CWE-204",
                    ))
                    logger.info(f"[BizLogic] Account enumeration at {endpoint}")

        return findings

    async def _test_response_fingerprinting(
        self,
        client: "httpx.AsyncClient",
        ctx: CategoryContext,
    ) -> list[dict[str, Any]]:
        """Test for response fingerprinting vulnerabilities."""
        findings = []

        # Test endpoints that might leak information
        test_endpoints = ctx.get_endpoints_matching(["user", "profile", "account", "check"])

        for endpoint in test_endpoints[:5]:
            response_patterns = []

            # Send requests with different IDs
            for test_id in ["1", "2", "9999", "admin", "test"]:
                await ctx.acquire_rate_limit()

                try:
                    test_url = f"{endpoint}/{test_id}" if not endpoint.endswith("/") else f"{endpoint}{test_id}"
                    response = await client.get(test_url, headers=ctx.auth_headers)

                    pattern = {
                        "id": test_id,
                        "status": response.status_code,
                        "length": len(response.text),
                        "hash": hashlib.md5(response.text.encode()).hexdigest()[:8],
                    }
                    response_patterns.append(pattern)

                except asyncio.TimeoutError:
                    pass
                except Exception as e:
                    logger.debug(f"[BizLogic-FP] Error: {e}")

            # Analyze patterns for fingerprinting
            if len(response_patterns) >= 3:
                statuses = set(p["status"] for p in response_patterns)
                lengths = set(p["length"] for p in response_patterns)

                # Different status codes or significantly different lengths
                # indicate potential fingerprinting
                if len(statuses) > 1 or (max(lengths) - min(lengths) > 100):
                    findings.append(self._create_finding(
                        name="Response Fingerprinting for Enumeration",
                        severity="MEDIUM",
                        description=(
                            f"Response fingerprinting detected at {endpoint}. "
                            f"Different responses for different resource IDs allow "
                            f"attackers to enumerate valid resources."
                        ),
                        host=ctx.host,
                        endpoint=endpoint,
                        evidence=[
                            f"Status codes observed: {statuses}",
                            f"Response length range: {min(lengths)}-{max(lengths)}",
                            f"Patterns: {response_patterns[:3]}",
                        ],
                        cvss_score=5.0,
                        cwe_id="CWE-204",
                        metadata={"patterns": response_patterns}
                    ))

        return findings

    async def _test_resource_idor(
        self,
        client: "httpx.AsyncClient",
        ctx: CategoryContext,
    ) -> list[dict[str, Any]]:
        """Test for IDOR on resource endpoints."""
        findings = []

        idor_endpoints = ctx.get_endpoints_matching(IDOR_PATTERNS)

        for endpoint in idor_endpoints[:5]:
            await ctx.acquire_rate_limit()

            # Try accessing different resource IDs
            test_ids = ["1", "2", "100", "admin"]

            for test_id in test_ids:
                try:
                    test_url = f"{endpoint}/{test_id}"
                    response = await client.get(test_url, headers=ctx.auth_headers)

                    # Check for IDOR indicators
                    if response.status_code == 200:
                        resp_lower = response.text.lower()

                        # Look for sensitive data exposure
                        sensitive_indicators = [
                            "email", "password", "phone", "address",
                            "ssn", "credit", "card", "balance",
                        ]

                        exposed_fields = [ind for ind in sensitive_indicators if ind in resp_lower]

                        if exposed_fields:
                            findings.append(self._create_finding(
                                name=f"Potential IDOR: Resource Access",
                                severity="HIGH",
                                description=(
                                    f"Potential IDOR detected at {test_url}. "
                                    f"Direct access to resource ID {test_id} returned sensitive data. "
                                    f"Exposed fields: {', '.join(exposed_fields)}"
                                ),
                                host=ctx.host,
                                endpoint=test_url,
                                evidence=[
                                    f"Resource ID: {test_id}",
                                    f"Status: {response.status_code}",
                                    f"Exposed fields: {exposed_fields}",
                                ],
                                cvss_score=7.5,
                                cwe_id="CWE-639",
                                metadata={"resource_id": test_id, "exposed_fields": exposed_fields}
                            ))
                            break  # Found IDOR, don't need to test more IDs

                except asyncio.TimeoutError:
                    pass
                except Exception as e:
                    logger.debug(f"[BizLogic-IDOR] Error: {e}")

        return findings


__all__ = ["IDORTestingCategory"]
