"""
Business Logic Scanner - Workflow Bypass Category.

Tests for state machine bypass, multi-step transaction abuse,
and workflow verification bypass vulnerabilities.

Extracted from business_logic_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

from utils.logger import get_logger
from utils.scan_client import get_scan_client

from scanning.modules.business_logic.business_base import (
    WorkflowState,
    VALID_TRANSITIONS,
    TransactionContext,
)
from scanning.modules.business_logic.categories.base import (
    BaseBusinessCategory,
    CategoryContext,
    CategoryResult,
)

if TYPE_CHECKING:
    import httpx

logger = get_logger(__name__)


# Workflow step patterns
WORKFLOW_PATTERNS = {
    "checkout": [
        ("cart", WorkflowState.CART_CREATED),
        ("address", WorkflowState.ADDRESS_SET),
        ("payment", WorkflowState.PAYMENT_PENDING),
        ("confirm", WorkflowState.ORDER_CONFIRMED),
    ],
    "registration": [
        ("register", WorkflowState.ACCOUNT_CREATED),
        ("verify", WorkflowState.EMAIL_PENDING),
        ("confirm", WorkflowState.EMAIL_VERIFIED),
    ],
    "password_reset": [
        ("forgot", WorkflowState.PASSWORD_RESET_REQUESTED),
        ("reset", WorkflowState.PASSWORD_RESET_COMPLETED),
    ],
}

# Endpoints for bypass testing
BYPASS_ENDPOINTS = [
    # Payment/checkout bypass
    ("checkout", "payment", "confirm", "complete"),
    # Verification bypass
    ("verify", "confirm", "activate", "enable"),
    # Admin bypass
    ("admin", "dashboard", "manage", "control"),
    # Step skip
    ("step2", "step3", "final", "submit"),
]


class WorkflowBypassCategory(BaseBusinessCategory):
    """Workflow bypass testing category.

    Tests for:
    - State machine bypass (skipping required steps)
    - Multi-step transaction abuse
    - Verification bypass (email, phone)
    - Payment step bypass
    - Admin/privileged access bypass
    """

    @property
    def name(self) -> str:
        return "workflow_bypass"

    @property
    def priority_tier(self) -> int:
        return 1  # CRITICAL tier

    async def test(self, ctx: CategoryContext) -> CategoryResult:
        """Test for workflow bypass vulnerabilities."""
        findings: list[dict[str, Any]] = []
        attempts = 0
        errors: list[str] = []

        async with get_scan_client(timeout=ctx.timeout) as client:
            # Test state machine bypass
            sm_findings = await self._test_state_machine_bypass(client, ctx)
            findings.extend(sm_findings)
            attempts += 10

            # Test workflow step skipping
            skip_findings = await self._test_step_skipping(client, ctx)
            findings.extend(skip_findings)
            attempts += 15

            # Test verification bypass
            verify_findings = await self._test_verification_bypass(client, ctx)
            findings.extend(verify_findings)
            attempts += 5

        if findings:
            return CategoryResult.vulnerable(findings, attempts)
        return CategoryResult.not_found(attempts, errors)

    async def _test_state_machine_bypass(
        self,
        client: "httpx.AsyncClient",
        ctx: CategoryContext,
    ) -> list[dict[str, Any]]:
        """Test for state machine bypass vulnerabilities."""
        findings = []

        # Test each workflow pattern
        for workflow_name, steps in WORKFLOW_PATTERNS.items():
            # Try to access final step directly (skip intermediate)
            if len(steps) < 2:
                continue

            final_step_pattern, final_state = steps[-1]
            final_endpoints = ctx.get_endpoints_matching([final_step_pattern])

            for endpoint in final_endpoints[:2]:
                await ctx.acquire_rate_limit()

                try:
                    # Try accessing final step without completing previous steps
                    response = await client.get(
                        endpoint,
                        headers=ctx.auth_headers,
                    )

                    # If we got a successful response without going through steps
                    if response.status_code == 200:
                        # Check if it's actually the protected content
                        if self._is_protected_content(response.text, workflow_name):
                            findings.append(self._create_finding(
                                name=f"State Machine Bypass: {workflow_name.title()}",
                                severity="CRITICAL",
                                description=(
                                    f"State machine bypass detected in {workflow_name} workflow. "
                                    f"Direct access to {final_step_pattern} step without completing "
                                    f"required previous steps is possible."
                                ),
                                host=ctx.host,
                                endpoint=endpoint,
                                evidence=[
                                    f"Workflow: {workflow_name}",
                                    f"Skipped to: {final_step_pattern}",
                                    f"Response status: {response.status_code}",
                                    f"Response length: {len(response.text)}",
                                ],
                                cvss_score=9.0,
                                cwe_id="CWE-841",
                                metadata={
                                    "workflow": workflow_name,
                                    "bypassed_state": final_state.name,
                                }
                            ))
                            logger.info(f"[BizLogic] State machine bypass: {workflow_name} at {endpoint}")

                except asyncio.TimeoutError:
                    pass
                except Exception as e:
                    logger.debug(f"[BizLogic-Workflow] Error: {e}")

        return findings

    async def _test_step_skipping(
        self,
        client: "httpx.AsyncClient",
        ctx: CategoryContext,
    ) -> list[dict[str, Any]]:
        """Test for step skipping vulnerabilities."""
        findings = []

        # Find multi-step endpoints (step1, step2, step3, etc.)
        for patterns in BYPASS_ENDPOINTS:
            endpoints = []
            for pattern in patterns:
                eps = ctx.get_endpoints_matching([pattern])
                endpoints.extend(eps[:1])

            if len(endpoints) < 2:
                continue

            # Try accessing later steps without earlier ones
            for i, endpoint in enumerate(endpoints[1:], 1):
                await ctx.acquire_rate_limit()

                try:
                    # Try POST to later step directly
                    response = await client.post(
                        endpoint,
                        json={"skip_validation": True, "step": i + 1},
                        headers={"Content-Type": "application/json", **ctx.auth_headers},
                    )

                    if response.status_code in (200, 201):
                        # Check if bypass was successful
                        resp_lower = response.text.lower()
                        if "success" in resp_lower or "complete" in resp_lower:
                            findings.append(self._create_finding(
                                name="Workflow Step Bypass",
                                severity="HIGH",
                                description=(
                                    f"Workflow step bypass detected. Direct access to step {i + 1} "
                                    f"at {endpoint} is possible without completing previous steps."
                                ),
                                host=ctx.host,
                                endpoint=endpoint,
                                evidence=[
                                    f"Step accessed: {i + 1}",
                                    f"Endpoint: {endpoint}",
                                    f"Response: {response.text[:300]}",
                                ],
                                cvss_score=8.0,
                                cwe_id="CWE-841",
                            ))

                except asyncio.TimeoutError:
                    pass
                except Exception as e:
                    logger.debug(f"[BizLogic-Step] Error: {e}")

        return findings

    async def _test_verification_bypass(
        self,
        client: "httpx.AsyncClient",
        ctx: CategoryContext,
    ) -> list[dict[str, Any]]:
        """Test for verification bypass (email, phone, etc.)."""
        findings = []

        # Verification endpoints
        verify_patterns = ["verify", "confirm", "activate", "validate"]
        verify_endpoints = ctx.get_endpoints_matching(verify_patterns)

        for endpoint in verify_endpoints[:3]:
            await ctx.acquire_rate_limit()

            # Try to verify with invalid/guessable token
            bypass_payloads = [
                {"token": "000000", "code": "000000"},
                {"token": "123456", "verified": True},
                {"code": "111111", "skip": True},
                {"verification_code": "", "force": True},
            ]

            for payload in bypass_payloads:
                try:
                    response = await client.post(
                        endpoint,
                        json=payload,
                        headers={"Content-Type": "application/json", **ctx.auth_headers},
                    )

                    if response.status_code == 200:
                        resp_lower = response.text.lower()
                        if "success" in resp_lower or "verified" in resp_lower:
                            findings.append(self._create_finding(
                                name="Verification Bypass",
                                severity="HIGH",
                                description=(
                                    f"Verification bypass detected at {endpoint}. "
                                    f"Invalid or guessable verification code was accepted."
                                ),
                                host=ctx.host,
                                endpoint=endpoint,
                                evidence=[
                                    f"Payload: {payload}",
                                    f"Response: {response.text[:300]}",
                                ],
                                cvss_score=8.5,
                                cwe_id="CWE-302",
                            ))
                            break

                except asyncio.TimeoutError:
                    pass
                except Exception as e:
                    logger.debug(f"[BizLogic-Verify] Error: {e}")

        return findings

    def _is_protected_content(self, content: str, workflow: str) -> bool:
        """Check if response contains protected workflow content."""
        content_lower = content.lower()

        # Check for workflow-specific indicators
        if workflow == "checkout":
            return any(kw in content_lower for kw in
                      ["order confirmed", "thank you", "receipt", "order number"])
        elif workflow == "registration":
            return any(kw in content_lower for kw in
                      ["welcome", "account created", "registration complete"])
        elif workflow == "password_reset":
            return any(kw in content_lower for kw in
                      ["password changed", "reset successful", "new password"])

        # Generic check
        return "success" in content_lower or "complete" in content_lower


__all__ = ["WorkflowBypassCategory"]
