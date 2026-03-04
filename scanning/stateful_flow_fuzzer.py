"""
Stateful Flow Fuzzer - Multi-Step Business Flow Testing

Tests complex multi-step workflows for vulnerabilities:
- Checkout flows: cart → shipping → payment → confirm
- Authentication flows: login → 2FA → session
- Registration flows: signup → verify → activate
- Transaction flows: initiate → authorize → execute

Attack Strategies:
1. Step Skipping: Jump directly to final step
2. Step Repetition: Repeat steps for double-charge/credit
3. Parameter Pollution: Inject values between steps
4. State Manipulation: Modify session state mid-flow
5. Race Conditions: Parallel step execution
6. Rollback Abuse: Partial completion then cancel

Author: PHANTOM AI
Version: 1.0.0
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import random
import ssl
import string
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Callable
from urllib.parse import urljoin, urlparse

import aiohttp

from utils.logger import get_logger

if TYPE_CHECKING:
    from utils.rate_limiter import RateLimiter

logger = get_logger(__name__)


class FlowType(Enum):
    """Types of business flows to test."""
    CHECKOUT = "checkout"
    AUTHENTICATION = "authentication"
    REGISTRATION = "registration"
    PAYMENT = "payment"
    TRANSFER = "transfer"
    SUBSCRIPTION = "subscription"
    ORDER = "order"
    REFUND = "refund"
    PASSWORD_RESET = "password_reset"
    MFA_ENROLLMENT = "mfa_enrollment"
    CUSTOM = "custom"


class AttackType(Enum):
    """Types of flow attacks."""
    STEP_SKIP = auto()           # Skip intermediate steps
    STEP_REPEAT = auto()         # Repeat a step multiple times
    STEP_REORDER = auto()        # Execute steps out of order
    PARAM_POLLUTION = auto()     # Inject params between steps
    STATE_MANIPULATION = auto()  # Modify state mid-flow
    RACE_CONDITION = auto()      # Parallel execution
    ROLLBACK_ABUSE = auto()      # Partial completion + cancel
    VALUE_MANIPULATION = auto()  # Change values between steps
    TOKEN_REPLAY = auto()        # Replay tokens from previous flows
    SESSION_FIXATION = auto()    # Fix session before auth


@dataclass
class FlowStep:
    """Represents a single step in a business flow."""
    name: str
    endpoint: str
    method: str = "POST"
    data: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    expected_status: list[int] = field(default_factory=lambda: [200, 201, 302])
    extract_fields: list[str] = field(default_factory=list)  # Fields to extract for next step
    required_fields: list[str] = field(default_factory=list)  # Fields required from previous
    is_critical: bool = False  # If True, failure stops the flow
    delay_after: float = 0.0   # Delay after this step


@dataclass
class FlowState:
    """Maintains state during flow execution."""
    flow_id: str
    current_step: int = 0
    extracted_values: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    responses: list[dict] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    completed: bool = False
    error: str = ""


@dataclass
class FlowFinding:
    """Represents a vulnerability found in a flow."""
    flow_type: FlowType
    attack_type: AttackType
    severity: str
    description: str
    steps_involved: list[str]
    evidence: list[str]
    impact: str
    confidence: float
    metadata: dict = field(default_factory=dict)


# =============================================================================
# PREDEFINED FLOW TEMPLATES
# =============================================================================

FLOW_TEMPLATES = {
    FlowType.CHECKOUT: [
        FlowStep(
            name="add_to_cart",
            endpoint="/api/cart/add",
            method="POST",
            data={"product_id": "{product_id}", "quantity": 1},
            extract_fields=["cart_id", "item_id"],
        ),
        FlowStep(
            name="view_cart",
            endpoint="/api/cart",
            method="GET",
            extract_fields=["total", "items"],
        ),
        FlowStep(
            name="apply_coupon",
            endpoint="/api/cart/coupon",
            method="POST",
            data={"code": "{coupon_code}"},
            extract_fields=["discount", "new_total"],
        ),
        FlowStep(
            name="set_shipping",
            endpoint="/api/checkout/shipping",
            method="POST",
            data={"address_id": "{address_id}", "method": "standard"},
            extract_fields=["shipping_cost", "delivery_date"],
            is_critical=True,
        ),
        FlowStep(
            name="set_payment",
            endpoint="/api/checkout/payment",
            method="POST",
            data={"payment_method": "card", "card_token": "{card_token}"},
            extract_fields=["payment_id", "amount"],
            is_critical=True,
        ),
        FlowStep(
            name="confirm_order",
            endpoint="/api/checkout/confirm",
            method="POST",
            data={"cart_id": "{cart_id}", "payment_id": "{payment_id}"},
            extract_fields=["order_id", "confirmation_number"],
            is_critical=True,
        ),
    ],

    FlowType.AUTHENTICATION: [
        FlowStep(
            name="login_start",
            endpoint="/api/auth/login",
            method="POST",
            data={"username": "{username}", "password": "{password}"},
            extract_fields=["session_token", "mfa_required", "mfa_token"],
        ),
        FlowStep(
            name="mfa_verify",
            endpoint="/api/auth/mfa/verify",
            method="POST",
            data={"mfa_token": "{mfa_token}", "code": "{mfa_code}"},
            extract_fields=["access_token", "refresh_token"],
            is_critical=True,
        ),
        FlowStep(
            name="session_create",
            endpoint="/api/auth/session",
            method="POST",
            data={"access_token": "{access_token}"},
            extract_fields=["session_id", "user_id"],
        ),
    ],

    FlowType.REGISTRATION: [
        FlowStep(
            name="check_availability",
            endpoint="/api/users/check",
            method="POST",
            data={"username": "{username}", "email": "{email}"},
            extract_fields=["available"],
        ),
        FlowStep(
            name="register",
            endpoint="/api/users/register",
            method="POST",
            data={"username": "{username}", "email": "{email}", "password": "{password}"},
            extract_fields=["user_id", "verification_token"],
            is_critical=True,
        ),
        FlowStep(
            name="verify_email",
            endpoint="/api/users/verify",
            method="POST",
            data={"token": "{verification_token}"},
            extract_fields=["verified"],
        ),
        FlowStep(
            name="complete_profile",
            endpoint="/api/users/profile",
            method="PUT",
            data={"name": "{name}", "phone": "{phone}"},
            extract_fields=["profile_complete"],
        ),
    ],

    FlowType.PAYMENT: [
        FlowStep(
            name="initiate_payment",
            endpoint="/api/payments/initiate",
            method="POST",
            data={"amount": "{amount}", "currency": "{currency}"},
            extract_fields=["payment_id", "client_secret"],
            is_critical=True,
        ),
        FlowStep(
            name="authorize_payment",
            endpoint="/api/payments/authorize",
            method="POST",
            data={"payment_id": "{payment_id}", "card_token": "{card_token}"},
            extract_fields=["authorization_code"],
            is_critical=True,
        ),
        FlowStep(
            name="capture_payment",
            endpoint="/api/payments/capture",
            method="POST",
            data={"payment_id": "{payment_id}", "authorization_code": "{authorization_code}"},
            extract_fields=["transaction_id", "receipt"],
            is_critical=True,
        ),
    ],

    FlowType.TRANSFER: [
        FlowStep(
            name="initiate_transfer",
            endpoint="/api/transfers/initiate",
            method="POST",
            data={"from_account": "{from_account}", "to_account": "{to_account}", "amount": "{amount}"},
            extract_fields=["transfer_id", "otp_token"],
            is_critical=True,
        ),
        FlowStep(
            name="verify_otp",
            endpoint="/api/transfers/verify-otp",
            method="POST",
            data={"transfer_id": "{transfer_id}", "otp": "{otp_code}"},
            extract_fields=["verified"],
            is_critical=True,
        ),
        FlowStep(
            name="confirm_transfer",
            endpoint="/api/transfers/confirm",
            method="POST",
            data={"transfer_id": "{transfer_id}"},
            extract_fields=["confirmation_id", "new_balance"],
            is_critical=True,
        ),
    ],

    FlowType.SUBSCRIPTION: [
        FlowStep(
            name="select_plan",
            endpoint="/api/subscriptions/plans/{plan_id}",
            method="GET",
            extract_fields=["plan_id", "price", "features"],
        ),
        FlowStep(
            name="create_subscription",
            endpoint="/api/subscriptions",
            method="POST",
            data={"plan_id": "{plan_id}", "payment_method": "{payment_method}"},
            extract_fields=["subscription_id", "trial_end"],
            is_critical=True,
        ),
        FlowStep(
            name="activate_subscription",
            endpoint="/api/subscriptions/{subscription_id}/activate",
            method="POST",
            extract_fields=["active", "next_billing"],
        ),
    ],

    FlowType.REFUND: [
        FlowStep(
            name="request_refund",
            endpoint="/api/refunds/request",
            method="POST",
            data={"order_id": "{order_id}", "reason": "{reason}"},
            extract_fields=["refund_id", "status"],
            is_critical=True,
        ),
        FlowStep(
            name="approve_refund",
            endpoint="/api/refunds/{refund_id}/approve",
            method="POST",
            extract_fields=["approved", "amount"],
        ),
        FlowStep(
            name="process_refund",
            endpoint="/api/refunds/{refund_id}/process",
            method="POST",
            extract_fields=["processed", "transaction_id"],
            is_critical=True,
        ),
    ],
}


class StatefulFlowFuzzer:
    """
    Fuzzer for multi-step business flows.

    Tests flows by:
    1. Learning normal flow execution
    2. Applying attack mutations
    3. Detecting unexpected behavior
    """

    def __init__(
        self,
        base_url: str,
        auth_headers: dict | None = None,
        timeout: float = 15.0,
    ):
        self.base_url = base_url.rstrip('/')
        self.auth_headers = auth_headers or {}
        self.timeout = timeout
        self._findings: list[FlowFinding] = []
        self._flow_cache: dict[str, FlowState] = {}

    async def fuzz_flow(
        self,
        flow_type: FlowType,
        rate_limiter: "RateLimiter",
        initial_values: dict | None = None,
        custom_steps: list[FlowStep] | None = None,
        attacks: list[AttackType] | None = None,
    ) -> list[FlowFinding]:
        """
        Fuzz a business flow with various attack strategies.

        Args:
            flow_type: Type of flow to test
            rate_limiter: Rate limiter
            initial_values: Initial values for flow variables
            custom_steps: Custom flow steps (overrides template)
            attacks: Specific attacks to test (None = all)

        Returns:
            List of findings
        """
        findings = []

        # Get flow steps
        steps = custom_steps or FLOW_TEMPLATES.get(flow_type, [])
        if not steps:
            logger.warning(f"[FlowFuzzer] No steps defined for {flow_type.value}")
            return findings

        logger.info(f"[FlowFuzzer] Testing {flow_type.value} flow with {len(steps)} steps")

        # Initialize values
        values = initial_values or {}
        values.setdefault("product_id", "1")
        values.setdefault("quantity", "1")
        values.setdefault("username", f"test_{int(time.time())}")
        values.setdefault("email", f"test_{int(time.time())}@test.local")
        values.setdefault("password", "Test123!")
        values.setdefault("amount", "100")
        values.setdefault("currency", "USD")

        # First, execute normal flow to establish baseline
        baseline_state = await self._execute_flow(
            steps, values, rate_limiter, "baseline"
        )

        if not baseline_state.completed:
            logger.warning(f"[FlowFuzzer] Baseline flow failed: {baseline_state.error}")
            # Continue anyway - partial execution may still reveal issues

        # Determine attacks to run
        attack_list = attacks or list(AttackType)

        # Run each attack type
        for attack_type in attack_list:
            try:
                attack_findings = await self._run_attack(
                    attack_type, flow_type, steps, values, baseline_state, rate_limiter
                )
                findings.extend(attack_findings)
            except Exception as e:
                logger.debug(f"[FlowFuzzer] Attack {attack_type.name} failed: {e}")

        self._findings.extend(findings)
        logger.info(f"[FlowFuzzer] Found {len(findings)} vulnerabilities in {flow_type.value}")

        return findings

    async def _execute_flow(
        self,
        steps: list[FlowStep],
        values: dict,
        rate_limiter: "RateLimiter",
        flow_id: str,
    ) -> FlowState:
        """Execute a flow and return final state."""
        state = FlowState(
            flow_id=flow_id,
            extracted_values=copy.deepcopy(values),
        )

        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            for i, step in enumerate(steps):
                state.current_step = i

                try:
                    await rate_limiter.acquire()

                    # Build URL with variable substitution
                    url = self._build_url(step.endpoint, state.extracted_values)

                    # Build request data
                    data = self._substitute_values(step.data, state.extracted_values)

                    # Build headers
                    headers = {**self.auth_headers, **step.headers, **state.headers}
                    headers["Content-Type"] = "application/json"

                    # Execute request
                    start_time = time.time()

                    if step.method == "GET":
                        async with session.get(url, headers=headers, ssl=ssl_ctx) as resp:
                            response = await self._process_response(resp, step, state)
                    elif step.method == "POST":
                        async with session.post(url, json=data, headers=headers, ssl=ssl_ctx) as resp:
                            response = await self._process_response(resp, step, state)
                    elif step.method == "PUT":
                        async with session.put(url, json=data, headers=headers, ssl=ssl_ctx) as resp:
                            response = await self._process_response(resp, step, state)
                    elif step.method == "DELETE":
                        async with session.delete(url, headers=headers, ssl=ssl_ctx) as resp:
                            response = await self._process_response(resp, step, state)
                    else:
                        continue

                    elapsed = time.time() - start_time

                    state.responses.append({
                        "step": step.name,
                        "status": response["status"],
                        "elapsed": elapsed,
                        "extracted": response.get("extracted", {}),
                    })

                    # Check if step succeeded
                    if response["status"] not in step.expected_status:
                        if step.is_critical:
                            state.error = f"Critical step {step.name} failed: {response['status']}"
                            return state
                        logger.debug(f"[FlowFuzzer] Step {step.name} returned {response['status']}")

                    # Delay if specified
                    if step.delay_after > 0:
                        await asyncio.sleep(step.delay_after)

                except Exception as e:
                    state.error = f"Step {step.name} error: {str(e)}"
                    if step.is_critical:
                        return state

        state.completed = True
        return state

    async def _process_response(
        self,
        response: aiohttp.ClientResponse,
        step: FlowStep,
        state: FlowState,
    ) -> dict:
        """Process response and extract values."""
        result = {
            "status": response.status,
            "headers": dict(response.headers),
            "extracted": {},
        }

        # Update cookies
        for cookie in response.cookies.values():
            state.cookies[cookie.key] = cookie.value

        # Try to parse JSON and extract fields
        try:
            body = await response.json()
            result["body"] = body

            for field in step.extract_fields:
                value = self._extract_field(body, field)
                if value is not None:
                    state.extracted_values[field] = value
                    result["extracted"][field] = value

        except (ValueError, TypeError):
            result["body"] = await response.text()

        return result

    def _extract_field(self, data: dict, field: str) -> Any:
        """Extract field from nested dict using dot notation."""
        if not isinstance(data, dict):
            return None

        parts = field.split('.')
        current = data

        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            elif isinstance(current, list) and part.isdigit():
                idx = int(part)
                if idx < len(current):
                    current = current[idx]
                else:
                    return None
            else:
                return None

        return current

    def _build_url(self, endpoint: str, values: dict) -> str:
        """Build URL with variable substitution."""
        url = endpoint
        for key, value in values.items():
            url = url.replace(f"{{{key}}}", str(value))
        return urljoin(self.base_url, url)

    def _substitute_values(self, data: dict, values: dict) -> dict:
        """Substitute {variable} placeholders in data."""
        result = {}
        for key, value in data.items():
            if isinstance(value, str):
                for var_name, var_value in values.items():
                    value = value.replace(f"{{{var_name}}}", str(var_value))
            result[key] = value
        return result

    async def _run_attack(
        self,
        attack_type: AttackType,
        flow_type: FlowType,
        steps: list[FlowStep],
        values: dict,
        baseline: FlowState,
        rate_limiter: "RateLimiter",
    ) -> list[FlowFinding]:
        """Run specific attack type against flow."""

        if attack_type == AttackType.STEP_SKIP:
            return await self._attack_step_skip(flow_type, steps, values, baseline, rate_limiter)

        elif attack_type == AttackType.STEP_REPEAT:
            return await self._attack_step_repeat(flow_type, steps, values, baseline, rate_limiter)

        elif attack_type == AttackType.STEP_REORDER:
            return await self._attack_step_reorder(flow_type, steps, values, baseline, rate_limiter)

        elif attack_type == AttackType.RACE_CONDITION:
            return await self._attack_race_condition(flow_type, steps, values, baseline, rate_limiter)

        elif attack_type == AttackType.VALUE_MANIPULATION:
            return await self._attack_value_manipulation(flow_type, steps, values, baseline, rate_limiter)

        elif attack_type == AttackType.ROLLBACK_ABUSE:
            return await self._attack_rollback_abuse(flow_type, steps, values, baseline, rate_limiter)

        return []

    async def _attack_step_skip(
        self,
        flow_type: FlowType,
        steps: list[FlowStep],
        values: dict,
        baseline: FlowState,
        rate_limiter: "RateLimiter",
    ) -> list[FlowFinding]:
        """Test skipping intermediate steps."""
        findings = []

        if len(steps) < 3:
            return findings

        # Try jumping directly to final step
        final_step = steps[-1]

        # Copy values from baseline (simulating knowledge of expected values)
        attack_values = {**values, **baseline.extracted_values}

        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            await rate_limiter.acquire()

            url = self._build_url(final_step.endpoint, attack_values)
            data = self._substitute_values(final_step.data, attack_values)
            headers = {**self.auth_headers, "Content-Type": "application/json"}

            try:
                async with session.post(url, json=data, headers=headers, ssl=ssl_ctx) as resp:
                    status = resp.status
                    body = await resp.text()

                    # Check if step succeeded without previous steps
                    if status in final_step.expected_status:
                        findings.append(FlowFinding(
                            flow_type=flow_type,
                            attack_type=AttackType.STEP_SKIP,
                            severity="CRITICAL",
                            description=(
                                f"Step skipping vulnerability: Final step '{final_step.name}' "
                                f"can be executed directly without completing intermediate steps"
                            ),
                            steps_involved=[steps[0].name, "...", final_step.name],
                            evidence=[
                                f"Skipped steps: {[s.name for s in steps[:-1]]}",
                                f"Final step returned: {status}",
                                f"Response length: {len(body)} bytes",
                            ],
                            impact="Attacker can bypass business logic validation and complete transactions without proper authorization",
                            confidence=90.0,
                            metadata={"skipped_steps": len(steps) - 1},
                        ))

            except Exception as e:
                logger.debug(f"[FlowFuzzer] Step skip attack failed: {e}")

        return findings

    async def _attack_step_repeat(
        self,
        flow_type: FlowType,
        steps: list[FlowStep],
        values: dict,
        baseline: FlowState,
        rate_limiter: "RateLimiter",
    ) -> list[FlowFinding]:
        """Test repeating critical steps (double-charge, double-credit)."""
        findings = []

        # Find critical steps (payment, confirmation, etc.)
        critical_steps = [s for s in steps if s.is_critical]
        if not critical_steps:
            return findings

        attack_values = {**values, **baseline.extracted_values}

        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            for step in critical_steps:
                await rate_limiter.acquire()

                url = self._build_url(step.endpoint, attack_values)
                data = self._substitute_values(step.data, attack_values)
                headers = {**self.auth_headers, "Content-Type": "application/json"}

                success_count = 0

                # Try executing the same step multiple times
                for attempt in range(3):
                    try:
                        async with session.post(url, json=data, headers=headers, ssl=ssl_ctx) as resp:
                            if resp.status in step.expected_status:
                                success_count += 1
                    except Exception:
                        pass
                    await rate_limiter.acquire()

                # If step succeeds multiple times, it's a vulnerability
                if success_count > 1:
                    findings.append(FlowFinding(
                        flow_type=flow_type,
                        attack_type=AttackType.STEP_REPEAT,
                        severity="CRITICAL" if "payment" in step.name.lower() or "transfer" in step.name.lower() else "HIGH",
                        description=(
                            f"Step repetition vulnerability: Critical step '{step.name}' "
                            f"can be executed {success_count} times"
                        ),
                        steps_involved=[step.name],
                        evidence=[
                            f"Step: {step.name}",
                            f"Successful executions: {success_count}/3",
                            f"Endpoint: {step.endpoint}",
                        ],
                        impact="Double-charge, double-credit, or duplicate transaction execution",
                        confidence=85.0,
                        metadata={"success_count": success_count},
                    ))

        return findings

    async def _attack_step_reorder(
        self,
        flow_type: FlowType,
        steps: list[FlowStep],
        values: dict,
        baseline: FlowState,
        rate_limiter: "RateLimiter",
    ) -> list[FlowFinding]:
        """Test executing steps out of order."""
        findings = []

        if len(steps) < 3:
            return findings

        # Try executing steps in reverse order
        reversed_steps = list(reversed(steps))
        attack_values = {**values, **baseline.extracted_values}

        state = await self._execute_flow(reversed_steps, attack_values, rate_limiter, "reorder")

        if state.completed:
            findings.append(FlowFinding(
                flow_type=flow_type,
                attack_type=AttackType.STEP_REORDER,
                severity="HIGH",
                description="Step reordering vulnerability: Flow completes with steps executed in reverse order",
                steps_involved=[s.name for s in reversed_steps],
                evidence=[
                    f"Original order: {[s.name for s in steps]}",
                    f"Executed order: {[s.name for s in reversed_steps]}",
                    f"Flow completed: {state.completed}",
                ],
                impact="Business logic bypass through step reordering",
                confidence=75.0,
            ))

        return findings

    async def _attack_race_condition(
        self,
        flow_type: FlowType,
        steps: list[FlowStep],
        values: dict,
        baseline: FlowState,
        rate_limiter: "RateLimiter",
    ) -> list[FlowFinding]:
        """Test race conditions in flow execution."""
        findings = []

        critical_steps = [s for s in steps if s.is_critical]
        if not critical_steps:
            return findings

        attack_values = {**values, **baseline.extracted_values}

        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            for step in critical_steps:
                url = self._build_url(step.endpoint, attack_values)
                data = self._substitute_values(step.data, attack_values)
                headers = {**self.auth_headers, "Content-Type": "application/json"}

                # Send multiple parallel requests
                async def make_request():
                    try:
                        async with session.post(url, json=data, headers=headers, ssl=ssl_ctx) as resp:
                            return resp.status, await resp.text()
                    except Exception:
                        return None, None

                # Execute 5 parallel requests
                tasks = [make_request() for _ in range(5)]
                results = await asyncio.gather(*tasks)

                # Analyze results
                success_count = sum(1 for status, _ in results if status and status in step.expected_status)

                if success_count > 1:
                    findings.append(FlowFinding(
                        flow_type=flow_type,
                        attack_type=AttackType.RACE_CONDITION,
                        severity="CRITICAL",
                        description=(
                            f"Race condition in critical step '{step.name}': "
                            f"{success_count}/5 parallel requests succeeded"
                        ),
                        steps_involved=[step.name],
                        evidence=[
                            f"Parallel requests: 5",
                            f"Successful: {success_count}",
                            f"Step: {step.name}",
                        ],
                        impact="Double-spend, duplicate transactions, or TOCTOU exploitation",
                        confidence=90.0,
                        metadata={"parallel_success": success_count},
                    ))

        return findings

    async def _attack_value_manipulation(
        self,
        flow_type: FlowType,
        steps: list[FlowStep],
        values: dict,
        baseline: FlowState,
        rate_limiter: "RateLimiter",
    ) -> list[FlowFinding]:
        """Test manipulating values between flow steps."""
        findings = []

        # Manipulation payloads for different fields
        manipulations = {
            "amount": [0, -1, -100, 0.01, 999999999],
            "quantity": [-1, 0, 999999],
            "price": [0, -1, 0.01],
            "discount": [100, 150, -50],
        }

        attack_values = {**values, **baseline.extracted_values}

        for field, payloads in manipulations.items():
            if field in attack_values:
                original_value = attack_values[field]

                for payload in payloads:
                    attack_values[field] = payload

                    state = await self._execute_flow(
                        steps, attack_values, rate_limiter, f"manipulate_{field}_{payload}"
                    )

                    if state.completed:
                        findings.append(FlowFinding(
                            flow_type=flow_type,
                            attack_type=AttackType.VALUE_MANIPULATION,
                            severity="CRITICAL" if payload < 0 or payload > 100000 else "HIGH",
                            description=(
                                f"Value manipulation accepted: {field} changed from "
                                f"{original_value} to {payload}"
                            ),
                            steps_involved=[s.name for s in steps],
                            evidence=[
                                f"Field: {field}",
                                f"Original: {original_value}",
                                f"Manipulated: {payload}",
                                f"Flow completed: {state.completed}",
                            ],
                            impact="Financial manipulation, negative balance, or business rule bypass",
                            confidence=85.0,
                            metadata={"field": field, "payload": payload},
                        ))

                attack_values[field] = original_value

        return findings

    async def _attack_rollback_abuse(
        self,
        flow_type: FlowType,
        steps: list[FlowStep],
        values: dict,
        baseline: FlowState,
        rate_limiter: "RateLimiter",
    ) -> list[FlowFinding]:
        """Test partial completion followed by cancellation."""
        findings = []

        # Execute partial flow (all steps except last)
        if len(steps) < 2:
            return findings

        partial_steps = steps[:-1]
        attack_values = {**values, **baseline.extracted_values}

        state = await self._execute_flow(partial_steps, attack_values, rate_limiter, "partial")

        if not state.error:
            # Try to cancel/rollback
            cancel_endpoints = [
                "/api/cart/clear",
                "/api/order/cancel",
                "/api/checkout/cancel",
                "/api/payment/cancel",
                "/api/transaction/rollback",
            ]

            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            timeout = aiohttp.ClientTimeout(total=self.timeout)

            async with aiohttp.ClientSession(timeout=timeout) as session:
                for cancel_endpoint in cancel_endpoints:
                    await rate_limiter.acquire()
                    url = urljoin(self.base_url, cancel_endpoint)

                    try:
                        async with session.post(
                            url,
                            json=state.extracted_values,
                            headers={**self.auth_headers, "Content-Type": "application/json"},
                            ssl=ssl_ctx,
                        ) as resp:
                            if resp.status in [200, 201, 204]:
                                findings.append(FlowFinding(
                                    flow_type=flow_type,
                                    attack_type=AttackType.ROLLBACK_ABUSE,
                                    severity="HIGH",
                                    description=(
                                        f"Rollback abuse: Partial flow completion followed by "
                                        f"successful cancellation at {cancel_endpoint}"
                                    ),
                                    steps_involved=[s.name for s in partial_steps] + ["cancel"],
                                    evidence=[
                                        f"Completed steps: {[s.name for s in partial_steps]}",
                                        f"Cancel endpoint: {cancel_endpoint}",
                                        f"Cancel status: {resp.status}",
                                    ],
                                    impact="State manipulation, partial refund abuse, or resource exhaustion",
                                    confidence=70.0,
                                ))
                                break

                    except Exception:
                        pass

        return findings

    def get_findings(self) -> list[FlowFinding]:
        """Get all findings from fuzzing."""
        return self._findings.copy()

    def clear_findings(self) -> None:
        """Clear all findings."""
        self._findings.clear()
