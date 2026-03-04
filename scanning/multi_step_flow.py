"""
Multi-step Flow Support v1.0 - Navigate Complex Workflows Before Testing

PROBLEM:
Many vulnerabilities only appear after specific workflow navigation:
- Payment bypass: requires cart → checkout → payment flow
- Authorization bypass: requires role assignment → action
- Race conditions: require specific state setup
- Business logic: require multi-step process completion

Scanner tests endpoints in isolation → misses flow-dependent vulns.

SOLUTION:
1. Detect multi-step flows from discovered endpoints
2. Define flow navigation sequences
3. Execute flows to reach target states
4. Test vulnerabilities at each step after proper setup

Philosophy: "Test the flow, not just the endpoint."

Author: PHANTOM AI
Version: 1.0.0
"""

from __future__ import annotations

import asyncio
import re
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple, Callable
from enum import Enum
from urllib.parse import urljoin, urlparse
import logging

logger = logging.getLogger(__name__)


class FlowType(Enum):
    """Types of multi-step flows."""
    CHECKOUT = "checkout"
    REGISTRATION = "registration"
    AUTHENTICATION = "authentication"
    PASSWORD_RESET = "password_reset"
    MFA_SETUP = "mfa_setup"
    PAYMENT = "payment"
    ORDER = "order"
    SUBSCRIPTION = "subscription"
    PROFILE_UPDATE = "profile_update"
    FILE_UPLOAD = "file_upload"
    FORM_WIZARD = "form_wizard"
    APPROVAL = "approval"
    TRANSFER = "transfer"
    CUSTOM = "custom"


class StepStatus(Enum):
    """Status of a flow step."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class FlowStep:
    """Definition of a single step in a flow."""
    name: str
    url: str
    method: str = "GET"
    data: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    expected_status: List[int] = field(default_factory=lambda: [200, 201, 302])

    # Step behavior
    extract_fields: List[str] = field(default_factory=list)  # Fields to extract from response
    required_in_response: List[str] = field(default_factory=list)  # Must contain these
    forbidden_in_response: List[str] = field(default_factory=list)  # Must NOT contain these
    wait_seconds: float = 0.0  # Wait before executing

    # Extracted data
    extracted_data: Dict[str, str] = field(default_factory=dict)
    status: StepStatus = StepStatus.PENDING
    response_body: str = ""
    response_status: int = 0


@dataclass
class FlowDefinition:
    """Complete multi-step flow definition."""
    name: str
    flow_type: FlowType
    steps: List[FlowStep]
    description: str = ""

    # Flow state
    current_step: int = 0
    is_complete: bool = False
    accumulated_data: Dict[str, str] = field(default_factory=dict)

    # Test points (steps where we inject payloads)
    test_step_indices: List[int] = field(default_factory=list)

    def reset(self) -> None:
        """Reset flow to initial state."""
        self.current_step = 0
        self.is_complete = False
        self.accumulated_data.clear()
        for step in self.steps:
            step.status = StepStatus.PENDING
            step.extracted_data.clear()
            step.response_body = ""
            step.response_status = 0


@dataclass
class FlowExecutionResult:
    """Result of flow execution."""
    success: bool = False
    steps_completed: int = 0
    total_steps: int = 0
    failed_step: Optional[str] = None
    error: str = ""
    accumulated_data: Dict[str, str] = field(default_factory=dict)
    took_seconds: float = 0.0

    # For testing
    reached_test_points: List[int] = field(default_factory=list)


class MultiStepFlowEngine:
    """
    Execute multi-step flows and enable testing at each step.

    Usage:
        engine = MultiStepFlowEngine(http_client, auth_context)

        # Define a checkout flow
        checkout = engine.create_checkout_flow(base_url)

        # Execute up to payment step
        result = await engine.execute_to_step(checkout, "payment")

        # Now test payment endpoint with accumulated state
        test_data = result.accumulated_data
        # ... inject payloads using test_data context
    """

    # Flow patterns for auto-detection
    FLOW_PATTERNS: Dict[FlowType, Dict[str, List[str]]] = {
        FlowType.CHECKOUT: {
            "steps": ["cart", "shipping", "payment", "confirm", "complete"],
            "urls": [r"/cart", r"/checkout", r"/shipping", r"/payment", r"/order"],
        },
        FlowType.REGISTRATION: {
            "steps": ["register", "verify", "profile", "complete"],
            "urls": [r"/register", r"/signup", r"/verify", r"/profile"],
        },
        FlowType.AUTHENTICATION: {
            "steps": ["login", "mfa", "verify"],
            "urls": [r"/login", r"/auth", r"/mfa", r"/verify", r"/2fa"],
        },
        FlowType.PASSWORD_RESET: {
            "steps": ["request", "verify", "reset", "complete"],
            "urls": [r"/forgot", r"/reset", r"/password", r"/verify-email"],
        },
        FlowType.PAYMENT: {
            "steps": ["select", "details", "confirm", "process"],
            "urls": [r"/pay", r"/payment", r"/billing", r"/process"],
        },
        FlowType.SUBSCRIPTION: {
            "steps": ["plan", "payment", "confirm", "activate"],
            "urls": [r"/subscribe", r"/plan", r"/pricing", r"/upgrade"],
        },
        FlowType.TRANSFER: {
            "steps": ["recipient", "amount", "verify", "confirm", "execute"],
            "urls": [r"/transfer", r"/send", r"/pay", r"/wire"],
        },
    }

    def __init__(
        self,
        http_client: Any,
        auth_context: Optional[Any] = None,
        base_url: str = "",
    ):
        """
        Initialize flow engine.

        Args:
            http_client: HTTP client for requests
            auth_context: Optional auth context for headers
            base_url: Base URL for relative paths
        """
        self._client = http_client
        self._auth = auth_context
        self._base_url = base_url
        self._discovered_flows: Dict[str, FlowDefinition] = {}

    def detect_flows(self, endpoints: List[str]) -> List[FlowDefinition]:
        """
        Auto-detect multi-step flows from discovered endpoints.

        Args:
            endpoints: List of discovered endpoint URLs

        Returns:
            List of detected flow definitions
        """
        detected = []

        for flow_type, patterns in self.FLOW_PATTERNS.items():
            matching_endpoints = []

            for endpoint in endpoints:
                endpoint_lower = endpoint.lower()
                for url_pattern in patterns["urls"]:
                    if re.search(url_pattern, endpoint_lower):
                        matching_endpoints.append(endpoint)
                        break

            # Need at least 2 matching endpoints to form a flow
            if len(matching_endpoints) >= 2:
                flow = self._build_flow_from_endpoints(
                    flow_type,
                    matching_endpoints,
                    patterns["steps"]
                )
                detected.append(flow)
                self._discovered_flows[flow.name] = flow

        logger.info(
            f"[MULTI_STEP_FLOW] Detected {len(detected)} flows from "
            f"{len(endpoints)} endpoints"
        )

        return detected

    def _build_flow_from_endpoints(
        self,
        flow_type: FlowType,
        endpoints: List[str],
        expected_steps: List[str],
    ) -> FlowDefinition:
        """Build flow definition from matching endpoints."""
        steps = []

        for step_name in expected_steps:
            # Find endpoint matching this step
            matching_url = None
            for endpoint in endpoints:
                if step_name in endpoint.lower():
                    matching_url = endpoint
                    break

            if matching_url:
                step = FlowStep(
                    name=step_name,
                    url=matching_url,
                    method=self._guess_method_for_step(step_name),
                )
                steps.append(step)

        return FlowDefinition(
            name=f"{flow_type.value}_flow",
            flow_type=flow_type,
            steps=steps,
            description=f"Auto-detected {flow_type.value} flow",
        )

    def _guess_method_for_step(self, step_name: str) -> str:
        """Guess HTTP method based on step name."""
        get_steps = {"view", "show", "list", "get", "read", "select", "cart"}
        post_steps = {"submit", "process", "execute", "confirm", "complete", "pay", "register", "login"}

        step_lower = step_name.lower()

        if any(g in step_lower for g in get_steps):
            return "GET"
        elif any(p in step_lower for p in post_steps):
            return "POST"

        return "POST"  # Default to POST for multi-step flows

    def create_checkout_flow(
        self,
        base_url: str,
        add_to_cart_url: str = "/api/cart/add",
        checkout_url: str = "/api/checkout",
        payment_url: str = "/api/payment",
        confirm_url: str = "/api/order/confirm",
        product_id: str = "1",
    ) -> FlowDefinition:
        """
        Create a standard checkout flow.

        Args:
            base_url: Base URL
            add_to_cart_url: Cart add endpoint
            checkout_url: Checkout endpoint
            payment_url: Payment endpoint
            confirm_url: Confirmation endpoint
            product_id: Product ID to add

        Returns:
            FlowDefinition for checkout
        """
        base = base_url.rstrip("/")

        steps = [
            FlowStep(
                name="add_to_cart",
                url=f"{base}{add_to_cart_url}",
                method="POST",
                data={"product_id": product_id, "quantity": "1"},
                extract_fields=["cart_id", "basket_id", "session_id"],
            ),
            FlowStep(
                name="checkout",
                url=f"{base}{checkout_url}",
                method="POST",
                data={},  # Will use extracted cart_id
                extract_fields=["order_id", "checkout_id"],
            ),
            FlowStep(
                name="payment",
                url=f"{base}{payment_url}",
                method="POST",
                data={
                    "card_number": "4111111111111111",
                    "expiry": "12/25",
                    "cvv": "123",
                },
                extract_fields=["payment_id", "transaction_id"],
            ),
            FlowStep(
                name="confirm",
                url=f"{base}{confirm_url}",
                method="POST",
                data={},  # Will use extracted order_id, payment_id
                required_in_response=["success", "order", "confirmed"],
            ),
        ]

        flow = FlowDefinition(
            name="checkout_flow",
            flow_type=FlowType.CHECKOUT,
            steps=steps,
            description="Standard e-commerce checkout flow",
            test_step_indices=[1, 2, 3],  # Test checkout, payment, confirm steps
        )

        self._discovered_flows["checkout_flow"] = flow
        return flow

    def create_transfer_flow(
        self,
        base_url: str,
        select_recipient_url: str = "/api/transfer/recipient",
        enter_amount_url: str = "/api/transfer/amount",
        verify_url: str = "/api/transfer/verify",
        execute_url: str = "/api/transfer/execute",
        recipient_id: str = "12345",
        amount: str = "100.00",
    ) -> FlowDefinition:
        """Create a money transfer flow."""
        base = base_url.rstrip("/")

        steps = [
            FlowStep(
                name="select_recipient",
                url=f"{base}{select_recipient_url}",
                method="POST",
                data={"recipient_id": recipient_id},
                extract_fields=["recipient_name", "recipient_account"],
            ),
            FlowStep(
                name="enter_amount",
                url=f"{base}{enter_amount_url}",
                method="POST",
                data={"amount": amount, "currency": "USD"},
                extract_fields=["transfer_id", "fee"],
            ),
            FlowStep(
                name="verify",
                url=f"{base}{verify_url}",
                method="POST",
                data={},  # Uses accumulated data
                extract_fields=["verification_code", "otp_sent"],
            ),
            FlowStep(
                name="execute",
                url=f"{base}{execute_url}",
                method="POST",
                data={"verification_code": "123456"},  # Would need MFA bypass test
                required_in_response=["success", "transfer_id", "confirmation"],
            ),
        ]

        return FlowDefinition(
            name="transfer_flow",
            flow_type=FlowType.TRANSFER,
            steps=steps,
            description="Money transfer flow with MFA",
            test_step_indices=[1, 2, 3],  # Test amount, verify, execute
        )

    def create_custom_flow(
        self,
        name: str,
        steps: List[Dict[str, Any]],
    ) -> FlowDefinition:
        """
        Create a custom flow from step definitions.

        Args:
            name: Flow name
            steps: List of step dicts with url, method, data, etc.

        Returns:
            FlowDefinition
        """
        flow_steps = []

        for i, step_def in enumerate(steps):
            step = FlowStep(
                name=step_def.get("name", f"step_{i}"),
                url=step_def.get("url", ""),
                method=step_def.get("method", "POST"),
                data=step_def.get("data", {}),
                headers=step_def.get("headers", {}),
                expected_status=step_def.get("expected_status", [200, 201, 302]),
                extract_fields=step_def.get("extract_fields", []),
                required_in_response=step_def.get("required", []),
                wait_seconds=step_def.get("wait", 0.0),
            )
            flow_steps.append(step)

        return FlowDefinition(
            name=name,
            flow_type=FlowType.CUSTOM,
            steps=flow_steps,
        )

    async def execute_flow(
        self,
        flow: FlowDefinition,
        stop_before_step: Optional[str] = None,
    ) -> FlowExecutionResult:
        """
        Execute a flow completely or up to a specific step.

        Args:
            flow: Flow to execute
            stop_before_step: Optional step name to stop before

        Returns:
            FlowExecutionResult with accumulated state
        """
        flow.reset()
        start_time = time.time()
        result = FlowExecutionResult(total_steps=len(flow.steps))

        for i, step in enumerate(flow.steps):
            # Check if we should stop before this step
            if stop_before_step and step.name == stop_before_step:
                logger.info(
                    f"[MULTI_STEP_FLOW] Stopping before step '{step.name}'"
                )
                break

            try:
                step.status = StepStatus.IN_PROGRESS

                # Wait if required
                if step.wait_seconds > 0:
                    await asyncio.sleep(step.wait_seconds)

                # Execute step
                step_result = await self._execute_step(step, flow.accumulated_data)

                if step_result:
                    step.status = StepStatus.COMPLETED
                    result.steps_completed += 1

                    # Accumulate extracted data
                    flow.accumulated_data.update(step.extracted_data)

                    # Check if this is a test point
                    if i in flow.test_step_indices:
                        result.reached_test_points.append(i)
                else:
                    step.status = StepStatus.FAILED
                    result.failed_step = step.name
                    result.error = f"Step '{step.name}' failed"
                    break

            except Exception as e:
                step.status = StepStatus.FAILED
                result.failed_step = step.name
                result.error = str(e)
                logger.error(f"[MULTI_STEP_FLOW] Step '{step.name}' error: {e}")
                break

        result.success = result.steps_completed == result.total_steps or (
            stop_before_step is not None and result.failed_step is None
        )
        result.accumulated_data = flow.accumulated_data.copy()
        result.took_seconds = time.time() - start_time

        logger.info(
            f"[MULTI_STEP_FLOW] Executed '{flow.name}': "
            f"{result.steps_completed}/{result.total_steps} steps, "
            f"success={result.success}"
        )

        return result

    async def execute_to_step(
        self,
        flow: FlowDefinition,
        target_step: str,
    ) -> FlowExecutionResult:
        """
        Execute flow up to and including a specific step.

        Args:
            flow: Flow to execute
            target_step: Step name to execute up to

        Returns:
            FlowExecutionResult
        """
        flow.reset()
        start_time = time.time()
        result = FlowExecutionResult(total_steps=len(flow.steps))

        for i, step in enumerate(flow.steps):
            try:
                step.status = StepStatus.IN_PROGRESS

                if step.wait_seconds > 0:
                    await asyncio.sleep(step.wait_seconds)

                step_result = await self._execute_step(step, flow.accumulated_data)

                if step_result:
                    step.status = StepStatus.COMPLETED
                    result.steps_completed += 1
                    flow.accumulated_data.update(step.extracted_data)

                    if i in flow.test_step_indices:
                        result.reached_test_points.append(i)

                    # Stop after target step
                    if step.name == target_step:
                        break
                else:
                    step.status = StepStatus.FAILED
                    result.failed_step = step.name
                    result.error = f"Step '{step.name}' failed"
                    break

            except Exception as e:
                step.status = StepStatus.FAILED
                result.failed_step = step.name
                result.error = str(e)
                break

        result.success = result.failed_step is None
        result.accumulated_data = flow.accumulated_data.copy()
        result.took_seconds = time.time() - start_time

        return result

    async def _execute_step(
        self,
        step: FlowStep,
        accumulated_data: Dict[str, str],
    ) -> bool:
        """
        Execute a single flow step.

        Args:
            step: Step to execute
            accumulated_data: Data accumulated from previous steps

        Returns:
            True if step succeeded
        """
        # Build request data
        request_data = step.data.copy()

        # Inject accumulated data into request
        for key, value in accumulated_data.items():
            if key not in request_data:
                request_data[key] = value
            # Replace placeholders
            for data_key, data_value in list(request_data.items()):
                if isinstance(data_value, str) and f"{{{key}}}" in data_value:
                    request_data[data_key] = data_value.replace(f"{{{key}}}", value)

        # Build headers
        headers = step.headers.copy()
        if self._auth and hasattr(self._auth, "auth_headers"):
            headers.update(self._auth.auth_headers or {})

        try:
            # Make request
            if step.method.upper() == "GET":
                resp = await self._client.get(
                    step.url,
                    params=request_data,
                    headers=headers,
                    timeout=30.0,
                )
            else:
                headers.setdefault("Content-Type", "application/json")
                resp = await self._client.post(
                    step.url,
                    json=request_data,
                    headers=headers,
                    timeout=30.0,
                )

            # Get response details
            status = getattr(resp, "status_code", getattr(resp, "status", 0))
            step.response_status = status

            # Get body
            body = ""
            if hasattr(resp, "text"):
                if asyncio.iscoroutine(resp.text):
                    body = await resp.text
                elif callable(resp.text):
                    body = resp.text()
                else:
                    body = resp.text
            elif hasattr(resp, "content"):
                content = resp.content
                if isinstance(content, bytes):
                    body = content.decode("utf-8", errors="replace")
                else:
                    body = str(content)

            step.response_body = body

            # Check status
            if status not in step.expected_status:
                logger.debug(
                    f"[MULTI_STEP_FLOW] Step '{step.name}' got status {status}, "
                    f"expected {step.expected_status}"
                )
                return False

            # Check required content
            body_lower = body.lower()
            for required in step.required_in_response:
                if required.lower() not in body_lower:
                    logger.debug(
                        f"[MULTI_STEP_FLOW] Step '{step.name}' missing required: {required}"
                    )
                    return False

            # Check forbidden content
            for forbidden in step.forbidden_in_response:
                if forbidden.lower() in body_lower:
                    logger.debug(
                        f"[MULTI_STEP_FLOW] Step '{step.name}' has forbidden: {forbidden}"
                    )
                    return False

            # Extract fields
            self._extract_fields(step, body)

            return True

        except Exception as e:
            logger.debug(f"[MULTI_STEP_FLOW] Step '{step.name}' request error: {e}")
            return False

    def _extract_fields(self, step: FlowStep, body: str) -> None:
        """Extract specified fields from response body."""
        for field_name in step.extract_fields:
            # Try JSON extraction
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    # Direct key
                    if field_name in data:
                        step.extracted_data[field_name] = str(data[field_name])
                        continue

                    # Nested search
                    value = self._find_in_dict(data, field_name)
                    if value is not None:
                        step.extracted_data[field_name] = str(value)
                        continue
            except json.JSONDecodeError:
                pass

            # Try regex extraction
            patterns = [
                rf'"{field_name}"\s*:\s*"?([^",\}}\]]+)"?',
                rf"'{field_name}'\s*:\s*'?([^',\}}\]]+)'?",
                rf'{field_name}=([^&\s"\'<>]+)',
                rf'name="{field_name}"[^>]*value="([^"]+)"',
            ]

            for pattern in patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    step.extracted_data[field_name] = match.group(1)
                    break

    def _find_in_dict(self, d: Dict[str, Any], key: str) -> Any:
        """Recursively find key in nested dict."""
        if key in d:
            return d[key]

        for v in d.values():
            if isinstance(v, dict):
                result = self._find_in_dict(v, key)
                if result is not None:
                    return result
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        result = self._find_in_dict(item, key)
                        if result is not None:
                            return result

        return None

    def get_test_context_at_step(
        self,
        flow: FlowDefinition,
        step_index: int,
    ) -> Dict[str, Any]:
        """
        Get the testing context available at a specific step.

        Args:
            flow: Executed flow
            step_index: Index of step to get context for

        Returns:
            Dict with accumulated data and step info
        """
        context = {
            "accumulated_data": flow.accumulated_data.copy(),
            "step_name": flow.steps[step_index].name if step_index < len(flow.steps) else None,
            "step_url": flow.steps[step_index].url if step_index < len(flow.steps) else None,
            "previous_steps": [
                {
                    "name": s.name,
                    "status": s.status.value,
                    "extracted": s.extracted_data.copy(),
                }
                for s in flow.steps[:step_index]
            ],
        }
        return context

    def get_summary(self) -> Dict[str, Any]:
        """Get engine summary."""
        return {
            "discovered_flows": len(self._discovered_flows),
            "flows": [
                {
                    "name": f.name,
                    "type": f.flow_type.value,
                    "steps": len(f.steps),
                    "test_points": len(f.test_step_indices),
                }
                for f in self._discovered_flows.values()
            ],
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


async def execute_checkout_and_test(
    http_client: Any,
    base_url: str,
    auth_context: Optional[Any] = None,
    test_at_step: str = "payment",
) -> Tuple[FlowExecutionResult, Dict[str, str]]:
    """
    Execute checkout flow up to a step and return context for testing.

    Args:
        http_client: HTTP client
        base_url: Base URL
        auth_context: Auth context
        test_at_step: Step to stop at and test

    Returns:
        (FlowExecutionResult, accumulated_data for testing)
    """
    engine = MultiStepFlowEngine(http_client, auth_context, base_url)
    flow = engine.create_checkout_flow(base_url)
    result = await engine.execute_to_step(flow, test_at_step)
    return result, result.accumulated_data


def detect_flows_from_sitemap(
    endpoints: List[str],
    base_url: str = "",
) -> List[FlowDefinition]:
    """
    Detect multi-step flows from sitemap/crawled endpoints.

    Args:
        endpoints: List of discovered URLs
        base_url: Base URL

    Returns:
        List of detected flows
    """
    engine = MultiStepFlowEngine(None, None, base_url)
    return engine.detect_flows(endpoints)
