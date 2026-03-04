"""
Stateful Flow Scanner - ScanModule wrapper for StatefulFlowFuzzer

Integrates multi-step workflow vulnerability testing into the full scanner:
- Checkout flows: cart -> shipping -> payment -> confirm
- Authentication flows: login -> 2FA -> session
- Registration flows: signup -> verify -> activate
- Transaction flows: initiate -> authorize -> execute

Attack Strategies:
1. Step Skipping: Jump directly to final step
2. Step Repetition: Repeat steps for double-charge/credit
3. Step Reordering: Execute steps out of order
4. Race Conditions: Parallel step execution
5. Value Manipulation: Change values between steps
6. Rollback Abuse: Partial completion then cancel

Author: PHANTOM AI
Version: 1.0.0
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from scanning.findings import Finding
from scanning.vuln_scanner import ScanModule
from utils.logger import get_logger

if TYPE_CHECKING:
    from core.config_manager import Settings
    from utils.rate_limiter import RateLimiter

logger = get_logger(__name__)


class StatefulFlowScanner(ScanModule):
    """
    ScanModule wrapper for StatefulFlowFuzzer.

    Tests multi-step business workflows for logic vulnerabilities:
    - Step skipping (bypass intermediate validation)
    - Step repetition (double-charge, double-credit)
    - Race conditions in critical steps
    - Value manipulation between steps
    - Rollback/cancellation abuse
    """

    name = "stateful_flow"

    def __init__(
        self,
        settings: "Settings",
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self._findings: list[Finding] = []

    async def scan(
        self,
        host: str,
        asset_data: dict | None = None,
        rate_limiter: "RateLimiter | None" = None,
    ) -> dict[str, Any]:
        """
        Scan for multi-step workflow vulnerabilities.

        Args:
            host: Target URL
            asset_data: Contains endpoints, auth_context, domain_classification
            rate_limiter: Rate limiter for request throttling

        Returns:
            Dict with findings and info
        """
        from scanning.stateful_flow_fuzzer import (
            StatefulFlowFuzzer,
        )

        asset_data = asset_data or {}
        self._findings = []

        # Get auth context for authenticated flow testing
        auth_context = asset_data.get("auth_context")
        auth_headers = {}
        if auth_context and hasattr(auth_context, 'get_headers'):
            auth_headers = auth_context.get_headers() or {}
        elif auth_context and hasattr(auth_context, 'headers'):
            auth_headers = auth_context.headers or {}

        # Get domain classification to determine which flows to test
        domain_classification = asset_data.get("domain_classification") or {}
        domain_type = domain_classification.get("type", "unknown")

        # Get discovered endpoints for flow step discovery
        endpoints = asset_data.get("endpoints", [])

        logger.info(f"[StatefulFlow] Starting flow analysis on {host}")
        logger.info(f"[StatefulFlow] Domain type: {domain_type}, Endpoints: {len(endpoints)}, Auth: {bool(auth_headers)}")

        # Create fuzzer instance
        fuzzer = StatefulFlowFuzzer(
            base_url=host,
            auth_headers=auth_headers,
            timeout=15.0,
        )

        # Determine which flows to test based on domain type and discovered endpoints
        flows_to_test = self._detect_applicable_flows(
            domain_type=domain_type,
            endpoints=endpoints,
            host=host,
        )

        if not flows_to_test:
            logger.info("[StatefulFlow] No applicable flows detected, skipping")
            return {
                "findings": [],
                "info": [{
                    "type": "stateful_flow_skipped",
                    "reason": "No applicable multi-step flows detected",
                    "domain_type": domain_type,
                    "endpoints_checked": len(endpoints),
                }],
            }

        logger.info(f"[StatefulFlow] Testing {len(flows_to_test)} flow types: {[f.value for f in flows_to_test]}")

        # Initialize values from auth context if available
        initial_values = self._extract_initial_values(auth_context, asset_data)

        # Test each applicable flow
        all_findings = []
        for flow_type in flows_to_test:
            try:
                if rate_limiter:
                    await rate_limiter.acquire()

                flow_findings = await fuzzer.fuzz_flow(
                    flow_type=flow_type,
                    rate_limiter=rate_limiter,
                    initial_values=initial_values,
                    custom_steps=None,  # Use predefined templates
                    attacks=None,  # Run all attack types
                )

                # Convert FlowFinding to Finding objects
                for ff in flow_findings:
                    finding = self._convert_flow_finding(ff, host, flow_type)
                    all_findings.append(finding)
                    self._findings.append(finding)

            except Exception as e:
                logger.debug(f"[StatefulFlow] Error testing {flow_type.value}: {e}")

        logger.info(f"[StatefulFlow] Found {len(all_findings)} workflow vulnerabilities")

        return {
            "findings": [f.to_dict() if hasattr(f, 'to_dict') else f for f in all_findings],
            "info": [{
                "type": "stateful_flow_complete",
                "flows_tested": [f.value for f in flows_to_test],
                "total_findings": len(all_findings),
            }],
        }

    def _detect_applicable_flows(
        self,
        domain_type: str,
        endpoints: list[str],
        host: str,
    ) -> list:
        """Detect which flow types are applicable based on domain and endpoints."""
        from scanning.stateful_flow_fuzzer import FlowType

        applicable = []

        # Domain-based flow selection
        domain_flows = {
            "ecommerce": [FlowType.CHECKOUT, FlowType.PAYMENT, FlowType.REFUND, FlowType.ORDER],
            "marketplace": [FlowType.CHECKOUT, FlowType.PAYMENT, FlowType.REFUND, FlowType.TRANSFER],
            "fintech": [FlowType.TRANSFER, FlowType.PAYMENT, FlowType.SUBSCRIPTION],
            "saas": [FlowType.SUBSCRIPTION, FlowType.REGISTRATION, FlowType.AUTHENTICATION],
            "auth_centric": [FlowType.AUTHENTICATION, FlowType.REGISTRATION, FlowType.PASSWORD_RESET, FlowType.MFA_ENROLLMENT],
            "content": [FlowType.REGISTRATION, FlowType.SUBSCRIPTION],
            "api_service": [FlowType.AUTHENTICATION, FlowType.REGISTRATION],
        }

        if domain_type in domain_flows:
            applicable.extend(domain_flows[domain_type])

        # Endpoint-based flow detection (supplement domain detection)
        endpoint_str = " ".join(endpoints).lower()

        # Checkout flow indicators
        if any(kw in endpoint_str for kw in ["cart", "checkout", "basket", "order"]):
            if FlowType.CHECKOUT not in applicable:
                applicable.append(FlowType.CHECKOUT)

        # Payment flow indicators
        if any(kw in endpoint_str for kw in ["payment", "pay", "charge", "stripe", "braintree"]):
            if FlowType.PAYMENT not in applicable:
                applicable.append(FlowType.PAYMENT)

        # Transfer flow indicators
        if any(kw in endpoint_str for kw in ["transfer", "send", "withdraw", "deposit"]):
            if FlowType.TRANSFER not in applicable:
                applicable.append(FlowType.TRANSFER)

        # Subscription flow indicators
        if any(kw in endpoint_str for kw in ["subscription", "subscribe", "plan", "billing"]):
            if FlowType.SUBSCRIPTION not in applicable:
                applicable.append(FlowType.SUBSCRIPTION)

        # Auth flow indicators
        if any(kw in endpoint_str for kw in ["login", "auth", "mfa", "2fa", "otp"]):
            if FlowType.AUTHENTICATION not in applicable:
                applicable.append(FlowType.AUTHENTICATION)

        # Registration flow indicators
        if any(kw in endpoint_str for kw in ["register", "signup", "sign-up", "verify"]):
            if FlowType.REGISTRATION not in applicable:
                applicable.append(FlowType.REGISTRATION)

        # Refund flow indicators
        if any(kw in endpoint_str for kw in ["refund", "return", "cancel"]):
            if FlowType.REFUND not in applicable:
                applicable.append(FlowType.REFUND)

        # Password reset indicators
        if any(kw in endpoint_str for kw in ["password", "reset", "forgot"]):
            if FlowType.PASSWORD_RESET not in applicable:
                applicable.append(FlowType.PASSWORD_RESET)

        # Always test authentication if no specific flows found
        if not applicable:
            applicable.append(FlowType.AUTHENTICATION)
            applicable.append(FlowType.REGISTRATION)

        return applicable

    def _extract_initial_values(
        self,
        auth_context: Any,
        asset_data: dict,
    ) -> dict:
        """Extract initial values for flow testing from auth context."""
        values = {}

        # Extract from auth context
        if auth_context:
            if hasattr(auth_context, 'user_id'):
                values["user_id"] = auth_context.user_id
            if hasattr(auth_context, 'username'):
                values["username"] = auth_context.username
            if hasattr(auth_context, 'email'):
                values["email"] = auth_context.email
            if hasattr(auth_context, 'session_id'):
                values["session_id"] = auth_context.session_id

        # Extract from asset_data
        if "user_personas" in asset_data:
            personas = asset_data["user_personas"]
            if personas:
                first_persona = personas[0] if isinstance(personas, list) else personas
                if isinstance(first_persona, dict):
                    values.update({
                        k: v for k, v in first_persona.items()
                        if k in ["username", "email", "password", "user_id"]
                    })

        return values

    def _convert_flow_finding(self, flow_finding: Any, host: str, flow_type: Any) -> Finding:
        """Convert FlowFinding to standard Finding format."""
        # Map attack types to CWE
        attack_type_cwe = {
            "STEP_SKIP": "CWE-841",      # Improper Enforcement of Behavioral Workflow
            "STEP_REPEAT": "CWE-841",
            "STEP_REORDER": "CWE-841",
            "RACE_CONDITION": "CWE-362", # Race Condition
            "VALUE_MANIPULATION": "CWE-472",  # External Control of Assumed-Immutable Web Parameter
            "ROLLBACK_ABUSE": "CWE-841",
            "PARAM_POLLUTION": "CWE-235",  # Improper Handling of Extra Parameters
            "STATE_MANIPULATION": "CWE-384",  # Session Fixation
            "TOKEN_REPLAY": "CWE-294",   # Authentication Bypass by Capture-replay
            "SESSION_FIXATION": "CWE-384",
        }

        attack_type_name = flow_finding.attack_type.name if hasattr(flow_finding.attack_type, 'name') else str(flow_finding.attack_type)
        cwe = attack_type_cwe.get(attack_type_name, "CWE-841")

        # Build evidence from flow finding
        evidence = "\n".join(flow_finding.evidence) if flow_finding.evidence else ""

        return Finding(
            name=f"Stateful Flow Vulnerability: {attack_type_name.replace('_', ' ').title()}",
            severity=flow_finding.severity.upper(),
            confidence_score=flow_finding.confidence,
            description=flow_finding.description,
            evidence=evidence,
            remediation=(
                f"Implement proper state validation for {flow_type.value} flows:\n"
                f"1. Verify all previous steps completed before allowing current step\n"
                f"2. Use cryptographic tokens to track flow state server-side\n"
                f"3. Implement idempotency keys for critical operations\n"
                f"4. Add rate limiting on sensitive flow steps\n"
                f"5. Log and alert on flow state anomalies"
            ),
            endpoint=host,
            cwe_id=cwe,
            metadata={
                "flow_type": flow_type.value if hasattr(flow_type, 'value') else str(flow_type),
                "attack_type": attack_type_name,
                "steps_involved": flow_finding.steps_involved,
                "impact": flow_finding.impact,
                "scanner": "stateful_flow",
                **(flow_finding.metadata or {}),
            },
        )
