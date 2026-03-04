"""
PHANTOM AI - Workflow Inference Engine (Enhanced)

Multi-step stateful workflow vulnerability detection.
Discovers workflows and tests for vulnerabilities that only emerge
when legitimate actions are combined in unexpected ways.

Key Capabilities:
1. Automatic Workflow Discovery — Infers state machines from endpoints + responses
2. State Tracking — Tracks tokens, cookies, and values across requests
3. Transition Testing — Tests step skipping, repetition, reordering
4. Cross-Step Value Injection — Detects when values from step N affect step M
5. Orphan State Detection — Finds exploitable state after cancellation
6. Workflow Race Conditions — Tests concurrent execution of sequential steps

Works generically for ALL web applications by detecting domain type
and inferring valid/invalid state transitions from API behavior.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import ssl
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

import aiohttp  # Direct aiohttp for bypassing SafeAsyncClient

from scanning.findings import Finding, Severity, VulnType
from scanning.vuln_scanner import ScanModule
from utils.scan_client import get_scan_client
from utils.logger import get_logger
from scanning.scan_context import ScanContext

logger = get_logger(__name__)

# SSL context for permissive connections
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


class DomainType(Enum):
    """Detected business domain type."""
    ECOMMERCE = auto()      # Shopping, orders, payments
    SAAS = auto()           # Subscriptions, plans, users
    MARKETPLACE = auto()    # Listings, buyers, sellers
    FINTECH = auto()        # Transfers, accounts, KYC
    HEALTHCARE = auto()     # Appointments, records, prescriptions
    CONTENT = auto()        # Posts, comments, moderation
    AUTH_CENTRIC = auto()   # Login, registration, MFA
    API_SERVICE = auto()    # Generic API
    UNKNOWN = auto()


@dataclass
class WorkflowState:
    """A detected state in a workflow."""
    name: str
    url_pattern: str
    status_field: str = ""
    status_value: str = ""
    transitions: list[str] = field(default_factory=list)


@dataclass
class InferredWorkflow:
    """An inferred workflow state machine."""
    name: str
    domain: DomainType
    states: list[WorkflowState] = field(default_factory=list)
    entry_state: str = ""
    terminal_states: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)  # Actual discovered endpoints
    confidence: float = 0.0


@dataclass
class WorkflowExecutionState:
    """Tracks state during multi-step workflow execution."""
    current_state: str = ""
    state_tokens: dict[str, str] = field(default_factory=dict)  # token_name → value
    cookies: dict[str, str] = field(default_factory=dict)
    response_values: dict[str, Any] = field(default_factory=dict)  # Extracted values
    step_history: list[dict] = field(default_factory=list)  # Request/response log

    def clone(self) -> "WorkflowExecutionState":
        """Create a copy for parallel testing."""
        return WorkflowExecutionState(
            current_state=self.current_state,
            state_tokens=dict(self.state_tokens),
            cookies=dict(self.cookies),
            response_values=dict(self.response_values),
            step_history=list(self.step_history),
        )


# Domain detection patterns
DOMAIN_PATTERNS = {
    DomainType.ECOMMERCE: [
        r"/cart", r"/checkout", r"/order", r"/payment", r"/product",
        r"/basket", r"/shipping", r"/invoice", r"price", r"quantity",
    ],
    DomainType.SAAS: [
        r"/subscription", r"/plan", r"/billing", r"/workspace",
        r"/tenant", r"/team", r"/seat", r"trial", r"premium",
    ],
    DomainType.MARKETPLACE: [
        r"/listing", r"/seller", r"/buyer", r"/bid", r"/auction",
        r"/offer", r"/review", r"/rating", r"commission",
    ],
    DomainType.FINTECH: [
        r"/transfer", r"/account", r"/balance", r"/kyc", r"/withdraw",
        r"/deposit", r"/transaction", r"amount", r"currency",
    ],
    DomainType.HEALTHCARE: [
        r"/appointment", r"/patient", r"/prescription", r"/record",
        r"/doctor", r"/diagnosis", r"/treatment",
    ],
    DomainType.CONTENT: [
        r"/post", r"/comment", r"/article", r"/publish", r"/moderate",
        r"/draft", r"/review", r"content", r"author",
    ],
    DomainType.AUTH_CENTRIC: [
        r"/login", r"/register", r"/mfa", r"/2fa", r"/verify",
        r"/reset", r"/password", r"/session",
    ],
}

# Common status field names
STATUS_FIELDS = [
    "status", "state", "stage", "step", "phase",
    "workflow_status", "order_status", "payment_status",
    "subscription_status", "account_status", "verification_status",
]

# Common workflow patterns by domain
WORKFLOW_PATTERNS = {
    DomainType.ECOMMERCE: {
        "order": ["created", "pending", "confirmed", "processing", "shipped", "delivered", "cancelled", "refunded"],
        "payment": ["pending", "processing", "completed", "failed", "refunded"],
        "cart": ["active", "checkout", "converted", "abandoned"],
    },
    DomainType.SAAS: {
        "subscription": ["trial", "active", "past_due", "cancelled", "expired"],
        "user": ["pending", "active", "suspended", "deleted"],
        "workspace": ["creating", "active", "suspended", "deleted"],
    },
    DomainType.FINTECH: {
        "transfer": ["pending", "processing", "completed", "failed", "reversed"],
        "kyc": ["pending", "submitted", "reviewing", "approved", "rejected"],
        "account": ["pending", "active", "frozen", "closed"],
    },
    DomainType.CONTENT: {
        "post": ["draft", "pending_review", "published", "archived", "deleted"],
        "comment": ["pending", "approved", "rejected", "hidden"],
    },
}

# Response patterns for extracting state tokens
STATE_TOKEN_PATTERNS = {
    "cart_id": [r'"cart_id"\s*:\s*"?([^",}]+)', r'"cartId"\s*:\s*"?([^",}]+)', r'"basket"\s*:\s*"?([^",}]+)'],
    "order_id": [r'"order_id"\s*:\s*"?([^",}]+)', r'"orderId"\s*:\s*"?([^",}]+)', r'"orderNumber"\s*:\s*"?([^",}]+)'],
    "token": [r'"token"\s*:\s*"([^"]+)"', r'"access_token"\s*:\s*"([^"]+)"', r'"checkout_token"\s*:\s*"([^"]+)"'],
    "session_id": [r'"session"\s*:\s*"([^"]+)"', r'"sid"\s*:\s*"([^"]+)"', r'"sessionId"\s*:\s*"([^"]+)"'],
    "user_id": [r'"user_id"\s*:\s*"?([^",}]+)', r'"userId"\s*:\s*"?([^",}]+)'],
    "transaction_id": [r'"transaction_id"\s*:\s*"?([^",}]+)', r'"txId"\s*:\s*"?([^",}]+)'],
    "step": [r'"step"\s*:\s*(\d+)', r'"currentStep"\s*:\s*(\d+)', r'"stage"\s*:\s*(\d+)'],
    "next_url": [r'"next"\s*:\s*"([^"]+)"', r'"nextStep"\s*:\s*"([^"]+)"', r'"redirect"\s*:\s*"([^"]+)"'],
    "total": [r'"total"\s*:\s*"?([0-9.]+)', r'"amount"\s*:\s*"?([0-9.]+)', r'"price"\s*:\s*"?([0-9.]+)'],
}

# Workflow endpoint patterns for discovery
WORKFLOW_ENDPOINT_PATTERNS = {
    "checkout": {
        "states": ["cart", "shipping", "payment", "review", "complete"],
        "patterns": [
            (r"/cart|/basket|/bag", "cart"),
            (r"/shipping|/delivery|/address", "shipping"),
            (r"/payment|/pay|/billing", "payment"),
            (r"/review|/confirm|/summary", "review"),
            (r"/complete|/success|/thank|/order/\d+", "complete"),
        ],
    },
    "registration": {
        "states": ["signup", "verify", "profile"],
        "patterns": [
            (r"/register|/signup|/create-account", "signup"),
            (r"/verify|/confirm|/activate", "verify"),
            (r"/profile|/complete-profile|/onboard", "profile"),
        ],
    },
    "password_reset": {
        "states": ["request", "verify", "change"],
        "patterns": [
            (r"/forgot|/reset-password", "request"),
            (r"/verify|/token|/reset/[a-f0-9]+", "verify"),
            (r"/change-password|/new-password|/update-password", "change"),
        ],
    },
    "transfer": {
        "states": ["init", "confirm", "execute"],
        "patterns": [
            (r"/transfer|/send|/pay", "init"),
            (r"/confirm|/verify|/2fa|/otp", "confirm"),
            (r"/execute|/complete|/process", "execute"),
        ],
    },
    "refund": {
        "states": ["request", "review", "process"],
        "patterns": [
            (r"/refund|/return|/dispute", "request"),
            (r"/review|/pending|/status", "review"),
            (r"/process|/approve|/complete", "process"),
        ],
    },
}

# Sensitive parameters that shouldn't be settable early in workflow
CROSS_STEP_SENSITIVE_PARAMS = [
    "total", "price", "amount", "discount", "status", "approved", "verified",
    "paid", "completed", "admin", "role", "quantity", "shipping_cost",
]

# Invalid transitions to test (from_state -> to_state that should be blocked)
INVALID_TRANSITIONS = {
    DomainType.ECOMMERCE: [
        ("delivered", "pending"),      # Can't go back to pending after delivery
        ("refunded", "processing"),    # Can't process refunded order
        ("cancelled", "shipped"),      # Can't ship cancelled order
        ("pending", "delivered"),      # Can't skip to delivered
        ("failed", "completed"),       # Payment can't go from failed to completed
    ],
    DomainType.SAAS: [
        ("cancelled", "active"),       # Can't reactivate cancelled without payment
        ("expired", "trial"),          # Can't go back to trial
        ("deleted", "active"),         # Can't undelete
        ("suspended", "trial"),        # Can't get trial after suspension
    ],
    DomainType.FINTECH: [
        ("completed", "pending"),      # Can't undo completed transfer
        ("rejected", "approved"),      # Can't approve rejected KYC
        ("closed", "active"),          # Can't reopen closed account
        ("reversed", "processing"),    # Can't process reversed transfer
    ],
    DomainType.CONTENT: [
        ("deleted", "published"),      # Can't publish deleted content
        ("rejected", "published"),     # Can't publish rejected content (moderation bypass)
        ("archived", "draft"),         # Usually can't go back to draft
    ],
}


class WorkflowInferenceEngine(ScanModule):
    """
    Automatically infers workflow state machines and tests for bypass vulnerabilities.

    Works generically by detecting the application domain and inferring
    valid/invalid state transitions from API responses.
    """

    name = "workflow_inference"
    description = "Infers workflows from APIs and tests for bypass vulnerabilities"
    version = "1.0.0"
    author = "PHANTOM AI"
    tags = ["workflow", "business_logic", "state_machine", "bypass"]

    def __init__(
        self,
        settings: Any = None,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self._base_url = ""
        self._detected_domain = DomainType.UNKNOWN
        self._inferred_workflows: list[InferredWorkflow] = []
        self._discovered_endpoints: list[dict] = []
        self._status_values_seen: dict[str, set[str]] = defaultdict(set)
        self._auth_headers: dict[str, str] = {}
        self._rate_limiter: Any = None
        self._timeout = aiohttp.ClientTimeout(total=15)

    async def scan(
        self,
        host: str,
        port: int | None = None,
        extra_params: dict[str, Any] | None = None,
    ) -> list[Finding]:
        """Main entry point for workflow inference scanning."""

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(extra_params)
        self._auth_headers = self._ctx.auth_headers

        extra_params = extra_params or {}
        self._base_url = self._resolve_base_url(host, port)

        # Get auth context if available
        auth_context = extra_params.get("auth_context")
        if auth_context:
            if hasattr(auth_context, "auth_headers"):
                self._auth_headers = auth_context.auth_headers
            elif hasattr(auth_context, "token") and auth_context.token:
                self._auth_headers["Authorization"] = f"Bearer {auth_context.token}"
            if hasattr(auth_context, "cookies") and auth_context.cookies:
                cookie_str = "; ".join(f"{k}={v}" for k, v in auth_context.cookies.items())
                self._auth_headers["Cookie"] = cookie_str

        # Get rate limiter
        self._rate_limiter = extra_params.get("rate_limiter")

        # Get discovered endpoints
        endpoints = extra_params.get("endpoints", [])
        self._discovered_endpoints = [
            {"url": getattr(ep, "url", "") or getattr(ep, "path", ""),
             "method": getattr(ep, "method", "GET")}
            for ep in endpoints
        ]

        findings: list[Finding] = []

        # Phase 1: Detect domain type
        self._detected_domain = await self._detect_domain()
        logger.info(f"[WORKFLOW] Detected domain: {self._detected_domain.name}")

        # Phase 2: Discover status fields and values
        await self._discover_status_fields()

        # Phase 3: Infer workflows from endpoint patterns
        self._infer_workflows()
        self._discover_workflows_from_patterns()
        logger.info(f"[WORKFLOW] Inferred {len(self._inferred_workflows)} workflows")

        if not self._inferred_workflows:
            logger.info("[WORKFLOW] No workflows discovered, skipping multi-step tests")
            return findings

        # Phase 4: Test invalid transitions (existing)
        transition_findings = await self._test_invalid_transitions()
        findings.extend(transition_findings)

        # Phase 5: Test workflow bypass (existing)
        bypass_findings = await self._test_workflow_bypass()
        findings.extend(bypass_findings)

        # Phase 6: Multi-step workflow execution with step skipping
        skip_findings = await self._test_step_skipping()
        findings.extend(skip_findings)

        # Phase 7: Cross-step value injection
        injection_findings = await self._test_cross_step_injection()
        findings.extend(injection_findings)

        # Phase 8: Step repetition (double-apply coupons, etc.)
        repeat_findings = await self._test_step_repetition()
        findings.extend(repeat_findings)

        # Phase 9: Orphan state detection
        orphan_findings = await self._test_orphan_state()
        findings.extend(orphan_findings)

        # Phase 10: Workflow race conditions
        race_findings = await self._test_workflow_race()
        findings.extend(race_findings)

        # Phase 11: Sequence manipulation (existing)
        sequence_findings = await self._test_sequence_manipulation()
        findings.extend(sequence_findings)

        # Deduplicate findings
        findings = self._deduplicate_findings(findings)

        logger.info(f"[WORKFLOW] Complete: {len(findings)} findings")
        return findings

    def _deduplicate_findings(self, findings: list[Finding]) -> list[Finding]:
        """Deduplicate findings by (name, matched_at)."""
        seen = set()
        unique = []
        for f in findings:
            key = (f.name, getattr(f, "matched_at", ""))
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _resolve_base_url(self, host: str, port: int | None) -> str:
        """Resolve base URL from host and port."""
        if host.startswith(("http://", "https://")):
            return host.rstrip("/")

        if port in (443, 8443):
            protocol = "https"
        else:
            protocol = "http"

        if port and port not in (80, 443):
            return f"{protocol}://{host}:{port}"
        return f"{protocol}://{host}"

    async def _detect_domain(self) -> DomainType:
        """Detect the business domain from discovered endpoints."""
        domain_scores: dict[DomainType, int] = defaultdict(int)

        # Score based on endpoint patterns
        for ep in self._discovered_endpoints:
            url = ep.get("url", "").lower()
            for domain, patterns in DOMAIN_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, url, re.IGNORECASE):
                        domain_scores[domain] += 1

        # Also check response content from a few endpoints
        try:
            async with get_scan_client(verify_ssl=False, timeout=10.0) as client:
                for ep in self._discovered_endpoints[:5]:
                    url = urljoin(self._base_url, ep.get("url", ""))
                    try:
                        resp = await client.get(url, headers=self._auth_headers)
                        if resp.status_code == 200:
                            body = resp.text.lower()
                            for domain, patterns in DOMAIN_PATTERNS.items():
                                for pattern in patterns:
                                    if re.search(pattern, body):
                                        domain_scores[domain] += 0.5
                    except Exception:
                        pass
        except Exception:
            pass

        if domain_scores:
            return max(domain_scores, key=domain_scores.get)
        return DomainType.UNKNOWN

    async def _discover_status_fields(self) -> None:
        """Discover status fields and their values from API responses."""
        try:
            async with get_scan_client(verify_ssl=False, timeout=10.0) as client:
                for ep in self._discovered_endpoints[:20]:
                    url = urljoin(self._base_url, ep.get("url", ""))
                    try:
                        resp = await client.get(url, headers=self._auth_headers)
                        if resp.status_code == 200:
                            try:
                                data = resp.json()
                                self._extract_status_from_json(data)
                            except json.JSONDecodeError:
                                pass
                    except Exception:
                        pass
        except Exception:
            pass

    def _extract_status_from_json(self, data: Any, prefix: str = "") -> None:
        """Recursively extract status fields from JSON response."""
        if isinstance(asset_data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key

                # Check if this is a status field
                if key.lower() in STATUS_FIELDS or "status" in key.lower():
                    if isinstance(value, str) and value:
                        self._status_values_seen[key].add(value.lower())

                # Recurse into nested objects
                self._extract_status_from_json(value, full_key)

        elif isinstance(data, list):
            for item in data[:10]:  # Limit to first 10 items
                self._extract_status_from_json(item, prefix)

    def _infer_workflows(self) -> None:
        """Infer workflows from discovered endpoints and status values."""
        self._inferred_workflows = []

        # Use domain-specific workflow patterns
        if self._detected_domain in WORKFLOW_PATTERNS:
            patterns = WORKFLOW_PATTERNS[self._detected_domain]
            for workflow_name, states in patterns.items():
                # Find matching endpoints for this workflow
                matching_endpoints = [
                    ep for ep in self._discovered_endpoints
                    if workflow_name.lower() in ep.get("url", "").lower()
                ]

                if matching_endpoints:
                    workflow = InferredWorkflow(
                        name=workflow_name,
                        domain=self._detected_domain,
                        states=[WorkflowState(name=s, url_pattern=f"/{workflow_name}") for s in states],
                        entry_state=states[0] if states else "",
                        terminal_states=[states[-1]] if states else [],
                    )
                    self._inferred_workflows.append(workflow)

        # Also infer from discovered status values
        for status_field, values in self._status_values_seen.items():
            if len(values) >= 2:  # Need at least 2 states for a workflow
                workflow = InferredWorkflow(
                    name=f"inferred_{status_field}",
                    domain=self._detected_domain,
                    states=[WorkflowState(name=v, url_pattern="", status_field=status_field, status_value=v) for v in values],
                    entry_state=list(values)[0],
                    terminal_states=[],
                )
                self._inferred_workflows.append(workflow)

    async def _test_invalid_transitions(self) -> list[Finding]:
        """Test invalid state transitions."""
        findings: list[Finding] = []

        invalid_transitions = INVALID_TRANSITIONS.get(self._detected_domain, [])
        if not invalid_transitions:
            return findings

        # Find endpoints that accept status updates
        status_endpoints = [
            ep for ep in self._discovered_endpoints
            if any(method in ep.get("method", "").upper() for method in ["PUT", "PATCH", "POST"])
        ]

        try:
            async with get_scan_client(verify_ssl=False, timeout=10.0) as client:
                for ep in status_endpoints[:10]:
                    url = urljoin(self._base_url, ep.get("url", ""))
                    method = ep.get("method", "POST").upper()

                    for from_state, to_state in invalid_transitions:
                        # Try to force invalid transition
                        for status_field in STATUS_FIELDS:
                            payload = {status_field: to_state}

                            try:
                                if method == "PUT":
                                    resp = await client.put(url, json=payload, headers=self._auth_headers)
                                elif method == "PATCH":
                                    resp = await client.patch(url, json=payload, headers=self._auth_headers)
                                else:
                                    resp = await client.post(url, json=payload, headers=self._auth_headers)

                                # Check if transition was accepted
                                if resp.status_code in (200, 201, 204):
                                    body = resp.text.lower()
                                    if to_state.lower() in body or "success" in body:
                                        findings.append(Finding(
                                            vuln_type=VulnType.WORKFLOW_BYPASS,
                                            name=f"Invalid State Transition Accepted: {from_state} → {to_state}",
                                            description=(
                                                f"The application accepted an invalid state transition from "
                                                f"`{from_state}` to `{to_state}` at endpoint `{url}`.\n\n"
                                                f"This indicates missing workflow validation that could allow:\n"
                                                f"- Skipping required steps (payment, verification)\n"
                                                f"- Reversing completed actions\n"
                                                f"- Bypassing business rules\n\n"
                                                f"**Payload:** `{json.dumps(payload)}`"
                                            ),
                                            severity=Severity.HIGH,
                                            confidence_score=85.0,
                                            host=urlparse(url).netloc,
                                            endpoint=url,
                                            metadata={
                                                "from_state": from_state,
                                                "to_state": to_state,
                                                "status_field": status_field,
                                                "method": method,
                                                "domain": self._detected_domain.name,
                                            },
                                        ))
                                        break  # Found vulnerability, move to next transition
                            except Exception:
                                pass

        except Exception as e:
            logger.debug(f"[WORKFLOW] Error testing transitions: {e}")

        return findings

    async def _test_workflow_bypass(self) -> list[Finding]:
        """Test for workflow bypass by skipping required steps."""
        findings: list[Finding] = []

        # Find terminal endpoints (checkout, confirm, submit, complete)
        terminal_patterns = [
            r"checkout", r"confirm", r"submit", r"complete", r"finalize",
            r"approve", r"verify", r"process", r"execute",
        ]

        terminal_endpoints = [
            ep for ep in self._discovered_endpoints
            if any(re.search(p, ep.get("url", ""), re.IGNORECASE) for p in terminal_patterns)
        ]

        try:
            async with get_scan_client(verify_ssl=False, timeout=10.0) as client:
                for ep in terminal_endpoints[:5]:
                    url = urljoin(self._base_url, ep.get("url", ""))
                    method = ep.get("method", "POST").upper()

                    # Try to access terminal endpoint directly without prior steps
                    try:
                        if method == "POST":
                            resp = await client.post(url, json={}, headers=self._auth_headers)
                        else:
                            resp = await client.get(url, headers=self._auth_headers)

                        # Check if we got a success response (should require prior steps)
                        if resp.status_code in (200, 201, 202):
                            body = resp.text.lower()
                            # Look for success indicators
                            if any(ind in body for ind in ["success", "completed", "confirmed", "approved"]):
                                findings.append(Finding(
                                    vuln_type=VulnType.WORKFLOW_BYPASS,
                                    name="Workflow Step Bypass",
                                    description=(
                                        f"The terminal workflow endpoint at `{url}` accepted a request "
                                        f"without requiring prior workflow steps.\n\n"
                                        f"This could allow an attacker to:\n"
                                        f"- Skip payment/verification steps\n"
                                        f"- Complete orders without payment\n"
                                        f"- Approve actions without required checks\n\n"
                                        f"**Method:** `{method}`\n"
                                        f"**Status:** {resp.status_code}"
                                    ),
                                    severity=Severity.CRITICAL,
                                    confidence_score=80.0,
                                    host=urlparse(url).netloc,
                                    endpoint=url,
                                    metadata={
                                        "method": method,
                                        "response_status": resp.status_code,
                                        "domain": self._detected_domain.name,
                                    },
                                ))
                    except Exception:
                        pass

        except Exception as e:
            logger.debug(f"[WORKFLOW] Error testing bypass: {e}")

        return findings

    async def _test_sequence_manipulation(self) -> list[Finding]:
        """Test for sequence manipulation vulnerabilities."""
        findings: list[Finding] = []

        # Look for endpoints with sequence/step parameters
        sequence_params = ["step", "stage", "phase", "seq", "sequence", "order", "position"]

        try:
            async with get_scan_client(verify_ssl=False, timeout=10.0) as client:
                for ep in self._discovered_endpoints[:15]:
                    url = urljoin(self._base_url, ep.get("url", ""))
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)

                    # Check if URL has sequence-like parameters
                    for param in sequence_params:
                        if param in params or param in url.lower():
                            # Try to manipulate sequence
                            for test_value in ["-1", "0", "99999", "999"]:
                                test_url = f"{url}?{param}={test_value}" if "?" not in url else f"{url}&{param}={test_value}"

                                try:
                                    resp = await client.get(test_url, headers=self._auth_headers)

                                    if resp.status_code == 200:
                                        body = resp.text.lower()
                                        # Check for signs of sequence bypass
                                        if any(ind in body for ind in ["success", "complete", "final", "done"]):
                                            findings.append(Finding(
                                                vuln_type=VulnType.WORKFLOW_BYPASS,
                                                name="Sequence Manipulation Vulnerability",
                                                description=(
                                                    f"The endpoint at `{url}` is vulnerable to sequence manipulation.\n\n"
                                                    f"Setting `{param}={test_value}` allowed bypassing the normal "
                                                    f"workflow sequence.\n\n"
                                                    f"This could allow an attacker to:\n"
                                                    f"- Skip to final workflow steps\n"
                                                    f"- Access steps out of order\n"
                                                    f"- Bypass validation at intermediate steps"
                                                ),
                                                severity=Severity.HIGH,
                                                confidence_score=75.0,
                                                host=urlparse(url).netloc,
                                                endpoint=test_url,
                                                metadata={
                                                    "param": param,
                                                    "test_value": test_value,
                                                    "original_url": url,
                                                },
                                            ))
                                            break
                                except Exception:
                                    pass

        except Exception as e:
            logger.debug(f"[WORKFLOW] Error testing sequence manipulation: {e}")

        return findings

    # =========================================================================
    # NEW: Multi-Step Stateful Workflow Testing
    # =========================================================================

    def _discover_workflows_from_patterns(self) -> None:
        """Discover workflows from endpoint patterns."""
        for wf_name, wf_config in WORKFLOW_ENDPOINT_PATTERNS.items():
            matched_states = []
            matched_endpoints = []

            for pattern, state_name in wf_config["patterns"]:
                for ep in self._discovered_endpoints:
                    url = ep.get("url", "")
                    if re.search(pattern, url, re.IGNORECASE):
                        matched_states.append(state_name)
                        matched_endpoints.append(url)
                        break

            if len(matched_states) >= 2:
                # Build workflow from matched states
                states = [
                    WorkflowState(name=s, url_pattern=e)
                    for s, e in zip(matched_states, matched_endpoints)
                ]
                workflow = InferredWorkflow(
                    name=wf_name,
                    domain=self._detected_domain,
                    states=states,
                    entry_state=matched_states[0] if matched_states else "",
                    terminal_states=[matched_states[-1]] if matched_states else [],
                    endpoints=matched_endpoints,
                    confidence_score=min(0.9, 0.4 + len(matched_states) * 0.15),
                )
                # Check if we already have this workflow
                if not any(w.name == wf_name for w in self._inferred_workflows):
                    self._inferred_workflows.append(workflow)
                    logger.info(f"[WORKFLOW] Discovered {wf_name}: states={matched_states}")

    async def _execute_workflow_state(
        self,
        endpoint: str,
        method: str,
        exec_state: WorkflowExecutionState,
        extra_data: dict | None = None,
    ) -> dict | None:
        """Execute a single workflow state and track state changes."""
        try:
            url = endpoint
            if not url.startswith("http"):
                url = urljoin(self._base_url, url)

            headers = {**self._auth_headers}
            body = extra_data or {}

            # Add state tokens to request
            for token_name, token_value in exec_state.state_tokens.items():
                body[token_name] = token_value

            if self._rate_limiter:
                await self._rate_limiter.acquire()

            async with aiohttp.ClientSession(
                timeout=self._timeout,
            ) as session:
                # Set cookies from exec state
                for name, value in exec_state.cookies.items():
                    session.cookie_jar.update_cookies({name: value})

                if method.upper() == "POST":
                    async with session.post(
                        url, json=body, headers=headers, ssl=_SSL_CTX
                    ) as resp:
                        return await self._process_state_response(resp, exec_state, endpoint)
                else:
                    async with session.get(
                        url, headers=headers, ssl=_SSL_CTX
                    ) as resp:
                        return await self._process_state_response(resp, exec_state, endpoint)

        except Exception as e:
            logger.debug(f"[WORKFLOW] State execution failed: {endpoint}: {e}")
            return None

    async def _process_state_response(
        self,
        resp: aiohttp.ClientResponse,
        exec_state: WorkflowExecutionState,
        endpoint: str,
    ) -> dict:
        """Process response and extract state tokens."""
        text = await resp.text()

        result = {
            "status": resp.status,
            "headers": dict(resp.headers),
            "body": text[:3000],
            "body_hash": hashlib.md5(text.encode()).hexdigest(),
            "endpoint": endpoint,
        }

        # Extract state tokens from response
        for token_name, patterns in STATE_TOKEN_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    exec_state.state_tokens[token_name] = match.group(1)
                    break

        # Update cookies from response
        for cookie in resp.cookies.values():
            exec_state.cookies[cookie.key] = cookie.value

        # Record in history
        exec_state.step_history.append({
            "endpoint": endpoint,
            "status": resp.status,
            "body_hash": result["body_hash"],
            "tokens_captured": list(exec_state.state_tokens.keys()),
        })

        return result

    def _is_success_response(self, resp: dict) -> bool:
        """Check if response indicates successful state transition."""
        status = resp.get("status", 0)
        if status not in (200, 201, 202, 302):
            return False

        body = resp.get("body", "").lower()

        # Success indicators
        success_words = ["success", "complete", "confirmed", "approved", "done", "thank", "created"]
        if any(word in body for word in success_words):
            return True

        # Check for IDs (indicates something was created)
        if re.search(r'"(?:order|transaction|confirmation|id|token)_?(?:id)?"\s*:', body):
            return True

        # 200/201 with JSON and no error
        if status in (200, 201) and "{" in body and '"error"' not in body.lower():
            return True

        return False

    async def _test_step_skipping(self) -> list[Finding]:
        """Test if intermediate workflow steps can be skipped."""
        findings: list[Finding] = []

        for workflow in self._inferred_workflows:
            if len(workflow.states) < 3:
                continue  # Need at least 3 states to skip

            logger.debug(f"[WORKFLOW] Testing step skipping for {workflow.name}")

            # Test 1: Skip all middle steps (first → last)
            first_state = workflow.states[0]
            last_state = workflow.states[-1]

            exec_state = WorkflowExecutionState()

            # Execute first state
            first_resp = await self._execute_workflow_state(
                first_state.url_pattern, "GET", exec_state
            )

            if not first_resp:
                continue

            # Try to skip to last state
            last_resp = await self._execute_workflow_state(
                last_state.url_pattern, "POST", exec_state
            )

            if last_resp and self._is_success_response(last_resp):
                skipped = [s.name for s in workflow.states[1:-1]]
                findings.append(Finding(
                    name=f"Multi-Step Skip: {workflow.name}",
                    severity=Severity.HIGH if workflow.name in ("checkout", "transfer", "payment") else "MEDIUM",
                    confidence_score=90,
                    vulnerability_type="business_logic",
                    module_name="workflow_inference",
                    description=(
                        f"Workflow '{workflow.name}' allows skipping {len(skipped)} required steps. "
                        f"Steps skipped: {', '.join(skipped)}. "
                        f"This can bypass payment, verification, or authorization checks."
                    ),
                    endpoint=last_state.url_pattern,
                    evidence=[
                        f"Workflow: {workflow.name} ({len(workflow.states)} states)",
                        f"First state: {first_state.name}",
                        f"Skipped: {skipped}",
                        f"Final state accessed with status {last_resp.get('status')}",
                    ],
                    metadata={
                        "workflow": workflow.name,
                        "skipped_steps": skipped,
                        "test_type": "multi_step_skip",
                    },
                ))
                continue  # Found issue, move to next workflow

            # Test 2: Skip individual steps
            for i in range(1, len(workflow.states) - 1):
                skipped_state = workflow.states[i]
                next_state = workflow.states[i + 1]

                exec_state = WorkflowExecutionState()

                # Execute states up to the one before skipped
                for j in range(i):
                    await self._execute_workflow_state(
                        workflow.states[j].url_pattern,
                        "POST" if j > 0 else "GET",
                        exec_state
                    )

                # Try to skip to next state
                skip_resp = await self._execute_workflow_state(
                    next_state.url_pattern, "POST", exec_state
                )

                if skip_resp and self._is_success_response(skip_resp):
                    findings.append(Finding(
                        name=f"Step Skip: {skipped_state.name} in {workflow.name}",
                        severity=Severity.MEDIUM,
                        confidence_score=85,
                        vulnerability_type="business_logic",
                        module_name="workflow_inference",
                        description=(
                            f"Step '{skipped_state.name}' can be skipped in workflow '{workflow.name}'. "
                            f"This may bypass validation, payment, or security checks at that step."
                        ),
                        endpoint=next_state.url_pattern,
                        evidence=[
                            f"Skipped: {skipped_state.name} ({skipped_state.url_pattern})",
                            f"Accessed: {next_state.name} ({next_state.url_pattern})",
                        ],
                        metadata={
                            "workflow": workflow.name,
                            "skipped_step": skipped_state.name,
                            "test_type": "single_step_skip",
                        },
                    ))
                    break  # One finding per workflow

        return findings

    async def _test_cross_step_injection(self) -> list[Finding]:
        """Test injecting final-step values in early workflow steps."""
        findings: list[Finding] = []

        for workflow in self._inferred_workflows:
            if len(workflow.states) < 2:
                continue

            first_state = workflow.states[0]
            url = first_state.url_pattern
            if not url.startswith("http"):
                url = urljoin(self._base_url, url)

            for param in CROSS_STEP_SENSITIVE_PARAMS[:8]:  # Test first 8
                try:
                    if self._rate_limiter:
                        await self._rate_limiter.acquire()

                    body = {param: "0", "_test": "cross_step_injection"}

                    async with aiohttp.ClientSession(timeout=self._timeout) as session:
                        async with session.post(
                            url, json=body, headers=self._auth_headers, ssl=_SSL_CTX
                        ) as resp:
                            if resp.status in (200, 201):
                                text = await resp.text()
                                text_lower = text.lower()

                                # Check if param was accepted (echoed back or no error)
                                if (f'"{param}"' in text_lower or
                                    ('"error"' not in text_lower and len(text) > 50)):
                                    findings.append(Finding(
                                        name=f"Cross-Step Injection: {param}",
                                        severity=Severity.HIGH if param in ("total", "price", "amount", "admin") else "MEDIUM",
                                        confidence_score=75,
                                        vulnerability_type="business_logic",
                                        module_name="workflow_inference",
                                        description=(
                                            f"Sensitive parameter '{param}' can be set in early workflow step "
                                            f"('{first_state.name}'). This value may persist to later steps, "
                                            f"allowing manipulation of totals, status, or access controls."
                                        ),
                                        endpoint=url,
                                        evidence=[
                                            f"Workflow: {workflow.name}",
                                            f"Injected: {param}=0 at step {first_state.name}",
                                            f"Response status: {resp.status}",
                                        ],
                                        metadata={
                                            "workflow": workflow.name,
                                            "injected_param": param,
                                            "test_type": "cross_step_injection",
                                        },
                                    ))
                                    break  # One finding per workflow

                except Exception as e:
                    logger.debug(f"[WORKFLOW] Cross-step injection test failed: {e}")

        return findings

    async def _test_step_repetition(self) -> list[Finding]:
        """Test if workflow steps can be repeated for extra benefit."""
        findings: list[Finding] = []

        # Keywords that suggest repeatable benefit
        benefit_keywords = ["coupon", "discount", "bonus", "credit", "reward", "apply", "redeem", "promo"]

        for workflow in self._inferred_workflows:
            for state in workflow.states:
                path_lower = state.url_pattern.lower()
                if not any(kw in path_lower for kw in benefit_keywords):
                    continue

                exec_state = WorkflowExecutionState()

                # Execute workflow up to this state
                state_idx = workflow.states.index(state)
                for i in range(state_idx + 1):
                    await self._execute_workflow_state(
                        workflow.states[i].url_pattern,
                        "POST" if i > 0 else "GET",
                        exec_state
                    )

                if not exec_state.step_history:
                    continue

                first_hash = exec_state.step_history[-1].get("body_hash", "")

                # Try to repeat the beneficial step
                repeat_resp = await self._execute_workflow_state(
                    state.url_pattern, "POST", exec_state
                )

                if repeat_resp and self._is_success_response(repeat_resp):
                    second_hash = repeat_resp.get("body_hash", "")

                    # If response differs, benefit may have been applied twice
                    if first_hash != second_hash:
                        findings.append(Finding(
                            name=f"Step Repeat: {state.name}",
                            severity=Severity.HIGH,
                            confidence_score=80,
                            vulnerability_type="business_logic",
                            module_name="workflow_inference",
                            description=(
                                f"Step '{state.name}' in workflow '{workflow.name}' can be repeated, "
                                f"potentially applying benefits (discounts, credits, rewards) multiple times."
                            ),
                            endpoint=state.url_pattern,
                            evidence=[
                                f"Workflow: {workflow.name}",
                                f"Repeated step: {state.name}",
                                f"First response hash: {first_hash[:16]}...",
                                f"Second response hash: {second_hash[:16]}...",
                            ],
                            metadata={
                                "workflow": workflow.name,
                                "repeated_step": state.name,
                                "test_type": "step_repeat",
                            },
                        ))
                        break  # One finding per workflow

        return findings

    async def _test_orphan_state(self) -> list[Finding]:
        """Test for exploitable orphan state after workflow cancellation."""
        findings: list[Finding] = []

        cancel_patterns = ["/cancel", "/abort", "/clear", "/reset", "/abandon", "/delete"]

        for workflow in self._inferred_workflows:
            if len(workflow.states) < 2:
                continue

            # Execute first 2 steps to create state
            exec_state = WorkflowExecutionState()
            for state in workflow.states[:2]:
                await self._execute_workflow_state(
                    state.url_pattern,
                    "POST" if workflow.states.index(state) > 0 else "GET",
                    exec_state
                )

            if not exec_state.state_tokens:
                continue  # No state to test

            captured_tokens = dict(exec_state.state_tokens)

            # Try to find and execute cancel endpoint
            cancel_executed = False
            for pattern in cancel_patterns:
                cancel_url = urljoin(self._base_url, pattern)
                try:
                    if self._rate_limiter:
                        await self._rate_limiter.acquire()

                    async with aiohttp.ClientSession(timeout=self._timeout) as session:
                        async with session.post(
                            cancel_url, json={}, headers=self._auth_headers, ssl=_SSL_CTX
                        ) as resp:
                            if resp.status in (200, 201, 204):
                                cancel_executed = True
                                break
                except Exception:
                    pass

            if not cancel_executed:
                continue

            # After cancel, try to access captured state tokens
            for token_name, token_value in captured_tokens.items():
                if token_name not in ("cart_id", "order_id", "session_id", "transaction_id"):
                    continue

                # Try common resource patterns
                resource_patterns = [
                    f"/api/{token_name.replace('_id', '')}/{token_value}",
                    f"/api/{token_name.replace('_id', '')}s/{token_value}",
                    f"/{token_name.replace('_id', '')}/{token_value}",
                ]

                for resource_pattern in resource_patterns:
                    resource_url = urljoin(self._base_url, resource_pattern)
                    try:
                        async with aiohttp.ClientSession(timeout=self._timeout) as session:
                            async with session.get(
                                resource_url, headers=self._auth_headers, ssl=_SSL_CTX
                            ) as resp:
                                if resp.status == 200:
                                    text = await resp.text()
                                    if len(text) > 50 and "error" not in text.lower():
                                        findings.append(Finding(
                                            name=f"Orphan State: {token_name}",
                                            severity=Severity.MEDIUM,
                                            confidence_score=70,
                                            vulnerability_type="business_logic",
                                            module_name="workflow_inference",
                                            description=(
                                                f"After cancelling workflow '{workflow.name}', the "
                                                f"{token_name} resource remains accessible. This orphan "
                                                f"state may allow data access or resuming cancelled operations."
                                            ),
                                            endpoint=resource_url,
                                            evidence=[
                                                f"Workflow: {workflow.name}",
                                                f"Orphan: {token_name}={token_value}",
                                                f"Resource still accessible after cancel",
                                            ],
                                            metadata={
                                                "workflow": workflow.name,
                                                "orphan_token": token_name,
                                                "test_type": "orphan_state",
                                            },
                                        ))
                                        break
                    except Exception:
                        pass

        return findings

    async def _test_workflow_race(self) -> list[Finding]:
        """Test for race conditions between workflow steps."""
        findings: list[Finding] = []

        for workflow in self._inferred_workflows:
            if len(workflow.states) < 2:
                continue

            logger.debug(f"[WORKFLOW] Testing race conditions for {workflow.name}")

            # Prepare concurrent requests for multiple steps
            async def execute_step(state: WorkflowState) -> tuple[str, int, str]:
                url = state.url_pattern
                if not url.startswith("http"):
                    url = urljoin(self._base_url, url)
                try:
                    async with aiohttp.ClientSession(timeout=self._timeout) as session:
                        async with session.post(
                            url, json={}, headers=self._auth_headers, ssl=_SSL_CTX
                        ) as resp:
                            text = await resp.text()
                            return state.name, resp.status, text[:500]
                except Exception as e:
                    return state.name, 0, str(e)

            # Execute first 3 steps concurrently
            states_to_test = workflow.states[:3]
            tasks = [execute_step(state) for state in states_to_test]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Analyze results
            success_count = sum(
                1 for r in results
                if isinstance(r, tuple) and r[1] in (200, 201, 202)
            )

            if success_count >= 2:
                successful_steps = [
                    r[0] for r in results
                    if isinstance(r, tuple) and r[1] in (200, 201, 202)
                ]

                # Check if non-adjacent steps succeeded (indicates race)
                step_indices = []
                for step_name in successful_steps:
                    for i, s in enumerate(workflow.states):
                        if s.name == step_name:
                            step_indices.append(i)
                            break

                if len(step_indices) >= 2:
                    # Multiple non-initial steps succeeded concurrently
                    if max(step_indices) - min(step_indices) >= 1 or min(step_indices) > 0:
                        findings.append(Finding(
                            name=f"Workflow Race: {workflow.name}",
                            severity=Severity.MEDIUM,
                            confidence_score=65,
                            vulnerability_type="business_logic",
                            module_name="workflow_inference",
                            description=(
                                f"Multiple steps of workflow '{workflow.name}' can execute concurrently, "
                                f"potentially bypassing sequential validation or causing state corruption. "
                                f"Concurrent successes: {successful_steps}"
                            ),
                            endpoint=workflow.endpoints[0] if workflow.endpoints else self._base_url,
                            evidence=[
                                f"Workflow: {workflow.name}",
                                f"Concurrent steps: {successful_steps}",
                                f"Expected sequential execution",
                            ],
                            metadata={
                                "workflow": workflow.name,
                                "concurrent_steps": successful_steps,
                                "test_type": "workflow_race",
                            },
                        ))

        return findings
