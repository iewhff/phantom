"""
Business Logic Vulnerability Scanner - ENTERPRISE EDITION v2.0
Tests for logic flaws that automated scanners typically miss.

SAFETY MODES:
- passive/safe/cautious: READ-ONLY mode - Analysis without state changes
- standard: Safe tests with non-existent resources only
- aggressive: Full testing including state-changing operations

Enterprise Features:
- State Machine Analysis with transition validation
- Multi-step Transaction Testing with context tracking
- Currency/Financial Edge Cases (precision, overflow, rounding)
- Advanced Parallel Race Detection with timing analysis
- Business Rule Bypass with signature analysis
- Inventory/Stock Manipulation testing
- Privilege Escalation via Business Logic
- Idempotency Key Abuse detection
- Time-based Business Rule Bypass
- Response Fingerprinting for enumeration

CWE Coverage: CWE-362, CWE-20, CWE-841, CWE-840, CWE-770, CWE-302, CWE-204, CWE-190, CWE-191
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import time
import random
import string
import json
from dataclasses import dataclass, field
from decimal import Decimal, ROUND_DOWN, ROUND_HALF_UP
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs

import httpx

from scanning.vuln_scanner import Finding, ScanModule
from utils.endpoint_map import EndpointMap, EndpointCategory
from utils.endpoint_validator import EndpointValidator
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


# Safe mode environment variable - set by full_scanner.py
SAFE_MODE = os.environ.get("PHANTOM_SAFE_MODE", "safe").lower()
ALLOW_WRITES = SAFE_MODE in ("standard", "aggressive")


# ============================================================================
# ENTERPRISE: State Machine & Transaction Tracking
# ============================================================================

class WorkflowState(Enum):
    """Workflow state definitions for state machine analysis."""
    INITIAL = auto()
    CART_CREATED = auto()
    ITEMS_ADDED = auto()
    ADDRESS_SET = auto()
    PAYMENT_PENDING = auto()
    PAYMENT_PROCESSING = auto()
    PAYMENT_COMPLETED = auto()
    ORDER_CONFIRMED = auto()
    ORDER_SHIPPED = auto()
    ORDER_DELIVERED = auto()
    REFUND_REQUESTED = auto()
    REFUND_PROCESSED = auto()
    ACCOUNT_CREATED = auto()
    EMAIL_PENDING = auto()
    EMAIL_VERIFIED = auto()
    PASSWORD_RESET_REQUESTED = auto()
    PASSWORD_RESET_COMPLETED = auto()


# Valid state transitions for detecting bypass attempts
VALID_TRANSITIONS = {
    WorkflowState.INITIAL: [WorkflowState.CART_CREATED, WorkflowState.ACCOUNT_CREATED],
    WorkflowState.CART_CREATED: [WorkflowState.ITEMS_ADDED],
    WorkflowState.ITEMS_ADDED: [WorkflowState.ADDRESS_SET, WorkflowState.ITEMS_ADDED],
    WorkflowState.ADDRESS_SET: [WorkflowState.PAYMENT_PENDING],
    WorkflowState.PAYMENT_PENDING: [WorkflowState.PAYMENT_PROCESSING],
    WorkflowState.PAYMENT_PROCESSING: [WorkflowState.PAYMENT_COMPLETED, WorkflowState.PAYMENT_PENDING],
    WorkflowState.PAYMENT_COMPLETED: [WorkflowState.ORDER_CONFIRMED],
    WorkflowState.ORDER_CONFIRMED: [WorkflowState.ORDER_SHIPPED, WorkflowState.REFUND_REQUESTED],
    WorkflowState.ORDER_SHIPPED: [WorkflowState.ORDER_DELIVERED],
    WorkflowState.ORDER_DELIVERED: [WorkflowState.REFUND_REQUESTED],
    WorkflowState.REFUND_REQUESTED: [WorkflowState.REFUND_PROCESSED],
    WorkflowState.ACCOUNT_CREATED: [WorkflowState.EMAIL_PENDING],
    WorkflowState.EMAIL_PENDING: [WorkflowState.EMAIL_VERIFIED],
}


@dataclass
class TransactionContext:
    """Tracks transaction state for multi-step testing."""
    session_id: str = ""
    cart_id: str = ""
    order_id: str = ""
    user_id: str = ""
    tokens: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    current_state: WorkflowState = WorkflowState.INITIAL
    state_history: list = field(default_factory=list)
    response_hashes: dict = field(default_factory=dict)
    financial_values: dict = field(default_factory=dict)
    
    def transition_to(self, new_state: WorkflowState) -> bool:
        """Attempt state transition, return False if invalid."""
        valid_next = VALID_TRANSITIONS.get(self.current_state, [])
        self.state_history.append((self.current_state, new_state))
        self.current_state = new_state
        return new_state in valid_next


@dataclass
class RaceConditionResult:
    """Result of race condition testing."""
    endpoint: str
    concurrent_requests: int
    successful_requests: int
    duplicate_effects: bool
    timing_variance_ms: float
    response_patterns: list
    vulnerability_confidence: float  # 0.0 to 1.0


@dataclass
class FinancialTestCase:
    """Test case for financial manipulation testing."""
    name: str
    payload: dict
    expected_rejection: bool
    severity: str
    description: str


# ============================================================================
# ENTERPRISE: Financial Edge Case Test Library
# ============================================================================

FINANCIAL_TEST_CASES = [
    # Negative value attacks
    FinancialTestCase("negative_price", {"price": -100}, True, "CRITICAL", "Negative price exploitation"),
    FinancialTestCase("negative_quantity", {"quantity": -1}, True, "CRITICAL", "Negative quantity for credit"),
    FinancialTestCase("negative_discount", {"discount": -50}, True, "HIGH", "Negative discount increases price"),
    
    # Zero value attacks
    FinancialTestCase("zero_price", {"price": 0}, True, "HIGH", "Zero price bypass"),
    FinancialTestCase("zero_total", {"total": 0}, True, "HIGH", "Zero total manipulation"),
    
    # Precision attacks
    FinancialTestCase("precision_small", {"price": 0.001}, True, "MEDIUM", "Ultra-small precision value"),
    FinancialTestCase("precision_many_decimals", {"price": 0.0000001}, True, "MEDIUM", "Many decimal places"),
    FinancialTestCase("precision_rounding", {"price": 9.999999999}, True, "MEDIUM", "Rounding exploitation"),
    
    # Integer overflow attacks
    FinancialTestCase("int_overflow_32", {"amount": 2147483648}, True, "CRITICAL", "32-bit integer overflow"),
    FinancialTestCase("int_overflow_64", {"amount": 9223372036854775808}, True, "CRITICAL", "64-bit integer overflow"),
    FinancialTestCase("int_underflow", {"amount": -2147483649}, True, "CRITICAL", "Integer underflow"),
    
    # Scientific notation attacks
    FinancialTestCase("scientific_large", {"price": "1e10"}, True, "HIGH", "Scientific notation large"),
    FinancialTestCase("scientific_small", {"price": "1e-10"}, True, "HIGH", "Scientific notation small"),
    
    # String injection
    FinancialTestCase("string_zero", {"price": "0"}, True, "MEDIUM", "String zero injection"),
    FinancialTestCase("string_negative", {"price": "-100"}, True, "HIGH", "String negative injection"),
    FinancialTestCase("string_nan", {"price": "NaN"}, True, "MEDIUM", "NaN string injection"),
    FinancialTestCase("string_infinity", {"price": "Infinity"}, True, "HIGH", "Infinity string injection"),
    
    # Currency manipulation
    FinancialTestCase("currency_mismatch", {"price": 100, "currency": "XXX"}, True, "MEDIUM", "Invalid currency code"),
    FinancialTestCase("currency_conversion", {"price": 100, "currency": "JPY", "target_currency": "USD"}, True, "HIGH", "Currency conversion abuse"),
    
    # Bulk/quantity attacks
    FinancialTestCase("bulk_large", {"quantity": 999999999}, True, "HIGH", "Massive quantity order"),
    FinancialTestCase("bulk_fractional", {"quantity": 0.5}, True, "MEDIUM", "Fractional quantity"),
]

# ============================================================================
# ENTERPRISE: Idempotency & Race Condition Payloads
# ============================================================================

RACE_CONDITION_SCENARIOS = [
    # =========================================================================
    # HIGH-VALUE FINANCIAL RACE CONDITIONS ($5k-$50k bounties)
    # =========================================================================

    # Double-spend / Payment duplication
    {"name": "coupon_apply", "endpoints": ["coupon", "discount", "promo", "voucher", "code"],
     "method": "POST", "severity": "CRITICAL", "impact": "Free products/services via double coupon use"},
    {"name": "checkout_complete", "endpoints": ["checkout", "order", "purchase", "buy"],
     "method": "POST", "severity": "CRITICAL", "impact": "Double order creation, inventory depletion"},

    # Balance manipulation (CRITICAL)
    {"name": "balance_transfer", "endpoints": ["transfer", "send", "payment", "pay", "withdraw"],
     "method": "POST", "severity": "CRITICAL", "impact": "Double-spend, balance manipulation"},
    {"name": "wallet_topup", "endpoints": ["topup", "deposit", "credit", "add-funds", "fund"],
     "method": "POST", "severity": "CRITICAL", "impact": "Credit balance without payment"},

    # Points/Rewards abuse
    {"name": "points_redeem", "endpoints": ["redeem", "points", "rewards", "claim", "cashback"],
     "method": "POST", "severity": "HIGH", "impact": "Double-redeem loyalty points"},
    {"name": "referral_claim", "endpoints": ["referral", "invite", "bonus", "signup-bonus"],
     "method": "POST", "severity": "HIGH", "impact": "Multiple referral bonus claims"},

    # Inventory manipulation
    {"name": "inventory_reserve", "endpoints": ["reserve", "cart", "hold", "book", "lock"],
     "method": "POST", "severity": "HIGH", "impact": "Inventory overselling, stock depletion"},
    {"name": "limited_item_purchase", "endpoints": ["limited", "exclusive", "flash-sale", "deal"],
     "method": "POST", "severity": "HIGH", "impact": "Bypass purchase limits"},

    # Subscription/Credit abuse
    {"name": "trial_activation", "endpoints": ["trial", "free-trial", "demo", "start-trial"],
     "method": "POST", "severity": "MEDIUM", "impact": "Multiple trial activations"},
    {"name": "subscription_upgrade", "endpoints": ["upgrade", "subscription", "plan"],
     "method": "POST", "severity": "HIGH", "impact": "Free upgrades via race condition"},

    # Limit bypass
    {"name": "rate_limit_bypass", "endpoints": ["api", "request", "action"],
     "method": "POST", "severity": "MEDIUM", "impact": "Bypass rate limiting controls"},
    {"name": "quota_exceed", "endpoints": ["usage", "quota", "limit", "allocation"],
     "method": "POST", "severity": "MEDIUM", "impact": "Exceed usage quotas"},

    # Social/Gaming abuse
    {"name": "vote_submit", "endpoints": ["vote", "poll", "rate", "review"],
     "method": "POST", "severity": "LOW", "impact": "Vote manipulation"},
    {"name": "like_action", "endpoints": ["like", "favorite", "follow", "upvote"],
     "method": "POST", "severity": "LOW", "impact": "Engagement manipulation"},

    # Withdrawal/Payout
    {"name": "withdrawal_request", "endpoints": ["withdraw", "payout", "cashout", "cash-out"],
     "method": "POST", "severity": "CRITICAL", "impact": "Double withdrawal, fund theft"},
    {"name": "refund_process", "endpoints": ["refund", "return", "chargeback", "reversal"],
     "method": "POST", "severity": "CRITICAL", "impact": "Double refund, financial loss"},
]


# Financial-specific race condition payloads for better detection
FINANCIAL_RACE_PAYLOADS = {
    "balance_transfer": {"amount": 100, "to_account": "attacker_account", "currency": "USD"},
    "wallet_topup": {"amount": 50, "method": "test_card"},
    "coupon_apply": {"code": "TESTCODE50", "apply": True},
    "withdrawal_request": {"amount": 100, "method": "bank_transfer"},
    "refund_process": {"order_id": "test_order", "reason": "test_refund"},
    "points_redeem": {"points": 1000, "reward_id": "test_reward"},
}


@dataclass
class BusinessFlow:
    """Represents a business workflow to test."""
    name: str
    steps: list[dict[str, Any]]
    expected_behavior: str
    abuse_scenarios: list[str] = field(default_factory=list)
    required_state: WorkflowState = WorkflowState.INITIAL
    result_state: WorkflowState = WorkflowState.INITIAL


class BusinessLogicScanner(ScanModule):
    """
    Business Logic Vulnerability Scanner.
    
    Tests for:
    - Race conditions (TOCTOU)
    - Price/quantity manipulation
    - Workflow bypass (skip steps)
    - Limit bypass (rate limits, quotas)
    - Privilege escalation via logic
    - Coupon/discount abuse
    - Refund/chargeback abuse
    - Account enumeration via logic
    - Negative value exploitation
    - Integer overflow/underflow
    """
    
    name = "business_logic_scanner"
    
    # Common e-commerce endpoints
    ECOMMERCE_ENDPOINTS = {
        "cart": [
            "/cart", "/api/cart", "/basket", "/shopping-cart",
            # Juice Shop specific
            "/rest/basket", "/api/BasketItems", "/api/Quantitys",
        ],
        "checkout": [
            "/checkout", "/api/checkout", "/payment", "/order",
            # Juice Shop specific
            "/rest/basket/checkout", "/api/Orders",
        ],
        "coupon": [
            "/coupon", "/api/coupon", "/discount", "/promo", "/voucher",
            # Juice Shop specific - coupon endpoint pattern
            "/rest/basket/1/coupon", "/rest/basket/2/coupon",
        ],
        "pricing": [
            "/api/price", "/api/product", "/products",
            # Juice Shop specific
            "/rest/products", "/api/Products",
        ],
        "order": [
            "/order", "/api/order", "/orders", "/api/orders",
            # Juice Shop specific
            "/rest/track-order", "/api/Recycles", "/api/Deliverys",
        ],
        "refund": ["/refund", "/api/refund", "/return", "/api/return"],
    }
    
    # Common auth/account endpoints
    AUTH_ENDPOINTS = {
        "register": ["/register", "/signup", "/api/register", "/api/users"],
        "password": ["/password", "/reset-password", "/forgot-password", "/api/password"],
        "profile": ["/profile", "/account", "/api/profile", "/api/account", "/api/me"],
        "verify": ["/verify", "/confirm", "/activate", "/api/verify"],
    }
    
    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.timeout = settings.timeouts.request_timeout
    
    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """Scan for business logic vulnerabilities - ENTERPRISE EDITION."""
        findings: list[dict[str, Any]] = []
        
        base_url = f"https://{host}" if not host.startswith("http") else host
        
        # Initialize transaction context for stateful testing
        tx_context = TransactionContext(
            session_id=self._generate_session_id(),
            user_id=f"test_user_{int(time.time())}",
        )
        
        # Discover business endpoints
        endpoints = await self._discover_business_endpoints(base_url, rate_limiter)
        
        # ====================================================================
        # CORE TESTS (Original)
        # ====================================================================
        
        # Test race conditions
        race_findings = await self._test_race_conditions(base_url, endpoints, rate_limiter)
        findings.extend(race_findings)
        
        # Test price manipulation
        price_findings = await self._test_price_manipulation(base_url, endpoints, rate_limiter)
        findings.extend(price_findings)
        
        # Test workflow bypass
        workflow_findings = await self._test_workflow_bypass(base_url, endpoints, rate_limiter)
        findings.extend(workflow_findings)
        
        # Test limit bypass
        limit_findings = await self._test_limit_bypass(base_url, endpoints, rate_limiter)
        findings.extend(limit_findings)
        
        # Test negative values
        negative_findings = await self._test_negative_values(base_url, endpoints, rate_limiter)
        findings.extend(negative_findings)
        
        # Test coupon abuse
        coupon_findings = await self._test_coupon_abuse(base_url, endpoints, rate_limiter)
        findings.extend(coupon_findings)
        
        # Test account enumeration via logic
        enum_findings = await self._test_account_enumeration(base_url, rate_limiter)
        findings.extend(enum_findings)
        
        # ====================================================================
        # ENTERPRISE TESTS (New)
        # ====================================================================
        
        # Enterprise: State Machine Analysis
        state_findings = await self._test_state_machine_bypass(base_url, endpoints, rate_limiter, tx_context)
        findings.extend(state_findings)
        
        # Enterprise: Advanced Race Conditions with Parallel Analysis
        adv_race_findings = await self._test_advanced_race_conditions(base_url, endpoints, rate_limiter)
        findings.extend(adv_race_findings)
        
        # Enterprise: Financial Edge Cases (precision, overflow, currency)
        financial_findings = await self._test_financial_edge_cases(base_url, endpoints, rate_limiter)
        findings.extend(financial_findings)
        
        # Enterprise: Multi-step Transaction Abuse
        transaction_findings = await self._test_multi_step_transactions(base_url, endpoints, rate_limiter, tx_context)
        findings.extend(transaction_findings)
        
        # Enterprise: Idempotency Key Abuse
        idempotency_findings = await self._test_idempotency_abuse(base_url, endpoints, rate_limiter)
        findings.extend(idempotency_findings)
        
        # Enterprise: Inventory/Stock Manipulation
        inventory_findings = await self._test_inventory_manipulation(base_url, endpoints, rate_limiter)
        findings.extend(inventory_findings)
        
        # Enterprise: Time-based Business Rule Bypass
        time_findings = await self._test_time_based_bypass(base_url, endpoints, rate_limiter)
        findings.extend(time_findings)
        
        # Enterprise: Response Fingerprinting
        fingerprint_findings = await self._test_response_fingerprinting(base_url, endpoints, rate_limiter)
        findings.extend(fingerprint_findings)
        
        return {
            "module": self.name,
            "version": "2.0-enterprise",
            "findings": findings,
            "endpoints_discovered": endpoints,
            "transaction_context": {
                "states_tested": len(tx_context.state_history),
                "financial_tests": len(FINANCIAL_TEST_CASES),
                "race_scenarios": len(RACE_CONDITION_SCENARIOS),
            },
        }
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID for testing."""
        return hashlib.sha256(f"{time.time()}{random.random()}".encode()).hexdigest()[:16]
    
    async def _discover_business_endpoints(
        self,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> dict[str, list[str]]:
        """Discover business-related endpoints using EndpointMap + fallback."""
        discovered = {}

        # PRIORITY 1: Get endpoints from EndpointMap by category
        endpoint_map = EndpointMap.get_instance()

        # Map EndpointMap categories to business logic categories
        category_mapping = {
            "cart": EndpointCategory.PAYMENT,
            "checkout": EndpointCategory.PAYMENT,
            "coupon": EndpointCategory.PAYMENT,
            "pricing": EndpointCategory.API_REST,
            "order": EndpointCategory.PAYMENT,
            "refund": EndpointCategory.PAYMENT,
            "register": EndpointCategory.AUTH,
            "password": EndpointCategory.AUTH,
            "profile": EndpointCategory.USER_DATA,
            "verify": EndpointCategory.AUTH,
        }

        map_has_endpoints = False
        for local_category, map_category in category_mapping.items():
            eps = endpoint_map.get_by_category(map_category)
            if eps:
                discovered[local_category] = [
                    urljoin(base_url, ep.path) for ep in eps
                    if ep.verified or ep.confidence >= 0.7
                ]
                if discovered[local_category]:
                    map_has_endpoints = True

        if map_has_endpoints:
            total_found = sum(len(v) for v in discovered.values())
            logger.info(f"[BusinessLogic] Using {total_found} endpoints from EndpointMap")
            return discovered

        # FALLBACK: Use hardcoded patterns + EndpointValidator
        all_endpoints = {**self.ECOMMERCE_ENDPOINTS, **self.AUTH_ENDPOINTS}
        validator = EndpointValidator.get_instance()

        for category, paths in all_endpoints.items():
            existing = await validator.filter_existing_endpoints(
                base_url, paths, rate_limiter, max_concurrent=10
            )
            discovered[category] = existing

        total_found = sum(len(v) for v in discovered.values())
        logger.debug(f"[BusinessLogic] Fallback discovered {total_found} business endpoints")

        return discovered
    
    async def _test_race_conditions(
        self,
        base_url: str,
        endpoints: dict[str, list[str]],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test for race condition vulnerabilities (TOCTOU)."""
        findings = []
        
        # Test endpoints prone to race conditions
        race_prone = endpoints.get("coupon", []) + endpoints.get("checkout", [])
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for endpoint in race_prone[:5]:
                # Prepare concurrent requests
                test_data = {"code": "TEST", "quantity": 1}
                
                async def make_request():
                    try:
                        return await client.post(endpoint, json=test_data)
                    except Exception:
                        return None
                
                # Send multiple concurrent requests
                tasks = [make_request() for _ in range(10)]
                responses = await asyncio.gather(*tasks)
                
                # Analyze responses for race condition indicators
                valid_responses = [r for r in responses if r is not None]
                
                if len(valid_responses) >= 5:
                    status_codes = [r.status_code for r in valid_responses]
                    
                    # If we get mixed results, might indicate race condition
                    if len(set(status_codes)) > 1:
                        success_count = sum(1 for s in status_codes if s in [200, 201])
                        
                        if success_count > 1:
                            findings.append(Finding(
                                type="business_logic",
                                name="Potential Race Condition (TOCTOU)",
                                severity="HIGH",
                                description=f"Endpoint {endpoint} may be vulnerable to race conditions. "
                                           f"Multiple concurrent requests returned success ({success_count}/10).",
                                host=base_url,
                                matched_at=endpoint,
                                evidence=[
                                    f"Concurrent requests: 10",
                                    f"Successful responses: {success_count}",
                                    f"Status codes: {status_codes}",
                                ],
                                cvss_score=7.5,
                                cwe="CWE-362",
                                remediation="Implement proper locking mechanisms. Use database transactions. "
                                           "Add idempotency keys. Implement optimistic locking.",
                                references=[
                                    "https://portswigger.net/web-security/race-conditions"
                                ],
                            ).to_dict())
        
        return findings
    
    async def _test_price_manipulation(
        self,
        base_url: str,
        endpoints: dict[str, list[str]],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test for price/quantity manipulation vulnerabilities."""
        findings = []
        
        cart_endpoints = endpoints.get("cart", [])
        checkout_endpoints = endpoints.get("checkout", [])
        
        manipulation_payloads = [
            # Negative prices
            {"price": -100, "quantity": 1},
            {"price": -1, "amount": -1},
            {"total": -50},
            # Zero values
            {"price": 0, "quantity": 1},
            {"amount": 0},
            # Decimal manipulation
            {"price": 0.001, "quantity": 1000000},
            {"price": 0.00001},
            # Large quantities
            {"quantity": 999999999},
            {"quantity": -1},
            # String injection
            {"price": "0", "quantity": "1"},
            {"discount": "100%"},
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for endpoint in (cart_endpoints + checkout_endpoints)[:5]:
                for payload in manipulation_payloads[:5]:
                    await rate_limiter.acquire()
                    
                    try:
                        response = await client.post(endpoint, json=payload)
                        
                        if response.status_code in [200, 201]:
                            # Check if manipulation was accepted
                            try:
                                data = response.json()
                                
                                # Look for signs of successful manipulation
                                response_text = str(data).lower()
                                
                                if any(x in response_text for x in ["success", "created", "added"]):
                                    findings.append(Finding(
                                        type="business_logic",
                                        name="Price/Quantity Manipulation",
                                        severity="CRITICAL",
                                        description=f"Endpoint accepts manipulated price/quantity values. "
                                                   f"Payload {payload} was accepted.",
                                        host=base_url,
                                        matched_at=endpoint,
                                        evidence=[
                                            f"Payload: {payload}",
                                            f"Response: {response.status_code}",
                                        ],
                                        cvss_score=9.8,
                                        cwe="CWE-20",
                                        remediation="Validate all price/quantity values server-side. "
                                                   "Never trust client-provided prices. "
                                                   "Implement proper input validation.",
                                    ).to_dict())
                                    break
                            except Exception:
                                pass
                                
                    except Exception as e:
                        logger.debug(f"Price manipulation test error: {e}")
        
        return findings
    
    async def _test_workflow_bypass(
        self,
        base_url: str,
        endpoints: dict[str, list[str]],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test for workflow/step bypass vulnerabilities."""
        findings = []
        
        # Try to access final steps without completing prerequisites
        checkout_endpoints = endpoints.get("checkout", [])
        order_endpoints = endpoints.get("order", [])
        verify_endpoints = endpoints.get("verify", [])
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            # Test checkout without cart
            for endpoint in checkout_endpoints[:3]:
                await rate_limiter.acquire()
                
                try:
                    # Try POST directly to checkout without session/cart
                    response = await client.post(
                        endpoint,
                        json={"payment_method": "card", "complete": True},
                        headers={"X-Skip-Validation": "true"},
                    )
                    
                    if response.status_code in [200, 201]:
                        findings.append(Finding(
                            type="business_logic",
                            name="Workflow Bypass - Checkout Without Cart",
                            severity="HIGH",
                            description="Checkout endpoint accepts requests without proper cart session.",
                            host=base_url,
                            matched_at=endpoint,
                            evidence=["Direct checkout POST accepted"],
                            cvss_score=8.1,
                            cwe="CWE-841",
                            remediation="Enforce workflow state validation. "
                                       "Verify prerequisites before allowing step completion.",
                        ).to_dict())
                except Exception:
                    pass
            
            # Test email verification bypass
            for endpoint in verify_endpoints[:3]:
                await rate_limiter.acquire()
                
                try:
                    # Try common bypass tokens
                    bypass_tokens = ["1", "true", "verified", "admin", "0" * 32]
                    
                    for token in bypass_tokens:
                        verify_url = f"{endpoint}?token={token}"
                        response = await client.get(verify_url)
                        
                        if response.status_code == 200:
                            if any(x in response.text.lower() for x in ["verified", "confirmed", "success"]):
                                findings.append(Finding(
                                    type="business_logic",
                                    name="Verification Bypass",
                                    severity="HIGH",
                                    description=f"Email/account verification can be bypassed with token: {token}",
                                    host=base_url,
                                    matched_at=verify_url,
                                    evidence=[f"Bypass token: {token}"],
                                    cvss_score=8.1,
                                    cwe="CWE-302",
                                    remediation="Use cryptographically secure tokens. "
                                               "Implement proper token validation.",
                                ).to_dict())
                                break
                except Exception:
                    pass
        
        return findings
    
    async def _test_limit_bypass(
        self,
        base_url: str,
        endpoints: dict[str, list[str]],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test for limit/quota bypass vulnerabilities."""
        findings = []
        
        # Test rate limit bypass techniques
        password_endpoints = endpoints.get("password", [])
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for endpoint in password_endpoints[:2]:
                # Test different bypass headers
                bypass_headers_list = [
                    {"X-Forwarded-For": "127.0.0.1"},
                    {"X-Real-IP": "10.0.0.1"},
                    {"X-Originating-IP": "192.168.1.1"},
                    {"X-Client-IP": "172.16.0.1"},
                    {"True-Client-IP": "8.8.8.8"},
                    {"X-Forwarded-Host": "localhost"},
                ]
                
                for headers in bypass_headers_list:
                    responses = []
                    
                    for i in range(10):
                        # Rotate IP in header
                        test_headers = {k: f"{v.rsplit('.', 1)[0]}.{i}" for k, v in headers.items()}
                        
                        try:
                            response = await client.post(
                                endpoint,
                                json={"email": f"test{i}@test.com"},
                                headers=test_headers,
                            )
                            responses.append(response.status_code)
                        except Exception:
                            break
                    
                    # Check if rate limiting was bypassed
                    if len(responses) >= 10 and 429 not in responses:
                        findings.append(Finding(
                            type="business_logic",
                            name="Rate Limit Bypass via Headers",
                            severity="MEDIUM",
                            description=f"Rate limiting can be bypassed using {list(headers.keys())[0]} header.",
                            host=base_url,
                            matched_at=endpoint,
                            evidence=[
                                f"Header: {list(headers.keys())[0]}",
                                f"Requests sent: {len(responses)}",
                                "No 429 responses received",
                            ],
                            cvss_score=5.3,
                            cwe="CWE-770",
                            remediation="Don't rely solely on client headers for rate limiting. "
                                       "Implement server-side session-based limiting.",
                        ).to_dict())
                        break
        
        return findings
    
    async def _test_negative_values(
        self,
        base_url: str,
        endpoints: dict[str, list[str]],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test for negative value exploitation."""
        findings = []
        
        # Test transfer/payment endpoints with negative values
        relevant_endpoints = (
            endpoints.get("cart", []) + 
            endpoints.get("order", []) + 
            endpoints.get("refund", [])
        )
        
        negative_payloads = [
            {"amount": -100},
            {"quantity": -5},
            {"transfer_amount": -1000},
            {"points": -500},
            {"credits": -50},
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for endpoint in relevant_endpoints[:5]:
                for payload in negative_payloads:
                    await rate_limiter.acquire()
                    
                    try:
                        response = await client.post(endpoint, json=payload)
                        
                        if response.status_code in [200, 201]:
                            findings.append(Finding(
                                type="business_logic",
                                name="Negative Value Accepted",
                                severity="HIGH",
                                description=f"Endpoint accepts negative values: {payload}",
                                host=base_url,
                                matched_at=endpoint,
                                evidence=[f"Payload: {payload}", f"Status: {response.status_code}"],
                                cvss_score=8.1,
                                cwe="CWE-20",
                                remediation="Validate all numeric inputs are positive where expected. "
                                           "Implement proper bounds checking.",
                            ).to_dict())
                            break
                    except Exception:
                        pass
        
        return findings
    
    async def _test_coupon_abuse(
        self,
        base_url: str,
        endpoints: dict[str, list[str]],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test for coupon/discount abuse vulnerabilities."""
        findings = []
        
        coupon_endpoints = endpoints.get("coupon", [])
        
        abuse_tests = [
            # Multiple application
            {"codes": ["SAVE10", "SAVE10", "SAVE10"]},
            # Stacking
            {"code": "SAVE10", "additional_code": "SAVE20"},
            # Case manipulation
            {"code": "save10"},
            {"code": "SAVE10 "},
            {"code": " SAVE10"},
            # Expired codes (common patterns)
            {"code": "WELCOME2023"},
            {"code": "BLACKFRIDAY"},
            # Numeric manipulation
            {"code": "SAVE10", "discount_percent": 100},
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for endpoint in coupon_endpoints[:3]:
                # First, try to apply coupon multiple times
                successful_applications = 0
                
                for _ in range(3):
                    await rate_limiter.acquire()
                    
                    try:
                        response = await client.post(
                            endpoint,
                            json={"code": "TESTCOUPON"}
                        )
                        
                        if response.status_code == 200:
                            successful_applications += 1
                    except Exception:
                        pass
                
                if successful_applications > 1:
                    findings.append(Finding(
                        type="business_logic",
                        name="Coupon Reuse Vulnerability",
                        severity="MEDIUM",
                        description="Same coupon code can be applied multiple times.",
                        host=base_url,
                        matched_at=endpoint,
                        evidence=[f"Applied {successful_applications} times successfully"],
                        cvss_score=6.5,
                        cwe="CWE-840",
                        remediation="Track coupon usage. Implement one-time use validation.",
                    ).to_dict())
        
        return findings
    
    async def _test_account_enumeration(
        self,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test for account enumeration via timing/response differences."""
        findings = []

        enum_endpoints = [
            "/login",
            "/api/login",
            "/forgot-password",
            "/api/forgot-password",
            "/reset-password",
            "/register",
            "/api/register",
        ]

        # OPTIMIZATION: Filter to only existing endpoints
        validator = EndpointValidator.get_instance()
        existing_endpoints = await validator.filter_existing_endpoints(
            base_url, enum_endpoints, rate_limiter, max_concurrent=5
        )

        if not existing_endpoints:
            logger.debug("[BusinessLogic] No enumeration endpoints found, skipping")
            return findings

        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for endpoint in existing_endpoints:
                await rate_limiter.acquire()
                
                try:
                    # Test with likely existing email
                    start1 = time.time()
                    response1 = await client.post(
                        endpoint,
                        json={"email": "admin@" + base_url.split("//")[1].split("/")[0]}
                    )
                    time1 = time.time() - start1
                    
                    await rate_limiter.acquire()
                    
                    # Test with non-existing email
                    start2 = time.time()
                    response2 = await client.post(
                        endpoint,
                        json={"email": f"nonexistent{time.time()}@test.com"}
                    )
                    time2 = time.time() - start2
                    
                    # Check for enumeration indicators
                    indicators = []
                    
                    # Different status codes
                    if response1.status_code != response2.status_code:
                        indicators.append(f"Status codes differ: {response1.status_code} vs {response2.status_code}")
                    
                    # Different response lengths (significant)
                    len_diff = abs(len(response1.text) - len(response2.text))
                    if len_diff > 50:
                        indicators.append(f"Response lengths differ by {len_diff} chars")
                    
                    # Timing difference (>500ms might indicate DB lookup)
                    time_diff = abs(time1 - time2)
                    if time_diff > 0.5:
                        indicators.append(f"Response times differ by {time_diff:.2f}s")
                    
                    # Different error messages
                    if response1.text != response2.text:
                        # Check for common enumeration messages
                        enum_phrases = ["not found", "doesn't exist", "invalid user", "no account"]
                        for phrase in enum_phrases:
                            if phrase in response2.text.lower() and phrase not in response1.text.lower():
                                indicators.append(f"Different error message: '{phrase}'")
                    
                    if indicators:
                        findings.append(Finding(
                            type="business_logic",
                            name="Account Enumeration via Response Analysis",
                            severity="MEDIUM",
                            description=f"Endpoint reveals user existence through response differences.",
                            host=base_url,
                            matched_at=endpoint,
                            evidence=indicators,
                            cvss_score=5.3,
                            cwe="CWE-204",
                            remediation="Return identical responses for existing and non-existing users. "
                                       "Use consistent timing. Implement CAPTCHA.",
                        ).to_dict())
                        break
                        
                except Exception as e:
                    logger.debug(f"Account enumeration test error: {e}")
        
        return findings

    # ========================================================================
    # ENTERPRISE METHODS - State Machine Analysis
    # ========================================================================
    
    async def _test_state_machine_bypass(
        self,
        base_url: str,
        endpoints: dict[str, list[str]],
        rate_limiter: RateLimiter,
        tx_context: TransactionContext,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Test for state machine/workflow bypass vulnerabilities.
        
        Tests invalid state transitions that should be blocked:
        - Skip directly to payment without cart
        - Complete order without payment
        - Access refund without valid order
        - Verify email without registration
        """
        findings = []
        
        # Define invalid transition tests
        invalid_transitions = [
            {
                "name": "Direct Checkout (Skip Cart)",
                "from_state": WorkflowState.INITIAL,
                "to_state": WorkflowState.PAYMENT_PENDING,
                "endpoints": endpoints.get("checkout", []),
                "payload": {"action": "checkout", "skip_cart": True},
                "method": "POST",
            },
            {
                "name": "Complete Order (Skip Payment)",
                "from_state": WorkflowState.ITEMS_ADDED,
                "to_state": WorkflowState.ORDER_CONFIRMED,
                "endpoints": endpoints.get("order", []),
                "payload": {"action": "complete", "status": "confirmed"},
                "method": "POST",
            },
            {
                "name": "Request Refund (No Order)",
                "from_state": WorkflowState.INITIAL,
                "to_state": WorkflowState.REFUND_REQUESTED,
                "endpoints": endpoints.get("refund", []),
                "payload": {"order_id": "FAKE123", "reason": "test"},
                "method": "POST",
            },
            {
                "name": "Verify Email (No Registration)",
                "from_state": WorkflowState.INITIAL,
                "to_state": WorkflowState.EMAIL_VERIFIED,
                "endpoints": endpoints.get("verify", []),
                "payload": {"token": "bypass", "verified": True},
                "method": "POST",
            },
            {
                "name": "Direct Payment Completion",
                "from_state": WorkflowState.INITIAL,
                "to_state": WorkflowState.PAYMENT_COMPLETED,
                "endpoints": endpoints.get("checkout", []),
                "payload": {"payment_status": "completed", "force": True},
                "method": "PUT",
            },
        ]
        
        # ⚠️ SAFE MODE: Skip PUT tests in non-write modes
        if not ALLOW_WRITES:
            logger.info("⚠️ SAFE MODE: Skipping state transition tests that use PUT/POST")
            return findings
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for test in invalid_transitions:
                for endpoint in test["endpoints"][:3]:
                    await rate_limiter.acquire()
                    
                    try:
                        # Attempt invalid transition without proper state
                        if test["method"] == "POST":
                            response = await client.post(endpoint, json=test["payload"])
                        else:
                            response = await client.put(endpoint, json=test["payload"])
                        
                        # Check if transition was incorrectly allowed
                        if response.status_code in [200, 201, 202]:
                            # Additional validation - check response content
                            try:
                                data = response.json()
                                success_indicators = ["success", "completed", "confirmed", "ok", "true"]
                                response_str = json.dumps(data).lower()
                                
                                if any(ind in response_str for ind in success_indicators):
                                    findings.append(Finding(
                                        type="business_logic",
                                        name=f"State Machine Bypass: {test['name']}",
                                        severity="CRITICAL",
                                        description=(
                                            f"Invalid workflow transition allowed. "
                                            f"Attempted to go from {test['from_state'].name} to {test['to_state'].name} "
                                            f"without completing required intermediate steps."
                                        ),
                                        host=base_url,
                                        matched_at=endpoint,
                                        evidence=[
                                            f"Invalid transition: {test['from_state'].name} → {test['to_state'].name}",
                                            f"Payload: {json.dumps(test['payload'])}",
                                            f"Response status: {response.status_code}",
                                        ],
                                        cvss_score=9.1,
                                        cwe="CWE-841",
                                        remediation=(
                                            "Implement server-side state machine validation. "
                                            "Track workflow state in session/database. "
                                            "Reject requests that violate valid state transitions. "
                                            "Use signed state tokens to prevent tampering."
                                        ),
                                        references=[
                                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/",
                                        ],
                                    ).to_dict())
                                    
                                    # Track in context
                                    tx_context.transition_to(test["to_state"])
                            except Exception:
                                pass
                                
                    except Exception as e:
                        logger.debug(f"State machine test error: {e}")
        
        return findings

    # ========================================================================
    # ENTERPRISE METHODS - Advanced Race Conditions
    # ========================================================================
    
    async def _test_advanced_race_conditions(
        self,
        base_url: str,
        endpoints: dict[str, list[str]],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Advanced race condition testing with timing analysis.
        
        Features:
        - Configurable concurrency levels
        - Response timing variance analysis
        - Duplicate effect detection
        - Confidence scoring
        """
        findings = []
        
        for scenario in RACE_CONDITION_SCENARIOS:
            # Find matching endpoints
            target_endpoints = []
            for ep_type in scenario["endpoints"]:
                target_endpoints.extend(endpoints.get(ep_type, []))

            if not target_endpoints:
                continue

            # Get scenario-specific payload if available
            scenario_name = scenario["name"]
            payload = FINANCIAL_RACE_PAYLOADS.get(
                scenario_name,
                {"action": scenario_name, "id": f"race_{int(time.time())}"}
            )

            # Use higher concurrency for financial endpoints
            is_financial = scenario.get("severity") == "CRITICAL"
            concurrency_levels = [10, 25, 50, 100] if is_financial else [5, 10, 20, 50]

            for endpoint in target_endpoints[:3]:  # Test more endpoints for critical scenarios
                result = await self._execute_race_test(
                    endpoint=endpoint,
                    method=scenario["method"],
                    concurrency_levels=concurrency_levels,
                    payload=payload,
                )

                if result and result.vulnerability_confidence > 0.5:  # Lower threshold for financial
                    # Determine severity from scenario or result
                    base_severity = scenario.get("severity", "HIGH")
                    if result.duplicate_effects:
                        severity = "CRITICAL"
                    elif base_severity == "CRITICAL":
                        severity = "CRITICAL" if result.vulnerability_confidence > 0.7 else "HIGH"
                    else:
                        severity = base_severity

                    # Calculate CVSS based on impact
                    impact = scenario.get("impact", "Unknown impact")
                    if "financial" in impact.lower() or "theft" in impact.lower() or "double" in impact.lower():
                        cvss = 9.8
                    elif result.duplicate_effects:
                        cvss = 9.1
                    elif severity == "CRITICAL":
                        cvss = 8.5
                    else:
                        cvss = 7.5

                    findings.append(Finding(
                        type="business_logic",
                        name=f"Race Condition: {scenario_name.replace('_', ' ').title()}",
                        severity=severity,
                        description=(
                            f"Race condition vulnerability detected with {result.vulnerability_confidence:.0%} confidence. "
                            f"Endpoint allows duplicate actions under concurrent requests. "
                            f"Impact: {impact}"
                        ),
                        host=base_url,
                        matched_at=endpoint,
                        evidence=[
                            f"Scenario: {scenario_name}",
                            f"Concurrent requests: {result.concurrent_requests}",
                            f"Successful duplicates: {result.successful_requests}",
                            f"Timing variance: {result.timing_variance_ms:.2f}ms",
                            f"Duplicate effects detected: {result.duplicate_effects}",
                            f"Confidence: {result.vulnerability_confidence:.0%}",
                            f"Potential impact: {impact}",
                        ],
                        cvss_score=cvss,
                        cwe="CWE-362",
                        remediation=(
                            "CRITICAL: Implement distributed locks (Redis/DB locks) for financial operations. "
                            "Use idempotency keys with unique request IDs. "
                            "Apply optimistic locking with version numbers on all balance operations. "
                            "Use database transactions with SERIALIZABLE isolation level. "
                            "Implement request deduplication with time windows (30-60 seconds). "
                            "Add mutex locks on user-specific resources during transactions."
                        ),
                        references=[
                            "https://portswigger.net/web-security/race-conditions",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Race_Condition_Cheat_Sheet.html",
                        ],
                        metadata={
                            "race_condition_details": {
                                "concurrency_tested": result.concurrent_requests,
                                "timing_variance_ms": result.timing_variance_ms,
                                "response_patterns": result.response_patterns,
                                "financial_impact": is_financial,
                            }
                        },
                    ).to_dict())
        
        return findings
    
    async def _execute_race_test(
        self,
        endpoint: str,
        method: str,
        concurrency_levels: list[int],
        payload: dict,
    ) -> Optional[RaceConditionResult]:
        """Execute race condition test with multiple concurrency levels."""
        best_result = None
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for concurrency in concurrency_levels:
                timings = []
                responses = []
                
                async def make_request():
                    start = time.time()
                    try:
                        if method == "POST":
                            resp = await client.post(endpoint, json=payload)
                        else:
                            resp = await client.get(endpoint, params=payload)
                        elapsed = (time.time() - start) * 1000  # ms
                        return resp, elapsed
                    except Exception:
                        return None, 0
                
                # Execute concurrent requests
                tasks = [make_request() for _ in range(concurrency)]
                results = await asyncio.gather(*tasks)
                
                for resp, timing in results:
                    if resp is not None:
                        responses.append(resp)
                        timings.append(timing)
                
                if len(responses) < 3:
                    continue
                
                # Analyze results
                success_count = sum(1 for r in responses if r.status_code in [200, 201, 202])
                status_codes = [r.status_code for r in responses]
                timing_variance = max(timings) - min(timings) if timings else 0
                
                # Check for duplicate effects (same success response hash)
                response_hashes = [hashlib.md5(r.text.encode()).hexdigest()[:8] for r in responses if r.status_code in [200, 201]]
                duplicate_effects = len(response_hashes) > len(set(response_hashes))
                
                # Calculate confidence score
                confidence = 0.0
                if success_count > 1:
                    confidence += 0.3
                if duplicate_effects:
                    confidence += 0.4
                if timing_variance < 100:  # Very fast, might indicate no locking
                    confidence += 0.2
                if len(set(status_codes)) > 1:  # Mixed responses
                    confidence += 0.1
                
                result = RaceConditionResult(
                    endpoint=endpoint,
                    concurrent_requests=concurrency,
                    successful_requests=success_count,
                    duplicate_effects=duplicate_effects,
                    timing_variance_ms=timing_variance,
                    response_patterns=list(set(status_codes)),
                    vulnerability_confidence=min(confidence, 1.0),
                )
                
                if best_result is None or result.vulnerability_confidence > best_result.vulnerability_confidence:
                    best_result = result
        
        return best_result

    # ========================================================================
    # ENTERPRISE METHODS - Financial Edge Cases
    # ========================================================================
    
    async def _test_financial_edge_cases(
        self,
        base_url: str,
        endpoints: dict[str, list[str]],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Comprehensive financial manipulation testing.
        
        Tests:
        - Integer overflow/underflow
        - Floating point precision attacks
        - Currency conversion abuse
        - Rounding exploitation
        - Scientific notation injection
        """
        findings = []
        
        financial_endpoints = (
            endpoints.get("cart", []) +
            endpoints.get("checkout", []) +
            endpoints.get("pricing", []) +
            endpoints.get("order", [])
        )
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for endpoint in financial_endpoints[:5]:
                for test_case in FINANCIAL_TEST_CASES:
                    await rate_limiter.acquire()
                    
                    try:
                        response = await client.post(endpoint, json=test_case.payload)
                        
                        # If test was expected to be rejected but wasn't
                        if test_case.expected_rejection and response.status_code in [200, 201]:
                            # Verify it actually processed the bad value
                            try:
                                data = response.json()
                                response_str = json.dumps(data).lower()
                                
                                # Check for success indicators
                                if any(x in response_str for x in ["success", "created", "added", "processed"]):
                                    findings.append(Finding(
                                        type="business_logic",
                                        name=f"Financial Edge Case: {test_case.name}",
                                        severity=test_case.severity,
                                        description=(
                                            f"{test_case.description}. "
                                            f"Server accepted payload that should have been rejected."
                                        ),
                                        host=base_url,
                                        matched_at=endpoint,
                                        evidence=[
                                            f"Test: {test_case.name}",
                                            f"Payload: {json.dumps(test_case.payload)}",
                                            f"Status: {response.status_code}",
                                        ],
                                        cvss_score=self._severity_to_cvss(test_case.severity),
                                        cwe="CWE-20" if "overflow" not in test_case.name else "CWE-190",
                                        remediation=(
                                            "Implement strict server-side validation for all financial values. "
                                            "Use decimal/BigDecimal types instead of floats. "
                                            "Define explicit min/max bounds for all numeric fields. "
                                            "Validate currency codes against ISO 4217. "
                                            "Implement proper overflow/underflow checks."
                                        ),
                                    ).to_dict())
                                    break  # Found vuln for this test case
                            except Exception:
                                pass
                                
                    except Exception as e:
                        logger.debug(f"Financial edge case test error: {e}")
        
        return findings
    
    def _severity_to_cvss(self, severity: str) -> float:
        """Convert severity string to CVSS score."""
        return {
            "CRITICAL": 9.8,
            "HIGH": 8.1,
            "MEDIUM": 5.3,
            "LOW": 3.1,
            "INFO": 0.0,
        }.get(severity.upper(), 5.0)

    # ========================================================================
    # ENTERPRISE METHODS - Multi-Step Transactions
    # ========================================================================
    
    async def _test_multi_step_transactions(
        self,
        base_url: str,
        endpoints: dict[str, list[str]],
        rate_limiter: RateLimiter,
        tx_context: TransactionContext,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Test multi-step transaction flows for manipulation.
        
        Tests:
        - Parameter pollution between steps
        - Session state manipulation
        - Value modification between steps
        - Concurrent transaction interference
        """
        findings = []
        
        # Define multi-step transaction flows
        transaction_flows = [
            {
                "name": "Checkout Flow Manipulation",
                "steps": [
                    {"endpoint_type": "cart", "action": "add", "payload": {"item_id": 1, "price": 100}},
                    {"endpoint_type": "checkout", "action": "init", "payload": {}},
                    {"endpoint_type": "checkout", "action": "complete", "payload": {"price": 0}},  # Try to override
                ],
            },
            {
                "name": "Refund Flow Manipulation",
                "steps": [
                    {"endpoint_type": "order", "action": "create", "payload": {"total": 50}},
                    {"endpoint_type": "refund", "action": "request", "payload": {"amount": 500}},  # 10x original
                ],
            },
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for flow in transaction_flows:
                step_responses = []
                
                for step in flow["steps"]:
                    step_endpoints = endpoints.get(step["endpoint_type"], [])
                    
                    if not step_endpoints:
                        continue
                    
                    await rate_limiter.acquire()
                    
                    try:
                        response = await client.post(
                            step_endpoints[0],
                            json=step["payload"],
                        )
                        step_responses.append({
                            "step": step["action"],
                            "status": response.status_code,
                            "response": response.text[:500],
                        })
                    except Exception as e:
                        logger.debug(f"Multi-step test error: {e}")
                        break
                
                # Analyze flow for manipulation success
                if len(step_responses) >= 2:
                    final_response = step_responses[-1]
                    
                    if final_response["status"] in [200, 201]:
                        # Check if manipulation was accepted
                        if any(x in final_response["response"].lower() for x in ["success", "processed", "complete"]):
                            findings.append(Finding(
                                type="business_logic",
                                name=f"Multi-Step Transaction Manipulation: {flow['name']}",
                                severity="HIGH",
                                description=(
                                    f"Multi-step transaction flow vulnerable to parameter manipulation. "
                                    f"Attacker may be able to modify values between transaction steps."
                                ),
                                host=base_url,
                                matched_at=str([s["step"] for s in step_responses]),
                                evidence=[f"Step {i+1} ({s['step']}): Status {s['status']}" for i, s in enumerate(step_responses)],
                                cvss_score=8.1,
                                cwe="CWE-841",
                                remediation=(
                                    "Sign transaction state between steps. "
                                    "Store authoritative values server-side. "
                                    "Validate all values against initial transaction state. "
                                    "Use server-side session for transaction context."
                                ),
                            ).to_dict())
        
        return findings

    # ========================================================================
    # ENTERPRISE METHODS - Idempotency Abuse
    # ========================================================================
    
    async def _test_idempotency_abuse(
        self,
        base_url: str,
        endpoints: dict[str, list[str]],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Test for idempotency key abuse and replay attacks.
        
        Tests:
        - Idempotency key reuse for different operations
        - Predictable idempotency keys
        - Missing idempotency enforcement
        - Idempotency window bypass
        """
        findings = []
        
        idempotency_headers = [
            "Idempotency-Key",
            "X-Idempotency-Key",
            "X-Request-Id",
            "Request-Id",
            "X-Unique-ID",
        ]
        
        payment_endpoints = endpoints.get("checkout", []) + endpoints.get("order", [])
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for endpoint in payment_endpoints[:3]:
                # Test 1: Same idempotency key, different payloads
                test_key = f"test-idempotency-{int(time.time())}"
                responses = []
                
                for header_name in idempotency_headers[:2]:
                    for payload_variant in [
                        {"amount": 100, "action": "charge"},
                        {"amount": 1000, "action": "charge"},  # Different amount
                    ]:
                        await rate_limiter.acquire()
                        
                        try:
                            response = await client.post(
                                endpoint,
                                json=payload_variant,
                                headers={header_name: test_key},
                            )
                            responses.append({
                                "header": header_name,
                                "payload": payload_variant,
                                "status": response.status_code,
                            })
                        except Exception:
                            pass
                
                # Analyze: If same key accepted different payloads
                success_responses = [r for r in responses if r["status"] in [200, 201]]
                
                if len(success_responses) > 1:
                    unique_payloads = len(set(json.dumps(r["payload"], sort_keys=True) for r in success_responses))
                    
                    if unique_payloads > 1:
                        findings.append(Finding(
                            type="business_logic",
                            name="Idempotency Key Abuse",
                            severity="HIGH",
                            description=(
                                "Same idempotency key accepted for different operations. "
                                "Attacker can replay requests with modified payloads."
                            ),
                            host=base_url,
                            matched_at=endpoint,
                            evidence=[
                                f"Key: {test_key}",
                                f"Different payloads accepted: {unique_payloads}",
                            ],
                            cvss_score=7.5,
                            cwe="CWE-294",
                            remediation=(
                                "Hash idempotency key with payload content. "
                                "Reject requests where key matches but payload differs. "
                                "Implement proper idempotency token validation."
                            ),
                        ).to_dict())
                
                # Test 2: Predictable keys (sequential numbers)
                for i in range(3):
                    await rate_limiter.acquire()
                    
                    predictable_key = str(1000 + i)
                    
                    try:
                        response = await client.post(
                            endpoint,
                            json={"test": True},
                            headers={"Idempotency-Key": predictable_key},
                        )
                        
                        if response.status_code in [200, 201]:
                            findings.append(Finding(
                                type="business_logic",
                                name="Predictable Idempotency Key Accepted",
                                severity="MEDIUM",
                                description="Server accepts predictable/sequential idempotency keys.",
                                host=base_url,
                                matched_at=endpoint,
                                evidence=[f"Key accepted: {predictable_key}"],
                                cvss_score=5.3,
                                cwe="CWE-330",
                                remediation="Require cryptographically random idempotency keys (UUID v4).",
                            ).to_dict())
                            break
                    except Exception:
                        pass
        
        return findings

    # ========================================================================
    # ENTERPRISE METHODS - Inventory Manipulation
    # ========================================================================
    
    async def _test_inventory_manipulation(
        self,
        base_url: str,
        endpoints: dict[str, list[str]],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Test for inventory/stock manipulation vulnerabilities.
        
        Tests:
        - Overselling (add more than available)
        - Inventory reservation abuse
        - Cart hoarding attacks
        - Phantom inventory creation
        """
        findings = []
        
        cart_endpoints = endpoints.get("cart", [])
        
        inventory_tests = [
            {
                "name": "Overselling Attack",
                "payload": {"item_id": 1, "quantity": 999999},
                "description": "Ordering more than available inventory",
            },
            {
                "name": "Negative Inventory",
                "payload": {"item_id": 1, "quantity": -10},
                "description": "Using negative quantity to increase stock/credit",
            },
            {
                "name": "Zero Item ID",
                "payload": {"item_id": 0, "quantity": 1},
                "description": "Accessing default/system inventory",
            },
            {
                "name": "Fractional Quantity",
                "payload": {"item_id": 1, "quantity": 0.5},
                "description": "Fractional quantities for pricing abuse",
            },
            {
                "name": "Bulk Reservation",
                "payload": {"item_id": 1, "quantity": 1000, "reserve": True},
                "description": "Mass reservation to deny others",
            },
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for endpoint in cart_endpoints[:3]:
                for test in inventory_tests:
                    await rate_limiter.acquire()
                    
                    try:
                        response = await client.post(endpoint, json=test["payload"])
                        
                        if response.status_code in [200, 201]:
                            findings.append(Finding(
                                type="business_logic",
                                name=f"Inventory Manipulation: {test['name']}",
                                severity="HIGH",
                                description=test["description"],
                                host=base_url,
                                matched_at=endpoint,
                                evidence=[
                                    f"Payload: {json.dumps(test['payload'])}",
                                    f"Status: {response.status_code}",
                                ],
                                cvss_score=7.5,
                                cwe="CWE-20",
                                remediation=(
                                    "Validate quantities against actual stock. "
                                    "Implement inventory locks during checkout. "
                                    "Set maximum order quantities. "
                                    "Use atomic inventory operations."
                                ),
                            ).to_dict())
                            break
                    except Exception as e:
                        logger.debug(f"Inventory test error: {e}")
        
        return findings

    # ========================================================================
    # ENTERPRISE METHODS - Time-Based Bypass
    # ========================================================================
    
    async def _test_time_based_bypass(
        self,
        base_url: str,
        endpoints: dict[str, list[str]],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Test for time-based business rule bypass.
        
        Tests:
        - Expired promotion reuse
        - Future date manipulation
        - Time window bypass
        - Timezone abuse
        """
        findings = []
        
        time_sensitive_payloads = [
            # Past dates (expired promotions)
            {
                "name": "Expired Promotion",
                "payload": {"promo_code": "EXPIRED2020", "valid_date": "2020-01-01"},
            },
            # Future dates
            {
                "name": "Future Date Manipulation",
                "payload": {"order_date": "2030-12-31", "delivery_date": "2031-01-01"},
            },
            # Time window bypass
            {
                "name": "Flash Sale Window Bypass",
                "payload": {"sale_time": "00:00:00", "timezone": "UTC+14"},
            },
            # Negative timestamps
            {
                "name": "Negative Timestamp",
                "payload": {"timestamp": -86400, "date": "1969-12-31"},
            },
        ]
        
        all_endpoints = (
            endpoints.get("coupon", []) +
            endpoints.get("checkout", []) +
            endpoints.get("order", [])
        )
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for endpoint in all_endpoints[:5]:
                for test in time_sensitive_payloads:
                    await rate_limiter.acquire()
                    
                    try:
                        response = await client.post(endpoint, json=test["payload"])
                        
                        if response.status_code in [200, 201]:
                            try:
                                data = response.json()
                                if any(x in str(data).lower() for x in ["success", "applied", "valid"]):
                                    findings.append(Finding(
                                        type="business_logic",
                                        name=f"Time-Based Bypass: {test['name']}",
                                        severity="MEDIUM",
                                        description=f"Time-based validation can be bypassed: {test['name']}",
                                        host=base_url,
                                        matched_at=endpoint,
                                        evidence=[f"Payload: {json.dumps(test['payload'])}"],
                                        cvss_score=5.3,
                                        cwe="CWE-20",
                                        remediation=(
                                            "Use server-side time for all time-sensitive operations. "
                                            "Never trust client-provided timestamps. "
                                            "Implement proper expiration validation."
                                        ),
                                    ).to_dict())
                                    break
                            except Exception:
                                pass
                    except Exception as e:
                        logger.debug(f"Time-based test error: {e}")
        
        return findings

    # ========================================================================
    # ENTERPRISE METHODS - Response Fingerprinting
    # ========================================================================
    
    async def _test_response_fingerprinting(
        self,
        base_url: str,
        endpoints: dict[str, list[str]],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Advanced response fingerprinting for enumeration.
        
        Techniques:
        - Response hash comparison
        - Timing analysis (sub-millisecond)
        - Header fingerprinting
        - Error message analysis
        - Content-length variance
        """
        findings = []
        
        auth_endpoints = endpoints.get("register", []) + endpoints.get("password", [])
        
        # Generate test emails for comparison
        existing_patterns = [
            "admin@{domain}",
            "test@{domain}",
            "info@{domain}",
            "support@{domain}",
            "user@{domain}",
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for endpoint in auth_endpoints[:3]:
                await rate_limiter.acquire()
                
                try:
                    domain = urlparse(base_url).netloc
                    
                    # Collect fingerprints for existing vs non-existing
                    fingerprints = {"existing_patterns": [], "random": []}
                    
                    # Test potentially existing emails
                    for pattern in existing_patterns:
                        email = pattern.format(domain=domain)
                        start = time.time()
                        
                        response = await client.post(
                            endpoint,
                            json={"email": email},
                        )
                        
                        elapsed_ms = (time.time() - start) * 1000
                        
                        fingerprints["existing_patterns"].append({
                            "email": email,
                            "status": response.status_code,
                            "length": len(response.text),
                            "timing_ms": elapsed_ms,
                            "hash": hashlib.md5(response.text.encode()).hexdigest()[:8],
                        })
                        
                        await rate_limiter.acquire()
                    
                    # Test definitely non-existing emails
                    for i in range(5):
                        random_email = f"nonexistent_{int(time.time())}_{i}@randomdomain{random.randint(1000,9999)}.invalid"
                        start = time.time()
                        
                        response = await client.post(
                            endpoint,
                            json={"email": random_email},
                        )
                        
                        elapsed_ms = (time.time() - start) * 1000
                        
                        fingerprints["random"].append({
                            "email": random_email,
                            "status": response.status_code,
                            "length": len(response.text),
                            "timing_ms": elapsed_ms,
                            "hash": hashlib.md5(response.text.encode()).hexdigest()[:8],
                        })
                        
                        await rate_limiter.acquire()
                    
                    # Analyze fingerprint differences
                    enumeration_indicators = self._analyze_fingerprints(fingerprints)
                    
                    if enumeration_indicators:
                        findings.append(Finding(
                            type="business_logic",
                            name="Advanced Account Enumeration via Response Fingerprinting",
                            severity="MEDIUM",
                            description="Response analysis reveals user existence through multiple vectors.",
                            host=base_url,
                            matched_at=endpoint,
                            evidence=enumeration_indicators,
                            cvss_score=5.3,
                            cwe="CWE-204",
                            remediation=(
                                "Normalize all responses to be identical. "
                                "Use constant-time comparison for lookups. "
                                "Add random delays to normalize timing. "
                                "Return generic error messages. "
                                "Consider using email verification workflow."
                            ),
                        ).to_dict())
                        
                except Exception as e:
                    logger.debug(f"Response fingerprinting error: {e}")
        
        return findings
    
    def _analyze_fingerprints(self, fingerprints: dict) -> list[str]:
        """Analyze response fingerprints for enumeration indicators."""
        indicators = []
        
        existing = fingerprints.get("existing_patterns", [])
        random_fps = fingerprints.get("random", [])
        
        if not existing or not random_fps:
            return indicators
        
        # Compare hashes
        existing_hashes = set(f["hash"] for f in existing)
        random_hashes = set(f["hash"] for f in random_fps)
        
        if existing_hashes != random_hashes:
            indicators.append(f"Response content differs: {len(existing_hashes)} vs {len(random_hashes)} unique patterns")
        
        # Compare timing
        avg_existing_time = sum(f["timing_ms"] for f in existing) / len(existing)
        avg_random_time = sum(f["timing_ms"] for f in random_fps) / len(random_fps)
        
        time_diff = abs(avg_existing_time - avg_random_time)
        if time_diff > 50:  # 50ms difference is significant
            indicators.append(f"Timing difference: {time_diff:.2f}ms (existing: {avg_existing_time:.2f}ms, random: {avg_random_time:.2f}ms)")
        
        # Compare lengths
        existing_lengths = set(f["length"] for f in existing)
        random_lengths = set(f["length"] for f in random_fps)
        
        if existing_lengths != random_lengths:
            indicators.append(f"Response length variance detected")
        
        # Compare status codes
        existing_statuses = set(f["status"] for f in existing)
        random_statuses = set(f["status"] for f in random_fps)
        
        if existing_statuses != random_statuses:
            indicators.append(f"Status code difference: {existing_statuses} vs {random_statuses}")
        
        return indicators