"""
Business Logic Scanner - Base Types.

Contains enums, dataclasses, constants, and priority tiers for
business logic vulnerability detection.

Extracted from business_logic_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


# Version
BUSINESS_LOGIC_SCANNER_VERSION = "2.0.0-ENTERPRISE"

# ============================================================================
# SAFE MODE CONFIGURATION
# ============================================================================

# Safe mode environment variable - set by full_scanner.py
SAFE_MODE = os.environ.get("PHANTOM_SAFE_MODE", "safe").lower()

# New safety levels:
# - safe: Allow POST/PUT for testing (normal user actions)
# - cautious: Same as safe (deprecated, kept for compatibility)
# - standard: Same as safe
# - aggressive: Allow DELETE and mass operations
ALLOW_WRITES = SAFE_MODE in ("safe", "cautious", "standard", "aggressive")
ALLOW_DESTRUCTIVE = SAFE_MODE in ("aggressive",)


# ============================================================================
# BUSINESS LOGIC PRIORITY TIERS — Attacker Cost Model Integration
# ============================================================================

BUSINESS_LOGIC_PRIORITY: dict[str, tuple[str, int, int, int]] = {
    # TIER 1: CRITICAL — Direct financial loss, trivial to exploit
    "negative_quantity": ("CRITICAL", 10, 1, 9),
    "negative_value": ("CRITICAL", 10, 1, 9),
    "price_manipulation": ("CRITICAL", 10, 2, 8),
    "payment_bypass": ("CRITICAL", 10, 2, 7),
    "state_machine_bypass": ("CRITICAL", 9, 3, 7),
    "checkout_bypass": ("CRITICAL", 10, 2, 6),

    # TIER 2: HIGH — Significant impact, moderate effort
    "workflow_bypass": ("HIGH", 8, 4, 6),
    "verification_bypass": ("HIGH", 8, 3, 5),
    "authorization_bypass": ("HIGH", 9, 3, 6),
    "race_condition": ("HIGH", 8, 5, 7),
    "double_spend": ("HIGH", 9, 4, 8),
    "idempotency_abuse": ("HIGH", 7, 4, 8),
    "inventory_manipulation": ("HIGH", 8, 3, 6),
    "idor_basket": ("HIGH", 7, 2, 7),
    "transaction_manipulation": ("HIGH", 8, 4, 6),
    "data_isolation": ("HIGH", 8, 3, 6),

    # TIER 3: MEDIUM — Limited impact or requires effort
    "coupon_reuse": ("MEDIUM", 5, 2, 8),
    "rate_limit_bypass": ("MEDIUM", 4, 3, 9),
    "account_enumeration": ("MEDIUM", 3, 2, 9),
    "zero_quantity": ("MEDIUM", 3, 1, 5),
    "time_based_bypass": ("MEDIUM", 5, 4, 4),
    "response_fingerprint": ("MEDIUM", 3, 3, 8),
    "predictable_key": ("MEDIUM", 4, 3, 6),

    # TIER 4: LOW — Minimal impact, theoretical
    "zero_star_rating": ("LOW", 1, 1, 3),
    "review_manipulation": ("LOW", 2, 2, 4),
    "ui_inconsistency": ("LOW", 1, 1, 2),
    "calculation_rounding": ("LOW", 2, 3, 3),
}


def get_business_priority(finding_name: str) -> tuple[str, int, int, int]:
    """Get priority tier for a business logic finding."""
    name_lower = finding_name.lower().replace(" ", "_").replace("-", "_")

    for pattern, priority in BUSINESS_LOGIC_PRIORITY.items():
        if pattern in name_lower:
            return priority

    # Default: MEDIUM priority with average scores
    return ("MEDIUM", 5, 5, 5)


# ============================================================================
# WORKFLOW STATE MACHINE
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
VALID_TRANSITIONS: dict[WorkflowState, list[WorkflowState]] = {
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


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class TransactionContext:
    """Tracks transaction state for multi-step testing."""
    session_id: str = ""
    cart_id: str = ""
    order_id: str = ""
    user_id: str = ""
    tokens: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    current_state: WorkflowState = WorkflowState.INITIAL
    state_history: list[tuple[WorkflowState, WorkflowState]] = field(default_factory=list)
    response_hashes: dict[str, str] = field(default_factory=dict)
    financial_values: dict[str, float] = field(default_factory=dict)

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
    response_patterns: list[str]
    vulnerability_confidence: float  # 0.0 to 1.0


@dataclass
class FinancialTestCase:
    """Test case for financial manipulation testing."""
    name: str
    payload: dict[str, Any]
    expected_rejection: bool
    severity: str
    description: str


@dataclass
class BusinessFlow:
    """Represents a business workflow to test."""
    name: str
    steps: list[dict[str, Any]]
    expected_behavior: str
    abuse_scenarios: list[str] = field(default_factory=list)
    required_state: WorkflowState = WorkflowState.INITIAL
    result_state: WorkflowState = WorkflowState.INITIAL


@dataclass
class ResponseBehavior:
    """Captures behavioral characteristics of an API response."""
    endpoint: str
    method: str
    status_code: int
    response_time_ms: float
    body_size: int
    field_count: int
    numeric_fields: dict[str, float]
    has_error: bool
    error_type: str
    timestamp: float


@dataclass
class AnomalyResult:
    """Result of anomaly detection analysis."""
    is_anomalous: bool
    anomaly_type: str  # "timing", "size", "value", "behavior", "sequence"
    anomaly_score: float  # 0-100, higher = more anomalous
    normal_range: str  # e.g., "50-150ms"
    observed_value: str
    evidence: list[str]
    suggested_finding_type: str  # e.g., "race_condition", "overflow"


# ============================================================================
# FINANCIAL TEST CASES
# ============================================================================

FINANCIAL_TEST_CASES: list[FinancialTestCase] = [
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
# RACE CONDITION SCENARIOS
# ============================================================================

RACE_CONDITION_SCENARIOS: list[dict[str, Any]] = [
    # HIGH-VALUE FINANCIAL RACE CONDITIONS
    {"name": "coupon_apply", "endpoints": ["coupon", "discount", "promo", "voucher", "code"],
     "method": "POST", "severity": "CRITICAL", "impact": "Free products via double coupon"},
    {"name": "checkout_complete", "endpoints": ["checkout", "order", "purchase", "buy"],
     "method": "POST", "severity": "CRITICAL", "impact": "Double order creation"},
    {"name": "balance_transfer", "endpoints": ["transfer", "send", "payment", "pay", "withdraw"],
     "method": "POST", "severity": "CRITICAL", "impact": "Double-spend, balance manipulation"},
    {"name": "wallet_topup", "endpoints": ["topup", "deposit", "credit", "add-funds", "fund"],
     "method": "POST", "severity": "CRITICAL", "impact": "Credit without payment"},
    {"name": "points_redeem", "endpoints": ["redeem", "points", "rewards", "claim", "cashback"],
     "method": "POST", "severity": "HIGH", "impact": "Double-redeem loyalty points"},
    {"name": "referral_claim", "endpoints": ["referral", "invite", "bonus", "signup-bonus"],
     "method": "POST", "severity": "HIGH", "impact": "Multiple referral bonus claims"},
    {"name": "inventory_reserve", "endpoints": ["reserve", "cart", "hold", "book", "lock"],
     "method": "POST", "severity": "HIGH", "impact": "Inventory overselling"},
    {"name": "limited_item_purchase", "endpoints": ["limited", "exclusive", "flash-sale", "deal"],
     "method": "POST", "severity": "HIGH", "impact": "Bypass purchase limits"},
    {"name": "trial_activation", "endpoints": ["trial", "free-trial", "demo", "start-trial"],
     "method": "POST", "severity": "MEDIUM", "impact": "Multiple trial activations"},
    {"name": "subscription_upgrade", "endpoints": ["upgrade", "subscription", "plan"],
     "method": "POST", "severity": "HIGH", "impact": "Free upgrades via race"},
    {"name": "rate_limit_bypass", "endpoints": ["api", "request", "action"],
     "method": "POST", "severity": "MEDIUM", "impact": "Bypass rate limiting"},
    {"name": "vote_submit", "endpoints": ["vote", "poll", "rate", "review"],
     "method": "POST", "severity": "LOW", "impact": "Vote manipulation"},
    {"name": "withdrawal_request", "endpoints": ["withdraw", "payout", "cashout"],
     "method": "POST", "severity": "CRITICAL", "impact": "Double withdrawal"},
    {"name": "refund_process", "endpoints": ["refund", "return", "chargeback"],
     "method": "POST", "severity": "CRITICAL", "impact": "Double refund"},
]


FINANCIAL_RACE_PAYLOADS: dict[str, dict[str, Any]] = {
    "balance_transfer": {"amount": 100, "to_account": "attacker_account", "currency": "USD"},
    "wallet_topup": {"amount": 50, "method": "test_card"},
    "coupon_apply": {"code": "TESTCODE50", "apply": True},
    "withdrawal_request": {"amount": 100, "method": "bank_transfer"},
    "refund_process": {"order_id": "test_order", "reason": "test_refund"},
    "points_redeem": {"points": 1000, "reward_id": "test_reward"},
}


__all__ = [
    # Version
    "BUSINESS_LOGIC_SCANNER_VERSION",
    # Safety
    "SAFE_MODE",
    "ALLOW_WRITES",
    "ALLOW_DESTRUCTIVE",
    # Priority
    "BUSINESS_LOGIC_PRIORITY",
    "get_business_priority",
    # Workflow
    "WorkflowState",
    "VALID_TRANSITIONS",
    # Dataclasses
    "TransactionContext",
    "RaceConditionResult",
    "FinancialTestCase",
    "BusinessFlow",
    "ResponseBehavior",
    "AnomalyResult",
    # Test cases
    "FINANCIAL_TEST_CASES",
    "RACE_CONDITION_SCENARIOS",
    "FINANCIAL_RACE_PAYLOADS",
]
